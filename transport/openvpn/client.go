package openvpn

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
)

type Client struct {
	config *ClientConfig
	mux    *PacketMux

	control     *ControlChannel
	controlConn *ControlConn
	tlsConn     *tls.Conn
	data        *DataChannel
	push        *PushReply

	// sessionErr records why the session died (AUTH_FAILED, HALT, soft
	// reset, ...) so the adapter can log something actionable instead of
	// a generic "connection closed".
	sessionErr atomic.Pointer[error]
	runCtx     context.Context

	// optionsString is the OCC options string sent in the key method 2
	// record; it is also echoed in OCC_REPLY when the server probes us.
	optionsString string
	// tlsReadBuf holds TLS plaintext read but not yet consumed, so control
	// channel messages coalesced in one flight are not lost between phases.
	tlsReadBuf []byte

	cancel context.CancelFunc

	writeSem *semaphore.Weighted

	lastSendNano    atomic.Int64
	lastReceiveNano atomic.Int64
}

func NewClient(config *ClientConfig, io PacketIO) (*Client, error) {
	if config == nil {
		return nil, errors.New("nil openvpn client config")
	}
	if io == nil {
		return nil, errors.New("nil openvpn packet io")
	}
	var crypt *TLSCrypt
	if len(config.TLSCryptKey) > 0 {
		var err error
		crypt, err = NewTLSCrypt(config.TLSCryptKey, true)
		if err != nil {
			return nil, err
		}
	}
	local, err := NewSessionID()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	mux := NewPacketMux(io)
	go mux.Run(runCtx)
	client := &Client{
		config:   config,
		mux:      mux,
		control:  NewControlChannel(mux, crypt, local),
		cancel:   cancel,
		runCtx:   runCtx,
		writeSem: semaphore.NewWeighted(1),
	}
	go client.control.RunRetransmitter(runCtx)
	client.markSend()
	client.markReceive()
	return client, nil
}

func (c *Client) Handshake(ctx context.Context) (*PushReply, error) {
	if c == nil {
		return nil, errors.New("nil openvpn client")
	}
	if err := c.control.SendReset(ctx); err != nil {
		return nil, fmt.Errorf("send hard reset: %w", err)
	}
	if err := c.waitServerReset(ctx); err != nil {
		return nil, err
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	c.controlConn = NewControlConn(c.control)
	c.tlsConn = tls.Client(c.controlConn, tlsConfig)
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.tlsConn.SetDeadline(deadline)
	}
	if err := c.tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("openvpn tls handshake: %w", err)
	}

	c.optionsString = InstallScriptOptionsString(c.config.Proto, c.config.Cipher, c.config.Auth, c.config.CompLZO)
	clientRecord, err := NewClientKeyMethod2Record(
		c.optionsString,
		InstallScriptPeerInfo(c.config.Cipher, c.config.CompLZO, c.config.PeerInfo),
		strings.TrimSpace(c.config.Username),
		c.config.Password,
	)
	if err != nil {
		return nil, err
	}
	clientBytes, err := clientRecord.MarshalClient()
	if err != nil {
		return nil, err
	}
	if _, err := c.tlsConn.Write(clientBytes); err != nil {
		return nil, fmt.Errorf("write key method 2 client record: %w", err)
	}
	serverRecord, err := c.readServerKeyMethod(ctx)
	if err != nil {
		return nil, err
	}

	sources := clientRecord.Sources
	sources.Server = serverRecord.Sources.Server
	keys, err := DeriveClientKeyMaterial(sources, c.control.LocalSessionID(), c.control.RemoteSessionID(), c.config.DataCipherKeyLength())
	if err != nil {
		return nil, fmt.Errorf("derive data channel keys: %w", err)
	}

	if _, err := c.tlsConn.Write([]byte(PushRequest + "\x00")); err != nil {
		return nil, fmt.Errorf("write push request: %w", err)
	}
	push, err := c.readPushReply(ctx)
	if err != nil {
		return nil, err
	}
	c.push = push
	c.data, err = NewDataChannel(keys, c.config.Cipher, c.config.Auth, push.PeerID)
	if err != nil {
		return nil, err
	}
	// The server answered PUSH_REPLY, so it received everything we sent.
	// Drop any packet still awaiting an ACK before the keeper takes over.
	c.control.ClearPending()
	c.startControlKeeper()
	c.markSend()
	c.markReceive()
	return push, nil
}

// ErrRenegotiationRequested is recorded when the server starts a key
// renegotiation (P_CONTROL_SOFT_RESET_V1). Renegotiation is not implemented
// yet, so the session is torn down cleanly and re-established on the next
// dial instead of lingering until the server's hand-window kills it.
var ErrRenegotiationRequested = errors.New("openvpn server requested key renegotiation")

// startControlKeeper keeps consuming the control channel after the
// handshake. Without it the packet mux control queue fills up and stalls
// the data channel, and server messages (AUTH_FAILED on token expiry,
// RESTART, HALT, soft resets) go unnoticed.
func (c *Client) startControlKeeper() {
	c.controlConn.SetNotify(func(packet *ControlPacket) error {
		if packet.Opcode == PControlSoftResetV1 {
			return ErrRenegotiationRequested
		}
		return nil
	})
	go func() {
		for c.runCtx.Err() == nil {
			msg, err := c.readControlMessage(c.runCtx)
			if err != nil {
				if c.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					c.failSession(err)
				}
				return
			}
			switch {
			case strings.HasPrefix(msg, "AUTH_FAILED"):
				c.failSession(newAuthFailedError(msg))
				return
			case strings.HasPrefix(msg, "HALT"):
				c.failSession(fmt.Errorf("openvpn server sent halt: %q", msg))
				return
			case strings.HasPrefix(msg, "RESTART"):
				c.failSession(fmt.Errorf("openvpn server requested restart: %q", msg))
				return
			default:
				// INFO, PUSH_REPLY updates and unknown messages are
				// acknowledged by the transport and ignored for now.
			}
		}
	}()
}

func (c *Client) failSession(err error) {
	c.sessionErr.CompareAndSwap(nil, &err)
	_ = c.Close()
}

// SessionErr reports why the session was terminated, if the reason is known.
func (c *Client) SessionErr() error {
	if p := c.sessionErr.Load(); p != nil {
		return *p
	}
	return nil
}

func (c *Client) WriteIPPacket(ctx context.Context, packet []byte) error {
	return c.writeDataPacket(ctx, packet)
}

// WritePing sends the keepalive magic. Like every other data channel
// payload (the reference implementation included), it must go through the
// compression framing, otherwise servers running comp-lzo drop our pings.
func (c *Client) WritePing(ctx context.Context) error {
	return c.writeDataPacket(ctx, openVPNPingPacket)
}

func (c *Client) writeDataPacket(ctx context.Context, packet []byte) error {
	if c.data == nil {
		return errors.New("openvpn data channel is not ready")
	}
	if err := c.writeSem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer c.writeSem.Release(1)
	if c.config.CompLZO == CompLzoYes {
		compressed, err := lzo1xCompressSafe(packet)
		if err != nil {
			return err
		}
		packet = compressed
	}
	encrypted, err := c.data.Encrypt(packet)
	if err != nil {
		return err
	}
	err = c.mux.WritePacket(ctx, encrypted)
	if err != nil {
		return err
	}
	c.markSend()
	return nil
}

// ErrRemoteExit is returned by ReadIPPacket when the server announces it is
// going away (OCC_EXIT / explicit-exit-notify).
var ErrRemoteExit = errors.New("openvpn peer sent exit notify")

func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	if c.data == nil {
		return nil, errors.New("openvpn data channel is not ready")
	}
	for {
		packet, err := c.mux.ReadDataPacket(ctx)
		if err != nil {
			return nil, err
		}
		plain, err := c.data.Decrypt(packet)
		if err != nil {
			continue
		}
		c.markReceive()
		// Compression framing wraps every data channel payload, so it must
		// be stripped before recognizing ping and OCC messages.
		if c.config.CompLZO == CompLzoYes && len(plain) > 0 {
			plain, err = lzo1xDecompressSafe(plain)
			if err != nil {
				continue
			}
		}
		if IsPingPacket(plain) {
			continue
		}
		if isOCCPacket(plain) {
			if err := c.handleOCC(ctx, plain); err != nil {
				return nil, err
			}
			continue
		}
		if len(plain) == 0 {
			continue
		}
		return plain, nil
	}
}

func (c *Client) handleOCC(ctx context.Context, packet []byte) error {
	switch occOpcode(packet) {
	case OCCExit:
		return ErrRemoteExit
	case OCCRequest:
		writeCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = c.writeDataPacket(writeCtx, buildOCCReply(c.optionsString))
	}
	return nil
}

// SendExitNotify implements --explicit-exit-notify: tell the server we are
// going away so it can drop the session immediately instead of keeping it
// alive until its keepalive timeout. Only meaningful over UDP.
func (c *Client) SendExitNotify(ctx context.Context) error {
	if c.data == nil || c.config.Proto != ProtoUDP {
		return nil
	}
	packet := buildOCCPacket(OCCExit, nil)
	var lastErr error
	for i := 0; i < 2; i++ {
		if err := c.writeDataPacket(ctx, packet); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (c *Client) SinceSend() time.Duration {
	return time.Duration(int64(time.Since(start)) - c.lastSendNano.Load())
}

func (c *Client) SinceReceive() time.Duration {
	return time.Duration(int64(time.Since(start)) - c.lastReceiveNano.Load())
}

func (c *Client) markSend() {
	c.lastSendNano.Store(int64(time.Since(start)))
}

func (c *Client) markReceive() {
	c.lastReceiveNano.Store(int64(time.Since(start)))
}

// The absolute value doesn't matter, but it should be in the past,
// so that every timestamp obtained with Now() is non-zero,
// even on systems with low timer resolutions (e.g. Windows).
var start = time.Now().Add(-time.Hour)

func (c *Client) Close() error {
	notifyCtx, notifyCancel := context.WithTimeout(context.Background(), time.Second)
	_ = c.SendExitNotify(notifyCtx)
	notifyCancel()
	if c.cancel != nil {
		c.cancel()
	}
	if c.tlsConn != nil {
		_ = c.tlsConn.Close()
	}
	if c.mux != nil {
		return c.mux.Close()
	}
	return nil
}

func (c *Client) waitServerReset(ctx context.Context) error {
	// Retransmission of our hard reset (and every later control packet) is
	// handled by the channel's RunRetransmitter goroutine.
	for {
		packet, err := c.control.Read(ctx)
		if err != nil {
			return fmt.Errorf("read hard reset response: %w", err)
		}
		switch packet.Opcode {
		case PControlHardResetServerV2:
			return c.control.SendAck(ctx)
		case PControlHardResetServerV1:
			return fmt.Errorf("openvpn server replied with unsupported key method 1 reset")
		}
	}
}

func (c *Client) readServerKeyMethod(ctx context.Context) (*KeyMethod2Record, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.tlsConn.SetReadDeadline(deadline)
		}
		n, err := c.tlsConn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read key method 2 server record: %w", err)
		}
		buf = append(buf, tmp[:n]...)
		// A server that rejects our credentials may answer with a control
		// message instead of its key method record.
		if bytes.HasPrefix(buf, []byte("AUTH_FAILED")) {
			return nil, newAuthFailedError(stringUpToNUL(buf))
		}
		record, consumed, err := parseServerKeyMethod2Record(buf)
		if err == nil {
			// Keep anything the server coalesced after its record (for
			// example an early PUSH_REPLY) for the message reader.
			c.tlsReadBuf = append(c.tlsReadBuf, buf[consumed:]...)
			return record, nil
		}
		if !strings.Contains(err.Error(), "truncated") && !errors.Is(err, ioStringEOF) {
			return nil, err
		}
	}
}

// takeControlMessage extracts the next complete NUL-terminated control
// channel message from the buffered TLS plaintext.
func (c *Client) takeControlMessage() (string, bool) {
	for {
		idx := bytes.IndexByte(c.tlsReadBuf, 0)
		if idx < 0 {
			return "", false
		}
		msg := string(c.tlsReadBuf[:idx])
		c.tlsReadBuf = c.tlsReadBuf[idx+1:]
		if msg != "" {
			return msg, true
		}
	}
}

func (c *Client) readControlMessage(ctx context.Context) (string, error) {
	tmp := make([]byte, 4096)
	for {
		if msg, ok := c.takeControlMessage(); ok {
			return msg, nil
		}
		// Always apply the context deadline; a zero time clears any stale
		// deadline left over from an earlier phase.
		deadline, _ := ctx.Deadline()
		_ = c.tlsConn.SetReadDeadline(deadline)
		n, err := c.tlsConn.Read(tmp)
		if n > 0 {
			c.tlsReadBuf = append(c.tlsReadBuf, tmp[:n]...)
			continue
		}
		if err != nil {
			return "", err
		}
	}
}

func (c *Client) readPushReply(ctx context.Context) (*PushReply, error) {
	// The server may legitimately delay PUSH_REPLY (deferred auth, load), so
	// repeat PUSH_REQUEST at the reference implementation's interval until a
	// reply or a fatal message arrives.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(PushRequestInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = c.tlsConn.Write([]byte(PushRequest + "\x00"))
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	var messages []string
	for {
		msg, err := c.readControlMessage(ctx)
		if err != nil {
			return nil, fmt.Errorf("read push reply: %w", err)
		}
		switch {
		case strings.HasPrefix(msg, "PUSH_REPLY"):
			messages = append(messages, msg)
			if pushReplyContinuation(msg) == pushContinuationPartial {
				continue
			}
			return ParsePushReplyMessages(messages)
		case strings.HasPrefix(msg, "AUTH_FAILED"):
			return nil, newAuthFailedError(msg)
		case strings.HasPrefix(msg, "HALT"):
			return nil, fmt.Errorf("openvpn server sent halt: %q", msg)
		case strings.HasPrefix(msg, "RESTART"):
			return nil, fmt.Errorf("openvpn server requested restart: %q", msg)
		default:
			// AUTH_PENDING, INFO and other messages: keep waiting within
			// the handshake deadline.
		}
	}
}

// AuthFailedError is returned when the server replies AUTH_FAILED,
// distinguishing bad credentials from network timeouts.
type AuthFailedError struct {
	Reason string
}

func (e *AuthFailedError) Error() string {
	if e.Reason == "" {
		return "openvpn authentication failed"
	}
	return "openvpn authentication failed: " + e.Reason
}

func newAuthFailedError(message string) error {
	reason := ""
	if idx := strings.IndexByte(message, ','); idx >= 0 {
		reason = strings.TrimSpace(message[idx+1:])
	}
	return &AuthFailedError{Reason: reason}
}

func stringUpToNUL(buf []byte) string {
	if idx := bytes.IndexByte(buf, 0); idx >= 0 {
		return string(buf[:idx])
	}
	return string(buf)
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.config.CA) {
		return nil, errors.New("parse openvpn ca certificate")
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("openvpn server did not provide certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range cs.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		return err
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	}
	certPEM := bytes.TrimSpace(c.config.Cert)
	keyPEM := bytes.TrimSpace(c.config.Key)
	if len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(c.config.Cert, c.config.Key)
		if err != nil {
			return nil, fmt.Errorf("parse client certificate/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

var _ net.Conn = (*ControlConn)(nil)
