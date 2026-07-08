package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
)

type PacketIO interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

const (
	// ControlRetransmitInterval mirrors --tls-timeout: an un-ACKed control
	// packet is retransmitted after 2 seconds, doubling per attempt.
	ControlRetransmitInterval    = 2 * time.Second
	ControlRetransmitMaxInterval = 16 * time.Second

	// maxControlPayload caps the TLS bytes carried by one P_CONTROL_V1.
	// The reference implementation limits whole control packets to
	// --max-packet-size (default 1250); after the worst-case tls-crypt,
	// session, ACK and message-id overhead (~80 bytes) a 1024-byte payload
	// keeps every control packet safely below common path MTUs, so large
	// TLS flights (client certificates!) no longer rely on IP
	// fragmentation, which many networks drop.
	maxControlPayload = 1024

	// controlSendAckMax mirrors CONTROL_SEND_ACK_MAX: at most this many
	// ACKs hitch a ride on an outgoing non-P_ACK_V1 control packet.
	controlSendAckMax = 4
	// reliableAckSize mirrors RELIABLE_ACK_SIZE: the largest ACK array a
	// standalone P_ACK_V1 may carry.
	reliableAckSize = 8
)

// pendingControl tracks an outgoing reliable packet awaiting an ACK,
// with its retransmission schedule.
type pendingControl struct {
	packet   *ControlPacket
	nextSend time.Time
	interval time.Duration
}

type ControlChannel struct {
	io      PacketIO
	wrapper ControlWrapper
	clock   func() time.Time
	keyID   uint8
	local   SessionID
	remote  SessionID

	// wkc is the tls-crypt-v2 wrapped client key, appended unencrypted to
	// the P_CONTROL_HARD_RESET_CLIENT_V3 packet; empty for other modes.
	wkc []byte

	mu            sync.Mutex
	sendPacketID  uint32
	sendMessage   uint32
	recvMessage   uint32
	ackPending    []uint32
	pending       map[uint32]*pendingControl
	recvPending   map[uint32]*ControlPacket
	readDeadline  time.Time
	writeDeadline time.Time
}

// SetTLSCryptV2WKc enables tls-crypt-v2 mode: the client hard reset becomes a
// P_CONTROL_HARD_RESET_CLIENT_V3 carrying the wrapped client key. Must be
// called before the handshake starts.
func (c *ControlChannel) SetTLSCryptV2WKc(wkc []byte) {
	c.wkc = wkc
}

func NewControlChannel(io PacketIO, wrapper ControlWrapper, local SessionID) *ControlChannel {
	return &ControlChannel{
		io:          io,
		wrapper:     wrapper,
		clock:       time.Now,
		local:       local,
		pending:     make(map[uint32]*pendingControl),
		recvPending: make(map[uint32]*ControlPacket),
	}
}

func (c *ControlChannel) LocalSessionID() SessionID {
	return c.local
}

func (c *ControlChannel) RemoteSessionID() SessionID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

func (c *ControlChannel) SetRemoteSessionID(id SessionID) {
	c.mu.Lock()
	c.remote = id
	c.mu.Unlock()
}

func (c *ControlChannel) CurrentKeyID() uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keyID
}

// StartKeySession switches the channel to a new key id after a soft reset:
// the reliable stream restarts from message id 0 on both sides while the
// session ids and the tls-crypt packet-id counter carry over, mirroring how
// the reference implementation opens a new key_state inside the running
// tls_session. The server's soft reset is message 0 of the new stream and
// is scheduled for acknowledgement here.
func (c *ControlChannel) StartKeySession(keyID uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyID = keyID
	c.sendMessage = 0
	c.recvMessage = 1
	c.ackPending = []uint32{0}
	c.pending = make(map[uint32]*pendingControl)
	c.recvPending = make(map[uint32]*ControlPacket)
}

func (c *ControlChannel) SendReset(ctx context.Context) error {
	opcode := PControlHardResetClientV2
	if len(c.wkc) > 0 {
		opcode = PControlHardResetClientV3
	}
	_, err := c.Send(ctx, opcode, nil)
	return err
}

func (c *ControlChannel) Send(ctx context.Context, opcode Opcode, payload []byte) (uint32, error) {
	if !opcode.HasMessageID() {
		return 0, fmt.Errorf("opcode %s cannot carry a reliable message", opcode)
	}

	c.mu.Lock()
	messageID := c.sendMessage
	c.sendMessage++
	packet := &ControlPacket{
		Opcode:           opcode,
		KeyID:            c.keyID,
		LocalSession:     c.local,
		AckIDs:           c.takeAcksLocked(controlSendAckMax),
		AckRemoteSession: c.remote,
		MessageID:        messageID,
		Payload:          cloneBytes(payload),
	}
	c.pending[messageID] = &pendingControl{
		packet:   packet,
		nextSend: c.clock().Add(ControlRetransmitInterval),
		interval: ControlRetransmitInterval,
	}
	c.mu.Unlock()

	if err := c.writeControlPacket(ctx, packet); err != nil {
		return 0, err
	}
	return messageID, nil
}

// takeAcksLocked removes and returns at most limit pending ACK ids;
// c.mu must be held.
func (c *ControlChannel) takeAcksLocked(limit int) []uint32 {
	if len(c.ackPending) == 0 {
		return nil
	}
	n := len(c.ackPending)
	if n > limit {
		n = limit
	}
	acks := append([]uint32(nil), c.ackPending[:n]...)
	if n == len(c.ackPending) {
		c.ackPending = nil
	} else {
		c.ackPending = append([]uint32(nil), c.ackPending[n:]...)
	}
	return acks
}

func (c *ControlChannel) SendAck(ctx context.Context) error {
	for {
		c.mu.Lock()
		acks := c.takeAcksLocked(reliableAckSize)
		if len(acks) == 0 {
			c.mu.Unlock()
			return nil
		}
		packet := &ControlPacket{
			Opcode:           PAckV1,
			KeyID:            c.keyID,
			LocalSession:     c.local,
			AckIDs:           acks,
			AckRemoteSession: c.remote,
		}
		c.mu.Unlock()
		if err := c.writeControlPacket(ctx, packet); err != nil {
			return err
		}
	}
}

func (c *ControlChannel) Read(ctx context.Context) (*ControlPacket, error) {
	for {
		c.mu.Lock()
		if packet, ok := c.recvPending[c.recvMessage]; ok {
			delete(c.recvPending, c.recvMessage)
			c.recvMessage++
			c.mu.Unlock()
			return packet, nil
		}
		c.mu.Unlock()

		packet, err := c.readControlPacket(ctx)
		if err != nil {
			return nil, err
		}

		var deliver *ControlPacket
		sendAck := false

		c.mu.Lock()
		if c.remote == (SessionID{}) && packet.LocalSession != c.local {
			c.remote = packet.LocalSession
		}
		if packet.Opcode == PControlSoftResetV1 && packet.KeyID != c.keyID {
			// A soft reset for a different key id opens a new key session:
			// its message id lives in a fresh reliable-layer space, so it
			// must not be merged into (or ACKed within) the current stream.
			// Surface it so the client can renegotiate. Retransmissions of
			// the reset that opened the *current* session fall through and
			// are re-ACKed as ordinary duplicates.
			c.mu.Unlock()
			return packet, nil
		}
		if packet.KeyID != c.keyID {
			// Stale traffic from a previous (lame duck) key session, e.g. a
			// late retransmission: it is not part of the current stream and
			// its ACKs reference foreign message ids.
			c.mu.Unlock()
			continue
		}
		for _, ackID := range packet.AckIDs {
			delete(c.pending, ackID)
		}
		if packet.Opcode.HasMessageID() {
			c.ackPending = appendAck(c.ackPending, packet.MessageID)
		}

		switch {
		case packet.Opcode == PAckV1:
		case !packet.Opcode.HasMessageID():
			deliver = packet
		case packet.MessageID < c.recvMessage:
			sendAck = true
		case packet.MessageID == c.recvMessage:
			deliver = packet
			c.recvMessage++
		default:
			if _, exists := c.recvPending[packet.MessageID]; !exists {
				c.recvPending[packet.MessageID] = packet
			}
			sendAck = true
		}

		c.mu.Unlock()

		if deliver != nil {
			return deliver, nil
		}
		if sendAck {
			if err := c.SendAck(ctx); err != nil {
				return nil, err
			}
		}
	}
}

func (c *ControlChannel) PendingMessages() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// ClearPending drops un-ACKed outgoing packets. Called when a handshake
// phase completes and the peer demonstrably received everything (it
// answered), so late ACK loss must not trigger pointless retransmissions.
func (c *ControlChannel) ClearPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = make(map[uint32]*pendingControl)
}

// RetransmitDue resends every reliable packet whose retransmission timer
// expired, doubling its backoff, and reports how long the caller may sleep
// before the next packet becomes due.
func (c *ControlChannel) RetransmitDue(ctx context.Context) (time.Duration, error) {
	now := c.clock()
	wait := ControlRetransmitInterval

	c.mu.Lock()
	var due []*ControlPacket
	for _, entry := range c.pending {
		if !entry.nextSend.After(now) {
			entry.interval *= 2
			if entry.interval > ControlRetransmitMaxInterval {
				entry.interval = ControlRetransmitMaxInterval
			}
			entry.nextSend = now.Add(entry.interval)
			// Retransmissions carry part of the current ACK backlog and
			// always get a fresh tls-crypt packet id (assigned in
			// writeControlPacket).
			cp := *entry.packet
			cp.AckIDs = c.takeAcksLocked(controlSendAckMax)
			cp.AckRemoteSession = c.remote
			due = append(due, &cp)
		}
		if until := entry.nextSend.Sub(now); until < wait {
			wait = until
		}
	}
	c.mu.Unlock()

	for _, packet := range due {
		if err := c.writeControlPacket(ctx, packet); err != nil {
			return wait, err
		}
	}
	return wait, nil
}

// RunRetransmitter drives the reliability layer until ctx is cancelled,
// mirroring the reference implementation's --tls-timeout handling. Without
// it a single lost UDP control packet stalls the whole handshake.
func (c *ControlChannel) RunRetransmitter(ctx context.Context) {
	timer := time.NewTimer(ControlRetransmitInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		wait, err := c.RetransmitDue(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient write failure: keep the packet pending and retry
			// on the next tick.
		}
		if wait < 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		timer.Reset(wait)
	}
}

func (c *ControlChannel) writeControlPacket(ctx context.Context, packet *ControlPacket) error {
	c.mu.Lock()
	c.sendPacketID++
	packetID := c.sendPacketID
	unixTime := uint32(c.clock().Unix())
	deadline := c.writeDeadline
	c.mu.Unlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	encoded, err := packet.Encode(c.wrapper, packetID, unixTime)
	if err != nil {
		return err
	}
	// tls-crypt-v2: the wrapped client key rides unencrypted after the
	// tls-crypt payload of the hard reset (and each of its retransmissions)
	// so the server can recover Kc.
	if packet.Opcode == PControlHardResetClientV3 && len(c.wkc) > 0 {
		encoded = append(append([]byte(nil), encoded...), c.wkc...)
	}
	return c.io.WritePacket(ctx, encoded)
}

func (c *ControlChannel) readControlPacket(ctx context.Context) (*ControlPacket, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	raw, err := c.io.ReadPacket(ctx)
	if err != nil {
		return nil, err
	}
	packet, _, _, err := DecodeControlPacket(c.wrapper, raw)
	return packet, err
}

func (c *ControlChannel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func appendAck(acks []uint32, ack uint32) []uint32 {
	for _, existing := range acks {
		if existing == ack {
			return acks
		}
	}
	return append(acks, ack)
}

type ControlConn struct {
	channel *ControlChannel
	readBuf []byte
	closed  bool
	mu      sync.Mutex

	// notify, when set, observes non-P_CONTROL_V1 packets (e.g. soft
	// resets) seen while reading the TLS stream. A returned error aborts
	// the read, surfacing session-level events through the TLS layer.
	notify func(*ControlPacket) error
}

func NewControlConn(channel *ControlChannel) *ControlConn {
	return &ControlConn{channel: channel}
}

// SetNotify installs the observer for non-TLS control packets. It must be
// set before the next Read; there is no synchronization with a concurrent
// reader.
func (c *ControlConn) SetNotify(notify func(*ControlPacket) error) {
	c.notify = notify
}

func (c *ControlConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	for {
		packet, err := c.channel.Read(context.Background())
		if err != nil {
			return 0, err
		}
		if packet.Opcode != PControlV1 {
			if c.notify != nil {
				if err := c.notify(packet); err != nil {
					return 0, err
				}
			}
			if err := c.channel.SendAck(context.Background()); err != nil {
				return 0, err
			}
			continue
		}
		if err := c.channel.SendAck(context.Background()); err != nil {
			return 0, err
		}
		if len(packet.Payload) == 0 {
			continue
		}
		n := copy(b, packet.Payload)
		if n < len(packet.Payload) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf, packet.Payload[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *ControlConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	// Fragment the TLS byte stream: one oversized control packet would be
	// sent as a fragmented IP datagram over UDP, which many paths drop.
	// The peer's reliability layer reassembles the stream from the
	// per-message ids, so chunk boundaries are invisible to TLS.
	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxControlPayload {
			chunk = b[:maxControlPayload]
		}
		if _, err := c.channel.Send(context.Background(), PControlV1, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		b = b[len(chunk):]
	}
	return total, nil
}

func (c *ControlConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.channel.io.Close()
}

func (c *ControlConn) LocalAddr() net.Addr {
	return c.channel.io.LocalAddr()
}

func (c *ControlConn) RemoteAddr() net.Addr {
	return c.channel.io.RemoteAddr()
}

func (c *ControlConn) SetDeadline(t time.Time) error {
	return c.channel.SetDeadline(t)
}

func (c *ControlConn) SetReadDeadline(t time.Time) error {
	return c.channel.SetReadDeadline(t)
}

func (c *ControlConn) SetWriteDeadline(t time.Time) error {
	return c.channel.SetWriteDeadline(t)
}

type streamPacketIO struct {
	conn          net.Conn
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

type datagramPacketIO struct {
	conn          net.Conn
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewDatagramPacketIO(conn net.Conn) PacketIO {
	return &datagramPacketIO{conn: conn}
}

func (d *datagramPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	if err := setReadDeadlineFromContext(d.conn, ctx, &d.deadlineMu, &d.readDeadline); err != nil {
		return nil, err
	}
	buf := make([]byte, 64*1024)
	n, err := d.conn.Read(buf)
	if err != nil {
		return nil, contextIOError(ctx, err)
	}
	return buf[:n], nil
}

func (d *datagramPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	if err := setWriteDeadlineFromContext(d.conn, ctx, &d.deadlineMu, &d.writeDeadline); err != nil {
		return err
	}
	_, err := d.conn.Write(packet)
	return contextIOError(ctx, err)
}

func (d *datagramPacketIO) Close() error {
	return d.conn.Close()
}

func (d *datagramPacketIO) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *datagramPacketIO) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

func NewTCPPacketIO(conn net.Conn) PacketIO {
	return &streamPacketIO{conn: conn}
}

func (s *streamPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	if err := setReadDeadlineFromContext(s.conn, ctx, &s.deadlineMu, &s.readDeadline); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(s.conn, lenBuf[:]); err != nil {
		return nil, contextIOError(ctx, err)
	}
	size := int(lenBuf[0])<<8 | int(lenBuf[1])
	if size == 0 {
		return nil, errors.New("empty openvpn tcp packet")
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(s.conn, packet); err != nil {
		return nil, contextIOError(ctx, err)
	}
	return packet, nil
}

func (s *streamPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) > 0xffff {
		return fmt.Errorf("openvpn tcp packet too large: %d", len(packet))
	}
	if err := setWriteDeadlineFromContext(s.conn, ctx, &s.deadlineMu, &s.writeDeadline); err != nil {
		return err
	}
	frame := pool.Get(2 + len(packet))
	defer pool.Put(frame)
	frame[0] = byte(len(packet) >> 8)
	frame[1] = byte(len(packet))
	copy(frame[2:], packet)
	_, err := s.conn.Write(frame)
	return contextIOError(ctx, err)
}

func (s *streamPacketIO) Close() error {
	return s.conn.Close()
}

func (s *streamPacketIO) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *streamPacketIO) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func setReadDeadlineFromContext(conn net.Conn, ctx context.Context, mu *sync.Mutex, current *time.Time) error {
	deadline, hasDeadline := ctx.Deadline()
	mu.Lock()
	defer mu.Unlock()
	if current.Equal(deadline) {
		return nil
	}
	if hasDeadline {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
	} else if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	*current = deadline
	return nil
}

func setWriteDeadlineFromContext(conn net.Conn, ctx context.Context, mu *sync.Mutex, current *time.Time) error {
	deadline, hasDeadline := ctx.Deadline()
	mu.Lock()
	defer mu.Unlock()
	if current.Equal(deadline) {
		return nil
	}
	if hasDeadline {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
	} else if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	*current = deadline
	return nil
}

func contextIOError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
