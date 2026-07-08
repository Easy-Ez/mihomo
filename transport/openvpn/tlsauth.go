package openvpn

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// ControlWrapper protects the control channel. Both tls-crypt (encrypt +
// authenticate) and tls-auth (authenticate only) implement it; a nil
// wrapper means an unprotected plaintext control channel.
type ControlWrapper interface {
	// Wrap turns the header (opcode+session id) plus plaintext body into an
	// on-wire control packet, stamping the given reliability packet id and
	// unix time.
	Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error)
	// Unwrap validates an incoming control packet and returns its header,
	// stamped packet id / unix time and plaintext body.
	Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error)
}

// Key direction values for --tls-auth (the third argument of the tls-auth
// directive / the --key-direction option).
const (
	KeyDirectionBidirectional = -1 // no key-direction: both ends use key slot 0
	KeyDirectionServer        = 0
	KeyDirectionClient        = 1 // the usual client setting
)

// TLSAuth implements --tls-auth: the control channel stays in plaintext but
// every packet is prefixed with an HMAC (using the --auth digest) computed
// over the packet id, header and body. This is the second most common
// control-channel protection after tls-crypt and is required to talk to the
// many servers configured with "tls-auth ta.key".
type TLSAuth struct {
	sendKey []byte
	recvKey []byte
	newHash func() hash.Hash
	size    int
}

func NewTLSAuth(staticKey []byte, authName string, keyDirection int) (*TLSAuth, error) {
	if len(staticKey) != staticKeySize {
		return nil, fmt.Errorf("invalid tls-auth static key length %d, expected %d", len(staticKey), staticKeySize)
	}
	newHash, size, err := newDataChannelAuth(authName)
	if err != nil {
		return nil, fmt.Errorf("tls-auth digest: %w", err)
	}
	// The 256-byte static key holds two 128-byte key slots, each laid out as
	// cipher[64] || hmac[64]; tls-auth only uses the hmac halves.
	key0HMAC := staticKey[keySlotSize/2 : keySlotSize/2+size]
	key1HMAC := staticKey[keySlotSize+keySlotSize/2 : keySlotSize+keySlotSize/2+size]

	send, recv := key1HMAC, key0HMAC // KeyDirectionClient
	switch keyDirection {
	case KeyDirectionServer:
		send, recv = key0HMAC, key1HMAC
	case KeyDirectionBidirectional:
		send, recv = key0HMAC, key0HMAC
	}
	return &TLSAuth{
		sendKey: cloneBytes(send),
		recvKey: cloneBytes(recv),
		newHash: newHash,
		size:    size,
	}, nil
}

func (a *TLSAuth) tag(key, header, pid, plaintext []byte) []byte {
	// HMAC input order matches the reference implementation's internal
	// (post-swap) layout: packet-id, then the opcode+session-id header,
	// then the body.
	mac := hmac.New(a.newHash, key)
	_, _ = mac.Write(pid)
	_, _ = mac.Write(header)
	_, _ = mac.Write(plaintext)
	return mac.Sum(nil)
}

func (a *TLSAuth) Wrap(header []byte, packetID uint32, unixTime uint32, plaintext []byte) ([]byte, error) {
	if len(header) != TLSCryptHeaderSize {
		return nil, fmt.Errorf("invalid tls-auth header length %d, expected %d", len(header), TLSCryptHeaderSize)
	}
	var pid [TLSCryptPIDSize]byte
	binary.BigEndian.PutUint32(pid[:4], packetID)
	binary.BigEndian.PutUint32(pid[4:], unixTime)
	tag := a.tag(a.sendKey, header, pid[:], plaintext)

	// On-wire order: header, HMAC, packet-id+time, body.
	out := make([]byte, 0, len(header)+len(tag)+len(pid)+len(plaintext))
	out = append(out, header...)
	out = append(out, tag...)
	out = append(out, pid[:]...)
	out = append(out, plaintext...)
	return out, nil
}

func (a *TLSAuth) Unwrap(packet []byte) (header []byte, packetID uint32, unixTime uint32, plaintext []byte, err error) {
	if len(packet) < TLSCryptHeaderSize+a.size+TLSCryptPIDSize {
		return nil, 0, 0, nil, errors.New("tls-auth packet too short")
	}
	header = cloneBytes(packet[:TLSCryptHeaderSize])
	tagStart := TLSCryptHeaderSize
	pidStart := tagStart + a.size
	bodyStart := pidStart + TLSCryptPIDSize
	tag := packet[tagStart:pidStart]
	pid := packet[pidStart:bodyStart]
	plaintext = packet[bodyStart:]

	expected := a.tag(a.recvKey, header, pid, plaintext)
	if !hmac.Equal(tag, expected) {
		return nil, 0, 0, nil, errors.New("tls-auth authentication failed")
	}
	packetID = binary.BigEndian.Uint32(pid[:4])
	unixTime = binary.BigEndian.Uint32(pid[4:])
	return header, packetID, unixTime, plaintext, nil
}
