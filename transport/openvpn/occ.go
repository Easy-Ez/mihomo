package openvpn

import "bytes"

// OCC (options consistency check) messages travel over the data channel as
// regular encrypted payloads: a 16-byte magic prefix, a one-byte opcode and
// an optional payload. Constants match occ.h/occ.c in upstream OpenVPN.
var occMagic = []byte{
	0x28, 0x7f, 0x34, 0x6b,
	0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3,
	0xaf, 0xc5, 0x45, 0x9c,
}

const (
	OCCRequest        = 0 // request options string from peer
	OCCReply          = 1 // deliver options string to peer
	OCCMTULoadRequest = 2 // ask peer to send a big packet to us
	OCCMTULoad        = 3 // send a big packet to peer
	OCCMTURequest     = 4 // ask peer to tell us its max received packet size
	OCCMTUReply       = 5 // send max received packet size to peer
	OCCExit           = 6 // tell peer we are about to disconnect
)

func isOCCPacket(packet []byte) bool {
	return len(packet) > len(occMagic) && bytes.Equal(packet[:len(occMagic)], occMagic)
}

func occOpcode(packet []byte) byte {
	return packet[len(occMagic)]
}

func buildOCCPacket(opcode byte, payload []byte) []byte {
	out := make([]byte, 0, len(occMagic)+1+len(payload))
	out = append(out, occMagic...)
	out = append(out, opcode)
	out = append(out, payload...)
	return out
}

// buildOCCReply carries our options string, NUL-terminated like the
// reference implementation (occ.c writes strlen+1 bytes).
func buildOCCReply(options string) []byte {
	payload := make([]byte, 0, len(options)+1)
	payload = append(payload, options...)
	payload = append(payload, 0)
	return buildOCCPacket(OCCReply, payload)
}
