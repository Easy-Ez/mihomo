package openvpn

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/pierrec/lz4/v4"
	"github.com/rasky/go-lzo"
)

// Compression framing bytes, matching comp.h in upstream OpenVPN.
const (
	compNoByte     = 0xFA // NO_COMPRESS_BYTE: v1 uncompressed (prepended)
	compNoByteSwap = 0xFB // NO_COMPRESS_BYTE_SWAP: v1 uncompressed (swap form)
	compLZOByte    = 0x66 // LZO_COMPRESS_BYTE
	compLZ4Byte    = 0x69 // LZ4_COMPRESS_BYTE

	compV2Indicator    = 0x50 // COMP_ALGV2_INDICATOR_BYTE
	compV2Uncompressed = 0x00 // COMP_ALGV2_UNCOMPRESSED_BYTE
	compV2LZ4          = 0x01 // COMP_ALGV2_LZ4_BYTE

	lz4DecompressBudget = 128 * 1024
)

// compressionMode selects the data-channel compression framing. This client
// never compresses outgoing traffic (compression is a security risk), but it
// must emit whatever framing byte the negotiated mode requires or the server
// drops the packet, and it must strip/decompress the server's framing.
type compressionMode int

const (
	compressNone   compressionMode = iota
	compressLZO                    // comp-lzo [yes|no|adaptive]: v1, no swap
	compressV1Stub                 // compress / stub / lzo / lz4: v1 with swap
	compressV2Stub                 // compress stub-v2 / lz4-v2: v2 escape framing
)

var errCompress = errors.New("openvpn compression framing error")

// compressFrame adds the outgoing (uncompressed) framing for the mode.
func compressFrame(mode compressionMode, payload []byte) []byte {
	switch mode {
	case compressLZO:
		// v1, no swap: prepend NO_COMPRESS_BYTE.
		out := make([]byte, 1+len(payload))
		out[0] = compNoByte
		copy(out[1:], payload)
		return out
	case compressV1Stub:
		// v1 swap: move the first payload byte to the tail, put the swap
		// indicator at the front. Preserves payload alignment.
		if len(payload) == 0 {
			return []byte{compNoByteSwap}
		}
		out := make([]byte, 1+len(payload))
		out[0] = compNoByteSwap
		copy(out[1:], payload[1:])
		out[len(out)-1] = payload[0]
		return out
	case compressV2Stub:
		// v2: zero overhead unless the payload starts with the indicator,
		// in which case escape it as [0x50, uncompressed-op].
		if len(payload) > 0 && payload[0] == compV2Indicator {
			out := make([]byte, 2+len(payload))
			out[0] = compV2Indicator
			out[1] = compV2Uncompressed
			copy(out[2:], payload)
			return out
		}
		return payload
	default:
		return payload
	}
}

// decompressFrame strips the framing and decompresses an incoming packet.
func decompressFrame(mode compressionMode, packet []byte) ([]byte, error) {
	switch mode {
	case compressNone:
		return packet, nil
	case compressV2Stub:
		return decompressV2(packet)
	default:
		// Both comp-lzo and v1 compress decode the same way: dispatch on the
		// first byte, so a client does not need to know which v1 variant the
		// server negotiated.
		return decompressV1(packet)
	}
}

func decompressV1(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, nil
	}
	switch packet[0] {
	case compNoByte:
		return packet[1:], nil
	case compNoByteSwap:
		// Reverse the swap: the original first byte sits at the tail.
		out := make([]byte, len(packet)-1)
		out[0] = packet[len(packet)-1]
		copy(out[1:], packet[1:len(packet)-1])
		return out, nil
	case compLZOByte:
		return lzoDecompress(packet[1:])
	case compLZ4Byte:
		return lz4Decompress(packet[1:])
	default:
		return nil, fmt.Errorf("%w: unknown v1 header 0x%02x", errCompress, packet[0])
	}
}

func decompressV2(packet []byte) ([]byte, error) {
	if len(packet) == 0 || packet[0] != compV2Indicator {
		// No v2 header present: passthrough.
		return packet, nil
	}
	if len(packet) < 2 {
		return nil, fmt.Errorf("%w: truncated v2 header", errCompress)
	}
	switch packet[1] {
	case compV2Uncompressed:
		return packet[2:], nil
	case compV2LZ4:
		return lz4Decompress(packet[2:])
	default:
		return nil, fmt.Errorf("%w: unknown v2 op 0x%02x", errCompress, packet[1])
	}
}

func lzoDecompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	out, err := lzo.Decompress1X(bytes.NewReader(src), len(src), 0)
	if err != nil {
		return nil, fmt.Errorf("%w: lzo: %v", errCompress, err)
	}
	return out, nil
}

func lz4Decompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	dst := make([]byte, lz4DecompressBudget)
	n, err := lz4.UncompressBlock(src, dst)
	if err != nil {
		return nil, fmt.Errorf("%w: lz4: %v", errCompress, err)
	}
	return dst[:n], nil
}
