package openvpn

import (
	"bytes"
	"testing"
)

func TestCompressLZOFrameRoundTrip(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x11, 0x22, 0x33}
	framed := compressFrame(compressLZO, payload)
	if framed[0] != compNoByte {
		t.Fatalf("expected NO_COMPRESS_BYTE prefix, got 0x%02x", framed[0])
	}
	out, err := decompressFrame(compressLZO, framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("roundtrip mismatch: %x", out)
	}
}

func TestCompressV1SwapRoundTrip(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	framed := compressFrame(compressV1Stub, payload)
	if framed[0] != compNoByteSwap {
		t.Fatalf("expected swap indicator, got 0x%02x", framed[0])
	}
	// The original first byte must be moved to the tail (alignment trick).
	if framed[len(framed)-1] != 0xAA {
		t.Fatalf("swap did not move first byte to tail: %x", framed)
	}
	out, err := decompressFrame(compressV1Stub, framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("swap roundtrip mismatch: %x", out)
	}
}

func TestCompressV2PassthroughAndEscape(t *testing.T) {
	// A payload not starting with the indicator gets no framing overhead.
	plain := []byte{0x45, 0x01, 0x02}
	framed := compressFrame(compressV2Stub, plain)
	if !bytes.Equal(framed, plain) {
		t.Fatalf("v2 passthrough must not add bytes: %x", framed)
	}
	out, err := decompressFrame(compressV2Stub, framed)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("v2 passthrough roundtrip: %x err=%v", out, err)
	}

	// A payload that starts with 0x50 must be escaped as [0x50,0x00,...].
	escapeMe := []byte{compV2Indicator, 0x11, 0x22}
	framed = compressFrame(compressV2Stub, escapeMe)
	if len(framed) != len(escapeMe)+2 || framed[0] != compV2Indicator || framed[1] != compV2Uncompressed {
		t.Fatalf("v2 escape framing wrong: %x", framed)
	}
	out, err = decompressFrame(compressV2Stub, framed)
	if err != nil || !bytes.Equal(out, escapeMe) {
		t.Fatalf("v2 escape roundtrip: %x err=%v", out, err)
	}
}

func TestDecompressV1RejectsUnknownHeader(t *testing.T) {
	if _, err := decompressFrame(compressLZO, []byte{0x12, 0x34}); err == nil {
		t.Fatal("expected error for unknown v1 header")
	}
}

func TestResolveCompressionMode(t *testing.T) {
	cases := []struct {
		compLZO  string
		compress string
		want     compressionMode
		wantErr  bool
	}{
		{"", "", compressNone, false},
		{"yes", "", compressLZO, false},
		{"no", "", compressLZO, false}, // comp-lzo no still needs framing
		{"", "stub", compressV1Stub, false},
		{"", "stub-v2", compressV2Stub, false},
		{"", "lz4-v2", compressV2Stub, false},
		{"yes", "stub", compressNone, true}, // mutually exclusive
		{"", "bogus", compressNone, true},
	}
	for _, tc := range cases {
		got, err := resolveCompressionMode(tc.compLZO, tc.compress)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("comp-lzo=%q compress=%q: expected error", tc.compLZO, tc.compress)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("comp-lzo=%q compress=%q: got %d err=%v want %d", tc.compLZO, tc.compress, got, err, tc.want)
		}
	}
}
