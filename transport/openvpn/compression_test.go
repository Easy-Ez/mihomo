package openvpn

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/rasky/go-lzo"
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

func TestCompressLZODecompressesServerData(t *testing.T) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 7)
	}
	compressed := append([]byte{compLZOByte}, lzo.Compress1X(payload)...)
	out, err := decompressFrame(compressLZO, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("lzo payload mismatch")
	}
}

func TestCompressV1SwapRoundTrip(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	framed := compressFrame(compressV1Stub, payload)
	if framed[0] != compNoByteSwap {
		t.Fatalf("expected swap indicator, got 0x%02x", framed[0])
	}
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
	if out, err := decompressFrame(compressV1Stub, []byte{compNoByteSwap}); err != nil || len(out) != 0 {
		t.Fatalf("empty swap frame: %x err=%v", out, err)
	}
}

func TestCompressV1LZ4(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefgh"), 64)
	dst := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock(payload, dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	framed := append([]byte{compLZ4Byte}, dst[:n]...)
	out, err := decompressFrame(compressV1Stub, framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("lz4 payload mismatch")
	}
}

func TestCompressV2PassthroughAndEscape(t *testing.T) {
	plain := []byte{0x45, 0x01, 0x02}
	framed := compressFrame(compressV2Stub, plain)
	if !bytes.Equal(framed, plain) {
		t.Fatalf("v2 passthrough must not add bytes: %x", framed)
	}
	out, err := decompressFrame(compressV2Stub, framed)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("v2 passthrough roundtrip: %x err=%v", out, err)
	}

	escapeMe := []byte{compV2Indicator, 0x11, 0x22}
	framed = compressFrame(compressV2Stub, escapeMe)
	if len(framed) != len(escapeMe)+2 || framed[0] != compV2Indicator || framed[1] != compV2Uncompressed {
		t.Fatalf("v2 escape framing wrong: %x", framed)
	}
	out, err = decompressFrame(compressV2Stub, framed)
	if err != nil || !bytes.Equal(out, escapeMe) {
		t.Fatalf("v2 escape roundtrip: %x err=%v", out, err)
	}

	payload := bytes.Repeat([]byte("0123456789"), 40)
	dst := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock(payload, dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = decompressFrame(compressV2Stub, append([]byte{compV2Indicator, compV2LZ4}, dst[:n]...))
	if err != nil || !bytes.Equal(out, payload) {
		t.Fatalf("v2 lz4: err=%v", err)
	}
}

func TestDecompressRejectsBadFraming(t *testing.T) {
	if _, err := decompressFrame(compressLZO, []byte{0x12, 0x34}); err == nil {
		t.Fatal("expected error for unknown v1 header")
	}
	if _, err := decompressFrame(compressV2Stub, []byte{compV2Indicator}); err == nil {
		t.Fatal("expected error for truncated v2 header")
	}
	if _, err := decompressFrame(compressV2Stub, []byte{compV2Indicator, 0x7f, 1}); err == nil {
		t.Fatal("expected error for unknown v2 op")
	}
	garbage := make([]byte, 64)
	rand.Read(garbage)
	if _, err := decompressFrame(compressLZO, append([]byte{compLZOByte}, garbage...)); err == nil {
		t.Fatal("expected error for corrupt lzo data")
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
		{"adaptive", "", compressLZO, false},
		{"no", "", compressNone, false},
		{"", "stub", compressV1Stub, false},
		{"", "lzo", compressV1Stub, false},
		{"", "lz4", compressV1Stub, false},
		{"", "Stub-V2", compressV2Stub, false},
		{"", "lz4-v2", compressV2Stub, false},
		{"no", "stub-v2", compressV2Stub, false},
		{"yes", "stub", compressNone, true},
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
			t.Fatalf("comp-lzo=%q compress=%q: got %v err=%v want %v", tc.compLZO, tc.compress, got, err, tc.want)
		}
	}
}

func TestPushedCompressionMode(t *testing.T) {
	if _, ok := pushedCompressionMode(&PushReply{}); ok {
		t.Fatal("no pushed compression must not select a mode")
	}
	cases := []struct {
		push *PushReply
		want compressionMode
	}{
		{&PushReply{HasCompress: true}, compressV1Stub},
		{&PushReply{HasCompress: true, Compress: "stub"}, compressV1Stub},
		{&PushReply{HasCompress: true, Compress: "lz4"}, compressV1Stub},
		{&PushReply{HasCompress: true, Compress: "stub-v2"}, compressV2Stub},
		{&PushReply{HasCompress: true, Compress: "lz4-v2"}, compressV2Stub},
		{&PushReply{HasCompLZO: true, CompLZO: "no"}, compressLZO},
		{&PushReply{HasCompLZO: true, CompLZO: "yes"}, compressLZO},
	}
	for _, tc := range cases {
		got, ok := pushedCompressionMode(tc.push)
		if !ok || got != tc.want {
			t.Fatalf("push %+v: got %v ok=%v want %v", tc.push, got, ok, tc.want)
		}
	}
}

func TestPingFramingFollowsCompressionMode(t *testing.T) {
	for _, mode := range []compressionMode{compressNone, compressLZO, compressV1Stub, compressV2Stub} {
		client := &Client{config: &ClientConfig{}, compressMode: mode}
		framed, err := client.frameOutbound(openVPNPingPacket)
		if err != nil {
			t.Fatal(err)
		}
		if mode != compressNone && mode != compressV2Stub && IsPingPacket(framed) {
			t.Fatalf("%v: ping must carry framing, got % x", mode, framed)
		}
		plain, err := client.unframeInbound(framed)
		if err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		if !IsPingPacket(plain) {
			t.Fatalf("%v: unframed payload is not a ping: % x", mode, plain)
		}
	}
}
