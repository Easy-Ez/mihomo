package openvpn

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestLzo1xSafe(t *testing.T) {
	data := make([]byte, 1024)
	rand.Read(data)
	compressed, err := lzo1xCompressSafe(data)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := lzo1xDecompressSafe(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decompressed) {
		t.Fatal("decompressed data is not equal to original")
	}
}

func TestPingFramingWithCompLZO(t *testing.T) {
	client := &Client{config: &ClientConfig{CompLZO: CompLzoYes}}
	framed, err := client.frameOutbound(openVPNPingPacket)
	if err != nil {
		t.Fatal(err)
	}
	if len(framed) != 1+len(openVPNPingPacket) || framed[0] != lzoCompressNone {
		t.Fatalf("ping must carry the comp-lzo framing byte, got % x", framed)
	}
	if IsPingPacket(framed) {
		t.Fatal("framed ping must not be detected before unframing")
	}
	plain, err := client.unframeInbound(framed)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPingPacket(plain) {
		t.Fatalf("unframed payload is not a ping: % x", plain)
	}

	none := &Client{config: &ClientConfig{}}
	framed, err = none.frameOutbound(openVPNPingPacket)
	if err != nil {
		t.Fatal(err)
	}
	if !IsPingPacket(framed) {
		t.Fatalf("without comp-lzo the ping must be sent as-is, got % x", framed)
	}
}
