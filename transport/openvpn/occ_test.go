package openvpn

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestOCCPacketFraming(t *testing.T) {
	reply := buildOCCReply("V4,dev-type tun")
	if !isOCCPacket(reply) {
		t.Fatal("reply must be recognized as an OCC packet")
	}
	if occOpcode(reply) != occReply {
		t.Fatalf("opcode = %d, want %d", occOpcode(reply), occReply)
	}
	payload := reply[len(occMagic)+1:]
	if !bytes.Equal(payload, []byte("V4,dev-type tun\x00")) {
		t.Fatalf("payload = %q, want NUL-terminated options", payload)
	}

	exit := buildOCCPacket(occExit, nil)
	if len(exit) != len(occMagic)+1 || occOpcode(exit) != occExit {
		t.Fatalf("exit packet = % x", exit)
	}

	if isOCCPacket(occMagic) {
		t.Fatal("magic without opcode is not a complete OCC packet")
	}
	if isOCCPacket(openVPNPingPacket) {
		t.Fatal("ping must not be mistaken for OCC")
	}
	ipPacket := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	if isOCCPacket(ipPacket) {
		t.Fatal("IP packet must not be mistaken for OCC")
	}
}

func TestHandleOCCExitSurfacesRemoteExit(t *testing.T) {
	client := &Client{config: &ClientConfig{Proto: ProtoUDP}}
	err := client.handleOCC(context.Background(), buildOCCPacket(occExit, nil))
	if !errors.Is(err, ErrRemoteExit) {
		t.Fatalf("OCC_EXIT error = %v, want ErrRemoteExit", err)
	}
	for _, opcode := range []byte{occReply, occMTULoadRequest, occMTULoad, occMTURequest, occMTUReply, 42} {
		if err := client.handleOCC(context.Background(), buildOCCPacket(opcode, []byte{1, 2, 3})); err != nil {
			t.Fatalf("opcode %d must be ignored, got %v", opcode, err)
		}
	}
}

func TestSendExitNotifySkipsWhenNotReady(t *testing.T) {
	udp := &Client{config: &ClientConfig{Proto: ProtoUDP}}
	if err := udp.SendExitNotify(context.Background()); err != nil {
		t.Fatalf("no data channel: %v", err)
	}
	tcp := &Client{config: &ClientConfig{Proto: ProtoTCP}}
	if err := tcp.SendExitNotify(context.Background()); err != nil {
		t.Fatalf("tcp: %v", err)
	}
}
