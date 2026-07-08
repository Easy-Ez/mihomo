package openvpn

import (
	"bytes"
	"testing"
)

func TestOCCPacketDetection(t *testing.T) {
	exit := buildOCCPacket(OCCExit, nil)
	if !isOCCPacket(exit) {
		t.Fatal("exit packet not recognized as OCC")
	}
	if occOpcode(exit) != OCCExit {
		t.Fatalf("unexpected OCC opcode: %d", occOpcode(exit))
	}
	if isOCCPacket(openVPNPingPacket) {
		t.Fatal("ping packet misdetected as OCC")
	}
	if isOCCPacket(occMagic) {
		t.Fatal("bare magic without opcode must not be OCC")
	}
	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	if isOCCPacket(ipPacket) {
		t.Fatal("ip packet misdetected as OCC")
	}
}

func TestOCCReplyCarriesNULTerminatedOptions(t *testing.T) {
	options := "V4,dev-type tun"
	reply := buildOCCReply(options)
	if !isOCCPacket(reply) || occOpcode(reply) != OCCReply {
		t.Fatalf("unexpected OCC reply framing: %x", reply)
	}
	payload := reply[len(occMagic)+1:]
	if !bytes.Equal(payload, append([]byte(options), 0)) {
		t.Fatalf("unexpected OCC reply payload: %x", payload)
	}
}
