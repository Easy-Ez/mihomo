package openvpn

import (
	"bytes"
	"crypto/aes"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func TestDataChannelAESGCMV2RoundTrip(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	encrypted, err := client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	if opcode, _ := parseOpcodeKeyID(encrypted[0]); opcode != PDataV2 {
		t.Fatalf("unexpected data opcode: %s", opcode)
	}
	if packetID := binary.BigEndian.Uint32(encrypted[4:8]); packetID != 1 {
		t.Fatalf("unexpected first data packet id: %d", packetID)
	}
	plain, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, ipPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure")
	}
	encrypted, err = client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[7] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure after packet id tamper")
	}
}

func TestDataChannelAcceptsOutOfOrderPacketsWithinReplayWindow(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	packets := [][]byte{
		{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1},
		{0x45, 0, 0, 20, 1, 2, 3, 5, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1},
		{0x45, 0, 0, 20, 1, 2, 3, 6, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1},
	}
	encrypted := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		out, err := client.Encrypt(packet)
		if err != nil {
			t.Fatal(err)
		}
		encrypted = append(encrypted, out)
	}

	for _, index := range []int{0, 2, 1} {
		plain, err := server.Decrypt(encrypted[index])
		if err != nil {
			t.Fatalf("decrypt packet %d: %v", index+1, err)
		}
		if !bytes.Equal(plain, packets[index]) {
			t.Fatalf("unexpected packet %d plaintext: %x", index+1, plain)
		}
	}
	if _, err := server.Decrypt(encrypted[1]); err == nil {
		t.Fatal("expected duplicate packet to be rejected")
	}
}

func TestDataChannelPacketIDExhaustion(t *testing.T) {
	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	channel, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	channel.sendPacketID = ^uint32(0) - 1
	if _, err := channel.Encrypt([]byte{0x45}); err != nil {
		t.Fatalf("second-to-last packet id must still work: %v", err)
	}
	// The final packet id would wrap the counter and reuse an AEAD nonce.
	if _, err := channel.Encrypt([]byte{0x45}); err == nil {
		t.Fatal("expected packet id exhaustion error")
	}
}

func TestClientRoutesDataPacketsByKeyID(t *testing.T) {
	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	oldChannel, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	newChannel, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{}
	client.data.Store(newChannel)
	client.dataOld.Store(oldChannel)

	if got := client.dataForPacket([]byte{opcodeKeyID(PDataV2, 1), 0, 0, 7}); got != newChannel {
		t.Fatal("key id 1 must route to the active channel")
	}
	if got := client.dataForPacket([]byte{opcodeKeyID(PDataV2, 0), 0, 0, 7}); got != oldChannel {
		t.Fatal("key id 0 must route to the lame duck channel")
	}
	if got := client.dataForPacket([]byte{opcodeKeyID(PDataV2, 5), 0, 0, 7}); got != nil {
		t.Fatal("unknown key id must not match any channel")
	}

	// The header of an encrypted packet carries the channel's key id, so
	// the peer can route it the same way.
	encrypted, err := newChannel.Encrypt([]byte{0x45})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(encrypted[0]); keyID != 1 {
		t.Fatalf("unexpected key id in header: %d", keyID)
	}
	if newChannel.KeyID() != 1 || oldChannel.KeyID() != 0 {
		t.Fatalf("unexpected channel key ids: %d/%d", newChannel.KeyID(), oldChannel.KeyID())
	}
}

func TestParsePushReply(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,block-ipv6\x00")
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Prefixes) != 1 || reply.Prefixes[0].String() != "10.8.0.2/24" {
		t.Fatalf("unexpected prefixes: %#v", reply.Prefixes)
	}
	if reply.PeerID != 3 || !reply.Redirect || !reply.BlockIPv6 {
		t.Fatalf("unexpected push flags: %#v", reply)
	}
	if len(reply.DNS) != 1 || reply.DNS[0].String() != "8.8.8.8" {
		t.Fatalf("unexpected DNS: %#v", reply.DNS)
	}
}

func TestParsePushReplyPointToPointIfconfig(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.211.254.254,ifconfig 10.211.1.37 10.211.254.254,peer-id 16777215\x00")
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Prefixes) != 1 || reply.Prefixes[0].String() != "10.211.1.37/32" {
		t.Fatalf("unexpected prefixes: %#v", reply.Prefixes)
	}
	if len(reply.DNS) != 1 || reply.DNS[0].String() != "10.211.254.254" {
		t.Fatalf("unexpected DNS: %#v", reply.DNS)
	}
}

func TestDataChannelChaCha20Poly1305V2RoundTrip(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 32),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 32),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherChaCha20Poly1305, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherChaCha20Poly1305, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	encrypted, err := client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, ipPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestDataChannelAESCBCSHA1V2RoundTrip(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherAES128CBC, AuthSHA1, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherAES128CBC, AuthSHA1, 7, 0)
	if err != nil {
		t.Fatal(err)
	}

	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	encrypted, err := client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	if opcode, _ := parseOpcodeKeyID(encrypted[0]); opcode != PDataV2 {
		t.Fatalf("unexpected data opcode: %s", opcode)
	}
	headerSize := 4
	if len(encrypted) < headerSize+sha1.Size+DataChannelCBCIVSize+aes.BlockSize {
		t.Fatalf("encrypted CBC packet too short: %d", len(encrypted))
	}
	if len(encrypted[headerSize+sha1.Size+DataChannelCBCIVSize:])%aes.BlockSize != 0 {
		t.Fatal("encrypted CBC payload is not block aligned")
	}

	plain, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, ipPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected HMAC authentication failure")
	}

	encrypted, err = client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[headerSize+sha1.Size] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected HMAC authentication failure after IV tamper")
	}
}
