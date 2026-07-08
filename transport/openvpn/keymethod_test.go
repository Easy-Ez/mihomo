package openvpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestKeyMethod2ClientMarshalAndDerive(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  installScriptOptionsString(ProtoUDP, CipherAES128GCM, AuthSHA256, compressNone),
		PeerInfo: installScriptPeerInfo(CipherAES128GCM, compressNone, nil),
	}
	for i := range record.Sources.Client.PreMaster {
		record.Sources.Client.PreMaster[i] = byte(i + 1)
	}
	for i := range record.Sources.Client.Random1 {
		record.Sources.Client.Random1[i] = byte(i + 2)
		record.Sources.Client.Random2[i] = byte(i + 3)
		record.Sources.Server.Random1[i] = byte(i + 4)
		record.Sources.Server.Random2[i] = byte(i + 5)
	}

	encoded, err := record.MarshalClient()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(encoded[:4]) != 0 || encoded[4] != KeyMethod2 {
		t.Fatalf("unexpected key method prefix: %x", encoded[:5])
	}
	if !bytes.Contains(encoded, []byte(record.Options)) {
		t.Fatalf("encoded record is missing options")
	}

	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	keys, err := DeriveClientKeyMaterial(record.Sources, clientID, serverID, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.SendCipherKey) != 16 || len(keys.RecvCipherKey) != 16 {
		t.Fatalf("unexpected cipher key lengths: %d/%d", len(keys.SendCipherKey), len(keys.RecvCipherKey))
	}
	if len(keys.SendHMACKey) != maxHMACKeyLength || len(keys.RecvHMACKey) != maxHMACKeyLength {
		t.Fatalf("unexpected hmac key lengths: %d/%d", len(keys.SendHMACKey), len(keys.RecvHMACKey))
	}
	if bytes.Equal(keys.SendCipherKey, keys.RecvCipherKey) {
		t.Fatalf("send and recv keys should differ")
	}
}

func TestKeyMethod2DeriveAES256(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  installScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA256, compressNone),
		PeerInfo: installScriptPeerInfo(CipherAES256GCM, compressNone, nil),
	}
	for i := range record.Sources.Client.PreMaster {
		record.Sources.Client.PreMaster[i] = byte(i + 1)
	}
	for i := range record.Sources.Client.Random1 {
		record.Sources.Client.Random1[i] = byte(i + 2)
		record.Sources.Client.Random2[i] = byte(i + 3)
		record.Sources.Server.Random1[i] = byte(i + 4)
		record.Sources.Server.Random2[i] = byte(i + 5)
	}
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	keys, err := DeriveClientKeyMaterial(record.Sources, clientID, serverID, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.SendCipherKey) != 32 || len(keys.RecvCipherKey) != 32 {
		t.Fatalf("unexpected cipher key lengths: %d/%d", len(keys.SendCipherKey), len(keys.RecvCipherKey))
	}
	if len(keys.SendHMACKey) != maxHMACKeyLength || len(keys.RecvHMACKey) != maxHMACKeyLength {
		t.Fatalf("unexpected hmac key lengths: %d/%d", len(keys.SendHMACKey), len(keys.RecvHMACKey))
	}
	if bytes.Equal(keys.SendCipherKey, keys.RecvCipherKey) {
		t.Fatalf("send and recv keys should differ")
	}
}

func TestInstallScriptOptionsCBCSHA1(t *testing.T) {
	options := installScriptOptionsString(ProtoTCP, CipherAES256CBC, AuthSHA1, compressNone)
	for _, want := range []string{"proto TCPv4_CLIENT", "cipher AES-256-CBC", "auth SHA1", "keysize 256"} {
		if !bytes.Contains([]byte(options), []byte(want)) {
			t.Fatalf("options missing %q: %s", want, options)
		}
	}
}

func TestinstallScriptPeerInfo(t *testing.T) {
	// The configured cipher is advertised first, followed by the other AEAD
	// ciphers so the server can pick one via NCP.
	base := installScriptPeerInfo(CipherAES128GCM, compressNone, nil)
	if base != "IV_VER=mihomo-openvpn\nIV_PROTO=6\nIV_CIPHERS=AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\n" {
		t.Fatalf("unexpected default peer-info: %q", base)
	}

	// User-defined entries are appended after the built-in fields, sorted by key.
	info := installScriptPeerInfo(CipherAES128GCM, compressNone, map[string]string{
		"UV_DEVICE_ID": "laptop-001",
		"IV_HWADDR":    "52:54:00:ff:72:87",
	})
	want := base + "IV_HWADDR=52:54:00:ff:72:87\nUV_DEVICE_ID=laptop-001\n"
	if info != want {
		t.Fatalf("unexpected peer-info:\n got %q\nwant %q", info, want)
	}
}

func TestDataCiphersListPutsConfiguredFirst(t *testing.T) {
	if got := dataCiphersList(CipherAES256GCM); got != "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305" {
		t.Fatalf("unexpected cipher list: %q", got)
	}
	if got := dataCiphersList(CipherChaCha20Poly1305); got != "CHACHA20-POLY1305:AES-256-GCM:AES-128-GCM" {
		t.Fatalf("unexpected cipher list: %q", got)
	}
}

func TestParseServerKeyMethod2Record(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "IV_VER=server\n")

	record, err := ParseServerKeyMethod2Record(packet)
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" || record.PeerInfo != "IV_VER=server\n" {
		t.Fatalf("unexpected parsed strings: %#v", record)
	}
	if record.Sources.Server.Random1[0] != 1 || record.Sources.Server.Random2[0] != 2 {
		t.Fatalf("unexpected server randoms")
	}
}

func TestParseServerKeyMethod2RecordKeepsTrailingData(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	recordLen := len(packet)

	// A server may coalesce an early PUSH_REPLY into the same flight.
	trailing := []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")
	record, consumed, err := parseServerKeyMethod2Record(append(packet, trailing...))
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" {
		t.Fatalf("unexpected options: %q", record.Options)
	}
	if consumed != recordLen {
		t.Fatalf("expected %d consumed bytes, got %d", recordLen, consumed)
	}
}

func TestParseServerKeyMethod2RecordTruncatedIsRetryable(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")

	for _, cut := range []int{3, 40, len(packet) - 1} {
		if _, _, err := parseServerKeyMethod2Record(packet[:cut]); !errors.Is(err, ioStringEOF) {
			t.Fatalf("truncation at %d bytes must be retryable, got %v", cut, err)
		}
	}
}
