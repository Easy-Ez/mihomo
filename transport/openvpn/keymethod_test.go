package openvpn

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestKeyMethod2ClientMarshalAndDerive(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  InstallScriptOptionsString(ProtoUDP, CipherAES128GCM, AuthSHA256, ""),
		PeerInfo: InstallScriptPeerInfo(CipherAES128GCM, nil, "", nil),
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
		Options:  InstallScriptOptionsString(ProtoUDP, CipherAES256GCM, AuthSHA256, ""),
		PeerInfo: InstallScriptPeerInfo(CipherAES256GCM, nil, "", nil),
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
	options := InstallScriptOptionsString(ProtoTCP, CipherAES256CBC, AuthSHA1, "")
	for _, want := range []string{"proto TCPv4_CLIENT", "cipher AES-256-CBC", "auth SHA1", "keysize 256"} {
		if !bytes.Contains([]byte(options), []byte(want)) {
			t.Fatalf("options missing %q: %s", want, options)
		}
	}
}

func TestInstallScriptPeerInfo(t *testing.T) {
	// Without user-defined peer-info the output is unchanged (backward compatible).
	base := InstallScriptPeerInfo(CipherAES128GCM, nil, "", nil)
	if base != "IV_VER=mihomo-openvpn\nIV_PROTO=22\nIV_CIPHERS=AES-128-GCM\n" {
		t.Fatalf("unexpected default peer-info: %q", base)
	}

	// User-defined entries are appended after the built-in fields, sorted by key.
	info := InstallScriptPeerInfo(CipherAES128GCM, nil, "", map[string]string{
		"UV_DEVICE_ID": "laptop-001",
		"IV_HWADDR":    "52:54:00:ff:72:87",
	})
	want := base + "IV_HWADDR=52:54:00:ff:72:87\nUV_DEVICE_ID=laptop-001\n"
	if info != want {
		t.Fatalf("unexpected peer-info:\n got %q\nwant %q", info, want)
	}

	// A user-defined IV_VER replaces the built-in value, while other generated
	// fields are not duplicated by peer-info entries.
	overridden := InstallScriptPeerInfo(CipherAES128GCM, nil, CompLzoYes, map[string]string{
		"IV_VER":     "custom-client/1.0",
		"IV_PROTO":   "999",
		"IV_LZO":     "0",
		"IV_CIPHERS": "AES-256-CBC",
	})
	want = "IV_VER=custom-client/1.0\nIV_PROTO=22\nIV_LZO=1\nIV_CIPHERS=AES-128-GCM\n"
	if overridden != want {
		t.Fatalf("unexpected overridden peer-info:\n got %q\nwant %q", overridden, want)
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

func TestParseServerKeyMethod2RecordShortenedPreservesTail(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = append(packet, []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")...)

	record, consumed, err := ParseServerKeyMethod2RecordConsumed(packet)
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" {
		t.Fatalf("options = %q", record.Options)
	}
	if record.Username != "" || record.Password != "" || record.PeerInfo != "" {
		t.Fatalf("optional strings should be empty: %#v", record)
	}
	tail := packet[consumed:]
	if !bytes.HasPrefix(tail, []byte("PUSH_REPLY")) {
		t.Fatalf("expected leftover PUSH_REPLY, got %q", tail)
	}
}

func TestInstallScriptPeerInfoCompressionModes(t *testing.T) {
	cases := []struct {
		mode    compressionMode
		want    []string
		exclude []string
	}{
		{compressNone, []string{"IV_COMP_STUB=0\n"}, []string{"IV_LZO=", "IV_COMP_STUB=1", "IV_LZO_STUB=", "IV_COMP_STUBv2="}},
		{compressLZO, []string{"IV_LZO=1\n", "IV_COMP_STUB=0\n"}, []string{"IV_COMP_STUB=1"}},
		{compressV1Stub, []string{"IV_COMP_STUB=1\n", "IV_LZO_STUB=1\n"}, []string{"IV_LZO=1", "IV_COMP_STUBv2="}},
		{compressV2Stub, []string{"IV_COMP_STUBv2=1\n", "IV_COMP_STUB=1\n", "IV_LZO_STUB=1\n"}, []string{"IV_LZO=1"}},
	}
	for _, tc := range cases {
		info := installScriptPeerInfo(CipherAES128GCM, nil, tc.mode, map[string]string{"IV_COMP_STUB": "0", "IV_HWADDR": "aa:bb"})
		for _, want := range tc.want {
			if !strings.Contains(info, want) {
				t.Errorf("%v: missing %q in %q", tc.mode, want, info)
			}
		}
		for _, exclude := range tc.exclude {
			if strings.Contains(info, exclude) {
				t.Errorf("%v: unexpected %q in %q", tc.mode, exclude, info)
			}
		}
		if strings.Count(info, "IV_COMP_STUB=") > 1 {
			t.Errorf("%v: user IV_COMP_STUB must not duplicate the built-in line: %q", tc.mode, info)
		}
		if !strings.Contains(info, "IV_HWADDR=aa:bb\n") {
			t.Errorf("%v: user peer-info dropped: %q", tc.mode, info)
		}
	}
	if !strings.Contains(installScriptOptions(ProtoUDP, CipherAES128GCM, AuthSHA256, compressV2Stub), "link-mtu 1544,tun-mtu 1500,proto UDPv4,comp-lzo,") {
		t.Fatal("compress modes must advertise comp-lzo in the options string")
	}
	if strings.Contains(installScriptOptions(ProtoUDP, CipherAES128GCM, AuthSHA256, compressNone), "comp-lzo") {
		t.Fatal("no compression must not advertise comp-lzo")
	}
}

func TestConfigCompressOption(t *testing.T) {
	base := func() *ClientConfig {
		return &ClientConfig{RemoteHost: "vpn.example.com", RemotePort: 1194, CA: []byte(testCert), Username: "user"}
	}
	cfg := base()
	cfg.Compress = " LZ4-V2 "
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.Compress != "lz4-v2" || cfg.compressMode != compressV2Stub {
		t.Fatalf("compress = %q mode=%v", cfg.Compress, cfg.compressMode)
	}
	cfg = base()
	cfg.CompLZO = "yes"
	cfg.Compress = "stub"
	if err := cfg.Prepare(); err == nil {
		t.Fatal("comp-lzo and compress together must be rejected")
	}
	cfg = base()
	cfg.Compress = "zstd"
	if err := cfg.Prepare(); err == nil {
		t.Fatal("unknown compress algorithm must be rejected")
	}
}
