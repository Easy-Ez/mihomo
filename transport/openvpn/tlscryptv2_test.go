package openvpn

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
	"time"
)

// makeWKc builds a fake wrapped client key with a valid trailing length field.
func makeWKc(n int) []byte {
	wkc := make([]byte, n)
	for i := range wkc {
		wkc[i] = byte(i)
	}
	wkc[n-2] = byte(n >> 8)
	wkc[n-1] = byte(n)
	return wkc
}

func tlsCryptV2ClientKeyPEM(kc, wkc []byte) []byte {
	raw := append(append([]byte(nil), kc...), wkc...)
	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: raw})
}

func TestDecodeTLSCryptV2ClientKey(t *testing.T) {
	kc := testStaticKey()
	wkc := makeWKc(290)
	block := tlsCryptV2ClientKeyPEM(kc, wkc)

	gotKc, gotWkc, err := DecodeTLSCryptV2ClientKey(block)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotKc, kc) {
		t.Fatal("Kc mismatch")
	}
	if !bytes.Equal(gotWkc, wkc) {
		t.Fatal("WKc mismatch")
	}
}

func TestDecodeTLSCryptV2ClientKeyLengthMismatch(t *testing.T) {
	kc := testStaticKey()
	wkc := makeWKc(290)
	wkc[len(wkc)-1] ^= 0xff // corrupt the declared length
	block := tlsCryptV2ClientKeyPEM(kc, wkc)
	if _, _, err := DecodeTLSCryptV2ClientKey(block); err == nil {
		t.Fatal("expected length mismatch error")
	}
}

func TestConfigTLSCryptV2(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.TLSCrypt = nil
	cfg.TLSCryptV2 = tlsCryptV2ClientKeyPEM(testStaticKey(), makeWKc(290))
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLSCryptV2Kc) != 256 || len(cfg.TLSCryptV2WKc) != 290 {
		t.Fatalf("unexpected parsed lengths: kc=%d wkc=%d", len(cfg.TLSCryptV2Kc), len(cfg.TLSCryptV2WKc))
	}
}

func TestConfigRejectsTLSCryptAndV2(t *testing.T) {
	cfg := yamlStyleConfig() // already has TLSCrypt
	cfg.TLSCryptV2 = tlsCryptV2ClientKeyPEM(testStaticKey(), makeWKc(290))
	if err := cfg.Prepare(); err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
}

func TestTLSCryptV2ResetCarriesWrappedKey(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	kc := testStaticKey()
	clientCrypt, err := NewTLSCrypt(kc, true)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	control := NewControlChannel(clientIO, clientCrypt, clientID)
	wkc := makeWKc(290)
	control.SetTLSCryptV2WKc(wkc)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := control.SendReset(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if op, _ := parseOpcodeKeyID(raw[0]); op != PControlHardResetClientV3 {
		t.Fatalf("expected V3 hard reset, got %s", op)
	}
	// The wrapped key must ride unencrypted at the tail.
	if !bytes.Equal(raw[len(raw)-len(wkc):], wkc) {
		t.Fatal("WKc not appended to reset packet")
	}
	// Stripping the WKc must leave a valid tls-crypt packet the server can
	// unwrap with the same Kc.
	serverCrypt, err := NewTLSCrypt(kc, false)
	if err != nil {
		t.Fatal(err)
	}
	packet, _, _, err := DecodeControlPacket(serverCrypt, raw[:len(raw)-len(wkc)])
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV3 {
		t.Fatalf("unexpected decoded opcode: %s", packet.Opcode)
	}
}
