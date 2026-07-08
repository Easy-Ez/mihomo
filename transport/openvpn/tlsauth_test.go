package openvpn

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestTLSAuthWrapUnwrapRoundTrip(t *testing.T) {
	// Client (key-direction 1) and server (key-direction 0) must share the
	// same send/recv HMAC keys in opposite roles.
	client, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionServer)
	if err != nil {
		t.Fatal(err)
	}

	header := make([]byte, TLSCryptHeaderSize)
	header[0] = opcodeKeyID(PControlV1, 0)
	copy(header[1:], []byte("clientid"))
	body := []byte("control channel payload")

	wire, err := client.Wrap(header, 42, 1700000000, body)
	if err != nil {
		t.Fatal(err)
	}
	// On-wire layout: header || hmac || packet-id(4) || time(4) || body.
	if len(wire) != TLSCryptHeaderSize+client.size+TLSCryptPIDSize+len(body) {
		t.Fatalf("unexpected wire length %d", len(wire))
	}

	gotHeader, packetID, unixTime, plaintext, err := server.Unwrap(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHeader, header) {
		t.Fatalf("header mismatch: %x", gotHeader)
	}
	if packetID != 42 || unixTime != 1700000000 {
		t.Fatalf("unexpected packet id/time: %d/%d", packetID, unixTime)
	}
	if !bytes.Equal(plaintext, body) {
		t.Fatalf("body mismatch: %q", plaintext)
	}

	// Any tampered byte must fail the HMAC.
	wire[len(wire)-1] ^= 0xff
	if _, _, _, _, err := server.Unwrap(wire); err == nil {
		t.Fatal("expected authentication failure on tampered body")
	}
}

func TestTLSAuthRejectsWrongKeyDirection(t *testing.T) {
	client, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionClient)
	if err != nil {
		t.Fatal(err)
	}
	// A peer that also uses key-direction 1 has swapped keys and must reject.
	peer, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionClient)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, TLSCryptHeaderSize)
	wire, err := client.Wrap(header, 1, 2, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := peer.Unwrap(wire); err == nil {
		t.Fatal("expected authentication failure with mismatched key direction")
	}
}

func TestControlChannelTLSAuthRoundTrip(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientAuth, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionClient)
	if err != nil {
		t.Fatal(err)
	}
	serverAuth, err := NewTLSAuth(testStaticKey(), AuthSHA256, KeyDirectionServer)
	if err != nil {
		t.Fatal(err)
	}
	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, clientAuth, clientID)
	server := NewControlChannel(serverIO, serverAuth, serverID)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Send(ctx, PControlV1, []byte("hello tls-auth")); err != nil {
		t.Fatal(err)
	}
	packet, err := server.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlV1 || string(packet.Payload) != "hello tls-auth" {
		t.Fatalf("unexpected packet: %s %q", packet.Opcode, packet.Payload)
	}
	if server.RemoteSessionID() != clientID {
		t.Fatalf("server did not learn client session id")
	}
}
