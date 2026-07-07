package openvpn

import (
	"testing"
	"time"
)

func TestParsePushReplyKeepalive(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,ping 10,ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,peer-id 3\x00")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Ping != 10*time.Second {
		t.Fatalf("unexpected pushed ping: %s", reply.Ping)
	}
	if reply.PingRestart != 120*time.Second {
		t.Fatalf("unexpected pushed ping-restart: %s", reply.PingRestart)
	}
}

func TestParsePushReplyMessagesContinuation(t *testing.T) {
	messages := []string{
		"PUSH_REPLY,route 10.1.0.0 255.255.0.0,route 10.2.0.0 255.255.0.0,push-continuation 2",
		"PUSH_REPLY,route 10.3.0.0 255.255.0.0,ifconfig 10.8.0.2 255.255.255.0,peer-id 5,push-continuation 1",
	}
	reply, err := ParsePushReplyMessages(messages)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Routes) != 3 {
		t.Fatalf("expected 3 merged routes, got %#v", reply.Routes)
	}
	if len(reply.Prefixes) != 1 || reply.Prefixes[0].String() != "10.8.0.2/24" {
		t.Fatalf("unexpected prefixes: %#v", reply.Prefixes)
	}
	if reply.PeerID != 5 {
		t.Fatalf("unexpected peer id: %d", reply.PeerID)
	}
}

func TestPushReplyContinuation(t *testing.T) {
	if got := pushReplyContinuation("PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 2\x00"); got != pushContinuationPartial {
		t.Fatalf("expected partial continuation, got %d", got)
	}
	if got := pushReplyContinuation("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1\x00"); got != pushContinuationEnd {
		t.Fatalf("expected end continuation, got %d", got)
	}
	if got := pushReplyContinuation("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00"); got != 0 {
		t.Fatalf("expected no continuation, got %d", got)
	}
}

func TestParsePushReplyAuthToken(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,auth-token SESS_ID_abc123,auth-token-user dXNlcjE=,ifconfig 10.8.0.2 255.255.255.0\x00")
	if err != nil {
		t.Fatal(err)
	}
	if reply.AuthToken != "SESS_ID_abc123" {
		t.Fatalf("unexpected auth token: %q", reply.AuthToken)
	}
	if reply.AuthTokenUser != "user1" {
		t.Fatalf("unexpected auth token user: %q", reply.AuthTokenUser)
	}
}

func TestParsePushReplyCipher(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,cipher AES-256-GCM,ifconfig 10.8.0.2 255.255.255.0\x00")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Cipher != "AES-256-GCM" {
		t.Fatalf("unexpected pushed cipher: %q", reply.Cipher)
	}
}

func TestNegotiateCipher(t *testing.T) {
	c := &Client{config: &ClientConfig{Cipher: CipherAES128GCM}}

	// No pushed cipher: keep the configured one.
	if got, err := c.negotiateCipher(&PushReply{}); err != nil || got != CipherAES128GCM {
		t.Fatalf("expected configured cipher, got %q err=%v", got, err)
	}
	// Server selects a different supported cipher: adopt it.
	if got, err := c.negotiateCipher(&PushReply{Cipher: "AES-256-GCM"}); err != nil || got != CipherAES256GCM {
		t.Fatalf("expected negotiated AES-256-GCM, got %q err=%v", got, err)
	}
	// Unsupported cipher: fail clearly rather than silently mis-decrypt.
	if _, err := c.negotiateCipher(&PushReply{Cipher: "BF-CBC"}); err == nil {
		t.Fatal("expected error for unsupported negotiated cipher")
	}
}

func TestParsePushReplyMessagesRejectsNonPush(t *testing.T) {
	if _, err := ParsePushReplyMessages([]string{"AUTH_FAILED"}); err == nil {
		t.Fatal("expected error for non-push message")
	}
}
