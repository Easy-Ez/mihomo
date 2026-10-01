package openvpn

import (
	"strings"
	"testing"
	"time"
)

func TestParsePushReplyRecordsUnknownOptions(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.8.0.1,sndbuf 1048576,topology net30,ifconfig 10.8.0.2 255.255.255.0,peer-id 3")
	if err != nil {
		t.Fatal(err)
	}
	if !reply.Redirect || len(reply.DNS) != 1 || reply.PeerID != 3 {
		t.Fatalf("known options not parsed: %+v", reply)
	}
	want := []string{"sndbuf 1048576", "topology net30"}
	if strings.Join(reply.Unknown, "|") != strings.Join(want, "|") {
		t.Fatalf("unknown options = %v, want %v", reply.Unknown, want)
	}
}

func TestMergePushReplyKeepsUnknownOptions(t *testing.T) {
	first, err := parsePushReplyInner("PUSH_REPLY,sndbuf 1,push-continuation 2")
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsePushReplyInner("PUSH_REPLY,topology net30,sndbuf 1,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergePushReply(first, second)
	want := []string{"sndbuf 1", "topology net30"}
	if strings.Join(merged.Unknown, "|") != strings.Join(want, "|") {
		t.Fatalf("merged unknown options = %v, want %v", merged.Unknown, want)
	}
}

func TestRedactPushReply(t *testing.T) {
	raw := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_abc123,auth-token-user dXNlcg==,peer-id 1\x00"
	got := redactPushReply(raw)
	if strings.Contains(got, "abc123") || strings.Contains(got, "dXNlcg==") {
		t.Fatalf("token leaked: %q", got)
	}
	want := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token <redacted>,auth-token-user <redacted>,peer-id 1"
	if got != want {
		t.Fatalf("redacted = %q, want %q", got, want)
	}
	if redactPushReply("") != "" {
		t.Fatal("empty input must stay empty")
	}
}

func TestParsePushReplyKeepalive(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping 10,ping-restart 120,peer-id 1")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Ping != 10*time.Second || reply.PingRestart != 120*time.Second {
		t.Fatalf("keepalive = %s/%s, want 10s/2m0s", reply.Ping, reply.PingRestart)
	}
	if len(reply.Unknown) != 0 {
		t.Fatalf("keepalive options must not be reported as unknown: %v", reply.Unknown)
	}

	reply, err = ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping abc,ping-restart -5")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Ping != 0 || reply.PingRestart != 0 {
		t.Fatalf("invalid keepalive values must be ignored, got %s/%s", reply.Ping, reply.PingRestart)
	}
}

func TestMergePushReplyKeepsKeepalive(t *testing.T) {
	first, err := parsePushReplyInner("PUSH_REPLY,ping 10,ping-restart 60,push-continuation 2")
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsePushReplyInner("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergePushReply(first, second)
	if merged.Ping != 10*time.Second || merged.PingRestart != 60*time.Second {
		t.Fatalf("merged keepalive = %s/%s, want 10s/1m0s", merged.Ping, merged.PingRestart)
	}
}

func TestParsePushReplyCompression(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,compress stub-v2")
	if err != nil {
		t.Fatal(err)
	}
	if !reply.HasCompress || reply.Compress != "stub-v2" || reply.HasCompLZO {
		t.Fatalf("compress push = %+v", reply)
	}
	reply, err = ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,comp-lzo no")
	if err != nil {
		t.Fatal(err)
	}
	if !reply.HasCompLZO || reply.CompLZO != "no" || reply.HasCompress {
		t.Fatalf("comp-lzo push = %+v", reply)
	}
	reply, err = ParsePushReply("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,compress")
	if err != nil {
		t.Fatal(err)
	}
	if !reply.HasCompress || reply.Compress != "" {
		t.Fatalf("bare compress push = %+v", reply)
	}
	if len(reply.Unknown) != 0 {
		t.Fatalf("compression options must not be reported as unknown: %v", reply.Unknown)
	}
}

func TestMergePushReplyKeepsCompression(t *testing.T) {
	first, _ := parsePushReplyInner("PUSH_REPLY,compress lz4-v2,push-continuation 2")
	second, _ := parsePushReplyInner("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 1")
	merged := mergePushReply(first, second)
	if !merged.HasCompress || merged.Compress != "lz4-v2" {
		t.Fatalf("merged compression = %+v", merged)
	}
}
