package openvpn

import (
	"strings"
	"testing"
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
