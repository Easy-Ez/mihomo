package outbound

import (
	"testing"
	"time"

	ovpn "github.com/metacubex/mihomo/transport/openvpn"
)

func TestOpenVPNKeepalivePushedOverridesConfig(t *testing.T) {
	config := &ovpn.ClientConfig{PingInterval: 5 * time.Second, PingRestart: 30 * time.Second}

	ping, restart, source := openVPNKeepalive(config, nil)
	if ping != 5*time.Second || restart != 30*time.Second || source != "config" {
		t.Fatalf("without push: %s/%s (%s)", ping, restart, source)
	}

	ping, restart, source = openVPNKeepalive(config, &ovpn.PushReply{Ping: 10 * time.Second, PingRestart: 120 * time.Second})
	if ping != 10*time.Second || restart != 120*time.Second || source != "pushed" {
		t.Fatalf("pushed values must win: %s/%s (%s)", ping, restart, source)
	}

	ping, restart, source = openVPNKeepalive(config, &ovpn.PushReply{PingRestart: 120 * time.Second})
	if ping != 5*time.Second || restart != 120*time.Second || source != "ping config, ping-restart pushed" {
		t.Fatalf("partial push: %s/%s (%s)", ping, restart, source)
	}

	ping, restart, _ = openVPNKeepalive(&ovpn.ClientConfig{}, &ovpn.PushReply{Ping: 10 * time.Second, PingRestart: 60 * time.Second})
	if ping != 10*time.Second || restart != 60*time.Second {
		t.Fatalf("unconfigured keepalive must adopt pushed values: %s/%s", ping, restart)
	}
}
