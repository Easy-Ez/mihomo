package diagnostic

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type testDialer struct {
	dialer net.Dialer
}

func (d testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

func (testDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, nil
}

func TestPercentile(t *testing.T) {
	if got := percentile([]float64{4, 1, 3, 2}, .5); got != 2.5 {
		t.Fatalf("p50=%v", got)
	}
}

func TestValidateRejectsUnsafeRequest(t *testing.T) {
	r := defaults(StartRequest{Proxy: "DIRECT", Profile: ProfileGame, Target: "example.com", Token: "secret"})
	if validate(r) == nil {
		t.Fatal("expected hostname to be rejected")
	}
}

func TestManagerPublishesSamplesWhileRunIsActive(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})}
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Close()
		listener.Close()
	})

	manager := NewManager(func(string) (C.Dialer, bool, error) {
		return testDialer{}, true, nil
	})
	run, err := manager.Start(StartRequest{
		Proxy:      "DIRECT",
		Profile:    ProfileWeb,
		Target:     "127.0.0.1",
		Port:       uint16(listener.Addr().(*net.TCPAddr).Port),
		Token:      "test-token",
		DurationMs: 1_000,
		IntervalMs: 50,
	})
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(750 * time.Millisecond)
	seenLiveSample := false
	for time.Now().Before(deadline) {
		current, getErr := manager.Get(run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State == "running" && len(current.Samples) > 0 {
			seenLiveSample = true
			current.Samples[0].Error = "mutated clone"
			fresh, getErr := manager.Get(run.ID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if fresh.Samples[0].Error == "mutated clone" {
				t.Fatal("Get returned manager-owned sample storage")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !seenLiveSample {
		t.Fatal("run did not expose samples before completion")
	}
	if err := manager.Cancel(run.ID); err != nil {
		t.Fatal(err)
	}
	cancelDeadline := time.Now().Add(time.Second)
	for time.Now().Before(cancelDeadline) {
		current, getErr := manager.Get(run.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if current.State != "running" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run did not stop after cancellation")
}
