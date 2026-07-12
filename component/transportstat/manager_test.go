package transportstat

import (
	"testing"
	"time"
)

type staticProvider struct {
	snapshot Snapshot
}

func (p staticProvider) TransportSnapshot() Snapshot {
	return p.snapshot
}

func TestManagerLifecycleAndReconnect(t *testing.T) {
	manager := NewManager()
	events, cancel := manager.Subscribe(8)
	defer cancel()
	provider := staticProvider{snapshot: Snapshot{
		ID: "first", Adapter: "US", Protocol: "tuic", RemoteAddress: "127.0.0.1:443", CreatedAt: time.Now(),
	}}
	if reconnect := manager.Register(provider); reconnect != 0 {
		t.Fatalf("first reconnect count = %d, want 0", reconnect)
	}
	if snapshots := manager.Snapshot(); len(snapshots) != 1 || snapshots[0].ID != "first" {
		t.Fatalf("unexpected snapshots: %#v", snapshots)
	}
	if event := <-events; event.Type != EventTransportCreated {
		t.Fatalf("first event = %q, want %q", event.Type, EventTransportCreated)
	}
	manager.Unregister("first", "test close")
	if event := <-events; event.Type != EventTransportClosed || event.Reason != "test close" || event.Snapshot == nil || event.Snapshot.State != "closed" {
		t.Fatalf("unexpected close event: %#v", event)
	}

	provider.snapshot.ID = "second"
	if reconnect := manager.Register(provider); reconnect != 1 {
		t.Fatalf("second reconnect count = %d, want 1", reconnect)
	}
	if event := <-events; event.Type != EventTransportCreated {
		t.Fatalf("unexpected create event: %#v", event)
	}
	if event := <-events; event.Type != EventTransportReconnected || event.Count != 1 {
		t.Fatalf("unexpected reconnect event: %#v", event)
	}
}
