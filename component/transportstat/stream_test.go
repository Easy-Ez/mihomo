package transportstat

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStreamStats(t *testing.T) {
	var callbackCount int
	stats := NewStreamStats(func(durationMicros uint64, blocked bool, atUnixMs int64) {
		callbackCount++
		if callbackCount == 2 && !blocked {
			t.Error("second write should be blocked")
		}
	})
	stats.ObserveWrite(10 * time.Millisecond)
	stats.ObserveWrite(75 * time.Millisecond)

	snapshot := stats.Snapshot()
	if snapshot.WriteCount != 2 || snapshot.WriteBlockedCount != 1 {
		t.Fatalf("unexpected counts: %#v", snapshot)
	}
	if snapshot.WriteDurationTotalMicros != 85000 || snapshot.MaxWriteDurationMicros != 75000 {
		t.Fatalf("unexpected durations: %#v", snapshot)
	}
	if snapshot.LastWriteAtUnixMs == 0 || callbackCount != 2 {
		t.Fatalf("unexpected callback state: %#v, callbacks=%d", snapshot, callbackCount)
	}
	encoded, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "{}" {
		t.Fatal("stream stats JSON must contain the live snapshot")
	}
}
