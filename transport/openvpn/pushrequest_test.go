package openvpn

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

type countingWriter struct {
	mu     sync.Mutex
	writes [][]byte
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (w *countingWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.writes)
}

func TestRepeatPushRequestResendsUntilStopped(t *testing.T) {
	w := &countingWriter{}
	stop := repeatPushRequest(context.Background(), w, 5*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for w.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop()
	stop() // idempotent
	if n := w.count(); n < 2 {
		t.Fatalf("expected repeated PUSH_REQUEST writes, got %d", n)
	}
	w.mu.Lock()
	first := w.writes[0]
	w.mu.Unlock()
	if !bytes.Equal(first, []byte(PushRequest+"\x00")) {
		t.Fatalf("resent message = %q", first)
	}
	settled := w.count()
	time.Sleep(30 * time.Millisecond)
	if w.count() != settled {
		t.Fatal("writes continued after stop")
	}
}

func TestRepeatPushRequestStopsOnContext(t *testing.T) {
	w := &countingWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	stop := repeatPushRequest(ctx, w, 5*time.Millisecond)
	defer stop()
	cancel()
	time.Sleep(10 * time.Millisecond)
	settled := w.count()
	time.Sleep(30 * time.Millisecond)
	if w.count() != settled {
		t.Fatal("writes continued after context cancellation")
	}
}
