package transportstat

import (
	"encoding/json"
	"sync/atomic"
	"time"
)

const WriteBlockedThreshold = 50 * time.Millisecond

type StreamSnapshot struct {
	WriteCount               uint64 `json:"writeCount"`
	WriteBlockedCount        uint64 `json:"writeBlockedCount"`
	WriteDurationTotalMicros uint64 `json:"writeDurationTotalMicros"`
	MaxWriteDurationMicros   uint64 `json:"maxWriteDurationMicros"`
	LastWriteDurationMicros  uint64 `json:"lastWriteDurationMicros"`
	LastWriteAtUnixMs        int64  `json:"lastWriteAtUnixMs,omitempty"`
}

type StreamStats struct {
	writeCount               atomic.Uint64
	writeBlockedCount        atomic.Uint64
	writeDurationTotalMicros atomic.Uint64
	maxWriteDurationMicros   atomic.Uint64
	lastWriteDurationMicros  atomic.Uint64
	lastWriteAtUnixMs        atomic.Int64
	onWrite                  func(durationMicros uint64, blocked bool, atUnixMs int64)
}

func NewStreamStats(onWrite func(durationMicros uint64, blocked bool, atUnixMs int64)) *StreamStats {
	return &StreamStats{onWrite: onWrite}
}

func (s *StreamStats) ObserveWrite(duration time.Duration) {
	if s == nil {
		return
	}
	durationMicros := uint64(duration.Microseconds())
	blocked := duration >= WriteBlockedThreshold
	atUnixMs := time.Now().UnixMilli()
	s.writeCount.Add(1)
	s.writeDurationTotalMicros.Add(durationMicros)
	s.lastWriteDurationMicros.Store(durationMicros)
	s.lastWriteAtUnixMs.Store(atUnixMs)
	if blocked {
		s.writeBlockedCount.Add(1)
	}
	for current := s.maxWriteDurationMicros.Load(); durationMicros > current; current = s.maxWriteDurationMicros.Load() {
		if s.maxWriteDurationMicros.CompareAndSwap(current, durationMicros) {
			break
		}
	}
	if s.onWrite != nil {
		s.onWrite(durationMicros, blocked, atUnixMs)
	}
}

func (s *StreamStats) Snapshot() StreamSnapshot {
	if s == nil {
		return StreamSnapshot{}
	}
	return StreamSnapshot{
		WriteCount:               s.writeCount.Load(),
		WriteBlockedCount:        s.writeBlockedCount.Load(),
		WriteDurationTotalMicros: s.writeDurationTotalMicros.Load(),
		MaxWriteDurationMicros:   s.maxWriteDurationMicros.Load(),
		LastWriteDurationMicros:  s.lastWriteDurationMicros.Load(),
		LastWriteAtUnixMs:        s.lastWriteAtUnixMs.Load(),
	}
}

func (s *StreamStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Snapshot())
}

type StreamProvider interface {
	TransportID() string
	TransportStreamStats() *StreamStats
}
