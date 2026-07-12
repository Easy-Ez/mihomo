package metrics

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/qlog"
	"github.com/metacubex/quic-go/qlogwriter"
)

type traceContextKey struct{}

type TraceSession struct {
	mu            sync.Mutex
	lastPTOCount  uint32
	ptoTotal      atomic.Uint64
	cwnd          atomic.Uint64
	bytesInFlight atomic.Uint64
	observation   atomic.Pointer[observation]
}

func WithTrace(ctx context.Context) (context.Context, *TraceSession) {
	session := &TraceSession{}
	return context.WithValue(ctx, traceContextKey{}, session), session
}

func NewTracer(existing func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	return func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
		session, _ := ctx.Value(traceContextKey{}).(*TraceSession)
		var downstream qlogwriter.Trace
		if existing != nil {
			downstream = existing(ctx, isClient, connID)
		}
		if session == nil {
			return downstream
		}
		return &transportTrace{session: session, downstream: downstream}
	}
}

func (s *TraceSession) bind(observation *observation) {
	s.observation.Store(observation)
}

func (s *TraceSession) recordPTOCount(count uint32) {
	s.mu.Lock()
	var delta uint64
	if count > s.lastPTOCount {
		delta = uint64(count - s.lastPTOCount)
		s.ptoTotal.Add(delta)
	}
	s.lastPTOCount = count
	total := s.ptoTotal.Load()
	s.mu.Unlock()
	if delta > 0 {
		if observation := s.observation.Load(); observation != nil {
			observation.publishPTO(total, delta)
		}
	}
}

type transportTrace struct {
	session    *TraceSession
	downstream qlogwriter.Trace
}

func (t *transportTrace) AddProducer() qlogwriter.Recorder {
	var downstream qlogwriter.Recorder
	if t.downstream != nil {
		downstream = t.downstream.AddProducer()
	}
	return &transportRecorder{session: t.session, downstream: downstream}
}

func (t *transportTrace) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema || t.downstream != nil && t.downstream.SupportsSchemas(schema)
}

type transportRecorder struct {
	session    *TraceSession
	downstream qlogwriter.Recorder
}

func (r *transportRecorder) RecordEvent(event qlogwriter.Event) {
	switch event := event.(type) {
	case qlog.PTOCountUpdated:
		r.session.recordPTOCount(event.PTOCount)
	case *qlog.PTOCountUpdated:
		r.session.recordPTOCount(event.PTOCount)
	case qlog.MetricsUpdated:
		r.recordMetrics(event)
	case *qlog.MetricsUpdated:
		r.recordMetrics(*event)
	}
	if r.downstream != nil {
		r.downstream.RecordEvent(event)
	}
}

func (r *transportRecorder) recordMetrics(event qlog.MetricsUpdated) {
	if event.CongestionWindow >= 0 {
		r.session.cwnd.Store(uint64(event.CongestionWindow))
	}
	if event.BytesInFlight >= 0 {
		r.session.bytesInFlight.Store(uint64(event.BytesInFlight))
	}
}

func (r *transportRecorder) Close() error {
	if r.downstream != nil {
		return r.downstream.Close()
	}
	return nil
}
