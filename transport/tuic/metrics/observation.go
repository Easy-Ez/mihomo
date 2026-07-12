package metrics

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/transportstat"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
)

type observation struct {
	id        string
	adapter   string
	conn      *quic.Conn
	trace     *TraceSession
	createdAt time.Time

	reconnectTotal   atomic.Uint64
	openStreams      atomic.Int64
	bytesLostTotal   atomic.Uint64
	packetsLostTotal atomic.Uint64
	lossEventsTotal  atomic.Uint64
	cwnd             atomic.Uint64
	bytesInFlight    atomic.Uint64
	writeCount       atomic.Uint64
	writeBlocked     atomic.Uint64
	writeTotalMicros atomic.Uint64
	writeMaxMicros   atomic.Uint64
	writeLastMicros  atomic.Uint64
	writeLastAt      atomic.Int64
}

var observations sync.Map

func ObserveClientTransport(adapter string, conn *quic.Conn, controller congestion.CongestionControl, trace *TraceSession) {
	if conn == nil {
		return
	}
	observation := &observation{
		id:        utils.NewUUIDV4().String(),
		adapter:   adapter,
		conn:      conn,
		trace:     trace,
		createdAt: time.Now(),
	}
	if trace != nil {
		trace.bind(observation)
	}
	if controller != nil {
		controller = wrapCongestionController(controller, observation)
		conn.SetCongestionControl(controller)
		observation.cwnd.Store(uint64(controller.GetCongestionWindow()))
	}
	observations.Store(conn, observation)
	observation.reconnectTotal.Store(transportstat.DefaultManager.Register(observation))

	go func() {
		<-conn.Context().Done()
		reason := "connection closed"
		if err := context.Cause(conn.Context()); err != nil {
			reason = err.Error()
		}
		observations.Delete(conn)
		transportstat.DefaultManager.Unregister(observation.id, reason)
	}()
}

func OpenStream(conn *quic.Conn) (string, *transportstat.StreamStats, func()) {
	value, ok := observations.Load(conn)
	if !ok {
		return "", nil, func() {}
	}
	observation := value.(*observation)
	observation.openStreams.Add(1)
	stats := transportstat.NewStreamStats(observation.observeWrite)
	var once sync.Once
	return observation.id, stats, func() {
		once.Do(func() {
			observation.openStreams.Add(-1)
		})
	}
}

func (o *observation) observeWrite(durationMicros uint64, blocked bool, atUnixMs int64) {
	o.writeCount.Add(1)
	o.writeTotalMicros.Add(durationMicros)
	o.writeLastMicros.Store(durationMicros)
	o.writeLastAt.Store(atUnixMs)
	if blocked {
		o.writeBlocked.Add(1)
	}
	for current := o.writeMaxMicros.Load(); durationMicros > current; current = o.writeMaxMicros.Load() {
		if o.writeMaxMicros.CompareAndSwap(current, durationMicros) {
			break
		}
	}
}

func (o *observation) TransportSnapshot() transportstat.Snapshot {
	stats := o.conn.ConnectionStats()
	cwnd := o.cwnd.Load()
	bytesInFlight := o.bytesInFlight.Load()
	ptoTotal := uint64(0)
	if o.trace != nil {
		ptoTotal = o.trace.ptoTotal.Load()
		if tracedCwnd := o.trace.cwnd.Load(); tracedCwnd != 0 {
			cwnd = tracedCwnd
			bytesInFlight = o.trace.bytesInFlight.Load()
		}
	}
	return transportstat.Snapshot{
		ID:                         o.id,
		Adapter:                    o.adapter,
		Protocol:                   "tuic",
		LocalAddress:               addressString(o.conn.LocalAddr()),
		RemoteAddress:              addressString(o.conn.RemoteAddr()),
		State:                      "active",
		CreatedAt:                  o.createdAt,
		OpenStreams:                o.openStreams.Load(),
		ReconnectTotal:             o.reconnectTotal.Load(),
		MinRTTMs:                   durationMilliseconds(stats.MinRTT),
		LatestRTTMs:                durationMilliseconds(stats.LatestRTT),
		SmoothedRTTMs:              durationMilliseconds(stats.SmoothedRTT),
		RTTVariationMs:             durationMilliseconds(stats.MeanDeviation),
		BytesSent:                  stats.BytesSent,
		PacketsSent:                stats.PacketsSent,
		BytesReceived:              stats.BytesReceived,
		PacketsReceived:            stats.PacketsReceived,
		BytesLostTotal:             o.bytesLostTotal.Load(),
		PacketsLostTotal:           o.packetsLostTotal.Load(),
		LossEventsTotal:            o.lossEventsTotal.Load(),
		PTOTotal:                   ptoTotal,
		CongestionWindow:           cwnd,
		BytesInFlight:              bytesInFlight,
		CongestionMetricsAvailable: cwnd != 0,
		WriteCount:                 o.writeCount.Load(),
		WriteBlockedCount:          o.writeBlocked.Load(),
		WriteDurationTotalMicros:   o.writeTotalMicros.Load(),
		MaxWriteDurationMicros:     o.writeMaxMicros.Load(),
		LastWriteDurationMicros:    o.writeLastMicros.Load(),
		LastWriteAtUnixMs:          o.writeLastAt.Load(),
	}
}

func (o *observation) recordLoss(packets, bytes, before, after uint64) {
	if packets == 0 {
		return
	}
	o.packetsLostTotal.Add(packets)
	o.bytesLostTotal.Add(bytes)
	o.lossEventsTotal.Add(1)
	o.bytesInFlight.Store(after)
	transportstat.DefaultManager.Publish(transportstat.Event{
		Type: transportstat.EventPacketLoss, TransportID: o.id, Adapter: o.adapter, Protocol: "tuic",
		Count: packets, Bytes: bytes, Before: before, After: after,
	})
}

func (o *observation) publishPTO(total, delta uint64) {
	transportstat.DefaultManager.Publish(transportstat.Event{
		Type: transportstat.EventPTO, TransportID: o.id, Adapter: o.adapter, Protocol: "tuic", Count: total, Delta: delta,
	})
}

func (o *observation) recordCongestionWindow(before, after uint64) {
	o.cwnd.Store(after)
	if before > 0 && after*2 < before {
		transportstat.DefaultManager.Publish(transportstat.Event{
			Type: transportstat.EventCwndCollapse, TransportID: o.id, Adapter: o.adapter, Protocol: "tuic", Before: before, After: after,
		})
	}
}

func addressString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
