package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/transportstat"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
	"github.com/metacubex/quic-go/monotime"
	"github.com/metacubex/quic-go/qlog"
)

type fakeCongestionController struct {
	cwnd congestion.ByteCount
}

func (f *fakeCongestionController) SetRTTStatsProvider(congestion.RTTStatsProvider) {}
func (f *fakeCongestionController) TimeUntilSend(congestion.ByteCount) monotime.Time {
	return 0
}
func (f *fakeCongestionController) HasPacingBudget(monotime.Time) bool { return true }
func (f *fakeCongestionController) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}
func (f *fakeCongestionController) CanSend(congestion.ByteCount) bool { return true }
func (f *fakeCongestionController) MaybeExitSlowStart()               {}
func (f *fakeCongestionController) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}
func (f *fakeCongestionController) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
	f.cwnd /= 2
}
func (f *fakeCongestionController) OnRetransmissionTimeout(bool)            {}
func (f *fakeCongestionController) SetMaxDatagramSize(congestion.ByteCount) {}
func (f *fakeCongestionController) InSlowStart() bool                       { return false }
func (f *fakeCongestionController) InRecovery() bool                        { return false }
func (f *fakeCongestionController) GetCongestionWindow() congestion.ByteCount {
	return f.cwnd
}

type fakeCongestionControllerEx struct {
	*fakeCongestionController
}

func (f *fakeCongestionControllerEx) OnCongestionEventEx(_ congestion.ByteCount, _ monotime.Time, _ []congestion.AckedPacketInfo, _ []congestion.LostPacketInfo) {
	f.cwnd /= 2
}

func TestCongestionControllerMetrics(t *testing.T) {
	observation := &observation{id: "transport", adapter: "US"}
	controller := wrapCongestionController(&fakeCongestionController{cwnd: 1200}, observation)
	controller.OnPacketSent(monotime.Now(), 300, 1, 100, true)
	controller.OnCongestionEvent(1, 100, 400)

	if observation.packetsLostTotal.Load() != 1 || observation.bytesLostTotal.Load() != 100 {
		t.Fatalf("unexpected loss totals: packets=%d bytes=%d", observation.packetsLostTotal.Load(), observation.bytesLostTotal.Load())
	}
	if observation.bytesInFlight.Load() != 300 || observation.cwnd.Load() != 600 {
		t.Fatalf("unexpected congestion state: inFlight=%d cwnd=%d", observation.bytesInFlight.Load(), observation.cwnd.Load())
	}
}

func TestExtendedCongestionControllerMetrics(t *testing.T) {
	observation := &observation{id: "transport", adapter: "US"}
	controller := wrapCongestionController(&fakeCongestionControllerEx{
		fakeCongestionController: &fakeCongestionController{cwnd: 2000},
	}, observation)
	extended, ok := controller.(congestion.CongestionControlEx)
	if !ok {
		t.Fatal("extended congestion control capability was not preserved")
	}
	extended.OnCongestionEventEx(1000, monotime.Now(), nil, []congestion.LostPacketInfo{
		{PacketNumber: 1, BytesLost: 100},
		{PacketNumber: 2, BytesLost: 200},
	})
	if observation.packetsLostTotal.Load() != 2 || observation.bytesLostTotal.Load() != 300 {
		t.Fatalf("unexpected extended loss totals: packets=%d bytes=%d", observation.packetsLostTotal.Load(), observation.bytesLostTotal.Load())
	}
}

func TestExtendedCongestionControllerDoesNotReportProbeRTTAsCollapse(t *testing.T) {
	events, cancel := transportstat.DefaultManager.Subscribe(4)
	defer cancel()
	observation := &observation{id: "transport-probe-rtt", adapter: "US"}
	controller := wrapCongestionController(&fakeCongestionControllerEx{
		fakeCongestionController: &fakeCongestionController{cwnd: 2000},
	}, observation)
	extended := controller.(congestion.CongestionControlEx)
	extended.OnCongestionEventEx(0, monotime.Now(), nil, nil)
	if observation.cwnd.Load() != 1000 {
		t.Fatalf("cwnd = %d, want 1000", observation.cwnd.Load())
	}
	select {
	case event := <-events:
		t.Fatalf("unexpected event for loss-free window reduction: %+v", event)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestTraceSessionPTOAndMetrics(t *testing.T) {
	ctx, session := WithTrace(context.Background())
	trace := NewTracer(nil)(ctx, true, quic.ConnectionID{})
	recorder := trace.AddProducer()
	defer recorder.Close()

	recorder.RecordEvent(qlog.PTOCountUpdated{PTOCount: 1})
	recorder.RecordEvent(qlog.PTOCountUpdated{PTOCount: 2})
	recorder.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	recorder.RecordEvent(qlog.PTOCountUpdated{PTOCount: 1})
	recorder.RecordEvent(qlog.MetricsUpdated{CongestionWindow: 4096, BytesInFlight: 512})

	if session.ptoTotal.Load() != 3 {
		t.Fatalf("PTO total = %d, want 3", session.ptoTotal.Load())
	}
	if session.cwnd.Load() != 4096 || session.bytesInFlight.Load() != 512 {
		t.Fatalf("unexpected traced metrics: cwnd=%d inFlight=%d", session.cwnd.Load(), session.bytesInFlight.Load())
	}
}
