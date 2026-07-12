package metrics

import (
	"github.com/metacubex/quic-go/congestion"
	"github.com/metacubex/quic-go/monotime"
)

type monitoredCongestionController struct {
	congestion.CongestionControl
	observation *observation
}

func wrapCongestionController(controller congestion.CongestionControl, observation *observation) congestion.CongestionControl {
	monitored := &monitoredCongestionController{
		CongestionControl: controller,
		observation:       observation,
	}
	if extended, ok := controller.(congestion.CongestionControlEx); ok {
		return &monitoredCongestionControllerEx{
			monitoredCongestionController: monitored,
			extended:                      extended,
		}
	}
	return monitored
}

func (m *monitoredCongestionController) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount, packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
	m.CongestionControl.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytes, isRetransmittable)
	m.observation.bytesInFlight.Store(uint64(bytesInFlight + bytes))
	m.captureCongestionWindow()
}

func (m *monitoredCongestionController) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount, priorInFlight congestion.ByteCount, eventTime monotime.Time) {
	m.CongestionControl.OnPacketAcked(number, ackedBytes, priorInFlight, eventTime)
	m.observation.bytesInFlight.Store(subtract(uint64(priorInFlight), uint64(ackedBytes)))
	m.captureCongestionWindow()
}

func (m *monitoredCongestionController) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount, priorInFlight congestion.ByteCount) {
	before := uint64(m.CongestionControl.GetCongestionWindow())
	m.CongestionControl.OnCongestionEvent(number, lostBytes, priorInFlight)
	after := uint64(m.CongestionControl.GetCongestionWindow())
	m.observation.recordLoss(1, uint64(lostBytes), uint64(priorInFlight), subtract(uint64(priorInFlight), uint64(lostBytes)))
	m.observation.recordCongestionWindow(before, after)
}

func (m *monitoredCongestionController) OnRetransmissionTimeout(packetsRetransmitted bool) {
	m.CongestionControl.OnRetransmissionTimeout(packetsRetransmitted)
	m.captureCongestionWindow()
}

func (m *monitoredCongestionController) captureCongestionWindow() {
	m.observation.cwnd.Store(uint64(m.CongestionControl.GetCongestionWindow()))
}

type monitoredCongestionControllerEx struct {
	*monitoredCongestionController
	extended congestion.CongestionControlEx
}

func (m *monitoredCongestionControllerEx) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	before := uint64(m.extended.GetCongestionWindow())
	m.extended.OnCongestionEventEx(priorInFlight, eventTime, ackedPackets, lostPackets)
	after := uint64(m.extended.GetCongestionWindow())
	var bytesLost uint64
	for _, packet := range lostPackets {
		bytesLost += uint64(packet.BytesLost)
	}
	m.observation.recordLoss(uint64(len(lostPackets)), bytesLost, uint64(priorInFlight), subtract(uint64(priorInFlight), bytesLost))
	m.observation.recordCongestionWindow(before, after)
}

func subtract(value, amount uint64) uint64 {
	if amount >= value {
		return 0
	}
	return value - amount
}
