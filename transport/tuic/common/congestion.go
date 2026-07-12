package common

import (
	"github.com/metacubex/mihomo/transport/tuic/congestion"
	congestionv2 "github.com/metacubex/mihomo/transport/tuic/congestion_v2"

	"github.com/metacubex/quic-go"
	c "github.com/metacubex/quic-go/congestion"
)

const (
	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
)

func SetCongestionController(quicConn *quic.Conn, cc string, cwnd int, profile string) {
	controller := NewCongestionController(quicConn, cc, cwnd, profile)
	if controller != nil {
		quicConn.SetCongestionControl(controller)
	}
}

func NewCongestionController(quicConn *quic.Conn, cc string, cwnd int, profile string) c.CongestionControl {
	if cwnd == 0 {
		cwnd = 32
	}
	switch cc {
	case "cubic":
		return congestion.NewCubicSender(
			congestion.GetInitialPacketSize(quicConn),
			false,
		)
	case "new_reno":
		return congestion.NewCubicSender(
			congestion.GetInitialPacketSize(quicConn),
			true,
		)
	case "bbr_meta_v1":
		return congestion.NewBBRSender(
			congestion.GetInitialPacketSize(quicConn),
			c.ByteCount(cwnd)*congestion.InitialMaxDatagramSize,
			congestion.DefaultBBRMaxCongestionWindow*congestion.InitialMaxDatagramSize,
		)
	case "bbr_meta_v2":
		fallthrough
	case "bbr":
		return congestionv2.NewBbrSender(
			congestionv2.GetInitialPacketSize(quicConn),
			c.ByteCount(cwnd),
			congestionv2.Profile(profile),
		)
	}
	return nil
}
