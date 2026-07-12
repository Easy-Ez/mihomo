package diagnostic

import "time"

type Profile string

const (
	ProfileGame  Profile = "game"
	ProfileWeb   Profile = "web"
	ProfileVideo Profile = "video"
)

type StartRequest struct {
	Proxy         string  `json:"proxy"`
	Profile       Profile `json:"profile"`
	Target        string  `json:"target"`
	Port          uint16  `json:"port"`
	Token         string  `json:"token"`
	DurationMs    int64   `json:"durationMs,omitempty"`
	IntervalMs    int64   `json:"intervalMs,omitempty"`
	PacketSize    int     `json:"packetSize,omitempty"`
	DownloadBytes int64   `json:"downloadBytes,omitempty"`
	RateMbps      float64 `json:"rateMbps,omitempty"`
}

type PublicRequest struct {
	Proxy           string  `json:"proxy"`
	Profile         Profile `json:"profile"`
	Target          string  `json:"target"`
	Port            uint16  `json:"port"`
	TokenConfigured bool    `json:"tokenConfigured"`
	DurationMs      int64   `json:"durationMs"`
	IntervalMs      int64   `json:"intervalMs,omitempty"`
	PacketSize      int     `json:"packetSize,omitempty"`
	DownloadBytes   int64   `json:"downloadBytes,omitempty"`
	RateMbps        float64 `json:"rateMbps,omitempty"`
}

type Sample struct {
	Sequence  int64   `json:"sequence"`
	AtMs      float64 `json:"atMs"`
	Success   bool    `json:"success"`
	LatencyMs float64 `json:"latencyMs,omitempty"`
	Bytes     int64   `json:"bytes,omitempty"`
	GapMs     float64 `json:"gapMs,omitempty"`
	Error     string  `json:"error,omitempty"`
}

type Summary struct {
	Sent             int64   `json:"sent,omitempty"`
	Received         int64   `json:"received,omitempty"`
	Succeeded        int64   `json:"succeeded,omitempty"`
	Failed           int64   `json:"failed,omitempty"`
	SuccessPercent   float64 `json:"successPercent,omitempty"`
	LossPercent      float64 `json:"lossPercent,omitempty"`
	RTTP50Ms         float64 `json:"rttP50Ms,omitempty"`
	RTTP95Ms         float64 `json:"rttP95Ms,omitempty"`
	RTTP99Ms         float64 `json:"rttP99Ms,omitempty"`
	JitterP95Ms      float64 `json:"jitterP95Ms,omitempty"`
	MaxOutageMs      float64 `json:"maxOutageMs,omitempty"`
	MaxLossBurst     int64   `json:"maxLossBurst,omitempty"`
	TTFBMs           float64 `json:"ttfbMs,omitempty"`
	ThroughputMbps   float64 `json:"throughputMbps,omitempty"`
	StallCount       int64   `json:"stallCount,omitempty"`
	MaxStallMs       float64 `json:"maxStallMs,omitempty"`
	TransferredBytes int64   `json:"transferredBytes,omitempty"`
	DurationMs       float64 `json:"durationMs"`
}

type Run struct {
	ID         string        `json:"id"`
	State      string        `json:"state"`
	Request    PublicRequest `json:"request"`
	StartedAt  time.Time     `json:"startedAt"`
	FinishedAt *time.Time    `json:"finishedAt,omitempty"`
	Summary    Summary       `json:"summary"`
	Samples    []Sample      `json:"samples,omitempty"`
	Error      string        `json:"error,omitempty"`

	cancel func()
}
