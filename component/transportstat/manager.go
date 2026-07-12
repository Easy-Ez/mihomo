package transportstat

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	EventTransportCreated     = "transport_created"
	EventTransportClosed      = "transport_closed"
	EventTransportReconnected = "transport_reconnected"
	EventPacketLoss           = "packet_loss"
	EventPTO                  = "pto"
	EventCwndCollapse         = "cwnd_collapse"
	EventHeartbeat            = "heartbeat"
)

type Snapshot struct {
	ID                         string    `json:"id"`
	Adapter                    string    `json:"adapter"`
	Protocol                   string    `json:"protocol"`
	LocalAddress               string    `json:"localAddress,omitempty"`
	RemoteAddress              string    `json:"remoteAddress,omitempty"`
	State                      string    `json:"state"`
	CreatedAt                  time.Time `json:"createdAt"`
	OpenStreams                int64     `json:"openStreams"`
	ReconnectTotal             uint64    `json:"reconnectTotal"`
	MinRTTMs                   float64   `json:"minRttMs,omitempty"`
	LatestRTTMs                float64   `json:"latestRttMs,omitempty"`
	SmoothedRTTMs              float64   `json:"smoothedRttMs,omitempty"`
	RTTVariationMs             float64   `json:"rttVariationMs,omitempty"`
	BytesSent                  uint64    `json:"bytesSent"`
	PacketsSent                uint64    `json:"packetsSent"`
	BytesReceived              uint64    `json:"bytesReceived"`
	PacketsReceived            uint64    `json:"packetsReceived"`
	BytesLostTotal             uint64    `json:"bytesLostTotal"`
	PacketsLostTotal           uint64    `json:"packetsLostTotal"`
	LossEventsTotal            uint64    `json:"lossEventsTotal"`
	PTOTotal                   uint64    `json:"ptoTotal"`
	CongestionWindow           uint64    `json:"congestionWindow,omitempty"`
	BytesInFlight              uint64    `json:"bytesInFlight,omitempty"`
	CongestionMetricsAvailable bool      `json:"congestionMetricsAvailable"`
	WriteCount                 uint64    `json:"writeCount"`
	WriteBlockedCount          uint64    `json:"writeBlockedCount"`
	WriteDurationTotalMicros   uint64    `json:"writeDurationTotalMicros"`
	MaxWriteDurationMicros     uint64    `json:"maxWriteDurationMicros"`
	LastWriteDurationMicros    uint64    `json:"lastWriteDurationMicros"`
	LastWriteAtUnixMs          int64     `json:"lastWriteAtUnixMs,omitempty"`
	LastError                  string    `json:"lastError,omitempty"`
}

type Provider interface {
	TransportSnapshot() Snapshot
}

type Event struct {
	Sequence    uint64    `json:"sequence"`
	Time        time.Time `json:"time"`
	Type        string    `json:"type"`
	TransportID string    `json:"transportId,omitempty"`
	Adapter     string    `json:"adapter,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Count       uint64    `json:"count,omitempty"`
	Delta       uint64    `json:"delta,omitempty"`
	Bytes       uint64    `json:"bytes,omitempty"`
	Before      uint64    `json:"before,omitempty"`
	After       uint64    `json:"after,omitempty"`
	Snapshot    *Snapshot `json:"snapshot,omitempty"`
}

type Manager struct {
	mu          sync.RWMutex
	providers   map[string]Provider
	subscribers map[uint64]chan Event
	seen        map[string]uint64
	subscriber  atomic.Uint64
	sequence    atomic.Uint64
}

func NewManager() *Manager {
	return &Manager{
		providers:   make(map[string]Provider),
		subscribers: make(map[uint64]chan Event),
		seen:        make(map[string]uint64),
	}
}

var DefaultManager = NewManager()

func (m *Manager) Register(provider Provider) uint64 {
	snapshot := provider.TransportSnapshot()
	key := snapshot.Protocol + "\x00" + snapshot.Adapter + "\x00" + snapshot.RemoteAddress

	m.mu.Lock()
	reconnectTotal := m.seen[key]
	m.seen[key] = reconnectTotal + 1
	m.providers[snapshot.ID] = provider
	m.mu.Unlock()

	m.Publish(Event{Type: EventTransportCreated, TransportID: snapshot.ID, Adapter: snapshot.Adapter, Protocol: snapshot.Protocol})
	if reconnectTotal > 0 {
		m.Publish(Event{Type: EventTransportReconnected, TransportID: snapshot.ID, Adapter: snapshot.Adapter, Protocol: snapshot.Protocol, Count: reconnectTotal})
	}
	return reconnectTotal
}

func (m *Manager) Unregister(id, reason string) {
	m.mu.Lock()
	provider, ok := m.providers[id]
	if ok {
		delete(m.providers, id)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	snapshot := provider.TransportSnapshot()
	snapshot.State = "closed"
	snapshot.LastError = reason
	m.Publish(Event{
		Type: EventTransportClosed, TransportID: id, Adapter: snapshot.Adapter, Protocol: snapshot.Protocol,
		Reason: reason, Snapshot: &snapshot,
	})
}

func (m *Manager) Snapshot() []Snapshot {
	m.mu.RLock()
	providers := make([]Provider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, provider)
	}
	m.mu.RUnlock()

	snapshots := make([]Snapshot, 0, len(providers))
	for _, provider := range providers {
		snapshots = append(snapshots, provider.TransportSnapshot())
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].CreatedAt.Before(snapshots[j].CreatedAt)
	})
	return snapshots
}

func (m *Manager) Publish(event Event) {
	event.Sequence = m.sequence.Add(1)
	if event.Time.IsZero() {
		event.Time = time.Now()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, subscriber := range m.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
}

func (m *Manager) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer < 1 {
		buffer = 1
	}
	id := m.subscriber.Add(1)
	ch := make(chan Event, buffer)
	m.mu.Lock()
	m.subscribers[id] = ch
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		delete(m.subscribers, id)
		m.mu.Unlock()
	}
}

func (m *Manager) Sequence() uint64 {
	return m.sequence.Load()
}
