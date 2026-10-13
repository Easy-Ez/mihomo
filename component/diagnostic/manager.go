package diagnostic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

var (
	ErrNotFound = errors.New("diagnostic run not found")
	ErrBusy     = errors.New("too many active diagnostic runs")
)

type DialerFactory func(proxy string) (dialer C.Dialer, supportsUDP bool, err error)

type Manager struct {
	mu      sync.RWMutex
	runs    map[string]*Run
	order   []string
	active  int
	maxRuns int
	factory DialerFactory
}

func NewManager(factory DialerFactory) *Manager {
	return &Manager{runs: make(map[string]*Run), maxRuns: 4, factory: factory}
}

func (m *Manager) Start(request StartRequest) (Run, error) {
	request = defaults(request)
	if err := validate(request); err != nil {
		return Run{}, err
	}
	dialer, supportsUDP, err := m.factory(request.Proxy)
	if err != nil {
		return Run{}, err
	}
	if request.Profile == ProfileGame && !supportsUDP {
		return Run{}, fmt.Errorf("proxy %q does not support UDP", request.Proxy)
	}
	m.mu.Lock()
	if m.active >= m.maxRuns {
		m.mu.Unlock()
		return Run{}, ErrBusy
	}
	id, err := newID()
	if err != nil {
		m.mu.Unlock()
		return Run{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &Run{ID: id, State: "running", Request: publicRequest(request), StartedAt: time.Now().UTC(), cancel: cancel}
	m.runs[id] = run
	m.order = append([]string{id}, m.order...)
	m.active++
	if len(m.order) > 100 {
		delete(m.runs, m.order[len(m.order)-1])
		m.order = m.order[:len(m.order)-1]
	}
	result := cloneRun(run)
	m.mu.Unlock()
	go m.execute(ctx, id, dialer, request)
	return result, nil
}

func (m *Manager) execute(ctx context.Context, id string, dialer C.Dialer, request StartRequest) {
	var summary Summary
	var samples []Sample
	var err error
	emit := func(sample Sample) {
		m.appendSample(id, sample)
	}
	switch request.Profile {
	case ProfileGame:
		summary, samples, err = runGame(ctx, dialer, request, emit)
	case ProfileWeb:
		summary, samples, err = runWeb(ctx, dialer, request, emit)
	case ProfileVideo:
		summary, samples, err = runVideo(ctx, dialer, request, emit)
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return
	}
	run.Summary, run.Samples, run.FinishedAt, run.cancel = summary, samples, &now, nil
	if err != nil {
		run.Error = err.Error()
		if errors.Is(err, context.Canceled) {
			run.State = "cancelled"
		} else {
			run.State = "failed"
		}
	} else {
		run.State = "completed"
	}
	m.active--
}

func (m *Manager) appendSample(id string, sample Sample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run := m.runs[id]; run != nil && run.State == "running" {
		run.Samples = append(run.Samples, sample)
	}
}

func (m *Manager) Get(id string) (Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, ok := m.runs[id]
	if !ok {
		return Run{}, ErrNotFound
	}
	return cloneRun(run), nil
}

func (m *Manager) List() []Run {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Run, 0, len(m.order))
	for _, id := range m.order {
		if run := m.runs[id]; run != nil {
			result = append(result, cloneRun(run))
		}
	}
	return result
}

func (m *Manager) Cancel(id string) error {
	m.mu.RLock()
	run, ok := m.runs[id]
	if !ok {
		m.mu.RUnlock()
		return ErrNotFound
	}
	cancel := run.cancel
	m.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func defaults(r StartRequest) StartRequest {
	if r.Port == 0 {
		r.Port = 46080
	}
	if r.DurationMs == 0 {
		r.DurationMs = 30_000
	}
	if r.IntervalMs == 0 {
		r.IntervalMs = 100
	}
	if r.PacketSize == 0 {
		r.PacketSize = 256
	}
	if r.DownloadBytes == 0 {
		r.DownloadBytes = 8 << 20
	}
	return r
}

func validate(r StartRequest) error {
	if strings.TrimSpace(r.Proxy) == "" || strings.TrimSpace(r.Target) == "" || strings.TrimSpace(r.Token) == "" {
		return errors.New("proxy, target and token are required")
	}
	if net.ParseIP(r.Target) == nil {
		return errors.New("target must be an IP address")
	}
	if r.Profile != ProfileGame && r.Profile != ProfileWeb && r.Profile != ProfileVideo {
		return errors.New("profile must be game, web or video")
	}
	if r.DurationMs < 1_000 || r.DurationMs > 600_000 {
		return errors.New("durationMs must be between 1000 and 600000")
	}
	if r.IntervalMs < 50 || r.IntervalMs > 10_000 {
		return errors.New("intervalMs must be between 50 and 10000")
	}
	if r.PacketSize < udpHeaderSize || r.PacketSize > 1400 {
		return fmt.Errorf("packetSize must be between %d and 1400", udpHeaderSize)
	}
	if r.DownloadBytes < 1 || r.DownloadBytes > 64<<20 {
		return errors.New("downloadBytes must be between 1 and 67108864")
	}
	if r.RateMbps < 0 || r.RateMbps > 1000 {
		return errors.New("rateMbps must be between 0 and 1000")
	}
	return nil
}

func publicRequest(r StartRequest) PublicRequest {
	return PublicRequest{Proxy: r.Proxy, Profile: r.Profile, Target: r.Target, Port: r.Port, TokenConfigured: r.Token != "", DurationMs: r.DurationMs, IntervalMs: r.IntervalMs, PacketSize: r.PacketSize, DownloadBytes: r.DownloadBytes, RateMbps: r.RateMbps}
}

func cloneRun(run *Run) Run {
	value := *run
	value.cancel = nil
	value.Samples = append([]Sample(nil), run.Samples...)
	return value
}

func newID() (string, error) {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
