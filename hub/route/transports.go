package route

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/transportstat"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

const (
	defaultTransportInterval = 1000
	minimumTransportInterval = 100
)

type transportSnapshotResponse struct {
	Sequence   uint64                   `json:"sequence"`
	Time       time.Time                `json:"time"`
	Transports []transportstat.Snapshot `json:"transports"`
}

func transportRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getTransports)
	r.Get("/events", getTransportEvents)
	return r
}

func getTransports(w http.ResponseWriter, r *http.Request) {
	interval, ok := parseTransportInterval(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Upgrade") != "websocket" {
		render.JSON(w, r, currentTransportSnapshot())
		return
	}

	conn, _, err := wsUpgrade(r, w)
	if err != nil {
		return
	}
	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		if err := json.NewEncoder(buf).Encode(currentTransportSnapshot()); err != nil {
			return err
		}
		return wsWriteServerText(conn, buf.Bytes())
	}
	if err := sendSnapshot(); err != nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if err := sendSnapshot(); err != nil {
			return
		}
	}
}

func getTransportEvents(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "websocket" {
		render.Status(r, http.StatusUpgradeRequired)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	events, cancel := transportstat.DefaultManager.Subscribe(256)
	defer cancel()
	conn, _, err := wsUpgrade(r, w)
	if err != nil {
		return
	}
	buf := &bytes.Buffer{}
	sendEvent := func(event transportstat.Event) error {
		buf.Reset()
		if err := json.NewEncoder(buf).Encode(event); err != nil {
			return err
		}
		return wsWriteServerText(conn, buf.Bytes())
	}
	if err := sendEvent(transportstat.Event{
		Sequence: transportstat.DefaultManager.Sequence(),
		Time:     time.Now(), Type: transportstat.EventHeartbeat,
	}); err != nil {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event := <-events:
			if err := sendEvent(event); err != nil {
				return
			}
		case now := <-heartbeat.C:
			if err := sendEvent(transportstat.Event{
				Sequence: transportstat.DefaultManager.Sequence(),
				Time:     now, Type: transportstat.EventHeartbeat,
			}); err != nil {
				return
			}
		}
	}
}

func parseTransportInterval(w http.ResponseWriter, r *http.Request) (time.Duration, bool) {
	interval := defaultTransportInterval
	if value := r.URL.Query().Get("interval"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < minimumTransportInterval {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return 0, false
		}
		interval = parsed
	}
	return time.Duration(interval) * time.Millisecond, true
}

func currentTransportSnapshot() transportSnapshotResponse {
	return transportSnapshotResponse{
		Sequence:   transportstat.DefaultManager.Sequence(),
		Time:       time.Now(),
		Transports: transportstat.DefaultManager.Snapshot(),
	}
}
