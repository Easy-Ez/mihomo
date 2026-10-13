package diagnostic

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

const (
	udpMagic      = "LTP1"
	udpHeaderSize = 56
)

type sampleEmitter func(Sample)

func emitSample(samples *[]Sample, sample Sample, emit sampleEmitter) {
	*samples = append(*samples, sample)
	if emit != nil {
		emit(sample)
	}
}

func runGame(ctx context.Context, dialer C.Dialer, request StartRequest, emit sampleEmitter) (Summary, []Sample, error) {
	ip, _ := netip.ParseAddr(request.Target)
	remote := netip.AddrPortFrom(ip.Unmap(), request.Port)
	pc, err := dialer.ListenPacket(ctx, "udp", "", remote)
	if err != nil {
		return Summary{}, nil, err
	}
	defer pc.Close()
	udpAddr := net.UDPAddrFromAddrPort(remote)
	duration, interval := time.Duration(request.DurationMs)*time.Millisecond, time.Duration(request.IntervalMs)*time.Millisecond
	started := time.Now()
	runID := uint64(started.UnixNano())
	digest := sha256.Sum256([]byte(request.Token))
	var mu sync.Mutex
	sentAt, received := map[uint32]time.Time{}, map[uint32]bool{}
	samples := make([]Sample, 0, int(duration/interval)+1)
	readDone := make(chan error, 1)
	readStop := make(chan struct{})
	go func() {
		buffer := make([]byte, 64<<10)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, _, readErr := pc.ReadFrom(buffer)
			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					select {
					case <-readStop:
						readDone <- nil
						return
					case <-ctx.Done():
						readDone <- ctx.Err()
						return
					default:
					}
					if time.Since(started) > duration+2*time.Second {
						readDone <- nil
						return
					}
					continue
				}
				select {
				case <-readStop:
					readDone <- nil
					return
				default:
				}
				readDone <- readErr
				return
			}
			if n < udpHeaderSize || string(buffer[:4]) != udpMagic || string(buffer[4:20]) != string(digest[:16]) {
				continue
			}
			if binary.BigEndian.Uint64(buffer[20:28]) != runID {
				continue
			}
			seq := binary.BigEndian.Uint32(buffer[28:32])
			mu.Lock()
			sent, ok := sentAt[seq]
			if ok && !received[seq] {
				received[seq] = true
				emitSample(&samples, Sample{Sequence: int64(seq), AtMs: float64(time.Since(started).Microseconds()) / 1000, Success: true, LatencyMs: float64(time.Since(sent).Microseconds()) / 1000, Bytes: int64(n)}, emit)
			}
			mu.Unlock()
		}
	}()
	readerStopped := false
	stopReader := func() error {
		if readerStopped {
			return nil
		}
		readerStopped = true
		close(readStop)
		_ = pc.SetReadDeadline(time.Now())
		err := <-readDone
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
	snapshotSamples := func() []Sample {
		mu.Lock()
		defer mu.Unlock()
		return append([]Sample(nil), samples...)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var sequence uint32
	send := func() error {
		packet := make([]byte, request.PacketSize)
		copy(packet[:4], udpMagic)
		copy(packet[4:20], digest[:16])
		binary.BigEndian.PutUint64(packet[20:28], runID)
		binary.BigEndian.PutUint32(packet[28:32], sequence)
		now := time.Now()
		binary.BigEndian.PutUint64(packet[32:40], uint64(now.UnixNano()))
		mu.Lock()
		sentAt[sequence] = now
		mu.Unlock()
		_, writeErr := pc.WriteTo(packet, udpAddr)
		sequence++
		return writeErr
	}
	_ = send()
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			_ = stopReader()
			return Summary{}, snapshotSamples(), ctx.Err()
		case <-deadline.C:
			break loop
		case <-ticker.C:
			if err := send(); err != nil {
				_ = stopReader()
				return Summary{}, snapshotSamples(), err
			}
		}
	}
	grace := 3 * interval
	if grace > 2*time.Second {
		grace = 2 * time.Second
	}
	time.Sleep(grace)
	if err := stopReader(); err != nil {
		return Summary{}, snapshotSamples(), err
	}
	mu.Lock()
	summary := summarizeGame(started, sequence, received, samples, interval)
	finalSamples := append([]Sample(nil), samples...)
	mu.Unlock()
	return summary, finalSamples, nil
}

func summarizeGame(started time.Time, sent uint32, received map[uint32]bool, samples []Sample, interval time.Duration) Summary {
	latencies := make([]float64, 0, len(samples))
	bySeq := make(map[int64]float64, len(samples))
	for _, sample := range samples {
		latencies = append(latencies, sample.LatencyMs)
		bySeq[sample.Sequence] = sample.LatencyMs
	}
	jitter := make([]float64, 0, len(samples))
	var last float64
	haveLast := false
	var burst, maxBurst int64
	for seq := uint32(0); seq < sent; seq++ {
		if !received[seq] {
			burst++
			if burst > maxBurst {
				maxBurst = burst
			}
			continue
		}
		burst = 0
		if v, ok := bySeq[int64(seq)]; ok {
			if haveLast {
				jitter = append(jitter, math.Abs(v-last))
			}
			last = v
			haveLast = true
		}
	}
	receivedCount := int64(len(received))
	sentCount := int64(sent)
	loss := sentCount - receivedCount
	return Summary{Sent: sentCount, Received: receivedCount, Succeeded: receivedCount, Failed: loss, SuccessPercent: percent(receivedCount, sentCount), LossPercent: percent(loss, sentCount), RTTP50Ms: percentile(latencies, .5), RTTP95Ms: percentile(latencies, .95), RTTP99Ms: percentile(latencies, .99), JitterP95Ms: percentile(jitter, .95), MaxLossBurst: maxBurst, MaxOutageMs: float64(maxBurst) * float64(interval.Microseconds()) / 1000, DurationMs: float64(time.Since(started).Microseconds()) / 1000}
}

func runWeb(ctx context.Context, dialer C.Dialer, request StartRequest, emit sampleEmitter) (Summary, []Sample, error) {
	started := time.Now()
	duration := time.Duration(request.DurationMs) * time.Millisecond
	interval := time.Duration(request.IntervalMs) * time.Millisecond
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	samples := []Sample{}
	var seq int64
	for time.Since(started) < duration {
		one := time.Now()
		url := fmt.Sprintf("http://%s/ping?nonce=%d", net.JoinHostPort(request.Target, strconv.Itoa(int(request.Port))), seq)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return Summary{}, samples, err
		}
		req.Header.Set("Authorization", "Bearer "+request.Token)
		resp, err := client.Do(req)
		sample := Sample{Sequence: seq, AtMs: float64(time.Since(started).Microseconds()) / 1000, LatencyMs: float64(time.Since(one).Microseconds()) / 1000}
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			sample.Success = resp.StatusCode == http.StatusOK
			if !sample.Success {
				sample.Error = resp.Status
			}
		} else {
			sample.Error = err.Error()
		}
		emitSample(&samples, sample, emit)
		seq++
		select {
		case <-ctx.Done():
			return Summary{}, samples, ctx.Err()
		case <-time.After(interval):
		}
	}
	return summarizeRequests(started, samples), samples, nil
}

func runVideo(ctx context.Context, dialer C.Dialer, request StartRequest, emit sampleEmitter) (Summary, []Sample, error) {
	started := time.Now()
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute}
	url := fmt.Sprintf("http://%s/download?bytes=%d&rateMbps=%g", net.JoinHostPort(request.Target, strconv.Itoa(int(request.Port))), request.DownloadBytes, request.RateMbps)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Summary{}, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+request.Token)
	resp, err := client.Do(req)
	if err != nil {
		return Summary{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Summary{}, nil, fmt.Errorf("reflector returned %s", resp.Status)
	}
	first := time.Now()
	ttfb := float64(first.Sub(started).Microseconds()) / 1000
	buffer := make([]byte, 32<<10)
	samples := []Sample{}
	var total int64
	var stalls, maxStall float64
	var stallCount int64
	last := first
	var seq int64
	for {
		n, readErr := resp.Body.Read(buffer)
		now := time.Now()
		gap := float64(now.Sub(last).Microseconds()) / 1000
		if n > 0 {
			total += int64(n)
			sample := Sample{Sequence: seq, AtMs: float64(now.Sub(started).Microseconds()) / 1000, Success: true, Bytes: int64(n), GapMs: gap}
			emitSample(&samples, sample, emit)
			seq++
			if gap > 500 {
				stallCount++
				stalls += gap
				if gap > maxStall {
					maxStall = gap
				}
			}
			last = now
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Summary{}, samples, readErr
		}
	}
	elapsed := time.Since(started)
	_ = stalls
	return Summary{Succeeded: 1, SuccessPercent: 100, TTFBMs: ttfb, ThroughputMbps: float64(total*8) / elapsed.Seconds() / 1_000_000, StallCount: stallCount, MaxStallMs: maxStall, TransferredBytes: total, DurationMs: float64(elapsed.Microseconds()) / 1000}, samples, nil
}

func summarizeRequests(started time.Time, samples []Sample) Summary {
	values := []float64{}
	var success int64
	var burst, maxBurst int64
	for _, s := range samples {
		if s.Success {
			success++
			values = append(values, s.LatencyMs)
			burst = 0
		} else {
			burst++
			if burst > maxBurst {
				maxBurst = burst
			}
		}
	}
	total := int64(len(samples))
	failed := total - success
	return Summary{Sent: total, Received: success, Succeeded: success, Failed: failed, SuccessPercent: percent(success, total), LossPercent: percent(failed, total), RTTP50Ms: percentile(values, .5), RTTP95Ms: percentile(values, .95), RTTP99Ms: percentile(values, .99), MaxLossBurst: maxBurst, DurationMs: float64(time.Since(started).Microseconds()) / 1000}
}
func percentile(values []float64, fraction float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	index := fraction * float64(len(sorted)-1)
	lo, hi := int(math.Floor(index)), int(math.Ceil(index))
	if lo == hi {
		return sorted[lo]
	}
	return sorted[lo] + (sorted[hi]-sorted[lo])*(index-float64(lo))
}
func percent(value, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) * 100 / float64(total)
}
