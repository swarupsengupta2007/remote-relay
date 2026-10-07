package transport

import (
	"context"
	"math"
	"reflect"
	"sync"
	"time"
	"unsafe"

	kcp "github.com/xtaci/kcp-go/v5"
)

// TunerState represents the current ARQ and congestion tuning state.
type TunerState string

const (
	// StateLowLoss represents clean links (<0.5% loss): throttled flush (30ms), resend=1, Reno congestion control.
	StateLowLoss TunerState = "low_loss"
	// StateModerate represents moderate loss links (0.5% - 3.0% loss): balanced flush (20ms), resend=2, Reno congestion control.
	StateModerate TunerState = "moderate"
	// StateHighLoss represents lossy links (>3.0% loss): high frequency flush (10ms), resend=2, no congestion window throttling.
	StateHighLoss TunerState = "high_loss"
)

// AdaptiveKCPConfig configures dynamic ARQ and congestion tuning for KCP sessions.
type AdaptiveKCPConfig struct {
	Enabled            bool          `toml:"adaptive_kcp"`
	CheckInterval      time.Duration // Sampling evaluation interval (default 100ms)
	LowLossThreshold   float64       // Loss rate threshold for low-loss mode (default 0.005, i.e. 0.5%)
	HighLossThreshold  float64       // Loss rate threshold for high-loss mode (default 0.03, i.e. 3.0%)
	QueueThreshold     int           // Send queue length threshold for congestion backpressure (default 32)
	LowLossInterval    int           // Flush interval (ms) on clean links (default 30ms)
	LowLossResend      int           // Fast retransmit count on clean links (default 1)
	LowLossNC          int           // Congestion control on clean links (default 0: active)
	HighLossInterval   int           // Flush interval (ms) on lossy links (default 10ms)
	HighLossResend     int           // Fast retransmit count on lossy links (default 2)
	HighLossNC         int           // Congestion control on lossy links (default 1: turbo)
	ModerateInterval   int           // Flush interval (ms) on moderate links (default 20ms)
	ModerateResend     int           // Fast retransmit count on moderate links (default 2)
	ModerateNC         int           // Congestion control on moderate links (default 0: active)
	StabilizationTicks int           // Consecutive clean samples required before downscaling (default 2)
	HistoryWindowSize  int           // Size of the sliding history window (default 5 samples)
}

// DefaultAdaptiveKCPConfig returns the production configuration for dynamic ARQ tuning.
func DefaultAdaptiveKCPConfig() AdaptiveKCPConfig {
	return AdaptiveKCPConfig{
		Enabled:            true,
		CheckInterval:      100 * time.Millisecond,
		LowLossThreshold:   0.005, // <0.5% loss
		HighLossThreshold:  0.03,  // >3.0% loss
		QueueThreshold:     32,
		LowLossInterval:    30, // 30ms flush
		LowLossResend:      1,  // Fast retransmit 1
		LowLossNC:          0,  // Congestion control enabled (saves mobile quota)
		HighLossInterval:   10, // 10ms flush (fast recovery)
		HighLossResend:     2,  // Fast retransmit 2
		HighLossNC:         1,  // Turbo mode (bypasses cwnd collapse)
		ModerateInterval:   20, // 20ms flush
		ModerateResend:     2,
		ModerateNC:         0,
		StabilizationTicks: 2, // 200ms of sustained clean link before downscaling
		HistoryWindowSize:  5, // 5 samples = 500ms sliding window
	}
}

// TunerStats provides an observable snapshot of the KCP session's adaptive state.
type TunerStats struct {
	Enabled        bool       `json:"enabled"`
	State          TunerState `json:"state"`
	MovingLossRate float64    `json:"moving_loss_rate"`
	SendQueueLen   int        `json:"send_queue_len"`
	SendBufLen     int        `json:"send_buf_len"`
	SRTT           int32      `json:"srtt_ms"`
	RTO            uint32     `json:"rto_ms"`
	Interval       int        `json:"interval_ms"`
	Resend         int        `json:"resend"`
	NoCongestion   int        `json:"no_congestion"`
	Transitions    uint64     `json:"transitions"`
	TotalSamples   uint64     `json:"total_samples"`
}

// MetricsSampler provides transport metrics for the adaptive controller.
type MetricsSampler interface {
	SampleMetrics() (outSegs, retransSegs, lostSegs, sndQueue, sndBuf uint64, srtt int32, rto uint32)
}

// defaultSampler counts transmits from this session's snd_buf. Loss on one
// session must not move another session's tuner, so it does not read the
// process-global SNMP counters.
type defaultSampler struct {
	sess    *kcp.UDPSession
	seen    map[uint32]uint32 // sn -> last observed xmit
	out     uint64
	retrans uint64
}

func (s *defaultSampler) SampleMetrics() (outSegs, retransSegs, lostSegs, sndQueue, sndBuf uint64, srtt int32, rto uint32) {
	if s == nil || s.sess == nil {
		return
	}
	// GetSRTT and GetRTO take the session lock themselves.
	srtt = s.sess.GetSRTT()
	rto = s.sess.GetRTO()
	outSegs, retransSegs, sndQueue, sndBuf = s.sampleLocked()
	return
}

func (s *defaultSampler) sampleLocked() (out, retrans, sndQueue, sndBuf uint64) {
	if s.seen == nil {
		s.seen = make(map[uint32]uint32)
	}
	sessVal := reflect.ValueOf(s.sess).Elem()
	muField := sessVal.FieldByName("mu")
	kcpField := sessVal.FieldByName("kcp")
	if !muField.IsValid() || !kcpField.IsValid() || kcpField.IsNil() {
		return s.out, s.retrans, 0, 0
	}
	mu := (*sync.Mutex)(unsafe.Pointer(muField.UnsafeAddr()))
	mu.Lock()
	defer mu.Unlock()

	kcpVal := kcpField.Elem()
	sndQueue = uint64(ringLen(kcpVal.FieldByName("snd_queue")))
	sndBufV := kcpVal.FieldByName("snd_buf")
	sndBuf = uint64(ringLen(sndBufV))

	present := make(map[uint32]struct{})
	walkRing(sndBufV, func(sn, xmit uint32) {
		present[sn] = struct{}{}
		prev, ok := s.seen[sn]
		switch {
		case !ok:
			if xmit > 0 {
				s.out += uint64(xmit)
				s.retrans += uint64(xmit - 1)
			}
			s.seen[sn] = xmit
		case xmit > prev:
			delta := xmit - prev
			s.out += uint64(delta)
			if prev == 0 {
				s.retrans += uint64(delta - 1)
			} else {
				s.retrans += uint64(delta)
			}
			s.seen[sn] = xmit
		}
	})
	for sn := range s.seen {
		if _, ok := present[sn]; !ok {
			delete(s.seen, sn)
		}
	}
	return s.out, s.retrans, sndQueue, sndBuf
}

// ringLen and walkRing read a kcp RingBuffer without calling its methods.
// Those methods are not callable through reflect when the buffer is reached
// via an unexported session field.
func ringLen(v reflect.Value) int {
	v = deref(v)
	if !v.IsValid() {
		return 0
	}
	head := int(v.FieldByName("head").Int())
	tail := int(v.FieldByName("tail").Int())
	n := v.FieldByName("elements").Len()
	if n == 0 || head == tail {
		return 0
	}
	if head < tail {
		return tail - head
	}
	return n - head + tail
}

func walkRing(v reflect.Value, fn func(sn, xmit uint32)) {
	v = deref(v)
	if !v.IsValid() {
		return
	}
	head := int(v.FieldByName("head").Int())
	tail := int(v.FieldByName("tail").Int())
	elements := v.FieldByName("elements")
	n := elements.Len()
	if n == 0 || head == tail {
		return
	}
	visit := func(i int) {
		seg := elements.Index(i)
		fn(uint32(seg.FieldByName("sn").Uint()), uint32(seg.FieldByName("xmit").Uint()))
	}
	if head < tail {
		for i := head; i < tail; i++ {
			visit(i)
		}
		return
	}
	for i := head; i < n; i++ {
		visit(i)
	}
	for i := 0; i < tail; i++ {
		visit(i)
	}
}

func deref(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return reflect.Value{}
		}
		return v.Elem()
	}
	return v
}

type sampleDelta struct {
	out     uint64
	retrans uint64
}

// AdaptiveTuner monitors moving loss rate and send queue length, dynamically adjusting
// KCP ARQ parameters (interval, resend, nc) to balance bandwidth efficiency and throughput.
type AdaptiveTuner struct {
	sess    *kcp.UDPSession
	cfg     AdaptiveKCPConfig
	sampler MetricsSampler

	mu                 sync.RWMutex
	state              TunerState
	curInterval        int
	curResend          int
	curNC              int
	movingLossRate     float64
	sndQueueLen        int
	sndBufLen          int
	srtt               int32
	rto                uint32
	transitions        uint64
	totalSamples       uint64
	consecutiveLowLoss int

	windowDeltas []sampleDelta
	windowIdx    int

	lastOutSegs     uint64
	lastRetransSegs uint64
	lastLostSegs    uint64
	initialized     bool

	onTransition func(from, to TunerState, stats TunerStats)

	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

// NewAdaptiveTuner creates a new tuner for the specified KCP session.
func NewAdaptiveTuner(sess *kcp.UDPSession, cfg AdaptiveKCPConfig) *AdaptiveTuner {
	if cfg.HistoryWindowSize <= 0 {
		cfg.HistoryWindowSize = 5
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 100 * time.Millisecond
	}
	if cfg.StabilizationTicks <= 0 {
		cfg.StabilizationTicks = 2
	}
	return &AdaptiveTuner{
		sess:         sess,
		cfg:          cfg,
		sampler:      &defaultSampler{sess: sess},
		windowDeltas: make([]sampleDelta, 0, cfg.HistoryWindowSize),
	}
}

// SetSampler replaces the metrics sampler (useful for unit testing).
func (t *AdaptiveTuner) SetSampler(s MetricsSampler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sampler = s
}

// SetOnTransition sets an optional callback when the tuning state changes.
func (t *AdaptiveTuner) SetOnTransition(cb func(from, to TunerState, stats TunerStats)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onTransition = cb
}

// Start launches the background monitoring goroutine.
func (t *AdaptiveTuner) Start() {
	if !t.cfg.Enabled || t.sess == nil {
		return
	}
	t.mu.Lock()
	if t.cancel != nil {
		t.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.done = make(chan struct{})
	t.mu.Unlock()

	go func() {
		defer close(t.done)
		ticker := time.NewTicker(t.cfg.CheckInterval)
		defer ticker.Stop()

		// Initial sample
		t.Step()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.Step()
			}
		}
	}()
}

// Stop gracefully terminates the background monitoring goroutine.
func (t *AdaptiveTuner) Stop() {
	t.stopOnce.Do(func() {
		t.mu.Lock()
		cancel := t.cancel
		done := t.done
		t.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
	})
}

// Step performs a single evaluation and tuning adjustment. It is thread-safe.
func (t *AdaptiveTuner) Step() TunerStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.sampler == nil {
		return t.statsLocked()
	}

	out, retrans, lost, sndQ, sndBuf, srtt, rto := t.sampler.SampleMetrics()
	t.sndQueueLen = int(sndQ)
	t.sndBufLen = int(sndBuf)
	t.srtt = srtt
	t.rto = rto
	t.totalSamples++

	if !t.initialized {
		t.lastOutSegs = out
		t.lastRetransSegs = retrans
		t.lastLostSegs = lost
		t.initialized = true
		// Apply initial low loss parameters if link starts clean
		t.applyParametersLocked(t.cfg.LowLossInterval, t.cfg.LowLossResend, t.cfg.LowLossNC, StateLowLoss)
		return t.statsLocked()
	}

	var dOut, dRetrans uint64
	if out >= t.lastOutSegs {
		dOut = out - t.lastOutSegs
	} else {
		// Counter reset or wrap
		dOut = out
	}
	if retrans >= t.lastRetransSegs {
		dRetrans = retrans - t.lastRetransSegs
	} else {
		dRetrans = retrans
	}
	t.lastOutSegs = out
	t.lastRetransSegs = retrans
	t.lastLostSegs = lost

	// Push sample into sliding history window
	if len(t.windowDeltas) < t.cfg.HistoryWindowSize {
		t.windowDeltas = append(t.windowDeltas, sampleDelta{out: dOut, retrans: dRetrans})
	} else {
		t.windowDeltas[t.windowIdx] = sampleDelta{out: dOut, retrans: dRetrans}
		t.windowIdx = (t.windowIdx + 1) % t.cfg.HistoryWindowSize
	}

	var totalOut, totalRetrans uint64
	for _, w := range t.windowDeltas {
		totalOut += w.out
		totalRetrans += w.retrans
	}

	var sampleLossRate float64
	if totalOut > 0 {
		sampleLossRate = float64(totalRetrans) / float64(totalOut)
	}

	var tickLossRate float64
	if dOut > 0 {
		tickLossRate = float64(dRetrans) / float64(dOut)
	}

	// Update moving loss rate: fast attack on loss spike, EWMA otherwise, decay on idle
	if totalOut == 0 || dOut == 0 {
		t.movingLossRate = t.movingLossRate * 0.5
		if t.movingLossRate < 0.001 {
			t.movingLossRate = 0
		}
	} else if totalRetrans == 0 {
		t.movingLossRate = 0
	} else if tickLossRate >= t.cfg.HighLossThreshold || sampleLossRate >= t.cfg.HighLossThreshold {
		// Fast-attack: immediately adopt high loss rate to react to loss spikes without filter delay
		t.movingLossRate = math.Max(tickLossRate, sampleLossRate)
	} else {
		// Smooth EWMA across samples
		const alpha = 0.5
		t.movingLossRate = alpha*sampleLossRate + (1.0-alpha)*t.movingLossRate
	}

	// Determine target state and parameters
	if t.movingLossRate >= t.cfg.HighLossThreshold {
		// Packet loss spike (>3.0%): scale up retransmission frequency (10ms, resend=2, nc=1)
		t.consecutiveLowLoss = 0
		t.applyParametersLocked(t.cfg.HighLossInterval, t.cfg.HighLossResend, t.cfg.HighLossNC, StateHighLoss)
	} else if t.movingLossRate < t.cfg.LowLossThreshold {
		// Low packet loss (<0.5%): throttle back to 30ms and resend=1 to conserve mobile quota
		t.consecutiveLowLoss++
		if t.consecutiveLowLoss >= t.cfg.StabilizationTicks {
			interval := t.cfg.LowLossInterval
			resend := t.cfg.LowLossResend
			nc := t.cfg.LowLossNC
			// If send queue is backing up, reduce flush interval to relieve queue pressure while preserving nc=0
			if t.sndQueueLen > t.cfg.QueueThreshold {
				interval = t.cfg.ModerateInterval
			}
			t.applyParametersLocked(interval, resend, nc, StateLowLoss)
		}
	} else {
		// Moderate packet loss (0.5% - 3.0%): balanced mode (20ms, resend=2, nc=0)
		t.consecutiveLowLoss = 0
		t.applyParametersLocked(t.cfg.ModerateInterval, t.cfg.ModerateResend, t.cfg.ModerateNC, StateModerate)
	}

	return t.statsLocked()
}

func (t *AdaptiveTuner) applyParametersLocked(interval, resend, nc int, newState TunerState) {
	oldState := t.state
	changed := t.curInterval != interval || t.curResend != resend || t.curNC != nc || t.state != newState
	if changed {
		t.curInterval = interval
		t.curResend = resend
		t.curNC = nc
		if t.state != "" && t.state != newState {
			t.transitions++
		}
		t.state = newState
		if t.sess != nil {
			t.sess.SetNoDelay(1, interval, resend, nc)
		}
		cb := t.onTransition
		if cb != nil && oldState != "" && oldState != newState {
			stats := t.statsLocked()
			cb(oldState, newState, stats)
		}
	}
}

// Stats returns a snapshot of current tuning metrics.
func (t *AdaptiveTuner) Stats() TunerStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.statsLocked()
}

func (t *AdaptiveTuner) statsLocked() TunerStats {
	return TunerStats{
		Enabled:        t.cfg.Enabled,
		State:          t.state,
		MovingLossRate: t.movingLossRate,
		SendQueueLen:   t.sndQueueLen,
		SendBufLen:     t.sndBufLen,
		SRTT:           t.srtt,
		RTO:            t.rto,
		Interval:       t.curInterval,
		Resend:         t.curResend,
		NoCongestion:   t.curNC,
		Transitions:    t.transitions,
		TotalSamples:   t.totalSamples,
	}
}
