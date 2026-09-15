package transport

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/remote-relay/relay/internal/proto"
	kcp "github.com/xtaci/kcp-go/v5"
)

type mockSampler struct {
	mu          sync.Mutex
	outSegs     uint64
	retransSegs uint64
	lostSegs    uint64
	sndQueue    uint64
	sndBuf      uint64
	srtt        int32
	rto         uint32
}

func (m *mockSampler) SampleMetrics() (outSegs, retransSegs, lostSegs, sndQueue, sndBuf uint64, srtt int32, rto uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outSegs, m.retransSegs, m.lostSegs, m.sndQueue, m.sndBuf, m.srtt, m.rto
}

func (m *mockSampler) setMetrics(out, retrans, lost, sndQ, sndB uint64, srtt int32, rto uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outSegs = out
	m.retransSegs = retrans
	m.lostSegs = lost
	m.sndQueue = sndQ
	m.sndBuf = sndB
	m.srtt = srtt
	m.rto = rto
}

func TestAdaptiveKCPConfigDefaults(t *testing.T) {
	cfg := DefaultAdaptiveKCPConfig()
	if !cfg.Enabled {
		t.Fatal("expected Enabled to be true by default")
	}
	if cfg.LowLossThreshold != 0.005 {
		t.Fatalf("expected LowLossThreshold=0.005, got %v", cfg.LowLossThreshold)
	}
	if cfg.HighLossThreshold != 0.03 {
		t.Fatalf("expected HighLossThreshold=0.03, got %v", cfg.HighLossThreshold)
	}
	if cfg.LowLossInterval != 30 {
		t.Fatalf("expected LowLossInterval=30, got %d", cfg.LowLossInterval)
	}
	if cfg.LowLossResend != 1 {
		t.Fatalf("expected LowLossResend=1, got %d", cfg.LowLossResend)
	}
	if cfg.LowLossNC != 0 {
		t.Fatalf("expected LowLossNC=0, got %d", cfg.LowLossNC)
	}
	if cfg.HighLossInterval != 10 {
		t.Fatalf("expected HighLossInterval=10, got %d", cfg.HighLossInterval)
	}
	if cfg.HighLossResend != 2 {
		t.Fatalf("expected HighLossResend=2, got %d", cfg.HighLossResend)
	}
	if cfg.HighLossNC != 1 {
		t.Fatalf("expected HighLossNC=1, got %d", cfg.HighLossNC)
	}
}

func TestAdaptiveTunerStateTransitions(t *testing.T) {
	cfg := DefaultAdaptiveKCPConfig()
	cfg.StabilizationTicks = 2
	cfg.HistoryWindowSize = 5

	tuner := NewAdaptiveTuner(nil, cfg)
	mock := &mockSampler{}
	tuner.SetSampler(mock)

	var transitions []string
	tuner.SetOnTransition(func(from, to TunerState, stats TunerStats) {
		transitions = append(transitions, string(from)+"->"+string(to))
	})

	// Step 1: Initial step with zero loss
	mock.setMetrics(100, 0, 0, 0, 0, 20, 40)
	s := tuner.Step()
	if s.State != StateLowLoss {
		t.Fatalf("expected initial state %s, got %s", StateLowLoss, s.State)
	}
	if s.Interval != 30 || s.Resend != 1 || s.NoCongestion != 0 {
		t.Fatalf("expected (30, 1, 0), got (%d, %d, %d)", s.Interval, s.Resend, s.NoCongestion)
	}

	// Step 2: Still clean link (out=200, retrans=0)
	mock.setMetrics(200, 0, 0, 0, 0, 20, 40)
	s = tuner.Step()
	if s.State != StateLowLoss {
		t.Fatalf("expected %s, got %s", StateLowLoss, s.State)
	}

	// Step 3: Packet loss spike: 100 packets sent, 5 retransmissions (5% loss > 3%)
	mock.setMetrics(300, 5, 2, 5, 2, 35, 70)
	s = tuner.Step()
	if s.State != StateHighLoss {
		t.Fatalf("expected fast-attack transition to %s, got %s (moving loss=%f)", StateHighLoss, s.State, s.MovingLossRate)
	}
	if s.Interval != 10 || s.Resend != 2 || s.NoCongestion != 1 {
		t.Fatalf("expected high loss params (10, 2, 1), got (%d, %d, %d)", s.Interval, s.Resend, s.NoCongestion)
	}
	if s.Transitions != 1 {
		t.Fatalf("expected 1 transition, got %d", s.Transitions)
	}

	// Step 4: Sustained loss: another 100 packets sent, 4 retransmissions (4% loss)
	mock.setMetrics(400, 9, 3, 4, 1, 40, 80)
	s = tuner.Step()
	if s.State != StateHighLoss {
		t.Fatalf("expected sustained %s, got %s", StateHighLoss, s.State)
	}

	// Step 5: Loss clears (0 drops on 100 packets)
	// Window still has historical drops from steps 3 and 4, so state may be moderate or high
	mock.setMetrics(500, 9, 3, 0, 0, 25, 50)
	s = tuner.Step()

	// Steps 6, 7, 8: Clean packets push out loss from sliding window
	mock.setMetrics(600, 9, 3, 0, 0, 20, 40)
	tuner.Step()
	mock.setMetrics(700, 9, 3, 0, 0, 20, 40)
	tuner.Step()
	mock.setMetrics(800, 9, 3, 0, 0, 20, 40)
	tuner.Step()

	// Step 9: Clean link first tick (consecutiveLowLoss = 1, waiting for stabilization)
	mock.setMetrics(900, 9, 3, 0, 0, 20, 40)
	s = tuner.Step()
	if s.MovingLossRate != 0 {
		t.Fatalf("expected moving loss rate 0, got %f", s.MovingLossRate)
	}

	// Step 10: Clean link sustained past stabilization ticks (consecutiveLowLoss = 2 >= StabilizationTicks)
	mock.setMetrics(1000, 9, 3, 0, 0, 20, 40)
	s = tuner.Step()
	if s.State != StateLowLoss {
		t.Fatalf("expected recovery to %s, got %s (moving loss=%f)", StateLowLoss, s.State, s.MovingLossRate)
	}
	if s.Interval != 30 || s.Resend != 1 || s.NoCongestion != 0 {
		t.Fatalf("expected low loss params (30, 1, 0), got (%d, %d, %d)", s.Interval, s.Resend, s.NoCongestion)
	}
}

func TestAdaptiveTunerQueueBackpressure(t *testing.T) {
	cfg := DefaultAdaptiveKCPConfig()
	cfg.QueueThreshold = 10
	cfg.StabilizationTicks = 1

	tuner := NewAdaptiveTuner(nil, cfg)
	mock := &mockSampler{}
	tuner.SetSampler(mock)

	// Step 1: Initial clean link
	mock.setMetrics(100, 0, 0, 0, 0, 10, 20)
	tuner.Step()

	// Step 2: Clean link with low queue length
	mock.setMetrics(200, 0, 0, 5, 0, 10, 20)
	s := tuner.Step()
	if s.State != StateLowLoss || s.Interval != 30 || s.NoCongestion != 0 {
		t.Fatalf("expected (30, 1, 0), got (%d, %d, %d)", s.Interval, s.Resend, s.NoCongestion)
	}

	// Step 3: Clean link but send queue spikes above threshold (queue=15 > 10)
	mock.setMetrics(300, 0, 0, 15, 0, 10, 20)
	s = tuner.Step()
	if s.State != StateLowLoss {
		t.Fatalf("expected state %s, got %s", StateLowLoss, s.State)
	}
	// Interval should reduce to ModerateInterval (20ms) to drain queue while preserving nc=0
	if s.Interval != 20 || s.NoCongestion != 0 {
		t.Fatalf("expected queue backpressure adaptation (20, 1, 0), got (%d, %d, %d)", s.Interval, s.Resend, s.NoCongestion)
	}
}

func TestAdaptiveTunerIdleDecayAndWrap(t *testing.T) {
	cfg := DefaultAdaptiveKCPConfig()
	tuner := NewAdaptiveTuner(nil, cfg)
	mock := &mockSampler{}
	tuner.SetSampler(mock)

	// Step 1: Initial
	mock.setMetrics(100, 0, 0, 0, 0, 10, 20)
	tuner.Step()

	// Step 2: Loss spike
	mock.setMetrics(200, 10, 2, 0, 0, 10, 20)
	s := tuner.Step()
	if s.State != StateHighLoss {
		t.Fatalf("expected %s, got %s", StateHighLoss, s.State)
	}

	// Step 3: Link goes completely idle (no new packets)
	for i := 0; i < 10; i++ {
		s = tuner.Step()
	}
	if s.MovingLossRate != 0 {
		t.Fatalf("expected loss rate to decay to 0 on idle link, got %f", s.MovingLossRate)
	}

	// Step 4: Counter reset (e.g. SNMP reset from 200 to 10)
	mock.setMetrics(10, 0, 0, 0, 0, 10, 20)
	s = tuner.Step()
	if s.MovingLossRate < 0 {
		t.Fatalf("expected non-negative loss rate after reset, got %f", s.MovingLossRate)
	}
}

func TestAdaptiveKCPIntegrationE2E(t *testing.T) {
	srvMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvMux.Close()

	srvCfg := DefaultAdaptiveKCPConfig()
	srvCfg.CheckInterval = 20 * time.Millisecond
	ln, err := ListenKCPWithOptions(srvMux.KCP(), srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		provider, ok := conn.(KCPStatsProvider)
		if !ok {
			t.Errorf("server conn does not implement KCPStatsProvider")
			return
		}
		stats, ok := provider.AdaptiveKCPStats()
		if !ok || !stats.Enabled {
			t.Errorf("expected stats.Enabled=true, got %+v", stats)
			return
		}

		f, err := conn.ReadFrame()
		if err != nil {
			t.Errorf("server ReadFrame: %v", err)
			return
		}
		_ = conn.WriteFrame(proto.Frame{Type: proto.TypePong, Payload: f.Payload})
	}()

	cliMux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliMux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cliCfg := DefaultAdaptiveKCPConfig()
	cliCfg.CheckInterval = 20 * time.Millisecond
	cli, err := DialKCPWithOptions(ctx, cliMux.KCP(), srvMux.LocalAddr(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	provider, ok := cli.(KCPStatsProvider)
	if !ok {
		t.Fatalf("client conn does not implement KCPStatsProvider")
	}
	stats, ok := provider.AdaptiveKCPStats()
	if !ok || !stats.Enabled {
		t.Fatalf("expected client stats.Enabled=true, got %+v", stats)
	}

	payload := bytes.Repeat([]byte("adaptive-kcp-payload-"), 50)
	if err := cli.WriteFrame(proto.Frame{Type: proto.TypePing, Payload: payload}); err != nil {
		t.Fatal(err)
	}

	pong, err := cli.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if pong.Type != proto.TypePong || !bytes.Equal(pong.Payload, payload) {
		t.Fatalf("pong mismatch")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func TestAdaptiveKCPDisabled(t *testing.T) {
	mux, err := ListenUDPMux("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	cfg := DefaultAdaptiveKCPConfig()
	cfg.Enabled = false

	sess, err := kcp.NewConn2(mux.LocalAddr(), nil, 0, 0, mux.KCP())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	conn := wrapKCPWithConfig(sess, cfg)
	defer conn.Close()

	provider, ok := conn.(KCPStatsProvider)
	if !ok {
		t.Fatalf("expected conn to implement KCPStatsProvider")
	}
	stats, ok := provider.AdaptiveKCPStats()
	if ok || stats.Enabled {
		t.Fatalf("expected tuner to be disabled, got ok=%v, stats=%+v", ok, stats)
	}
}
