package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

const samplePrometheusText = `
# HELP relay_active_sessions Number of currently active sessions by transport
# TYPE relay_active_sessions gauge
relay_active_sessions{transport="kcp"} 3
relay_active_sessions{transport="quic"} 12
relay_active_sessions{transport="tcp"} 26
relay_active_sessions{transport="ws"} 1
# HELP relay_buffer_bytes_total Total buffer capacity in bytes
# TYPE relay_buffer_bytes_total gauge
relay_buffer_bytes_total 67108864
# HELP relay_buffer_bytes_used Current bytes allocated in ring buffers
# TYPE relay_buffer_bytes_used gauge
relay_buffer_bytes_used 17056000
# HELP relay_buffer_utilization_ratio Ratio of ring buffer memory utilization (0.0 - 1.0)
# TYPE relay_buffer_utilization_ratio gauge
relay_buffer_utilization_ratio 0.254152774810791
# HELP relay_bytes_transferred_total Total bytes transferred by direction and transport
# TYPE relay_bytes_transferred_total counter
relay_bytes_transferred_total{direction="down",transport="quic"} 1205862400
relay_bytes_transferred_total{direction="up",transport="quic"} 257120000
# HELP relay_held_sessions_active Current number of sessions held in disconnected state
# TYPE relay_held_sessions_active gauge
relay_held_sessions_active 1
# HELP relay_process_uptime_seconds Process uptime in seconds
# TYPE relay_process_uptime_seconds gauge
relay_process_uptime_seconds 12252.5
# HELP relay_rbac_rejections_total Total RBAC connection rejections by reason
# TYPE relay_rbac_rejections_total counter
relay_rbac_rejections_total{reason="dest_forbidden"} 2
# HELP relay_reconnect_total Total reconnection attempts by status
# TYPE relay_reconnect_total counter
relay_reconnect_total{status="failure"} 1
relay_reconnect_total{status="success"} 14
# HELP relay_socks_streams_active Number of active SOCKS5 dynamic proxy streams
# TYPE relay_socks_streams_active gauge
relay_socks_streams_active 5
# HELP relay_standby_conns_active Current number of standby hot-carrier connections
# TYPE relay_standby_conns_active gauge
relay_standby_conns_active 2
# HELP relay_chain_hops_total Total onward chain hops established
# TYPE relay_chain_hops_total counter
relay_chain_hops_total 8
# HELP relay_splice_calls_total Total splice(2) system calls executed
# TYPE relay_splice_calls_total counter
relay_splice_calls_total 12410
# HELP relay_spliced_bytes_total Total bytes spliced via kernel splice(2)
# TYPE relay_spliced_bytes_total counter
relay_spliced_bytes_total{direction="in"} 398458880
relay_spliced_bytes_total{direction="out"} 1127428096
# HELP relay_accepts_total Total connections accepted
# TYPE relay_accepts_total counter
relay_accepts_total 120
# HELP relay_refused_total Total connections refused
# TYPE relay_refused_total counter
relay_refused_total 2
`

func TestParsePrometheusText(t *testing.T) {
	snap, err := ParsePrometheus([]byte(samplePrometheusText))
	if err != nil {
		t.Fatalf("unexpected error parsing Prometheus text: %v", err)
	}

	if snap.SessionsTCP != 26 {
		t.Errorf("expected 26 TCP sessions, got %d", snap.SessionsTCP)
	}
	if snap.SessionsQUIC != 12 {
		t.Errorf("expected 12 QUIC sessions, got %d", snap.SessionsQUIC)
	}
	if snap.SessionsKCP != 3 {
		t.Errorf("expected 3 KCP sessions, got %d", snap.SessionsKCP)
	}
	if snap.SessionsWS != 1 {
		t.Errorf("expected 1 WS session, got %d", snap.SessionsWS)
	}
	if snap.SessionsTotal != 42 {
		t.Errorf("expected 42 total sessions, got %d", snap.SessionsTotal)
	}
	if snap.SessionsHeld != 1 {
		t.Errorf("expected 1 held session, got %d", snap.SessionsHeld)
	}
	if snap.StandbyConns != 2 {
		t.Errorf("expected 2 standby conns, got %d", snap.StandbyConns)
	}
	if snap.SocksStreams != 5 {
		t.Errorf("expected 5 SOCKS streams, got %d", snap.SocksStreams)
	}
	if snap.BytesUpTotal != 257120000 {
		t.Errorf("expected 257120000 bytes up, got %d", snap.BytesUpTotal)
	}
	if snap.BytesDownTotal != 1205862400 {
		t.Errorf("expected 1205862400 bytes down, got %d", snap.BytesDownTotal)
	}
	if snap.ReconnectSuccess != 14 {
		t.Errorf("expected 14 reconnect successes, got %d", snap.ReconnectSuccess)
	}
	if snap.ReconnectFailure != 1 {
		t.Errorf("expected 1 reconnect failure, got %d", snap.ReconnectFailure)
	}
	if snap.TotalRBACRejects != 2 || snap.RBACRejections["dest_forbidden"] != 2 {
		t.Errorf("expected 2 RBAC rejections for dest_forbidden, got %d", snap.TotalRBACRejects)
	}
	if snap.SpliceCalls != 12410 {
		t.Errorf("expected 12410 splice calls, got %d", snap.SpliceCalls)
	}
	if snap.AcceptsTotal != 120 {
		t.Errorf("expected 120 accepts, got %d", snap.AcceptsTotal)
	}
	if snap.RefusedTotal != 2 {
		t.Errorf("expected 2 refused, got %d", snap.RefusedTotal)
	}
}

func TestSparklineRendering(t *testing.T) {
	vals := []float64{0, 10, 20, 30, 40, 50, 60, 70}
	spark := RenderSparkline(vals, 8)
	if len([]rune(spark)) != 8 {
		t.Fatalf("expected sparkline rune length 8, got %d (%s)", len([]rune(spark)), spark)
	}
	if !strings.HasPrefix(spark, " ") {
		t.Errorf("expected sparkline to start with lowest rune, got %s", spark)
	}
	if !strings.HasSuffix(spark, "█") {
		t.Errorf("expected sparkline to end with highest rune, got %s", spark)
	}

	// Flatline test
	flat := RenderSparkline([]float64{10, 10, 10, 10}, 4)
	if flat != "    " {
		t.Errorf("expected all lowest runes for flatline, got %q", flat)
	}
}

func TestRateTracker(t *testing.T) {
	tracker := NewRateTracker(10)
	t0 := time.Now()
	t1 := t0.Add(1 * time.Second)

	upRate, downRate := tracker.Update(t0, 1000, 2000)
	if upRate != 0 || downRate != 0 {
		t.Errorf("initial update should yield rate 0, got %f, %f", upRate, downRate)
	}

	upRate, downRate = tracker.Update(t1, 3000, 7000)
	if upRate != 2000 {
		t.Errorf("expected upRate 2000, got %f", upRate)
	}
	if downRate != 5000 {
		t.Errorf("expected downRate 5000, got %f", downRate)
	}
}

func TestRenderFrame(t *testing.T) {
	snap, err := ParsePrometheus([]byte(samplePrometheusText))
	if err != nil {
		t.Fatal(err)
	}

	renderer := NewRenderer(DashboardConfig{
		Endpoint: "http://127.0.0.1:9090/metrics",
		Interval: 1 * time.Second,
		Color:    "never",
	})
	tracker := NewRateTracker(10)

	frame := renderer.RenderFrame(snap, tracker, 80, nil)

	expectedSnippets := []string{
		"REMOTE-RELAY TOP",
		"Target: http://127.0.0.1:9090/metrics",
		"Active Transports & Multiplexing",
		"TCP: 26",
		"QUIC: 12",
		"KCP: 3",
		"WS: 1",
		"Throughput & Bandwidth Rates",
		"Upload:",
		"Download:",
		"Memory & Ring Buffer Utilization",
		"Buffer:",
		"Reliability, Resiliency & Security",
		"Reconnections: 14 ok",
		"RBAC Rejections: 2",
	}

	for _, snip := range expectedSnippets {
		if !strings.Contains(frame, snip) {
			t.Errorf("rendered frame missing expected snippet %q:\n%s", snip, frame)
		}
	}

	// Sad path error rendering
	errFrame := renderer.RenderFrame(nil, tracker, 80, errors.New("connection refused"))
	if !strings.Contains(errFrame, "CONNECTION WARNING") || !strings.Contains(errFrame, "connection refused") {
		t.Errorf("error frame missing disconnection warning:\n%s", errFrame)
	}
}

func TestFormatStats(t *testing.T) {
	snap, err := ParsePrometheus([]byte(samplePrometheusText))
	if err != nil {
		t.Fatal(err)
	}

	report := FormatStats(snap, "http://127.0.0.1:9090/metrics")

	requiredStrings := []string{
		"REMOTE-RELAY METRICS SNAPSHOT",
		"Total Live:     42",
		"Breakdown:      TCP: 26, QUIC: 12, KCP: 3, WS: 1",
		"Utilization:    25.4%",
		"Upload Total:",
		"Download Total:",
		"Reconnections:  14 success / 1 failure",
		"RBAC Rejects:   2 (dest_forbidden: 2)",
	}

	for _, req := range requiredStrings {
		if !strings.Contains(report, req) {
			t.Errorf("FormatStats report missing required snippet %q:\n%s", req, report)
		}
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "http://127.0.0.1:9090/metrics"},
		{"127.0.0.1:9090", "http://127.0.0.1:9090/metrics"},
		{"127.0.0.1:9090/metrics", "http://127.0.0.1:9090/metrics"},
		{"http://localhost:8080", "http://localhost:8080/metrics"},
		{"https://secure.example.com/custom/metrics", "https://secure.example.com/custom/metrics"},
	}

	for _, tc := range tests {
		out := NormalizeEndpoint(tc.input)
		if out != tc.expected {
			t.Errorf("NormalizeEndpoint(%q) = %q, expected %q", tc.input, out, tc.expected)
		}
	}
}

func TestRunStatsOutput(t *testing.T) {
	var buf bytes.Buffer
	opts := AppOptions{
		Endpoint: "http://invalid-non-existent-domain-4040.local/metrics",
	}
	err := RunStats(opts, &buf)
	if err == nil {
		t.Error("expected error scraping non-existent host, got nil")
	}
}
