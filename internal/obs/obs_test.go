package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsPrometheusFormat(t *testing.T) {
	m := NewMetrics()

	// Record sample metrics
	m.ActiveSessions.WithLabelValues("quic").Set(42)
	m.ActiveSessions.WithLabelValues("tcp").Set(10)
	m.ReconnectTotal.WithLabelValues("success").Add(5)
	m.ReconnectTotal.WithLabelValues("failure").Inc()
	m.ReconnectDuration.Observe(0.12)
	m.ReconnectDuration.Observe(1.4)
	m.HeldDuration.Observe(2.5)
	m.BytesTransferred.WithLabelValues("up", "quic").Add(1048576)
	m.BytesTransferred.WithLabelValues("down", "quic").Add(2097152)
	m.BufferUtilization.Set(0.45)
	m.HopChainDepth.Observe(2)
	m.SocksStreams.Set(3)
	m.RBACRejections.WithLabelValues("user_forbidden").Inc()
	m.AcceptsTotal.Add(100)
	m.RefusedTotal.Add(2)

	ts := httptest.NewServer(m.HTTPHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("http.Get error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %q", ct)
	}

	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		t.Fatalf("reading body error: %v", err)
	}
	body := buf.String()

	// Verify required Prometheus lines
	requiredSnippets := []string{
		`# HELP relay_active_sessions`,
		`# TYPE relay_active_sessions gauge`,
		`relay_active_sessions{transport="quic"} 42`,
		`relay_active_sessions{transport="tcp"} 10`,
		`# HELP relay_reconnect_total`,
		`# TYPE relay_reconnect_total counter`,
		`relay_reconnect_total{status="success"} 5`,
		`relay_reconnect_total{status="failure"} 1`,
		`# TYPE relay_reconnect_duration_seconds histogram`,
		`relay_reconnect_duration_seconds_bucket{le="0.1"} 0`,
		`relay_reconnect_duration_seconds_bucket{le="0.5"} 1`,
		`relay_reconnect_duration_seconds_bucket{le="2"} 2`,
		`relay_reconnect_duration_seconds_bucket{le="+Inf"} 2`,
		`relay_reconnect_duration_seconds_count 2`,
		`relay_bytes_transferred_total{direction="up",transport="quic"} 1048576`,
		`relay_bytes_transferred_total{direction="down",transport="quic"} 2097152`,
		`relay_buffer_utilization_ratio 0.45`,
		`relay_socks_streams_active 3`,
		`relay_rbac_rejections_total{reason="user_forbidden"} 1`,
		`relay_accepts_total 100`,
		`relay_refused_total 2`,
	}

	for _, snip := range requiredSnippets {
		if !strings.Contains(body, snip) {
			t.Errorf("missing expected Prometheus output snippet %q in body:\n%s", snip, body)
		}
	}
}

func TestConcurrentMetricUpdates(t *testing.T) {
	c := NewCounter()
	g := NewGauge()
	h := NewHistogram([]float64{1, 10, 100})

	const numGoroutines = 20
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				c.Inc()
				g.Add(1.0)
				g.Dec()
				h.Observe(float64(j % 50))
			}
		}()
	}
	wg.Wait()

	if val := c.Get(); val != float64(numGoroutines*iterations) {
		t.Errorf("expected counter %f, got %f", float64(numGoroutines*iterations), val)
	}
	if val := g.Get(); val != 0 {
		t.Errorf("expected gauge 0, got %f", val)
	}
	_, _, count, _ := h.Snapshot()
	if count != uint64(numGoroutines*iterations) {
		t.Errorf("expected histogram count %d, got %d", numGoroutines*iterations, count)
	}
}

func TestTraceparentParsingAndFormatting(t *testing.T) {
	raw := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, err := ParseTraceparent(raw)
	if err != nil {
		t.Fatalf("unexpected error parsing valid traceparent: %v", err)
	}
	if tc.Version != "00" {
		t.Errorf("expected version 00, got %s", tc.Version)
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected trace id 4bf92f3577b34da6a3ce929d0e0e4736, got %s", tc.TraceID)
	}
	if tc.SpanID != "00f067aa0ba902b7" {
		t.Errorf("expected span id 00f067aa0ba902b7, got %s", tc.SpanID)
	}
	if tc.Flags != "01" {
		t.Errorf("expected flags 01, got %s", tc.Flags)
	}

	formatted := FormatTraceparent(tc)
	if formatted != raw {
		t.Errorf("formatted %q != original %q", formatted, raw)
	}

	// Sad path checks
	invalidList := []string{
		"",
		"00",
		"00-1234-5678-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zeros trace ID
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zeros span ID
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz", // non-hex flags
	}
	for _, bad := range invalidList {
		if _, err := ParseTraceparent(bad); err == nil {
			t.Errorf("expected error for invalid traceparent %q, got nil", bad)
		}
	}
}

func TestTracerAndSpanHierarchy(t *testing.T) {
	tracer := NewTracer("test-relay", "")
	defer tracer.Close()

	ctx := context.Background()
	ctx, rootSpan := tracer.Start(ctx, "Handshake", WithAttribute("session_id", "s-123"))
	if rootSpan.TraceID == "" || rootSpan.SpanID == "" {
		t.Fatal("expected non-empty trace and span IDs")
	}

	// Child span should inherit TraceID and have ParentSpanID set to rootSpan.SpanID
	_, childSpan := tracer.Start(ctx, "Upgrade", WithAttribute("transport", "quic"))
	if childSpan.TraceID != rootSpan.TraceID {
		t.Errorf("expected child TraceID %s == root TraceID %s", childSpan.TraceID, rootSpan.TraceID)
	}
	if childSpan.ParentSpanID != rootSpan.SpanID {
		t.Errorf("expected child ParentSpanID %s == root SpanID %s", childSpan.ParentSpanID, rootSpan.SpanID)
	}

	childSpan.End()
	rootSpan.End()

	recent := tracer.RecentSpans()
	if len(recent) < 2 {
		t.Fatalf("expected at least 2 recent spans, got %d", len(recent))
	}
}

func TestOTLPPayloadSerialization(t *testing.T) {
	var capturedPayload []byte
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		mu.Lock()
		capturedPayload = buf.Bytes()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tracer := NewTracer("test-relay-service", server.URL)
	_, span := tracer.Start(context.Background(), "ChainHop", WithAttribute("hop", "1"))
	span.SetStatus("OK", "success")
	span.End()

	// Wait for worker to flush
	time.Sleep(700 * time.Millisecond)
	_ = tracer.Close()

	mu.Lock()
	payload := capturedPayload
	mu.Unlock()

	if len(payload) == 0 {
		t.Fatal("expected captured OTLP payload, got empty")
	}

	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("failed to parse OTLP json payload: %v", err)
	}
	if !strings.Contains(string(payload), "ChainHop") {
		t.Errorf("OTLP payload did not contain span name ChainHop: %s", string(payload))
	}
	if !strings.Contains(string(payload), "test-relay-service") {
		t.Errorf("OTLP payload did not contain service name: %s", string(payload))
	}
}
