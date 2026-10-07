package obs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type contextKey string

const spanContextKey contextKey = "remote-relay.span"

// TraceContext represents the parsed W3C TraceContext.
type TraceContext struct {
	Version  string
	TraceID  string
	SpanID   string
	Flags    string
}

// GenerateTraceID generates a 16-byte (32 hex char) random trace ID.
func GenerateTraceID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	// Ensure not all zero
	if b == [16]byte{} {
		b[0] = 1
	}
	return hex.EncodeToString(b[:])
}

// GenerateSpanID generates an 8-byte (16 hex char) random span ID.
func GenerateSpanID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	if b == [8]byte{} {
		b[0] = 1
	}
	return hex.EncodeToString(b[:])
}

// ParseTraceparent parses a W3C traceparent header string.
// E.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
func ParseTraceparent(tp string) (TraceContext, error) {
	tp = strings.TrimSpace(tp)
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		return TraceContext{}, errors.New("invalid traceparent: expected 4 hyphen-separated fields")
	}

	version := parts[0]
	traceID := parts[1]
	spanID := parts[2]
	flags := parts[3]

	if len(version) != 2 || len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return TraceContext{}, errors.New("invalid traceparent field lengths")
	}

	if _, err := hex.DecodeString(version); err != nil {
		return TraceContext{}, fmt.Errorf("invalid traceparent version hex: %w", err)
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return TraceContext{}, fmt.Errorf("invalid traceparent trace-id hex: %w", err)
	}
	if _, err := hex.DecodeString(spanID); err != nil {
		return TraceContext{}, fmt.Errorf("invalid traceparent span-id hex: %w", err)
	}
	if _, err := hex.DecodeString(flags); err != nil {
		return TraceContext{}, fmt.Errorf("invalid traceparent flags hex: %w", err)
	}

	// TraceID and SpanID cannot be all zeroes
	if traceID == strings.Repeat("0", 32) || spanID == strings.Repeat("0", 16) {
		return TraceContext{}, errors.New("traceparent trace-id or span-id cannot be all zeros")
	}

	return TraceContext{
		Version: version,
		TraceID: traceID,
		SpanID:  spanID,
		Flags:   flags,
	}, nil
}

// FormatTraceparent formats a TraceContext into a W3C traceparent string.
func FormatTraceparent(tc TraceContext) string {
	ver := tc.Version
	if ver == "" {
		ver = "00"
	}
	flg := tc.Flags
	if flg == "" {
		flg = "01"
	}
	return fmt.Sprintf("%s-%s-%s-%s", ver, tc.TraceID, tc.SpanID, flg)
}

// Span represents an OpenTelemetry trace span.
type Span struct {
	mu           sync.Mutex
	Name         string
	TraceID      string
	SpanID       string
	ParentSpanID string
	StartTime    time.Time
	EndTime      time.Time
	Attributes   map[string]string
	StatusCode   string // "UNSET", "OK", "ERROR"
	StatusMsg    string
	tracer       *Tracer
}

// SetAttribute sets a key/value attribute on the span.
func (s *Span) SetAttribute(key, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = val
}

// SetStatus sets the status of the span.
func (s *Span) SetStatus(code, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.StatusCode = code
	s.StatusMsg = msg
}

// End finishes the span and enqueues it for export if an exporter is configured.
func (s *Span) End() {
	s.mu.Lock()
	if s.EndTime.IsZero() {
		s.EndTime = time.Now()
	}
	s.mu.Unlock()

	if s.tracer != nil {
		s.tracer.recordSpan(s)
	}
}

// Traceparent returns the W3C traceparent string for this span.
func (s *Span) Traceparent() string {
	return FormatTraceparent(TraceContext{
		Version: "00",
		TraceID: s.TraceID,
		SpanID:  s.SpanID,
		Flags:   "01",
	})
}

// SpanOption configures span creation.
type SpanOption func(*Span)

// WithParentTraceparent seeds the span from an incoming W3C traceparent string.
func WithParentTraceparent(tp string) SpanOption {
	return func(s *Span) {
		tc, err := ParseTraceparent(tp)
		if err == nil {
			s.TraceID = tc.TraceID
			s.ParentSpanID = tc.SpanID
		}
	}
}

// WithAttribute sets an initial attribute on the span.
func WithAttribute(key, val string) SpanOption {
	return func(s *Span) {
		if s.Attributes == nil {
			s.Attributes = make(map[string]string)
		}
		s.Attributes[key] = val
	}
}

// Tracer manages span creation and optional asynchronous OTLP export.
type Tracer struct {
	serviceName  string
	otelEndpoint string
	client       *http.Client
	spanQueue    chan *Span
	done         chan struct{}
	wg           sync.WaitGroup
	mu           sync.Mutex
	recentSpans  []*Span // In-memory ring buffer of recent spans for local diagnostics
	maxRecent    int
}

// NewTracer creates a new Tracer. If otelEndpoint is non-empty, background exporting is started.
func NewTracer(serviceName, otelEndpoint string) *Tracer {
	t := &Tracer{
		serviceName:  serviceName,
		otelEndpoint: strings.TrimSpace(otelEndpoint),
		client:       &http.Client{Timeout: 5 * time.Second},
		spanQueue:    make(chan *Span, 2048),
		done:         make(chan struct{}),
		maxRecent:    256,
		recentSpans:  make([]*Span, 0, 256),
	}

	if t.otelEndpoint != "" {
		t.wg.Add(1)
		go t.exportWorker()
	}

	return t
}

// Start begins a new Span.
func (t *Tracer) Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	parent := SpanFromContext(ctx)

	s := &Span{
		Name:       name,
		StartTime:  time.Now(),
		Attributes: make(map[string]string),
		StatusCode: "OK",
		tracer:     t,
	}

	if parent != nil {
		s.TraceID = parent.TraceID
		s.ParentSpanID = parent.SpanID
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.TraceID == "" {
		s.TraceID = GenerateTraceID()
	}
	if s.SpanID == "" {
		s.SpanID = GenerateSpanID()
	}

	return ContextWithSpan(ctx, s), s
}

func (t *Tracer) recordSpan(s *Span) {
	t.mu.Lock()
	if len(t.recentSpans) >= t.maxRecent {
		t.recentSpans = t.recentSpans[1:]
	}
	t.recentSpans = append(t.recentSpans, s)
	t.mu.Unlock()

	if t.otelEndpoint == "" {
		return
	}

	select {
	case t.spanQueue <- s:
	default:
		// Queue full, drop to prevent blocking relay network operations
	}
}

// RecentSpans returns a snapshot of recent spans recorded in memory.
func (t *Tracer) RecentSpans() []*Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	res := make([]*Span, len(t.recentSpans))
	copy(res, t.recentSpans)
	return res
}

func (t *Tracer) exportWorker() {
	defer t.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]*Span, 0, 64)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		t.exportBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-t.done:
			// Drain remaining
			for {
				select {
				case s := <-t.spanQueue:
					batch = append(batch, s)
				default:
					flush()
					return
				}
			}
		case s := <-t.spanQueue:
			batch = append(batch, s)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (t *Tracer) exportBatch(spans []*Span) {
	payload, err := t.buildOTLPPayload(spans)
	if err != nil {
		return
	}

	url := t.otelEndpoint
	if !strings.HasSuffix(url, "/v1/traces") && !strings.Contains(url, "/v1/") {
		url = strings.TrimRight(url, "/") + "/v1/traces"
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (t *Tracer) buildOTLPPayload(spans []*Span) ([]byte, error) {
	type otlpKeyValue struct {
		Key   string `json:"key"`
		Value struct {
			StringValue string `json:"stringValue"`
		} `json:"value"`
	}

	type otlpSpan struct {
		TraceID           string         `json:"traceId"`
		SpanID            string         `json:"spanId"`
		ParentSpanID      string         `json:"parentSpanId,omitempty"`
		Name              string         `json:"name"`
		StartTimeUnixNano uint64         `json:"startTimeUnixNano"`
		EndTimeUnixNano   uint64         `json:"endTimeUnixNano"`
		Attributes        []otlpKeyValue `json:"attributes,omitempty"`
		Status            struct {
			Code    int    `json:"code"`
			Message string `json:"message,omitempty"`
		} `json:"status"`
	}

	type otlpScopeSpans struct {
		Scope struct {
			Name string `json:"name"`
		} `json:"scope"`
		Spans []otlpSpan `json:"spans"`
	}

	type otlpResourceSpans struct {
		Resource struct {
			Attributes []otlpKeyValue `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
	}

	type otlpPayload struct {
		ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
	}

	serviceAttr := otlpKeyValue{Key: "service.name"}
	serviceAttr.Value.StringValue = t.serviceName

	otlpSpansList := make([]otlpSpan, 0, len(spans))
	for _, s := range spans {
		s.mu.Lock()
		os := otlpSpan{
			TraceID:           s.TraceID,
			SpanID:            s.SpanID,
			ParentSpanID:      s.ParentSpanID,
			Name:              s.Name,
			StartTimeUnixNano: uint64(s.StartTime.UnixNano()),
			EndTimeUnixNano:   uint64(s.EndTime.UnixNano()),
		}

		if s.StatusCode == "ERROR" {
			os.Status.Code = 2
		} else {
			os.Status.Code = 1
		}
		os.Status.Message = s.StatusMsg

		for k, v := range s.Attributes {
			kv := otlpKeyValue{Key: k}
			kv.Value.StringValue = v
			os.Attributes = append(os.Attributes, kv)
		}
		s.mu.Unlock()

		otlpSpansList = append(otlpSpansList, os)
	}

	scope := otlpScopeSpans{
		Spans: otlpSpansList,
	}
	scope.Scope.Name = "github.com/remote-relay/relay/internal/obs"

	resSpan := otlpResourceSpans{
		ScopeSpans: []otlpScopeSpans{scope},
	}
	resSpan.Resource.Attributes = []otlpKeyValue{serviceAttr}

	root := otlpPayload{
		ResourceSpans: []otlpResourceSpans{resSpan},
	}

	return json.Marshal(root)
}

// Close gracefully stops the tracer and flushes spans.
func (t *Tracer) Close() error {
	close(t.done)
	t.wg.Wait()
	return nil
}

// ContextWithSpan returns a context carrying the span.
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, spanContextKey, span)
}

// SpanFromContext extracts the span from the context, or returns nil if absent.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	if s, ok := ctx.Value(spanContextKey).(*Span); ok {
		return s
	}
	return nil
}
