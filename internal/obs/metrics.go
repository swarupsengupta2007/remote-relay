package obs

import (
	"bytes"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents a Prometheus metric type.
type MetricType string

const (
	TypeCounter   MetricType = "counter"
	TypeGauge     MetricType = "gauge"
	TypeHistogram MetricType = "histogram"
)

// Metric is an interface implemented by individual metric instances.
type Metric interface {
	WritePrometheus(buf *bytes.Buffer, name string, constLabels map[string]string)
}

// Collector is an interface for registering metric families.
type Collector interface {
	Name() string
	Help() string
	Type() MetricType
	WritePrometheus(buf *bytes.Buffer)
}

// Label represents a key-value label pair.
type Label struct {
	Name  string
	Value string
}

// Counter is a monotonically increasing counter.
type Counter struct {
	val uint64 // math.Float64bits storage for atomic float operations
}

// NewCounter creates a new Counter.
func NewCounter() *Counter {
	return &Counter{}
}

// Inc increments the counter by 1.
func (c *Counter) Inc() {
	c.Add(1.0)
}

// Set sets the counter to the specified absolute value.
func (c *Counter) Set(val float64) {
	atomic.StoreUint64(&c.val, math.Float64bits(val))
}

// Add adds the given value to the counter. If val < 0, it is ignored.
func (c *Counter) Add(val float64) {
	if val < 0 {
		return
	}
	for {
		oldBits := atomic.LoadUint64(&c.val)
		newVal := math.Float64frombits(oldBits) + val
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapUint64(&c.val, oldBits, newBits) {
			return
		}
	}
}

// Get returns the current counter value.
func (c *Counter) Get() float64 {
	return math.Float64frombits(atomic.LoadUint64(&c.val))
}

// WritePrometheus writes the metric line.
func (c *Counter) WritePrometheus(buf *bytes.Buffer, name string, labels map[string]string) {
	writeSample(buf, name, labels, c.Get())
}

// Gauge is a numerical value that can arbitrarily go up and down.
type Gauge struct {
	val uint64 // math.Float64bits
}

// NewGauge creates a new Gauge.
func NewGauge() *Gauge {
	return &Gauge{}
}

// Set sets the gauge to the given value.
func (g *Gauge) Set(val float64) {
	atomic.StoreUint64(&g.val, math.Float64bits(val))
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.Add(1.0)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.Add(-1.0)
}

// Add adds the given delta to the gauge.
func (g *Gauge) Add(delta float64) {
	for {
		oldBits := atomic.LoadUint64(&g.val)
		newVal := math.Float64frombits(oldBits) + delta
		newBits := math.Float64bits(newVal)
		if atomic.CompareAndSwapUint64(&g.val, oldBits, newBits) {
			return
		}
	}
}

// Get returns the current gauge value.
func (g *Gauge) Get() float64 {
	return math.Float64frombits(atomic.LoadUint64(&g.val))
}

// WritePrometheus writes the metric line.
func (g *Gauge) WritePrometheus(buf *bytes.Buffer, name string, labels map[string]string) {
	writeSample(buf, name, labels, g.Get())
}

// Histogram tracks the size and distribution of events into configurable buckets.
type Histogram struct {
	mu      sync.RWMutex
	buckets []float64 // upper bounds sorted ascending
	counts  []uint64  // count for each bucket
	count   uint64    // total count
	sum     float64   // sum of all observed values
}

// NewHistogram creates a new Histogram with specified upper bound buckets.
func NewHistogram(buckets []float64) *Histogram {
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)
	return &Histogram{
		buckets: sorted,
		counts:  make([]uint64, len(sorted)),
	}
}

// Observe records a new observation in the histogram.
func (h *Histogram) Observe(val float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += val
	for i, bound := range h.buckets {
		if val <= bound {
			h.counts[i]++
		}
	}
}

// Snapshot returns a copy of the histogram's state.
func (h *Histogram) Snapshot() (buckets []float64, counts []uint64, totalCount uint64, sum float64) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	bCopy := make([]float64, len(h.buckets))
	copy(bCopy, h.buckets)
	cCopy := make([]uint64, len(h.counts))
	copy(cCopy, h.counts)
	return bCopy, cCopy, h.count, h.sum
}

// WritePrometheus formats the histogram according to Prometheus exposition format.
func (h *Histogram) WritePrometheus(buf *bytes.Buffer, name string, labels map[string]string) {
	buckets, counts, count, sum := h.Snapshot()

	for i, bound := range buckets {
		bucketLabels := copyLabels(labels)
		bucketLabels["le"] = formatFloat(bound)
		writeSample(buf, name+"_bucket", bucketLabels, float64(counts[i]))
	}

	infLabels := copyLabels(labels)
	infLabels["le"] = "+Inf"
	writeSample(buf, name+"_bucket", infLabels, float64(count))

	writeSample(buf, name+"_sum", labels, sum)
	writeSample(buf, name+"_count", labels, float64(count))
}

// MetricVec manages dimensional metrics by label keys.
type MetricVec[T Metric] struct {
	mu        sync.RWMutex
	name      string
	help      string
	typ       MetricType
	labelKeys []string
	metrics   map[string]T
	labelsMap map[string]map[string]string
	factory   func() T
}

// NewCounterVec creates a new Counter vector.
func NewCounterVec(name, help string, labelKeys []string) *MetricVec[*Counter] {
	return &MetricVec[*Counter]{
		name:      name,
		help:      help,
		typ:       TypeCounter,
		labelKeys: labelKeys,
		metrics:   make(map[string]*Counter),
		labelsMap: make(map[string]map[string]string),
		factory:   NewCounter,
	}
}

// NewGaugeVec creates a new Gauge vector.
func NewGaugeVec(name, help string, labelKeys []string) *MetricVec[*Gauge] {
	return &MetricVec[*Gauge]{
		name:      name,
		help:      help,
		typ:       TypeGauge,
		labelKeys: labelKeys,
		metrics:   make(map[string]*Gauge),
		labelsMap: make(map[string]map[string]string),
		factory:   NewGauge,
	}
}

// NewHistogramVec creates a new Histogram vector.
func NewHistogramVec(name, help string, labelKeys []string, buckets []float64) *MetricVec[*Histogram] {
	return &MetricVec[*Histogram]{
		name:      name,
		help:      help,
		typ:       TypeHistogram,
		labelKeys: labelKeys,
		metrics:   make(map[string]*Histogram),
		labelsMap: make(map[string]map[string]string),
		factory: func() *Histogram {
			return NewHistogram(buckets)
		},
	}
}

func (v *MetricVec[T]) Name() string     { return v.name }
func (v *MetricVec[T]) Help() string     { return v.help }
func (v *MetricVec[T]) Type() MetricType { return v.typ }

func (v *MetricVec[T]) key(vals []string) string {
	return strings.Join(vals, "\x00")
}

// WithLabelValues returns the metric with the specified label values.
func (v *MetricVec[T]) WithLabelValues(vals ...string) T {
	k := v.key(vals)

	v.mu.RLock()
	m, ok := v.metrics[k]
	v.mu.RUnlock()
	if ok {
		return m
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if m, ok := v.metrics[k]; ok {
		return m
	}

	m = v.factory()
	v.metrics[k] = m
	lbls := make(map[string]string, len(v.labelKeys))
	for i, key := range v.labelKeys {
		if i < len(vals) {
			lbls[key] = vals[i]
		}
	}
	v.labelsMap[k] = lbls
	return m
}

// WritePrometheus writes all metrics in the vector.
func (v *MetricVec[T]) WritePrometheus(buf *bytes.Buffer) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	writeHeader(buf, v.name, v.help, v.typ)

	keys := make([]string, 0, len(v.metrics))
	for k := range v.metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		m := v.metrics[k]
		lbls := v.labelsMap[k]
		m.WritePrometheus(buf, v.name, lbls)
	}
}

// SingleMetric wraps a single Metric as a Collector.
type SingleMetric struct {
	name   string
	help   string
	typ    MetricType
	metric Metric
}

// NewSingleMetric wraps a single Counter, Gauge, or Histogram.
func NewSingleMetric(name, help string, typ MetricType, m Metric) *SingleMetric {
	return &SingleMetric{
		name:   name,
		help:   help,
		typ:    typ,
		metric: m,
	}
}

func (s *SingleMetric) Name() string     { return s.name }
func (s *SingleMetric) Help() string     { return s.help }
func (s *SingleMetric) Type() MetricType { return s.typ }

func (s *SingleMetric) WritePrometheus(buf *bytes.Buffer) {
	writeHeader(buf, s.name, s.help, s.typ)
	s.metric.WritePrometheus(buf, s.name, nil)
}

// Registry stores and serializes collectors.
type Registry struct {
	mu         sync.RWMutex
	collectors []Collector
}

// NewRegistry creates a new Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a collector to the registry.
func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, c)
}

// Gather serializes all registered metrics into standard Prometheus text format.
func (r *Registry) Gather() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var buf bytes.Buffer
	for _, c := range r.collectors {
		c.WritePrometheus(&buf)
	}
	return buf.Bytes()
}

// Helper formatting functions

func writeHeader(buf *bytes.Buffer, name, help string, typ MetricType) {
	if help != "" {
		buf.WriteString("# HELP ")
		buf.WriteString(name)
		buf.WriteByte(' ')
		buf.WriteString(help)
		buf.WriteByte('\n')
	}
	buf.WriteString("# TYPE ")
	buf.WriteString(name)
	buf.WriteByte(' ')
	buf.WriteString(string(typ))
	buf.WriteByte('\n')
}

func writeSample(buf *bytes.Buffer, name string, labels map[string]string, val float64) {
	buf.WriteString(name)
	if len(labels) > 0 {
		buf.WriteByte('{')
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(k)
			buf.WriteString("=\"")
			escapeLabelValue(buf, labels[k])
			buf.WriteByte('"')
		}
		buf.WriteByte('}')
	}
	buf.WriteByte(' ')
	buf.WriteString(formatFloat(val))
	buf.WriteByte('\n')
}

func escapeLabelValue(buf *bytes.Buffer, val string) {
	for i := 0; i < len(val); i++ {
		b := val[i]
		switch b {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\n':
			buf.WriteString(`\n`)
		default:
			buf.WriteByte(b)
		}
	}
}

func formatFloat(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func copyLabels(m map[string]string) map[string]string {
	cp := make(map[string]string, len(m)+1)
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

// Metrics encapsulates all server-level metrics defined in FEAT-OBS-01.
type Metrics struct {
	Registry *Registry

	// Metrics specified in FEAT-OBS-01
	ActiveSessions    *MetricVec[*Gauge]     // relay_active_sessions{transport="quic|kcp|tcp|ws"}
	ReconnectTotal    *MetricVec[*Counter]   // relay_reconnect_total{status="success|failure"}
	ReconnectDuration *Histogram             // relay_reconnect_duration_seconds
	HeldDuration      *Histogram             // relay_held_duration_seconds
	BytesTransferred  *MetricVec[*Counter]   // relay_bytes_transferred_total{direction="up|down", transport="..."}
	BufferUtilization *Gauge                 // relay_buffer_utilization_ratio
	HopChainDepth     *Histogram             // relay_hop_chain_depth
	SocksStreams      *Gauge                 // relay_socks_streams_active
	RBACRejections    *MetricVec[*Counter]   // relay_rbac_rejections_total{reason="..."}

	// Additional operational metrics
	AcceptsTotal      *Counter               // relay_accepts_total
	RefusedTotal      *Counter               // relay_refused_total
	SplicedBytes      *MetricVec[*Counter]   // relay_spliced_bytes_total{direction="in|out"}
	SpliceCalls       *Counter               // relay_splice_calls_total
	KCPSegments       *MetricVec[*Counter]   // relay_kcp_segments_total{type="out|retrans|lost|snd_queue"}
	BFDDeadPeers      *Counter               // relay_bfd_dead_peer_total
	ProcessUptime     *Gauge                 // relay_process_uptime_seconds
	BufferBytesUsed   *Gauge                 // relay_buffer_bytes_used
	BufferBytesTotal  *Gauge                 // relay_buffer_bytes_total
	HeldSessions      *Gauge                 // relay_held_sessions_active
	StandbyConns      *Gauge                 // relay_standby_conns_active
	ChainSessions     *Gauge                 // relay_chain_sessions_active
	ChainHopsTotal    *Counter               // relay_chain_hops_total
	ChainAuthRelays   *Counter               // relay_chain_auth_relays_total
	ChainRefused      *Counter               // relay_chain_refused_total
	ChainAttestFails  *Counter               // relay_chain_attest_failures_total

	startTime time.Time
}

// NewMetrics initializes the standard remote-relay Prometheus metrics collection.
func NewMetrics() *Metrics {
	reg := NewRegistry()

	reconnectBuckets := []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0}
	heldBuckets := []float64{0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0}
	hopBuckets := []float64{1, 2, 3, 4, 5, 8, 10}

	m := &Metrics{
		Registry:          reg,
		ActiveSessions:    NewGaugeVec("relay_active_sessions", "Number of currently active sessions by transport", []string{"transport"}),
		ReconnectTotal:    NewCounterVec("relay_reconnect_total", "Total reconnection attempts by status", []string{"status"}),
		ReconnectDuration: NewHistogram(reconnectBuckets),
		HeldDuration:      NewHistogram(heldBuckets),
		BytesTransferred:  NewCounterVec("relay_bytes_transferred_total", "Total bytes transferred by direction and transport", []string{"direction", "transport"}),
		BufferUtilization: NewGauge(),
		HopChainDepth:     NewHistogram(hopBuckets),
		SocksStreams:      NewGauge(),
		RBACRejections:    NewCounterVec("relay_rbac_rejections_total", "Total RBAC connection rejections by reason", []string{"reason"}),

		AcceptsTotal:      NewCounter(),
		RefusedTotal:      NewCounter(),
		SplicedBytes:      NewCounterVec("relay_spliced_bytes_total", "Total bytes spliced via kernel splice(2)", []string{"direction"}),
		SpliceCalls:       NewCounter(),
		KCPSegments:       NewCounterVec("relay_kcp_segments_total", "KCP SNMP segment counters", []string{"type"}),
		BFDDeadPeers:      NewCounter(),
		ProcessUptime:     NewGauge(),
		BufferBytesUsed:   NewGauge(),
		BufferBytesTotal:  NewGauge(),
		HeldSessions:      NewGauge(),
		StandbyConns:      NewGauge(),
		ChainSessions:     NewGauge(),
		ChainHopsTotal:    NewCounter(),
		ChainAuthRelays:   NewCounter(),
		ChainRefused:      NewCounter(),
		ChainAttestFails:  NewCounter(),

		startTime: time.Now(),
	}

	// Register all collectors
	reg.Register(m.ActiveSessions)
	reg.Register(m.ReconnectTotal)
	reg.Register(NewSingleMetric("relay_reconnect_duration_seconds", "Histogram of reconnection latency durations", TypeHistogram, m.ReconnectDuration))
	reg.Register(NewSingleMetric("relay_held_duration_seconds", "Histogram of held session durations prior to reconnect or expiry", TypeHistogram, m.HeldDuration))
	reg.Register(m.BytesTransferred)
	reg.Register(NewSingleMetric("relay_buffer_utilization_ratio", "Ratio of ring buffer memory utilization (0.0 - 1.0)", TypeGauge, m.BufferUtilization))
	reg.Register(NewSingleMetric("relay_hop_chain_depth", "Histogram of multi-hop jumphost chain depths", TypeHistogram, m.HopChainDepth))
	reg.Register(NewSingleMetric("relay_socks_streams_active", "Number of active SOCKS5 dynamic proxy streams", TypeGauge, m.SocksStreams))
	reg.Register(m.RBACRejections)

	reg.Register(NewSingleMetric("relay_accepts_total", "Total connections accepted", TypeCounter, m.AcceptsTotal))
	reg.Register(NewSingleMetric("relay_refused_total", "Total connections refused", TypeCounter, m.RefusedTotal))
	reg.Register(m.SplicedBytes)
	reg.Register(NewSingleMetric("relay_splice_calls_total", "Total splice(2) system calls executed", TypeCounter, m.SpliceCalls))
	reg.Register(m.KCPSegments)
	reg.Register(NewSingleMetric("relay_bfd_dead_peer_total", "Total BFD dead peer triggers detected", TypeCounter, m.BFDDeadPeers))
	reg.Register(NewSingleMetric("relay_process_uptime_seconds", "Process uptime in seconds", TypeGauge, m.ProcessUptime))
	reg.Register(NewSingleMetric("relay_buffer_bytes_used", "Current bytes allocated in ring buffers", TypeGauge, m.BufferBytesUsed))
	reg.Register(NewSingleMetric("relay_buffer_bytes_total", "Total buffer capacity in bytes", TypeGauge, m.BufferBytesTotal))
	reg.Register(NewSingleMetric("relay_held_sessions_active", "Current number of sessions held in disconnected state", TypeGauge, m.HeldSessions))
	reg.Register(NewSingleMetric("relay_standby_conns_active", "Current number of standby hot-carrier connections", TypeGauge, m.StandbyConns))
	reg.Register(NewSingleMetric("relay_chain_sessions_active", "Current active multi-hop chained sessions", TypeGauge, m.ChainSessions))
	reg.Register(NewSingleMetric("relay_chain_hops_total", "Total onward chain hops established", TypeCounter, m.ChainHopsTotal))
	reg.Register(NewSingleMetric("relay_chain_auth_relays_total", "Total chain auth delegations handled", TypeCounter, m.ChainAuthRelays))
	reg.Register(NewSingleMetric("relay_chain_refused_total", "Total chain requests refused", TypeCounter, m.ChainRefused))
	reg.Register(NewSingleMetric("relay_chain_attest_failures_total", "Total chain host attestation verification failures", TypeCounter, m.ChainAttestFails))

	return m
}

// UpdateUptime updates the process uptime gauge.
func (m *Metrics) UpdateUptime() {
	m.ProcessUptime.Set(time.Since(m.startTime).Seconds())
}

// HTTPHandler returns an http.Handler that serves the Prometheus metrics text format.
func (m *Metrics) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.UpdateUptime()
		payload := m.Registry.Gather()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	})
}
