package tui

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// MetricSample represents a single parsed Prometheus metric sample.
type MetricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Snapshot represents a parsed set of relay metrics at a point in time.
type Snapshot struct {
	Timestamp      time.Time
	ScrapeDuration time.Duration

	// Header & Health
	UptimeSeconds float64
	PID           int

	// Active Sessions & Transports
	SessionsTCP   int
	SessionsKCP   int
	SessionsQUIC  int
	SessionsWS    int
	SessionsTotal int
	SessionsHeld  int
	StandbyConns  int
	SocksStreams  int
	ChainSessions int

	// Memory & Buffers
	BufferUsedBytes  int64
	BufferTotalBytes int64
	BufferUtilRatio  float64

	// Throughput Counters
	BytesUpTotal   uint64
	BytesDownTotal uint64

	// Resiliency & Reliability
	ReconnectSuccess     uint64
	ReconnectFailure     uint64
	ReconnectDurationSum float64
	ReconnectCount       uint64
	HeldDurationSum      float64
	HeldCount            uint64

	AcceptsTotal     uint64
	RefusedTotal     uint64
	BFDDeadPeers     uint64
	RBACRejections   map[string]uint64
	TotalRBACRejects uint64

	// Splicing & KCP
	SplicedBytesIn  uint64
	SplicedBytesOut uint64
	SpliceCalls     uint64
	KCPSegsOut      uint64
	KCPSegsRetrans  uint64
	KCPSegsLost     uint64
	KCPSndQueue     uint64
	ChainHopsTotal  uint64

	RawMetrics map[string]float64
}

// ParsePrometheus parses standard Prometheus text exposition format into a Snapshot.
func ParsePrometheus(data []byte) (*Snapshot, error) {
	snap := &Snapshot{
		Timestamp:      time.Now(),
		RBACRejections: make(map[string]uint64),
		RawMetrics:     make(map[string]float64),
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		sample, err := parseSample(line)
		if err != nil {
			continue
		}

		snap.RawMetrics[sample.Name] = sample.Value

		switch sample.Name {
		case "relay_active_sessions":
			t := sample.Labels["transport"]
			val := int(sample.Value)
			switch t {
			case "tcp":
				snap.SessionsTCP = val
			case "kcp":
				snap.SessionsKCP = val
			case "quic":
				snap.SessionsQUIC = val
			case "ws":
				snap.SessionsWS = val
			}
			snap.SessionsTotal += val

		case "relay_held_sessions_active":
			snap.SessionsHeld = int(sample.Value)

		case "relay_standby_conns_active":
			snap.StandbyConns = int(sample.Value)

		case "relay_socks_streams_active":
			snap.SocksStreams = int(sample.Value)

		case "relay_chain_sessions_active":
			snap.ChainSessions = int(sample.Value)

		case "relay_buffer_utilization_ratio":
			snap.BufferUtilRatio = sample.Value

		case "relay_buffer_bytes_used":
			snap.BufferUsedBytes = int64(sample.Value)

		case "relay_buffer_bytes_total":
			snap.BufferTotalBytes = int64(sample.Value)

		case "relay_bytes_transferred_total":
			dir := sample.Labels["direction"]
			if dir == "up" {
				snap.BytesUpTotal += uint64(sample.Value)
			} else if dir == "down" {
				snap.BytesDownTotal += uint64(sample.Value)
			}

		case "relay_reconnect_total":
			st := sample.Labels["status"]
			if st == "success" {
				snap.ReconnectSuccess += uint64(sample.Value)
			} else if st == "failure" {
				snap.ReconnectFailure += uint64(sample.Value)
			}

		case "relay_reconnect_duration_seconds_sum":
			snap.ReconnectDurationSum = sample.Value

		case "relay_reconnect_duration_seconds_count":
			snap.ReconnectCount = uint64(sample.Value)

		case "relay_held_duration_seconds_sum":
			snap.HeldDurationSum = sample.Value

		case "relay_held_duration_seconds_count":
			snap.HeldCount = uint64(sample.Value)

		case "relay_accepts_total":
			snap.AcceptsTotal = uint64(sample.Value)

		case "relay_refused_total":
			snap.RefusedTotal = uint64(sample.Value)

		case "relay_bfd_dead_peer_total":
			snap.BFDDeadPeers = uint64(sample.Value)

		case "relay_rbac_rejections_total":
			reason := sample.Labels["reason"]
			if reason == "" {
				reason = "unknown"
			}
			c := uint64(sample.Value)
			snap.RBACRejections[reason] += c
			snap.TotalRBACRejects += c

		case "relay_spliced_bytes_total":
			dir := sample.Labels["direction"]
			if dir == "in" {
				snap.SplicedBytesIn += uint64(sample.Value)
			} else if dir == "out" {
				snap.SplicedBytesOut += uint64(sample.Value)
			}

		case "relay_splice_calls_total":
			snap.SpliceCalls = uint64(sample.Value)

		case "relay_kcp_segments_total":
			typ := sample.Labels["type"]
			switch typ {
			case "out":
				snap.KCPSegsOut = uint64(sample.Value)
			case "retrans":
				snap.KCPSegsRetrans = uint64(sample.Value)
			case "lost":
				snap.KCPSegsLost = uint64(sample.Value)
			case "snd_queue":
				snap.KCPSndQueue = uint64(sample.Value)
			}

		case "relay_chain_hops_total":
			snap.ChainHopsTotal = uint64(sample.Value)

		case "relay_process_uptime_seconds":
			snap.UptimeSeconds = sample.Value
		}
	}

	return snap, nil
}

func parseSample(line string) (MetricSample, error) {
	// Format: metric_name{label1="v1",label2="v2"} value [timestamp]
	// or:     metric_name value [timestamp]
	braceOpen := strings.IndexByte(line, '{')
	braceClose := strings.IndexByte(line, '}')

	var name string
	labels := make(map[string]string)
	var valStr string

	if braceOpen != -1 && braceClose != -1 && braceClose > braceOpen {
		name = strings.TrimSpace(line[:braceOpen])
		labelsContent := line[braceOpen+1 : braceClose]
		labels = parseLabels(labelsContent)

		rest := strings.TrimSpace(line[braceClose+1:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return MetricSample{}, fmt.Errorf("missing value in line: %s", line)
		}
		valStr = fields[0]
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return MetricSample{}, fmt.Errorf("invalid line: %s", line)
		}
		name = fields[0]
		valStr = fields[1]
	}

	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		if valStr == "NaN" {
			val = math.NaN()
		} else if valStr == "+Inf" {
			val = math.Inf(1)
		} else if valStr == "-Inf" {
			val = math.Inf(-1)
		} else {
			return MetricSample{}, fmt.Errorf("bad float value %q: %w", valStr, err)
		}
	}

	return MetricSample{
		Name:   name,
		Labels: labels,
		Value:  val,
	}, nil
}

func parseLabels(s string) map[string]string {
	labels := make(map[string]string)
	if s == "" {
		return labels
	}

	pairs := strings.Split(s, ",")
	for _, p := range pairs {
		p = strings.TrimSpace(p)
		eq := strings.IndexByte(p, '=')
		if eq == -1 {
			continue
		}
		k := strings.TrimSpace(p[:eq])
		v := strings.Trim(strings.TrimSpace(p[eq+1:]), `"`)
		labels[k] = v
	}
	return labels
}
