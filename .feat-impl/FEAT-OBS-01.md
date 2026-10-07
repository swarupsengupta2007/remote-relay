# FEAT-OBS-01: Prometheus Exporter, OpenTelemetry Tracing & Live Metrics TUI Dashboard (`relay top`)

## 1. Executive Summary

Production deployment of `remote-relay` in enterprise environments demands both standard machine-scraped observability (for Prometheus, Grafana, and Datadog SLA alerting) and instant, interactive developer/operator diagnostics directly on remote jumphosts without setting up external monitoring stacks.

Previously, `remote-relay` only exposed basic `expvar` variables (`sessions`, `held`, `buffer_used`, `accepts`, `refused`). It lacked dimensional label vectors, histograms with latency percentiles, W3C distributed trace context propagation, and terminal diagnostic tools analogous to `top`, `htop`, or `iftop`.

**FEAT-OBS-01** introduces:
1. **Zero-Dependency Native Prometheus Exporter (`/metrics`)**: Built in [`internal/obs`](file:///root/remote-relay/internal/obs) using Go standard library and atomic primitives. Exposes dimensional gauges, counters, and histograms adhering strictly to Prometheus 0.0.4 text exposition format with zero third-party dependencies.
2. **W3C OpenTelemetry Distributed Tracing**: Generates W3C TraceContext spans (`traceparent` header format: `00-<trace_id>-<span_id>-01`) for key session lifecycle phases (`Handshake`, `Upgrade`, `Resume`, `ChainHop`). Wire-propagated across hops via optional `traceparent` fields on [`proto.Hello`](file:///root/remote-relay/internal/proto/messages.go), [`proto.Resume`](file:///root/remote-relay/internal/proto/messages.go), and chain frames, with optional asynchronous OTLP/HTTP JSON exporting (`--otel-endpoint`).
3. **Interactive Terminal TUI Dashboard (`relay top`)**: Real-time live metrics dashboard built with clean ANSI terminal control and `golang.org/x/term` alt-screen buffer. Displays server health, transport breakdowns, live upload/download transfer rates with Unicode sparklines (` ▂▃▄▅▆▇█`), ring buffer capacity gauges with backpressure alerts, and resiliency counters.
4. **Instant Snapshot Subcommand (`relay stats`)**: Clean one-shot text summary command for scripts, automation, and remote SSH execution (`ssh server relay stats`).
5. **Headless & Non-TTY Fallback**: Detects non-interactive environments (`!term.IsTerminal` or `--batch`) and gracefully emits plain-text snapshots without terminal escape codes.

---

## 2. Technical Architecture

### 2.1 Component Interaction & Metric Flow

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Operator / Terminal
    participant Top as relay top / relay stats
    participant Server as relay server (:7443)
    participant Obs as internal/obs (Registry & Tracer)
    participant Prom as Prometheus / Grafana
    participant Collector as OpenTelemetry Collector

    Note over Server,Obs: Server starts with --metrics-listen :9090
    Server->>Obs: Register collectors & initialize tracer

    loop Client Session Lifecycle
        Server->>Obs: Trace Handshake / Resume / ChainHop
        Server->>Obs: Update gauges & counters (sessions, bytes, buffers, RBAC)
        opt OTLP Configured (--otel-endpoint)
            Obs-->>Collector: Async batch POST /v1/traces (OTLP JSON)
        end
    end

    par External Scraping
        Prom->>Server: GET :9090/metrics
        Server->>Obs: syncMetrics() & Gather()
        Obs-->>Prom: Prometheus text exposition (text/plain; version=0.0.4)
    and Interactive TUI Dashboard
        Admin->>Top: relay top --endpoint http://127.0.0.1:9090/metrics
        Top->>Server: Periodic HTTP GET /metrics (default: 1s)
        Server-->>Top: Prometheus text exposition
        Top->>Top: Parse text into Snapshot, compute delta rates & sparklines
        Top->>Admin: Render ANSI multi-panel dashboard to alt-screen buffer
    end
```

---

## 3. Implementation Details

### 3.1 Prometheus Metrics Registry (`internal/obs/metrics.go`)

The metrics collection in [`internal/obs`](file:///root/remote-relay/internal/obs) is completely self-contained and avoids heavy external dependencies:
- **`Counter`**: Monotonically increasing counter with atomic `Inc()`, `Add(val float64)`, `Set(val float64)`, and `Get() float64`.
- **`Gauge`**: Arbitrary numerical gauge with atomic `Set(val float64)`, `Inc()`, `Dec()`, `Add(val float64)`, and `Get() float64`.
- **`Histogram`**: Tracks value distribution into configured upper-bound buckets (`le`), maintaining total observation count, cumulative sum, and `+Inf` bucket.
- **`MetricVec`**: Generic dimensional vector mapping sorted label key-value pairs to metric instances.
- **Standard Metrics Catalog**:
  - `relay_active_sessions{transport="quic|kcp|tcp|ws"}` (gauge)
  - `relay_reconnect_total{status="success|failure"}` (counter)
  - `relay_reconnect_duration_seconds` (histogram: 0.1s, 0.5s, 1s, 2s, 5s, 10s)
  - `relay_held_duration_seconds` (histogram: 0.5s, 1s, 2s, 5s, 10s, 30s, 60s, 120s, 300s)
  - `relay_bytes_transferred_total{direction="up|down", transport="..."}` (counter)
  - `relay_buffer_utilization_ratio` (gauge: 0.0 - 1.0)
  - `relay_hop_chain_depth` (histogram: 1, 2, 3, 4, 5, 8, 10)
  - `relay_socks_streams_active` (gauge)
  - `relay_rbac_rejections_total{reason="..."}` (counter)
  - Operational metrics: `relay_accepts_total`, `relay_refused_total`, `relay_spliced_bytes_total`, `relay_splice_calls_total`, `relay_kcp_segments_total`, `relay_bfd_dead_peer_total`, `relay_process_uptime_seconds`, `relay_buffer_bytes_used`, `relay_buffer_bytes_total`, `relay_held_sessions_active`, `relay_standby_conns_active`, `relay_chain_sessions_active`.

### 3.2 OpenTelemetry Distributed Tracing (`internal/obs/tracer.go`)

- **W3C TraceContext Specification**: Validates and serializes `00-<32 hex trace-id>-<16 hex span-id>-01`.
- **Wire Propagation**: Added `Traceparent string json:"traceparent,omitempty"` to [`proto.Hello`](file:///root/remote-relay/internal/proto/messages.go), [`proto.Resume`](file:///root/remote-relay/internal/proto/messages.go), and [`proto.ChainHello`](file:///root/remote-relay/internal/proto/messages.go).
- **Session Lifecycle Spans**:
  - `Handshake`: Recorded during client connection negotiation and RBAC authorization.
  - `Upgrade`: Recorded when dynamic transport upgrade probes complete.
  - `Resume`: Recorded during link reconnection and token/fallback re-authentication.
  - `ChainHop`: Recorded during multi-hop intermediate relay routing.
- **Asynchronous OTLP JSON Exporter**: When `--otel-endpoint` (or `otel_endpoint` in TOML) is configured, spans are buffered non-blockingly and asynchronously flushed to `/v1/traces` in standard OTLP/HTTP JSON format.

### 3.3 Live Terminal Metrics TUI Dashboard (`internal/tui`)

- **Prometheus Text Parser ([`internal/tui/parser.go`](file:///root/remote-relay/internal/tui/parser.go))**: Tokenizes comments, metric identifiers, label maps, and float64 values into a strongly typed `Snapshot`.
- **Sparkline & Rate Tracker ([`internal/tui/sparkline.go`](file:///root/remote-relay/internal/tui/sparkline.go))**: Maintains moving history windows and renders 8-level Unicode sparklines (` ▂▃▄▅▆▇█`) for instantaneous upload and download transfer rates.
- **Interactive Multi-Panel Dashboard ([`internal/tui/dashboard.go`](file:///root/remote-relay/internal/tui/dashboard.go))**:
  - **Header & Health Panel**: Server uptime, status, PID, scrape latency, refresh rate, and paused indicator.
  - **Transport Breakdown**: Proportional visual bar and counts for `TCP`, `QUIC`, `KCP`, `WS`, plus active SOCKS streams and chain hops.
  - **Throughput Rates**: Upload and download transfer rates ($\text{KiB/s}$, $\text{MiB/s}$) with moving deltas and sparklines.
  - **Memory & Buffer Utilization**: Current buffer bytes vs total buffer capacity with percentage gauge and backpressure alerts.
  - **Reliability & Resiliency Counters**: Reconnect rates, BFD dead-peer triggers, failovers, and RBAC rejection counts.
  - **Interactive Keybindings**: `q`/`Esc` to exit, `r` to force refresh, `p` to pause/resume live updates, `+`/`-` or `1`/`2`/`5` to adjust refresh intervals.
  - **Sad Path Resilience**: Clear disconnection alert box and retry countdown when server restarts or endpoint is temporarily unreachable.
- **Fail-Safe Terminal Lifecycle**: Restores alternate screen buffer (`\033[?1049l`), cursor (`\033[?25h`), and terminal state on exit, `SIGINT`, `SIGTERM`, or window resize (`SIGWINCH`).

---

## 4. CLI Usage & Commands

```bash
# Start server with dedicated metrics HTTP endpoint
relay server --metrics-listen 127.0.0.1:9090 --otel-endpoint http://collector:4318/v1/traces

# Launch interactive live metrics TUI dashboard
relay top --endpoint http://127.0.0.1:9090/metrics

# Adjust refresh frequency or color mode
relay top --endpoint 127.0.0.1:9090 --interval 2s --color=always

# One-shot formatted text snapshot (ideal for SSH remote commands and scripts)
relay stats --endpoint http://127.0.0.1:9090/metrics
# or using batch flag
relay top --endpoint http://127.0.0.1:9090/metrics --batch
```

---

## 5. Verification & Testing Matrix

- `internal/obs/obs_test.go`:
  - `TestMetricsPrometheusFormat`: Verifies valid Prometheus 0.0.4 text output with `# HELP`, `# TYPE`, labels, and histogram buckets.
  - `TestConcurrentMetricUpdates`: Concurrency stress test under high parallel goroutine loads.
  - `TestTraceparentParsingAndFormatting`: Validates W3C traceparent parsing, format generation, and invalid format handling.
  - `TestTracerAndSpanHierarchy`: Verifies parent-child span trace ID inheritance.
  - `TestOTLPPayloadSerialization`: Verifies OTLP/HTTP JSON serialization with a mock HTTP receiver.
- `internal/tui/tui_test.go`:
  - `TestParsePrometheusText`: Validates parsing of live Prometheus text output into `Snapshot`.
  - `TestSparklineRendering`: Verifies Unicode sparkline generation and range normalization.
  - `TestRateTracker`: Verifies moving throughput delta and rate calculations.
  - `TestRenderFrame`: Validates multi-panel ANSI layout rendering and disconnection overlay.
  - `TestFormatStats`: Validates one-shot summary generation.
  - `TestNormalizeEndpoint`: Validates URL scheme and default normalization.
- `internal/relay/obs_test.go`:
  - `TestMetricsListenEndpoint`: Integration test starting `relay.Server` with `MetricsListen`, scraping `/metrics`, and validating exposed metrics.
  - `TestPprofAndExpvarListen`: Verifies `/metrics` is also mounted on `pprof` and `expvar` listeners when enabled.
