# FEAT-PERF-02: Adaptive KCP Congestion & Dynamic ARQ Tuning

## 1. Executive Summary

In Milestone 3, KCP transport (`internal/transport/kcp.go`) was introduced using fixed turbo ARQ parameters:
$$\text{nodelay}=1, \quad \text{interval}=10\text{ms}, \quad \text{resend}=2, \quad \text{nc}=1$$

While these aggressive parameters provide strong throughput on lossy wireless channels, they introduce serious liabilities under fluctuating network conditions:
1. **Bandwidth Saturation & Mobile Quota Waste**: On clean mobile links (loss $< 0.5\%$), polling and flushing every $10\text{ms}$ generates up to $100$ empty or redundant ACK/probe packets per second. On metered cellular connections, this depletes mobile data quotas and increases radio power consumption.
2. **Bufferbloat & Packet Bloat**: Disabling congestion control ($\text{nc}=1$) forces KCP to transmit at the full advertised window without backing off upon packet drop. On bandwidth-constrained links, this causes queue build-up, latency inflation, and packet bloat.
3. **Static Inflexibility**: Real-world wireless networks fluctuate dynamically (e.g. entering elevators, cellular cell handovers, micro-burst congestion). Fixed parameters cannot adapt between latency-optimal and bandwidth-conservative states.

**FEAT-PERF-02** implements an autonomous **Adaptive KCP Dynamic ARQ & Congestion Controller** in `internal/transport`:
- **Dynamic Link Probing & Moving Loss Rate**: Computes moving loss rate using a sliding history window combined with fast-attack response on sudden spikes and smooth Exponential Weighted Moving Average (EWMA).
- **Send Queue Backpressure Monitoring**: Monitors segment ring buffer length (`snd_queue.Len()` / `RingBufferSndQueue`) to detect congestion build-up before packet drops occur.
- **Dynamic 3-Tier State Machine**:
  - **Clean Link / Low Loss ($<0.5\%$)**: Throttles flush interval to $30\text{ms}$, sets fast retransmit `resend=1`, and activates Reno congestion control ($\text{nc}=0$), saving mobile bandwidth and battery while preserving snappy interactive latency.
  - **Moderate Loss ($0.5\% - 3.0\%$)**: Operates in balanced mode ($20\text{ms}$, `resend=2`, `nc=0`).
  - **Loss Spike ($>3.0\%$)**: Automatically scales up retransmission frequency ($10\text{ms}$, `resend=2`, `nc=1`), bypassing cwnd throttling to blast through wireless loss.
- **Hysteresis & Stabilization**: Requires consecutive clean samples (`StabilizationTicks = 2`) before downscaling, eliminating flapping between states on noisy links.
- **Full Observability**: Publishes live metrics (`kcp_out_segs`, `kcp_retrans_segs`, `kcp_lost_segs`, `kcp_snd_queue`) via `/debug/vars` expvar and provides `KCPStatsProvider` interface.
- **CLI & TOML Controls**: Fully configurable via `adaptive_kcp = true/false` in server/client TOML and `--adaptive-kcp` / `--no-adaptive-kcp` CLI flags.

---

## 2. Architecture & State Machine

### 2.1 Dynamic ARQ State Machine

```mermaid
stateDiagram-v2
    [*] --> LowLoss: Link Initialized (Clean)
    
    LowLoss --> HighLoss: Loss Spike (>3.0%) [Fast Attack]
    LowLoss --> ModerateLoss: Moderate Loss (0.5% - 3.0%)
    
    ModerateLoss --> HighLoss: Loss Spike (>3.0%) [Fast Attack]
    ModerateLoss --> LowLoss: Sustained Clean Link (<0.5%) for 2 Ticks
    
    HighLoss --> ModerateLoss: Loss Moderates (0.5% - 3.0%)
    HighLoss --> LowLoss: Sustained Clean Link (<0.5%) for 2 Ticks
    
    state LowLoss {
        interval : 30ms
        resend : 1
        nc : 0 (Congestion Control ON)
    }
    
    state ModerateLoss {
        interval : 20ms
        resend : 2
        nc : 0 (Congestion Control ON)
    }
    
    state HighLoss {
        interval : 10ms
        resend : 2
        nc : 1 (Turbo Mode / cwnd bypass)
    }
```

### 2.2 Sequence Flow: Ingress Link Loss Spike & Recovery

```mermaid
sequenceDiagram
    autonumber
    actor Peer as Remote KCP Peer
    participant Net as Carrier Link (veth / netem)
    participant KCP as KCP Engine (UDPSession)
    participant Tuner as AdaptiveTuner Goroutine (100ms)
    participant Pump as Relay Pump Data Stream

    Note over Net: Phase 1: Clean Link (Loss < 0.5%)
    Tuner->>KCP: Step(): loss=0.000 < 0.005
    Note over Tuner,KCP: State: LowLoss (interval=30ms, resend=1, nc=0)<br/>Quiescent packet rate reduced by 66%
    
    Note over Net: Phase 2: Loss Spike Injected (5% netem loss)
    Peer->>Net: Transmit Packets (5% dropped)
    KCP->>KCP: Detects Missing Segments -> Fast Retransmit
    Tuner->>KCP: Step(): tickLoss=0.050 >= 0.030
    Note over Tuner: Fast Attack Triggered!
    Tuner->>KCP: SetNoDelay(1, 10, 2, 1)
    Note over Tuner,KCP: State: HighLoss (interval=10ms, resend=2, nc=1)<br/>Retransmissions scale up; throughput sustained
    
    Note over Net: Phase 3: Link Recovered (Loss 0%)
    Peer->>Net: Packets Delivered Cleanly (0% drops)
    Tuner->>KCP: Step(): tick 1 clean (waiting for stabilization)
    Tuner->>KCP: Step(): tick 2 clean (stabilization verified)
    Tuner->>KCP: SetNoDelay(1, 30, 1, 0)
    Note over Tuner,KCP: State: LowLoss (interval=30ms, resend=1, nc=0)<br/>Bandwidth conservation restored
```

---

## 3. Mathematical & Algorithmic Specification

### 3.1 Metrics Sampling & Sliding Window
At every evaluation interval $T_{\text{check}} = 100\text{ms}$, the controller captures the delta of transmitted and retransmitted segments:
$$\Delta \text{Out}_k = \text{OutSegs}_k - \text{OutSegs}_{k-1}$$
$$\Delta \text{Retrans}_k = \text{RetransSegs}_k - \text{RetransSegs}_{k-1}$$

Samples are maintained in a 5-element ring buffer (representing $500\text{ms}$ of recent history):
$$\text{TotalOut} = \sum_{i=1}^W \Delta \text{Out}_i, \quad \text{TotalRetrans} = \sum_{i=1}^W \Delta \text{Retrans}_i$$

The sample loss rate is:
$$r_{\text{sample}} = \begin{cases} \frac{\text{TotalRetrans}}{\text{TotalOut}}, & \text{TotalOut} > 0 \\ 0, & \text{TotalOut} = 0 \end{cases}$$

### 3.2 Fast Attack & Smooth Decay
- **Spike Detection (Fast Attack)**: If the current tick loss rate $r_{\text{tick}} \ge 3.0\%$ or window loss rate $r_{\text{sample}} \ge 3.0\%$, the moving loss rate immediately adopts the spike value:
  $$\text{movingLossRate} = \max(r_{\text{tick}}, r_{\text{sample}})$$
  This eliminates multi-second filtering delays when transitioning onto poor cellular links.
- **Clean Window Reset**: If $\text{TotalRetrans} = 0$, the moving loss rate drops immediately to $0.0$.
- **Smooth Filtering (EWMA)**: When loss is moderate ($<3.0\%$), EWMA smoothing with $\alpha = 0.5$ filters transient jitter:
  $$\text{movingLossRate} = \alpha \cdot r_{\text{sample}} + (1 - \alpha) \cdot \text{movingLossRate}$$
- **Idle Decay**: If no packets were transmitted, the rate decays by $50\%$ per interval until zero.

### 3.3 Send Queue Backpressure Adjustment
If $\text{sndQueueLen} > \text{QueueThreshold}$ ($32$ segments), the controller detects local buffer pressure. Even under low loss, the flush interval is adjusted to $20\text{ms}$ to accelerate transmission while strictly enforcing $\text{nc}=0$ so KCP honors flow control backpressure.

---

## 4. Configuration & Observability

### 4.1 Configuration Options
In TOML configuration:
```toml
# Server and Client TOML
adaptive_kcp = true # Default: true (set false to pin nodelay=1, interval=10, resend=2, nc=1)
```

CLI flags:
```bash
relay server --adaptive-kcp       # Enabled by default
relay server --no-adaptive-kcp    # Pinned static mode

relay client --kcp --adaptive-kcp # Enabled by default
relay client --kcp --no-adaptive-kcp
```

### 4.2 Observability & expvar
Live metrics published to `/debug/vars`:
| Metric Key | Type | Description |
|---|---|---|
| `kcp_out_segs` | `uint64` | Total KCP segments transmitted on wire |
| `kcp_retrans_segs` | `uint64` | Accumulated fast, early, and RTO retransmissions |
| `kcp_lost_segs` | `uint64` | Segments inferred as lost due to RTO timeouts |
| `kcp_snd_queue` | `uint64` | Segments awaiting send window entry |

Any `transport.Conn` carrying KCP implements `transport.KCPStatsProvider`:
```go
type KCPStatsProvider interface {
    AdaptiveKCPStats() (TunerStats, bool)
}
```

---

## 5. Verification & Empirical Benchmarks

### 5.1 Automated Unit & Concurrency Test Matrix
- `TestAdaptiveKCPConfigDefaults`: Asserts default parameters ($30\text{ms}/10\text{ms}$, thresholds $0.5\%/3.0\%$).
- `TestAdaptiveTunerStateTransitions`: Evaluates deterministic mock metrics through clean link $\to$ $5\%$ spike fast-attack $\to$ sliding window clearing $\to$ 2-tick stabilization back to `low_loss`.
- `TestAdaptiveTunerQueueBackpressure`: Validates send queue threshold adaptation ($Q > 32 \to \text{interval}=20\text{ms}, \text{nc}=0$).
- `TestAdaptiveTunerIdleDecayAndWrap`: Asserts clean zero decay on idle traffic and SNMP counter reset safety.
- `TestAdaptiveKCPIntegrationE2E`: Full client/server UDP mux exchange with live `AdaptiveKCPStats()`.
- `TestAdaptiveKCPDisabled`: Confirms zero tuner overhead when disabled.
- `TestAdaptiveKCPInRelay`: End-to-end bidirectional relay transfer with SHA-256 integrity check.
- **Race Detector**: `go test -race ./...` 100% green across all packages.

### 5.2 Live Dual-Netns Simulation Benchmark (`scripts/test_perf_kcp_adaptive.py`)
Executed inside isolated Linux network namespaces (`ns-srv` $\leftrightarrow$ `ns-cli`) over virtual ethernet with real OpenSSH `ProxyCommand`:

```
=== Test 1: Byte & Packet Efficiency on Clean Link (Adaptive vs Fixed 10ms) ===
  Fixed 10ms KCP total packets: 166
  Adaptive KCP total packets: 154
  Packet Reduction: 12 packets (7.2% reduction)
>>> [PASS] ADAPT-01-Byte-Efficiency: Adaptive KCP reduced packets from 166 to 154 (7.2% reduction)

=== Test 2: Dynamic Adaptation under Loss Profile (0% -> 5% -> 0%) ===
Launching stream transfer across netem loss profile...
  [Phase 1] Clean link: 0% loss, 40ms delay...
  [Phase 2] Injecting 5% packet loss spike (>3%)...
  [Phase 3] Restoring link to 0% loss (<0.5%)...
>>> [PASS] ADAPT-02-Loss-Profile: Byte-exact SHA-256 match (ae953867a6244f22...) across 0% -> 5% -> 0% netem profile

=== Test 3: HA Dual-Path with Adaptive KCP (--allow-ha) ===
>>> [PASS] ADAPT-03-AllowHA-KCP: Byte-exact SHA-256 match (c75fbd7259be1192...) under --allow-ha and Adaptive KCP

SUMMARY: 3 passed, 0 failed
```
