# remote-relay — verification status & findings

Complete verification of the TCP data plane (`--tcp`), network resilience matrix, resource management, and realistic network path benchmarks.

All experiments were executed with strict network isolation using dedicated Linux network namespaces (`ns-srv` <-> `ns-cli`) over a `veth` pair (`veth-srv` 10.200.1.1/24 <-> `veth-cli` 10.200.1.2/24). Hot host networking remained 100% untouched throughout all tests (`lo` qdisc stayed `noqueue`, zero relay firewall rules on host).

---

## 1. Summary of Verification Results

| Category | Checks | Status | Details |
|---|---|---|---|
| **Code Quality & CI** | `gofmt`, `go vet`, `staticcheck` | **PASS** | Clean across all packages; staticcheck 0 findings |
| **Race & Unit Tests** | `go test -race -count=1 ./...` | **PASS** | Clean across all packages (`internal/relay` ~29s) |
| **Coverage** | All packages | **PASS** | `cmd/relay` 74.3%, `auth` 75.0%, `config` 77.9%, `logging` 82.4%, `proto` 94.2%, `relay` 77.1%, `session` 77.1%, `transport` 76.5% |
| **Cross-Builds** | linux/amd64, linux/arm64, darwin/arm64 | **PASS** | All binaries compile cleanly |
| **TCP Break Matrix** | T0 through T11 (13 trials) | **PASS (13/13)** | Real `sshd` + `ProxyCommand`, 32 MiB payloads, SHA-256 verified |
| **Backpressure** | Throttled / paused reader mid-stream | **PASS** | Ring buffer bounded; completed byte-exact (SHA-256 match) |
| **Resource Leaks** | 50 sequential broken/resumed sessions | **PASS** | Zero FD leaks (delta: 0 FDs), `sessions`=0, `held`=0, `buffer_used`=0 |
| **Netem Benchmarks** | 80ms RTT, 3% loss | **PASS** | TCP: 0.06 MB/s, QUIC: 0.04 MB/s, KCP: 2.00 MB/s (33x–50x faster) |
| **Deduplication (I3)**| 80ms RTT, 25% reorder, 1% duplicate | **PASS** | Verified byte-exact on TCP, QUIC, and KCP |
| **Host Safety** | Host `lo`, `iptables`, production `sshd:22` | **PASS** | 100% untouched; all traffic and faults confined to namespaces |

---

## 2. TCP Break Matrix Results (T0–T11)

All tests executed with `--tcp`, real `sshd`, 32 MiB payloads, and SHA-256 verification inside isolated dual netns:

- [x] **T0** (No UDP opened in `--tcp` mode): **PASS** (`rc=0`, only TCP listener bound, client logged `transport=tcp`).
- [x] **T1** (Silent blackhole 5s < `idle_timeout` 30s): **PASS** (`rc=0`, dur=21.9s, exact=True, 0 resumes).
- [x] **T2** (Silent blackhole 40s > `idle_timeout` 30s): **PASS** (`rc=0`, dur=56.2s, exact=True, resumes=1, server logged `heldMs=10046`).
- [x] **T3** (RST kill 1s): **PASS** (`rc=0`, dur=14.2s, exact=True, resumes=1).
- [x] **T4** (3 repeated RST kills in one session): **PASS** (`rc=0`, dur=14.5s, exact=True, resumes=3).
- [x] **T5** (RST kill during UPLOAD direction): **PASS** (`rc=0`, dur=14.3s, exact=True, resumes=1).
- [x] **T6** (Negative control: `hold_timeout=10s` + 15s outage): **PASS** (`rc=255`, clean termination, server expired held session, client logged `ERR_UNKNOWN_SESSION`).
- [x] **T7** (Break during initial handshake): **PASS** (`rc=0`, dur=3.4s, established=True, message matches).
- [x] **T8** (Break while session is idle, then transfer): **PASS** (`rc=0`, dur=8.4s, exact=True, resumes=2).
- [x] **T9a** (Hold boundary under: 5s outage < 10s hold): **PASS** (`rc=0`, exact=True).
- [x] **T9b** (Hold boundary over: 15s outage > 10s hold): **PASS** (`rc=255`, clean failure).
- [x] **T10** (Server process restart mid-session): **PASS** (`rc=255`, clean failure with `ERR_UNKNOWN_SESSION`).
- [x] **T11** (Outage longer than client's `reconnect_max_elapsed`): **PASS** (`rc=255`, client logged `reconnect budget exhausted`).

---

## 3. Resource & Backpressure Checks (§3.3)

- [x] **Backpressure**: Standard output reader paused for 5 seconds mid-transfer during 32 MiB download. The server's internal ring buffer remained bounded, flow control paused upstream reads, and the transfer finished byte-exact.
- [x] **FD Leak Check**: Server `/proc/<pid>/fd` counted before and after 50 sequential broken/resumed TCP sessions. Baseline FDs: 7, Final FDs: 7 (delta: 0 leaked file descriptors).
- [x] **Goroutine & Buffer Leak Check**: Server `/debug/vars` expvar scraped before and after 50 sessions. `sessions` returned to 0, `held` returned to 0, and `buffer_used` returned to 0.

---

## 4. Realistic Network Path Benchmarks (§3.4)

Transfers of 16 MiB payloads across the `veth` link under two `tc netem` profiles:

### Scenario A: High Latency & Packet Loss (`netem delay 80ms 20ms loss 3%`)
| Transport | Duration (s) | Throughput (MB/s) | Resumes | Byte-Exact |
|---|---|---|---|---|
| **TCP** (`--tcp`) | 257.03 | 0.06 | 0 | Yes |
| **QUIC** (default) | 356.31 | 0.04 | 0 | Yes |
| **KCP** (`--kcp`) | **7.98** | **2.00** | 0 | **Yes (33x–50x faster)** |

*Observation*: TCP and QUIC congestion control back off severely under 80ms RTT and 3% random packet loss. KCP's aggressive ARQ with nodelay/selective repeat sustains 2.00 MB/s.

### Scenario B: Aggressive Reordering & Duplication (`delay 80ms 20ms reorder 25% gap 5 duplicate 1%`)
| Transport | Duration (s) | Throughput (MB/s) | Byte-Exact |
|---|---|---|---|
| **TCP** (`--tcp`) | 319.20 | 0.05 | Yes |
| **QUIC** (default) | 471.21 | 0.03 | Yes |
| **KCP** (`--kcp`) | **5.47** | **2.93** | **Yes** |

*Observation*: Confirms stream integrity and the I3 deduplication/sequencing invariant under heavy out-of-order delivery and duplicated packets.

---

## 5. Code Fixes & Improvements

1. `internal/transport/kcp.go`: Added `//lint:ignore SA1019` explaining stream mode requirement for framing, clearing the only staticcheck finding.
2. `internal/relay/pump.go`: Fixed `reconnectable(err)` to recognize wrapped `net.Error` timeouts, ensuring dial timeouts during network blackouts are retried up to `maxElapsed`.
3. `internal/relay/client.go`:
   - Added initial `clientHello` retry with backoff so transient initial drops don't fail immediately.
   - Bound resume dials with `context.WithDeadline(ctx, deadline)` honoring `reconnect_max_elapsed`.
   - Added structured resume logging (`log.Info("session resumed", ...)`).
4. `cmd/relay`: Added `cmd/relay/main_test.go` testing CLI flag parsing, flag precedence (`--tcp` > `--kcp` > config > default), and `%h %p` positional argument handling (raising package coverage to 74.3%).
5. `internal/proto`: Added tests in `proto_test.go` for `Type.String()`, `proto.Error`, `MarshalFrame`/`UnmarshalPayload`, `RandomNonce()`, and truncated payload decoders (raising package coverage to 94.2%).
6. `internal/transport`: Added `conn_test.go` and `quic_test.go` testing `Kind.String()`, cert generation/loading, TCP transport, and QUIC transport (raising package coverage to 76.5%).
7. `.github/workflows/ci.yml`: Created GitHub Actions CI workflow running `gofmt`, `go vet`, `staticcheck`, `go test -race`, and cross-compilation for `linux/amd64`, `linux/arm64`, and `darwin/arm64`.

---

## 6. High Availability Dual-Path System (`--allow-ha`)

Implementation and verification of the auto-probing and dual-path High Availability system for `remote-relay`.

### 6.1 Design Principles
1. **Strict Transport Enforcement by Default**: When the user requests UDP (default QUIC or `--kcp`) without `--allow-ha`, UDP is strictly mandatory. If UDP route is blocked, unroutable, or fails probing, the client terminates immediately with `udp route unavailable and --allow-ha not specified` rather than silently staying on TCP.
2. **High Availability (`--allow-ha`)**: When `--allow-ha` is enabled:
   - Traffic metric: **`UDP > TCP`**.
   - If UDP is available, data flows over UDP.
   - If UDP fails or is blocked, client seamlessly downgrades to TCP without session disruption.
   - While running on TCP, client continuously probes UDP in the background at `ha_probe_interval` (default 10s, configurable in TOML).
   - When UDP route is restored, client seamlessly upgrades back to UDP mid-stream without lost or duplicate bytes.
3. **Mutual Exclusion**: `--tcp` and `--allow-ha` cannot be passed together (immediate CLI error with exit code 2).

### 6.2 Implementation Changes
- `internal/config/config.go`: Added `AllowHA` (`toml:"allow_ha"`) and `HAProbeInterval` (`toml:"ha_probe_interval"`), client validation enforcing `--allow-ha cannot be used with tcp transport`, and `IsTCP()` helper.
- `cmd/relay/main.go`: Added `--allow-ha` flag with mutual exclusion validation (exit code 2).
- `internal/relay/upgrade.go`: Updated `tryUpgrade` and `takeUpgrade` to enforce strict UDP failure, and implement the background probe supervisor when downgraded in HA mode.
- `internal/relay/client.go`: Added strict pre-flight UDP verification before transferring user data and after resume.
- `internal/relay/ha_test.go`: Added unit tests covering strict mode failure, seamless upgrade, downgrade to TCP, and flapping oscillation.

### 6.3 Verification Matrix Results
| Test ID | Scenario | Expected Behavior | Status |
|---|---|---|---|
| **HA-Unit** | Flag & config validation | `--tcp` + `--allow-ha` errors out with exit code 2; `allow_ha` loads from TOML. | **PASS** |
| **HA-Strict** | No `--allow-ha`, UDP blocked | Client pre-flight fails immediately with exit code != 0 (`udp route unavailable and --allow-ha not specified`). Zero user bytes sent over TCP. | **PASS** (`rc=255`) |
| **HA-Upgrade** | `--allow-ha`, UDP blocked at start | Client operates on TCP. Mid-transfer, UDP is unblocked. Prober detects UDP, client upgrades to QUIC, 32 MiB completes byte-exact. | **PASS** (`rc=0`, SHA-256 match) |
| **HA-Downgrade** | `--allow-ha`, active on QUIC | UDP dropped mid-transfer. Client seamlessly resumes on TCP via RESUME, 32 MiB completes byte-exact. | **PASS** (`rc=0`, SHA-256 match) |
| **HA-Oscillate** | `--allow-ha`, flapping UDP | Repeatedly dropped and restored UDP every 2s during 32 MiB transfer. Dynamic switching between QUIC and TCP completed byte-exact. | **PASS** (`rc=0`, SHA-256 match) |
