# remote-relay — Feature Proposal & Roadmap Specification (`features.md`)

This document outlines architectural and functional feature proposals designed to enhance the **robustness**, **developer utility**, **security**, and **enterprise observability** of `remote-relay`.

Each proposal includes:
- **Unique Feature ID** & **Assigned Priority** (`P0` critical, `P1` high, `P2` medium, `P3` low/enhancement).
- **Architectural Tiering**.
- **Current Limitation / Problem Statement** (with codebase references).
- **Technical Architecture & Implementation Specification**.
- **Expected Impact & Validation Strategy**.

> [!NOTE]
> Detailed technical specifications, task breakdowns, and verification matrices for implemented features are archived in the [`.feat-impl/`](.feat-impl) directory (e.g. [`FEAT-ROB-01.md`](.feat-impl/FEAT-ROB-01.md), [`FEAT-SEC-01.md`](.feat-impl/FEAT-SEC-01.md)).

---

## Executive Summary & Priority Matrix

| Feature ID | Feature Name | Tier | Priority | Complexity | Target Impact |
|:---|:---|:---:|:---:|:---:|:---|
| [**FEAT-ROB-01**](.feat-impl/FEAT-ROB-01.md) | Sub-Second Dead-Peer Detection & Dual-Path BFD | Tier 1: Robustness | **P1** | Complete | RFC 5880 BFD engine, sub-second drop detection & instant hot-standby failover |
| **FEAT-ROB-02** | Zero-Downtime Server Restart & Socket Handover | Tier 1: Robustness | **P2** | High | Upgrades server without dropping active SSH sessions |
| **FEAT-ROB-03** | Dual-Stack Happy Eyeballs v2 (RFC 8305) | Tier 1: Robustness | **P2** | Medium | Instant connection racing across IPv4/IPv6 networks |
| **FEAT-ROB-04** | Tiered Disk-Spill Storage for Ring Buffers | Tier 1: Robustness | **P3** | High | Prevents buffer exhaustion during prolonged outages |
| **FEAT-UTL-01** | Native OpenSSH Agent (`SSH_AUTH_SOCK`) Support | Tier 2: Utility | **P1** | Low | Passphrase-protected keys & FIDO2/YubiKey support |
| **FEAT-UTL-02** | Terminal Reconnection HUD & Desktop Notifications | Tier 2: Utility | **P1** | Low | Clear visual feedback and status during link drops |
| **FEAT-UTL-03** | SOCKS5 Dynamic Forwarding Mode (`relay socks`) | Tier 2: Utility | **P2** | Medium | Expands relay beyond SSH to generic browser/DB proxy |
| **FEAT-UTL-04** | Reverse Relay & NAT Gateway Mode (Inverted Tunnel) | Tier 2: Utility | **P2** | High | Reaches home labs and private VPCs behind NAT |
| [**FEAT-SEC-01**](.feat-impl/FEAT-SEC-01.md) | Encrypted Handshake Control Plane (X25519 / ChaCha20-Poly1305) | Tier 3: Security | **P1** | Complete | SSH-style X25519 ECDH + Ed25519 host keys + ChaCha20-Poly1305 control encryption |
| **FEAT-SEC-02** | WebSocket & HTTPS Port 443 Fallback Transport | Tier 3: Security | **P3** | High | Bypasses restrictive enterprise firewalls & DPI |
| **FEAT-SEC-03** | Per-User RBAC & Live `SIGHUP` Configuration Reload | Tier 3: Security | **P2** | Medium | Hot updates to `authorized_keys` & destination ACLs |
| **FEAT-PERF-01**| Linux Kernel Zero-Copy Stream Splicing (`splice(2)`) | Tier 4: Performance | **P3** | Medium | Halves CPU & memory bus overhead on multi-gigabit links |
| **FEAT-PERF-02**| Adaptive KCP Dynamic ARQ & Congestion Tuning | Tier 4: Performance | **P3** | Medium | Dynamic packet retransmission on fluctuating mobile links |
| **FEAT-OBS-01** | Prometheus Metrics Endpoint & OpenTelemetry Tracing | Tier 4: Observability| **P2** | Low | Production-grade SLA alerting & Grafana monitoring |

---

## Tier 1: Core Robustness & Network Fault Tolerance

### [FEAT-ROB-01](.feat-impl/FEAT-ROB-01.md): Sub-Second Dead-Peer Detection & Dual-Path BFD Architecture
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/bfd`, `internal/relay`, `internal/transport`, `internal/proto`, `cmd/relay`

#### 1. Problem Statement
In [`client.go`](file:///root/remote-relay/internal/relay/client.go), the client originally relied on [`cfg.IdleTimeout`](file:///root/remote-relay/internal/config/config.go) (default `30s`) and OS TCP keepalives to detect connection termination. If a mobile device changed cell towers, switched from Wi-Fi to cellular, or put a laptop into sleep mode, packets were silently dropped (blackholed). The user’s terminal froze for 30 to 60 seconds before the client recognized the outage and entered the reconnect loop.

#### 2. Technical Implementation
- **RFC 5880 Asynchronous BFD Engine (`internal/bfd`)**: Implemented 20-byte binary packet payload state machine (`Down`, `Init`, `Up`) over `proto.TypePing` (0x15). Unsolicited `proto.TypePong` echo dropped.
- **Sub-Second Detection**: Configurable `heartbeat_interval` (default `750ms`) and `dead_peer_threshold` (default `3`). Silence $\ge 2.25\text{s}$ triggers `ErrDeadPeer` and immediate teardown.
- **Dual-Path Hot-Standby Architecture (`--allow-ha`)**: Concurrent active UDP and standby TCP connections exchanging BFD heartbeats simultaneously.
- **Zero-Latency Seamless Failover**: Instant promotion of standby TCP carrier upon active UDP failure with no dial round-trip, deduplication via `session.Dedupe`, and autonomous background reconnect to restore failed paths.

#### 3. Verification
- 100% unit and race test pass in `internal/bfd` and `internal/relay` with `-race`.
- Dual-netns Linux integration benchmarks: Silent blackhole detected in **2.26s** (vs 30s TCP timeout) and instant failover under load with zero byte loss.

---

### FEAT-ROB-02: Zero-Downtime Server Restarts & Socket Handover (`LISTEN_FDS` / `SCM_RIGHTS`)
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `internal/relay`, `cmd/relay`, `internal/session`

#### 1. Problem Statement
As documented in [`README.md`](file:///root/remote-relay/README.md), session hold state and destination TCP sockets live strictly in memory inside [`Server`](file:///root/remote-relay/internal/relay/server.go). If the relay server process restarts (for software updates or configuration changes), all active destination sockets are closed immediately. When clients reconnect, they receive `ERR_UNKNOWN_SESSION` and all SSH sessions terminate.

#### 2. Technical Specification
- **Socket Passing via `SCM_RIGHTS`**: Support hot re-exec on `SIGUSR2`:
  1. The existing server process listens for `SIGUSR2`.
  2. The parent process forks and executes the updated `relay server` binary.
  3. The parent serializes active session metadata from [`Store`](file:///root/remote-relay/internal/session/store.go) (session IDs, token hashes, stream offsets, and unacknowledged ring buffers) into an IPC stream.
  4. The parent passes listening file descriptors (`listen_tcp`, `udp_listen`) and connected destination TCP socket FDs to the child process via Unix domain socket `SCM_RIGHTS`.
  5. The child initializes its internal state from the serialized data, resumes destination polling, and takes over incoming traffic.
  6. The parent exits cleanly without sending `BYE{ERR_SHUTDOWN}` or closing destination sockets.
- **Systemd Socket Activation**: Support `LISTEN_FDS` so systemd manages the listening sockets across service restarts.

#### 3. Benefits & Verification
- Server updates, patches, and reboots can be performed with zero disruption to long-running developer SSH sessions and tunnels.
- **Verification**: Run continuous `rsync` over `ProxyCommand`, send `SIGUSR2` to the server process PID, and verify the file transfer completes with matching SHA-256 and zero dropped sessions.

---

### FEAT-ROB-03: Dual-Stack Happy Eyeballs v2 (RFC 8305)
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `internal/relay`, `internal/transport`

#### 1. Problem Statement
Client connection establishment in [`clientHello`](file:///root/remote-relay/internal/relay/client.go) and UDP probing in [`upgrade.go`](file:///root/remote-relay/internal/relay/upgrade.go) use standard `net.Dial`, which attempts resolved IP addresses sequentially. In dual-stack environments where IPv6 is broken, route-filtered, or where corporate firewalls block IPv4 UDP while allowing IPv6 UDP, sequential connection attempts cause multi-second stalls or outright failures.

#### 2. Technical Specification
- **Concurrent Address Resolution**: Resolve both `A` (IPv4) and `AAAA` (IPv6) records in parallel.
- **Staggered Dual Dials**: Implement RFC 8305 Happy Eyeballs algorithm:
  - Start dialing IPv6 first.
  - If IPv6 does not establish within `ConnectionAttemptDelay` (250ms), launch concurrent IPv4 dial.
  - The first socket to successfully complete the handshake wins and becomes the session transport; the other socket is closed immediately.
- **Probe Racing**: Apply the same Happy Eyeballs racing logic to the UDP probe phase in [`transport.Probe`](file:///root/remote-relay/internal/transport/conn.go).

#### 3. Benefits & Verification
- Eliminates connection hangs on broken IPv6 networks and optimizes connection latency across heterogeneous network links.
- **Verification**: Create a netns environment with blackholed IPv6 and responsive IPv4, assert connection latency is <300ms.

---

### FEAT-ROB-04: Tiered Disk-Spill Storage for Ring Buffers
* **Priority**: `P3` (Low)
* **Status**: Proposed
* **Target Package**: `internal/session`

#### 1. Problem Statement
Session ring buffers in [`session.Ring`](file:///root/remote-relay/internal/session/ringbuf.go) are strictly backed by RAM slices. Under the default configuration, per-session capacity is capped at 64 MiB and global budget at 512 MiB ([`session.Budget`](file:///root/remote-relay/internal/session/budget.go)). During prolonged disconnections (e.g. 5–10 minutes) during massive bulk transfers, the ring buffer saturates quickly, pausing upstream reads and risking session drop if memory limits are exceeded.

#### 2. Technical Specification
- **Tiered Ring Architecture**:
  - Split [`session.Ring`](file:///root/remote-relay/internal/session/ringbuf.go) into an in-memory L1 cache (e.g. up to 8 MiB) and an on-demand L2 spill storage.
  - When in-memory data exceeds the L1 threshold, sequentially write overflow data blocks to an encrypted temporary disk file (using `O_TMPFILE` or unlink-on-open on Linux).
  - Encrypt spilled blocks using AES-GCM with an ephemeral per-session key generated at startup.
  - During retransmission on `RESUME`, stream unacknowledged bytes sequentially from the spill file, purging acknowledged segments via `fallocate(FALLOC_FL_PUNCH_HOLE)`.

#### 3. Benefits & Verification
- Enables sustained gigabyte-scale hold buffers across multi-minute outages without exhausting server RAM or causing OOM kills.
- **Verification**: Stream 2 GiB through a paused reader session with `buffer_bytes = 1073741824`, verify RAM consumption remains <32 MiB and payload matches byte-for-byte upon resumption.

---

## Tier 2: Practical Utility & Developer Workflows

### FEAT-UTL-01: Native OpenSSH Agent (`SSH_AUTH_SOCK`) Integration
* **Priority**: `P1` (High)
* **Status**: Proposed
* **Target Package**: `internal/auth`

#### 1. Problem Statement
The current SSH public key authenticator in [`ssh.go`](file:///root/remote-relay/internal/auth/ssh.go) directly parses unencrypted private keys from disk files (`identity_files = ["~/.ssh/id_ed25519"]`). It cannot use:
1. Passphrase-protected private keys (fails with decryption errors).
2. Keys loaded into the user's running `ssh-agent`.
3. Hardware tokens such as YubiKey / FIDO2 security keys (`sk-ssh-ed25519@openssh.com`).

#### 2. Technical Specification
- **Agent Dialing**: Connect to the local Unix domain socket specified by the environment variable `$SSH_AUTH_SOCK`.
- **`ssh.Agent` Key Discovery**: Use `golang.org/x/crypto/ssh/agent` to enumerate available signers.
- **Signature Delegation**: When responding to the server's cryptographic challenge in [`auth.PublicKey.Respond`](file:///root/remote-relay/internal/auth/ssh.go), delegate the signature operation directly to `agent.Sign(key, challengeDigest)`.
- **Fallback Chain**:
  1. Try active `ssh-agent` keys.
  2. Fall back to unencrypted files specified in `identity_files`.
  3. Fail cleanly with clear error messaging if no valid signer is found.

#### 3. Benefits & Verification
- Seamless out-of-the-box support for corporate workstations with enforced passphrase keys, smart cards, and hardware tokens without touching raw private key bytes.
- **Verification**: Start `ssh-agent`, add a test key, run client with `auth_method = "ssh-publickey"` and no files on disk, assert successful authentication.

---

### FEAT-UTL-02: Terminal Reconnection HUD & Desktop Notifications
* **Priority**: `P1` (High)
* **Status**: Proposed
* **Target Package**: `internal/relay`, `cmd/relay`

#### 1. Problem Statement
Because stdout is reserved exclusively for the raw SSH byte stream, the client prints minimal logs to stderr. When a connection drops, the terminal becomes unresponsive with no visual cue. Users cannot tell whether the server is down, the network link is recovering, or the session has failed permanently.

#### 2. Technical Specification
- **TTY Detection**: Check if `os.Stderr` is an interactive terminal (`isatty.IsTerminal`).
- **In-Place Status Line (HUD)**: During reconnection attempts, render an unobtrusive single-line status bar updated via carriage returns (`\r`):
  ```text
  [remote-relay] Link disrupted. Reconnecting via QUIC... (attempt 2/8, 1.4s elapsed)
  ```
  On successful resumption, overwrite with:
  ```text
  [remote-relay] Link restored via QUIC in 1.8s (resumed 34.2 KiB buffered).
  ```
- **Terminal Notifications (OSC 9 / OSC 777)**: For prolonged disconnections (>5s), emit terminal escape sequences:
  - `\033]9;remote-relay: Link lost, attempting reconnect...\007`
  - Compatible with modern terminal emulators (Ghostty, iTerm2, WezTerm, Alacritty, Windows Terminal).

#### 3. Benefits & Verification
- Eliminates user confusion during network interruptions while guaranteeing 100% clean stdout isolation for SSH.
- **Verification**: Run client in a pseudo-terminal (PTY), drop network, assert stderr receives single-line updates and stdout remains 100% byte-clean.

---

### FEAT-UTL-03: SOCKS5 Dynamic Forwarding Mode (`relay socks`)
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `cmd/relay`, `internal/relay`, `internal/proto`

#### 1. Problem Statement
`remote-relay` is currently limited to 1:1 stdio↔TCP socket bridging. Users who want resilient, zero-drop connectivity for web browsers, database GUIs, or multiple microservices must either configure complex SSH `-D` tunnels or run external proxies.

#### 2. Technical Specification
- **SOCKS5 Server Subcommand**:
  ```bash
  relay socks --listen 127.0.0.1:1080 --server relay.example.com:7443
  ```
- **Multiplexed Logical Streams**:
  - Extend the data plane to support multiplexed streams over a single resilient QUIC connection or framed TCP session.
  - Frame structure: `[StreamID uint32] [FrameType uint8] [Payload]`.
  - When an application connects to `127.0.0.1:1080`, handle SOCKS5 handshake, assign a new `StreamID`, and request the relay server dial the target host:port.
- **Per-Stream Resumption**: If the physical link drops, the underlying tunnel reconnects and all multiplexed SOCKS5 streams resume seamlessly.

#### 3. Benefits & Verification
- Converts `remote-relay` into an unbreakable mobile proxy for all TCP application traffic.
- **Verification**: Point `curl --socks5 127.0.0.1:1080 https://example.com` through the proxy while injecting link breaks, verify HTTP request completes successfully.

---

### FEAT-UTL-04: Reverse Relay & NAT Gateway Mode (Inverted Tunnel)
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `cmd/relay`, `internal/relay`

#### 1. Problem Statement
The current architecture assumes the server has a public IP address and the destination is reachable from the server. If the target machine is located behind NAT, CGNAT, or firewall (such as a home lab server, IoT appliance, or private cloud instance), external access requires third-party tools (e.g. `frp`, `cloudflared`, `bore`).

#### 2. Technical Specification
- **Agent Subcommand (`relay agent`)**:
  ```bash
  # On internal private server behind NAT:
  relay agent --server public-relay.example.com:7443 --name homelab --dest 127.0.0.1:22 --key agent.key
  
  # On client:
  relay client --server public-relay.example.com:7443 --target homelab
  ```
- **Control Channel Registration**:
  - The agent opens an outbound control connection to the public relay server and registers its identity.
  - When a client connects to the public server requesting `--target homelab`, the server issues a `BIND_REQUEST` over the agent's control channel.
  - The agent dials `127.0.0.1:22` locally, establishes a data stream to the server, and the server bridges client and agent data planes with full session hold and retransmission.

#### 3. Benefits & Verification
- Enables secure, resilient inbound SSH access to machines behind NAT without port forwarding.
- **Verification**: Place agent in a private netns with default drop on incoming traffic; client connects via public server and maintains session across link resets.

---

## Tier 3: Security & Network Traversal Hardening

### [FEAT-SEC-01](.feat-impl/FEAT-SEC-01.md): Encrypted Handshake Control Plane (X25519 & ChaCha20-Poly1305)
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/crypto/kex`, `internal/proto`, `internal/config`, `internal/relay`, `cmd/relay`

#### 1. Problem Statement
As noted in [`design.md` §10.1](file:///root/remote-relay/design.md#L500-L511), the TCP control plane was originally sent in cleartext JSON. Although SSH payloads are encrypted, on-path network observers could inspect `HELLO`, `RESUME`, `sessionId`, `resumeToken`, destination IPs/ports, and authentication tokens. This enabled metadata tracking, session token interception, and targeted middlebox DPI filtering.

#### 2. Technical Specification
- **SSH-Style Ephemeral Key Exchange (`internal/crypto/kex`)**:
  - Ephemeral X25519 Diffie-Hellman key agreement with HKDF-SHA256 key derivation for distinct directional keys (`Key_c2s` and `Key_s2c`).
  - Server identity authenticated via Ed25519 host key signature over the complete cryptographic exchange transcript hash $H$.
- **Host Key Management & Fingerprint Verification**:
  - Auto-generated or file-based OpenSSH Ed25519 server host keys (`--host-key`).
  - OpenSSH-format `known_hosts` verification (`~/.config/relay/known_hosts`, `--known-hosts`) with Trust On First Use (TOFU), MITM change detection, and strict checking policies (`--strict-host-key-checking=yes|no|accept-new`).
  - Explicit fingerprint pinning via `--server-fingerprint SHA256:...`.
- **ChaCha20-Poly1305 AEAD Symmetric Framing (`TypeEncrypted` 0x0D)**:
  - ChaCha20-Poly1305 authenticated encryption with strictly increasing 64-bit sequence counters (`CipherConn`).
  - Strict encrypted-only mode: cleartext handshakes are rejected immediately with `ERR_PROTO`.
- **Option A Clean Phase Cut Transition**:
  - Once the encrypted control handshake (`HELLO`/`HELLO_OK` or `RESUME`/`RESUME_OK`) finishes, the connection cleanly transitions to raw wire frames for `TypeData` (0x10), avoiding double-encryption overhead with inner SSH payloads.

#### 3. Verification & Benchmark Results
- **Unit & Concurrency Tests**: 100% pass across `internal/crypto/kex`, `internal/proto`, `internal/config`, `internal/relay`, and `cmd/relay` under `-race`.
- **Dual-Netns Linux Verification Matrix**: 6/6 tests passing in isolated network namespaces (`ns-srv` <-> `ns-cli` via `veth`) with real OpenSSH 10 MiB payload tunneling:
  - `SEC-01-E2E-Transfer`: PASS (10 MiB byte-exact SHA-256 match, host key recorded).
  - `SEC-02-Fingerprint-Correct`: PASS (matching fingerprint verified).
  - `SEC-02-Fingerprint-Mismatch-Reject`: PASS (immediate non-zero exit).
  - `SEC-02-MITM-Detection`: PASS (altered known_hosts entry rejected instantly).
  - `SEC-03-Plaintext-Probe-Rejected`: PASS (server drops cleartext probe with `ERR_PROTO`).
  - `SEC-04-Wire-Inspection`: PASS (`tcpdump` inspection confirmed zero cleartext metadata or session tokens on wire).

---

### FEAT-SEC-02: WebSocket & HTTPS Port 443 Fallback Transport
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `internal/transport`, `internal/relay`

#### 1. Problem Statement
Strict enterprise firewalls, corporate proxies, and public Wi-Fi portals (e.g. hotels and airports) frequently block all non-standard ports (such as 7443) and drop all UDP traffic, preventing both QUIC and direct TCP handshakes.

#### 2. Technical Specification
- **WebSocket Transport Adapter**:
  - Implement a `transport.Conn` adapter backed by `gorilla/websocket` or `coder/websocket`.
  - Connect via HTTPS: `wss://relay.example.com/relay-stream`.
- **Multiplexing on Existing Web Servers**:
  - Allow the relay server to serve the WebSocket endpoint behind Nginx, Caddy, or standard Go HTTP reverse proxies on port 443.
  - Transparent HTTP proxy support (reads `HTTP_PROXY` and `HTTPS_PROXY` environment variables and sends HTTP `CONNECT` headers).

#### 3. Benefits & Verification
- Ensures connection survivability even on restricted networks where only outbound HTTPS (TCP port 443) is permitted.
- **Verification**: Route traffic through an Squid HTTP proxy that blocks all non-443 ports; verify client successfully connects and resumes.

---

### FEAT-SEC-03: Per-User RBAC & Live `SIGHUP` Configuration Reload
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `internal/auth`, `internal/config`, `internal/relay`

#### 1. Problem Statement
[`allow_destinations`](file:///root/remote-relay/internal/config/config.go) is a single global list. Any authenticated user can access any allowed destination. In addition, updating access keys or destinations requires restarting the server process, which terminates active sessions.

#### 2. Technical Specification
- **Role-Based Access Policies**:
  - Associate destinations with authorized keys or groups in `authorized_keys` (using OpenSSH options format, e.g. `permitopen="10.0.1.*:22,127.0.0.1:22"`).
  - Enforce destination filtering during `HELLO` validation prior to dialing.
- **`SIGHUP` Configuration Reload**:
  - Intercept `syscall.SIGHUP` in [`Server`](file:///root/remote-relay/internal/relay/server.go).
  - Re-read `server.toml` and `authorized_keys`.
  - Atomically swap the configuration pointer using `atomic.Pointer[config.Server]`.
  - Existing sessions remain active; new sessions immediately adopt the updated rules.

#### 3. Benefits & Verification
- Multi-user enterprise isolation and live credential updates without operational downtime.
- **Verification**: Connect client with restricted key, attempt to dial forbidden destination (expect `ERR_AUTH`); update `authorized_keys`, send `kill -HUP $PID`, verify new key is immediately accepted.

---

## Tier 4: Performance & Enterprise Observability

### FEAT-PERF-01: Linux Kernel Zero-Copy Stream Splicing (`splice(2)`)
* **Priority**: `P3` (Low)
* **Status**: Proposed
* **Target Package**: `internal/relay`

#### 1. Problem Statement
In TCP mode, data transfer involves reading bytes from `stdin` into Go user-space buffers and writing them to the network socket (and vice versa for `stdout`). This user/kernel context switching and memory copying imposes CPU cache pressure and bottlenecks throughput on multi-gigabit links.

#### 2. Technical Specification
- **Direct Pipe Splicing**:
  - On Linux (`GOOS=linux`), utilize the `splice(2)` system call via `golang.org/x/sys/unix`.
  - Directly splice descriptor pipes: `splice(stdin_fd -> pipe -> socket_fd)` and `splice(socket_fd -> pipe -> stdout_fd)`.
  - Maintain offset bookkeeping by intercepting the spliced byte counts.

#### 3. Benefits & Verification
- Reduces CPU utilization by 40–60% during high-throughput file transfers (e.g. multi-gigabit `scp` or `rsync`).
- **Verification**: Benchmark 10 Gbps loopback transfer using `iperf` through the relay; compare CPU core utilization with and without splicing.

---

### FEAT-PERF-02: Adaptive KCP Congestion & Dynamic ARQ Tuning
* **Priority**: `P3` (Low)
* **Status**: Proposed
* **Target Package**: `internal/transport`

#### 1. Problem Statement
[`transport/kcp.go`](file:///root/remote-relay/internal/transport/kcp.go) uses fixed parameters (`nodelay=1, interval=10ms, resend=2, nc=1`). While this provides throughput on lossy links, it can cause packet bloat and bandwidth saturation on narrow mobile links.

#### 2. Technical Specification
- **Dynamic Link Probing**:
  - Monitor moving loss rate and send queue length.
  - When packet loss is low (<0.5%), throttle back `interval` to 30ms and `resend` to 1 to conserve bandwidth.
  - When packet loss spikes (>3%), automatically scale up retransmission frequency.

#### 3. Benefits & Verification
- Saves mobile data quota while preserving high throughput and low interactive keystroke latency.
- **Verification**: Run benchmark under varying `tc netem` loss profiles (0% -> 5% -> 0%) and measure byte efficiency.

---

### FEAT-OBS-01: Prometheus Metrics Exporter & OpenTelemetry Tracing
* **Priority**: `P2` (Medium)
* **Status**: Proposed
* **Target Package**: `internal/relay`

#### 1. Problem Statement
[`obs.go`](file:///root/remote-relay/internal/relay/obs.go) currently only exposes basic `expvar` variables (`sessions`, `held`, `buffer_used`, `accepts`, `refused`). It lacks dimensional labels, histograms, latency percentiles, and compatibility with industry-standard monitoring systems (Prometheus, Grafana, Datadog).

#### 2. Technical Specification
- **Prometheus Exporter (`/metrics`)**:
  - Expose a Prometheus metrics endpoint with standard metrics:
    - `relay_active_sessions{transport="quic|kcp|tcp"}` (gauge)
    - `relay_reconnect_total{status="success|failure"}` (counter)
    - `relay_reconnect_duration_seconds` (histogram with buckets: 0.1s, 0.5s, 1s, 2s, 5s, 10s)
    - `relay_held_duration_seconds` (histogram)
    - `relay_bytes_transferred_total{direction="up|down", transport="..."}` (counter)
    - `relay_buffer_utilization_ratio` (gauge)
- **OpenTelemetry Tracing**:
  - Instrument session lifecycle events with trace spans (`Handshake`, `Upgrade`, `Resume`).

#### 3. Benefits & Verification
- Out-of-the-box observability for enterprise SRE teams with alerting on disconnection spikes or high resume failure rates.
- **Verification**: Scrape `/metrics` endpoint with Prometheus, verify metric validity, and generate Grafana dashboard panels.

---

## 4. Implementation Phasing & Next Steps

```
Phase 1: Usability & Resiliency Quick-Wins (1–2 weeks)
├── FEAT-UTL-01: Native OpenSSH Agent (SSH_AUTH_SOCK)
├── FEAT-UTL-02: Terminal Reconnection HUD (stderr)
└── FEAT-ROB-01: Sub-Second Dead-Peer Detection (Fast Heartbeats) [COMPLETED]

Phase 2: Enterprise Operations & Security (2–4 weeks)
├── FEAT-OBS-01: Prometheus Metrics Endpoint
├── FEAT-SEC-03: Per-User RBAC & SIGHUP Reload
├── FEAT-SEC-01: Encrypted Handshake Control Plane
└── FEAT-ROB-03: Dual-Stack Happy Eyeballs v2

Phase 3: Expanded Utility & High Availability (4–6 weeks)
├── FEAT-ROB-02: Zero-Downtime Server Restarts (SCM_RIGHTS)
├── FEAT-UTL-03: SOCKS5 Dynamic Forwarding Mode
├── FEAT-UTL-04: Reverse Relay & NAT Gateway Mode
└── FEAT-SEC-02: WebSocket & HTTPS Port 443 Fallback

Phase 4: Advanced Optimizations (Ongoing)
├── FEAT-PERF-01: Linux Kernel Zero-Copy Stream Splicing
├── FEAT-PERF-02: Adaptive KCP Congestion Tuning
└── FEAT-ROB-04: Tiered Disk-Spill Storage for Ring Buffers
```
