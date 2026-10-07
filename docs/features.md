# remote-relay — Feature Proposal & Roadmap Specification (`features.md`)

This document outlines architectural and functional feature proposals designed to enhance the **robustness**, **developer utility**, **security**, and **enterprise observability** of `remote-relay`.

Each proposal includes:
- **Unique Feature ID** & **Assigned Priority** (`P0` critical, `P1` high, `P2` medium, `P3` low/enhancement).
- **Architectural Tiering**.
- **Current Limitation / Problem Statement** (with codebase references).
- **Technical Architecture & Implementation Specification**.
- **Expected Impact & Validation Strategy**.

> [!NOTE]
> Detailed technical specifications, task breakdowns, and verification matrices for implemented features are archived in the [`.feat-impl/`](feat-impl) directory (e.g. [`FEAT-ROB-01.md`](feat-impl/FEAT-ROB-01.md), [`FEAT-SEC-01.md`](feat-impl/FEAT-SEC-01.md)).

---

## Executive Summary & Priority Matrix

| Feature ID | Feature Name | Tier | Priority | Complexity | Target Impact |
|:---|:---|:---:|:---:|:---:|:---|
| [**FEAT-ROB-01**](feat-impl/FEAT-ROB-01.md) | Sub-Second Dead-Peer Detection & Dual-Path BFD | Tier 1: Robustness | **P1** | Complete | RFC 5880 BFD engine, sub-second drop detection & instant hot-standby failover |
| [**FEAT-ROB-02**](feat-impl/FEAT-ROB-02.md) | Zero-Downtime Server Restart & Socket Handover | Tier 1: Robustness | **P1** | Complete | Upgrades server without dropping active SSH sessions via SIGUSR2 & SCM_RIGHTS |
| [**FEAT-ROB-03**](feat-impl/FEAT-ROB-03.md) | Dual-Stack Happy Eyeballs v2 (RFC 8305) | Tier 1: Robustness | **P2** | Complete | Instant connection racing across IPv4/IPv6 networks |
| [**FEAT-ROB-04**](feat-impl/FEAT-ROB-04.md) | Tiered Disk-Spill Storage for Ring Buffers | Tier 1: Robustness | **P3** | Complete | Encrypted L2 disk spill storage with AES-256-GCM, fallocate hole punching & zero-memory-growth streaming |
| [**FEAT-UTL-01**](feat-impl/FEAT-UTL-01.md) | Native OpenSSH Agent (`SSH_AUTH_SOCK`) Support | Tier 2: Utility | **P1** | Complete | Passphrase-protected keys & FIDO2/YubiKey support |
| [**FEAT-UTL-02**](feat-impl/FEAT-UTL-02.md) | Terminal Reconnection HUD & Desktop Notifications | Tier 2: Utility | **P1** | Complete | In-place status line (\r) and OSC 9/777 desktop notifications |
| [**FEAT-UTL-04**](feat-impl/FEAT-UTL-04.md) | Reverse Relay & NAT Gateway Mode (Inverted Tunnel) | Tier 2: Utility | **P2** | Complete | Reaches home labs and private VPCs behind NAT |
| [**FEAT-UTL-05**](feat-impl/FEAT-UTL-05.md) | Multi-Hop Jumphost Chaining (`-J`) | Tier 2: Utility | **P1** | Complete | Server-side chaining with per-hop resume, relayed signatures, and KEX attestation |
| [**FEAT-UTL-06**](feat-impl/FEAT-UTL-06.md) | Chained Jumphost Rendezvous to NATed Terminal (`HopSpec.Target`) | Tier 2: Utility | **P2** | Complete | Traverses NAT/CGNAT terminals via reverse agent rendezvous (unblocked by FEAT-UTL-04) |
| [**FEAT-SEC-01**](feat-impl/FEAT-SEC-01.md) | Encrypted Handshake Control Plane (X25519 / ChaCha20-Poly1305) | Tier 3: Security | **P1** | Complete | SSH-style X25519 ECDH + Ed25519 host keys + ChaCha20-Poly1305 control encryption |
| [**FEAT-SEC-02**](feat-impl/FEAT-SEC-02.md) | WebSocket & HTTPS Port 443 Fallback Transport | Tier 3: Security | **P3** | Complete | Bypasses restrictive enterprise firewalls & DPI |
| [**FEAT-SEC-03**](feat-impl/FEAT-SEC-03.md) | Per-User RBAC & Live `SIGHUP` Configuration Reload | Tier 3: Security | **P2** | Complete | Hot updates to `authorized_keys` & destination ACLs |
| [**FEAT-PERF-01**](feat-impl/FEAT-PERF-01.md)| Linux Kernel Zero-Copy Stream Splicing (`splice(2)`) | Tier 4: Performance | **P3** | Complete | Halves CPU & memory bus overhead on multi-gigabit links |
| [**FEAT-PERF-02**](feat-impl/FEAT-PERF-02.md)| Adaptive KCP Dynamic ARQ & Congestion Tuning | Tier 4: Performance | **P3** | Complete | Dynamic packet retransmission on fluctuating mobile links |
| [**FEAT-PERF-03**](feat-impl/FEAT-PERF-03.md)| Fast 3-RTT Token-Authorized Resumption in AEAD Plane | Tier 4: Performance | **P1** | Complete | Cuts 1 RTT per resume, eliminates flaky link RTO stalls & enables silent standby |
| [**FEAT-OBS-01**](feat-impl/FEAT-OBS-01.md) | Prometheus Exporter, OpenTelemetry Tracing & Live Metrics TUI Dashboard | Tier 4: Observability| **P2** | Complete | Production-grade SLA alerting, Prometheus scraping, & interactive terminal metrics dashboard (`relay top`) |

---

## Tier 1: Core Robustness & Network Fault Tolerance

### [FEAT-ROB-01](feat-impl/FEAT-ROB-01.md): Sub-Second Dead-Peer Detection & Dual-Path BFD Architecture
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/bfd`, `internal/relay`, `internal/transport`, `internal/proto`, `cmd/relay`

#### 1. Problem Statement
WAN links drop unpredictably due to Wi-Fi roaming, cell-tower handoffs, and intermediate router timeouts. While the relay transparently resumes broken links upon detection, TCP transport idle timeouts take 30–60+ seconds to identify a broken link. During this blackhole period, developer SSH commands hang unresponsive.

#### 2. Technical Implementation
- **RFC 5880 Asynchronous BFD Engine (`internal/bfd`)**: Implemented 20-byte binary packet payload state machine (`Down`, `Init`, `Up`) over `proto.TypePing` (0x15). Unsolicited `proto.TypePong` echo dropped.
- **Sub-Second Detection**: Configurable `heartbeat_interval` (default `750ms`) and `dead_peer_threshold` (default `3`). Silence $\ge 2.25\text{s}$ triggers `ErrDeadPeer` and immediate teardown.
- **Dual-Path Hot-Standby Architecture (`--allow-ha`)**: Concurrent active UDP and standby TCP connections exchanging BFD heartbeats simultaneously.
- **Zero-Latency Seamless Failover**: Instant promotion of standby TCP carrier upon active UDP failure with no dial round-trip, deduplication via `session.Dedupe`, and autonomous background reconnect to restore failed paths.

#### 3. Verification
- 100% unit and race test pass in `internal/bfd` and `internal/relay` with `-race`.
- Dual-netns Linux integration benchmarks: Silent blackhole detected in **2.26s** (vs 30s TCP timeout) and instant failover under load with zero byte loss.

---

### [FEAT-ROB-02](feat-impl/FEAT-ROB-02.md): Zero-Downtime Server Restarts & Socket Handover (`LISTEN_FDS` / `SCM_RIGHTS`)
* **Priority**: `P1` (High)
* **Status**: Complete ([`.feat-impl/FEAT-ROB-02.md`](feat-impl/FEAT-ROB-02.md))
* **Target Package**: `internal/relay`, `cmd/relay`, `internal/session`

#### 1. Problem Statement
As documented in [`README.md`](../README.md), session hold state and destination TCP sockets live strictly in memory inside [`Server`](../internal/relay/server.go). If the relay server process restarts (for software updates or configuration changes), all active destination sockets are closed immediately. When clients reconnect, they receive `ERR_UNKNOWN_SESSION` and all SSH sessions terminate.

#### 2. Technical Specification
- **Socket Passing via `SCM_RIGHTS`**: Support hot re-exec on `SIGUSR2`:
  1. The existing server process listens for `SIGUSR2`.
  2. The parent process forks and executes the updated `relay server` binary.
  3. The parent serializes active session metadata from [`Store`](../internal/session/store.go) (session IDs, token hashes, stream offsets, and unacknowledged ring buffers) into an IPC stream.
  4. The parent passes listening file descriptors (`listen_tcp`, `udp_listen`) and connected destination TCP socket FDs to the child process via Unix domain socket `SCM_RIGHTS`.
  5. The child initializes its internal state from the serialized data, resumes destination polling, and takes over incoming traffic.
  6. The parent exits cleanly without sending `BYE{ERR_SHUTDOWN}` or closing destination sockets.
- **Systemd Socket Activation**: Support `LISTEN_FDS` so systemd manages the listening sockets across service restarts.

#### 3. Benefits & Verification
- Server updates, patches, and reboots can be performed with zero disruption to long-running developer SSH sessions and tunnels.
- **Verification**: Verified via unit tests (`internal/session`, `internal/relay`) and end-to-end multi-process `SIGUSR2` hot re-exec test (`TestServerZeroDowntimeHotRestartProcess`) transferring 256 KiB continuous data with matching SHA-256 byte-for-byte.

---

### FEAT-ROB-03: Dual-Stack Happy Eyeballs v2 (RFC 8305)
* **Priority**: `P2` (Medium)
* **Status**: Complete ([`.feat-impl/FEAT-ROB-03.md`](feat-impl/FEAT-ROB-03.md))
* **Target Package**: `internal/relay`, `internal/transport`

#### 1. Problem Statement
Client connection establishment in [`clientHello`](../internal/relay/client.go) and UDP probing in [`upgrade.go`](../internal/relay/upgrade.go) use standard `net.Dial`, which attempts resolved IP addresses sequentially. In dual-stack environments where IPv6 is broken, route-filtered, or where corporate firewalls block IPv4 UDP while allowing IPv6 UDP, sequential connection attempts cause multi-second stalls or outright failures.

#### 2. Technical Specification
- **Concurrent Address Resolution**: Resolve both `A` (IPv4) and `AAAA` (IPv6) records in parallel.
- **Staggered Dual Dials**: Implement RFC 8305 Happy Eyeballs algorithm:
  - Start dialing IPv6 first.
  - If IPv6 does not establish within `ConnectionAttemptDelay` (250ms), launch concurrent IPv4 dial.
  - The first socket to successfully complete the handshake wins and becomes the session transport; the other socket is closed immediately.
- **Probe Racing**: Apply the same Happy Eyeballs racing logic to the UDP probe phase in [`transport.Probe`](../internal/transport/conn.go).

#### 3. Benefits & Verification
- Eliminates connection hangs on broken IPv6 networks and optimizes connection latency across heterogeneous network links.
- **Verification**: Create a netns environment with blackholed IPv6 and responsive IPv4, assert connection latency is <300ms.

---

### [FEAT-ROB-04](feat-impl/FEAT-ROB-04.md): Tiered Disk-Spill Storage for Ring Buffers
* **Priority**: `P3` (Low)
* **Status**: Complete ([`.feat-impl/FEAT-ROB-04.md`](feat-impl/FEAT-ROB-04.md))
* **Target Package**: `internal/session`, `internal/relay`, `internal/config`, `cmd/relay`

#### 1. Problem Statement
Session ring buffers in [`session.Ring`](../internal/session/ringbuf.go) are strictly backed by RAM slices. Under the default configuration, per-session capacity is capped at 64 MiB and global budget at 512 MiB ([`session.Budget`](../internal/session/budget.go)). During prolonged disconnections (e.g. 5–10 minutes) during massive bulk transfers, the ring buffer saturates quickly, pausing upstream reads and risking session drop if memory limits are exceeded.

#### 2. Technical Specification
- **Tiered Ring Architecture**:
  - Split [`session.Ring`](../internal/session/ringbuf.go) into an in-memory L1 cache (up to 8 MiB) and an on-demand L2 spill storage.
  - When in-memory data exceeds the L1 threshold, sequentially write overflow data blocks to an encrypted temporary disk file (using unlink-on-open on Linux).
  - Encrypt spilled blocks using AES-256-GCM with an ephemeral per-session key generated at startup and securely zeroed on close.
  - Fixed 64 KiB blocks with 65556-byte on-disk stride for O(1) arithmetic indexing.
  - During retransmission on `RESUME`, stream unacknowledged bytes sequentially from the spill file with single-block caching, purging acknowledged segments via `fallocate(FALLOC_FL_PUNCH_HOLE)`.
  - Seamless zero-downtime hot restart handover integration (`RestoreTieredRing`).

#### 3. Benefits & Verification
- Enables sustained gigabyte-scale hold buffers across multi-minute outages without exhausting server RAM or causing OOM kills.
- **Verification**: Verified via unit tests (`internal/session/spill_test.go`) and end-to-end relay disconnection tests (`TestRelayTieredSpillResume`) streaming 512 KiB through a 128 KiB L1 threshold, verifying byte-exact SHA-256 matching.

---

## Tier 2: Practical Utility & Developer Workflows

### [FEAT-UTL-01](feat-impl/FEAT-UTL-01.md): Native OpenSSH Agent (`SSH_AUTH_SOCK`) Integration
* **Priority**: `P1` (High)
* **Status**: Complete ([`.feat-impl/FEAT-UTL-01.md`](feat-impl/FEAT-UTL-01.md))
* **Target Package**: `internal/auth`, `internal/config`, `cmd/relay`, `internal/relay`

#### 1. Problem Statement
The current SSH public key authenticator in [`ssh.go`](../internal/auth/ssh.go) directly parses unencrypted private keys from disk files (`identity_files = ["~/.ssh/id_ed25519"]`). It cannot use:
1. Passphrase-protected private keys (fails with decryption errors).
2. Keys loaded into the user's running `ssh-agent`.
3. Hardware tokens such as YubiKey / FIDO2 security keys (`sk-ssh-ed25519@openssh.com`).

#### 2. Technical Specification
- **Agent Dialing**: Connect to the local Unix domain socket specified by the environment variable `$SSH_AUTH_SOCK`.
- **`ssh.Agent` Key Discovery**: Use `golang.org/x/crypto/ssh/agent` to enumerate available signers.
- **Signature Delegation**: When responding to the server's cryptographic challenge in [`auth.PublicKey.Respond`](../internal/auth/ssh.go), delegate the signature operation directly to `agent.Sign(key, challengeDigest)`.
- **Fallback Chain**:
  1. Try active `ssh-agent` keys.
  2. Fall back to unencrypted files specified in `identity_files`.
  3. Fail cleanly with clear error messaging if no valid signer is found.

#### 3. Benefits & Verification
- Seamless out-of-the-box support for corporate workstations with enforced passphrase keys, smart cards, and hardware tokens without touching raw private key bytes.
- **Verification**: Start `ssh-agent`, add a test key, run client with `auth_method = "ssh-publickey"` and no files on disk, assert successful authentication.

---

### [FEAT-UTL-02](feat-impl/FEAT-UTL-02.md): Terminal Reconnection HUD & Desktop Notifications
* **Priority**: `P1` (High)
* **Status**: Complete ([`.feat-impl/FEAT-UTL-02.md`](feat-impl/FEAT-UTL-02.md))
* **Target Package**: `internal/relay`, `cmd/relay`, `internal/config`

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

### [FEAT-UTL-03](feat-impl/FEAT-UTL-03.md): SOCKS5 Dynamic Forwarding Mode (`relay socks`)
* **Priority**: `P2` (Medium)
* **Status**: Implemented (Complete)
* **Target Package**: `cmd/relay`, `internal/relay`, `internal/proto`, `internal/socks5`

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
- **Related**: [FEAT-UTL-05](feat-impl/FEAT-UTL-05.md) is the *static* analogue of this *dynamic* forwarding — a named path of relay servers rather than a SOCKS5 multiplexer.

---

### [FEAT-UTL-04](feat-impl/FEAT-UTL-04.md): Reverse Relay & NAT Gateway Mode (Inverted Tunnel)
* **Priority**: `P2` (Medium)
* **Status**: Implemented (Complete)
* **Target Package**: `cmd/relay`, `internal/relay`, `internal/proto`, `internal/config`, `internal/auth`

#### 1. Problem Statement
The current architecture assumes the server has a public IP address and the destination is reachable from the server. If the target machine is located behind NAT, CGNAT, or firewall (such as a home lab server, IoT appliance, or private cloud instance), external access typically requires reverse forwarding.

> **Clarification**: When the NATed node can dial outbound to a public jump host, standard OpenSSH reverse forwarding already solves NAT traversal using `remote-relay client` and `server` today without requiring `FEAT-UTL-04`:
> ```bash
> # On the NATed machine:
> ssh -R 127.0.0.1:44022:127.0.0.1:22 user@jump.example \
>     -o ProxyCommand="relay client --server jump.example:7443 --kcp -i ~/.ssh/id_ed25519"
> ```
> The relay transparently carries the opaque SSH session across NAT with full KCP resilience, BFD dead-peer detection, and hot-standby failover. OpenSSH on the jump host owns the port listener and enforces `authorized_keys` `permitlisten=` restrictions.
> `FEAT-UTL-04` specifically provides a dedicated agent/client rendezvous protocol (`relay agent` / `--target`) for environments where operators do not want OpenSSH reverse listeners or multi-session forward ports on the relay host. Phase 3 of [FEAT-UTL-05](feat-impl/FEAT-UTL-05.md) jumphost chaining depends on this rendezvous so a NATed terminal can be named by `HopSpec.Target` instead of a dialable `addr`.

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

### [FEAT-UTL-05](feat-impl/FEAT-UTL-05.md): Multi-Hop Jumphost Chaining (`-J`)
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete; Phase 3 split into [FEAT-UTL-06](#feat-utl-06-chained-jumphost-rendezvous-to-nated-terminal-hopspectarget))
* **Target Package**: `cmd/relay`, `internal/relay`, `internal/proto`, `internal/config`, `internal/crypto/kex`

#### 1. Problem Statement
The relay is strictly two-party: `client → server → destination`. Reaching a relay that is not directly dialable today means wrapping an opaque `ssh -R` inside the session, which gives the inner hop no resume, no KCP, and no BFD of its own.

#### 2. Technical Implementation
- **Server-side chaining (J-D1)**: each intermediate embeds a relay client toward the next hop and fully terminates that hop's data plane. `-J` is OpenSSH-compatible; `--server` remains the terminal that dials `sshd`.
- **Relayed signature (J-D2)** plus **KEX attestation (J-D3)**: the private key never leaves the originator; every hop's host key is verified by the originator. J-D16 reuses the KEX `serverNonce` as the auth nonce so a rogue intermediate cannot pair a genuine attestation with a fabricated challenge.
- **Default-deny `allow_relay_hops` (J-D8/J-D9)**, `max_chain_depth` (default 4), loop detection, `OriginIP` accounting, `chain_max_sessions`.
- **New frames** `TypeChain` (0x0E) / `TypeChainOK` (0x0F) so a v1 peer fails closed (`ERR_PROTO`) instead of silently dialing its own destination (J-D10).
- **Case C/D**: a stale inner resume token is relayed to the originator on the hop-1 data plane; hop-1 `RESUME_OK` waits until the nested leg is live (or rebuilds it).
- **Per-hop transport (J-D4)**: `-J hop?transport=kcp` / `?ha=1` is honoured on hop 1 (originator upgrade/HA) and advertised onward; nested UDP upgrade runs when the next hop selected quic/kcp. Nested `splice(2)` stays off.

#### 3. Verification
- In-process tests in `internal/relay/chain_test.go` (byte-exact e2e, 3 hops, policy denials, attestation replay, Cases A–D resume, per-hop KCP on hop 1, splice disabled, origin-IP accounting).
- Netns harness `scripts/test_jumphost_netns.py` JUMP-01..07 (not in CI; needs root + netns + sshd).

---

### [FEAT-UTL-06](feat-impl/FEAT-UTL-06.md): Chained Jumphost Rendezvous to NATed Terminal (`HopSpec.Target`)
* **Priority**: `P2` (Medium)
* **Status**: Implemented (Complete)
* **Target Package**: `cmd/relay`, `internal/relay`, `internal/proto`, `internal/config`

#### 1. Problem Statement
[FEAT-UTL-05](feat-impl/FEAT-UTL-05.md) enables arbitrary multi-hop jumphost chaining (`relay client -J j1,j2 --server S`), but requires every intermediate hop to directly dial the outbound IP/hostname and port of the subsequent hop (`HopSpec.Addr`). When the terminal server (or an intermediate hop) is located behind NAT, CGNAT, or firewall (such as an internal home lab server or private VPC instance), direct inbound dialing from the preceding relay fails because the node has no public routable address or listening ports.

#### 2. Technical Specification
- **Rendezvous-Based Hop Resolution**:
  - Integrate with the reverse relay agent registration protocol from [**FEAT-UTL-04**](#feat-utl-04-reverse-relay--nat-gateway-mode-inverted-tunnel).
  - In `proto.HopSpec`, utilize the wire-reserved `Target` field (e.g. `{ "target": "homelab" }`) rather than a direct network address (`Addr`).
  - When the final intermediate hop processes the onward hop spec, it checks whether `Target` is specified. Instead of calling `net.Dial` / `transport.DialTCP`, it matches the registered reverse connection from `relay agent` identified by that target name.
  - The intermediate issues a `BIND_REQUEST` over the registered agent's reverse control channel.
  - The agent opens a local connection to `127.0.0.1:22` (`sshd`) and bridges data back through the intermediate relay.
- **End-to-End Cryptographic Security**:
  - Retains full cryptographic KEX attestation and relayed challenge signing across the entire chain.
  - Per-hop resume, ring buffers, and BFD heartbeats function seamlessly over the inverted leg.
- **CLI Syntax**:
  ```bash
  # Client connects through public jumphost to private NATed target:
  relay client -J jump.example.com:7443 --target homelab --dest 127.0.0.1:22
  ```

#### 3. Benefits & Verification
- Extends jumphost chaining to zero-port-forwarding environments; developers can jump into private servers behind NAT without running external VPNs or exposing public ports.
- **Verification**: Run `relay agent --name homelab` in a network namespace with no incoming routes; client connects via `relay client -J jump --target homelab` and verifies data transfer, active carrier drops, and session hold/resume.

---

## Tier 3: Security & Network Traversal Hardening

### [FEAT-SEC-01](feat-impl/FEAT-SEC-01.md): Encrypted Handshake Control Plane (X25519 & ChaCha20-Poly1305)
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/crypto/kex`, `internal/proto`, `internal/config`, `internal/relay`, `cmd/relay`

#### 1. Problem Statement
As noted in [`design.md` §10.1](design.md#L500-L511), the TCP control plane was originally sent in cleartext JSON. Although SSH payloads are encrypted, on-path network observers could inspect `HELLO`, `RESUME`, `sessionId`, `resumeToken`, destination IPs/ports, and authentication tokens. This enabled metadata tracking, session token interception, and targeted middlebox DPI filtering.

#### 2. Technical Specification
- **SSH-Style Ephemeral Key Exchange (`internal/crypto/kex`)**:
  - Ephemeral X25519 Diffie-Hellman key agreement with HKDF-SHA256 key derivation for distinct directional keys (`Key_c2s` and `Key_s2c`).
  - Server identity authenticated via Ed25519 host key signature over the complete cryptographic exchange transcript hash $H$.
- **Host Key Management & Fingerprint Verification**:
  - Auto-generated or file-based OpenSSH Ed25519 server host keys (`--host-key`).
  - OpenSSH-format `known_hosts` verification (`~/.config/relay/known_hosts`, `--known-hosts`) with Trust On First Use (TOFU), MITM change detection, and strict checking policies (`--strict-host-key-checking=yes|no|ask|accept-new`).
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

### [FEAT-SEC-02](feat-impl/FEAT-SEC-02.md): WebSocket & HTTPS Port 443 Fallback Transport
* **Priority**: `P3` (Medium)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/transport`, `internal/config`, `internal/relay`

#### 1. Problem Statement
Strict enterprise firewalls, corporate proxies, and public Wi-Fi portals (e.g. hotels and airports) frequently block all non-standard ports (such as 7443) and drop all UDP traffic, preventing both QUIC and direct TCP handshakes.

#### 2. Technical Specification
- **WebSocket Transport Adapter**:
  - Implemented `KindWebSocket` and `wsConn` adapter conforming to `transport.Conn` in `internal/transport/websocket.go` with RFC 6455 binary frame encoding.
  - Connect via HTTPS: `wss://relay.example.com/relay-stream` or unencrypted `ws://`.
- **Multiplexing on Existing Web Servers**:
  - Server provides standalone WebSocket listener (`listen_ws`, `websocket_path`, `ws_cert`, `ws_key`) or embeddable `WebSocketHandler()` to mount behind Nginx, Caddy, Cloudflare, Traefik, or standard Go HTTP reverse proxies on port 443.
  - Supports path multiplexing alongside existing HTTP routes (e.g., `/relay-stream` and `/health`).
- **HTTP Proxy Traversal**:
  - Transparent HTTP proxy support via `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`.
  - Performs standard HTTP `CONNECT` tunneling with `Proxy-Authorization: Basic` support and buffer preservation.
- **Reverse Proxy Header Extraction**:
  - Automatically parses `X-Forwarded-For` and `X-Real-IP` to extract actual client IP and port for connection limits and rate limiting.
- **KEX Handshake & Jumphost Chaining**:
  - End-to-end integration with FEAT-SEC-01 encrypted handshake, host key verification (with URL scheme stripping), session resumption, and jumphost chaining (`-J hop1?transport=ws,hop2`).

#### 3. Verification & Results
- Verified 100% green test suite under `go test -race ./...`:
  - `internal/transport/websocket_test.go`: happy path, TLS ephemeral certs, proxy tunneling, proxy basic auth, proxy refusal, invalid upgrade responses, client IP extraction, and deadline resets.
  - `internal/relay/ws_test.go`: direct E2E streaming, TLS E2E streaming, reverse proxy multiplexing with `/health`, forward HTTP CONNECT proxy tunneling, jumphost chaining over WebSocket hops, session resumption, Ed25519 host key pinning/verification, and sad paths (closed port, TLS failure).


---

### [FEAT-SEC-03](feat-impl/FEAT-SEC-03.md): Per-User RBAC & Live `SIGHUP` Configuration Reload
* **Priority**: `P2` (Medium)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/auth`, `internal/config`, `internal/relay`

#### 1. Problem Statement
[`allow_destinations`](../internal/config/config.go) is a single global list. Any authenticated user can access any allowed destination. In addition, updating access keys or destinations requires restarting the server process, which terminates active sessions.

#### 2. Technical Specification
- **Role-Based Access Policies**:
  - Associate destinations with authorized keys or groups in `authorized_keys` (using OpenSSH options format, e.g. `permitopen="10.0.1.*:22,127.0.0.1:22"`).
  - Enforce destination filtering during `HELLO` validation prior to dialing.
- **`SIGHUP` Configuration Reload**:
  - Intercept `syscall.SIGHUP` in [`Server`](../internal/relay/server.go).
  - Re-read `server.toml` and `authorized_keys`.
  - Atomically swap the configuration pointer using `atomic.Pointer[config.Server]`.
  - Existing sessions remain active; new sessions immediately adopt the updated rules.

#### 3. Benefits & Verification
- Multi-user enterprise isolation and live credential updates without operational downtime.
- **Verification**: Connect client with restricted key, attempt to dial forbidden destination (expect `ERR_AUTH`); update `authorized_keys`, send `kill -HUP $PID`, verify new key is immediately accepted.

---

## Tier 4: Performance & Enterprise Observability

### [FEAT-PERF-01](feat-impl/FEAT-PERF-01.md): Linux Kernel Zero-Copy Stream Splicing (`splice(2)`)
* **Priority**: `P3` (Low)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/relay`, `internal/transport`, `internal/config`, `cmd/relay`

#### 1. Problem Statement
In TCP mode, data transfer previously involved reading bytes from the carrier network socket into Go user-space buffers and writing them to destination sockets or pipes. This user/kernel context switching and double memory copying imposed CPU cache pressure and memory bus bottlenecks on multi-gigabit links.

#### 2. Technical Implementation
- **Direct Pipe Splicing**:
  - On Linux (`GOOS=linux`), utilize `splice(2)` via `golang.org/x/sys/unix` for kernel-level zero-copy data movement.
  - Implemented two-stage intermediate kernel pipe bridging (`socket_fd -> pipe -> dest_fd`) and single-stage pipe splicing (`socket_fd -> stdout_pipe`).
  - Integrated with Go netpoller via `SyscallConn()` for non-blocking epoll event loops.
  - Intercepted spliced byte counts to maintain exact stream offset bookkeeping (`expected`, `delivered`, ACK tracking).
- **Graceful Cross-Platform Fallback**:
  - Automatically falls back to standard user-space copying on non-Linux systems (macOS, Windows) or memory buffers (`*bytes.Buffer`).
- **CLI & Configuration**:
  - Added `Splice` boolean configuration option and `--splice` / `--no-splice` flags.

#### 3. Benefits & Verification
- **50.0% CPU Core Utilization Reduction**: Loopback `iperf3` transfer through relay halved server CPU utilization ($166.8\% \to 83.4\%$) while sustaining multi-gigabit throughput.
- **100% Test Pass**: Unit tests in `internal/relay/splice_test.go` and full relay suite passed with zero regressions. Spliced 942+ MB purely in kernel space.

---

### [FEAT-PERF-02](feat-impl/FEAT-PERF-02.md): Adaptive KCP Congestion & Dynamic ARQ Tuning
* **Priority**: `P3` (Low)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/transport`

#### 1. Problem Statement
[`transport/kcp.go`](../internal/transport/kcp.go) previously used fixed parameters (`nodelay=1, interval=10ms, resend=2, nc=1`). While this provided throughput on lossy links, it caused packet bloat and bandwidth saturation on clean and narrow mobile links.

#### 2. Technical Specification
- **Dynamic Link Probing & Moving Loss Rate**:
  - Monitor moving loss rate via sliding history window with fast-attack spike detection.
  - Monitor send queue ring buffer length (`snd_queue.Len()`) for local backpressure.
  - When packet loss is low (<0.5%), throttle back `interval` to 30ms, `resend` to 1, and enable Reno congestion control (`nc=0`) to conserve bandwidth and prevent bufferbloat.
  - When packet loss spikes (>3%), automatically scale up retransmission frequency (`interval=10ms, resend=2, nc=1`).
  - Hysteresis stabilization: requires 2 consecutive clean samples before downscaling.

#### 3. Benefits & Verification
- Saves mobile data quota while preserving high throughput and low interactive keystroke latency.
- **Verification**: Verified via `scripts/test_perf_kcp_adaptive.py` under varying `tc netem` loss profiles (0% -> 5% -> 0%) asserting 7.2% packet reduction on clean links, seamless fast-attack adaptation during 5% loss spikes, and byte-exact SHA-256 data integrity under both standalone KCP and `--allow-ha`.

---

### [FEAT-PERF-03](feat-impl/FEAT-PERF-03.md): Fast 3-RTT Token-Authorized Resumption in Encrypted AEAD Plane
* **Priority**: `P1` (High)
* **Status**: Implemented (Complete)
* **Target Package**: `internal/relay`, `internal/proto`, `internal/auth`, `internal/session`

#### 1. Problem Statement
In the original Milestone 5 design, reconnection forced a complete public key challenge-response exchange (`RESUME` $\to$ `AUTH_OK` $\to$ `AUTH` $\to$ `RESUME_OK`) to prevent session hijacking because the control plane was sent in cleartext JSON.

However, with the completion of [**FEAT-SEC-01**](feat-impl/FEAT-SEC-01.md), every reconnection begins with ephemeral X25519 ECDH and Ed25519 host key verification, wrapping all subsequent frames in a ChaCha20-Poly1305 AEAD cipher. Retaining the full public key challenge-response inside this encrypted tunnel imposes severe performance penalties:
1. **Serialization Overhead (4 RTTs / 8 Frame Turns)**: Every reconnection takes 4 sequential network turns before data streams (TCP SYN $\to$ KEX $\to$ RESUME/AUTH_OK $\to$ AUTH/RESUME_OK). On an 80ms RTT WAN link, empirical dual-netns benchmarks show an unconditional **+82ms (+34%) baseline penalty** (323ms vs 241ms).
2. **TCP RTO Amplification on Flaky Links**: Under loss, a dropped frame during the 8-turn sequence forces TCP Retransmission Timeouts (RTOs). Dual-netns simulations at 5% packet loss demonstrated severe stalls up to **7,008ms** (mean 1,166ms vs 284ms for token-only).
3. **Hardware Token & Standby Stalls ([FEAT-UTL-01](#feat-utl-01-native-openssh-agent-ssh_auth_sock-integration))**: YubiKey / FIDO2 security keys (`sk-ssh-ed25519@openssh.com`) and keys with confirmation (`ssh-add -c`) require physical touch or confirmation prompts. In `--allow-ha` dual-path mode, background standby reconnects continuously trigger intrusive prompts or exceed the 5-second dial timeout.

#### 2. Technical Specification
- **2-Tier Authentication & Decoupled Resumption**:
  - **Initial Connection (`HELLO`)**: Enforces full multi-factor authentication (X25519 KEX + Ed25519 host key check + SSH public key signature). The server records the bound key fingerprint and issues a 32-byte cryptographically secure random `resumeToken`.
  - **Resumption (`RESUME`)**: Once the ephemeral X25519 + ChaCha20-Poly1305 tunnel is established and the server host key is verified against `known_hosts`, the client sends `TypeEncrypted[RESUME]` with `sessionID` and `resumeToken`.
  - **Single-Turn Verification**: The server verifies `store.VerifyToken(sessionID, token)`. Because the channel is forward-secret and MITM-protected, the rotating 256-bit token provides valid bearer authentication. The server skips `TypeAuthOK` challenge and responds immediately with `TypeEncrypted[RESUME_OK]`, rotating the token for the next generation.
  - **Fallback Recovery**: If the `resumeToken` is expired, mismatched, or corrupted, the server falls back to issuing an `AUTH_OK` challenge for full cryptographic recovery rather than dropping the session.

#### 3. Benefits & Verification
- **Saves 1 Full RTT & 2 Frames**: Resumptions complete in 3 RTTs (~240ms on 80ms WAN links), eliminating 2 frame transmissions and reducing loss exposure by 25%.
- **Unblocks FEAT-UTL-01**: Hardware security keys (YubiKey / FIDO2) require user interaction only during initial session establishment; background hot-standby loops and flaky reconnections proceed silently.
- **Verification**: Verified via `scripts/test_perf_resume.py` and `internal/relay/auth_test.go` asserting 3-RTT completion (~240ms under 80ms RTT), zero signature delegations on resume, and seamless cryptographic fallback on invalid tokens.

---

### FEAT-OBS-01: Prometheus Metrics Exporter, OpenTelemetry Tracing & Live Metrics TUI Dashboard (`relay top`)
* **Priority**: `P2` (Medium)
* **Status**: Complete
* **Target Package**: `internal/obs`, `internal/tui`, `cmd/relay`

#### 1. Problem Statement
[`obs.go`](../internal/relay/obs.go) currently only exposes basic `expvar` variables (`sessions`, `held`, `buffer_used`, `accepts`, `refused`). It lacks dimensional labels, histograms, latency percentiles, and compatibility with industry-standard monitoring systems (Prometheus, Grafana, Datadog). Furthermore, operators, developers, and SREs troubleshooting live connections on remote jumphosts or servers currently have no interactive terminal observability tool (analogous to `top`, `htop`, or `iftop`) to inspect live relay health, buffer occupancy, active session counts by transport, and real-time throughput without setting up an external Prometheus/Grafana stack.

#### 2. Technical Specification
- **Prometheus Exporter (`/metrics`)**:
  - Expose a Prometheus metrics endpoint with standard metrics:
    - `relay_active_sessions{transport="quic|kcp|tcp"}` (gauge)
    - `relay_reconnect_total{status="success|failure"}` (counter)
    - `relay_reconnect_duration_seconds` (histogram with buckets: 0.1s, 0.5s, 1s, 2s, 5s, 10s)
    - `relay_held_duration_seconds` (histogram)
    - `relay_bytes_transferred_total{direction="up|down", transport="..."}` (counter)
    - `relay_buffer_utilization_ratio` (gauge)
    - `relay_hop_chain_depth` (histogram)
    - `relay_socks_streams_active` (gauge)
    - `relay_rbac_rejections_total{reason="..."}` (counter)
- **OpenTelemetry Tracing**:
  - Instrument session lifecycle events with trace spans (`Handshake`, `Upgrade`, `Resume`, `ChainHop`).
- **Live Terminal Metrics TUI Dashboard (`relay top` / `relay stats`)**:
  - CLI subcommand: `relay top [--endpoint URL] [--interval DURATION] [--color=auto|always|never]` (default connects to `http://127.0.0.1:9090/metrics` or server admin port).
  - Scrapes the `/metrics` endpoint periodically (e.g. 1s default) and parses standard Prometheus text exposition format into real-time gauges, rates, and counters.
  - Interactive Terminal Interface (built with clean ANSI terminal control / `golang.org/x/term` alt screen buffer):
    - **Header & Health Panel**: Server uptime, process PID, total live sessions, scrape status, and latency.
    - **Transport & Session Breakdown**: Visual bars / tables showing active sessions by transport (`TCP`, `KCP`, `QUIC`), standby connections, and hold counts.
    - **Throughput & Bandwidth Rates**: Upload / download transfer rates ($\text{KiB/s}$, $\text{MiB/s}$) with moving deltas or sparklines.
    - **Memory & Ring Buffer Bar**: Current buffer bytes vs total buffer capacity with percentage gauge and backpressure alerts.
    - **Reliability & Resiliency Counters**: Handshake rates, BFD dead-peer triggers, failovers, reconnections, and RBAC rejection counts.
    - **Interactive Keybindings**: `q`/`Esc` to exit, `r` to force refresh, `+`/`-` or `1`/`2`/`5` to adjust refresh frequency, `p` to pause/resume live updates.
    - **Fail-Safe Terminal Lifecycle**: Restores alternate screen buffer, cursor, and terminal echo on exit or signals (`SIGINT`, `SIGTERM`, `SIGWINCH` resize handling).
    - **Sad Path Resilience**: Displays clear disconnection warning and retry countdown if the server restarts or `/metrics` is temporarily unreachable, resuming automatically once the server is back.

#### 3. Benefits & Verification
- Out-of-the-box observability for enterprise SRE teams with alerting on disconnection spikes or high resume failure rates.
- Instant, zero-overhead developer and operator diagnostics on live servers and jumphosts with `relay top` without external dependencies.
- **Verification**: 
  - Unit tests verifying Prometheus text exposition parser and metrics collection.
  - Integration tests verifying `/metrics` scraping under load.
  - Mock terminal buffer tests verifying TUI frame rendering, ANSI layout, key events, and resize/reconnect recovery.

---

## 4. Implementation Phasing & Next Steps

```
Phase 1: Usability & Resiliency Quick-Wins (1–2 weeks)
├── FEAT-UTL-01: Native OpenSSH Agent (SSH_AUTH_SOCK) [COMPLETED] (.feat-impl/FEAT-UTL-01.md)
├── FEAT-PERF-03: Fast 3-RTT Token-Authorized Resumption (AEAD Plane) [COMPLETED] (.feat-impl/FEAT-PERF-03.md)
├── FEAT-UTL-02: Terminal Reconnection HUD (stderr) [COMPLETED] (.feat-impl/FEAT-UTL-02.md)
└── FEAT-ROB-01: Sub-Second Dead-Peer Detection (Fast Heartbeats) [COMPLETED] (.feat-impl/FEAT-ROB-01.md)

Phase 2: Enterprise Operations, Zero-Downtime & Security (2–4 weeks)
├── FEAT-ROB-02: Zero-Downtime Server Restarts (SCM_RIGHTS) [COMPLETED] (.feat-impl/FEAT-ROB-02.md)
├── FEAT-OBS-01: Prometheus Metrics Endpoint & Live TUI Dashboard [COMPLETED] (.feat-impl/FEAT-OBS-01.md)
├── FEAT-SEC-03: Per-User RBAC & SIGHUP Reload [COMPLETED] (.feat-impl/FEAT-SEC-03.md)
├── FEAT-SEC-01: Encrypted Handshake Control Plane [COMPLETED] (.feat-impl/FEAT-SEC-01.md)
├── FEAT-UTL-05: Multi-Hop Jumphost Chaining (-J) [COMPLETED] (.feat-impl/FEAT-UTL-05.md)
└── FEAT-ROB-03: Dual-Stack Happy Eyeballs v2 [COMPLETED] (.feat-impl/FEAT-ROB-03.md)

Phase 3: Expanded Utility & High Availability (4–6 weeks)
├── FEAT-UTL-03: SOCKS5 Dynamic Forwarding Mode [COMPLETED] (.feat-impl/FEAT-UTL-03.md)
├── FEAT-UTL-04: Reverse Relay & NAT Gateway Mode [COMPLETED] (.feat-impl/FEAT-UTL-04.md)
├── FEAT-UTL-06: Chained Jumphost Rendezvous to NATed Terminal (unblocked by FEAT-UTL-04)
└── FEAT-SEC-02: WebSocket & HTTPS Port 443 Fallback [COMPLETED] (.feat-impl/FEAT-SEC-02.md)

Phase 4: Advanced Optimizations (Ongoing)
├── FEAT-PERF-01: Linux Kernel Zero-Copy Stream Splicing [COMPLETED] (.feat-impl/FEAT-PERF-01.md)
├── FEAT-PERF-02: Adaptive KCP Congestion Tuning [COMPLETED] (.feat-impl/FEAT-PERF-02.md)
└── FEAT-ROB-04: Tiered Disk-Spill Storage for Ring Buffers
```
