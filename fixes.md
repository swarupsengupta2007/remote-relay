# Comprehensive Codebase Audit & Gap Analysis Report

**Target Document:** [`features.md`](file:///root/remote-relay/features.md)  
**Codebase:** `remote-relay` (Go 1.24)  
**Date of Audit:** October 5, 2026  
**Status:** Audit Completed  

---

## 1. Executive Summary

A comprehensive architectural and source code probe was conducted against the 17 core features specified in [`features.md`](file:///root/remote-relay/features.md) and their respective design documents in `.feat-impl/`. The investigation evaluated functional correctness, protocol compliance, concurrency safety, edge-case resilience, and happy/sad path execution.

While the core streaming engine, cryptographic handshake, and protocol multiplexing architectures are well-structured and pass baseline unit tests, the probe revealed **8 critical/high-severity vulnerabilities and functional bugs**, along with multiple protocol deviations and unhandled failure paths. Most notably, these issues include:
1. **Child server crash on hot restart** when SOCKS5, reverse agent, or jumphost sessions are active.
2. **File descriptor corruption and use-after-free** during Linux zero-copy splicing due to GC finalizers on `os.NewFile`.
3. **Silent data loss and sequence desynchronization** during asymmetric carrier degradation in sub-second BFD failovers.
4. **IP address spoofing vulnerability** in the WebSocket transport.
5. **Head-of-line blocking across all concurrent SOCKS5 connections** under backpressure.
6. **Zero throughput metric tracking** leaving the live TUI dashboard (`relay top`) unable to display real-time traffic volume.

### Feature Audit Scorecard

| Feature Code | Feature Name | Spec Status | Code Quality | Critical Bugs / Deviations |
| :--- | :--- | :--- | :--- | :--- |
| **FEAT-ROB-01** | Sub-Second BFD & Dead-Peer Detection | Implemented | Needs Fix | Silent data loss on asymmetric UDP loss ([standby.go:72-84](file:///root/remote-relay/internal/relay/standby.go#L72-L84)) |
| **FEAT-ROB-02** | Zero-Downtime Hot Restart & SCM_RIGHTS | Implemented | Critical | Child panic on non-TCP dest ([server.go:491](file:///root/remote-relay/internal/relay/server.go#L491)); premature listener close ([server_unix.go:125](file:///root/remote-relay/internal/relay/server_unix.go#L125)) |
| **FEAT-ROB-03** | Dual-Stack Happy Eyeballs v2 (RFC 8305) | Implemented | Needs Fix | Hardcoded probe nonce collision on multi-address families ([udpmux.go:287](file:///root/remote-relay/internal/transport/udpmux.go#L287)) |
| **FEAT-ROB-04** | Tiered Disk-Spill Storage for Ring Buffers | Implemented | Minor | Ignored disk read errors in snapshot ([ringbuf.go:566](file:///root/remote-relay/internal/session/ringbuf.go#L566)); startup deadlock risk ([ringbuf.go:590](file:///root/remote-relay/internal/session/ringbuf.go#L590)) |
| **FEAT-UTL-01** | Native OpenSSH Agent Integration | Implemented | Solid | Unhandled sad path for encrypted PKCS#8 keys without `.pub` sidecars |
| **FEAT-UTL-02** | Terminal Reconnection HUD & Notifications | Implemented | Solid | Compliant OSC 9 / OSC 777 implementation; minor raw mode edge cases |
| **FEAT-UTL-03** | SOCKS5 Dynamic Forwarding (`relay socks`) | Implemented | Needs Fix | Multiplexer HOL blocking stalls all streams for 3s under backpressure ([socks_server.go:354](file:///root/remote-relay/internal/relay/socks_server.go#L354)) |
| **FEAT-UTL-04** | Reverse Relay & NAT Gateway Agent | Implemented | Needs Fix | Permanent hang on dead agent connection ([server.go:2467](file:///root/remote-relay/internal/relay/server.go#L2467)); clients rejected during agent hold ([agent_registry.go:160](file:///root/remote-relay/internal/relay/agent_registry.go#L160)) |
| **FEAT-UTL-05** | Multi-Hop Jumphost Chaining (`-J`) | Implemented | Functional | Handover state omits nested hops during hot restart |
| **FEAT-UTL-06** | Jumphost Rendezvous to NATed Agent | Implemented | Functional | Verified end-to-end rendezvous across intermediate proxies |
| **FEAT-SEC-01** | Encrypted Control Plane (AEAD X25519) | Implemented | Solid | ChaCha20-Poly1305 with monotonic sequence numbers; clean phase-cut |
| **FEAT-SEC-02** | WebSocket / HTTPS Port 443 Fallback | Implemented | Security Vuln | Unvalidated `X-Forwarded-For` allows IP spoofing and rate limit bypass ([websocket.go:404](file:///root/remote-relay/internal/transport/websocket.go#L404)) |
| **FEAT-SEC-03** | Per-User RBAC & Live SIGHUP Reload | Implemented | Needs Fix | SIGHUP reload wipes CLI flag overrides ([main.go:154](file:///root/remote-relay/cmd/relay/main.go#L154), [server.go:170](file:///root/remote-relay/internal/relay/server.go#L170)) |
| **FEAT-PERF-01**| Linux Kernel Zero-Copy Stream Splicing | Implemented | Critical | Retain pipe FD leak & use-after-free via GC finalizers on `os.NewFile` ([splice_linux.go:273](file:///root/remote-relay/internal/relay/splice_linux.go#L273)) |
| **FEAT-PERF-02**| Adaptive KCP Dynamic ARQ Tuning | Implemented | Needs Fix | Process-global SNMP counter bleed corrupts tuning across concurrent sessions ([kcp_adaptive.go:93](file:///root/remote-relay/internal/transport/kcp_adaptive.go#L93)) |
| **FEAT-PERF-03**| Fast 3-RTT Token Resumption | Implemented | Solid | 3-RTT fast path cleanly operational; fallback to challenge verified |
| **FEAT-OBS-01** | Prometheus Metrics, Tracing & TUI | Implemented | Deviation | `relay_bytes_transferred_total` never incremented (TUI displays 0 B); missing `Upgrade` tracing span |

---

## 2. Critical Bugs & Security Vulnerabilities (P0 / P1)

### BUG-01: Child Server Panic on Hot Restart for Non-TCP Sessions
- **Severity:** P0 (Fatal Crash / Service Interruption)
- **Affected Files:**
  - [`internal/relay/server.go:490-538`](file:///root/remote-relay/internal/relay/server.go#L490-L538)
  - [`internal/relay/pump.go:610`](file:///root/remote-relay/internal/relay/pump.go#L610)
  - [`internal/relay/handover.go:12-24`](file:///root/remote-relay/internal/relay/handover.go#L12-L24)
- **Root Cause:**
  When `HotRestart()` executes on the parent server, it iterates through all live sessions. For direct TCP sessions, it duplicates the destination TCP socket descriptor. However, for SOCKS5 proxy sessions, reverse NAT agent sessions, or Jumphost chained hops, `l.dest` is `nil` (since data is bridged via in-memory pipes or virtual stream muxes). The handover payload marks `HasDestFD = false`.
  During state adoption in the newly spawned child process (`s.adoptHandover()`), if `hSess.HasDestFD` is false, `dtcp` remains `nil`. The child server proceeds to initialize `newPump` with:
  ```go
  p := newPump(s.sessionContext(), sessionIO{
      src:        dtcp, // nil!
      sink:       dtcp, // nil!
      rawSrc:     dtcp,
      rawSink:    dtcp,
  ...
  ```
  When the child starts pumping IO (`p.startIO()`), `p.srcReader()` executes:
  ```go
  n, err := p.io.src.Read(buf) // nil pointer dereference!
  ```
  This immediately crashes the child server process during startup.
- **Impact:**
  Triggering `SIGUSR2` hot restart while any SOCKS5 stream, reverse agent tunnel, or multi-hop chain is active immediately crashes the replacement server. Because the parent server already dropped active carriers and closed listeners before confirmation, this causes total network outage.
- **Fix Required:**
  1. Distinguish session types in `HandoverSession` (`SessionType`: direct, socks, agent, chained).
  2. For non-direct TCP sessions, reconstruct proper virtual endpoints or gracefully hold them in the session store until client reconnection occurs, avoiding running `pump.srcReader()` on a `nil` descriptor.

---

### BUG-02: File Descriptor Corruption & Use-After-Free in Linux Splice Retain
- **Severity:** P0 (Resource Corruption / Silent Data Failure)
- **Affected Files:**
  - [`internal/relay/splice_linux.go:261-279`](file:///root/remote-relay/internal/relay/splice_linux.go#L261-L279)
- **Root Cause:**
  In [`spliceSrcToSocket()`](file:///root/remote-relay/internal/relay/splice_linux.go#L261), when data is teed to `pRetain` so it can be stored into the in-memory ring buffer, line 273 executes:
  ```go
  if _, rErr := io.ReadFull(os.NewFile(uintptr(rrfd), "retain"), buf); rErr == nil {
      retained = buf
  }
  ```
  `os.NewFile` creates an anonymous `*os.File` wrapping `rrfd`. The caller does not retain this `*os.File` pointer. As soon as the function returns or the next Go runtime garbage collection cycle runs, the finalizer registered by `os.NewFile` executes and calls `close(rrfd)`.
  `pRetain` is a pooled pipe structure. The underlying read file descriptor `rrfd` is now closed beneath `pRetain`.
- **Impact:**
  Subsequent invocations of `spliceSrcToSocket()` reusing that pipe will receive `EBADF`. If another thread in the relay server opens a socket or file that gets assigned the recycled file descriptor number, `io.ReadFull()` will read from or close another client's connection, resulting in cross-connection data corruption and mysterious crashes under load.
- **Fix Required:**
  Do not instantiate temporary `*os.File` wrappers. Read directly from the raw pipe descriptor using `unix.Read(rrfd, buf)`:
  ```go
  var totalRead int
  for totalRead < int(nDrain) {
      n, err := unix.Read(rrfd, buf[totalRead:])
      if err != nil {
          if err == unix.EINTR { continue }
          break
      }
      if n == 0 { break }
      totalRead += n
  }
  ```

---

### BUG-03: Silent Data Loss & Sequence Gap on Asymmetric UDP BFD Failure
- **Severity:** P1 (Data Loss / Connection Desynchronization)
- **Affected Files:**
  - [`internal/relay/standby.go:72-84`](file:///root/remote-relay/internal/relay/standby.go#L72-L84)
  - [`internal/relay/server.go:1694-1702`](file:///root/remote-relay/internal/relay/server.go#L1694-L1702)
- **Root Cause:**
  In [`clientStandby`](file:///root/remote-relay/internal/relay/standby.go#L72), the reader loop on the standby TCP connection discards every frame that is not a BFD ping:
  ```go
  f, err := conn.ReadFrame()
  if err != nil {
      runCancel()
      return
  }
  if f.Type == proto.TypePing {
      pkt, perr := bfd.DecodePacket(f.Payload)
      if perr == nil {
          _, _ = sess.Receive(pkt)
      }
  }
  // All other frame types (DATA, ACK, etc.) are silently dropped!
  ```
  In real network topologies, UDP packet drops are often asymmetric (e.g., client-to-server UDP works, but server-to-client UDP is blocked by a stateful NAT table timeout). When the server's BFD timer expires first, the server instantly promotes the standby TCP carrier and begins streaming downstream DATA and ACK frames over TCP.
  The client's UDP timer has not yet expired (up to 2.25s). Meanwhile, the client's standby loop **silently drops all incoming DATA frames** received over TCP. When the client finally switches, these frames are gone forever, resulting in unrecoverable `ERR_OFFSET_GAP`.
  In contrast, the server side correctly handles this in [`server.go:1694-1701`](file:///root/remote-relay/internal/relay/server.go#L1694-L1701) by prefetching non-ping frames and promoting immediately.
- **Impact:**
  Silent loss of downstream data bytes during carrier failover, leading to protocol desynchronization and broken sessions.
- **Fix Required:**
  Mirror the server's logic inside [`clientStandby`](file:///root/remote-relay/internal/relay/standby.go): when any non-ping frame is received on the standby connection, prefetch it into a buffered slice, cancel the active carrier context immediately, and promote the standby carrier to active.

---

### BUG-04: UDP Probe Nonce Collision on Multi-Address Endpoints
- **Severity:** P1 (Probe Failure / Transport Selection Degradation)
- **Affected Files:**
  - [`internal/transport/udpmux.go:287-289`](file:///root/remote-relay/internal/transport/udpmux.go#L287-L289)
  - [`internal/transport/udpmux.go:232-267`](file:///root/remote-relay/internal/transport/udpmux.go#L232-L267)
- **Root Cause:**
  In `internal/transport/udpmux.go`:
  ```go
  func Probe(ctx context.Context, mux *UDPMux, addr net.Addr, token [16]byte, attempts int, timeout time.Duration) error {
      ...
      const nonce = uint64(1) // Hardcoded constant!
      ch := mux.armProbeWait(nonce, addr)
      defer mux.disarmProbeWait(nonce)
  ```
  `UDPMux.probeWait` is a map keyed by `nonce`. When `ProbeDualStack` resolves multiple IPv6 (or IPv4) addresses and races UDP probes concurrently across the same `UDPMux`, all concurrent probe routines use `nonce = 1`.
  The second call to `armProbeWait(1, addr2)` finds the existing waiter channel and returns it instead of registering `addr2`. When a `PROBE_OK` response arrives from `addr2`, `signalProbeOK` checks `!sameUDPAddr(w.addr, from)` and discards the packet because `w.addr` was set to `addr1`.
- **Impact:**
  Concurrent UDP probes fail or time out erroneously on multi-homed or dual-stack servers, forcing the client to fall back to TCP unnecessarily.
- **Fix Required:**
  Generate a monotonically increasing atomic or cryptographically random 64-bit nonce for each probe invocation:
  ```go
  var probeNonceCounter uint64 // package-level atomic
  ...
  nonce := atomic.AddUint64(&probeNonceCounter, 1)
  ```

---

### BUG-05: SOCKS5 Head-of-Line Blocking Freezes All Multiplexed Streams
- **Severity:** P1 (Performance Bottleneck / Cascading Stall)
- **Affected Files:**
  - [`internal/relay/socks_server.go:346-364`](file:///root/remote-relay/internal/relay/socks_server.go#L346-L364)
  - [`internal/relay/socks_server.go:107-124`](file:///root/remote-relay/internal/relay/socks_server.go#L107-L124)
- **Root Cause:**
  `socksServerMux.run()` runs a single sequential loop reading multiplexer frames from the client (`socks5.ReadMuxFrame(smux.toMuxR)`). When a `TypeStreamData` frame arrives, it synchronously calls `handleData(streamID, payload)`.
  Inside `handleData()`:
  ```go
  select {
  case st.dataCh <- payload:
  case <-st.resetCh:
  case <-smux.ctx.Done():
  default:
      select {
      case st.dataCh <- payload:
      case <-time.After(3 * time.Second): // Synchronous 3-second block!
          smux.closeStream(streamID)
          ...
      }
  }
  ```
  If a single destination TCP socket buffer fills up (e.g., a slow file upload or stalled target), `st.dataCh` fills to capacity (64 chunks). `handleData` blocks on `time.After(3 * time.Second)` **inside the multiplexer reader loop**.
- **Impact:**
  While blocked, the server cannot read frames for **any other stream** on that connection. Fast streams, ping frames, and new stream opening requests are completely halted for up to 3 seconds.
- **Fix Required:**
  Implement per-stream credit-based flow control or buffer frames asynchronously with backpressure signaling, rather than blocking the multiplexer frame dispatcher.

---

### BUG-06: Unchecked `X-Forwarded-For` Client IP Spoofing in WebSocket Transport
- **Severity:** P1 (Security Vulnerability / ACL Bypass)
- **Affected Files:**
  - [`internal/transport/websocket.go:404-415`](file:///root/remote-relay/internal/transport/websocket.go#L404-L415)
- **Root Cause:**
  `ExtractClientIP()` parses incoming HTTP requests for reverse proxy compatibility:
  ```go
  if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
      parts := strings.Split(xff, ",")
      ip := strings.TrimSpace(parts[0])
      if net.ParseIP(ip) != nil {
          return ip
      }
  }
  ```
  The function blindly trusts `X-Forwarded-For` and `X-Real-IP` headers without verifying whether the direct peer connection originated from a trusted reverse proxy IP (e.g., `127.0.0.1` or configured CIDRs).
- **Impact:**
  Any untrusted client connecting directly to the server's WebSocket port (`listen_ws`) can forge arbitrary `X-Forwarded-For` headers to:
  1. Bypass per-IP connection limits (`MaxConnsPerIP`).
  2. Evade security audit logging and fail2ban rules.
  3. Deny service to legitimate IP addresses by exhausting their connection quotas.
- **Fix Required:**
  Only inspect `X-Forwarded-For` and `X-Real-IP` if the remote TCP address matches a configured `trusted_proxies` list in `config.Server`. Otherwise, strictly return `rawAddr`.

---

### BUG-07: Unbounded Agent Control Connection Leak on Silent Network Drops
- **Severity:** P1 (Availability / Connection Hanging)
- **Affected Files:**
  - [`internal/relay/server.go:2454-2472`](file:///root/remote-relay/internal/relay/server.go#L2454-L2472)
- **Root Cause:**
  In [`runAgentControlLoop()`](file:///root/remote-relay/internal/relay/server.go#L2454), the server loops reading frames from an agent's control connection:
  ```go
  f, err := conn.ReadFrame()
  if err != nil {
      s.log.Debug("agent control conn read closed", ...)
      return
  }
  ```
  `conn.ReadFrame()` has **no read deadline** and no application-level heartbeat detection. If an agent host abruptly powers down, switches WiFi networks, or experiences a stateful NAT drop without sending a TCP RST/FIN, the server's read call blocks indefinitely.
- **Impact:**
  The server keeps the agent registered in `s.agentReg` as "healthy". When incoming clients request that agent (`--target homelab`), the server dispatches `AgentBind` requests into the dead socket and hangs until the client dial timeout (10s) expires.
- **Fix Required:**
  Set a read deadline on the agent control connection renewed on every incoming frame, or run a periodic ping ticker verifying agent responsiveness within `HeartbeatInterval * 2`.

---

### BUG-08: Zero Throughput Metrics in `relay top` Dashboard
- **Severity:** P2 (Observability Failure)
- **Affected Files:**
  - [`internal/obs/metrics.go:458, 499`](file:///root/remote-relay/internal/obs/metrics.go#L458-L499)
  - [`internal/relay/pump.go`](file:///root/remote-relay/internal/relay/pump.go)
  - [`internal/relay/splice_linux.go`](file:///root/remote-relay/internal/relay/splice_linux.go)
- **Root Cause:**
  `relay_bytes_transferred_total` (`BytesTransferred` counter vector) is declared in `internal/obs/metrics.go` with labels `direction` (`up`/`down`) and `transport` (`tcp`/`quic`/`ws`).
  However, **nowhere in the entire relay data pipeline** (`pump.go`, `splice_linux.go`, `server.go`, or `client.go`) is `BytesTransferred.WithLabelValues(...).Add(n)` ever called. The only references to this metric exist in mock test assertions.
- **Impact:**
  When operators run `relay top` to monitor live relay health, the "Upload Total", "Download Total", and real-time bandwidth sparklines display permanently as `0 B` and flat lines, even when gigabytes of data are streaming through the relay.
- **Fix Required:**
  Add metric updates inside `pump.go` (in `srcReader` and `sinkWriter`) and `splice_linux.go`:
  ```go
  if p.metrics != nil {
      p.metrics.BytesTransferred.WithLabelValues(p.cfg.outDir.String(), p.carrierKind.String()).Add(uint64(n))
  }
  ```

---

## 3. Comprehensive 17-Feature Audit Matrix

### FEAT-ROB-01: Sub-Second BFD & Dead-Peer Detection
- **Specification:**
  - Continuous bidirectional heartbeats on active and standby paths.
  - Negotiable interval down to 250ms with 3-miss detection threshold (750ms failover).
  - Standby TCP connection maintained with zero data until failover.
- **Implementation:**
  - Package: [`internal/bfd`](file:///root/remote-relay/internal/bfd) implements RFC 5880 packet encoding and state machine.
  - Relay glue: [`internal/relay/standby.go`](file:///root/remote-relay/internal/relay/standby.go) and [`internal/relay/server.go:1670-1740`](file:///root/remote-relay/internal/relay/server.go#L1670-L1740).
- **Happy Path:**
  Client establishes UDP primary and TCP standby. Both exchange BFD packets with configured `TxInterval` (default 250ms). When primary carrier is healthy, zero application data passes over TCP.
- **Sad Paths & Edge Cases:**
  - *Asymmetric Loss (Unhandled Bug):* Addressed in [BUG-03](#bug-03-silent-data-loss--sequence-gap-on-asymmetric-udp-bfd-failure). Client standby reader drops incoming data frames if server promotes first.
  - *NAT Rebinding:* Handled properly via UDP mux authenticated token lookup.
  - *Stale Standby Connection:* If standby carrier dies silently, client reconnects standby path in background.

---

### FEAT-ROB-02: Zero-Downtime Server Restart & Socket Handover via SCM_RIGHTS / LISTEN_FDS
- **Specification:**
  - Seamless binary upgrades via `SIGUSR2` signal or systemd socket activation (`LISTEN_FDS`).
  - Active TCP/UDP listening sockets and client destination FDs passed via Unix domain socket using `SCM_RIGHTS`.
  - In-flight ring buffers and session tokens transferred to child process without dropping connections.
- **Implementation:**
  - Modules: [`internal/relay/server_unix.go`](file:///root/remote-relay/internal/relay/server_unix.go), [`internal/relay/handover.go`](file:///root/remote-relay/internal/relay/handover.go).
- **Happy Path:**
  Operator sends `kill -SIGUSR2 <pid>`. Parent serializes `HandoverState`, opens Unix socket, spawns child with `RELAY_HANDOVER_SOCK`. Child adopts listeners and destination FDs, sends ACK, parent exits cleanly.
- **Sad Paths & Edge Cases:**
  - *Child Panic on Non-TCP Dest (Critical Bug):* Addressed in [BUG-01](#bug-01-child-server-panic-on-hot-restart-for-non-tcp-sessions).
  - *Premature Listener Close (Unhandled Sad Path):* In [`server_unix.go:125-129`](file:///root/remote-relay/internal/relay/server_unix.go#L125-L129), parent closes listeners and drops client carriers **before** child process acknowledges adoption. If child initialization fails, all listening sockets are terminated.
  - *RestoreTieredRing Deadlock Risk:* In [`internal/session/ringbuf.go:590`](file:///root/remote-relay/internal/session/ringbuf.go#L590), `RestoreTieredRing` calls `r.Append(context.Background(), data)`, which invokes `budget.Wait()`. If budget is full, the server blocks indefinitely during boot.

---

### FEAT-ROB-03: Dual-Stack Happy Eyeballs v2 (RFC 8305)
- **Specification:**
  - Parallel resolution of IPv6 (AAAA) and IPv4 (A) records.
  - Staggered connection attempts with configurable `resolution_delay` (default 250ms).
  - Fast UDP probe racing across address families.
- **Implementation:**
  - Transport logic: [`internal/transport/happy_eyeballs.go`](file:///root/remote-relay/internal/transport/happy_eyeballs.go), [`internal/transport/udpmux.go`](file:///root/remote-relay/internal/transport/udpmux.go).
- **Happy Path:**
  Client resolves hostname to dual-stack IPs. IPv6 connection starts immediately; IPv4 waits 250ms. Whichever completes handshake first becomes the active carrier; the other is canceled.
- **Sad Paths & Edge Cases:**
  - *Probe Nonce Collision (Bug):* Addressed in [BUG-04](#bug-04-udp-probe-nonce-collision-on-multi-address-endpoints).
  - *DNS Hang on Single Family:* Handled cleanly via context timeouts.
  - *IPv6 Blackhole:* Handled by 250ms fallback to IPv4.

---

### FEAT-ROB-04: Tiered Disk-Spill Storage for Ring Buffers
- **Specification:**
  - L1 memory ring buffer backed by temporary disk spill storage for unacknowledged data.
  - Automatic hole-punching via `fallocate(FALLOC_FL_PUNCH_HOLE)` to reclaim space upon ACK.
  - Enforced memory budgets per session.
- **Implementation:**
  - Ring buffer: [`internal/session/ringbuf.go`](file:///root/remote-relay/internal/session/ringbuf.go), [`internal/session/spill.go`](file:///root/remote-relay/internal/session/spill.go).
- **Happy Path:**
  Bursty incoming data exceeding `spill_l1_bytes` spills to encrypted temporary files in `spill_dir`. As peer ACKs advance, `PunchHole` frees filesystem blocks.
- **Sad Paths & Edge Cases:**
  - *Silent Corrupted Snapshot (Bug):* In [`ringbuf.go:566`](file:///root/remote-relay/internal/session/ringbuf.go#L566), `r.spill.ReadAt` errors are discarded (`_, _ = r.spill.ReadAt(...)`). On disk read failure, snapshot returns zeroed bytes without notifying the caller.
  - *ENOSPC on Disk Spill:* If disk is full, `spillOneBlockLocked` returns an error, which causes `pump.srcReader` to terminate the session instead of exerting backpressure on the sender.

---

### FEAT-UTL-01: Native OpenSSH Agent SSH_AUTH_SOCK Integration
- **Specification:**
  - Query active `SSH_AUTH_SOCK` for Ed25519, ECDSA, and RSA signing keys.
  - Support passphrase-protected keys loaded in agent without disk private keys.
  - Key matching and fallback order: explicit identities -> agent keys -> default disk files.
- **Implementation:**
  - Auth module: [`internal/auth/ssh.go:290-410`](file:///root/remote-relay/internal/auth/ssh.go#L290-L410).
- **Happy Path:**
  Client detects `SSH_AUTH_SOCK`, queries available signers, extracts public keys, and signs server authentication challenges seamlessly.
- **Sad Paths & Edge Cases:**
  - *PKCS#8 Passphrase Key Without `.pub` File:* If a private key file is encrypted in PKCS#8 format and has no accompanying `.pub` file, `extractPublicKey` returns `nil`, failing to match it against keys loaded in `ssh-agent`.

---

### FEAT-UTL-02: Terminal Reconnection HUD & Desktop Notifications
- **Specification:**
  - Single-line status updates on stderr using `\r` during disconnection.
  - Desktop notifications via terminal OSC escape sequences (OSC 9 for iTerm2/WezTerm, OSC 777 for Ghostty/Alacritty) for disruptions exceeding `NotificationTimeout` (default 5s).
- **Implementation:**
  - Module: [`internal/relay/hud.go`](file:///root/remote-relay/internal/relay/hud.go).
- **Happy Path:**
  On carrier drop, HUD displays retry counter and elapsed time on stderr. When connection is restored, HUD clears or prints success summary. If downtime exceeds 5s, OSC 9/777 notifications are dispatched.
- **Sad Paths & Edge Cases:**
  - *Non-TTY Stderr:* Correctly suppressed via `term.IsTerminal()`.
  - *ANSI Truncation:* Correctly computes visible rune width to avoid wrapping long terminals.

---

### FEAT-UTL-03: SOCKS5 Dynamic Forwarding Mode (`relay socks`)
- **Specification:**
  - Client exposes local SOCKS5 proxy (`127.0.0.1:1080`).
  - Multiplexes multiple TCP streams over a single relay tunnel session.
  - Server enforces per-user RBAC and destination ACLs.
- **Implementation:**
  - Client side: [`internal/relay/socks_client.go`](file:///root/remote-relay/internal/relay/socks_client.go).
  - Server side: [`internal/relay/socks_server.go`](file:///root/remote-relay/internal/relay/socks_server.go).
- **Happy Path:**
  Browser connects to `127.0.0.1:1080`, issues SOCKS5 CONNECT request. Server validates destination ruleset, dials target, streams frames bidirectional.
- **Sad Paths & Edge Cases:**
  - *Multiplexer Head-of-Line Blocking (Bug):* Addressed in [BUG-05](#bug-05-socks5-head-of-line-blocking-freezes-all-multiplexed-streams).
  - *Unbounded Goroutines on Dial Stalls:* Target dial timeouts spawn goroutines with no concurrency semaphore.

---

### FEAT-UTL-04: Reverse Relay & NAT Gateway Mode / Agent
- **Specification:**
  - Agents behind NAT register named targets (`--target homelab`) with persistent control connection.
  - Server holds agent registration during brief disconnects (`agent_hold_timeout`, default 15s).
  - Clients connect to named targets without knowing agent IP.
- **Implementation:**
  - Modules: [`internal/relay/agent_registry.go`](file:///root/remote-relay/internal/relay/agent_registry.go), [`internal/relay/server.go:2454-2485`](file:///root/remote-relay/internal/relay/server.go#L2454-L2485).
- **Happy Path:**
  Agent registers with `AgentRegister`. Client dials `--target homelab`. Server sends `AgentBind` to agent, agent connects to local target and opens data pipe to server, server joins streams.
- **Sad Paths & Edge Cases:**
  - *Agent Control Loop Hang (Bug):* Addressed in [BUG-07](#bug-07-unbounded-agent-control-connection-leak-on-silent-network-drops).
  - *Immediate Client Rejection During Hold (Bug):* In [`agent_registry.go:160`](file:///root/remote-relay/internal/relay/agent_registry.go#L160), if an agent is within its 15s hold period (`ControlConn == nil`), client requests fail immediately instead of waiting for agent reconnect.

---

### FEAT-UTL-05: Multi-Hop Jumphost Chaining (`-J`)
- **Specification:**
  - End-to-end multi-relay traversal via `-J hop1,hop2`.
  - Nested hop-by-hop KEX authentication with independent resume tokens.
  - Per-hop hold and reconnect resilience.
- **Implementation:**
  - Module: [`internal/relay/chain.go`](file:///root/remote-relay/internal/relay/chain.go).
- **Happy Path:**
  Client establishes session with Hop 1, sends `CHAIN` frame containing downstream hops. Hop 1 establishes KEX with Hop 2, forwarding challenges back to client. Data streams are bridged end-to-end.
- **Sad Paths & Edge Cases:**
  - *Hot Restart Support:* Nested chained sessions cannot currently be serialized across process restart (lacks dest socket FD).

---

### FEAT-UTL-06: Chained Jumphost Rendezvous to NATed Terminal (`HopSpec.Target`)
- **Specification:**
  - Final hop in jumphost chain can be an agent target name rather than explicit `host:port`.
  - Intermediate jumphosts route to the final relay where the agent is registered.
- **Implementation:**
  - Verified across [`internal/relay/chain.go`](file:///root/remote-relay/internal/relay/chain.go) and [`internal/relay/chain_target_test.go`](file:///root/remote-relay/internal/relay/chain_target_test.go).
- **Happy Path:**
  Chain terminates at destination relay holding target agent; rendezvous bind executes cleanly.

---

### FEAT-SEC-01: Encrypted Control Plane: X25519 & ChaCha20-Poly1305 AEAD
- **Specification:**
  - Ephemeral X25519 key exchange signed by Ed25519 host key.
  - ChaCha20-Poly1305 AEAD wrapping for all control frames.
  - Strict anti-replay monotonic 64-bit sequence numbers.
- **Implementation:**
  - Cryptography: [`internal/crypto/kex`](file:///root/remote-relay/internal/crypto/kex).
- **Happy Path:**
  KEX handshake completes in 1 RTT. Subsequent HELLO/AUTH frames are encrypted and authenticated. Option A phase cut hands off cleanly to raw data plane.
- **Sad Paths & Edge Cases:**
  - *Replay Attacks:* Rejected cleanly via `seq != c.recvSeq`.
  - *Tampered Frames:* Rejected by Poly1305 tag verification.

---

### FEAT-SEC-02: WebSocket & HTTPS Port 443 Fallback Transport
- **Specification:**
  - WebSocket fallback over standard HTTPS port 443 with TLS.
  - HTTP CONNECT proxy traversal with Basic auth support.
  - Reverse proxy IP extraction (`X-Forwarded-For`).
- **Implementation:**
  - Transport: [`internal/transport/websocket.go`](file:///root/remote-relay/internal/transport/websocket.go).
- **Happy Path:**
  Client dials `wss://...`, completes HTTP upgrade, frames relay messages inside binary WebSocket frames.
- **Sad Paths & Edge Cases:**
  - *IP Spoofing Vulnerability (Security Bug):* Addressed in [BUG-06](#bug-06-unchecked-x-forwarded-for-client-ip-spoofing-in-websocket-transport). Direct clients can forge client IP headers.

---

### FEAT-SEC-03: Per-User RBAC & Live SIGHUP Config Reload
- **Specification:**
  - `authorized_keys` options: `permitopen`, `permitagent`, `no-port-forwarding`, `no-agent-forwarding`.
  - Atomic config reload upon `SIGHUP` without disrupting active connections.
  - CLI flag precedence over reloaded TOML values.
- **Implementation:**
  - Parsing: [`internal/auth/ssh.go:490-580`](file:///root/remote-relay/internal/auth/ssh.go#L490-L580).
  - Server reload: [`internal/relay/server.go:160-220`](file:///root/remote-relay/internal/relay/server.go#L160-L220).
- **Happy Path:**
  Admin modifies `authorized_keys` or TOML and sends `kill -HUP <pid>`. Server re-parses keys and config atomically. Active connections remain uninterrupted.
- **Sad Paths & Edge Cases:**
  - *CLI Override Loss (Bug):* In [`cmd/relay/main.go:154`](file:///root/remote-relay/cmd/relay/main.go#L154), `srv.SetOptions(opts)` is never invoked. On `SIGHUP`, CLI flag overrides are wiped out by TOML values.
  - *Malformed Key Lines:* Correctly ignored without failing valid keys in the file.

---

### FEAT-PERF-01: Linux Kernel Zero-Copy Stream Splicing `splice(2)`
- **Specification:**
  - Direct kernel socket-to-socket transfer via pipe buffers (`splice(2)` / `tee(2)` / `vmsplice(2)`).
  - Ring buffer tee retention for session recovery.
  - Non-blocking netpoller integration.
- **Implementation:**
  - Module: [`internal/relay/splice_linux.go`](file:///root/remote-relay/internal/relay/splice_linux.go).
- **Happy Path:**
  Data splices directly from source socket to destination socket without copying into userspace memory.
- **Sad Paths & Edge Cases:**
  - *Pipe FD Corruption / Use-After-Free (Critical Bug):* Addressed in [BUG-02](#bug-02-file-descriptor-corruption--use-after-free-in-linux-splice-retain).
  - *Pipe Capacity Saturation:* Handled via Go netpoller non-blocking retry.

---

### FEAT-PERF-02: Adaptive KCP Dynamic ARQ & Congestion Tuning
- **Specification:**
  - Periodic sampling of loss rate, RTT, and queue depth.
  - Dynamic ARQ parameter adjustment (`normal`, `lossy`, `degraded`).
- **Implementation:**
  - Controller: [`internal/transport/kcp_adaptive.go`](file:///root/remote-relay/internal/transport/kcp_adaptive.go).
- **Happy Path:**
  Clean link operates at 30ms interval. Under loss, tuner drops interval to 15ms or 10ms with aggressive resend.
- **Sad Paths & Edge Cases:**
  - *SNMP Counter Bleed (Bug):* In [`kcp_adaptive.go:93`](file:///root/remote-relay/internal/transport/kcp_adaptive.go#L93), `defaultSampler` reads global `kcp.DefaultSnmp` counters. Loss spikes on one client cause all sessions to degrade.

---

### FEAT-PERF-03: Fast 3-RTT Token Resumption in AEAD Plane
- **Specification:**
  - Fast resume using cached session token inside AEAD channel.
  - Bypasses public key challenge negotiation down to 3 RTT (TCP conn -> KEX -> RESUME).
  - Cryptographic fallback to challenge if token is invalid or expired.
- **Implementation:**
  - Logic: [`internal/relay/server.go:1335-1362`](file:///root/remote-relay/internal/relay/server.go#L1335-L1362), [`internal/relay/upgrade.go:300-360`](file:///root/remote-relay/internal/relay/upgrade.go#L300-L360).
- **Happy Path:**
  Client connects, performs KEX, sends RESUME with token. Server verifies token, skips challenge, returns RESUME_OK. Session resumes immediately in 3 RTT.
- **Sad Paths & Edge Cases:**
  - *Stale/Corrupted Token:* Server falls back to SSH challenge-response authentication seamlessly.

---

### FEAT-OBS-01: Prometheus Metrics Exporter, OpenTelemetry Tracing & Live TUI Dashboard `relay top`
- **Specification:**
  - Prometheus `/metrics` endpoint with counters, gauges, histograms.
  - OpenTelemetry distributed tracing with `traceparent` propagation across hops (`Handshake`, `Resume`, `Upgrade`, `ChainHop`).
  - Terminal UI dashboard (`relay top`).
- **Implementation:**
  - Modules: [`internal/obs`](file:///root/remote-relay/internal/obs), [`internal/tui`](file:///root/remote-relay/internal/tui).
- **Happy Path:**
  Prometheus scrapes `/metrics`. `relay top` displays live terminal UI. Trace spans record latency.
- **Sad Paths & Edge Cases:**
  - *Zero Throughput Counters (Bug):* Addressed in [BUG-08](#bug-08-zero-throughput-metrics-in-relay-top-dashboard).
  - *Missing Upgrade Span (Deviation):* `Upgrade` span promised in spec is never started in [`upgrade.go`](file:///root/remote-relay/internal/relay/upgrade.go).

---

## 4. Unhandled Happy & Sad Paths Summary

| Path / Scenario | Affected Feature | Current Behavior | Desired Behavior |
| :--- | :--- | :--- | :--- |
| **Asymmetric Carrier Loss** | FEAT-ROB-01 | Client standby drops incoming TCP DATA frames until UDP timeout | Client pre-buffers DATA frames and promotes standby TCP immediately |
| **Hot Restart with Virtual Streams** | FEAT-ROB-02 | Child server panics on nil destination socket pointer | Reconstruct virtual session pipes or hold sessions in store |
| **Parent Crash During Handover** | FEAT-ROB-02 | Parent closes listeners before child acknowledges adoption | Keep listeners open until child sends handover confirmation |
| **Disk Exhaustion during Spill** | FEAT-ROB-04 | Session terminates immediately with IO error | Throttle source reader and wait for client ACKs before discarding |
| **Client Connects to Holding Agent** | FEAT-UTL-04 | Client immediately rejected with "disconnected" | Client blocked/queued up to remaining hold timeout |
| **Direct WebSocket Client IP Spoof** | FEAT-SEC-02 | Untrusted `X-Forwarded-For` header adopted | Header ignored unless direct peer is in `trusted_proxies` |
| **SIGHUP Reload Overwriting Flags** | FEAT-SEC-03 | CLI flag overrides erased upon config reload | Preserve original startup flags across reload |
| **SOCKS5 Stream Write Saturated** | FEAT-UTL-03 | Reader loop blocks for 3s, freezing all streams | Drop/reset offending stream or pause stream reading asynchronously |

---

## 5. Remediation Plan & Recommendations

### Phase 1: High Priority Stability & Security Fixes (Immediate)
1. **Fix Hot Restart Crash (BUG-01):**
   Update [`adoptHandover()`](file:///root/remote-relay/internal/relay/server.go#L490) to check `hSess.HasDestFD`. If false, do not invoke `newPump` with nil sockets; instead, register sessions in held state awaiting client or agent reconnection.
2. **Fix Splice FD Leak & Corruption (BUG-02):**
   Replace `io.ReadFull(os.NewFile(...))` in [`splice_linux.go:273`](file:///root/remote-relay/internal/relay/splice_linux.go#L273) with direct `unix.Read` syscalls.
3. **Fix Asymmetric Failover Data Loss (BUG-03):**
   Update [`clientStandby`](file:///root/remote-relay/internal/relay/standby.go#L72) to prefetch non-ping frames and trigger immediate promotion.
4. **Fix WebSocket IP Spoofing (BUG-06):**
   Add `TrustedProxies []string` to `config.Server` and gate `X-Forwarded-For` parsing in [`websocket.go:404`](file:///root/remote-relay/internal/transport/websocket.go#L404).

### Phase 2: Concurrency & Protocol Resilience
1. **Fix UDP Probe Nonce Collisions (BUG-04):**
   Use atomic counter for probe nonces in [`udpmux.go:287`](file:///root/remote-relay/internal/transport/udpmux.go#L287).
2. **Fix SOCKS5 HOL Blocking (BUG-05):**
   Decouple frame dispatch from stream writing in [`socks_server.go:346`](file:///root/remote-relay/internal/relay/socks_server.go#L346).
3. **Set Deadlines on Agent Control Loops (BUG-07):**
   Add heartbeat verification to [`server.go:2467`](file:///root/remote-relay/internal/relay/server.go#L2467).
4. **Preserve CLI Flag Overrides on SIGHUP (FEAT-SEC-03):**
   Call `srv.SetOptions(opts)` in [`main.go:154`](file:///root/remote-relay/cmd/relay/main.go#L154).

### Phase 3: Telemetry, Observability & Cleanup
1. **Wire Up Throughput Metrics (BUG-08):**
   Add `BytesTransferred.Add()` calls in [`pump.go`](file:///root/remote-relay/internal/relay/pump.go) and [`splice_linux.go`](file:///root/remote-relay/internal/relay/splice_linux.go).
2. **Add Missing Tracing Spans (FEAT-OBS-01):**
   Instrument transport upgrade sequence with `Upgrade` span in [`upgrade.go`](file:///root/remote-relay/internal/relay/upgrade.go).
3. **Per-Session KCP Metrics (FEAT-PERF-02):**
   Provide per-session KCP metric sampler to avoid global counter bleeding.
