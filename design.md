# remote-relay — design

A resumable stdio↔port relay in Go. The client is typically used as an SSH
`ProxyCommand`; the server terminates the tunnel and dials a destination
(default `127.0.0.1:22`, i.e. the local `sshd`). If the WAN link between client
and server breaks, the client reconnects and **resumes the same session** so that
the consumer (`ssh`) never observes a disconnect.

Status: design draft, pre-implementation. Go ≥ 1.23, Linux/macOS.

---

## 1. Goals

1. Byte-exact, in-order, reliable bidirectional stream relay between client
   stdio and a server-side destination TCP socket.
2. Transport negotiation: handshake always over TCP; data plane upgrades to UDP
   (QUIC by default, KCP on request) when a UDP probe succeeds.
3. **Transparent reconnection.** A broken client↔server link is invisible to the
   consumer: the destination socket stays open, in-flight data is retained, and
   the stream resumes at exact byte offsets with no loss and no duplication.
4. Many concurrent sessions per server process, each with its own destination.
5. One shared, lazily-opened UDP endpoint on the server, kept open afterwards.
6. Single static binary, subcommand style: `relay server`, `relay client`.

## 2. Non-goals (v1)

- No authentication or authorization (deferred, see §10).
- No NAT traversal for a NATed *server*; the server's UDP address must be
  routable from clients (a NATed *client* is fully supported).
- No multiplexing of several logical channels inside one session (one session =
  one byte stream, exactly what `ProxyCommand` needs).
- No reliance on QUIC connection migration; our own resume path covers IP
  changes.
- No Windows service packaging; no built-in TLS termination for the TCP
  handshake (v1 control plane is cleartext).

## 3. Decisions log

| # | Decision | Rationale |
|---|---|---|
| D1 | Support **both** QUIC and KCP. Client picks; default QUIC, `--kcp` overrides. | Operator choice per link quality; QUIC brings TLS 1.3 for free, KCP wins on some lossy paths. |
| D2 | v1 auth: **none**, no IP allowlist. Later: SSH-style public-key auth reusing `~/.ssh/id_*` and `authorized_keys`. | Ship the hard part (resume) first; the payload is an already-encrypted SSH stream (§10). |
| D3 | **Many concurrent sessions**, per-session destination announced in the handshake. | One server serves many users/hosts; enables `ProxyCommand="relay client %h %p"`. |
| D4 | On link break the server **holds the destination socket and buffers its output**, resuming by session token + byte offsets. Defaults `hold_timeout = 5m`, `buffer_bytes = 64 MiB`, both **config-file tunable**. | Requirement: the break must be invisible to the consumer. |
| D5 | **One shared UDP endpoint** on the server, opened lazily on first upgrade, kept open for the process lifetime. | Fewest firewall rules / fds; sessions demux inside it. |
| D6 | Server UDP is **publicly reachable**: it advertises `host:port` in the TCP handshake; a probe confirms reachability before upgrading; on probe failure the session stays on TCP. | Simplest correct model; TCP remains a valid permanent fallback. |
| D7 | After a successful upgrade the **TCP connection is closed**; any later break is repaired by re-dialing TCP and issuing `RESUME`. | One code path for *all* breakage instead of two (upgrade-downgrade + resume). |
| D8 | Control-plane payloads are **JSON**; data-plane frames are **fixed binary**. | Handshake/resume happens a handful of times per session and is worth being able to read in a hexdump; DATA is the hot path. |
| D9 | Only **one active data path at a time** per direction; switching is an explicit, quiesced `SWITCH` handshake. | Prevents reordering/duplication that two simultaneously-live paths would cause. |
| D10 | Shared UDP socket disambiguates stacks with a **1-byte tag prefix** managed by an internal `udpMux`. | Deterministic; avoids heuristic first-byte sniffing between QUIC headers and KCP `conv`. |

---

## 4. Architecture

```
            CLIENT HOST                                   SERVER HOST
 ┌──────────────────────────────┐          ┌───────────────────────────────────┐
 │  ssh (consumer)              │          │                      relay server │
 │    │ stdin/stdout (pipes)    │          │                                   │
 │    ▼                         │          │  ┌────────────┐   ┌────────────┐  │
 │  relay client                │          │  │ session S1 │   │ session S2 │  │
 │  ┌────────────────────────┐  │          │  │  upLog     │   │  ...       │  │
 │  │ stdio pumps (2 gorout.)│  │          │  │  downLog   │  │             │  │
 │  │ session state machine  │◄─┼──TCP─────┼─►│ hold timer │  │             │  │
 │  │ resume + dedupe        │  │ (ctrl)   │  └─────┬──────┘   └────────────┘  │
 │  │ transport selector     │◄─┼──UDP─────┼───────►│                          │
 │  └────────────────────────┘  │ QUIC/KCP │   ┌────▼─────┐                    │
 │                              │  (data)  │   │ udpMux   │ 1 shared socket    │
 └──────────────────────────────┘          │   └──────────┘                    │
                                           │        │ dial                     │
                                           │        ▼                          │
                                           │  127.0.0.1:22  (sshd)             │
                                           └───────────────────────────────────┘
```

Per session there are two independent, separately-sequenced byte streams:

- **up** — client stdin → server → destination.
- **down** — destination → server → client stdout.

Each direction has its own absolute byte offset space starting at 0.

### 4.1 Repository layout

```
go.mod
design.md
README.md
cmd/relay/main.go              # subcommands: server | client | version
internal/config/               # TOML load, defaults, validation, flag overlay
internal/proto/                # frame codec, control message types, error codes
internal/transport/            # Conn interface; tcp / quic / kcp adapters; udpMux
internal/session/              # state machine, offsets, dedupe, ringbuf, store
internal/relay/                # client & server pumps (stdio↔conn, dest↔conn)
internal/auth/                 # Authenticator iface: none (v1), sshpubkey (M5)
internal/logging/              # slog setup, per-session fields
```

### 4.2 Dependencies

| Module | Use | Milestone |
|---|---|---|
| `github.com/quic-go/quic-go` | QUIC data plane | M2 |
| `github.com/xtaci/kcp-go/v5` | KCP data plane (verify exact path/version at implementation time) | M3 |
| `github.com/BurntSushi/toml` | config files | M0 |
| `golang.org/x/crypto/ssh` | parse `authorized_keys` / sign with `~/.ssh/id_*` | M5 |

Everything else is stdlib (`log/slog`, `encoding/binary`, `encoding/json`,
`crypto/rand`).

---

## 5. Wire protocol

### 5.1 Framing (identical on TCP, QUIC streams and KCP)

All transports carry the same length-prefixed frames, so one codec serves all
three and the transport adapters stay dumb byte pipes.

```
Frame := Type uint8 | PayloadLen uint32 (big-endian) | Payload [PayloadLen]byte
```

- Hard limit `maxFrameLen = 1 MiB`. A frame declaring more is a fatal protocol
  error (`ERR_FRAME`) and the connection is dropped.
- `DATA` payload ≤ `dataChunkBytes` (default 64 KiB).
- QUIC: one bidirectional stream per direction per session; frames written
  straight into the stream (QUIC preserves order and boundaries are our own).
- KCP: stream mode enabled, so we must not assume datagram boundaries — the
  length prefix handles it.

### 5.2 Frame types

| Type | Name | Payload | Direction |
|---|---|---|---|
| `0x01` | `HELLO` | JSON `Hello` | C→S |
| `0x02` | `HELLO_OK` | JSON `HelloOK` | S→C |
| `0x03` | `RESUME` | JSON `Resume` | C→S |
| `0x04` | `RESUME_OK` | JSON `ResumeOK` | S→C |
| `0x05` | `RESUME_FAIL` | JSON `Fail{code,msg}` | S→C |
| `0x06` | `SWITCH` | JSON `Switch{dir,from,offset}` | both |
| `0x07` | `BYE` | JSON `Bye{code,msg}` | both |
| `0x08` | `ERR` | JSON `Fail{code,msg}` | both |
| `0x10` | `DATA` | `Seq uint64 BE` + bytes | both |
| `0x11` | `ACK` | `AckedThrough uint64 BE` | both |
| `0x12` | `CLOSE_DIR` | JSON `CloseDir{dir,finalOffset}` | both |
| `0x13` | `PROBE` | `Token[16]` + `Nonce uint64` | C→S (UDP) |
| `0x14` | `PROBE_OK` | `Nonce uint64` | S→C (UDP) |
| `0x15` | `PING` | `Nonce uint64` + `SentUnixMillis uint64` | both |
| `0x16` | `PONG` | echoes `PING` payload | both |

`Seq` is the absolute offset of the first payload byte in that direction.
`AckedThrough` is exclusive: "I have durably consumed bytes `[0, AckedThrough)`".

### 5.3 Control messages (JSON)

```jsonc
// C→S HELLO
{
  "v": 1,
  "sessionId": "",              // empty for a new session
  "resumeToken": "",            // base64, empty for a new session
  "transport": ["quic","kcp"],  // preference order; ["tcp"] disables upgrade
  "destination": "127.0.0.1:22",// "" = server default
  "clientNonce": "…",           // base64, 16B, anti-replay for M5 auth
  "auth": {},                   // empty object in v1
  "window": 4194304             // proposed send window
}

// S→C HELLO_OK
{
  "v": 1,
  "sessionId": "s-9f2c1a",
  "resumeToken": "…",           // base64, 32B, bearer credential for RESUME
  "transport": "quic",          // selected
  "udp": { "addr": "203.0.113.7:7443", "probeToken": "…", "probeTimeoutMs": 2000,
           "probeAttempts": 2 },
  "limits": { "bufferBytes": 67108864, "holdTimeoutMs": 300000,
              "window": 4194304, "dataChunkBytes": 65536 },
  "serverNonce": "…"
}

// C→S RESUME (sent on a fresh TCP connection after a break)
{ "v":1, "sessionId":"s-9f2c1a", "resumeToken":"…", "transport":["quic"],
  "downAcked": 184320,          // bytes the client already wrote to stdout
  "clientNonce":"…" }

// S→C RESUME_OK
{ "v":1, "sessionId":"s-9f2c1a", "resumeToken":"…",   // rotated on every resume
  "upAcked": 90210,             // bytes the server already wrote to the destination
  "downNext": 184320,           // where the server will resume sending down
  "state": { "upClosed": false, "downClosed": false, "heldMs": 4213 },
  "transport":"quic", "udp": { … }, "limits": { … } }
```

`resumeToken` is **rotated on every successful `RESUME_OK`** so a captured token
cannot be replayed against a later incarnation of the session.

### 5.4 Error codes

`ERR_VERSION`, `ERR_PROTO`, `ERR_FRAME`, `ERR_DEST_REFUSED`, `ERR_DEST_FORBIDDEN`
(destination not in `allow_destinations`), `ERR_NO_CAPACITY` (session or global
buffer budget exhausted), `ERR_UNKNOWN_SESSION`, `ERR_BAD_TOKEN`, `ERR_EXPIRED`
(hold window elapsed), `ERR_AUTH`, `ERR_SHUTDOWN`, `ERR_INTERNAL`.

---

## 6. Session lifecycle

```
        new HELLO                       probe ok            link break
  ┌───────────────► ESTABLISHED ────────────────► UPGRADED ──────────────┐
  │                   (TCP data)                    (UDP data)            │
  │                       ▲                             │                 ▼
  │                       │        probe fail /         │            DEGRADED
  │                       └──────── SWITCH(tcp) ────────┘        (re-dial TCP,
  │                                                                       │
  │                                                        RESUME within  │
  │                                                        hold window    │
  │                                                                       ▼
  │                                                            HELD ──► RESUMING
  │                                                    hold_timeout ▲      │
  └──────────────────────────────────────────────────────────────────┘    │
                                                    CLOSED ◄──────────────┘
```

- **ESTABLISHED** — TCP handshake done, destination dialed, data flowing on TCP.
- **UPGRADED** — probe succeeded, `SWITCH` completed, TCP conn closed (D7), data
  on QUIC/KCP.
- **DEGRADED** — the UDP path failed; the client immediately attempts re-dial +
  `RESUME`, which lands back in ESTABLISHED (and re-probes to try upgrading
  again). A session may cycle UPGRADED→DEGRADED→UPGRADED indefinitely.
- **HELD** — server-side only: no live transport connection, destination socket
  still open, `downLog` still filling, `hold_timeout` counting down.
- **RESUMING → ESTABLISHED** — offsets reconciled, tails retransmitted, half-close
  flags restored.
- **CLOSED** — `BYE`, fatal `ERR`, hold expiry, destination EOF+drain, or process
  shutdown. Destination socket closed, buffers freed, token invalidated.

### 6.1 Handshake / upgrade sequence

1. Client dials `listen_tcp`, sends `HELLO`.
2. Server checks version, destination allowlist, session capacity; allocates
   `sessionId` + `resumeToken`; dials the destination. Dial failure ⇒
   `ERR{ERR_DEST_REFUSED}`.
3. Server replies `HELLO_OK`. If the client's preference is `["tcp"]`, or UDP is
   disabled in config, `udp` is `null` and the session stays on TCP forever.
4. Server ensures the shared UDP endpoint is running (lazily started on first
   need, then kept open — D5).
5. Client sends `PROBE` datagrams to `udp.addr` (up to `probeAttempts`,
   `probeTimeoutMs` each) carrying `probeToken`. Server replies `PROBE_OK` on the
   same 5-tuple. The probe both proves reachability and, for KCP/NAT, warms the
   client's outbound UDP mapping.
6. On success the client sends `SWITCH{dir:both, from:"tcp", offset:{up:upNext,
   down:downNext}}` over TCP and **quiesces**: it stops sending `DATA` on TCP and
   waits until every TCP-sent byte is `ACK`ed (bounded by `switchTimeout`, 5s).
7. Client establishes the chosen UDP transport, re-sends `RESUME` (same token,
   now carrying the quiesced offsets) over it; server validates and continues the
   session on UDP. Both sides close the TCP connection.

Step 7 reuses the resume path deliberately: "upgrade" and "recover from break"
become the same operation, so there is exactly one reconciliation routine to get
right (D7).

### 6.2 Path switch invariant (D9)

At any instant a direction has exactly one live path. `SWITCH` carries the offset
at which the new path takes over; the old path must be drained (`ACK`ed through
that offset) before the new path emits its first `DATA`. Because offsets are
absolute and monotonically increasing, a receiver that sees a `DATA.Seq` below
its expected offset applies the dedupe rule (§7.2) rather than treating it as an
error.

---

## 7. Reliability, resume and backpressure

### 7.1 Invariants

- **I1 — ACK means durable.** The server emits `ACK{up}` only after `Write` to the
  destination has returned. The client emits `ACK{down}` only after the payload
  has been written *and flushed* to stdout. Therefore `AckedThrough` is a
  promise that the bytes are already where they need to be.
- **I2 — Retransmit from the peer's ACK.** After a break, each side resends only
  bytes at offsets ≥ the peer's `AckedThrough`. Nothing else is ever resent.
- **I3 — Offset dedupe.** A receiver that gets `DATA` whose range overlaps
  already-consumed bytes discards the overlapping prefix and consumes the rest.
  Combined with I1+I2 this yields **exactly-once delivery into the consumer**,
  which is the property SSH depends on: a duplicated or dropped byte corrupts the
  SSH binary protocol and kills the session.
- **I4 — Gap is fatal.** A `DATA.Seq` beyond `expected` (after dedupe) means a
  protocol bug or a lost-path race ⇒ `ERR{ERR_PROTO}`, close session. We never
  silently paper over a gap.
- **I5 — One writer per sink.** Exactly one goroutine writes to stdout, one to
  the destination, per session. Network readers never block on sink writes.

### 7.2 Dedupe detail

```
expected = deliveredOffset            // bytes already handed to the sink
if seq + len(payload) <= expected { drop whole frame }        // pure duplicate
if seq < expected { payload = payload[expected-seq:]; seq = expected }
if seq > expected { ERR_PROTO }                                // I4
write(payload); deliveredOffset += len(payload); sendACK(deliveredOffset)
```

### 7.3 Buffers

Per session, per direction:

- `sendLog` — a growable byte ring holding bytes emitted but not yet
  cumulatively `ACK`ed. This is the retransmit source for resume. It grows
  lazily and is capped by `buffer_bytes`.
- Healthy link: outstanding unacked bytes are also capped by `send_window`
  (default 4 MiB), which is the real flow-control knob.
- Broken link: no `ACK`s arrive, so `send_window` cannot be respected; the ring
  keeps absorbing from the source until `buffer_bytes` (default 64 MiB), then the
  pump stops reading its source.

Because the ring only holds *unacked* data, the steady-state footprint of an
idle session is near zero; `buffer_bytes` is a ceiling, not a reservation.

**Backpressure chain (server, down direction):**

```
sshd → destination socket → destReader → downLog(≤buffer_bytes) → netWriter → transport
                                              ▲
                     full ⇒ stop reading ⇒ kernel TCP buffer fills ⇒ sshd blocks
```

The identical chain runs on the client for stdin: `buffer_bytes` full ⇒ stop
reading stdin ⇒ the `ProxyCommand` pipe fills ⇒ `ssh` blocks on `write()`. In
both cases the consumer experiences slowness, never an error — which is precisely
the "invisible break" requirement.

**Global budget.** `max_sessions × buffer_bytes` is unbounded memory in the worst
case (1024 × 64 MiB = 64 GiB). The server therefore also enforces
`total_buffer_bytes` (default 512 MiB) across all live sessions. When the global
budget is exhausted: new sessions are refused with `ERR_NO_CAPACITY`, and
existing sessions fall back to pure backpressure (they stop reading their source)
rather than being killed. Per-session `buffer_bytes` is reduced to the remaining
global headroom when they conflict.

### 7.4 Hold window

When a session's transport connection dies, the server starts a
`hold_timeout` timer (default 5m) and keeps:

- the destination socket open and being drained into `downLog` (bounded),
- `upLog`, offsets, half-close flags, `resumeToken`.

Outcomes:
- `RESUME` arrives with a valid token before expiry ⇒ timer cancelled, session
  continues, `heldMs` reported for observability.
- Token invalid / unknown session ⇒ `RESUME_FAIL{ERR_BAD_TOKEN|ERR_UNKNOWN_SESSION}`.
- Timer expires ⇒ `CLOSED`: destination closed, buffers freed, token zeroed,
  session-count metric decremented, one log line at `info`.
- Client that gave up (retries exhausted) ⇒ it exits non-zero; the server cleans
  up when the hold timer expires.

The client mirrors this with a bounded retry budget
(`reconnect_max_elapsed`, default 5m, matching the server hold) using jittered
exponential backoff, and exits with a message on **stderr** when exhausted.

### 7.5 Half-close and EOF

- Client stdin EOF ⇒ `CLOSE_DIR{up, finalOffset}` ⇒ server `CloseWrite()`s the
  destination after draining up to `finalOffset`.
- Destination EOF ⇒ server `CLOSE_DIR{down, finalOffset}` ⇒ client stops writing
  stdout after that offset. The client does **not** close stdout until the
  session ends, so a half-closed remote still returns data.
- Half-close flags are part of session state and are reported in `RESUME_OK`
  (`state.upClosed` / `state.downClosed`) so a resumed session never re-opens a
  closed direction.
- Both directions closed and drained ⇒ `BYE` ⇒ `CLOSED`.

---

## 8. Transports

`internal/transport.Conn` is the single abstraction the session layer uses:

```go
type Conn interface {
    ReadFrame() (Frame, error)   // blocking
    WriteFrame(Frame) error      // safe for one writer goroutine
    SetDeadline(time.Time) error
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Kind() Kind                  // KindTCP | KindQUIC | KindKCP
    Close() error
}
```

### 8.1 TCP
- `net.Dialer` with 10s timeout; `SetNoDelay(true)`; keepalive 15s.
- Reads/writes wrapped in `bufio` (128 KiB) to coalesce small frames.
- Also the permanent control channel for `HELLO`/`RESUME` and a valid data plane
  when UDP is unavailable or disabled.

### 8.2 QUIC (`quic-go`)
- Server: one `quic.Transport` bound to the shared UDP socket via `udpMux` (§8.4);
  `Listen` yields **one QUIC connection per session** (D5 + decision from the
  interview), each connection using two bidirectional streams (up, down).
- TLS: v1 has no auth (D2), so the server generates an **ephemeral self-signed
  certificate at boot** (or loads `quic_cert`/`quic_key` if configured) and the
  client sets `InsecureSkipVerify: true` with ALPN `"relay/1"`. This still gives
  a fully encrypted data plane; it provides no peer authentication.
- `quic.Config`: `MaxIdleTimeout = idle_timeout`, `KeepAlivePeriod =
  keepalive_interval`, `InitialStreamReceiveWindow`/`ConnectionReceiveWindow`
  ≥ `send_window`, `EnableDatagrams = false`.
- We do not depend on connection migration (non-goal); a peer address change
  surfaces as an idle timeout and goes through resume.

### 8.3 KCP (`kcp-go`)
- Server: one `Listener` on the shared UDP socket; **one KCP conversation per
  session**, demultiplexed by KCP's own `conv` field. Session identity is *not*
  carried in `conv` (kcp-go chooses it); it travels in the `RESUME`/`HELLO` frame
  that is always the first thing sent on a new conversation. This keeps us off
  any non-public API for forcing a `conv` value.
  > Implementation note: verify that the chosen kcp-go version accepts a custom
  > `net.PacketConn` front-end (`Listener.ServePacketConn` or equivalent) so it
  > can share the socket through `udpMux`. If it does not, fall back to D5′: a
  > second, separate lazily-opened UDP port for KCP (`udp_listen_kcp`). This is
  > the one place where the shared-endpoint decision may need to bend; it is
  > contained inside `internal/transport` and invisible to the session layer.
- Client: `DialWithOptions(remote, block=false, 0, 0)` — **FEC off** (QUIC/KCP
  already retransmit; FEC adds redundancy cost without helping a resumable
  byte stream) unless measurements say otherwise.
- Tuning: `SetNoDelay(1, 10, 2, 1)` (nodelay, 10ms tick, 2 fast-resend
  triggers, **stream mode on**), `SetMSS(1376)`, `SetWindowSize(256, 256)`,
  `SetACKNoDelay(true)`, `SetReadBuffer`/`SetWriteBuffer` ≥ 4 MiB.
- KCP provides no encryption and no authentication ⇒ with `--kcp` the data plane
  is cleartext on the wire. Accepted for v1 because the payload is an
  SSH-encrypted stream (§10.2); must be revisited before any non-SSH use.
- Liveness: KCP has no idle timeout, so the session layer drives `PING`/`PONG`
  every `keepalive_interval` and declares the path dead after `idle_timeout`
  without any inbound frame. This also keeps NAT mappings warm on the client.

### 8.4 `udpMux` — one socket, two stacks (D10)

A single UDP socket is owned by `udpMux`, which runs one read loop and routes
datagrams to the right stack. Every datagram on the wire is prefixed with a
1-byte stack tag added on egress and stripped on ingress:

```
0x01 = KCP payload   0x02 = QUIC payload
```

Each stack is handed a synthetic `net.PacketConn` (channel-backed) so neither
needs to know it is sharing. Cost: 1 byte/datagram plus the loss of quic-go's
GSO/read-batching fast paths. Benefit: deterministic demux, one firewall rule,
one socket that is opened lazily and then kept open for the process lifetime.

Rejected alternative: sniffing the first byte (`b[0]&0x80` ⇒ QUIC header form,
else KCP `conv`). It works in practice but is a heuristic that silently
misroutes on collision; the tag is cheap and we own both ends.

If `udpMux` proves to be a throughput problem in M2/M3 measurements, the fallback
is D5′ (one port per stack), which requires no session-layer change.

### 8.5 Transport selection precedence

`--tcp` flag > `--kcp` flag > client config `transport` > default `quic`. The
server may refuse a requested transport it does not have enabled and will then
select the next preference from `HELLO.transport`, or stay on TCP.

---

## 9. Concurrency model

Per session, on both client and server (5 goroutines + supervisor):

| Goroutine | Reads | Writes |
|---|---|---|
| `srcReader` | stdin (client) / destination (server) | `sendLog` ring |
| `netWriter` | `sendLog` ring | transport `DATA` frames |
| `netReader` | transport frames | dispatch: `sinkQ`, ACK advance, control |
| `sinkWriter` | `sinkQ` | stdout (client) / destination (server) |
| `timer` | — | `PING`, hold deadline, idle deadline |
| supervisor | — | state transitions, `RESUME`, teardown, `Close` fan-out |

Rules:
- `netReader` never writes to a sink directly (I5) and never blocks on one; it
  enqueues to a bounded `sinkQ`. If `sinkQ` is full it stops reading the
  transport, which is correct backpressure (QUIC/KCP/TCP all buffer for us).
- Exactly one goroutine owns `sendLog` appends, one owns its `AdvanceTo(ack)`;
  the ring is mutex-guarded with a `sync.Cond` for the writer's wait.
- Teardown is idempotent and fan-out via `context.Context`; every goroutine
  selects on `ctx.Done()`.
- Server-wide: an accept loop for TCP, one read loop for `udpMux`, one
  `quic.Transport` listener loop, one kcp `Listener` accept loop, and a session
  store (`map[sessionID]*Session` guarded by `RWMutex`, plus a
  `map[tokenHash]sessionID` index so tokens are never compared in linear scan).

---

## 10. Security posture (v1: no auth)

### 10.1 What is exposed
- The TCP handshake is cleartext: `HELLO`/`HELLO_OK`/`RESUME` (including
  `resumeToken`) are readable by an on-path observer.
- QUIC data plane: encrypted (TLS 1.3) but **unauthenticated** — vulnerable to
  an active MITM at handshake time.
- KCP data plane: cleartext.
- Anyone who can reach `listen_tcp` can open a session to any destination the
  server allows ⇒ with `allow_destinations` empty the server is an **open TCP
  proxy**. This is the single biggest v1 risk.

### 10.2 Why this is tolerable for the intended use
The relay carries an SSH transport stream. SSH already provides confidentiality,
integrity and peer authentication end-to-end between `ssh` and `sshd`. Therefore:
- A passive observer learns metadata only (endpoints, timing, volume) — on the
  KCP path also the ciphertext, which SSH's own crypto still protects.
- An active attacker who sniffs a `resumeToken` and hijacks a live session can
  inject or drop bytes, but cannot authenticate to `sshd`: injected bytes fail
  SSH's MAC and the SSH session dies. The realistic blast radius is
  **denial of service and metadata disclosure, not authentication bypass**.

### 10.3 Mandatory v1 mitigations (cheap, do them anyway)
1. `allow_destinations` defaults to `["127.0.0.1:22"]`, **not** empty. Running
   as an open proxy requires an explicit `allow_destinations = ["*"]`.
2. `resumeToken` is 32 random bytes from `crypto/rand`, stored **hashed**
   (SHA-256) in the session store, rotated on every resume, zeroed on close.
3. Frame length and JSON payload caps (§5.1) to bound allocation per connection.
4. Global budgets: `max_sessions`, `total_buffer_bytes`, `max_conns_per_ip`
   (default 8) to blunt trivial resource exhaustion.
5. Server logs never include `resumeToken` or payload bytes; only `sessionId`
   (which is not a credential).

### 10.4 Deferred: SSH-style public-key auth (M5)
`internal/auth.Authenticator` is defined in M0 with a single v1 implementation
(`noneAuthenticator`) so the handshake already carries the `auth` object:

```go
type Authenticator interface {
    Name() string                                  // "none" | "ssh-publickey"
    // Server side: verify the client's response to the challenge.
    Verify(challenge Challenge, auth json.RawMessage) (Identity, error)
    // Client side: produce the response.
    Respond(challenge Challenge) (json.RawMessage, error)
}
```

Planned `ssh-publickey` flow (mirrors SSH so operators reuse what they have):
1. Client sends `HELLO` with `auth: {method:"ssh-publickey", user:"alice",
   pubkey:"<authorized_keys line>", clientNonce}`.
2. Server derives `challenge = SHA256(sessionId ‖ clientNonce ‖ serverNonce ‖
   destination ‖ canonical(HELLO))` and sends it in `HELLO_OK` **before**
   allocating a session or dialing the destination.
3. Client signs the challenge with the private key matching `~/.ssh/id_*`
   (try ed25519, ecdsa, rsa in that order; support PEM and OpenSSH formats) and
   replies `AUTH{sig}`.
4. Server verifies against `authorized_keys` (path configurable, default
   `~/.ssh/authorized_keys` of the relay user), enforces key-type/size policy,
   then proceeds. Failure ⇒ `ERR{ERR_AUTH}` after a fixed delay (no oracle).
5. `RESUME` is bound to the authenticated identity: the session stores the
   verified key fingerprint and a resumed client must re-sign the resume
   challenge with the same key. `resumeToken` alone is then never sufficient.

Binding the challenge to `destination` prevents an authenticated client from
being redirected into opening a connection to a different host.

---

## 11. Configuration

Precedence: **CLI flag > config file > built-in default**. Config is TOML
(`--config path`); server default `/etc/relay/server.toml`, client default
`$HOME/.config/relay/client.toml`, both optional. Durations use Go syntax
(`"5m"`), sizes are integers in bytes.

### 11.1 Server

```toml
listen_tcp          = "0.0.0.0:7443"
udp_listen          = "0.0.0.0:7443"   # shared endpoint (D5); lazily opened
udp_announce        = ""               # public host:port; "" = derive from listen_tcp host
transports          = ["quic", "kcp"]  # enabled data planes; [] = TCP only
default_destination = "127.0.0.1:22"
allow_destinations  = ["127.0.0.1:22"] # ["*"] = open proxy (discouraged, see §10.3)

hold_timeout        = "5m"             # D4
buffer_bytes        = 67108864         # 64 MiB per session per direction
total_buffer_bytes  = 536870912        # 512 MiB global ceiling
send_window         = 4194304          # 4 MiB unacked when healthy
data_chunk_bytes    = 65536

max_sessions        = 1024
max_conns_per_ip    = 8
probe_timeout       = "2s"
probe_attempts      = 2
keepalive_interval  = "5s"
idle_timeout        = "30s"
switch_timeout      = "5s"
dial_timeout        = "10s"

quic_cert           = ""               # "" = ephemeral self-signed at boot
quic_key            = ""
log_level           = "info"           # debug|info|warn|error
log_format          = "text"           # text|json
pprof_listen        = ""               # "" = disabled
expvar_listen       = ""               # "" = disabled
```

### 11.2 Client

```toml
server               = "relay.example.com:7443"
destination          = ""              # "" = server default; %h:%p overrides
transport            = "quic"          # quic|kcp|tcp
buffer_bytes         = 67108864
send_window          = 4194304
probe_timeout        = "2s"
reconnect_backoff    = ["100ms","250ms","500ms","1s","2s","5s","10s"]
reconnect_max_elapsed = "5m"           # keep in sync with server hold_timeout
log_level            = "warn"          # quiet by default: stderr reaches the user's tty
log_format           = "text"
```

CLI: `relay client --server HOST:PORT [--dest HOST:PORT] [--kcp|--tcp]
[--config PATH] [--log-level LVL] [%h %p]`, `relay server [--config PATH]
[--listen ...] [--log-level LVL]`, `relay version`.

### 11.3 Logging discipline (critical)

The client's **stdout is the SSH transport**. Any diagnostic byte written there
corrupts the session. Therefore: all client logging goes to stderr; the relay
writer is the only code path that touches stdout; a unit test asserts no log
statement can reach stdout.

---

## 12. Usage

`~/.ssh/config` on the client machine:

```
Host via-relay
    HostName relay.example.com          # only used for %h substitution bookkeeping
    User alice
    ProxyCommand relay client --server relay.example.com:7443
```

The server dials its own `default_destination` (`127.0.0.1:22`), so `sshd` on
the relay host is reached. To relay to a *third* host instead, allow it
server-side and pass it through:

```
ProxyCommand relay client --server relay.example.com:7443 --dest %h:%p
```

Manual smoke test without SSH:

```
relay server --config server.toml --log-level debug
printf 'hello\n' | relay client --server 127.0.0.1:7443 --dest 127.0.0.1:7   # echo port
```

---

## 13. Testing strategy

**Unit**
- `proto`: frame codec round-trip; oversize frame rejection; every control
  struct marshals/unmarshals; unknown frame type ⇒ `ERR_PROTO`.
- `session/ringbuf`: append / `AdvanceTo` / `Slice(from)` / growth to cap /
  overflow signalling; absolute-offset arithmetic across wraparound.
- `session/dedupe`: table-driven over I3 cases (pure duplicate, partial overlap,
  exact continuation, gap ⇒ fatal, zero-length).
- `config`: defaults, TOML override, flag override, validation errors
  (`buffer_bytes > total_buffer_bytes`, bad duration, empty `transports`).

**Integration** (in-process, `127.0.0.1`, real sockets; a `net.TCPListener` echo
server stands in for `sshd`)
- End-to-end byte-exactness for 1 MiB / 64 MiB / 512 MiB payloads in both
  directions concurrently; assert SHA-256 match and offset monotonicity.
- A **verifiable payload pattern** (`offset || counter` records) so any duplicate,
  gap or reorder is detected positionally, not just by hash.
- Fault injection, each asserting *byte-exact, no-dup, no-gap*:
  - kill the TCP conn mid-stream (pre-upgrade);
  - kill the UDP path mid-stream ⇒ DEGRADED ⇒ resume on TCP;
  - kill the UDP path, re-probe ⇒ resume and re-upgrade;
  - change the client's source address between attempts (simulated NAT rebind);
  - `RESUME` with a stale token ⇒ `ERR_BAD_TOKEN`; after hold expiry ⇒
    `ERR_EXPIRED`; unknown session ⇒ `ERR_UNKNOWN_SESSION`.
- Backpressure: block the client's stdout reader, verify the server's
  `downLog` fills to `buffer_bytes`, that the destination stops being read, and
  that no data is lost when the reader unblocks.
- Global budget: exceed `total_buffer_bytes` across sessions, verify
  `ERR_NO_CAPACITY` for new sessions and survival (not death) of existing ones.
- Half-close: stdin EOF propagates to destination `CloseWrite`; destination EOF
  propagates to the client without truncating in-flight down data.
- Concurrency: 64 simultaneous sessions over one shared UDP endpoint, mixed
  QUIC/KCP, with random link kills for 60s; assert every surviving session is
  byte-exact and that goroutine count returns to baseline (leak check via
  `goleak`-style counting).

**Manual / field**
- `ssh -o ProxyCommand=... user@relayhost` against a real `sshd`; run
  `rsync`/`scp` of a large file through it.
- `tc qdisc add dev … netem delay 80ms 20ms loss 3%` and compare TCP vs QUIC vs
  KCP throughput and resume counts; record numbers in `README.md`.
- Wireshark/tcpdump capture confirming the 1-byte `udpMux` tag and that the TCP
  conn really closes after upgrade.

**CI**: `gofmt -l`, `go vet ./...`, `staticcheck`, `go test -race ./...`,
`go build` for linux/amd64 + linux/arm64 + darwin/arm64.

---

## 14. Milestones

| | Scope | Exit criterion |
|---|---|---|
| **M0** | Repo skeleton, config, `proto` codec, `transport.Conn` + TCP adapter, session store, TCP-only relay both directions, `relay client`/`relay server` CLI. | `ssh -o ProxyCommand="relay client …"` works against a local `sshd` over TCP; end-to-end byte-exactness test green under `-race`. |
| **M1** | Resume: `resumeToken`, offsets, dedupe (I1–I4), `sendLog` ring, hold timer, `buffer_bytes`/`total_buffer_bytes`, backpressure chains, half-close, client reconnect backoff. | All fault-injection tests pass: killing the TCP conn mid-`rsync` does not break the SSH session. |
| **M2** | `udpMux`, QUIC adapter, `PROBE`/`PROBE_OK`, `SWITCH`, upgrade + re-upgrade, keepalive/idle deadlines, ephemeral self-signed cert. | Default path is QUIC; killing UDP mid-stream resumes transparently; probe failure falls back to TCP permanently for that session. |
| **M3** | KCP adapter on the shared socket, `--kcp`, KCP tuning, per-session conversation demux. | Same fault suite passes with `--kcp`; netem comparison numbers recorded. |
| **M4** | Hardening: `max_sessions`, `max_conns_per_ip`, graceful shutdown (`SIGTERM` ⇒ `BYE` ⇒ drain), structured logs, expvar/pprof, README. | 64-session concurrency/leak test green; server restart is clean. |
| **M5** | `auth.Authenticator` + `ssh-publickey`: challenge/response, `~/.ssh/id_*` signing, `authorized_keys` verification, resume bound to key fingerprint. | A client without a valid key gets `ERR_AUTH` before any destination dial; an authorized client's resumed session must re-sign. |

---

## 15. Risks and open questions

| | Risk | Mitigation / owner |
|---|---|---|
| R1 | kcp-go may not support a custom `net.PacketConn` front-end, blocking the single shared socket (D5). | Contained in `internal/transport`; fall back to D5′ (separate lazily-opened KCP port). Decide in M3, no session-layer impact. |
| R2 | `udpMux` costs quic-go's GSO/read-batching fast paths ⇒ lower QUIC throughput. | Measure in M2 against a direct-socket build; if the loss exceeds ~20%, take D5′. |
| R3 | 64 MiB × many sessions is a large memory ceiling. | `total_buffer_bytes` global budget + lazy ring growth + refuse-new rather than kill-existing (§7.3). |
| R4 | v1 open TCP proxy if `allow_destinations` is widened. | Default is `["127.0.0.1:22"]`; `["*"]` must be explicit and logs a warning at startup (§10.3). |
| R5 | Token sniffing on the cleartext TCP handshake allows session hijack ⇒ DoS. | Accepted for v1 (§10.2); eliminated in M5 by binding resume to a key fingerprint. Interim option: run the TCP handshake over TLS with the same ephemeral cert. |
| R6 | `SWITCH` quiescing could stall if a path is silently black-holed. | `switch_timeout` (5s): on expiry abort the switch, keep the old path, and let the idle timer trigger the normal resume path. |
| R7 | A resumed SSH session that was held for minutes may still die because `sshd`'s own `ClientAliveInterval` fired while its socket was unread. | Real, and outside our control. `hold_timeout` should be set below the deployment's `sshd` alive-interval budget; document this in `README.md` and surface `heldMs` in logs so operators can tune. |
| R8 | Offset bookkeeping bugs are silent stream corruption — the worst failure mode for SSH. | I1–I5 as explicit invariants, the positional payload pattern in tests (§13), `-race` on all tests, and `ERR_PROTO` on any gap rather than best-effort recovery. |

Open questions to settle during implementation (not blocking M0/M1):
1. Should `--keep-tcp` retain the TCP conn as a control plane after upgrade
   (rejected as D7, but it would make `SWITCH`-free instant fallback possible)?
2. Is FEC ever worth enabling on KCP for this workload, or is it pure overhead?
3. Do we want an optional `tls` wrapper for the TCP handshake in v1 as a cheap
   R5 mitigation, or wait for M5?
