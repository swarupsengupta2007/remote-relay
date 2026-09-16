# remote-relay

A resumable stdio↔port relay in Go, typically used as an SSH `ProxyCommand`.
The client forwards its stdin/stdout to a server that dials a destination TCP
socket (default `127.0.0.1:22`, the local `sshd`). Handshake is always TCP;
the data plane upgrades to UDP (QUIC by default, KCP with `--kcp`) when a
probe succeeds. If the WAN link breaks, the client reconnects and **resumes
the same session** so the consumer (`ssh`) does not see a disconnect.

Handshake authentication is **mandatory** (`auth_method = "ssh-publickey"`).
The legacy unauthenticated mode (`"none"`) is completely deprecated and removed.
Both `--authorized-keys` (server) and `--identity` / `-i` (client) flags are
available alongside TOML config and standard `~/.ssh` fallback paths (`flag > TOML > ~/.ssh`).
The payload is typically an already-encrypted SSH stream.
See **Authentication** and **Security** below.

## Status

| Milestone / Feature | In this tree |
|---|---|
| M0 TCP relay | yes |
| M1 resume / hold / retransmit | yes |
| M2 QUIC upgrade | yes |
| M3 KCP | yes |
| M4 session limits, graceful shutdown, observability | yes |
| M5 SSH public-key auth | yes |
| FEAT-ROB-01 BFD Sub-Second Detection & Dual-Path HA | yes |
| FEAT-SEC-01 Encrypted Handshake (X25519 & ChaCha20-Poly1305) | yes |
| FEAT-PERF-03 Fast 3-RTT Token-Authorized Resumption | yes |
| FEAT-ROB-03 Dual-Stack Happy Eyeballs v2 (RFC 8305) | yes |
| FEAT-PERF-01 Linux Kernel Zero-Copy Stream Splicing (`splice(2)`) | yes |
| FEAT-PERF-02 Adaptive KCP Dynamic ARQ & Congestion Tuning | yes |
| FEAT-UTL-05 Multi-Hop Jumphost Chaining (`-J`) | yes (Phase 1: TCP hops; inner stale-token re-auth deferred) |
| Single-Session KCP Repeated-Kills Soak & Netns Harness | yes |

### Netem & BFD Benchmarks (dual-netns veth)

| Scenario | TCP (`--tcp`) | QUIC (default) | KCP (`--kcp`) |
|---|---|---|---|
| **High Latency & Loss** (16 MiB, 80ms RTT, 3% loss) | 257.0s (0.06 MB/s) | 356.3s (0.04 MB/s) | **7.98s (2.00 MB/s)** *(33x–50x faster)* |
| **Reorder & Duplicate** (16 MiB, 80ms RTT, 25% reorder, 1% dup) | 319.2s (0.05 MB/s) | 471.2s (0.03 MB/s) | **5.47s (2.93 MB/s)** *(byte-exact)* |
| **Silent Blackhole Detection** (iptables DROP, default config) | 30.0s (`idle_timeout`) | 30.0s (`idle_timeout`) | **2.26s** (RFC 5880 BFD, ceiling 2.25s) |
| **Hot-Standby Promotion** (`--allow-ha` QUIC → TCP Failover) | N/A | N/A | **2.71s** (0 lost bytes, zero-dial promotion) |

The default CI 64-session soak mixes TCP+QUIC on the shared UDP mux (~10s,
random link kills). Mixed KCP at that kill rate expired instead of resuming
(likely liveness/scale with KCP's delayed Close and idle timers, not a mux
`conv` identity bug). A smaller 8+8 KCP/QUIC test uses the M3 idle/keepalive
settings. A 60s mixed soak is not run in default CI.

## Build

Go 1.23 or later.

```
go build -o relay ./cmd/relay
./relay version
```

## Server

```
./relay server [--config /etc/relay/server.toml] [--listen 0.0.0.0:7443] [--authorized-keys /path/to/authorized_keys] [--host-key /etc/relay/ssh_host_ed25519_key] [--heartbeat-interval 750ms] [--dead-peer-threshold 3] [--log-level info]
```

If `--config` is omitted the server loads `/etc/relay/server.toml` when that
file exists, otherwise built-in defaults. CLI flags override the file.

`allow_destinations` defaults to `["127.0.0.1:22"]`. Set `["*"]` only if you
intend to run an open TCP proxy; the server logs a warning at startup in that
case.

The shared UDP endpoint (`udp_listen`, default `0.0.0.0:7443`) is opened
lazily on first upgrade and kept for the process lifetime (one firewall rule,
QUIC and KCP demuxed on the same socket).

### Example `server.toml`

```toml
listen_tcp          = "0.0.0.0:7443"
udp_listen          = "0.0.0.0:7443"
udp_announce        = ""               # public host:port; empty = derive
transports          = ["quic", "kcp"]
default_destination = "127.0.0.1:22"
allow_destinations  = ["127.0.0.1:22"] # ["*"] = open proxy (discouraged)

hold_timeout        = "5m"             # keep below sshd ClientAliveInterval * ClientAliveCountMax (R7)
buffer_bytes        = 67108864         # 64 MiB per session per direction
total_buffer_bytes  = 536870912        # 512 MiB global ceiling
send_window         = 4194304
data_chunk_bytes    = 65536

max_sessions        = 1024
max_conns_per_ip    = 8
probe_timeout       = "2s"
probe_attempts      = 2
heartbeat_interval  = "750ms"          # RFC 5880 BFD ping interval
dead_peer_threshold = 3                # missed pings before teardown (3 * 750ms = 2.25s)
keepalive_interval  = "5s"
idle_timeout        = "30s"
switch_timeout      = "5s"
dial_timeout        = "10s"

quic_cert           = ""               # empty = ephemeral self-signed
quic_key            = ""
log_level           = "info"           # debug|info|warn|error
log_format          = "text"           # text|json
pprof_listen        = ""               # empty = disabled
expvar_listen       = ""               # empty = disabled

auth_method         = "ssh-publickey"  # mandatory (none deprecated & removed)
authorized_keys     = ""               # empty = ~/.ssh/authorized_keys of the relay user
auth_fail_delay     = "200ms"          # fixed delay on ERR_AUTH (no oracle)

# FEAT-UTL-05 jumphost chaining. Empty allow_relay_hops refuses every CHAIN.
allow_relay_hops         = []           # literal host:port as clients write them; ["*"] needs max_chain_depth = 1
max_chain_depth          = 4
max_chain_conns_per_peer = 256          # per upstream relay address
chain_auth_timeout       = "10s"
chain_max_sessions       = 0            # 0 ⇒ max_sessions / 4
relay_known_hosts        = ""           # optional; originator still verifies every hop
relay_strict_host_key_checking = "yes"
```

## Client

Logs go to **stderr**. stdout is the relayed byte stream and must stay clean
(it is the SSH transport).

```
./relay client --server HOST:PORT [-J|--jumphost|--chain HOST:PORT] [-i|--identity PATH] [--auth-sock PATH] [--dest HOST:PORT] [--tcp|--kcp] [--allow-ha] [--server-fingerprint FP] [--known-hosts PATH] [--strict-host-key-checking yes|no|ask|accept-new] [--heartbeat-interval 750ms] [--dead-peer-threshold 3] [--config PATH] [--log-level warn] [%h %p]
```

Default client config path: `$HOME/.config/relay/client.toml` (optional).

Transport selection: `--tcp` > `--kcp` > config `transport` > default `quic`.
`--kcp` selects the KCP data plane (cleartext; the SSH payload is still
encrypted). `--tcp` disables UDP upgrade and stays on TCP for the whole
session.

`--allow-ha` enables dual-path High Availability with zero-latency hot-standby failover.
When operating over UDP (QUIC or KCP), a hot-standby TCP connection is attached and
exchanges RFC 5880 BFD heartbeats in parallel. If the active UDP path fails or blackholes
(detected within `dead_peer_threshold * heartbeat_interval`, e.g. 2.25s), the standby
TCP link is instantly promoted to active without handshake round-trips. Background
supervisors automatically recover dropped standby links and seamlessly migrate back
to UDP when it recovers. Without `--allow-ha`, requesting UDP strictly mandates UDP
reachability and terminates immediately if blocked.

### Example `client.toml`

```toml
server                = "relay.example.com:7443"
destination           = ""              # empty = server default; %h:%p overrides
transport             = "quic"          # quic|kcp|tcp
buffer_bytes          = 67108864
send_window           = 4194304
probe_timeout         = "2s"
heartbeat_interval    = "750ms"         # RFC 5880 BFD ping interval
dead_peer_threshold   = 3               # missed pings before teardown (3 * 750ms = 2.25s)
reconnect_backoff     = ["100ms","250ms","500ms","1s","2s","5s","10s"]
reconnect_max_elapsed = "5m"            # keep in sync with server hold_timeout
allow_ha              = false           # true = dual-path HA (UDP primary, TCP fallback)
ha_probe_interval     = "10s"           # interval for background UDP probing when on TCP
log_level             = "warn"
log_format            = "text"
auth_method           = "ssh-publickey" # mandatory (none deprecated & removed)
auth_user             = ""              # empty = current user
identity_files        = []              # empty = try ~/.ssh/id_ed25519, id_ecdsa, id_rsa
jumphost              = []              # same value as -J; --server is still the terminal
sshd_alive_budget     = "2m"            # warn when Σ hold_timeout across hops exceeds this
```

### SSH ProxyCommand

```
Host via-relay
    HostName relay.example.com
    User alice
    ProxyCommand relay client --server relay.example.com:7443 -i ~/.ssh/id_ed25519
```

To reach a terminal relay through one or more intermediates, pass `-J` the
same way OpenSSH does. `--server` is always the **terminal** (the process that
dials `sshd`); `-J` names the hops before it:

```
Host via-jumps
    HostName 127.0.0.1
    User alice
    ProxyCommand relay client --server S.example.com:7443 -J j1.example.com:7443,j2.example.com:7443 --dest %h:%p -i ~/.ssh/id_ed25519
```

Each hop is a full independent relay session (its own KEX, resume token, ring,
BFD). The originator verifies every hop's host key; the private key never
leaves the client. Intermediates must list permitted next hops in
`allow_relay_hops` (empty = chaining refused). Per-hop `?transport=kcp|quic|tcp`
and `?ha=1` are honoured on the originator’s hop 1 and advertised to later hops.
Nested `splice(2)` is not used; an intermediate ACKs when bytes are in its nested
ring, not when the next hop has them.

A hop can be pinned inline to skip `known_hosts`:

```
-J 'j1.example.com:7443#SHA256:AbCd…'
```

The server dials its own `default_destination` (`127.0.0.1:22`), so `sshd` on
the relay host is reached.

Force TCP or KCP:

```
ProxyCommand relay client --server relay.example.com:7443 --tcp
ProxyCommand relay client --server relay.example.com:7443 --kcp
```

To pass the SSH target through as the destination (the server must allow it):

```
ProxyCommand relay client --server relay.example.com:7443 --dest %h:%p
```

Manual smoke test without SSH (needs an echo/discard listener on the dest):

```
relay server --config server.toml --log-level debug
printf 'hello\n' | relay client --server 127.0.0.1:7443 --dest 127.0.0.1:7
```

## Authentication

Handshake authentication is **mandatory** (`auth_method = "ssh-publickey"`).
The legacy unauthenticated mode (`"none"`) is completely deprecated and removed.

Configuration follows strict precedence: **CLI flag > TOML config > `~/.ssh` default**.

**Server**:
* Flag: `--authorized-keys /path/to/authorized_keys`
* Config (`server.toml`):
  ```toml
  auth_method     = "ssh-publickey"
  authorized_keys = "/var/lib/relay/authorized_keys"
  auth_fail_delay = "200ms"
  ```
* **Server Fail-Fast**: If neither `--authorized-keys` nor TOML `authorized_keys` is
  configured, the server checks `~/.ssh/authorized_keys`. If that default file is missing
  or has no valid public keys, the server **fails fast** at startup (exit code 1). If either
  flag or TOML is supplied, that path is used directly.
* Keys supported: Ed25519, ECDSA (P-256/384/521), RSA ≥ 2048 with SHA-2 (`rsa-sha2-256` / `rsa-sha2-512`).
* Challenge is signed and verified **before** allocating a session or dialing the destination. Failure triggers fixed `auth_fail_delay` (200ms default) with no timing oracle.

**Client**:
* Flag: `-i` / `--identity /path/to/private_key`, `--auth-sock /path/to/agent.sock`
* Config (`client.toml`):
  ```toml
  auth_method    = "ssh-publickey"
  auth_user      = "alice"
  auth_sock      = ""                               # empty = use $SSH_AUTH_SOCK
  identity_files = ["/home/alice/.ssh/id_ed25519"]
  ```
* **OpenSSH Agent (FEAT-UTL-01)**: Connects to local `ssh-agent` via `$SSH_AUTH_SOCK` (or `--auth-sock`). Enables passphrase-protected keys, hardware tokens (YubiKey / FIDO2 `sk-ssh-ed25519@openssh.com`), and keys loaded into `ssh-agent` without storing unencrypted keys on disk.
* **Fallback Chain**: Active `ssh-agent` keys $\to$ unencrypted `identity_files` $\to$ default `~/.ssh/id_*` on disk.
* **Fast Resumption (FEAT-PERF-03)**: Resumption inside the forward-secret tunnel is verified via 3-RTT token-authorized fast path, with transparent fallback to cryptographic challenge re-signing if the token is stale or expired. Hardware tokens only require physical touch once during initial connection.

## Resume, hold, and BFD failover

1. HELLO is always over TCP. The server may advertise a UDP address.
2. The client probes UDP. On success it `SWITCH`es the data plane to QUIC
   (default) or KCP (`--kcp`). Without `--allow-ha`, the initial TCP connection is closed.
   With `--allow-ha`, the TCP connection attaches as a hot-standby carrier.
3. Both active and standby links exchange continuous RFC 5880 BFD heartbeats (`proto.TypePing`, 0x15).
   If the remote peer stops responding within `dead_peer_threshold * heartbeat_interval`
   (default $3 \times 750\text{ms} = 2.25\text{s}$), the pump triggers `ErrDeadPeer` and initiates teardown or failover.
4. Under `--allow-ha`, an active UDP failure immediately promotes the hot-standby TCP carrier with zero
   round-trip dial delay. In-flight data is deduplicated seamlessly via `session.Dedupe`.
5. Any link break without a standby carrier is repaired via TCP reconnect: re-dial TCP, send
   `RESUME` with the session token and byte offsets. In-flight data is
   retransmitted from the server's ring; the destination socket stays open.

`hold_timeout` (default 5m) is how long the server keeps the destination
socket and buffers after a link break. The client retry budget
(`reconnect_max_elapsed`, default 5m) should match it.

**Hold is in-process.** A server process exit (including a restart) drops
every session: dest sockets are closed, tokens are gone, and a client that
reconnects gets `ERR_UNKNOWN_SESSION`. Clients will try to resume if the
process comes back within `hold_timeout`, but they cannot; start a new SSH
session. "Clean restart" means no leaked goroutines or sockets, not that
sessions survive process death.

On a **chained** session this is sharper (JR3): an intermediate ACKs hop-1 bytes
once they are in its nested ring, not once the next hop (or `sshd`) has them.
If that intermediate process exits, ACKed bytes are lost and the client sees
`ERR_UNKNOWN_SESSION`. Same operational rule as a direct hop — restart `ssh` —
plus the extra exposure that the crash is of a hop the originator is not
directly talking to.

### `hold_timeout` vs `sshd` `ClientAliveInterval` (R7)

A resumed SSH session that was held for minutes may still die because
`sshd`'s own `ClientAliveInterval` / `ClientAliveCountMax` fired while its
socket was unread. That is outside the relay's control. Set `hold_timeout`
**below** the deployment's `sshd` alive-interval budget. Resume logs include
`heldMs` so you can see how long a session sat in hold.

Across a chain the worst-case park is the **sum** of each hop's `hold_timeout`.
A 3-hop path with 5 m holds can stall 15 m, which will exceed most `sshd`
alive budgets (JR8). The client logs a warning when that sum exceeds
`sshd_alive_budget` (default 2 m).

## Limits

| Knob | Default | Effect |
|---|---|---|
| `max_sessions` | 1024 | Extra HELLO is refused with `ERR_NO_CAPACITY`. |
| `max_conns_per_ip` | 8 | Extra HELLO from the same client IP is refused with `ERR_NO_CAPACITY`. RESUME of an existing session is still allowed. Chained sessions count the originator (`OriginIP`), not the upstream relay. |
| `max_chain_conns_per_peer` | 256 | Cap on chained sessions from one upstream relay address. |
| `chain_max_sessions` | `max_sessions/4` | Extra CHAIN is refused with `ERR_NO_CAPACITY`. A chained session holds two rings on the intermediate. |
| `total_buffer_bytes` | 512 MiB | Global ring occupancy. New sessions are refused with `ERR_NO_CAPACITY`; existing sessions backpressure instead of being killed. |
| `buffer_bytes` | 64 MiB | Per-session per-direction cap, clipped to remaining global headroom. |

## Graceful shutdown

`SIGINT` / `SIGTERM` (or `Server.Shutdown`): stop accepting, send
`BYE{ERR_SHUTDOWN}` to live sessions, drain, close destination sockets,
release buffers, exit 0. Drain is bounded (a few seconds) so the process
cannot hang forever.

## Observability

Structured `slog` on stderr. `log_format = "json"` or `"text"`. Logs carry
`sessionId` and fields such as `heldMs`, `dest`, `transport`. They never
include `resumeToken` or payload bytes.

`pprof_listen` and `expvar_listen` are disabled when empty.

- pprof: `http://<pprof_listen>/debug/pprof/`
- expvar: `http://<expvar_listen>/debug/vars` — `sessions`, `held`,
  `buffer_used`, `accepts`, `refused`, `chain_sessions`, `chain_hops_total`,
  `chain_auth_relays`, `chain_refused`, `chain_attest_failures` (plus the usual
  process expvars)

If both are set to the same address, one HTTP server serves both.

## Security

- **Strict Control-Plane Encryption (FEAT-SEC-01)**: Control plane is strictly encrypted
  via Ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 with monotonically increasing
  64-bit sequence nonces. Unencrypted handshakes are rejected unconditionally (`ERR_PROTO`).
- **Host Key Verification & Pinning**: Server identity is authenticated via Ed25519 host key
  signatures over the key exchange transcript hash. Verified against OpenSSH `known_hosts`
  (`--known-hosts`, `--strict-host-key-checking`) or pinned SHA-256 fingerprint (`--server-fingerprint`).
  Verification fails closed if known_hosts cannot be resolved unless `--strict-host-key-checking=no`.
- **Protected Resumption & Fast-Path (FEAT-PERF-03)**: Session tokens (`resumeToken`) are never
  exposed on the wire in cleartext; they are exchanged solely inside the forward-secret AEAD tunnel.
  Fast 3-RTT resumption authenticates via token alone; expired/stale tokens fall back transparently
  to full public-key challenge re-signing.
- **Mandatory Client Authentication**: Handshake authentication is mandatory (`ssh-publickey`).
  The server will not dial the destination socket until a valid signature over the destination-bound
  challenge is verified against `authorized_keys`.
- **Option A Clean Phase Cut**: Following successful handshake (`HELLO_OK` / `RESUME_OK`), the
  session transitions cleanly to raw framing for `TypeData` payload frames, eliminating double-encryption
  overhead with inner SSH streams.
- The relayed payload is typically already an end-to-end authenticated and encrypted SSH connection.

## License
 
See the repository. Emulated WAN network benchmarks (`tc netem`) are
recorded under **Status** above.
