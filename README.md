# remote-relay

A resumable stdio↔port relay in Go, typically used as an SSH `ProxyCommand`.
The client forwards its stdin/stdout to a server that dials a destination TCP
socket (default `127.0.0.1:22`, the local `sshd`). Handshake is always TCP;
the data plane upgrades to UDP (QUIC by default, KCP with `--kcp`) when a
probe succeeds. If the WAN link breaks, the client reconnects and **resumes
the same session** so the consumer (`ssh`) does not see a disconnect.

Handshake authentication is **off by default** (`auth_method = "none"`). Set
`auth_method = "ssh-publickey"` to require a signed challenge before the
server dials. The payload is still typically an already-encrypted SSH stream.
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
./relay server [--config /etc/relay/server.toml] [--listen 0.0.0.0:7443] [--heartbeat-interval 750ms] [--dead-peer-threshold 3] [--log-level info]
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

hold_timeout        = "5m"
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

auth_method         = "none"           # none | ssh-publickey
authorized_keys     = ""               # empty = ~/.ssh/authorized_keys of the relay user
auth_fail_delay     = "200ms"          # fixed delay on ERR_AUTH (no oracle)
```

## Client

Logs go to **stderr**. stdout is the relayed byte stream and must stay clean
(it is the SSH transport).

```
./relay client --server HOST:PORT [--dest HOST:PORT] [--tcp|--kcp] [--allow-ha] [--heartbeat-interval 750ms] [--dead-peer-threshold 3] [--config PATH] [--log-level warn] [%h %p]
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
auth_method           = "none"          # none | ssh-publickey
auth_user             = ""              # empty = current user
identity_files        = []              # empty = try ~/.ssh/id_ed25519, id_ecdsa, id_rsa
```

### SSH ProxyCommand

```
Host via-relay
    HostName relay.example.com
    User alice
    ProxyCommand relay client --server relay.example.com:7443
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

`auth_method` defaults to `"none"` so existing deployments stay open. Auth is
TOML-only (no CLI flag).

To require SSH public-key auth on the relay handshake:

**Server** (`server.toml`):

```toml
auth_method     = "ssh-publickey"
authorized_keys = "/var/lib/relay/authorized_keys"  # OpenSSH authorized_keys file
auth_fail_delay = "200ms"
```

The server verifies the offered key against `authorized_keys` (ed25519, ecdsa
P-256/384/521, RSA ≥ 2048 with `rsa-sha2-256`/`rsa-sha2-512`). It sends a
challenge **before** allocating a session or dialing the destination. Failure
is `ERR_AUTH` after `auth_fail_delay` (same delay for unknown key and bad
signature). `RESUME` must re-sign with the same key; `resumeToken` alone is
not enough.

**Client** (`client.toml`):

```toml
auth_method    = "ssh-publickey"
auth_user      = "alice"
identity_files = ["/home/alice/.ssh/id_ed25519"]
```

If `identity_files` is empty the client tries `~/.ssh/id_ed25519`, `id_ecdsa`,
`id_rsa` (PEM and OpenSSH formats). Both sides must set `ssh-publickey`; a
`none` client against an authenticating server gets `ERR_AUTH`.

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

### `hold_timeout` vs `sshd` `ClientAliveInterval` (R7)

A resumed SSH session that was held for minutes may still die because
`sshd`'s own `ClientAliveInterval` / `ClientAliveCountMax` fired while its
socket was unread. That is outside the relay's control. Set `hold_timeout`
**below** the deployment's `sshd` alive-interval budget. Resume logs include
`heldMs` so you can see how long a session sat in hold.

## Limits

| Knob | Default | Effect |
|---|---|---|
| `max_sessions` | 1024 | Extra HELLO is refused with `ERR_NO_CAPACITY`. |
| `max_conns_per_ip` | 8 | Extra HELLO from the same client IP is refused with `ERR_NO_CAPACITY`. RESUME of an existing session is still allowed. |
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
  `buffer_used`, `accepts`, `refused` (plus the usual process expvars)

If both are set to the same address, one HTTP server serves both.

## Security

- TCP handshake is cleartext (HELLO / RESUME, including `resumeToken`).
- QUIC data plane is TLS 1.3 but unauthenticated (ephemeral self-signed cert
  by default).
- KCP data plane is cleartext.
- With the default `auth_method = "none"`, anyone who can reach `listen_tcp`
  can open a session to any destination the server allows.

With `auth_method = "ssh-publickey"`, the server does not dial until a
signature over a dest-bound challenge verifies against `authorized_keys`, and
RESUME is bound to that key fingerprint.

This is tolerable when the payload is SSH: SSH already authenticates and
encrypts end-to-end. The realistic blast radius without relay auth is denial
of service and metadata disclosure, not authentication bypass of `sshd`.

## License
 
See the repository. Emulated WAN network benchmarks (`tc netem`) are
recorded under **Status** above.
