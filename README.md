# remote-relay

A resumable stdio↔port relay in Go, typically used as an SSH `ProxyCommand`.
The client forwards its stdin/stdout to a server that dials a destination TCP
socket (default `127.0.0.1:22`, the local `sshd`). Handshake is always TCP;
the data plane upgrades to UDP (QUIC by default, KCP with `--kcp`) when a
probe succeeds. If the WAN link breaks, the client reconnects and **resumes
the same session** so the consumer (`ssh`) does not see a disconnect.

v1 has no authentication. The payload is expected to be an already-encrypted
SSH stream. See **Security** below.

## Status

| Milestone | In this tree |
|---|---|
| M0 TCP relay | yes |
| M1 resume / hold / retransmit | yes |
| M2 QUIC upgrade | yes |
| M3 KCP | yes |
| M4 session limits, graceful shutdown, observability | yes |
| M5 SSH public-key auth | no |

Netem (delay/loss) comparison numbers for TCP vs QUIC vs KCP are **not
recorded in this environment**.

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
./relay server [--config /etc/relay/server.toml] [--listen 0.0.0.0:7443] [--log-level info]
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
```

## Client

Logs go to **stderr**. stdout is the relayed byte stream and must stay clean
(it is the SSH transport).

```
./relay client --server HOST:PORT [--dest HOST:PORT] [--tcp|--kcp] [--config PATH] [--log-level warn] [%h %p]
```

Default client config path: `$HOME/.config/relay/client.toml` (optional).

Transport selection: `--tcp` > `--kcp` > config `transport` > default `quic`.
`--kcp` selects the KCP data plane (cleartext; the SSH payload is still
encrypted). `--tcp` disables UDP upgrade and stays on TCP for the whole
session.

### Example `client.toml`

```toml
server                = "relay.example.com:7443"
destination           = ""              # empty = server default; %h:%p overrides
transport             = "quic"          # quic|kcp|tcp
buffer_bytes          = 67108864
send_window           = 4194304
probe_timeout         = "2s"
reconnect_backoff     = ["100ms","250ms","500ms","1s","2s","5s","10s"]
reconnect_max_elapsed = "5m"            # keep in sync with server hold_timeout
log_level             = "warn"
log_format            = "text"
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

## Resume, hold, and UDP upgrade

1. HELLO is always over TCP. The server may advertise a UDP address.
2. The client probes UDP. On success it `SWITCH`es the data plane to QUIC
   (default) or KCP (`--kcp`) and **closes the TCP connection**.
3. On probe failure the session stays on TCP for its lifetime.
4. Any later break (TCP or UDP) is repaired the same way: re-dial TCP, send
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

## Security (v1)

- TCP handshake is cleartext (HELLO / RESUME, including `resumeToken`).
- QUIC data plane is TLS 1.3 but unauthenticated (ephemeral self-signed cert
  by default).
- KCP data plane is cleartext.
- Anyone who can reach `listen_tcp` can open a session to any destination
  the server allows.

This is tolerable when the payload is SSH: SSH already authenticates and
encrypts end-to-end. The realistic blast radius is denial of service and
metadata disclosure, not authentication bypass. M5 adds SSH public-key auth
on the relay handshake.

## License

See the repository. Not a network-performance paper; field `tc netem`
numbers were not collected here.
