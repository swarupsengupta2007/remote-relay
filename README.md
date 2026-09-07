# remote-relay

A stdio↔port relay intended for use as an SSH `ProxyCommand`. The client
forwards its stdin/stdout to a server that dials a destination TCP socket
(default `127.0.0.1:22`). Handshake is always TCP; the data plane upgrades to
UDP (QUIC by default, KCP with `--kcp`) when a probe succeeds. A broken link
is resumed transparently so the consumer does not see a disconnect.

## Build

```
go build -o relay ./cmd/relay
```

## Server

```
./relay server [--config /etc/relay/server.toml] [--listen 0.0.0.0:7443] [--log-level info]
```

`allow_destinations` defaults to `["127.0.0.1:22"]`. Set `["*"]` only if you
intend to run an open proxy (the server logs a warning in that case).

The shared UDP endpoint (`udp_listen`, default `0.0.0.0:7443`) is opened lazily
on first upgrade and kept for the process lifetime.

## Client

Logs go to **stderr**. stdout is the relayed byte stream and must stay clean.

```
./relay client --server HOST:PORT [--dest HOST:PORT] [--tcp|--kcp] [--config PATH] [--log-level warn] [%h %p]
```

Transport selection: `--tcp` > `--kcp` > config `transport` > default `quic`.
`--kcp` selects the KCP data plane (cleartext; the SSH payload is still
encrypted). `--tcp` disables UDP upgrade.

### SSH ProxyCommand

```
Host via-relay
    HostName relay.example.com
    User alice
    ProxyCommand relay client --server relay.example.com:7443
```

Force TCP or KCP:

```
ProxyCommand relay client --server relay.example.com:7443 --tcp
ProxyCommand relay client --server relay.example.com:7443 --kcp
```

To pass the SSH target through as the destination (server must allow it):

```
ProxyCommand relay client --server relay.example.com:7443 --dest %h:%p
```

## Status

| Milestone | In this tree |
|---|---|
| M0 TCP relay | yes |
| M1 resume / hold / retransmit | yes |
| M2 QUIC upgrade | yes |
| M3 KCP | yes |
| M5 SSH public-key auth | no |
