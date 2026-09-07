# remote-relay

A stdio↔port relay intended for use as an SSH `ProxyCommand`. The client
forwards its stdin/stdout to a server that dials a destination TCP socket
(default `127.0.0.1:22`).

This tree is **milestone M0**: TCP handshake and a bidirectional byte relay.
Session resume after a link break and UDP (QUIC/KCP) upgrade are not included.

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

## Client

Logs go to **stderr**. stdout is the relayed byte stream and must stay clean.

```
./relay client --server HOST:PORT [--dest HOST:PORT] [--tcp] [--config PATH] [--log-level warn] [%h %p]
```

`--kcp` is rejected in M0 (`not implemented yet`). A `transport = "quic"` config
value is accepted but the process stays on TCP and logs a warning.

### SSH ProxyCommand

```
Host via-relay
    HostName relay.example.com
    User alice
    ProxyCommand relay client --server relay.example.com:7443 --tcp
```

To pass the SSH target through as the destination (server must allow it):

```
ProxyCommand relay client --server relay.example.com:7443 --tcp --dest %h:%p
```

## Status

| Milestone | In this tree |
|---|---|
| M0 TCP relay | yes |
| M1 resume / hold / retransmit | no |
| M2 QUIC upgrade | no |
| M3 KCP | no |
| M5 SSH public-key auth | no |
