# remote-relay — work in progress

Hand-off log. Each agent writes **only its own work** under its heading.
Do not rewrite another agent's section. Do not replace this file with a
snapshot of the tree; later agents append below.

Last updated: 2026-09-09 (Grok).

---

## Qwen

Wrote `design.md` (initial commit `c38b628`). Design-only; no implementation
in that commit.

---

## Grok

Date: 2026-09-08.
Request: implement `@design.md`.

Ran `/execute-plan` against `design.md` (PLAN_ID `867299d2`, effort 1,
concurrency 4, plain-git — no Graphite, no origin at the time). The design
has no `## PR Plan`; milestones §14 were used as a 6-PR linear DAG
(M0 → M5). Workspace was not a git repo; git was initialized locally.

Assembled tip of this work: `b6069bbea8e3cdb474fa0ca92944f4fa547e28e3`
(`execute-plan/867299d2-pr-6-m5-ssh-public-key-authentication`).
`go test -race ./...` was green on that tree.

Stack branches (local):

```
execute-plan/867299d2-pr-1-m0-repo-skeleton-proto-codec-tcp-transport-and-tcp
execute-plan/867299d2-pr-2-m1-transparent-resume-ring-buffers-hold-window-and
execute-plan/867299d2-pr-3-m2-udpmux-quic-adapter-probe-and-path-switch
execute-plan/867299d2-pr-4-m3-kcp-adapter-on-shared-udp-endpoint
execute-plan/867299d2-pr-5-m4-session-limits-graceful-shutdown-observability
execute-plan/867299d2-pr-6-m5-ssh-public-key-authentication
```

### M0 — TCP relay skeleton

`cmd/relay` (`server` | `client` | `version`), `internal/{config,logging,proto,transport,session,relay,auth,version}`, TOML + flags, frame codec (Type | BE32 len | payload, max 1 MiB), TCP `transport.Conn`, stdio↔dest pumps, `none` authenticator.

### M1 — resume

`resumeToken` 32B from `crypto/rand`, SHA-256 hashed in the store, rotated on resume, previous generation valid until the first inbound frame after `RESUME_OK`. I1–I5: ACK durable, retransmit from ACK, offset dedupe, gap fatal, one writer per sink. `sendLog` ring, `send_window` / `buffer_bytes` / `total_buffer_bytes`, `hold_timeout` 5m, client reconnect backoff, half-close (`CLOSE_DIR`).

### M2 — QUIC upgrade

Shared UDP `udpMux` (tag `0x01` KCP, `0x02` QUIC). Handshake always TCP; `PROBE` / `PROBE_OK` / `SWITCH`; after upgrade TCP is closed (D7). quic-go v0.62.0, ALPN `relay/1`, `InsecureSkipVerify`, ephemeral self-signed cert. Probe failure stays on TCP for that session.

### M3 — KCP

kcp-go/v5 v5.6.72 on the same mux via `ServeConn` / `NewConn2` (`ownConn=false`), FEC off, stream mode. `--kcp`. R1 resolved as mux `ServeConn`, not a second KCP port (D5′).

### M4 — hardening

`max_sessions`, `max_conns_per_ip` (HELLO flood cap counts live TCP sockets; resumed TCP does not steal HELLO slots). SIGTERM → `BYE` drain (BYE must not block on a full ctrl queue). Structured logs (client logs never touch stdout). expvar / pprof. README. 64-session soak in CI is TCP+QUIC; mixed KCP at that kill rate expired rather than resuming (liveness/scale, not mux identity) — documented, plus an 8+8 mixed test.

### M5 — ssh-publickey

`auth.Authenticator`: `none` | `ssh-publickey`. Default remains `none` (D2). TOML-only (`auth_method`, `authorized_keys`, `auth_fail_delay`, `auth_user`, `identity_files`).

Wire (design sketched the challenge inside `HELLO_OK`; that frame is post-dial, so extra types were added):

```
none:          HELLO → HELLO_OK
ssh-publickey: HELLO → AUTH_OK(challenge) → AUTH(sig) → HELLO_OK
resume:        RESUME → AUTH_OK → AUTH → RESUME_OK
```

`AUTH` = 0x09, `AUTH_OK` = 0x0A. `AUTH_OK` is the challenge, not success. Challenge is `SHA256(sessionId ‖ clientNonce ‖ serverNonce ‖ dest ‖ on-wire HELLO/RESUME JSON)`. Issued before `store.Add` and before dest dial. Client signs `~/.ssh/id_ed25519` then `id_ecdsa` then `id_rsa` (PEM + OpenSSH). Server verifies `authorized_keys` (ed25519, ecdsa P-256/384/521, RSA ≥ 2048 with `rsa-sha2-256`/`rsa-sha2-512`; `ssh-rsa` SHA-1 rejected). Failure is `ERR_AUTH` after a fixed delay (unknown key and bad sig share the delay). Session stores the key fingerprint; `RESUME` must re-sign with the same key — `resumeToken` alone is not enough. Non-empty client dest must match `AUTH_OK.destination` or the client refuses to sign; empty dest may adopt the server default.

Not in M5 (not in §10.4): ssh-agent, passphrase-protected keys, `authorized_keys` options, SSH certificates, user ACL.

### Review-fix notes from this run

- Handshake deadline must cover dest dial; `SetDeadline` is a write deadline under backpressure; `CLOSE_DIR` validated; HELLO_OK chunk clamped.
- `reconnect_max_elapsed` is session-lifetime; do not rotate the token before `RESUME_OK` is observed; hold-wait timer vs `attachCh`; occupancy budget must wake other rings on `Release`; HELLO_OK before `lives` insert.
- SWITCH needs a server timeout; UDP bind family; close quic `Transport`.
- KCP `Close` must wake the reader.
- SIGTERM must not block on a full ctrlQ; `ipConns` must not count the whole `handle()` lifetime.
- Client must not copy `AUTH_OK.destination` into the hash when it already sent a dest; fail-delay is measured from verify, not handshake start.

### Left on the table at the end of this work

These were **not** done here:

- `relay version` still printed `0.1.0-m0`.
- Field `tc netem` numbers were not recorded (no netem in that environment).
- Mixed-KCP 64-session soak at the CI kill rate.
- No GitHub origin / PRs at assembly time (plain-git local stack only).

---

## Next agent

Append a new `## <Agent>` heading below this line. Write what you changed,
not a restatement of the tree.
