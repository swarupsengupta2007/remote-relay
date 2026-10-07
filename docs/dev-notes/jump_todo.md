# FEAT-UTL-05 jumphost chaining — execution ledger

**Purpose of this file:** hand-off ledger. If the working agent stops (quota, crash,
context loss), a fresh agent reads this file, runs `git status` / `git diff`, and
continues from the first unchecked box. Keep it updated *as work happens*, not at
the end.

- Source plan: `jumphost_plan.md` (750 lines, authoritative design; J-D1…J-D16, JR1…JR11)
- Branch: `main`. Working tree was clean at commit `9a1dd00` when work started.
- Nothing has been committed yet. Commit in logical chunks (see "Commit plan").

## Scope agreed

Implement **Phase 1 in full** (the plan's §6 Phase 1 checklist + exit criteria) plus
the cheap/low-risk parts of **Phase 2**. Explicitly deferred (high risk, needs the
most delicate code in the tree — see JR11):

- Phase 2.4 Case C: mid-session `TypeAuthOK{hop>0}` in `netReader` (pump.go ~:951),
  pump quiesce, `chain_auth_timeout` enforcement.
- Phase 2.5 Case D: rebuild-on-resume when the nested session is already dead.
- Phase 2.2/2.3: per-hop transport + per-hop UDP probe/SWITCH/upgrade (Phase 1
  forces TCP on every hop).
- Phase 2.10: re-enable `splice(2)` on a nested leg.
- Phase 3 (NATed terminal, depends on FEAT-UTL-04) — wire field `HopSpec.Target`
  is reserved, nothing else.

Consequence to remember: on a nested leg whose resume token has gone stale, the
intermediate cannot relay a fresh challenge (Case C is unimplemented), so it tears
the chain down instead. The originator then sees `BYE`/`ERR_UNKNOWN_SESSION` and
`ssh` restarts. This is correct-but-degraded, must be documented in README, and is
the main reason to finish Phase 2.

## Progress

Phase 1 (plus cheap Phase 2) is implemented in the working tree. Nothing has
been committed; ask before committing. `gofmt`, `go vet`, and
`go test -race -count=1` pass across proto, crypto, config, auth, cmd, relay,
transport, session, bfd, logging.

### 1.0 J-D16 gate — KEX nonce reused as auth nonce — **DONE**
- `internal/crypto/kex/kex.go`: `ServerSession` gained `nonce`/`nonceSet` fields,
  `ServerNonce() []byte` and `AttestationNonce() string` (base64). `ProcessInit`
  records the nonce it already generated. Added `encoding/base64` import.
- `internal/relay/server.go`:
  - `handle()` captures `kexNonce := kexSrv.AttestationNonce()` right after
    `ProcessInit` and passes it to `handleHello` / `handleResume`.
  - `helloAuth(conn, hello, canonical, dest, kexNonce)` and
    `resumeAuth(conn, msg, canonical, kexNonce)` now call the new
    `authServerNonce(kexNonce)` helper (kex nonce, else `proto.RandomNonce()` for
    QUIC/KCP RESUME carriers that run no KEX).
  - `helloAuth` returns `kexNonce` on the `!RequiresChallenge()` path too, so
    `HelloOK.ServerNonce` is always the KEX nonce. The old
    `if serverNonce == "" { RandomNonce() }` block in `handleHello` was deleted.
  - `handleResume` signature gained `kexNonce string`; `internal/relay/udp.go`
    passes `""` from `handleQUIC`/`handleKCP` (with a comment saying why).
- Test: `TestNonceBindingKexEqualsAuth` in `chain_test.go`.

### 1.1 proto — **DONE**
- `internal/proto/proto.go`: `TypeChain 0x0E`, `TypeChainOK 0x0F` (with the J-D10
  fail-closed rationale in a comment), added to `Known()` and `String()`.
- `internal/proto/errors.go`: `CodeChainTooLong` / `CodeChainLoop` /
  `CodeHopForbidden` + sentinels `ErrChainTooLong` / `ErrChainLoop` /
  `ErrHopForbidden`.
- `internal/proto/messages.go`: `Auth.Hop`; `AuthOK.Hop`, `.HelloJSON`, `.Attest`;
  new `HopSpec`, `HopAttestation`, `ChainHello`, `ChainHelloOK`.
  **Deliberate deviation from plan §2.9:** `ChainHelloOK` carries **no** resume
  token. Plan §3.4 already says the client must discard and never log token₂; not
  transmitting it is strictly better and costs nothing (the intermediate learns
  token₂ from the `HelloOK` it receives onward, not from `ChainHelloOK`).
  `ChainHelloOK.SetupMs` added for the JR6 `chainSetupMs` observability ask.

### 1.2 kex attestation — **DONE**
- `internal/crypto/kex/hostkey.go`: `RawEd25519ToAuthorizedKeysLine(pub []byte)`
  and `VerifyAttestation(kexInit, kexReply, knownHostsPath, addr, pin, strict)
  ([]byte /*serverNonce*/, error)`. It recomputes `ExchangeHash`, checks the
  Ed25519 sig, then calls the existing `VerifyKnownHosts` (so the fail-closed
  behaviour for `knownHostsPath == ""` from wip.md §1 is inherited, not
  duplicated). Returns the attested `serverNonce` — the caller MUST compare it
  against `AuthOK.ServerNonce`; that comparison is the whole point of J-D16.
- Tests: `internal/crypto/kex/attest_test.go`.

### 1.3 config — **DONE**
- `internal/config/chain.go` + `chain_test.go`. Defaults, Validate, ParseJumphost,
  HopAllowed, ChainSessionLimit, CLI>TOML precedence.

### 1.4 relay server — **DONE** (Phase 1; Case C/D deferred)
- DONE so far, in service of this step: `dialDestination(ctx, dest)
  (*net.TCPConn, *proto.Error)` extracted in `server.go` and used by
  `handleHello`; `handle()` dispatches `proto.TypeChain` to
  `s.handleChain(ctx, cipherConn, f, ip, releaseTCP, kexNonce)` and the
  `MaxConnsPerIP` flood cap now counts `TypeChain` like `TypeHello`.
  `handleChain` lives in `internal/relay/chain.go`; the nested pump is in `chain_nested.go`.
- Plan for `internal/relay/chain.go` (new file):
  - `handleChain(ctx, conn, f, ip, releaseTCP, kexNonce)`:
    1. Unmarshal `proto.ChainHello`; `V == 1`; `len(Hops) >= 1`.
    2. Policy, in this order, all *before* any dial:
       - `len(AllowRelayHops) == 0` ⇒ `ERR_HOP_FORBIDDEN` (J-D8 default-deny).
       - every hop in `Hops` must satisfy `config.HopAllowed` (J-D9: check the
         whole remaining path, not just `Hops[0]`).
       - `len(Hops)+1 > MaxChainDepth` ⇒ `ERR_CHAIN_TOO_LONG`.
       - loop detection (JR9): any `Hops[i].Addr` equal to one of this server's
         own addresses, or any `Visited` entry equal to one of them, or a
         duplicate inside `Hops` ⇒ `ERR_CHAIN_LOOP`. Helper
         `(s *Server) chainSelfAddrs() []string` returning `s.Addr()` and
         `s.cfg.ListenTCP`; compare with a small `addrEqual` that treats a
         wildcard host (`0.0.0.0`, `::`, `""`) as matching any host on the same
         port.
       - chained-session capacity: a counter on `Server` vs `ChainSessionLimit()`.
       - `OriginIP` accounting (J-D14/JR4): use `ChainHello.OriginIP` instead of
         the TCP peer IP for `tryReserveIPSess`/`decIPSess` when non-empty, and
         add a per-upstream-peer counter bounded by `MaxChainConnsPerPeer`.
         **Open question #1 from the plan is unresolved** — decide whether to
         trust `OriginIP` blindly. Recommended interim: trust it only for
         *accounting* (never for policy/allow-lists) and cap what one upstream
         relay may open via `MaxChainConnsPerPeer`; note the residual spoofing
         risk in the FEAT doc.
    3. Authenticate the client for *this* hop by issuing our own challenge:
       build `auth.Challenge{SessionID: sess.ID, Destination: ch.Destination,
       ClientNonce: ch.ClientNonce, ServerNonce: kexNonce, Canonical: f.Payload,
       Offer: ch.Auth}`, `issueChallenge(conn, …)` with
       `Hop = len(Visited)+1` and `HelloJSON = string(f.Payload)` (no `Attest` —
       the originator ran this KEX itself), read `TypeAuth`, `s.auth.Verify`.
       This reuses `helloAuth`'s shape; generalise rather than copy if it stays
       readable. NOTE: `issueChallenge` must grow the ability to set `Hop` and
       `HelloJSON`, so change its signature to take a prebuilt `proto.AuthOK`
       or extra args — check its other two callers (`helloAuth`, `resumeAuth`).
    4. Reserve IP session, `store.Add(sess)`.
    5. Dial `Hops[0].Addr` over TCP (`transport.DialTCPWithDelayAndBind` with the
       server's own dial timeout), run the KEX **as a client**
       (`kex.NewClientSession`, write `TypeKexInit`, read `TypeKexReply`), and
       keep the 48/144-byte payloads — they are this hop's attestation. Verify
       the onward host key: `Hops[0].Fp` pin if present, else
       `RelayKnownHosts` + `RelayStrictHostKeyChecking`; if neither is configured,
       log a warning and proceed, because the *originator* independently verifies
       this transcript via the attestation (J-D3 is the authoritative check; an
       intermediate has no prompt and TOFU is impossible unattended).
    6. Build the onward frame: `tail := Hops[1:]`; if `len(tail) > 0` send
       `TypeChain` with `ChainHello{ChainID, Hops: tail, Destination,
       Visited: append(Visited, selfAddr), OriginIP, Transport:
       Hops[0].Transport, ClientNonce: fresh, Auth: <offer copied verbatim from
       the inbound frame>, Window}`, else send a plain
       `TypeHello` (`proto.Hello`) — this is why the terminal needs no chain code.
       Keep `canonical := <exact JSON bytes written>`; the next hop echoes them
       back as `HelloJSON` and the originator recomputes the digest over them.
    7. Relay loop toward the originator (bounded by `ChainAuthTimeout`, capped at
       `ChainAuthRelaysMax`): read onward frames and
       - `TypeAuthOK` with `Hop == 0` ⇒ it is the *next* hop's own challenge:
         set `Hop = len(Visited)+2`, attach `Attest` (our KexInit/KexReply,
         base64, plus `HostKeySSH` from `RawEd25519ToAuthorizedKeysLine`), set
         `HelloJSON = string(canonical)`, forward inbound; then read the
         originator's `TypeAuth`, strip `Hop`, forward onward.
       - `TypeAuthOK` with `Hop > 0` ⇒ already labelled by a deeper intermediate:
         forward inbound verbatim, relay the signature back onward verbatim.
       - `TypeChainOK` ⇒ forward inbound verbatim (informational; count
         `chain_hops_total`).
       - `TypeHelloOK` ⇒ the onward session is up: capture `SessionID`,
         `ResumeToken` (kept ONLY in the intermediate; never forwarded),
         `Limits`, `Transport`. Stop relaying.
       - `TypeErr` / `TypeResumeFail` ⇒ map to an inbound `writeErr` and abort.
    8. Build the bridge + nested pump (see below), then send the originator one
       `TypeChainOK` per completed onward hop (relayed ones already went through;
       emit ours for the hop we just terminated) and finally our own
       `proto.HelloOK` for hop 1 — same construction as `handleHello`.
    9. Register a `live` and `l.run(ctx, rawConn)` exactly like `handleHello`.
  - `nestedHop` type implementing the `sessionIO` seam (`pump.go:33-44`):
    two in-memory pipes (`io.Pipe`), `toOnward` (inbound pump's `sink` →
    nested pump's `src`) and `fromOnward` (nested pump's `sink` → inbound pump's
    `src`). Inbound pump gets `src: fromOnward.R, sink: toOnward.W,
    closeWrite: toOnward.W.Close` (J-D15: an inbound CLOSE_DIR{up} becomes EOF
    for the nested pump, which then emits its own CLOSE_DIR{up} onward),
    `closeSrc: nested.close`, `rawSrc: nil, rawSink: nil` (J-D13: no fd ⇒ no
    splice), `outDir: DirDown, inDir: DirUp`. The nested pump mirrors it with
    `outDir: DirUp, inDir: DirDown` and `splice: false` in its `pumpConfig`.
    `close()` must be `sync.Once`, cancel the nested ctx, close all four pipe
    ends with `io.ErrClosedPipe` (so `srcReader`'s existing
    `errors.Is(err, io.ErrClosedPipe)` branch returns cleanly instead of failing
    the session), then `pump.shutdown()` and close the onward conn.
  - `live` struct: add `nested *nestedHop`; `live.cleanup` must close it so
    teardown fans out to both sessions. `live.dest` stays `*net.TCPConn` and is
    nil for a chained session — check every use.
  - Nested runner: `pump.startIO()` then a small loop
    `serveConn → on reconnectable error → re-dial + RESUME (reuse
    clientResume/writeResumeRole with a synthesised config.Client whose Server is
    the hop addr and Transport is "tcp") → AdvanceTo(rok.UpAcked)`, with the
    retry budget clamped to the nested `Limits.HoldTimeoutMs` (mirrors
    `client.go:139-144`). If RESUME fails, tear the chain down (Case C/D are out
    of scope).
  - **Invariant to respect:** the inbound pump must ACK only after bytes are in
    the nested ring, never after the next hop has them — that is the I1
    weakening documented as JR3. Do not "fix" it by making the bridge
    synchronous end-to-end; it would serialise both hops' windows.
- `reconnectable()` (pump.go ~:646): add `CodeChainTooLong`, `CodeChainLoop`,
  `CodeHopForbidden` to the non-reconnectable list so a policy refusal surfaces
  to `ssh` immediately instead of burning the 5-minute retry budget.

### 1.5 relay client — **DONE**
- `client.go`: `clientHello` must branch on `cfg.Jumphost`:
  - dial `hops[0].Addr` (NOT `cfg.Server`; `cfg.Server` is the terminal),
  - KEX + host-key verify against `hops[0].Fp` / `cfg.KnownHosts` /
    `cfg.ServerFingerprint` exactly as today,
  - send `TypeChain` with `ChainHello{ChainID: random base64 16B, Hops:
    hops[1:] ++ [terminal HopSpec from cfg.Server], Destination: cfg.Destination,
    Visited: nil, OriginIP: "", Transport: cfg.TransportPreference(),
    ClientNonce, Auth: offer, Window}`,
  - then the per-hop verify-and-sign loop: for each inbound `TypeAuthOK`,
    `completeChainAuth(hop, authOK)` →
    1. `AuthOK.Destination` must equal the requested destination (generalises the
       existing guard at `client.go:449-457`);
    2. if `Attest != nil`: `kex.VerifyAttestation` against **the address the
       client asked for** (`hops[hop-1].Addr`), with that hop's pin; compare the
       returned `serverNonce` (base64) against `AuthOK.ServerNonce` — mismatch ⇒
       refuse to sign (**JR1 regression guard**);
    3. base64-decode `HelloJSON`, extract its `clientNonce`, recompute
       `auth.DeriveChallenge`, compare with `AuthOK.Challenge`;
    4. `a.Sign(ch)`, then send `TypeAuth` as `proto.Auth{Sig: …, Hop: hop}`.
    Never sign a challenge whose `Hop` is 0 on a chained path, and never sign one
    for a hop index outside `1..len(hops)`.
  - collect `TypeChainOK` frames (log `chainSetupMs`, discard everything else —
    there is no token in them by design), then read the final `TypeHelloOK`.
- Generalise `completeClientAuth` (`client.go:444`) rather than duplicating it;
  keep the direct path byte-identical in behaviour (many existing tests).
- The client keeps only token₁. `RunClient`'s resume loop is unchanged: it
  resumes hop 1, and the intermediate keeps the nested session alive across it.
- At startup, warn when the summed worst-case hold exceeds `SSHDAliveBudget`
  (§2.7 / JR8). The client only learns each hop's `HoldTimeoutMs` from
  `ChainHelloOK`/`HelloOK`, so compute the sum after the handshake and log a
  warning then.

### 1.6 cmd/relay — **DONE**
- `-J` / `--jumphost` (also accept `--chain` as an alias — plan open question #2;
  cheap and avoids confusing users who type `ssh -J`). Repeatable AND
  comma-separated: reuse the existing `stringSliceFlag` type in `main.go`, then
  let `config.ParseJumphost` do the comma splitting.
- Use the `fs.Visit` "was this flag set" pattern (as for `--dest`) so precedence
  stays CLI > TOML > default.
- Reject `-J` with an empty `--server` (the terminal is always explicit).
- Update `usage()`.

### 1.7 Phase 1 constraints — **DONE**
Transport forced to TCP on every hop (`Transport: []string{"tcp"}` in the onward
frame), no HA on a nested leg, no Case C. Enforce by ignoring per-hop
`transport=`/`ha=` from `-J` in Phase 1 **but still parse them** (1.3 item 6) so
Phase 2 is additive. Log a warning if a user asks for a non-TCP hop transport.

### 1.8 Tests — **DONE**
See §Tests below.

### 1.9 Docs — **DONE**
- Promote `jumphost_plan.md` → `.feat-impl/FEAT-UTL-05.md` (match the house style
  of `.feat-impl/FEAT-PERF-03.md` / `FEAT-ROB-03.md`; read one first).
- `features.md`: add FEAT-UTL-05 to the Priority Matrix + Tier 2, cross-reference
  from FEAT-UTL-04 and FEAT-UTL-03.
- `design.md`: fold J-D1…J-D16 into §3 as D11+, add invariant **I6** to §7.1,
  add JR1–JR11 to §15, update the §5.2 frame-type table (0x0E/0x0F) and §4.1 repo
  layout (`internal/relay/chain.go`).
- `README.md`: new "Jumphost chaining" section; extend the Status table; add the
  **JR3** caveat ("bytes ACKed at an intermediate are only in its nested ring; an
  intermediate crash loses them") next to the existing "Hold is in-process"
  caveat; add the Σ-hold vs `ClientAliveInterval` warning next to the R7 note.
- `wip.md`: append an entry per phase (read the tail first to match the format).

### 1.10 netns harness — **DONE** (not wired into CI)
`scripts/test_jumphost_netns.py`, following `scripts/test_sec_netns.py`'s skeleton
(`T=/tmp/relay-verify`, `BIN`, `netns()`, `cleanup()`, `setup_env()`,
`record_result()`, PASS/FAIL summary, `sys.exit(1)`). Scenarios JUMP-01…JUMP-07
from plan §7.2. Not wired into CI (needs root + netns + real sshd), same status as
the existing harnesses.

## Tests to write

New file `internal/relay/chain_test.go`. Reuse the existing fixture: `TestMain`
in `test_main_test.go` sets `RELAY_TEST_IDENTITY`, `RELAY_TEST_AUTHORIZED_KEYS`,
`RELAY_TEST_KNOWN_HOSTS=/dev/null`; helpers `startRelayCfg` (e2e_test.go:70),
`echoDest` (sec_test.go:27), `makePattern`/`checkPattern` (e2e_test.go:20,41).
Add `startChain(t, nHops, terminalDest)` returning the head address + `[]*Server`.
Every chained server needs `Transports: ["tcp"]`, a host key (auto-generated per
server by `NewServer`), `AuthorizedKeys` from the env, and a non-empty
`AllowRelayHops` naming the next hop's real bound address — which means the
servers must be started **innermost-first** so each address is known before the
previous one is configured.

| Test | Asserts | Status |
|---|---|---|
| `TestNonceBindingKexEqualsAuth` | `AuthOK.ServerNonce` is byte-identical to `KexReply[32:48]` (base64) on both HELLO and RESUME paths | DONE |
| `TestChainE2EByteExactBothDirections` | 1 MiB positional pattern both ways, SHA-256 match | DONE |
| `TestChainThreeHops` | N-hop recursion, depth ≤ `max_chain_depth` | DONE |
| `TestChainHopNotAllowed` | empty `allow_relay_hops` ⇒ `ERR_HOP_FORBIDDEN`, before any dial | DONE |
| `TestChainDepthExceeded` | ⇒ `ERR_CHAIN_TOO_LONG`, and `reconnectable()` says false | DONE |
| `TestChainLoopDetected` | self-reference and duplicate hops ⇒ `ERR_CHAIN_LOOP` | DONE |
| `TestChainAttestationHostKeyMismatch` | rogue terminal ⇒ client refuses to sign | DONE |
| `TestChainAttestationReplay` | stale `KexReply` + fresh fabricated `AuthOK` ⇒ rejected (JR1 / J-D16 regression; must fail if the nonces are ever decoupled again) | DONE |
| `TestChainDestinationMismatch` | intermediate lies about `Destination` ⇒ client refuses | DONE |
| `TestChainVersionSkewFailClosed` | default-deny / unknown type ⇒ fail closed, never a silent direct dial | DONE |
| `TestChainTerminalHasNoChainCode` | terminal has empty `allow_relay_hops` and serves the last hop as an ordinary `Hello` | DONE |
| `TestChainHalfClosePropagation` | stdin EOF → CLOSE_DIR → nested CLOSE_DIR → terminal `CloseWrite` (J-D15) | DONE |
| `TestChainResumeOuterHopOnly` | kill the hop-1 carrier; nested session untouched; stream byte-exact | DONE |
| `TestChainBackpressureGlobalBudget` | `chain_max_sessions` refuses new, existing survive | DONE |
| `TestChainOriginIPAccounting` | `max_conns_per_ip` counts originators, not the upstream relay (JR4) | DONE |
| `TestChainSpliceDisabled` | 0 `splice(2)` calls on a nested leg | DONE |
| `TestChainConcurrencyLeak` | chained sessions, random outer kills, goroutines return to baseline | DONE (8 sessions; 64 is the direct-session soak) |
| kex unit tests for `VerifyAttestation` + `RawEd25519ToAuthorizedKeysLine` | `internal/crypto/kex/attest_test.go` | DONE |
| config unit tests for `ParseJumphost` + new `Validate()` rules | `internal/config/chain_test.go` | DONE |
| `cmd/relay` `-J` parsing test | `cmd/relay/main_test.go` | DONE |

Deferred with Phase 2: `TestChainResumeInnerHopOnly`, `TestChainResumeBothHops`,
`TestChainStaleTokenInnerRelaysSignature`, `TestChainPerHopTransport`,
`TestChainTerminalPreJD16Refuses` (needs a way to simulate a pre-J-D16 server).

## Verification (run all, in this order)

```
cd /root/remote-relay
gofmt -l . && go vet ./... && go build ./...
go test -race -count=1 -timeout 10m ./internal/proto/... ./internal/crypto/... ./internal/config/...
go test -race -count=1 -timeout 10m ./internal/relay/... ./internal/auth/... ./cmd/...
staticcheck ./...        # if installed; CI runs it, see .github/workflows/ci.yml
```
Chain tests pass under `-race`. Resume of a chained session must dial hop 1,
not `--server` (the terminal) — see `pathCfg` in `RunClient`.

## Commit plan

1. `fix(kex): reuse KEX serverNonce as auth serverNonce (J-D16)` — kex.go +
   server.go + udp.go + `TestNonceBindingKexEqualsAuth`. Standalone hardening of
   the existing two-party protocol; lands first per plan §6 ("GATE").
2. `feat(proto): add CHAIN/CHAIN_OK frames and chain messages` — proto + errors +
   their tests.
3. `feat(config): jumphost + allow_relay_hops configuration` — config + tests.
4. `feat(relay): multi-hop jumphost chaining (-J)` — chain.go, client.go, main.go
   + chain_test.go.
5. `docs: FEAT-UTL-05 jumphost chaining` — .feat-impl, features.md, design.md,
   README.md, wip.md, scripts/test_jumphost_netns.py.

Ask the user before committing (no standing authorisation in this session).

## Gotchas learned so far

- The data plane is **not** relay-encrypted: after the handshake both sides drop
  to the raw carrier ("Option A clean phase cut"). `clientHello` returns
  `cipherConn.Underlying()`; the server does `unwrapConn(conn)`. So a nested leg
  pumps plain frames on the onward TCP conn — matching what the terminal expects.
- `writeResumeRole` (upgrade.go:290) performs its own KEX for TCP carriers, so
  `clientResume` is reusable for a nested RESUME if you synthesise a
  `config.Client` with `Server = hopAddr`, `Transport = "tcp"`, the identity
  files, and the destination.
- `sec_test.go:540-560` asserts the base64 `serverNonce` never appears in
  plaintext on the wire. J-D16 puts the *raw* nonce in the clear inside
  `KEX_REPLY[32:48]`, which does not trip that test (it greps for the base64
  string). Both roles are public values; see the J-D16 rationale in plan §2.5.
- `pump.shutdown()` calls `io.closeSrc` then waits `srcWG`, and waits `sinkWG`
  when `closeWrite != nil`. Any teardown path through the bridge must unblock
  both goroutines *before* waiting, hence closing all four pipe ends in
  `nestedHop.close()`.
- `getSinkFD()` falls back from `rawSrc/rawSink` to `src/sink`, so the bridge
  pipes must not expose an `Fd()` — use `io.Pipe`, not the `pipePair` OS pipes
  from `splice_linux.go`.
- Existing tests set `StrictHostKeyChecking = "no"` + `RELAY_TEST_KNOWN_HOSTS=/dev/null`;
  attestation tests that need a *strict* check must write a real temporary
  known_hosts file instead of relying on the env default.
- Originator resume must target hop 1 (`pathCfg.Server = hops[0].Addr`). Using
  `cfg.Server` (the terminal) yields `ERR_UNKNOWN_SESSION` on the first outer
  drop.
- Do not mutate `Server.cfg` after `Serve` starts: `Serve` reads `AllowRelayHops`
  at startup and `-race` will flag it (`TestChainLoopDetected`).
