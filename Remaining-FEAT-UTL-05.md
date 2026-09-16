# Remaining FEAT-UTL-05 — Phase 2 (Case C / Case D / per-hop transport)

**Status:** Agreed remaining-work spec. No code changed by this document.
**Date:** 2026-09-15
**Source:** interview over the leftover of [`.feat-impl/FEAT-UTL-05.md`](.feat-impl/FEAT-UTL-05.md) / `jumphost_plan.md` §6 Phase 2–3, against the Phase 1 tree.
**Target packages:** `internal/relay` (`pump.go`, `chain.go`, `chain_nested.go`, `client.go`, `client_chain.go`, `upgrade.go`), `internal/config` (no new knobs required)

> Phase 1 is in the working tree and is **not** re-litigated here. This document is the shared understanding of what is still missing, why it hurts, and how we will build it.

---

## 1. Interview outcome (locked)

| # | Question | Decision |
|---|---|---|
| **R-D1** | Inner resume token stale, hop-1 already on the data plane | **Case C** — relay the challenge mid-session on the hop-1 carrier. Quiesce rules below. Bounded by existing `chain_auth_timeout` / `chain_auth_relays_max`. |
| **R-D2** | Both hops break, or hop-1 resumes into a dead nested session | **Case D** — before `RESUME_OK`, j1 checks the nested leg; if it is dead, rebuild hops 2…N on this resume, using the client's presence on hop 1 to relay signatures. Reuses Case C's relay path. |
| **R-D3** | Per-hop `?transport=` / `?ha=` | **Full J-D4** — each hop may QUIC/KCP-upgrade and may run `--allow-ha`. Phase 1's TCP force is lifted. |
| **R-D4** | Nested `splice(2)` (JR7) | **Defer indefinitely.** Not on the critical path. Nested splice is not “splice two TCP sockets together”; j1 still terminates two sessions. At best each pump splices TCP ↔ an OS-pipe bridge. WAN-bound jumphosts do not need it; mixing splice fd lifetime with Case C quiesce is the wrong risk (R8). Keep `io.Pipe` + `splice: false` + `rawSrc`/`rawSink` nil. |
| **R-D5** | Phase 3 NATed terminal (`HopSpec.Target`) | **Out of scope.** Wire field stays reserved. Blocked on FEAT-UTL-04. This document does not design rendezvous. |
| **R-D6** | `OriginIP` trust | **Unchanged.** Trusted for accounting only, never for allow-lists. `max_chain_conns_per_peer` is the amplifier cap. Residual spoofing is accepted. |
| **R-D7** | Implementation order | **Case C → Case D → per-hop transport + HA.** Correctness of resume first. Transport is additive on a working nested runner. Case D is a consumer of Case C's relay, not a second crypto design. |

No remaining product forks. Open questions at the end are engineering details, not scope.

---

## 2. What Phase 1 already delivered (do not redo)

The originator can:

```
relay client --server S.example.com:7443 -J j1.example.com:7443[,j2…] --dest 127.0.0.1:22
```

Every hop is a full relay session (J-D1). The private key never leaves the client (J-D2). The client verifies every hop's host key via KEX attestation bound to the auth nonce (J-D3 + J-D16). Chaining is default-deny (`allow_relay_hops`). N-hop recursion, loop detection, `OriginIP` accounting, `chain_max_sessions`, Σ-hold warning, and chain expvars are in.

**Phase 1 forces TCP on every hop** (`RunClient` rewrites `cfg.Transport = "tcp"` when `-J` is set; `chainHopTransport` always returns `[]string{"tcp"}`). Nested resume is token-fast-path only: `nestedClientConfig` carries **no identity**, so `writeResumeRole`'s `TypeAuthOK` branch cannot succeed.

**The production gap this document closes:**

| Event | Phase 1 | Remaining |
|---|---|---|
| Outer hop breaks (Case A) | Originator `RESUME`s hop 1 with token₁. Nested untouched. | Keep. |
| Inner hop breaks, token₂ valid (Case B) | Nested `clientResume` fast path. Originator not involved. | Keep. Then add per-hop upgrade after resume. |
| Inner hop breaks, token₂ stale (Case C) | Nested resume fails → `onGone` → chain torn down → `ssh` restarts. | Relay the challenge to the originator on the hop-1 data plane. |
| Both hops break / nested already dead (Case D) | Hop-1 `RESUME_OK` into a dead chain, or `ERR_UNKNOWN_SESSION`. | Rebuild onward hops before answering `RESUME_OK`. |
| Lossy middle leg | TCP only. `-J ?transport=kcp` is parsed and ignored. | Honour per-hop transport and HA. |
| Nested splice | Disabled. | Stays disabled (R-D4). |

---

## 3. Problems (shared statement)

### 3.1 Case C — inner stale token, outer carrier live

`nestedHop.run` (`chain_nested.go:186-227`) already retries with `clientResume` → `writeResumeRole` (`upgrade.go:290`). On TCP that is a **new** KEX + `RESUME` on a fresh socket to S. PERF-03 fast path returns `RESUME_OK`. Stale token makes S emit `TypeAuthOK` on **that** resume socket (`server.go:580-584`).

`writeResumeRole` then calls `completeClientAuth` (`upgrade.go:371-382`) using `clientAuth(cfg)`. For a nested hop `cfg` has empty `IdentityFiles` / `AuthSock` (`chain.go:686-690`). The intermediate **must not** gain the originator's key. Sign fails → nested runner gives up → `onGone` expires hop 1.

The originator *can* sign: it still holds the key, and hop-1 is up. After the Option A phase cut there is no HELLO channel; control frames already ride the carrier (`SWITCH`, `BYE`, `CLOSE_DIR`, `PING`). `TypeAuthOK` / `TypeAuth` can too. **`netReader` does not dispatch them** (`pump.go:952`, default → `ERR_PROTO`).

So Case C is not new crypto. It is: **take the AUTH_OK that already appears on the nested resume socket, carry it across the hop-1 data plane, get AUTH back, finish `writeResumeRole`.** Plus the concurrency rule that this must not interleave with `SWITCH` (JR11 / R8).

Cost if we skip it: every inner hold-expiry or token rotation kills `ssh`. Rare per hour, fatal per occurrence.

### 3.2 Case D — outer resume into a dead inner

Hop-1 `RESUME` is handled in `handleResume` (`server.go:534`) with no nested check. `Offer` attaches the new carrier to the inbound pump even if `live.nested` has already called `onGone` and expired the session — or, worse, if `onGone` has not yet run and the nested runner is mid-failure.

Two bad outcomes:

1. `RESUME_OK` into a chain whose onward leg is gone. Originator pumps into a pipe whose other end is closed. Stream dies after a false success.
2. Nested Case C needs a signature **while hop-1 is down**. There is no data-plane channel. The inner hop dies; when the client later resumes hop 1 it hits (1).

JR2. The fix is: **hop-1 resume does not succeed until the nested leg is live**, and if it is not, **rebuild it now**, because the client is present on this TCP/KEX connection and can sign.

Case D's signature relay is *easier* than Case C's: the hop-1 resume connection is still in handshake (AEAD wrapping `RESUME` / `AUTH_OK` / `RESUME_OK`). Extra `TypeAuthOK{hop>1}` / `TypeAuth` frames can sit between hop-1's own fallback AUTH (if any) and `RESUME_OK`, the same shape `clientChainHello` already loops on (`client_chain.go:148-190`). Case C is the harder cousin because it uses the data plane.

### 3.3 Per-hop transport (J-D4)

Every hop still handshakes over TCP; QUIC/KCP accept paths take `RESUME` only (`udp.go`). Per-hop transport is a per-hop **upgrade**, not a per-hop dial. Phase 1 never starts that upgrade on a nested leg (`chainHopTransport` returns TCP; `nestedHop.run` is serveConn + TCP resume only; originator `pathCfg.AllowHA = false`).

Without this, a lossy j1↔S leg cannot get KCP, and a nested hop cannot keep a TCP standby. That is the operational reason people wanted server-side chaining over client-side nesting (J-D1).

### 3.4 Explicitly not problems for this remaining work

- J-D16 nonce binding, attestation, default-deny, N-hop recursion, OriginIP accounting, chain capacity, Σ-hold warning: done.
- Nested splice: accepted as never (R-D4).
- NATed terminal: UTL-04's problem (R-D5).
- Changing `DeriveChallenge` inputs: forbidden (J-D12). Case C/D reuse the same challenge and attestation as setup.

---

## 4. Solutions

### 4.1 Case C — mid-session signature relay

```mermaid
sequenceDiagram
    participant C as originator
    participant J as j1 inbound pump
    participant N as nestedHop.run
    participant S as S (next hop)

    Note over N,S: hop-2 carrier died; nested sendLog still holds unacked bytes
    N->>S: TCP + KEX + RESUME(token₂)
    S->>N: AUTH_OK (stale token; hop=0 on this socket)
    N->>J: request relay (AUTH_OK + attest of this KEX)
    Note over J: reject if inbound SWITCH in flight
    J->>C: TypeAuthOK{hop:2, helloJson, attest, challenge}
    Note over C: verifyRelayedChallenge (same as setup); Sign; never hop=0
    C->>J: TypeAuth{hop:2, sig}
    J->>N: AUTH (hop stripped)
    N->>S: AUTH
    S->>N: RESUME_OK (new token₂, offsets)
    N->>N: serveConn on new carrier from UpAcked
```

**Where AUTH_OK is intercepted.** Do not wait until it hits `netReader` on the nested data pump — that pump's `serveConn` has already returned. Intercept inside the nested resume handshake:

- Extend `writeResumeRole` (or a nested wrapper around it) with an optional `onChallenge func(proto.AuthOK) (proto.Auth, error)` hook.
- When `cfg` has no signer and `TypeAuthOK` arrives, call the hook instead of `completeClientAuth`.
- The hook blocks until the originator answers or `chain_auth_timeout` fires.

`nestedHop` owns the hook. It posts the challenge to the inbound `live` and waits.

**Hop-1 data-plane send (j1 → originator).** The inbound pump is in `serveConn`. Adding a frame type to `netWriter`'s ctrl path is the existing `sendCtrl` seam (`pump.go:526`). Case C sends `TypeAuthOK` that way. Cap outstanding relays per session with `chain_auth_relays_max` (already counted in `negotiateOnward`; reuse the same counter on `live`).

**Hop-1 data-plane receive (originator → j1).** `netReader` default branch today is `ERR_PROTO`. Add:

| Side | Frame | Action |
|---|---|---|
| Originator `netReader` | `TypeAuthOK` with `Hop ∈ 1..N` | `verifyRelayedChallenge` + `Sign` + `sendCtrl(TypeAuth)`. Refuse `Hop==0` on a chained client. |
| Originator `netReader` | `TypeAuthOK` with `Hop==0` | `ERR_PROTO` — hop-1 re-auth stays on the resume handshake, never the data plane. |
| j1 inbound `netReader` | `TypeAuth` with `Hop` matching the outstanding relay | Deliver to the nested waiter; do not treat as session data. |
| Either | `TypeAuthOK`/`TypeAuth` while `p.quiesce` is set (SWITCH in flight) | Fail the relay (timeout/ERR_PROTO). Do not start SWITCH while a relay is outstanding. |

**Quiesce (JR11).** Do **not** reuse `startQuiesce`/`waitQuiesced` for Case C. That machinery parks `netWriter` until ACKs catch `sentOff` so a SWITCH can cut over. Case C does not change the hop-1 carrier. Nested `serveConn` is already down.

What we *do* need:

1. **Mutex with SWITCH on the inbound pump.** One flag, e.g. `live.chainAuthHeld`, set for the duration of the hook. `handleSwitch` returns `ERR_PROTO` (or waits with `switch_timeout` then aborts the switch) if the flag is set. The hook refuses to start if `p.quiesce` is set.
2. **Nested IO keeps running.** `srcReader`/`sinkWriter` on the nested pump continue to fill/drain the pipes and rings. Bytes wait in the nested sendLog. Inbound ACKs still mean “in the nested ring” (I1 weakening / JR3 — unchanged).
3. **Timeout.** `chain_auth_timeout` (default 10s, already on `Server`) wraps the hook. On expiry: fail the nested resume attempt (retry until hold budget), do not wedge hop 1.

**Attestation on Case C.** The nested resume KEX is a *new* transcript. The AUTH_OK from S is bound to *that* KEX nonce (J-D16). Relay `Attest` built from this resume KEX_INIT/KEX_REPLY, same as `negotiateOnward`. Originator must verify again — a rogue j1 must not substitute a cached setup attestation. `verifyRelayedChallenge` already does this; call it.

`HelloJSON` for a resume challenge is the **RESUME payload** S hashed (`resumeAuth` uses `canonical := f.Payload`). Echo that JSON as `AuthOK.HelloJSON`. Originator `verifyRelayedChallenge` already extracts `clientNonce` from `helloJson` and recomputes `DeriveChallenge`. Extend the parser to accept either a HELLO object or a RESUME object (both have `clientNonce`). Destination still has to match.

**Originator RunClient.** Today after HELLO it never calls `completeChainAuth`. Case C needs `netReader` on the *client* pump to sign. That is the same `verifyRelayedChallenge` used at setup. Keep hop-index bounds `1..len(hops)`.

**Failure policy.** If the originator refuses (attestation mismatch, dest mismatch, timeout): nested resume fails, hold budget continues, then `onGone` as today. Do not tear hop 1 down until nested hold expires. A single bad signature is not a reason to kill an otherwise live outer session immediately — but a **policy** refusal (host key) should fail closed and tear down (same as setup). Distinguisher: `errors.Is(err, kex.ErrHostKey)` or `CodeAuth` from `verifyRelayedChallenge` → `onGone`; timeout → retry nested resume.

### 4.2 Case D — rebuild-on-resume

```mermaid
sequenceDiagram
    participant C as originator
    participant J as j1 handleResume
    participant N as nestedHop
    participant S as S

    C->>J: TCP + KEX + RESUME(token₁)
    alt token₁ stale
        J->>C: AUTH_OK hop=1 (no attest; client did this KEX)
        C->>J: AUTH
    end
    J->>J: nested still live?
    alt live (Case A)
        J->>C: RESUME_OK
    else dead
        J->>N: negotiateOnward (or restart nestedHop)
        Note over J,C: same AUTH_OK{hop>1}/AUTH/CHAIN_OK loop as setup, on this resume socket
        J->>C: RESUME_OK
    end
```

**Liveness check.** Before `writeResumeOK` (`server.go:1029`), if `l.nested != nil`:

- nested `termError() == nil` and nested ctx not cancelled and nested `conn != nil` → live. Existing Case A path.
- otherwise → rebuild.

Do this **after** hop-1 token/fallback auth, **before** `RESUME_OK`. A dead nested session must not receive `Offer` until rebuilt.

**Rebuild.** Call the same `negotiateOnward` used at setup (fresh TCP, KEX, Hello/Chain, attestation relay). Inbound conn for the relay is the **resume** `transport.Conn` (still cipher-wrapped, still handshake-phase). Originator `clientResume` / `writeResumeRole` must loop on `TypeAuthOK` with `Hop > 1` and `TypeChainOK` the way `clientChainHello` does, then read `RESUME_OK`.

Do **not** emit a new hop-1 `HELLO_OK`. Token₁ / session id stay. Nested `sessionID` / token₂ / rings: new nested hop, new rings carved from the budget; old nested `close()` first.

**If rebuild fails.** `writeResumeFail(ERR_EXPIRED)` (or `ERR_DEST_REFUSED` if the next hop is down). Originator does not attach to a corpse. `ssh` restarts. That is honest.

**Case C during Case D.** If rebuild's *nested* resume (after Hello) immediately needs Case C, we are still on the hop-1 resume socket, not the data plane. Handle it in the handshake loop, not `netReader`. One relay implementation, two carriers (handshake conn vs data-plane `sendCtrl`).

**Client change.** `writeResumeRole` after sending `RESUME`, today: optional hop-1 `AUTH_OK` then `RESUME_OK`. For a chained client (`len(cfg.Jumphost) > 0`): accept a sequence of `AUTH_OK{hop>1}` / `CHAIN_OK` / hop-1 `AUTH_OK` / `RESUME_OK`. Refuse `AUTH_OK{hop=0}` except as the hop-1 fallback (existing). Reuse `completeChainAuth`.

### 4.3 Per-hop transport + HA (after C and D)

Lift the Phase 1 TCP force.

**Originator hop 1.** Stop rewriting `cfg.Transport` / `AllowHA` in `RunClient` (`client.go:48-60`). `pathCfg` already dials `hops[0]`. Set `pathCfg.Transport` from `hops[0].Transport` if present, else the client's `--tcp/--kcp/transport`. Set `pathCfg.AllowHA` from `hops[0].AllowHA` or `--allow-ha`. Hop 1 then uses the existing upgrade + `standbyManager` path unchanged.

**Hello/Chain preference list.** `ChainHello.Transport` and onward `Hello.Transport` become `chainHopTransport(next)` honouring `next.Transport` (map through `TransportPreferenceList`) instead of `[]string{"tcp"}`. Empty hop transport ⇒ that server's own `transports` (send the originator's global preference, or omit and let the server pick — match today's `Hello.Transport` behaviour).

**Nested runner.** Replace “TCP serveConn + TCP clientResume” with a RunClient-shaped loop: `startUpgrade`, `serveConnWithBFD`, `standbyManager` if `next.AllowHA`. `nestedClientConfig` sets `Transport` and `AllowHA` from the hop spec. `Splice` stays false.

**UDP on a nested leg.** Same as a normal client: after `HelloOK.UDP`, probe, SWITCH. The nested pump is the SWITCH party. Inbound pump is unaware. Do not SWITCH inbound because nested upgraded.

**Case C + upgrade.** Nested resume after KCP: `clientResume` may go UDP (`writeResumeRole` skips KEX on non-TCP). Stale token on UDP resume still yields `AUTH_OK` on that UDP control stream; the hook still relays onto hop-1's (possibly KCP) data plane via `sendCtrl`. Same frames. SWITCH mutex still applies on hop-1.

**Accept paths.** Unchanged: QUIC/KCP still take `RESUME` only. First nested dial remains TCP.

---

## 5. Invariants for remaining work

1. **I6 unchanged.** The bridge is still a copy between two `sessionIO` seams. Case C/D must not introduce a third offset space.
2. **I1 weakening (JR3) unchanged.** j1 ACKs when bytes are in the nested ring, including while Case C is blocked in `writeResumeRole`.
3. **No SWITCH ↔ Case C interleaving.** Exactly one of `{inbound SWITCH, chain-auth relay}` at a time.
4. **Never sign hop 0 on a chained data plane.** Hop-1 re-auth stays on the resume handshake.
5. **J-D16 on every relayed challenge**, including resume KEX. Attestation nonce must equal `AUTH_OK.serverNonce`.
6. **Private key never on an intermediate.** Nested `onChallenge` hook is the only signer path, and it blocks on the originator.
7. **`RESUME_OK` on hop 1 implies nested live** (Case D). No false attach.
8. **Nested splice stays off.** `io.Pipe`, no `Fd()`, `getSinkFD` must not see an OS pipe.

---

## 6. API / code seams (no wire version bump)

`V` stays 1. Frame types 0x0E/0x0F and optional `Auth.Hop` / `AuthOK.{Hop,HelloJSON,Attest}` already exist. Remaining work is dispatch and runner behaviour.

| Seam | Change |
|---|---|
| `writeResumeRole` | Optional `onChallenge` hook when the local authenticator cannot sign. |
| `nestedHop.run` | Provide the hook; on Case C post to `live`. After C/D, speak upgrade/HA. |
| `live` | `chainAuthHeld` flag; method `relayChainAuth(ctx, aok) (Auth, error)` sending AUTH_OK via `sendCtrl` and waiting for AUTH from `netReader`. |
| `pump.netReader` | Client: AUTH_OK hop>0 → sign. Server inbound: AUTH hop>0 → complete relay. Mutex with SWITCH. |
| `handleResume` | Nested liveness check; rebuild via `negotiateOnward` on the resume conn; then `RESUME_OK`. |
| `clientResume` / `writeResumeRole` (originator) | Chained clients accept AUTH_OK hop>1 + CHAIN_OK before RESUME_OK. |
| `RunClient` | Stop forcing TCP/HA off when `-J` is set. |
| `chainHopTransport` / `nestedClientConfig` | Honour hop spec transport and `AllowHA`. `Splice` remains false. |
| `verifyRelayedChallenge` | `helloJson` may be RESUME JSON (has `clientNonce`). |

Config knobs already exist: `chain_auth_timeout`, `chain_auth_relays_max`. No new TOML for remaining phases.

---

## 7. Alternatives considered

**Tear down on Case C (keep Phase 1).** Rejected in interview. Inner hold-expiry would always restart `ssh`, which is the failure mode server-side chaining was meant to avoid on the inner leg.

**Case C only if hop-1 is still TCP.** Rejected. Control frames already flow on QUIC/KCP. Restricting to TCP would make Case C disappear the moment hop-1 upgrades — the common `--kcp` WAN case.

**Fail hop-1 resume if nested is dead, no rebuild.** Rejected. Honest, but a simultaneous blip on both legs (JR2) becomes an `ssh` restart when the client is *right there* and can sign. Rebuild is the whole point of J-D1 once Case C exists.

**Per-hop transport before Case C.** Rejected (R-D7). KCP on a nested leg whose stale-token path still kills the chain is a false win. Transport plugs into `nestedHop.run` after that loop can survive AUTH_OK.

**OS-pipe bridge + splice.** Rejected (R-D4). `getSinkFD` falling back to `src`/`sink` is exactly why Phase 1 used `io.Pipe`. Splice is a LAN 10G CPU optimisation; jumphosts are WAN-bound; Case C is the correctness work.

**`trusted_relays` for OriginIP.** Rejected (R-D6). A compromised j1 can already DoS. Per-peer cap is enough.

---

## 8. Security

Case C/D do not weaken J-D2/J-D3/J-D16:

- Each inner re-auth is a **new** server-chosen challenge. Relayed signatures remain single-use and destination-bound.
- Resume KEX attestation is fresh. A cached setup `KexReply` cannot satisfy J-D16 against a new `AUTH_OK.serverNonce`.
- `chain_auth_relays_max` (default 8) bounds a compromised j1 using Case C as a signing oracle. `auth_fail_delay` still applies on the server that verifies.
- Mid-session `TypeAuthOK` with `Hop==0` is rejected on a chained originator so a rogue frame cannot trigger hop-1 signing outside the resume handshake.
- OriginIP policy unchanged (R-D6).

---

## 9. Observability

Existing expvars stay. Case C/D should increment:

- `chain_auth_relays` — every mid-session or resume-rebuild relay (already incremented in setup `negotiateOnward`).
- `chain_attest_failures` — originator or intermediate attestation reject during C/D.
- `chain_gone` — only when nested hold expires *after* Case C retries are exhausted, not on a successful rebuild.

Logs (never tokens): `chainId`, `hop`, `upstream`, `chainAuth="relay|timeout|rebuilt"`.

---

## 10. Tests (remaining)

Phase 1 tests in `chain_test.go` stay. Add:

| Test | Asserts |
|---|---|
| `TestChainResumeInnerHopOnly` | Kill hop-2 carrier; originator never re-auths; byte-exact (Case B, still missing as an explicit test). |
| `TestChainStaleTokenInnerRelaysSignature` | Force nested `ERR_BAD_TOKEN`; originator sees one `TypeAuthOK{hop>1}` on the data plane; stream continues (Case C). |
| `TestChainResumeBothHops` | Drop both carriers within 100 ms; hop-1 resume rebuilds nested; byte-exact (Case D). |
| `TestChainCaseCDuringSwitchRejected` | SWITCH in flight + Case C → relay fails or switch aborts; no offset gap (JR11). |
| `TestChainCaseCAttestationReplay` | Nested resume AUTH_OK with mismatched nonce → originator refuses; chain fails closed. |
| `TestChainPerHopTransport` | hop 1 KCP, hop 2 TCP (or hop 1 TCP, hop 2 KCP); each upgrade independent. |
| `TestChainNestedHA` | `?ha=1` on hop 2; nested standby promotes; originator idle. |
| `TestChainConcurrencyLeak` | Raise from 8 toward 64 once C/D exist. |

Netns `scripts/test_jumphost_netns.py`: implement the skipped JUMP-03 (inner kill), JUMP-04 (simultaneous), JUMP-05 (KCP leg). JUMP-01/02/06/07 already sketched.

---

## 11. Rollout

No protocol version bump. Old intermediates without Case C still tear down on stale inner tokens (Phase 1 behaviour) — fail closed, not fail open. Originators that cannot handle mid-session `TypeAuthOK` will `ERR_PROTO` on Case C; document that chained clients must be upgraded before relying on inner hold.

Per-hop transport is similarly additive: old intermediates ignore `transport=` (Phase 1). New intermediates honour it.

Rollback: `chain_auth_timeout` does not disable Case C. If we need a kill switch, a server `chain_relay_mid_session = false` defaulting **on** is optional; not required for v1 of remaining work. Prefer shipping C/D always-on behind the existing timeout.

---

## 12. Key decisions

1. **Case C is mid-session frame relay, not a new handshake.** Hook `writeResumeRole`; carry AUTH_OK/AUTH on hop-1 via `sendCtrl`/`netReader`. Same `verifyRelayedChallenge` as setup.
2. **Do not reuse SWITCH quiesce for Case C.** Mutex against SWITCH; leave nested rings running.
3. **Case D is “no RESUME_OK until nested live”, with rebuild using the resume socket as the Case C carrier.** Fail the resume if rebuild fails.
4. **Full J-D4 after C/D.** Nested runner becomes RunClient-shaped. Originator stops forcing TCP.
5. **Nested splice is never.** JR7 accepted.
6. **Phase 3 and OriginIP policy unchanged.**
7. **Order: C, then D, then transport+HA.**

---

## 13. Open questions

None that block writing code. Engineering choices implementers may take without another interview:

- Hook signature on `writeResumeRole` vs a `nestedResume()` wrapper that duplicates the AUTH_OK branch. Prefer a hook to avoid forking PERF-03.
- SWITCH vs Case C: fail the switch vs fail the relay. Prefer **fail the relay and let nested hold retry** if SWITCH is already quiescing — SWITCH is user-visible path change and should complete.
- Rebuild vs resume-nested-only in Case D when nested ctx is cancelled but token₂ might still be valid at S: **try nested `clientResume` first** (cheap Case B), rebuild only if that returns `ERR_UNKNOWN_SESSION` / `ERR_EXPIRED` / non-reconnectable. Stale token during that attempt **is** Case C on the hop-1 resume socket.

---

## 14. PR Plan

### PR 1: Case C — mid-session inner re-auth
- **Files:** `internal/relay/upgrade.go` (`onChallenge` hook), `chain_nested.go`, `chain.go` (`live.relayChainAuth`), `pump.go` (`netReader` AUTH_OK/AUTH + SWITCH mutex), `client.go` / `client_chain.go` (originator data-plane sign), `chain_test.go`
- **Dependencies:** none (Phase 1)
- **Description:** Nested stale-token resume relays AUTH_OK to the originator on hop-1, waits for AUTH, completes inner RESUME. Timeout and attest-fail behaviour as §4.1. Tests: `TestChainStaleTokenInnerRelaysSignature`, `TestChainCaseCDuringSwitchRejected`, `TestChainCaseCAttestationReplay`.

### PR 2: Case D — rebuild-on-resume
- **Files:** `internal/relay/server.go` (`handleResume` nested liveness), `chain.go` (`negotiateOnward` from a resume conn), `upgrade.go` / `client.go` (chained `writeResumeRole` loop), `chain_test.go`
- **Dependencies:** PR 1 (handshake-time relay is the same hook; data-plane Case C must already exist so a rebuild that immediately stale-tokens does not regress)
- **Description:** Hop-1 `RESUME_OK` only if nested live. Else try nested resume, else `negotiateOnward`, else `RESUME_FAIL`. Test: `TestChainResumeBothHops`. Also add `TestChainResumeInnerHopOnly` (Case B) if not already landed in PR 1.

### PR 3: Per-hop transport + HA
- **Files:** `internal/relay/client.go` (stop TCP force), `chain.go` (`chainHopTransport`, `nestedClientConfig`), `chain_nested.go` (upgrade + standby loop), `chain_test.go`, `scripts/test_jumphost_netns.py` JUMP-03/04/05
- **Dependencies:** PR 2 (nested runner must survive AUTH_OK before we put KCP under it)
- **Description:** Honour `?transport=` / `?ha=1`. Nested RunClient-shaped loop. Tests: `TestChainPerHopTransport`, `TestChainNestedHA`. Enable JUMP-03/04/05 in the netns harness.

### PR 4: Docs
- **Files:** `.feat-impl/FEAT-UTL-05.md` (mark Phase 2 done except splice/Phase 3), `README.md` (remove “TCP-only” caveat; keep JR3), `features.md`, `wip.md`, this file's status
- **Dependencies:** PR 3
- **Description:** Document Case C/D and per-hop transport as implemented. Nested splice remains deferred. Phase 3 still UTL-04.

---

## References

- [`.feat-impl/FEAT-UTL-05.md`](.feat-impl/FEAT-UTL-05.md) — Phase 1 spec (J-D1…J-D16, JR1…JR11, §2.10 Cases A–D)
- [`jumphost_plan.md`](jumphost_plan.md) — original plan
- [`jump_todo.md`](jump_todo.md) — Phase 1 execution ledger
- [`design.md`](design.md) §3 D11–D16, §7.1 I6, §15 JR1–JR11
- [`internal/relay/chain_nested.go`](internal/relay/chain_nested.go) — nested runner (token-only resume)
- [`internal/relay/upgrade.go`](internal/relay/upgrade.go) `writeResumeRole` — AUTH_OK branch to hook
- [`internal/relay/pump.go`](internal/relay/pump.go) `netReader` / `startQuiesce` / `handleSwitch`
- [`.feat-impl/FEAT-PERF-01.md`](.feat-impl/FEAT-PERF-01.md) — why nested splice is not “splice two TCPs”
- [`.feat-impl/FEAT-PERF-03.md`](.feat-impl/FEAT-PERF-03.md) — token resume vs cryptographic fallback (the AUTH_OK Case C intercepts)
