# FEAT-UTL-05: Multi-Hop Jumphost Chaining (`-J`)

**Status:** Implemented (Phase 1 + cheap Phase 2). Mid-session inner-hop re-auth (Case C), rebuild-on-resume (Case D), per-hop QUIC/KCP/HA, and nested `splice(2)` are deferred.
**Target packages:** `cmd/relay`, `internal/relay`, `internal/proto`, `internal/auth`, `internal/config`, `internal/crypto/kex`
**Date:** 2026-09-15

> Promoted from `jumphost_plan.md`. Decisions J-D1…J-D16 are folded into
> `design.md` §3 as D11+; invariant I6 is in §7.1; JR1–JR11 are in §15.

---

## 1. Executive summary

Today the relay is strictly two-party: `client → server → destination`. This plan
adds **server-side chaining** so a client can reach a relay server it cannot dial
directly:

```
client ──hop 1──► j1 ──hop 2──► j2 ──hop 3──► S ──► 127.0.0.1:22 (sshd)
```

The client names the intermediates with an OpenSSH-compatible `-J`; `--server`
remains the **terminal** relay, the one that dials `sshd`:

```
relay client --server S.example.com:7443 -J j1.example.com:7443,j2.example.com:7443 --dest %h:%p
```

**The defining property:** every hop is a *full, independent relay session* —
its own X25519 KEX, its own `resumeToken`, its own ring buffer, its own BFD
heartbeats, its own QUIC/KCP upgrade, its own `--allow-ha` standby. A break on
hop 1 is invisible to hop 2 and to `sshd`; a break on hop 2 is invisible to the
client. This is what distinguishes the feature from what already works today
(`ssh -R` carrying an opaque session, per `relay_feedback.md` §2 and
`features.md:217-223`).

**The hard part is authentication.** Only the client holds the private key, and
the auth challenge is destination-bound
(`internal/auth/auth.go:71-82`), so each hop needs its own signature over its own
transcript. The design resolves this with a **relayed signature** plus a **KEX
attestation relay**, so that the private key never leaves the client *and* the
client cryptographically verifies every hop's host key — without the client being
the KEX party on any hop but the first.

**Backwards compatibility is strong:** the terminal server never has to
*understand chaining*. It needs exactly one additive change — reusing its KEX
`serverNonce` as its auth `serverNonce` (J-D16) — so that the attestation the
client verifies is cryptographically bound to the challenge it signs. An old
server that receives a chained handshake fails closed (`ERR_PROTO`), never
silently downgrades to a direct dial.

> **⚠ Confirmed defect found while planning (J-D16 / JR1).** The two nonces are
> *not* the same value today: `kex.go:159-161` generates the KEX `serverNonce`,
> while `server.go:1270` and `server.go:1309` generate the auth `serverNonce`
> independently via `proto.RandomNonce()`. Without J-D16 the attestation relay
> in §2.5 is unsound. This is the first thing Phase 1 implements.

### 1.1 Decisions taken (from the design interview)

| # | Decision | Chosen | Rejected alternative | Why |
|---|---|---|---|---|
| **J-D1** | Chain model | **Server-side chaining** — each intermediate embeds a relay *client* toward the next hop and fully terminates that hop's data plane. | Client-side nesting (client runs session B inside session A). | Per-hop resume, per-hop KCP, per-hop BFD/HA. Nesting makes hop 2 TCP-only forever and doubles buffering in the client. |
| **J-D2** | Onward auth | **Relayed signature** — the next hop's fresh challenge travels back over the already-authenticated hop-1 channel; the client signs; the intermediate forwards. | Client-issued chain credential; shared inter-server secret. | Private key never leaves the client; intermediates gain nothing reusable (challenge is server-chosen, single-use). A shared secret would let a compromised j1 impersonate any client to j2. |
| **J-D3** | Hop host keys | **Client verifies every hop**, via a **KEX attestation relay**. | Intermediate verifies and merely reports the fingerprint. | A rogue j1 must not be able to MITM hop 2 or redirect the client into signing for a different server. |
| **J-D4** | Per-hop transport | **Client picks transport for every hop.** | Each hop uses its own server config; or UDP on hop 1 only. | The operator knows which leg is bad. A lossy middle leg must be able to get KCP. |
| **J-D5** | Chain depth | **N-hop**, OpenSSH-compatible `-J a,b,c`, `max_chain_depth` default 4, loop detection. | Single jumphost only. | Generalising now is cheaper than retrofitting a depth field. |
| **J-D6** | Hop-2 topology | **Phase 1–2: the intermediate dials onward.** A NATed terminal that must dial *out* is Phase 3 and depends on FEAT-UTL-04. | Support both now. | UTL-04's rendezvous agent does not exist in the tree. |
| **J-D7** | Phasing | **Three phases** (§6). | One big increment. | The tree already carries uncommitted FEAT-PERF-01/02 work. |

### 1.2 Decisions made by the author (not asked; recorded for review)

| # | Decision | Rationale |
|---|---|---|
| **J-D8** | Chaining is **default-deny** on every server. A new `allow_relay_hops` list must name permitted next hops; empty ⇒ `ERR_DEST_FORBIDDEN`. | Mirrors `allow_destinations` (`config.go:593`). Without it, any authenticated client could turn a relay into an open chaining proxy and DoS amplifier. |
| **J-D9** | An intermediate enforces `allow_relay_hops` against **every remaining hop** in the path, not just the next one. | j1 sees the whole path; refusing early beats refusing three hops in after resources are committed. |
| **J-D10** | New **frame types** `0x0E TypeChain` / `0x0F TypeChainOK`, *not* optional fields on `Hello`. | `ReadFrame` returns `ErrProto` on an unknown type (`codec.go:39`), so a v1 server **fails closed**. An optional `Hello.Chain` field would be silently ignored by `encoding/json` and the server would dial `127.0.0.1:22` on itself — a fail-open, which is the worst possible outcome here. |
| **J-D11** | `V` stays `1`. Chaining is signalled by frame type, not by a version bump. | `V` is equality-checked (`server.go:341`, `server.go:531`); bumping it would break every existing peer for a feature most sessions do not use. |
| **J-D12** | `DeriveChallenge`'s **inputs are unchanged**; the attestation is bound to the challenge by nonce reuse instead (J-D16). | Avoids a versioned crypto change and avoids a new `AuthOK` field that an untrusted intermediate could strip. |
| **J-D13** | `splice(2)` is **disabled** on a nested leg in Phase 1–2. | `getSrcFD`/`getSinkFD` (`pump.go:143-176`) need a real `*net.TCPConn`; a nested relay stream is a `transport.Conn`. Phase 2 may re-enable it when the nested carrier is TCP and exposes `RawTCPConn()` (`transport/conn.go:42`). |
| **J-D14** | Originating client IP is propagated as `OriginIP` in `ChainHello`; intermediates apply `max_conns_per_ip` against it. | Without this, **every** chained session arrives at j2 from j1's single IP and trips `max_conns_per_ip = 8` almost immediately. See **JR4**. |
| **J-D15** | Half-close on a nested leg maps `CloseWrite()` → `CLOSE_DIR{up, finalOffset}`. | The nested destination has no TCP FIN to send. `sessionIO.closeWrite` (`pump.go:33-44`) is already a function hook, so this is a substitution, not a refactor. |
| **J-D16** | **Reuse the KEX `serverNonce` as the auth `serverNonce`.** Thread the value out of `kex.ServerSession.ProcessInit` into `helloAuth`/`resumeAuth`, replacing the independent `proto.RandomNonce()` calls at `server.go:1270` and `server.go:1309`. | `ExchangeHash` already covers `serverNonce` (`kex.go:27-33`) and is signed by the server's host key. `DeriveChallenge` also covers `ServerNonce` (`auth.go:71-82`). Making them the *same* value binds the attestation to the challenge with no format change. Both roles are **public** values, so reuse costs nothing cryptographically — a nonce only needs freshness and uniqueness, which still hold. Wire-compatible: existing clients just see a different opaque 16-byte value. |

---

## 2. Technical architecture

### 2.1 The seam being used

Two existing facts make this tractable:

1. The destination dial is concrete — `net.Dialer.DialContext(ctx, "tcp", dest)`
   at `internal/relay/server.go:395-409` — but the pump consumes it through an
   `io.Reader`/`io.Writer` seam, `sessionIO` (`internal/relay/pump.go:33-44`,
   wired at `server.go:461-471`). **A nested relay session can present itself as
   that seam** without touching the pump's goroutine model (design.md §9).
2. `RunClient` (`internal/relay/client.go:32`) already contains a complete
   reconnect/resume loop with backoff and budget clamping (`client.go:130-274`).
   **An intermediate reuses it verbatim** as its onward-hop driver.

What must be added is the control-plane plumbing: chain negotiation, KEX
attestation relay, and signature relay.

### 2.2 Roles

| Role | Who | Behaviour |
|---|---|---|
| **Originator** | `relay client -J …` | Dials hop 1. Sends `TypeChain`. Verifies every hop's attestation. Signs every hop's challenge. Owns hop-1 resume. |
| **Intermediate** | `relay server` with `allow_relay_hops` non-empty | Terminates the inbound hop. Dials `Hops[0]`. Performs the onward KEX **itself**. Relays attestation back, challenge back, signature forward. Terminates the outbound hop's data plane with its own ring/resume/BFD. |
| **Terminal** | `relay server` — needs **J-D16 only** | Sees an ordinary `TypeHello`. Issues an ordinary challenge. Dials `Destination` (`sshd`). Knows nothing about chaining. |

### 2.3 Path semantics

`Hops` in a `ChainHello` lists the relay servers **after the receiver**, with the
terminal server last. `Destination` is what the *terminal* dials. Each
intermediate strips itself and forwards the tail.

```
-J j1,j2   --server S   --dest 127.0.0.1:22

  client → j1 :  ChainHello{ Hops:[j2, S], Destination:"127.0.0.1:22" }
  j1     → j2 :  ChainHello{ Hops:[S],     Destination:"127.0.0.1:22" }
  j2     → S  :  Hello     {               Destination:"127.0.0.1:22" }   ← plain v1
```

When the tail is empty the sender emits an ordinary `Hello`, which is why the
terminal requires no changes.

### 2.4 Setup sequence (single jumphost, the general case recurses)

```mermaid
sequenceDiagram
    participant C as client (originator)
    participant J as j1 (intermediate)
    participant S as S (terminal; J-D16 only)
    participant D as sshd 127.0.0.1:22

    C->>J: TCP dial
    C->>J: KEX_INIT (0x0B)
    J->>C: KEX_REPLY (0x0C) — C verifies j1 host key
    Note over C,J: hop-1 AEAD channel up (ChaCha20-Poly1305)

    C->>J: TypeChain (0x0E) {ChainID, Hops:[S], Destination, OriginIP, Transport, ClientNonce, Auth offer}
    J->>J: policy: len(Hops)+1 ≤ max_chain_depth?<br/>allow_relay_hops ⊇ Hops?<br/>ChainID ∉ Visited?
    J->>S: TCP dial

    J->>S: KEX_INIT (j1's own ephemeral key + nonce)
    S->>J: KEX_REPLY {serverEph, serverNonce, hostKey, sig}
    Note over J: j1 verifies S against j1's known_hosts<br/>j1 derives hop-2 AEAD keys

    J->>S: Hello{Destination} (encrypted, on hop-2 channel)
    S->>J: AuthOK{SessionID, ServerNonce, Challenge, Destination}

    J->>C: AuthOK (relayed) {Hop:2, Challenge, Destination,<br/>Attest:{KexInit, KexReply, HostKeySSH}, HelloJSON}
    Note over C: 1. verify S host key ∈ client known_hosts / -J pin<br/>2. verify Ed25519 sig over ExchangeHash(KexInit,KexReply)<br/>3. check Attest.serverNonce == AuthOK.ServerNonce  ← holds only after J-D16<br/>4. check AuthOK.Destination == requested<br/>5. recompute digest from HelloJSON, compare to Challenge
    C->>J: Auth (relayed) {Hop:2, Sig}
    J->>S: Auth{Sig}
    S->>S: Verify against authorized_keys (same key on all servers)
    S->>D: net.Dialer.DialContext("tcp", "127.0.0.1:22")
    S->>J: HelloOK{SessionID, ResumeToken₂, Limits, UDP}

    J->>C: TypeChainOK (0x0F) {Hop:2, SessionID, ResumeToken₂ (opaque to C), Limits, UDP}
    J->>C: HelloOK (hop 1) {SessionID, ResumeToken₁, Limits, UDP}

    par hop-1 data plane
        C-->>J: PROBE / SWITCH / DATA (KCP per -J hop-1 transport)
    and hop-2 data plane
        J-->>S: PROBE / SWITCH / DATA (transport per -J hop-2 spec)
    end
    S-->>D: bytes
```

**Cost:** roughly **+2 RTT per additional hop** at setup (challenge out, signature
back), on top of the TCP dial and KEX that hop already needs. See **JR6**.

### 2.5 Why the attestation is sound

`ExchangeHash = SHA256(clientEph ‖ serverEph ‖ clientNonce ‖ serverNonce ‖ serverHostKey)`
(`internal/crypto/kex/kex.go:28`), signed by the server's Ed25519 host key
(`kex.go:172`).

The client cannot derive hop-2's AEAD keys — it has no ephemeral private key for
that hop, j1 generated it. But it does not need to. It can recompute
`ExchangeHash` from the relayed `KexInit` (j1's ephemeral + nonce) and `KexReply`
(S's ephemeral + nonce + host key + signature), and verify the signature against
a host key it recognises from **its own** `known_hosts`. That proves:

> *the holder of the private key matching the expected host key for S signed a
> transcript containing this specific `serverNonce`.*

**Binding the attestation to the challenge (J-D16).** Proving "the real S signed
*some* transcript" is not enough. The client must know that the challenge it is
about to sign came from *that same* S session. Otherwise a rogue j1 can:

1. open a genuine KEX with the real S and harvest a valid `KexReply`,
2. never send S a `Hello` at all,
3. relay the genuine attestation to the client together with a **fabricated**
   `AuthOK` of its own choosing,
4. collect the client's signature — and replay it against any other relay that
   trusts the same `authorized_keys` (which, by assumption, is all of them).

This is the classic agent-forwarding hazard, and the attestation is precisely
what closes it — *if and only if* the attestation and the challenge are bound.

The binding is available for free. `ExchangeHash` already covers `serverNonce`
(`kex.go:27-33`) and is signed by S's host key; `DeriveChallenge` already covers
`ServerNonce` (`auth.go:71-82`). **They must be the same 16 bytes.**

> **Confirmed: today they are not.** The KEX nonce is generated at
> `kex.go:159-161`; the auth nonce is generated independently by
> `proto.RandomNonce()` at `server.go:1270` (HELLO) and `server.go:1309`
> (RESUME). The attack above is therefore live against the naive design.

**Fix (J-D16):** return the KEX `serverNonce` from `ProcessInit` and use it as the
auth `serverNonce` in both `helloAuth` and `resumeAuth`. This is safe because both
uses are **public** values — the KEX nonce is transmitted in the clear inside
`KexReply` at bytes `[32:48]` (`kex.go:187`), and the auth nonce is sent inside
`AuthOK`. A nonce only requires freshness and uniqueness, and reusing one public
value in an HKDF salt and in a SHA-256 preimage creates no cross-protocol
weakness. It is also wire-compatible: existing clients simply observe a different
opaque value.

With J-D16 in place a replayed attestation carries a stale `serverNonce`, which
cannot match a fresh `AuthOK.ServerNonce`, and the fabricated-challenge attack
fails at step 3.

What the client does *not* get: forward secrecy against j1 on hop 2. j1 holds
hop-2's AEAD keys and is a MITM on hop-2 plaintext **by construction**. That is
acceptable because (a) j1 already sees the entire SSH ciphertext stream as the
hop-1 destination today, and (b) the payload is an end-to-end authenticated and
encrypted SSH session — the relay's host-key verification protects the *tunnel*,
while `ssh`'s own host-key check protects the *endpoint*. Chaining does not
weaken either; it just means j1 is trusted with tunnel plaintext it was always
trusted with.

### 2.6 Steady state and failure composition

```
                     ┌── hop-1 session ──┐   ┌── hop-2 session ──┐
  ssh ⇄ client stdio │ ring · BFD · KCP  │ j1│ ring · BFD · KCP  │ S ⇄ sshd
                     │ token₁ · hold₁    │   │ token₂ · hold₂    │
                     └───────────────────┘   └───────────────────┘
```

| Event | Who notices | What happens | Does `ssh` see it? |
|---|---|---|---|
| client↔j1 carrier dies | j1's hop-1 pump (`ErrDeadPeer` via BFD, ≤ 2.25 s) | j1 starts `hold₁`; **the nested hop-2 session keeps running and keeps BFD-ing S**. Client re-dials j1, `RESUME` with token₁. | **No** |
| j1↔S carrier dies | j1's nested client (`RunClient` resume loop) | j1 re-dials S, `RESUME` with token₂ — **PERF-03 fast path, no client involvement**. S holds the `sshd` socket across it. | **No** |
| j1 process exits | client | `RESUME` ⇒ `ERR_UNKNOWN_SESSION`. j1 held the only connection to S, so hop 2 is gone too. Client exits non-zero; `ssh` restarts. | **Yes** — see **JR3** |
| S process exits | j1's nested client | `ERR_UNKNOWN_SESSION`; the `sshd` socket is gone. j1 propagates `BYE` inbound. | **Yes** (unavoidable; same as today) |
| `hold₂` expires while client is away | S | S tears down; j1's nested resume budget is clamped to `HoldTimeoutMs` from `HelloOK` (`client.go:139-144`) so it gives up at the same moment. | **Yes** |

**New invariant to state explicitly:**

> **I6 — Chain composition.** A chained relay delivers exactly-once into `sshd`
> if and only if every hop independently satisfies I1–I3 (design.md §7.1). The
> bridge at an intermediate is a straight copy between two `sessionIO` seams; it
> adds no reordering, no deduplication and no loss of its own.

**Where I1 weakens.** I1 says "ACK means durable — the server emits `ACK{up}`
only after `Write` to the destination has returned." At an intermediate, "the
destination" is the *nested ring*. j1 therefore ACKs hop-1 bytes once they are
buffered for S, not once S has them. If j1 crashes, ACKed bytes are lost. A
direct hop does not have this exposure (its destination is a real `sshd` socket).
This is **JR3** and is inherent to server-side chaining; document it rather than
paper over it.

### 2.7 `hold_timeout` coordination

Generalises R7 (design.md §15) from one hop to N:

```
client.reconnect_max_elapsed  ≥  hold₁
j1.nested reconnect budget    ≤  hold₂      (already auto-clamped, client.go:139-144)
Σ holdᵢ over all hops         <  sshd ClientAliveInterval × ClientAliveCountMax
```

The last line is the one operators will get wrong. A 3-hop chain with 5 m holds
each can park a session for 15 m in the worst case, which will exceed most
`sshd` alive budgets. **Phase 1 must log the summed worst-case hold at client
startup** and warn when it exceeds a configurable `sshd_alive_budget`.

### 2.8 Per-hop transport (J-D4)

`-J` entries carry an optional query suffix; the terminal hop keeps using
`--tcp` / `--kcp` / `transport` exactly as today.

```
-J 'j1.example.com:7443?transport=kcp&ha=1,j2.example.com:7443?transport=tcp#SHA256:AbC…'
```

| Token | Meaning |
|---|---|
| `user@host:port` | Address. `user` maps to that hop's `auth_user` (all hops share one key today, so it is informational). |
| `?transport=quic\|kcp\|tcp` | Preference for the hop **into** that server. Empty ⇒ that server's own `transports`. |
| `?ha=1` | `--allow-ha` for that hop. |
| `#SHA256:…` | Inline host-key pin for that hop; short-circuits `known_hosts` and removes the TOFU window entirely (the posture `relay_feedback.md` §6.2 recommends for unattended tunnels). |

Every hop still handshakes over TCP first — the QUIC/KCP accept paths only take
`TypeResume` (`internal/relay/udp.go:172,208`) — so per-hop transport selection
is a per-hop *upgrade* decision, not a per-hop dial decision.

### 2.9 Wire format additions

```
0x0E  TypeChain     C→S   JSON ChainHello
0x0F  TypeChainOK   S→C   JSON ChainHelloOK
```

`0x09 TypeAuth` / `0x0A TypeAuthOK` are **extended with optional fields**, which
is safe because they only carry chain semantics after a `TypeChain` has been
accepted (J-D10).

```jsonc
// C→S  TypeChain — sent instead of TypeHello when -J is non-empty
{
  "v": 1,
  "chainId":     "…",            // base64 16B, client-generated; correlation + loop detection
  "hops": [                      // relay servers AFTER the receiver; terminal last
    { "addr": "j2.example.com:7443", "transport": "kcp", "allowHa": true,
      "fp": "", "user": "" },
    { "addr": "S.example.com:7443",  "transport": "tcp", "allowHa": false,
      "fp": "SHA256:…", "user": "alice" }
  ],
  "destination": "127.0.0.1:22", // what the TERMINAL dials
  "visited":     [],             // each intermediate appends its own listen addr
  "originIp":    "203.0.113.9",  // J-D14, for max_conns_per_ip at intermediates
  "transport":   ["quic","kcp"], // preference for THIS hop (into the receiver)
  "clientNonce": "…",
  "auth":        {},             // existing Offer shape
  "window":      4194304,
  "sessionId":   "",             // non-empty only on a chained RESUME
  "resumeToken": ""
}

// S→C  TypeChainOK — one per completed onward hop, then a normal HelloOK for hop 1
{
  "v": 1, "hop": 2, "addr": "S.example.com:7443",
  "sessionId": "s-…", "transport": "kcp",
  "limits": { "bufferBytes": 67108864, "holdTimeoutMs": 300000, … },
  "udp": { … }                   // informational; the client cannot use it
}

// S→C  TypeAuthOK — existing struct, plus:
{
  "sessionId": "…", "serverNonce": "…", "challenge": "…", "destination": "…",
  "hop": 2,                      // NEW, 0/absent = this hop (back compatible)
  "helloJson": "…",              // NEW: canonical HELLO/ChainHello the receiver sent upstream
  "attest": {                    // NEW: absent for hop 1, where the client did the KEX itself
    "addr":      "S.example.com:7443",
    "kexInit":   "…",            // base64 48B  — dialer's clientEph ‖ clientNonce
    "kexReply":  "…",            // base64 144B — serverEph ‖ serverNonce ‖ hostKey ‖ sig
    "hostKeySsh":"…"             // base64 SSH wire-format pubkey, for known_hosts matching
  }
}

// C→S  TypeAuth — existing struct, plus:
{ "sig": "…", "hop": 2 }         // NEW
```

`hostKeySsh` is needed because `KexReply` carries a **raw 32-byte** Ed25519 key
while `known_hosts` matching needs the `ssh-ed25519 AAAA…` wire form, and because
non-standard ports use `[host]:port` patterns. A helper belongs in
`internal/crypto/kex/hostkey.go` next to `VerifyKnownHosts` (`hostkey.go:161`).

New error codes: `ERR_CHAIN_TOO_LONG`, `ERR_CHAIN_LOOP`, `ERR_HOP_FORBIDDEN`.
These extend `internal/proto/errors.go:3-15` alongside `ERR_DEST_FORBIDDEN`.

### 2.10 Resume across a chain

**Case A — outer hop breaks (common).** Client `RESUME`s hop 1 with token₁. j1's
nested session to S was never disturbed. Normal PERF-03 fast path; if the token
is stale, j1 issues a hop-1 challenge and the client signs it — exactly today's
behaviour. No chain re-negotiation.

**Case B — inner hop breaks (common).** j1's nested client `RESUME`s hop 2 with
token₂. **The client is not involved at all** on the PERF-03 fast path. This is
the main operational win of J-D1 over client-side nesting.

**Case C — inner token stale, needs a signature (rare, and the tricky one).** j1
must relay S's fresh challenge back to the client. But after the "Option A clean
phase cut" the hop-1 TCP control connection is closed and `TypeData` flows on the
carrier. Control frames (`SWITCH`, `BYE`, `CLOSE_DIR`, `PING`) already flow
mid-session on the carrier, so `TypeAuthOK`/`TypeAuth` can too — but
`netReader`'s dispatch (`internal/relay/pump.go:951`) does not handle them today.

> **Work item:** teach `netReader` to accept a mid-session `TypeAuthOK{hop>0}`,
> quiesce the nested pump, surface the challenge to the originator, await
> `TypeAuth{hop}`, and resume. Bounded by a new `chain_auth_timeout` (default
> 10 s) so a silent client cannot wedge an intermediate.

**Case D — both hops break simultaneously.** If the outer carrier is down, the
relayed-signature path for the inner hop has no channel. The inner hop cannot
re-authenticate and dies. The client then sees a hop-1 resume succeed into a dead
chain, or a `BYE`. **JR2.** Mitigation: on a chained resume, j1 re-validates that
its nested session is still live before answering `RESUME_OK`; if it is not, j1
rebuilds the whole onward chain as part of the resume, using the client's
presence on hop 1 to relay fresh signatures.

### 2.11 Limits, memory and capacity

| Resource | Direct session | Chained session at an intermediate |
|---|---|---|
| Rings | 2 (up, down) | **4** (in-up, in-down, out-up, out-down) |
| Worst-case ring memory | 2 × `buffer_bytes` = 128 MiB | **4 × `buffer_bytes` = 256 MiB** |
| `max_sessions` slots | 1 | 1 (but see below) |
| Goroutines (design.md §9) | 5 + supervisor | **10 + 2 supervisors** |

Every nested ring is allocated with `session.NewRing(bufCap, s.budget)`
(`server.go:459`) so the global `total_buffer_bytes` ceiling is respected
automatically and exhaustion still refuses-new rather than kills-existing
(design.md §7.3). But the practical effect is that **`max_sessions` overstates
chained capacity by ~2×**. Phase 1 should add a `chain_max_sessions` (default
`max_sessions / 4`) so an operator cannot be surprised.

**`max_conns_per_ip` (J-D14, JR4).** All chained traffic arrives at j2 from j1's
one address. With the default of 8, the ninth chained session is refused even
though it comes from a distinct human. `OriginIP` fixes the accounting; a
separate `max_chain_conns_per_peer` (default 256) bounds what one upstream relay
may open, so a compromised j1 cannot exhaust j2.

---

## 3. Component changes

### 3.1 `internal/proto`

- `proto.go`: add `TypeChain 0x0E`, `TypeChainOK 0x0F`; extend `Known()` (:56)
  and `String()` (:70).
- `messages.go`: add `ChainHello`, `ChainHelloOK`, `HopSpec`, `HopAttestation`;
  add optional `Hop int` + `Attest *HopAttestation` + `HelloJSON string` to
  `AuthOK` (:48); add optional `Hop int` to `Auth` (:42).
- `errors.go`: add `ERR_CHAIN_TOO_LONG`, `ERR_CHAIN_LOOP`, `ERR_HOP_FORBIDDEN`
  with sentinels and `Is()` support (:22-60).

### 3.2 `internal/crypto/kex`

- `hostkey.go`: new `RawEd25519ToAuthorizedKeysLine(pub []byte) (string, error)`
  and `VerifyAttestation(kexInit, kexReply []byte, knownHosts, pin, addr string) error`
  — recompute `ExchangeHash` (`kex.go:28`), verify the Ed25519 signature, then
  match the host key against `known_hosts` (with `[host]:port` patterns) or the
  inline pin. Must **fail closed** when `knownHostsPath == ""` — the fix already
  landed per `wip.md` §1; do not regress it here.
- **`kex.go` (J-D16):** `ServerSession.ProcessInit` (:172) currently returns
  `(replyPayload, c2sKey, s2cKey)`. Add the `serverNonce` it generated at
  :159-161 to the return set (or expose a `ServerNonce() []byte` accessor on
  `ServerSession`) so `internal/relay` can reuse it as the auth nonce. Also expose
  the `ExchangeHash` for logging/attestation assembly.
- No change to `DeriveKeys`, `CipherConn` or the `ExchangeHash` construction
  itself (J-D12).

### 3.3 `internal/auth`

- `auth.go`: **no change to `DeriveChallenge` (:71-82)** — the attestation
  binding is achieved by nonce reuse (J-D16), not by a new input term.
- `ssh.go`: `Verify` (:135) needs no change — an intermediate presents a normal
  signature over a normal challenge. `loadSigners` (:250-338) is reused by the
  originator for every hop.

### 3.4 `internal/relay`

**Client (`client.go`)**
- `RunClient` (:32): when `cfg.Jumphost` is non-empty, send `TypeChain` instead of
  `Hello`; then run the per-hop verify-and-sign loop.
- Generalise `completeClientAuth` (:444) into `completeChainAuth(hop, authOK)`:
  verify attestation → check `AuthOK.Destination` (the existing mismatch guard at
  :449-457 becomes per-hop) → recompute digest from `HelloJSON` → compare to
  `Challenge` → sign → send `Auth{hop}`.
- Keep token₁ only; `ResumeToken₂` is reported by j1 but is **opaque and
  discarded** by the client (it can never use it — j1 owns that session).
  Log it nowhere. This satisfies "different resume tokens per server" without
  giving the client credentials it cannot use.

**Server (`server.go`)**
- **J-D16 (do this first):** replace the independent `proto.RandomNonce()` calls
  at :1270 (`helloAuth`) and :1309 (`resumeAuth`) with the KEX `serverNonce`
  surfaced by `ProcessInit`. This is a standalone, testable change that also
  tightens the existing two-party protocol — it can land on its own commit before
  any chaining code.
- `handle` (:233): dispatch `TypeChain` alongside `TypeHello`/`TypeResume`
  (:317-329). Unknown type already yields `ErrProto` (:257-262), which is the
  fail-closed behaviour J-D10 relies on.
- New `handleChain` (:~333 analogue of `handleHello`): policy checks → dial
  `Hops[0]` → onward KEX → onward `ChainHello`/`Hello` → relay attestation and
  challenge inbound → relay signature outbound → build the nested pump →
  `TypeChainOK` → normal `HelloOK` for hop 1.
- Extract the destination dial (:395-409) into a small `dialDestination` seam so
  `handleHello` and `handleChain` share it.
- New `nestedDest` type implementing the `sessionIO` contract (`pump.go:33-44`)
  over a nested relay session: `Read`/`Write` bridge to the nested pump,
  `closeWrite` sends `CLOSE_DIR{up}` (J-D15), `rawSrc`/`rawSink` return `nil`
  (J-D13).
- `live` struct (:585): add `nested *nestedHop` so teardown fans out to both
  sessions and hold timers are coordinated (§2.7).

**Pump (`pump.go`)**
- `netReader` (:951): dispatch mid-session `TypeAuthOK{hop>0}` (Case C, §2.10).
- `reconnectable` (:646): chain-policy errors (`ERR_HOP_FORBIDDEN`,
  `ERR_CHAIN_LOOP`, `ERR_CHAIN_TOO_LONG`) are **not** reconnectable; they must
  surface to `ssh` immediately rather than burning the 5 m retry budget.

**Observability (`obs.go`)**
- Log fields: `chainId`, `hop`, `hops`, `upstream`, `originIp`. Never log
  `resumeToken` for any hop (design.md §11.3).
- expvars: `chain_sessions`, `chain_hops_total`, `chain_auth_relays`,
  `chain_refused`, `chain_attest_failures`.

### 3.5 `internal/config`

```toml
# server.toml — new
allow_relay_hops        = []      # empty ⇒ chaining refused (J-D8)
max_chain_depth         = 4
max_chain_conns_per_peer = 256    # per upstream relay address
chain_auth_timeout      = "10s"   # Case C quiesce bound
chain_max_sessions      = 0       # 0 ⇒ derive as max_sessions / 4

# client.toml — new
jumphost        = []              # same value as -J
sshd_alive_budget = "2m"          # warn when Σ holdᵢ exceeds this (§2.7)
```

`Validate()` (`config.go:398` server, `:454` client) must reject
`allow_relay_hops = ["*"]` unless `max_chain_depth == 1`, and must reject
`jumphost` entries that do not parse.

### 3.6 `cmd/relay`

- `runClient` (`main.go:142`): add `-J` / `--jumphost`, repeatable **and**
  comma-separated, parsed into `[]HopSpec`. Follow the existing
  `fs.Visit`-based "was this flag set" pattern used for `--dest`
  (`main.go:184-191`) so precedence stays **CLI > TOML > default**.
- `%h %p` positional handling (`main.go:196-212`) is unchanged; it still feeds
  `--dest`, which is now the *terminal's* dial target.
- Reject `-J` together with an empty `--server`: the terminal is always explicit.

---

## 4. Security analysis

| Property | Direct today | Chained | Note |
|---|---|---|---|
| Control plane encrypted | ✔ mandatory (`server.go:257-262`) | ✔ per hop | Each hop is an independent X25519 + ChaCha20-Poly1305 channel. |
| Client authenticated by pubkey | ✔ | ✔ **every hop, by the client itself** | J-D2. Intermediates never hold key material. |
| Server identity verified by client | ✔ `VerifyKnownHosts` | ✔ **every hop**, via attestation | J-D3, §2.5. Sound only with **J-D16** (attestation ↔ challenge nonce binding). |
| Challenge bound to destination | ✔ `auth.go:78` | ✔ per hop, plus attestation binding | The existing `AuthOK.Destination` mismatch guard (`client.go:449-457`) becomes per-hop and is what stops j1 from redirecting the client into signing for a different target. |
| Forward secrecy vs. the intermediate | n/a | ✖ on hops ≥ 2 | j1 holds hop-2 keys by construction. Accepted: j1 already sees the SSH ciphertext, and `ssh`'s own host-key check is the end-to-end guarantee. |
| Resume tokens | in-memory, per process (`client.go:124`) | in-memory, per hop, per process | Naturally satisfies "different resume tokens per server". Never logged. |
| Open-proxy risk | `allow_destinations` (`config.go:593`) | `allow_relay_hops`, **default deny** | J-D8/J-D9. An intermediate is not a general-purpose forwarder. |
| Version-skew fail-open | n/a | ✖ prevented | J-D10: unknown frame type ⇒ `ErrProto` (`codec.go:39`). Must be tested (`TestChainVersionSkewFailClosed`). |

**What a compromised intermediate can do:** read and modify hop-≥2 plaintext
(i.e. the SSH ciphertext — useless), DoS the chain, and observe `OriginIP`.
**What it cannot do:** impersonate the client to the next hop (no key), redirect
the client's signature to a different destination (per-hop `Destination` guard),
or substitute a rogue next hop (client verifies the attested host key).

**What a compromised intermediate can do that is new:** mount a
challenge-relay oracle — repeatedly trigger Case C to make the client sign many
challenges. Bounded by `chain_auth_timeout`, by the existing `auth_fail_delay`
(200 ms, no timing oracle), and by the fact that each challenge is single-use and
destination-bound. Add a per-session cap `chain_auth_relays_max` (default 8).

---

## 5. Risks

| | Risk | Severity | Mitigation |
|---|---|---|---|
| **JR1** | **Attestation freshness — CONFIRMED, not hypothetical.** The KEX `serverNonce` (`kex.go:159-161`) and the auth `serverNonce` (`proto.RandomNonce()` at `server.go:1270`/`:1309`) are different values. Without a fix, a rogue intermediate can pair a genuine attestation from a real KEX with a fabricated `AuthOK` and harvest a client signature that is valid against *any* server sharing the same `authorized_keys` — the agent-forwarding hazard, reintroduced. | **Critical** | **Resolved by J-D16** (§2.5): reuse the KEX nonce as the auth nonce, binding the signed `ExchangeHash` to the signed challenge. `TestChainAttestationReplay` is the regression test. |
| **JR2** | Inner-hop stale-token fallback needs the outer control channel live. If both hops break at once, the inner hop cannot re-authenticate. | High | §2.10 Case D: j1 rebuilds the onward chain during the hop-1 resume instead of answering `RESUME_OK` into a dead chain. |
| **JR3** | I1 weakens at an intermediate: bytes ACKed into the nested ring are lost if the intermediate crashes. | Medium | Inherent to J-D1. Document in README next to the existing "hold is in-process" caveat. FEAT-ROB-02 (`SCM_RIGHTS` handover) is the real fix and should be prioritised alongside. |
| **JR4** | `max_conns_per_ip` false positives — all chained traffic arrives from one peer IP. | High (would break the feature on first real use) | J-D14 `OriginIP` + `max_chain_conns_per_peer`. |
| **JR5** | 4 rings and ~12 goroutines per chained session at an intermediate; `max_sessions` overstates capacity ~2×. | Medium | `chain_max_sessions`; all nested rings on the shared `Budget`. |
| **JR6** | +2 RTT per hop at setup. On a 300 ms WAN a 3-hop chain adds ~1.2 s to connect. | Low | Acceptable; PERF-03 fast path removes it on resume. Log `chainSetupMs` per hop so it is visible. |
| **JR7** | No `splice(2)` on a nested leg (J-D13) ⇒ the PERF-01 CPU win does not apply to intermediates. | Low | Phase 2 may re-enable when the nested carrier is TCP and exposes `RawTCPConn()` (`transport/conn.go:42`). |
| **JR8** | Σ `hold_timeout` across hops exceeds the target `sshd` alive budget — a generalisation of R7 that is much easier to hit. | Medium | §2.7: warn at client startup against `sshd_alive_budget`. |
| **JR9** | Loop / hairpin: `-J` naming the client's own host, or two intermediates pointing at each other. | Medium | `ChainID` + `Visited` + self-address check + `max_chain_depth`. `TestChainLoopDetected`. |
| **JR10** | `allow_relay_hops = ["*"]` turns a relay into an open chaining amplifier. | Medium | Reject in `Validate()` unless `max_chain_depth == 1`; warn at startup exactly as `AllowAll` does today (`server.go:176`). |
| **JR11** | Mid-session `TypeAuthOK` handling (Case C) requires quiescing a pump — new concurrency in the most delicate code in the tree (R8: offset bugs are silent stream corruption). | High | Implement behind `chain_auth_timeout`, `-race` on every test, and never allow a quiesce to interleave with a `SWITCH`. |

---

## 6. Implementation phasing

### Phase 1 — one jumphost, TCP both hops, correct crypto

```
Phase 1
├─ [ ] 1.0  J-D16: surface serverNonce from kex.ProcessInit; use it in helloAuth
│            (server.go:1270) and resumeAuth (server.go:1309) in place of
│            proto.RandomNonce().  ← GATE; lands as its own commit, and is a
│            standalone hardening of the existing two-party protocol
├─ [ ] 1.1  internal/proto: TypeChain/TypeChainOK, ChainHello, ChainHelloOK,
│            HopSpec, HopAttestation, AuthOK/Auth extensions, 3 new error codes
├─ [ ] 1.2  internal/crypto/kex: RawEd25519ToAuthorizedKeysLine, VerifyAttestation
├─ [ ] 1.3  internal/config: allow_relay_hops, max_chain_depth, jumphost,
│            Validate() rules (J-D8, JR10)
├─ [ ] 1.4  internal/relay/server.go: dialDestination seam extraction,
│            handleChain, nestedDest implementing sessionIO, policy + loop checks
├─ [ ] 1.5  internal/relay/client.go: TypeChain send path, completeChainAuth
│            (generalising client.go:444), per-hop destination guard
├─ [ ] 1.6  cmd/relay: -J parsing (repeatable + comma + query suffix + #pin)
├─ [ ] 1.7  Transport forced to TCP on both hops; no HA; no Case C
└─ [ ] 1.8  Tests: chained e2e fixture, policy denial, loop, depth, attestation
             mismatch, version-skew fail-closed, half-close, byte-exactness
```

**Phase 1 exit criteria:** `ssh -o ProxyCommand='relay client --server S -J j1'`
transfers 16 MiB byte-exact (SHA-256) in both directions through two in-process
servers, and every policy/attestation negative test fails closed.

### Phase 2 — N-hop, per-hop transport, HA, mid-session re-auth

```
Phase 2
├─ [ ] 2.1  Recursive handleChain for arbitrary depth ≤ max_chain_depth
├─ [ ] 2.2  Per-hop transport + ha from the -J query suffix (J-D4)
├─ [ ] 2.3  Per-hop UDP probe/SWITCH/upgrade at each intermediate
├─ [ ] 2.4  Case C: mid-session TypeAuthOK in netReader (pump.go:951),
│            quiesce, chain_auth_timeout, chain_auth_relays_max
├─ [ ] 2.5  Case D: rebuild-on-resume when the nested session is already dead
├─ [ ] 2.6  OriginIP accounting + max_chain_conns_per_peer (J-D14, JR4)
├─ [ ] 2.7  chain_max_sessions, 4-ring budget accounting (JR5)
├─ [ ] 2.8  Σ hold warning against sshd_alive_budget (JR8)
├─ [ ] 2.9  obs.go: chainId/hop/upstream fields, 5 new expvars
├─ [ ] 2.10 Optional: re-enable splice when the nested carrier is TCP (JR7)
└─ [ ] 2.11 Tests: repeated inner/outer/both kills, per-hop KCP, HA promotion
             on an inner hop, 64 chained sessions leak check, netns harness
```

**Phase 2 exit criteria:** `scripts/test_jumphost_netns.py` passes — 3 netns
(`ns-cli ↔ ns-j1 ↔ ns-srv`), real `sshd`, real `ssh -o ProxyCommand`, `tc netem`
40 ms / 2 % on the cli↔j1 leg, repeated `iptables` kills on **each** leg
independently and simultaneously, SHA-256 byte-exact, zero goroutine/fd leaks.

### Phase 3 — NATed terminal (depends on FEAT-UTL-04)

Out of scope here beyond reserving the wire format. When `relay agent` exists
(`features.md:209-244`), a `HopSpec` gains a `target` name so an intermediate can
resolve the next hop by **rendezvous** rather than by dial:

```
{ "target": "homelab" }   // instead of { "addr": "…" }
```

Reserved now so no v2 break is needed later. `ChainHello` is unchanged; only
`HopSpec` grows an optional field, which `encoding/json` tolerates.

---

## 7. Verification matrix (planned)

### 7.1 Go in-process tests

Reuse the `TestMain` fixture (`internal/relay/test_main_test.go`, ephemeral
ed25519 + `RELAY_TEST_*` env vars) and `startRelayCfg` / `echoDest` /
`makePattern`+`checkPattern` (`e2e_test.go:70`, `sec_test.go:27`,
`e2e_test.go:20,41`). New fixture: `startChain(t, nHops, terminalDest)` returning
`[]*Server` plus the head address.

| Test | Asserts |
|---|---|
| `TestChainE2EByteExactBothDirections` | 1 MiB positional pattern, SHA-256 match, no dup/gap |
| `TestChainThreeHops` | N-hop recursion, depth ≤ `max_chain_depth` |
| `TestChainHopNotAllowed` | default-deny: empty `allow_relay_hops` ⇒ `ERR_HOP_FORBIDDEN`, **before** any dial |
| `TestChainDepthExceeded` | ⇒ `ERR_CHAIN_TOO_LONG`, not reconnectable (`pump.go:646`) |
| `TestChainLoopDetected` | self-reference and mutual reference ⇒ `ERR_CHAIN_LOOP` |
| `TestChainAttestationHostKeyMismatch` | rogue terminal ⇒ client refuses to sign, no signature emitted |
| `TestChainAttestationReplay` | stale `KexReply` paired with a fresh fabricated `AuthOK` ⇒ rejected (**J-D16 regression test**; must fail if the nonces are decoupled again) |
| `TestNonceBindingKexEqualsAuth` | unit-level guard: `AuthOK.ServerNonce` is byte-identical to the `serverNonce` inside `KexReply[32:48]`, for both HELLO and RESUME paths |
| `TestChainDestinationMismatch` | intermediate lies about `Destination` ⇒ client refuses (generalises `client.go:449-457`) |
| `TestChainVersionSkewFailClosed` | v1 server + `TypeChain` ⇒ `ErrProto`, never a silent direct dial |
| `TestChainTerminalHasNoChainCode` | the terminal is configured with an empty `allow_relay_hops` and never receives a `TypeChain`; it serves the last hop as an ordinary `Hello` |
| `TestChainTerminalPreJD16Refuses` | a terminal without the J-D16 nonce reuse produces an attestation the client rejects — fail closed, not fail open |
| `TestChainResumeOuterHopOnly` | kill hop-1 carrier; inner session untouched; `ssh`-equivalent stream byte-exact |
| `TestChainResumeInnerHopOnly` | kill hop-2 carrier; client never re-authenticates (PERF-03 fast path) |
| `TestChainResumeBothHops` | Case D rebuild |
| `TestChainStaleTokenInnerRelaysSignature` | Case C mid-session `TypeAuthOK` |
| `TestChainHalfClosePropagation` | stdin EOF → `CLOSE_DIR` → nested `CLOSE_DIR` → terminal `CloseWrite` (J-D15) |
| `TestChainBackpressureGlobalBudget` | 4 rings share `total_buffer_bytes`; new refused, existing survive |
| `TestChainOriginIPAccounting` | `max_conns_per_ip` counts originators, not the upstream relay (JR4) |
| `TestChainPerHopTransport` | hop 1 KCP, hop 2 TCP, hop 3 QUIC — each upgrade independent |
| `TestChainConcurrencyLeak` | 64 chained sessions, random kills, goroutines return to baseline |
| `TestChainSpliceDisabled` | 0 `splice(2)` syscalls on a nested leg (J-D13) |

CI gate unchanged: `gofmt -l`, `go vet ./...`, `staticcheck ./...`,
`go test -race -count=1 -timeout 10m ./...`, cross-build
(`.github/workflows/ci.yml`).

### 7.2 Netns harness

`scripts/test_jumphost_netns.py`, following `test_sec_netns.py`'s skeleton
(`T=/tmp/relay-verify`, `BIN`, `netns()`, `cleanup()`, `setup_env()`,
`record_result()`, PASS/FAIL summary, `sys.exit(1)`).

| ID | Scenario | Target |
|---|---|---|
| `JUMP-01-Baseline` | 3 netns, real `ssh -J`-equivalent ProxyCommand, 16 MiB `rsync` | SHA-256 byte-exact |
| `JUMP-02-OuterKill` | `tc netem` 40 ms / 2 % + repeated `iptables` DROP on cli↔j1 | resume ≤ 2.25 s (BFD), zero lost bytes |
| `JUMP-03-InnerKill` | same on j1↔srv | client sees nothing; `chain_auth_relays` stays 0 |
| `JUMP-04-SimultaneousKill` | both legs killed within 100 ms | Case D rebuild, byte-exact |
| `JUMP-05-KCPLeg` | `--kcp` on the lossy leg only | compare against TCP on the same profile |
| `JUMP-06-WireInspect` | `tcpdump` on j1↔srv | no `resumeToken`, no payload, no cleartext handshake |
| `JUMP-07-Depth` | 3 intermediates | `max_chain_depth` enforced end to end |

Not in CI (needs root, netns, real `sshd`) — same status as the existing
harnesses.

### 7.3 Benchmark to record in README

Same netem profiles as the existing table (16 MiB, 80 ms RTT, 3 % loss), measured
for **direct vs 1-hop vs 2-hop**, TCP/QUIC/KCP on the WAN leg. Report throughput,
setup RTTs, and resume counts. This is the number that will decide whether the
+2 RTT/hop (JR6) and the 4-ring memory (JR5) are acceptable in production.

---

## 8. Documentation to update

- `README.md`: new "Jumphost chaining" section; extend the Status table; add the
  JR3 caveat next to "Hold is in-process"; add the Σ-hold vs `ClientAliveInterval`
  warning next to the existing R7 note.
- `features.md`: add `FEAT-UTL-05` to the Priority Matrix and Tier 2, and
  cross-reference it from `FEAT-UTL-04` (§Phase 3 depends on it) and
  `FEAT-UTL-03` (SOCKS5 is the *dynamic* analogue of this *static* chaining).
- `design.md`: fold J-D1…J-D15 into the §3 decisions log as D11+; add I6 to §7.1;
  add JR1–JR11 to §15; update the §5.2 frame-type table and §4.1 repo layout.
- `wip.md`: append an entry per phase.

---

## 9. Open questions to settle during Phase 1

1. Should `OriginIP` be trusted from the upstream relay, or only from peers whose
   host key is pinned in a new `trusted_relays` list? Trusting it blindly lets a
   compromised j1 spoof an arbitrary origin IP and evade `max_conns_per_ip`.
2. Does `-J` need to interoperate with OpenSSH's own `-J`? I.e. should
   `ProxyCommand relay client --server S -J j1` be composable with an outer
   `ssh -J`? Probably not, but the flag collision will confuse users; consider
   `--chain` as an alias.
3. Should `chain_max_sessions` be a hard cap or a soft one that only affects
   `buffer_bytes` clipping?
4. Is a per-hop `user` meaningful while all hops share one key? Keep the field
   for parity with OpenSSH, or drop it until RBAC (FEAT-SEC-03) exists?
5. J-D16 changes `AuthOK.ServerNonce` semantics for **all** sessions, not just
   chained ones. It is wire-compatible, but should it ship behind a flag for one
   release so a mixed-version fleet can be rolled forward deliberately?
