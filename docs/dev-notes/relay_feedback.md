# relay_feedback — review against a real deployment target

Reviewer: Claude (mythlab estate work). Read-only review; no source changed.

| | |
|---|---|
| Reviewed | 2026-09-11, ~12:35–15:05 IST |
| Tree | `4c57865` + uncommitted working tree (18 modified, 5 untracked), `main` ahead 3 of origin |
| Build | `go build ./cmd/relay` **clean**, twice (12:38 and 15:05) |
| Tests | not run |

> **The tree moved during the review.** `internal/crypto/kex/hostkey.go` and
> `internal/config/config.go` were rewritten at **15:00**, while §6 of this file
> was being drafted. Two findings I had written up were fixed by that edit and
> are recorded below as *fixed mid-review* rather than deleted — the rewrite is
> the right one and the record is worth keeping. Everything else here was
> re-verified against the 15:00 state.

---

## 1. Verdict for the case that prompted this

The concrete target is a roaming VM (`d13`) whose only remote access is a
reverse SSH forward published on a public cloud jump host (`oci4`), currently
carried by `tssh --kcp` + `tsshd`. That path failed the day before this review:
all ten UDP ports in the `tsshd` range were held by abandoned processes, and a
restart loop manufactured orphans faster than they drained.

**remote-relay is a good fit, and the fit is better than a transport swap — it
removes the failure class rather than replacing it.**

What gates adoption is now *purely operational* (§5). The security model, which
I had expected to be the weak part of a WIP tree, is the strongest part of it
(§4).

---

## 2. The architectural finding: FEAT-UTL-04 is not required for this

`features.md` positions **FEAT-UTL-04 (Reverse Relay & NAT Gateway Mode)** as
the answer for "target machine behind NAT / CGNAT", and it is `Status:
Proposed`. The binary confirms it is absent:

```
usage: relay <server|client|version> [flags]      # no `agent` subcommand
```

The instinct is therefore that a NATed destination blocks this use case. **It
does not**, because the direction that has to traverse NAT is the *initiator's*,
and `design.md` §2 already says a NATed **client** is fully supported. The
reverse forward does not need the relay to be reverse — it rides inside the SSH
session the relay carries:

```sh
# on the NATed host
ssh -R 127.0.0.1:44022:127.0.0.1:22 svc-user@jump.example \
    -o ProxyCommand="relay client --server jump.example:7443 --kcp"

# on the jump host
relay server           # default_destination = 127.0.0.1:22
```

The relay carries the SSH connection to the jump host's own `sshd`; the `-R` is
opaque payload. This works with what is in the tree today.

**Why this is worth writing down:** `tssh` conflated two things this design
separates — *which end initiates* and *which end owns the listener*. `tsshd`
publishes the listener itself, so its transport had to know a reverse forward
existed. Here the transport carries an opaque byte stream and OpenSSH does the
forwarding, so the relay never needs to know. That separation is also what hands
authorization back to `sshd`: with `sshd` owning the listener again, an
`authorized_keys` `permitlisten=` restriction starts being enforced, which it
cannot be under `tsshd`.

**Suggestion:** FEAT-UTL-04 is still the elegant end state (`--target d13`, no
`ssh -R`, no loopback listener on the jump host). But its problem statement
overstates what is currently impossible. Worth a note in `features.md` that the
ProxyCommand shape already covers NATed *destinations* when the destination is
willing to dial out — otherwise a reader defers a solved use case to a P2.

---

## 3. What it replaces, concretely

| | `tssh --kcp` + `tsshd` | remote-relay |
|---|---|---|
| link break | session dies → supervisor restart → **new** `tsshd`, new port | `RESUME` at byte offsets; consumer never sees it |
| ports on the public host | **10** UDP, plus a counting chain to detect orphans | **1** TCP + 1 UDP, shared by all sessions (D5) |
| orphan management | a reaper and a client-side idle timeout, both 30 min | `hold_timeout`, in-process |
| wrapper scripts | one, because `tssh` ignores `ExitOnForwardFailure` | none — OpenSSH honours it |
| `permitlisten` on the jump account | **inert** — `tsshd` owns the listener | **enforced** — `sshd` does |
| host key verification on the tunnel | none | mandatory (§4) |
| blackhole detection | none | BFD, `dead_peer_threshold × heartbeat_interval` |
| second path | none | `--allow-ha` hot-standby TCP, zero-dial promotion |

The first row is the important one. The outage being fixed happened because *a
dropped tunnel was a new session*; resume means it is not.

`--allow-ha` deserves a specific call-out: a hot-standby TCP carrier under
continuous BFD, promoted without a dial round-trip, is a capability the
incumbent has never had. For a link that intermittently blackholes rather than
cleanly dropping — which is the observed failure on this host — it is directly
on point.

---

## 4. Security review

Verified in code, not from the specs.

**Control-plane encryption is mandatory, not configurable.**

```go
// internal/relay/server.go:256
// Strict encrypted-only enforcement (FEAT-SEC-01)
if f.Type != proto.TypeKexInit {
    s.log.Warn("rejecting unencrypted handshake: expected KEX_INIT", …)
    writeErr(conn, proto.CodeProto, "encrypted handshake required (expected KEX_INIT)")
```

There is no toggle. Ephemeral X25519 → HKDF-SHA256 → ChaCha20-Poly1305 with
64-bit sequence nonces, server identity via Ed25519 host key signature over the
transcript hash.

**FEAT-PERF-03 is the piece that makes PKA viable on a flaky link**, and it is
easy to under-rate. A signature per reconnect would be a real cost on a path
where reconnects are the normal case rather than the exception. Token-authorized
resume at 3 RTTs, with transparent fallback to a challenge against the *bound*
fingerprint when the token is stale, removes that cost without weakening the
wire.

The reasoning is worth preserving explicitly, because it inverts M5's: a bearer
token was unsafe pre-SEC-01 **because the control plane was cleartext**, so only
a per-connection signature could prevent hijack. Post-SEC-01 the token is only
ever presented inside a forward-secret AEAD tunnel whose far end has already
proved possession of the host key. The signature did not become unnecessary —
*the channel that made it necessary was removed.* That is why PERF-03 can drop
an authentication factor and still be strictly stronger on the wire than M5.

**Not a defect, but a deployment trap:** `auth_method` defaults to `"none"` on
both sides (`internal/config/config.go`, server and client `Default*`
constructors). The capability is complete; the default is permissive. Any
public-facing deployment must set `ssh-publickey` on both ends — with `"none"`,
anyone who reaches `listen_tcp` gets a session to whatever `allow_destinations`
permits. README says so, which is the right call, but the pairing of *permissive
default* with *public listener* is the single easiest way to misdeploy this.

**Posture change worth stating plainly for any deployment replacing `tsshd`:**
`tsshd` has no listener for most of its life — the port only exists during a
session. A relay server always answers. Ten usually-dead UDP ports become one
always-live TCP + UDP pair: fewer firewall rules, more standing surface. With
mandatory KEX + host-key verification + `ssh-publickey` that is a good trade,
but it is a trade and should be recorded as one.

---

## 5. Operational gates — what would block production use

These are the two items I would want closed before this carries a host whose
only other access is a physical console.

**5.1 Hold is in-process.** A server restart drops every session with
`ERR_UNKNOWN_SESSION`: destination sockets closed, tokens gone. README states
this honestly. It is the same *shape* as the problem this replaces — a
transport-layer event that costs sessions — by a different mechanism.
FEAT-ROB-02 (`LISTEN_FDS` / `SCM_RIGHTS` handover) is `Proposed`. It degrades to
"supervisor rebuilds the tunnel" rather than anything worse, so it is a gate on
*confidence*, not on function.

**5.2 The KCP-under-repeated-kills soak result.** From README:

> *"Mixed KCP at that kill rate expired instead of resuming (likely
> liveness/scale with KCP's delayed Close and idle timers, not a mux `conv`
> identity bug)."*

**This is the single most important open item for this use case**, because the
workload is precisely *KCP under repeated link kills*. It is one session rather
than 64, so scale is probably not the mechanism — but "KCP + kills = expired
instead of resumed" is the exact property the entire plan leans on, and it is
currently recorded as not holding in the one test that stresses it.

Two suggestions: raise this above the P2/P3 features in the roadmap, and add a
**1-session, long-duration, high-kill-rate KCP soak** to CI. The 64-session mix
answers a different question (scale) than the one that matters here (does a
single KCP session survive many kills over hours).

---

## 6. Defects and documentation drift

### 6.1 README describes a code path that no longer exists — **live**

`README.md` "Security" states:

> *"TCP handshake is cleartext (HELLO / RESUME, including `resumeToken`)."*

This is false as of FEAT-SEC-01: cleartext is rejected unconditionally
(`internal/relay/server.go:256`). A reader provisioning from the README
provisions the wrong threat model — and in the *pessimistic* direction, which
means the mistake is to add unnecessary mitigation rather than to skip a
necessary one. Still worth fixing: it is the first place anyone looks.

The README **Status** table has the same drift in the other direction — it lists
M0–M5, ROB-01 and SEC-01, but not ROB-03, PERF-01 or PERF-03, which are in
`git log` and marked Implemented in `features.md`. The README understates the
tree by four features.

### 6.2 `knownHostsPath == ""` skips verification entirely — **live**

```go
// internal/crypto/kex/hostkey.go:186
if knownHostsPath == "" {
    return nil // No known_hosts configured and no home directory
}
```

Reached when `--known-hosts` is unset *and* `os.UserHomeDir()` fails. A daemon
started without `HOME` in its environment — which is the normal case for a
systemd unit that does not set it — therefore performs **no host key
verification at all**, silently and with no log line. That is a fail-open on the
one check that stops an active MITM.

Suggested: return an error, or at minimum log at `WARN`. A silent skip is
indistinguishable from a successful verification in every observable way, which
is the property that makes it dangerous rather than merely lax.

Mitigation for deployers today: pass `--server-fingerprint SHA256:…`, which
short-circuits ahead of the file lookup and has no TOFU window at all. For an
unattended tunnel that is the right setting regardless.

### 6.3 Flag vocabulary disagrees across three places — **live**

| source | documented values |
|---|---|
| `README.md:114` usage line | `yes\|no\|accept-new` |
| `cmd/relay/main.go:117` flag help | `yes\|no\|ask` |
| `internal/config/config.go` validator | `""`, `ask`, `yes`, `no`, `accept-new` |

The validator is the superset and accepts everything either doc names, so
nothing breaks — but each document tells the reader that one of the valid values
does not exist.

### 6.4 Host-key default and TOFU prompt — **fixed mid-review**

At the start of this review the default was a literal `"ask"` with no TTY
discrimination, and `"ask"` never prompted: it appended to `known_hosts`
silently, i.e. behaved as `accept-new`. So a headless client got TOFU when the
spec promised strict.

The 15:00 rewrite fixes both:

- `config.DefaultStrictHostKeyChecking()` returns `"ask"` on a TTY and `"yes"`
  headless, matching `FEAT-SEC-01.md`;
- `handleTOFU()` re-derives the same TTY/headless default when the mode is
  empty, and `"ask"` now genuinely prompts, refusing when no terminal is
  available.

Recorded rather than deleted because the *shape* of the bug is worth keeping: a
mode named `ask` that never asks is not a weaker security setting, it is a
**mislabelled** one — a deployer reading `ask` in a config file would reasonably
conclude a human was in the loop.

Two notes on the fix, neither blocking:

- A key **change** is correctly fatal (`REMOTE HOST IDENTIFICATION HAS
  CHANGED`), and an unknown host is TOFU-or-refuse per mode. That matches
  OpenSSH semantics closely enough that operators will not be surprised.
- `defaultPromptUser` treats a read error with `io.EOF` and a non-empty line as
  a valid answer; worth a test for the `yes` + EOF-without-newline case.

### 6.5 Minor

- `internal/crypto/kex/hostkey.go:207` falls back to `&net.TCPAddr{IP:
  net.IPv4zero, Port: 7443}` when `ResolveTCPAddr` fails, hardcoding the default
  port inside a crypto helper. Harmless today; it will be wrong on the day
  someone changes the port and a name fails to resolve.
- README's `hold_timeout` vs `sshd ClientAliveInterval` note (R7) is a good
  catch and easy to miss. Consider promoting it from prose into the
  `server.toml` example as a comment on `hold_timeout` itself, where the person
  choosing the value will actually be looking.

---

## 7. Deployment recommendation for the target case

1. `auth_method = "ssh-publickey"` on **both** ends. Not optional for a public
   listener.
2. Pin the host key: `--server-fingerprint SHA256:…` on the client. Sidesteps
   §6.2 entirely and removes the TOFU window.
3. `--kcp` on the flaky leg. The netem numbers justify it on their own — 16 MiB
   at 80 ms / 3 % loss: **7.98 s vs 257 s** for TCP.
4. `--allow-ha` — the failure mode on this link is blackholing, not clean drops.
5. Keep `hold_timeout` below the destination `sshd`'s alive-interval budget
   (R7).
6. **Do not cut over.** Stand a second listener and a second reverse forward on
   a spare port, prove a real login end to end, run it as the *non-primary*
   through deliberate link flaps, and move the primary port only once it has
   survived that — performing the cutover over the *other* path, never the one
   being replaced. This is also how §5.2 gets answered on a real link instead of
   in netem.

---

## 8. Roadmap opinion

- **Raise:** the single-session KCP-under-kills soak (§5.2). It is the
  difference between "promising" and "deployable" for the roaming-host case,
  which is the case this project appears to exist for.
- **Raise:** FEAT-ROB-02. In-process hold is the last remaining way a
  transport-layer event costs sessions.
- **Lower / reframe:** FEAT-UTL-04. Valuable, but its problem statement claims
  ground the current design already covers (§2), so it reads as more blocking
  than it is.
- **Keep:** the `.feat-impl/` convention. Each spec carries the problem, the
  wire format, and the verification — `FEAT-PERF-03.md` in particular explains
  *why an authentication factor could be dropped*, which is exactly the
  reasoning that is expensive to reconstruct later and cheap to record now.
