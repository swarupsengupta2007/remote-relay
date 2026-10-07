# Namespace suite failures

**Run:** 2026-10-05, Linux network namespaces, binary built from this tree  
**Log:** `/tmp/relay-netns-check/run.log`  
**Result:** 34 passed, 9 failed (`EXIT:1`)  
**Host stack:** unchanged. Link, address, route, rule, iptables, ip6tables, nft, and the sampled sysctls matched the pre-test snapshot after cleanup. Veths were created with both ends inside namespaces.

The nine `FAIL` lines are below. Eight are product behavior. The IPv6 ping line is a harness check; the Happy Eyeballs capture in the same run is the IPv6 evidence.

| Check | Feature | Measured result |
|---|---|---|
| `tcp-resume-after-kill` | FEAT-PERF-01 / FEAT-PERF-03 | Sink longer than the payload; client exit 0 |
| `hot-restart-with-metrics` | FEAT-ROB-02 | Child died on `metrics listen: address already in use` |
| `hot-restart-websocket` | FEAT-ROB-02 / FEAT-SEC-02 | Port 8444 gone after `SIGUSR2` |
| `trusted-proxy-honors-xff` | FEAT-SEC-02 | Forged `X-Forwarded-For` absent after the proxy was trusted |
| `jumphost-to-nated-agent` | FEAT-UTL-06 | `ERR_HOP_FORBIDDEN` from the terminal |
| `bfd-dead-peer-detected` | FEAT-ROB-01 | No `dead-peer` log inside 2.5 s |
| `bfd-without-ha-aborts` | FEAT-ROB-01 | Still retrying at 15.01 s |
| `hud-reconnect-line` | FEAT-UTL-02 | Status line present; OSC 9 / OSC 777 absent on a 7.2 s outage |
| `netns-paths` | harness | One-shot `ping -6` returned 1 |

A wildcard-bind loop, seen on an earlier run and still present in `addrEqual`, is recorded after the nine because this run avoided it by binding the jump to a concrete address.

---

## 1. Splice resume writes bytes the sink already has

**Check:** `tcp-resume-after-kill`  
**Features:** FEAT-PERF-01, FEAT-PERF-03

`ss -K` inside the client namespace hit a live socket:

```text
ESTAB 0  498112  10.88.4.2:59668  10.88.4.1:7443
```

The client exited 0. The payload was 1,048,576 bytes. The sink file was 1,053,175 bytes, 4,599 bytes long. It matched the payload through offset 233975. The extra span is payload bytes `[229376:233975]`.

`spliceSocketToSink` returns a positive count together with an error after those bytes have already been spliced into the sink (`internal/relay/splice_linux.go`, the `return transferred, err` and `return transferred + pumped, err` paths around lines 170–226). The caller in `internal/relay/pump.go` (lines 1098–1104) returns on `spErr != nil` before `expected += uint64(spliced)` and before the ACK. Resume retransmits from the last ACK, and the server writes that span again.

The same 1 MiB kill, with the server started `--no-splice`, was byte-exact (`tcp-resume-after-kill-nosplice`). Client `--no-splice` does not disable the server pump.

---

## 2. Hot restart kills the child when metrics is bound

**Check:** `hot-restart-with-metrics`  
**Feature:** FEAT-ROB-02

`metrics_listen` was `10.88.4.1:9090`. After `SIGUSR2` the parent logged handover acknowledged and `exiting parent process cleanly after hot restart`, then exited. The child (pid 1654539) logged:

```text
relay server: metrics listen: listen tcp 10.88.4.1:9090: bind: address already in use
```

The child was gone, the relay port was not listening, and the address was still busy (`rc=-9`). A session was held (`s-beb4bc52ec73`) and then died with the child.

`Listen` returns immediately when `tryAdoptSockets` succeeds (`internal/relay/server.go` lines 649–650), so it never reaches `listenWS` either. `Serve` then calls `startDebug` (line 700) while the parent still holds the metrics socket. `HandoverTo` (`internal/relay/server_unix.go`) passes the TCP listener, the UDP listener, and destination fds. It does not pass the metrics listener, and the parent calls `os.Exit(0)` (line 315) only after the child has acknowledged. `serveDebug` uses `net.Listen` (`internal/relay/obs.go` line 197). Go sets `SO_REUSEADDR` and not `SO_REUSEPORT`, so the child's bind fails while the parent socket is still open.

With `metrics_listen` empty, a TCP session survived the same handover: child 1656889 stayed up, session `s-2c93c2f1c167` resumed in 69 ms, and 1,048,576 bytes were exact (`hot-restart-tcp-session`). A second `SIGUSR2` during SOCKS left the listener up, raised no panic, and carried 17 bytes exactly (`hot-restart-socks-no-panic`).

---

## 3. Hot restart drops the WebSocket listener

**Check:** `hot-restart-websocket`  
**Features:** FEAT-ROB-02, FEAT-SEC-02

This check ran in the phase with `metrics_listen` empty, so it is separate from the metrics bind crash. `listen_ws` was `ws://0.0.0.0:8444`. After `SIGUSR2`, port 8444 was not listening.

The adopt path returns from `Listen` before `listenWS` (`internal/relay/server.go` lines 649–666). `startWS` returns immediately when `s.wsLn` is nil (`internal/relay/ws_server.go` lines 128–133). `HandoverTo` does not pass the WebSocket listener. Before the restart, a 256 KiB WebSocket upload was byte-exact.

---

## 4. A trusted proxy's `X-Forwarded-For` is ignored

**Check:** `trusted-proxy-honors-xff`  
**Feature:** FEAT-SEC-02

A reverse proxy in the client namespace terminated the upgrade, injected `X-Forwarded-For: 198.51.100.50`, and TCP-connected to `10.88.4.1:8444`. With `trusted_proxies` empty, the forged address stayed out of the session log and the proxy's TCP peer was logged. That check passed, and the body was 23 bytes exact.

SIGHUP then set `trusted_proxies = ["10.88.4.2"]`. The server logged `configuration reloaded successfully via SIGHUP`. The next WebSocket session still logged the proxy's TCP address. `198.51.100.50` was absent. The body was 21 bytes exact.

`handleWebSocket` computes the connection address with `ExtractRemoteAddr`, then calls `ExtractClientIP(req, ws.RemoteAddr(), trusted)` (`internal/relay/ws_server.go` lines 22–23). `ws.RemoteAddr()` on a server `golang.org/x/net/websocket` conn is a `*websocket.Addr` holding the Origin URL. `ExtractClientIP` (`internal/transport/websocket.go` lines 405–412) substitutes `req.RemoteAddr` only when the raw address is nil, so `peerTrusted` runs on the Origin URL. `ipFromNetAddr` cannot parse that URL, trust stays false, and the function falls through to `req.RemoteAddr`, the proxy's TCP address. The session log line uses the address passed to `WrapWebSocket`, which is the `ExtractRemoteAddr` result, so a working trust check would have logged `198.51.100.50`.

---

## 5. `-J` plus `--target` is refused by an empty allow list

**Check:** `jumphost-to-nated-agent`  
**Feature:** FEAT-UTL-06

The client was `relay client -J 10.88.1.1:7443 --server 10.88.2.2:7443 --target homelab`. It printed:

```text
relay client: ERR_HOP_FORBIDDEN: chaining is not enabled on this server
```

SSH then reported `kex_exchange_identification: Connection closed by remote host`. The jump log, after the successful plain hops, was:

```text
onward hop failed … code=ERR_HOP_FORBIDDEN reason="chaining is not enabled on this server" upstream=10.88.2.2:7443
```

The client sends the jump a chain whose remaining hops are `[10.88.2.2:7443, target:homelab]`. The jump's allow list contained `10.88.2.2:7443`, so it dialed the terminal. Because the tail is non-empty, it forwards a `CHAIN` whose only hop is the target (`internal/relay/chain.go` lines 928–940). The terminal's `allow_relay_hops` is empty. `chainPolicy` returns `ERR_HOP_FORBIDDEN` / `chaining is not enabled on this server` at lines 713–714, before the `h.Target != ""` branch at line 717. `handleChain` would treat `next.Target != ""` as the rendezvous (line 158), and that code is never reached.

Empty `allow_relay_hops` on a bare hop is the intended default deny: `jumphost-default-deny` exited 255. With the hop allowed and the jump bound to `10.88.1.1:7443`, TCP and KCP each carried 256 KiB byte-exact. Direct `--target homelab`, with no `-J`, returned `AGENT_OK`. The in-process chained-target tests set the terminal's allow list to `*`, so they do not cover an empty terminal allow list.

**Related, from the earlier run.** With the jump listening on `0.0.0.0:7443`, a hop to `10.88.2.2:7443` was `ERR_CHAIN_LOOP`. `addrEqual` (`internal/relay/chain.go` lines 779–794) treats a wildcard bind as every host on the same port. This run bound the jump to `10.88.1.1:7443` and did not repeat the wildcard case.

---

## 6. A blackholed peer does not log `dead-peer`

**Check:** `bfd-dead-peer-detected`  
**Feature:** FEAT-ROB-01

Heartbeat was 200 ms and the dead-peer threshold was 3, so the window was 2.5 s. The server log in that window for session `s-e99cdf47bde7` was:

```text
serveConn ending … rawErr="read tcp 10.88.4.1:7443->10.88.4.2:52010: read: connection reset by peer"
session held … heldMs=0
```

There was no `dead-peer` line. `relay_bfd_dead_peer_total` is registered in `internal/obs/metrics.go` (line 541) and nothing in the tree calls `BFDDeadPeers.Add`.

With `--allow-ha`, the same class of blackhole promoted the TCP standby in 2.17 s (`standby connection promoted to active carrier`, session `s-b64ed765f696`) and the payload was byte-exact.

---

## 7. Without HA, a failed UDP probe keeps retrying

**Check:** `bfd-without-ha-aborts`  
**Feature:** FEAT-ROB-01

The client was killed at 15.01 s with `rc=-9`. Stderr ended in `kcp-go` `UDPSession.postProcess`, from the kill. There was no recorded `panic:` and no key-exchange failure.

`clientResume` treats a failed strict UDP probe as retryable (`internal/relay/client.go` lines 351–363) until the hold budget is exhausted. The immediate abort in that loop is the case `target == "tcp"` or `udp == nil`: `udp route unavailable and --allow-ha not specified` (lines 345–349). A blackholed UDP socket does not take that branch.

---

## 8. A 7.2 s stall restored the link and emitted no desktop notification

**Check:** `hud-reconnect-line`  
**Feature:** FEAT-UTL-02

The client ran on a PTY. Stdout was 262144 bytes and matched the payload. The status capture was:

```text
[remote-relay] Link disrupted. Reconnecting via TCP...
[remote-relay] Link disrupted. Reconnecting via TCP... (attempt 1/8, 0.0s elapsed)
[remote-relay] Link restored via TCP in 7.2s (resumed 128.0 KiB buffered).
```

OSC 9 / OSC 777 was absent. The server was `--no-splice`, so the resumed bytes were exact.

`OnDisrupted` draws the status line and does not emit OSC (`internal/relay/hud.go` lines 123–124). OSC is emitted from `OnAttempt` when elapsed time is already at least `NotificationTimeout`, default 5 s (lines 137–140). The reconnect loop calls `OnAttempt`, then blocks inside `clientResume` for the whole dial (`internal/relay/client.go` lines 307–309). This outage was one attempt stuck in TCP retransmit until the drop was lifted at 6.2 s. The wall time was 7.2 s. A second `OnAttempt` never ran, so the 5 s notification was never evaluated. `OnRestored` emits the recovery OSC only after `notificationSent` is set.

---

## 9. One-shot IPv6 ping failed during path setup

**Check:** `netns-paths`  
**Kind:** harness

IPv4 pings from client to server, client to jump, agent to server, and loss namespace to server all returned 0. `ping -6 -c 1 -W 1 fd88:4::1` returned 1. A 0.6 s connect to `[fd88:4::1]:7443` timed out (`rc=2`), which is the intended blackhole.

The Happy Eyeballs check later in the same run is the IPv6 result: a SYN to `fd88:4::1` and a SYN to `10.88.4.1` were both in the capture, and the 13-byte transfer finished in 0.261 s (`happy-eyeballs-v6-blackhole`). An earlier private repro that dropped all IPv6 input, including neighbor discovery, dialed `[fd88:4::1]:7443` with `connect: no route to host` and captured only IPv4 SYNs. The suite run dropped only TCP/7443 and UDP/7443.

---

## Resolution (2026-10-06)

Rerun of the full suite on the fixed tree: **43 passed, 0 failed** (`EXIT:0`), host stack restored.

| # | Fix | Regression test |
|---|---|---|
| 1 | `netReader` counts spliced bytes into `expected`/`delivered` before returning a splice error; the pipe→sink stage waits on `EAGAIN` (`waitWritable`) instead of failing with drained bytes stranded in the pipe. | `TestSpliceCarrierResetMidFrameCountsDelivered` |
| 2, 3 | `HandoverTo` passes the WebSocket listener (unwrapped, `wsRawLn`) and every debug listener (`DebugListen`, by configured address); the child adopts them, `serveDebug` uses an adopted listener first, and `Listen` binds `listen_ws` after any adoption that did not supply it (systemd too). | `TestHandoverPassesWSAndMetricsListeners` |
| 4 | `ExtractClientIP` takes the direct peer from `req.RemoteAddr`; `rawAddr` is only a fallback when it parses as an IP. | `TestWebSocket_ClientIPExtraction` (Origin-URL case) |
| 5 | `chainPolicy` applies the `allow_relay_hops` default-deny only to relay hops; a lone target hop is a local rendezvous. `addrEqual` matches a wildcard bind only against this host's own addresses. | `TestChainedJumphostTarget_TerminalWithoutRelayHops`, `TestAddrEqualWildcard` |
| 6 | BFD expiry logs `dead-peer detected: bfd timeout` and increments `relay_bfd_dead_peer_total` (active and standby carriers, both sides). | netns `bfd-dead-peer-detected` (0.65 s) |
| 7 | Strict mode (no `--allow-ha`) probes UDP before resuming when the UDP carrier died, and aborts after two consecutive failed probes in one outage. | netns `bfd-without-ha-aborts` (4.4 s); no unit test for the resume path |
| 8 | The HUD arms a timer at disruption so the OSC 9/777 notification fires while a single attempt blocks. | `TestHUD_NotificationDuringBlockedAttempt` |
| 9 | Harness: IPv6 addresses added `nodad`, and the v6 ping retries like the v4 ones. | netns `netns-paths` |
