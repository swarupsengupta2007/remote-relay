# remote-relay — High Availability (HA) Dual-Path System (`--allow-ha`)

## 1. Overview & Objectives

In `remote-relay`, the default transport selection is **QUIC** (or **KCP** when `--kcp` is passed), with **TCP** available via `--tcp`. Previously, if a UDP probe failed during the initial upgrade, the client would silently remain on TCP. This behavior was misleading to users expecting an active UDP data plane.

The **High Availability (`--allow-ha`)** dual-path architecture changes this:
1. **Strict Transport Enforcement by Default**: When the user requests UDP (default QUIC or `--kcp`) without `--allow-ha`, UDP is **strictly mandatory**. If the UDP route cannot be established or is broken, the client fails cleanly rather than silently downgrading to TCP.
2. **High Availability (`--allow-ha`)**: When `--allow-ha` is enabled:
   - The relay keeps both UDP and TCP paths active or monitored concurrently.
   - Priority metric: **`UDP > TCP`**.
   - If UDP is available, data flows over UDP.
   - If UDP fails or is blocked, the relay seamlessly **downgrades** to TCP without disrupting the user stream.
   - While running on TCP, the client continuously probes the UDP route in the background. Once UDP connectivity is restored, the relay seamlessly **upgrades** back to UDP.
   - Neither upgrade nor downgrade disrupts the end-to-end user stream (e.g. SSH session stays alive and byte-exact).

---

## 2. Architecture & State Machine

```
                            +-----------------------------+
                            |   User Application (SSH)    |
                            +--------------+--------------+
                                           |
                                           v
                          +--------------------------------+
                          |   Client Relay Core (Pump)     |
                          |   Traffic Metric: UDP > TCP    |
                          +---------------+----------------+
                                          |
                +-------------------------+-------------------------+
                |                                                   |
                v                                                   v
      [Active / Primary: UDP]                             [Backup / Standby: TCP]
         (QUIC or KCP)                                      (Fallback Route)
                |                                                   |
                +-------------------------+-------------------------+
                                          |
                                          v
                              +-----------------------+
                              | Relay Server (ns-srv) |
                              | Attaches via RESUME   |
                              +-----------------------+
```

### State Transitions in HA Mode (`allow_ha = true`)

1. **Session Initialization**:
   - Initial `HELLO` exchange always takes place over TCP to exchange cryptographic tokens, verify identity, and receive the server's UDP endpoint and probe token.
   - Client probes UDP immediately.
   - **Branch A (UDP available)**: Client switches data plane to UDP (`QUIC` or `KCP`). State: `ACTIVE_UDP`.
   - **Branch B (UDP unavailable)**: Client logs downgrade to TCP and maintains data plane on TCP. Starts background UDP prober. State: `ACTIVE_TCP_PROBING`.

2. **State `ACTIVE_UDP` (Primary Data Flow)**:
   - All session frames pass over UDP.
   - If UDP link drops, suffers hard timeouts, or receives ICMP unreachable / RST:
     - Client enters reconnect loop.
     - With `allow_ha = true`, client falls back to TCP, issues `RESUME`, transfers session state, and resumes data plane on TCP without dropping bytes.
     - State transitions to `ACTIVE_TCP_PROBING`.

3. **State `ACTIVE_TCP_PROBING` (Fallback Data Flow + Background Probing)**:
   - Session data flows over TCP uninterrupted.
   - A background prober periodically sends UDP probes to the server's UDP endpoint.
   - Once the UDP probe succeeds:
     - The client quiesces the active TCP stream (`waitQuiesced`).
     - Sends `SWITCH` frame over TCP with current sequence offsets.
     - Dials UDP (`QUIC` or `KCP`) and issues `RESUME` on the new UDP connection.
     - Swaps the active connection to UDP.
     - State transitions back to `ACTIVE_UDP`.

### Strict Mode (`allow_ha = false`)

- Initial UDP probe failure triggers immediate fatal termination (`ErrNoUDP: UDP route unavailable and --allow-ha not specified`).
- Reconnection attempts strictly target UDP; no silent downgrade to TCP is permitted.

---

## 3. Configuration & CLI Specification

### 3.1 CLI Flag
- `--allow-ha`: Enables High Availability dual-path mode (UDP primary, TCP fallback, continuous background re-probing and seamless dynamic switching).
- **Validation**:
  - Valid with default (QUIC) or `--kcp`.
  - **Mutually exclusive with `--tcp`**: Passing `--tcp` and `--allow-ha` together results in an immediate CLI argument parsing error (exit code `2`).

### 3.2 TOML Configuration (`client.toml`)
```toml
server                = "10.200.1.1:7443"
transport             = "quic"                 # or "kcp"
allow_ha              = true                   # enable HA dual-path mode
ha_probe_interval     = "10s"                  # interval for background UDP probes when downgraded
```

### 3.3 Flag Precedence
- `--allow-ha` CLI flag overrides `allow_ha` in TOML.
- If `--allow-ha` is omitted on the CLI and `allow_ha` is omitted in TOML, default is `false` (strict UDP mode).

---

## 4. Implementation Steps

### Phase 1: Configuration & CLI Flag Support
1. **`internal/config/config.go`**:
   - Add `AllowHA bool` and `HAProbeInterval Duration` to `Client` and `ClientOptions`.
   - Parse `allow_ha` and `ha_probe_interval` in TOML decoding.
   - Enforce validation rule: `TCP` and `AllowHA` cannot both be true.
2. **`cmd/relay/main.go`**:
   - Add `--allow-ha` flag to `runClient`.
   - Validate flag compatibility (`--tcp` + `--allow-ha` returns error 2).
3. **`cmd/relay/main_test.go`**:
   - Unit tests for `--allow-ha` flag, TOML loading, and mutual exclusion with `--tcp`.

### Phase 2: Strict UDP Mode Enforcement
1. **`internal/relay/upgrade.go` & `client.go`**:
   - In `tryUpgrade` / `takeUpgrade`:
     - If UDP probe fails and `!cfg.AllowHA`: return a non-reconnectable fatal error (`proto.ErrNoUDP` or descriptive error) to terminate the client immediately.
     - If UDP probe fails and `cfg.AllowHA`: log `"udp probe failed; operating on tcp in HA mode"` and continue on TCP.

### Phase 3: Dual-Path HA Supervisor & Background Prober
1. **`internal/relay/upgrade.go`**:
   - Implement `startHAProbeSupervisor`:
     - Runs while the session is active on TCP and `cfg.AllowHA` is true.
     - Sends periodic UDP probes at `HAProbeInterval` (default 10s–15s).
     - When a probe succeeds, initiates seamless path switch (`tryUpgrade`).
2. **`internal/relay/client.go`**:
   - Handle dynamic upgrade signals: when background upgrade completes, replace `current` connection with the new UDP connection and advance send offsets.
   - Handle dynamic downgrade: when UDP fails, if `cfg.AllowHA` is true, re-dial TCP, send `RESUME`, swap `current` to TCP, and spawn the HA probe supervisor.

---

## 5. Verification Matrix (Isolated Dual-Netns)

All verification tests run strictly within `ns-srv` <-> `ns-cli` over `veth`:

| Test ID | Scenario | Expected Behavior |
|---|---|---|
| **HA-Unit** | Flag & config validation | `--tcp` + `--allow-ha` errors out with exit code 2; `allow_ha` loads from TOML. |
| **HA-Strict** | No `--allow-ha`, UDP dropped | Client attempts initial UDP probe, fails, and terminates immediately without silent TCP fallback. |
| **HA-InitialFail** | `--allow-ha`, UDP dropped at start | Client falls back to TCP; transfers start. Mid-stream, unblock UDP; client seamlessly upgrades to QUIC/KCP. Transfer completes byte-exact. |
| **HA-Downgrade** | `--allow-ha`, active on QUIC/KCP | Drop UDP mid-stream (`iptables -A ... -p udp -j DROP`). Relay seamlessly downgrades to TCP. Transfer completes byte-exact. |
| **HA-Oscillate** | `--allow-ha`, flapping UDP | Repeatedly drop and restore UDP every few seconds. Traffic flips between UDP and TCP dynamically. Complete 32 MiB transfer byte-exact. |
