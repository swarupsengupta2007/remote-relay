# FEAT-UTL-04: Reverse Relay & NAT Gateway Mode (Inverted Tunnel)

## 1. Executive Summary

In enterprise, IoT, edge, and homelab environments, target servers (such as internal databases, build workers, NAS devices, or management planes) frequently sit behind strict NAT firewalls, cellular CGNATs, or corporate VPCs with zero open inbound ports. Standard bastion/jumphost tunneling models fail because the relay server cannot reach inward to establish a connection.

**FEAT-UTL-04** introduces **Reverse Relay & NAT Gateway Mode (Inverted Tunnel)** into `remote-relay`. This allows an agent inside a restricted network to establish an outbound, authenticated control connection to a public relay server, pin and reserve named logical targets (e.g. `homelab`, `nas`, `k8s-master`), and bind local TCP endpoints on demand when external clients request access.

Key architectural highlights:
1. **Key-Bound Target Reservation**: Target names are bound to SSH public keys with a 15-second grace period (`agent_hold_timeout`) preventing race conditions, target hijacking, or hostile takeover during transient network disconnects.
2. **Strict RBAC via `authorized_keys`**: Integrates `permitlisten="<target1>,<target2>"` into SSH authorized key options and identity checks, restricting which agents may claim which target names.
3. **On-Demand Reverse Data Sessions (`agent-data`)**: Dual-session symmetrical in-memory bridging (`newMemoryPipePair`) pairs a client relay session with an on-demand reverse agent session without holding idle data sockets open.
4. **Resiliency & Independent Reconnects**: Both client and agent legs operate as independent relay sessions with ring buffers, resume tokens, cryptographic fallbacks, and BFD/ping-pong heartbeats.
5. **Zero External Dependencies**: Implemented entirely with Go standard library and existing crypto primitives, maintaining 100% test coverage and race-detector cleanliness.

---

## 2. Technical Architecture & Sequence Diagrams

### 2.1 Agent Registration & Rendezvous Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client (`relay client --target nas`)
    participant Server as Relay Server
    participant Agent as Edge Agent (`relay agent --name nas`)
    participant Target as Local Service (e.g. 127.0.0.1:22)

    Note over Server,Agent: Phase 1: Persistent Authenticated Control Channel
    Agent->>Server: KEX Handshake (Ed25519)
    Agent->>Server: AGENT_REGISTER {Name: "nas", Dest: "127.0.0.1:22", AllowDest: [...]}
    Server->>Server: Verify SSH Key & RBAC `permitlisten="nas"`
    Server->>Server: Pin target "nas" in AgentRegistry
    Server-->>Agent: AGENT_REGISTER_OK {Target: "nas"}
    loop Heartbeat Keepalive
        Agent->>Server: PING
        Server-->>Agent: PONG
    end

    Note over Client,Server: Phase 2: Client Connection & Rendezvous
    Client->>Server: KEX + HELLO {Target: "nas"}
    Server->>Server: Lookup "nas" in AgentRegistry -> Online
    Server->>Server: Create In-Memory Pipe Pair (clientPipe, agentPipe)
    Server-->>Agent: AGENT_BIND (Control Channel) {BindID: "b-...", Target: "nas"}

    par Parallel Data Connection Setup
        Agent->>Target: Dial TCP "127.0.0.1:22"
        Agent->>Server: Outbound Dial + HELLO {Role: "agent-data", ResumeToken: "b-..."}
        Server-->>Agent: HELLO_OK
        Agent->>Server: AGENT_BIND_OK {BindID: "b-...", Status: "ok"}
    and Client Handshake Completion
        Server-->>Client: HELLO_OK
    end

    Note over Client,Target: Phase 3: Dual Symmetrical Pump Transfer
    Client<-->>Server: Client Leg (TCP/QUIC/KCP/WS)
    Server<-->>Server: In-Memory Bridge (clientPipe <-> agentPipe)
    Server<-->>Agent: Agent Leg (TCP/QUIC/KCP/WS)
    Agent<-->>Target: Local Socket (TCP 127.0.0.1:22)
```

---

## 3. Implementation Details

### 3.1 Wire Protocol Additions (`internal/proto`)

Four new frame types and constants were introduced:
- `TypeAgentRegister` (`0x17`): Payload [`AgentRegister`](file:///root/remote-relay/internal/proto/messages.go) carrying target name, client nonce, default destination, destination whitelist, and authentication offer.
- `TypeAgentRegisterOK` (`0x18`): Payload [`AgentRegisterOK`](file:///root/remote-relay/internal/proto/messages.go) acknowledging reservation.
- `TypeAgentBind` (`0x19`): Payload [`AgentBind`](file:///root/remote-relay/internal/proto/messages.go) dispatched by server over control channel to request reverse connection.
- `TypeAgentBindOK` (`0x1A`): Payload [`AgentBindOK`](file:///root/remote-relay/internal/proto/messages.go) confirming local service dial and data leg establishment.
- `RoleAgentData = "agent-data"`: Specialized session role identifying on-demand reverse data sessions.
- `DestTargetPrefix = "target:"`: Standardized destination prefix identifying named reverse targets.

### 3.2 RBAC & `authorized_keys` (`internal/auth`)

1. **Option Parsing**: Added `permitlisten="..."` option support in [`internal/auth/ssh.go`](file:///root/remote-relay/internal/auth/ssh.go), parsing comma-separated allowed targets or wildcard `*`.
2. **Identity Struct**: Extended [`auth.Identity`](file:///root/remote-relay/internal/auth/auth.go) and `AuthorizedKeyEntry` with `PermittedTargets []string`.
3. **Verification**: `Verify()` enforces that when `PermittedTargets` is specified, an agent registering target `name` must match one of the entries or `*`.

### 3.3 Server Agent Registry & Rendezvous (`internal/relay/agent_registry.go`)

- Implemented [`AgentRegistry`](file:///root/remote-relay/internal/relay/agent_registry.go) tracking registered targets, pinned Ed25519 fingerprints, raw public keys, control connections, and pending binds.
- **Key Pinning & Grace Period**: When an agent disconnects, `OnControlDisconnect` begins a configurable grace period (`agent_hold_timeout`, default 15s). During this window, no other key may hijack the target name. If the same key reconnects, the target reservation is transparently restored.
- **In-Memory Pipe (`memoryPipeConn`)**: Full `net.Conn` implementation backed by bidirectional Go `io.Pipe`, implementing `SetDeadline`, `CloseWrite`, and proper EOF propagation.
- **Thread Safety (`safeConn`)**: Synchronized frame writer wrapper protecting control connections from concurrent heartbeat, ping, pong, and bind request/response writes.

### 3.4 Reverse Relay Agent Engine (`internal/relay/agent.go`)

- [`RunAgent(ctx, cfg, log)`](file:///root/remote-relay/internal/relay/agent.go): Long-running daemon loop that connects to the relay server, registers the target, handles periodic heartbeats, and spawns `handleAgentBind` on bind requests.
- **Policy Enforcement**: Validates destination overrides against `cfg.AllowDestinations` (`agent.DestinationAllowed(dest)`). Disallowed overrides fail-closed with error messages sent back to server.
- **Phase Cut Handling**: Strips outer crypto layers after `HELLO_OK` and starts the internal bidirectional IO pump bridging local destinations to the relay server.
- **Exponential Backoff**: Automatically reconnects with exponential backoff if the control channel is severed.

### 3.5 Client and CLI Integration (`cmd/relay/main.go`)

- **Subcommand `agent`**:
  ```bash
  relay agent --server example.com:7443 --name homelab --dest 127.0.0.1:22 -i ~/.ssh/id_ed25519
  ```
- **Client Flag `--target`**:
  ```bash
  relay client --server example.com:7443 --target homelab -i ~/.ssh/id_ed25519
  ```
- Also supports destination-style syntax: `relay client --server example.com:7443 --dest target:homelab` or OpenSSH `ProxyCommand relay client --server example.com:7443 --target %h %p`.

---

## 4. Verification & Testing

Unit, integration, and soak test suites verified across the codebase:
- [`TestAgentRegistrationAndReservation`](file:///root/remote-relay/internal/relay/agent_test.go): Verified agent registration, key pinning, and rejection of different keys attempting to claim existing targets.
- [`TestAgentPermitListenRBAC`](file:///root/remote-relay/internal/relay/agent_test.go): Verified `permitlisten` enforcement and rejection of unpermitted target registrations.
- [`TestAgentEndToEndDataTransfer`](file:///root/remote-relay/internal/relay/agent_test.go): Verified full bidirectional data exchange through inverted tunnel from client to target echo server.
- [`TestAgentDestinationAllowedPolicy`](file:///root/remote-relay/internal/relay/agent_test.go): Verified agent destination whitelisting and fail-closed rejection of disallowed overrides.
- [`TestAgentControlGracePeriodAndReconnect`](file:///root/remote-relay/internal/relay/agent_test.go): Verified 15-second grace period reservation hold and reconnection of dropped control connection.
- **Race Detector**: All agent tests pass cleanly with `go test -race -count=5 ./internal/relay/...`.
- **Full Suite**: Complete repository test suite (`go test ./...`) and `go vet ./...` pass with 0 failures and 0 warnings.
