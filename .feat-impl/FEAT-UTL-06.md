# FEAT-UTL-06: Chained Jumphost Rendezvous to NATed Terminal (`HopSpec.Target`)

## 1. Executive Summary

In complex network topologies (such as multi-tier enterprise DMZs, hybrid cloud VPCs, and isolated lab environments), machines are often separated by multiple intermediate bastion/jumphost relays and situated behind strict NAT, CGNAT, or firewall boundaries. [FEAT-UTL-05](.feat-impl/FEAT-UTL-05.md) provided arbitrary multi-hop jumphost chaining (`-J`) for dialable IP/hostname endpoints, while [FEAT-UTL-04](.feat-impl/FEAT-UTL-04.md) introduced reverse relay agent rendezvous for single-server setups.

**FEAT-UTL-06** unifies these two capabilities by enabling **Chained Jumphost Rendezvous to NATed Terminals**. Clients can traverse one or more intermediate jumphost relays and terminate directly at a private NATed agent registered via `relay agent` using the wire-reserved `HopSpec.Target` field.

### Key Architectural Capabilities:
1. **Zero-Port-Forwarding Chained Access**: Private servers behind NAT/CGNAT need no public IP or listening port to be reached across arbitrary multi-hop relay bastions.
2. **Seamless Wire Protocol Integration**: Utilizes the wire-declared [`proto.HopSpec.Target`](file:///root/remote-relay/internal/proto/messages.go#L94) field, ensuring complete backwards compatibility with existing framing (`TypeChain`, `TypeChainOK`, `TypeHelloOK`).
3. **End-to-End Cryptographic Security**: Retains per-hop cryptographic KEX attestation ([J-D3](file:///root/remote-relay/features.md#L258)) and relayed challenge signing ([J-D2](file:///root/remote-relay/features.md#L258)) across all intermediate relays.
4. **Independent Hop Resilience & Per-Hop Resume**: Carrier drop on any leg (client $\leftrightarrow$ jumphost 1, jumphost 1 $\leftrightarrow$ jumphost 2, or agent $\leftrightarrow$ jumphost 2) triggers independent reconnects and seamless retransmission from local ring buffers without dropping the end-to-end session.
5. **Flexible CLI Syntax**:
   - `relay client -J jump.example.com:7443 --target homelab [--dest 127.0.0.1:22]`
   - `relay client -J j1:7443,j2:7443 --target homelab`
   - `relay client -J j1:7443,target:homelab`
   - `relay client -J j1:7443 --server j2:7443 --target homelab`

---

## 2. Technical Architecture & Sequence Diagrams

### 2.1 Multi-Hop Chained Target Rendezvous Flow

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client (`relay client -J j1,j2 --target homelab`)
    participant J1 as Relay Jumphost 1 (`j1`)
    participant J2 as Relay Jumphost 2 (`j2`)
    participant Agent as Private Agent (`relay agent --name homelab`)
    participant Dest as Local Service (e.g. 127.0.0.1:22)

    Note over J2,Agent: Prior: Agent establishes reverse control channel with J2
    Agent->>J2: AGENT_REGISTER {Name: "homelab"}
    J2-->>Agent: AGENT_REGISTER_OK

    Note over Client,J1: Phase 1: Client dials Hop 1 (J1)
    Client->>J1: KEX Init / Reply (authenticated)
    Client->>J1: CHAIN {Hops: [j2, target:homelab], Dest: "target:homelab"}

    Note over J1,J2: Phase 2: J1 dials Hop 2 (J2) and relays attestation
    J1->>J2: KEX Init / Reply
    J1-->>Client: Relayed AUTH_OK {Hop: 2, Attest: J2_KEX}
    Client-->>J1: AUTH Signature for Hop 2
    J1->>J2: Forwarded AUTH Signature
    J1->>J2: CHAIN {Hops: [target:homelab], Dest: "target:homelab"}

    Note over J2,Agent: Phase 3: J2 Target Rendezvous
    J2->>J2: Inspect Hops[0]: Target == "homelab"
    J2->>Agent: AGENT_BIND {Target: "homelab", Dest: "127.0.0.1:22"}
    par Parallel Agent Data Leg
        Agent->>Dest: Dial TCP 127.0.0.1:22
        Agent->>J2: Connect + HELLO {Role: "agent-data", BindID: "..."}
        J2-->>Agent: HELLO_OK
    and J2 Rendezvous Completion
        J2->>J2: Bridge clientPipe <-> agentPipe
        J2-->>J1: CHAIN_OK {Hop: 3, Addr: "target:homelab"}
        J2-->>J1: HELLO_OK (Session J2)
    end

    Note over Client,J1: Phase 4: Final Handshake Propagation
    J1-->>Client: CHAIN_OK {Hop: 3, Addr: "target:homelab"}
    J1-->>Client: CHAIN_OK {Hop: 2, Addr: "j2"}
    J1-->>Client: HELLO_OK (Session J1)

    Note over Client,Dest: Phase 5: End-to-End Data Plane
    Client<-->>J1: Inbound Pump (Leg 1)
    J1<-->>J2: Intermediate Pump (Leg 2)
    J2<-->>Agent: In-Memory Bridge -> Reverse Data Pump (Leg 3)
    Agent<-->>Dest: Local Socket (TCP)
```

---

## 3. Implementation Details

### 3.1 Hop Specification & CLI Parsing (`internal/config`)

- **`ParseHopSpec`** ([`internal/config/chain.go`](file:///root/remote-relay/internal/config/chain.go)):
  - Added support for `target:<name>` tokens in `-J` entries.
  - Strips optional query/fragment metadata and populates `hop.Target = <name>`.
- **`Client.validateChain`** ([`internal/config/chain.go`](file:///root/remote-relay/internal/config/chain.go)):
  - Enforces that a target hop must be the terminal hop in the chain (`i == len(hops)-1`).
  - Ensures a target is not specified simultaneously in both `--target` and inline `-J`.
  - Disallows standalone single-hop target chains without at least one intermediate relay (`len(hops) >= 2`).
- **`Client.hasTargetChain` & `Client.Validate`** ([`internal/config/config.go`](file:///root/remote-relay/internal/config/config.go)):
  - When `--target <name>` is provided with `-J`, `--server` is optional: the client connects to the intermediate jumphosts and names the NATed agent as the terminal target.

### 3.2 Client Chain Assembly (`internal/relay/client_chain.go`, `client.go`)

- **`clientChainHello`**:
  - Dynamically builds the hop slice: `[jumphosts..., server (if set), target (if set)]`.
  - Determines canonical destination: if `--dest` is not specified, defaults to `proto.DestTargetPrefix + targetName` (`target:<name>`).
  - Originator verifies host-key attestations for each intermediate relay while respecting that the terminal target is served via agent rendezvous.
- **Data-Plane Relayed Authentication**:
  - Populates `chainHops` and `dest` in [`client.go`](file:///root/remote-relay/internal/relay/client.go) so that mid-session relayed authentication challenges match the destination and hop structure.

### 3.3 Server-Side Chain Rendezvous (`internal/relay/chain.go`)

- **`chainPolicy`**:
  - Allows terminal hops where `h.Target != ""` without attempting network IP address resolution via `net.SplitHostPort`.
  - Validates `s.Config().TargetAllowed(h.Target)` against server policy.
  - Ensures target hops do not trigger false positives in loop detection (`h.Addr != ""`).
- **Destination Verification**:
  - Allows empty destination for chained target requests (`isChainedTarget`), enabling agents to use their default destination unless overridden by the client.
- **Target Rendezvous in `handleChain`**:
  - When `next.Target != ""`, the server recognizes itself as the terminal rendezvous relay for the private agent.
  - Checks agent status via `s.agentReg.GetTarget(next.Target)`.
  - Checks RBAC permissions via `id.PermittedTargets`.
  - Calls `s.agentReg.CreateBind(next.Target, targetDestOverride, originIP, conn.RemoteAddr())`.
  - Waits on `pb.ReadyCh` for the agent's reverse data session to connect.
  - Emits `proto.TypeChainOK` for `nextHopIndex` with `Addr: "target:" + next.Target`.
  - Emits `proto.TypeHelloOK` for `ownHopIndex`.
  - Attaches `clientPipe` directly to `sessionIO` and starts the pump.

---

## 4. Verification & Testing

Comprehensive tests in [`internal/relay/chain_target_test.go`](file:///root/remote-relay/internal/relay/chain_target_test.go) and [`internal/config/chain_test.go`](file:///root/remote-relay/internal/config/chain_test.go):

| Test Case | Description | Result |
| :--- | :--- | :--- |
| `TestChainedTargetConfig` | Validates `target:<name>` in `ParseHopSpec`, optional server validation, and policy rejections | **PASS** |
| `TestChainedJumphostTarget_SingleHop` | Client $\to$ `jump` $\to$ `target:homelab` with 32 KiB bidirectional payload transfer | **PASS** |
| `TestChainedJumphostTarget_MultiHop` | Client $\to$ `j1` $\to$ `j2` $\to$ `target:homelab` with 32 KiB bidirectional payload transfer | **PASS** |
| `TestChainedJumphostTarget_HopSyntax` | Verifies `-J j1,target:homelab` CLI syntax | **PASS** |
| `TestChainedJumphostTarget_DestinationOverride` | Client specifies `--dest` override routed across chain to agent-whitelisted endpoint | **PASS** |
| `TestChainedJumphostTarget_Policies` | Enforces offline agent rejection, server `allow_targets` refusal, and agent destination refusal | **PASS** |
| `TestChainedJumphostTarget_ResumeOnHopDrop` | Drops carrier at intermediate hop during active transfer; verifies transparent reconnect and zero byte loss | **PASS** |
