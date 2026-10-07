# FEAT-ROB-04: Tiered Disk-Spill Storage for Ring Buffers

## 1. Executive Summary

In high-throughput, multi-session network relays, session ring buffers ([`session.Ring`](../../internal/session/ringbuf.go)) are typically backed by RAM slices. In `remote-relay`, buffer memory was previously bounded by a per-session cap (default 64 MiB) and a global process-wide budget ([`session.Budget`](../../internal/session/budget.go), default 512 MiB). During prolonged carrier disconnections (e.g. 5–10 minutes) under massive bulk transfers (gigabytes of file copies, database dumps, or VM image syncs), RAM buffers fill to capacity rapidly. This forced upstream reads to pause, risked stalls across competing sessions, and exposed the process to OOM terminations on memory-constrained servers.

**FEAT-ROB-04** solves this by implementing **Tiered Disk-Spill Storage for Ring Buffers**. The ring buffer is architected into a hybrid tiered memory hierarchy:
- **Tier 1 (L1 RAM Buffer)**: Low-latency in-memory circular slice bounded by `L1Cap` (default 8 MiB) and global RAM budget.
- **Tier 2 (L2 Encrypted Disk Spill File)**: Ephemeral, unlink-on-open temporary file utilizing fixed 64 KiB plaintext blocks encrypted with AES-256-GCM.
- **Dynamic Spill Triggering**: Spills oldest RAM blocks to disk when unacknowledged bytes exceed `L1Cap` OR when the global memory `Budget` is exhausted. Spilling releases RAM budget immediately back to the global pool.
- **Zero-Copy Resumption Streaming**: On `RESUME`, reads stream sequentially from the spill file with single-block caching without reloading backlogs into RAM.
- **Block Reclamation & Truncation**: Reclaims disk space on-the-fly using `fallocate(FALLOC_FL_PUNCH_HOLE)` as ACKs advance, resetting files to 0 bytes when fully drained.
- **Hot Restart Preservation**: Full compatibility with zero-downtime hot restart ([FEAT-ROB-02](FEAT-ROB-02.md)) snapshotting and restore.

---

## 2. Technical Architecture & Design Decisions

### 2.1 Tiered Memory Layout

The ring buffer presents a single, strictly continuous logical stream offset range $[base, base + length)$:

```
Stream Offsets:   [base ------------------------------------------ base + length)
Zone Layout:      [=== L2 Encrypted Disk Spill ===][==== L1 Resident RAM ====]
                   ^                              ^                         ^
                   base                   base + spillLen             base + length
```

- **Zone 1 (L2 Disk Spill)**: Spanned by $[base, base + spillLen)$. Stored as an append-only sequence of encrypted blocks on disk.
- **Zone 2 (L1 In-Memory RAM)**: Spanned by $[base + spillLen, base + length)$. Stored in circular slice `r.buf`.
- **Seamless Boundary**: `r.Slice(from, max)` automatically bridges Zone 1 and Zone 2 without caller awareness.

### 2.2 On-Disk Block Encryption & Fixed Stride

To guarantee constant-time block addressing without an in-memory index table:
- Every block is encrypted using **AES-256-GCM**.
- Ephemeral 32-byte key is generated via `crypto/rand` per spill file, securely zeroed on `Release()`.
- On-disk block format:
  ```text
  +------------------+-----------------------------+--------------------+
  | 4 bytes          | 65536 bytes                 | 16 bytes           |
  | BigEndian uint32 | AES-256-GCM Encrypted Block | AES-GCM Auth Tag   |
  | Payload Length   | (Padded to 64 KiB)          |                    |
  +------------------+-----------------------------+--------------------+
  Total Stride: 65556 bytes
  ```
- **Arithmetic Offset Calculation**: The physical file offset for block index $B$ is unconditionally:
  $$\text{DiskOffset} = B \times 65556$$
- Nonce generation uses a 96-bit monotonic counter: `[uint64(blockIndex), uint32(0)]`.
- Additional Authenticated Data (AAD) binds each block to its block index: `[uint64(blockIndex)]`.

### 2.3 Ephemeral File Management & Punch Hole Space Reclamation

1. **Unlink on Open**: Spilled temporary files are created with `os.CreateTemp` and immediately unlinked via `os.Remove(f.Name())`. If the process terminates abnormally, the Linux kernel reclaims storage instantly with zero lingering disk artifacts.
2. **`fallocate(FALLOC_FL_PUNCH_HOLE)`**: As acknowledgments advance `base` past full 64 KiB blocks, `PunchHole` issues:
   ```go
   unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, punchStart, punchLen)
   ```
   releasing physical disk blocks on ext4, XFS, and Btrfs while preserving logical offsets.
3. **Reset on Catch-up**: When the consumer fully catches up (`spillLen == 0`), `file.Truncate(0)` resets the file descriptor and block counters to 0.

### 2.4 Dual-Trigger Spill Mechanism

Spilling from RAM to disk occurs under two distinct triggers:
1. **L1 Threshold Trigger**: When unacknowledged RAM bytes exceed `L1Cap` (default 8 MiB, configured via `--spill-l1-bytes` or `spill_l1_bytes` in TOML).
2. **Global RAM Budget Exhaustion**: When `r.budget.TryAcquire()` fails due to memory contention from other concurrent sessions. Spilling 64 KiB to disk calls `r.budget.Release(64 KiB)`, relieving global memory pressure without blocking or dropping sessions.

---

## 3. Configuration & CLI Integration

Tiered storage is configurable across Server, Client, Agent, and SOCKS modes:

### 3.1 TOML Configuration Options
```toml
# In server.toml / client.toml / agent.toml:
spill_dir = "/var/tmp/relay"       # Directory for spill temp files (default: system temp dir)
spill_l1_bytes = 8388608           # Per-session L1 RAM threshold in bytes (default: 8 MiB)
no_spill = false                   # Explicitly disable disk spilling (pure RAM mode)
```

### 3.2 Command-Line Flags
- `--spill-dir DIR`: Directory for encrypted disk spill files.
- `--spill-l1-bytes BYTES`: RAM threshold before spilling to disk.
- `--no-spill`: Disable tiered disk spilling and retain pure in-memory operation.

---

## 4. Verification & Testing Matrix

| Test Case | Package | Location | Verification Focus | Status |
|:---|:---|:---|:---|:---:|
| `TestSpillFile_WriteRead` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L16) | AES-256-GCM block encryption/decryption, padding & read cache | **PASS** |
| `TestSpillFile_HolePunchAndReset` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L60) | `fallocate` hole punching, truncation & block counter reset | **PASS** |
| `TestTieredRing_BasicSpillAndResume` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L94) | Dual-tier append, L1 threshold overflow & sequential read back | **PASS** |
| `TestTieredRing_BudgetRelief` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L137) | Global RAM budget relief under memory pressure | **PASS** |
| `TestTieredRing_SliceStraddle` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L187) | `Slice` reads seamlessly spanning disk Zone 1 and RAM Zone 2 | **PASS** |
| `TestTieredRing_SnapshotRestoreWithSpill` | `session` | [`spill_test.go`](../../internal/session/spill_test.go#L233) | Hot-restart snapshot and restore spanning disk and RAM | **PASS** |
| `TestRelayTieredSpillResume` | `relay` | [`spill_test.go`](../../internal/relay/spill_test.go#L19) | End-to-end carrier disconnection under 512 KiB load with 128 KiB L1 | **PASS** |
| `TestRelaySpillCLIAndConfigFlags` | `relay` | [`spill_test.go`](../../internal/relay/spill_test.go#L145) | CLI flag parsing and TOML overrides for spill options | **PASS** |
| `TestRelayTieredSpillDirect` | `relay` | [`spill_test.go`](../../internal/relay/spill_test.go#L207) | Live tiered ring spill state verification and hole punch drain | **PASS** |
| `Full Suite Race Verification` | `all` | `go test -race ./...` | Concurrency safety across all packages with race detector | **PASS** |
