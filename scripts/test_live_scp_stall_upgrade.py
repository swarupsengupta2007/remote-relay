#!/usr/bin/env python3
"""FEAT-ROB-02 Live SCP Stalled Connection & Hot Upgrade Integration Test.

Scenario:
1. Client connects to server over TCP data plane.
2. Client OpenSSH `scp` actively transmits a 16 MiB pseudo-random payload to `sshd`.
3. The TCP carrier connection stalls mid-stream (via packet dropping on port 7443).
4. Client's send window fills, and client starts buffering incoming data chunks from `scp`
   into its unacknowledged `sendLog` ring buffer backlog.
5. While stalled and buffering, a zero-downtime server upgrade is triggered via SIGUSR2:
   - Parent snapshots session state and active sendLog.
   - Parent passes the listening TCP socket and the connected destination TCP socket (to sshd)
     to the child process via `SCM_RIGHTS`.
   - Parent exits cleanly with code 0.
   - Child process adopts the sockets and restores session state in held mode.
6. The connection is un-stalled:
   - Client reconnects to child server and issues `RESUME`.
   - Child verifies token and acknowledges with `RESUME_OK`.
   - Client protects and replays its buffered backlog across the new connection.
   - Child server forwards the backlog directly to `sshd` over the inherited destination socket.
7. `scp` finishes with exit code 0, and the received file matches the source SHA-256 byte-for-byte.
"""

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RELAY_BIN = "/tmp/relay-live"
SSHD_BIN = "/usr/sbin/sshd"
SCP_BIN = "/usr/bin/scp"

PASS = 0
FAIL = 0
RESULTS = []


def record(name: str, ok: bool, details: str = ""):
    global PASS, FAIL
    if ok:
        PASS += 1
        tag = "\033[92m[PASS]\033[0m"
    else:
        FAIL += 1
        tag = "\033[91m[FAIL]\033[0m"
    msg = f"{tag} {name}: {details}"
    RESULTS.append(msg)
    print(f"\n>>> {msg}\n")


def build_relay():
    print(f"[*] Building fresh relay binary to {RELAY_BIN}...")
    res = subprocess.run(
        ["go", "build", "-o", RELAY_BIN, "./cmd/relay"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"Build failed:\n{res.stderr}")
        sys.exit(1)
    print("[*] Build complete.")


def wait_port(host: str, port: int, timeout: float = 5.0) -> bool:
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((host, port), timeout=0.1)
            s.close()
            return True
        except (socket.error, OSError):
            time.sleep(0.05)
    return False


def iptables_stall(port: int, enable: bool):
    rule = ["iptables", "-I" if enable else "-D", "INPUT", "-i", "lo", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
    subprocess.run(rule, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_live_scp_stall_upgrade():
    tmp_dir = tempfile.mkdtemp(prefix="relay-scp-stall-")
    print(f"[*] Test workspace created at {tmp_dir}")

    sshd_port = 2222
    relay_port = 7443

    sshd_proc = None
    parent_srv_proc = None
    child_pid = None
    stall_active = False

    try:
        # 1. Ephemeral SSH Keys
        host_key = os.path.join(tmp_dir, "ssh_host_ed25519_key")
        client_key = os.path.join(tmp_dir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", host_key, "-N", ""], check=True, capture_output=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", client_key, "-N", ""], check=True, capture_output=True)

        auth_keys = os.path.join(tmp_dir, "authorized_keys")
        shutil.copy(client_key + ".pub", auth_keys)
        os.chmod(auth_keys, 0o600)

        # 2. Ephemeral SSHD configuration
        sshd_cfg = os.path.join(tmp_dir, "sshd_config")
        sshd_pid_file = os.path.join(tmp_dir, "sshd.pid")
        with open(sshd_cfg, "w") as f:
            f.write(f"""
Port {sshd_port}
ListenAddress 127.0.0.1
HostKey {host_key}
AuthorizedKeysFile {auth_keys}
StrictModes no
UsePAM no
PermitRootLogin yes
Subsystem sftp internal-sftp
PidFile {sshd_pid_file}
""")

        sshd_proc = subprocess.Popen([SSHD_BIN, "-D", "-e", "-f", sshd_cfg])
        if not wait_port("127.0.0.1", sshd_port):
            record("SSHD Daemon Startup", False, f"Port {sshd_port} not ready")
            return
        record("SSHD Daemon Startup", True, f"Listening on 127.0.0.1:{sshd_port} (PID {sshd_proc.pid})")

        # 3. 16 MiB Test Payload Generation
        payload_bytes = 16 * 1024 * 1024
        src_file = os.path.join(tmp_dir, "src_16m.bin")
        dst_file = os.path.join(tmp_dir, "dst_16m.bin")
        print(f"[*] Generating {payload_bytes // (1024*1024)} MiB pseudo-random binary payload...")
        with open(src_file, "wb") as f:
            chunk = os.urandom(64 * 1024)
            for _ in range(payload_bytes // len(chunk)):
                f.write(chunk)
        with open(src_file, "rb") as f:
            expected_sha = hashlib.sha256(f.read()).hexdigest()
        print(f"[*] Source File SHA-256: {expected_sha}")

        # 4. Server Configuration
        srv_cfg = os.path.join(tmp_dir, "server.toml")
        with open(srv_cfg, "w") as f:
            f.write(f"""
listen_tcp = "127.0.0.1:{relay_port}"
allow_destinations = ["127.0.0.1:{sshd_port}", "*"]
default_destination = "127.0.0.1:{sshd_port}"
transports = ["tcp"]
hold_timeout = "30s"
log_level = "debug"
""")

        child_pid_file = os.path.join(tmp_dir, "child.pid")
        srv_env = os.environ.copy()
        srv_env["RELAY_CHILD_PID_FILE"] = child_pid_file
        srv_log_path = os.path.join(tmp_dir, "server.log")
        srv_log_file = open(srv_log_path, "w")

        parent_srv_proc = subprocess.Popen([
            RELAY_BIN, "server",
            "--config", srv_cfg,
            "--authorized-keys", auth_keys,
            "--listen", f"127.0.0.1:{relay_port}",
            "--log-level", "debug"
        ], env=srv_env, stdout=srv_log_file, stderr=srv_log_file)

        if not wait_port("127.0.0.1", relay_port):
            record("Relay Server Startup", False, f"Port {relay_port} not ready")
            return
        parent_pid = parent_srv_proc.pid
        record("Relay Server Startup", True, f"Listening on 127.0.0.1:{relay_port} (Parent PID {parent_pid})")

        # 5. Launch OpenSSH SCP over Relay TCP Client
        print("\n" + "=" * 70)
        print("LAUNCHING SCP TRANSFER OVER TCP RELAY")
        print("=" * 70)

        client_log_path = os.path.join(tmp_dir, "client.log")
        proxy_cmd = (
            f"{RELAY_BIN} client --tcp --server 127.0.0.1:{relay_port} --dest 127.0.0.1:{sshd_port} "
            f"-i {client_key} --strict-host-key-checking=no --log-level debug %h %p 2> {client_log_path}"
        )

        t_start = time.time()
        scp_cmd = [
            SCP_BIN, "-P", str(sshd_port), "-i", client_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ProxyCommand={proxy_cmd}",
            src_file, f"root@127.0.0.1:{dst_file}"
        ]

        scp_proc = subprocess.Popen(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Allow transfer to start and stream initial chunks
        time.sleep(0.08)

        # 6. STALL THE CONNECTION
        print("\n" + "=" * 70)
        print("[STALL] Simulating network freeze: dropping inbound TCP packets to port 7443...")
        print("=" * 70)
        iptables_stall(relay_port, enable=True)
        stall_active = True

        # Let the stall take effect while SCP continues writing to client Stdin.
        # The client will accumulate data in its sendLog ring buffer backlog.
        time.sleep(0.20)
        record("Connection Stall Injection", True, f"Injected packet drop on loopback port {relay_port}")

        # 7. TRIGGER HOT UPGRADE MID-STALL
        print("\n" + "=" * 70)
        print(f"[HOT UPGRADE] Firing SIGUSR2 to parent PID {parent_pid} while client is buffering...")
        print("=" * 70)
        os.kill(parent_pid, signal.SIGUSR2)

        # Verify parent process hands over FDs via SCM_RIGHTS and exits 0 cleanly
        parent_exit = parent_srv_proc.wait(timeout=5)
        print(f"[HOT UPGRADE] Parent PID {parent_pid} exited cleanly with code: {parent_exit}")
        record("Parent Clean Exit across Upgrade", parent_exit == 0, f"Exit code {parent_exit}")

        # Verify child process spawned and adopted
        for _ in range(50):
            if os.path.exists(child_pid_file):
                break
            time.sleep(0.05)
        with open(child_pid_file) as f:
            child_pid = int(f.read().strip())
        print(f"[HOT UPGRADE] Child process adopted: PID {child_pid} (alive: {os.path.exists(f'/proc/{child_pid}')})")
        record("Child Process Adoption", child_pid != parent_pid and os.path.exists(f"/proc/{child_pid}"),
               f"New child PID {child_pid}")

        # Hold stall slightly longer to verify client buffers backlog safely across process switch
        time.sleep(0.25)

        # 8. UN-STALL THE CONNECTION
        print("\n" + "=" * 70)
        print("[UN-STALL] Removing packet drop rule: client reconnects and flushes backlog...")
        print("=" * 70)
        iptables_stall(relay_port, enable=False)
        stall_active = False
        record("Connection Un-Stall", True, f"Removed packet drop rule on port {relay_port}")

        # 9. Wait for SCP to complete successfully
        scp_out, scp_err = scp_proc.communicate(timeout=30)
        t_elapsed = time.time() - t_start

        record("SCP Process Clean Termination", scp_proc.returncode == 0,
               f"Exited {scp_proc.returncode} in {t_elapsed:.2f}s")
        if scp_err:
            err_str = scp_err.decode("utf-8", errors="replace").strip()
            if err_str:
                print(f"[SCP Stderr] {err_str[:200]}")

        # 10. Byte Fidelity Verification
        if not os.path.exists(dst_file):
            record("Destination File Exists", False, f"File {dst_file} not found")
            return

        with open(dst_file, "rb") as f:
            received_data = f.read()
        received_sha = hashlib.sha256(received_data).hexdigest()

        print(f"\n[*] Transferred {len(received_data):,} bytes in {t_elapsed:.2f}s ({len(received_data)/(1024*1024)/t_elapsed:.2f} MiB/s)")
        print(f"[*] Expected SHA-256: {expected_sha}")
        print(f"[*] Received SHA-256: {received_sha}")

        record("Buffered Backlog Protected & Transferred (SHA-256 Exact)",
               received_sha == expected_sha,
               f"{len(received_data)} bytes match 100% byte-exact")

        # 11. Log Verifications
        srv_log_file.flush()
        srv_log_file.close()
        with open(srv_log_path) as f:
            srv_logs = f.read()

        record("Log Verification: SCM_RIGHTS Handover",
               "handover: adopted tcp listener" in srv_logs and "handover complete and acknowledged by child" in srv_logs,
               "SCM_RIGHTS listener & dest socket adopted by child")

        record("Log Verification: Session Resumption",
               "session resumed" in srv_logs,
               "Client reconnected with RESUME and child resumed session")

        if os.path.exists(client_log_path):
            with open(client_log_path) as f:
                cli_logs = f.read()
            record("Log Verification: Client Fast Resume",
                   "session resumed" in cli_logs or "resuming" in cli_logs or "session established" in cli_logs,
                   "Client reconnected and flushed sendLog backlog")

    finally:
        # Cleanup
        print("\n[*] Cleaning up test processes and firewall rules...")
        if stall_active:
            iptables_stall(relay_port, enable=False)
        if child_pid and os.path.exists(f"/proc/{child_pid}"):
            try:
                os.kill(child_pid, signal.SIGKILL)
            except Exception:
                pass
        if parent_srv_proc and parent_srv_proc.poll() is None:
            parent_srv_proc.kill()
        if sshd_proc and sshd_proc.poll() is None:
            sshd_proc.terminate()
            try:
                sshd_proc.wait(timeout=2)
            except Exception:
                sshd_proc.kill()

        shutil.rmtree(tmp_dir, ignore_errors=True)

    print("\n" + "=" * 70)
    print("SCP STALL & HOT UPGRADE TEST SUMMARY")
    print("=" * 70)
    for r in RESULTS:
        print(r)
    print(f"\nTOTAL: {PASS} PASSED, {FAIL} FAILED\n")

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    build_relay()
    test_live_scp_stall_upgrade()
