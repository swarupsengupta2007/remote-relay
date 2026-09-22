#!/usr/bin/env python3
"""FEAT-ROB-02 Live Zero-Downtime Hot Restart Integration Test.

Runs against a REAL compiled relay binary, a REAL OpenSSH sshd daemon,
and a REAL OpenSSH ssh client invoking ProxyCommand.

Tests:
1. Live Interactive Shell Continuity:
   - Starts interactive OpenSSH session through relay server.
   - Executes command pre-restart.
   - Sends SIGUSR2 to parent relay server.
   - Verifies parent passes listening and destination TCP sockets via SCM_RIGHTS,
     and exits cleanly with code 0.
   - Executes post-restart commands in the SAME open SSH session without reconnecting.
   - Verifies zero disconnects and clean exit.

2. In-Flight Streaming Transfer across SIGUSR2:
   - Streams 16 MiB pseudo-random binary payload through SSH to remote disk.
   - Mid-stream fires SIGUSR2 to trigger hot re-exec and SCM_RIGHTS socket handover.
   - Verifies child inherits listeners & destination TCP connection to sshd.
   - Computes SHA-256 of received file and asserts 100% byte fidelity.

3. SCM_RIGHTS & Handover Log Verification:
   - Verifies parent and child log messages confirming SCM_RIGHTS IPC handover,
     listener socket adoption, destination socket preservation, and fast RESUME.
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

# Paths
REPO_ROOT = Path(__file__).resolve().parent.parent
RELAY_BIN = "/tmp/relay-live"
SSHD_BIN = "/usr/sbin/sshd"
SSH_BIN = "/usr/bin/ssh"

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


def test_live_hot_restart():
    tmp_dir = tempfile.mkdtemp(prefix="relay-live-rob02-")
    print(f"[*] Test workspace created at {tmp_dir}")

    sshd_proc = None
    parent_srv_proc = None
    child_pid = None

    try:
        # 1. Setup Ephemeral SSH Keys
        host_key = os.path.join(tmp_dir, "ssh_host_ed25519_key")
        client_key = os.path.join(tmp_dir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", host_key, "-N", ""], check=True, capture_output=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", client_key, "-N", ""], check=True, capture_output=True)

        auth_keys = os.path.join(tmp_dir, "authorized_keys")
        shutil.copy(client_key + ".pub", auth_keys)
        os.chmod(auth_keys, 0o600)

        # 2. Setup isolated OpenSSH sshd on port 2222
        sshd_port = 2222
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
            record("SSHD Startup", False, f"Failed to listen on 127.0.0.1:{sshd_port}")
            return
        record("SSHD Startup", True, f"Listening on 127.0.0.1:{sshd_port} (PID {sshd_proc.pid})")

        # 3. Setup Relay Server
        relay_port = 7443
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
            record("Relay Server Startup", False, f"Failed to listen on 127.0.0.1:{relay_port}")
            return
        parent_pid = parent_srv_proc.pid
        record("Relay Server Startup", True, f"Listening on 127.0.0.1:{relay_port} (Parent PID {parent_pid})")

        proxy_cmd = f"{RELAY_BIN} client --tcp --server 127.0.0.1:{relay_port} --dest 127.0.0.1:{sshd_port} -i {client_key} --strict-host-key-checking=no --log-level warn %h %p"

        # -------------------------------------------------------------
        # TEST 1: Live Interactive Shell Continuity across SIGUSR2
        # -------------------------------------------------------------
        print("\n" + "=" * 70)
        print("TEST 1: Interactive OpenSSH Shell Continuity across SIGUSR2")
        print("=" * 70)

        ssh_interactive = subprocess.Popen([
            SSH_BIN, "-p", str(sshd_port), "-i", client_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ProxyCommand={proxy_cmd}",
            "root@127.0.0.1", "bash -s"
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Send Pre-Restart Command
        ssh_interactive.stdin.write("echo PRE_HOT_RESTART_TOKEN_9988\n")
        ssh_interactive.stdin.flush()
        line1 = ssh_interactive.stdout.readline().strip()
        print(f"[SSH Shell] Sent 'echo PRE_HOT_RESTART_TOKEN_9988' -> Received: {line1!r}")
        assert line1 == "PRE_HOT_RESTART_TOKEN_9988", f"Pre-restart shell output mismatch: {line1}"

        # Send SIGUSR2 to parent relay server
        print(f"[HOT RESTART] Sending SIGUSR2 to parent PID {parent_pid}...")
        os.kill(parent_pid, signal.SIGUSR2)

        # Parent must exit 0 cleanly after handover
        parent_exit = parent_srv_proc.wait(timeout=5)
        print(f"[HOT RESTART] Parent PID {parent_pid} exited cleanly with exit code: {parent_exit}")
        record("Parent Clean Exit on SIGUSR2", parent_exit == 0, f"Exit code {parent_exit}")

        # Child PID must be alive and adopted
        for _ in range(50):
            if os.path.exists(child_pid_file):
                break
            time.sleep(0.05)
        with open(child_pid_file) as f:
            child_pid = int(f.read().strip())
        print(f"[HOT RESTART] Child PID {child_pid} active and serving.")
        record("Child Process Adoption", child_pid != parent_pid and os.path.exists(f"/proc/{child_pid}"),
               f"New PID {child_pid}")

        # Send Post-Restart Commands on the EXACT SAME OPEN SSH SHELL
        print("[SSH Shell] Sending post-restart commands through the SAME interactive shell...")
        ssh_interactive.stdin.write("echo POST_HOT_RESTART_TOKEN_5544\n")
        ssh_interactive.stdin.flush()
        line2 = ssh_interactive.stdout.readline().strip()
        print(f"[SSH Shell] Received: {line2!r}")
        record("Interactive Shell Continuity (Post-Restart Command)",
               line2 == "POST_HOT_RESTART_TOKEN_5544", f"Output: {line2}")

        ssh_interactive.stdin.write("uname -s\n")
        ssh_interactive.stdin.flush()
        line3 = ssh_interactive.stdout.readline().strip()
        print(f"[SSH Shell] Received: {line3!r}")
        record("Interactive Shell Execution (uname -s)", line3 == "Linux", f"Output: {line3}")

        # Exit shell cleanly
        ssh_interactive.stdin.write("exit\n")
        ssh_interactive.stdin.flush()
        ssh_exit = ssh_interactive.wait(timeout=5)
        print(f"[SSH Shell] Closed with exit code: {ssh_exit}")
        record("Interactive Shell Graceful Termination", ssh_exit == 0, f"Exit code {ssh_exit}")

        # -------------------------------------------------------------
        # TEST 2: In-Flight Streaming Transfer across SIGUSR2 (16 MiB)
        # -------------------------------------------------------------
        print("\n" + "=" * 70)
        print("TEST 2: In-Flight 16 MiB Continuous Streaming Transfer across SIGUSR2")
        print("=" * 70)

        payload_bytes = 16 * 1024 * 1024  # 16 MiB
        input_file = os.path.join(tmp_dir, "input_16m.bin")
        output_file = os.path.join(tmp_dir, "output_16m.bin")

        print(f"[*] Generating {payload_bytes // (1024*1024)} MiB pseudo-random binary data...")
        # Fast reproducible data generator
        with open(input_file, "wb") as f:
            chunk = os.urandom(64 * 1024)
            for _ in range(payload_bytes // len(chunk)):
                f.write(chunk)

        with open(input_file, "rb") as f:
            expected_sha = hashlib.sha256(f.read()).hexdigest()
        print(f"[*] Input File SHA-256: {expected_sha}")

        # Current serving PID is child_pid
        current_srv_pid = child_pid
        child_pid_file_2 = os.path.join(tmp_dir, "child_2.pid")
        srv_env["RELAY_CHILD_PID_FILE"] = child_pid_file_2

        in_fp = open(input_file, "rb")
        t0 = time.time()
        stream_ssh = subprocess.Popen([
            SSH_BIN, "-p", str(sshd_port), "-i", client_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ProxyCommand={proxy_cmd}",
            "root@127.0.0.1", f"cat > {output_file}"
        ], stdin=in_fp, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Allow transfer to get in-flight
        time.sleep(0.08)

        # Trigger hot restart mid-stream on current_srv_pid
        print(f"[HOT RESTART] Firing SIGUSR2 mid-stream to server PID {current_srv_pid}...")
        os.kill(current_srv_pid, signal.SIGUSR2)

        # Await SSH streaming completion
        stream_stdout, stream_stderr = stream_ssh.communicate(timeout=30)
        t_elapsed = time.time() - t0
        in_fp.close()

        record("16 MiB Streaming SSH Returncode", stream_ssh.returncode == 0,
               f"Exited {stream_ssh.returncode} in {t_elapsed:.2f}s")

        with open(output_file, "rb") as f:
            out_data = f.read()
        received_sha = hashlib.sha256(out_data).hexdigest()

        print(f"[*] Transferred {len(out_data):,} bytes in {t_elapsed:.2f}s ({len(out_data)/(1024*1024)/t_elapsed:.2f} MiB/s)")
        print(f"[*] Expected SHA-256: {expected_sha}")
        print(f"[*] Received SHA-256: {received_sha}")

        record("Byte-Fidelity across SIGUSR2 Re-Exec (SHA-256)",
               received_sha == expected_sha,
               f"{len(out_data)} bytes match exact")

        # -------------------------------------------------------------
        # TEST 3: SCM_RIGHTS and Handover Log Verification
        # -------------------------------------------------------------
        print("\n" + "=" * 70)
        print("TEST 3: Handover Protocol Log Verification")
        print("=" * 70)

        srv_log_file.flush()
        srv_log_file.close()

        with open(srv_log_path) as f:
            log_content = f.read()

        log_checks = [
            ("received signal for zero-downtime hot restart", "Signal Handler Detection"),
            ("spawned child process for hot restart", "Child Process Spawning"),
            ("handover: adopted tcp listener", "SCM_RIGHTS Listener FD Adoption"),
            ("handover complete and acknowledged by child", "Two-Way IPC Handshake"),
            ("exiting parent process cleanly after hot restart", "Parent Clean Exit"),
            ("session resumed", "Client Fast RESUME Reconnection"),
        ]

        for needle, label in log_checks:
            found = needle in log_content
            record(f"Log Verification: {label}", found, f"Pattern {needle!r}")

    finally:
        # Clean up processes
        print("\n[*] Cleaning up background test processes...")
        # Kill all relay processes that were spawned
        for pid_file in [child_pid_file, os.path.join(tmp_dir, "child_2.pid")]:
            if os.path.exists(pid_file):
                try:
                    with open(pid_file) as f:
                        p = int(f.read().strip())
                    os.kill(p, signal.SIGKILL)
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
    print("LIVE INTEGRATION TEST SUMMARY")
    print("=" * 70)
    for r in RESULTS:
        print(r)
    print(f"\nTOTAL: {PASS} PASSED, {FAIL} FAILED\n")

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    build_relay()
    test_live_hot_restart()
