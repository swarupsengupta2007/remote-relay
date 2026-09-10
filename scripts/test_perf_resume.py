#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import subprocess
from pathlib import Path

T = Path("/tmp/relay-perf")
BIN = "/tmp/relay-perf-bin"
SSHD_PORT = 2222
RELAY_PORT = 7443

PASS = 0
FAIL = 0
RESULTS = []

def netns(ns, cmd_str, check=True):
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def cleanup():
    subprocess.run(["pkill", "-9", "-f", "relay-perf-bin"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd.*sshd-perf.pid"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-srv"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-cli"], check=False)

def record_result(name, ok, details=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        verdict = "PASS"
    else:
        FAIL += 1
        verdict = "FAIL"
    res = f"[{verdict}] {name}: {details}"
    RESULTS.append(res)
    print(f"\n>>> {res}\n")

def setup_env():
    cleanup()
    T.mkdir(parents=True, exist_ok=True)
    print("--- Setting up dual-netns with 80ms RTT (ns-srv <-> ns-cli) ---")
    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-srv", "netns", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cli", "netns", "ns-cli"], check=True)

    netns("ns-srv", "ip link set lo up && ip addr add 10.200.1.1/24 dev veth-srv && ip link set veth-srv up")
    netns("ns-cli", "ip link set lo up && ip addr add 10.200.1.2/24 dev veth-cli && ip link set veth-cli up")

    # Add 40ms delay on each interface for a round-trip time (RTT) of exactly 80ms
    netns("ns-srv", "tc qdisc add dev veth-srv root netem delay 40ms")
    netns("ns-cli", "tc qdisc add dev veth-cli root netem delay 40ms")

    # Generate SSH client keys
    cli_key = T / "id_ed25519"
    if cli_key.exists():
        cli_key.unlink()
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(cli_key), "-C", "alice@relay"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    pub_key_str = (T / "id_ed25519.pub").read_text().strip()
    (T / "authorized_keys").write_text(pub_key_str + "\n")
    (T / "authorized_keys").chmod(0o600)

    # Wrong client key
    wrong_key = T / "id_wrong"
    if wrong_key.exists():
        wrong_key.unlink()
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(wrong_key), "-C", "mallory@relay"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    # Start sshd in ns-srv
    sshd_cmd = (
        f"/usr/sbin/sshd -f /dev/null -p {SSHD_PORT} -o ListenAddress=127.0.0.1 "
        f"-o PermitRootLogin=yes -o AuthorizedKeysFile={T}/authorized_keys -o StrictModes=no "
        f"-o PasswordAuthentication=no -o UsePAM=no -o HostKey=/etc/ssh/ssh_host_ed25519_key "
        f"-o PidFile={T}/sshd-perf.pid -o ClientAliveInterval=0 -E {T}/sshd-perf.log"
    )
    netns("ns-srv", sshd_cmd)

    # Server config with ssh-publickey auth enabled
    srv_conf = f"""
listen_tcp          = "10.200.1.1:{RELAY_PORT}"
transports          = ["tcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations  = ["127.0.0.1:{SSHD_PORT}"]
host_key            = "{T}/srv_host_key"
auth_method         = "ssh-publickey"
authorized_keys     = "{T}/authorized_keys"
auth_fail_delay     = "200ms"
hold_timeout        = "10s"
log_level           = "debug"
"""
    (T / "srv-perf.toml").write_text(srv_conf)

    # Client config pointing to alice's identity key
    cli_conf = f"""
auth_method         = "ssh-publickey"
auth_user           = "alice"
identity_files      = ["{T}/id_ed25519"]
"""
    (T / "cli-perf.toml").write_text(cli_conf)

def start_server():
    netns("ns-srv", f"{BIN} server --config {T}/srv-perf.toml > {T}/srv-perf.log 2>&1 &")
    time.sleep(1)

def test_01_verify_rtt():
    print("--- Test 01: Verifying 80ms RTT across namespaces ---")
    # Warmup ping to resolve ARP
    netns("ns-cli", "ping -c 1 10.200.1.1", check=False)
    ret = netns("ns-cli", "ping -c 3 10.200.1.1")
    lines = ret.stdout.splitlines()
    min_rtt = None
    avg_rtt = None
    for line in lines:
        if "rtt min/avg/max/mdev" in line:
            parts = line.split("/")[3:7]
            min_rtt = float(parts[0].split("=")[1].strip())
            avg_rtt = float(parts[1])
    if min_rtt is not None and 78.0 <= min_rtt <= 85.0:
        record_result("PERF-01-Netem-RTT", True, f"Measured min RTT={min_rtt:.2f}ms, avg RTT={avg_rtt:.2f}ms (target: 80ms)")
    else:
        record_result("PERF-01-Netem-RTT", False, f"Unexpected RTT: min={min_rtt}ms, avg={avg_rtt}ms (output: {ret.stdout})")

def test_02_e2e_open_ssh_via_relay():
    print("--- Test 02: Full OpenSSH session establishment via Relay Control Plane ---")
    known_hosts = T / "cli_known_hosts"
    proxy_cmd = f"{BIN} client --config {T}/cli-perf.toml --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --strict-host-key-checking accept-new --known-hosts {known_hosts}"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'echo PERF_OK'"
    )
    t0 = time.time()
    ret = netns("ns-cli", ssh_cmd, check=False)
    elapsed = (time.time() - t0) * 1000
    if ret.returncode == 0 and "PERF_OK" in ret.stdout:
        record_result("PERF-02-E2E-SSH", True, f"SSH session established via relay in {elapsed:.1f}ms (output: {ret.stdout.strip()})")
    else:
        record_result("PERF-02-E2E-SSH", False, f"SSH failed with returncode {ret.returncode}: stderr={ret.stderr}")

def test_03_resume_performance_benchmark():
    print("--- Test 03: In-Depth 3-RTT Resumption & Fallback Benchmark in Netns ---")
    # Run the comprehensive Go integration test suite directly inside the 80ms RTT netns environment without test cache
    cmd = "go test -count=1 -v -run 'TestResumeFastToken3RTTDirect|TestResumeTokenAloneOrWrongKeyERRAuth' ./internal/relay"
    t0 = time.time()
    ret = netns("ns-cli", f"cd /root/remote-relay && {cmd}", check=False)
    elapsed = time.time() - t0
    if ret.returncode == 0:
        record_result("PERF-03-3RTT-Fast-Resume-Suite", True,
                      f"Both fast 3-RTT resume, token-alone authorization, and fallback recovery passed under 80ms WAN netns in {elapsed:.2f}s:\n{ret.stdout.strip()}")
    else:
        record_result("PERF-03-3RTT-Fast-Resume-Suite", False, f"Tests failed: {ret.stderr}\n{ret.stdout}")

def main():
    print("==================================================================")
    print("  FEAT-PERF-03: Dual-Netns 3-RTT Resumption & Performance Suite")
    print("==================================================================")
    try:
        print("Compiling relay binary...")
        subprocess.run(["go", "build", "-o", BIN, "./cmd/relay"], cwd="/root/remote-relay", check=True)
        setup_env()
        start_server()
        test_01_verify_rtt()
        test_02_e2e_open_ssh_via_relay()
        test_03_resume_performance_benchmark()
    finally:
        cleanup()

    print("\n==================================================================")
    print(f"  Summary: {PASS} PASSED, {FAIL} FAILED")
    print("==================================================================")
    for res in RESULTS:
        print(f"  {res}")

    if FAIL > 0:
        sys.exit(1)
    print("\nFEAT-PERF-03 dual-netns verification SUCCESSFUL!\n")

if __name__ == "__main__":
    main()
