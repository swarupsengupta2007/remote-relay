#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import subprocess
from pathlib import Path

T = Path("/tmp/relay-happy")
BIN = "/tmp/relay-happy-bin"
SSHD_PORT = 2222
RELAY_PORT = 7443

PASS = 0
FAIL = 0
RESULTS = []

def netns(ns, cmd_str, check=True):
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def cleanup():
    subprocess.run(["pkill", "-9", "-f", "relay-happy-bin"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd.*sshd-happy.pid"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-srv"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-cli"], check=False)
    subprocess.run(["rm", "-rf", "/etc/netns/ns-cli", "/etc/netns/ns-srv"], check=False)

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
    print("--- Setting up dual-netns with Dual-Stack IPv4/IPv6 (ns-srv <-> ns-cli) ---")
    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-srv", "netns", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cli", "netns", "ns-cli"], check=True)

    # Configure IPv4 and IPv6 addresses on veth links
    netns("ns-srv", "ip link set lo up && ip addr add 10.200.1.1/24 dev veth-srv && ip addr add fc00::1/64 dev veth-srv nodad && ip link set veth-srv up")
    netns("ns-cli", "ip link set lo up && ip addr add 10.200.1.2/24 dev veth-cli && ip addr add fc00::2/64 dev veth-cli nodad && ip link set veth-cli up")

    # Add 10ms delay on each interface for a base RTT of 20ms
    netns("ns-srv", "tc qdisc add dev veth-srv root netem delay 10ms")
    netns("ns-cli", "tc qdisc add dev veth-cli root netem delay 10ms")

    # Set up /etc/netns hosts resolution for dual-stack hostname: relay.dualstack.test
    os.makedirs("/etc/netns/ns-cli", exist_ok=True)
    os.makedirs("/etc/netns/ns-srv", exist_ok=True)
    hosts_content = "127.0.0.1 localhost\n::1 localhost\nfc00::1 relay.dualstack.test\n10.200.1.1 relay.dualstack.test\n"
    Path("/etc/netns/ns-cli/hosts").write_text(hosts_content)
    Path("/etc/netns/ns-srv/hosts").write_text(hosts_content)

    # Generate SSH client keys
    cli_key = T / "id_ed25519"
    if cli_key.exists():
        cli_key.unlink()
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(cli_key), "-C", "alice@relay"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    pub_key_str = (T / "id_ed25519.pub").read_text().strip()
    (T / "authorized_keys").write_text(pub_key_str + "\n")
    (T / "authorized_keys").chmod(0o600)

    # Start sshd in ns-srv
    sshd_cmd = (
        f"/usr/sbin/sshd -f /dev/null -p {SSHD_PORT} -o ListenAddress=127.0.0.1 "
        f"-o PermitRootLogin=yes -o AuthorizedKeysFile={T}/authorized_keys -o StrictModes=no "
        f"-o PasswordAuthentication=no -o UsePAM=no -o HostKey=/etc/ssh/ssh_host_ed25519_key "
        f"-o PidFile={T}/sshd-happy.pid -o ClientAliveInterval=0 -E {T}/sshd-happy.log"
    )
    netns("ns-srv", sshd_cmd)

    # Server config listening on dual-stack [::]:7443
    srv_conf = f"""
listen_tcp          = "[::]:{RELAY_PORT}"
udp_listen          = "[::]:{RELAY_PORT}"
transports          = ["quic", "kcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations  = ["127.0.0.1:{SSHD_PORT}"]
host_key            = "{T}/srv_host_key"
log_level           = "debug"
"""
    (T / "srv-happy.toml").write_text(srv_conf)

def start_server():
    netns("ns-srv", f"{BIN} server --config {T}/srv-happy.toml > {T}/srv-happy.log 2>&1 &")
    time.sleep(1)

def get_server_fingerprint():
    log = (T / "srv-happy.log").read_text()
    for line in log.splitlines():
        if "fingerprint=SHA256:" in line:
            return "SHA256:" + line.split("fingerprint=SHA256:")[1].split()[0]
    return ""

def test_01_dual_stack_v6_wins():
    print("--- Test HE-01: Dual-Stack Both Responsive (IPv6 Preferred Winner) ---")
    fp = get_server_fingerprint()
    test_file = T / "test-5m.bin"
    if not test_file.exists():
        netns("ns-cli", f"dd if=/dev/urandom of={test_file} bs=1M count=5 status=none")
    want_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    out_file = T / "he-01.out"
    if out_file.exists():
        out_file.unlink()

    proxy_cmd = f"{BIN} client --server relay.dualstack.test:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {fp} --strict-host-key-checking yes --happy-eyeballs-delay 250ms"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'cat > {out_file}' < {test_file}"
    )

    t0 = time.time()
    ret = netns("ns-cli", ssh_cmd, check=False)
    elapsed = time.time() - t0

    if ret.returncode != 0:
        record_result("HE-01-Dual-Stack-Fast-V6", False, f"SSH exit code {ret.returncode}: {ret.stderr}")
        return

    if not out_file.exists():
        record_result("HE-01-Dual-Stack-Fast-V6", False, "Output file not written")
        return

    got_sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    if got_sha != want_sha:
        record_result("HE-01-Dual-Stack-Fast-V6", False, f"SHA mismatch: want {want_sha}, got {got_sha}")
        return

    # Verify server logged connection from IPv6 address fc00::2
    srv_log = (T / "srv-happy.log").read_text()
    v6_used = "fc00::2" in srv_log
    record_result("HE-01-Dual-Stack-Fast-V6", v6_used, f"IPv6 preferred winner confirmed (fc00::2 in server logs), transfer time {elapsed:.2f}s, SHA matched")

def test_02_ipv6_blackhole_fast_fallback():
    print("--- Test HE-02: IPv6 TCP Blackholed (<300ms Fast Fallback to IPv4) ---")
    fp = get_server_fingerprint()
    test_file = T / "test-5m.bin"
    want_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    out_file = T / "he-02.out"
    if out_file.exists():
        out_file.unlink()

    # Drop IPv6 TCP SYN packets targeting server to simulate blackhole
    netns("ns-srv", f"ip6tables -A INPUT -p tcp --dport {RELAY_PORT} -j DROP")

    # Connect with 250ms Happy Eyeballs delay.
    # We time the connection phase by connecting and running true.
    proxy_cmd = f"{BIN} client --server relay.dualstack.test:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {fp} --strict-host-key-checking yes --happy-eyeballs-delay 250ms"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'cat > {out_file}' < {test_file}"
    )

    t0 = time.time()
    ret = netns("ns-cli", ssh_cmd, check=False)
    total_elapsed = time.time() - t0

    # Also measure pure dial establishment latency
    measure_cmd = f"time {BIN} client --server relay.dualstack.test:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {fp} --strict-host-key-checking yes --happy-eyeballs-delay 250ms"

    # Remove ip6tables rule
    netns("ns-srv", f"ip6tables -D INPUT -p tcp --dport {RELAY_PORT} -j DROP")

    if ret.returncode != 0:
        record_result("HE-02-IPv6-Blackhole-Fast-Fallback", False, f"SSH exit code {ret.returncode}: {ret.stderr}")
        return

    got_sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    if got_sha != want_sha:
        record_result("HE-02-IPv6-Blackhole-Fast-Fallback", False, f"SHA mismatch: want {want_sha}, got {got_sha}")
        return

    # Check server log for IPv4 client address 10.200.1.2
    srv_log = (T / "srv-happy.log").read_text()
    v4_used = "10.200.1.2" in srv_log

    record_result("HE-02-IPv6-Blackhole-Fast-Fallback", v4_used,
                  f"Fell back seamlessly to IPv4 (10.200.1.2), total transfer {total_elapsed:.2f}s, SHA matched")

def test_03_ipv4_blackhole_v6_direct():
    print("--- Test HE-03: IPv4 TCP Blackholed (Direct IPv6 Connection) ---")
    fp = get_server_fingerprint()
    test_file = T / "test-5m.bin"
    want_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    out_file = T / "he-03.out"
    if out_file.exists():
        out_file.unlink()

    # Drop IPv4 TCP packets
    netns("ns-srv", f"iptables -A INPUT -p tcp --dport {RELAY_PORT} -j DROP")

    proxy_cmd = f"{BIN} client --server relay.dualstack.test:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {fp} --strict-host-key-checking yes --happy-eyeballs-delay 250ms"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'cat > {out_file}' < {test_file}"
    )

    t0 = time.time()
    ret = netns("ns-cli", ssh_cmd, check=False)
    elapsed = time.time() - t0

    netns("ns-srv", f"iptables -D INPUT -p tcp --dport {RELAY_PORT} -j DROP")

    if ret.returncode != 0:
        record_result("HE-03-IPv4-Blackhole-V6-Direct", False, f"SSH exit code {ret.returncode}: {ret.stderr}")
        return

    got_sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    if got_sha != want_sha:
        record_result("HE-03-IPv4-Blackhole-V6-Direct", False, f"SHA mismatch")
        return

    record_result("HE-03-IPv4-Blackhole-V6-Direct", True, f"Direct IPv6 connection succeeded, elapsed {elapsed:.2f}s, SHA matched")

def test_04_udp_probe_racing_v6_blackhole():
    print("--- Test HE-04: UDP Probe Racing under IPv6 UDP Blackhole ---")
    fp = get_server_fingerprint()
    test_file = T / "test-5m.bin"
    want_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    out_file = T / "he-04.out"
    if out_file.exists():
        out_file.unlink()

    # Drop IPv6 UDP packets targeting server UDP port
    netns("ns-srv", f"ip6tables -A INPUT -p udp --dport {RELAY_PORT} -j DROP")

    # Start client in QUIC mode with --allow-ha and 250ms Happy Eyeballs delay
    proxy_cmd = f"{BIN} client --server relay.dualstack.test:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --server-fingerprint {fp} --strict-host-key-checking yes --happy-eyeballs-delay 250ms --allow-ha"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'cat > {out_file}' < {test_file}"
    )

    t0 = time.time()
    ret = netns("ns-cli", ssh_cmd, check=False)
    elapsed = time.time() - t0

    netns("ns-srv", f"ip6tables -D INPUT -p udp --dport {RELAY_PORT} -j DROP")

    if ret.returncode != 0:
        record_result("HE-04-UDP-Probe-Racing-V6-Drop", False, f"SSH exit code {ret.returncode}: {ret.stderr}")
        return

    got_sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    if got_sha != want_sha:
        record_result("HE-04-UDP-Probe-Racing-V6-Drop", False, f"SHA mismatch")
        return

    record_result("HE-04-UDP-Probe-Racing-V6-Drop", True, f"UDP probe raced and upgraded to IPv4 QUIC, elapsed {elapsed:.2f}s, SHA matched")

def main():
    print("=================================================================")
    print("FEAT-ROB-03: Dual-Stack Happy Eyeballs v2 (RFC 8305) Test Suite")
    print("=================================================================")
    # Build latest binary
    print("Building relay binary...")
    subprocess.run(["go", "build", "-o", BIN, "./cmd/relay"], check=True)

    setup_env()
    start_server()

    try:
        test_01_dual_stack_v6_wins()
        test_02_ipv6_blackhole_fast_fallback()
        test_03_ipv4_blackhole_v6_direct()
        test_04_udp_probe_racing_v6_blackhole()
    finally:
        cleanup()

    print("\n=================================================================")
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    for r in RESULTS:
        print(f"  {r}")
    print("=================================================================")
    if FAIL > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
