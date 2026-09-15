#!/usr/bin/env python3
import os
import sys
import time
import signal
import hashlib
import subprocess
from pathlib import Path

T = Path("/tmp/relay-kcp-soak")
BIN = "/tmp/relay-kcp-bin"
SSHD_PORT = 2222
RELAY_PORT = 7443

PASS = 0
FAIL = 0
RESULTS = []

def netns(ns, cmd_str, check=True):
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def cleanup():
    subprocess.run(["pkill", "-9", "-f", "relay-kcp-bin"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd.*sshd-kcp-soak.pid"], check=False)
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
    if T.exists():
        subprocess.run(["rm", "-rf", str(T)], check=True)
    T.mkdir(parents=True, exist_ok=True)

    print("--- Building relay binary ---")
    subprocess.run(["go", "build", "-o", BIN, "./cmd/relay"], check=True, cwd="/root/remote-relay")

    print("--- Setting up dual-netns (ns-srv <-> ns-cli) ---")
    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-srv", "netns", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cli", "netns", "ns-cli"], check=True)

    netns("ns-srv", "ip link set lo up && ip addr add 10.200.1.1/24 dev veth-srv && ip link set veth-srv up")
    netns("ns-cli", "ip link set lo up && ip addr add 10.200.1.2/24 dev veth-cli && ip link set veth-cli up")

    # Add 40ms delay (80ms RTT) and 2% packet loss to simulate WAN
    netns("ns-srv", "tc qdisc add dev veth-srv root netem delay 40ms loss 2%")

    # Generate test client key and server authorized_keys
    client_key = T / "client_id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(client_key)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    auth_keys = T / "authorized_keys"
    auth_keys.write_text((T / "client_id_ed25519.pub").read_text())
    os.chmod(auth_keys, 0o600)

    # Server host key
    server_key = T / "ssh_host_ed25519_key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(server_key)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    # Start sshd in ns-srv
    sshd_cmd = (
        f"/usr/sbin/sshd -f /dev/null -p {SSHD_PORT} -o ListenAddress=127.0.0.1 "
        f"-o PermitRootLogin=yes -o AuthorizedKeysFile={auth_keys} -o StrictModes=no "
        f"-o PasswordAuthentication=no -o UsePAM=no -o HostKey={server_key} "
        f"-o PidFile={T}/sshd-kcp-soak.pid -o ClientAliveInterval=0 -E {T}/sshd.log"
    )
    netns("ns-srv", sshd_cmd)
    time.sleep(0.5)

def run_test_soak(test_name, allow_ha=False, num_kills=5, payload_mb=8):
    print(f"=== Starting {test_name} (allow_ha={allow_ha}, kills={num_kills}, payload={payload_mb}MB) ===")
    
    server_conf = T / f"server-{test_name}.toml"
    server_conf.write_text(f"""
listen_tcp = "10.200.1.1:{RELAY_PORT}"
udp_listen = "10.200.1.1:{RELAY_PORT}"
transports = ["kcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations = ["127.0.0.1:{SSHD_PORT}"]
authorized_keys = "{T}/authorized_keys"
host_key = "{T}/ssh_host_ed25519_key"
heartbeat_interval = "200ms"
dead_peer_threshold = 3
hold_timeout = "30s"
log_level = "info"
""")

    # Launch server in ns-srv
    srv_log = T / f"srv-{test_name}.log"
    srv_proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns-srv", BIN, "server", "--config", str(server_conf)],
        stdout=subprocess.DEVNULL, stderr=open(srv_log, "w")
    )
    time.sleep(0.8)

    # Create test payload
    payload_file = T / f"payload-{test_name}.bin"
    payload_data = os.urandom(payload_mb * 1024 * 1024)
    payload_file.write_bytes(payload_data)
    expected_hash = hashlib.sha256(payload_data).hexdigest()

    known_hosts = T / f"known_hosts-{test_name}"
    ha_flag = "--allow-ha" if allow_ha else ""
    client_cmd = (
        f"{BIN} client --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} "
        f"--kcp {ha_flag} -i {T}/client_id_ed25519 "
        f"--known-hosts {known_hosts} --strict-host-key-checking accept-new "
        f"--heartbeat-interval 200ms --dead-peer-threshold 3"
    )

    ssh_cmd = (
        f"ssh -p {SSHD_PORT} -i {T}/client_id_ed25519 -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 "
        f'-o ProxyCommand="{client_cmd}" root@127.0.0.1 "cat > /tmp/received.bin"'
    )

    print(f"Launching client transfer...")
    cli_proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns-cli", "bash", "-c", ssh_cmd],
        stdin=open(payload_file, "rb"), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Inject link drops periodically during the transfer
    time.sleep(1.0)
    for i in range(num_kills):
        if cli_proc.poll() is not None:
            break
        print(f"  [Kill {i+1}/{num_kills}] Dropping UDP traffic...")
        netns("ns-srv", f"iptables -A INPUT -p udp --dport {RELAY_PORT} -j DROP")
        time.sleep(0.6)
        print(f"  [Kill {i+1}/{num_kills}] Restoring UDP traffic...")
        netns("ns-srv", f"iptables -F INPUT")
        time.sleep(1.2)

    try:
        out, err = cli_proc.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        cli_proc.kill()
        record_result(test_name, False, "Transfer timed out")
        srv_proc.terminate()
        return

    if cli_proc.returncode != 0:
        err_msg = err.decode(errors='replace')
        record_result(test_name, False, f"Client failed rc={cli_proc.returncode}: {err_msg[:200]}")
        srv_proc.terminate()
        return

    # Verify received data in ns-srv
    actual_hash = netns("ns-srv", "sha256sum /tmp/received.bin", check=True).stdout.split()[0].strip()

    if actual_hash == expected_hash:
        record_result(test_name, True, f"{payload_mb} MiB byte-exact SHA-256 match after {num_kills} link drops")
    else:
        record_result(test_name, False, f"Hash mismatch: expected {expected_hash}, got {actual_hash}")

    netns("ns-srv", "rm -f /tmp/received.bin")
    srv_proc.terminate()
    srv_proc.wait()

def main():
    try:
        setup_env()
        # Test 1: Standalone KCP repeated link drops
        run_test_soak("SOAK-01-KCP-Standalone-Repeated-Drops", allow_ha=False, num_kills=5, payload_mb=4)
        # Test 2: Dual-path KCP with --allow-ha repeated link blackholes
        run_test_soak("SOAK-02-KCP-AllowHA-Repeated-Blackholes", allow_ha=True, num_kills=5, payload_mb=4)

        print("\n======================= SUMMARY =======================")
        for r in RESULTS:
            print(r)
        print(f"\nTOTAL: {PASS} passed, {FAIL} failed\n")
        if FAIL > 0:
            sys.exit(1)
    finally:
        cleanup()

if __name__ == "__main__":
    main()
