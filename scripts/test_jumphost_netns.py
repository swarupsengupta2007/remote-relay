#!/usr/bin/env python3
"""FEAT-UTL-05 jumphost chaining netns harness.

Not in CI (needs root, netns, real sshd) — same status as test_sec_netns.py.

Topology:
  ns-cli 10.10.1.2  --veth-cj--  ns-j1 10.10.1.1
  ns-j1  10.10.2.1  --veth-js--  ns-srv 10.10.2.2  (sshd on 127.0.0.1:2222)

Covers JUMP-01..07: baseline, outer/inner/simultaneous kill, per-hop KCP,
wire inspect, depth. Nested splice and Phase 3 (NATed terminal) stay out.
"""
import os
import sys
import time
import hashlib
import subprocess
from pathlib import Path

T = Path("/tmp/relay-verify")
BIN = "/tmp/relay-linux-amd64"
SSHD_PORT = 2222
J1_PORT = 7443
SRV_PORT = 7443

PASS = 0
FAIL = 0
SKIP = 0
RESULTS = []


def netns(ns, cmd_str, check=True):
    return subprocess.run(
        ["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check,
    )


def cleanup():
    subprocess.run(["pkill", "-9", "-f", "relay-linux-amd64"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd.*sshd-jump.pid"], check=False)
    subprocess.run(["pkill", "-9", "-f", "tcpdump"], check=False)
    for ns in ("ns-cli", "ns-j1", "ns-srv"):
        subprocess.run(["ip", "netns", "del", ns], check=False)


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


def record_skip(name, details=""):
    global SKIP
    SKIP += 1
    res = f"[SKIP] {name}: {details}"
    RESULTS.append(res)
    print(f"\n>>> {res}\n")


def setup_env():
    cleanup()
    T.mkdir(parents=True, exist_ok=True)
    print("--- Building relay binary ---")
    subprocess.run(["go", "build", "-o", BIN, "./cmd/relay"], check=True, cwd="/root/remote-relay")

    print("--- Setting up triple-netns (ns-cli <-> ns-j1 <-> ns-srv) ---")
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-j1"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "add", "veth-cj-cli", "type", "veth", "peer", "name", "veth-cj-j1"], check=True)
    subprocess.run(["ip", "link", "add", "veth-js-j1", "type", "veth", "peer", "name", "veth-js-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cj-cli", "netns", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cj-j1", "netns", "ns-j1"], check=True)
    subprocess.run(["ip", "link", "set", "veth-js-j1", "netns", "ns-j1"], check=True)
    subprocess.run(["ip", "link", "set", "veth-js-srv", "netns", "ns-srv"], check=True)

    netns("ns-cli", "ip link set lo up && ip addr add 10.10.1.2/24 dev veth-cj-cli && ip link set veth-cj-cli up")
    netns("ns-j1", "ip link set lo up && ip addr add 10.10.1.1/24 dev veth-cj-j1 && ip link set veth-cj-j1 up && ip addr add 10.10.2.1/24 dev veth-js-j1 && ip link set veth-js-j1 up")
    netns("ns-srv", "ip link set lo up && ip addr add 10.10.2.2/24 dev veth-js-srv && ip link set veth-js-srv up")
    netns("ns-j1", "sysctl -w net.ipv4.ip_forward=1")

    client_key = T / "id_ed25519"
    if client_key.exists():
        client_key.unlink()
        Path(str(client_key) + ".pub").unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(client_key)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    auth_keys = T / "authorized_keys"
    auth_keys.write_text((T / "id_ed25519.pub").read_text())
    os.chmod(auth_keys, 0o600)

    for name in ("j1_host_key", "srv_host_key", "sshd_host_key"):
        p = T / name
        if p.exists():
            p.unlink()
            Path(str(p) + ".pub").unlink(missing_ok=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(p)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    sshd_cmd = (
        f"/usr/sbin/sshd -f /dev/null -p {SSHD_PORT} -o ListenAddress=127.0.0.1 "
        f"-o PermitRootLogin=yes -o AuthorizedKeysFile={auth_keys} -o StrictModes=no "
        f"-o PasswordAuthentication=no -o UsePAM=no -o HostKey={T}/sshd_host_key "
        f"-o PidFile={T}/sshd-jump.pid -o ClientAliveInterval=0 -E {T}/sshd-jump.log"
    )
    netns("ns-srv", sshd_cmd)

    (T / "j1.toml").write_text(f"""
listen_tcp          = "10.10.1.1:{J1_PORT}"
udp_listen          = "10.10.1.1:{J1_PORT}"
transports          = ["tcp", "kcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations  = ["127.0.0.1:{SSHD_PORT}"]
allow_relay_hops    = ["10.10.2.2:{SRV_PORT}"]
max_chain_depth     = 4
host_key            = "{T}/j1_host_key"
authorized_keys     = "{auth_keys}"
log_level           = "debug"
""")
    (T / "srv.toml").write_text(f"""
listen_tcp          = "10.10.2.2:{SRV_PORT}"
transports          = ["tcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations  = ["127.0.0.1:{SSHD_PORT}"]
host_key            = "{T}/srv_host_key"
authorized_keys     = "{auth_keys}"
log_level           = "debug"
""")


def start_servers():
    netns("ns-j1", f"{BIN} server --config {T}/j1.toml > {T}/j1.log 2>&1 &")
    netns("ns-srv", f"{BIN} server --config {T}/srv.toml > {T}/srv.log 2>&1 &")
    time.sleep(1)


def proxy_cmd():
    kh = T / "cli_known_hosts"
    return (
        f"{BIN} client --server 10.10.2.2:{SRV_PORT} -J 10.10.1.1:{J1_PORT} "
        f"--dest 127.0.0.1:{SSHD_PORT} --tcp "
        f"--strict-host-key-checking accept-new --known-hosts {kh} "
        f"-i {T}/id_ed25519"
    )


def ssh(cmd, check=False):
    full = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o GlobalKnownHostsFile=/dev/null -o ProxyCommand='{proxy_cmd()}' "
        f"root@dummy {cmd}"
    )
    return netns("ns-cli", full, check=check)


def jump_01_baseline():
    print("--- JUMP-01-Baseline: 16 MiB through one jumphost ---")
    src = T / "jump-16m.bin"
    dst = T / "jump-16m.out"
    if src.exists():
        src.unlink()
    netns("ns-cli", f"dd if=/dev/urandom of={src} bs=1M count=16 status=none")
    want = hashlib.sha256(src.read_bytes()).hexdigest()
    if dst.exists():
        dst.unlink()
    ret = ssh(f"'cat > {dst}' < {src}")
    if ret.returncode != 0:
        record_result("JUMP-01-Baseline", False, f"ssh rc={ret.returncode}: {ret.stderr[-400:]}")
        return
    if not dst.exists():
        record_result("JUMP-01-Baseline", False, "output missing")
        return
    got = hashlib.sha256(dst.read_bytes()).hexdigest()
    record_result("JUMP-01-Baseline", got == want, f"SHA-256 {'match' if got == want else 'mismatch'}")


def jump_02_outer_kill():
    print("--- JUMP-02-OuterKill: DROP cli↔j1 during transfer ---")
    src = T / "jump-kill.bin"
    dst = T / "jump-kill.out"
    netns("ns-cli", f"dd if=/dev/urandom of={src} bs=1M count=4 status=none")
    want = hashlib.sha256(src.read_bytes()).hexdigest()
    if dst.exists():
        dst.unlink()
    netns("ns-cli", "tc qdisc add dev veth-cj-cli root netem delay 40ms loss 2%", check=False)
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns-cli", "bash", "-c",
         f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes "
         f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
         f"-o ProxyCommand='{proxy_cmd()}' root@dummy 'cat > {dst}' < {src}"],
    )
    time.sleep(1.5)
    netns("ns-j1", "iptables -A INPUT -i veth-cj-j1 -j DROP", check=False)
    time.sleep(3)
    netns("ns-j1", "iptables -D INPUT -i veth-cj-j1 -j DROP", check=False)
    try:
        rc = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        record_result("JUMP-02-OuterKill", False, "ssh timed out after outer DROP")
        return
    ok = rc == 0 and dst.exists() and hashlib.sha256(dst.read_bytes()).hexdigest() == want
    record_result("JUMP-02-OuterKill", ok, f"rc={rc} byte-exact={ok}")


def _kill_transfer(name, drop_cmds, undrop_cmds):
    src = T / f"jump-{name}.bin"
    dst = T / f"jump-{name}.out"
    netns("ns-cli", f"dd if=/dev/urandom of={src} bs=1M count=4 status=none")
    want = hashlib.sha256(src.read_bytes()).hexdigest()
    if dst.exists():
        dst.unlink()
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "ns-cli", "bash", "-c",
         f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes "
         f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
         f"-o ProxyCommand='{proxy_cmd()}' root@dummy 'cat > {dst}' < {src}"],
    )
    time.sleep(1.5)
    for c in drop_cmds:
        netns(c[0], c[1], check=False)
    time.sleep(3)
    for c in undrop_cmds:
        netns(c[0], c[1], check=False)
    try:
        rc = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        record_result(name, False, "ssh timed out after DROP")
        return
    ok = rc == 0 and dst.exists() and hashlib.sha256(dst.read_bytes()).hexdigest() == want
    record_result(name, ok, f"rc={rc} byte-exact={ok}")


def jump_03_inner_kill():
    print("--- JUMP-03-InnerKill: DROP j1↔S during transfer ---")
    _kill_transfer(
        "JUMP-03-InnerKill",
        [("ns-srv", "iptables -A INPUT -i veth-js-srv -j DROP")],
        [("ns-srv", "iptables -D INPUT -i veth-js-srv -j DROP")],
    )


def jump_04_simultaneous_kill():
    print("--- JUMP-04-SimultaneousKill: DROP both hops during transfer ---")
    _kill_transfer(
        "JUMP-04-SimultaneousKill",
        [
            ("ns-j1", "iptables -A INPUT -i veth-cj-j1 -j DROP"),
            ("ns-srv", "iptables -A INPUT -i veth-js-srv -j DROP"),
        ],
        [
            ("ns-j1", "iptables -D INPUT -i veth-cj-j1 -j DROP"),
            ("ns-srv", "iptables -D INPUT -i veth-js-srv -j DROP"),
        ],
    )


def jump_05_kcp_leg():
    print("--- JUMP-05-KCPLeg: hop 1 KCP, hop 2 TCP ---")
    src = T / "jump-kcp.bin"
    dst = T / "jump-kcp.out"
    netns("ns-cli", f"dd if=/dev/urandom of={src} bs=1M count=4 status=none")
    want = hashlib.sha256(src.read_bytes()).hexdigest()
    if dst.exists():
        dst.unlink()
    kh = T / "cli_known_hosts_kcp"
    cmd = (
        f"{BIN} client --server 10.10.2.2:{SRV_PORT} "
        f"-J '10.10.1.1:{J1_PORT}?transport=kcp' "
        f"--dest 127.0.0.1:{SSHD_PORT} --kcp "
        f"--strict-host-key-checking accept-new --known-hosts {kh} "
        f"-i {T}/id_ed25519"
    )
    full = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{cmd}' root@dummy 'cat > {dst}' < {src}"
    )
    ret = netns("ns-cli", full, check=False)
    ok = ret.returncode == 0 and dst.exists() and hashlib.sha256(dst.read_bytes()).hexdigest() == want
    record_result("JUMP-05-KCPLeg", ok, f"rc={ret.returncode} byte-exact={ok}")


def jump_06_wireinspect():
    print("--- JUMP-06-WireInspect: no resumeToken on j1↔srv ---")
    pcap = T / "jump-wire.pcap"
    if pcap.exists():
        pcap.unlink()
    netns("ns-j1", f"tcpdump -i veth-js-j1 -w {pcap} tcp port {SRV_PORT} >/dev/null 2>&1 &")
    time.sleep(0.5)
    ret = ssh("'echo JUMP_WIRE_OK'")
    time.sleep(0.5)
    netns("ns-j1", "pkill -9 -f tcpdump", check=False)
    if ret.returncode != 0:
        record_result("JUMP-06-WireInspect", False, f"ssh failed: {ret.stderr[-200:]}")
        return
    data = pcap.read_bytes() if pcap.exists() else b""
    leaks = []
    for s in (b"resumeToken", b"resume_token"):
        if s in data:
            leaks.append(s.decode())
    record_result("JUMP-06-WireInspect", not leaks, "clean" if not leaks else f"leaked {leaks}")


def jump_07_depth():
    print("--- JUMP-07-Depth: max_chain_depth enforced ---")
    # Rewrite j1 with depth 1 and retry a 2-hop chain (j1 + S).
    text = (T / "j1.toml").read_text().replace("max_chain_depth     = 4", "max_chain_depth     = 1")
    (T / "j1-depth.toml").write_text(text)
    netns("ns-j1", "pkill -9 -f 'relay-linux-amd64 server'", check=False)
    time.sleep(0.3)
    netns("ns-j1", f"{BIN} server --config {T}/j1-depth.toml > {T}/j1-depth.log 2>&1 &")
    time.sleep(1)
    ret = ssh("'echo SHOULD_FAIL'")
    ok = ret.returncode != 0
    record_result("JUMP-07-Depth", ok, "CHAIN refused at depth 1" if ok else "depth 1 unexpectedly allowed a 2-hop chain")
    netns("ns-j1", "pkill -9 -f 'relay-linux-amd64 server'", check=False)
    time.sleep(0.3)
    netns("ns-j1", f"{BIN} server --config {T}/j1.toml > {T}/j1.log 2>&1 &")
    time.sleep(1)


def main():
    print("==========================================================")
    print("  FEAT-UTL-05: Jumphost chaining netns harness")
    print("==========================================================")
    try:
        setup_env()
        start_servers()
        jump_01_baseline()
        jump_02_outer_kill()
        jump_03_inner_kill()
        jump_04_simultaneous_kill()
        jump_05_kcp_leg()
        jump_06_wireinspect()
        jump_07_depth()
    finally:
        cleanup()

    print("\n==========================================================")
    print(f"  Summary: {PASS} PASSED, {FAIL} FAILED, {SKIP} SKIPPED")
    print("==========================================================")
    for res in RESULTS:
        print(f"  {res}")
    if FAIL > 0:
        sys.exit(1)
    print("\nFEAT-UTL-05 jumphost netns harness complete.\n")


if __name__ == "__main__":
    main()
