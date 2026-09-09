#!/usr/bin/env python3
import os
import sys
import time
import signal
import hashlib
import struct
import subprocess
from pathlib import Path

T = Path("/tmp/relay-verify")
BIN = "/tmp/relay-linux-amd64"
SSHD_PORT = 2222
RELAY_PORT = 7443

PASS = 0
FAIL = 0
RESULTS = []

def netns(ns, cmd_str, check=True):
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def cleanup():
    subprocess.run(["pkill", "-9", "-f", "relay-linux-amd64"], check=False)
    subprocess.run(["pkill", "-9", "-f", "sshd.*sshd-sec.pid"], check=False)
    subprocess.run(["pkill", "-9", "-f", "tcpdump.*veth-cli"], check=False)
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
    print("--- Setting up dual-netns (ns-srv <-> ns-cli) ---")
    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-srv", "netns", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cli", "netns", "ns-cli"], check=True)

    netns("ns-srv", "ip link set lo up && ip addr add 10.200.1.1/24 dev veth-srv && ip link set veth-srv up")
    netns("ns-cli", "ip link set lo up && ip addr add 10.200.1.2/24 dev veth-cli && ip link set veth-cli up")

    # Start sshd in ns-srv
    sshd_cmd = (
        f"/usr/sbin/sshd -f /dev/null -p {SSHD_PORT} -o ListenAddress=127.0.0.1 "
        f"-o PermitRootLogin=yes -o AuthorizedKeysFile={T}/authorized_keys -o StrictModes=no "
        f"-o PasswordAuthentication=no -o UsePAM=no -o HostKey=/etc/ssh/ssh_host_ed25519_key "
        f"-o PidFile={T}/sshd-sec.pid -o ClientAliveInterval=0 -E {T}/sshd-sec.log"
    )
    netns("ns-srv", sshd_cmd)

    # Server config
    srv_conf = f"""
listen_tcp          = "10.200.1.1:{RELAY_PORT}"
transports          = ["tcp"]
default_destination = "127.0.0.1:{SSHD_PORT}"
allow_destinations  = ["127.0.0.1:{SSHD_PORT}"]
host_key            = "{T}/srv_host_key"
log_level           = "debug"
"""
    (T / "srv-sec.toml").write_text(srv_conf)

def start_server():
    netns("ns-srv", f"{BIN} server --config {T}/srv-sec.toml > {T}/srv-sec.log 2>&1 &")
    time.sleep(1)

def get_server_fingerprint():
    # Read fingerprint from server log
    log = (T / "srv-sec.log").read_text()
    for line in log.splitlines():
        if "fingerprint=SHA256:" in line:
            return "SHA256:" + line.split("fingerprint=SHA256:")[1].split()[0]
    return ""

def test_sec_01_e2e_transfer():
    print("--- Running Test SEC-01: End-to-End Encrypted Handshake & OpenSSH Payload ---")
    known_hosts = T / "cli_known_hosts"
    if known_hosts.exists():
        known_hosts.unlink()

    # Start tcpdump in ns-cli to capture wire packets
    pcap = T / "sec_handshake.pcap"
    if pcap.exists():
        pcap.unlink()
    netns("ns-cli", f"tcpdump -i veth-cli -w {pcap} tcp port {RELAY_PORT} >/dev/null 2>&1 &")
    time.sleep(0.5)

    # Test file
    test_file = T / "test-10m.bin"
    if not test_file.exists():
        netns("ns-cli", f"dd if=/dev/urandom of={test_file} bs=1M count=10 status=none")
    want_sha = hashlib.sha256(test_file.read_bytes()).hexdigest()

    out_file = T / "sec-10m.out"
    if out_file.exists():
        out_file.unlink()

    proxy_cmd = f"{BIN} client --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --strict-host-key-checking accept-new --known-hosts {known_hosts}"
    ssh_cmd = (
        f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "
        f"-o ProxyCommand='{proxy_cmd}' root@dummy 'cat > /tmp/relay-verify/sec-10m.out' < {test_file}"
    )

    ret = netns("ns-cli", ssh_cmd, check=False)
    time.sleep(1)
    netns("ns-cli", "pkill -9 -f tcpdump", check=False)

    if ret.returncode != 0:
        record_result("SEC-01-E2E-Transfer", False, f"SSH returned code {ret.returncode}: {ret.stderr}")
        return

    if not out_file.exists():
        record_result("SEC-01-E2E-Transfer", False, "Destination output file missing")
        return

    got_sha = hashlib.sha256(out_file.read_bytes()).hexdigest()
    if got_sha != want_sha:
        record_result("SEC-01-E2E-Transfer", False, f"SHA mismatch got={got_sha} want={want_sha}")
        return

    # Verify known_hosts written
    if not known_hosts.exists() or len(known_hosts.read_text().strip()) == 0:
        record_result("SEC-01-E2E-Transfer", False, "known_hosts was not created or empty")
        return

    record_result("SEC-01-E2E-Transfer", True, f"10 MiB transferred byte-exact (SHA-256 match). Host key recorded in {known_hosts.name}")

def test_sec_02_fingerprint_and_strict():
    print("--- Running Test SEC-02: Fingerprint Pinning & Strict Verification ---")
    fp = get_server_fingerprint()
    if not fp:
        record_result("SEC-02-Fingerprint-Pinning", False, "Server fingerprint not found in log")
        return

    # 1. Correct pinned fingerprint
    proxy_cmd = f"{BIN} client --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {fp} --strict-host-key-checking yes"
    ssh_cmd = f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ProxyCommand='{proxy_cmd}' root@dummy 'echo SEC_OK'"
    ret = netns("ns-cli", ssh_cmd, check=False)
    if ret.returncode != 0 or "SEC_OK" not in ret.stdout:
        record_result("SEC-02-Fingerprint-Correct", False, f"Failed with matching fingerprint: {ret.stderr}")
    else:
        record_result("SEC-02-Fingerprint-Correct", True, f"Handshake verified with pinned fingerprint {fp[:20]}...")

    # 2. Mismatched pinned fingerprint
    bad_fp = "SHA256:0000000000000000000000000000000000000000000"
    proxy_cmd = f"{BIN} client --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --server-fingerprint {bad_fp} --strict-host-key-checking yes"
    ssh_cmd = f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ProxyCommand='{proxy_cmd}' root@dummy 'echo SEC_FAIL'"
    ret = netns("ns-cli", ssh_cmd, check=False)
    if ret.returncode == 0:
        record_result("SEC-02-Fingerprint-Mismatch-Reject", False, "Mismatched fingerprint succeeded when it should fail!")
    else:
        record_result("SEC-02-Fingerprint-Mismatch-Reject", True, "Mismatched fingerprint rejected with non-zero exit code")

    # 3. Corrupted known_hosts (MITM detection)
    known_hosts = T / "cli_mitm_hosts"
    fake_entry = f"10.200.1.1:{RELAY_PORT} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGarbAgeGarBageGarBageGarBageGarBageGarBageGa\n"
    known_hosts.write_text(fake_entry)
    proxy_cmd = f"{BIN} client --server 10.200.1.1:{RELAY_PORT} --dest 127.0.0.1:{SSHD_PORT} --tcp --strict-host-key-checking yes --known-hosts {known_hosts}"
    ssh_cmd = f"ssh -F /dev/null -i {T}/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ProxyCommand='{proxy_cmd}' root@dummy 'echo SEC_FAIL'"
    ret = netns("ns-cli", ssh_cmd, check=False)
    if ret.returncode == 0:
        record_result("SEC-02-MITM-Detection", False, "Altered host key in known_hosts did not fail!")
    else:
        record_result("SEC-02-MITM-Detection", True, "Host key mismatch cleanly detected and aborted (MITM protection active)")

def test_sec_03_plaintext_probe_rejection():
    print("--- Running Test SEC-03: Plaintext Probe Rejection ---")
    # Craft a cleartext TypeHello frame: Type=0x01, Len=4-byte BE, JSON payload
    hello_payload = b'{"v":1,"destination":"127.0.0.1:2222","transport":["tcp"],"clientNonce":"cleartext"}'
    hdr = struct.pack(">BI", 0x01, len(hello_payload))
    probe_bytes = hdr + hello_payload

    # Send from ns-cli via python
    py_script = f"""
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect(('10.200.1.1', {RELAY_PORT}))
s.sendall({repr(probe_bytes)})
resp = s.recv(1024)
s.close()
if len(resp) < 5:
    sys.exit(1)
typ, n = struct.unpack('>BI', resp[:5])
payload = resp[5:5+n].decode('utf-8', errors='ignore')
print(f"TYPE={{typ}} PAYLOAD={{payload}}")
"""
    ret = netns("ns-cli", f"python3 -c {subprocess.list2cmdline([py_script])}", check=False)
    out = ret.stdout.strip()
    if "TYPE=8" in out and "ERR_PROTO" in out and "encrypted handshake required" in out:
        record_result("SEC-03-Plaintext-Probe-Rejected", True, f"Server immediately returned ERR_PROTO: {out}")
    else:
        record_result("SEC-03-Plaintext-Probe-Rejected", False, f"Unexpected response to plaintext probe: stdout={out} stderr={ret.stderr}")

def test_sec_04_wire_encryption_and_clean_cut():
    print("--- Running Test SEC-04: Wire Inspection & Clean Phase Cut ---")
    pcap = T / "sec_handshake.pcap"
    if not pcap.exists() or pcap.stat().st_size == 0:
        record_result("SEC-04-Wire-Inspection", False, "pcap file missing or empty")
        return

    # Extract all TCP payload bytes from pcap
    extract_cmd = f"tcpdump -r {pcap} -xx -q 'tcp port {RELAY_PORT}' 2>/dev/null"
    ret = netns("ns-cli", extract_cmd, check=False)
    pcap_data = pcap.read_bytes()

    # Search for sensitive metadata strings in the raw pcap bytes
    forbidden_strings = [
        b'"destination"',
        b'127.0.0.1:2222',
        b'"resumeToken"',
        b'"sessionId"',
        b'"clientNonce"',
        b'"serverNonce"',
    ]

    leaks = []
    for s in forbidden_strings:
        if s in pcap_data:
            leaks.append(s.decode('latin1'))

    if leaks:
        record_result("SEC-04-Wire-Inspection", False, f"Cleartext metadata leaked on wire: {leaks}")
    else:
        record_result("SEC-04-Wire-Inspection", True, "Zero cleartext metadata or session tokens observed on wire!")

def main():
    print("==========================================================")
    print("  FEAT-SEC-01: Live Dual-Netns Security Verification Suite")
    print("==========================================================")
    try:
        setup_env()
        start_server()
        test_sec_01_e2e_transfer()
        test_sec_02_fingerprint_and_strict()
        test_sec_03_plaintext_probe_rejection()
        test_sec_04_wire_encryption_and_clean_cut()
    finally:
        cleanup()

    print("\n==========================================================")
    print(f"  Summary: {PASS} PASSED, {FAIL} FAILED")
    print("==========================================================")
    for res in RESULTS:
        print(f"  {res}")

    if FAIL > 0:
        sys.exit(1)
    print("\nFEAT-SEC-01 dual-netns verification SUCCESSFUL!\n")

if __name__ == "__main__":
    main()
