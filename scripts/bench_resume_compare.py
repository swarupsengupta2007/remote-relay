#!/usr/bin/env python3
import time
import subprocess
from pathlib import Path

BIN = "/tmp/relay-perf-bin"
T = Path("/tmp/relay-bench")
RELAY_PORT = 7443

def netns(ns, cmd_str, check=True):
    return subprocess.run(["ip", "netns", "exec", ns, "bash", "-c", cmd_str],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)

def run():
    print("--- Running Dual-Netns Direct Benchmark: 3-RTT vs 4-RTT under 80ms WAN RTT ---")
    T.mkdir(parents=True, exist_ok=True)
    subprocess.run(["pkill", "-9", "-f", "relay-perf-bin"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-srv"], check=False)
    subprocess.run(["ip", "netns", "del", "ns-cli"], check=False)

    subprocess.run(["ip", "netns", "add", "ns-srv"], check=True)
    subprocess.run(["ip", "netns", "add", "ns-cli"], check=True)
    subprocess.run(["ip", "link", "add", "veth-srv", "type", "veth", "peer", "name", "veth-cli"], check=True)
    subprocess.run(["ip", "link", "set", "veth-srv", "netns", "ns-srv"], check=True)
    subprocess.run(["ip", "link", "set", "veth-cli", "netns", "ns-cli"], check=True)

    netns("ns-srv", "ip link set lo up && ip addr add 10.200.1.1/24 dev veth-srv && ip link set veth-srv up")
    netns("ns-cli", "ip link set lo up && ip addr add 10.200.1.2/24 dev veth-cli && ip link set veth-cli up")
    netns("ns-srv", "tc qdisc add dev veth-srv root netem delay 40ms")
    netns("ns-cli", "tc qdisc add dev veth-cli root netem delay 40ms")

    # Client keys
    cli_key = T / "id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(cli_key), "-C", "alice@relay"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    pub_key_str = (T / "id_ed25519.pub").read_text().strip()
    (T / "authorized_keys").write_text(pub_key_str + "\n")
    (T / "authorized_keys").chmod(0o600)

    # Server config
    srv_conf = f"""
listen_tcp          = "10.200.1.1:{RELAY_PORT}"
transports          = ["tcp"]
default_destination = "127.0.0.1:9999"
allow_destinations  = ["127.0.0.1:9999"]
host_key            = "{T}/srv_host_key"
auth_method         = "ssh-publickey"
authorized_keys     = "{T}/authorized_keys"
auth_fail_delay     = "0ms"
hold_timeout        = "30s"
log_level           = "error"
"""
    (T / "srv.toml").write_text(srv_conf)

    # Start dummy destination listener in ns-srv
    netns("ns-srv", "python3 -c \"import socket; s = socket.socket(); s.bind(('127.0.0.1', 9999)); s.listen(5); [s.accept() for _ in iter(int, 1)]\" &", check=False)

    # Build binary and start server in ns-srv
    subprocess.run(["go", "build", "-o", BIN, "./cmd/relay"], cwd="/root/remote-relay", check=True)
    netns("ns-srv", f"{BIN} server --config {T}/srv.toml > {T}/srv.log 2>&1 &")
    time.sleep(1)

    try:
        ret = netns("ns-cli", "cd /root/remote-relay && go test -count=1 -v -run TestBenchmarkClientTurns ./internal/relay", check=False)
        print(ret.stdout)
    finally:
        subprocess.run(["pkill", "-9", "-f", "relay-perf-bin"], check=False)
        subprocess.run(["ip", "netns", "del", "ns-srv"], check=False)
        subprocess.run(["ip", "netns", "del", "ns-cli"], check=False)

if __name__ == "__main__":
    run()
