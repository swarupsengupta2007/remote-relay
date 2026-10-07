#!/usr/bin/env python3
"""Exercise remote-relay inside network namespaces.

Host interfaces, routes, rules, and firewalls are snapshotted and must match
at the end. veth pairs are created with both ends already in a namespace, so
they never appear on the host. iptables, ip6tables, tc, and sysctl run only
via `ip netns exec`.

Run as root from anywhere: `sudo python3 scripts/test_netns_suite.py`.
It builds the relay from this checkout and works in RELAY_NETNS_DIR
(default /tmp/relay-netns-check). Exit status is 0 only if every check passes.
"""

import hashlib
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
T = Path(os.environ.get("RELAY_NETNS_DIR", "/tmp/relay-netns-check"))
BIN = T / "relay"
KEY = T / "id_ed25519"
KEY_BAD = T / "id_ed25519_bad"
KNOWN = T / "known_hosts"
AUTH = T / "authorized_keys"
HOST_KEY = T / "srv_host_key"
JUMP_KEY = T / "jump_host_key"
SSHD_KEY = T / "sshd_host_key"
SSHD_KEY_AGT = T / "sshd_host_key_agt"
SRV_CFG = T / "server.toml"
JUMP_CFG = T / "jump.toml"
CHILD_PID = T / "child.pid"
WWW = T / "www"

NS_ALL = ["rr-cli", "rr-srv", "rr-jump", "rr-agt", "rr-loss"]
SRV = "10.88.4.1"
JUMP = "10.88.1.1"
TERM = "10.88.2.2"
AGT_SRV = "10.88.3.1"
LOSS_SRV = "10.88.5.1"

PASS = 0
FAIL = 0
RESULTS = []
SPAWNED = []  # (popen, logfh, pgid)
AGENT_PROC = None
HOST_BEFORE = None


def say(msg):
    print(msg, flush=True)


def record(name, ok, details=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        verdict = "PASS"
    else:
        FAIL += 1
        verdict = "FAIL"
    line = f"[{verdict}] {name}: {details}"
    RESULTS.append(line)
    say("\n>>> " + line + "\n")


def run(args, timeout=30, check=False, input_bytes=None, env=None, text=False, cwd=None):
    return subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=check,
        env=env,
        text=text,
        cwd=cwd,
    )


def netns(ns, args, timeout=30, input_bytes=None, env=None):
    return run(["ip", "netns", "exec", ns, *args], timeout=timeout, input_bytes=input_bytes, env=env)


def clean_env(extra=None):
    env = os.environ.copy()
    for k in ("SSH_AUTH_SOCK", "RELAY_TEST_IDENTITY", "RELAY_TEST_AUTH_SOCK", "RELAY_HANDOVER_FD", "RELAY_HUD"):
        env.pop(k, None)
    if extra:
        env.update(extra)
    return env


def normalize_snapshot(name, text):
    """Compare the host stack, not live counters or lease timers."""
    if name in ("iptables", "ip6tables"):
        lines = []
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            line = re.sub(r" \[\d+:\d+\]", "", line)
            lines.append(line)
        return "\n".join(lines) + "\n"
    if name == "nft":
        text = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", text)
        return text
    if name == "addr":
        return re.sub(r"valid_lft \S+ preferred_lft \S+", "valid_lft L preferred_lft L", text)
    if name == "route":
        return re.sub(r"\bexpires \S+", "expires E", text)
    return text


def host_snapshot():
    cmds = {
        "link": ["ip", "-o", "link", "show"],
        "addr": ["ip", "-o", "addr", "show"],
        "route": ["ip", "-o", "route", "show", "table", "all"],
        "rule": ["ip", "rule", "show"],
        "netns": ["ip", "netns", "list"],
        "iptables": ["iptables-save"],
        "ip6tables": ["ip6tables-save"],
        "sysctl": ["sysctl", "-n",
                   "net.ipv4.ip_forward",
                   "net.ipv4.conf.all.rp_filter",
                   "net.ipv4.conf.default.rp_filter",
                   "net.ipv6.conf.all.forwarding"],
    }
    out = {}
    for name, cmd in cmds.items():
        r = run(cmd, timeout=15, text=True)
        raw = r.stdout if r.returncode == 0 else f"ERR {r.returncode}\n{r.stderr}"
        out[name] = normalize_snapshot(name, raw)
    nft = run(["nft", "list", "ruleset"], timeout=15, text=True)
    raw = nft.stdout if nft.returncode == 0 else f"ERR {nft.returncode}\n{nft.stderr}"
    out["nft"] = normalize_snapshot("nft", raw)
    return out


def snapshot_diff(a, b):
    diffs = []
    for k in a:
        if a[k] != b.get(k):
            diffs.append(k)
    return diffs


def cleanup():
    global AGENT_PROC
    if AGENT_PROC is not None:
        try:
            os.kill(AGENT_PROC, signal.SIGTERM)
        except ProcessLookupError:
            pass
        AGENT_PROC = None
    for ns in NS_ALL:
        r = run(["ip", "netns", "pids", ns], timeout=10, text=True)
        for tok in (r.stdout or "").split():
            try:
                os.kill(int(tok), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
    time.sleep(0.3)
    for ns in NS_ALL:
        run(["ip", "netns", "del", ns], timeout=10)
    shutil.rmtree("/etc/netns/rr-cli", ignore_errors=True)
    for p, fh, pgid in SPAWNED:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            fh.close()
        except Exception:
            pass
    SPAWNED.clear()


def spawn(ns, argv, log_path, env_extra=None):
    pidfile = str(log_path) + ".pid"
    try:
        os.remove(pidfile)
    except FileNotFoundError:
        pass
    script = 'echo $$ > "$1"; shift; exec "$@"'
    cmd = ["ip", "netns", "exec", ns, "bash", "-c", script, "spawn", pidfile, *argv]
    logf = open(log_path, "w")
    proc = subprocess.Popen(
        cmd,
        stdout=logf,
        stderr=subprocess.STDOUT,
        env=clean_env(env_extra),
        start_new_session=True,
    )
    SPAWNED.append((proc, logf, proc.pid))
    deadline = time.time() + 5
    pid = None
    while time.time() < deadline:
        if os.path.exists(pidfile):
            raw = Path(pidfile).read_text().strip()
            if raw:
                pid = int(raw)
                break
        time.sleep(0.05)
    return pid, proc


def stop_pid(pid):
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def listening(ns, port):
    r = netns(ns, ["ss", "-ltn"], timeout=5)
    text = (r.stdout or b"") + (r.stderr or b"")
    return f":{port}".encode() in text


def wait_listen(ns, port, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if listening(ns, port):
            return True
        time.sleep(0.05)
    return False


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def write_cfg(path, fields):
    lines = []
    for k, v in fields.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, list):
            inner = ", ".join(toml_quote(x) for x in v)
            lines.append(f"{k} = [{inner}]")
        else:
            lines.append(f"{k} = {toml_quote(v)}")
    path.write_text("\n".join(lines) + "\n")


def toml_quote(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def base_server_fields():
    return {
        "listen_tcp": "0.0.0.0:7443",
        "udp_listen": "0.0.0.0:7443",
        "listen_ws": "ws://0.0.0.0:8444",
        "websocket_path": "/relay-stream",
        "metrics_listen": f"{SRV}:9090",
        "transports": ["quic", "kcp", "tcp"],
        "default_destination": "127.0.0.1:2222",
        "allow_destinations": ["127.0.0.1:2222", "127.0.0.1:18080", "127.0.0.1:19000", "127.0.0.1:19001"],
        "authorized_keys": str(AUTH),
        "host_key": str(HOST_KEY),
        "auth_method": "ssh-publickey",
        "auth_fail_delay": "20ms",
        "log_level": "info",
        "log_format": "text",
        "heartbeat_interval": "750ms",
        "dead_peer_threshold": 3,
        "hold_timeout": "2m",
        "idle_timeout": "30s",
        "probe_timeout": "2s",
        "probe_attempts": 2,
        "dial_timeout": "5s",
        "allow_relay_hops": [],
        "max_chain_depth": 4,
        "relay_strict_host_key_checking": "no",
        "spill_dir": str(T / "spill"),
        "spill_l1_bytes": 65536,
        "max_conns_per_ip": 64,
        "trusted_proxies": [],
    }


SERVER_PID = None
SERVER_LOG = T / "srv.log"


def start_server(extra_fields=None, cli_args=None):
    global SERVER_PID
    stop_pid(SERVER_PID)
    SERVER_PID = None
    fields = base_server_fields()
    if extra_fields:
        fields.update(extra_fields)
    write_cfg(SRV_CFG, fields)
    argv = [str(BIN), "server", "--config", str(SRV_CFG), "--authorized-keys", str(AUTH), "--host-key", str(HOST_KEY)]
    if cli_args:
        argv.extend(cli_args)
    env = {"RELAY_CHILD_PID_FILE": str(CHILD_PID)}
    pid, _ = spawn("rr-srv", argv, SERVER_LOG, env)
    SERVER_PID = pid
    ok = wait_listen("rr-srv", 7443, 8) and wait_listen("rr-srv", 8444, 8)
    return ok, pid


def log_tail(path, n=40):
    if not path.exists():
        return ""
    lines = path.read_text(errors="replace").splitlines()
    return "\n".join(lines[-n:])


def log_since(path, offset):
    if not path.exists():
        return ""
    data = path.read_text(errors="replace")
    return data[offset:]


def log_len(path):
    if not path.exists():
        return 0
    return path.stat().st_size


def client_argv(extra):
    extra = list(extra)
    has_server = any(a == "--server" or a.startswith("--server=") for a in extra)
    argv = [str(BIN), "client"]
    if not has_server:
        argv += ["--server", f"{SRV}:7443"]
    argv += [
        "-i", str(KEY),
        "--strict-host-key-checking", "accept-new",
        "--known-hosts", str(KNOWN),
        "--log-level", "warn",
        *extra,
    ]
    return argv


def start_sink(out_path, port=19000, delay=0.0, log_name="sink.log"):
    script = T / "sink.py"
    script.write_text(
        "import socket,sys,time\n"
        "port=int(sys.argv[1]); out=sys.argv[2]; delay=float(sys.argv[3])\n"
        "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('127.0.0.1', port)); s.listen(1); s.settimeout(40)\n"
        "c,_=s.accept()\n"
        "if delay: time.sleep(delay)\n"
        "c.settimeout(40)\n"
        "f=open(out,'wb',buffering=0)\n"
        "try:\n"
        "    while True:\n"
        "        b=c.recv(65536)\n"
        "        if not b: break\n"
        "        f.write(b)\n"
        "finally:\n"
        "    f.close(); c.close(); s.close()\n"
    )
    return spawn("rr-srv", ["python3", str(script), str(port), str(out_path), str(delay)], T / log_name)


def wait_exact(path, payload, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            try:
                if path.read_bytes() == payload:
                    return True
            except OSError:
                pass
        time.sleep(0.05)
    return path.exists() and path.read_bytes() == payload


def pipe_upload(label, payload, extra, timeout=25, sink_delay=0.0, ns="rr-cli", port=19000, server=None):
    out = T / f"{label}.out"
    if out.exists():
        out.unlink()
    pid, _ = start_sink(out, port=port, delay=sink_delay, log_name=f"sink-{label}.log")
    if not wait_listen("rr-srv", port, 5):
        stop_pid(pid)
        return False, "sink did not listen: " + log_tail(T / f"sink-{label}.log")
    dest_args = ["--dest", f"127.0.0.1:{port}", *extra]
    if server:
        dest_args = ["--server", server, *dest_args]
    argv = client_argv(dest_args)
    try:
        r = netns(ns, argv, timeout=timeout, input_bytes=payload)
    except subprocess.TimeoutExpired as e:
        stop_pid(pid)
        return False, f"client timeout after {timeout}s stderr={(e.stderr or b'')[-400:]!r}"
    got_it = wait_exact(out, payload, timeout=5)
    stop_pid(pid)
    if r.returncode != 0:
        err = (r.stderr or b"").decode(errors="replace")[-500:]
        return False, f"client exit {r.returncode}: {err}"
    if not got_it:
        got = out.read_bytes() if out.exists() else b""
        return False, f"len got {len(got)} want {len(payload)}"
    return True, f"{len(payload)} bytes exact"


def metrics_text():
    r = netns("rr-cli", ["curl", "-fsS", "--max-time", "3", f"http://{SRV}:9090/metrics"], timeout=8)
    if r.returncode != 0:
        return ""
    return (r.stdout or b"").decode(errors="replace")


def metric_sum(text, name):
    total = 0.0
    found = False
    for line in text.splitlines():
        if not line.startswith(name):
            continue
        if line.startswith(name + "{") or line.startswith(name + " "):
            found = True
            try:
                total += float(line.split()[-1])
            except ValueError:
                pass
    return found, total


def setup():
    global HOST_BEFORE
    T.mkdir(parents=True, exist_ok=True)
    (T / "spill").mkdir(exist_ok=True)
    WWW.mkdir(exist_ok=True)
    say("--- building relay ---")
    r = run(["go", "build", "-o", str(BIN), "./cmd/relay"], timeout=180, text=True, cwd=str(ROOT))
    if r.returncode != 0:
        say(r.stderr)
        raise SystemExit("build failed")

    say("--- host snapshot ---")
    HOST_BEFORE = host_snapshot()

    say("--- creating namespaces (veth ends born inside them) ---")
    for ns in NS_ALL:
        run(["ip", "netns", "del", ns], timeout=10)
        run(["ip", "netns", "add", ns], timeout=10, check=True)

    pairs = [
        ("rr-cli", "veth-cj", "rr-jump", "veth-jc"),
        ("rr-jump", "veth-js", "rr-srv", "veth-sj"),
        ("rr-cli", "veth-cs", "rr-srv", "veth-sc"),
        ("rr-agt", "veth-as", "rr-srv", "veth-sa"),
        ("rr-loss", "veth-ls", "rr-srv", "veth-sl"),
    ]
    for a, ia, b, ib in pairs:
        run(["ip", "link", "add", ia, "netns", a, "type", "veth", "peer", "name", ib, "netns", b], timeout=10, check=True)

    def up(ns, script):
        r = netns(ns, ["bash", "-c", script], timeout=10)
        if r.returncode != 0:
            raise SystemExit(f"setup {ns} failed: {r.stderr.decode()}")

    up("rr-cli", "ip link set lo up; ip addr add 10.88.1.2/24 dev veth-cj; ip link set veth-cj up; ip addr add 10.88.4.2/24 dev veth-cs; ip link set veth-cs up; ip -6 addr add fd88:4::2/64 dev veth-cs nodad")
    up("rr-jump", "ip link set lo up; ip addr add 10.88.1.1/24 dev veth-jc; ip link set veth-jc up; ip addr add 10.88.2.1/24 dev veth-js; ip link set veth-js up")
    up("rr-srv", "ip link set lo up; ip addr add 10.88.4.1/24 dev veth-sc; ip link set veth-sc up; ip addr add 10.88.2.2/24 dev veth-sj; ip link set veth-sj up; ip addr add 10.88.3.1/24 dev veth-sa; ip link set veth-sa up; ip addr add 10.88.5.1/24 dev veth-sl; ip link set veth-sl up; ip -6 addr add fd88:4::1/64 dev veth-sc nodad; sysctl -w net.ipv4.conf.all.rp_filter=0; sysctl -w net.ipv4.conf.default.rp_filter=0")
    up("rr-agt", "ip link set lo up; ip addr add 10.88.3.2/24 dev veth-as; ip link set veth-as up; iptables -P INPUT DROP; iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
    up("rr-loss", "ip link set lo up; ip addr add 10.88.5.2/24 dev veth-ls; ip link set veth-ls up; tc qdisc add dev veth-ls root netem delay 20ms loss 8%")

    # Blackhole IPv6 to the server so Happy Eyeballs must fall back. Rule lives in rr-srv only.
    # Drop relay port 7443 on IPv6, but leave ICMPv6 alone so neighbor
    # discovery can resolve fd88:4::1. A blanket INPUT DROP makes connect()
    # fail with "no route to host" and never emits a TCP SYN.
    r = netns("rr-srv", ["ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", "7443", "-j", "DROP"], timeout=10)
    if r.returncode != 0:
        say("ip6tables warning: " + r.stderr.decode(errors="replace"))
    r = netns("rr-srv", ["ip6tables", "-A", "INPUT", "-p", "udp", "--dport", "7443", "-j", "DROP"], timeout=10)
    if r.returncode != 0:
        say("ip6tables warning: " + r.stderr.decode(errors="replace"))

    nsdir = Path("/etc/netns/rr-cli")
    nsdir.mkdir(parents=True, exist_ok=True)
    # Hosts only. A netns resolv.conf would replace DNS for every lookup inside
    # rr-cli; Happy Eyeballs must see this file without a dead nameserver.
    (nsdir / "hosts").write_text("127.0.0.1 localhost\n10.88.4.1 relay.test\nfd88:4::1 relay.test\n")

    mid = host_snapshot()
    # While namespaces exist, host link/addr/route/rule/firewall must be unchanged.
    # `ip netns list` is expected to differ.
    for key in ("link", "addr", "route", "rule", "iptables", "ip6tables", "nft", "sysctl"):
        if mid[key] != HOST_BEFORE[key]:
            record("host-stack-untouched-while-netns-up", False, f"{key} changed during setup")
            return False
    host_links = mid["link"]
    if "rr-p" in host_links or "veth-c" in host_links or "veth-s" in host_links or "veth-j" in host_links or "veth-a" in host_links or "veth-l" in host_links:
        record("host-stack-untouched-while-netns-up", False, "a test interface is visible on the host")
        return False
    record("host-stack-untouched-while-netns-up", True, "host link, addr, route, rule, iptables, ip6tables, nft unchanged")

    say("--- keys and sshd ---")
    # Host keys are regenerated every run. Strict checking must not keep the
    # previous run's pins, or every later dial dies as a changed host key.
    for stale in (KNOWN, T / "agent_known", T / "jump_known", T / "known_bad"):
        stale.unlink(missing_ok=True)
    for p in (KEY, KEY_BAD, HOST_KEY, JUMP_KEY, SSHD_KEY, SSHD_KEY_AGT):
        if p.exists():
            p.unlink()
        pub = Path(str(p) + ".pub")
        if pub.exists():
            pub.unlink()
        run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(p)], timeout=15, check=True)
    AUTH.write_text(Path(str(KEY) + ".pub").read_text())
    os.chmod(AUTH, 0o600)
    os.chmod(KEY, 0o600)

    def start_sshd(ns, key, pidfile, logf):
        cmd = (
            f"/usr/sbin/sshd -f /dev/null -p 2222 -o ListenAddress=127.0.0.1 "
            f"-o PermitRootLogin=yes -o AuthorizedKeysFile={AUTH} -o StrictModes=no "
            f"-o PasswordAuthentication=no -o UsePAM=no -o UseDNS=no -o HostKey={key} "
            f"-o PidFile={pidfile} -o ClientAliveInterval=0 -E {logf}"
        )
        r = netns(ns, ["bash", "-c", cmd], timeout=10)
        if r.returncode != 0:
            raise SystemExit(f"sshd {ns} failed: {r.stderr.decode()} {r.stdout.decode()}")

    start_sshd("rr-srv", SSHD_KEY, T / "sshd-srv.pid", T / "sshd-srv.log")
    start_sshd("rr-agt", SSHD_KEY_AGT, T / "sshd-agt.pid", T / "sshd-agt.log")
    if not wait_listen("rr-srv", 2222, 5):
        raise SystemExit("sshd not listening in rr-srv: " + log_tail(T / "sshd-srv.log"))
    if not wait_listen("rr-agt", 2222, 5):
        raise SystemExit("sshd not listening in rr-agt: " + log_tail(T / "sshd-agt.log"))

    (WWW / "a.txt").write_text("alpha-socks-payload\n")
    (WWW / "b.txt").write_text("beta-socks-payload\n")
    http_pid, _ = spawn(
        "rr-srv",
        ["python3", "-m", "http.server", "18080", "--bind", "127.0.0.1", "--directory", str(WWW)],
        T / "http.log",
    )
    if not wait_listen("rr-srv", 18080, 5):
        raise SystemExit(f"http.server failed pid={http_pid}: " + log_tail(T / "http.log"))
    (WWW / "big.bin").write_bytes(os.urandom(512 * 1024))

    def ping_ok(ns, dest, *flags):
        last = 1
        for _ in range(4):
            r = netns(ns, ["ping", *flags, "-c", "1", "-W", "2", dest], timeout=8)
            last = r.returncode
            if last == 0:
                return 0
        return last

    ping = ping_ok("rr-cli", SRV)
    ping_j = ping_ok("rr-cli", JUMP)
    ping_a = ping_ok("rr-agt", AGT_SRV)
    ping_l = ping_ok("rr-loss", LOSS_SRV)
    # Addresses are added with nodad, and the ping retries like the v4 ones,
    # so a first ICMPv6 echo racing neighbor discovery is not a failure.
    ping6_rc = ping_ok("rr-cli", "fd88:4::1", "-6")
    # Closed-port v6 would refuse immediately. A dropped SYN must time out.
    tcp6 = netns("rr-cli", ["python3", "-c",
        "import socket,sys\n"
        "s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(0.6)\n"
        "try:\n"
        "    s.connect(('fd88:4::1',7443)); sys.exit(0)\n"
        "except socket.timeout:\n"
        "    sys.exit(2)\n"
        "except OSError as e:\n"
        "    print(e); sys.exit(1)\n"], timeout=5)
    paths_ok = ping == 0 and ping_j == 0 and ping_a == 0 and ping_l == 0
    v6_ndp = ping6_rc == 0
    v6_tcp_blackhole = tcp6.returncode == 2
    record(
        "netns-paths",
        paths_ok and v6_ndp and v6_tcp_blackhole,
        f"v4 cli->srv={ping} cli->jump={ping_j} agt->srv={ping_a} loss->srv={ping_l} "
        f"v6_ping_rc={ping6_rc} v6_tcp7443_rc={tcp6.returncode} {(tcp6.stdout or b'')[:80]!r}",
    )
    if not paths_ok:
        return False

    payload = os.urandom(256 * 1024)
    (T / "payload-256k.bin").write_bytes(payload)
    (T / "payload-1m.bin").write_bytes(os.urandom(1024 * 1024))
    return True


def ssh_via(proxy_script, remote_cmd, stdin_path=None, timeout=25, ns="rr-cli"):
    os.chmod(proxy_script, 0o755)
    argv = [
        "ssh", "-F", "/dev/null",
        "-i", str(KEY),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "PasswordAuthentication=no",
        "-o", f"ProxyCommand={proxy_script}",
        "-o", "ConnectTimeout=15",
        "root@dummy",
        remote_cmd,
    ]
    data = Path(stdin_path).read_bytes() if stdin_path else None
    return netns(ns, argv, timeout=timeout, input_bytes=data)


def write_proxy(path, args):
    # args is a list; quote for sh
    quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in args)
    path.write_text("#!/bin/sh\nexec " + quoted + "\n")
    os.chmod(path, 0o755)


def test_tcp_ssh():
    payload = T / "payload-256k.bin"
    out = T / "ssh-tcp.out"
    if out.exists():
        out.unlink()
    proxy = T / "proxy-tcp.sh"
    write_proxy(proxy, client_argv(["--tcp", "--dest", "127.0.0.1:2222"]))
    r = ssh_via(proxy, f"cat > {out}", stdin_path=payload, timeout=20)
    if r.returncode != 0:
        record("tcp-ssh-transfer", False, (r.stderr or b"").decode(errors="replace")[-400:])
        return
    if not out.exists() or sha256_file(out) != sha256_file(payload):
        record("tcp-ssh-transfer", False, "sha mismatch or missing output")
        return
    if not KNOWN.exists() or "ssh-ed25519" not in KNOWN.read_text():
        record("tcp-ssh-transfer", False, "known_hosts was not recorded")
        return
    record("tcp-ssh-transfer", True, "256 KiB SSH payload byte-exact; host key saved")


def test_pipe(mode_args, name):
    payload = (T / "payload-256k.bin").read_bytes()
    ok, detail = pipe_upload(name, payload, mode_args, timeout=25)
    record(name, ok, detail)


def test_quic_and_kcp():
    test_pipe([], "quic-upload")
    test_pipe(["--kcp"], "kcp-upload")


def test_metrics_and_splice():
    text = metrics_text()
    if not text:
        record("metrics-bytes-and-splice", False, "metrics scrape failed")
        return
    ok_b, nbytes = metric_sum(text, "relay_bytes_transferred_total")
    ok_s, sbytes = metric_sum(text, "relay_spliced_bytes_total")
    ok_c, calls = metric_sum(text, "relay_splice_calls_total")
    detail = f"bytes={nbytes:.0f} spliced={sbytes:.0f} splice_calls={calls:.0f}"
    good = ok_b and nbytes >= 256 * 1024 and ok_s and sbytes > 0 and ok_c and calls > 0
    record("metrics-bytes-and-splice", good, detail)
    r = netns("rr-cli", [str(BIN), "stats", "--endpoint", f"http://{SRV}:9090/metrics"], timeout=10)
    out = (r.stdout or b"").decode(errors="replace")
    stats_ok = r.returncode == 0 and ("splice" in out.lower() or "bytes" in out.lower() or "session" in out.lower())
    record("relay-stats-scrape", stats_ok, f"exit {r.returncode} " + (out.strip().splitlines()[0] if out.strip() else "empty"))
    top = netns("rr-cli", [str(BIN), "top", "--batch", "--endpoint", f"http://{SRV}:9090/metrics", "--color", "never"], timeout=10)
    top_out = (top.stdout or b"").decode(errors="replace")
    top_ok = top.returncode == 0 and ("bytes" in top_out.lower() or "session" in top_out.lower() or "splice" in top_out.lower())
    record("relay-top-batch", top_ok, f"exit {top.returncode} " + (top_out.strip().splitlines()[0] if top_out.strip() else (top.stderr or b"")[:160].decode(errors="replace")))


def byte_note(path, payload):
    """Describe a sink mismatch. extra>0 means the sink contains more than was sent."""
    if not path.exists():
        return "missing"
    got = path.read_bytes()
    if got == payload:
        return f"exact {len(got)}"
    n = min(len(got), len(payload))
    i = 0
    while i < n and got[i] == payload[i]:
        i += 1
    extra = len(got) - len(payload)
    note = f"out={len(got)} extra={extra} prefix={i}"
    if extra > 0 and i + extra <= len(got):
        inserted = got[i:i + extra]
        at = payload.find(inserted)
        if at >= 0:
            note += f" inserted_from_payload[{at}:{at + extra}]"
    return note


def test_resume():
    # Server is still the process started with --splice.
    _resume_case("tcp-resume-after-kill", ["--tcp"])
    # Client --no-splice does not change the server pump. Restart so this
    # case measures userspace resume on both ends.
    ok, _pid = start_server(cli_args=["--log-level", "debug", "--no-splice"])
    if not ok:
        record("tcp-resume-after-kill-nosplice", False, "nosplice server failed: " + log_tail(SERVER_LOG))
        return
    _resume_case("tcp-resume-after-kill-nosplice", ["--tcp", "--no-splice"])


def _resume_case(name, mode):
    # Slow the direct path so the TCP session is still open when we kill it.
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "4mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    payload = (T / "payload-1m.bin").read_bytes()
    out = T / f"{name}.out"
    if out.exists():
        out.unlink()
    pid, _ = start_sink(out, delay=0.0, log_name=f"sink-{name}.log")
    if not wait_listen("rr-srv", 19000, 5):
        record(name, False, "sink failed")
        netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
        return
    argv = client_argv([*mode, "--dest", "127.0.0.1:19000"])
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=clean_env(),
    )
    try:
        # Feed in a thread so we can kill the socket mid-transfer.
        import threading
        err_box = {}

        def feed():
            try:
                proc.stdin.write(payload)
                proc.stdin.close()
            except Exception as e:
                err_box["e"] = e

        th = threading.Thread(target=feed)
        th.start()
        time.sleep(0.4)
        kr = netns("rr-cli", ["ss", "-K", "-t", "dst", SRV, "dport", "=", "7443"], timeout=5)
        th.join(timeout=20)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    finally:
        netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    exact = wait_exact(out, payload, timeout=5)
    stop_pid(pid)
    if proc.returncode is None or not exact or proc.returncode != 0:
        err = (proc.stderr.read() if proc.stderr else b"").decode(errors="replace")[-300:]
        record(name, False, f"rc={proc.returncode} {byte_note(out, payload)} ss={kr.stdout[-80:]!r} {err}")
        return
    record(name, True, f"1 MiB exact after killing the client TCP ({' '.join(mode)})")


def spill_fds():
    hits = []
    for ns in ("rr-cli", "rr-srv"):
        r = run(["ip", "netns", "pids", ns], timeout=5, text=True)
        for tok in (r.stdout or "").split():
            fd_dir = Path(f"/proc/{tok}/fd")
            if not fd_dir.is_dir():
                continue
            cmdline = ""
            try:
                cmdline = Path(f"/proc/{tok}/cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace")
            except OSError:
                pass
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if "relay-spill" in target:
                    hits.append(f"{ns} pid={tok} {target} cmd={cmdline[:80]}")
    return hits


def test_spill():
    payload = (T / "payload-256k.bin").read_bytes()
    out = T / "spill.out"
    if out.exists():
        out.unlink()
    # Destination does not read, so the uploader's resume ring keeps unacked bytes.
    pid, _ = start_sink(out, delay=2.5, log_name="sink-spill.log")
    if not wait_listen("rr-srv", 19000, 5):
        record("disk-spill", False, "sink failed")
        stop_pid(pid)
        return
    argv = client_argv([
        "--tcp", "--dest", "127.0.0.1:19000",
        "--spill-l1-bytes", "65536", "--spill-dir", str(T / "spill"),
    ])
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(),
    )
    import threading

    def feed():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except Exception:
            pass

    threading.Thread(target=feed, daemon=True).start()
    hits = []
    deadline = time.time() + 2.2
    while time.time() < deadline and not hits:
        hits = spill_fds()
        time.sleep(0.05)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
    exact = wait_exact(out, payload, timeout=5)
    stop_pid(pid)
    record("disk-spill", bool(hits) and exact, f"spill_fd={hits[:2]} exact={exact} rc={proc.returncode}")


def test_socks():
    pid, _ = spawn(
        "rr-cli",
        [str(BIN), "socks", "--listen", "127.0.0.1:1080", "--server", f"{SRV}:7443", "--tcp",
         "-i", str(KEY), "--strict-host-key-checking", "accept-new", "--known-hosts", str(KNOWN),
         "--log-level", "warn"],
        T / "socks.log",
    )
    if not wait_listen("rr-cli", 1080, 8):
        record("socks5-two-streams", False, "socks listen failed: " + log_tail(T / "socks.log"))
        stop_pid(pid)
        return
    def one(path):
        return netns(
            "rr-cli",
            ["curl", "-fsS", "--max-time", "10", "--socks5", "127.0.0.1:1080", f"http://127.0.0.1:18080/{path}"],
            timeout=15,
        )
    a = one("a.txt")
    b = one("b.txt")
    # concurrent
    pa = subprocess.Popen(["ip", "netns", "exec", "rr-cli", "curl", "-fsS", "--max-time", "10", "--socks5", "127.0.0.1:1080", "http://127.0.0.1:18080/a.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pb = subprocess.Popen(["ip", "netns", "exec", "rr-cli", "curl", "-fsS", "--max-time", "10", "--socks5", "127.0.0.1:1080", "http://127.0.0.1:18080/b.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    oa, ea = pa.communicate(timeout=15)
    ob, eb = pb.communicate(timeout=15)
    stop_pid(pid)
    ok = (
        a.returncode == 0 and a.stdout == b"alpha-socks-payload\n"
        and b.returncode == 0 and b.stdout == b"beta-socks-payload\n"
        and pa.returncode == 0 and oa == b"alpha-socks-payload\n"
        and pb.returncode == 0 and ob == b"beta-socks-payload\n"
    )
    detail = f"seq={a.returncode}/{b.returncode} par={pa.returncode}/{pb.returncode}"
    if not ok:
        detail += " socks-log=" + log_tail(T / "socks.log", 15).replace("\n", " | ")
        detail += " curl=" + (ea + eb)[-200:].decode(errors="replace")
    record("socks5-two-streams", ok, detail)


def test_websocket():
    payload = (T / "payload-256k.bin").read_bytes()
    ok, detail = pipe_upload("ws", payload, ["--ws", "--server", f"{SRV}:8444"], timeout=25)
    # pipe_upload's client_argv already sets --server SRV:7443 then extra repeats --server.
    # Flag parsing: last wins? Go flag uses the last occurrence for strings. Verify.
    record("websocket-upload", ok, detail)


def test_trusted_proxy_and_reload():
    proxy_py = T / "xff_proxy.py"
    proxy_py.write_text(r'''
import socket, threading, sys
listen = sys.argv[1]
up_host, up_port = sys.argv[2].rsplit(":", 1)
def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except Exception:
        pass
    try:
        a.shutdown(socket.SHUT_RD)
    except Exception:
        pass
    try:
        b.shutdown(socket.SHUT_WR)
    except Exception:
        pass
def handle(c):
    data = b""
    c.settimeout(10)
    try:
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                c.close()
                return
            data += chunk
            if len(data) > 65536:
                break
        head, rest = data.split(b"\r\n\r\n", 1)
        if b"x-forwarded-for" not in head.lower():
            head += b"\r\nX-Forwarded-For: 198.51.100.50"
        up = socket.create_connection((up_host, int(up_port)), timeout=5)
        up.sendall(head + b"\r\n\r\n" + rest)
        c.settimeout(None)
        up.settimeout(None)
        t1 = threading.Thread(target=pipe, args=(c, up), daemon=True)
        t2 = threading.Thread(target=pipe, args=(up, c), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host, port = listen.rsplit(":", 1)
s.bind((host, int(port)))
s.listen(16)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
''')
    pid, _ = spawn("rr-cli", ["python3", str(proxy_py), "10.88.4.2:8888", f"{SRV}:8444"], T / "proxy.log")
    if not wait_listen("rr-cli", 8888, 5):
        record("trusted-proxy-ignores-xff", False, "proxy failed: " + log_tail(T / "proxy.log"))
        stop_pid(pid)
        return
    payload = b"proxy-payload-untrusted"
    off = log_len(SERVER_LOG)
    ok, detail = pipe_upload("xff-untrusted", payload, ["--ws", "--server", "10.88.4.2:8888"], timeout=20)
    fresh = log_since(SERVER_LOG, off)
    forged = "198.51.100.50" in fresh
    real = "10.88.4.2" in fresh
    record("trusted-proxy-ignores-xff", ok and real and not forged, f"transfer={ok} log_has_real={real} log_has_forged={forged} {detail}")

    # Reload: trust the proxy and try to demote log level in TOML.
    # Keep the key unrestricted so the XFF transfer is not refused by permitopen.
    pub = Path(str(KEY) + ".pub").read_text().strip()
    fields = base_server_fields()
    fields["log_level"] = "error"
    fields["trusted_proxies"] = ["10.88.4.2"]
    write_cfg(SRV_CFG, fields)
    off = log_len(SERVER_LOG)
    os.kill(SERVER_PID, signal.SIGHUP)
    time.sleep(0.4)
    reloaded = "configuration reloaded successfully" in log_since(SERVER_LOG, off)
    # CLI was --log-level debug, so an info reload line must still be emitted.
    record("cli-log-level-survives-reload", reloaded, "info reload line present" if reloaded else "reload info line missing (log level may have dropped to error): " + log_tail(SERVER_LOG, 8).replace("\n", " | "))

    off = log_len(SERVER_LOG)
    ok2, detail2 = pipe_upload("xff-trusted", b"proxy-payload-trusted", ["--ws", "--server", "10.88.4.2:8888"], timeout=20)
    fresh = log_since(SERVER_LOG, off)
    record("trusted-proxy-honors-xff", ok2 and "198.51.100.50" in fresh, f"transfer={ok2} forged_in_log={'198.51.100.50' in fresh} {detail2}")

    # permitopen allows only :2222, so the pipe dest must be rejected.
    AUTH.write_text(f'permitopen="127.0.0.1:2222" {pub}\n')
    write_cfg(SRV_CFG, fields)
    os.kill(SERVER_PID, signal.SIGHUP)
    time.sleep(0.4)
    ok3, detail3 = pipe_upload("rbac-deny", b"nope", ["--tcp"], timeout=15)
    record("rbac-permitopen-denies", (not ok3), "denied as expected" if not ok3 else "unexpectedly allowed: " + detail3)

    # SSH to the permitted dest still works.
    proxy = T / "proxy-rbac.sh"
    write_proxy(proxy, client_argv(["--tcp", "--dest", "127.0.0.1:2222"]))
    r = ssh_via(proxy, "echo RBAC_OK", timeout=15)
    record("rbac-permitopen-allows-listed", r.returncode == 0 and b"RBAC_OK" in (r.stdout or b""), (r.stdout or b"")[:80].decode(errors="replace") + (r.stderr or b"")[-200:].decode(errors="replace"))

    # Widen permitopen via another HUP.
    AUTH.write_text(pub + "\n")
    fields["log_level"] = "info"
    fields["trusted_proxies"] = []
    write_cfg(SRV_CFG, fields)
    os.kill(SERVER_PID, signal.SIGHUP)
    time.sleep(0.4)
    ok4, detail4 = pipe_upload("rbac-restored", b"restored-ok", ["--tcp"], timeout=15)
    record("rbac-sighup-restores-key", ok4, detail4)
    stop_pid(pid)


def test_fingerprint_and_plaintext_and_badkey():
    log = SERVER_LOG.read_text(errors="replace")
    fp = ""
    for line in log.splitlines():
        if "fingerprint=" in line and "SHA256:" in line:
            fp = "SHA256:" + line.split("SHA256:")[1].split()[0].strip('"')
            break
    if not fp:
        record("fingerprint-pin", False, "no fingerprint in server log")
    else:
        payload = b"fp-ok"
        ok, detail = pipe_upload("fp", payload, ["--tcp", "--server-fingerprint", fp, "--strict-host-key-checking", "yes"], timeout=15)
        record("fingerprint-pin-accept", ok, fp[:24] + "... " + detail)
        okb, detailb = pipe_upload(
            "fp-bad", b"fp-bad",
            ["--tcp", "--server-fingerprint", "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--strict-host-key-checking", "yes"],
            timeout=15,
        )
        record("fingerprint-pin-reject", not okb, "rejected" if not okb else "accepted forged pin")

    py = (
        "import socket,struct,sys\n"
        "p=b'{\"v\":1,\"destination\":\"127.0.0.1:2222\",\"transport\":[\"tcp\"],\"clientNonce\":\"clear\"}'\n"
        "s=socket.create_connection(('10.88.4.1',7443),2)\n"
        "s.sendall(struct.pack('>BI',1,len(p))+p)\n"
        "s.settimeout(2)\n"
        "try:\n"
        "    d=s.recv(64)\n"
        "except Exception as e:\n"
        "    print('REJECT', type(e).__name__); sys.exit(0)\n"
        "print(repr(d[:40]))\n"
        "# EOF or a short error/close is rejection. A multi-frame success would be longer and echo the dest.\n"
        "sys.exit(0 if (not d or b'127.0.0.1:2222' not in d) else 1)\n"
    )
    r = netns("rr-cli", ["python3", "-c", py], timeout=8)
    out = (r.stdout or b"").decode(errors="replace")
    # A cleartext hello must not be treated as a successful session. Any response should be an error frame or a close.
    record("plaintext-hello-rejected", r.returncode == 0, out.strip()[:160] or (r.stderr or b"").decode()[:160])

    argv = [
        str(BIN), "client", "--server", f"{SRV}:7443", "--dest", "127.0.0.1:19000", "--tcp",
        "-i", str(KEY_BAD), "--strict-host-key-checking", "accept-new", "--known-hosts", str(T / "known_bad"),
        "--log-level", "warn",
    ]
    out = T / "badkey.out"
    pid, _ = start_sink(out)
    wait_listen("rr-srv", 19000, 5)
    r = netns("rr-cli", argv, timeout=15, input_bytes=b"nope")
    stop_pid(pid)
    record("unknown-key-rejected", r.returncode != 0, f"exit {r.returncode}")


def test_happy_eyeballs():
    r = netns("rr-cli", ["getent", "ahosts", "relay.test"], timeout=5)
    resolved = (r.stdout or b"").decode()
    if "fd88:4::1" not in resolved or "10.88.4.1" not in resolved:
        record("happy-eyeballs-v6-blackhole", False, "name did not resolve inside netns: " + resolved.strip())
        return
    pcap = T / "he.pcap"
    if pcap.exists():
        pcap.unlink()
    dump_pid, _ = spawn("rr-cli", ["timeout", "8", "tcpdump", "-i", "veth-cs", "-n", "-c", "40", "-w", str(pcap), "tcp", "port", "7443"], T / "tcpdump.log")
    time.sleep(0.4)
    payload = b"he-ok-payload"
    # Start the sink before the clock so elapsed is the dial plus the transfer.
    out = T / "he.out"
    if out.exists():
        out.unlink()
    sink_pid, _ = start_sink(out, log_name="sink-he.log")
    if not wait_listen("rr-srv", 19000, 5):
        record("happy-eyeballs-v6-blackhole", False, "sink failed")
        stop_pid(dump_pid)
        stop_pid(sink_pid)
        return
    argv = client_argv(["--dest", "127.0.0.1:19000", "--tcp", "--server", "relay.test:7443", "--happy-eyeballs-delay", "250ms", "--log-level", "debug"])
    t0 = time.time()
    try:
        rr = netns("rr-cli", argv, timeout=8, input_bytes=payload)
    except subprocess.TimeoutExpired as e:
        rr = e
    elapsed = time.time() - t0
    ok = not isinstance(rr, subprocess.TimeoutExpired) and rr.returncode == 0 and wait_exact(out, payload, timeout=3)
    detail = f"{len(payload)} bytes exact" if ok else (getattr(rr, "stderr", b"") or b"")[-240:].decode(errors="replace")
    stop_pid(sink_pid)
    time.sleep(0.3)
    stop_pid(dump_pid)
    saw_v6 = saw_v4 = False
    td = run(["tcpdump", "-n", "-r", str(pcap)], timeout=10)
    text = (td.stdout or b"").decode(errors="replace")
    saw_v6 = "fd88:4::1" in text or "fd88:4::1.7443" in text
    saw_v4 = "10.88.4.1.7443" in text or "10.88.4.1" in text
    good = ok and elapsed < 2.0 and saw_v4 and saw_v6
    record("happy-eyeballs-v6-blackhole", good, f"elapsed={elapsed:.3f}s v6_syn={saw_v6} v4={saw_v4} transfer={ok} {detail}")


def test_hud():
    import errno
    import fcntl
    import pty
    import select
    import struct
    import termios
    import threading
    payload = (T / "payload-256k.bin").read_bytes()
    out = T / "hud.out"
    if out.exists():
        out.unlink()
    pid, _ = start_sink(out, log_name="sink-hud.log")
    if not wait_listen("rr-srv", 19000, 5):
        record("hud-reconnect-line", False, "sink failed")
        return
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "2mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    master, slave = pty.openpty()
    # A zero-size pty truncates the status line down to a few columns.
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 200, 0, 0))
    os.set_blocking(master, False)
    argv = client_argv(["--tcp", "--no-splice", "--dest", "127.0.0.1:19000", "--hud", "--log-level", "warn"])
    env = clean_env({"TERM": "xterm"})
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=slave, env=env,
    )
    os.close(slave)
    buf = bytearray()
    buf_lock = threading.Lock()

    def read_pty():
        while True:
            ready, _, _ = select.select([master], [], [], 0.2)
            if not ready:
                if proc.poll() is not None:
                    while True:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as e:
                            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                return
                            return
                        if not chunk:
                            return
                        with buf_lock:
                            buf.extend(chunk)
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                return
            if not chunk:
                return
            with buf_lock:
                buf.extend(chunk)

    reader = threading.Thread(target=read_pty, daemon=True)
    reader.start()

    def feed():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except Exception:
            pass

    threading.Thread(target=feed, daemon=True).start()
    try:
        time.sleep(0.4)
        netns("rr-cli", ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "7443", "-j", "DROP"], timeout=5)
        netns("rr-cli", ["iptables", "-A", "INPUT", "-p", "tcp", "--sport", "7443", "-j", "DROP"], timeout=5)
        netns("rr-cli", ["ss", "-K", "-t", "dst", SRV, "dport", "=", "7443"], timeout=5)
        # NotificationTimeout defaults to 5s. Hold the blackhole past that.
        time.sleep(6.2)
    finally:
        netns("rr-cli", ["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "7443", "-j", "DROP"], timeout=5)
        netns("rr-cli", ["iptables", "-D", "INPUT", "-p", "tcp", "--sport", "7443", "-j", "DROP"], timeout=5)
        netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
    time.sleep(0.4)
    try:
        os.close(master)
    except OSError:
        pass
    reader.join(timeout=2)
    exact = wait_exact(out, payload, timeout=3)
    stop_pid(pid)
    with buf_lock:
        raw = bytes(buf)
    (T / "hud-capture.bin").write_bytes(raw)
    text = raw.decode(errors="replace")
    disrupted = "Link disrupted" in text or "Reconnecting" in text
    osc = "\033]9;" in text or "777;notify" in text
    # Status line and OSC are the HUD feature. Byte exactness is resume, reported beside it.
    record(
        "hud-reconnect-line",
        disrupted and osc,
        f"disrupted={disrupted} osc={osc} exact={exact} rc={proc.returncode} capture={len(raw)}B {byte_note(out, payload)} tail={text[-240:]!r}",
    )


def test_agent():
    # Direct dial to the agent address must fail (sshd is localhost-only and INPUT drops new flows).
    probe = netns("rr-srv", ["python3", "-c",
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('10.88.3.2',2222)); sys.exit(0)\n"
        "except Exception as e:\n"
        "    print(type(e).__name__); sys.exit(1)\n"], timeout=8)
    direct_blocked = probe.returncode != 0
    pid, _ = spawn(
        "rr-agt",
        [str(BIN), "agent", "--server", f"{AGT_SRV}:7443", "--name", "homelab", "--dest", "127.0.0.1:2222",
         "--tcp", "-i", str(KEY), "--strict-host-key-checking", "accept-new", "--known-hosts", str(T / "agent_known"),
         "--heartbeat-interval", "200ms", "--log-level", "info"],
        T / "agent.log",
    )
    deadline = time.time() + 8
    registered = False
    while time.time() < deadline:
        if "agent registered target successfully" in (T / "agent.log").read_text(errors="replace"):
            registered = True
            break
        time.sleep(0.1)
    if not registered:
        record("reverse-agent", False, "agent did not register: " + log_tail(T / "agent.log"))
        stop_pid(pid)
        return
    out = T / "agent-ssh.out"
    if out.exists():
        out.unlink()
    proxy = T / "proxy-agent.sh"
    write_proxy(proxy, client_argv(["--tcp", "--target", "homelab"]))
    r = ssh_via(proxy, f"echo AGENT_OK > {out}", timeout=15)
    body = out.read_text() if out.exists() else ""
    record("reverse-agent", direct_blocked and r.returncode == 0 and "AGENT_OK" in body,
           f"direct_blocked={direct_blocked} ssh={r.returncode} body={body.strip()} {(r.stderr or b'')[-180:].decode(errors='replace')}")

    off = log_len(SERVER_LOG)
    t0 = time.time()
    netns("rr-agt", ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-agt", ["iptables", "-A", "INPUT", "-p", "tcp", "--sport", "7443", "-j", "DROP"], timeout=5)
    # Abort the live control connection so the server observes silence immediately.
    netns("rr-agt", ["ss", "-K", "-t", "dst", AGT_SRV, "dport", "=", "7443"], timeout=5)
    dropped = False
    while time.time() - t0 < 8:
        fresh = log_since(SERVER_LOG, off)
        if "agent control conn read closed" in fresh or "target" in fresh and "offline" in fresh:
            dropped = True
            break
        # Also accept the agent log losing the connection and the next client failing.
        if "agent control connection lost" in (T / "agent.log").read_text(errors="replace")[max(0, off):]:
            pass
        time.sleep(0.1)
    elapsed = time.time() - t0
    # Server idle bound is 2 * 750ms. Allow slack, but not the 30s idle timeout.
    server_log = log_since(SERVER_LOG, off)
    saw_server = "agent control conn read closed" in server_log
    record("agent-silent-control-drops", saw_server and elapsed < 4.0, f"server_closed={saw_server} in {elapsed:.2f}s")
    netns("rr-agt", ["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-agt", ["iptables", "-D", "INPUT", "-p", "tcp", "--sport", "7443", "-j", "DROP"], timeout=5)
    deadline = time.time() + 10
    back = False
    while time.time() < deadline:
        if (T / "agent.log").read_text(errors="replace").count("agent registered target successfully") >= 2:
            back = True
            break
        time.sleep(0.1)
    if back:
        r2 = ssh_via(proxy, "echo AGENT_BACK", timeout=15)
        back_ok = r2.returncode == 0 and b"AGENT_BACK" in (r2.stdout or b"")
    else:
        back_ok = False
    record("agent-reregisters-after-restore", back and back_ok, f"reregistered={back} ssh={back_ok}")
    # Leave the agent up for the jumphost-to-agent test.
    return pid


def test_jumphost(agent_up):
    fields = {
        # Bind the jumphost's own addresses. A wildcard 0.0.0.0:7443 is treated
        # as every host on that port by loop detection, so a hop to the next
        # relay would be refused as a loop back to this process.
        "listen_tcp": f"{JUMP}:7443",
        "udp_listen": f"{JUMP}:7443",
        "transports": ["tcp", "quic", "kcp"],
        "default_destination": "127.0.0.1:2222",
        "allow_destinations": ["127.0.0.1:2222"],
        "authorized_keys": str(AUTH),
        "host_key": str(JUMP_KEY),
        "auth_method": "ssh-publickey",
        "auth_fail_delay": "20ms",
        "log_level": "info",
        "log_format": "text",
        "allow_relay_hops": [],
        "max_chain_depth": 4,
        "relay_strict_host_key_checking": "no",
        "heartbeat_interval": "750ms",
        "dead_peer_threshold": 3,
        "hold_timeout": "2m",
        "idle_timeout": "30s",
        "probe_timeout": "2s",
    }
    write_cfg(JUMP_CFG, fields)
    pid, _ = spawn(
        "rr-jump",
        [str(BIN), "server", "--config", str(JUMP_CFG), "--authorized-keys", str(AUTH), "--host-key", str(JUMP_KEY), "--log-level", "info"],
        T / "jump.log",
    )
    if not wait_listen("rr-jump", 7443, 8):
        record("jumphost-default-deny", False, "jump server failed: " + log_tail(T / "jump.log"))
        return
    argv = [
        str(BIN), "client", "-J", f"{JUMP}:7443", "--server", f"{TERM}:7443", "--dest", "127.0.0.1:2222", "--tcp",
        "-i", str(KEY), "--strict-host-key-checking", "accept-new", "--known-hosts", str(T / "jump_known"),
        "--log-level", "warn",
    ]
    proxy = T / "proxy-jump-deny.sh"
    write_proxy(proxy, argv)
    r = ssh_via(proxy, "echo NO", timeout=15)
    record("jumphost-default-deny", r.returncode != 0, f"exit {r.returncode}")

    fields["allow_relay_hops"] = [f"{TERM}:7443"]
    write_cfg(JUMP_CFG, fields)
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.5)
    out = T / "jump.out"
    if out.exists():
        out.unlink()
    payload = T / "payload-256k.bin"
    proxy = T / "proxy-jump.sh"
    write_proxy(proxy, argv)
    r = ssh_via(proxy, f"cat > {out}", stdin_path=payload, timeout=25)
    ok = r.returncode == 0 and out.exists() and sha256_file(out) == sha256_file(payload)
    record("jumphost-tcp", ok, "256 KiB exact via -J" if ok else (r.stderr or b"").decode(errors="replace")[-300:])

    argv_k = [
        str(BIN), "client", "-J", f"{JUMP}:7443?transport=kcp", "--server", f"{TERM}:7443", "--dest", "127.0.0.1:2222", "--tcp",
        "-i", str(KEY), "--strict-host-key-checking", "accept-new", "--known-hosts", str(T / "jump_known"),
        "--log-level", "warn",
    ]
    outk = T / "jump-kcp.out"
    if outk.exists():
        outk.unlink()
    proxy = T / "proxy-jump-kcp.sh"
    write_proxy(proxy, argv_k)
    r = ssh_via(proxy, f"cat > {outk}", stdin_path=payload, timeout=30)
    ok = r.returncode == 0 and outk.exists() and sha256_file(outk) == sha256_file(payload)
    record("jumphost-kcp-hop", ok, "256 KiB exact" if ok else (r.stderr or b"").decode(errors="replace")[-300:])

    if agent_up:
        argv_t = [
            str(BIN), "client", "-J", f"{JUMP}:7443", "--server", f"{TERM}:7443", "--target", "homelab", "--tcp",
            "-i", str(KEY), "--strict-host-key-checking", "accept-new", "--known-hosts", str(T / "jump_known"),
            "--log-level", "warn",
        ]
        proxy = T / "proxy-jump-agent.sh"
        write_proxy(proxy, argv_t)
        r = ssh_via(proxy, "echo JUMP_AGENT", timeout=20)
        record("jumphost-to-nated-agent", r.returncode == 0 and b"JUMP_AGENT" in (r.stdout or b""),
               (r.stdout or b"")[:60].decode(errors="replace") + (r.stderr or b"")[-220:].decode(errors="replace"))
    stop_pid(pid)


def test_ssh_agent():
    global AGENT_PROC
    r = run(["ssh-agent", "-s"], timeout=10, text=True)
    if r.returncode != 0:
        record("ssh-agent-auth", False, r.stderr)
        return
    sock = None
    pid = None
    for line in r.stdout.splitlines():
        if "SSH_AUTH_SOCK=" in line:
            sock = line.split("SSH_AUTH_SOCK=")[1].split(";")[0]
        if "SSH_AGENT_PID=" in line:
            pid = int(line.split("SSH_AGENT_PID=")[1].split(";")[0])
    AGENT_PROC = pid
    env = os.environ.copy()
    env["SSH_AUTH_SOCK"] = sock
    add = run(["ssh-add", str(KEY)], timeout=10, env=env, text=True)
    if add.returncode != 0:
        record("ssh-agent-auth", False, add.stderr)
        return
    payload = b"agent-auth-ok"
    argv = [
        str(BIN), "client", "--server", f"{SRV}:7443", "--dest", "127.0.0.1:19000", "--tcp",
        "--auth-sock", sock, "--strict-host-key-checking", "accept-new", "--known-hosts", str(KNOWN),
        "--log-level", "warn",
    ]
    out = T / "agent-auth.out"
    spid, _ = start_sink(out)
    wait_listen("rr-srv", 19000, 5)
    rr = netns("rr-cli", argv, timeout=15, input_bytes=payload, env=clean_env({"SSH_AUTH_SOCK": sock}))
    stop_pid(spid)
    time.sleep(0.2)
    ok = rr.returncode == 0 and out.exists() and out.read_bytes() == payload
    record("ssh-agent-auth", ok, "signed via SSH_AUTH_SOCK without --identity" if ok else (rr.stderr or b"").decode(errors="replace")[-250:])


def _sigusr2_child(parent):
    try:
        os.remove(CHILD_PID)
    except FileNotFoundError:
        pass
    os.kill(parent, signal.SIGUSR2)
    deadline = time.time() + 5
    while time.time() < deadline:
        if CHILD_PID.exists():
            raw = CHILD_PID.read_text().strip()
            if raw and int(raw) != parent:
                return int(raw)
        time.sleep(0.05)
    return None


def test_hot_restart():
    global SERVER_PID
    import threading
    # Phase 1: metrics_listen is still bound by the parent. The child calls
    # startDebug after it acks, while the parent has not exited yet.
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "4mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    payload = (T / "payload-1m.bin").read_bytes()
    out = T / "hot-metrics.out"
    if out.exists():
        out.unlink()
    sink_pid, _ = start_sink(out, log_name="sink-hot-metrics.log")
    metrics_detail = "sink failed"
    if wait_listen("rr-srv", 19000, 5):
        argv = client_argv(["--tcp", "--no-splice", "--dest", "127.0.0.1:19000"])
        proc = subprocess.Popen(
            ["ip", "netns", "exec", "rr-cli", *argv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(),
        )

        def feed():
            try:
                proc.stdin.write(payload)
                proc.stdin.close()
            except Exception:
                pass

        threading.Thread(target=feed, daemon=True).start()
        time.sleep(0.4)
        parent = SERVER_PID
        child = None
        off = log_len(SERVER_LOG)
        try:
            child = _sigusr2_child(parent)
        except ProcessLookupError:
            child = None
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        if child:
            SERVER_PID = child
        time.sleep(0.3)
        still = wait_listen("rr-srv", 7443, 2)
        child_state = "missing"
        if child and Path(f"/proc/{child}/status").exists():
            child_state = "alive"
        fresh = log_since(SERVER_LOG, off)
        (T / "hot-metrics.log").write_text(fresh)
        bind_busy = "address already in use" in fresh
        metrics_detail = (
            f"child={child} state={child_state} listening={still} bind_busy={bind_busy} "
            f"rc={proc.returncode} tail={fresh.replace(chr(10), ' | ')[-360:]}"
        )
        # Success is the replacement process still accepting on 7443.
        record("hot-restart-with-metrics", still and child_state == "alive" and not bind_busy, metrics_detail)
    else:
        record("hot-restart-with-metrics", False, metrics_detail)
    netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    stop_pid(sink_pid)

    # Phase 2: no metrics listener, so handover is not racing a second bind.
    # WebSocket is still configured. Listen() returns before listenWS on adopt,
    # so 8444 is part of the observation.
    ok, pid = start_server(extra_fields={"metrics_listen": ""}, cli_args=["--log-level", "debug", "--no-splice"])
    if not ok:
        record("hot-restart-tcp-session", False, "metrics-free server failed: " + log_tail(SERVER_LOG))
        record("hot-restart-websocket", False, "server failed")
        record("hot-restart-socks-no-panic", False, "server failed")
        return
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "4mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    out = T / "hot.out"
    if out.exists():
        out.unlink()
    sink_pid, _ = start_sink(out, log_name="sink-hot.log")
    if not wait_listen("rr-srv", 19000, 5):
        record("hot-restart-tcp-session", False, "sink failed")
        record("hot-restart-websocket", False, "sink failed")
        record("hot-restart-socks-no-panic", False, "sink failed")
        netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
        return
    argv = client_argv(["--tcp", "--no-splice", "--dest", "127.0.0.1:19000"])
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(),
    )

    def feed2():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except Exception:
            pass

    threading.Thread(target=feed2, daemon=True).start()
    time.sleep(0.4)
    parent = SERVER_PID
    child = _sigusr2_child(parent)
    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
    netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    exact_bytes = wait_exact(out, payload, timeout=5)
    stop_pid(sink_pid)
    if child:
        SERVER_PID = child
    log = SERVER_LOG.read_text(errors="replace")
    panic = "panic:" in log.lower() or "nil pointer" in log.lower()
    exact = exact_bytes and proc.returncode == 0
    still = wait_listen("rr-srv", 7443, 3)
    ws_up = listening("rr-srv", 8444)
    child_state = "missing"
    if child and Path(f"/proc/{child}/status").exists():
        child_state = "alive"
    shutil.copy(SERVER_LOG, T / "hot-server.log")
    tail = log_tail(SERVER_LOG, 12).replace("\n", " | ")
    record(
        "hot-restart-tcp-session",
        exact and still and child_state == "alive" and not panic,
        f"child={child} state={child_state} exact={exact} listening={still} rc={proc.returncode} "
        f"panic={panic} {byte_note(out, payload)} log={tail[-400:]}",
    )
    record("hot-restart-websocket", ws_up, f"8444_listening={ws_up} after SIGUSR2 (listen_ws was configured)")

    # Active SOCKS session must not crash the child on a second handover.
    socks_pid, _ = spawn(
        "rr-cli",
        [str(BIN), "socks", "--listen", "127.0.0.1:1080", "--server", f"{SRV}:7443", "--tcp",
         "-i", str(KEY), "--strict-host-key-checking", "yes", "--known-hosts", str(KNOWN), "--log-level", "warn"],
        T / "socks-hot.log",
    )
    if not wait_listen("rr-cli", 1080, 8):
        record("hot-restart-socks-no-panic", False, "socks failed to start: " + log_tail(T / "socks-hot.log"))
        stop_pid(socks_pid)
        return
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "2mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    curl = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", "curl", "-fsS", "--max-time", "20", "--socks5", "127.0.0.1:1080", "http://127.0.0.1:18080/big.bin", "-o", str(T / "socks-hot.bin")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    time.sleep(0.5)
    off = log_len(SERVER_LOG)
    try:
        os.remove(CHILD_PID)
    except FileNotFoundError:
        pass
    parent = SERVER_PID
    try:
        os.kill(parent, signal.SIGUSR2)
    except ProcessLookupError:
        record("hot-restart-socks-no-panic", False, "server pid gone before second restart")
        curl.kill()
        stop_pid(socks_pid)
        return
    time.sleep(0.4)
    try:
        curl.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        curl.kill()
    netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    stop_pid(socks_pid)
    fresh = log_since(SERVER_LOG, off).lower()
    panic = "panic:" in fresh or "nil pointer" in fresh
    child = None
    if CHILD_PID.exists():
        raw = CHILD_PID.read_text().strip()
        if raw:
            child = int(raw)
            SERVER_PID = child
    still = wait_listen("rr-srv", 7443, 3)
    # A new TCP upload must work on the replacement process.
    ok, detail = pipe_upload("after-hot", b"after-hot-restart", ["--tcp"], timeout=15)
    record("hot-restart-socks-no-panic", still and not panic and ok, f"listening={still} panic={panic} new_transfer={ok} {detail}")


def test_bfd_and_ha_and_loss():
    global SERVER_PID
    stop_pid(SERVER_PID)
    SERVER_PID = None
    # Also stop anything still bound in rr-srv relay-wise; port must be free.
    time.sleep(0.3)
    ok, pid = start_server(
        {"heartbeat_interval": "200ms", "dead_peer_threshold": 3, "idle_timeout": "30s"},
        ["--log-level", "info", "--heartbeat-interval", "200ms", "--dead-peer-threshold", "3"],
    )
    if not ok:
        record("bfd-udp-blackhole", False, "fast server failed: " + log_tail(SERVER_LOG))
        return
    # Detection without HA: UDP drop must fail the KCP client well under the 30s idle timeout.
    payload = os.urandom(64 * 1024)
    out = T / "bfd.out"
    spid, _ = start_sink(out)
    if not wait_listen("rr-srv", 19000, 5):
        record("bfd-udp-blackhole", False, "sink failed")
        return
    argv = client_argv(["--kcp", "--dest", "127.0.0.1:19000", "--heartbeat-interval", "200ms", "--dead-peer-threshold", "3", "--log-level", "info"])
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(),
    )
    try:
        proc.stdin.write(payload)
        proc.stdin.flush()
    except Exception:
        pass
    time.sleep(1.0)
    off = log_len(SERVER_LOG)
    netns("rr-cli", ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-cli", ["iptables", "-A", "INPUT", "-p", "udp", "--sport", "7443", "-j", "DROP"], timeout=5)
    t0 = time.time()
    detected = None
    while time.time() - t0 < 15:
        if detected is None and "dead-peer" in log_since(SERVER_LOG, off):
            detected = time.time() - t0
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    elapsed = time.time() - t0
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=3)
    err = b""
    if proc.stderr:
        try:
            err = proc.stderr.read()
        except Exception:
            pass
    netns("rr-cli", ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-cli", ["iptables", "-D", "INPUT", "-p", "udp", "--sport", "7443", "-j", "DROP"], timeout=5)
    stop_pid(spid)
    record(
        "bfd-dead-peer-detected",
        detected is not None and detected < 2.5,
        f"server_log_s={detected} window=2.5s (3x200ms) tail={log_since(SERVER_LOG, off)[-240:].replace(chr(10), ' | ')}",
    )
    err_txt = err.decode(errors="replace")
    kex_fail = "host key" in err_txt or "REMOTE HOST" in err_txt
    # A handshake rejection is not dead-peer detection. The client must have
    # been in a session, then exited because the UDP path died, inside the
    # detection window rather than the 30s idle timeout.
    record(
        "bfd-without-ha-aborts",
        (not kex_fail) and proc.returncode not in (0, None) and elapsed < 12,
        f"rc={proc.returncode} exit_s={elapsed:.2f} kex_fail={kex_fail} stderr={err_txt[-220:]}",
    )

    # HA: same blackhole, transfer must finish via the TCP standby.
    netns("rr-cli", ["tc", "qdisc", "replace", "dev", "veth-cs", "root", "tbf", "rate", "3mbit", "burst", "20kb", "latency", "50ms"], timeout=10)
    payload = (T / "payload-1m.bin").read_bytes()
    out = T / "ha.out"
    if out.exists():
        out.unlink()
    spid, _ = start_sink(out)
    argv = client_argv(["--kcp", "--allow-ha", "--dest", "127.0.0.1:19000", "--heartbeat-interval", "200ms", "--dead-peer-threshold", "3", "--log-level", "info"])
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "rr-cli", *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(),
    )
    import threading

    def feed():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except Exception:
            pass

    threading.Thread(target=feed, daemon=True).start()
    time.sleep(1.0)
    netns("rr-cli", ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-cli", ["iptables", "-A", "INPUT", "-p", "udp", "--sport", "7443", "-j", "DROP"], timeout=5)
    t0 = time.time()
    try:
        proc.wait(timeout=25)
        elapsed = time.time() - t0
    except subprocess.TimeoutExpired:
        proc.kill()
        elapsed = time.time() - t0
    netns("rr-cli", ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-cli", ["iptables", "-D", "INPUT", "-p", "udp", "--sport", "7443", "-j", "DROP"], timeout=5)
    netns("rr-cli", ["tc", "qdisc", "del", "dev", "veth-cs", "root"], timeout=5)
    exact = wait_exact(out, payload, timeout=5)
    stop_pid(spid)
    ha_err = b""
    if proc.stderr:
        try:
            ha_err = proc.stderr.read()
        except Exception:
            pass
    promoted = "standby connection promoted" in SERVER_LOG.read_text(errors="replace") or b"standby connection promoted" in ha_err
    record("ha-failover-kcp-to-tcp", exact and proc.returncode == 0 and elapsed < 20,
           f"exact={exact} rc={proc.returncode} elapsed={elapsed:.2f}s promoted_log={promoted} stderr={ha_err[-180:].decode(errors='replace')}")

    # Two live KCP sessions at once: 8% loss on rr-loss, clean path from rr-cli.
    # Tuner state is not exported; byte-exact completion of both is the check.
    def kcp_from(ns, label, server, port):
        payload_b = os.urandom(128 * 1024)
        outp = T / f"{label}.out"
        if outp.exists():
            outp.unlink()
        sp, _ = start_sink(outp, port=port, log_name=f"sink-{label}.log")
        if not wait_listen("rr-srv", port, 5):
            stop_pid(sp)
            return False, "sink failed"
        argv = [
            str(BIN), "client", "--server", f"{server}:7443", "--dest", f"127.0.0.1:{port}", "--kcp",
            "--adaptive-kcp", "-i", str(KEY), "--strict-host-key-checking", "accept-new",
            "--known-hosts", str(KNOWN), "--log-level", "warn",
            "--heartbeat-interval", "200ms",
        ]
        try:
            r = netns(ns, argv, timeout=40, input_bytes=payload_b)
        except subprocess.TimeoutExpired:
            stop_pid(sp)
            return False, "timeout"
        ok = r.returncode == 0 and wait_exact(outp, payload_b, timeout=5)
        stop_pid(sp)
        return ok, f"rc={r.returncode} {(r.stderr or b'')[-160:].decode(errors='replace')}"

    import threading
    box = {}

    def run_one(ns, label, server, port):
        box[label] = kcp_from(ns, label, server, port)

    t1 = threading.Thread(target=run_one, args=("rr-cli", "kcp-clean", SRV, 19000))
    t2 = threading.Thread(target=run_one, args=("rr-loss", "kcp-lossy", LOSS_SRV, 19001))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    lok, ldetail = box.get("kcp-lossy", (False, "missing"))
    cok, cdetail = box.get("kcp-clean", (False, "missing"))
    record("kcp-lossy-and-clean-isolated", lok and cok, f"simultaneous lossy={lok} {ldetail} clean={cok} {cdetail}")


def test_host_clean():
    cleanup()
    after = host_snapshot()
    diffs = snapshot_diff(HOST_BEFORE, after)
    record("host-stack-restored", not diffs, "identical to pre-test snapshot" if not diffs else "changed: " + ", ".join(diffs))
    if diffs:
        for k in diffs:
            say(f"--- diff {k} (first 20 mismatched lines) ---")
            a = HOST_BEFORE[k].splitlines()
            b = after[k].splitlines()
            import difflib
            for line in difflib.unified_diff(a, b, lineterm="", n=1):
                say(line)
                if line.startswith("+") or line.startswith("-"):
                    pass


def main():
    try:
        if not setup():
            return 1
        ok, pid = start_server(cli_args=["--log-level", "debug", "--splice"])
        if not ok:
            record("server-start", False, log_tail(SERVER_LOG))
            return 1
        record("server-start", True, f"pid {pid} tcp/ws listening")
        test_tcp_ssh()
        test_quic_and_kcp()
        test_metrics_and_splice()
        test_resume()
        test_spill()
        test_socks()
        test_websocket()
        test_trusted_proxy_and_reload()
        test_fingerprint_and_plaintext_and_badkey()
        test_happy_eyeballs()
        test_hud()
        test_ssh_agent()
        agent_pid = test_agent()
        test_jumphost(bool(agent_pid))
        if agent_pid:
            stop_pid(agent_pid)
        test_hot_restart()
        test_bfd_and_ha_and_loss()
    except Exception as e:
        import traceback
        record("harness-exception", False, f"{e}\n{traceback.format_exc()[-800:]}")
    finally:
        if HOST_BEFORE is not None and not any(r.startswith("[PASS] host-stack-restored") or r.startswith("[FAIL] host-stack-restored") for r in RESULTS):
            try:
                test_host_clean()
            except Exception as e:
                record("host-stack-restored", False, str(e))
        else:
            cleanup()
    say("\n==== summary ====")
    for line in RESULTS:
        say(line)
    say(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


def _on_term(sig, _frame):
    try:
        cleanup()
    finally:
        os._exit(128 + sig)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    sys.exit(main())
