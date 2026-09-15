#!/usr/bin/env python3
"""
Performance & Benchmark Verification Script for FEAT-PERF-01
Linux Kernel Zero-Copy Stream Splicing (splice(2))

Measures throughput and CPU utilization with and without splice(2)
during high-throughput iperf3 stream transfers through remote-relay.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

DIR = Path("/tmp/relay-perf-splice")
BIN = DIR / "relay-bin"
HOST_KEY = DIR / "relay_host_ed25519"
SRV_TOML = DIR / "srv.toml"
CLI_TOML = DIR / "cli.toml"

DEST_PORT = 15201
RELAY_PORT = 17443
SOCAT_PORT = 15202
EXPVAR_PORT = 19090

CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])

def log(msg):
    print(f"[*] {msg}", flush=True)

def cleanup():
    subprocess.run(["pkill", "-9", "-f", str(BIN)], check=False)
    subprocess.run(["pkill", "-9", "-f", "iperf3.*15201"], check=False)
    subprocess.run(["pkill", "-9", "-f", "socat.*15202"], check=False)
    time.sleep(0.3)

def read_proc_stat(pid):
    """Returns (utime_ticks, stime_ticks) for a process."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
            # utime is 14th (idx 13), stime is 15th (idx 14)
            return int(parts[13]), int(parts[14])
    except Exception:
        return 0, 0

def get_expvar():
    try:
        with urlopen(f"http://127.0.0.1:{EXPVAR_PORT}/debug/vars", timeout=2) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}

def run_bench(splice_enabled, duration=5, reverse=False):
    cleanup()
    mode_name = "SPLICE (zero-copy)" if splice_enabled else "NO-SPLICE (copy fallback)"
    log(f"--- Starting Benchmark Run: {mode_name} (duration={duration}s, reverse={reverse}) ---")

    # Start iperf3 server
    iperf_srv = subprocess.Popen(
        ["iperf3", "-s", "-p", str(DEST_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.3)

    # Server config
    SRV_TOML.write_text(f"""
listen_tcp = "127.0.0.1:{RELAY_PORT}"
default_destination = "127.0.0.1:{DEST_PORT}"
allow_destinations = ["127.0.0.1:{DEST_PORT}", "*"]
transports = ["tcp"]
host_key = "{HOST_KEY}"
log_level = "error"
splice = {str(splice_enabled).lower()}
expvar_listen = "127.0.0.1:{EXPVAR_PORT}"
""")

    # Client config
    CLI_TOML.write_text(f"""
server = "127.0.0.1:{RELAY_PORT}"
destination = "127.0.0.1:{DEST_PORT}"
transport = "tcp"
known_hosts = "/dev/null"
strict_host_key_checking = "no"
log_level = "error"
splice = {str(splice_enabled).lower()}
""")

    # Launch relay server
    srv_proc = subprocess.Popen(
        [str(BIN), "server", "--config", str(SRV_TOML)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)

    # Launch socat bridge executing relay client
    socat_cmd = f"socat TCP-LISTEN:{SOCAT_PORT},reuseaddr,fork SYSTEM:'{BIN} client --config {CLI_TOML}'"
    socat_proc = subprocess.Popen(
        socat_cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    time.sleep(0.5)

    # Record initial CPU stats for server
    u0, s0 = read_proc_stat(srv_proc.pid)
    t0 = time.monotonic()

    # Run iperf3 client
    iperf_args = [
        "iperf3", "-c", "127.0.0.1", "-p", str(SOCAT_PORT),
        "-t", str(duration), "-J"
    ]
    if reverse:
        iperf_args.append("-R")

    iperf_run = subprocess.run(iperf_args, capture_output=True, text=True)
    t1 = time.monotonic()

    # Record final CPU stats
    u1, s1 = read_proc_stat(srv_proc.pid)
    elapsed = max(t1 - t0, 0.001)

    # Calculate CPU utilization
    cpu_ticks = (u1 - u0) + (s1 - s0)
    cpu_seconds = cpu_ticks / CLK_TCK
    cpu_util = (cpu_seconds / elapsed) * 100.0

    # Retrieve expvar stats
    expvars = get_expvar()
    spliced_in = expvars.get("spliced_bytes_in", 0)
    spliced_out = expvars.get("spliced_bytes_out", 0)
    splice_calls = expvars.get("splice_calls_total", 0)

    # Parse iperf3 JSON results
    throughput_gbps = 0.0
    bytes_sent = 0
    try:
        data = json.loads(iperf_run.stdout)
        if "sum_received" in data.get("end", {}):
            bits_per_second = data["end"]["sum_received"]["bits_per_second"]
            throughput_gbps = bits_per_second / 1e9
        elif "sum_sent" in data.get("end", {}):
            bits_per_second = data["end"]["sum_sent"]["bits_per_second"]
            throughput_gbps = bits_per_second / 1e9
        if "sum_sent" in data.get("end", {}):
            bytes_sent = data["end"]["sum_sent"]["bytes"]
        elif "sum_received" in data.get("end", {}):
            bytes_sent = data["end"]["sum_received"]["bytes"]
    except Exception as e:
        log(f"Warning parsing iperf output: {e}\nstdout: {iperf_run.stdout[:200]}\nstderr: {iperf_run.stderr[:200]}")

    # Clean up processes for this run
    try:
        os.killpg(os.getpgid(socat_proc.pid), signal.SIGTERM)
    except Exception:
        pass
    srv_proc.terminate()
    iperf_srv.terminate()
    cleanup()

    result = {
        "mode": mode_name,
        "splice": splice_enabled,
        "reverse": reverse,
        "throughput_gbps": throughput_gbps,
        "bytes_sent_mb": bytes_sent / (1024 * 1024),
        "cpu_seconds": cpu_seconds,
        "cpu_util_pct": cpu_util,
        "spliced_in_mb": spliced_in / (1024 * 1024),
        "spliced_out_mb": spliced_out / (1024 * 1024),
        "splice_calls": splice_calls,
    }

    log(f"Results for {mode_name}:")
    log(f"  Throughput:      {throughput_gbps:.2f} Gbit/s")
    log(f"  Transferred:     {result['bytes_sent_mb']:.1f} MB")
    log(f"  Server CPU:      {cpu_seconds:.2f}s ({cpu_util:.1f}% core utilization)")
    log(f"  Spliced In/Out:  {result['spliced_in_mb']:.1f} MB in, {result['spliced_out_mb']:.1f} MB out ({splice_calls} calls)")

    return result

def main():
    if sys.platform != "linux":
        print("This benchmark requires Linux with splice(2) support.")
        sys.exit(0)

    if not shutil.which("iperf3"):
        print("iperf3 is required but not installed.")
        sys.exit(1)

    if not shutil.which("socat"):
        print("socat is required but not installed.")
        sys.exit(1)

    DIR.mkdir(parents=True, exist_ok=True)
    cleanup()

    log("Building relay binary...")
    subprocess.run(["go", "build", "-o", str(BIN), "./cmd/relay"], check=True)

    log("Generating test host key...")
    if HOST_KEY.exists():
        HOST_KEY.unlink()
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(HOST_KEY)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
    )

    # Run benchmarks
    bench_duration = 4

    log("\n=======================================================")
    log("BENCHMARK 1: Standard User-Space Buffers (--no-splice)")
    log("=======================================================")
    res_nosplice = run_bench(splice_enabled=False, duration=bench_duration)

    log("\n=======================================================")
    log("BENCHMARK 2: Linux Kernel Zero-Copy Stream Splicing (--splice)")
    log("=======================================================")
    res_splice = run_bench(splice_enabled=True, duration=bench_duration)

    log("\n=======================================================")
    log("BENCHMARK 3: Bidirectional Reverse / Download Mode (--splice -R)")
    log("=======================================================")
    res_splice_rev = run_bench(splice_enabled=True, duration=bench_duration, reverse=True)

    # Compute CPU reduction
    cpu_no = max(res_nosplice["cpu_util_pct"], 0.01)
    cpu_sp = res_splice["cpu_util_pct"]
    cpu_reduction = ((cpu_no - cpu_sp) / cpu_no) * 100.0

    print("\n" + "=" * 68)
    print("           FEAT-PERF-01 BENCHMARK VERIFICATION REPORT")
    print("=" * 68)
    print(f"{'Metric':<28} | {'No-Splice (Copy)':<16} | {'Splice (Zero-Copy)':<16}")
    print("-" * 68)
    print(f"{'Throughput':<28} | {res_nosplice['throughput_gbps']:>10.2f} Gbps | {res_splice['throughput_gbps']:>10.2f} Gbps")
    print(f"{'Data Transferred':<28} | {res_nosplice['bytes_sent_mb']:>10.1f} MB   | {res_splice['bytes_sent_mb']:>10.1f} MB")
    print(f"{'Server CPU Time':<28} | {res_nosplice['cpu_seconds']:>10.2f} s    | {res_splice['cpu_seconds']:>10.2f} s")
    print(f"{'Server Core Utilization':<28} | {res_nosplice['cpu_util_pct']:>10.1f} %    | {res_splice['cpu_util_pct']:>10.1f} %")
    print(f"{'Spliced Kernel Bytes':<28} | {res_nosplice['spliced_in_mb']:>10.1f} MB   | {res_splice['spliced_in_mb']:>10.1f} MB")
    print(f"{'Splice Syscalls':<28} | {res_nosplice['splice_calls']:>10d}      | {res_splice['splice_calls']:>10d}")
    print("-" * 68)
    print(f"{'CPU Core Utilization Reduction:':<40} {cpu_reduction:>+6.1f} %")
    print(f"{'Reverse Mode (Downstream):':<40} {res_splice_rev['throughput_gbps']:>6.2f} Gbps ({res_splice_rev['bytes_sent_mb']:.1f} MB)")
    print("=" * 68)

    # Verification checks
    assert res_nosplice["splice_calls"] == 0, "No-splice mode should have 0 splice syscalls"
    assert res_splice["splice_calls"] > 0, "Splice mode should execute splice syscalls"
    assert res_splice["spliced_in_mb"] > 100.0, "Splice mode should transfer > 100MB via splice"
    assert res_splice_rev["throughput_gbps"] > 1.0, "Reverse splice mode should achieve > 1.0 Gbps"

    log("Zero-copy stream splicing verification PASSED successfully!")

if __name__ == "__main__":
    main()
