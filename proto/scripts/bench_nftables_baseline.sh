#!/usr/bin/env bash
# bench_nftables_baseline.sh -- nftables cgroup-match baseline comparison.
# Compares ProcRoute (eBPF cgroup/connect4 hooks) against an equivalent
# nftables ruleset using cgroup v2 socket matching for per-app destination
# filtering.
# IMPORTANT: Uses only 10.0.0.0/8 and 172.16.0.0/12 as internal prefixes
# (NOT 192.168.0.0/16) to avoid blocking SSH to the VM itself.
# Usage: sudo ./scripts/bench_nftables_baseline.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${PROTO_DIR}/../results"
BIN="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/benchmark.yaml"
PROCROUTE_CG="/sys/fs/cgroup/procroute"
LISTENER_CPU="${LISTENER_CPU:-0}"
CLIENT_CPU="${CLIENT_CPU:-1}"

COUNT=5000
WARMUP=200
EXT_PORT=18080
INT_ALLOW_IP="10.1.2.3"
INT_ALLOW_PORT=443
INT_DENY_IP="10.255.255.1"
INT_DENY_PORT=80

mkdir -p "$RESULTS_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

# cleanup
cleanup_all() {
    fuser -k ${EXT_PORT}/tcp 2>/dev/null || true
    fuser -k ${INT_ALLOW_PORT}/tcp 2>/dev/null || true
    nft flush ruleset 2>/dev/null || true
    echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
}
trap cleanup_all EXIT

# Ensure loopback aliases (must be before listeners)
for addr in 10.1.2.3 10.250.0.5 10.0.2.10; do
    ip addr show lo | grep -q "$addr" || ip addr add ${addr}/32 dev lo
done
echo "Loopback aliases configured"

# Kill stale listeners
fuser -k ${EXT_PORT}/tcp 2>/dev/null || true
fuser -k ${INT_ALLOW_PORT}/tcp 2>/dev/null || true
sleep 0.3

# start TCP listeners
start_listener() {
    taskset -c "$LISTENER_CPU" python3 -c "
import socket, sys, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$1', $2))
s.listen(128)
if os.fork() == 0:
    while True:
        c, _ = s.accept(); c.close()
    sys.exit(0)
"
}

start_listener "127.0.0.1" "${EXT_PORT}"
start_listener "${INT_ALLOW_IP}" "${INT_ALLOW_PORT}"
sleep 0.3
echo "Listeners started on 127.0.0.1:${EXT_PORT} and ${INT_ALLOW_IP}:${INT_ALLOW_PORT}"

# Stop ProcRoute daemon
echo "--- Stopping ProcRoute daemon ---"
pkill -f "procroute daemon" 2>/dev/null || true
sleep 2

# Create cgroups for nftables matching
echo "--- Creating cgroups ---"
mkdir -p "${PROCROUTE_CG}"
for app in corp-browser vpn-client ssh-client corp-ide internal-dns; do
    mkdir -p "${PROCROUTE_CG}/${app}"
done
echo "Cgroups ready"

# PHASE A: nftables baseline
echo ""
echo "=== PHASE A: nftables cgroup-match baseline ==="

# Write nftables ruleset to a file (avoids heredoc-over-SSH issues)
# NOTE: Only 10.0.0.0/8 and 172.16.0.0/12 -- excludes 192.168.0.0/16
# to avoid blocking SSH connectivity to this VM.
NFT_FILE="/tmp/procroute_nft_baseline.nft"
cat > "$NFT_FILE" <<'NFTRULES'
flush ruleset

table inet procroute_baseline {
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow established/related (avoids re-evaluating every packet)
        ct state established,related accept

        # External destinations: always allow (skip internal check)
        ip daddr != { 10.0.0.0/8, 172.16.0.0/12 } accept

        # Per-app allow rules for internal destinations (new connections only):

        # corp-browser: TCP/443 to 10.0.0.0/8
        socket cgroupv2 level 2 "procroute/corp-browser" ip daddr 10.0.0.0/8 tcp dport 443 accept

        # vpn-client: all to all internal prefixes
        socket cgroupv2 level 2 "procroute/vpn-client" accept

        # ssh-client: TCP/22 to 10.250.0.0/16
        socket cgroupv2 level 2 "procroute/ssh-client" ip daddr 10.250.0.0/16 tcp dport 22 accept

        # corp-ide: TCP/443 to 10.0.0.0/8, TCP/8000-8099 to 10.100.0.0/16
        socket cgroupv2 level 2 "procroute/corp-ide" ip daddr 10.0.0.0/8 tcp dport 443 accept
        socket cgroupv2 level 2 "procroute/corp-ide" ip daddr 10.100.0.0/16 tcp dport 8000-8099 accept

        # internal-dns: UDP/53 to specific VIPs
        socket cgroupv2 level 2 "procroute/internal-dns" ip daddr { 10.0.0.53, 10.0.1.53 } udp dport 53 accept

        # Default-deny: drop all other internal traffic
        ip daddr { 10.0.0.0/8, 172.16.0.0/12 } log prefix "nft-deny: " counter drop
    }
}
NFTRULES

echo "--- Installing nftables rules ---"
nft -f "$NFT_FILE"
echo "nftables rules loaded:"
nft list chain inet procroute_baseline output | head -20

# nftables connect-latency benchmark
echo ""
echo "--- nftables latency benchmark (${COUNT} iters x 4 conditions) ---"

BENCH_SCRIPT="/tmp/bench_latency.py"
cat > "$BENCH_SCRIPT" <<'PYEOF'
import socket, sys, time

condition = sys.argv[1]
host      = sys.argv[2]
port      = int(sys.argv[3])
count     = int(sys.argv[4])
warmup    = int(sys.argv[5])
timeout_s = float(sys.argv[6]) if len(sys.argv) > 6 else 1.0
# timeout_s <= 0 means blocking socket (for BPF deny which returns EPERM
# synchronously; settimeout() uses non-blocking I/O which can swallow EPERM)
use_blocking = timeout_s <= 0

for _ in range(warmup):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not use_blocking:
        s.settimeout(timeout_s)
    try:    s.connect((host, port))
    except OSError: pass
    finally: s.close()

latencies = []
for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not use_blocking:
        s.settimeout(timeout_s)
    t0 = time.perf_counter_ns()
    try:    s.connect((host, port))
    except OSError: pass
    finally:
        t1 = time.perf_counter_ns()
        s.close()
    lat = t1 - t0
    latencies.append(lat)
    print(f"{condition},{i},{lat}")

latencies.sort()
n = len(latencies)
if n > 0:
    p50  = latencies[n // 2]
    p90  = latencies[int(n * 0.90)]
    p95  = latencies[int(n * 0.95)]
    p99  = latencies[int(n * 0.99)]
    p999 = latencies[min(int(n * 0.999), n - 1)]
    for stat, val in [("p50", p50), ("p90", p90), ("p95", p95),
                      ("p99", p99), ("p999", p999)]:
        print(f"{condition},{stat},{int(val)}")
    sys.stderr.write(f"# {condition}: p50={p50}ns p90={p90}ns p95={p95}ns p99={p99}ns\n")
PYEOF

NFT_OUT="${RESULTS_DIR}/nft_latency.csv"
echo "condition,iteration,latency_ns" > "$NFT_OUT"

# A. baseline -- outside procroute cgroup, external dest
echo "  [1/4] baseline" >&2
echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" baseline 127.0.0.1 "$EXT_PORT" "$COUNT" "$WARMUP" >> "$NFT_OUT"

# B. nft_ext_miss -- corp-browser cgroup, external dest (first rule accepts)
echo "  [2/4] nft_ext_miss" >&2
echo $$ > "${PROCROUTE_CG}/corp-browser/cgroup.procs"
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" nft_ext_miss 127.0.0.1 "$EXT_PORT" "$COUNT" "$WARMUP" >> "$NFT_OUT"

# C. nft_int_allow -- corp-browser cgroup, 10.1.2.3:443 (allow rule matches)
echo "  [3/4] nft_int_allow" >&2
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" nft_int_allow "$INT_ALLOW_IP" "$INT_ALLOW_PORT" "$COUNT" "$WARMUP" >> "$NFT_OUT"

# D. nft_int_deny -- procroute parent cgroup, no app match -> drop
echo "  [4/4] nft_int_deny" >&2
echo $$ > "${PROCROUTE_CG}/cgroup.procs"
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" nft_int_deny "$INT_DENY_IP" "$INT_DENY_PORT" "$COUNT" "$WARMUP" 0.005 >> "$NFT_OUT"

echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
echo "nftables latency -> $NFT_OUT"

# nftables pivot prevention
echo ""
echo "--- nftables pivot prevention test ---"

PIVOT_FILE="${RESULTS_DIR}/nftables_pivot_block.csv"
echo "service,target,port,proto,result" > "$PIVOT_FILE"
BLOCKED=0
TOTAL=0

echo $$ > "${PROCROUTE_CG}/cgroup.procs"

pivot() {
    local svc="$1" tgt="$2" port="$3" proto="$4"
    TOTAL=$((TOTAL + 1))
    if [[ "$proto" == "tcp" ]]; then
        if timeout 1 bash -c "echo > /dev/tcp/${tgt}/${port}" 2>/dev/null; then
            echo "${svc},${tgt},${port},${proto},ALLOWED" >> "$PIVOT_FILE"
        else
            BLOCKED=$((BLOCKED + 1))
            echo "${svc},${tgt},${port},${proto},BLOCKED" >> "$PIVOT_FILE"
        fi
    else
        if python3 -c "
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.5)
try: s.sendto(b'x',('${tgt}',${port})); sys.exit(0)
except: sys.exit(1)
finally: s.close()
" 2>/dev/null; then
            echo "${svc},${tgt},${port},${proto},ALLOWED" >> "$PIVOT_FILE"
        else
            BLOCKED=$((BLOCKED + 1))
            echo "${svc},${tgt},${port},${proto},BLOCKED" >> "$PIVOT_FILE"
        fi
    fi
}

for i in $(seq 1 10); do pivot SSH 10.0.0.$i 22 tcp; done
for i in $(seq 1 10); do pivot SSH 10.250.0.$i 22 tcp; done
for i in $(seq 11 20); do pivot SSH 10.0.0.$i 22 tcp; done
for i in $(seq 1 10); do pivot HTTPS 10.0.0.$i 443 tcp; done
for i in $(seq 11 20); do pivot HTTPS 10.0.0.$i 443 tcp; done
for i in $(seq 1 10); do pivot RDP 10.0.0.$i 3389 tcp; done
for i in $(seq 1 5); do pivot PostgreSQL 10.0.0.$i 5432 tcp; done
for i in $(seq 1 5); do pivot PostgreSQL 10.0.1.$i 5432 tcp; done
for i in $(seq 1 5); do pivot Alt-HTTP 10.0.0.$i 8080 tcp; done
for i in $(seq 6 10); do pivot Alt-HTTP 10.0.0.$i 8080 tcp; done
pivot DNS 10.0.0.100 53 udp
pivot DNS 10.0.1.100 53 udp

echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
echo "Pivot test: ${BLOCKED}/${TOTAL} blocked -> $PIVOT_FILE"

# nftables reload latency
echo ""
echo "--- nftables reload latency (10 trials) ---"

RELOAD_FILE="${RESULTS_DIR}/nftables_reload_latency.csv"
RELOAD_SCRIPT="/tmp/nft_reload_bench.py"
cat > "$RELOAD_SCRIPT" <<'RPYEOF'
import subprocess, time, sys
nft_file = sys.argv[1]
trials = int(sys.argv[2])
print("trial,reload_ms")
for t in range(trials):
    subprocess.run(["nft", "flush", "ruleset"], check=True, capture_output=True)
    t0 = time.perf_counter_ns()
    subprocess.run(["nft", "-f", nft_file], check=True, capture_output=True)
    t1 = time.perf_counter_ns()
    ms = (t1 - t0) / 1e6
    print(f"{t},{ms:.3f}")
    sys.stderr.write(f"  reload trial {t}: {ms:.3f} ms\n")
RPYEOF

python3 "$RELOAD_SCRIPT" "$NFT_FILE" 10 > "$RELOAD_FILE"
echo "Reload latency -> $RELOAD_FILE"

# Tear down nftables
nft flush ruleset
echo "nftables rules removed"

# PHASE B: ProcRoute eBPF head-to-head
echo ""
echo "=== PHASE B: ProcRoute eBPF head-to-head ==="

echo "--- Starting ProcRoute daemon ---"
"$BIN" daemon --policy "$POLICY" > /dev/null 2>/tmp/procroute-bench.log &
DAEMON_PID=$!
sleep 3

if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "error: daemon failed to start" >&2
    cat /tmp/procroute-bench.log >&2
    exit 1
fi
echo "Daemon running (pid $DAEMON_PID)"

# Kill stale listeners and restart them
fuser -k ${EXT_PORT}/tcp 2>/dev/null || true
fuser -k ${INT_ALLOW_PORT}/tcp 2>/dev/null || true
sleep 0.3
start_listener "127.0.0.1" "${EXT_PORT}"
start_listener "${INT_ALLOW_IP}" "${INT_ALLOW_PORT}"
sleep 0.3

BPF_OUT="${RESULTS_DIR}/bpf_latency.csv"
echo "condition,iteration,latency_ns" > "$BPF_OUT"

echo "--- ProcRoute latency benchmark (${COUNT} iters x 4 conditions) ---"

# A. baseline
echo "  [1/4] baseline" >&2
echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" baseline 127.0.0.1 "$EXT_PORT" "$COUNT" "$WARMUP" >> "$BPF_OUT"

# B. bpf_ext_miss
echo "  [2/4] bpf_ext_miss" >&2
echo $$ > "${PROCROUTE_CG}/corp-browser/cgroup.procs"
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" bpf_ext_miss 127.0.0.1 "$EXT_PORT" "$COUNT" "$WARMUP" >> "$BPF_OUT"

# C. bpf_int_allow
echo "  [3/4] bpf_int_allow" >&2
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" bpf_int_allow "$INT_ALLOW_IP" "$INT_ALLOW_PORT" "$COUNT" "$WARMUP" >> "$BPF_OUT"

# D. bpf_int_deny
echo "  [4/4] bpf_int_deny" >&2
echo $$ > "${PROCROUTE_CG}/cgroup.procs"
taskset -c "$CLIENT_CPU" python3 "$BENCH_SCRIPT" bpf_int_deny "$INT_DENY_IP" "$INT_DENY_PORT" "$COUNT" "$WARMUP" 0 >> "$BPF_OUT"

echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
echo "ProcRoute latency -> $BPF_OUT"

# ProcRoute reload latency
echo ""
echo "--- ProcRoute reload latency (5 trials) ---"

BPF_RELOAD="${RESULTS_DIR}/bpf_reload_latency.csv"
echo "trial,reload_ms" > "$BPF_RELOAD"

for t in $(seq 0 4); do
    pkill -f "procroute daemon" 2>/dev/null || true
    sleep 1
    T0=$(date +%s%N)
    "$BIN" daemon --policy "$POLICY" > /dev/null 2>/dev/null &
    NEW_PID=$!
    sleep 2
    T1=$(date +%s%N)
    MS=$(python3 -c "print(f'{($T1 - $T0) / 1e6:.3f}')")
    echo "${t},${MS}" >> "$BPF_RELOAD"
    echo "  procroute reload trial ${t}: ${MS} ms" >&2
done
echo "ProcRoute reload -> $BPF_RELOAD"

# Stop daemon
pkill -f "procroute daemon" 2>/dev/null || true

echo ""
echo "=== Experiment complete ==="
echo "Results:"
echo "  ${RESULTS_DIR}/nft_latency.csv"
echo "  ${RESULTS_DIR}/bpf_latency.csv"
echo "  ${RESULTS_DIR}/nftables_pivot_block.csv"
echo "  ${RESULTS_DIR}/nftables_reload_latency.csv"
echo "  ${RESULTS_DIR}/bpf_reload_latency.csv"
