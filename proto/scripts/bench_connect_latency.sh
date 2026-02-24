#!/usr/bin/env bash
# bench_connect_latency.sh -- TCP connect() latency microbenchmark for ProcRoute.
# Runs four conditions back-to-back, each exercising a distinct BPF
# decision path:
#   1. baseline   -- outside the ProcRoute cgroup (no BPF hook fires).
#   2. ext_miss   -- inside an authorized app cgroup, connecting to an
#                   external (non-internal) destination.  Hook fires,
#                   internal-prefix LPM misses, returns BPF_OK.
#   3. int_allow  -- inside an authorized app cgroup, connecting to an
#                   internal-prefix destination the policy allows.
#                   Full allow path: LPM hit -> cgroup->app -> per-app
#                   LPM -> port/proto check.
#   4. int_deny   -- inside the ProcRoute parent cgroup with no app
#                   binding, connecting to an internal-prefix dest.
#                   Hook returns EPERM.
# Produces CSV with columns:
#   condition,iteration,latency_ns
# A summary row per condition is appended:
#   condition,stat,value_ns
# Prerequisites
#   - procroute daemon running:
#       sudo ./bin/procroute daemon --policy policy/example.yaml
#   - 10.1.2.3/32 assigned to loopback (ip addr add 10.1.2.3/32 dev lo)
#   - python3 (for nanosecond-precision timing)
# Usage
#   sudo ./scripts/bench_connect_latency.sh [options]
# Options
#   --count  N      iterations per condition  (default 5000)
#   --port   P      external TCP listener port (default 18080)
#   --output FILE   write CSV here            (default stdout)
#   --warmup N      warm-up iterations        (default 500)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/benchmark.yaml"
PROCROUTE_CG="/sys/fs/cgroup/procroute"
LISTENER_CPU="${LISTENER_CPU:-0}"
CLIENT_CPU="${CLIENT_CPU:-1}"

COUNT=5000
WARMUP=500
EXT_PORT=18080
INT_ALLOW_IP="10.1.2.3"
INT_ALLOW_PORT=443
INT_DENY_IP="10.255.255.1"
INT_DENY_PORT=80
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count)  COUNT="$2";    shift 2 ;;
        --port)   EXT_PORT="$2"; shift 2 ;;
        --output) OUTPUT="$2";   shift 2 ;;
        --warmup) WARMUP="$2";   shift 2 ;;
        --policy) POLICY="$2";   shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# preflight
if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "error: python3 is required for nanosecond-precision timing" >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found at $BIN -- run 'make' first" >&2
    exit 1
fi

if [[ ! -d "$PROCROUTE_CG" ]]; then
    echo "error: procroute cgroup not found -- is the daemon running?" >&2
    exit 1
fi

# Verify the internal-prefix IP is reachable on loopback
if ! ip addr show lo | grep -q "$INT_ALLOW_IP"; then
    echo "error: $INT_ALLOW_IP not found on lo -- run:" >&2
    echo "  ip addr add $INT_ALLOW_IP/32 dev lo" >&2
    exit 1
fi

# start ephemeral TCP listeners
LISTENER_PIDS=()

cleanup_listeners() {
    for pid in "${LISTENER_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup_listeners EXIT

start_listener() {
    local bind_ip="$1"
    local bind_port="$2"
    taskset -c "$LISTENER_CPU" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$bind_ip', $bind_port))
s.listen(128)
sys.stderr.write('listener ready on $bind_ip:$bind_port\n')
sys.stderr.flush()
while True:
    c, _ = s.accept()
    c.close()
" &
    LISTENER_PIDS+=($!)
}

# Listener 1: external destination (baseline + ext_miss)
start_listener "127.0.0.1" "$EXT_PORT"

# Listener 2: internal-prefix destination (int_allow)
start_listener "$INT_ALLOW_IP" "$INT_ALLOW_PORT"

sleep 0.5

for pid in "${LISTENER_PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "error: a TCP listener failed to start (PID $pid)" >&2
        exit 1
    fi
done

# Python benchmark driver
# Writes CSV rows to stdout, summary to stderr.
BENCH_PY=$(cat <<'PYEOF'
import socket
import sys
import time

condition = sys.argv[1]
host      = sys.argv[2]
port      = int(sys.argv[3])
count     = int(sys.argv[4])
warmup    = int(sys.argv[5])

# warm-up (not recorded)
for _ in range(warmup):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((host, port))
    except OSError:
        pass
    finally:
        s.close()

latencies = []
errors = 0

for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    t0 = time.perf_counter_ns()
    try:
        s.connect((host, port))
    except OSError:
        errors += 1
    finally:
        t1 = time.perf_counter_ns()
        s.close()
    lat = t1 - t0
    latencies.append(lat)
    print(f"{condition},{i},{lat}")

# summary stats
latencies.sort()
n = len(latencies)
if n > 0:
    mean = sum(latencies) / n
    p50  = latencies[n // 2]
    p90  = latencies[int(n * 0.90)]
    p99  = latencies[int(n * 0.99)]
    mn   = latencies[0]
    mx   = latencies[-1]
    for stat, val in [("mean", mean), ("p50", p50), ("p90", p90),
                      ("p99", p99), ("min", mn), ("max", mx)]:
        print(f"{condition},{stat},{int(val)}")
    print(f"# {condition}: n={n} errors={errors} mean={mean:.0f}ns "
          f"p50={p50}ns p90={p90}ns p99={p99}ns min={mn}ns max={mx}ns",
          file=sys.stderr)
PYEOF
)

# helper: run benchmark under a given cgroup
run_condition() {
    local condition="$1"
    local cgroup_path="$2"   # empty string = don't move
    local target_ip="$3"
    local target_port="$4"

    if [[ -n "$cgroup_path" ]]; then
        # Use $BASHPID (not $$) to move the current subshell process,
        # since this function may run inside a { ... } | pipe subshell
        # where $$ still refers to the parent script PID.
        echo $BASHPID > "${cgroup_path}/cgroup.procs"
    fi

    taskset -c "$CLIENT_CPU" python3 -c "$BENCH_PY" "$condition" "$target_ip" "$target_port" "$COUNT" "$WARMUP"

    # move back to root cgroup so next condition starts clean
    echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
}

# run
emit() {
    if [[ -n "$OUTPUT" ]]; then
        cat >> "$OUTPUT"
    else
        cat
    fi
}

{
    echo "condition,iteration,latency_ns"

    # Condition 1: baseline (outside ProcRoute cgroup -> external dest)
    echo "--- baseline (no BPF hook) ---" >&2
    run_condition "baseline" "" "127.0.0.1" "$EXT_PORT"

    # Condition 2: ext_miss (authorized cgroup -> external dest)
    echo "--- ext_miss (hook fires, prefix miss -> fast allow) ---" >&2
    APP_CG="${PROCROUTE_CG}/corp-browser"
    if [[ -d "$APP_CG" ]]; then
        run_condition "ext_miss" "$APP_CG" "127.0.0.1" "$EXT_PORT"
    else
        echo "warning: $APP_CG not found, skipping ext_miss" >&2
    fi

    # Condition 3: int_allow (authorized cgroup -> internal dest, policy allows)
    echo "--- int_allow (hook fires, full allow path) ---" >&2
    if [[ -d "$APP_CG" ]]; then
        run_condition "int_allow" "$APP_CG" "$INT_ALLOW_IP" "$INT_ALLOW_PORT"
    else
        echo "warning: $APP_CG not found, skipping int_allow" >&2
    fi

    # Condition 4: int_deny (procroute parent cgroup, no app binding -> deny)
    echo "--- int_deny (hook fires, no principal -> deny) ---" >&2
    DENY_PY=$(cat <<DPYEOF
import socket
import sys
import time

count     = int(sys.argv[1])
warmup    = int(sys.argv[2])
deny_ip   = "$INT_DENY_IP"
deny_port = $INT_DENY_PORT

# Use blocking socket: BPF cgroup/connect4 returns EPERM synchronously,
# so connect() should fail immediately without needing a timeout.
# Using settimeout() causes Python to use non-blocking I/O internally,
# which on some kernels swallows EPERM and falls through to a select()
# timeout loop.

# warm-up
for _ in range(warmup):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((deny_ip, deny_port))
    except OSError:
        pass
    finally:
        s.close()

latencies = []
errors = 0

for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t0 = time.perf_counter_ns()
    try:
        s.connect((deny_ip, deny_port))
    except OSError:
        errors += 1
    finally:
        t1 = time.perf_counter_ns()
        s.close()
    lat = t1 - t0
    latencies.append(lat)
    print(f"int_deny,{i},{lat}")

latencies.sort()
n = len(latencies)
if n > 0:
    mean = sum(latencies) / n
    p50  = latencies[n // 2]
    p90  = latencies[int(n * 0.90)]
    p99  = latencies[int(n * 0.99)]
    mn   = latencies[0]
    mx   = latencies[-1]
    for stat, val in [("mean", mean), ("p50", p50), ("p90", p90),
                      ("p99", p99), ("min", mn), ("max", mx)]:
        print(f"int_deny,{stat},{int(val)}")
    print(f"# int_deny: n={n} errors={errors} mean={mean:.0f}ns "
          f"p50={p50}ns p90={p90}ns p99={p99}ns min={mn}ns max={mx}ns",
          file=sys.stderr)
DPYEOF
    )

    echo $BASHPID > "${PROCROUTE_CG}/cgroup.procs"

    # Verify daemon survived the warmup (ring buffer overflow can crash it)
    if ! pgrep -f "procroute daemon" > /dev/null 2>&1; then
        echo "error: procroute daemon died before int_deny measurement -- ring buffer overflow?" >&2
        exit 1
    fi

    taskset -c "$CLIENT_CPU" python3 -c "$DENY_PY" "$COUNT" "$WARMUP"
    echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true

} | emit

echo "done" >&2
