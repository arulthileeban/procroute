#!/usr/bin/env bash
# bench_wg_latency.sh -- TCP connect latency benchmark for WireGuard pipeline.
# Measures TCP connect() latency across four configurations:
#   1. wg_baseline        -- bare WireGuard (no ProcRoute)
#   2. wg_tag_only        -- client tagger, no gateway enforcer
#   3. wg_enforce_nocache -- full pipeline, flow cache disabled
#   4. wg_enforce_cache   -- full pipeline, flow cache enabled
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built
#   - python3 installed
# CSV output:
#   config,metric,p50_us,p95_us,p99_us,mean_us
# Usage:
#   sudo ./scripts/bench_wg_latency.sh [options]
# Options:
#   --tcp-count N    TCP connect iterations (default 2000)
#   --tcp-warmup N   Warmup iterations (default 200)
#   --output FILE    Write CSV here (default stdout)
#   --policy FILE    Policy YAML (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/example.yaml"

TCP_COUNT=2000
TCP_WARMUP=200
OUTPUT=""
LISTEN_PORT=18443
PER_CONFIG_TIMEOUT=300  # seconds per config before giving up

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tcp-count)  TCP_COUNT="$2";  shift 2 ;;
        --tcp-warmup) TCP_WARMUP="$2"; shift 2 ;;
        --output)     OUTPUT="$2";     shift 2 ;;
        --policy)     POLICY="$2";     shift 2 ;;
        --timeout)    PER_CONFIG_TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { echo "[bench_wg_latency] $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "error: python3 is required" >&2
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "error: binary not found at $BINARY" >&2
    exit 1
fi

if ! ip netns list | grep -qw ns_client; then
    echo "ns_client doesn't exist -- need wg_ns.sh up" >&2
    exit 1
fi

# State
PIDS_TO_KILL=()
LOGDIR=$(mktemp -d /tmp/bench-wg-latency-XXXXXX)

cleanup() {
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    PIDS_TO_KILL=()
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        for d in /sys/fs/cgroup/procroute/*/; do
            [[ -d "$d" ]] || continue
            rmdir "$d" 2>/dev/null || true
        done
        rmdir /sys/fs/cgroup/procroute 2>/dev/null || true
    fi
    rm -rf "$LOGDIR"
}
trap cleanup EXIT

kill_bg() {
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    PIDS_TO_KILL=()
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        find /sys/fs/cgroup/procroute -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
            rmdir "$d" 2>/dev/null || true
        done
        rmdir /sys/fs/cgroup/procroute 2>/dev/null || true
    fi
    sleep 0.3
}

wait_ready() {
    local logfile="$1"
    local pattern="$2"
    local timeout="${3:-30}"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "$pattern" "$logfile" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        elapsed=$((elapsed + 1))
    done
    return 1
}

# TCP benchmark Python script
TCP_BENCH_PY=$(cat <<'PYEOF'
import socket
import sys
import time

host    = sys.argv[1]
port    = int(sys.argv[2])
count   = int(sys.argv[3])
warmup  = int(sys.argv[4])
config  = sys.argv[5]

# warm-up -- use short timeout and bail early if too many failures
warmup_errors = 0
for _ in range(warmup):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((host, port))
    except OSError:
        warmup_errors += 1
    finally:
        s.close()
    # If >50% of warmup connections fail, bail out early
    if warmup_errors > max(10, warmup // 2):
        print(f"# {config}: bailing out -- {warmup_errors}/{warmup} warmup errors", file=sys.stderr)
        print(f"{config},tcp_connect,0,0,0,0")
        sys.exit(0)

latencies = []
errors = 0

for i in range(count):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2.0)
    t0 = time.perf_counter_ns()
    try:
        s.connect((host, port))
    except OSError:
        errors += 1
    finally:
        t1 = time.perf_counter_ns()
        s.close()
    latencies.append(t1 - t0)

latencies.sort()
n = len(latencies)
if n > 0:
    p50  = latencies[int(n * 0.50)] / 1000.0
    p95  = latencies[int(n * 0.95)] / 1000.0
    p99  = latencies[int(n * 0.99)] / 1000.0
    mean = sum(latencies) / n / 1000.0
    print(f"{config},tcp_connect,{p50:.2f},{p95:.2f},{p99:.2f},{mean:.2f}")
    print(f"# {config}: n={n} errors={errors} p50={p50:.1f}us p95={p95:.1f}us p99={p99:.1f}us mean={mean:.1f}us",
          file=sys.stderr)
else:
    print(f"{config},tcp_connect,0,0,0,0")
PYEOF
)

# Listener management
LISTENER_PID=""

start_listener() {
    kill_listener
    ip netns exec ns_server python3 -c "
import socket, sys, signal
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('fd01:2::3', $LISTEN_PORT))
s.listen(1024)
sys.stderr.write('listener ready on fd01:2::3:$LISTEN_PORT\n')
sys.stderr.flush()
while True:
    try:
        c, _ = s.accept()
        c.close()
    except Exception:
        break
" &
    LISTENER_PID=$!
    PIDS_TO_KILL+=("$LISTENER_PID")
    sleep 0.5
}

kill_listener() {
    if [[ -n "${LISTENER_PID:-}" ]]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}

# Output helper
emit_line() {
    if [[ -n "$OUTPUT" ]]; then
        echo "$1" >> "$OUTPUT"
    else
        echo "$1"
    fi
}

# Main
emit_line "config,metric,p50_us,p95_us,p99_us,mean_us"

run_tcp_bench() {
    local cmd_prefix="$1"
    local config="$2"
    local line
    line=$(timeout "$PER_CONFIG_TIMEOUT" $cmd_prefix python3 -c "$TCP_BENCH_PY" "fd01:2::3" "$LISTEN_PORT" "$TCP_COUNT" "$TCP_WARMUP" "$config" 2>/dev/null) || true
    if [[ -z "$line" ]]; then
        log "  WARNING: $config timed out or failed"
        emit_line "$config,tcp_connect,0,0,0,0"
    else
        emit_line "$line"
    fi
}

# Config 1: wg_baseline
log "Config: wg_baseline"
start_listener
run_tcp_bench "ip netns exec ns_client" "wg_baseline"

# Config 2: wg_tag_only
log "Config: wg_tag_only"
kill_bg
start_listener

CLIENT_LOG="$LOGDIR/client_tag.log"
cd "$PROTO_DIR"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client_tag.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

run_tcp_bench "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY --" "wg_tag_only"

# Config 3: wg_enforce_nocache
log "Config: wg_enforce_nocache"
kill_bg
start_listener

CLIENT_LOG="$LOGDIR/client_nc.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client_nc.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

GW_LOG="$LOGDIR/gw_nc.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 --no-flow-cache \
    >"$LOGDIR/gw_nc.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; exit 1; }

run_tcp_bench "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY --" "wg_enforce_nocache"

# Config 4: wg_enforce_cache
log "Config: wg_enforce_cache"
kill_bg
start_listener

CLIENT_LOG="$LOGDIR/client_c.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client_c.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

GW_LOG="$LOGDIR/gw_c.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/gw_c.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; exit 1; }

run_tcp_bench "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY --" "wg_enforce_cache"

log "done"
