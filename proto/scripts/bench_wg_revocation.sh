#!/usr/bin/env bash
# bench_wg_revocation.sh -- Revocation latency benchmark for WireGuard pipeline.
# Measures three revocation-related metrics:
#   1. epoch_bump       -- Time for SIGUSR2 -> "epoch bumped" in log (BPF map update)
#   2. new_conn_block   -- Connect latency of first post-bump connection vs steady-state
#                         median (cache miss on new epoch forces slow-path re-evaluation)
#   3. cache_invalidation -- Miss rate in the delta window after epoch bump
#                          (all cached entries stale -> ~100% misses expected)
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built with SIGUSR2 epoch handler
#   - iperf3 and python3 installed
# CSV output:
#   metric,trial,value_us
# Usage:
#   sudo ./scripts/bench_wg_revocation.sh [options]
# Options:
#   --trials N      Number of trials per metric (default 5)
#   --output FILE   Write CSV here (default stdout)
#   --policy FILE   Policy YAML (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/example.yaml"

TRIALS=5
OUTPUT=""
IPERF_PORT=15206
LISTEN_PORT=18445

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)   TRIALS="$2";   shift 2 ;;
        --output)   OUTPUT="$2";   shift 2 ;;
        --policy)   POLICY="$2";   shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Logging
log() { echo "[bench_wg_revocation] $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

for cmd in iperf3 python3; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd is required" >&2
        exit 1
    fi
done

if [[ ! -x "$BINARY" ]]; then
    echo "error: binary not found at $BINARY -- run 'make' first" >&2
    exit 1
fi

if ! ip netns list | grep -qw ns_client; then
    echo "error: namespace ns_client not found -- run wg_ns.sh up first" >&2
    exit 1
fi

# State
PIDS_TO_KILL=()
LOGDIR=$(mktemp -d /tmp/bench-wg-revocation-XXXXXX)

cleanup() {
    log "Cleaning up ..."
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    PIDS_TO_KILL=()
    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        find /sys/fs/cgroup/procroute -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
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

# Output helper
emit_line() {
    if [[ -n "$OUTPUT" ]]; then
        echo "$1" >> "$OUTPUT"
    else
        echo "$1"
    fi
}

# Parse SIGUSR1 stats from gateway log
parse_stats() {
    local logfile="$1"
    local stats_line
    stats_line=$(grep "flow_cache_stats:" "$logfile" | tail -1 | sed 's/.*flow_cache_stats: //')
    if [[ -z "$stats_line" ]]; then
        echo "0 0 0"
        return
    fi
    python3 -c "
import json
s = json.loads('$stats_line')
print(f\"{s['hits']} {s['misses']} {s['inserts']}\")
"
}

# Epoch bump latency Python helper
EPOCH_BUMP_PY=$(cat <<'PYEOF'
import os, signal, sys, time

client_pid = int(sys.argv[1])
client_log = sys.argv[2]

# Count existing "epoch bumped" lines
with open(client_log, "r") as f:
    baseline_count = f.read().count("epoch bumped")

# Send SIGUSR2 and measure time until new "epoch bumped" appears
t0 = time.monotonic_ns()
os.kill(client_pid, signal.SIGUSR2)

timeout = 5.0  # seconds
deadline = time.monotonic() + timeout
found = False
while time.monotonic() < deadline:
    with open(client_log, "r") as f:
        if f.read().count("epoch bumped") > baseline_count:
            t1 = time.monotonic_ns()
            found = True
            break
    time.sleep(0.0001)  # 100us poll

if found:
    elapsed_us = (t1 - t0) / 1000
    print(f"{elapsed_us:.0f}")
else:
    print("-1")
PYEOF
)

# Connect latency Python helper
CONNECT_LATENCY_PY=$(cat <<'PYEOF'
import socket, sys, time

host = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3])

latencies = []
for i in range(count):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(5.0)
    t0 = time.monotonic_ns()
    try:
        s.connect((host, port))
        t1 = time.monotonic_ns()
        latencies.append((t1 - t0) / 1000)  # microseconds
        s.close()
    except OSError:
        s.close()
        latencies.append(-1)

# Print each latency on its own line
for lat in latencies:
    print(f"{lat:.0f}")
PYEOF
)

# Setup: start full pipeline (client tagger + gateway enforcer, cache on)
log "Setting up full pipeline"
cd "$PROTO_DIR"

CLIENT_LOG="$LOGDIR/client.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; cat "$CLIENT_LOG" >&2; exit 1; }
log "  wg-client ready (PID=$CLIENT_PID)"

GW_LOG="$LOGDIR/gw.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/gw.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
log "  wg-gateway ready (PID=$GW_PID)"

emit_line "metric,trial,value_us"

# Metric 1: epoch_bump -- SIGUSR2 -> "epoch bumped" latency
log "Metric: epoch_bump"
for trial in $(seq 1 "$TRIALS"); do
    BUMP_US=$(python3 -c "$EPOCH_BUMP_PY" "$CLIENT_PID" "$CLIENT_LOG")
    emit_line "epoch_bump,$trial,$BUMP_US"
    log "  trial $trial: ${BUMP_US}us"
    sleep 0.2
done

# Metric 2: new_conn_block -- post-epoch-bump connect latency spike
# Approach:
#   1. Warm up flow cache with steady traffic
#   2. Measure N steady-state connects -> get median
#   3. Bump epoch via SIGUSR2 on client
#   4. Immediately measure N connects -> first one(s) hit slow path
#   5. Report: first post-bump connect latency vs steady-state median
log "Metric: new_conn_block"

# Start TCP listener in ns_server
ip netns exec ns_server python3 -c "
import socket, sys, signal, threading
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('fd01:2::3', $LISTEN_PORT))
s.listen(1024)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except Exception:
        break
" &
LISTEN_PID=$!
PIDS_TO_KILL+=("$LISTEN_PID")
sleep 0.5

# Warm up: run short iperf3 to populate flow cache
pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
sleep 0.2
ip netns exec ns_server iperf3 -s -B "fd01:2::3" -p "$IPERF_PORT" -D 2>/dev/null
sleep 0.3
nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
    --app vpn-client --policy "$POLICY" -- \
    iperf3 -c fd01:2::3 -p "$IPERF_PORT" -t 2 >/dev/null 2>&1 || true
sleep 0.5

CONNECT_COUNT=10

for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"

    # Measure steady-state connect latencies
    STEADY_LATENCIES=$(nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
        --app vpn-client --policy "$POLICY" -- \
        python3 -c "$CONNECT_LATENCY_PY" "fd01:2::3" "$LISTEN_PORT" "$CONNECT_COUNT" 2>/dev/null)

    STEADY_MEDIAN=$(echo "$STEADY_LATENCIES" | python3 -c "
import sys
vals = [float(x) for x in sys.stdin.read().strip().split('\n') if float(x) >= 0]
vals.sort()
n = len(vals)
if n == 0:
    print(0)
else:
    print(f'{vals[n//2]:.0f}')
")

    # Bump epoch on client
    python3 -c "$EPOCH_BUMP_PY" "$CLIENT_PID" "$CLIENT_LOG" >/dev/null

    # Immediately measure post-bump connects
    POST_LATENCIES=$(nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
        --app vpn-client --policy "$POLICY" -- \
        python3 -c "$CONNECT_LATENCY_PY" "fd01:2::3" "$LISTEN_PORT" "$CONNECT_COUNT" 2>/dev/null)

    FIRST_POST=$(echo "$POST_LATENCIES" | head -1)

    # Value = first post-bump connect latency (the slow-path hit)
    # Also emit steady median as reference
    emit_line "new_conn_block,$trial,$FIRST_POST"
    emit_line "steady_state_median,$trial,$STEADY_MEDIAN"
    log "    steady_median=${STEADY_MEDIAN}us first_post_bump=${FIRST_POST}us"
    sleep 0.2
done

# Kill TCP listener
kill "$LISTEN_PID" 2>/dev/null || true
wait "$LISTEN_PID" 2>/dev/null || true
PIDS_TO_KILL=("${PIDS_TO_KILL[@]/$LISTEN_PID/}")

# Metric 3: cache_invalidation -- miss rate after epoch bump
log "Metric: cache_invalidation"

for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"

    # Run iperf3 to warm cache
    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    sleep 0.2
    ip netns exec ns_server iperf3 -s -B "fd01:2::3" -p "$IPERF_PORT" -D 2>/dev/null
    sleep 0.3

    nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
        --app vpn-client --policy "$POLICY" -- \
        iperf3 -c fd01:2::3 -p "$IPERF_PORT" -t 3 >/dev/null 2>&1 || true
    sleep 0.3

    # Get baseline stats
    kill -USR1 "$GW_PID"
    sleep 0.3
    STATS_BEFORE=$(parse_stats "$GW_LOG")
    HITS_0=$(echo "$STATS_BEFORE" | awk '{print $1}')
    MISSES_0=$(echo "$STATS_BEFORE" | awk '{print $2}')

    # Start background iperf3 (will run for 3s)
    nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
        --app vpn-client --policy "$POLICY" -- \
        iperf3 -c fd01:2::3 -p "$IPERF_PORT" -t 3 >/dev/null 2>&1 &
    IPERF_BG_PID=$!

    # Wait a moment for traffic to start flowing
    sleep 0.5

    # Bump epoch on client -- all cached entries now stale
    python3 -c "$EPOCH_BUMP_PY" "$CLIENT_PID" "$CLIENT_LOG" >/dev/null

    # Wait for traffic to flow with new epoch
    sleep 1.5

    # Wait for iperf3 to finish
    wait "$IPERF_BG_PID" 2>/dev/null || true
    sleep 0.3

    # Get stats after
    kill -USR1 "$GW_PID"
    sleep 0.3
    STATS_AFTER=$(parse_stats "$GW_LOG")
    HITS_1=$(echo "$STATS_AFTER" | awk '{print $1}')
    MISSES_1=$(echo "$STATS_AFTER" | awk '{print $2}')

    # Compute delta miss rate (as parts per 10000 -> value_us field reused)
    MISS_RATE=$(python3 -c "
h0, m0, h1, m1 = $HITS_0, $MISSES_0, $HITS_1, $MISSES_1
dh = h1 - h0
dm = m1 - m0
total = dh + dm
if total > 0:
    rate = dm / total * 10000  # basis points (100% = 10000)
    print(f'{rate:.0f}')
else:
    print('0')
")
    emit_line "cache_invalidation,$trial,$MISS_RATE"
    log "    hits_delta=$((HITS_1 - HITS_0)) misses_delta=$((MISSES_1 - MISSES_0)) miss_rate_bps=$MISS_RATE"

    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    sleep 0.3
done

log "done"
