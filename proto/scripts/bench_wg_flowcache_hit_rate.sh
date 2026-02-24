#!/usr/bin/env bash
# bench_wg_flowcache_hit_rate.sh -- Flow cache effectiveness measurement.
# Runs two workloads through the WireGuard gateway with cache enabled
# and reads flow cache stats via SIGUSR1:
#   1. many_short_flows -- 1000 sequential TCP connections (different source ports)
#   2. few_long_flows   -- single iperf3 stream for 5 seconds
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built
#   - python3 installed
# CSV output:
#   workload,hits,misses,inserts,hit_rate_pct
# Usage:
#   sudo ./scripts/bench_wg_flowcache_hit_rate.sh [options]
# Options:
#   --short-flows N   Number of short-flow connections (default 1000)
#   --long-duration N Long-flow iperf3 duration in seconds (default 5)
#   --output FILE     Write CSV here (default stdout)
#   --policy FILE     Policy YAML (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/example.yaml"

SHORT_FLOWS=1000
LONG_DURATION=5
OUTPUT=""
LISTEN_PORT=18444
IPERF_PORT=15203

while [[ $# -gt 0 ]]; do
    case "$1" in
        --short-flows)  SHORT_FLOWS="$2";  shift 2 ;;
        --long-duration) LONG_DURATION="$2"; shift 2 ;;
        --output)       OUTPUT="$2";       shift 2 ;;
        --policy)       POLICY="$2";       shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { printf "%s\n" "[flowcache] $*" >&2; }

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
    echo "error: namespace ns_client not found -- run wg_ns.sh up first" >&2
    exit 1
fi

# State
PIDS_TO_KILL=()
LOGDIR=$(mktemp -d /tmp/bench-wg-flowcache-XXXXXX)
GW_PID=""

cleanup() {
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
    rm -rf "$LOGDIR"
}
trap cleanup EXIT

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

# Short-flow workload Python script
SHORT_FLOW_PY=$(cat <<'PYEOF'
import socket, sys

host  = sys.argv[1]
port  = int(sys.argv[2])
count = int(sys.argv[3])

errors = 0
for i in range(count):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect((host, port))
        s.close()
    except OSError:
        errors += 1
        s.close()

print(f"completed {count} connections, {errors} errors", file=sys.stderr)
PYEOF
)

# Parse SIGUSR1 stats from gateway log
parse_stats() {
    local logfile="$1"
    # Extract the last flow_cache_stats JSON line
    local stats_line
    stats_line=$(grep "flow_cache_stats:" "$logfile" | tail -1 | sed 's/.*flow_cache_stats: //')
    if [[ -z "$stats_line" ]]; then
        echo "0,0,0,0.00"
        return
    fi
    python3 -c "
import json, sys
s = json.loads('$stats_line')
print(f\"{s['hits']},{s['misses']},{s['inserts']},{s['hit_rate_pct']:.2f}\")
"
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
emit_line "workload,hits,misses,inserts,hit_rate_pct"

# Setup: start wg-client + wg-gateway (cache enabled)
cd "$PROTO_DIR"

CLIENT_LOG="$LOGDIR/client.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }
log "wg-client ready"

GW_LOG="$LOGDIR/gw.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/gw.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
log "wg-gateway ready (PID=$GW_PID)"

# Workload 1: many short flows
log "Workload: many_short_flows ($SHORT_FLOWS connections)"

# Start TCP listener
ip netns exec ns_server python3 -c "
import socket, sys, signal
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

# Run short-flow workload
nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
    --app vpn-client --policy "$POLICY" -- \
    python3 -c "$SHORT_FLOW_PY" "fd01:2::3" "$LISTEN_PORT" "$SHORT_FLOWS"

sleep 0.5

# Get stats after short-flow workload
kill -USR1 "$GW_PID"
sleep 0.5
STATS=$(parse_stats "$GW_LOG")
emit_line "many_short_flows,$STATS"
log "  stats: $STATS"

# Kill listener
kill "$LISTEN_PID" 2>/dev/null || true
wait "$LISTEN_PID" 2>/dev/null || true

# Note previous stats (we'll subtract to get delta for next workload)
PREV_STATS="$STATS"

# Workload 2: few long flows
log "Workload: few_long_flows (iperf3 ${LONG_DURATION}s)"

if command -v iperf3 &>/dev/null; then
    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    sleep 0.2
    ip netns exec ns_server iperf3 -s -B "fd01:2::3" -p "$IPERF_PORT" -D 2>/dev/null
    sleep 0.3

    nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
        --app vpn-client --policy "$POLICY" -- \
        iperf3 -c fd01:2::3 -p "$IPERF_PORT" -t "$LONG_DURATION" >/dev/null 2>&1 || true

    sleep 0.5

    # Get stats (cumulative since gateway start)
    kill -USR1 "$GW_PID"
    sleep 0.5

    # Parse cumulative stats and compute delta
    CUM_STATS=$(parse_stats "$GW_LOG")
    DELTA_LINE=$(python3 -c "
prev = '$PREV_STATS'.split(',')
cum  = '$CUM_STATS'.split(',')
hits    = int(cum[0]) - int(prev[0])
misses  = int(cum[1]) - int(prev[1])
inserts = int(cum[2]) - int(prev[2])
total   = hits + misses
rate    = (hits / total * 100) if total > 0 else 0
print(f'few_long_flows,{hits},{misses},{inserts},{rate:.2f}')
")
    emit_line "$DELTA_LINE"
    log "  cumulative stats: $CUM_STATS"

    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
else
    log "WARNING: iperf3 not found, skipping few_long_flows"
    emit_line "few_long_flows,0,0,0,0.00"
fi

log "done"
