#!/usr/bin/env bash
# bench_wg_throughput.sh -- iperf3 throughput benchmark for WireGuard pipeline.
# Measures TCP throughput across four configurations:
#   1. wg_baseline      -- bare WireGuard (no ProcRoute)
#   2. wg_tag_only      -- client tagger running, no gateway enforcer
#   3. wg_enforce_nocache -- full pipeline, flow cache disabled
#   4. wg_enforce_cache   -- full pipeline, flow cache enabled (default)
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built (make -C proto)
#   - iperf3 and python3 installed
# CSV output:
#   config,trial,duration_s,bytes,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct
# Usage:
#   sudo ./scripts/bench_wg_throughput.sh [options]
# Options:
#   --trials N      Number of trials per config (default 10)
#   --duration N    iperf3 test duration in seconds (default 10)
#   --output FILE   Write CSV here (default stdout)
#   --policy FILE   Policy YAML (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/example.yaml"

TRIALS=10
DURATION=10
OUTPUT=""
IPERF_PORT=15201

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)   TRIALS="$2";   shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --output)   OUTPUT="$2";   shift 2 ;;
        --policy)   POLICY="$2";   shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Logging
log() { echo "[wg-tput] $*" >&2; }

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
LOGDIR=$(mktemp -d /tmp/bench-wg-throughput-XXXXXX)

cleanup() {
    log "Cleaning up ..."
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    PIDS_TO_KILL=()
    # Remove procroute cgroups
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
    # Clean cgroups between configs
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        find /sys/fs/cgroup/procroute -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
            rmdir "$d" 2>/dev/null || true
        done
        rmdir /sys/fs/cgroup/procroute 2>/dev/null || true
    fi
    sleep 0.3
}

# Wait for a process to log a ready message
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

# JSON -> CSV extractor
EXTRACT_PY=$(cat <<'PYEOF'
import json, sys

config = sys.argv[1]
trial  = sys.argv[2]
raw    = sys.stdin.read()

try:
    data = json.loads(raw)
except json.JSONDecodeError:
    print(f"{config},{trial},0,0,0,0,0.0,0.0")
    sys.exit(0)

end = data.get("end", {})
s_sum = end.get("sum_sent", end.get("sum", {}))
cpu   = end.get("cpu_utilization_percent", {})

duration   = s_sum.get("seconds", 0)
bytes_tx   = s_sum.get("bytes", 0)
bps        = s_sum.get("bits_per_second", 0)
retrans    = s_sum.get("retransmits", 0)
cpu_sender = cpu.get("host_total", 0)
cpu_recv   = cpu.get("remote_total", 0)

print(f"{config},{trial},{duration:.2f},{bytes_tx},{bps:.0f},{retrans},{cpu_sender:.2f},{cpu_recv:.2f}")
PYEOF
)

# Output helper
emit_line() {
    if [[ -n "$OUTPUT" ]]; then
        echo "$1" >> "$OUTPUT"
    else
        echo "$1"
    fi
}

# Start iperf3 server in ns_server
start_server() {
    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    sleep 0.2
    ip netns exec ns_server iperf3 -s -B "fd01:2::3" -p "$IPERF_PORT" -D 2>/dev/null
    sleep 0.3
}

kill_server() {
    pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
    sleep 0.2
}

# Run one trial of iperf3
run_iperf() {
    local config="$1"
    local trial="$2"
    local client_cmd="$3"  # full command to run iperf3 client
    local iperf_timeout=$(( DURATION + 30 ))  # generous timeout beyond iperf3 duration

    kill_server
    start_server

    local json_out
    json_out=$(timeout "$iperf_timeout" bash -c "$client_cmd" 2>/dev/null || echo '{}')
    local line
    line=$(echo "$json_out" | python3 -c "$EXTRACT_PY" "$config" "$trial")
    emit_line "$line"
}

# Main
emit_line "config,trial,duration_s,bytes,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct"

# Config 1: wg_baseline
log "Config: wg_baseline (no ProcRoute)"
for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"
    run_iperf "wg_baseline" "$trial" \
        "ip netns exec ns_client iperf3 -c fd01:2::3 -p $IPERF_PORT -t $DURATION --json"
done

# Config 2: wg_tag_only
log "Config: wg_tag_only (client tagger, no gateway)"
kill_bg

# Start wg-client in ns_client
CLIENT_LOG="$LOGDIR/client.log"
cd "$PROTO_DIR"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")

if ! wait_ready "$CLIENT_LOG" "wg-client ready"; then
    log "ERROR: wg-client did not become ready"
    cat "$CLIENT_LOG" >&2
    exit 1
fi
log "  wg-client ready (PID=$CLIENT_PID)"

for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"
    run_iperf "wg_tag_only" "$trial" \
        "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -t $DURATION --json"
done

# Config 3: wg_enforce_nocache
log "Config: wg_enforce_nocache (full pipeline, cache off)"
kill_bg

# Start wg-client
CLIENT_LOG="$LOGDIR/client_nc.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client_nc.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

# Start wg-gateway with --no-flow-cache
GW_LOG="$LOGDIR/gw_nc.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 --no-flow-cache \
    >"$LOGDIR/gw_nc.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
log "  wg-gateway ready (PID=$GW_PID, no-flow-cache)"

for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"
    run_iperf "wg_enforce_nocache" "$trial" \
        "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -t $DURATION --json"
done

# Config 4: wg_enforce_cache
log "Config: wg_enforce_cache (full pipeline, cache on)"
kill_bg

# Start wg-client
CLIENT_LOG="$LOGDIR/client_c.log"
nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/client_c.out" 2>"$CLIENT_LOG" &
CLIENT_PID=$!
PIDS_TO_KILL+=("$CLIENT_PID")
wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

# Start wg-gateway (default = cache enabled)
GW_LOG="$LOGDIR/gw_c.log"
ip netns exec ns_gateway "$BINARY" wg-gateway \
    --policy "$POLICY" --iface wg0 \
    >"$LOGDIR/gw_c.deny" 2>"$GW_LOG" &
GW_PID=$!
PIDS_TO_KILL+=("$GW_PID")
wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
log "  wg-gateway ready (PID=$GW_PID, cache on)"

for trial in $(seq 1 "$TRIALS"); do
    log "  trial $trial/$TRIALS"
    run_iperf "wg_enforce_cache" "$trial" \
        "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -t $DURATION --json"
done

log "done"
