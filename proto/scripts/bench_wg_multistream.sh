#!/usr/bin/env bash
# bench_wg_multistream.sh -- Parallel-stream throughput benchmark for WireGuard pipeline.
# Runs iperf3 with multiple parallel streams (-P) across four configurations:
#   1. wg_baseline        -- bare WireGuard (no ProcRoute)
#   2. wg_tag_only        -- client tagger running, no gateway enforcer
#   3. wg_enforce_nocache -- full pipeline, flow cache disabled
#   4. wg_enforce_cache   -- full pipeline, flow cache enabled (default)
# Shows flow cache behavior under concurrency (multiple TCP streams).
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built (make -C proto)
#   - iperf3 and python3 installed
# CSV output:
#   config,streams,trial,duration_s,bytes,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct
# Usage:
#   sudo ./scripts/bench_wg_multistream.sh [options]
# Options:
#   --trials N              Number of trials per config (default 3)
#   --duration N            iperf3 test duration in seconds (default 10)
#   --stream-counts "N ..." Space-separated parallel stream counts (default "8 16")
#   --output FILE           Write CSV here (default stdout)
#   --policy FILE           Policy YAML (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/example.yaml"

TRIALS=3
DURATION=10
STREAM_COUNTS="8 16"
OUTPUT=""
IPERF_PORT=15204

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)         TRIALS="$2";         shift 2 ;;
        --duration)       DURATION="$2";       shift 2 ;;
        --stream-counts)  STREAM_COUNTS="$2";  shift 2 ;;
        --output)         OUTPUT="$2";         shift 2 ;;
        --policy)         POLICY="$2";         shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Logging
log() { echo "[wg-multi] $*" >&2; }

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
    echo "$BINARY missing -- did you run make?" >&2
    exit 1
fi

if ! ip netns list | grep -qw ns_client; then
    echo "ns_client not found, run wg_ns.sh up" >&2
    exit 1
fi

# State
PIDS_TO_KILL=()
LOGDIR=$(mktemp -d /tmp/bench-wg-multistream-XXXXXX)

cleanup() {
    log "Cleaning up ..."
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

# JSON -> CSV extractor (adds streams column)
EXTRACT_PY=$(cat <<'PYEOF'
import json, sys

config  = sys.argv[1]
streams = sys.argv[2]
trial   = sys.argv[3]
raw     = sys.stdin.read()

try:
    data = json.loads(raw)
except json.JSONDecodeError:
    print(f"{config},{streams},{trial},0,0,0,0,0.0,0.0")
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

print(f"{config},{streams},{trial},{duration:.2f},{bytes_tx},{bps:.0f},{retrans},{cpu_sender:.2f},{cpu_recv:.2f}")
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

# Run one trial of iperf3 with -P streams
run_iperf() {
    local config="$1"
    local streams="$2"
    local trial="$3"
    local client_cmd="$4"
    local iperf_timeout=$(( DURATION + 30 ))

    kill_server
    start_server

    local json_out
    json_out=$(timeout "$iperf_timeout" bash -c "$client_cmd" 2>/dev/null || echo '{}')
    local line
    line=$(echo "$json_out" | python3 -c "$EXTRACT_PY" "$config" "$streams" "$trial")
    emit_line "$line"
}

# Main
emit_line "config,streams,trial,duration_s,bytes,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct"

for STREAMS in $STREAM_COUNTS; do
    log "=== Stream count: $STREAMS ==="

    # Config 1: wg_baseline
    log "Config: wg_baseline (no ProcRoute), P=$STREAMS"
    kill_bg
    for trial in $(seq 1 "$TRIALS"); do
        log "  trial $trial/$TRIALS"
        run_iperf "wg_baseline" "$STREAMS" "$trial" \
            "ip netns exec ns_client iperf3 -c fd01:2::3 -p $IPERF_PORT -P $STREAMS -t $DURATION --json"
    done

    # Config 2: wg_nftables
    log "Config: wg_nftables, P=$STREAMS"
    kill_bg

    CLIENT_LOG="$LOGDIR/client_nft_${STREAMS}.log"
    cd "$PROTO_DIR"
    nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
        --policy "$POLICY" --iface wg0 \
        >"$LOGDIR/client_nft_${STREAMS}.out" 2>"$CLIENT_LOG" &
    CLIENT_PID=$!
    PIDS_TO_KILL+=("$CLIENT_PID")
    wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

    ip netns exec ns_gateway nft -f - <<'NFTRULES'
flush ruleset
table ip6 procroute_wg_nft {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ip6 daddr != fd01:2::/64 accept
        iifname "wg0" ip6 flowlabel != 0 accept
    }
}
NFTRULES

    for trial in $(seq 1 "$TRIALS"); do
        log "  trial $trial/$TRIALS"
        run_iperf "wg_nftables" "$STREAMS" "$trial" \
            "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -P $STREAMS -t $DURATION --json"
    done
    ip netns exec ns_gateway nft flush ruleset 2>/dev/null || true

    # Config 3: wg_tag_only
    log "Config: wg_tag_only, P=$STREAMS"
    kill_bg

    CLIENT_LOG="$LOGDIR/client_tag_${STREAMS}.log"
    cd "$PROTO_DIR"
    nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
        --policy "$POLICY" --iface wg0 \
        >"$LOGDIR/client_tag_${STREAMS}.out" 2>"$CLIENT_LOG" &
    CLIENT_PID=$!
    PIDS_TO_KILL+=("$CLIENT_PID")
    wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

    for trial in $(seq 1 "$TRIALS"); do
        log "  trial $trial/$TRIALS"
        run_iperf "wg_tag_only" "$STREAMS" "$trial" \
            "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -P $STREAMS -t $DURATION --json"
    done

    # Config 4: wg_enforce_nocache
    log "Config: wg_enforce_nocache, P=$STREAMS"
    kill_bg

    CLIENT_LOG="$LOGDIR/client_nc_${STREAMS}.log"
    nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
        --policy "$POLICY" --iface wg0 \
        >"$LOGDIR/client_nc_${STREAMS}.out" 2>"$CLIENT_LOG" &
    CLIENT_PID=$!
    PIDS_TO_KILL+=("$CLIENT_PID")
    wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

    GW_LOG="$LOGDIR/gw_nc_${STREAMS}.log"
    ip netns exec ns_gateway "$BINARY" wg-gateway \
        --policy "$POLICY" --iface wg0 --no-flow-cache \
        >"$LOGDIR/gw_nc_${STREAMS}.deny" 2>"$GW_LOG" &
    GW_PID=$!
    PIDS_TO_KILL+=("$GW_PID")
    wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
    log "  wg-gateway ready (PID=$GW_PID, no-flow-cache)"

    for trial in $(seq 1 "$TRIALS"); do
        log "  trial $trial/$TRIALS"
        run_iperf "wg_enforce_nocache" "$STREAMS" "$trial" \
            "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -P $STREAMS -t $DURATION --json"
    done

    # Config 4: wg_enforce_cache
    log "Config: wg_enforce_cache, P=$STREAMS"
    kill_bg

    CLIENT_LOG="$LOGDIR/client_c_${STREAMS}.log"
    nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
        --policy "$POLICY" --iface wg0 \
        >"$LOGDIR/client_c_${STREAMS}.out" 2>"$CLIENT_LOG" &
    CLIENT_PID=$!
    PIDS_TO_KILL+=("$CLIENT_PID")
    wait_ready "$CLIENT_LOG" "wg-client ready" || { log "ERROR: wg-client failed"; exit 1; }

    GW_LOG="$LOGDIR/gw_c_${STREAMS}.log"
    ip netns exec ns_gateway "$BINARY" wg-gateway \
        --policy "$POLICY" --iface wg0 \
        >"$LOGDIR/gw_c_${STREAMS}.deny" 2>"$GW_LOG" &
    GW_PID=$!
    PIDS_TO_KILL+=("$GW_PID")
    wait_ready "$GW_LOG" "wg-gateway ready" || { log "ERROR: wg-gateway failed"; cat "$GW_LOG" >&2; exit 1; }
    log "  wg-gateway ready (PID=$GW_PID, cache on)"

    for trial in $(seq 1 "$TRIALS"); do
        log "  trial $trial/$TRIALS"
        run_iperf "wg_enforce_cache" "$STREAMS" "$trial" \
            "nsenter --net=/var/run/netns/ns_client $BINARY launch --app vpn-client --policy $POLICY -- iperf3 -c fd01:2::3 -p $IPERF_PORT -P $STREAMS -t $DURATION --json"
    done
done

log "done"
