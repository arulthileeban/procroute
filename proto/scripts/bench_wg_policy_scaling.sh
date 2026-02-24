#!/usr/bin/env bash
# bench_wg_policy_scaling.sh -- Policy size scaling experiment for WireGuard gateway.
# Varies the number of principals and prefixes in the policy and measures:
#   - Gateway startup time (time to load BPF + populate maps)
#   - Short iperf3 throughput burst through the gateway
# Prerequisites:
#   - WireGuard namespace testbed up (wg_ns.sh up)
#   - procroute binary built
#   - generate_policy.py in scripts/
#   - iperf3 and python3 installed
# CSV output:
#   n_principals,prefixes_per_principal,trial,startup_ms,mbps
# Usage:
#   sudo ./scripts/bench_wg_policy_scaling.sh [options]
# Options:
#   --trials N              Trials per config (default 3)
#   --principal-sizes "..." Space-separated principal counts (default "10 50 100 250 500")
#   --prefix-sizes "..."    Space-separated prefix counts per principal (default "5 10 25")
#   --burst-duration N      iperf3 burst duration in seconds (default 5)
#   --output FILE           Write CSV here (default stdout)
#   --policy FILE           Base policy for wg-client (default ../policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"
BASE_POLICY="${PROTO_DIR}/policy/example.yaml"
GENERATE_PY="${SCRIPT_DIR}/generate_policy.py"
BPF_SRC="${PROTO_DIR}/bpf/procroute.c"

TRIALS=3
PRINCIPAL_SIZES="10 50 100 250 500"
PREFIX_SIZES="5 10 25"
BURST_DURATION=5
OUTPUT=""
IPERF_PORT=15202

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)          TRIALS="$2";          shift 2 ;;
        --principal-sizes) PRINCIPAL_SIZES="$2"; shift 2 ;;
        --prefix-sizes)    PREFIX_SIZES="$2";    shift 2 ;;
        --burst-duration)  BURST_DURATION="$2";  shift 2 ;;
        --output)          OUTPUT="$2";          shift 2 ;;
        --policy)          BASE_POLICY="$2";     shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

log() { echo "[bench_wg_scaling] $*" >&2; }

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
    echo "error: binary not found at $BINARY" >&2
    exit 1
fi

if [[ ! -f "$GENERATE_PY" ]]; then
    echo "error: generate_policy.py not found at $GENERATE_PY" >&2
    exit 1
fi

if ! ip netns list | grep -qw ns_client; then
    echo "error: namespace ns_client not found -- run wg_ns.sh up first" >&2
    exit 1
fi

# State
PIDS_TO_KILL=()
TMPDIR_SCALING=$(mktemp -d /tmp/bench-wg-scaling-XXXXXX)
BPF_PATCHED=0
BPF_BACKUP=""

cleanup() {
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    PIDS_TO_KILL=()
    # Restore BPF source
    if [[ $BPF_PATCHED -eq 1 && -n "$BPF_BACKUP" && -f "$BPF_BACKUP" ]]; then
        cp "$BPF_BACKUP" "$BPF_SRC"
        make -C "$PROTO_DIR" all >/dev/null 2>&1 || true
        log "restored BPF source"
    fi
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        find /sys/fs/cgroup/procroute -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
            rmdir "$d" 2>/dev/null || true
        done
        rmdir /sys/fs/cgroup/procroute 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_SCALING"
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
    local timeout="${3:-60}"
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

# BPF map patching (same as eval_baremetal.sh)
patch_bpf_limits() {
    local n_prefixes="$1"
    local n_principals="$2"

    local prefix_entries=$((n_prefixes > 1024 ? n_prefixes : 1024))
    local allow_entries=$(( n_prefixes * n_principals ))
    if [[ $allow_entries -lt 8192 ]]; then
        allow_entries=8192
    fi
    # Round up to next power of two
    local v=$allow_entries
    v=$(( v - 1 ))
    v=$(( v | (v >> 1) ))
    v=$(( v | (v >> 2) ))
    v=$(( v | (v >> 4) ))
    v=$(( v | (v >> 8) ))
    v=$(( v | (v >> 16) ))
    allow_entries=$(( v + 1 ))

    if [[ $BPF_PATCHED -eq 0 ]]; then
        BPF_BACKUP="${TMPDIR_SCALING}/procroute.c.orig"
        cp "$BPF_SRC" "$BPF_BACKUP"
    fi

    python3 -c "
import re, sys
with open('$BPF_SRC', 'r') as f:
    src = f.read()
def patch_map(src, map_name, new_max):
    lines = src.split('\n')
    for i, line in enumerate(lines):
        if '} ' + map_name + ' SEC' in line:
            for j in range(i-1, max(i-6, -1), -1):
                if 'max_entries' in lines[j]:
                    lines[j] = re.sub(r'max_entries,\s*\d+', f'max_entries, {new_max}', lines[j])
                    return '\n'.join(lines)
    return src
src = patch_map(src, 'internal_prefixes_v4', $prefix_entries)
src = patch_map(src, 'internal_prefixes_v6', $prefix_entries)
src = patch_map(src, 'app_allow_v4', $allow_entries)
src = patch_map(src, 'app_allow_v6', $allow_entries)
with open('$BPF_SRC', 'w') as f:
    f.write(src)
"
    BPF_PATCHED=1
    log "  patched BPF maps: prefix=$prefix_entries allow=$allow_entries"
}

# JSON -> Mbps extractor
EXTRACT_MBPS_PY=$(cat <<'PYEOF'
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    end = data.get("end", {})
    s_sum = end.get("sum_sent", end.get("sum", {}))
    bps = s_sum.get("bits_per_second", 0)
    print(f"{bps / 1e6:.2f}")
except Exception:
    print("0")
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

# Main
emit_line "n_principals,prefixes_per_principal,trial,startup_ms,mbps"

CURRENT_PATCH_KEY=""

for M in $PRINCIPAL_SIZES; do
    for PP in $PREFIX_SIZES; do
        TOTAL_PREFIXES=$(( M * PP ))
        log "--- config: M=$M principals, PP=$PP prefixes/principal (total=$TOTAL_PREFIXES) ---"

        # Determine if BPF patching is needed
        NEEDS_PATCH=0
        if [[ $TOTAL_PREFIXES -gt 1024 ]] || [[ $(( TOTAL_PREFIXES * M )) -gt 8192 ]]; then
            NEEDS_PATCH=1
        fi

        PATCH_KEY="${TOTAL_PREFIXES}_${M}"
        if [[ $NEEDS_PATCH -eq 1 && "$PATCH_KEY" != "$CURRENT_PATCH_KEY" ]]; then
            patch_bpf_limits "$TOTAL_PREFIXES" "$M"
            make -C "$PROTO_DIR" all >/dev/null 2>&1 || { log "ERROR: rebuild failed"; continue; }
            CURRENT_PATCH_KEY="$PATCH_KEY"
        elif [[ $NEEDS_PATCH -eq 0 && $BPF_PATCHED -eq 1 ]]; then
            cp "$BPF_BACKUP" "$BPF_SRC"
            make -C "$PROTO_DIR" all >/dev/null 2>&1
            BPF_PATCHED=0
            CURRENT_PATCH_KEY=""
        fi

        # Generate policy
        GEN_POLICY="${TMPDIR_SCALING}/policy_${M}_${PP}.yaml"
        python3 "$GENERATE_PY" --prefixes "$TOTAL_PREFIXES" --principals "$M" \
            --ipv6 --output "$GEN_POLICY"

        for trial in $(seq 1 "$TRIALS"); do
            log "  trial $trial/$TRIALS"
            kill_bg

            # Start wg-client (uses base policy for tag-only cgroup setup)
            CLIENT_LOG="$TMPDIR_SCALING/client_${M}_${PP}_${trial}.log"
            cd "$PROTO_DIR"
            nsenter --net=/var/run/netns/ns_client "$BINARY" wg-client \
                --policy "$BASE_POLICY" --iface wg0 \
                >/dev/null 2>"$CLIENT_LOG" &
            CLIENT_PID=$!
            PIDS_TO_KILL+=("$CLIENT_PID")
            wait_ready "$CLIENT_LOG" "wg-client ready" || { log "  ERROR: wg-client failed"; continue; }

            # Start wg-gateway with generated policy, measure startup time
            GW_LOG="$TMPDIR_SCALING/gw_${M}_${PP}_${trial}.log"
            T_START=$(date +%s%N)

            ip netns exec ns_gateway "$BINARY" wg-gateway \
                --policy "$GEN_POLICY" --iface wg0 \
                >/dev/null 2>"$GW_LOG" &
            GW_PID=$!
            PIDS_TO_KILL+=("$GW_PID")

            if wait_ready "$GW_LOG" "wg-gateway ready" 60; then
                T_END=$(date +%s%N)
                STARTUP_NS=$(( T_END - T_START ))
                STARTUP_MS=$(python3 -c "print(f'{$STARTUP_NS / 1_000_000:.2f}')")
            else
                STARTUP_MS=""
                log "  ERROR: wg-gateway did not start"
            fi

            # Run short iperf3 burst
            pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
            sleep 0.2
            ip netns exec ns_server iperf3 -s -B "fd01:2::3" -p "$IPERF_PORT" -D 2>/dev/null
            sleep 0.3

            MBPS=""
            if [[ -n "$STARTUP_MS" ]]; then
                JSON_OUT=$(nsenter --net=/var/run/netns/ns_client "$BINARY" launch \
                    --app vpn-client --policy "$BASE_POLICY" -- \
                    iperf3 -c fd01:2::3 -p "$IPERF_PORT" -t "$BURST_DURATION" --json 2>/dev/null || echo '{}')
                MBPS=$(echo "$JSON_OUT" | python3 -c "$EXTRACT_MBPS_PY")
            fi

            emit_line "${M},${PP},${trial},${STARTUP_MS:-},${MBPS:-}"
            log "    startup=${STARTUP_MS:-FAIL}ms mbps=${MBPS:-FAIL}"

            pkill -f "iperf3.*-s.*-p $IPERF_PORT" 2>/dev/null || true
        done
    done
done

log "done"
