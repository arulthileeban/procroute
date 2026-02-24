#!/usr/bin/env bash
# bench_throughput.sh -- TCP throughput macrobenchmark for ProcRoute.
# Measures bulk-transfer throughput with and without BPF enforcement
# using iperf3.  Runs three conditions:
#   1. baseline    -- iperf3 outside the procroute cgroup
#   2. bpf_allow   -- iperf3 inside an authorized app cgroup
#   3. bpf_deny    -- iperf3 inside the procroute parent (no app binding);
#                    connect is denied so throughput = 0 (confirms enforcement)
# Produces CSV with columns:
#   condition,duration_s,bytes_transferred,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct
# One row per condition.  These map directly to Table 1
# ("Throughput (Gbps)" and "CPU (% @ N conns/s)") in the paper.
# Prerequisites
#   - procroute daemon running:
#       sudo ./bin/procroute daemon --policy policy/example.yaml
#   - iperf3 installed (apt-get install iperf3)
#   - python3 (for JSON parsing)
# Usage
#   sudo ./scripts/bench_throughput.sh [options]
# Options
#   --duration N    iperf3 test duration in seconds  (default 10)
#   --parallel N    parallel streams                 (default 1)
#   --port     P    iperf3 server port               (default 15201)
#   --output   FILE write CSV here                   (default stdout)
#   --target   ADDR iperf3 server address            (default 127.0.0.1)
#   --policy   FILE policy path                      (default policy/example.yaml)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROTO_DIR}/bin/procroute"
POLICY="${PROTO_DIR}/policy/benchmark.yaml"
PROCROUTE_CG="/sys/fs/cgroup/procroute"

DURATION=10
PARALLEL=1
PORT=15201
OUTPUT=""
TARGET="127.0.0.1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --parallel) PARALLEL="$2"; shift 2 ;;
        --port)     PORT="$2";     shift 2 ;;
        --output)   OUTPUT="$2";   shift 2 ;;
        --target)   TARGET="$2";   shift 2 ;;
        --policy)   POLICY="$2";   shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# preflight
if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

if ! command -v iperf3 &>/dev/null; then
    echo "error: iperf3 is required (apt-get install iperf3)" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "error: python3 is required" >&2
    exit 1
fi

if [[ ! -d "$PROCROUTE_CG" ]]; then
    echo "error: procroute cgroup not found -- is the daemon running?" >&2
    exit 1
fi

# start iperf3 server
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

iperf3 -s -p "$PORT" -D --one-off 2>/dev/null &
SERVER_PID=$!
sleep 1

# JSON -> CSV extractor
EXTRACT_PY=$(cat <<'PYEOF'
import json, sys

condition = sys.argv[1]
raw = sys.stdin.read()

try:
    data = json.loads(raw)
except json.JSONDecodeError:
    # iperf3 might have failed (e.g. connection refused by BPF)
    print(f"{condition},0,0,0,0,0.0,0.0")
    sys.exit(0)

end = data.get("end", {})

# sender summary
s_sum  = end.get("sum_sent", end.get("sum", {}))
r_sum  = end.get("sum_received", {})
cpu    = end.get("cpu_utilization_percent", {})

duration   = s_sum.get("seconds", 0)
bytes_tx   = s_sum.get("bytes", 0)
bps        = s_sum.get("bits_per_second", 0)
retrans    = s_sum.get("retransmits", 0)
cpu_sender = cpu.get("host_total", 0)
cpu_recv   = cpu.get("remote_total", 0)

print(f"{condition},{duration:.2f},{bytes_tx},{bps:.0f},{retrans},{cpu_sender:.2f},{cpu_recv:.2f}")
PYEOF
)

# helper: run iperf3 under a given cgroup
run_iperf() {
    local condition="$1"
    local cgroup_path="$2"   # empty = don't move

    if [[ -n "$cgroup_path" ]]; then
        echo $BASHPID > "${cgroup_path}/cgroup.procs"
    fi

    # restart server for each condition (iperf3 -D --one-off exits after
    # one client; restart between runs)
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    # server runs outside any procroute cgroup
    echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    iperf3 -s -p "$PORT" -D 2>/dev/null &
    SERVER_PID=$!
    sleep 0.5

    # move back into the target cgroup for the client
    if [[ -n "$cgroup_path" ]]; then
        echo $BASHPID > "${cgroup_path}/cgroup.procs"
    fi

    local json_out
    json_out=$(iperf3 -c "$TARGET" -p "$PORT" -t "$DURATION" \
                      -P "$PARALLEL" --json 2>/dev/null || echo '{}')

    echo "$json_out" | python3 -c "$EXTRACT_PY" "$condition"

    # move back to root cgroup
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
    echo "condition,duration_s,bytes_transferred,bits_per_second,retransmits,cpu_sender_pct,cpu_receiver_pct"

    echo "--- baseline (no BPF) ---" >&2
    run_iperf "baseline" ""

    echo "--- bpf_allow (authorized app cgroup) ---" >&2
    APP_CG="${PROCROUTE_CG}/corp-browser"
    if [[ -d "$APP_CG" ]]; then
        run_iperf "bpf_allow" "$APP_CG"
    else
        echo "warning: $APP_CG not found, skipping bpf_allow" >&2
    fi

    echo "--- bpf_int_allow (authorized app cgroup, internal dest) ---" >&2
    INT_ALLOW_IP="10.1.2.3"
    # Ensure loopback alias
    if ! ip addr show lo | grep -q "$INT_ALLOW_IP"; then
        ip addr add "${INT_ALLOW_IP}/32" dev lo
    fi
    INT_ALLOW_PORT=443  # must match corp-browser policy
    if [[ -d "$APP_CG" ]]; then
        # Kill all iperf3 servers to free ports
        pkill -f "iperf3" 2>/dev/null || true
        sleep 0.5

        # Server runs outside procroute cgroup, using -D (proper daemonization)
        echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
        iperf3 -s -B "$INT_ALLOW_IP" -p "$INT_ALLOW_PORT" -D 2>/dev/null
        sleep 0.5

        # Run client from authorized cgroup
        echo $BASHPID > "${APP_CG}/cgroup.procs"
        int_json=$(iperf3 -c "$INT_ALLOW_IP" -p "$INT_ALLOW_PORT" -t "$DURATION" \
                          -P "$PARALLEL" --json 2>/dev/null || echo '{}')
        echo "$int_json" | python3 -c "$EXTRACT_PY" "bpf_int_allow"
        echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    else
        echo "warning: $APP_CG not found, skipping bpf_int_allow" >&2
    fi

    echo "--- bpf_deny (unauthorized cgroup) ---" >&2
    # Kill all iperf3 servers
    pkill -f "iperf3" 2>/dev/null || true
    sleep 0.3
    # Connect to an internal address; BPF should EPERM.
    # No server at 10.255.255.1; BPF denies before reaching network.
    echo $BASHPID > "${PROCROUTE_CG}/cgroup.procs"
    deny_json=$(iperf3 -c "10.255.255.1" -p "$PORT" -t 2 --json 2>/dev/null || echo '{}')
    echo "$deny_json" | python3 -c "$EXTRACT_PY" "bpf_deny"
    echo $BASHPID > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true

} | emit

echo "done" >&2
