#!/usr/bin/env bash
# bench_policy_scaling.sh -- Q6: Policy-update latency and lookup scaling.
# Two micro-experiments:
#   (A) Update latency: wall-clock time to load BPF maps as policy size grows.
#   (B) Lookup scaling:  int_allow connect() latency at each policy size.
# Policy sizes (number of internal prefixes + proportional grants):
#   4, 16, 64, 256, 512, 1024
# For each size N:
#   - Generate a synthetic policy with N internal /24 prefixes and
#     N per-app allow entries spread across 5 applications.
#   - corp-browser always gets 10.1.2.3:443 in its grants (for the
#     int_allow benchmark).
#   - Time daemon startup to "BPF maps populated" marker.
#   - Run 2000 int_allow connect() iterations (pinned to CPU 0).
#   - Kill the daemon.
# Outputs:
#   results/policy_scaling_update.csv   -- N, trial, startup_ms
#   results/policy_scaling_lookup.csv   -- N, trial, p50_us, p90_us, p99_us
# Prerequisites:
#   - 10.1.2.3/32 on loopback
#   - procroute binary built
#   - python3, taskset
# Usage (on the VM as root):
#   sudo ./scripts/bench_policy_scaling.sh [--trials N]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
BIN="${PROTO_DIR}/bin/procroute"
RESULTS_DIR="${PROTO_DIR}/../results"
PROCROUTE_CG="/sys/fs/cgroup/procroute"
INT_ALLOW_IP="10.1.2.3"
INT_ALLOW_PORT=443
CPU_CORE=0

TRIALS=3
CONNECT_COUNT=2000
CONNECT_WARMUP=200
SIZES="4 16 64 256 512 1024"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --trials)  TRIALS="$2";  shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# preflight
if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

for cmd in python3 taskset; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd is required" >&2
        exit 1
    fi
done

if [[ ! -x "$BIN" ]]; then
    echo "error: binary not found at $BIN -- run 'make' first" >&2
    exit 1
fi

if ! ip addr show lo | grep -q "$INT_ALLOW_IP"; then
    echo "error: $INT_ALLOW_IP not found on lo" >&2
    exit 1
fi

mkdir -p "$RESULTS_DIR"

TMPDIR_BENCH=$(mktemp -d /tmp/procroute-bench-XXXXXX)
trap "rm -rf $TMPDIR_BENCH" EXIT

# synthetic policy generator
generate_policy() {
    local n_prefixes="$1"
    local outfile="$2"

    python3 -c "
import sys

N = $n_prefixes

# Generate N internal /24 prefixes from 10.x.y.0/24
# We use the first 3 from the standard set, then generate the rest
prefixes = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
for i in range(3, N):
    b2 = (i >> 8) & 0xFF
    b3 = i & 0xFF
    if b2 > 255:
        break
    prefixes.append(f'10.{b2}.{b3}.0/24')

# Trim or pad to exactly N
prefixes = prefixes[:N]
if len(prefixes) < N:
    # Shouldn't happen for N <= 1024
    sys.exit('too many prefixes requested')

print('version: 1')
print()
print('internal_prefixes:')
for p in prefixes:
    print(f'  - {p}')
print()
print('applications:')

# 5 fixed apps; distribute synthetic grant prefixes among them
apps = [
    ('corp-browser', '/system.slice/corp-browser.service'),
    ('vpn-client',   '/system.slice/vpn-client.service'),
    ('ssh-client',   '/user.slice/user-1000.slice/app-ssh.scope/*'),
    ('corp-ide',     '/user.slice/user-1000.slice/app-ide.scope/*'),
    ('internal-dns', '/system.slice/resolved.service'),
]

# corp-browser always gets 10.1.2.3:443 (for int_allow benchmark)
# plus its share of synthetic grants
for ai, (app_id, cgroup) in enumerate(apps):
    print(f'  - app_id: {app_id}')
    print(f'    match:')
    print(f'      cgroup: {cgroup}')
    print(f'    allow:')

    # Always give corp-browser access to 10.0.0.0/8 on 443
    if app_id == 'corp-browser':
        print(f'      - prefixes:')
        print(f'          - 10.0.0.0/8')
        print(f'        ports: [443]')
        print(f'        protocol: tcp')

    # Distribute the N internal prefixes as grants across apps
    # Each app gets roughly N/5 grants; guarantee at least one
    app_grants = [p for j, p in enumerate(prefixes) if j % 5 == ai]
    if not app_grants:
        app_grants = [prefixes[0]]
    if app_grants:
        print(f'      - prefixes:')
        for g in app_grants:
            print(f'          - {g}')
        if app_id == 'internal-dns':
            print(f'        ports: [53]')
            print(f'        protocol: udp')
        elif app_id == 'ssh-client':
            print(f'        ports: [22]')
            print(f'        protocol: tcp')
        else:
            print(f'        ports: [443]')
            print(f'        protocol: tcp')
    print()
" > "$outfile"
}

# connect latency driver
BENCH_PY=$(cat <<'PYEOF'
import socket
import sys
import time

host      = sys.argv[1]
port      = int(sys.argv[2])
count     = int(sys.argv[3])
warmup    = int(sys.argv[4])

# warm-up
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

latencies.sort()
n = len(latencies)
if n > 0:
    p50  = latencies[int(n * 0.50)]
    p90  = latencies[int(n * 0.90)]
    p99  = latencies[int(n * 0.99)]
    mean = sum(latencies) / n
    # Output: p50_us,p90_us,p99_us,mean_us,errors
    print(f"{p50/1000:.2f},{p90/1000:.2f},{p99/1000:.2f},{mean/1000:.2f},{errors}")
else:
    print("0,0,0,0,0")
PYEOF
)

# run experiments
UPDATE_CSV="${RESULTS_DIR}/policy_scaling_update.csv"
LOOKUP_CSV="${RESULTS_DIR}/policy_scaling_lookup.csv"

echo "n_prefixes,trial,startup_ms" > "$UPDATE_CSV"
echo "n_prefixes,trial,p50_us,p90_us,p99_us,mean_us,errors" > "$LOOKUP_CSV"

echo "=== Q6: Policy Scaling Benchmark ===" >&2
echo "Sizes: $SIZES" >&2
echo "Trials: $TRIALS" >&2
echo "Connect iterations: $CONNECT_COUNT (warmup: $CONNECT_WARMUP)" >&2
echo "" >&2

for N in $SIZES; do
    echo "--- N=$N prefixes ---" >&2

    POLICY_FILE="${TMPDIR_BENCH}/policy_${N}.yaml"
    generate_policy "$N" "$POLICY_FILE"

    # Count actual entries for reporting
    n_lines=$(grep -c '^\s*-' "$POLICY_FILE" || true)
    echo "  generated policy: $(wc -l < "$POLICY_FILE") lines" >&2

    for trial in $(seq 1 "$TRIALS"); do
        echo "  trial $trial/$TRIALS" >&2

        # Experiment A: startup/update latency
        # Kill any running daemon
        pkill -f "procroute daemon" 2>/dev/null || true
        sleep 0.5
        # Clean up cgroups from previous run: move all procs to root,
        # then rmdir children before parent (rm -rf does not work on cgroupfs)
        if [[ -d "$PROCROUTE_CG" ]]; then
            for cg in "$PROCROUTE_CG"/*/; do
                [[ -d "$cg" ]] || continue
                while read -r pid; do
                    echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
                done < "${cg}cgroup.procs" 2>/dev/null
                rmdir "$cg" 2>/dev/null || true
            done
            while read -r pid; do
                echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
            done < "${PROCROUTE_CG}/cgroup.procs" 2>/dev/null
            rmdir "$PROCROUTE_CG" 2>/dev/null || true
        fi
        sleep 0.2

        # Time the daemon startup until "BPF maps populated"
        READY_FILE="${TMPDIR_BENCH}/ready_${N}_${trial}"
        rm -f "$READY_FILE"

        T_START=$(date +%s%N)

        "$BIN" daemon --policy "$POLICY_FILE" > /dev/null 2>"${TMPDIR_BENCH}/daemon_${N}_${trial}.log" &
        DAEMON_PID=$!

        # Wait for "BPF maps populated" or "daemon ready" in stderr
        TIMEOUT=30
        ELAPSED=0
        while [[ $ELAPSED -lt $TIMEOUT ]]; do
            if grep -q "daemon ready" "${TMPDIR_BENCH}/daemon_${N}_${trial}.log" 2>/dev/null; then
                break
            fi
            if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
                echo "  ERROR: daemon exited prematurely" >&2
                cat "${TMPDIR_BENCH}/daemon_${N}_${trial}.log" >&2
                break
            fi
            sleep 0.1
            ELAPSED=$((ELAPSED + 1))
        done

        T_END=$(date +%s%N)
        STARTUP_NS=$(( T_END - T_START ))
        STARTUP_MS=$(python3 -c "print(f'{$STARTUP_NS / 1_000_000:.2f}')")

        echo "$N,$trial,$STARTUP_MS" >> "$UPDATE_CSV"
        echo "    startup: ${STARTUP_MS} ms" >&2

        # Experiment B: lookup scaling (int_allow connect latency)
        # Verify daemon is running and cgroup exists
        if [[ -d "${PROCROUTE_CG}/corp-browser" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then

            # Start listener on internal IP (pinned)
            taskset -c "$CPU_CORE" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$INT_ALLOW_IP', $INT_ALLOW_PORT))
s.listen(1024)
sys.stderr.write('listener ready\n')
sys.stderr.flush()
while True:
    c, _ = s.accept()
    c.close()
" &
            LISTENER_PID=$!
            sleep 0.3

            # Move into corp-browser cgroup and run benchmark
            echo $$ > "${PROCROUTE_CG}/corp-browser/cgroup.procs"

            RESULT=$(taskset -c "$CPU_CORE" python3 -c "$BENCH_PY" \
                "$INT_ALLOW_IP" "$INT_ALLOW_PORT" "$CONNECT_COUNT" "$CONNECT_WARMUP" 2>/dev/null)

            echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true

            echo "$N,$trial,$RESULT" >> "$LOOKUP_CSV"
            echo "    int_allow: p50=$(echo "$RESULT" | cut -d, -f1) us" >&2

            kill "$LISTENER_PID" 2>/dev/null || true
            wait "$LISTENER_PID" 2>/dev/null || true
        else
            echo "    SKIP lookup (daemon not ready)" >&2
            echo "$N,$trial,,,," >> "$LOOKUP_CSV"
        fi

        # Kill daemon for next iteration
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        sleep 0.3
    done
done

echo "" >&2
echo "=== Results ===" >&2
echo "Update latency: $UPDATE_CSV" >&2
echo "Lookup scaling: $LOOKUP_CSV" >&2
echo "" >&2
echo "--- Update latency ---" >&2
cat "$UPDATE_CSV" >&2
echo "" >&2
echo "--- Lookup scaling ---" >&2
cat "$LOOKUP_CSV" >&2
