#!/usr/bin/env bash
# eval_baremetal.sh -- One-shot bare-metal evaluation for ProcRoute.
# Runs the full evaluation suite on a fresh Ubuntu/Debian bare-metal server:
#   Phase 0: Preflight checks
#   Phase 1: Dependency installation
#   Phase 2: Build
#   Phase 3: System preparation
#   Phase 4: Scaling experiments (2D sweep: prefixes x principals)
#   Phase 5: Full benchmark suite
#   Phase 6: System info collection
#   Phase 7: Package results
#   Phase 8: Cleanup (EXIT trap -- always runs)
# Usage:
#   sudo bash proto/scripts/eval_baremetal.sh [--skip-deps] [--skip-scaling] [--skip-suite]
# Environment overrides:
#   SKIP_DEPS=1         Skip dependency installation
#   SKIP_SCALING=1      Skip the scaling experiment sweep
#   SKIP_FULL_SUITE=1   Skip the full benchmark suite
#   PREFIX_SIZES="4 16" Override prefix sweep sizes
#   PRINCIPAL_SIZES="5" Override principal sweep sizes
#   SCALING_TRIALS=3    Trials per scaling config (default 3)
#   CONNECT_COUNT=2000  Connect iterations per scaling test (default 2000)
#   CONNECT_WARMUP=200  Warmup iterations (default 200)
#   CPU_CORE=0          CPU to pin benchmarks to (default 0)

set -euo pipefail

# Constants & defaults
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$PROTO_DIR")"
BIN="${PROTO_DIR}/bin/procroute"
BPF_SRC="${PROTO_DIR}/bpf/procroute.c"
BPF_OBJ="${PROTO_DIR}/bpf/procroute.o"
PROCROUTE_CG="/sys/fs/cgroup/procroute"
GENERATE_PY="${SCRIPT_DIR}/generate_policy.py"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="${PROTO_DIR}/../results/eval_${TIMESTAMP}"

# Scaling sweep defaults
PREFIX_SIZES="${PREFIX_SIZES:-4 16 64 256 512 1024 2048 4096}"
PRINCIPAL_SIZES="${PRINCIPAL_SIZES:-5 10 25 50 100 200}"
SCALING_TRIALS="${SCALING_TRIALS:-3}"

# Benchmark parameters
CONNECT_COUNT="${CONNECT_COUNT:-2000}"
CONNECT_WARMUP="${CONNECT_WARMUP:-200}"
CPU_CORE="${CPU_CORE:-0}"
LISTENER_CPU="${LISTENER_CPU:-0}"
CLIENT_CPU="${CLIENT_CPU:-1}"
INT_ALLOW_IP="10.1.2.3"
INT_ALLOW_PORT=443
DAEMON_TIMEOUT=60

# Skip flags
SKIP_DEPS="${SKIP_DEPS:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SCALING="${SKIP_SCALING:-0}"
SKIP_FULL_SUITE="${SKIP_FULL_SUITE:-0}"

# Parse CLI args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deps)    SKIP_DEPS=1;       shift ;;
        --skip-build)   SKIP_BUILD=1;      shift ;;
        --skip-scaling) SKIP_SCALING=1;    shift ;;
        --skip-suite)   SKIP_FULL_SUITE=1; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# The daemon opens bpf/procroute.o relative to CWD, so we must run from PROTO_DIR.
# All other paths in this script are absolute, so this is safe.
cd "$PROTO_DIR"

# State tracking
BPF_PATCHED=0        # 1 if we modified procroute.c
BPF_BACKUP=""        # path to original backup
SAVED_GOVERNOR=""    # previous CPU governor
DAEMON_PID=""        # PID of running procroute daemon
LISTENER_PID=""      # PID of TCP listener
LOOPBACK_ALIASES=()  # IPs we added to lo

# Logging helpers
log()  { echo "[$(date '+%H:%M:%S')] $*" >&2; }
warn() { echo "[$(date '+%H:%M:%S')] WARNING: $*" >&2; }
die()  { echo "[$(date '+%H:%M:%S')] FATAL: $*" >&2; exit 1; }

# Cleanup (Phase 8) -- registered as EXIT trap
cleanup() {
    local ec=$?
    log "Phase 8: Cleanup"

    # Kill daemon
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    pkill -f "procroute daemon" 2>/dev/null || true

    # Kill listener
    if [[ -n "$LISTENER_PID" ]]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi

    # Remove loopback aliases
    for alias_ip in "${LOOPBACK_ALIASES[@]}"; do
        ip addr del "${alias_ip}/32" dev lo 2>/dev/null || true
    done

    # Clean cgroups
    rm -rf "${PROCROUTE_CG}" 2>/dev/null || true

    # Restore BPF source
    restore_bpf_source

    # Restore CPU governor
    if [[ -n "$SAVED_GOVERNOR" ]]; then
        for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            echo "$SAVED_GOVERNOR" > "$f" 2>/dev/null || true
        done
        log "  restored CPU governor to $SAVED_GOVERNOR"
    fi

    # Re-enable THP
    echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true

    # Flush any nftables rules we might have added
    nft flush ruleset 2>/dev/null || true

    # Clean temp dir
    [[ -d "${TMPDIR_EVAL:-}" ]] && rm -rf "$TMPDIR_EVAL"

    if [[ $ec -eq 0 ]]; then
        log "Cleanup complete (success)"
    else
        log "Cleanup complete (script exited with code $ec)"
    fi
}
trap cleanup EXIT

TMPDIR_EVAL=$(mktemp -d /tmp/procroute-eval-XXXXXX)

# BPF source patching
# patch_bpf_limits N_PREFIXES N_PRINCIPALS
#   Adjusts max_entries for internal_prefixes_{v4,v6} and app_allow_{v4,v6}
#   in procroute.c.  Backs up the original on first call.
#   Uses Python for context-aware patching since max_entries and the map
#   name are on different lines.
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

    # Back up original on first patch
    if [[ $BPF_PATCHED -eq 0 ]]; then
        BPF_BACKUP="${TMPDIR_EVAL}/procroute.c.orig"
        cp "$BPF_SRC" "$BPF_BACKUP"
    fi

    # Use Python to do context-aware patching: find the map name on its
    # closing line ('} map_name SEC(...)') then search backwards for the
    # nearest max_entries line within the same struct.
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
    print(f'warning: could not patch {map_name}', file=sys.stderr)
    return src

src = patch_map(src, 'internal_prefixes_v4', $prefix_entries)
src = patch_map(src, 'internal_prefixes_v6', $prefix_entries)
src = patch_map(src, 'app_allow_v4', $allow_entries)
src = patch_map(src, 'app_allow_v6', $allow_entries)

with open('$BPF_SRC', 'w') as f:
    f.write(src)
" || die "failed to patch BPF source"

    BPF_PATCHED=1
    log "  patched BPF maps: prefix_entries=${prefix_entries}, allow_entries=${allow_entries}"
}

restore_bpf_source() {
    if [[ $BPF_PATCHED -eq 1 && -n "$BPF_BACKUP" && -f "$BPF_BACKUP" ]]; then
        cp "$BPF_BACKUP" "$BPF_SRC"
        BPF_PATCHED=0
        log "  restored BPF source from backup"
    fi
}

# Daemon management
# wait_daemon_ready PID LOGFILE TIMEOUT
wait_daemon_ready() {
    local pid="$1"
    local logfile="$2"
    local timeout="$3"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if grep -q "daemon ready" "$logfile" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            warn "daemon exited prematurely"
            cat "$logfile" >&2
            return 1
        fi
        sleep 0.1
        elapsed=$((elapsed + 1))
    done
    warn "daemon did not become ready within ${timeout}s"
    return 1
}

kill_daemon() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        DAEMON_PID=""
    fi
    pkill -f "procroute daemon" 2>/dev/null || true
    sleep 0.3
    rm -rf "${PROCROUTE_CG}" 2>/dev/null || true
    sleep 0.2
}

kill_listener() {
    if [[ -n "$LISTENER_PID" ]]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
}

# Connect latency benchmark (embedded Python)
BENCH_CONNECT_PY=$(cat <<'PYEOF'
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

# Phase 0 -- Preflight checks
log "Phase 0: Preflight checks"

if [[ $EUID -ne 0 ]]; then
    die "must be run as root"
fi

# Kernel version check (need >= 5.8 for BPF cgroup hooks)
KVER=$(uname -r)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
if [[ $KMAJOR -lt 5 ]] || { [[ $KMAJOR -eq 5 ]] && [[ $KMINOR -lt 8 ]]; }; then
    die "kernel $KVER too old; need >= 5.8 for BPF cgroup sock_addr hooks"
fi
log "  kernel: $KVER (OK)"

# cgroup v2 check
if ! mount | grep -q "cgroup2"; then
    die "cgroup v2 not mounted"
fi
log "  cgroup v2: mounted (OK)"

# VM detection (warning only)
if command -v systemd-detect-virt &>/dev/null; then
    if systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt 2>/dev/null)
        warn "running inside virtualization: $VIRT -- tail latencies may be unreliable"
    else
        log "  bare metal: yes (OK)"
    fi
fi

# Check that generate_policy.py exists
if [[ ! -f "$GENERATE_PY" ]]; then
    die "generate_policy.py not found at $GENERATE_PY"
fi

log "  results dir: $RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

# Phase 1 -- Dependency installation
if [[ "$SKIP_DEPS" -eq 1 ]]; then
    log "Phase 1: Skipping dependency installation (SKIP_DEPS=1)"
else
    log "Phase 1: Installing dependencies"

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    # Core packages (these should all be available)
    PKGS=(
        build-essential
        clang
        llvm
        libbpf-dev
        "linux-headers-$(uname -r)"
        iperf3
        python3
        python3-yaml
        nftables
        iproute2
        netcat-openbsd
        util-linux
        sysstat
        wget
    )

    apt-get install -y -qq "${PKGS[@]}" || warn "some core packages failed to install"

    # Optional packages (install individually so failures don't block others)
    for pkg in python3-matplotlib; do
        apt-get install -y -qq "$pkg" 2>/dev/null || true
    done

    # bpftool: not a standalone package on Ubuntu 24.04+, lives in linux-tools-*
    if ! command -v bpftool &>/dev/null; then
        apt-get install -y -qq "linux-tools-$(uname -r)" 2>/dev/null || \
        apt-get install -y -qq linux-tools-common "linux-tools-$(uname -r)" 2>/dev/null || \
            warn "bpftool not found -- some benchmarks may fail"
    fi

    # Install Go if missing or too old
    GO_MIN_MINOR=21
    INSTALL_GO=0
    if ! command -v go &>/dev/null; then
        INSTALL_GO=1
    else
        GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
        GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
        GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
        if [[ $GO_MAJOR -lt 1 ]] || { [[ $GO_MAJOR -eq 1 ]] && [[ $GO_MINOR -lt $GO_MIN_MINOR ]]; }; then
            INSTALL_GO=1
        fi
    fi

    if [[ $INSTALL_GO -eq 1 ]]; then
        log "  installing Go 1.22.5..."
        GO_TAR="go1.22.5.linux-amd64.tar.gz"
        wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
        rm -rf /usr/local/go
        tar -C /usr/local -xzf "/tmp/${GO_TAR}"
        rm -f "/tmp/${GO_TAR}"
        export PATH="/usr/local/go/bin:$PATH"
        log "  go version: $(go version)"
    fi

    # Verify critical commands
    for cmd in clang python3 taskset iperf3 bpftool; do
        if ! command -v "$cmd" &>/dev/null; then
            warn "$cmd not found after install"
        fi
    done

    log "  dependencies installed"
fi

# Ensure Go is on PATH (might have been installed in a prior run)
if [[ -d /usr/local/go/bin ]] && ! command -v go &>/dev/null; then
    export PATH="/usr/local/go/bin:$PATH"
fi

# Phase 2 -- Build
if [[ "$SKIP_BUILD" -eq 1 ]]; then
    log "Phase 2: Skipping build (--skip-build)"
else
    log "Phase 2: Building prototype"
    make -C "$PROTO_DIR" clean
    make -C "$PROTO_DIR" all
    log "  build successful"
fi

if [[ ! -x "$BIN" ]]; then
    die "binary not found at $BIN"
fi
if [[ ! -f "$BPF_OBJ" ]]; then
    die "BPF object not found at $BPF_OBJ"
fi

# Phase 3 -- System preparation
log "Phase 3: System preparation"

# Add loopback aliases
add_loopback_alias() {
    local ip="$1"
    if ! ip addr show lo | grep -q "$ip"; then
        ip addr add "${ip}/32" dev lo
        LOOPBACK_ALIASES+=("$ip")
        log "  added loopback alias: $ip"
    else
        log "  loopback alias already present: $ip"
    fi
}

add_loopback_alias "10.1.2.3"
add_loopback_alias "10.0.2.10"

# Kill stale daemons and cgroups
pkill -f "procroute daemon" 2>/dev/null || true
sleep 0.3
rm -rf "${PROCROUTE_CG}" 2>/dev/null || true

# CPU governor -> performance
if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    SAVED_GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
    for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > "$f" 2>/dev/null || true
    done
    log "  CPU governor: $SAVED_GOVERNOR -> performance"
else
    log "  CPU governor: not adjustable (no cpufreq)"
fi

# Disable transparent hugepages (reduces latency jitter)
if [[ -f /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
    log "  THP disabled"
fi

log "  system prepared"

# Phase 4 -- Scaling experiments
if [[ "$SKIP_SCALING" -eq 1 ]]; then
    log "Phase 4: Skipping scaling experiments (SKIP_SCALING=1)"
else
    log "Phase 4: Scaling experiments"
    log "  prefix sizes:    $PREFIX_SIZES"
    log "  principal sizes: $PRINCIPAL_SIZES"
    log "  trials:          $SCALING_TRIALS"
    log "  connect count:   $CONNECT_COUNT (warmup: $CONNECT_WARMUP)"

    UPDATE_CSV="${RESULTS_DIR}/scaling_update_latency.csv"
    LOOKUP_CSV="${RESULTS_DIR}/scaling_lookup_latency.csv"

    echo "n_prefixes,n_principals,trial,startup_ms" > "$UPDATE_CSV"
    echo "n_prefixes,n_principals,trial,p50_us,p90_us,p99_us,mean_us,errors" > "$LOOKUP_CSV"

    # Track whether BPF source needs patching for this config.
    CURRENT_PATCH_KEY=""

    for N in $PREFIX_SIZES; do
        for M in $PRINCIPAL_SIZES; do
            log "--- config: N=$N prefixes, M=$M principals ---"

            # Determine if we need to patch BPF maps
            NEEDS_PATCH=0
            TOTAL_GRANTS=$(( N * M ))
            if [[ $N -gt 1024 ]] || [[ $TOTAL_GRANTS -gt 8192 ]]; then
                NEEDS_PATCH=1
            fi

            PATCH_KEY="${N}_${M}"
            if [[ $NEEDS_PATCH -eq 1 && "$PATCH_KEY" != "$CURRENT_PATCH_KEY" ]]; then
                log "  patching BPF maps for N=$N, M=$M"
                patch_bpf_limits "$N" "$M"
                make -C "$PROTO_DIR" all 2>&1 | tail -3
                CURRENT_PATCH_KEY="$PATCH_KEY"
            elif [[ $NEEDS_PATCH -eq 0 && $BPF_PATCHED -eq 1 ]]; then
                log "  restoring default BPF maps"
                restore_bpf_source
                make -C "$PROTO_DIR" all 2>&1 | tail -3
                CURRENT_PATCH_KEY=""
            fi

            # Generate policy
            POLICY_FILE="${TMPDIR_EVAL}/policy_${N}_${M}.yaml"
            python3 "$GENERATE_PY" --prefixes "$N" --principals "$M" \
                --output "$POLICY_FILE"
            log "  generated policy: $(wc -l < "$POLICY_FILE") lines"

            for trial in $(seq 1 "$SCALING_TRIALS"); do
                log "  trial $trial/$SCALING_TRIALS"

                # Experiment A: startup/update latency
                kill_daemon

                DAEMON_LOG="${TMPDIR_EVAL}/daemon_${N}_${M}_${trial}.log"
                T_START=$(date +%s%N)

                "$BIN" daemon --policy "$POLICY_FILE" > /dev/null 2>"$DAEMON_LOG" &
                DAEMON_PID=$!

                if wait_daemon_ready "$DAEMON_PID" "$DAEMON_LOG" "$DAEMON_TIMEOUT"; then
                    T_END=$(date +%s%N)
                    STARTUP_NS=$(( T_END - T_START ))
                    STARTUP_MS=$(python3 -c "print(f'{$STARTUP_NS / 1_000_000:.2f}')")
                    echo "$N,$M,$trial,$STARTUP_MS" >> "$UPDATE_CSV"
                    log "    startup: ${STARTUP_MS} ms"
                else
                    echo "$N,$M,$trial," >> "$UPDATE_CSV"
                    log "    startup: FAILED"
                    kill_daemon
                    continue
                fi

                # Experiment B: lookup latency
                # The app-0 cgroup is created by the daemon
                APP0_CG="${PROCROUTE_CG}/app-0"
                if [[ -d "$APP0_CG" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then

                    # Start TCP listener on internal IP
                    kill_listener
                    taskset -c "$LISTENER_CPU" python3 -c "
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

                    if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
                        warn "listener failed to start"
                        echo "$N,$M,$trial,,,,," >> "$LOOKUP_CSV"
                        continue
                    fi

                    # Move into app-0 cgroup and run benchmark
                    echo $$ > "${APP0_CG}/cgroup.procs"

                    RESULT=$(taskset -c "$CLIENT_CPU" python3 -c "$BENCH_CONNECT_PY" \
                        "$INT_ALLOW_IP" "$INT_ALLOW_PORT" \
                        "$CONNECT_COUNT" "$CONNECT_WARMUP" 2>/dev/null) || RESULT=",,,,0"

                    echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true

                    echo "$N,$M,$trial,$RESULT" >> "$LOOKUP_CSV"
                    log "    int_allow: p50=$(echo "$RESULT" | cut -d, -f1) us"

                    kill_listener
                else
                    warn "app-0 cgroup not found or daemon not running"
                    echo "$N,$M,$trial,,,,," >> "$LOOKUP_CSV"
                fi

                kill_daemon
            done
        done
    done

    # Restore BPF source after scaling sweep
    if [[ $BPF_PATCHED -eq 1 ]]; then
        restore_bpf_source
        make -C "$PROTO_DIR" all 2>&1 | tail -3
        log "  rebuilt with original BPF map sizes"
    fi

    log "  scaling results:"
    log "    $UPDATE_CSV"
    log "    $LOOKUP_CSV"
fi

# Phase 5 -- Full benchmark suite
SUITE_POLICY="${PROTO_DIR}/policy/benchmark.yaml"
if [[ "$SKIP_FULL_SUITE" -eq 1 ]]; then
    log "Phase 5: Skipping full benchmark suite (SKIP_FULL_SUITE=1)"
elif [[ ! -f "$SUITE_POLICY" ]]; then
    log "Phase 5: Skipping full benchmark suite (example policy not found at $SUITE_POLICY)"
else
    log "Phase 5: Full benchmark suite"

    # Use the example policy -- existing benchmark scripts expect cgroup names
    # from it (corp-browser, vpn-client, etc.).  Phase 4 tests policy scale.

    # Start daemon for the suite
    kill_daemon
    SUITE_LOG="${RESULTS_DIR}/suite_daemon.log"
    "$BIN" daemon --policy "$SUITE_POLICY" > /dev/null 2>"$SUITE_LOG" &
    DAEMON_PID=$!

    # ensure_suite_daemon -- restart the daemon if it died between benchmarks
    ensure_suite_daemon() {
        if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
            return 0  # still running
        fi
        log "  restarting suite daemon"
        kill_daemon
        SUITE_LOG="${RESULTS_DIR}/suite_daemon_$(date +%s).log"
        "$BIN" daemon --policy "$SUITE_POLICY" > /dev/null 2>"$SUITE_LOG" &
        DAEMON_PID=$!
        if ! wait_daemon_ready "$DAEMON_PID" "$SUITE_LOG" "$DAEMON_TIMEOUT"; then
            warn "suite daemon failed to restart"
            return 1
        fi
        log "  suite daemon restarted"
        return 0
    }

    if ! wait_daemon_ready "$DAEMON_PID" "$SUITE_LOG" "$DAEMON_TIMEOUT"; then
        warn "suite daemon failed to start -- skipping suite"
    else
        log "  suite daemon ready"

        # Set up shared environment for sub-scripts
        export PROTO_DIR RESULTS_DIR

        # 5a: Connect latency
        log "  [5a] Connect latency benchmark"
        SUITE_LATENCY="${RESULTS_DIR}/suite_connect_latency.csv"
        if [[ -x "${SCRIPT_DIR}/bench_connect_latency.sh" ]]; then
            "${SCRIPT_DIR}/bench_connect_latency.sh" \
                --policy "$SUITE_POLICY" \
                --output "$SUITE_LATENCY" \
                --count 10000 \
                --warmup 500 \
                2>&1 | while IFS= read -r line; do log "    $line"; done || \
                warn "bench_connect_latency.sh failed"
            log "    -> $SUITE_LATENCY"
        else
            warn "bench_connect_latency.sh not found"
        fi

        # 5b: Connection rate
        ensure_suite_daemon
        log "  [5b] Connection rate benchmark"
        SUITE_CONNRATE="${RESULTS_DIR}/suite_connrate.csv"
        if [[ -x "${SCRIPT_DIR}/bench_connrate.sh" ]]; then
            "${SCRIPT_DIR}/bench_connrate.sh" \
                --output "$SUITE_CONNRATE" \
                --trials 3 \
                2>&1 | while IFS= read -r line; do log "    $line"; done || \
                warn "bench_connrate.sh failed"
            log "    -> $SUITE_CONNRATE"
        else
            warn "bench_connrate.sh not found"
        fi

        # 5c: Throughput
        ensure_suite_daemon
        log "  [5c] Throughput benchmark"
        SUITE_THROUGHPUT="${RESULTS_DIR}/suite_throughput.csv"
        if [[ -x "${SCRIPT_DIR}/bench_throughput.sh" ]]; then
            "${SCRIPT_DIR}/bench_throughput.sh" \
                --policy "$SUITE_POLICY" \
                --output "$SUITE_THROUGHPUT" \
                2>&1 | while IFS= read -r line; do log "    $line"; done || \
                warn "bench_throughput.sh failed"
            log "    -> $SUITE_THROUGHPUT"
        else
            warn "bench_throughput.sh not found"
        fi

        # 5d: Pivot prevention
        ensure_suite_daemon
        log "  [5d] Pivot prevention test"
        SUITE_PIVOT="${RESULTS_DIR}/suite_pivot_block.txt"
        if [[ -x "${SCRIPT_DIR}/test_pivot_block.sh" ]]; then
            "${SCRIPT_DIR}/test_pivot_block.sh" \
                --policy "$SUITE_POLICY" \
                > "$SUITE_PIVOT" 2>&1 || \
                warn "test_pivot_block.sh failed"
            log "    -> $SUITE_PIVOT"
        else
            warn "test_pivot_block.sh not found"
        fi

        # 5e: Update-race safety
        # update_race_demo.sh manages its own daemon
        kill_daemon
        log "  [5e] Update-race safety demo"
        SUITE_RACE="${RESULTS_DIR}/suite_update_race.txt"
        RACE_SCRIPT="${REPO_DIR}/bench/update_race_demo.sh"
        if [[ -x "$RACE_SCRIPT" ]]; then
            PROTO_DIR="$PROTO_DIR" RESULTS_DIR="$RESULTS_DIR" \
                "$RACE_SCRIPT" > "$SUITE_RACE" 2>&1 || \
                warn "update_race_demo.sh failed"
            log "    -> $SUITE_RACE"
        else
            warn "update_race_demo.sh not found at $RACE_SCRIPT"
        fi

        # 5f: Revocation latency
        # revocation_bench.sh expects daemon running
        ensure_suite_daemon
        log "  [5f] Revocation latency benchmark"
        SUITE_REVOC="${RESULTS_DIR}/suite_revocation.txt"
        REVOC_SCRIPT="${REPO_DIR}/bench/revocation_bench.sh"
        if [[ -x "$REVOC_SCRIPT" ]]; then
            PROTO_DIR="$PROTO_DIR" RESULTS_DIR="$RESULTS_DIR" \
                "$REVOC_SCRIPT" > "$SUITE_REVOC" 2>&1 || \
                warn "revocation_bench.sh failed"
            log "    -> $SUITE_REVOC"
        else
            warn "revocation_bench.sh not found at $REVOC_SCRIPT"
        fi

        # 5g: BPF hook runtime histogram
        # Must run while suite daemon is alive (before nftables kills it)
        log "  [5g] BPF hook runtime histogram"
        BPF_RUNTIME_SCRIPT="${REPO_DIR}/bench/read_bpf_runtime.py"
        SUITE_BPF_RT="${RESULTS_DIR}/suite_bpf_runtime.csv"
        if [[ -f "$BPF_RUNTIME_SCRIPT" ]]; then
            python3 "$BPF_RUNTIME_SCRIPT" > "$SUITE_BPF_RT" 2>&1 || \
                warn "read_bpf_runtime.py failed"
            log "    -> $SUITE_BPF_RT"
        else
            warn "read_bpf_runtime.py not found at $BPF_RUNTIME_SCRIPT"
        fi

        # 5h: nftables comparison
        # This needs its own daemon lifecycle, so kill ours first and
        # let the script manage its own.
        log "  [5h] nftables comparison"
        kill_daemon
        SUITE_NFT="${RESULTS_DIR}/suite_nftables.txt"
        if [[ -x "${SCRIPT_DIR}/bench_nftables_baseline.sh" ]]; then
            "${SCRIPT_DIR}/bench_nftables_baseline.sh" \
                > "$SUITE_NFT" 2>&1 || \
                warn "bench_nftables_baseline.sh failed"
            # Copy its result files into our results dir
            for f in "${PROTO_DIR}/../results"/nft_*.csv "${PROTO_DIR}/../results"/bpf_*.csv \
                     "${PROTO_DIR}/../results"/nftables_*.csv; do
                [[ -f "$f" ]] && cp "$f" "$RESULTS_DIR/" 2>/dev/null || true
            done
            log "    -> $SUITE_NFT"
        else
            warn "bench_nftables_baseline.sh not found"
        fi
    fi

    # Clean up suite daemon
    kill_daemon

    log "  full suite complete"
fi

# Phase 6 -- System info collection
log "Phase 6: Collecting system info"

SYSINFO="${RESULTS_DIR}/system_info.txt"
{
    echo "=== ProcRoute Bare-Metal Evaluation ==="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    echo "=== CPU ==="
    lscpu 2>/dev/null || echo "(lscpu not available)"
    echo ""

    echo "=== Memory ==="
    free -h 2>/dev/null || echo "(free not available)"
    echo ""

    echo "=== Kernel ==="
    uname -a
    echo ""

    echo "=== Kernel command line ==="
    cat /proc/cmdline 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== OS Release ==="
    cat /etc/os-release 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== bpftool version ==="
    bpftool version 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== Go version ==="
    go version 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== Clang version ==="
    clang --version 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== Network interfaces ==="
    ip addr show 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== Cgroup mounts ==="
    mount | grep cgroup 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== Virtualization ==="
    systemd-detect-virt 2>/dev/null || echo "(not available)"
    echo ""

    echo "=== NUMA topology ==="
    numactl --hardware 2>/dev/null || echo "(numactl not available)"
    echo ""

    echo "=== CPU governor ==="
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "(not available)"
    echo ""
} > "$SYSINFO"

log "  -> $SYSINFO"

# Phase 7 -- Package results
log "Phase 7: Packaging results"

TARBALL="${PROTO_DIR}/../procroute_eval_${TIMESTAMP}.tar.gz"

# Copy daemon logs into results dir
cp "${TMPDIR_EVAL}"/daemon_*.log "$RESULTS_DIR/" 2>/dev/null || true

tar -czf "$TARBALL" -C "$(dirname "$RESULTS_DIR")" "$(basename "$RESULTS_DIR")"

log "  tarball: $TARBALL"
log ""
log "=== Evaluation complete ==="
log "Results directory: $RESULTS_DIR"
log ""
log "Output files:"
if command -v find &>/dev/null; then
    find "$RESULTS_DIR" -type f -printf "  %-50P  %s bytes\n" 2>/dev/null | sort >&2
fi
log ""
log "Tarball: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
