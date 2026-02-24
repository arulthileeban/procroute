#!/usr/bin/env bash
# eval_wg_all.sh -- Master runner for all WireGuard evaluation benchmarks.
# Runs the full WireGuard evaluation suite:
#   1. Preflight checks
#   2. Build prototype
#   3. Set up WireGuard testbed
#   4. Run throughput benchmark
#   5. Run latency benchmark
#   6. Run flow cache hit rate benchmark
#   7. Run multi-stream throughput benchmark
#   8. Run CPU utilization benchmark
#   9. Run revocation latency benchmark
#  10. Run policy scaling benchmark
#  11. Generate plots (if matplotlib available)
#  12. Collect system info
#  13. Print summary
# Usage:
#   sudo ./scripts/eval_wg_all.sh [options]
# Options:
#   --skip-build        Skip build step
#   --skip-throughput   Skip throughput benchmark
#   --skip-latency      Skip latency benchmark
#   --skip-flowcache    Skip flow cache benchmark
#   --skip-multistream  Skip multi-stream benchmark
#   --skip-cpu          Skip CPU benchmark
#   --skip-revocation   Skip revocation benchmark
#   --skip-scaling      Skip policy scaling benchmark
#   --skip-plots        Skip plot generation
#   --trials N          Override trial count for all benchmarks (default 10)
#   --duration N        Override iperf3 duration (default 10)
#   --output-dir DIR    Results directory (default proto/results/wg_eval_<timestamp>)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${PROTO_DIR}/bin/procroute"

SKIP_BUILD=0
SKIP_THROUGHPUT=0
SKIP_LATENCY=0
SKIP_FLOWCACHE=0
SKIP_MULTISTREAM=0
SKIP_CPU=0
SKIP_REVOCATION=0
SKIP_SCALING=0
SKIP_PLOTS=0
TRIALS=10
DURATION=10
TCP_COUNT=2000
TCP_WARMUP=200
LATENCY_TIMEOUT=300
RESULTS_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)     SKIP_BUILD=1;      shift ;;
        --skip-throughput) SKIP_THROUGHPUT=1; shift ;;
        --skip-latency)   SKIP_LATENCY=1;    shift ;;
        --skip-flowcache) SKIP_FLOWCACHE=1;  shift ;;
        --skip-multistream) SKIP_MULTISTREAM=1; shift ;;
        --skip-cpu)       SKIP_CPU=1;        shift ;;
        --skip-revocation) SKIP_REVOCATION=1; shift ;;
        --skip-scaling)   SKIP_SCALING=1;    shift ;;
        --skip-plots)     SKIP_PLOTS=1;      shift ;;
        --trials)         TRIALS="$2";       shift 2 ;;
        --duration)       DURATION="$2";     shift 2 ;;
        --tcp-count)      TCP_COUNT="$2";    shift 2 ;;
        --tcp-warmup)     TCP_WARMUP="$2";   shift 2 ;;
        --latency-timeout) LATENCY_TIMEOUT="$2"; shift 2 ;;
        --output-dir)     RESULTS_DIR="$2";  shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [[ -z "$RESULTS_DIR" ]]; then
    RESULTS_DIR="${PROTO_DIR}/results/wg_eval_${TIMESTAMP}"
fi

# Logging
log()  { echo "[$(date '+%H:%M:%S')] $*" >&2; }
warn() { echo "[$(date '+%H:%M:%S')] WARNING: $*" >&2; }

# Cleanup
cleanup() {
    local ec=$?
    log "Cleanup"
    # Tear down testbed
    "$SCRIPT_DIR/wg_ns.sh" down 2>/dev/null || true
    # Remove cgroups
    if [[ -d /sys/fs/cgroup/procroute ]]; then
        find /sys/fs/cgroup/procroute -mindepth 1 -type d 2>/dev/null | sort -r | while read -r d; do
            rmdir "$d" 2>/dev/null || true
        done
        rmdir /sys/fs/cgroup/procroute 2>/dev/null || true
    fi
    if [[ $ec -eq 0 ]]; then
        log "Evaluation complete (success)"
    else
        log "Evaluation complete (exit code $ec)"
    fi
}
trap cleanup EXIT

# Phase 0: Preflight
log "Phase 0: Preflight checks"

if [[ $EUID -ne 0 ]]; then
    echo "error: must be run as root" >&2
    exit 1
fi

for cmd in python3 wg ip; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd is required" >&2
        exit 1
    fi
done

if ! command -v iperf3 &>/dev/null; then
    warn "iperf3 not found -- throughput and some flow cache tests will be skipped"
fi

mkdir -p "$RESULTS_DIR"
log "  results dir: $RESULTS_DIR"

# Phase 1: Build
if [[ $SKIP_BUILD -eq 1 ]]; then
    log "Phase 1: Skipping build"
else
    log "Phase 1: Building prototype"
    make -C "$PROTO_DIR" clean all 2>&1 | tail -5
    if [[ ! -x "$BINARY" ]]; then
        echo "error: build failed -- $BINARY not found" >&2
        exit 1
    fi
    log "  build successful"
fi

# Phase 2: Set up WireGuard testbed
log "Phase 2: Setting up WireGuard testbed"
"$SCRIPT_DIR/wg_ns.sh" down 2>/dev/null || true
"$SCRIPT_DIR/wg_ns.sh" up 2>&1 | tee "$RESULTS_DIR/testbed.log" | while IFS= read -r line; do log "  $line"; done
log "  testbed ready"

# Phase 3: Throughput benchmark
if [[ $SKIP_THROUGHPUT -eq 1 ]]; then
    log "Phase 3: Skipping throughput benchmark"
else
    log "Phase 3: Throughput benchmark (trials=$TRIALS, duration=${DURATION}s)"
    THROUGHPUT_CSV="$RESULTS_DIR/wg_throughput.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_throughput.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_throughput.sh" \
            --trials "$TRIALS" \
            --duration "$DURATION" \
            --output "$THROUGHPUT_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_throughput.sh failed"
        log "  -> $THROUGHPUT_CSV"
    else
        warn "bench_wg_throughput.sh not found"
    fi
fi

# Ensure testbed is still up after throughput test
if ! ip netns list | grep -qw ns_client; then
    log "  re-creating testbed"
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 4: Latency benchmark
if [[ $SKIP_LATENCY -eq 1 ]]; then
    log "Phase 4: Skipping latency benchmark"
else
    log "Phase 4: Latency benchmark"
    LATENCY_CSV="$RESULTS_DIR/wg_latency.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_latency.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_latency.sh" \
            --tcp-count "$TCP_COUNT" \
            --tcp-warmup "$TCP_WARMUP" \
            --timeout "$LATENCY_TIMEOUT" \
            --output "$LATENCY_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_latency.sh failed"
        log "  -> $LATENCY_CSV"
    else
        warn "bench_wg_latency.sh not found"
    fi
fi

# Ensure testbed is still up
if ! ip netns list | grep -qw ns_client; then
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 5: Flow cache hit rate
if [[ $SKIP_FLOWCACHE -eq 1 ]]; then
    log "Phase 5: Skipping flow cache benchmark"
else
    log "Phase 5: Flow cache hit rate benchmark"
    FLOWCACHE_CSV="$RESULTS_DIR/wg_flowcache.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_flowcache_hit_rate.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_flowcache_hit_rate.sh" \
            --output "$FLOWCACHE_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_flowcache_hit_rate.sh failed"
        log "  -> $FLOWCACHE_CSV"
    else
        warn "bench_wg_flowcache_hit_rate.sh not found"
    fi
fi

# Ensure testbed is still up
if ! ip netns list | grep -qw ns_client; then
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 6: Multi-stream throughput
if [[ $SKIP_MULTISTREAM -eq 1 ]]; then
    log "Phase 6: Skipping multi-stream benchmark"
else
    log "Phase 6: Multi-stream throughput benchmark (trials=$TRIALS, duration=${DURATION}s)"
    MULTISTREAM_CSV="$RESULTS_DIR/wg_multistream.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_multistream.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_multistream.sh" \
            --trials "$TRIALS" \
            --duration "$DURATION" \
            --output "$MULTISTREAM_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_multistream.sh failed"
        log "  -> $MULTISTREAM_CSV"
    else
        warn "bench_wg_multistream.sh not found"
    fi
fi

# Ensure testbed is still up
if ! ip netns list | grep -qw ns_client; then
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 7: CPU utilization
if [[ $SKIP_CPU -eq 1 ]]; then
    log "Phase 7: Skipping CPU benchmark"
else
    log "Phase 7: CPU utilization benchmark (trials=$TRIALS, duration=${DURATION}s)"
    CPU_CSV="$RESULTS_DIR/wg_cpu.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_cpu.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_cpu.sh" \
            --trials "$TRIALS" \
            --duration "$DURATION" \
            --output "$CPU_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_cpu.sh failed"
        log "  -> $CPU_CSV"
    else
        warn "bench_wg_cpu.sh not found"
    fi
fi

# Ensure testbed is still up
if ! ip netns list | grep -qw ns_client; then
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 8: Revocation latency
if [[ $SKIP_REVOCATION -eq 1 ]]; then
    log "Phase 8: Skipping revocation benchmark"
else
    log "Phase 8: Revocation latency benchmark (trials=$TRIALS)"
    REVOCATION_CSV="$RESULTS_DIR/wg_revocation.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_revocation.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_revocation.sh" \
            --trials "$TRIALS" \
            --output "$REVOCATION_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_revocation.sh failed"
        log "  -> $REVOCATION_CSV"
    else
        warn "bench_wg_revocation.sh not found"
    fi
fi

# Ensure testbed is still up
if ! ip netns list | grep -qw ns_client; then
    "$SCRIPT_DIR/wg_ns.sh" up >/dev/null 2>&1
fi

# Phase 9: Policy scaling
if [[ $SKIP_SCALING -eq 1 ]]; then
    log "Phase 9: Skipping policy scaling benchmark"
else
    log "Phase 9: Policy scaling benchmark"
    SCALING_CSV="$RESULTS_DIR/wg_scaling.csv"
    if [[ -x "$SCRIPT_DIR/bench_wg_policy_scaling.sh" ]]; then
        "$SCRIPT_DIR/bench_wg_policy_scaling.sh" \
            --trials 3 \
            --output "$SCALING_CSV" \
            2>&1 | while IFS= read -r line; do log "  $line"; done || \
            warn "bench_wg_policy_scaling.sh failed"
        log "  -> $SCALING_CSV"
    else
        warn "bench_wg_policy_scaling.sh not found"
    fi
fi

# Phase 10: Generate plots
if [[ $SKIP_PLOTS -eq 1 ]]; then
    log "Phase 10: Skipping plot generation"
else
    log "Phase 10: Generating plots"
    PLOTTER="${PROTO_DIR}/tools/plot_wg_eval.py"
    if [[ -f "$PLOTTER" ]]; then
        if python3 -c "import matplotlib" 2>/dev/null; then
            python3 "$PLOTTER" --results-dir "$RESULTS_DIR" --output-dir "$RESULTS_DIR" \
                2>&1 | while IFS= read -r line; do log "  $line"; done || \
                warn "plot_wg_eval.py failed"
        else
            warn "matplotlib not available -- skipping plots"
        fi
    else
        warn "plot_wg_eval.py not found at $PLOTTER"
    fi
fi

# Phase 11: System info
log "Phase 11: Collecting system info"
SYSINFO="$RESULTS_DIR/system_info.txt"
{
    echo "=== WireGuard Evaluation System Info ==="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "=== Kernel ==="
    uname -a
    echo ""
    echo "=== CPU ==="
    lscpu 2>/dev/null | head -20 || echo "(not available)"
    echo ""
    echo "=== Memory ==="
    free -h 2>/dev/null || echo "(not available)"
    echo ""
    echo "=== WireGuard ==="
    wg --version 2>/dev/null || echo "(not available)"
    echo ""
    echo "=== CPU governor ==="
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "(not available)"
    echo ""
    echo "=== Virtualization ==="
    systemd-detect-virt 2>/dev/null || echo "(not available)"
    echo ""
} > "$SYSINFO"
log "  -> $SYSINFO"

# Phase 12: Summary
log ""
log "==============================================="
log "  WireGuard Evaluation Complete"
log "  Results: $RESULTS_DIR"
log "==============================================="
log ""
log "Output files:"
for f in "$RESULTS_DIR"/*.csv "$RESULTS_DIR"/*.pdf "$RESULTS_DIR"/*.tex; do
    [[ -f "$f" ]] && log "  $(basename "$f")"
done
