#!/usr/bin/env bash
# run_all.sh -- Run all artifact experiments and print summary tables.
# Usage: sudo ./scripts/run_all.sh
# Runs from proto/. Estimated time: ~2 hours on a 2-CPU VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROTO_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# Preflight
if [[ $EUID -ne 0 ]]; then echo "error: run as root" >&2; exit 1; fi
for cmd in python3 iperf3 nft wg; do
    command -v "$cmd" &>/dev/null || { echo "error: $cmd not found" >&2; exit 1; }
done
[[ -x bin/procroute ]] || { echo "error: run 'make' first" >&2; exit 1; }
mount | grep -q cgroup2 || { echo "error: cgroup v2 not mounted" >&2; exit 1; }

# Loopback alias
ip addr add 10.1.2.3/32 dev lo 2>/dev/null || true

mkdir -p results ../results

# ---- Loopback benchmarks ----
log "=== Phase 1: Loopback benchmarks ==="

# Start daemon with benchmark policy
pkill -f "procroute daemon" 2>/dev/null || true; sleep 1
setsid ./bin/procroute daemon --policy policy/benchmark.yaml </dev/null >daemon.log 2>&1 &
sleep 2
./bin/procroute launch --app corp-browser --policy policy/benchmark.yaml -- true 2>/dev/null

log "Pivot test (~5 min)"
./scripts/test_pivot_block.sh 2>&1 | tail -3

log "Connect latency (~15 min)"
for t in 1 2 3; do
    ./scripts/bench_connect_latency.sh \
        --count 5000 --warmup 200 --port 18080 \
        --output results/connect_latency_trial${t}.csv 2>/dev/null
done
log "  done"

log "Throughput (~2 min)"
./scripts/bench_throughput.sh --duration 5 --output results/throughput.csv 2>/dev/null
log "  done"

log "Policy scaling (~20 min)"
pkill -f "procroute daemon" 2>/dev/null || true; sleep 1
./scripts/bench_policy_scaling.sh --trials 2 2>&1 | grep -E "^(---|=)" || true
log "  done"

log "nftables comparison (~10 min)"
./scripts/bench_nftables_baseline.sh 2>&1 | tail -3
log "  done"

log "eval_baremetal (~30 min)"
./scripts/eval_baremetal.sh --skip-deps --skip-build 2>&1 | grep -E "^\[|Phase|complete" || true
log "  done"

# ---- WireGuard benchmarks ----
log "=== Phase 2: WireGuard benchmarks ==="

./scripts/wg_ns.sh down 2>/dev/null || true
./scripts/wg_ns.sh up 2>&1 | tail -1

log "WG throughput (~10 min)"
./scripts/bench_wg_throughput.sh --trials 5 --duration 5 \
    --output results/wg_tp.csv 2>&1 | grep -E "Config:|done"

log "WG latency (~5 min)"
./scripts/bench_wg_latency.sh --output results/wg_lat.csv 2>&1 | grep -E "Config:|done"

log "WG multistream (~10 min)"
./scripts/bench_wg_multistream.sh --trials 3 --duration 5 \
    --output results/wg_ms.csv 2>&1 | grep -E "Config:|done"

log "WG policy scaling (~10 min)"
./scripts/bench_wg_policy_scaling.sh --trials 2 \
    --output results/wg_sc.csv 2>&1 | grep -E "Config:|done" || true

log "WG revocation (~5 min)"
./scripts/bench_wg_revocation.sh --output results/wg_rev.csv 2>&1 | grep -E "Config:|done" || true

./scripts/wg_ns.sh down

# ---- Summary ----
log "=== Phase 3: Summary ==="
echo ""
./scripts/summarize_results.sh --results-dir ../results --wg-dir results
echo ""
log "All experiments complete. Results in proto/results/ and results/."
