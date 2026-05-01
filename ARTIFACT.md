# ProcRoute Artifact

Repository: https://github.com/arulthileeban/procroute

## Overview

ProcRoute prototype and scripts to reproduce the evaluation. eBPF + Go,
runs on Linux with cgroup v2. No external datasets -- experiments generate
their own workloads.

## Setup

Tested on Ubuntu 22.04+ and WSL2 (kernel 6.1+). Needs root for BPF.

```bash
sudo apt-get install clang llvm libbpf-dev make golang iperf3 python3 nftables wireguard-tools
```

Check your system:
```bash
uname -r                             # >= 5.8
mount | grep cgroup2                 # should show /sys/fs/cgroup
```

Add a loopback alias used by the latency and policy-scaling benchmarks:
```bash
sudo ip addr add 10.1.2.3/32 dev lo   # does not survive reboot
```

We used a VirtualBox VM with Ubuntu 24.04 (2 CPUs, 4 GB RAM) for development.

## Build and run

```bash
cd proto
make

# start daemon (terminal 1)
sudo ./bin/procroute daemon --policy policy/example.yaml \
    2>daemon.log | tee deny_events.jsonl

# launch authorized app (terminal 2)
sudo ./bin/procroute launch --app corp-browser \
    --policy policy/example.yaml \
    -- curl -so /dev/null https://10.1.2.3
```

## Reproducing the evaluation

All commands below run from `proto/`. Estimated total time: ~2 hours on
a 2-CPU VM (individual estimates below).

First, restart the daemon with the benchmark policy (no `exec_hash`
verification, so `iperf3`/`python3` are not rejected):

```bash
# stop any running daemon, then start with benchmark policy
sudo pkill procroute; sleep 1
sudo ./bin/procroute daemon --policy policy/benchmark.yaml \
    2>daemon.log | tee deny_events.jsonl &
# register the corp-browser cgroup for benchmarks
sudo ./bin/procroute launch --app corp-browser \
    --policy policy/benchmark.yaml -- true
```

**Pivot test** (~5 min, Table 7 / App A.2):
```bash
sudo ./scripts/test_pivot_block.sh
```
Should print 82/82 blocked.

**Connect latency** (~15 min, Table 6 / App A.1):
```bash
mkdir -p results
for t in 1 2 3 4 5; do
    sudo ./scripts/bench_connect_latency.sh \
        --count 10000 --warmup 500 --port 18080 \
        --output results/connect_latency_trial${t}.csv
    sleep 2
done
```
Baseline p50 ~23 us, internal-allow ~26 us on bare metal;
expect higher absolute values on a VM.

**Throughput** (~2 min, Table 1 / App A.1):
```bash
sudo ./scripts/bench_throughput.sh --duration 10 \
    --output results/throughput.csv
```

**Policy scaling** (~20 min, Table 8 / App A.3):
```bash
sudo ./scripts/bench_policy_scaling.sh
```
Results go to `results/policy_scaling_*.csv`.

**Update safety and revocation** (~30 min, Table 9 / App A.4, Table 11 / App A.6):
```bash
sudo ./scripts/eval_baremetal.sh --skip-deps --skip-build
```
Results go to `results/eval_<timestamp>/`. Should show 0 transient allows.

**nftables comparison** (~10 min, Table 10 / App A.5):
```bash
sudo ./scripts/bench_nftables_baseline.sh
```
Results go to `results/nft_latency.csv` and `results/bpf_latency.csv`.

### WireGuard (Sec. 6.3, ~30 min)

Set up the network-namespace testbed (single machine, no second VM needed):
```bash
sudo ./scripts/wg_ns.sh up
```

Individual experiments:
```bash
sudo ./scripts/bench_wg_throughput.sh --output results/wg_tp.csv       # Table 2
sudo ./scripts/bench_wg_latency.sh --output results/wg_lat.csv         # Table 2
sudo ./scripts/bench_wg_multistream.sh --output results/wg_ms.csv      # Table 3
sudo ./scripts/bench_wg_policy_scaling.sh --output results/wg_sc.csv   # Table 4
sudo ./scripts/bench_wg_revocation.sh --output results/wg_rev.csv      # Table 5
```

Or all at once: `sudo ./scripts/eval_wg_all.sh --output-dir results/wg/`

Teardown: `sudo ./scripts/wg_ns.sh down`

The `wg_nftables` row in Tables 2--3 used a manual nftables cgroupv2
socket-match configuration on the gateway; the raw data from our
hardware run is in `proto/results/wg_baremetal_<timestamp>/`.

## Summarizing results

After running the experiments, generate formatted tables matching the paper:
```bash
./scripts/summarize_results.sh
```
Use `--results-dir` and `--wg-dir` if CSVs are in non-default locations.
Output is printed to stdout as ASCII tables. Table 1 (summary) and
Table 7 (pivot matrix) are not computed -- Table 1 aggregates the
others; Table 7 is deterministic (82/82 blocked).

## Notes

Absolute numbers depend on hardware. The important things are:
- Connect overhead is a few microseconds
- Throughput overhead <10%
- 82/82 pivot attempts blocked (deterministic)
- 0 transient allows during reload (deterministic)
- Policy scaling is flat

Scripts output CSVs. Policy format is in `proto/policy/schema.json`,
example in `proto/policy/example.yaml`.
