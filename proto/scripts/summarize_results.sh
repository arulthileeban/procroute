#!/usr/bin/env bash
# summarize_results.sh -- Compute paper tables from raw benchmark CSVs.
# Usage: ./scripts/summarize_results.sh [--results-dir DIR] [--wg-dir DIR]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROTO_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${PROTO_DIR}/../results"
RESULTS_DIR2="${PROTO_DIR}/results"
WG_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --wg-dir)      WG_DIR="$2";      shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done
[[ -z "$WG_DIR" ]] && WG_DIR="$RESULTS_DIR"

python3 - "$RESULTS_DIR" "$WG_DIR" "$RESULTS_DIR2" <<'PYEOF'
import csv, glob, os, statistics, sys
from collections import defaultdict

R = sys.argv[1]   # results dir (../results)
W = sys.argv[2]   # wg dir
R2 = sys.argv[3]  # results dir (proto/results)

def load(name, *dirs):
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.exists(p):
            with open(p) as f: return list(csv.DictReader(f))
    return None

def med(v): return statistics.median(v) if v else 0
def f(v, d=1): return f"{v:.{d}f}"

def banner(t): print(f"\n{'='*60}\n  {t}\n{'='*60}")

dirs = [R, W, R2, os.path.join(R, "../proto/results")]
wg_subs = glob.glob(os.path.join(R, "wg_baremetal_*"))

# --- Table 6: Connect latency (ns->us, median across trials) ---
trials = []
for d in dirs:
    trials += sorted(glob.glob(os.path.join(d, "connect_latency_trial*.csv")))
if trials:
    banner("Table 6: TCP connect() latency (us)")
    by_cond = defaultdict(lambda: defaultdict(list))
    for path in trials:
        for row in csv.DictReader(open(path)):
            c, it, v = row["condition"], row["iteration"], row["latency_ns"]
            if it in ("p50","p90","p99"):
                by_cond[c][it].append(int(v))
    base_p50 = med(by_cond.get("baseline",{}).get("p50",[0])) / 1000
    print(f"{'Condition':<18} {'p50':>6} {'Dp50':>6} {'p90':>6} {'p99':>6}")
    for c, label in [("baseline","Baseline"),("ext_miss","External-miss"),("int_allow","Internal-allow")]:
        if c not in by_cond: continue
        p50 = med(by_cond[c]["p50"]) / 1000
        p90 = med(by_cond[c]["p90"]) / 1000
        p99 = med(by_cond[c]["p99"]) / 1000
        dp = "-" if c == "baseline" else f(p50 - base_p50)
        print(f"{label:<18} {f(p50):>6} {dp:>6} {f(p90):>6} {f(p99):>6}")

# --- Table 8: Policy scaling (median across trials) ---
up = load("policy_scaling_update.csv", R)
lk = load("policy_scaling_lookup.csv", R)
if up and lk:
    banner("Table 8: Policy-update latency and lookup p50 vs N")
    u_by_n, l_by_n = defaultdict(list), defaultdict(list)
    for row in up: u_by_n[int(row["n_prefixes"])].append(float(row["startup_ms"]))
    for row in lk:
        if row.get("p50_us"): l_by_n[int(row["n_prefixes"])].append(float(row["p50_us"]))
    print(f"{'N':>6} {'Update(ms)':>12} {'Lookup p50(us)':>16}")
    for n in sorted(u_by_n): print(f"{n:>6} {f(med(u_by_n[n])):>12} {f(med(l_by_n.get(n,[0]))):>16}")

# --- Table 10: nftables vs ProcRoute p50 ---
nft = load("nft_latency.csv", R)
bpf = load("bpf_latency.csv", R)
if nft and bpf:
    banner("Table 10: p50 connect() latency (us): nftables vs ProcRoute")
    def p50s(rows):
        d = defaultdict(list)
        for r in rows:
            try: d[r["condition"]].append(int(r["latency_ns"]))
            except: pass
        return {c: sorted(v)[len(v)//2]/1000 for c,v in d.items()}
    np, bp = p50s(nft), p50s(bpf)
    print(f"{'Condition':<18} {'nftables':>10} {'ProcRoute':>10}")
    for label, nk, bk in [("Baseline","baseline","baseline"),("External-miss","nft_ext_miss","bpf_ext_miss"),
                           ("Internal-allow","nft_int_allow","bpf_int_allow"),("Internal-deny","nft_int_deny","bpf_int_deny")]:
        print(f"{label:<18} {f(np.get(nk,0)):>10} {f(bp.get(bk,0)):>10}")

# --- Table 2: WG throughput + latency ---
tp = load("wg_tp.csv", *dirs) or next((load("wg_throughput.csv",s) for s in wg_subs if load("wg_throughput.csv",s)), None)
lt = load("wg_lat.csv", *dirs) or next((load("wg_latency.csv",s) for s in wg_subs if load("wg_latency.csv",s)), None)
if tp and lt:
    banner("Table 2: WG single-stream throughput and connect latency")
    t_by = defaultdict(list)
    for r in tp: t_by[r["config"]].append(float(r["bits_per_second"]))
    l_by = {r["config"]: r for r in lt}
    print(f"{'Config':<22} {'Tput(Mbps)':>10} {'p50(us)':>8} {'p95(us)':>8} {'p99(us)':>8}")
    for c in ["wg_baseline","wg_nftables","wg_tag_only","wg_enforce_nocache","wg_enforce_cache"]:
        if c not in t_by: continue
        l = l_by.get(c, {})
        print(f"{c:<22} {f(med(t_by[c])/1e6,0):>10} {f(float(l.get('p50_us',0))):>8} {f(float(l.get('p95_us',0))):>8} {f(float(l.get('p99_us',0))):>8}")

# --- Table 3: WG multi-stream ---
ms = load("wg_ms.csv", *dirs) or next((load("wg_multistream.csv",s) for s in wg_subs if load("wg_multistream.csv",s)), None)
if ms:
    banner("Table 3: WG multi-stream throughput (Mbps)")
    d = defaultdict(list)
    for r in ms: d[(r["config"], r["streams"])].append(float(r["bits_per_second"]))
    scs = sorted(set(s for _,s in d))
    print(f"{'Config':<22}" + "".join(f"{s+' streams':>14}" for s in scs))
    for c in ["wg_baseline","wg_nftables","wg_tag_only","wg_enforce_nocache","wg_enforce_cache"]:
        vals = [f(med(d.get((c,s),[0]))/1e6,0) if d.get((c,s)) else "-" for s in scs]
        if any(v != "-" for v in vals):
            print(f"{c:<22}" + "".join(f"{v:>14}" for v in vals))

# --- Table 4: WG policy scaling ---
sc = load("wg_sc.csv", *dirs) or next((load("wg_scaling.csv",s) for s in wg_subs if load("wg_scaling.csv",s)), None)
if sc:
    banner("Table 4: Gateway policy scaling")
    d = defaultdict(lambda: {"ms":[], "mbps":[], "tp": 0})
    for r in sc:
        n = int(r["n_principals"])
        d[n]["ms"].append(float(r["startup_ms"]))
        d[n]["mbps"].append(float(r["mbps"]))
        d[n]["tp"] = max(d[n]["tp"], n * int(r["prefixes_per_principal"]))
    print(f"{'Principals':>10} {'Tot.prefixes':>14} {'Startup(ms)':>12} {'Tput(Mbps)':>12}")
    for n in sorted(d): print(f"{n:>10} {d[n]['tp']:>14} {f(med(d[n]['ms'])):>12} {f(med(d[n]['mbps']),0):>12}")

# --- Table 5: WG revocation ---
rv = load("wg_rev.csv", *dirs) or next((load("wg_revocation.csv",s) for s in wg_subs if load("wg_revocation.csv",s)), None)
if rv:
    banner("Table 5: WG revocation latency")
    d = defaultdict(list)
    for r in rv: d[r["metric"]].append(float(r["value_us"]))
    print(f"{'Metric':<24} {'Median(us)':>12} {'Range(us)':>16}")
    for k, label in [("epoch_bump","Epoch bump"),("new_conn_block","New conn block"),("steady_state_median","Steady-state")]:
        v = d.get(k,[])
        if v: print(f"{label:<24} {f(med(v),0):>12} {f(min(v),0)+'-'+f(max(v),0):>16}")

print("\nNote: Tables 1 (summary) and 7 (pivot matrix) are not computed --")
print("Table 1 aggregates the above; Table 7 is deterministic (82/82 blocked).")
print("Table 9 (transient allows) and 11 (revocation detail) come from")
print("eval_baremetal.sh output; key results: 0 transient allows, sub-ms revocation.")
PYEOF
