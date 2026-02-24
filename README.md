# ProcRoute

Per-process route authorization for split-tunnel VPN/ZTNA on Linux.
Uses cgroup v2 + eBPF to restrict internal routes to authorized apps.

Accepted at [SACMAT 2026](https://www.sacmat.org/2026/).

## Build

```bash
sudo apt-get install clang llvm libbpf-dev make golang iperf3 python3
cd proto && make
```

Requires Linux 5.8+ with cgroup v2 and root.

## Usage

```bash
# start daemon
sudo ./bin/procroute daemon --policy policy/example.yaml

# run an authorized app (in another terminal)
sudo ./bin/procroute launch --app corp-browser \
    --policy policy/example.yaml -- curl -so /dev/null https://10.1.2.3
```

See [ARTIFACT.md](ARTIFACT.md) for reproducing the paper's experiments.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
