# ProcRoute Prototype

eBPF + cgroup v2 prototype for process-scoped route authorization on Linux.

## Overview

ProcRoute enforces per-process network access control for split-tunnel remote
access. Connections to internal (corporate) IP prefixes are denied by default;
only processes running in explicitly authorized cgroups are allowed through.

**Decision logic** (per connection):
1. Extract destination IP/port/protocol
2. LPM lookup in `internal_prefixes` -- miss -> ALLOW (not internal)
3. Look up cgroup ID -> app identity -- miss -> DENY
4. Per-app LPM lookup for prefix -- miss -> DENY
5. Check port/protocol -- mismatch -> DENY
6. ALLOW

## Prerequisites

```bash
# Ubuntu/Debian (WSL2 works with kernel 6.1+)
sudo apt-get install clang llvm libbpf-dev make golang
```

Requires:
- Linux kernel 5.8+ (cgroup BPF, ring buffer)
- cgroup v2 (default on modern distros and WSL2)
- Root privileges for BPF and cgroup operations

## Build

```bash
make          # compile BPF object + Go binary -> bin/procroute
make clean    # remove artifacts
make fmt      # clang-format + gofmt
```

## Usage

### 1. Start the daemon

```bash
sudo ./bin/procroute daemon --policy policy/example.yaml
```

The daemon:
- Creates cgroup hierarchy under `/sys/fs/cgroup/procroute/`
- Loads BPF programs and attaches to the procroute cgroup
- Populates maps with policy rules
- Streams deny events as JSON to stdout

### 2. Launch an authorized process

```bash
sudo ./bin/procroute launch \
    --app corp-browser \
    --policy policy/example.yaml \
    -- curl https://10.1.2.3
```

This moves the process into `/sys/fs/cgroup/procroute/corp-browser/` and
execs the command. The BPF hook will recognize the cgroup and apply the
app-specific allow rules.

### 3. Test deny behavior

Any process in the procroute cgroup hierarchy without an app binding will
be denied access to internal prefixes:

```bash
# From another terminal, move a shell into the procroute cgroup
echo $$ | sudo tee /sys/fs/cgroup/procroute/cgroup.procs
curl https://10.1.2.3    # -> blocked by BPF, deny event logged
```

## Policy format

See `policy/example.yaml` for a complete example and `policy/schema.json`
for the JSON Schema definition.

## Testing

```bash
sudo ./scripts/test_pivot_block.sh
```

## Benchmarking

```bash
# Start a listener
nc -l -k 8080 &

# Baseline (no BPF)
./scripts/bench_connect.sh --target 127.0.0.1:8080 --count 10000 --output baseline.tsv

# With BPF
sudo ./bin/procroute launch --app corp-browser --policy policy/example.yaml -- \
    ./scripts/bench_connect.sh --target 127.0.0.1:8080 --count 10000 --output bpf.tsv
```

## File structure

```
proto/
├── Makefile
├── go.mod
├── bpf/
│   ├── procroute.c              # BPF programs + maps (4 hooks)
│   └── headers/
│       ├── bpf_helpers.h        # BPF helper stubs
│       ├── bpf_endian.h         # Byte-order macros
│       └── common.h             # Shared structs
├── daemon/
│   ├── main.go                  # CLI entry (daemon + launch)
│   ├── generate.go              # bpf2go directive
│   ├── procroute_amd64.go       # BPF object loader
│   ├── loader.go                # Load, attach, populate maps
│   ├── cgroup.go                # Cgroup hierarchy management
│   ├── policy.go                # YAML policy parser
│   ├── logger.go                # Ring buffer -> JSON deny logs
│   └── types.go                 # Go ↔ BPF struct definitions
├── cmd/procroute/main.go        # Binary entry point
├── policy/
│   ├── example.yaml             # Example policy
│   └── schema.json              # JSON Schema
└── scripts/
    ├── test_pivot_block.sh      # Integration test
    └── bench_connect.sh         # Connect latency benchmark
```
