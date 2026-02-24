#!/usr/bin/env bash
# vm-setup.sh -- Provision a fresh Ubuntu 24.04 VM for ProcRoute artifact evaluation.
# Run this as root (or with sudo) inside the VM after cloning the repo.
set -euo pipefail

echo "=== ProcRoute VM Setup ==="

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y \
    clang llvm libbpf-dev make golang-go \
    iperf3 python3 python3-matplotlib \
    iproute2 nftables iputils-ping curl netcat-openbsd \
    wireguard-tools \
    ca-certificates git

# Verify kernel and cgroup v2
echo ""
echo "=== System checks ==="
echo "Kernel: $(uname -r)"

if ! mount | grep -q cgroup2; then
    echo "WARNING: cgroup v2 not mounted. Ensure your kernel supports it."
else
    echo "cgroup v2: OK ($(mount | grep cgroup2 | awk '{print $3}'))"
fi

CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "MISSING")
echo "Controllers: $CONTROLLERS"

# Build the prototype
echo ""
echo "=== Building prototype ==="
cd "$(dirname "$0")/proto"
make clean all
echo "Binary: $(ls -lh bin/procroute | awk '{print $5, $NF}')"

# Quick sanity test
echo ""
echo "=== Sanity check ==="
./bin/procroute --help 2>&1 | head -3 || true

echo ""
echo "=== Setup complete ==="
echo "Next steps:"
echo "  cd proto"
echo "  sudo ./bin/procroute daemon --policy policy/example.yaml"
echo "  sudo ./scripts/test_pivot_block.sh"
echo ""
echo "See ARTIFACT.md for full evaluation instructions."
