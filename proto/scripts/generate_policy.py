#!/usr/bin/env python3
"""generate_policy.py -- Synthetic ProcRoute policy generator.

Produces valid YAML conforming to proto/policy/schema.json with
configurable numbers of internal prefixes and application principals.

Usage:
    python3 generate_policy.py --prefixes N --principals M --output policy.yaml

The generated policy is deterministic for a given (N, M) pair:
  - First 3 internal prefixes are the RFC 1918 anchors (10.0.0.0/8,
    172.16.0.0/12, 192.168.0.0/16).  Remaining slots are filled with
    10.x.y.0/24 subnets.
  - Principals are named app-0 through app-{M-1}.
  - app-0 always receives a grant for 10.0.0.0/8 on port 443/tcp so
    that the int_allow benchmark target (10.1.2.3:443) always works.
  - Remaining prefixes are distributed round-robin across principals.
  - Port and protocol vary by principal index modulo 5:
      0 -> 443/tcp, 1 -> 22/tcp, 2 -> 53/udp, 3 -> 8080/tcp, 4 -> 443/tcp
"""

import argparse
import sys


# Port/protocol patterns cycled across principals.
PORT_PROTO = [
    ([443], "tcp"),
    ([22],  "tcp"),
    ([53],  "udp"),
    ([8080], "tcp"),
    ([443], "tcp"),
]


def generate_prefixes(n: int) -> list[str]:
    """Return a list of exactly *n* CIDR prefix strings."""
    anchors = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    prefixes = anchors[:n]
    idx = 3
    while len(prefixes) < n:
        b2 = (idx >> 8) & 0xFF
        b3 = idx & 0xFF
        if b2 > 255:
            print("error: cannot generate enough unique prefixes", file=sys.stderr)
            sys.exit(1)
        prefixes.append(f"10.{b2}.{b3}.0/24")
        idx += 1
    return prefixes


def generate_prefixes_v6(n: int) -> list[str]:
    """Return a list of exactly *n* IPv6 ULA CIDR prefix strings."""
    anchors = ["fd00::/8", "fd01::/16", "fd02::/16"]
    prefixes = anchors[:n]
    idx = 3
    while len(prefixes) < n:
        b1 = (idx >> 8) & 0xFFFF
        b2 = idx & 0xFFFF
        if b1 > 0xFFFF:
            print("error: cannot generate enough unique v6 prefixes", file=sys.stderr)
            sys.exit(1)
        prefixes.append(f"fd01:{b1:x}:{b2:x}::/48")
        idx += 1
    return prefixes


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic ProcRoute policy.")
    parser.add_argument("--prefixes", type=int, required=True,
                        help="Number of internal prefixes (>= 1)")
    parser.add_argument("--principals", type=int, required=True,
                        help="Number of application principals (>= 1)")
    parser.add_argument("--output", type=str, default="-",
                        help="Output file path (default: stdout)")
    parser.add_argument("--ipv6", action="store_true",
                        help="Generate IPv6 ULA prefixes instead of IPv4")
    args = parser.parse_args()

    n_prefixes = args.prefixes
    n_principals = args.principals

    if n_prefixes < 1 or n_principals < 1:
        print("error: --prefixes and --principals must be >= 1", file=sys.stderr)
        sys.exit(1)

    if args.ipv6:
        prefixes = generate_prefixes_v6(n_prefixes)
    else:
        prefixes = generate_prefixes(n_prefixes)

    out = sys.stdout if args.output == "-" else open(args.output, "w")
    try:
        _write_policy(out, prefixes, n_principals, ipv6=args.ipv6)
    finally:
        if out is not sys.stdout:
            out.close()


def _write_policy(out, prefixes: list[str], n_principals: int, ipv6: bool = False) -> None:
    w = out.write

    w("version: 1\n\n")
    w("exempt_ports:\n")
    w("  - 19999\n")
    w("  - 15202\n\n")
    w("internal_prefixes:\n")
    for p in prefixes:
        w(f"  - {p}\n")

    w("\napplications:\n")
    for i in range(n_principals):
        app_id = f"app-{i}"
        cgroup = f"/system.slice/app-{i}.service"
        ports, proto = PORT_PROTO[i % len(PORT_PROTO)]
        ports_str = ", ".join(str(p) for p in ports)

        w(f"  - app_id: {app_id}\n")
        w(f"    match:\n")
        w(f"      cgroup: {cgroup}\n")
        w(f"    allow:\n")

        # app-0 always gets an anchor grant so the benchmark target works
        if i == 0:
            anchor = "fd00::/8" if ipv6 else "10.0.0.0/8"
            w(f"      - prefixes:\n")
            w(f"          - {anchor}\n")
            w(f"        ports: [443]\n")
            w(f"        protocol: tcp\n")

        # Round-robin: assign prefixes where (prefix_index % n_principals == i).
        # When n_principals > n_prefixes some apps get nothing from round-robin;
        # give them a wrapped prefix so every app has at least one allow rule.
        app_prefixes = [p for j, p in enumerate(prefixes) if j % n_principals == i]
        if not app_prefixes:
            app_prefixes = [prefixes[i % len(prefixes)]]
        w(f"      - prefixes:\n")
        for ap in app_prefixes:
            w(f"          - {ap}\n")
        w(f"        ports: [{ports_str}]\n")
        w(f"        protocol: {proto}\n")

    w("")


if __name__ == "__main__":
    main()
