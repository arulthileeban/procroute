#!/usr/bin/env bash
# wg_ns.sh -- WireGuard-in-network-namespaces testbed
# Usage: sudo ./wg_ns.sh up | down
set -euo pipefail

# Require root
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root" >&2
  exit 1
fi

# Namespace and interface names
NS_CLIENT="ns_client"
NS_GW="ns_gateway"
NS_SERVER="ns_server"

VETH_CG_C="veth-cg-c"   # client  end (in ns_client)
VETH_CG_G="veth-cg-g"   # gateway end (in ns_gateway)

VETH_GS_G="veth-gs-g"   # gateway end (in ns_gateway)
VETH_GS_S="veth-gs-s"   # server  end (in ns_server)

# IP plan
# outer transport (client <-> gateway) -- IPv4, unchanged
OUTER_CLIENT="192.0.2.2/24"
OUTER_GW="192.0.2.1/24"

# WireGuard tunnel -- IPv6 ULA
WG_CLIENT="fd10:10::2/64"
WG_GW="fd10:10::1/64"
WG_PORT=51820

# internal network (gateway <-> server) -- IPv6 ULA
INT_GW="fd01:2::1/64"
INT_SERVER="fd01:2::3/64"

# Helpers
log() { echo "[wg_ns] $*"; }

gen_keys() {
  # Generate a WireGuard keypair; prints "privatekey publickey"
  local priv pub
  priv=$(wg genkey)
  pub=$(echo "$priv" | wg pubkey)
  echo "$priv $pub"
}

# UP
do_up() {
  log "Creating namespaces ..."
  ip netns add "$NS_CLIENT"
  ip netns add "$NS_GW"
  ip netns add "$NS_SERVER"

  # Bring up loopback in each namespace
  ip netns exec "$NS_CLIENT" ip link set lo up
  ip netns exec "$NS_GW"     ip link set lo up
  ip netns exec "$NS_SERVER"  ip link set lo up

  # veth: client <-> gateway (outer transport, IPv4)
  log "Creating outer veth pair (client <-> gateway) ..."
  ip link add "$VETH_CG_C" type veth peer name "$VETH_CG_G"
  ip link set "$VETH_CG_C" netns "$NS_CLIENT"
  ip link set "$VETH_CG_G" netns "$NS_GW"

  ip netns exec "$NS_CLIENT" ip addr add "$OUTER_CLIENT" dev "$VETH_CG_C"
  ip netns exec "$NS_CLIENT" ip link set "$VETH_CG_C" up

  ip netns exec "$NS_GW" ip addr add "$OUTER_GW" dev "$VETH_CG_G"
  ip netns exec "$NS_GW" ip link set "$VETH_CG_G" up

  # veth: gateway <-> server (internal, IPv6)
  log "Creating internal veth pair (gateway <-> server) ..."
  ip link add "$VETH_GS_G" type veth peer name "$VETH_GS_S"
  ip link set "$VETH_GS_G" netns "$NS_GW"
  ip link set "$VETH_GS_S" netns "$NS_SERVER"

  ip netns exec "$NS_GW" ip -6 addr add "$INT_GW" dev "$VETH_GS_G"
  ip netns exec "$NS_GW" ip link set "$VETH_GS_G" up

  ip netns exec "$NS_SERVER" ip -6 addr add "$INT_SERVER" dev "$VETH_GS_S"
  ip netns exec "$NS_SERVER" ip link set "$VETH_GS_S" up

  # Default route in ns_server back through gateway (IPv6)
  ip netns exec "$NS_SERVER" ip -6 route add default via fd01:2::1

  # WireGuard keys
  log "Generating WireGuard keys ..."
  read -r CLIENT_PRIV CLIENT_PUB <<< "$(gen_keys)"
  read -r GW_PRIV     GW_PUB     <<< "$(gen_keys)"

  # WireGuard interface in ns_gateway
  log "Configuring wg0 in ns_gateway ..."
  ip netns exec "$NS_GW" ip link add wg0 type wireguard
  ip netns exec "$NS_GW" ip -6 addr add "$WG_GW" dev wg0

  # Write temporary key files
  GW_KEY_FILE=$(mktemp)
  echo "$GW_PRIV" > "$GW_KEY_FILE"

  ip netns exec "$NS_GW" wg set wg0 \
    listen-port "$WG_PORT" \
    private-key "$GW_KEY_FILE" \
    peer "$CLIENT_PUB" allowed-ips fd00::/8

  ip netns exec "$NS_GW" ip link set wg0 up
  rm -f "$GW_KEY_FILE"

  # WireGuard interface in ns_client
  log "Configuring wg0 in ns_client ..."
  ip netns exec "$NS_CLIENT" ip link add wg0 type wireguard
  ip netns exec "$NS_CLIENT" ip -6 addr add "$WG_CLIENT" dev wg0

  CLIENT_KEY_FILE=$(mktemp)
  echo "$CLIENT_PRIV" > "$CLIENT_KEY_FILE"

  ip netns exec "$NS_CLIENT" wg set wg0 \
    listen-port 0 \
    private-key "$CLIENT_KEY_FILE" \
    peer "$GW_PUB" allowed-ips fd00::/8 \
    endpoint 192.0.2.1:"$WG_PORT"

  ip netns exec "$NS_CLIENT" ip link set wg0 up
  rm -f "$CLIENT_KEY_FILE"

  # Routing
  log "Setting up routes ..."
  # Client reaches all fd00::/8 via wg0
  ip netns exec "$NS_CLIENT" ip -6 route add fd00::/8 dev wg0

  # Forwarding in ns_gateway
  log "Enabling IPv6 forwarding in ns_gateway ..."
  ip netns exec "$NS_GW" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

  log "Testbed UP."
  log "  outer:    client 192.0.2.2  <-->  gateway 192.0.2.1  (IPv4)"
  log "  wg:       client fd10:10::2 <-->  gateway fd10:10::1 (IPv6)"
  log "  internal: gateway fd01:2::1 <-->  server  fd01:2::3  (IPv6)"
}

# DOWN
do_down() {
  log "Tearing down namespaces ..."
  for ns in "$NS_CLIENT" "$NS_GW" "$NS_SERVER"; do
    if ip netns list | grep -qw "$ns"; then
      ip netns del "$ns"
      log "  deleted $ns"
    else
      log "  $ns not found, skipping"
    fi
  done
  log "Testbed DOWN."
}

# Main
case "${1:-}" in
  up)   do_up   ;;
  down) do_down ;;
  *)
    echo "Usage: $0 {up|down}" >&2
    exit 1
    ;;
esac
