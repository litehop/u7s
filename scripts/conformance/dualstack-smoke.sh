#!/usr/bin/env bash
# Proves the --dual-stack rig seeding: VM<->VM IPv6 ping and TCP over the
# static ULAs, plus that the seeding survives re-run (idempotence) and a
# reboot of the boot unit. Needs two RUNNING rig VMs on the SAME Lima network.
#
# Usage: scripts/conformance/dualstack-smoke.sh <vm-a> <vm-b>
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

[ $# -eq 2 ] || { echo "usage: $0 <vm-a> <vm-b>" >&2; exit 1; }
A="$1"
B="$2"
ADDR_A=$(lan_v6_addr_for "$A") || { echo "FAIL: no v6 host id for $A" >&2; exit 1; }
ADDR_B=$(lan_v6_addr_for "$B") || { echo "FAIL: no v6 host id for $B" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== seeding $A ($ADDR_A) <-> $B ($ADDR_B)"
lan_v6_seed_mesh "$A" "$B"
echo "=== re-seeding (idempotence)"
lan_v6_seed_mesh "$A" "$B"

IFACE_A=$(lan_v6_vm_iface "$A")
n=$(limactl shell "$A" ip -6 addr show dev "$IFACE_A" | grep -c "$ADDR_A/64" || true)
[ "$n" = "1" ] || fail "$A carries $ADDR_A $n times after re-seed, want exactly 1"

echo "=== ping6 $A -> $B and back"
limactl shell "$A" ping -6 -c3 -W2 "$ADDR_B" || fail "ping6 $A -> $B"
limactl shell "$B" ping -6 -c3 -W2 "$ADDR_A" || fail "ping6 $B -> $A"

echo "=== TCP $A -> $B over v6"
# python3 is in the Ubuntu cloud image; used inside the VM only.
limactl shell "$B" bash -c "nohup timeout 20 python3 -c \"
import socket
s=socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$ADDR_B', 7777)); s.listen(1); c,_=s.accept(); c.sendall(b'pong-v6'); c.close()\" >/dev/null 2>&1 &"
sleep 1
got=$(limactl shell "$A" bash -c "timeout 10 bash -c 'exec 3<>/dev/tcp/$ADDR_B/7777; cat <&3'" || true)
[ "$got" = "pong-v6" ] || fail "TCP $A -> [$ADDR_B]:7777 returned '$got', want 'pong-v6'"

echo "=== boot unit restores state: flush then restart unit"
limactl shell "$A" sudo ip -6 neigh flush dev "$IFACE_A" nud permanent
limactl shell "$A" sudo ip -6 addr flush dev "$IFACE_A" scope global
limactl shell "$A" sudo systemctl restart u7s-lan-v6.service
limactl shell "$A" ping -6 -c2 -W2 "$ADDR_B" || fail "ping6 after unit restart"

echo "PASS: dualstack-smoke $A <-> $B"
