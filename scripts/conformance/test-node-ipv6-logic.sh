#!/usr/bin/env bash
# Unit tests for lima-start.sh's dual-stack node-IP derivation (mayor-dqd2y).
#
# Root cause: lima's user-v2 network never assigns eth0 a global-scope IPv6
# address (DHCP-assigned IPv4 only, verified live: eth0 carries just a
# link-local fe80:: address). Without a 2nd-family address, kubelet only ever
# reports a single IPv4 node address, and upstream's [Feature:IPv6DualStack]
# "should have at least one dual-stack node" e2e (dual_stack.go) fails on
# every run — see bd mayor-dqd2y / scout mayor-j0g9u.
#
# The fix assigns a per-node ULA (fd85:<octet>::1) to eth0 and passes it to
# kubelet via --node-ip alongside the existing IPv4. This test proves the
# per-node octet derivation cannot collide across a multi-node run (the exact
# bug class the existing POD_SUBNET_OCTET scheme was already built to avoid —
# reusing an already-taken octet would make two nodes fight over the same
# eth0 address) and that lima-start.sh actually wires the derived address into
# both the `ip addr replace` call and the kubelet ExecStart's --node-ip flag
# (not just computes it and drops it).
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016,SC1003 # file-wide: every single-quoted grep pattern below
# intentionally matches the literal, unexpanded source text of lima-start.sh, not
# something meant to expand in this script's own shell.
set -euo pipefail

PASS=0
FAIL=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '${expected}', got '${actual}'"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_true() {
  local label="$1"
  shift
  if "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# node_ipv6_for() -- mirrors lima-start.sh's `NODE_IPV6="fd85:${POD_SUBNET_OCTET}::1"`.
# A dual-stack cluster with multiple nodes must never derive the same ULA for
# two different nodes -- a collision would leave one node's kubelet unable to
# distinguish its own address from a peer's (and would silently make the
# "at least one dual-stack node" e2e pass or fail depending on which node
# ginkgo happened to inspect, instead of every node genuinely being dual-stack).
# ---------------------------------------------------------------------------
node_ipv6_for() {
  local pod_subnet_octet="$1"
  echo "fd85:${pod_subnet_octet}::1"
}

assert_eq "primary node (octet 0) gets fd85:0::1" \
  "fd85:0::1" "$(node_ipv6_for 0)"
assert_eq "2nd node (octet 1, from --node-suffix -2) gets fd85:1::1" \
  "fd85:1::1" "$(node_ipv6_for 1)"
assert_true "primary and 2nd node addresses never collide (distinct octets -> distinct ULAs)" \
  test "$(node_ipv6_for 0)" != "$(node_ipv6_for 1)"

# ---------------------------------------------------------------------------
# Structural checks against the real script: the mirror function above proves
# the derivation is collision-free, but not that lima-start.sh actually
# applies the derived address to eth0 AND passes the same value to kubelet.
# Fail on revert: if a future edit drops the `ip addr replace` call (or
# recomputes a different value for --node-ip than what was actually assigned
# to the interface), kubelet would report a --node-ip that doesn't exist on
# any local interface and crash-loop instead of registering, or would fall
# straight back to the original single-IPv4-only failure mode.
# ---------------------------------------------------------------------------
DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"

assert_true "lima-start.sh derives NODE_IPV6 from the same POD_SUBNET_OCTET used for the pod CIDR" \
  grep -qF 'NODE_IPV6="fd85:${POD_SUBNET_OCTET}::1"' "$LIMA_START"
# Must NOT hardcode "eth0": Ubuntu 26.04's first-boot NIC rename can fail
# (LP: #2136392), leaving the primary interface named e.g. enp0s1 instead —
# confirmed live on lima-node-4, where a hardcoded `dev eth0` broke this exact
# fix with "Cannot find device \"eth0\"" before this interface-agnostic form.
assert_true "lima-start.sh assigns NODE_IPV6 to the detected interface, not a hardcoded 'eth0'" \
  grep -qF 'limactl shell "$VM_NAME" sudo ip -6 addr replace "${NODE_IPV6}/64" dev "$LIMA_VM_IFACE"' "$LIMA_START"
assert_true "lima-start.sh derives LIMA_VM_IFACE the same interface-agnostic way as LIMA_VM_IP (scope global, not a fixed name)" \
  grep -qF "LIMA_VM_IFACE=\$(limactl shell \"\$VM_NAME\" ip -4 -o addr show scope global" "$LIMA_START"
assert_true "lima-start.sh passes both address families to kubelet via --node-ip" \
  grep -qF '  --node-ip=${LIMA_VM_IP},${NODE_IPV6} \\\\' "$LIMA_START"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
