#!/usr/bin/env bash
# Unit tests for lima-start.sh's VM-reprovision staleness check: network
# *name* comparison, not just key presence.
#
# Separate Lima `user-v2*` networks are separate L2 segments with no path
# between them (each is its own gvisor-tap-vsock daemon instance). The
# staleness check must verify a reused VM's recorded network NAME matches
# what this invocation wants, not merely that a `networks:` key exists -- so
# a `--reset` that dropped a previously passed `--network user-v2-workers-a`
# doesn't silently revert an isolated worker back onto the shared,
# defect-prone user-v2.
#
# It also covers the same-network pre-flight (assert_same_lima_network) that
# runs before flannel is applied: flannel.1's VXLAN needs a real L2 path
# between paired VMs.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: every single-quoted grep pattern below
# intentionally matches the literal, unexpanded source text of lima-start.sh,
# not something meant to expand in this script's own shell.
set -euo pipefail

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
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
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"

# ---------------------------------------------------------------------------
# network_of() mirrors the exact awk extraction lima-start.sh uses against a
# VM's recorded ~/.lima/<vm>/lima.yaml to read back its actual network name.
# ---------------------------------------------------------------------------
network_of() {
  awk '/^networks:/{f=1;next} f&&/lima:/{print $NF;exit}' "$1"
}

FIXTURES=$(mktemp -d)
trap 'rm -rf "$FIXTURES"' EXIT
printf 'networks:\n  - lima: user-v2-workers-a\n\nimages:\n' > "$FIXTURES/vm-a.yaml"
printf 'networks:\n  - lima: user-v2-workers-a\n\nimages:\n' > "$FIXTURES/vm-a2.yaml"
printf 'networks:\n  - lima: user-v2-workers-b\n\nimages:\n' > "$FIXTURES/vm-b.yaml"

assert "two VMs recorded on the same network extract equal names (same-partition pairing stays allowed)" \
  "$([ "$(network_of "$FIXTURES/vm-a.yaml")" = "$(network_of "$FIXTURES/vm-a2.yaml")" ] && echo 1 || echo 0)"
assert "two VMs recorded on different networks extract different names (cross-partition pairing is detectable)" \
  "$([ "$(network_of "$FIXTURES/vm-a.yaml")" != "$(network_of "$FIXTURES/vm-b.yaml")" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Staleness check: compares the recorded network *name*, not just whether a
# `networks:` key is present.
# ---------------------------------------------------------------------------
assert_true "the staleness check reads RECORDED_NETWORK from the VM's own recorded lima.yaml" \
  grep -qF 'RECORDED_NETWORK=$(awk '"'"'/^networks:/{f=1;next} f&&/lima:/{print $NF;exit}'"'"' "$VM_DIR/lima.yaml" 2>/dev/null || true)' "$LIMA_START"
assert_true "the staleness check fails loud when RECORDED_NETWORK differs from the requested NETWORK, not merely when the key is absent" \
  grep -qF 'if grep -q '"'"'^networks:'"'"' "$LIMA_YAML" && [ "$RECORDED_NETWORK" != "$NETWORK" ]; then' "$LIMA_START"

# Regression guard: the old presence-only check (fires only when the key is
# fully ABSENT, blind to a wrong-but-present network name) must be gone --
# otherwise a VM reprovisioned onto the wrong partition would silently pass.
assert_false "(regression guard) the old presence-only staleness check (blind to a wrong network NAME) is gone" \
  grep -qF "grep -q '^networks:' \"\$LIMA_YAML\" && ! grep -q '^networks:' \"\$VM_DIR/lima.yaml\"" "$LIMA_START"

# ---------------------------------------------------------------------------
# Same-network pre-flight for flannel.1.
# ---------------------------------------------------------------------------
source "$DIR/_lib.sh"
LIMA_HOME="$FIXTURES/lima"
export LIMA_HOME
for vm in vm-a vm-a2 vm-b; do
  mkdir -p "$LIMA_HOME/$vm"
  cp "$FIXTURES/$vm.yaml" "$LIMA_HOME/$vm/lima.yaml"
done

NODES=""
kubectl() { echo "$NODES"; }
NODES="vm-a2"
assert_true "VMs on the same network pass the pre-flight (same-partition pairing stays allowed)" \
  assert_same_lima_network vm-a kc
NODES="vm-a vm-a2"
assert_true "the joining VM's own Node entry is not compared against itself" \
  assert_same_lima_network vm-a kc
NODES="vm-a2 vm-b"
out=$(assert_same_lima_network vm-a kc 2>&1) && rc=0 || rc=$?
assert "VMs on different networks fail loud, naming both networks, so no unreachable overlay is programmed" \
  "$([ "$rc" != 0 ] && echo "$out" | grep -q "user-v2-workers-a.*user-v2-workers-b" && echo 1 || echo 0)"
NODES="vm-a2 vm-gone"
out=$(assert_same_lima_network vm-a kc 2>&1) && rc=0 || rc=$?
assert "a registered peer with no local lima.yaml fails loud, naming it and the remedies, instead of silently skipping the check" \
  "$([ "$rc" != 0 ] && echo "$out" | grep -q "vm-gone" && echo "$out" | grep -q 'kubectl delete node vm-gone' && echo "$out" | grep -q -- '--reset' && echo 1 || echo 0)"
kubectl() { return 1; }
out=$(assert_same_lima_network vm-a kc 2>&1) && rc=0 || rc=$?
assert "a kubectl failure fails loud rather than iterating zero peers and passing a mispaired VM" \
  "$([ "$rc" != 0 ] && echo "$out" | grep -q 'cannot list cluster nodes' && echo 1 || echo 0)"
unset -f kubectl

APPLY_LINE=$(grep -n 'Applying flannel CNI DaemonSet' "$LIMA_START" | head -1 | cut -d: -f1 || true)
CHECK_LINE=$(grep -n 'assert_same_lima_network "\$VM_NAME" "\$KUBECONFIG_PATH"' "$LIMA_START" | head -1 | cut -d: -f1 || true)
assert "lima-start.sh runs the same-network pre-flight before applying flannel" \
  "$([ -n "$CHECK_LINE" ] && [ -n "$APPLY_LINE" ] && [ "$CHECK_LINE" -lt "$APPLY_LINE" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
