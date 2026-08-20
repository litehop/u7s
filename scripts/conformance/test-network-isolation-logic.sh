#!/usr/bin/env bash
# Unit tests for lima-start.sh's Phase-B worker-network partition guards:
# peer-network validation (inter-node route loop) and the staleness-check
# extension (network *name* comparison, not just key presence).
#
# Separate Lima `user-v2*` networks are separate L2 segments with no path
# between them (each is its own gvisor-tap-vsock daemon instance). Before this
# fix, lima-start.sh's inter-node route loop programmed a static route to a
# peer VM without ever checking they were on the same network -- a
# cross-network pairing (e.g. lima-node-2 on user-v2-workers-a paired via
# --extra-node with lima-node-5 on user-v2-workers-b) silently produced an
# unreachable `ip route`, surfacing only much later as a cryptic "Host is
# unreachable" deep into a conformance run. Likewise, the staleness check only
# verified a `networks:` key existed on a reused VM, not that it named the
# network THIS invocation wants -- so a `--reset` that dropped a previously
# passed `--network user-v2-workers-a` would silently revert an isolated
# worker back onto the shared, defect-prone user-v2.
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
# Structural checks against the real script: the mirror above proves the
# comparison logic is right, but not that lima-start.sh's route loop actually
# uses it before programming a route.
# ---------------------------------------------------------------------------
assert_true "lima-start.sh's route loop reads THIS_NET from the primary VM's own recorded lima.yaml" \
  grep -qF 'THIS_NET=$(awk '"'"'/^networks:/{f=1;next} f&&/lima:/{print $NF;exit}'"'"' "${HOME}/.lima/${VM_NAME}/lima.yaml")' "$LIMA_START"
assert_true "lima-start.sh's route loop reads PEER_NET from the peer VM's own recorded lima.yaml" \
  grep -qF 'PEER_NET=$(awk '"'"'/^networks:/{f=1;next} f&&/lima:/{print $NF;exit}'"'"' "${HOME}/.lima/${PEER}/lima.yaml")' "$LIMA_START"
assert_true "lima-start.sh fails loud (exit 1) on a THIS_NET/PEER_NET mismatch before programming any route" \
  grep -qF 'if [ "$THIS_NET" != "$PEER_NET" ]; then' "$LIMA_START"

# Regression guard: prove the route loop cannot program a peer route without
# first passing the network-match gate above (i.e. the gate is not dead code
# a future edit could route around).
ROUTE_LOOP=$(awk '/^for PEER in \$PEERS; do/,/^done$/' "$LIMA_START")
assert "the network-match gate appears BEFORE the first ip route replace in the loop body" \
  "$(echo "$ROUTE_LOOP" | grep -n 'THIS_NET\|ip route replace' | head -1 | grep -q THIS_NET && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Staleness-check extension: compares the recorded network *name*, not just
# whether a `networks:` key is present.
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
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
