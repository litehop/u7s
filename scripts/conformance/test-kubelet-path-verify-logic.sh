#!/usr/bin/env bash
# A node can be Ready while its host kubelet forward is dead (Lima's hostagent
# closes the listener on a kubelet restart), so logs/exec 502 and a sonobuoy run
# burns ~34 min at 0/460. verify_kubelet_paths must probe the real
# apiserver->kubelet path, repair it once, and otherwise fail naming the node.
set -euo pipefail

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

CALLS=$(mktemp)
OUT=$(mktemp)
trap 'rm -f "$CALLS" "$OUT"' EXIT
sleep() { :; }
# DEAD_NODES: space-separated nodes whose proxy probe fails; HEAL_ON_RESTART=1
# makes a kubelet restart of that VM revive it.
kubectl() {
  echo "kubectl $*" >> "$CALLS"
  case "$*" in *"get --raw /api/v1/nodes/"*"/proxy/healthz"*) ;; *) return 0 ;; esac
  local args="$*" node
  node="${args#*nodes/}"
  node="${node%%/*}"
  case " $DEAD_NODES " in *" $node "*) return 1 ;; esac
  return 0
}
limactl() {
  echo "limactl $*" >> "$CALLS"
  case "$*" in
    *"sudo systemctl start kubelet"*)
      if [ "$HEAL_ON_RESTART" = 1 ]; then DEAD_NODES=" ${DEAD_NODES/ ${2} / } "; fi ;;
    *"ss -Hltn"*) return 1 ;;
  esac
  return 0
}
run_verify() { : > "$CALLS"; local rc=0; verify_kubelet_paths kc "$@" >"$OUT" 2>&1 || rc=$?; return "$rc"; }

DEAD_NODES=""; HEAL_ON_RESTART=0
assert_true "healthy nodes pass" run_verify lima-node-2=10273 lima-node-3=10271
assert_true "healthy nodes are probed through the apiserver proxy, not just by a listener check -- Node Ready does not prove the path" \
  grep -q "get --raw /api/v1/nodes/lima-node-3/proxy/healthz" "$CALLS"
assert_false "a healthy path is never repaired by restarting the kubelet" \
  grep -q "systemctl" "$CALLS"

DEAD_NODES=" lima-node-3 "; HEAL_ON_RESTART=0
assert_false "a permanently dead extra-node forward fails the bring-up instead of declaring the stack up" \
  run_verify lima-node-2=10273 lima-node-3=10271
assert_true "the failure names the dead node and its host port so the operator knows which forward to look at" \
  grep -q "ERROR:.*lima-node-3.*10271" "$OUT"
assert_false "the healthy node is not blamed" \
  grep -q "ERROR:.*lima-node-2" "$OUT"
assert_true "a dead forward triggers exactly one repair attempt on that VM" \
  [ "$(grep -c 'limactl shell lima-node-3 sudo systemctl start kubelet' "$CALLS")" = 1 ]
assert_false "the healthy node's kubelet is left alone" \
  grep -q "lima-node-2 sudo systemctl" "$CALLS"
assert_true "the repair stops the kubelet before starting it, so Lima sees the guest port go away as a separate event" \
  [ "$(grep -n 'systemctl stop kubelet' "$CALLS" | head -1 | cut -d: -f1)" -lt "$(grep -n 'systemctl start kubelet' "$CALLS" | head -1 | cut -d: -f1)" ]

DEAD_NODES=" lima-node-3 "; HEAL_ON_RESTART=1
assert_true "a forward that comes back after the repair passes -- the re-check, not the restart, is what proves it" \
  run_verify lima-node-2=10273 lima-node-3=10271

assert_true "lima-start.sh restarts the kubelet with the spaced helper -- a plain restart races Lima's port-forward watcher" \
  grep -q '^restart_kubelet_spaced "\$VM_NAME"' "$DIR/lima-start.sh"
assert_true "run-all.sh verifies every node's kubelet path, in --stack-only too (before the stack-only exit)" \
  [ "$(grep -n 'verify_kubelet_paths' "$DIR/run-all.sh" | head -1 | cut -d: -f1)" -lt "$(grep -n 'skipped — --stack-only' "$DIR/run-all.sh" | head -1 | cut -d: -f1)" ]

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
