#!/usr/bin/env bash
# Guards against a Lima VM's baked kubelet hostPort forward drifting from the
# --kubelet-port a run is told to use: that mismatch leaves watch/list/get
# working while kubectl exec/logs/attach silently fail, which looks like spec
# failures. Fixture lima.yaml files under a fake LIMA_HOME; no VM is touched.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="$DIR/lima-kubelet-port.sh"
RUN_ALL="$DIR/run-all.sh"
LIMA_START="$DIR/lima-start.sh"

PASS=0
FAIL=0
assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"; PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"; FAIL=$(( FAIL + 1 ))
  fi
}

LIMA_HOME=$(mktemp -d)
export LIMA_HOME
trap 'rm -rf "$LIMA_HOME"' EXIT

mkvm() { mkdir -p "$LIMA_HOME/$1"; cat > "$LIMA_HOME/$1/lima.yaml"; }

mkvm vm-ok <<'Y'
networks:
- lima: user-v2
portForwards:
# comment
- guestPort: 10250
  hostPort: 10263

mounts:
- location: "~"
Y
mkvm vm-reversed <<'Y'
portForwards:
- hostPort: 8080
  guestPort: 80
- hostPort: 10270
  guestPort: 10250
Y
mkvm vm-nomap <<'Y'
portForwards:
- guestPort: 80
  hostPort: 10250
mounts:
- guestPort: 10250
  hostPort: 9999
Y

out=$("$HELPER" vm-ok 2>&1) && rc=0 || rc=$?
assert "helper prints the live host port for guest 10250" "$([ "$rc" = 0 ] && [ "$out" = 10263 ] && echo 1 || echo 0)"

out=$("$HELPER" vm-reversed 2>&1) && rc=0 || rc=$?
assert "helper handles hostPort listed before guestPort and ignores other guest ports" "$([ "$rc" = 0 ] && [ "$out" = 10270 ] && echo 1 || echo 0)"

out=$("$HELPER" vm-missing 2>&1) && rc=0 || rc=$?
assert "helper fails loud for a VM that does not exist" "$([ "$rc" != 0 ] && echo "$out" | grep -q 'does not exist' && echo 1 || echo 0)"

out=$("$HELPER" vm-nomap 2>&1) && rc=0 || rc=$?
assert "helper fails loud (and ignores guestPort outside portForwards) when 10250 is unmapped" "$([ "$rc" != 0 ] && echo "$out" | grep -q 'no portForwards entry' && echo 1 || echo 0)"

source "$DIR/_lib.sh"

out=$(assert_kubelet_port_matches_vm vm-ok 10263 2>&1) && rc=0 || rc=$?
assert "matching port passes" "$([ "$rc" = 0 ] && echo 1 || echo 0)"

out=$(assert_kubelet_port_matches_vm vm-ok 10253 2>&1) && rc=0 || rc=$?
assert "mismatch fails with the actionable message" "$([ "$rc" != 0 ] && [ "$out" = "error: vm-ok forwards guest 10250 to host 10263, but --kubelet-port=10253 was passed; pass --kubelet-port 10263 or reprovision" ] && echo 1 || echo 0)"

out=$(assert_kubelet_port_matches_vm vm-new 10253 2>&1) && rc=0 || rc=$?
assert "first provision (no VM dir) must not trip: the requested port gets baked in" "$([ "$rc" = 0 ] && echo 1 || echo 0)"

out=$(assert_kubelet_port_matches_vm vm-nomap 10250 2>&1) && rc=0 || rc=$?
assert "existing VM without a mapping fails rather than passing silently" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

# run-all.sh rejects a stale port before building or starting anything.
out=$("$RUN_ALL" --vm vm-ok --kubelet-port 10253 --stack-only 2>&1) && rc=0 || rc=$?
assert "run-all.sh aborts on --kubelet-port mismatch" "$([ "$rc" != 0 ] && echo "$out" | grep -q 'forwards guest 10250 to host 10263' && echo 1 || echo 0)"

out=$("$RUN_ALL" --vm vm-ok --kubelet-port 10263 --extra-node vm-reversed --extra-kubelet-port 10271 --stack-only 2>&1) && rc=0 || rc=$?
assert "run-all.sh aborts on --extra-kubelet-port mismatch" "$([ "$rc" != 0 ] && echo "$out" | grep -q 'vm-reversed forwards guest 10250 to host 10270' && echo 1 || echo 0)"

mkvm vm-quoted <<'Y'
portForwards:
- guestPort: "10250"   # kubelet
  hostPort: '10281'
Y
mkvm vm-flow <<'Y'
portForwards:
- {guestPort: 80, hostPort: 8080}
- {guestPort: 10250, hostPort: 10282}  # kubelet
Y
out=$("$HELPER" vm-quoted 2>&1) && rc=0 || rc=$?
assert "quoted values and trailing comments do not cause a false 'no portForwards entry' abort" "$([ "$rc" = 0 ] && [ "$out" = 10281 ] && echo 1 || echo 0)"
out=$("$HELPER" vm-flow 2>&1) && rc=0 || rc=$?
assert "flow-style {..} entries are parsed per-entry, not merged with a neighbour" "$([ "$rc" = 0 ] && [ "$out" = 10282 ] && echo 1 || echo 0)"
out=$("$HELPER" vm-nomap 2>&1) && rc=0 || rc=$?
assert "unmapped-10250 error tells the operator to pass --reset" "$([ "$rc" != 0 ] && echo "$out" | grep -q -- '--reset' && echo 1 || echo 0)"

# Run lima-start.sh's real gate line (extracted, not re-typed) so removing or
# mis-gating the call fails here.
GATE=$(grep -F 'assert_kubelet_port_matches_vm "$VM_NAME"' "$LIMA_START")
assert "lima-start.sh has exactly one kubelet-port gate line" "$([ "$(printf '%s\n' "$GATE" | wc -l)" -eq 1 ] && [ -n "$GATE" ] && echo 1 || echo 0)"
run_gate() { # <override> <vm> <port>
  ( _KUBELET_PORT_OVERRIDE="$1" VM_NAME="$2" KUBELET_PORT="$3"; eval "$GATE"; echo reached ) 2>/dev/null
}
out=$(run_gate "" vm-ok 10253) || true
assert "gate is skipped when --kubelet-port was not passed (default 10250 must not trip on a custom-port VM)" "$([ "$out" = reached ] && echo 1 || echo 0)"
out=$(run_gate 10253 vm-ok 10253) || true
assert "gate aborts lima-start when an explicit --kubelet-port mismatches the VM" "$([ -z "$out" ] && echo 1 || echo 0)"
out=$(run_gate 10263 vm-ok 10263) || true
assert "gate lets a matching explicit --kubelet-port continue" "$([ "$out" = reached ] && echo 1 || echo 0)"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
