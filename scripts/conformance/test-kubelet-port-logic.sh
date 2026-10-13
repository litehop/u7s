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

if grep -q 'assert_kubelet_port_matches_vm' "$LIMA_START"; then ok=1; else ok=0; fi
assert "lima-start.sh (also reached via add-node.sh) enforces the check" "$ok"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
