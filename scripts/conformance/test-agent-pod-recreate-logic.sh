#!/usr/bin/env bash
# Pod args are immutable: a reconnect without --reset that changes the
# konnectivity-agent args (e.g. a new --konnectivity-server-port) used to abort
# at `kubectl apply`, forcing the operator to delete the pod by hand.
# apply_pod_recreating_on_args_change deletes the live pod only on an args
# mismatch, then applies. The real agent-pod block extracted from lima-start.sh
# is driven too, so the pod name and args lima-start.sh passes are asserted.
set -euo pipefail

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

OLD=$'--proxy-server-port=8091\n--sync-interval=5s'
NEW=$'--proxy-server-port=8239\n--sync-interval=5s'

CALLS=$(mktemp)
MANIFEST=$(mktemp)
# STUB_EXISTS=1: `get` prints the pod name, then STUB_LIVE as its args.
# STUB_FAIL: verb that should fail.
kubectl() {
  local verb="" a
  for a in "$@"; do case "$a" in get|delete|apply) verb="$a"; break ;; esac; done
  echo "$verb $*" >> "$CALLS"
  [ "${STUB_FAIL:-}" = "$verb" ] && return 1
  if [ "$verb" = get ] && [ "${STUB_EXISTS:-}" = 1 ]; then
    echo "stub-pod"
    [ -n "${STUB_LIVE:-}" ] && printf '%s\n' "$STUB_LIVE"
  fi
  [ "$verb" = apply ] && cat > "$MANIFEST"
  return 0
}
run() { : > "$CALLS"; apply_pod_recreating_on_args_change kc kube-system konnectivity-agent-3 "$1" <<< "kind: Pod" >/dev/null 2>&1; }
count() { grep -c "^$1 " "$CALLS" || true; }

STUB_EXISTS=1 STUB_LIVE="$OLD" run "$NEW"
assert_true "mismatch: exactly one delete -- apply would hit the immutable-args error" [ "$(count delete)" = 1 ]
assert_true "mismatch: the delete targets the stale pod in kube-system" \
  grep -q '^delete .*pod konnectivity-agent-3 -n kube-system' "$CALLS"
assert_true "mismatch: the new pod is applied" [ "$(count apply)" = 1 ]
assert_true "mismatch: delete precedes apply -- applying first aborts on immutable args" \
  [ "$(grep -n '^delete' "$CALLS" | cut -d: -f1)" -lt "$(grep -n '^apply' "$CALLS" | cut -d: -f1)" ]

STUB_EXISTS=1 STUB_LIVE="$OLD" run "$OLD"
assert_true "match: no delete -- deleting a healthy agent drops the tunnel for nothing" [ "$(count delete)" = 0 ]
assert_true "match: still applied (spec drift elsewhere is mutable)" [ "$(count apply)" = 1 ]

STUB_EXISTS=0 run "$NEW"
assert_true "absent pod: no delete" [ "$(count delete)" = 0 ]
assert_true "absent pod: applied" [ "$(count apply)" = 1 ]

STUB_EXISTS=1 STUB_LIVE="" run "$NEW"
assert_true "existing pod with empty live args is a difference -- reading it as absent hits the immutable-args abort" \
  [ "$(count delete)" = 1 ]

rc=0; STUB_EXISTS=1 STUB_LIVE="$OLD" STUB_FAIL=delete run "$NEW" || rc=$?
assert_true "delete failure fails loud (rc != 0)" [ "$rc" != 0 ]
assert_true "delete failure: no apply attempted against the stale pod" [ "$(count apply)" = 0 ]

rc=0; STUB_EXISTS=1 STUB_LIVE="$OLD" STUB_FAIL=apply run "$NEW" || rc=$?
assert_true "apply failure fails loud (rc != 0)" [ "$rc" != 0 ]

rc=0; STUB_FAIL=get run "$NEW" || rc=$?
assert_true "unreadable live pod fails loud instead of guessing" [ "$rc" != 0 ]

# The real block from lima-start.sh, evaluated with the variables it expects.
BLOCK=$(sed -n '/^AGENT_ARGS=(/,/^PODEOF$/p' "$DIR/lima-start.sh")
assert_true "lima-start.sh agent-pod block was extracted" \
  grep -q '^apply_pod_recreating_on_args_change ' <<< "$BLOCK"
KUBECONFIG_PATH=/kc/path NODE_SUFFIX=-3 VM_NAME=vm-3 LIMA_HOST_IP=192.0.2.1 KONNECTIVITY_AGENT_PORT=8239
: > "$CALLS"
STUB_EXISTS=1 STUB_LIVE="$OLD" eval "$BLOCK" > /dev/null
assert_true "lima-start.sh deletes konnectivity-agent<suffix> in kube-system via its kubeconfig" \
  grep -q '^delete --kubeconfig=/kc/path delete pod konnectivity-agent-3 -n kube-system ' "$CALLS"
assert_true "lima-start.sh passes the port it renders into the manifest as the desired args" \
  grep -qx -e '--proxy-server-port=8239' <<< "$AGENT_ARGS_TEXT"
assert_true "applied manifest carries the same args lima-start.sh compares against" \
  grep -q -- '- --proxy-server-port=8239' "$MANIFEST"

: > "$CALLS"
STUB_EXISTS=1 STUB_LIVE="$AGENT_ARGS_TEXT" eval "$BLOCK" > /dev/null
assert_true "lima-start.sh leaves a live pod with identical args alone" [ "$(count delete)" = 0 ]

rm -f "$CALLS" "$MANIFEST"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
