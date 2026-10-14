#!/usr/bin/env bash
# Pod args are immutable: a reconnect without --reset that changes the
# konnectivity-agent args (e.g. a new --konnectivity-server-port) used to abort
# at `kubectl apply`, forcing the operator to delete the pod by hand.
# apply_pod_recreating_on_args_change deletes the live pod only on an args
# mismatch, then applies.
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

OLD=$'--proxy-server-port=8091\n--sync-interval=5s'
NEW=$'--proxy-server-port=8239\n--sync-interval=5s'

assert_true "changed port is a difference -- apply would hit the immutable-args error" \
  agent_args_differ "$NEW" "$OLD"
assert_false "identical args are left alone -- deleting a healthy agent drops the tunnel for nothing" \
  agent_args_differ "$OLD" "$OLD"
assert_false "no live pod (first bring-up) needs no delete" \
  agent_args_differ "$NEW" ""

CALLS=$(mktemp)
# STUB_LIVE: live args printed by `get`; STUB_FAIL: verb that should fail.
kubectl() {
  local verb="" a
  for a in "$@"; do case "$a" in get|delete|apply) verb="$a"; break ;; esac; done
  echo "$verb $*" >> "$CALLS"
  [ "${STUB_FAIL:-}" = "$verb" ] && return 1
  [ "$verb" = get ] && [ -n "${STUB_LIVE:-}" ] && printf '%s\n' "$STUB_LIVE"
  return 0
}
run() { : > "$CALLS"; apply_pod_recreating_on_args_change kc kube-system konnectivity-agent-3 "$1" <<< "kind: Pod" >/dev/null 2>&1; }
count() { grep -c "^$1 " "$CALLS" || true; }

STUB_LIVE="$OLD" run "$NEW"
assert_true "mismatch: exactly one delete" [ "$(count delete)" = 1 ]
assert_true "mismatch: the delete targets the stale pod in kube-system" \
  grep -q '^delete .*pod konnectivity-agent-3 -n kube-system' "$CALLS"
assert_true "mismatch: the new pod is applied" [ "$(count apply)" = 1 ]
assert_true "mismatch: delete precedes apply -- applying first aborts on immutable args" \
  [ "$(grep -n '^delete' "$CALLS" | cut -d: -f1)" -lt "$(grep -n '^apply' "$CALLS" | cut -d: -f1)" ]

STUB_LIVE="$OLD" run "$OLD"
assert_true "match: no delete" [ "$(count delete)" = 0 ]
assert_true "match: still applied (spec drift elsewhere is mutable)" [ "$(count apply)" = 1 ]

STUB_LIVE="" run "$NEW"
assert_true "absent pod: no delete" [ "$(count delete)" = 0 ]
assert_true "absent pod: applied" [ "$(count apply)" = 1 ]

rc=0; STUB_LIVE="$OLD" STUB_FAIL=delete run "$NEW" || rc=$?
assert_true "delete failure fails loud (rc != 0)" [ "$rc" != 0 ]
assert_true "delete failure: no apply attempted against the stale pod" [ "$(count apply)" = 0 ]

rc=0; STUB_LIVE="$OLD" STUB_FAIL=apply run "$NEW" || rc=$?
assert_true "apply failure fails loud (rc != 0)" [ "$rc" != 0 ]

rc=0; STUB_FAIL=get run "$NEW" || rc=$?
assert_true "unreadable live pod fails loud instead of guessing" [ "$rc" != 0 ]

assert_true "lima-start.sh applies the agent pod through the recreating helper" \
  grep -q '^apply_pod_recreating_on_args_change .*konnectivity-agent' "$DIR/lima-start.sh"

rm -f "$CALLS"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
