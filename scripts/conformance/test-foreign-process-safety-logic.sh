#!/usr/bin/env bash
# run-all.sh / u7s-start.sh must only signal processes u7s owns (u7s-apiserver
# of THIS workdir), never "whatever listens on --port". Lima auto-forwards
# other projects' guest ports onto the same host port, so a port-selected
# kill SIGTERMed another project's Lima host agent. A foreign holder must
# make the port pre-flight refuse to start, naming the holder, and survive.
#
# Calls the real u7s_owned_pids() / check_port_free() against throwaway
# sleepers and an nc listener started here on a port from 20000-29999.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
# shellcheck source=scripts/_kill-pattern.sh
source "$REPO/scripts/_kill-pattern.sh"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}
alive() { kill -0 "$1" 2>/dev/null; }
dead() { ! kill -0 "$1" 2>/dev/null; }
contains() { local needle="$1"; shift; local p; for p in "$@"; do [ "$p" = "$needle" ] && return 0; done; return 1; }
lacks() { ! contains "$@"; }

T=$(mktemp -d)
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf "$T"
}
trap cleanup EXIT

SPAWNED=""
spawn() {
  ( exec -a "$1" sleep 300 ) &
  SPAWNED=$!
  disown "$SPAWNED"
  PIDS+=("$SPAWNED")
}

free_port() {
  local port
  for _ in $(seq 1 50); do
    port=$(( (RANDOM % 10000) + 20000 ))
    if ! lsof -n -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then echo "$port"; return 0; fi
  done
  echo "no free port" >&2; return 1
}

# A listener that is NOT a u7s process, standing in for a Lima host agent.
PORT=$(free_port)
( exec -a "foreign-limactl-hostagent" nc -l "$PORT" </dev/null >/dev/null 2>&1 ) &
FOREIGN=$!
disown "$FOREIGN"
PIDS+=("$FOREIGN")
sleep 0.5

A="$T/wd/own"
B="$T/wd/other"
mkdir -p "$A" "$B"
spawn "u7s-apiserver --listen 127.0.0.1:9 --kubeconfig $A/kubeconfig"; OWN=$SPAWNED
spawn "u7s-apiserver --listen 127.0.0.1:9 --kubeconfig $B/kubeconfig"; OTHER=$SPAWNED
sleep 0.3

HOLDERS=$(lsof -n -iTCP:"$PORT" -sTCP:LISTEN -t)
assert_true "test setup: the foreign listener is really bound to the port" \
  [ "$HOLDERS" = "$FOREIGN" ]

# shellcheck disable=SC2207 # one PID per line
SELECTED=($(u7s_owned_pids apiserver "$A"))
assert_true "selects the caller's own-workdir u7s-apiserver" contains "$OWN" "${SELECTED[@]}"
assert_true "does not select a u7s-apiserver of a different workdir" lacks "$OTHER" "${SELECTED[@]}"
assert_true "does not select the non-u7s port holder (it was another project's Lima host agent)" \
  lacks "$FOREIGN" "${SELECTED[@]}"

# Callers signal exactly what the helper returns.
kill "${SELECTED[@]}"
sleep 0.5
assert_true "own-workdir u7s-apiserver is reaped" dead "$OWN"
assert_true "different-workdir u7s-apiserver survives" alive "$OTHER"
assert_true "non-u7s port holder survives" alive "$FOREIGN"

assert_true "run-all.sh selects the apiserver via u7s_owned_pids" \
  grep -q 'u7s_owned_pids apiserver' "$DIR/run-all.sh"
assert_true "u7s-start.sh selects the apiserver via u7s_owned_pids" \
  grep -q 'u7s_owned_pids apiserver' "$DIR/../u7s-start.sh"

assert_true "sample-run-metrics.sh selects the apiserver via u7s_owned_pids, not the port holder" \
  grep -q 'u7s_owned_pids apiserver' "$DIR/sample-run-metrics.sh"
assert_true "sample-run-metrics.sh does not resolve the apiserver by lsof on the port" \
  bash -c '! grep -A2 "^resolve_apiserver_pid" "$1" | grep -q lsof' _ "$DIR/sample-run-metrics.sh"

set +e
OUT=$(check_port_free "$PORT" "apiserver" 2>&1)
RC=$?
set -e
assert_true "pre-flight refuses to start when a foreign process holds the port" [ "$RC" = 1 ]
assert_true "pre-flight names the holder's pid" grep -q "pid $FOREIGN" <<< "$OUT"
assert_true "pre-flight names the holder's command" grep -q "foreign-limactl-hostagent" <<< "$OUT"
assert_true "pre-flight does not signal the holder" alive "$FOREIGN"

# u7s-start.sh --background restart: kill u7s_owned_pids of this workdir, then
# check_port_free. With no u7s process of the workdir, a foreign listener must
# fail the restart and survive.
PORT2=$(free_port)
( exec -a "foreign-restart-listener" nc -l "$PORT2" </dev/null >/dev/null 2>&1 ) &
FOREIGN2=$!
disown "$FOREIGN2"
PIDS+=("$FOREIGN2")
sleep 0.5
RESTART_WD="$T/wd/restart"
mkdir -p "$RESTART_WD"
OWNED_PIDS=$(u7s_owned_pids apiserver "$RESTART_WD")
assert_true "restart: no u7s-apiserver of the workdir exists to kill" [ -z "$OWNED_PIDS" ]
set +e
OUT2=$(check_port_free "$PORT2" "apiserver" 2>&1)
RC2=$?
set -e
assert_true "restart: refuses when a foreign process holds the port after the owned-pid kill" [ "$RC2" = 1 ]
assert_true "restart: names the foreign holder" grep -q "foreign-restart-listener" <<< "$OUT2"
assert_true "restart: foreign listener survives" alive "$FOREIGN2"

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
