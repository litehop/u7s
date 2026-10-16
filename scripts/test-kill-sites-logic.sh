#!/usr/bin/env bash
# Every workdir-scoped pkill/pgrep outside u7s-start.sh and 05-start-scheduler.sh
# (covered by test-restart-kill-scope-logic.sh) must kill/match ONLY its own
# workdir's process. An unanchored "...${WORKDIR}" pattern also takes down a
# peer worker's live stack whose workdir merely contains this one (suffix or
# prefix collision) or differs only where an unescaped '.' would match.
#
# The real lines are driven, not copies: run-all.sh's pkill lines and
# sample-run-metrics.sh's resolvers are extracted from the real files; reset.sh
# runs for real (--host-only) and its hostagent pgrep line is extracted. Targets
# are real sleepers whose argv mimics the daemons'.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
# shellcheck source=scripts/_kill-pattern.sh
source "$DIR/_kill-pattern.sh"

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}
alive() { kill -0 "$1" 2>/dev/null; }
dead() { ! kill -0 "$1" 2>/dev/null; }

T=$(mktemp -d)
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf "$T"
}
trap cleanup EXIT

spawn() {
  ( exec -a "$1" sleep 300 ) &
  SPAWNED=$!
  disown "$SPAWNED"
  PIDS+=("$SPAWNED")
}

# A is the workdir acting. B embeds A as a path suffix, C extends A, D differs
# from A only where the unescaped '.' wildcard would match.
A="$T/temp/a.b"
B="/zz$A"
C="${A}2"
D="$T/temp/aXb"

# spawn_all <argv fmt with @ for the path>: sets PA PB PC PD.
spawn_all() {
  spawn "${1//@/$A}"; PA=$SPAWNED
  spawn "${1//@/$B}"; PB=$SPAWNED
  spawn "${1//@/$C}"; PC=$SPAWNED
  spawn "${1//@/$D}"; PD=$SPAWNED
  sleep 0.3
}

assert_only_a_dies() {
  local label="$1"
  assert_true "$label: kills its own workdir's process" dead "$PA"
  assert_true "$label: spares a stack whose workdir ends with this one (suffix collision)" alive "$PB"
  assert_true "$label: spares a stack whose workdir extends this one (prefix collision)" alive "$PC"
  assert_true "$label: spares a stack differing only where an unescaped '.' would match" alive "$PD"
}

SCHED_FMT="u7s-scheduler --kubeconfig @/kubeconfig-scheduler"
KONN_FMT="konnectivity-server --server-cert=@/konnectivity-server.crt --x"
APISERVER_FMT="u7s-apiserver --db @/state.db --kubeconfig @/kubeconfig"

# --- run-all.sh: the two post-dhat pkill lines -----------------------------
KILL_CODE=$(grep -E '^[[:space:]]*pkill -f ' "$DIR/conformance/run-all.sh")
assert_true "run-all.sh has exactly its scheduler + konnectivity-server pkill lines" \
  [ "$(grep -c 'workdir_kill_pattern' <<< "$KILL_CODE")" = 2 ]
spawn_all "$SCHED_FMT"; S=("$PA" "$PB" "$PC" "$PD")
spawn_all "$KONN_FMT"
WORKDIR_ABS="$A"
eval "$KILL_CODE"
sleep 0.5
assert_true "run-all.sh scheduler: kills its own workdir's scheduler" dead "${S[0]}"
assert_true "run-all.sh scheduler: spares suffix-collision stack" alive "${S[1]}"
assert_true "run-all.sh scheduler: spares prefix-collision stack" alive "${S[2]}"
assert_true "run-all.sh scheduler: spares '.'-wildcard stack" alive "${S[3]}"
assert_only_a_dies "run-all.sh konnectivity-server"

# --- sample-run-metrics.sh: pid resolvers ----------------------------------
eval "$(sed -n '/^resolve_scheduler_pid() {/,/^}/p' "$DIR/conformance/sample-run-metrics.sh")"
eval "$(sed -n '/^resolve_konnectivity_pid() {/,/^}/p' "$DIR/conformance/sample-run-metrics.sh")"
assert_true "sample-run-metrics resolvers were extracted" declare -F resolve_scheduler_pid resolve_konnectivity_pid
WORKDIR="$A"
spawn_all "$SCHED_FMT"; S=("$PA" "$PB" "$PC" "$PD")
spawn_all "$KONN_FMT"; K=("$PA" "$PB" "$PC" "$PD")
assert_true "sample-run-metrics resolve_scheduler_pid returns only its own workdir's scheduler (not a colliding stack's)" \
  [ "$(resolve_scheduler_pid)" = "${S[0]}" ]
assert_true "sample-run-metrics resolve_konnectivity_pid returns only its own workdir's konnectivity-server" \
  [ "$(resolve_konnectivity_pid)" = "${K[0]}" ]
kill "${S[0]}" "${K[0]}"
sleep 0.3
assert_true "sample-run-metrics resolve_scheduler_pid is empty when only colliding stacks run (it would sample a peer's RSS)" \
  [ -z "$(resolve_scheduler_pid)" ]
assert_true "sample-run-metrics resolve_konnectivity_pid is empty when only colliding stacks run" \
  [ -z "$(resolve_konnectivity_pid)" ]

# --- reset.sh --host-only, run for real ------------------------------------
spawn_all "$APISERVER_FMT"; AP=("$PA" "$PB" "$PC" "$PD")
spawn_all "$SCHED_FMT"; S=("$PA" "$PB" "$PC" "$PD")
spawn_all "$KONN_FMT"; K=("$PA" "$PB" "$PC" "$PD")
RESET_RC=0
( git init -q "$T" && cd "$T" && bash "$REPO/scripts/conformance/reset.sh" --host-only --workdir "$A" ) >"$T/reset.out" 2>&1 || RESET_RC=$?
sleep 0.5
assert_true "reset.sh --host-only exits 0 after reaping its own stack (rc=$RESET_RC)" [ "$RESET_RC" = 0 ]
for i in 0 1 2 3; do
  case "$i" in
    0) who="its own workdir's"; chk=dead ;;
    1) who="a suffix-collision stack's"; chk=alive ;;
    2) who="a prefix-collision stack's"; chk=alive ;;
    3) who="a '.'-wildcard stack's"; chk=alive ;;
  esac
  for kind in AP S K; do
    eval "p=\${${kind}[$i]}"
    case "$kind" in AP) n=apiserver ;; S) n=scheduler ;; K) n=konnectivity-server ;; esac
    assert_true "reset.sh --host-only vs $who $n: $chk" "$chk" "$p"
  done
done

# --- reset.sh: hostagent backstop pgrep ------------------------------------
HA_LINE=$(grep -E 'stray_pids="\$\(pgrep -f ' "$DIR/conformance/reset.sh")
assert_true "reset.sh hostagent backstop line extracted and uses workdir_kill_pattern" \
  grep -q 'workdir_kill_pattern lima-hostagent' <<< "$HA_LINE"
HA_FMT="limactl hostagent --pidfile @.pid --socket @ vm"
HA_A="$T/ha/a.b/ha.sock"
HA_B="/zz$HA_A"
HA_C="${HA_A}2"
HA_D="$T/ha/aXb/ha.sock"
spawn "${HA_FMT//@/$HA_A}"; HA0=$SPAWNED
spawn "${HA_FMT//@/$HA_B}"
spawn "${HA_FMT//@/$HA_C}"
spawn "${HA_FMT//@/$HA_D}"
sleep 0.3
ha_sock="$HA_A"
eval "$HA_LINE"
assert_true "reset.sh hostagent backstop matches only the VM's own socket, not suffix/prefix/'.' collisions (would SIGKILL a sibling VM's hostagent)" \
  [ "$stray_pids" = "$HA0" ]

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
