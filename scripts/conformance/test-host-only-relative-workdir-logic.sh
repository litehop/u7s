#!/usr/bin/env bash
# Regression test: reset.sh --host-only given a RELATIVE --workdir (./temp/u7s,
# the form workers must use because the classifier denies "$PWD/temp/u7s") must
# kill every host process kind run-all.sh starts for that workdir, and only
# that workdir.
#
# The start scripts launch processes with the canonical path
# "$(cd "$WORKDIR" && pwd)" in argv, and the kill patterns match that string
# verbatim. reset.sh used to build "$PWD/./temp/u7s", which matches nothing:
# it reported success while u7s-scheduler and konnectivity-server kept running
# until worktree-hygiene reaped them. Dummies below carry the same argv shapes
# the real processes do (see workdir_kill_pattern in scripts/_kill-pattern.sh).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/reset.sh"

PASS=0
FAIL=0
LEFTOVER_PIDS=()

cleanup() {
  local p
  for p in "${LEFTOVER_PIDS[@]:-}"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
  rm -rf "${TMPROOT:-}"
}
trap cleanup EXIT

assert_dead() {
  local label="$1" pid="$2" _i
  for _i in 1 2 3 4 5; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: $label — PID $pid still alive, expected killed"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

assert_alive() {
  local label="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — PID $pid was killed, expected alive"
    FAIL=$(( FAIL + 1 ))
  fi
}

spawn_fake_process() {
  bash -c "exec -a '$1' sleep 60" >/dev/null 2>&1 &
  SPAWNED+=($!)
  LEFTOVER_PIDS+=($!)
}

# One dummy per host process kind run-all.sh starts, with real-shaped argv.
spawn_stack() {
  local wd="$1" kind
  for kind in \
    "u7s-apiserver --db $wd/state.db --kubeconfig $wd/kubeconfig" \
    "u7s-scheduler --kubeconfig $wd/kubeconfig-scheduler" \
    "proxy-server --cluster-cert=$wd/konnectivity-server.crt --cluster-key=$wd/konnectivity-server.key" \
    "bash scripts/conformance/sample-run-metrics.sh start --workdir $wd --port 6444"; do
    spawn_fake_process "$kind"
  done
}

TMPROOT="$(cd "$(mktemp -d)" && pwd)"
WT_A="$TMPROOT/wt-a"
WT_B="$TMPROOT/wt-b"
mkdir -p "$WT_A/temp/u7s" "$WT_B/temp/u7s"

SPAWNED=()
spawn_stack "$WT_A/temp/u7s"
A_PIDS=("${SPAWNED[@]}")
SPAWNED=()
spawn_stack "$WT_B/temp/u7s"
B_PIDS=("${SPAWNED[@]}")
sleep 0.3 # let the backgrounded exec -a take effect

set +e
OUT="$(cd "$WT_A" && bash "$SCRIPT" --host-only --workdir ./temp/u7s --port 6444 2>&1)"
EXIT=$?
set -e

if [ "$EXIT" -eq 0 ]; then
  echo "PASS: relative --workdir: --host-only exits 0"
  PASS=$(( PASS + 1 ))
else
  echo "FAIL: relative --workdir: --host-only exit $EXIT, output: $OUT"
  FAIL=$(( FAIL + 1 ))
fi

KINDS=(apiserver scheduler konnectivity-server sample-run-metrics)
for i in 0 1 2 3; do
  assert_dead "relative --workdir kills this worktree's ${KINDS[$i]} (a leftover squats the port slot until hygiene reaps it)" "${A_PIDS[$i]}"
  assert_alive "relative --workdir leaves the other worktree's ${KINDS[$i]} alone (killing another worker's stack breaks their run)" "${B_PIDS[$i]}"
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
