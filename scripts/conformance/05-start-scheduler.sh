#!/usr/bin/env bash
# Start u7s-scheduler on the host (backgrounded) for conformance testing.
#
# u7s-scheduler is a Rust binary — it runs on the host, not inside the Lima VM.
#
# Part of the scripts/conformance/ orchestration sequence.
set -euo pipefail

# Raise the FD limit before launching the scheduler below — see u7s-start.sh for
# why (macOS's default 256 soft RLIMIT_NOFILE is trivially exceeded by a
# long-running cluster-wide watch under sustained load).
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${U7S_TARGET_DIR:-$REPO/target}/release/u7s-scheduler"

TARGET_DIR_ARGS=()
if [[ -n "${U7S_TARGET_DIR:-}" ]]; then
  TARGET_DIR_ARGS=(--target-dir "$U7S_TARGET_DIR")
fi

WORKDIR="$PWD/temp/u7s"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --port) shift 2 ;;
    --vm) shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# Resolve to absolute so the pgrep/pkill match below (and the process's own
# --kubeconfig arg) is worktree-unique — a relative WORKDIR from different
# worktrees would otherwise produce identical process command lines and let
# one worker's restart kill another's scheduler.
mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"

LOG="$WORKDIR/scheduler.log"

echo "=== [05] Start u7s-scheduler (on host) ==="

cargo build --release -p u7s-scheduler --manifest-path "$REPO/Cargo.toml" "${TARGET_DIR_ARGS[@]+"${TARGET_DIR_ARGS[@]}"}"

if [ ! -f "$WORKDIR/kubeconfig" ]; then
  echo "error: kubeconfig not found at $WORKDIR/kubeconfig" >&2
  echo "Start u7s-apiserver first: scripts/u7s-start.sh" >&2
  exit 1
fi

# Scope the kill to a scheduler already bound to THIS kubeconfig so parallel
# workers on other VMs/ports keep their schedulers. A global `pkill -f
# u7s-scheduler` would tear down a peer worker's scheduler.
if pgrep -f "u7s-scheduler.*${WORKDIR}/kubeconfig" >/dev/null 2>&1; then
  echo "WARNING: u7s-scheduler for $WORKDIR already running — killing and restarting" >&2
  pkill -f "u7s-scheduler.*${WORKDIR}/kubeconfig" 2>/dev/null || true
  sleep 1
fi

echo "Starting u7s-scheduler (logs: $LOG) ..."
nohup "$BINARY" \
  --kubeconfig "$WORKDIR/kubeconfig" \
  > "$LOG" 2>&1 &
SCHEDULER_PID=$!
disown "$SCHEDULER_PID"

echo "u7s-scheduler running (PID $SCHEDULER_PID, logs: $LOG)"
echo "  tail -f $LOG"
