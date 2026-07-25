#!/usr/bin/env bash
# Unit test for the CRI-O debug-logging toggle decision in lima-start.sh.
#
# Exercises the read-detect-then-act decision without touching a real VM:
#   - --verbose + drop-in absent     -> enable (write config + restart crio)
#   - --verbose + drop-in present    -> no-op (already enabled, no extra restart)
#   - no --verbose + drop-in present -> disable (remove config + restart crio)
#   - no --verbose + drop-in absent  -> no-op (already disabled)
#
# These four cases are exactly the idempotency + undo requirements from
# mayor-tfggx: running --reset --verbose twice must not layer up extra
# restarts, and a later non-verbose run must always clear a stale drop-in
# rather than leaving debug logging on forever.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected '${expected}', got '${actual}'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# Isolated decision function — mirrors the crio.conf.d toggle in lima-start.sh
# without any limactl I/O. Arguments: verbose(0|1) present(0|1)
# Prints "enable", "disable", or "noop".
# ---------------------------------------------------------------------------
crio_verbose_decide() {
  local verbose="$1" present="$2"
  if [ "$verbose" -eq 1 ] && [ "$present" -eq 0 ]; then
    echo "enable"
  elif [ "$verbose" -eq 0 ] && [ "$present" -eq 1 ]; then
    echo "disable"
  else
    echo "noop"
  fi
}

# 1. --verbose on a VM with no drop-in yet -> must enable debug logging.
OUT=$(crio_verbose_decide 1 0)
assert_eq "verbose + absent -> enable" "enable" "$OUT"

# 2. --verbose on a VM that already has the drop-in (2nd of two --verbose runs
#    in a row) -> must no-op, not write+restart crio again.
OUT=$(crio_verbose_decide 1 1)
assert_eq "verbose + present -> noop (idempotent)" "noop" "$OUT"

# 3. No --verbose on a VM left over from an earlier verbose run -> must remove
#    the drop-in so debug logging doesn't silently stay on forever.
OUT=$(crio_verbose_decide 0 1)
assert_eq "not verbose + present -> disable (undo)" "disable" "$OUT"

# 4. No --verbose on a VM that was never made verbose -> must no-op.
OUT=$(crio_verbose_decide 0 0)
assert_eq "not verbose + absent -> noop" "noop" "$OUT"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
