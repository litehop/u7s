#!/usr/bin/env bash
# Runs the REAL retrieval block of 06-run-sonobuoy.sh against a stubbed limactl.
#
# retrieve is the only unbounded network call in result retrieval; an unbounded
# one hung the 2026-08-04 run with zero output. A timeout (exit 124) must be
# reported loudly, and a killed run must still exit with sonobuoy's own status.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/06-run-sonobuoy.sh"
PASS=0
FAIL=0
assert() {
  if [ "$2" = "1" ]; then echo "PASS: $1"; PASS=$(( PASS + 1 )); else echo "FAIL: $1"; FAIL=$(( FAIL + 1 )); fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BLOCK="$TMP/block.sh"
sed -n '/^echo "Retrieving results..."/,/^TIMESTAMP=/p' "$SCRIPT" | sed '$d' > "$BLOCK"
assert "retrieval block was extracted from the real script" \
  "$([ "$(wc -l < "$BLOCK")" -gt 5 ] && echo 1 || echo 0)"

mkdir -p "$TMP/bin"
cat > "$TMP/bin/limactl" <<'STUB'
#!/usr/bin/env bash
echo "limactl $*" >> "$STUB_LOG"
case "$*" in
  *"sonobuoy retrieve"*) exit "${STUB_RETRIEVE_RC:-0}" ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$TMP/bin/limactl"

# run_block <retrieve_rc> <sonobuoy_exit>; sets RC, ERR, LOG, OUT.
run_block() {
  export STUB_LOG="$TMP/log" STUB_RETRIEVE_RC="$1"
  : > "$STUB_LOG"
  RC=0
  PATH="$TMP/bin:$PATH" VM_NAME=vm SONOBUOY_EXIT="$2" \
    bash -c 'source "$1"; echo REACHED_COPY' _ "$BLOCK" >"$TMP/out" 2>"$TMP/err" || RC=$?
  ERR="$(cat "$TMP/err")"; OUT="$(cat "$TMP/out")"; LOG="$(cat "$STUB_LOG")"
}

run_block 0 0
case "$OUT" in *REACHED_COPY*) B=1 ;; *) B=0 ;; esac
assert "retrieve success falls through to the tarball copy step" \
  "$([ "$RC" -eq 0 ] && [ "$B" = 1 ] && echo 1 || echo 0)"
case "$LOG" in *"sudo timeout "[0-9]*" sonobuoy retrieve"*) B=1 ;; *) B=0 ;; esac
assert "retrieve is invoked under an in-VM timeout so a stalled exec cannot hang the run" "$B"

run_block 1 7
case "$OUT" in *REACHED_COPY*) B=0 ;; *) B=1 ;; esac
assert "retrieve failure on a killed run preserves sonobuoy's exit status" \
  "$([ "$RC" -eq 7 ] && [ "$B" = 1 ] && echo 1 || echo 0)"

run_block 1 0
assert "retrieve failure on a clean run exits 1 so a missing tarball is never reported as success" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

run_block 124 7
assert "retrieve timeout exits with sonobuoy's status" "$([ "$RC" -eq 7 ] && echo 1 || echo 0)"
case "$ERR" in *"'sonobuoy retrieve' timed out after 120s"*) B=1 ;; *) B=0 ;; esac
assert "retrieve timeout prints a loud error naming the call and the limit" "$B"

run_block 1 7
case "$ERR" in *"timed out"*) B=0 ;; *) B=1 ;; esac
assert "a plain retrieve failure is not mislabelled as a timeout" "$B"

echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
