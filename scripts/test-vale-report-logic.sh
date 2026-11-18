#!/usr/bin/env bash
# Unit test for scripts/vale-report.sh's exit-code contract.
#
# Runs the REAL script as a subprocess over fixture files. The contract matters
# because CI runs the script advisory-only: if alerts ever made the default
# mode exit non-zero, every prose nit would block merges; if --strict stopped
# failing on deterministic u7s/ errors, the future gate would silently pass.
#
# Skips (exit 0, loudly) when vale is not installed.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/vale-report.sh"

if ! command -v vale >/dev/null 2>&1; then
  echo "SKIP: vale not installed"
  exit 0
fi

PASS=0
FAIL=0
assert() {
  if [ "$2" = "1" ]; then
    echo "PASS: $1"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $1"
    FAIL=$(( FAIL + 1 ))
  fi
}

# Exit code of the script, without tripping set -e.
code() {
  set +e
  "$SCRIPT" "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

printf '# Clean\n\nRun the installer.\n' > "$SANDBOX/clean.md"
printf '# Cites\n\nSee ai/findings/2026-01-01-thing.md for the numbers.\n' > "$SANDBOX/findings.md"
printf '# Easy\n\nSimply run the installer.\n' > "$SANDBOX/minimizing.md"

assert "clean doc passes --strict" \
  "$([ "$(code --strict "$SANDBOX/clean.md")" = 0 ] && echo 1 || echo 0)"
assert "bare ai/findings path exits 0 without --strict (advisory must never block)" \
  "$([ "$(code "$SANDBOX/findings.md")" = 0 ] && echo 1 || echo 0)"
assert "bare ai/findings path fails --strict (deleted-on-close file is a broken reference)" \
  "$([ "$(code --strict "$SANDBOX/findings.md")" = 1 ] && echo 1 || echo 0)"
assert "warning-level u7s rule does not fail --strict (only deterministic errors gate)" \
  "$([ "$(code --strict "$SANDBOX/minimizing.md")" = 0 ] && echo 1 || echo 0)"

OUT="$("$SCRIPT" "$SANDBOX/minimizing.md" 2>&1)"
assert "report names the u7s rule that fired" \
  "$(echo "$OUT" | grep -q 'u7s.Minimizing' && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
