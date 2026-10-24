#!/usr/bin/env bash
# Logic test for the JWKS kid helpers in sa-key-rotation.sh. The e2e runs under pipefail, so a
# kid-presence check that early-exits grep inside a pipeline can fail on a present kid
# (SIGPIPE to the producer) and false-FAIL a required CI check.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/e2e-pki-rotation/sa-key-rotation.sh
source "$HERE/sa-key-rotation.sh"

PASS=0; FAIL=0
check() {
  local label="$1"; shift
  if "$@"; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
not() { ! "$@"; }

# Far more output than a pipe buffer, with the wanted kid sorting first: grep -q matches
# immediately while sort still has unwritten data.
jwks_kids() {
  { echo kid-a; for i in $(seq 1 30000); do echo "zz-filler-kid-$i"; done; } | sort
}

check "a listed kid is found even when the producer has more output than grep reads, so a present signing kid never false-fails the e2e" \
  kid_listed kid-a
check "an unlisted kid is reported absent" not kid_listed kid-missing
check "the first kid other than the given one is returned under a large listing" \
  test "$(first_other_kid kid-a)" = "zz-filler-kid-1"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
