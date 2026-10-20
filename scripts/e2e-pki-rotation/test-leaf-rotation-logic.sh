#!/usr/bin/env bash
# Logic test for the pure helpers in leaf-rotation.sh. The e2e's verdicts rest on three of
# them: poll (a deadline that actually expires, so a stuck rotation fails instead of hanging
# CI), pem_serial (the serial change is the evidence of a swap) and cert_has_life (renewal
# must happen while the old cert is still valid).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/e2e-pki-rotation/leaf-rotation.sh
source "$HERE/leaf-rotation.sh"
POLL_INTERVAL=0.2

PASS=0; FAIL=0
check() {
  local label="$1"; shift
  if "$@"; then echo "PASS: $label"; PASS=$((PASS + 1)); else echo "FAIL: $label"; FAIL=$((FAIL + 1)); fi
}
not() { ! "$@"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkcert() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj "/CN=$1" -keyout "$TMP/$1.key" -out "$TMP/$1.pem" 2>/dev/null
}
mkcert a
mkcert b

serial_of() { pem_serial <"$TMP/$1.pem"; }
check "two different certs have different serials, so a swap is observable" \
  not test "$(serial_of a)" = "$(serial_of b)"
check "the same cert has a stable serial, so no swap is not mistaken for one" \
  test "$(serial_of a)" = "$(serial_of a)"

check "a cert valid for a day has an hour of life left" cert_has_life "$TMP/a.pem" 3600
check "a cert valid for a day does not have two days of life left" not cert_has_life "$TMP/a.pem" 172800

tries="$TMP/tries"; : >"$tries"
third_try() { echo x >>"$tries"; [ "$(wc -l <"$tries")" -ge 3 ]; }
check "poll returns success once the condition turns true" poll 5 third_try
check "poll gives up after its deadline instead of hanging" not poll 1 false

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
