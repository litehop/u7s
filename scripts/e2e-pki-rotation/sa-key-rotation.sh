#!/usr/bin/env bash
# Real-binary proof that the apiserver rotates its ServiceAccount signing key with a kid
# overlap: tokens minted before the switch keep authenticating until they expire, new tokens
# carry the new kid, and the old kid leaves the JWKS (and stops verifying) once it is retired.
#
# Needs an apiserver built with --features pki-test-knobs and started with
# U7S_PKI_TEST_SA_ROTATION_SECS=<R> (run-all.sh --pki-test-sa-rotation <R> --stack-only does
# both). With R, the signing key rotates every R seconds, a successor is published R/4 before it
# signs, tokens live at most R/6 and the replaced key is dropped R/4 after the switch. Use
# R >= 120 so the one-second poll interval is small against those windows. One rotation takes
# about R seconds; --iterations n repeats it.
#
#   scripts/e2e-pki-rotation/sa-key-rotation.sh --kubeconfig temp/u7s/kubeconfig \
#       --workdir temp/u7s --rotation 120
#
# Asserts, with polling and deadlines (never fixed sleeps):
#   1. the JWKS lists the signing kid, then the successor too (published before it signs);
#   2. the last token minted before the switch (kid A) still authenticates (TokenReview) right
#      after the first token with the new kid B is minted, and B tokens authenticate;
#   3. the JWKS drops A once retired, and an A token no longer authenticates.
# With --pod <name> (a running pod whose projected token is read via kubectl exec) additionally
# asserts that token authenticates before, across and after the rotation: kubelet refreshes it
# in step with the (compressed) token lifetime.
#
# On failure the script dumps the JWKS, the rotation log lines and the apiserver log tail.
set -euo pipefail

POLL_INTERVAL=1

poll() {
  local deadline="$1"; shift
  local end=$((SECONDS + deadline))
  while ! "$@"; do
    [ "$SECONDS" -lt "$end" ] || return 1
    sleep "$POLL_INTERVAL"
  done
}

# jwt_kid <token>: the kid in the JWT header (base64url, so restore alphabet and padding).
jwt_kid() {
  local h="${1%%.*}"
  h="$(printf '%s' "$h" | tr '_-' '/+')"
  while [ $(( ${#h} % 4 )) -ne 0 ]; do h="$h="; done
  printf '%s' "$h" | openssl base64 -d -A | jq -r '.kid // empty'
}

# Capture before matching: `jwks_kids | grep -q` makes grep exit on the first hit, the
# upstream `sort` then dies of SIGPIPE and pipefail turns a present kid into a failure.
kid_listed() {
  local kids
  kids="$(jwks_kids)"
  grep -qx -- "$1" <<<"$kids"
}
# first_other_kid <kid>: a listed kid other than <kid>.
first_other_kid() {
  local kids
  kids="$(jwks_kids)"
  grep -vx -m1 -- "$1" <<<"$kids"
}

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

KC=""
WORKDIR=""
ROTATION=120
ITERATIONS=1
POD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KC="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --rotation) ROTATION="$2"; shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --pod) POD="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[ -n "$KC" ] && [ -n "$WORKDIR" ] || {
  echo "usage: $0 --kubeconfig <path> --workdir <path> [--rotation <R>] [--iterations <n>] [--pod <name>]" >&2
  exit 1
}

k() { kubectl --kubeconfig "$KC" --request-timeout=15s "$@"; }
mint() { k create token default --duration=10m; }
jwks_kids() { k get --raw /openid/v1/jwks | jq -r '.keys[].kid' | sort; }
jwks_count() { jwks_kids | wc -l | tr -d ' '; }
authenticates() {
  printf '{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"%s"}}' "$1" |
    k create --raw /apis/authentication.k8s.io/v1/tokenreviews -f - 2>/dev/null |
    jq -e '.status.authenticated == true' >/dev/null
}
pod_token_ok() {
  local t
  t="$(k exec "$POD" -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)" && authenticates "$t"
}

dump_diagnostics() {
  echo "=== diagnostics ===" >&2
  echo "--- jwks ---" >&2
  k get --raw /openid/v1/jwks >&2 2>&1 || true
  echo "--- apiserver SA key log lines ---" >&2
  grep -E "SA keyring|SA tokens now signed|SA key rotation|pki-test-knobs" "$WORKDIR/apiserver.log" >&2 || true
  echo "--- apiserver log tail ---" >&2
  tail -30 "$WORKDIR/apiserver.log" >&2 || true
}
fail() { echo "FAIL: $*" >&2; dump_diagnostics; exit 1; }
trap 'echo "FAIL: unexpected error at line $LINENO: $BASH_COMMAND" >&2; dump_diagnostics' ERR
set -E

grep -q "SA signing key rotates every" "$WORKDIR/apiserver.log" ||
  fail "apiserver.log has no SA rotation knob line: the binary was not built with --features pki-test-knobs or was started without U7S_PKI_TEST_SA_ROTATION_SECS"

poll 60 k get --raw /readyz >/dev/null 2>&1 || fail "apiserver not ready"

DEADLINE=$((ROTATION + 60))
LAST_A=""
B_KID=""

single_key() { [ "$(jwks_count)" = 1 ]; }
successor_published() { [ "$(jwks_count)" -ge 2 ]; }
switched() {
  local t
  t="$(mint)"
  [ "$(jwt_kid "$t")" = "$KID_B" ] && return 0
  LAST_A="$t"
  return 1
}
a_gone() { ! kid_listed "$KID_A"; }

for i in $(seq 1 "$ITERATIONS"); do
  echo "== rotation $i/$ITERATIONS =="
  # Start from a settled keyring: a replaced key still in its overlap would be mistaken for
  # the successor below.
  poll "$DEADLINE" single_key || fail "JWKS never settled to a single key"
  LAST_A="$(mint)"
  KID_A="$(jwt_kid "$LAST_A")"
  [ -n "$KID_A" ] || fail "token has no kid header"
  echo "signing kid A=$KID_A"
  kid_listed "$KID_A" || fail "JWKS does not list the signing kid $KID_A"
  authenticates "$LAST_A" || fail "fresh token not authenticated"
  [ -z "$POD" ] || poll 30 pod_token_ok || fail "pod projected token does not authenticate before rotation"

  echo "waiting for the successor to be published (JWKS lists two kids)"
  poll "$DEADLINE" successor_published || fail "successor key never appeared in the JWKS"
  KID_B="$(first_other_kid "$KID_A")"
  [ "$(jwt_kid "$(mint)")" = "$KID_A" ] || fail "successor already signs: it was not pre-published"
  echo "successor B=$KID_B published while A still signs"

  echo "waiting for signing to switch to B"
  POLL_INTERVAL=0.5 poll "$DEADLINE" switched || fail "signing never switched to the successor"
  authenticates "$LAST_A" || fail "token minted by A just before the switch stopped authenticating during the overlap"
  authenticates "$(mint)" || fail "token signed by the new key B does not authenticate"
  echo "A token (kid $KID_A) still authenticates after the switch; new tokens carry kid $KID_B"
  [ -z "$POD" ] || poll 60 pod_token_ok || fail "pod projected token stopped authenticating across the switch"

  echo "waiting for A to be retired"
  poll "$DEADLINE" a_gone || fail "old key $KID_A never left the JWKS"
  ! authenticates "$LAST_A" || fail "token from the retired key still authenticates"
  [ "$(jwks_count)" = 1 ] || fail "JWKS should hold only B after retirement, got: $(jwks_kids | tr '\n' ' ')"
  [ -z "$POD" ] || poll 60 pod_token_ok || fail "pod projected token does not authenticate after rotation"
  echo "rotation $i ok: A retired, JWKS=[$KID_B]"
done
echo "PASS: SA signing key rotated $ITERATIONS time(s) with overlap"
