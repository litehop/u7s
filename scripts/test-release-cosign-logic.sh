#!/usr/bin/env bash
# Regression test for scripts/build-release-tarball.sh's cosign verification of
# the upstream kubelet / kube-controller-manager binaries: a same-origin
# .sha256 cannot detect a compromised dl.k8s.io, so the build must abort when
# the Sigstore signature does not verify against Kubernetes' release identity.
#
# verify_k8s_signature() and the identity constants are extracted verbatim from
# the build script; curl and cosign are stubbed so no network is needed.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted patterns hold the build
# script's own literal, unexpanded source text.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$DIR/.." && pwd)"
SCRIPT="$DIR/build-release-tarball.sh"
WORKFLOW="$ROOT_DIR/.github/workflows/release-tarball.yaml"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

RUNNER="$WORK/runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  # curl stub: create whatever -o names, like a successful download.
  echo 'curl() { while [ $# -gt 0 ]; do [ "$1" = -o ] && : > "$2"; shift; done; }'
  echo 'cosign() { echo "$*" >> "$COSIGN_LOG"; return "$COSIGN_RC"; }'
  awk '/^K8S_COSIGN_IDENTITY=/,/^K8S_COSIGN_ISSUER=/' "$SCRIPT"
  awk '/^verify_k8s_signature\(\) \{/,/^\}/' "$SCRIPT"
  echo 'verify_k8s_signature "$1" "https://dl.k8s.io/x/kubelet"'
  echo 'echo VERIFIED'
} > "$RUNNER"

BIN="$WORK/kubelet"
: > "$BIN"

ok_status=0
COSIGN_LOG="$WORK/ok.log" COSIGN_RC=0 bash "$RUNNER" "$BIN" > "$WORK/ok.out" 2>&1 || ok_status=$?
assert "a signature cosign accepts lets the build continue" \
  "$([ "$ok_status" -eq 0 ] && grep -q VERIFIED "$WORK/ok.out" && echo 1 || echo 0)"
assert "cosign is pinned to the Kubernetes release signer identity and Google issuer, not any Sigstore identity" \
  "$(grep -q -- '--certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com --certificate-oidc-issuer https://accounts.google.com' "$WORK/ok.log" && echo 1 || echo 0)"
assert "the .sig and .cert are left next to the binary so they ship in the tarball" \
  "$([ -e "$BIN.sig" ] && [ -e "$BIN.cert" ] && echo 1 || echo 0)"

bad_status=0
COSIGN_LOG="$WORK/bad.log" COSIGN_RC=1 bash "$RUNNER" "$BIN" > "$WORK/bad.out" 2>&1 || bad_status=$?
assert "a signature cosign rejects aborts the build before the unverified binary is packaged" \
  "$([ "$bad_status" -ne 0 ] && ! grep -q VERIFIED "$WORK/bad.out" && grep -q 'cosign signature verification failed for kubelet' "$WORK/bad.out" && echo 1 || echo 0)"

# The function is useless unless the fetch loop calls it for each binary.
loop_body="$(awk '/^for bin in kubelet kube-controller-manager; do/,/^done/' "$SCRIPT")"
assert "the kubelet/kube-controller-manager fetch loop calls verify_k8s_signature" \
  "$(printf '%s' "$loop_body" | grep -qF 'verify_k8s_signature "$STAGE_DIR/$bin" "$url"' && echo 1 || echo 0)"
assert "the release workflow installs a pinned cosign before the tarball build" \
  "$(grep -qE 'uses: sigstore/cosign-installer@[0-9a-f]{40} ' "$WORKFLOW" && grep -qE 'cosign-release: v[0-9]+\.[0-9]+\.[0-9]+$' "$WORKFLOW" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
