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
LIB="$DIR/lib/release-fetch.sh"
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
  awk '/^K8S_COSIGN_IDENTITY=/,/^K8S_COSIGN_ISSUER=/' "$LIB"
  awk '/^verify_k8s_signature\(\) \{/,/^\}/' "$LIB"
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

# End to end through fetch_k8s_binary with real PATH lookup: cosign is optional,
# but when present it must gate the build, and the output must say which
# verification ran.
STUBS="$WORK/stubs"
NOCOSIGN="$WORK/nocosign"
mkdir -p "$STUBS" "$NOCOSIGN"
CONTENT_SHA="$(printf 'x\n' | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)"
cat > "$STUBS/curl" <<STUB
#!/usr/bin/env bash
out=""
while [ \$# -gt 0 ]; do [ "\$1" = -o ] && out="\$2"; shift; done
if [ -n "\$out" ]; then echo x > "\$out"; else echo $CONTENT_SHA; fi
STUB
cat > "$STUBS/cosign" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$COSIGN_LOG"
exit "$COSIGN_RC"
STUB
chmod +x "$STUBS/curl" "$STUBS/cosign"
cp "$STUBS/curl" "$NOCOSIGN/curl"
for tool in bash cut chmod basename dirname sha256sum shasum; do
  p="$(command -v "$tool" 2>/dev/null || true)"
  [ -n "$p" ] && ln -sf "$p" "$NOCOSIGN/$tool"
done

FETCH_RUNNER="$WORK/fetch-runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'K8S_VERSION=1.37.1'
  echo ". '$LIB'"
  echo 'fetch_k8s_binary "$1" amd64 kubelet'
  echo 'echo FETCHED'
} > "$FETCH_RUNNER"

run_fetch() { # <name> <PATH> <cosign-rc>
  mkdir -p "$WORK/$1"
  local st=0
  COSIGN_LOG="$WORK/$1.log" COSIGN_RC="$3" PATH="$2" bash "$FETCH_RUNNER" "$WORK/$1" > "$WORK/$1.out" 2>&1 || st=$?
  echo "$st" > "$WORK/$1.status"
}

run_fetch pass "$STUBS:$PATH" 0
assert "with cosign on PATH and a good signature the binary is fetched and the output says cosign verified" \
  "$([ "$(cat "$WORK/pass.status")" -eq 0 ] && grep -q FETCHED "$WORK/pass.out" && grep -q 'kubelet: sha256 + cosign signature verified' "$WORK/pass.out" && [ -s "$WORK/pass.log" ] && echo 1 || echo 0)"

run_fetch fail "$STUBS:$PATH" 1
assert "with cosign on PATH a bad signature aborts the build, so a tampered kubelet with a matching sha256 is never packaged" \
  "$([ "$(cat "$WORK/fail.status")" -ne 0 ] && ! grep -q FETCHED "$WORK/fail.out" && grep -q 'cosign signature verification failed for kubelet' "$WORK/fail.out" && echo 1 || echo 0)"

run_fetch absent "$NOCOSIGN" 1
assert "without cosign the build still succeeds on sha256 and says cosign verification was skipped, so the operator knows the weaker check ran" \
  "$([ "$(cat "$WORK/absent.status")" -eq 0 ] && grep -q FETCHED "$WORK/absent.out" && grep -q 'cosign verification SKIPPED (cosign is not installed)' "$WORK/absent.out" && [ ! -e "$WORK/absent/kubelet.sig" ] && echo 1 || echo 0)"

sha_runner="$WORK/sha-runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'K8S_VERSION=1.37.1'
  echo ". '$LIB'"
  echo 'sha256_of() { echo deadbeef; }'
  echo 'fetch_k8s_binary "$1" amd64 kubelet'
} > "$sha_runner"
mkdir -p "$WORK/shabad"
sha_status=0
PATH="$NOCOSIGN" bash "$sha_runner" "$WORK/shabad" > "$WORK/shabad.out" 2>&1 || sha_status=$?
assert "without cosign a sha256 mismatch still aborts, so skipping signatures never weakens the checksum gate" \
  "$([ "$sha_status" -ne 0 ] && grep -q 'checksum mismatch for kubelet' "$WORK/shabad.out" && echo 1 || echo 0)"

assert "the build script announces which verification will run (cosign present or skipped)" \
  "$(grep -qF "cosign verification skipped because cosign isn't installed" "$SCRIPT" && ! grep -q 'cosign not found on PATH' "$SCRIPT" && echo 1 || echo 0)"

# The function is useless unless every fetched binary goes through it.
loop_body="$(awk '/^for bin in kubelet kube-controller-manager kubectl; do/,/^done/' "$SCRIPT")"
fetch_body="$(awk '/^fetch_k8s_binary\(\) \{/,/^\}/' "$LIB")"
assert "the kubelet/kube-controller-manager/kubectl fetch loop goes through fetch_k8s_binary, which calls verify_k8s_signature" \
  "$(printf '%s' "$loop_body" | grep -qF 'fetch_k8s_binary "$STAGE_DIR" "$K8S_ARCH" "$bin"' && printf '%s' "$fetch_body" | grep -qF 'verify_k8s_signature "$dest/$bin" "$url"' && echo 1 || echo 0)"
assert "the release workflow installs a pinned cosign before the tarball build" \
  "$(grep -qE 'uses: sigstore/cosign-installer@[0-9a-f]{40} ' "$WORKFLOW" && grep -qE 'cosign-release: v[0-9]+\.[0-9]+\.[0-9]+$' "$WORKFLOW" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
