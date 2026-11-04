#!/usr/bin/env bash
# Regression test for scripts/build-release-tarball.sh's CNI plugin fetch:
# containernetworking/plugins publishes no signature, so the only integrity
# guard is the SHA-256 pinned in the build script. A build that accepts a
# tarball not matching the pin would ship unverified code that install.sh
# runs as root.
#
# fetch_cni_plugins() and the plugin list are extracted verbatim from the
# build script; curl is stubbed to serve a local fixture tarball.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted patterns hold the build
# script's own literal, unexpanded source text.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/build-release-tarball.sh"
LIB="$DIR/lib/release-fetch.sh"
ARM="$DIR/release-gate/build-arm64-tarball.sh"

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

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$WORK/fixture"
for f in bridge host-local loopback portmap dhcp tap; do
  printf 'fake %s\n' "$f" > "$WORK/fixture/$f"
  chmod 0755 "$WORK/fixture/$f"
done
# Upstream members are "./"-prefixed; GNU tar matches member names literally, so
# a fixture without the prefix would not exercise the real extract on Linux.
tar -czf "$WORK/good.tgz" -C "$WORK/fixture" ./bridge ./host-local ./loopback ./portmap ./dhcp ./tap
GOOD_SHA="$(sha256_of "$WORK/good.tgz")"
cp "$WORK/good.tgz" "$WORK/tampered.tgz"
printf 'extra' >> "$WORK/tampered.tgz"

RUNNER="$WORK/runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  echo 'curl() { while [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$SERVED" "$2"; case "$1" in https://*) echo "$1" >> "$URL_LOG";; esac; shift; done; }'
  echo '. "'"$LIB"'"'
  echo 'eval "$CALL"'
} > "$RUNNER"
export URL_LOG="$WORK/urls.log"
CALL_DIRECT='fetch_cni_plugins "$DEST" https://example.invalid/cni.tgz "$EXPECTED"'

ok_status=0
SERVED="$WORK/good.tgz" EXPECTED="$GOOD_SHA" DEST="$WORK/ok" CALL="$CALL_DIRECT" bash "$RUNNER" > "$WORK/ok.out" 2>&1 || ok_status=$?
assert "a tarball matching the pinned digest is unpacked" \
  "$([ "$ok_status" -eq 0 ] && [ -x "$WORK/ok/bridge" ] && [ -x "$WORK/ok/portmap" ] && echo 1 || echo 0)"
assert "only the plugins install.sh uses are staged, keeping unused plugins (dhcp, tap, ...) out of the release tarball" \
  "$([ "$(ls "$WORK/ok" | tr '\n' ' ')" = "bridge host-local loopback portmap " ] && echo 1 || echo 0)"

bad_status=0
SERVED="$WORK/tampered.tgz" EXPECTED="$GOOD_SHA" DEST="$WORK/bad" CALL="$CALL_DIRECT" bash "$RUNNER" > "$WORK/bad.out" 2>&1 || bad_status=$?
assert "a tampered tarball (digest differs from the pin) fails the build instead of shipping unverified plugins" \
  "$([ "$bad_status" -ne 0 ] && grep -q 'checksum mismatch' "$WORK/bad.out" && echo 1 || echo 0)"
assert "a tampered tarball is never extracted" \
  "$([ ! -e "$WORK/bad" ] && echo 1 || echo 0)"

pin_amd64="$(sed -n 's/^CNI_PLUGINS_SHA256_AMD64="\([0-9a-f]*\)"$/\1/p' "$LIB")"
pin_arm64="$(sed -n 's/^CNI_PLUGINS_SHA256_ARM64="\([0-9a-f]*\)"$/\1/p' "$LIB")"
assert "the shared lib pins distinct 64-hex SHA-256s for the amd64 and arm64 plugin tarballs" \
  "$([ "${#pin_amd64}" -eq 64 ] && [ "${#pin_arm64}" -eq 64 ] && [ "$pin_amd64" != "$pin_arm64" ] && echo 1 || echo 0)"

# Each arch must be checked against its own pin: an arm64 gate VM verifying
# against the amd64 digest (or vice versa) would either always fail or, worse,
# be wired to skip the check.
for arch in amd64 arm64; do
  other=arm64; [ "$arch" = arm64 ] && other=amd64
  pin_override="CNI_PLUGINS_SHA256_$(echo "$arch" | tr a-z A-Z)=$GOOD_SHA; CNI_PLUGINS_SHA256_$(echo "$other" | tr a-z A-Z)=0000"
  : > "$URL_LOG"
  st=0
  SERVED="$WORK/good.tgz" DEST="$WORK/arch-$arch" CALL="$pin_override; fetch_cni_plugins_for_arch \"\$DEST\" $arch" bash "$RUNNER" > "$WORK/arch-$arch.out" 2>&1 || st=$?
  assert "$arch plugins are fetched from the $arch release asset and verified against the $arch pin" \
    "$([ "$st" -eq 0 ] && grep -q "cni-plugins-linux-$arch-v" "$URL_LOG" && [ -x "$WORK/arch-$arch/bridge" ] && echo 1 || echo 0)"
  st=0
  SERVED="$WORK/good.tgz" DEST="$WORK/arch-$other" CALL="$pin_override; fetch_cni_plugins_for_arch \"\$DEST\" $other" bash "$RUNNER" > "$WORK/arch-$other-bad.out" 2>&1 || st=$?
  assert "$other plugins are rejected when only the $arch pin matches" \
    "$([ "$st" -ne 0 ] && grep -q 'checksum mismatch' "$WORK/arch-$other-bad.out" && echo 1 || echo 0)"
  rm -rf "$WORK/arch-$arch" "$WORK/arch-$other"
done

assert "the amd64 release build fetches kubectl through fetch_k8s_binary (sha256 + cosign) and plugins through fetch_cni_plugins_for_arch" \
  "$(grep -q '^  fetch_k8s_binary "\$STAGE_DIR" "\$K8S_ARCH" "\$bin"$' "$SCRIPT" && grep -q 'fetch_cni_plugins_for_arch "\$STAGE_DIR/cni-plugins" "\$K8S_ARCH"' "$SCRIPT" && echo 1 || echo 0)"
assert "the arm64 release-gate build stages kubectl (sha256 + cosign) and the pinned CNI plugins through the same shared functions, so install.sh finds every required binary" \
  "$(grep -q '^fetch_k8s_binary "\$STAGE" arm64 kubectl$' "$ARM" && grep -q 'fetch_cni_plugins_for_arch "\$STAGE/cni-plugins" arm64' "$ARM" && grep -q 'release-fetch.sh' "$ARM" && echo 1 || echo 0)"
assert "the arm64 gate build never reuses a cached kubectl, so a binary swapped in the cache is not shipped unverified" \
  "$(grep -q 'CACHE/kubectl' "$ARM" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
