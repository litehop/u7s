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
tar -czf "$WORK/good.tgz" -C "$WORK/fixture" bridge host-local loopback portmap dhcp tap
GOOD_SHA="$(sha256_of "$WORK/good.tgz")"
cp "$WORK/good.tgz" "$WORK/tampered.tgz"
printf 'extra' >> "$WORK/tampered.tgz"

RUNNER="$WORK/runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -euo pipefail'
  command -v sha256sum >/dev/null 2>&1 || echo 'sha256sum() { shasum -a 256 "$@"; }'
  echo 'curl() { while [ $# -gt 0 ]; do [ "$1" = -o ] && cp "$SERVED" "$2"; shift; done; }'
  awk '/^CNI_PLUGINS=/' "$SCRIPT"
  awk '/^fetch_cni_plugins\(\) \{/,/^\}/' "$SCRIPT"
  echo 'fetch_cni_plugins "$DEST" https://example.invalid/cni.tgz "$EXPECTED"'
} > "$RUNNER"

ok_status=0
SERVED="$WORK/good.tgz" EXPECTED="$GOOD_SHA" DEST="$WORK/ok" bash "$RUNNER" > "$WORK/ok.out" 2>&1 || ok_status=$?
assert "a tarball matching the pinned digest is unpacked" \
  "$([ "$ok_status" -eq 0 ] && [ -x "$WORK/ok/bridge" ] && [ -x "$WORK/ok/portmap" ] && echo 1 || echo 0)"
assert "only the plugins install.sh uses are staged, keeping unused plugins (dhcp, tap, ...) out of the release tarball" \
  "$([ "$(ls "$WORK/ok" | tr '\n' ' ')" = "bridge host-local loopback portmap " ] && echo 1 || echo 0)"

bad_status=0
SERVED="$WORK/tampered.tgz" EXPECTED="$GOOD_SHA" DEST="$WORK/bad" bash "$RUNNER" > "$WORK/bad.out" 2>&1 || bad_status=$?
assert "a tampered tarball (digest differs from the pin) fails the build instead of shipping unverified plugins" \
  "$([ "$bad_status" -ne 0 ] && grep -q 'checksum mismatch' "$WORK/bad.out" && echo 1 || echo 0)"
assert "a tampered tarball is never extracted" \
  "$([ ! -e "$WORK/bad" ] && echo 1 || echo 0)"

pin="$(sed -n 's/^CNI_PLUGINS_SHA256_AMD64="\([0-9a-f]*\)"$/\1/p' "$SCRIPT")"
assert "the build script pins a 64-hex SHA-256 for the amd64 plugin tarball and passes it to the fetch" \
  "$([ "${#pin}" -eq 64 ] && grep -q '^  "\$CNI_PLUGINS_SHA256_AMD64"$' "$SCRIPT" && echo 1 || echo 0)"
assert "kubectl is fetched through the same sha256 + cosign loop as kubelet" \
  "$(grep -q '^for bin in kubelet kube-controller-manager kubectl; do$' "$SCRIPT" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
