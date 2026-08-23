#!/usr/bin/env bash
# Regression test for install.sh's --tarball-url checksum verification
# (mayor-te5y0): a corrupted or tampered-with tarball download must never
# reach `tar -xzf` (and eventually run as root) just because curl's own exit
# code was 0 -- a proxy or flaky network can serve a truncated-but-200
# response, or bytes can get bit-flipped in transit.
#
# install.sh itself cannot be run directly here (it requires root + systemd +
# apt, none of which this test environment has, and none of which are
# relevant to the checksum logic under test) -- instead, the real
# fetch_tarball_with_checksum() function body is extracted verbatim from
# install.sh's own source at test time (same pattern test-install-logic.sh
# uses for its --iface regex) so this test fails if that logic regresses,
# not just if a hand-duplicated copy of it does. curl's file:// support
# stands in for http(s):// here: from fetch_tarball_with_checksum's own
# perspective the two are indistinguishable (same curl invocation, same
# subsequent sha256sum check), and file:// needs no network or Docker.
#
# Each call under test runs in its own `bash -c` subprocess (not sourced
# directly into this script): the function under test calls a bare `exit 1`
# on a checksum mismatch, which -- if run directly in this test script's own
# process -- would kill this whole test script instead of producing a
# reportable FAIL. Isolating it means a real failure is asserted and
# reported, not just crashed past.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# --- Extract the real function under test from install.sh's own source -----
EXTRACTED="$WORK_DIR/fetch_tarball_with_checksum.sh"
awk '/^fetch_tarball_with_checksum\(\) \{$/,/^}$/' "$INSTALL" > "$EXTRACTED"
assert "fetch_tarball_with_checksum() was successfully extracted from install.sh's real source (if this fails, the tests below are testing nothing -- a rename or reshape broke extraction)" \
  "$([ -s "$EXTRACTED" ] && echo 1 || echo 0)"

# Runs the real extracted function against $1 (a file:// URL) in its own
# subprocess, printing the resolved $TARBALL as a trailing "TARBALL=..."
# line on success so the caller can inspect the downloaded copy without this
# test script sharing a process (and thus a `set -e`/exit fate) with the
# function under test. Sets FETCH_EXIT/FETCH_OUTPUT/FETCH_TARBALL globals.
run_fetch() {
  local url="$1" out rc
  set +e
  out="$(FN_FILE="$EXTRACTED" URL="$url" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090 # dynamically extracted from install.sh
    source "$FN_FILE"
    fetch_tarball_with_checksum "$URL"
    echo "TARBALL=$TARBALL"
  ' 2>&1)"
  rc=$?
  set -e
  FETCH_EXIT="$rc"
  FETCH_OUTPUT="$out"
  # `|| true`: grep legitimately finds zero matches on the failure path (the
  # function exits before ever printing "TARBALL=..."), which must not trip
  # this script's own `set -e`/pipefail before FETCH_TARBALL is assigned.
  FETCH_TARBALL="$(printf '%s\n' "$out" | grep '^TARBALL=' | sed 's/^TARBALL=//')" || true
}

# --- Fixture: an "origin" server directory served via file:// -------------
ORIGIN_DIR="$WORK_DIR/origin"
mkdir -p "$ORIGIN_DIR"
GOOD_TARBALL="$ORIGIN_DIR/u7s-v0.0.0-test.tar.gz"
printf 'not a real tarball, just fixture bytes for the checksum test\n' > "$GOOD_TARBALL"
# The sidecar always holds the digest of the GENUINE bytes -- exactly what
# .github/workflows/release-tarball.yaml publishes for the real asset.
sha256sum "$GOOD_TARBALL" | cut -d' ' -f1 > "$GOOD_TARBALL.sha256"

# ---------------------------------------------------------------------------
# Happy path: uncorrupted download must succeed and must not be a vacuous
# always-pass check -- if this can't pass on matching input, the corrupted-
# download test below proves nothing about checksum logic specifically (it
# could just be that the function always fails).
# ---------------------------------------------------------------------------
run_fetch "file://$GOOD_TARBALL"
assert "fetch_tarball_with_checksum succeeds when the downloaded tarball matches its sidecar (the real-world happy path every install must pass through)" \
  "$([ "$FETCH_EXIT" -eq 0 ] && echo 1 || echo 0)"
if [ "$FETCH_EXIT" -ne 0 ]; then
  echo "$FETCH_OUTPUT"
fi
assert "on success, the resolved TARBALL points at a local copy with the exact bytes just verified (the caller's later 'tar -xzf \$TARBALL' must extract what was actually checked, not something else)" \
  "$([ -n "$FETCH_TARBALL" ] && [ -f "$FETCH_TARBALL" ] && diff -q "$FETCH_TARBALL" "$GOOD_TARBALL" >/dev/null 2>&1 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Corrupted download: bit-flip one byte of the origin tarball (simulating
# in-transit corruption or a truncated-but-200 proxy response) while its
# published sidecar still names the ORIGINAL, uncorrupted digest -- exactly
# what a real corrupted download looks like from the client's point of view.
# This is the acceptance-criteria case: install.sh must hard-fail here, not
# silently proceed to `tar -xzf` a tampered/corrupted archive as root.
# ---------------------------------------------------------------------------
CORRUPT_TARBALL="$ORIGIN_DIR/u7s-v0.0.0-corrupt.tar.gz"
cp "$GOOD_TARBALL" "$CORRUPT_TARBALL"
# Flip the first byte (0x6e 'n' -> 0x4e 'N') in place -- a real bit-flip, not
# a truncation or append, so file size is unchanged but content differs.
printf 'N' | dd of="$CORRUPT_TARBALL" bs=1 seek=0 count=1 conv=notrunc >/dev/null 2>&1
# The sidecar still names the CORRECT (pre-corruption) digest, exactly like a
# real release where the sidecar is generated once from the genuine artifact.
cp "$GOOD_TARBALL.sha256" "$CORRUPT_TARBALL.sha256"
assert "fixture setup: the corrupted tarball's bytes actually differ from the original (otherwise the assertions below wouldn't be exercising the mismatch path at all)" \
  "$(! diff -q "$CORRUPT_TARBALL" "$GOOD_TARBALL" >/dev/null 2>&1 && echo 1 || echo 0)"

run_fetch "file://$CORRUPT_TARBALL"
assert "fetch_tarball_with_checksum exits non-zero on a checksum mismatch (install.sh must genuinely FAIL, not just warn, or a corrupted/tampered download gets extracted and its binaries run as root)" \
  "$([ "$FETCH_EXIT" -ne 0 ] && echo 1 || echo 0)"
assert "the failure message names the mismatch explicitly (checksum mismatch + expected/actual), not a generic curl/tar error an operator would have to guess the cause of" \
  "$(printf '%s' "$FETCH_OUTPUT" | grep -q "checksum mismatch" && printf '%s' "$FETCH_OUTPUT" | grep -q "expected:" && printf '%s' "$FETCH_OUTPUT" | grep -q "actual:" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
