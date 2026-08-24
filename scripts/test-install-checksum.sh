#!/usr/bin/env bash
# Regression test for scripts/install.sh's fetch_tarball() checksum
# verification: install.sh must genuinely fail, not just warn, when a
# downloaded tarball's checksum doesn't match its sidecar.
#
# fetch_tarball() is extracted from install.sh's live source at test time (an
# awk range from its opening to its closing brace) rather than reimplemented
# here -- the whole point of this test is to exercise the actual shipped
# logic, not a hand-maintained copy that can silently drift out of sync.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted `echo`/`sed` patterns
# below intentionally hold install.sh's own literal, unexpanded source text.
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

# Extracts fetch_tarball() verbatim from an install.sh-shaped file and writes
# a standalone runner that sources it and calls fetch_tarball "$1", so a
# caller only has to `bash "$runner" <url>` and read $TARBALL back out.
write_fetch_tarball_runner() {
  local install_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    awk '/^fetch_tarball\(\) \{/,/^\}/' "$install_script"
    echo 'fetch_tarball "$1"'
    echo 'echo "TARBALL_PATH=$TARBALL"'
  } > "$runner"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- fixtures: a fake tarball and its correct sidecar ------------------------
TARBALL_SRC="$WORK/fake-release.tar.gz"
printf 'not a real tarball, just stable bytes to hash\n' > "$TARBALL_SRC"
sha256sum "$TARBALL_SRC" | cut -d' ' -f1 > "$TARBALL_SRC.sha256"

RUNNER="$WORK/runner.sh"
write_fetch_tarball_runner "$INSTALL" "$RUNNER"

# ---------------------------------------------------------------------------
# Happy path: a tarball whose bytes match its sidecar must download and
# verify cleanly -- every real release always has a correct sidecar, so a
# regression here would break every install, not just corrupted ones.
# ---------------------------------------------------------------------------
happy_status=0
happy_out="$(bash "$RUNNER" "file://$TARBALL_SRC" 2>&1)" || happy_status=$?
assert "fetch_tarball succeeds when the downloaded tarball's sha256 matches its .sha256 sidecar" \
  "$([ "$happy_status" -eq 0 ] && echo 1 || echo 0)"
assert "fetch_tarball still reports the downloaded tarball's local path once checksum verification passes" \
  "$(printf '%s' "$happy_out" | grep -q '^TARBALL_PATH=' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Corrupted tarball: the acceptance criterion this bead exists for. Bytes
# reaching `tar -xzf` unverified end up as binaries run as root, so a mismatch
# must hard-fail (non-zero exit with a clear message), not just log a
# warning and proceed.
# ---------------------------------------------------------------------------
CORRUPT_SRC="$WORK/corrupt-release.tar.gz"
cp "$TARBALL_SRC" "$CORRUPT_SRC"
printf 'x' >> "$CORRUPT_SRC"
cp "$TARBALL_SRC.sha256" "$CORRUPT_SRC.sha256"

corrupt_status=0
corrupt_out="$(bash "$RUNNER" "file://$CORRUPT_SRC" 2>&1)" || corrupt_status=$?
assert "fetch_tarball hard-fails (non-zero exit) when the downloaded tarball's sha256 does not match its sidecar" \
  "$([ "$corrupt_status" -ne 0 ] && echo 1 || echo 0)"
assert "fetch_tarball's checksum-mismatch error names the mismatch, so an operator isn't left debugging a bare non-zero exit" \
  "$(printf '%s' "$corrupt_out" | grep -qi 'mismatch' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove this suite would actually
# catch a reverted fix, not just document today's behavior. Bypass the
# checksum comparison in a scratch copy of install.sh and rerun the exact
# corruption scenario above against it -- if the corrupted download is then
# silently accepted, the corruption assertions above are doing real work.
# ---------------------------------------------------------------------------
MUTATED="$WORK/install-mutated.sh"
sed 's/if \[ "\$expected" != "\$actual" \]; then/if false; then/' "$INSTALL" > "$MUTATED"
if diff -q "$INSTALL" "$MUTATED" > /dev/null 2>&1; then
  assert "mutation self-check: the checksum-comparison line exists in install.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_RUNNER="$WORK/runner-mutated.sh"
  write_fetch_tarball_runner "$MUTATED" "$MUTATED_RUNNER"
  mutated_status=0
  bash "$MUTATED_RUNNER" "file://$CORRUPT_SRC" > /dev/null 2>&1 || mutated_status=$?
  assert "mutation self-check: with the checksum comparison bypassed, the same corrupted download is wrongly accepted -- proving the corruption test above would fail if this fix were ever reverted" \
    "$([ "$mutated_status" -eq 0 ] && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
