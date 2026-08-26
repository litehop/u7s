#!/usr/bin/env bash
# Regression test for scripts/build-release-tarball.sh's THIRD_PARTY_LICENSES.md
# staging step: the built tarball must actually contain the Apache-2.0
# attribution required for the bundled kubelet/kube-controller-manager
# binaries, not just have the file sitting unshipped in the repo root.
#
# The full build (cargo cross-compile + dl.k8s.io fetch) isn't practical to
# run in a lightweight test, so this extracts the staging-and-package tail of
# build-release-tarball.sh verbatim (same awk-range technique as
# test-install-checksum.sh) and runs it against fixture binaries -- exercising
# the actual shipped `cp`/`tar` lines rather than a hand-maintained copy that
# could silently drift out of sync.
#
# Exits 0 on success, 1 on any assertion failure.
# shellcheck disable=SC2016 # file-wide: single-quoted `grep`/`awk` patterns
# below intentionally hold build-release-tarball.sh's own literal, unexpanded
# source text.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$DIR/.." && pwd)"
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

# Extracts the staging-and-package tail of build-release-tarball.sh verbatim:
# from the license-copy comment through the final `tar tzf` listing. That
# range is exactly the code path this test exists to cover.
write_stage_and_package_runner() {
  local build_script="$1" runner="$2"
  {
    echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    awk '/^# Apache-2\.0 section 4/,/^tar tzf/' "$build_script"
  } > "$runner"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- fixtures: fake stage dir with all 4 binaries already "built"/"fetched" -
ROOT_DIR_FIXTURE="$WORK/root"
mkdir -p "$ROOT_DIR_FIXTURE"
cp "$ROOT_DIR/THIRD_PARTY_LICENSES.md" "$ROOT_DIR_FIXTURE/"

OUT_DIR="$WORK/dist"
STAGE_NAME="u7s-vTEST-x86_64-unknown-linux-gnu"
WORK_DIR="$WORK/work"
STAGE_DIR="$WORK_DIR/$STAGE_NAME"
mkdir -p "$STAGE_DIR" "$OUT_DIR"
for f in u7s-apiserver u7s-scheduler kubelet kube-controller-manager; do
  printf 'fake %s binary\n' "$f" > "$STAGE_DIR/$f"
done

RUNNER="$WORK/runner.sh"
write_stage_and_package_runner "$SCRIPT" "$RUNNER"

# ---------------------------------------------------------------------------
# Acceptance criterion this bead exists for: THIRD_PARTY_LICENSES.md must land
# inside the packaged tarball. Apache-2.0 section 4 requires redistributing
# license text with unmodified upstream binaries (kubelet,
# kube-controller-manager); a tarball missing it ships those binaries
# out of compliance.
# ---------------------------------------------------------------------------
status=0
ROOT_DIR="$ROOT_DIR_FIXTURE" OUT_DIR="$OUT_DIR" STAGE_NAME="$STAGE_NAME" \
  WORK_DIR="$WORK_DIR" STAGE_DIR="$STAGE_DIR" \
  bash "$RUNNER" > "$WORK/out.txt" 2>&1 || status=$?
assert "build-release-tarball.sh's staging/packaging step succeeds against a fully-staged directory" \
  "$([ "$status" -eq 0 ] && echo 1 || echo 0)"

TARBALL="$OUT_DIR/${STAGE_NAME}.tar.gz"
assert "the packaged tarball contains THIRD_PARTY_LICENSES.md (Apache-2.0 attribution for bundled kubelet/kube-controller-manager)" \
  "$(tar tzf "$TARBALL" 2>/dev/null | grep -q "${STAGE_NAME}/THIRD_PARTY_LICENSES.md" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove this suite would actually
# catch a reverted fix. Strip the license-copy line from a scratch copy of
# build-release-tarball.sh and rerun the same packaging step -- if the
# resulting tarball then lacks THIRD_PARTY_LICENSES.md, the assertion above
# is doing real work.
# ---------------------------------------------------------------------------
MUTATED="$WORK/build-release-tarball-mutated.sh"
grep -v 'cp "\$ROOT_DIR/THIRD_PARTY_LICENSES.md" "\$STAGE_DIR/"' "$SCRIPT" > "$MUTATED"
if diff -q "$SCRIPT" "$MUTATED" > /dev/null 2>&1; then
  assert "mutation self-check: the license-copy line exists in build-release-tarball.sh to mutate (if this fails, the line was renamed/reshaped and this suite no longer exercises it)" 0
else
  MUTATED_STAGE_NAME="${STAGE_NAME}-mutated"
  MUTATED_STAGE_DIR="$WORK_DIR/$MUTATED_STAGE_NAME"
  mkdir -p "$MUTATED_STAGE_DIR"
  for f in u7s-apiserver u7s-scheduler kubelet kube-controller-manager; do
    printf 'fake %s binary\n' "$f" > "$MUTATED_STAGE_DIR/$f"
  done

  MUTATED_RUNNER="$WORK/runner-mutated.sh"
  write_stage_and_package_runner "$MUTATED" "$MUTATED_RUNNER"

  mutated_status=0
  ROOT_DIR="$ROOT_DIR_FIXTURE" OUT_DIR="$OUT_DIR" STAGE_NAME="$MUTATED_STAGE_NAME" \
    WORK_DIR="$WORK_DIR" STAGE_DIR="$MUTATED_STAGE_DIR" \
    bash "$MUTATED_RUNNER" > /dev/null 2>&1 || mutated_status=$?

  mutated_tarball="$OUT_DIR/${MUTATED_STAGE_NAME}.tar.gz"
  assert "mutation self-check: with the license-copy line removed, the resulting tarball is missing THIRD_PARTY_LICENSES.md -- proving the assertion above would fail if this fix were ever reverted" \
    "$([ "$mutated_status" -eq 0 ] && ! tar tzf "$mutated_tarball" 2>/dev/null | grep -q 'THIRD_PARTY_LICENSES.md' && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
