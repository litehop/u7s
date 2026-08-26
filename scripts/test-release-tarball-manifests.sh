#!/usr/bin/env bash
# Regression test for scripts/build-release-tarball.sh's manifests/ staging
# step: vendored in-cluster manifest YAMLs committed at manifests/ (repo
# root) must actually land inside the packaged tarball, since install.sh
# copies them from there into --manifest-output-dir at install
# time -- the whole point of vendoring these files in-repo rather than having
# install.sh fetch them from GitHub, which fails outright on target nodes
# with no IPv4/GitHub connectivity at all.
#
# The full build (cargo cross-compile + dl.k8s.io fetch) isn't practical to
# run in a lightweight test, so this extracts the staging-and-package tail of
# build-release-tarball.sh verbatim (same awk-range technique as
# test-release-tarball-licenses.sh and test-install-checksum.sh) and runs it
# against fixture binaries and a fixture manifests/ dir -- exercising the
# actual shipped `mkdir`/`cp`/`tar` lines rather than a hand-maintained copy
# that could silently drift out of sync.
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
# from the license-copy comment (which precedes the manifests-staging step
# this test exists to cover) through the final `tar tzf` listing.
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

# --- fixtures: fake stage dir with all 4 binaries already "built"/"fetched",
# and a fixture manifests/ dir standing in for the repo-root one -------------
ROOT_DIR_FIXTURE="$WORK/root"
mkdir -p "$ROOT_DIR_FIXTURE/manifests"
cp "$ROOT_DIR/THIRD_PARTY_LICENSES.md" "$ROOT_DIR_FIXTURE/"
echo 'kind: ConfigMap' > "$ROOT_DIR_FIXTURE/manifests/kube-proxy.yaml"
# A non-.yaml file must NOT be swept into the tarball -- install.sh's own
# copy step globs *.yaml only, and a stray file here would otherwise ride
# along into every install's well-known auto-apply folder.
echo 'not a manifest' > "$ROOT_DIR_FIXTURE/manifests/README.md"

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
# Acceptance criterion this bead exists for: manifests/*.yaml
# committed at the repo root must end up inside the packaged tarball's own
# manifests/ directory, at the path install.sh's find-by-name manifest-copy
# step expects.
# ---------------------------------------------------------------------------
status=0
ROOT_DIR="$ROOT_DIR_FIXTURE" OUT_DIR="$OUT_DIR" STAGE_NAME="$STAGE_NAME" \
  WORK_DIR="$WORK_DIR" STAGE_DIR="$STAGE_DIR" \
  bash "$RUNNER" > "$WORK/out.txt" 2>&1 || status=$?
assert "build-release-tarball.sh's staging/packaging step succeeds against a fully-staged directory with a manifests/ fixture" \
  "$([ "$status" -eq 0 ] && echo 1 || echo 0)"

TARBALL="$OUT_DIR/${STAGE_NAME}.tar.gz"
assert "the packaged tarball contains manifests/kube-proxy.yaml, the vendored manifest committed at the repo root" \
  "$(tar tzf "$TARBALL" 2>/dev/null | grep -q "${STAGE_NAME}/manifests/kube-proxy.yaml" && echo 1 || echo 0)"

assert "the packaged tarball's manifests/ directory does NOT include manifests/README.md -- only *.yaml ships, matching install.sh's own *.yaml-only copy glob so non-manifest files never reach the well-known auto-apply folder" \
  "$(tar tzf "$TARBALL" 2>/dev/null | grep -q "${STAGE_NAME}/manifests/README.md" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# The repo's real manifests/ directory is empty today (kube-proxy/Flannel/
# CoreDNS migrate onto this mechanism via separate follow-on beads) -- the
# staging step must not fail or skip creating manifests/ in that case, since
# install.sh's own copy step still needs a manifests/ directory
# to find (even an empty one) rather than treating a missing directory
# differently from a real, currently-empty one.
# ---------------------------------------------------------------------------
EMPTY_ROOT_FIXTURE="$WORK/root-empty"
mkdir -p "$EMPTY_ROOT_FIXTURE/manifests"
cp "$ROOT_DIR/THIRD_PARTY_LICENSES.md" "$EMPTY_ROOT_FIXTURE/"

EMPTY_STAGE_NAME="${STAGE_NAME}-empty"
EMPTY_STAGE_DIR="$WORK_DIR/$EMPTY_STAGE_NAME"
mkdir -p "$EMPTY_STAGE_DIR"
for f in u7s-apiserver u7s-scheduler kubelet kube-controller-manager; do
  printf 'fake %s binary\n' "$f" > "$EMPTY_STAGE_DIR/$f"
done

empty_status=0
ROOT_DIR="$EMPTY_ROOT_FIXTURE" OUT_DIR="$OUT_DIR" STAGE_NAME="$EMPTY_STAGE_NAME" \
  WORK_DIR="$WORK_DIR" STAGE_DIR="$EMPTY_STAGE_DIR" \
  bash "$RUNNER" > "$WORK/out-empty.txt" 2>&1 || empty_status=$?
assert "the staging step succeeds and still creates manifests/ in the tarball when the repo's manifests/ directory has zero .yaml files yet -- today's real state, matching install.sh's own graceful handling of an empty well-known folder" \
  "$([ "$empty_status" -eq 0 ] && tar tzf "$OUT_DIR/${EMPTY_STAGE_NAME}.tar.gz" 2>/dev/null | grep -q "${EMPTY_STAGE_NAME}/manifests/" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Mutation self-check (CLAUDE.md rule 14): prove this suite would actually
# catch a reverted fix. Strip the manifests-staging block from a scratch copy
# of build-release-tarball.sh and rerun the same packaging step -- if the
# resulting tarball then lacks manifests/kube-proxy.yaml, the assertion above
# is doing real work.
# ---------------------------------------------------------------------------
MUTATED="$WORK/build-release-tarball-mutated.sh"
awk '/^# manifests\/\*\.yaml \(repo root/,/^fi$/ { next } { print }' "$SCRIPT" > "$MUTATED"
if diff -q "$SCRIPT" "$MUTATED" > /dev/null 2>&1; then
  assert "mutation self-check: the manifests-staging block exists in build-release-tarball.sh to mutate (if this fails, the block was renamed/reshaped and this suite no longer exercises it)" 0
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
  assert "mutation self-check: with the manifests-staging block removed, the resulting tarball is missing manifests/kube-proxy.yaml -- proving the assertion above would fail if this fix were ever reverted" \
    "$([ "$mutated_status" -eq 0 ] && ! tar tzf "$mutated_tarball" 2>/dev/null | grep -q 'manifests/kube-proxy.yaml' && echo 1 || echo 0)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
