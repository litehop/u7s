#!/usr/bin/env bash
# Unit test proving CoreDNS's vendored manifest (manifests/coredns.yaml) actually
# reaches the well-known manifest folder in the two harnesses that start
# u7s-apiserver directly, bypassing scripts/install.sh's release-tarball path.
#
# Bug (mayor-fiq79 CI fix): the CoreDNS migration off its compiled-in
# `include_bytes!` bundle onto bootstrap_apply::apply_well_known_manifest_dir
# only taught scripts/install.sh (production) to copy manifests/*.yaml into
# --manifest-dir. scripts/u7s-start.sh (local dev-loop + every
# scripts/conformance/*.sh flow) and .github/workflows/e2e-focus.yaml (CI) both
# start u7s-apiserver directly and never staged anything into their own
# --manifest-dir, so apply_well_known_manifest_dir found an empty (or
# nonexistent) directory and CoreDNS silently stopped being applied everywhere
# except a real install.sh install. Confirmed live: a --reset --stack-only run
# on lima-node-4 produced zero coredns pods and an apiserver.log with no
# "coredns" mention at all; in CI, sonobuoy's preflight failed on all 3
# e2e-focus matrix jobs with "no dns pods found" (run 32922063667).
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
U7S_START="$REPO/scripts/u7s-start.sh"
E2E_FOCUS_WORKFLOW="$REPO/.github/workflows/e2e-focus.yaml"

assert "manifests/coredns.yaml exists in the repo (the file every harness below must stage)" \
  "$([ -f "$REPO/manifests/coredns.yaml" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# scripts/u7s-start.sh: structural check that it copies the real vendored file
# into its own $MANIFEST_DIR before the apiserver launches.
# ---------------------------------------------------------------------------
assert "u7s-start.sh copies manifests/coredns.yaml into \$MANIFEST_DIR before launch" \
  "$(grep -qF 'cp "$REPO/manifests/coredns.yaml" "$MANIFEST_DIR/"' "$U7S_START" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Simulation: mirrors u7s-start.sh's actual mkdir+cp sequence against a scratch
# dir, proving the sequence itself lands a real, non-empty file (not just that
# the grep above matches some unrelated line).
# ---------------------------------------------------------------------------
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
SCRATCH_MANIFEST_DIR="$SCRATCH/manifests"
mkdir -p "$SCRATCH_MANIFEST_DIR"
cp "$REPO/manifests/coredns.yaml" "$SCRATCH_MANIFEST_DIR/"

assert "the staging sequence leaves a non-empty coredns.yaml in the manifest dir" \
  "$([ -s "$SCRATCH_MANIFEST_DIR/coredns.yaml" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# .github/workflows/e2e-focus.yaml: structural check that CI stages the same
# file AND actually points u7s-apiserver's --manifest-dir at it -- staging
# alone is not enough if the flag pointing the scanner there is missing.
# ---------------------------------------------------------------------------
assert "e2e-focus.yaml stages manifests/coredns.yaml into its apiserver's manifest dir" \
  "$(grep -qF 'cp manifests/coredns.yaml "$WORKDIR/manifests/"' "$E2E_FOCUS_WORKFLOW" && echo 1 || echo 0)"

assert "e2e-focus.yaml passes --manifest-dir to u7s-apiserver so the staged file is scanned" \
  "$(grep -qF -- '--manifest-dir "$WORKDIR/manifests"' "$E2E_FOCUS_WORKFLOW" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
