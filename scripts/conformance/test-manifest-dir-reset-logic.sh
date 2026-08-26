#!/usr/bin/env bash
# Unit test for $MANIFEST_DIR surviving a u7s-start.sh --reset cycle.
#
# Bug (review fix, PR #1376): $MANIFEST_DIR is a subdirectory of
# $WORKDIR ($WORKDIR/manifests), so --reset's `rm -rf "$WORKDIR"` wipes it
# too. Only $WORKDIR itself was recreated afterward (`mkdir -p "$WORKDIR"`),
# leaving $MANIFEST_DIR missing when the apiserver launches with
# --manifest-dir pointing at it. apply_well_known_manifest_dir
# (bootstrap_apply.rs) treats a missing dir as "nothing to apply" at info
# level, not an error -- so every --reset (u7s-start.sh's own documented
# "start fresh" flow) silently applied zero manifests, defeating the
# well-known-manifest-folder feature the conformance dev-loop depends on.
#
# This test runs the exact reset-then-recreate command sequence u7s-start.sh
# uses (rm -rf + mkdir -p) against a scratch directory, proving $MANIFEST_DIR
# survives, and includes a regression guard proving the pre-fix sequence
# (mkdir -p "$WORKDIR" alone) genuinely leaves it missing.
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

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# ---------------------------------------------------------------------------
# Post-fix sequence: mirrors u7s-start.sh's actual line order -- first-run
# creation, then a --reset wipe of $WORKDIR, then recreation of BOTH dirs.
# ---------------------------------------------------------------------------
WORKDIR="$SCRATCH/workdir"
MANIFEST_DIR="$WORKDIR/manifests"
mkdir -p "$MANIFEST_DIR"                  # first-run creation (u7s-start.sh line ~116)
echo "canary" > "$MANIFEST_DIR/canary.yaml"

rm -rf "$WORKDIR"                         # --reset wipe (line ~148)
mkdir -p "$WORKDIR" "$MANIFEST_DIR"       # post-fix recreation (line ~156)

assert "post-fix: \$MANIFEST_DIR exists after --reset, before apiserver launch" \
  "$([ -d "$MANIFEST_DIR" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: the pre-fix sequence recreated only $WORKDIR, so
# $MANIFEST_DIR must be genuinely absent afterward -- proving this test would
# have failed before the fix and isn't just documentation.
# ---------------------------------------------------------------------------
WORKDIR2="$SCRATCH/workdir2"
MANIFEST_DIR2="$WORKDIR2/manifests"
mkdir -p "$MANIFEST_DIR2"
rm -rf "$WORKDIR2"
mkdir -p "$WORKDIR2"                      # pre-fix: $MANIFEST_DIR2 not included

assert "(regression guard) pre-fix sequence leaves \$MANIFEST_DIR missing after --reset" \
  "$([ ! -d "$MANIFEST_DIR2" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural check against the real u7s-start.sh source: the simulation above
# proves the sequence works in isolation, but not that u7s-start.sh actually
# runs it. Grep for the fixed post-wipe recreation line.
# ---------------------------------------------------------------------------
U7S_START="$(cd "$(dirname "$0")/.." && pwd)/u7s-start.sh"
assert "u7s-start.sh recreates \$MANIFEST_DIR (not just \$WORKDIR) right after the --reset wipe" \
  "$(grep -qF 'mkdir -p "$WORKDIR" "$MANIFEST_DIR"' "$U7S_START" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
