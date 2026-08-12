#!/usr/bin/env bash
# Unit test for scripts/conformance/write-build-provenance.sh.
#
# Exercises the REAL script as a subprocess (same technique as
# test-sample-run-metrics-logic.sh), not a copied-out fragment of its logic.
#
# This is the regression guard for the exact incident that motivated the bead:
# a 2026-08-11 run read as a four-way regression (2 test failures, ~2x
# wall-clock, 64 watchdog namespace reaps, ~5x apiserver RSS) that turned out
# to be entirely a --features dhat / trim_backtraces(50) profiling artifact --
# discoverable only after a full multi-agent log-archaeology investigation,
# because no artifact in the run dir recorded whether profiling was even on.
# If the dhat feature/depth fields in meta/build.json ever silently stop
# reflecting --profile, that exact class of wasted investigation recurs.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/write-build-provenance.sh"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"

PASS=0
FAIL=0
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

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

# ---------------------------------------------------------------------------
# 1. No --profile: meta/build.json must record dhat as OFF -- a bare
#    conformance run's numbers must never be silently mistakable for a
#    profiled one when someone later diffs two run dirs.
# ---------------------------------------------------------------------------
RUN1="$TMPDIR_TEST/run1"
mkdir -p "$RUN1"
bash "$SCRIPT" --run-dir "$RUN1" --vm no-such-vm-1 --argv-json '["--focus","Foo"]' >/dev/null

BUILD1="$RUN1/meta/build.json"
assert "build.json is written under meta/, not alongside sonobuoy's own meta/config.json" \
  "$([ -f "$BUILD1" ] && echo 1 || echo 0)"
assert "un-profiled run: dhat_feature_enabled is false" \
  "$([ "$(jq -r '.apiserver.dhat_feature_enabled' "$BUILD1")" = "false" ] && echo 1 || echo 0)"
assert "un-profiled run: dhat_backtrace_depth is null (not a stray default depth)" \
  "$([ "$(jq -r '.apiserver.dhat_backtrace_depth' "$BUILD1")" = "null" ] && echo 1 || echo 0)"
assert "run_all_argv round-trips the exact invocation" \
  "$([ "$(jq -c '.run_all_argv' "$BUILD1")" = '["--focus","Foo"]' ] && echo 1 || echo 0)"
assert "git_sha is recorded and matches this checkout's actual HEAD" \
  "$([ "$(jq -r '.git_sha' "$BUILD1")" = "$(git -C "$REPO" rev-parse HEAD)" ] && echo 1 || echo 0)"
assert "no --extra-node: node_topology reports a single-VM cluster" \
  "$([ "$(jq -r '.node_topology.vm_count' "$BUILD1")" = "1" ] && [ "$(jq -r '.node_topology.extra_node' "$BUILD1")" = "null" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. --profile with NO --dhat-depth: must record depth 10 -- the dhat crate's
#    own default and the apiserver's safer fallback, not the old hardcoded 50
#    that made a full-suite --profile run cost +82% wall-clock silently.
# ---------------------------------------------------------------------------
RUN2="$TMPDIR_TEST/run2"
mkdir -p "$RUN2"
bash "$SCRIPT" --run-dir "$RUN2" --vm no-such-vm-2 --profile --argv-json '["--profile"]' >/dev/null
BUILD2="$RUN2/meta/build.json"
assert "--profile with no --dhat-depth: dhat_feature_enabled is true" \
  "$([ "$(jq -r '.apiserver.dhat_feature_enabled' "$BUILD2")" = "true" ] && echo 1 || echo 0)"
assert "--profile with no --dhat-depth: depth defaults to 10, not the old hardcoded 50" \
  "$([ "$(jq -r '.apiserver.dhat_backtrace_depth' "$BUILD2")" = "10" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. --profile --dhat-depth 50: an operator's deliberate deep-stack
#    investigation must be visible in the artifact too, not just the default.
# ---------------------------------------------------------------------------
RUN3="$TMPDIR_TEST/run3"
mkdir -p "$RUN3"
bash "$SCRIPT" --run-dir "$RUN3" --vm no-such-vm-3 --profile --dhat-depth 50 --argv-json '["--profile","--dhat-depth","50"]' >/dev/null
BUILD3="$RUN3/meta/build.json"
assert "--profile --dhat-depth 50: the non-default depth is recorded exactly" \
  "$([ "$(jq -r '.apiserver.dhat_backtrace_depth' "$BUILD3")" = "50" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. --extra-node: a 2-node topology must be distinguishable in the artifact
#    from a 1-node one -- otherwise a cross-run comparison can't rule out
#    "different node count" as the actual cause of a wall-clock difference.
# ---------------------------------------------------------------------------
RUN4="$TMPDIR_TEST/run4"
mkdir -p "$RUN4"
bash "$SCRIPT" --run-dir "$RUN4" --vm no-such-vm-4a --extra-node no-such-vm-4b --argv-json '[]' >/dev/null
BUILD4="$RUN4/meta/build.json"
assert "--extra-node: node_topology reports a 2-VM cluster with the extra node named" \
  "$([ "$(jq -r '.node_topology.vm_count' "$BUILD4")" = "2" ] && [ "$(jq -r '.node_topology.extra_node' "$BUILD4")" = "no-such-vm-4b" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Regression guard: prove a naive "always report the requested/default depth,
# whether or not dhat is even compiled in" approach -- the obvious first
# attempt, and exactly the ambiguity that cost the original investigation --
# is what the current script must NOT do.
# ---------------------------------------------------------------------------
write_build_json_old_buggy() {
  local run_dir="$1" dhat_depth="${2:-10}"
  mkdir -p "$run_dir/meta"
  jq -n --argjson depth "$dhat_depth" '{apiserver: {dhat_backtrace_depth: $depth}}' > "$run_dir/meta/build.json"
}
RUN_OLD="$TMPDIR_TEST/run-old-buggy"
mkdir -p "$RUN_OLD"
write_build_json_old_buggy "$RUN_OLD"
assert "(regression guard) naive always-report-a-depth approach can't distinguish un-profiled from depth-10-profiled" \
  "$([ "$(jq -r '.apiserver.dhat_backtrace_depth' "$RUN_OLD/meta/build.json")" = "$(jq -r '.apiserver.dhat_backtrace_depth' "$BUILD2")" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural checks against the real run-all.sh source: the above proves the
# writer's own logic is right, but not that run-all.sh actually invokes it
# for every sonobuoy run (not just profiled ones).
# ---------------------------------------------------------------------------
assert "run-all.sh actually invokes write-build-provenance.sh" \
  "$(grep -qF 'write-build-provenance.sh' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh captures the original argv before the arg-parsing loop consumes it" \
  "$(grep -qF 'ORIGINAL_ARGV=("$@")' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
