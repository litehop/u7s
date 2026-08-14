#!/usr/bin/env bash
# Unit test for the final monitoring-artifact re-copy gate in run-all.sh.
#
# Bug (mayor-xzkqw): the "Re-copy the monitoring artifacts now that they
# cover the whole run" block (which picks up metrics-03-pre-teardown.prom
# and any rss.csv/ring-age.csv growth since 06-run-sonobuoy.sh's own
# post-run copy) lived INSIDE `if [ "$PROFILE" -eq 1 ]`. Any plain
# (non --profile) conformance run never stops the apiserver in that block,
# so it never re-ran the copy -- the pre-teardown snapshot stayed trapped
# under --workdir (ephemeral/gitignored/worker-scoped) and never reached
# the permanent per-run temp/e2e/<slug>/monitoring/ directory that's meant
# to be the audited artifact set for a run.
#
# This test proves the gate now depends only on whether a $RUN_DIR was
# produced (i.e. sonobuoy ran at all) -- not on --profile -- and that the
# real run-all.sh source is wired that way, not just this mirror.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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
# should_recopy_monitoring() -- mirrors run-all.sh's post-fix gate exactly:
# the re-copy runs whenever a $RUN_DIR was produced (sonobuoy ran),
# regardless of --profile. Empty run_dir (e.g. --stack-only, where sonobuoy
# never ran) is a no-op.
# ---------------------------------------------------------------------------
should_recopy_monitoring() {
  local run_dir="$1"
  [ -n "$run_dir" ] && echo 1 || echo 0
}

# The pre-fix version -- mirrors the exact bug: the re-copy additionally
# required --profile, even though nothing about the copy itself is
# profile-specific.
should_recopy_monitoring_old_buggy() {
  local profile="$1" run_dir="$2"
  if [ "$profile" -eq 1 ] && [ -n "$run_dir" ]; then
    echo 1
  else
    echo 0
  fi
}

# recopy_monitoring() -- mirrors run-all.sh's actual copy commands verbatim.
recopy_monitoring() {
  local workdir="$1" run_dir="$2"
  local monitoring_dir="$run_dir/monitoring"
  mkdir -p "$monitoring_dir"
  [ -f "$workdir/rss.csv" ]      && cp "$workdir/rss.csv" "$monitoring_dir/rss.csv"
  [ -f "$workdir/vm-free.csv" ]  && cp "$workdir/vm-free.csv" "$monitoring_dir/vm-free.csv"
  [ -f "$workdir/ring-age.csv" ] && cp "$workdir/ring-age.csv" "$monitoring_dir/ring-age.csv"
  cp "$workdir"/metrics-*.prom "$monitoring_dir/" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Fixture: a run that produced a $RUN_DIR (sonobuoy ran) with a
# pre-teardown metrics snapshot sitting only under --workdir, exactly as
# run-all.sh leaves it right before this re-copy runs.
# ---------------------------------------------------------------------------
WORKDIR_T="$TMPDIR_TEST/workdir"
RUN_DIR_T="$TMPDIR_TEST/e2e/0814-slug"
mkdir -p "$WORKDIR_T" "$RUN_DIR_T"
echo "pre-teardown-metrics" > "$WORKDIR_T/metrics-03-pre-teardown.prom"

# ---------------------------------------------------------------------------
# 1. A PLAIN (non --profile) run: the fixed gate must still fire, so the
#    pre-teardown snapshot reaches the permanent RUN_DIR/monitoring/ dir --
#    this is the exact case that was broken before mayor-xzkqw.
# ---------------------------------------------------------------------------
if [ "$(should_recopy_monitoring "$RUN_DIR_T")" = "1" ]; then
  recopy_monitoring "$WORKDIR_T" "$RUN_DIR_T"
fi
assert "a plain conformance run's pre-teardown metrics snapshot reaches the permanent RUN_DIR/monitoring/ directory" \
  "$([ -f "$RUN_DIR_T/monitoring/metrics-03-pre-teardown.prom" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD buggy (--profile-gated) version genuinely
# drops the snapshot for this same plain-run fixture -- the actual bug this
# fix closes.
rm -rf "${RUN_DIR_T:?}/monitoring"
if [ "$(should_recopy_monitoring_old_buggy 0 "$RUN_DIR_T")" = "1" ]; then
  recopy_monitoring "$WORKDIR_T" "$RUN_DIR_T"
fi
assert "(regression guard) pre-fix --profile-gated re-copy genuinely drops the pre-teardown snapshot for a plain run" \
  "$([ ! -f "$RUN_DIR_T/monitoring/metrics-03-pre-teardown.prom" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. A --profile run: behavior must be unchanged -- the re-copy still fires.
# ---------------------------------------------------------------------------
if [ "$(should_recopy_monitoring "$RUN_DIR_T")" = "1" ]; then
  recopy_monitoring "$WORKDIR_T" "$RUN_DIR_T"
fi
assert "a --profile run's pre-teardown metrics snapshot still reaches RUN_DIR/monitoring/ (unchanged behavior)" \
  "$([ -f "$RUN_DIR_T/monitoring/metrics-03-pre-teardown.prom" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. --stack-only: sonobuoy never ran, so $RUN_DIR is empty -- the gate must
#    stay a no-op (nothing to write into, no directory to create).
# ---------------------------------------------------------------------------
assert "an empty RUN_DIR (--stack-only, sonobuoy never ran) keeps the gate a no-op" \
  "$([ "$(should_recopy_monitoring "")" = "0" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural check against the real run-all.sh source: the mirror above
# proves the decision logic is right, but not that run-all.sh actually
# wires it up that way instead of still nesting it inside --profile.
# ---------------------------------------------------------------------------
RUN_ALL="$(cd "$(dirname "$0")" && pwd)/run-all.sh"

assert "run-all.sh contains exactly one monitoring re-copy block (not left duplicated across --profile and non-profile paths)" \
  "$([ "$(grep -c 'Re-copy the monitoring artifacts' "$RUN_ALL")" -eq 1 ] && echo 1 || echo 0)"

# The exact bug was nesting depth, not the inner condition itself (the old
# code already gated the innermost `if` on RUN_DIR too, just several levels
# deep inside `if [ "$PROFILE" -eq 1 ]`). A top-level (zero-indent) match on
# this precise line -- which only this fix's block uses (the ${RUN_DIR:-}
# default is new; every pre-existing use of $RUN_DIR in this file assumes
# it's already set) -- is what actually distinguishes "runs for every
# RUN_DIR-producing invocation" from "runs only under --profile".
assert "run-all.sh's monitoring re-copy gate sits at top level, not re-nested inside the --profile teardown block" \
  "$(grep -qxF 'if [ -n "${RUN_DIR:-}" ]; then' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
