#!/usr/bin/env bash
# Unit test for scripts/sensitive-conformance-gate.sh's two fast-path
# mechanisms: comment-only-diff skip via difftastic, and reusing a fresh
# matching prior sonobuoy junit result.
#
# Exercises the REAL script (and, for scenarios C/D, the REAL compiled
# u7s-junit-reuse-check binary) as a subprocess against disposable sandbox
# git repos -- same technique as test-check-doc-budget-logic.sh -- not a
# reimplementation of the difftastic invocation or the junit-matching logic,
# which would keep passing even if the real mechanism regressed.
#
# This is a SAFETY-relevant gate: every scenario below that exercises a
# "can't tell for sure" situation (missing difft, a stale/mismatched junit)
# asserts the FAIL-SAFE direction -- the gate must fall through to requiring
# the expensive fresh sonobuoy run, never silently let the push through.
#
#   A. A genuine comment-only diff -> skipped via difftastic (only run if
#      difft is installed; otherwise reported as SKIP, not silently omitted
#      -- see scenario E for how the *safety* direction still gets covered
#      when difft is absent).
#   B. A genuine functional diff -> falls through to the fresh-run
#      requirement (regardless of whether difft/cargo happen to be
#      installed -- every path through the gate for a real change must
#      still end up blocked without a fresh PASS or a reusable one).
#   C. A stale prior junit result (a commit touching the sensitive file
#      landed after the recorded run's timestamp) -> rejected as
#      non-reusable, falls through to the fresh-run requirement. Requires
#      cargo to build the real u7s-junit-reuse-check binary; SKIP (not
#      silently omitted) if cargo is unavailable.
#   D. A fresh, clean, focus-matching prior junit result -> reused, skipping
#      the sonobuoy run. Same cargo requirement/skip as C.
#   E. difft missing from PATH -> the comment-only fast path is refused
#      (never silently skips) and the push falls through to the next
#      mechanism. Runs for real with difft's own directory stripped from
#      PATH when difft is installed (this dev machine); when difft is
#      genuinely absent (e.g. a CI runner) this exercises the exact same
#      code path with no simulation needed.
#   F. A regression lands on the ref actually being pushed, but a DIFFERENT
#      branch happens to be checked out locally (e.g. `git push
#      origin main:some-ref` while a decoy branch is checked out) -> still
#      rejected as non-reusable. This is an end-to-end check that this
#      SCRIPT threads the real pushed SHA into u7s-junit-reuse-check's
#      `--ref` (not the Rust crate's own unit tests, which can't catch a
#      wiring mistake here -- e.g. forgetting to pass `--ref` at all would
#      make u7s-junit-reuse-check silently fall back to checking out
#      whatever HEAD happens to be, hiding this exact regression). Same
#      cargo requirement/skip as C/D. See PR #1408 review for the original
#      wrong-ref finding.
#
# Exits 0 if every scenario that could run PASSED (skips are reported but do
# not fail the run); exits 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/sensitive-conformance-gate.sh"
SENSITIVE_FILE="crates/apiserver/src/handlers/pods.rs"
REQUIRED_FOCUS="ReplicationController should release no longer matching pods|Job should adopt matching orphans and release non-matching pods"

PASS=0
FAIL=0
SKIP=0

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

skip() {
  local label="$1" reason="$2"
  echo "SKIP: $label ($reason)"
  SKIP=$(( SKIP + 1 ))
}

new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

# Writes $SENSITIVE_FILE with the given body and commits it.
write_and_commit() {
  local dir="$1" body="$2" msg="$3"
  mkdir -p "$dir/$(dirname "$SENSITIVE_FILE")"
  printf '%s' "$body" > "$dir/$SENSITIVE_FILE"
  git -C "$dir" add -A
  git -C "$dir" commit -q -m "$msg"
}

# Same as write_and_commit, but at an explicit author/committer date
# (ISO-8601 WITH a UTC offset, so the fixture's own ordering is immune to
# ambient host timezone) -- only scenario F needs precise control over
# commit timing relative to a recorded junit timestamp; every other scenario
# uses real wall-clock commit times.
write_and_commit_at() {
  local dir="$1" body="$2" msg="$3" date_with_offset="$4"
  mkdir -p "$dir/$(dirname "$SENSITIVE_FILE")"
  printf '%s' "$body" > "$dir/$SENSITIVE_FILE"
  git -C "$dir" add -A
  GIT_AUTHOR_DATE="$date_with_offset" GIT_COMMITTER_DATE="$date_with_offset" \
    git -C "$dir" commit -q -m "$msg"
}

# Stages a junit_01.xml fixture under the layout
# scripts/conformance/06-run-sonobuoy.sh writes real results to.
write_junit_fixture() {
  local dir="$1" timestamp="$2" failures="$3" errors="$4" focus="$5"
  local results_dir="$dir/temp/e2e/fixture-run/plugins/e2e/results/global"
  mkdir -p "$results_dir"
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuites tests="1" disabled="0" errors="%s" failures="%s" time="1.0">\n' "$errors" "$failures"
    printf '  <testsuite name="Kubernetes e2e suite" package="/usr/local/bin" tests="1" disabled="0" skipped="0" errors="%s" failures="%s" time="1.0" timestamp="%s">\n' "$errors" "$failures" "$timestamp"
    printf '    <properties>\n'
    printf '      <property name="FocusStrings" value="%s"></property>\n' "$focus"
    printf '    </properties>\n'
    printf '    <testcase name="[It] spec" classname="Kubernetes e2e suite" status="passed" time="0.1"></testcase>\n'
    printf '  </testsuite>\n'
    printf '</testsuites>\n'
  } > "$results_dir/junit_01.xml"
}

# Portable epoch->UTC-ISO conversion, no trailing offset -- matches a real
# ginkgo junit timestamp (see u7s_junit_reuse_check::JunitSummary::timestamp
# doc comment: the sonobuoy e2e pod and its Lima VM both default to UTC with
# no TZ override, so this bare string denotes UTC wall-clock time). MUST be
# UTC, not this machine's local time: u7s-junit-reuse-check appends an
# explicit `+00:00` to this exact string before handing it to `git
# --since=`, so a host-local timestamp here would make these fixtures
# silently wrong on any non-UTC test-running machine. Same
# try-GNU-then-BSD-date fallback idiom as
# scripts/conformance/test-watchdog-logic.sh.
epoch_to_utc_iso() {
  local epoch="$1"
  date -u -d "@${epoch}" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null || \
    date -u -r "${epoch}" "+%Y-%m-%dT%H:%M:%S"
}

# Current PATH with difft's own directory removed -- the portable way to
# simulate "difft not installed" without touching the real binary. If difft
# is already absent, this is a no-op (returns $PATH unchanged), so scenario
# E below exercises the exact same "missing difft" code path whether it's
# simulated (dev machine with difftastic installed) or genuinely ambient
# (e.g. a CI runner without it).
path_without_difft() {
  local difft_bin difft_dir part out=""
  if ! difft_bin=$(command -v difft 2>/dev/null); then
    printf '%s' "$PATH"
    return 0
  fi
  difft_dir=$(dirname "$difft_bin")
  local IFS=':'
  read -ra parts <<< "$PATH"
  for part in "${parts[@]}"; do
    [ "$part" = "$difft_dir" ] && continue
    out="${out:+$out:}$part"
  done
  printf '%s' "$out"
}

# Runs the REAL gate script against sandbox $1 for range $2, with PATH
# optionally overridden by $3. Always strips the U7S_CONFORMANCE_GATE_*
# env vars first -- an operator's own shell may have these set for their
# assigned VM slot, and this test must be deterministic regardless (every
# scenario here is designed to be decided by the fast-path mechanisms alone,
# never by actually reaching a real sonobuoy run). Sets OUT/RC.
run_gate() {
  local dir="$1" range="$2" use_path="${3:-$PATH}"
  set +e
  OUT=$(env -u U7S_CONFORMANCE_GATE_VM -u U7S_CONFORMANCE_GATE_PORT -u U7S_CONFORMANCE_GATE_KUBELET_PORT \
    PATH="$use_path" bash "$SCRIPT" "$range" "$dir" 2>&1)
  RC=$?
  set -e
}

have_difft() { command -v difft >/dev/null 2>&1; }
have_cargo() { command -v cargo >/dev/null 2>&1; }

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

NOW=$(date +%s)

# ---------------------------------------------------------------------------
# A. Comment-only diff -> skipped via difftastic.
# ---------------------------------------------------------------------------
if have_difft; then
  SA="$SANDBOX_ROOT/a-comment-only"
  new_sandbox "$SA"
  write_and_commit "$SA" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    // old comment
    a + b
}
' old
  OLD_SHA=$(git -C "$SA" rev-parse HEAD)
  write_and_commit "$SA" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    // an entirely different comment, same code
    a + b
}
' new
  NEW_SHA=$(git -C "$SA" rev-parse HEAD)
  run_gate "$SA" "$OLD_SHA..$NEW_SHA"
  # Why this matters: this is the whole point of this fast path -- a pure
  # comment/typo fix to a sensitive file must not pay for a multi-minute
  # live-VM sonobuoy run.
  assert "comment-only diff to a sensitive file skips the sonobuoy gate" \
    "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
  assert "...via the documented difftastic comment-only marker (not some other 0-exit path)" \
    "$(printf '%s' "$OUT" | grep -q "$SENSITIVE_FILE: comment/whitespace-only diff" && echo 1 || echo 0)"
else
  skip "comment-only diff skips the sonobuoy gate" "difft not installed -- brew install difftastic"
fi

# ---------------------------------------------------------------------------
# B. Genuine functional diff -> falls through to the fresh-run requirement.
#    Must hold regardless of whether difft/cargo happen to be installed: a
#    real change to a known-recurring-regression function must never pass
#    through un-gated just because a fast-path tool was unavailable.
# ---------------------------------------------------------------------------
SB="$SANDBOX_ROOT/b-functional-diff"
new_sandbox "$SB"
write_and_commit "$SB" \
  'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b
}
' old
OLD_SHA=$(git -C "$SB" rev-parse HEAD)
write_and_commit "$SB" \
  'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b + 1
}
' new
NEW_SHA=$(git -C "$SB" rev-parse HEAD)
run_gate "$SB" "$OLD_SHA..$NEW_SHA"
assert "genuine functional diff to a sensitive file is NOT skipped" \
  "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
assert "...falls all the way through to the fresh-run VM-slot requirement" \
  "$(printf '%s' "$OUT" | grep -q 'U7S_CONFORMANCE_GATE_VM' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# C. Stale prior junit result (a commit landed after its recorded timestamp)
#    -> rejected as non-reusable, falls through to the fresh-run requirement.
# ---------------------------------------------------------------------------
if have_cargo; then
  SC="$SANDBOX_ROOT/c-stale-junit"
  new_sandbox "$SC"
  write_and_commit "$SC" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b
}
' old
  OLD_SHA=$(git -C "$SC" rev-parse HEAD)
  write_and_commit "$SC" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b + 1
}
' new
  NEW_SHA=$(git -C "$SC" rev-parse HEAD)
  # Junit recorded an hour BEFORE this test run started -- the "new" commit
  # made just above necessarily lands after it, exactly the commit-then-push
  # staleness case this reuse mechanism must catch.
  STALE_TS=$(epoch_to_utc_iso $(( NOW - 3600 )))
  write_junit_fixture "$SC" "$STALE_TS" 0 0 "$REQUIRED_FOCUS"
  run_gate "$SC" "$OLD_SHA..$NEW_SHA"
  assert "stale junit result (commit landed after its timestamp) is rejected" \
    "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
  assert "...junit-reuse-check itself reports no reusable result, not a build failure" \
    "$(printf '%s' "$OUT" | grep -q 'no reusable prior result' && echo 1 || echo 0)"
else
  skip "stale junit result is rejected" "cargo not installed -- cannot build u7s-junit-reuse-check"
fi

# ---------------------------------------------------------------------------
# D. Fresh, clean, focus-matching prior junit result -> reused, skipping the
#    sonobuoy run entirely. This is the other half of the fast-path story: a
#    push whose sensitive-file change was ALREADY verified by a still-valid
#    result must not pay for a redundant run.
# ---------------------------------------------------------------------------
if have_cargo; then
  SD="$SANDBOX_ROOT/d-fresh-junit"
  new_sandbox "$SD"
  write_and_commit "$SD" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b
}
' old
  OLD_SHA=$(git -C "$SD" rev-parse HEAD)
  write_and_commit "$SD" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b + 1
}
' new
  NEW_SHA=$(git -C "$SD" rev-parse HEAD)
  # Junit recorded an hour AFTER this test run started -- necessarily after
  # the "new" commit above, so no commit could have landed later.
  FRESH_TS=$(epoch_to_utc_iso $(( NOW + 3600 )))
  write_junit_fixture "$SD" "$FRESH_TS" 0 0 "$REQUIRED_FOCUS"
  run_gate "$SD" "$OLD_SHA..$NEW_SHA"
  assert "fresh matching clean junit result is reused, skipping the sonobuoy run" \
    "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
  assert "...output names the reused result, not a coincidental other 0-exit path" \
    "$(printf '%s' "$OUT" | grep -q 'Reusing prior sonobuoy result' && echo 1 || echo 0)"
else
  skip "fresh matching junit result is reused" "cargo not installed -- cannot build u7s-junit-reuse-check"
fi

# ---------------------------------------------------------------------------
# E. difft missing -> the comment-only fast path is refused, never silently
#    skipping verification just because a dev-tool happened to be absent.
#    Uses the SAME comment-only diff as scenario A, so the only variable is
#    difft's availability.
# ---------------------------------------------------------------------------
SE="$SANDBOX_ROOT/e-missing-difft"
new_sandbox "$SE"
write_and_commit "$SE" \
  'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    // old comment
    a + b
}
' old
OLD_SHA=$(git -C "$SE" rev-parse HEAD)
write_and_commit "$SE" \
  'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    // an entirely different comment, same code
    a + b
}
' new
NEW_SHA=$(git -C "$SE" rev-parse HEAD)
NO_DIFFT_PATH=$(path_without_difft)
run_gate "$SE" "$OLD_SHA..$NEW_SHA" "$NO_DIFFT_PATH"
assert "missing difft never silently skips a comment-only-looking diff" \
  "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
assert "...falls back because difft is reported missing, not for an unrelated reason" \
  "$(printf '%s' "$OUT" | grep -q 'difft not installed' && echo 1 || echo 0)"
assert "...never prints the comment-only-skip marker when difft could not run" \
  "$(! printf '%s' "$OUT" | grep -q "$SENSITIVE_FILE: comment/whitespace-only diff" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# F. A regression on the pushed ref is caught even when a DIFFERENT branch is
#    checked out locally -- end-to-end proof that THIS SCRIPT (not just
#    u7s-junit-reuse-check's own unit tests) threads the actually-pushed SHA
#    through, not the sandbox's checked-out HEAD.
# ---------------------------------------------------------------------------
if have_cargo; then
  SFF="$SANDBOX_ROOT/f-wrong-ref"
  new_sandbox "$SFF"
  # Explicit commit dates (not real wall-clock time, unlike every other
  # scenario) so the recorded junit timestamp below can be placed PRECISELY
  # between the base and regression commits -- this is what makes scenario F
  # a genuine isolation of the wrong-ref bug rather than just another stale-
  # junit case: base lands BEFORE the recording, regression lands AFTER it,
  # so only walking the actually-pushed ref's own history (not a decoy
  # HEAD's) can see the regression at all.
  write_and_commit_at "$SFF" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b
}
' old "2026-08-26T04:00:00+00:00"
  OLD_SHA=$(git -C "$SFF" rev-parse HEAD)
  write_and_commit_at "$SFF" \
    'fn validate_pod_spec_immutable(a: i32, b: i32) -> i32 {
    a + b + 1
}
' new "2026-08-26T05:00:00+00:00"
  NEW_SHA=$(git -C "$SFF" rev-parse HEAD)
  # Check out a DECOY branch pointing at the OLD commit -- simulates `git
  # push origin main:some-ref` (an explicit-refspec push) while a different
  # branch is checked out locally. $OLD_SHA..$NEW_SHA is still the range
  # being pushed; nothing about that range changes just because the sandbox
  # repo's own working copy is sitting elsewhere. Walking the decoy's own
  # history would only ever see the OLD commit, never the regression.
  git -C "$SFF" checkout -q -b decoy "$OLD_SHA"
  # Recorded between the two commits -- the literal, offset-less string
  # ginkgo would have written.
  RECORDED_AT="2026-08-26T04:30:00"
  write_junit_fixture "$SFF" "$RECORDED_AT" 0 0 "$REQUIRED_FOCUS"
  run_gate "$SFF" "$OLD_SHA..$NEW_SHA"
  assert "regression on the pushed ref is caught even when a different branch is checked out locally" \
    "$([ "$RC" -ne 0 ] && echo 1 || echo 0)"
  assert "...junit-reuse-check itself reports no reusable result, not a build failure" \
    "$(printf '%s' "$OUT" | grep -q 'no reusable prior result' && echo 1 || echo 0)"
else
  skip "regression on pushed ref is caught despite a different checked-out branch" "cargo not installed -- cannot build u7s-junit-reuse-check"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
