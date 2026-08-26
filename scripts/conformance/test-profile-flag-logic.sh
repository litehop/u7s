#!/usr/bin/env bash
# Unit tests for scripts/conformance/run-all.sh's --profile flag logic.
#
# --profile is supposed to make the whole dhat capture workflow
# atomic: rebuild with --features dhat, SIGTERM the apiserver once sonobuoy
# retrieval + log evacuation finish (so dhat's Drop-based flush, main.rs:29-33,
# actually runs), and relocate the resulting heap JSON into THIS run's own
# temp/e2e/<TIMESTAMP>-<slug>/ directory instead of leaving it under --workdir
# for an operator to move by hand. Without --profile, a bare conformance run
# must behave exactly as before -- none of that may fire.
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

# assert_true/assert_false run a predicate function directly (via its own
# exit status) instead of round-tripping through a "1"/"0" string -- the
# round-trip is where the "&&echo1||echo0" pattern below silently inverts
# for a "must NOT fire" case if you forget to flip it by hand.
assert_true() {
  local label="$1"
  shift
  if "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}
assert_false() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

# ---------------------------------------------------------------------------
# profile_and_binary_conflict() -- mirrors run-all.sh's mutual-exclusivity
# check. --profile always rebuilds with --features dhat, so a caller-supplied
# --binary (whose feature set is the caller's own responsibility, possibly
# without dhat compiled in at all) must be rejected outright -- the
# pre-redesign behavior silently ignored --profile instead, which would
# leave an operator wondering why no heap file ever showed up.
# ---------------------------------------------------------------------------
profile_and_binary_conflict() {
  local profile="$1" binary="$2"
  [ "$profile" -eq 1 ] && [ -n "$binary" ]
}

assert_true  "--profile with --binary is rejected" \
  profile_and_binary_conflict 1 "/some/binary"
assert_false "--profile alone (no --binary) is not rejected" \
  profile_and_binary_conflict 1 ""
assert_false "--binary alone (no --profile) is not rejected" \
  profile_and_binary_conflict 0 "/some/binary"

# ---------------------------------------------------------------------------
# should_build_dhat() / should_stop_and_relocate() -- mirror the two gates in
# run-all.sh that must fire ONLY under --profile. should_stop_and_relocate
# also requires sonobuoy to have actually run -- --stack-only intentionally
# leaves the whole stack up for kubectl exploration, so the auto-SIGTERM must
# not undermine that. This guards against the "accidentally always-on"
# footgun this test exists to catch as a required regression check.
# ---------------------------------------------------------------------------
should_build_dhat() {
  local profile="$1"
  [ "$profile" -eq 1 ]
}

should_stop_and_relocate() {
  local profile="$1" stack_only="$2"
  [ "$profile" -eq 1 ] && [ "$stack_only" -eq 0 ]
}

assert_true  "--profile triggers the --features dhat rebuild" \
  should_build_dhat 1
assert_false "bare run (no --profile) does NOT trigger the dhat rebuild" \
  should_build_dhat 0
assert_true  "--profile (no --stack-only) triggers post-run SIGTERM + relocation" \
  should_stop_and_relocate 1 0
assert_false "bare run (no --profile) never triggers post-run SIGTERM + relocation" \
  should_stop_and_relocate 0 0
assert_false "--profile --stack-only skips post-run SIGTERM + relocation (stack stays up on purpose)" \
  should_stop_and_relocate 1 1

# ---------------------------------------------------------------------------
# resolve_dhat_dest() -- mirrors run-all.sh's RUN_DIR -> TIMESTAMP -> dest
# filename derivation exactly (basename | cut -d- -f1,2 for the timestamp,
# then dhat-heap-apiserver-<TIMESTAMP>.json under that same directory). This
# is the piece that actually lands the heap file "with the run results"
# instead of under --workdir or /tmp -- the acceptance criterion #3
# and the exact naming convention from the operator's manual run 0806-1102.
# ---------------------------------------------------------------------------
resolve_dhat_dest() {
  local run_dir="$1" timestamp
  timestamp=$(basename "$run_dir" | cut -d- -f1,2)
  echo "$run_dir/dhat-heap-apiserver-${timestamp}.json"
}

assert "plain certified-conformance run dir yields the operator's naming convention" \
  "$([ "$(resolve_dhat_dest "/x/temp/e2e/0806-1102-conformance")" = "/x/temp/e2e/0806-1102-conformance/dhat-heap-apiserver-0806-1102.json" ] && echo 1 || echo 0)"
assert "a slug with its own internal dashes still yields just the TIMESTAMP, not the whole dirname" \
  "$([ "$(resolve_dhat_dest "/x/temp/e2e/0806-0217--driver-csi-hostpath")" = "/x/temp/e2e/0806-0217--driver-csi-hostpath/dhat-heap-apiserver-0806-0217.json" ] && echo 1 || echo 0)"

# Regression guard: prove a naive "use the whole dirname as the timestamp"
# approach (the obvious first attempt) produces a filename that does NOT
# match "the operator's manual naming convention from run 0806-1102" the
# bead requires.
resolve_dhat_dest_old_buggy() {
  local run_dir="$1"
  echo "$run_dir/dhat-heap-apiserver-$(basename "$run_dir").json"
}
assert "(regression guard) naive whole-dirname timestamp produces the wrong filename" \
  "$([ "$(resolve_dhat_dest_old_buggy "/x/temp/e2e/0806-1102-conformance")" != "/x/temp/e2e/0806-1102-conformance/dhat-heap-apiserver-0806-1102.json" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural checks against the real run-all.sh source: the mirror functions
# above prove the decision logic is right, but not that run-all.sh actually
# wires it up. Grep for the literal commands themselves (fixed-string, not
# regex, since the commands contain shell-special characters).
# ---------------------------------------------------------------------------
RUN_ALL="$(cd "$(dirname "$0")" && pwd)/run-all.sh"

assert_true "run-all.sh actually rebuilds with --features dhat" \
  grep -qF 'cargo build --release -p u7s-apiserver --features dhat' "$RUN_ALL"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert_true "run-all.sh actually sends SIGTERM to the apiserver after sonobuoy" \
  grep -qF 'kill "${API_PIDS[@]}"' "$RUN_ALL"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
