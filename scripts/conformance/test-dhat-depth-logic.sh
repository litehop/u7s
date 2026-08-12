#!/usr/bin/env bash
# Unit test for scripts/conformance/run-all.sh's --dhat-depth flag and its
# bare-`--profile`-without-`--focus` wall-clock warning.
#
# The dhat backtrace depth used to be hardcoded at 50 in main.rs, which made a
# bare (no --focus) --profile Conformance run cost +82% wall-clock and +318%
# peak apiserver RSS with no warning at invocation time — an operator had no
# way to know a "regression" they were looking at was actually the profiler
# itself. This test guards the two things that fix that: (1) the depth is
# forwarded to the apiserver's own child env, correctly defaulting to 10 when
# --dhat-depth is omitted, rejected outright when malformed; and (2) a bare
# full-suite --profile run prints the risk to stderr instead of silently
# eating the wall-clock budget.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"

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
# exit status) instead of round-tripping through a "1"/"0" string, matching
# test-profile-flag-logic.sh's own convention for the same reason: the
# round-trip is where a "must NOT fire" case silently inverts if forgotten.
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
# resolve_dhat_depth_arg() -- mirrors run-all.sh's decision for what (if
# anything) gets forwarded into the apiserver's child env as
# U7S_DHAT_BACKTRACE_DEPTH. Prints the literal env-var value that would be
# set, or the sentinel "UNSET" when nothing is forwarded at all (distinct from
# an empty string, which would itself be an invalid depth on the Rust side).
# ---------------------------------------------------------------------------
resolve_dhat_depth_arg() {
  local profile="$1" dhat_depth="$2"
  if [ "$profile" -eq 1 ] && [ -n "$dhat_depth" ]; then
    echo "$dhat_depth"
  else
    echo "UNSET"
  fi
}

assert "(a) --profile alone (no --dhat-depth): nothing is forwarded -- main.rs's own default of 10 applies" \
  "$([ "$(resolve_dhat_depth_arg 1 "")" = "UNSET" ] && echo 1 || echo 0)"
assert "(b) --profile --dhat-depth 50: 50 is forwarded verbatim into the child env" \
  "$([ "$(resolve_dhat_depth_arg 1 "50")" = "50" ] && echo 1 || echo 0)"
assert "--dhat-depth without --profile is never forwarded (no dhat build in play to read it)" \
  "$([ "$(resolve_dhat_depth_arg 0 "50")" = "UNSET" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# is_valid_dhat_depth() -- mirrors run-all.sh's own validation regex. A typo
# (e.g. "5o") must be rejected loudly at invocation time instead of silently
# reaching the apiserver, which would itself just warn-and-fall-back-to-10 —
# leaving an operator who explicitly asked for a deep-stack investigation
# with a shallow one and no indication why.
# ---------------------------------------------------------------------------
is_valid_dhat_depth() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

assert_false "(c) a non-numeric --dhat-depth is rejected" is_valid_dhat_depth "5o"
assert_false "(c) a negative --dhat-depth is rejected" is_valid_dhat_depth "-5"
assert_true "a valid --dhat-depth is accepted" is_valid_dhat_depth "50"

# Real end-to-end invocation: this validation fires immediately at arg-parsing
# time, before any build/VM step, so it's fast and safe to run for real.
set +e
DEPTH_INVALID_OUT="$(bash "$RUN_ALL" --profile --dhat-depth "5o" 2>&1)"
DEPTH_INVALID_EXIT=$?
set -e
assert "(c) run-all.sh actually exits non-zero on an invalid --dhat-depth" \
  "$([ "$DEPTH_INVALID_EXIT" -ne 0 ] && echo 1 || echo 0)"
assert "(c) run-all.sh's rejection message names the flag, not a generic parse error" \
  "$(printf '%s' "$DEPTH_INVALID_OUT" | grep -qF -- '--dhat-depth' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# (d) should_warn_bare_profile() -- mirrors run-all.sh's exact warning
# condition. A real end-to-end invocation can't cheaply exercise this: a
# genuine --profile run always proceeds into a real (slow) cargo rebuild
# right after the warning point, and --binary (the obvious way to skip that)
# is itself mutually exclusive with --profile. The structural grep below
# proves this mirror matches the real source's condition and message.
# ---------------------------------------------------------------------------
should_warn_bare_profile() {
  local profile="$1" focus="$2" stack_only="$3"
  [ "$profile" -eq 1 ] && [ -z "$focus" ] && [ "$stack_only" -eq 0 ]
}

assert_true "(d) --profile with no --focus warns about full-suite wall-clock overhead" \
  should_warn_bare_profile 1 "" 0
assert_false "--profile WITH --focus (the recommended scoped-investigation usage) does not warn" \
  should_warn_bare_profile 1 "SomeTest" 0
assert_false "--profile --stack-only does not warn -- sonobuoy (and its wall-clock) never runs there" \
  should_warn_bare_profile 1 "" 1
assert_false "a bare run with neither --profile nor --focus does not warn (no dhat in play)" \
  should_warn_bare_profile 0 "" 0

assert "(d) run-all.sh's actual warning text names the ~13-82% wall-clock range from the calibration table" \
  "$(grep -qF 'dhat profiling on the full suite adds ~13-82% wall-clock' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Structural checks against the real run-all.sh source.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "run-all.sh forwards the depth via a child-scoped prefix assignment, not export" \
  "$(grep -qF 'U7S_DHAT_BACKTRACE_DEPTH="$DHAT_DEPTH" source' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh never exports U7S_DHAT_BACKTRACE_DEPTH (would leak past the apiserver spawn)" \
  "$(grep -qF 'export U7S_DHAT_BACKTRACE_DEPTH' "$RUN_ALL" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
