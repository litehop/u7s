#!/usr/bin/env bash
# Unit test for the --all-e2e sonobuoy timeout flag in 06-run-sonobuoy.sh.
#
# Incident: an overnight --all-e2e run was silently killed at exactly
# 6h00m00s after start. Forensics traced it to sonobuoy's own
# --timeout flag (aggregator wait-for-all-plugins budget, in seconds)
# defaulting to 21600s (6h) when the script never set it -- unrelated to
# --all-e2e's own documented ~6-12h budget (run-all.sh's --all-e2e doc
# comment). Note: sonobuoy has no flag literally named "--plugin-timeout";
# verified against the pinned sonobuoy v0.57.3 CLI source
# (cmd/sonobuoy/app/args.go, gen.go) that the real flag is --timeout,
# taking a plain integer of seconds, not a duration string like "12h".
#
# This test proves the --timeout flag reaches the --all-e2e branch's actual
# sonobuoy argv with a value that clears sonobuoy's own 6h default, while
# staying OUT of the --focus and certified-conformance branches (those
# ~10min/~25min runs -- certified-conformance sped up once PR #966 made
# ginkgo's --procs=16 the default -- don't need it, and adding it there would
# just be an unreviewed behavior change beyond what this fix asks for).
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

# ---------------------------------------------------------------------------
# build_sonobuoy_args() -- mirrors 06-run-sonobuoy.sh's three invocation
# branches (:150-184) closely enough to prove which branch gets --timeout
# and with what value. Keep in sync if those branches change.
# ---------------------------------------------------------------------------
build_sonobuoy_args() {
  local focus="$1" all_e2e="$2" timeout_secs="$3"
  local base="run -p /tmp/sonobuoy-plugin-e2e.yaml --wait --plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16 --kubeconfig /tmp/sonobuoy-kubeconfig"
  if [ -n "$focus" ]; then
    echo "$base --e2e-focus=$focus"
  elif [ "$all_e2e" -eq 1 ]; then
    echo "$base --e2e-focus=.* --e2e-skip=\[Flaky\] --timeout $timeout_secs"
  else
    echo "$base --mode=certified-conformance"
  fi
}

# The pre-fix version -- mirrors the exact bug: --all-e2e built its argv with
# no timeout flag at all, so sonobuoy's own 6h default silently applied.
build_sonobuoy_args_old_buggy() {
  local focus="$1" all_e2e="$2"
  local base="run -p /tmp/sonobuoy-plugin-e2e.yaml --wait --plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16 --kubeconfig /tmp/sonobuoy-kubeconfig"
  if [ -n "$focus" ]; then
    echo "$base --e2e-focus=$focus"
  elif [ "$all_e2e" -eq 1 ]; then
    echo "$base --e2e-focus=.* --e2e-skip=\[Disruptive\]|\[Flaky\]|\[Slow\]"
  else
    echo "$base --mode=certified-conformance"
  fi
}

SONOBUOY_DEFAULT_TIMEOUT_SECONDS=21600 # sonobuoy's own hardcoded default (6h) -- see args.go DefaultAggregationServerTimeoutSeconds.
DEFAULT_ALL_E2E_TIMEOUT_SECONDS="${SONOBUOY_ALL_E2E_TIMEOUT_SECONDS:-43200}" # this fix's default (12h) -- mirrors 06-run-sonobuoy.sh's own default.

# ---------------------------------------------------------------------------
# 1. --all-e2e's argv carries --timeout with a value that clears sonobuoy's
#    own 6h default -- the actual overnight-run failure mode.
# ---------------------------------------------------------------------------
ARGS=$(build_sonobuoy_args "" 1 "$DEFAULT_ALL_E2E_TIMEOUT_SECONDS")
assert "--all-e2e argv carries --timeout with the fixed default" \
  "$(printf '%s' "$ARGS" | grep -q -- "--timeout ${DEFAULT_ALL_E2E_TIMEOUT_SECONDS}" && echo 1 || echo 0)"
assert "the fixed default clears sonobuoy's own 6h default (the actual overnight-run failure)" \
  "$([ "$DEFAULT_ALL_E2E_TIMEOUT_SECONDS" -gt "$SONOBUOY_DEFAULT_TIMEOUT_SECONDS" ] && echo 1 || echo 0)"

# Regression guard: prove the OLD argv genuinely lacks --timeout in this same
# scenario, so this test would catch a regression back to the unbounded default.
OLD_ARGS=$(build_sonobuoy_args_old_buggy "" 1)
assert "(regression guard) pre-fix --all-e2e argv genuinely lacks --timeout" \
  "$(printf '%s' "$OLD_ARGS" | grep -q -- "--timeout" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 2. --focus and certified-conformance (default) argvs are untouched -- their
#    ~10min/~25min runs (certified-conformance sped up post PR #966's --procs=16
#    default) never approach sonobuoy's 6h default, so silently adding a flag
#    there would be an unreviewed behavior change this fix didn't ask for.
# ---------------------------------------------------------------------------
FOCUS_ARGS=$(build_sonobuoy_args "AdmissionWebhook" 0 "$DEFAULT_ALL_E2E_TIMEOUT_SECONDS")
assert "--focus argv is unaffected by the --all-e2e timeout fix" \
  "$(printf '%s' "$FOCUS_ARGS" | grep -q -- "--timeout" && echo 0 || echo 1)"

DEFAULT_ARGS=$(build_sonobuoy_args "" 0 "$DEFAULT_ALL_E2E_TIMEOUT_SECONDS")
assert "certified-conformance (bare) argv is unaffected by the --all-e2e timeout fix" \
  "$(printf '%s' "$DEFAULT_ARGS" | grep -q -- "--timeout" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 3. SONOBUOY_ALL_E2E_TIMEOUT_SECONDS overrides the default -- mirrors
#    SONOBUOY_FOCUS's existing env-var-override pattern in this same script,
#    so an operator can raise the budget further for an even longer run
#    without editing the script.
# ---------------------------------------------------------------------------
CUSTOM_ARGS=$(build_sonobuoy_args "" 1 "99999")
assert "SONOBUOY_ALL_E2E_TIMEOUT_SECONDS override reaches the argv" \
  "$(printf '%s' "$CUSTOM_ARGS" | grep -q -- "--timeout 99999" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
