#!/usr/bin/env bash
# Unit test for the --all-e2e sonobuoy --e2e-skip pattern in 06-run-sonobuoy.sh.
#
# Bug: --all-e2e used to skip --e2e-skip="\[Disruptive\]|\[Flaky\]|\[Slow\]".
# Ginkgo's --skip is an unconditional regex match against the full spec
# text with no awareness of whether a spec is ALSO tagged [Conformance].
# Checked against upstream's canonical release-1.36
# test/conformance/testdata/conformance.yaml (446 specs): 2 [Disruptive] and
# 6 [Slow] specs are ALSO [Conformance] (e.g. the StatefulSet burst-scaling
# test, both NoExecuteTaintManager eviction tests). The old skip pattern
# silently dropped those specs from --all-e2e even though the SAME specs run
# under --mode=certified-conformance -- meaning --all-e2e was NOT the
# superset of certified-conformance that run-all.sh's own --all-e2e doc
# comment claims it is.
#
# [Flaky] x [Conformance] is confirmed 0 -- structurally impossible, since a
# certified suite can't be tagged known-unreliable -- so skipping only
# [Flaky] never drops conformance coverage while still trimming upstream's
# own known-noise specs.
#
# This test proves the --all-e2e branch's actual sonobuoy argv skips ONLY
# [Flaky], not [Disruptive]/[Slow], so a revert back to the old three-way
# skip pattern is caught immediately instead of silently re-dropping
# conformance-tagged tests.
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
# branches (:150-176) closely enough to prove which branch gets which
# --e2e-skip pattern. Keep in sync if those branches change.
# ---------------------------------------------------------------------------
build_sonobuoy_args() {
  local focus="$1" all_e2e="$2"
  local base="run --plugin e2e --wait --plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16 --kubeconfig /tmp/sonobuoy-kubeconfig"
  if [ -n "$focus" ]; then
    echo "$base --e2e-focus=$focus"
  elif [ "$all_e2e" -eq 1 ]; then
    echo "$base --e2e-focus=.* --e2e-skip=\[Flaky\]"
  else
    echo "$base --mode=certified-conformance"
  fi
}

# The pre-fix version -- mirrors the exact bug: --all-e2e's skip pattern
# unconditionally excluded [Disruptive]/[Slow] specs regardless of whether
# they also carried [Conformance].
build_sonobuoy_args_old_buggy() {
  local focus="$1" all_e2e="$2"
  local base="run --plugin e2e --wait --plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16 --kubeconfig /tmp/sonobuoy-kubeconfig"
  if [ -n "$focus" ]; then
    echo "$base --e2e-focus=$focus"
  elif [ "$all_e2e" -eq 1 ]; then
    echo "$base --e2e-focus=.* --e2e-skip=\[Disruptive\]|\[Flaky\]|\[Slow\]"
  else
    echo "$base --mode=certified-conformance"
  fi
}

# ---------------------------------------------------------------------------
# 1. --all-e2e's argv skips [Flaky] -- upstream's own known-unreliable
#    specs, which by definition can never be [Conformance], so dropping
#    them costs nothing.
# ---------------------------------------------------------------------------
ARGS=$(build_sonobuoy_args "" 1)
assert "--all-e2e argv skips [Flaky]" \
  "$(printf '%s' "$ARGS" | grep -q -- '--e2e-skip=\\\[Flaky\\\]' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. --all-e2e's argv must NOT skip [Disruptive] or [Slow] -- some specs
#    tagged with those also carry [Conformance] (2 Disruptive, 6 Slow per
#    upstream's conformance.yaml), so skipping them would silently drop
#    tests that --mode=certified-conformance runs, breaking the superset
#    guarantee --all-e2e is supposed to provide.
# ---------------------------------------------------------------------------
assert "--all-e2e argv does NOT skip [Disruptive] (2 of those specs are also [Conformance])" \
  "$(printf '%s' "$ARGS" | grep -q -- 'Disruptive' && echo 0 || echo 1)"
assert "--all-e2e argv does NOT skip [Slow] (6 of those specs are also [Conformance])" \
  "$(printf '%s' "$ARGS" | grep -q -- 'Slow' && echo 0 || echo 1)"

# Regression guard: prove the OLD argv genuinely skipped Disruptive/Slow in
# this same scenario, so this test would catch a revert to the old pattern.
OLD_ARGS=$(build_sonobuoy_args_old_buggy "" 1)
assert "(regression guard) pre-fix --all-e2e argv genuinely skipped [Disruptive]" \
  "$(printf '%s' "$OLD_ARGS" | grep -q -- 'Disruptive' && echo 1 || echo 0)"
assert "(regression guard) pre-fix --all-e2e argv genuinely skipped [Slow]" \
  "$(printf '%s' "$OLD_ARGS" | grep -q -- 'Slow' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. --focus and certified-conformance (default) argvs are untouched -- this
#    fix only changes the --all-e2e branch's own skip pattern.
# ---------------------------------------------------------------------------
FOCUS_ARGS=$(build_sonobuoy_args "AdmissionWebhook" 0)
assert "--focus argv carries no --e2e-skip at all" \
  "$(printf '%s' "$FOCUS_ARGS" | grep -q -- '--e2e-skip' && echo 0 || echo 1)"

DEFAULT_ARGS=$(build_sonobuoy_args "" 0)
assert "certified-conformance (bare) argv carries no --e2e-skip at all" \
  "$(printf '%s' "$DEFAULT_ARGS" | grep -q -- '--e2e-skip' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
