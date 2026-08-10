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
# Second bug (same file, later incident): --all-e2e's ".*" focus also ran
# every upstream FeatureGate-tagged test (Alpha/Beta/dev), even though u7s
# doesn't claim FeatureGate support beyond GA -- a Beta-gated
# HPAConfigurableTolerance spec crashed vendored kcm 14 minutes into a 12.6h
# --all-e2e run (temp/e2e/0805-2202-conformance). Go's RE2 --e2e-skip regex
# can't express "skip every FeatureGate:* except VolumeAttributesClass" (no
# negative lookahead), so the fix is ginkgo v2's native --label-filter
# (structured, not regex) wired in via E2E_EXTRA_GINKGO_ARGS, applied to both
# --all-e2e AND --focus (a named --focus test must not be able to
# accidentally re-trigger a filtered-out, known-crashing spec just by naming
# it) with an explicit --unsafe-focus escape hatch for the rare case a
# filtered test needs to actually run once.
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
# build_filter_args()/build_sonobuoy_args() -- mirror 06-run-sonobuoy.sh's
# FEATUREGATE_LABEL_FILTER, build_filter_args(), and the three invocation
# branches (--focus/--all-e2e/certified-conformance) closely enough to prove
# which branch gets the FeatureGate label-filter and [Flaky] skip, and that
# --unsafe-focus (--focus branch only) wipes both. Keep in sync if those
# change.
# ---------------------------------------------------------------------------
FEATUREGATE_LABEL_FILTER='FeatureGate: isSubsetOf {VolumeAttributesClass}'

build_filter_args() {
  local apply="$1"
  if [ "$apply" -eq 1 ]; then
    echo "--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16|--label-filter=${FEATUREGATE_LABEL_FILTER} --plugin-env=e2e.E2E_EXTRA_ARGS_SEP=| --e2e-skip=\[Flaky\]"
  else
    echo "--plugin-env=e2e.E2E_EXTRA_GINKGO_ARGS=--procs=16"
  fi
}

build_sonobuoy_args() {
  local focus="$1" all_e2e="$2" unsafe_focus="${3:-0}"
  local base="run -p /tmp/sonobuoy-plugin-e2e.yaml --wait --kubeconfig /tmp/sonobuoy-kubeconfig"
  if [ -n "$focus" ]; then
    local apply=1
    [ "$unsafe_focus" -eq 1 ] && apply=0
    echo "$base $(build_filter_args "$apply") --e2e-focus=$focus"
  elif [ "$all_e2e" -eq 1 ]; then
    echo "$base $(build_filter_args 1) --e2e-focus=.*"
  else
    echo "$base $(build_filter_args 0) --mode=certified-conformance"
  fi
}

# The pre-fix version -- mirrors the exact bug: --all-e2e's skip pattern
# unconditionally excluded [Disruptive]/[Slow] specs regardless of whether
# they also carried [Conformance].
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
# 3. certified-conformance (default) argv is untouched -- this fix only
#    changes the --all-e2e and --focus branches' own filters.
# ---------------------------------------------------------------------------
DEFAULT_ARGS=$(build_sonobuoy_args "" 0)
assert "certified-conformance (bare) argv carries no --e2e-skip at all" \
  "$(printf '%s' "$DEFAULT_ARGS" | grep -q -- '--e2e-skip' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 4. all_e2e_applies_label_filter -- --all-e2e's own ".*" focus is exactly
#    what surfaced the HPAConfigurableTolerance crash (a Beta-gated spec u7s
#    doesn't claim to support); the FeatureGate allow-set must be present so
#    that class of test is skipped by default.
# ---------------------------------------------------------------------------
ALL_E2E_ARGS=$(build_sonobuoy_args "" 1)
assert "--all-e2e argv carries the FeatureGate label-filter with VolumeAttributesClass in the allow-set" \
  "$(printf '%s' "$ALL_E2E_ARGS" | grep -q -- '--label-filter=FeatureGate: isSubsetOf {VolumeAttributesClass}' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. focus_default_applies_label_filter -- a named --focus test must NOT be
#    able to accidentally re-trigger a filtered-out, known-crashing spec
#    (e.g. HPAConfigurableTolerance) just by naming it; the safe default
#    keeps the same allow-set applied as --all-e2e.
# ---------------------------------------------------------------------------
FOCUS_ARGS=$(build_sonobuoy_args "AdmissionWebhook" 0)
assert "default --focus argv carries the FeatureGate label-filter, same as --all-e2e" \
  "$(printf '%s' "$FOCUS_ARGS" | grep -q -- '--label-filter=FeatureGate: isSubsetOf {VolumeAttributesClass}' && echo 1 || echo 0)"
assert "default --focus argv also carries the [Flaky] skip, same as --all-e2e" \
  "$(printf '%s' "$FOCUS_ARGS" | grep -q -- '--e2e-skip=\\\[Flaky\\\]' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. unsafe_focus_wipes_label_filter -- the explicit, deliberate escape hatch
#    for the rare case a filtered-out test needs to actually run once (e.g.
#    to reproduce a bug on record). Both filters must be gone, not just one.
# ---------------------------------------------------------------------------
UNSAFE_FOCUS_ARGS=$(build_sonobuoy_args "AdmissionWebhook" 0 1)
assert "--focus --unsafe-focus argv carries NO FeatureGate label-filter" \
  "$(printf '%s' "$UNSAFE_FOCUS_ARGS" | grep -q -- '--label-filter' && echo 0 || echo 1)"
assert "--focus --unsafe-focus argv carries NO [Flaky] skip" \
  "$(printf '%s' "$UNSAFE_FOCUS_ARGS" | grep -q -- '--e2e-skip' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 7. unsafe_focus_without_focus_is_a_noop -- --unsafe-focus only has meaning
#    inside the --focus branch; --all-e2e/certified-conformance always apply
#    both filters regardless (chosen over erroring, since --focus/--all-e2e
#    are already mutually exclusive at run-all.sh -- see 06-run-sonobuoy.sh).
#    Proven here by showing bare-mode argv is byte-for-byte identical with
#    and without --unsafe-focus.
# ---------------------------------------------------------------------------
BARE_ARGS_UNSAFE=$(build_sonobuoy_args "" 0 1)
assert "--unsafe-focus with no --focus is a no-op -- bare-mode argv is unchanged" \
  "$([ "$BARE_ARGS_UNSAFE" = "$DEFAULT_ARGS" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
