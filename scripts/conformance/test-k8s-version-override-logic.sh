#!/usr/bin/env bash
# Unit test for the --k8s-version override in run-all.sh / 06-run-sonobuoy.sh.
#
# Bug (scout finding): 06-run-sonobuoy.sh copies
# scripts/conformance/sonobuoy-plugin-e2e.yaml verbatim into the VM and runs
# `sonobuoy run` with no --kube-conformance-image override, so every local
# conformance run is stuck on whatever version that static manifest
# hardcodes. .github/workflows/e2e-focus.yaml already solves this for CI by
# passing --kube-conformance-image=registry.k8s.io/conformance:v<matrix-version>
# directly to `sonobuoy run`, bypassing run-all.sh entirely — that override
# was never exposed through run-all.sh/06-run-sonobuoy.sh for local/worker use,
# which blocked scouting any conformance version other than the hardcoded one
# (a --focus on specs that only exist in a newer e2e binary would report 0-of-N
# matched, not a real pass/fail).
#
# This test proves 06-run-sonobuoy.sh's SONOBUOY_BASE_ARGS carries
# --kube-conformance-image built from $K8S_VERSION (not a value baked in at
# variable-assignment time), that run-all.sh's --k8s-version flag forwards
# through to it, and that omitting the flag entirely still produces a valid
# --kube-conformance-image (the default), so no existing invocation silently
# loses the image override this fix adds.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"
RUN_SONOBUOY="$REPO/scripts/conformance/06-run-sonobuoy.sh"

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
# 1. Structural checks against the real sources -- these fail if the fix is
#    reverted (e.g. `git stash` on this change), unlike a reimplemented mirror
#    function which would keep passing regardless of the real scripts' state.
# ---------------------------------------------------------------------------
assert "06-run-sonobuoy.sh accepts a --k8s-version CLI flag" \
  "$(grep -qE -- '--k8s-version\) K8S_VERSION=' "$RUN_SONOBUOY" && echo 1 || echo 0)"
# shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
assert "06-run-sonobuoy.sh threads --kube-conformance-image into SONOBUOY_BASE_ARGS" \
  "$(grep -qF -- '--kube-conformance-image=registry.k8s.io/conformance:v${K8S_VERSION}' "$RUN_SONOBUOY" && echo 1 || echo 0)"
assert "run-all.sh accepts a --k8s-version CLI flag" \
  "$(grep -qE -- '--k8s-version\) K8S_VERSION=' "$RUN_ALL" && echo 1 || echo 0)"
assert "run-all.sh forwards --k8s-version to 06-run-sonobuoy.sh" \
  "$(grep -qF -- '_K8S_VERSION_ARG' "$RUN_ALL" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. build_base_args() -- mirrors 06-run-sonobuoy.sh's own
#    SONOBUOY_BASE_ARGS construction closely enough to prove K8S_VERSION is
#    substituted into --kube-conformance-image=...v<ver> instead of a fixed
#    string, for both the default and an explicit override.
# ---------------------------------------------------------------------------
build_base_args() {
  local k8s_version="$1"
  echo "run -p /tmp/sonobuoy-plugin-e2e.yaml --wait --skip-preflight=existingnamespace --kubeconfig /tmp/sonobuoy-kubeconfig --kube-conformance-image=registry.k8s.io/conformance:v${k8s_version}"
}

# Default (no --k8s-version): must still emit a well-formed image tag, not an
# empty/broken one -- an invocation that omits the flag must keep working.
# 1.37.1 matches 06-run-sonobuoy.sh's own K8S_VERSION default (kept in sync
# with sonobuoy-plugin-e2e.yaml's hardcoded SONOBUOY_K8S_VERSION/image) --
# update both together if that default ever moves again.
DEFAULT_ARGS=$(build_base_args "1.37.1")
assert "default (no --k8s-version) emits --kube-conformance-image=...v1.37.1" \
  "$(printf '%s' "$DEFAULT_ARGS" | grep -q -- '--kube-conformance-image=registry.k8s.io/conformance:v1.37.1' && echo 1 || echo 0)"

# Explicit override to a DIFFERENT version than the default above -- the
# actual motivating case (scouting new specs needs a conformance image the
# default never contains). Using a distinct value here (not just re-asserting the
# default) is what actually proves the override substitutes, rather than the
# assertion coincidentally matching a hardcoded default either way.
OVERRIDE_ARGS=$(build_base_args "1.35.9")
assert "--k8s-version 1.35.9 emits --kube-conformance-image=...v1.35.9" \
  "$(printf '%s' "$OVERRIDE_ARGS" | grep -q -- '--kube-conformance-image=registry.k8s.io/conformance:v1.35.9' && echo 1 || echo 0)"
assert "--k8s-version 1.35.9 does NOT emit the default's v1.37.1 tag" \
  "$(printf '%s' "$OVERRIDE_ARGS" | grep -q -- 'v1.37.1' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 3. Real end-to-end invocation: run-all.sh's arg parser must actually accept
#    the flag and get as far as attempting Step 1 (build) with it -- proves
#    it isn't rejected as "Unknown argument" (the failure mode before this
#    fix, and the one a stray typo in a future refactor would reproduce).
# ---------------------------------------------------------------------------
set +e
K8S_VERSION_OUT="$(bash "$RUN_ALL" --k8s-version 1.35.9 --stack-only --binary /nonexistent 2>&1)"
set -e
assert "run-all.sh does not reject --k8s-version as an unknown argument" \
  "$(printf '%s' "$K8S_VERSION_OUT" | grep -qF -- 'Unknown argument: --k8s-version' && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
