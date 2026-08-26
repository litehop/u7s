#!/usr/bin/env bash
# Unit test for the sonobuoy aggregator OOM fix.
#
# Root cause: the sonobuoy AGGREGATOR pod (namespace `sonobuoy`, pod name
# "sonobuoy" -- distinct from the "sonobuoy-e2e-job-*" worker pod that
# sonobuoy-plugin-e2e.yaml already bounds) is generated entirely by
# sonobuoy's own compiled-in Go code, with no CLI flag or plugin-manifest
# field to set its resources (confirmed at v0.57.3 by audit).
# It ships BestEffort (resources: {}), the kernel's
# highest-priority global-OOM victim, and was observed OOMKilled ~55s into
# a csi-hostpath focus run.
#
# Fix: pre-seed the `sonobuoy` namespace with a LimitRange (see
# sonobuoy-namespace-limitrange.yaml) BEFORE `sonobuoy run` in
# 06-run-sonobuoy.sh, so u7s's own LimitRange admission
# (apply_limit_ranges, crates/apiserver/src/limit_range.rs) injects a
# default memory+cpu REQUEST into the aggregator's container even though
# sonobuoy's plugin schema can never reach it directly. Request-only (no
# `default` limit) so it promotes BestEffort -> Burstable QoS without
# capping the aggregator's legitimate memory growth.
#
# This test proves both halves of the wiring statically: revert either one
# (drop the LimitRange's defaultRequest.memory, or drop the pre-seed calls
# from 06-run-sonobuoy.sh, or reorder them after the sonobuoy run call) and
# at least one assertion below fails.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

PASS=0
FAIL=0

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

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMITRANGE_YAML="$DIR/sonobuoy-namespace-limitrange.yaml"
RUN_SCRIPT="$DIR/06-run-sonobuoy.sh"

assert_true "sonobuoy-namespace-limitrange.yaml exists" \
  test -f "$LIMITRANGE_YAML"

assert_true "LimitRange targets the sonobuoy namespace -- a LimitRange in the wrong namespace never reaches the aggregator pod (u7s's LimitRange admission is namespace-scoped)" \
  grep -qE "^\s*namespace: sonobuoy\s*$" "$LIMITRANGE_YAML"

assert_true "LimitRange item type is Container -- u7s's apply_limit_ranges only reads type: Container items (Pod/PVC-scoped items are ignored), so a Pod-typed item here would silently never inject anything" \
  grep -qF "type: Container" "$LIMITRANGE_YAML"

has_memory_default_request() {
  grep -A5 "type: Container" "$LIMITRANGE_YAML" | grep -qE "memory: [0-9]+[A-Za-z]*"
}
assert_true "LimitRange sets a defaultRequest for memory -- without this, a container that omits resources.requests.memory gets nothing injected and stays BestEffort, the exact bug this fix targets" \
  has_memory_default_request

no_default_limit_set() {
  # "default:" (the LimitRange limit-injection key) must NOT appear in the
  # Container item -- only "defaultRequest:". A default LIMIT would cap the
  # aggregator's legitimate memory growth into a deterministic memcg OOM,
  # trading one fatal failure mode for another (the same reasoning already
  # documented for the e2e container in sonobuoy-plugin-e2e.yaml).
  ! grep -A5 "type: Container" "$LIMITRANGE_YAML" | grep -qE "^\s*default:\s*$"
}
assert_true "LimitRange is request-only (no default limit) -- a limit here would convert the aggregator's OOM class rather than fix it" \
  no_default_limit_set

assert_true "06-run-sonobuoy.sh applies the LimitRange manifest" \
  grep -qF "scripts/conformance/sonobuoy-namespace-limitrange.yaml" "$RUN_SCRIPT"

assert_true "06-run-sonobuoy.sh pre-creates the sonobuoy namespace before applying the LimitRange -- an apply against a nonexistent namespace fails outright" \
  grep -qF "create namespace sonobuoy" "$RUN_SCRIPT"

namespace_seed_precedes_sonobuoy_run() {
  local seed_line run_line
  seed_line=$(grep -n "create namespace sonobuoy" "$RUN_SCRIPT" | head -1 | cut -d: -f1)
  # shellcheck disable=SC2016 # intentional: matching the literal, unexpanded source text, not expanding it ourselves.
  run_line=$(grep -n 'sudo sonobuoy \$SONOBUOY_BASE_ARGS' "$RUN_SCRIPT" | head -1 | cut -d: -f1)
  [ -n "$seed_line" ] && [ -n "$run_line" ] && [ "$seed_line" -lt "$run_line" ]
}
assert_true "the namespace/LimitRange pre-seed runs BEFORE any 'sonobuoy run' invocation -- seeding it after the aggregator pod already exists would miss the pod's own CREATE admission entirely" \
  namespace_seed_precedes_sonobuoy_run

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
