#!/usr/bin/env bash
# Unit test for sonobuoy-plugin-e2e.yaml's podSpec hardening against
# transient node NotReady.
#
# Root cause (findings doc archived 2026-08-18): under real
# full-suite-scale churn, the lima VM's memory exhaustion gapped kubelet's
# NodeLease heartbeat 87.1s -- past node-controller's 40s default
# node-monitor-grace-period -- tripping the node.kubernetes.io/not-ready
# taint. node-controller's TaintManager then DELETEd the sonobuoy e2e-job
# pod itself (no toleration for that taint), silently killing the whole
# run's results ("could not retrieve sonobuoy pod") instead of the run
# simply reporting one slow test.
#
# This test proves the podSpec block that sonobuoy turns into the e2e-job
# pod's actual spec (confirmed live via `sonobuoy gen -p
# sonobuoy-plugin-e2e.yaml`, which renders it verbatim into the
# sonobuoy-plugins-cm ConfigMap the aggregator reads to build that pod)
# carries a BOUNDED toleration for that taint plus a high PriorityClass, so
# a brief flap no longer collaterally evicts the run's own control pod.
#
# Scope note: the sonobuoy AGGREGATOR pod ("sonobuoy" pod in the same
# incident's DELETE timeline, distinct from this e2e-job podSpec) is
# generated entirely from sonobuoy's own compiled-in Go template --
# confirmed via `sonobuoy run --help` / `sonobuoy gen config` (checked
# against both the pinned v0.57.3 and the latest v0.57.5) exposing no
# toleration or priorityClass flag/config field for it. That gap is an
# upstream limitation, not something a YAML template edit can reach; see
# the PR description for the follow-on.
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
PLUGIN_YAML="$DIR/sonobuoy-plugin-e2e.yaml"
TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_TEST"' EXIT

# ---------------------------------------------------------------------------
# Isolate the top-level podSpec: block (ends at the next top-level key,
# sonobuoy-config:) -- tolerations/priorityClassName are only meaningful on
# the POD's own spec, not the "spec:" block further down (the e2e
# container's plugin-run spec, which has its own unrelated env/image/command
# fields). A plain whole-file grep would still pass even if these fields
# were accidentally added to the wrong block, where sonobuoy would silently
# drop them.
# ---------------------------------------------------------------------------
POD_SPEC_BLOCK="$TMPDIR_TEST/podspec-block.yaml"
awk '/^podSpec:/{f=1} /^sonobuoy-config:/{f=0} f' "$PLUGIN_YAML" > "$POD_SPEC_BLOCK"

assert_true "podSpec block extraction actually matched something (sanity check on the awk range, not the fix itself)" \
  test -s "$POD_SPEC_BLOCK"

assert_true "podSpec sets priorityClassName to system-cluster-critical -- u7s resolves this without needing a seeded PriorityClass object (apiserver lib.rs's built-in special-case), keeping the e2e-job pod out of eviction ranking during the same memory pressure that causes the NotReady flap" \
  grep -qF "priorityClassName: system-cluster-critical" "$POD_SPEC_BLOCK"

assert_true "podSpec tolerates the node.kubernetes.io/not-ready taint key -- without it, node-controller's TaintManager deletes the e2e-job pod on ANY NotReady flap, silently losing the whole run's results" \
  grep -qF "key: node.kubernetes.io/not-ready" "$POD_SPEC_BLOCK"

not_ready_toleration_is_noexecute() {
  grep -A2 -B1 "key: node.kubernetes.io/not-ready" "$POD_SPEC_BLOCK" | grep -qF "effect: NoExecute"
}
assert_true "the not-ready toleration is scoped to NoExecute -- that is the actual effect node-controller applies for NotReady; a toleration under the wrong effect would silently fail to prevent the eviction this fix targets" \
  not_ready_toleration_is_noexecute

not_ready_toleration_has_bounded_seconds() {
  grep -A3 "key: node.kubernetes.io/not-ready" "$POD_SPEC_BLOCK" | grep -qE "tolerationSeconds: [0-9]+"
}
assert_true "the not-ready toleration carries a BOUNDED tolerationSeconds -- omitting it tolerates the taint FOREVER, which would mask a genuinely dead node indefinitely instead of still eventually rescheduling off it" \
  not_ready_toleration_has_bounded_seconds

TOLERATION_SECONDS=$(grep -A3 "key: node.kubernetes.io/not-ready" "$POD_SPEC_BLOCK" \
  | grep -oE "tolerationSeconds: [0-9]+" | grep -oE "[0-9]+" || true)
toleration_exceeds_observed_flap() {
  [ -n "$TOLERATION_SECONDS" ] && [ "$TOLERATION_SECONDS" -gt 87 ]
}
assert_true "tolerationSeconds (${TOLERATION_SECONDS:-unset}) exceeds the live-observed 87.1s NodeLease gap -- a shorter window would still lose the pod to the exact flap that caused this fix" \
  toleration_exceeds_observed_flap

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
