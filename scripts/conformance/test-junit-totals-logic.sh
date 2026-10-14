#!/usr/bin/env bash
# Unit test for junit_spec_totals in _lib.sh.
#
# The run summary once printed "Ran: 497" for a run whose e2e.txt said
# "Ran 460 of 3206 Specs": the junit holds one testcase per suite-level node
# execution (Synchronized{Before,After}Suite once per ginkgo process, Report*
# nodes), and those were counted as ran specs. Baseline comparisons quote
# these numbers, so they must equal ginkgo's own count.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

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

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 2 real specs ran (1 passed, 1 failed), 1 skipped, plus 4 passed suite nodes
# (2 ginkgo procs). tests = 2 + 1 + 4 = 7.
cat > "$TMP/mixed.xml" <<'EOF'
<testsuites tests="7" disabled="1" errors="0" failures="1" time="1.0">
  <testsuite name="Kubernetes e2e suite" tests="7" disabled="0" skipped="1" errors="0" failures="1">
    <testcase name="[ReportBeforeSuite]" classname="Kubernetes e2e suite" status="passed" time="0.03"></testcase>
    <testcase name="[SynchronizedBeforeSuite]" classname="Kubernetes e2e suite" status="passed" time="0.03"></testcase>
    <testcase name="[sig-a] spec one" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
    <testcase name="[sig-b] spec two" classname="Kubernetes e2e suite" status="failed" time="1"></testcase>
    <testcase name="[sig-c] spec three" classname="Kubernetes e2e suite" status="skipped" time="0"></testcase>
    <testcase name="[SynchronizedAfterSuite]" classname="Kubernetes e2e suite" status="passed" time="0.0"></testcase>
    <testcase name="[ReportAfterSuite] Kubernetes e2e suite report" classname="Kubernetes e2e suite" status="passed" time="0.03"></testcase>
  </testsuite>
</testsuites>
EOF
assert "suite-level nodes are not counted as ran specs, so the summary equals e2e.txt's 'Ran N of M'" \
  "$([ "$(junit_spec_totals "$TMP/mixed.xml")" = "2 1" ] && echo 1 || echo 0)"

# A failed suite node is not a spec but must still fail the run.
cat > "$TMP/suitefail.xml" <<'EOF'
<testsuites tests="2" disabled="0" errors="0" failures="1" time="1.0">
  <testsuite name="Kubernetes e2e suite" tests="2" disabled="0" skipped="0" errors="0" failures="1">
    <testcase name="[SynchronizedBeforeSuite]" classname="Kubernetes e2e suite" status="failed" time="0.03"></testcase>
    <testcase name="[sig-a] spec one" classname="Kubernetes e2e suite" status="passed" time="1"></testcase>
  </testsuite>
</testsuites>
EOF
assert "a failed suite node still counts in failures so a broken BeforeSuite cannot read green" \
  "$([ "$(junit_spec_totals "$TMP/suitefail.xml")" = "2 1" ] && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
