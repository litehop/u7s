#!/usr/bin/env bash
# Prints the executed specs of one or more sonobuoy run archives as "<passed|failed><TAB><name>",
# sorted and de-duplicated, from each archive's plugins/e2e/results/global/junit_01.xml. Skipped
# specs and suite-level nodes (BeforeSuite, ReportAfterSuite, ...) are omitted, so two outputs
# compare the spec set and the failure set that actually ran.
#
# The committed baselines (kcm-baseline-specs.txt, kcm-baseline-failures.txt) come from 2-node runs
# (run-all.sh --extra-node); compare only against runs of the same topology.
#
# Usage: scripts/conformance/spec-set.sh <run-dir>... > specs.txt
#        scripts/conformance/spec-set.sh --failed <run-dir>... > failures.txt
set -euo pipefail

FAILED_ONLY=0
if [ "${1:-}" = "--failed" ]; then FAILED_ONLY=1; shift; fi
[ $# -gt 0 ] || { echo "usage: $0 [--failed] <run-dir>..." >&2; exit 2; }

for d in "$@"; do
  j="$d/plugins/e2e/results/global/junit_01.xml"
  [ -f "$j" ] || { echo "spec-set: $j not found" >&2; exit 1; }
  sed -n -E 's/^ *<testcase name="(.*)" classname="[^"]*" status="(passed|failed)".*$/\2	\1/p' "$j"
done | grep -v -E "$(printf '\t')\[(Report(Before|After)Suite|Synchronized(Before|After)Suite|BeforeSuite|AfterSuite)\]" \
  | { if [ "$FAILED_ONLY" -eq 1 ]; then grep "^failed$(printf '\t')" || true; else cat; fi; } \
  | sort -u
