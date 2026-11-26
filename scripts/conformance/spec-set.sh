#!/usr/bin/env bash
# Prints the executed specs of one or more sonobuoy run archives as "<passed|failed><TAB><name>",
# sorted and de-duplicated, from each archive's plugins/e2e/results/global/junit_01.xml. Skipped
# specs and suite-level nodes (BeforeSuite, ReportAfterSuite, ...) are omitted, so two outputs
# compare the spec set and the failure set that actually ran.
#
# The committed baselines (kcm-baseline-specs.txt, kcm-baseline-failures.txt) were recorded on a
# single node with --single-node, which drops the specs listed in kcm-multinode-specs.txt: they
# fail on one node and pass on two, so including them would make a correct run of either topology
# diff against the baseline. Always pass --single-node when producing a set to compare.
#
# Usage: scripts/conformance/spec-set.sh [--single-node] <run-dir>... > specs.txt
#        scripts/conformance/spec-set.sh [--single-node] --failed <run-dir>... > failures.txt
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGLE_NODE=0
FAILED_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --single-node) SINGLE_NODE=1; shift ;;
    --failed) FAILED_ONLY=1; shift ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "usage: $0 [--single-node] [--failed] <run-dir>..." >&2; exit 2; }

MULTINODE="$HERE/kcm-multinode-specs.txt"
[ "$SINGLE_NODE" -eq 0 ] || [ -f "$MULTINODE" ] || { echo "spec-set: $MULTINODE not found" >&2; exit 1; }
drop_multinode() {
  if [ "$SINGLE_NODE" -eq 1 ]; then awk -F'\t' 'NR==FNR{x[$0]=1;next} !($2 in x)' "$MULTINODE" -; else cat; fi
}

for d in "$@"; do
  j="$d/plugins/e2e/results/global/junit_01.xml"
  [ -f "$j" ] || { echo "spec-set: $j not found" >&2; exit 1; }
  sed -n -E 's/^ *<testcase name="(.*)" classname="[^"]*" status="(passed|failed)".*$/\2	\1/p' "$j"
done | grep -v -E "$(printf '\t')\[(Report(Before|After)Suite|Synchronized(Before|After)Suite|BeforeSuite|AfterSuite)\]" \
  | drop_multinode \
  | { if [ "$FAILED_ONLY" -eq 1 ]; then grep "^failed$(printf '\t')" || true; else cat; fi; } \
  | sort -u
