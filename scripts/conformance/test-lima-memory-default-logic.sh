#!/usr/bin/env bash
# Regression test for the lima VM's default memory allocation in lima/kubelet.yaml.
#
# 4GiB repeatedly proved too small for real conformance load: the kernel
# OOM-killer killed the sonobuoy aggregator process, agnhost test pods, and
# CoreDNS during --focus 'Simple' runs, a curated 15-spec
# csi-hostpath focus OOM'd within 6s, the sig-network Services
# family at --procs=16 drove memory to 3663/3894MB used with a logged
# oom_watcher kill, and even a full-suite sonobuoy aggregator
# run OOM'd at 4GiB and needed a manual 6GiB bump to complete.
# If a future edit shrinks this back down, conformance runs silently start
# failing with misleading "pod has status Failed" / "could not retrieve
# sonobuoy pod" errors instead of an obvious memory-sizing message — this
# test must fail first.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_YAML="$DIR/../../lima/kubelet.yaml"

PASS=0
FAIL=0

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected to find '${needle}'"
    FAIL=$(( FAIL + 1 ))
  fi
}

MEMORY_LINE="$(grep -E '^memory:' "$LIMA_YAML" || true)"

if [ -z "$MEMORY_LINE" ]; then
  echo "FAIL: could not locate the 'memory:' line in $LIMA_YAML" >&2
  exit 1
fi

assert_contains "lima VM default memory is 8GiB (4GiB repeatedly OOM-killed sonobuoy/agnhost/coredns under real conformance load)" \
  "$MEMORY_LINE" 'memory: 8GiB'

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
