#!/usr/bin/env bash
# Writes meta/build.json into a conformance run's temp/e2e/<TIMESTAMP>-<slug>/
# directory.
#
# Without this, nothing in a run dir records what was actually tested: whether
# --profile (--features dhat) was in play, at what trim_backtraces() depth, the
# git SHA under test, or the exact run-all.sh invocation. A 2026-08-11 run that
# read as a four-way regression (2 test failures, ~2x wall-clock, 64 watchdog
# namespace reaps, ~5x apiserver RSS) turned out to be entirely a profiling
# artifact of an undocumented depth-50 rebuild -- confirmed only after a full
# multi-agent log-archaeology investigation, because nothing said the two runs
# being compared weren't built the same way. Deliberately NOT named
# meta/config.json -- that file is sonobuoy's own, written by sonobuoy itself.
#
# Usage:
#   write-build-provenance.sh --run-dir <dir> [--vm <name>] [--extra-node <name>]
#                              [--profile] [--dhat-depth <n>] [--argv-json <json>]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

RUN_DIR=""
VM="lima-node"
EXTRA_NODE=""
PROFILE=0
DHAT_DEPTH=""
ARGV_JSON="[]"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --vm) VM="$2"; shift 2 ;;
    --extra-node) EXTRA_NODE="$2"; shift 2 ;;
    --profile) PROFILE=1; shift ;;
    --dhat-depth) DHAT_DEPTH="$2"; shift 2 ;;
    --argv-json) ARGV_JSON="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$RUN_DIR" ]; then
  echo "error: --run-dir is required" >&2
  exit 1
fi

GIT_SHA=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY=false
[ -n "$(git -C "$REPO" status --porcelain 2>/dev/null)" ] && GIT_DIRTY=true

DHAT_ENABLED=false
DHAT_DEPTH_JSON="null"
if [ "$PROFILE" -eq 1 ]; then
  DHAT_ENABLED=true
  # 10 is dhat's own crate default, and the default U7S_DHAT_BACKTRACE_DEPTH
  # falls back to in main.rs when --dhat-depth isn't given -- kept in sync by
  # hand since this script has no Rust source to read it from.
  DHAT_DEPTH_JSON="${DHAT_DEPTH:-10}"
fi

# vm_spec_json <name> -- best-effort cpus/memory via `limactl list --json`.
# run-all.sh itself never tracks VM sizing (that's a manual `limactl edit
# --memory` operator action, see ai/prompts/vm-operations.md), so this is the
# only source of truth available at write time. Degrades to nulls rather than
# failing the whole provenance write if limactl is absent (e.g. this script's
# own unit test sandbox) or the named VM isn't found.
vm_spec_json() {
  local name="$1" spec=""
  if command -v limactl &>/dev/null; then
    spec=$(limactl list --json 2>/dev/null \
      | jq -c --arg n "$name" 'select(.name == $n) | {name: .name, cpus: .cpus, memory_bytes: .memory}' \
      | head -1) || true
  fi
  if [ -z "$spec" ]; then
    spec=$(jq -n --arg n "$name" '{name: $n, cpus: null, memory_bytes: null}')
  fi
  echo "$spec"
}

VM_SPECS_JSON="[$(vm_spec_json "$VM")]"
VM_COUNT=1
if [ -n "$EXTRA_NODE" ]; then
  VM_SPECS_JSON="[$(vm_spec_json "$VM"), $(vm_spec_json "$EXTRA_NODE")]"
  VM_COUNT=2
fi

mkdir -p "$RUN_DIR/meta"
jq -n \
  --arg git_sha "$GIT_SHA" \
  --argjson git_dirty "$GIT_DIRTY" \
  --argjson dhat_feature_enabled "$DHAT_ENABLED" \
  --argjson dhat_backtrace_depth "$DHAT_DEPTH_JSON" \
  --arg primary_vm "$VM" \
  --arg extra_node "$EXTRA_NODE" \
  --argjson vm_count "$VM_COUNT" \
  --argjson vm_specs "$VM_SPECS_JSON" \
  --argjson argv "$ARGV_JSON" \
  '{
    git_sha: $git_sha,
    git_dirty: $git_dirty,
    apiserver: {
      dhat_feature_enabled: $dhat_feature_enabled,
      dhat_backtrace_depth: $dhat_backtrace_depth
    },
    ginkgo: { procs: 16 },
    node_topology: {
      primary_vm: $primary_vm,
      extra_node: (if $extra_node == "" then null else $extra_node end),
      vm_count: $vm_count,
      vm_specs: $vm_specs
    },
    run_all_argv: $argv
  }' > "$RUN_DIR/meta/build.json"

echo "Build provenance: $RUN_DIR/meta/build.json"
