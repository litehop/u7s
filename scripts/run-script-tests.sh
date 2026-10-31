#!/usr/bin/env bash
# Discovers the bash regression-guard scripts under scripts/ and runs them in parallel.
# Each script's output is buffered and printed as one block when it finishes, so parallel
# runs stay readable; exits non-zero if discovery finds nothing or any script fails.
#
# Env: SCRIPT_TESTS_JOBS (default: nproc) -- parallelism.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 1

jobs="${SCRIPT_TESTS_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

find scripts -type f \( -name 'test-*-logic.sh' -o -name 'test-critical-reviewer-hook.sh' -o -name 'test-install-checksum.sh' -o -name 'test-release-tarball-licenses.sh' -o -name 'test-add-node-warning.sh' \) | sort > "$out_dir/list"
count=$(wc -l < "$out_dir/list")
if [ "$count" -eq 0 ]; then
  echo "no scripts/**/test-*-logic.sh regression scripts found -- discovery is broken" >&2
  exit 1
fi
echo "found $count regression-guard scripts, running $jobs at a time"

export out_dir
run_one() {
  local t="$1" log rc start
  log="$out_dir/$(printf '%s' "$t" | tr '/' '_').log"
  start=$SECONDS
  bash "$t" > "$log" 2>&1
  rc=$?
  # One printf per block keeps concurrent workers from interleaving.
  printf -- '--- %s (%s, %ss) ---\n%s\n' "$t" "$([ "$rc" -eq 0 ] && echo ok || echo "FAILED rc=$rc")" "$((SECONDS - start))" "$(cat "$log")"
  return "$rc"
}
export -f run_one

# xargs exits 123 if any invocation failed.
tr '\n' '\0' < "$out_dir/list" | xargs -0 -n1 -P "$jobs" bash -c 'run_one "$1"' _
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "script-tests: at least one script failed (xargs rc=$rc)" >&2
  exit 1
fi
