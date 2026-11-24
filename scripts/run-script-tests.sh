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

# Every scripts/**/*test*.sh is either run (name matches test-*.sh) or listed here with a
# reason. A test-looking script that is neither (e.g. test_foo.sh, foo.test.sh) fails the
# runner, so a new test can never be silently skipped.
excluded=(
  "scripts/conformance/lima-install-test.sh" # driver that needs a live rig Lima VM, not a logic test
)

find scripts -type f -iname '*test*.sh' ! -path scripts/run-script-tests.sh | sort > "$out_dir/all"
: > "$out_dir/list"
problems=()
while IFS= read -r t; do
  listed=0
  for e in "${excluded[@]}"; do
    [ "$t" = "$e" ] && listed=1
  done
  if [ "$listed" -eq 1 ]; then
    continue
  elif [[ "$(basename "$t")" == test-*.sh ]]; then
    echo "$t" >> "$out_dir/list"
  else
    problems+=("$t: looks like a test but is not named test-*.sh; rename it or add it to excluded")
  fi
done < "$out_dir/all"
for e in "${excluded[@]}"; do
  [ -f "$e" ] || problems+=("$e: excluded entry does not exist (stale allowlist)")
done
if [ "${#problems[@]}" -ne 0 ]; then
  printf 'script-tests: %s\n' "${problems[@]}" >&2
  exit 1
fi
count=$(wc -l < "$out_dir/list")
if [ "$count" -eq 0 ]; then
  echo "no scripts/**/test-*.sh regression scripts found -- discovery is broken" >&2
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
  [ "$rc" -eq 0 ] || echo "$t" >> "$out_dir/failed"
  return "$rc"
}
export -f run_one

# xargs exits 123 if any invocation failed.
tr '\n' '\0' < "$out_dir/list" | xargs -0 -n1 -P "$jobs" bash -c 'run_one "$1"' _
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "script-tests: at least one script failed (xargs rc=$rc): $(sort "$out_dir/failed" 2>/dev/null | tr '\n' ' ')" >&2
  exit 1
fi
