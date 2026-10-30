#!/usr/bin/env bash
# Logic test for cutover-lima.sh: argument validation (all before any VM is
# touched) and the guarantee that the script itself never runs a k3s
# uninstall, which deletes the k3s data directory the rollback depends on.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/cutover-lima.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
touch "$WORK/bin" "$WORK/tar"

PASS=0
FAIL=0
check() {
  local label="$1" want_rc="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = "$want_rc" ]; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (rc=$rc, want $want_rc)"
    FAIL=$((FAIL + 1))
  fi
}

check "no arguments is a usage error" 2 bash "$SCRIPT"
check "unknown flag is a usage error" 2 bash "$SCRIPT" --bogus
check "missing --tarball is a usage error" 2 bash "$SCRIPT" --vm v --u7s-bin "$WORK/bin"
check "nonexistent u7s binary fails before touching the VM" 2 \
  bash "$SCRIPT" --vm v --u7s-bin "$WORK/none" --tarball "$WORK/tar" --out "$WORK/out"
check "nonexistent tarball fails before touching the VM" 2 \
  bash "$SCRIPT" --vm v --u7s-bin "$WORK/bin" --tarball "$WORK/none" --out "$WORK/out"

# Executable lines (not comments) must not invoke the uninstall script.
uninstall_lines="$(grep -v '^[[:space:]]*#' "$SCRIPT" | grep -c 'k3s-uninstall' || true)"
if [ "$uninstall_lines" = 0 ]; then
  echo "PASS: script never invokes k3s-uninstall"
  PASS=$((PASS + 1))
else
  echo "FAIL: script invokes k3s-uninstall"
  FAIL=$((FAIL + 1))
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
