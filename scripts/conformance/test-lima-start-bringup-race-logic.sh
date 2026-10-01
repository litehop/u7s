#!/usr/bin/env bash
# Regression guard for fresh-clone bring-up races in lima-start.sh.
#
# A freshly cloned node can reach lima-start.sh before /tmp/kubelet-pods exists
# and while unattended-upgrades still holds the dpkg lock. The first fails the
# kube-proxy-pull.yaml write; the second aborts apt-get. Either kills
# `run-all.sh --reset`.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/lima-start.sh"
FAIL=0

check() {
  local label="$1" ok="$2"
  if [ "$ok" = 1 ]; then
    echo "PASS: $label"
  else
    echo "FAIL: $label"
    FAIL=1
  fi
}

write_line="$(grep -F 'cat > /tmp/kubelet-pods/kube-proxy-pull.yaml' "$SCRIPT" || true)"
ok=0
case "$write_line" in
  *"mkdir -p /tmp/kubelet-pods && cat >"*) ok=1 ;;
esac
check "the static-pod manifest write creates its directory first, so a fresh clone without /tmp/kubelet-pods does not fail bring-up" "$ok"

unlocked="$(grep -E 'sudo apt-get ' "$SCRIPT" | grep -vF 'DPkg::Lock::Timeout=' || true)"
ok=0
[ -z "$unlocked" ] && ok=1
check "every apt-get waits (bounded) for the dpkg lock, so unattended-upgrades on a fresh clone does not abort bring-up" "$ok"

exit "$FAIL"
