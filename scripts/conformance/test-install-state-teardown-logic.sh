#!/usr/bin/env bash
# Logic tests for run-all.sh's automatic install-teardown of VMs left in install state.
#
# Why it matters: a VM that ran install.sh keeps u7s-apiserver/u7s-kcm running; a host-rig
# bring-up on top of them fails with "node has no IPv4 podCIDR". Without the automatic
# teardown every operator and agent must remember a manual step first, and a clean VM must
# never be torn down (that would wipe a working rig VM's state for nothing).
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_BASH="$(command -v bash)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

PASS=0
FAIL=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"; PASS=$((PASS + 1))
  else
    echo "FAIL: $label -- expected '$expected', got '$actual'"; FAIL=$((FAIL + 1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"

# limactl stub: every VM is Running; `shell <vm> test -e <marker>` succeeds only for VMs listed
# in $TMP/install-state (one per line) and only for the install.sh marker.
cat > "$TMP/bin/limactl" <<EOF
#!$REAL_BASH
case "\$1" in
  list) echo Running ;;
  start) echo "limactl \$*" >> "$TMP/calls.log" ;;
  shell) [ "\$3" = test ] && [ "\$5" = "$INSTALL_STATE_MARKER" ] && grep -qx "\$2" "$TMP/install-state" ;;
esac
EOF
# bash stub: logs argv; install-teardown.sh fails for VMs listed in $TMP/teardown-fails.
cat > "$TMP/bin/bash" <<EOF
#!$REAL_BASH
printf '%s\n' "\$*" >> "$TMP/calls.log"
case "\$*" in
  *install-teardown.sh*) for v in \$(cat "$TMP/teardown-fails"); do case "\$*" in *"--vm \$v "*) exit 1 ;; esac; done ;;
esac
EOF
chmod +x "$TMP/bin/limactl" "$TMP/bin/bash"
export PATH="$TMP/bin:$PATH"

reset_fixture() { : > "$TMP/calls.log"; : > "$TMP/install-state"; : > "$TMP/teardown-fails"; }

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-b >> "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a vm-b 2>"$TMP/err.log" && rc=0 || rc=$?
check "install-state primary and extra node are both torn down before the rig touches them (rc)" "0" "$rc"
check "teardown ran once per install-state VM, with its own --vm" \
  "2" "$(grep -c "install-teardown.sh --vm vm-[ab] --workdir $TMP/wd" "$TMP/calls.log")"
check "teardown is announced loudly so an operator sees why their VM was wiped" \
  "2" "$(grep -c '^\[run-all\] vm-[ab] is in install state; running install-teardown.sh' "$TMP/err.log")"

reset_fixture
echo vm-b > "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a vm-b 2>/dev/null
check "a clean VM is never torn down (only the install-state one is)" \
  "1|vm-b" "$(grep -c 'install-teardown.sh' "$TMP/calls.log")|$(grep -o -e '--vm vm-.' "$TMP/calls.log" | sed 's/--vm //')"

reset_fixture
teardown_if_install_state "$DIR" "$TMP/wd" vm-a vm-b 2>/dev/null
check "no VM in install state means install-teardown.sh is not invoked at all" \
  "0" "$(grep -c 'install-teardown.sh' "$TMP/calls.log" || true)"

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-a > "$TMP/teardown-fails"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a 2>"$TMP/err.log" && rc=0 || rc=$?
check "a failed teardown returns non-zero (a half-torn-down VM must not proceed to bring-up)" "1" "$rc"

# End to end through run-all.sh: teardown precedes the store reset and a failure aborts the run.
reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-b >> "$TMP/install-state"
"$REAL_BASH" "$DIR/run-all.sh" --vm vm-a --port 6444 --extra-node vm-b --extra-kubelet-port 10002 \
  --stack-only --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 || true
first="$(grep -n -e install-teardown.sh -e 'reset.sh' "$TMP/calls.log" | head -1)"
check "run-all.sh tears down before reset.sh touches the VM" \
  "install-teardown.sh" "$(grep -o -e install-teardown.sh -e reset.sh <<<"$first")"
check "run-all.sh tears down the primary and the extra node" \
  "2" "$(grep -c 'install-teardown.sh' "$TMP/calls.log")"

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-a > "$TMP/teardown-fails"
"$REAL_BASH" "$DIR/run-all.sh" --vm vm-a --port 6444 --stack-only --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 && rc=0 || rc=$?
check "run-all.sh exits non-zero when teardown fails (rc)" "1" "$rc"
check "run-all.sh does not reach reset.sh/build after a failed teardown" \
  "0" "$(grep -c -e 'reset.sh' -e '01-build.sh' "$TMP/calls.log" || true)"

reset_fixture
echo vm-a > "$TMP/install-state"
"$REAL_BASH" "$DIR/run-all.sh" --install --reset --stack-only --vm vm-a --port 6444 --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 || true
check "--install never tears down (it is the install path itself)" \
  "0" "$(grep -c 'install-teardown.sh' "$TMP/calls.log" || true)"

check "reset.sh --store-only tolerates a missing /var/lib/kubelet (install-teardown removes it; the bring-up after it must not abort)" \
  "1" "$(grep -c '\[ ! -d /var/lib/kubelet \] || find /var/lib/kubelet' "$DIR/reset.sh")"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
