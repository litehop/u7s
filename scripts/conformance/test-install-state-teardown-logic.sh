#!/usr/bin/env bash
# Logic tests for run-all.sh's automatic install-teardown of VMs left in install state.
#
# Why it matters: a VM that ran install.sh keeps u7s units running; a host-rig bring-up on
# top of them fails with "node has no IPv4 podCIDR". Without the automatic teardown every
# operator and agent must remember a manual step first, and a clean VM must never be torn
# down (that would wipe a working rig VM's state for nothing).
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
mkdir "$TMP/bin" "$TMP/guest-bin"
PORT=59999

# limactl stub. Status comes from $TMP/status-<vm> (default Running); `start` flips it to
# Running. The marker probe (`shell <vm> sh -c <script>`) answers present only when the script
# names the real marker path and <vm> is listed in $TMP/install-state; $TMP/probe-fails makes it
# exit 255 (ssh failure) and $TMP/probe-garbage makes it print noise. `shell <vm> sudo bash -c`
# runs the script locally against guest-bin stubs. Every call is logged.
cat > "$TMP/bin/limactl" <<EOF
#!$REAL_BASH
echo "limactl \$*" >> "$TMP/calls.log"
case "\$1" in
  list)
    case "\$*" in
      *'{{.Name}} {{.Status}}'*) echo "vm-a Running" ;;
      *'{{.Name}}'*) echo vm-a ;;
      *) cat "$TMP/status-\${@: -1}" 2>/dev/null || echo Running ;;
    esac ;;
  start) echo Running > "$TMP/status-\$2" ;;
  template) echo '[]' ;;
  shell)
    if [ "\$3" = sh ]; then
      [ ! -e "$TMP/probe-fails" ] || exit 255
      [ ! -e "$TMP/probe-garbage" ] || { echo "Permission denied"; exit 0; }
      case "\$5" in *"$INSTALL_STATE_MARKER"*) grep -qx "\$2" "$TMP/install-state" && echo present || echo absent ;; *) echo absent ;; esac
    elif [ "\$3" = sudo ]; then
      PATH="$TMP/guest-bin:\$PATH" $REAL_BASH -c "\$6"
    fi ;;
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
# Guest-side stubs for reset.sh's wipe script: find logs instead of deleting anything.
for c in systemctl pkill findmnt; do printf '#!%s\nexit 0\n' "$REAL_BASH" > "$TMP/guest-bin/$c"; done
printf '#!%s\necho "find $*" >> "%s/find.log"\n' "$REAL_BASH" "$TMP" > "$TMP/guest-bin/find"
chmod +x "$TMP/bin/limactl" "$TMP/bin/bash" "$TMP/guest-bin/"*
export PATH="$TMP/bin:$PATH"

reset_fixture() {
  : > "$TMP/calls.log"; : > "$TMP/install-state"; : > "$TMP/teardown-fails"
  rm -f "$TMP"/status-* "$TMP/probe-fails" "$TMP/probe-garbage" "$TMP/find.log"
}
teardowns() { grep -c 'install-teardown.sh' "$TMP/calls.log" || true; }

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-b >> "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT vm-b=$PORT 2>"$TMP/err.log" && rc=0 || rc=$?
check "install-state primary and extra node are both torn down before the rig touches them (rc)" "0" "$rc"
check "teardown ran once per install-state VM, with its own --vm" \
  "2" "$(grep -c "install-teardown.sh --vm vm-[ab] --workdir $TMP/wd" "$TMP/calls.log")"
check "teardown is announced loudly so an operator sees why their VM was wiped" \
  "2" "$(grep -c '^\[run-all\] vm-[ab] is in install state; running install-teardown.sh' "$TMP/err.log")"

reset_fixture
echo vm-b > "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT vm-b=$PORT 2>/dev/null
check "a clean VM is never torn down (only the install-state one is)" \
  "1|vm-b" "$(teardowns)|$(grep -o -e '--vm vm-.' "$TMP/calls.log" | sed 's/--vm //')"

reset_fixture
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT vm-b=$PORT 2>/dev/null
check "no VM in install state means install-teardown.sh is not invoked at all" "0" "$(teardowns)"

# install.sh writes the marker first in every mode; the stub models any VM carrying it, with no
# u7s-apiserver.service involved. A marker that only a control-plane install writes would leave
# worker-mode and early-failed installs fighting the rig.
reset_fixture
echo vm-a > "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>/dev/null
check "a worker-mode install-state VM (marker, no apiserver unit) is torn down instead of fighting the rig" "1" "$(teardowns)"

reset_fixture
echo vm-a > "$TMP/install-state"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>/dev/null
check "a partial install (marker written, later steps never ran) is torn down, not mistaken for a clean VM" "1" "$(teardowns)"
INSTALL_SH="$DIR/../install.sh"
write_line="$(grep -n "^: > $INSTALL_STATE_MARKER\$" "$INSTALL_SH" | head -1 | cut -d: -f1)"
check "install.sh writes the exact marker the probe looks for (a mismatch makes every install look clean)" \
  "1" "$([ -n "$write_line" ] && echo 1 || echo 0)"
check "install.sh writes the marker before its first mutation (systemd preflight precedes it, install -d / systemctl follow)" \
  "0" "$(awk -v n="${write_line:-0}" 'NR < n && /^(install -d|mkdir|systemctl|cat >)/ {c++} END {print c + 0}' "$INSTALL_SH")"
check "install-teardown.sh removes the marker, so a torn-down VM is not torn down again" \
  "1" "$(grep -c "rm -f '\"\$INSTALL_STATE_MARKER\"'" "$DIR/install-teardown.sh")"

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-a > "$TMP/teardown-fails"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>"$TMP/err.log" && rc=0 || rc=$?
check "a failed teardown returns non-zero (a half-torn-down VM must not proceed to bring-up)" "1" "$rc"

# Probe failures: an ssh error must not read as "clean VM", or run-all proceeds on top of install state.
reset_fixture
echo vm-a > "$TMP/install-state"
: > "$TMP/probe-fails"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>"$TMP/err.log" && rc=0 || rc=$?
check "a probe ssh failure is an error, not 'clean VM' (rc)" "1" "$rc"
check "a probe ssh failure never reaches install-teardown.sh" "0" "$(teardowns)"
check "a probe ssh failure says so on stderr" "1" "$(grep -c 'cannot determine whether vm-a is in install state' "$TMP/err.log")"

reset_fixture
: > "$TMP/probe-garbage"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>"$TMP/err.log" && rc=0 || rc=$?
check "unexpected probe output (e.g. a shell error) is an error, not 'clean VM' (rc)" "1" "$rc"

# Stopped VM: a bare `limactl start` skips lima-start.sh's port check and provision sync.
reset_fixture
echo vm-a > "$TMP/install-state"
echo Stopped > "$TMP/status-vm-a"
vm_install_state_probe vm-a && rc=0 || rc=$?
check "probing a stopped VM reports 'stopped' (rc 3) instead of guessing" "3" "$rc"
check "the probe itself never starts a stopped VM" "0" "$(grep -c '^limactl start' "$TMP/calls.log" || true)"

reset_fixture
echo vm-a > "$TMP/install-state"
echo Stopped > "$TMP/status-vm-a"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>/dev/null && rc=0 || rc=$?
check "a stopped install-state VM is started, then torn down (rc)" "0" "$rc"
check "a stopped VM is provision-synced before it is started (stale golden provision otherwise)" \
  "template|start" "$(grep -o -e '^limactl template' -e '^limactl start' "$TMP/calls.log" | awk '{print $2}' | uniq | paste -sd'|' -)"
check "teardown runs after the stopped VM is up" "1" "$(teardowns)"

reset_fixture
echo Stopped > "$TMP/status-vm-a"
teardown_if_install_state "$DIR" "$TMP/wd" vm-a=$PORT 2>/dev/null && rc=0 || rc=$?
check "a stopped clean VM is started for the probe but never torn down" "0|0" "$rc|$(teardowns)"

# End to end through run-all.sh: teardown precedes the store reset and a failure aborts the run.
reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-b >> "$TMP/install-state"
"$REAL_BASH" "$DIR/run-all.sh" --vm vm-a --port 6444 --extra-node vm-b --extra-kubelet-port 10002 \
  --stack-only --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 || true
first="$(grep -n -e install-teardown.sh -e 'reset.sh' "$TMP/calls.log" | head -1)"
check "run-all.sh tears down before reset.sh touches the VM" \
  "install-teardown.sh" "$(grep -o -e install-teardown.sh -e reset.sh <<<"$first")"
check "run-all.sh tears down the primary and the extra node" "2" "$(teardowns)"

reset_fixture
echo vm-a > "$TMP/install-state"
echo vm-a > "$TMP/teardown-fails"
"$REAL_BASH" "$DIR/run-all.sh" --vm vm-a --port 6444 --stack-only --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 && rc=0 || rc=$?
check "run-all.sh exits non-zero when teardown fails (rc)" "1" "$rc"
check "run-all.sh does not reach reset.sh/build after a failed teardown" \
  "0" "$(grep -c -e 'reset.sh' -e '01-build.sh' "$TMP/calls.log" || true)"

reset_fixture
echo vm-a > "$TMP/install-state"
: > "$TMP/probe-fails"
"$REAL_BASH" "$DIR/run-all.sh" --vm vm-a --port 6444 --stack-only --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 && rc=0 || rc=$?
check "run-all.sh exits non-zero when the install-state probe fails (rc)" "1" "$rc"
check "run-all.sh does not reach reset.sh/build after a failed probe" \
  "0" "$(grep -c -e 'reset.sh' -e '01-build.sh' "$TMP/calls.log" || true)"

reset_fixture
echo vm-a > "$TMP/install-state"
"$REAL_BASH" "$DIR/run-all.sh" --install --reset --stack-only --vm vm-a --port 6444 --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 || true
check "--install --reset never tears down (it is the install path itself)" "0" "$(teardowns)"

reset_fixture
echo vm-a > "$TMP/install-state"
"$REAL_BASH" "$DIR/run-all.sh" --install --stack-only --vm vm-a --port 6444 --workdir "$TMP/wd" >"$TMP/out.log" 2>&1 || true
check "--install without --reset never tears down (re-running an install must keep its VM's install state)" "0" "$(teardowns)"
check "--install without --reset still hands off to install-run.sh" "1" "$(grep -c 'install-run.sh' "$TMP/calls.log" || true)"

# reset.sh --store-only after install-teardown: /var/lib/kubelet is gone, and find on a missing
# directory aborts the guest script, failing the whole bring-up. The dev host has no such dir;
# refuse to run where it does, since the guest script names the real path.
reset_fixture
if [ -e /var/lib/kubelet ]; then
  check "host must not have /var/lib/kubelet for the reset.sh fixture" "absent" "present"
else
  : > "$TMP/find.log"
  ( source "$DIR/reset.sh"; wipe_guest_state vm-a ) >"$TMP/wipe.log" 2>&1 && rc=0 || rc=$?
  check "wipe_guest_state succeeds on a VM whose /var/lib/kubelet is gone (rc)" "0" "$rc"
  check "wipe_guest_state does not run find on the missing kubelet dir" "0" "$(grep -c . "$TMP/find.log" 2>/dev/null || true)"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
