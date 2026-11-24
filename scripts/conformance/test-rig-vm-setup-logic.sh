#!/usr/bin/env bash
# The VM userspace additions (nfs-common, log rotation, journald retention) must reach both
# the host rig and --install mode through one shared step, and be recorded in run-meta.
# Without nfs-common an install-mode run fails every nfs-backed storage spec on a node a
# real user would never have configured that way, and the two topologies stop being
# comparable.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/conformance/_lib.sh
source "$DIR/_lib.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
# shellcheck source=scripts/lib/drain-grep.sh
source "$DIR/../lib/drain-grep.sh"
code_of() { grep -vE '^[[:space:]]*#' "$1"; }

for f in lima-start.sh install-bringup.sh; do
  code_of "$DIR/$f" | drain_grep -qxF 'rig_apply_vm_rig_setup "$VM_NAME"' \
    && ok "$f applies the shared VM rig setup -- else that topology lacks nfs-common / journal retention" \
    || bad "$f does not call rig_apply_vm_rig_setup: its VM drifts from the other topology"
done

for f in lima-start.sh install-bringup.sh lima-golden-bake.sh; do
  if code_of "$DIR/$f" | drain_grep -q 'nfs-common'; then
    bad "$f installs nfs-common itself instead of via rig_apply_vm_rig_setup"
  else
    ok "$f leaves nfs-common to the shared step"
  fi
done

mkdir -p "$TMP/bin"
cat > "$TMP/bin/limactl" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LIMA_LOG"
cat >/dev/null 2>&1 || true
EOF
chmod +x "$TMP/bin/limactl"
: > "$TMP/log"
LIMA_LOG="$TMP/log" PATH="$TMP/bin:$PATH" rig_apply_vm_rig_setup stubvm </dev/null >/dev/null 2>&1 && rc=0 || rc=$?
[ "$rc" = 0 ] && ok "shared step succeeds against a stubbed VM" || bad "shared step failed (rc=$rc)"
grep -qE 'apt-get .* install -y nfs-common' "$TMP/log" \
  && ok "nfs-common is installed -- nfs storage specs need /sbin/mount.nfs" \
  || bad "nfs-common is not installed by the shared step"
grep -q 'journalctl --vacuum-size' "$TMP/log" && grep -q 'systemctl restart logrotate.timer' "$TMP/log" \
  && ok "journald retention and logrotate timer are applied" \
  || bad "journald/logrotate setup missing from the shared step"
grep -qF 'vm-logrotate-journald-nfs-common' <<<"$RIG_ONLY_SETUP" \
  && ok "the shared step is named in RIG_ONLY_SETUP so run-meta records it" \
  || bad "RIG_ONLY_SETUP does not record the shared VM setup"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
