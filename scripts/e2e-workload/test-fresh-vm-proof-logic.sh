#!/usr/bin/env bash
# Logic test for fresh-vm-proof.sh with a mocked vps.sh and gcloud (no GCP needed). The
# script runs unattended against a paid VM, so what matters is: the VM is always deleted, a
# PASS always carries a recorded image+kernel, and only the one known deploy.sh error is
# tolerated.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

mkdir -p "$T/tree/scripts/e2e-workload" "$T/tree/scripts/gcp" "$T/tree/scripts/release-gate" "$T/bin"
cp "$HERE/fresh-vm-proof.sh" "$T/tree/scripts/e2e-workload/"
cp "$REPO/scripts/gcp/lib.sh" "$T/tree/scripts/gcp/"
cp "$REPO/scripts/release-gate/backend.sh" "$T/tree/scripts/release-gate/"
echo '#!/bin/sh' > "$T/tree/scripts/install.sh"
git -C "$T/tree" init -q
git -C "$T/tree" add -A
git -C "$T/tree" -c user.name=t -c user.email=t@t commit -q -m t

cat > "$T/bin/gcloud" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "config configurations describe"*) exit 0 ;;
  "config get-value project"*) echo p ;;
  "config get-value compute/zone"*) echo z-1 ;;
  "compute instances describe"*) echo "https://x/zones/z-1/disks/boot" ;;
  "compute disks describe"*) echo "${FAKE_IMAGE-https://x/global/images/ubuntu-2404-noble}" ;;
  "compute ssh"*) echo "${FAKE_KERNEL-6.8.0-gcp}" ;;
esac
EOF
cat > "$T/tree/scripts/gcp/vps.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LOG"
case "$1" in
  down) exit "${FAKE_DOWN_RC:-0}" ;;
  ssh)
    case "$*" in
      *deploy.sh*) echo "${FAKE_DEPLOY_OUT:-}"; exit "${FAKE_DEPLOY_RC:-0}" ;;
      *wordpress-smoke*) exit "${FAKE_SMOKE_RC:-0}" ;;
    esac ;;
esac
exit 0
EOF
chmod +x "$T/bin/gcloud" "$T/tree/scripts/gcp/vps.sh"

PASS=0; FAIL=0
RC=0
# run_case VAR=value... : runs the script, sets RC, leaves the vps.sh call log in $T/log
run_case() {
  : > "$T/log"
  RC=0
  env LOG="$T/log" PATH="$T/bin:$PATH" "$@" \
    bash "$T/tree/scripts/e2e-workload/fresh-vm-proof.sh" --tag v0 >"$T/out" 2>&1 || RC=$?
}
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; sed 's/^/    /' "$T/out" | tail -15; FAIL=$((FAIL + 1)); }
expect_fail() { if [ "$RC" -ne 0 ]; then ok "$1"; else bad "$1 (script exited 0)"; fi; }
expect_pass() { if [ "$RC" -eq 0 ]; then ok "$1"; else bad "$1 (rc=$RC)"; fi; }
expect_log() { if grep -q "$2" "$T/log"; then ok "$1"; else bad "$1 (no '$2' in vps.sh calls)"; fi; }
expect_no_log() { if grep -q "$2" "$T/log"; then bad "$1 ('$2' was called)"; else ok "$1"; fi; }

run_case
expect_pass "clean run exits 0"
expect_log "clean run deletes the VM" '^down '

run_case FAKE_SMOKE_RC=1
expect_fail "a failing smoke fails the run"
expect_log "a failing smoke still deletes the VM; otherwise a paid VM leaks" '^down '

run_case FAKE_IMAGE=
expect_fail "an unreadable image fails the run; a PASS with no recorded platform is not evidence"
expect_log "an unreadable image still deletes the VM; otherwise a paid VM leaks" '^down '
expect_no_log "an unreadable image stops before installing on an unidentified platform" 'install.sh --tarball'

run_case FAKE_KERNEL=
expect_fail "an empty kernel fails the run; a PASS with no recorded platform is not evidence"

run_case FAKE_DEPLOY_RC=1 FAKE_DEPLOY_OUT='error: connection refused'
expect_fail "an unexpected deploy.sh failure fails the run; hiding it would make the proof pass on a broken CSI driver"
expect_no_log "an unexpected deploy.sh failure stops before the smoke" 'wordpress-smoke'
expect_log "an unexpected deploy.sh failure still deletes the VM; otherwise a paid VM leaks" '^down '

run_case FAKE_DEPLOY_RC=1 FAKE_DEPLOY_OUT='error: resource mapping not found: no matches for kind "VolumeSnapshotClass" in version "snapshot.storage.k8s.io/v1"'
expect_pass "the known snapshotclass-without-CRDs error is tolerated"
expect_log "the known snapshotclass error still proceeds to the smoke" 'wordpress-smoke'

run_case FAKE_DOWN_RC=1
expect_fail "a failed VM delete fails the run; a WARN alone leaves a paid VM running unnoticed"

echo "---- $PASS passed, $FAIL failed ----"
[ "$FAIL" = 0 ]
