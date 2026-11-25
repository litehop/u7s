#!/usr/bin/env bash
# Upgrade gate: does re-running the candidate install.sh over the PREVIOUS release keep the
# cluster intact? (docs/install.md, "Upgrading"; supported path is the immediately previous
# release only.)
#
# Per run: fresh 1 vCPU / 1 GiB VM (the burst gate's shape) -> install the previous release with
# its zero-argument install.sh -> deploy a ConfigMap marker, a 2-replica Deployment and a
# DaemonSet -> record version, CA/sa.pub hashes, pod UIDs and restart counts -> start a 2 s
# /readyz poller -> re-run the candidate install.sh with no flags -> assert (verdict table:
# upgrade-lib.sh) -> re-run it once more for idempotence. API downtime is measured and
# reported; only an outage above UG_MAX_DOWNTIME_SECS (60) fails. Not a performance
# measurement: the burst gate's quiet-host / contention INVALID logic does not apply.
#
# Usage: upgrade-gate.sh [--backend lima|gcp] [--from TAG] [--release SNAPSHOT-TAG]
#                        [--prev-dir DIR --cand-dir DIR] [--keep] [--out DIR]
#   --from TAG       previous release (default: newest non-snapshot tag reachable from HEAD)
#   --release TAG    gcp: candidate, installed from the mirror (e.g. v0.4.7-snapshot.1);
#                    the previous release is installed from the mirror too
#   lima: the previous release is built (arm64, stamped U7S_RELEASE) from a scratch worktree of
#                    --from at ./temp/prev-src, the candidate from this checkout, both with
#                    build-arm64-tarball.sh; --prev-dir/--cand-dir reuse its finished output
#   --keep           do not delete the VM afterwards
#   --out DIR        results directory (default ./temp/upgrade-gate/<timestamp>)
# Exit codes: as burst-gate.sh ("Release-gate exit codes" in docs/dev-setup.md): 0 PASS,
# 1 FAIL, 2 usage error, 3 INVALID or PREEMPTED (infrastructure or the previous release's own
# install failed: not a verdict), 4 PASS but a VPS could not be deleted.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BACKEND=lima; FROM=""; RELEASE=""; PREV_DIR=""; CAND_DIR=""; KEEP=0; OUT=""; MEMORY=""; GCP_PROJECT=""
UG_WALL_SECS="${UG_WALL_SECS:-2700}"

while [ $# -gt 0 ]; do
  case "$1" in
    --backend) BACKEND="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --release) RELEASE="$2"; shift 2 ;;
    --prev-dir) PREV_DIR="$2"; shift 2 ;;
    --cand-dir) CAND_DIR="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# shellcheck source=lib.sh
. "$HERE/lib.sh"
# shellcheck source=upgrade-lib.sh
. "$HERE/upgrade-lib.sh"
# shellcheck source=backend.sh
. "$HERE/backend.sh"

[ -n "$FROM" ] || FROM="$(ug_default_from)" || { echo "no non-snapshot release tag reachable from HEAD; pass --from TAG" >&2; exit 2; }
ug_tag_valid "$FROM" || { echo "--from must look like v0.4.6, got '$FROM'" >&2; exit 2; }
case "$BACKEND" in
  lima)
    [ -z "$RELEASE" ] || { echo "--release is only for --backend gcp (lima builds the candidate from this checkout)" >&2; exit 2; }
    ;;
  gcp)
    ug_tag_valid "$RELEASE" || { echo "--backend gcp needs --release <snapshot tag>, got '$RELEASE'" >&2; exit 2; }
    [ "$RELEASE" != "$FROM" ] || { echo "--release and --from are the same tag" >&2; exit 2; }
    [ -z "$PREV_DIR$CAND_DIR" ] || { echo "--prev-dir/--cand-dir are lima only" >&2; exit 2; }
    # shellcheck source=../gcp/lib.sh
    . "$ROOT/scripts/gcp/lib.sh"
    export U7S_GCP_BOOT_DISK_TYPE=pd-balanced
    gcp_require_config
    GCP_PROJECT="$(gcloud config get-value project 2>/dev/null)" ;;
  *) echo "--backend must be lima or gcp, got '$BACKEND'" >&2; exit 2 ;;
esac
if [ "$BACKEND" = lima ] && [ -n "$PREV_DIR$CAND_DIR" ]; then
  { [ -n "$PREV_DIR" ] && [ -n "$CAND_DIR" ]; } || { echo "--prev-dir and --cand-dir go together" >&2; exit 2; }
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$PWD/temp/upgrade-gate/$STAMP}"
mkdir -p "$OUT"
VM="u7s-upg-${STAMP:4:4}${STAMP:9:6}-$(rg_nonce)"
VMS=""; PENDING=0
cleanup() {
  # The ssh/limactl client sits below the backgrounded shell function, so kill whole trees.
  local jobpids; jobpids="$(jobs -p | tr '\n' ' ')"
  [ -z "${jobpids// /}" ] || rg_kill_tree "$jobpids"
  if [ "$PENDING" = 1 ]; then
    vm_copy_from "$VM" /var/tmp/rg/out "$OUT/out" 2>/dev/null || true
  fi
  [ "$KEEP" = 1 ] && return
  local vm
  for vm in $VMS; do vm_delete "$vm"; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Runs a VM operation as a background job and waits for it, keeping its exit status: bash defers
# a trap until a foreground command ends, so a signal during a long limactl start / gcloud call
# would otherwise leave the VM running (and billing) until that call returned.
vm_bg() { "$@" & local bg_pid=$!; wait "$bg_pid"; }

STAGE="$OUT/stage"; mkdir -p "$STAGE"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
if [ "$BACKEND" = lima ]; then
  CAND_EXPECT="cand-${COMMIT:0:7}"
  if [ -z "$PREV_DIR" ]; then
    PREV_SRC="$ROOT/temp/prev-src"
    want="$(git -C "$ROOT" rev-list -n1 "$FROM")" || { echo "unknown tag $FROM" >&2; exit 2; }
    [ -d "$PREV_SRC" ] || git -C "$ROOT" worktree add "$PREV_SRC" "$FROM" >&2 || exit 2
    [ "$(git -C "$PREV_SRC" rev-parse HEAD)" = "$want" ] || { echo "$PREV_SRC is not at $FROM; remove it (git worktree remove) and rerun" >&2; exit 2; }
    PREV_DIR="$OUT/dist/prev"; CAND_DIR="$OUT/dist/cand"
    export U7S_BUILD_DATE; U7S_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Release builds are stamped (scripts/build-release-tarball.sh); an unstamped pair would both
    # report +u7s-dev and the version assertion could not tell them apart.
    U7S_RELEASE="${FROM#v}" U7S_GIT_COMMIT="$want" "$PREV_SRC/scripts/release-gate/build-arm64-tarball.sh" "$PREV_DIR" >"$OUT/build-prev.log" 2>&1 & bp=$!
    U7S_RELEASE="$CAND_EXPECT" U7S_GIT_COMMIT="$COMMIT" "$HERE/build-arm64-tarball.sh" "$CAND_DIR" >"$OUT/build-cand.log" 2>&1 & bc=$!
    wait "$bp" || { echo "previous-release build failed (see $OUT/build-prev.log)" >&2; exit 2; }
    wait "$bc" || { echo "candidate build failed (see $OUT/build-cand.log)" >&2; exit 2; }
  fi
  # Locally built tarballs are unsigned, so install.sh gets --tarball (as in the burst gate): a
  # Lima-only stand-in for the baked release URL; the upgrade is otherwise the flagless re-run.
  for side in prev cand; do
    src="$PREV_DIR"; [ "$side" = cand ] && src="$CAND_DIR"
    mkdir -p "$STAGE/$side"
    cp "$src"/u7s-gate-*.tar.gz "$src"/u7s-gate-*.tar.gz.sha256 "$src/install.sh" "$STAGE/$side/"
  done
  tb=u7s-gate-aarch64-unknown-linux-gnu.tar.gz
  PREV_INSTALL="bash /var/tmp/rg/prev/install.sh --tarball /var/tmp/rg/prev/$tb"
  CAND_INSTALL="bash /var/tmp/rg/cand/install.sh --tarball /var/tmp/rg/cand/$tb"
else
  CAND_EXPECT="${RELEASE#v}"
  PREV_INSTALL="bash /var/tmp/rg/prev-install.sh"; CAND_INSTALL="bash /var/tmp/rg/cand-install.sh"
fi
cp "$HERE/lib.sh" "$HERE/upgrade-lib.sh" "$HERE/upgrade-vm.sh" "$STAGE/"
printf 'PREV_INSTALL=%q\nCAND_INSTALL=%q\nCAND_EXPECT=%q\n' "$PREV_INSTALL" "$CAND_INSTALL" "$CAND_EXPECT" > "$STAGE/upgrade.env"

echo "==== upgrade $FROM -> ${RELEASE:-$CAND_EXPECT} on $BACKEND: VM $VM ===="
VMS="$VM"
status=""
if vm_bg vm_create "$VM" "$OUT"; then
  vm_bg vm_trim "$VM" >"$OUT/trim.log" 2>&1 || echo "warning: could not trim $VM (see $OUT/trim.log)" >&2
  vm_bg vm_shell "$VM" sudo install -d -m 0777 /var/tmp/rg
  vm_bg vm_copy_to "$VM" /var/tmp/rg "$STAGE"/* || echo "warning: could not copy the gate scripts to $VM" >&2
  if [ "$BACKEND" = gcp ]; then
    for pair in "prev-install.sh|$FROM" "cand-install.sh|$RELEASE"; do
      vm_bg vm_shell "$VM" curl -fsSL "https://u7s.dekiru.tech/${pair#*|}/install.sh" -o "/var/tmp/rg/${pair%%|*}" \
        || echo "warning: could not fetch install.sh for ${pair#*|} from the mirror" >&2
    done
  fi
  PENDING=1
  if [ "$BACKEND" = gcp ]; then
    vm_shell "$VM" sudo bash /var/tmp/rg/upgrade-vm.sh 2>&1 | gcp_redact -u >"$OUT/upgrade-vm.log" &
  else
    vm_shell "$VM" sudo bash /var/tmp/rg/upgrade-vm.sh >"$OUT/upgrade-vm.log" 2>&1 &
  fi
  gate_pid=$!
  tail -n +1 -f "$OUT/upgrade-vm.log" & tail_pid=$!
  ( sleep "$UG_WALL_SECS"; echo "run wall-clock cap ${UG_WALL_SECS}s hit; killing" >&2
    vm_shell "$VM" sudo pkill -KILL -f "$RG_VM_KILL_PATTERN" 2>/dev/null
    rg_kill_tree "$gate_pid" ) & wd_pid=$!
  wait "$gate_pid" 2>/dev/null
  kill "$wd_pid" "$tail_pid" 2>/dev/null
  vm_copy_from "$VM" /var/tmp/rg/out "$OUT/out" 2>/dev/null || echo "warning: could not copy results out of $VM" >&2
  PENDING=0
else
  status=INVALID
  echo "INFRASTRUCTURE (INVALID, not a u7s FAIL): $VM failed to create/start (see $OUT/*-create.log)" | tee "$OUT/verdict.txt"
fi

mkdir -p "$OUT/out"; touch "$OUT/out/results.env"
if [ -z "$status" ]; then
  echo "---- verdict ($FROM -> ${RELEASE:-$CAND_EXPECT}) ----"
  { ug_verdict "$OUT/out/results.env"; } | tee "$OUT/verdict.txt"
  ug_run_status "$OUT/out/results.env"; rc=$?
  he="$(rg_get "$OUT/out/results.env" harness_error)"
  [ -z "$he" ] || echo "HARNESS ERROR (INVALID, not a u7s FAIL): $he"
  if [ "$BACKEND" = gcp ] && [ "$rc" != 0 ]; then
    pre_rc=0; gcp_vps_was_preempted "$VM" || pre_rc=$?
    [ "$pre_rc" != 0 ] || { echo "PREEMPTED: Google reclaimed $VM; the run is not a verdict"; rc=3; }
  fi
else
  rc=3
fi
[ "$KEEP" = 1 ] || { vm_delete "$VM" && VMS=""; }
if [ -s "$OUT/leaked-vps.txt" ]; then
  echo "WARNING: VPS may still be running and billing:"; cat "$OUT/leaked-vps.txt"
  [ "$rc" != 0 ] || rc=4
fi
case "$rc" in 0) w=PASS ;; 1) w=FAIL ;; 3) w=INVALID ;; *) w="PASS but LEAKED VPS" ;; esac
echo "==== UPGRADE GATE: $w (results in $OUT) ===="
exit "$rc"
