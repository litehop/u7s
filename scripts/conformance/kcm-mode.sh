#!/usr/bin/env bash
# Rig knob for the KCM A/B memory harness. Applies a KCM mode to an install-mode VM
# (run-all.sh --install) and restarts u7s-kcm, in either mode, so both start from a fresh process.
#
#   R  the shipped Go KCM, unchanged: removes this script's drop-in if present.
#   T  the shipped Go KCM with extra --controllers exclusions (KCM_TRIM_EXCLUDE), applied as a
#      systemd drop-in derived from the installed unit's own ExecStart. install.sh is not touched.
#
# Nothing calls this unless asked: without it every rig run is byte-identical to before.
# T excludes 10 controllers. The first 11-controller trim failed the VolumeAttributesClass lifecycle spec: the
# apiserver adds the vac-protection finalizer and only volumeattributesclass-protection-controller removes
# it, so that controller must stay.
#
# Usage: scripts/conformance/kcm-mode.sh --vm <name> --mode R|T
# Prints the effective "--controllers=..." of the running KCM on stdout.
set -euo pipefail

# Candidate trim from the memory decomposition: HPA, TTL and the controllers for features
# the u7s apiserver does not serve. A KCM_TRIM_EXCLUDE in the environment replaces it (the
# leave-one-out sweep excludes one controller at a time).
KCM_TRIM_EXCLUDE="${KCM_TRIM_EXCLUDE:--ttl-controller,-legacy-serviceaccount-token-cleaner-controller,-validatingadmissionpolicy-status-controller,-storage-version-migrator-controller,-storageversion-garbage-collector-controller,-kube-apiserver-serving-clustertrustbundle-publisher-controller,-podcertificaterequest-cleaner-controller,-podgroup-protection-controller,-resourcepoolstatusrequest-controller,-horizontal-pod-autoscaler-controller}"

KCM_DROPIN=/etc/systemd/system/u7s-kcm.service.d/90-kcm-mode.conf

# stdin: an "ExecStart=..." line; stdout: the same line with KCM_TRIM_EXCLUDE appended to --controllers.
kcm_trim_execstart() {
  sed -E "s|--controllers=[^ ]+|&,${KCM_TRIM_EXCLUDE}|"
}

# stdout: the drop-in body for mode $1 given the installed ExecStart line on stdin; empty for R.
kcm_mode_dropin() {
  case "$1" in
    R) ;;
    T) printf '[Service]\nExecStart=\n'; kcm_trim_execstart ;;
    *) echo "kcm-mode: mode must be R or T, got '$1'" >&2; return 2 ;;
  esac
}

kcm_mode_apply() {
  local vm="$1" mode="$2" exec_line body
  case "$mode" in R|T) ;; *) echo "kcm-mode: mode must be R or T, got '$mode'" >&2; return 2 ;; esac
  limactl shell "$vm" sudo rm -f "$KCM_DROPIN"
  if [ "$mode" = T ]; then
    exec_line="$(limactl shell "$vm" sudo grep '^ExecStart=' /etc/systemd/system/u7s-kcm.service)"
    [ -n "$exec_line" ] || { echo "kcm-mode: no ExecStart in the installed u7s-kcm.service" >&2; return 1; }
    body="$(printf '%s\n' "$exec_line" | kcm_mode_dropin T)"
    limactl shell "$vm" sudo mkdir -p "$(dirname "$KCM_DROPIN")"
    printf '%s\n' "$body" | limactl shell "$vm" sudo tee "$KCM_DROPIN" >/dev/null
  fi
  limactl shell "$vm" sudo systemctl daemon-reload
  limactl shell "$vm" sudo systemctl restart u7s-kcm.service
  local _
  for _ in $(seq 1 30); do
    limactl shell "$vm" sudo systemctl is-active --quiet u7s-kcm.service && break
    sleep 1
  done
  limactl shell "$vm" sudo systemctl is-active --quiet u7s-kcm.service \
    || { echo "kcm-mode: u7s-kcm is not active after switching to $mode" >&2; return 1; }
  limactl shell "$vm" sudo systemctl show -p ExecStart u7s-kcm.service | grep -oE -- '--controllers=[^ ;]+' | sed -n 1p
}

kcm_kill_tree() {
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do kcm_kill_tree "$c"; done
  kill "$1" 2>/dev/null || true
}

# Runs kcm_mode_apply R and kills it and its children after KCM_REVERT_TIMEOUT_S (macOS has no
# timeout(1)); a dead VM or Lima ssh mux would otherwise hang the shell's exit forever. Teardown's
# clear-native-units.sh stays the backstop for the drop-in. Same watchdog as bounded() in
# scripts/e2e-install/cloud-two-node.sh.
kcm_mode_revert_bounded() {
  local vm="$1" secs="${KCM_REVERT_TIMEOUT_S:-120}" p w rc=0
  kcm_mode_apply "$vm" R >/dev/null &
  p=$!
  { sleep "$secs"; kcm_kill_tree "$p"; } >/dev/null 2>&1 &
  w=$!
  wait "$p" || rc=$?
  kcm_kill_tree "$w"
  wait "$w" 2>/dev/null || true
  [ "$rc" -lt 128 ] || { echo "kcm-mode: revert to R timed out after ${secs}s on $vm; teardown clears the drop-in" >&2; return 124; }
  return "$rc"
}

# Restores mode R on shell exit, including INT/TERM, so a driver that last ran T does not leave
# the trimmed drop-in on the VM for the next install.sh to boot.
kcm_mode_revert_on_exit() {
  KCM_REVERT_VM="$1"
  trap 'trap - EXIT; kcm_mode_revert_bounded "$KCM_REVERT_VM" || echo "kcm-mode: revert to R failed on $KCM_REVERT_VM" >&2' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  VM=""; MODE=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --vm) VM="$2"; shift 2 ;;
      --mode) MODE="$2"; shift 2 ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  [ -n "$VM" ] && [ -n "$MODE" ] || { echo "usage: $0 --vm <name> --mode R|T" >&2; exit 2; }
  kcm_mode_apply "$VM" "$MODE"
fi
