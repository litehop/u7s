#!/usr/bin/env bash
# Rig knob for the KCM A/B memory harness. Applies a KCM mode to an install-mode VM
# (run-all.sh --install) and restarts u7s-kcm, in either mode, so both start from a fresh process.
#
#   R  the shipped Go KCM, unchanged: removes this script's drop-in if present.
#   T  the shipped Go KCM with extra --controllers exclusions (KCM_TRIM_EXCLUDE), applied as a
#      systemd drop-in derived from the installed unit's own ExecStart. install.sh is not touched.
#
# Nothing calls this unless asked: without it every rig run is byte-identical to before.
# The T exclusions are an unvalidated candidate (no conformance run has confirmed them).
#
# Usage: scripts/conformance/kcm-mode.sh --vm <name> --mode R|T
# Prints the effective "--controllers=..." of the running KCM on stdout.
set -euo pipefail

# Candidate trim from the memory decomposition: HPA, TTL and the controllers for features
# the u7s apiserver does not serve.
KCM_TRIM_EXCLUDE="-ttl-controller,-legacy-serviceaccount-token-cleaner-controller,-validatingadmissionpolicy-status-controller,-storage-version-migrator-controller,-storageversion-garbage-collector-controller,-kube-apiserver-serving-clustertrustbundle-publisher-controller,-podcertificaterequest-cleaner-controller,-podgroup-protection-controller,-resourcepoolstatusrequest-controller,-volumeattributesclass-protection-controller,-horizontal-pod-autoscaler-controller"

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

# Restores mode R on shell exit, including INT/TERM, so a driver that last ran T does not leave
# the trimmed drop-in on the VM for the next install.sh to boot.
kcm_mode_revert_on_exit() {
  KCM_REVERT_VM="$1"
  trap 'trap - EXIT; kcm_mode_apply "$KCM_REVERT_VM" R >/dev/null || echo "kcm-mode: revert to R failed on $KCM_REVERT_VM" >&2' EXIT
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
