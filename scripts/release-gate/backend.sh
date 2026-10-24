#!/usr/bin/env bash
# VM backends for burst-gate.sh (sourced, not executed): lima (arm64, local) and gcp (x86_64
# Spot e2-micro, installed from the release mirror). Needs BACKEND and, for lima, HERE and
# MEMORY; for gcp, scripts/gcp/lib.sh sourced and gcp_require_config passed.
#
# vm_create NAME LOGDIR   create and start NAME; non-zero if it never became usable
# vm_shell NAME cmd...    run cmd as the login user; arguments keep their quoting
# vm_copy_to NAME DIR SRC...   copy files/directories into DIR on NAME
# vm_copy_from NAME SRC DST    copy a directory out of NAME
# vm_delete NAME
# vm_running NAME         one line describing NAME's state, for the host log

GCP_SSH_TRIES="${GCP_SSH_TRIES:-30}"
GCP_SSH_SLEEP="${GCP_SSH_SLEEP:-10}"

vm_create() {
  local name="$1" logdir="$2" args i
  case "$BACKEND" in
    lima)
      args=(--name "$name" --tty=false)
      [ -n "$MEMORY" ] && args+=(--memory "$MEMORY")
      limactl create "${args[@]}" "$HERE/u7s-vps-1g.yaml" >"$logdir/lima-create.log" 2>&1 \
        && limactl start "$name" >"$logdir/lima-start.log" 2>&1 ;;
    gcp)
      gcp_vps_create "$name" "$(gcp_zone)" 2>&1 | gcp_redact >"$logdir/gcp-create.log" || return 1
      for i in $(seq 1 "$GCP_SSH_TRIES"); do
        vm_shell "$name" true >/dev/null 2>&1 && return 0
        sleep "$GCP_SSH_SLEEP"
      done
      echo "$name never became reachable over IAP ssh" >>"$logdir/gcp-create.log"
      return 1 ;;
  esac
}

vm_shell() {
  local name="$1"; shift
  case "$BACKEND" in
    lima) limactl shell "$name" "$@" ;;
    gcp) gcp_scrub_stderr gcp_vps_ssh "$name" -- -o ServerAliveInterval=30 "$(printf '%q ' "$@")" ;;
  esac
}

vm_copy_to() {
  local name="$1" dir="$2" f; shift 2
  case "$BACKEND" in
    lima) for f in "$@"; do limactl copy -r "$f" "$name:$dir/" >/dev/null || return 1; done ;;
    gcp) gcp_scrub_stderr gcp_vps_scp --recurse "$@" "$name:$dir/" >/dev/null ;;
  esac
}

vm_copy_from() {
  case "$BACKEND" in
    lima) limactl copy -r "$1:$2" "$3" >/dev/null ;;
    gcp) gcp_scrub_stderr gcp_vps_scp --recurse "$1:$2" "$3" >/dev/null || return 1
         gcp_redact_tree "$3" ;;
  esac
}

# Non-zero if the VM may still exist. A leaked GCP VPS keeps billing, so it is named loudly
# on stderr and in $OUT/leaked-vps.txt.
vm_delete() {
  case "$BACKEND" in
    lima) limactl delete -f "$1" >/dev/null 2>&1 ;;
    gcp)
      gcp_vps_delete "$1" "$(gcp_zone)" >/dev/null 2>&1 && return 0
      echo "LEAKED GCP VPS $1: delete failed; remove it with scripts/gcp/vps.sh down $1" | tee -a "${OUT:-.}/leaked-vps.txt" >&2
      return 1 ;;
  esac
}

vm_running() {
  case "$BACKEND" in
    lima) limactl list 2>/dev/null | rg_other_vms "$1" | tr '\n' ' ' ;;
    gcp) gcloud compute instances list --filter="name=$1" --format='value(status)' 2>/dev/null | tr '\n' ' ' ;;
  esac
}

# Scrubs the gcloud project id from text on stdin (it must never reach logs we paste).
gcp_redact() { sed "$@" "s|${GCP_PROJECT:-@@none@@}|<project>|g"; }

# Runs a command with its stderr scrubbed of the project id; stdout and exit status untouched.
gcp_scrub_stderr() {
  local rc errf
  errf="$(mktemp)"
  "$@" 2>"$errf"; rc=$?
  gcp_redact <"$errf" >&2
  rm -f "$errf"
  return $rc
}

# Scrubs the project id from every file under $1 (copied-out logs echo the guest hostname).
gcp_redact_tree() {
  local f
  while IFS= read -r f; do
    grep -qaF "${GCP_PROJECT:-@@none@@}" "$f" || continue
    gcp_redact <"$f" >"$f.redacted" && mv "$f.redacted" "$f"
  done < <(find "$1" -type f)
}
