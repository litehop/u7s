#!/usr/bin/env bash
# Shared helpers for the GCP test-VPS scripts (sourced, not executed).
# Machine-specific settings (account, project, zone) live only in the local gcloud
# named configuration u7s-gcp (override: U7S_GCP_CONFIG), never in git.

GCP_NETWORK=u7s-test
GCP_REGION=us-west1
GCP_SUBNET_RANGE=10.80.0.0/24
GCP_IAP_RANGE=35.235.240.0/20
GCP_LABEL=u7s-test=1

# A stray CLOUDSDK_* variable (project, zone, config dir, impersonation...) would silently
# override the named configuration.
for _v in $(compgen -v CLOUDSDK_); do unset "$_v"; done
unset _v
export CLOUDSDK_ACTIVE_CONFIG_NAME="${U7S_GCP_CONFIG:-u7s-gcp}"

gcp_die() { echo "error: $*" >&2; exit 1; }

# Fails unless the named configuration exists and has a project.
gcp_require_config() {
  gcloud config configurations describe "$CLOUDSDK_ACTIVE_CONFIG_NAME" >/dev/null 2>&1 \
    || gcp_die "gcloud configuration '$CLOUDSDK_ACTIVE_CONFIG_NAME' not found; see docs/dev-setup.md (GCP test VPSes)"
  local project
  project="$(gcloud config get-value project 2>/dev/null)" || project=
  [ -n "$project" ] \
    || gcp_die "gcloud configuration '$CLOUDSDK_ACTIVE_CONFIG_NAME' has no project; see docs/dev-setup.md (GCP test VPSes)"
}

gcp_vps_create() {
  gcloud compute instances create "$1" --zone="$2" \
    --machine-type=e2-micro \
    --image-family=ubuntu-2604-lts-amd64 --image-project=ubuntu-os-cloud \
    --boot-disk-size=10GB --boot-disk-type=pd-standard \
    --network="$GCP_NETWORK" --subnet="$GCP_NETWORK" \
    --labels="$GCP_LABEL" \
    --provisioning-model=SPOT --instance-termination-action=STOP --max-run-duration=16h
}

# gcp_vps_ssh NAME [-- command...]
gcp_vps_ssh() {
  local name="$1"; shift
  [ "${1:-}" = -- ] && shift
  gcloud compute ssh "$name" --tunnel-through-iap -- "$@"
}

# gcp_vps_scp scp-args... (remote side written NAME:path)
gcp_vps_scp() { gcloud compute scp --tunnel-through-iap "$@"; }

# gcp_vps_delete NAME ZONE: refuses instances not labelled u7s-test=1. Never exits the caller:
# a transient API error is retried (GCP_DELETE_TRIES, GCP_DELETE_SLEEP) and then returned as
# non-zero so later cleanup still runs. An instance that does not exist counts as deleted.
gcp_vps_delete() {
  local label err i tries="${GCP_DELETE_TRIES:-4}" ok=0
  err="$(mktemp)"
  for i in $(seq 1 "$tries"); do
    if label="$(gcloud compute instances describe "$1" --zone="$2" --format='value(labels.u7s-test)' 2>"$err")"; then ok=1; break; fi
    if grep -q 'was not found' "$err"; then rm -f "$err"; return 0; fi
    sleep "${GCP_DELETE_SLEEP:-5}"
  done
  if [ "$ok" = 0 ]; then cat "$err" >&2; rm -f "$err"; echo "error: cannot describe $1 after $tries tries" >&2; return 1; fi
  rm -f "$err"
  [ "$label" = 1 ] || { echo "error: $1 is not labelled u7s-test=1; refusing to delete" >&2; return 1; }
  for i in $(seq 1 "$tries"); do
    gcloud compute instances delete "$1" --zone="$2" --quiet && return 0
    sleep "${GCP_DELETE_SLEEP:-5}"
  done
  echo "error: cannot delete $1 after $tries tries" >&2
  return 1
}

# Prints "NAME<TAB>ZONE" per u7s-test=1 instance.
gcp_vps_names() {
  gcloud compute instances list --filter="labels.u7s-test=1" --format='value(name,zone.basename())'
}

# The configured compute zone; fails if unset.
gcp_zone() {
  local zone
  zone="$(gcloud config get-value compute/zone 2>/dev/null)" || zone=
  [ -n "$zone" ] || gcp_die "gcloud configuration '$CLOUDSDK_ACTIVE_CONFIG_NAME' has no compute/zone; see docs/dev-setup.md (GCP test VPSes)"
  echo "$zone"
}

gcp_print_target() {
  echo "target: project=$(gcloud config get-value project 2>/dev/null) account=$(gcloud config get-value account 2>/dev/null) config=$CLOUDSDK_ACTIVE_CONFIG_NAME"
}

# Did Google reclaim NAME (Spot preemption)? Returns 0 yes, 1 no, 2 the lookup kept failing
# (GCP_OPS_TRIES, GCP_OPS_SLEEP): unknown, which callers must not read as "no".
gcp_vps_was_preempted() {
  local ops i
  for i in $(seq 1 "${GCP_OPS_TRIES:-3}"); do
    if ops="$(gcloud compute operations list \
      --filter="operationType=compute.instances.preempted AND targetLink~/$1\$" \
      --format='value(name)')"; then
      [ -n "$ops" ]; return $?
    fi
    sleep "${GCP_OPS_SLEEP:-5}"
  done
  return 2
}
