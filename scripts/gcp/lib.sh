#!/usr/bin/env bash
# Shared helpers for the GCP test-VPS scripts (sourced, not executed).
# Machine-specific settings (account, project, zone) live only in the local gcloud
# named configuration u7s-gcp (override: U7S_GCP_CONFIG), never in git.

GCP_NETWORK=u7s-test
GCP_REGION=us-west1
GCP_SUBNET_RANGE=10.80.0.0/24
GCP_IAP_RANGE=35.235.240.0/20
GCP_LABEL=u7s-test=1

# A stray CLOUDSDK_* variable would silently override the named configuration.
unset CLOUDSDK_CORE_PROJECT CLOUDSDK_CORE_ACCOUNT CLOUDSDK_COMPUTE_ZONE CLOUDSDK_COMPUTE_REGION
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
  gcloud compute instances create "$1" \
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

# gcp_vps_delete NAME ZONE: refuses instances not labelled u7s-test=1.
gcp_vps_delete() {
  local label
  label="$(gcloud compute instances describe "$1" --zone="$2" --format='value(labels.u7s-test)')" \
    || gcp_die "cannot describe $1"
  [ "$label" = 1 ] || gcp_die "$1 is not labelled u7s-test=1; refusing to delete"
  gcloud compute instances delete "$1" --zone="$2" --quiet
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

# True iff Google reclaimed NAME (Spot preemption).
gcp_vps_was_preempted() {
  local ops
  ops="$(gcloud compute operations list \
    --filter="operationType=compute.instances.preempted AND targetLink~/$1\$" \
    --format='value(name)')" || return 1
  [ -n "$ops" ]
}
