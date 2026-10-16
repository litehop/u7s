#!/usr/bin/env bash
# Shared helpers for the GCP test-VPS scripts (sourced, not executed).
# Machine-specific settings (account, project, zone) live only in the local gcloud
# named configuration u7s-gcp (override: U7S_GCP_CONFIG), never in git.

GCP_NETWORK=u7s-test
GCP_REGION=us-west1
GCP_SUBNET_RANGE=10.80.0.0/24
GCP_IAP_RANGE=35.235.240.0/20
GCP_LABEL=u7s-test=1

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

gcp_vps_ip() {
  gcloud compute instances describe "$1" --format='value(networkInterfaces[0].networkIP)'
}

gcp_vps_delete() { gcloud compute instances delete "$1" --quiet; }

gcp_vps_names() {
  gcloud compute instances list --filter="labels.u7s-test=1" --format='value(name)'
}

# True iff Google reclaimed NAME (Spot preemption).
gcp_vps_was_preempted() {
  local ops
  ops="$(gcloud compute operations list \
    --filter="operationType=compute.instances.preempted AND targetLink~/$1\$" \
    --format='value(name)')" || return 1
  [ -n "$ops" ]
}
