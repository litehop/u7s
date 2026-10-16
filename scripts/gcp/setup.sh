#!/usr/bin/env bash
# One-time (idempotent) GCP project setup for the u7s test VPSes: IAP API, the
# u7s-test VPC + subnet, and firewall rules (IAP SSH + intra-subnet only).
#
# Usage: setup.sh [--dry-run]
#   --dry-run  run only read-only gcloud calls and print the mutating commands that
#              would run given the project's current state
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

DRY_RUN=0
case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=1 ;;
  *) echo "usage: setup.sh [--dry-run]" >&2; exit 2 ;;
esac

gcp_require_config
gcp_print_target

# The only path to a mutating gcloud call; dry-run prints instead of executing.
mutate() {
  if [ "$DRY_RUN" = 1 ]; then
    echo "WOULD RUN: gcloud $*"
  else
    echo "RUN: gcloud $*"
    gcloud "$@"
  fi
}

# gcloud list ... -> true iff it printed something; a failed list aborts (not "absent").
exists() {
  local out
  out="$(gcloud "$@")" || gcp_die "gcloud $* failed"
  [ -n "$out" ]
}

enabled="$(gcloud services list --enabled --format='value(config.name)')"
for api in compute.googleapis.com iap.googleapis.com; do
  if grep -qx "$api" <<<"$enabled"; then echo "ok: $api enabled"; else mutate services enable "$api"; fi
done

# Listing compute resources needs the API; without it nothing exists yet.
net_exists=0
if grep -qx compute.googleapis.com <<<"$enabled" \
    && exists compute networks list --filter="name=$GCP_NETWORK" --format='value(name)'; then
  net_exists=1
  echo "ok: network $GCP_NETWORK"
else
  mutate compute networks create "$GCP_NETWORK" --subnet-mode=custom
fi

if [ "$net_exists" = 1 ] && exists compute networks subnets list \
    --filter="name=$GCP_NETWORK AND region:$GCP_REGION" --format='value(name)'; then
  echo "ok: subnet $GCP_NETWORK"
else
  mutate compute networks subnets create "$GCP_NETWORK" --network="$GCP_NETWORK" \
    --range="$GCP_SUBNET_RANGE" --region="$GCP_REGION"
fi

fw_exists() {
  [ "$net_exists" = 1 ] && exists compute firewall-rules list --filter="name=$1" --format='value(name)'
}
if fw_exists "$GCP_NETWORK-allow-iap-ssh"; then
  echo "ok: firewall $GCP_NETWORK-allow-iap-ssh"
else
  mutate compute firewall-rules create "$GCP_NETWORK-allow-iap-ssh" --network="$GCP_NETWORK" \
    --direction=INGRESS --allow=tcp:22 --source-ranges="$GCP_IAP_RANGE"
fi
if fw_exists "$GCP_NETWORK-allow-internal"; then
  echo "ok: firewall $GCP_NETWORK-allow-internal"
else
  mutate compute firewall-rules create "$GCP_NETWORK-allow-internal" --network="$GCP_NETWORK" \
    --direction=INGRESS --allow=all --source-ranges="$GCP_SUBNET_RANGE"
fi
