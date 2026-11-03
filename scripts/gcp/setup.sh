#!/usr/bin/env bash
# One-time (idempotent) GCP project setup for the u7s test VPSes: IAP API, the
# u7s-test VPC + subnets u7s-test and u7s-test-b (dual-stack, VPC flow logs), and firewall rules (IAP SSH +
# intra-VPC only, IPv4 and IPv6), plus the u7s-probe VPC + dual-stack subnet with an IAP SSH rule
# for the outside-VPC probe VM.
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

# VPC flow logs on both u7s-test subnets record what the provider delivered between nodes. The
# coarsest aggregation interval and the default sampling keep Logging ingestion small.
FLOW_LOGS=(--enable-flow-logs --logging-aggregation-interval=interval-5-min --logging-flow-sampling=0.5)

# ensure_subnet NAME RANGE: a dual-stack (external IPv6) u7s-test subnet in $GCP_REGION with flow logs.
# Sets subnet_present=1 when it already existed.
ensure_subnet() {
  local state
  subnet_present=0
  if [ "$net_exists" = 1 ] && exists compute networks subnets list \
      --filter="name=$1 AND region:$GCP_REGION" --format='value(name)'; then
    subnet_present=1
    state="$(gcloud compute networks subnets describe "$1" --region="$GCP_REGION" \
      --format='value(stackType)')" || gcp_die "cannot describe subnet $1"
    if [ "$state" = IPV4_IPV6 ]; then
      echo "ok: subnet $1 (dual-stack)"
    else
      # One-way: GCP cannot convert a dual-stack subnet back to IPV4_ONLY while in use,
      # and the IPv6 access type can never change afterwards.
      mutate compute networks subnets update "$1" --region="$GCP_REGION" \
        --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL
    fi
    state="$(gcloud compute networks subnets describe "$1" --region="$GCP_REGION" \
      --format='value(logConfig.enable)')" || gcp_die "cannot describe subnet $1"
    if [ "$state" = True ]; then
      echo "ok: subnet $1 (flow logs)"
    else
      mutate compute networks subnets update "$1" --region="$GCP_REGION" "${FLOW_LOGS[@]}"
    fi
  else
    mutate compute networks subnets create "$1" --network="$GCP_NETWORK" \
      --range="$2" --region="$GCP_REGION" \
      --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL "${FLOW_LOGS[@]}"
  fi
}

# subnet_v6 NAME: the subnet's external /64, the source range of its IPv6 traffic. It exists only
# once the subnet is dual-stack, so a dry run against a missing subnet prints a placeholder.
subnet_v6() {
  local p
  if [ "$DRY_RUN" = 1 ] && [ "$2" = 0 ]; then echo "<$1-external-ipv6-prefix>"; return; fi
  p="$(gcloud compute networks subnets describe "$1" --region="$GCP_REGION" \
    --format='value(externalIpv6Prefix)')" || gcp_die "cannot describe subnet $1"
  [ -n "$p" ] || [ "$DRY_RUN" = 1 ] || gcp_die "subnet $1 has no external IPv6 prefix"
  echo "${p:-<$1-external-ipv6-prefix>}"
}

ensure_subnet "$GCP_NETWORK" "$GCP_SUBNET_RANGE"
v6_a="$(subnet_v6 "$GCP_NETWORK" "$subnet_present")"
ensure_subnet "$GCP_SUBNET_B" "$GCP_SUBNET_B_RANGE"
v6_b="$(subnet_v6 "$GCP_SUBNET_B" "$subnet_present")"

fw_exists() {
  [ "$net_exists" = 1 ] && exists compute firewall-rules list --filter="name=$1" --format='value(name)'
}
if fw_exists "$GCP_NETWORK-allow-iap-ssh"; then
  echo "ok: firewall $GCP_NETWORK-allow-iap-ssh"
else
  mutate compute firewall-rules create "$GCP_NETWORK-allow-iap-ssh" --network="$GCP_NETWORK" \
    --direction=INGRESS --allow=tcp:22 --source-ranges="$GCP_IAP_RANGE"
fi

sorted_ranges() { tr ';,' '\n\n' <<<"$1" | sort | paste -sd, -; }
# ensure_internal_rule NAME RANGES: all ingress from exactly RANGES (comma-separated), both subnets'.
ensure_internal_rule() {
  local have
  if fw_exists "$1"; then
    have="$(gcloud compute firewall-rules describe "$1" --format='value(sourceRanges)')" \
      || gcp_die "cannot describe firewall $1"
    if [ "$(sorted_ranges "$have")" = "$(sorted_ranges "$2")" ]; then
      echo "ok: firewall $1"
    else
      mutate compute firewall-rules update "$1" --source-ranges="$2"
    fi
  else
    mutate compute firewall-rules create "$1" --network="$GCP_NETWORK" \
      --direction=INGRESS --allow=all --source-ranges="$2"
  fi
}
ensure_internal_rule "$GCP_NETWORK-allow-internal" "$GCP_SUBNET_RANGE,$GCP_SUBNET_B_RANGE"
# The IPv6 mirror. Ingress is implicitly denied for IPv6, so without it dual-stack VMs are
# unreachable. The IAP ssh rule has no IPv6 mirror: IAP forwards from IPv4 ranges only, so ssh
# stays IAP-only. No rule opens ::/0.
ensure_internal_rule "$GCP_NETWORK-allow-internal-v6" "$v6_a,$v6_b"

# The probe VPC: one dual-stack VM here reaches the test VPC only over its external addresses, so
# a LoadBalancer answering it is reachable from outside. It gets IAP ssh (IPv4-only) and nothing else.
probe_net=0
if grep -qx compute.googleapis.com <<<"$enabled" \
    && exists compute networks list --filter="name=$GCP_PROBE_NETWORK" --format='value(name)'; then
  probe_net=1
  echo "ok: network $GCP_PROBE_NETWORK"
else
  mutate compute networks create "$GCP_PROBE_NETWORK" --subnet-mode=custom
fi
if [ "$probe_net" = 1 ] && exists compute networks subnets list \
    --filter="name=$GCP_PROBE_NETWORK AND region:$GCP_REGION" --format='value(name)'; then
  probe_state="$(gcloud compute networks subnets describe "$GCP_PROBE_NETWORK" --region="$GCP_REGION" \
    --format='value(stackType)')" || gcp_die "cannot describe subnet $GCP_PROBE_NETWORK"
  if [ "$probe_state" = IPV4_IPV6 ]; then
    echo "ok: subnet $GCP_PROBE_NETWORK (dual-stack)"
  else
    mutate compute networks subnets update "$GCP_PROBE_NETWORK" --region="$GCP_REGION" \
      --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL
  fi
else
  mutate compute networks subnets create "$GCP_PROBE_NETWORK" --network="$GCP_PROBE_NETWORK" \
    --range="$GCP_PROBE_SUBNET_RANGE" --region="$GCP_REGION" \
    --stack-type=IPV4_IPV6 --ipv6-access-type=EXTERNAL
fi
if [ "$probe_net" = 1 ] && exists compute firewall-rules list \
    --filter="name=$GCP_PROBE_NETWORK-allow-iap-ssh" --format='value(name)'; then
  echo "ok: firewall $GCP_PROBE_NETWORK-allow-iap-ssh"
else
  mutate compute firewall-rules create "$GCP_PROBE_NETWORK-allow-iap-ssh" --network="$GCP_PROBE_NETWORK" \
    --direction=INGRESS --allow=tcp:22 --source-ranges="$GCP_IAP_RANGE"
fi
