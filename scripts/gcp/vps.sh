#!/usr/bin/env bash
# Spot e2-micro test VPSes on the u7s-test VPC (run scripts/gcp/setup.sh once first).
#
# Usage: vps.sh up NAME | ssh NAME [-- cmd...] | scp SRC... NAME:DST | down NAME | list | gc
#   up    create a Spot VPS (termination action STOP, max run 16h, label u7s-test=1)
#   list  every u7s-test=1 VPS with state and age; STOPPED ones still bill for disk
#   gc    delete every u7s-test=1 VPS, stopped included
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

usage() { sed -n '2,8p' "$0" >&2; exit 2; }

[ $# -ge 1 ] || usage
gcp_require_config
cmd="$1"; shift

case "$cmd" in
  up)   [ $# -eq 1 ] || usage; gcp_vps_create "$1" ;;
  ssh)  [ $# -ge 1 ] || usage; gcp_vps_ssh "$@" ;;
  scp)  [ $# -ge 2 ] || usage; gcp_vps_scp "$@" ;;
  down) [ $# -eq 1 ] || usage; gcp_vps_delete "$1" ;;
  list)
    gcloud compute instances list --filter="labels.u7s-test=1" \
      --format='table(name,status,creationTimestamp.date("%Y-%m-%dT%H:%MZ"):label=CREATED,zone.basename())'
    ;;
  gc)
    names="$(gcp_vps_names)"
    for n in $names; do gcp_vps_delete "$n"; done
    ;;
  *) usage ;;
esac
