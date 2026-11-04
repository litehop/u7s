#!/usr/bin/env bash
# Usage: set-kubelet-clusterdns.sh <kubelet-config.yaml> <ip> [<ip>...]
#
# Rewrites the kubelet config's clusterDNS list to the given kube-dns VIPs,
# so pods' resolv.conf points at the address CoreDNS's Service actually has.
# Idempotent. Fails if the config has no `clusterDNS:` key to rewrite.
set -euo pipefail

config="${1:?usage: set-kubelet-clusterdns.sh <kubelet-config.yaml> <ip>...}"
shift
[ "$#" -ge 1 ] || { echo "ERROR: no clusterDNS address given" >&2; exit 1; }

grep -q '^clusterDNS:' "$config" || { echo "ERROR: $config has no 'clusterDNS:' key to rewrite" >&2; exit 1; }

tmp="$(mktemp)"
awk -v ips="$*" '
  BEGIN { n = split(ips, a, " ") }
  /^clusterDNS:/ { print; for (i = 1; i <= n; i++) print "  - " a[i]; skip = 1; next }
  skip && /^  - / { next }
  { skip = 0; print }
' "$config" > "$tmp"
cat "$tmp" > "$config"
rm -f "$tmp"
