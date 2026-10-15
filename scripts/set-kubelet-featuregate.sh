#!/usr/bin/env bash
# Usage: set-kubelet-featuregate.sh <kubelet-config.yaml> <GateName>
#
# Ensures `featureGates:` in the kubelet config sets <GateName>: true. A VM cloned from
# lima-golden keeps the /etc/kubelet-config.yaml baked when the golden was last built, so a gate
# added to lima/kubelet.yaml afterwards never reaches it without this. Idempotent.
set -euo pipefail

config="${1:?usage: set-kubelet-featuregate.sh <kubelet-config.yaml> <GateName>}"
gate="${2:?usage: set-kubelet-featuregate.sh <kubelet-config.yaml> <GateName>}"

if grep -qxF "  $gate: true" "$config"; then
  exit 0
fi

if grep -qE "^  $gate:" "$config"; then
  sed -i.bak "s|^  $gate:.*|  $gate: true|" "$config"
  rm -f "$config.bak"
elif grep -qx 'featureGates:' "$config"; then
  sed -i.bak "/^featureGates:/a\\
\\  $gate: true" "$config"
  rm -f "$config.bak"
else
  printf 'featureGates:\n  %s: true\n' "$gate" >>"$config"
fi

if ! grep -qxF "  $gate: true" "$config"; then
  echo "ERROR: $config does not set '$gate: true' after rewrite; kubelet would ignore the gated field." >&2
  exit 1
fi
