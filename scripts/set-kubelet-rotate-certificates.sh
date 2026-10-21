#!/usr/bin/env bash
# Usage: set-kubelet-rotate-certificates.sh <kubelet-config.yaml>
#
# Ensures the kubelet config sets `rotateCertificates: true`, so the kubelet renews its own
# system:node client cert over the CSR API. A VM cloned from lima-golden keeps the config baked
# when the golden was last built, so the key never reaches it otherwise. Idempotent.
set -euo pipefail

config="${1:?usage: set-kubelet-rotate-certificates.sh <kubelet-config.yaml>}"

if grep -qx 'rotateCertificates: true' "$config"; then
  exit 0
fi

if grep -q '^rotateCertificates:' "$config"; then
  sed -i.bak 's|^rotateCertificates:.*|rotateCertificates: true|' "$config"
  rm -f "$config.bak"
else
  printf 'rotateCertificates: true\n' >>"$config"
fi

if ! grep -qx 'rotateCertificates: true' "$config"; then
  echo "ERROR: $config does not set 'rotateCertificates: true' after rewrite." >&2
  exit 1
fi
