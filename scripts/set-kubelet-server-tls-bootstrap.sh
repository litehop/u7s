#!/usr/bin/env bash
# Usage: set-kubelet-server-tls-bootstrap.sh <kubelet-config.yaml>
#
# Ensures the kubelet config sets `serverTLSBootstrap: true`, so the kubelet requests its serving
# cert through the CSR API and renews it itself, instead of serving a static file. A VM cloned
# from lima-golden keeps the config baked when the golden was last built, so the key never
# reaches it otherwise. Idempotent.
set -euo pipefail

config="${1:?usage: set-kubelet-server-tls-bootstrap.sh <kubelet-config.yaml>}"

if grep -qx 'serverTLSBootstrap: true' "$config"; then
  exit 0
fi

if grep -q '^serverTLSBootstrap:' "$config"; then
  sed -i.bak 's|^serverTLSBootstrap:.*|serverTLSBootstrap: true|' "$config"
  rm -f "$config.bak"
else
  printf 'serverTLSBootstrap: true\n' >>"$config"
fi

if ! grep -qx 'serverTLSBootstrap: true' "$config"; then
  echo "ERROR: $config does not set 'serverTLSBootstrap: true' after rewrite." >&2
  exit 1
fi
