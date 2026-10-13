#!/usr/bin/env bash
# Usage: set-kubelet-resolvconf.sh <kubelet-config.yaml>
#
# Points the kubelet config's resolvConf at a file with real upstream
# nameservers (kubeadm's rule: systemd-resolved active -> its non-stub file,
# else /etc/resolv.conf). `resolvConf: ""` gives CoreDNS nameserver 127.0.0.1
# and a self-forward loop. Idempotent. Fails if the config has no `resolvConf:`
# line to rewrite, since sed would otherwise no-op silently.
set -euo pipefail

config="${1:?usage: set-kubelet-resolvconf.sh <kubelet-config.yaml>}"

if systemctl is-active --quiet systemd-resolved; then
  rc=/run/systemd/resolve/resolv.conf
else
  rc=/etc/resolv.conf
fi

sed -i.bak "s|^resolvConf: .*|resolvConf: $rc|" "$config"
rm -f "$config.bak"

if ! grep -qxF "resolvConf: $rc" "$config"; then
  echo "ERROR: $config has no 'resolvConf:' line to rewrite; expected 'resolvConf: $rc' after sed. CoreDNS would inherit the node's local resolver and self-forward." >&2
  exit 1
fi
