#!/usr/bin/env bash
# Logic tests for run-all.sh --pod-cidr (RIG_POD_CIDR_V4 pass-through).
#
# Why it matters: KCM, flannel and kube-proxy must agree on the pod range. A flag that moves only
# one of them leaves nodes with podCIDRs flannel does not route, and a default run that drifts from
# 10.244.0.0/16 invalidates every earlier baseline.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

PASS=0
FAIL=0
check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "PASS: $label"; PASS=$((PASS + 1))
  else
    echo "FAIL: $label -- expected '$expected', got '$actual'"; FAIL=$((FAIL + 1))
  fi
}

# probe <pod-cidr or ""> <dual>: prints KCM flags, kube-proxy clusterCIDR and flannel Network line,
# sourcing _lib.sh in a fresh shell the way run-all.sh's children do (env inherited).
probe() {
  local d
  d="$(mktemp -d)"
  if [ -n "$1" ]; then export RIG_POD_CIDR_V4="$1"; else unset RIG_POD_CIDR_V4; fi
  # shellcheck source=scripts/conformance/_lib.sh
  ( source "$DIR/_lib.sh"
    rig_stage_manifests "$d" eth0 1500 "$2" 1.37.3 6443
    rig_kcm_cidr_flags "$2"
    grep -F 'clusterCIDR:' "$d/kube-proxy.yaml" | sed 's/^ *//'
    grep -F '"Network":' "$d/flannel.yaml" | sed 's/^ *//' )
}

check "default run keeps 10.244.0.0/16 in KCM, kube-proxy and flannel (default runs stay byte-identical)" \
  "--cluster-cidr=10.244.0.0/16 --node-cidr-mask-size=24|clusterCIDR: 10.244.0.0/16|\"Network\": \"10.244.0.0/16\"," \
  "$(probe "" 0 | paste -sd'|' -)"
check "custom pod CIDR reaches KCM, kube-proxy and flannel together" \
  "--cluster-cidr=10.200.0.0/16 --node-cidr-mask-size=24|clusterCIDR: 10.200.0.0/16|\"Network\": \"10.200.0.0/16\"," \
  "$(probe 10.200.0.0/16 0 | paste -sd'|' -)"
check "dual-stack keeps the v6 pod CIDR while the v4 one is overridden" \
  "--cluster-cidr=10.200.0.0/16,fd00:244::/56 --node-cidr-mask-size-ipv4=24 --node-cidr-mask-size-ipv6=64|clusterCIDR: 10.200.0.0/16,fd00:244::/56" \
  "$(probe 10.200.0.0/16 1 | sed -n '1,2p' | paste -sd'|' -)"

check "run-all.sh exports the parsed --pod-cidr as RIG_POD_CIDR_V4 (else the children never see it)" \
  "1" "$(grep -cF 'export RIG_POD_CIDR_V4="$POD_CIDR"' "$DIR/run-all.sh")"
check "run-all.sh --install rejects --pod-cidr (the real install.sh owns its CIDRs)" \
  "1" "$(grep -cF '"--pod-cidr=$POD_CIDR"' "$DIR/run-all.sh")"

echo ""
echo "rig pod-cidr logic: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
