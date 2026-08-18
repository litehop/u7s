#!/usr/bin/env bash
# Regression test for the kubelet feature-gate config in lima/kubelet.yaml
# (mayor-17kra).
#
# ClusterTrustBundle, ClusterTrustBundleProjection and PodCertificateRequest are
# Beta-since-1.36.2 but default-OFF in the real kubelet binary (`kubelet --help`
# lists all three as "BETA - default=false"). Without all three gates set,
# kubelet silently ignores the `clusterTrustBundle`/`podCertificate`
# projected-volume sources on a Pod spec instead of erroring — a pod using
# either source just hangs waiting for Ready with no file ever written, which
# is exactly the symptom mayor-moejy's e2e run observed. If a future edit drops
# any gate from the generated KubeletConfiguration, this test must fail —
# kubectl-level verification alone would not catch a regression until the next
# full conformance run.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_YAML="$DIR/../../lima/kubelet.yaml"

PASS=0
FAIL=0

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label — expected to find '${needle}'"
    FAIL=$(( FAIL + 1 ))
  fi
}

# Extract the single printf line that writes /etc/kubelet-config.yaml — the only
# place in the repo that generates the real kubelet's KubeletConfiguration
# (scripts/conformance/lima-start.sh only overrides the ExecStart drop-in, never
# this file's content — see lima-start.sh's own u7s.conf generation).
KUBELET_CONFIG_LINE="$(grep -F 'kubelet-config.yaml' "$LIMA_YAML" | grep -F 'printf')"

if [ -z "$KUBELET_CONFIG_LINE" ]; then
  echo "FAIL: could not locate the /etc/kubelet-config.yaml printf line in $LIMA_YAML" >&2
  exit 1
fi

assert_contains "KubeletConfiguration enables ClusterTrustBundle (kubelet's client-go lister/informer for the resource type)" \
  "$KUBELET_CONFIG_LINE" 'ClusterTrustBundle: true'

assert_contains "KubeletConfiguration enables ClusterTrustBundleProjection (kubelet honors clusterTrustBundle projected sources)" \
  "$KUBELET_CONFIG_LINE" 'ClusterTrustBundleProjection: true'

assert_contains "KubeletConfiguration enables PodCertificateRequest (kubelet honors podCertificate projected sources)" \
  "$KUBELET_CONFIG_LINE" 'PodCertificateRequest: true'

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
