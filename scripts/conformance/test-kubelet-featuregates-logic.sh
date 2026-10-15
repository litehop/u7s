#!/usr/bin/env bash
# Regression test for the kubelet feature-gate config in lima/kubelet.yaml.
#
# ClusterTrustBundle and ClusterTrustBundleProjection are Beta-since-1.33,
# PodCertificateRequest is Beta-since-1.35, but all three are default-OFF in
# the real kubelet binary (`kubelet --help`
# lists all three as "BETA - default=false"). Without all three gates set,
# kubelet silently ignores the `clusterTrustBundle`/`podCertificate`
# projected-volume sources on a Pod spec instead of erroring — a pod using
# either source just hangs waiting for Ready with no file ever written, which
# is exactly the symptom an e2e run observed. If a future edit drops
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

assert_contains "KubeletConfiguration enables AtomicWriteVolumeUserFields (Alpha, default-off: without it kubelet ignores projected defaultUser/user and files are owned by UID 0)" \
  "$KUBELET_CONFIG_LINE" 'AtomicWriteVolumeUserFields: true'

# lima-start.sh patches the gate into VMs cloned from an older golden via set-kubelet-featuregate.sh.
SET_GATE="$DIR/../set-kubelet-featuregate.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'kind: KubeletConfiguration\nfeatureGates:\n  ClusterTrustBundle: true\n' >"$WORK/with-block.yaml"
bash "$SET_GATE" "$WORK/with-block.yaml" AtomicWriteVolumeUserFields
assert_contains "set-kubelet-featuregate.sh adds the gate under an existing featureGates block" \
  "$(cat "$WORK/with-block.yaml")" '  AtomicWriteVolumeUserFields: true'
assert_contains "set-kubelet-featuregate.sh keeps the gates already in the block" \
  "$(cat "$WORK/with-block.yaml")" '  ClusterTrustBundle: true'

printf 'kind: KubeletConfiguration\n' >"$WORK/no-block.yaml"
bash "$SET_GATE" "$WORK/no-block.yaml" AtomicWriteVolumeUserFields
assert_contains "set-kubelet-featuregate.sh creates a featureGates block when the config has none" \
  "$(cat "$WORK/no-block.yaml")" 'featureGates:'

printf 'featureGates:\n  AtomicWriteVolumeUserFields: false\n' >"$WORK/off.yaml"
bash "$SET_GATE" "$WORK/off.yaml" AtomicWriteVolumeUserFields
assert_contains "set-kubelet-featuregate.sh flips an explicit false to true" \
  "$(cat "$WORK/off.yaml")" '  AtomicWriteVolumeUserFields: true'

bash "$SET_GATE" "$WORK/with-block.yaml" AtomicWriteVolumeUserFields
assert_contains "set-kubelet-featuregate.sh is idempotent (one occurrence after a second run)" \
  "$(grep -c 'AtomicWriteVolumeUserFields' "$WORK/with-block.yaml")" '1'

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
