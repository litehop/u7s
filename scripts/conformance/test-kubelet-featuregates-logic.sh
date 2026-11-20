#!/usr/bin/env bash
# Regression test for the kubelet feature-gate config in lima/kubelet.yaml.
#
# ClusterTrustBundle, ClusterTrustBundleProjection and PodCertificateRequest are
# GA and default-ON in kubelet 1.37 (install.sh appends them only for kubelet
# >= 1.37). The rig must leave them unset so it runs the same defaults a real
# install does; an explicit setting would mask a default flip. AtomicWriteVolumeUserFields
# is still default-off and must stay set, or projected-volume file ownership
# silently stays UID 0.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/drain-grep.sh"

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_YAML="$DIR/../../lima/kubelet.yaml"

PASS=0
FAIL=0

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if printf '%s' "$haystack" | drain_grep -qF -- "$needle"; then
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

assert_lacks() {
  local label="$1" haystack="$2" needle="$3"
  if printf '%s' "$haystack" | drain_grep -qF -- "$needle"; then
    echo "FAIL: $label — found '${needle}'"
    FAIL=$(( FAIL + 1 ))
  else
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  fi
}

for gate in ClusterTrustBundle ClusterTrustBundleProjection PodCertificateRequest; do
  assert_lacks "KubeletConfiguration leaves GA-default-on gate $gate unset (rig must match install's kubelet defaults)" \
    "$KUBELET_CONFIG_LINE" "$gate:"
done

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
