#!/usr/bin/env bash
# Regression test for the kubelet feature-gate config of the host rig.
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

source "$DIR/_lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The rig's kubelet config is install.sh's own write_kubelet_config_yaml output plus the
# recorded overlay (rig_kubelet_config_script); render it locally with /etc redirected.
mkdir -p "$WORK/bin" "$WORK/etc"
printf '#!/bin/sh\nexit 0\n' > "$WORK/bin/systemctl"
chmod +x "$WORK/bin/systemctl"
rig_kubelet_config_script 10.96.0.10 "$DIR/../install.sh" | sed -e "s#/etc/#$WORK/etc/#g" > "$WORK/render.sh"
PATH="$WORK/bin:$PATH" bash "$WORK/render.sh"
KUBELET_CONFIG_LINE="$(cat "$WORK/etc/u7s-rig/kubelet-config.yaml")"

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

assert_contains "lima-start.sh merges $RIG_KUBELET_GATE into the rendered config (Alpha, default-off: without it kubelet ignores projected defaultUser/user and files are owned by UID 0)" \
  "$(cat "$DIR/lima-start.sh")" '"$RIG_KUBELET_GATE" < "$(dirname "$0")/../set-kubelet-featuregate.sh"'
assert_contains "the rig's one gate overlay is AtomicWriteVolumeUserFields" "$RIG_KUBELET_GATE" 'AtomicWriteVolumeUserFields'

# lima-start.sh merges the gate into the rendered config via set-kubelet-featuregate.sh.
SET_GATE="$DIR/../set-kubelet-featuregate.sh"

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
