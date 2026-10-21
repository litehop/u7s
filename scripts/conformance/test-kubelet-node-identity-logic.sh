#!/usr/bin/env bash
# Regression test: the conformance rig's kubelet must authenticate as its own
# system:node:<VM> identity, never the admin kubeconfig. A kubelet running as
# system:masters bypasses the Node authorizer and NodeRestriction, so the rig
# would not exercise the authorization a real node is bound by, and a
# compromised kubelet would be cluster-admin.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_START="$DIR/lima-start.sh"
SET_ROTATE="$DIR/../set-kubelet-rotate-certificates.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

assert "lima-start.sh must not install the admin kubeconfig as the kubelet's kubeconfig (it would make the kubelet system:masters)" \
  "$(grep -q 'REWRITTEN' "$LIMA_START" && echo 0 || echo 1)"
assert "lima-start.sh issues the kubelet client cert with CN=system:node:<VM> in O=system:nodes" \
  "$(grep -qF -- '-subj "/O=system:nodes/CN=system:node:${VM_NAME}"' "$LIMA_START" && echo 1 || echo 0)"
assert "the kubelet's kubeconfig user is its client cert files, so kubelet's cert rotation can replace them" \
  "$(grep -qF 'client-certificate: /etc/kubelet-client.crt' "$LIMA_START" && echo 1 || echo 0)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'kind: KubeletConfiguration\nfailSwapOn: false\n' > "$WORK/missing.yaml"
bash "$SET_ROTATE" "$WORK/missing.yaml"
assert "rotateCertificates is added when the baked kubelet config lacks it (without it the node cert expires and the node drops off the cluster)" \
  "$(grep -qx 'rotateCertificates: true' "$WORK/missing.yaml" && echo 1 || echo 0)"

printf 'kind: KubeletConfiguration\nrotateCertificates: false\n' > "$WORK/off.yaml"
bash "$SET_ROTATE" "$WORK/off.yaml"
assert "rotateCertificates: false is flipped to true" \
  "$(grep -qx 'rotateCertificates: true' "$WORK/off.yaml" && ! grep -q 'false' "$WORK/off.yaml" && echo 1 || echo 0)"

bash "$SET_ROTATE" "$WORK/off.yaml"
assert "re-running is idempotent (lima-start.sh runs on every invocation)" \
  "$([ "$(grep -c '^rotateCertificates:' "$WORK/off.yaml")" -eq 1 ] && echo 1 || echo 0)"

echo ""
echo "Results:${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
