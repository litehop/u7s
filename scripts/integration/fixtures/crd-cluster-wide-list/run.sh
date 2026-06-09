#!/usr/bin/env bash
set -euo pipefail
# Fixture: crd-cluster-wide-list
# Asserts: cluster-wide list on a Namespaced CRD returns 200 OK (not 404).
# Correct Kubernetes behaviour: kubectl get <resource> without -n flag issues a
# cluster-wide list (/apis/<group>/<version>/<plural>) which must return 200.
# Bug context: PR #485 fixed this in u7s.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRD_NAME="widgets.apps.example.com"

cleanup() {
  kubectl delete crd "$CRD_NAME" --ignore-not-found --timeout=15s 2>/dev/null || true
}
trap cleanup EXIT

kubectl apply --validate=false -f "$DIR/widgets-crd.yaml"

kubectl wait crd/"$CRD_NAME" --for=condition=Established --timeout=30s

# Cluster-wide list must return 200 OK even for Namespaced CRDs.
# --all-namespaces forces the cluster-wide path: /apis/<group>/<version>/<plural>
output="$(kubectl get widgets.apps.example.com --all-namespaces --v=6 2>&1 || true)"

if echo "$output" | grep -q 'Response Status: 200 OK'; then
  echo "ASSERT OK: cluster-wide list returned 200 OK"
  exit 0
else
  echo "ASSERT FAIL: expected 200 OK for cluster-wide list but got:" >&2
  echo "$output" | grep -E 'Response Status:|error|Error' >&2
  exit 1
fi
