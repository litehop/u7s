#!/usr/bin/env bash
set -euo pipefail
# Fixture: namespace-drain
# Asserts: after a CRD is deleted, namespaces containing CRs drain within 30 seconds.
# Correct Kubernetes behaviour: namespace deletion should complete once all objects
# (including CRs whose CRD was deleted) are gone. The hang scenario is a u7s bug.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="integration-drain-test"
CRD_NAME="drainables.drain.example.com"

cleanup() {
  kubectl delete namespace "$NS" --ignore-not-found --timeout=10s 2>/dev/null || true
  kubectl delete crd "$CRD_NAME" --ignore-not-found --timeout=10s 2>/dev/null || true
}
trap cleanup EXIT

kubectl apply --validate=false -f "$DIR/drain-crd.yaml"
kubectl wait crd/"$CRD_NAME" --for=condition=Established --timeout=30s

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply --validate=false -f -

kubectl apply --validate=false -f "$DIR/drain-cr.yaml"

kubectl delete crd "$CRD_NAME" --timeout=15s

kubectl delete namespace "$NS" --wait=false

# Namespace must disappear within 30s (the known hang scenario is blocked finalizer removal).
if kubectl wait --for=delete namespace/"$NS" --timeout=30s 2>/dev/null; then
  echo "ASSERT OK: namespace drained within 30s after CRD deletion"
  exit 0
else
  echo "ASSERT FAIL: namespace $NS did not drain within 30s" >&2
  kubectl get namespace "$NS" -o json 2>&1 | grep -E '"phase"|"finalizers"' >&2 || true
  exit 1
fi
