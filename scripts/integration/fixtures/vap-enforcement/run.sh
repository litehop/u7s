#!/usr/bin/env bash
set -euo pipefail
# Fixture: vap-enforcement
# Asserts: a VAP binding scoped to a namespace correctly denies violating resources
# and allows compliant ones. This validates CEL expression evaluation in u7s.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="integration-vap-test"

cleanup() {
  kubectl delete namespace "$NS" --ignore-not-found --timeout=30s 2>/dev/null || true
  kubectl delete validatingadmissionpolicybinding require-min-replicas-binding --ignore-not-found 2>/dev/null || true
  kubectl delete validatingadmissionpolicy require-min-replicas --ignore-not-found 2>/dev/null || true
}
trap cleanup EXIT

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply --validate=false -f -
kubectl label namespace "$NS" integration-test=true --overwrite

kubectl apply --validate=false -f "$DIR/vap.yaml"
kubectl apply --validate=false -f "$DIR/vap-binding.yaml"

# Violating deployment (replicas=1) must be denied.
if kubectl apply --validate=false -f "$DIR/deploy-violating.yaml" 2>&1; then
  echo "ASSERT FAIL: violating deployment (replicas=1) was accepted but should have been denied" >&2
  exit 1
else
  echo "ASSERT OK: violating deployment (replicas=1) was denied by VAP"
fi

# Compliant deployment (replicas=3) must be accepted.
if kubectl apply --validate=false -f "$DIR/deploy-compliant.yaml" 2>&1; then
  echo "ASSERT OK: compliant deployment (replicas=3) was accepted"
else
  echo "ASSERT FAIL: compliant deployment (replicas=3) was rejected but should have been accepted" >&2
  exit 1
fi

exit 0
