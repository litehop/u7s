#!/usr/bin/env bash
set -euo pipefail
# Fixture: crd-410-gone
# Asserts: after a CRD is deleted, requests to its group return 410 Gone (not 404).
# Correct Kubernetes behaviour per API spec: the group/version resource endpoint returns
# 410 Gone when the CRD backing it has been deleted.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRD_NAME="crontabs.stable.example.com"

cleanup() {
  kubectl delete crd "$CRD_NAME" --ignore-not-found --timeout=15s 2>/dev/null || true
}
trap cleanup EXIT

kubectl apply --validate=false -f "$DIR/crontabs-crd.yaml"

kubectl wait crd/"$CRD_NAME" --for=condition=Established --timeout=30s

kubectl delete crd "$CRD_NAME" --timeout=15s

# After deletion the group endpoint must return 410 Gone, not 404.
# Use --raw to bypass discovery cache and hit the API path directly.
# --v=6 prints the HTTP response line: status="410 Gone"
output="$(kubectl get --raw /apis/stable.example.com/v1/crontabs --v=6 2>&1 || true)"

if echo "$output" | grep -q 'status="410 Gone"'; then
  echo "ASSERT OK: group endpoint returned 410 Gone after CRD deletion"
  exit 0
else
  echo "ASSERT FAIL: expected 410 Gone but got:" >&2
  echo "$output" | grep -E 'status="|error|Error' >&2
  exit 1
fi
