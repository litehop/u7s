#!/usr/bin/env bash
# Shipped-install smoke for Service-referenced webhooks and aggregated APIServices.
#
# On a host-process apiserver without konnectivity (the scripts/install.sh topology), the
# apiserver must reach <svc>.<ns>.svc backends via the Service's ClusterIP. This script
# deploys one agnhost webhook backend behind a Service and asserts:
#   1. a ValidatingWebhookConfiguration (failurePolicy Fail) denies a ConfigMap routed to
#      /always-deny and admits one routed to /configmaps;
#   2. an APIService backed by the same Service reaches Available=True and
#      `kubectl get --raw` is proxied to the backend.
#
# Requires: kubectl and openssl on PATH; a cluster that can pull the agnhost image.
set -euo pipefail

# Stop retrying only on the webhook's own denial; transient errors ("failed to respond",
# connection refused, timeouts) mean the backend is not programmed yet and must be retried.
smoke_should_stop() { [[ "$1" == *"denied the request"* ]]; }
[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

NS="default"
NAME="u7s-webhook-smoke"
AGNHOST_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.63.0"
API_GROUP="u7s-smoke.example.com"
KUBECTL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KUBECTL_ARGS=(--kubeconfig "$2"); shift 2 ;;
    -h|--help) echo "Usage: $(basename "$0") [--kubeconfig PATH]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

k() { kubectl "${KUBECTL_ARGS[@]}" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

TMP="$(mktemp -d)"
cleanup() {
  k delete apiservice "v1.$API_GROUP" --ignore-not-found >/dev/null 2>&1 || true
  k delete validatingwebhookconfiguration "$NAME" --ignore-not-found >/dev/null 2>&1 || true
  k -n "$NS" delete deployment,service,secret,configmap -l "app=$NAME" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

SVC_DNS="$NAME.$NS.svc"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$NAME-ca" \
  -keyout "$TMP/ca.key" -out "$TMP/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$SVC_DNS" -keyout "$TMP/tls.key" -out "$TMP/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$SVC_DNS" > "$TMP/ext.cnf"
openssl x509 -req -in "$TMP/tls.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" -CAcreateserial \
  -days 1 -extfile "$TMP/ext.cnf" -out "$TMP/tls.crt" 2>/dev/null
CA_B64="$(base64 < "$TMP/ca.crt" | tr -d '\n')"

k -n "$NS" create secret tls "$NAME" --cert="$TMP/tls.crt" --key="$TMP/tls.key"
k -n "$NS" label secret "$NAME" "app=$NAME"

k apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: $NAME, namespace: $NS, labels: {app: $NAME}}
spec:
  replicas: 1
  selector: {matchLabels: {app: $NAME}}
  template:
    metadata: {labels: {app: $NAME}}
    spec:
      containers:
      - name: webhook
        image: $AGNHOST_IMAGE
        args: [webhook, --tls-cert-file=/certs/tls.crt, --tls-private-key-file=/certs/tls.key, --port=8444]
        ports: [{containerPort: 8444}]
        readinessProbe: {httpGet: {path: /readyz, port: 8444, scheme: HTTPS}}
        volumeMounts: [{name: certs, mountPath: /certs, readOnly: true}]
      volumes: [{name: certs, secret: {secretName: $NAME}}]
---
apiVersion: v1
kind: Service
metadata: {name: $NAME, namespace: $NS, labels: {app: $NAME}}
spec:
  selector: {app: $NAME}
  ports: [{port: 443, targetPort: 8444}]
EOF
k -n "$NS" rollout status "deployment/$NAME" --timeout=240s

k apply -f - <<EOF
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata: {name: $NAME}
webhooks:
- name: deny.$API_GROUP
  clientConfig: {service: {namespace: $NS, name: $NAME, path: /always-deny}, caBundle: $CA_B64}
  rules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}]
  objectSelector: {matchLabels: {u7s-smoke: deny}}
  failurePolicy: Fail
  sideEffects: None
  admissionReviewVersions: [v1]
  timeoutSeconds: 10
- name: allow.$API_GROUP
  clientConfig: {service: {namespace: $NS, name: $NAME, path: /configmaps}, caBundle: $CA_B64}
  rules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [configmaps]}]
  objectSelector: {matchLabels: {u7s-smoke: allow}}
  failurePolicy: Fail
  sideEffects: None
  admissionReviewVersions: [v1]
  timeoutSeconds: 10
EOF

cm_yaml() {
  printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: %s-%s, namespace: %s, labels: {u7s-smoke: %s, app: %s}}\n' \
    "$NAME" "$1" "$NS" "$1" "$NAME"
}

# The apiserver picks up new webhook configs asynchronously, and kube-proxy may not
# have programmed the Service yet ("failed to respond"); retry until the deny lands.
denied=""
for _ in $(seq 1 15); do
  if out="$(cm_yaml deny | k create -f - 2>&1)"; then
    k -n "$NS" delete configmap "$NAME-deny" --ignore-not-found >/dev/null
    sleep 2
  else
    denied="$out"
    smoke_should_stop "$out" && break
    sleep 2
  fi
done
smoke_should_stop "$denied" || fail "deny webhook did not deny the ConfigMap; last output: ${denied:-<created>}"
echo "PASS: webhook denied -> $denied"

allow_out="$(cm_yaml allow | k create -f - 2>&1)" || fail "allow webhook rejected the ConfigMap: $allow_out"
echo "PASS: webhook admitted -> $allow_out"

k apply -f - <<EOF
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata: {name: v1.$API_GROUP}
spec:
  group: $API_GROUP
  version: v1
  groupPriorityMinimum: 1000
  versionPriority: 15
  service: {namespace: $NS, name: $NAME, port: 443}
  caBundle: $CA_B64
EOF
avail=""
for _ in $(seq 1 30); do
  avail="$(k get apiservice "v1.$API_GROUP" -o jsonpath='{.status.conditions[?(@.type=="Available")].status}')"
  [[ "$avail" == "True" ]] && break
  sleep 2
done
[[ "$avail" == "True" ]] || fail "APIService not Available: $(k get apiservice "v1.$API_GROUP" -o jsonpath='{.status.conditions}')"
raw="$(k get --raw "/apis/$API_GROUP/v1" 2>&1 || true)"
[[ "$raw" != *"error trying to reach service"* ]] || fail "APIService proxy could not reach the backend: $raw"
echo "PASS: APIService Available=True, proxied -> $raw"
