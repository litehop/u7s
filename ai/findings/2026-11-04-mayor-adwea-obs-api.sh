#!/bin/bash
# In-VM API streams, each prefixed with epoch: $1 = stream name.
S=https://127.0.0.1:6443
C=(-k --cert /var/lib/u7s/admin.pem --key /var/lib/u7s/admin.pem)
NODE=$(hostname)
case "$1" in
  lease) F='[now, .type, .object.metadata.name, .object.spec.renewTime]'; P="/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases?watch=1" ;;
  node) F='[now, .type, .object.metadata.name, (.object.status.conditions|map(select(.type=="Ready")|[.status,.reason,.lastHeartbeatTime,.lastTransitionTime])|.[0]), (.object.spec.taints//[]|map(.key))]'; P="/api/v1/nodes?watch=1" ;;
  events) F='[now, .type, .object.reason, .object.involvedObject.kind, .object.involvedObject.name, .object.count, (.object.message//""|.[0:160])]'; P="/api/v1/events?watch=1" ;;
  deploy) F='[now, .type, .object.metadata.name, .object.status.replicas, .object.status.readyReplicas, .object.spec.replicas]'; P="/apis/apps/v1/namespaces/default/deployments?watch=1" ;;
  podphase) F='[now, .type, .object.metadata.name, .object.status.phase, .object.spec.nodeName]'; P="/api/v1/namespaces/default/pods?labelSelector=app%3Drg-burst&watch=1" ;;
esac
case "$1" in
  probe)
    while :; do
      ts=$(date +%s.%N)
      r=$(curl -s -o /dev/null -m 10 -w '%{http_code} %{time_connect} %{time_total}' "${C[@]}" "$S/api/v1/namespaces/kube-system" 2>/dev/null)
      echo "$ts probe ${r:-fail}"
      sleep 1
    done ;;
  metrics)
    while :; do
      ts=$(date +%s.%N)
      curl -s -m 10 "${C[@]}" "$S/metrics" 2>/dev/null | grep -v -e '^#' -e '_bucket' -e certificate -e u7s_deletion | sed "s/^/$ts /"
      sleep 5
    done ;;
  *)
    while :; do
      echo "[$(date +%s.%N)] (re)connect $1"
      curl -sN "${C[@]}" "$S$P" 2>/dev/null | jq --unbuffered -c "$F"
      sleep 2
    done ;;
esac
