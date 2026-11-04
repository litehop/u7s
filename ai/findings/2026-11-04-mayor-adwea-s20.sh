#!/usr/bin/env bash
# usage: s20.sh (root on the VM, after WordPress is up): the gate's warm-up pod, 20-pod burst,
# scale back to 1, 60 s settle, then snapshot to /var/tmp/m-s20 (the gate's "end of settle20" point)
V=/var/tmp; KC=/var/lib/u7s/kubeconfig
k() { kubectl --kubeconfig $KC "$@"; }
k create deployment rg-burst --image=registry.k8s.io/pause:3.10 --replicas=1 > $V/s20.out 2>&1
k wait --for=condition=Available deployment/rg-burst --timeout=300s >> $V/s20.out 2>&1
sleep 5
s=$(date +%s)
k scale deployment/rg-burst --replicas=20 >> $V/s20.out 2>&1
k wait --for=jsonpath='{.status.readyReplicas}'=20 deployment/rg-burst --timeout=300s >> $V/s20.out 2>&1
echo "burst20_secs=$(( $(date +%s) - s ))" >> $V/s20.out
k scale deployment/rg-burst --replicas=1 >> $V/s20.out 2>&1
for i in $(seq 1 60); do [ "$(k get pods -l app=rg-burst --no-headers 2>/dev/null | wc -l)" -le 1 ] && break; sleep 5; done
sleep 60
bash $V/2026-11-04-mayor-adwea-collect.sh $V/m-s20 > /dev/null 2>&1
date -u +%FT%TZ > $V/s20.done
