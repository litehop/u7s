#!/bin/bash
# Runs on the VM as root: bash drive.sh > /tmp/e5idl.out
K="kubectl --kubeconfig /var/lib/u7s/kubeconfig"
D=rg-burst
wait_ready() { until [ "$($K get deploy $D -o jsonpath='{.status.readyReplicas}')" = "$1" ]; do sleep 1; done; }
$K scale deploy $D --replicas=0
sleep 300
bash /tmp/snap.sh "0pods-settled"
for n in 10 20; do
  $K scale deploy $D --replicas=$n
  sleep 3;  bash /tmp/snap.sh "->$n transition t+3s"
  wait_ready $n
  echo "ready$n at $(date -u +%T)"
  bash /tmp/snap.sh "${n}pods-just-ready"
  sleep 60
  bash /tmp/snap.sh "${n}pods-settled60s"
done
echo DONE
