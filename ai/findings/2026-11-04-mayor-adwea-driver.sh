#!/usr/bin/env bash
# usage: driver.sh TAG (root on the VM): install, 10 min idle settle, snapshot, WordPress+MariaDB, 5 min settle, snapshot
TAG="$1"; V=/var/tmp
bash $V/2026-11-04-mayor-adwea-install.sh "$TAG" > $V/inst.out 2>&1
if ! grep -q '^rc=0' $V/adwea/$TAG/install.log; then
  echo "first install attempt failed; re-running" >> $V/inst.out
  bash $V/2026-11-04-mayor-adwea-install.sh "$TAG" > $V/inst2.out 2>&1
fi
KC=/var/lib/u7s/kubeconfig
until kubectl --kubeconfig $KC get node 2>/dev/null | grep -q ' Ready'; do sleep 5; done
date -u +%FT%TZ > $V/settle.start
sleep 600
bash $V/2026-11-04-mayor-adwea-collect.sh $V/m-idle > /dev/null 2>&1
kubectl --kubeconfig $KC apply -f $V/mariadb-emptydir.yaml -f $V/wordpress.yaml > $V/wp-apply.out 2>&1
date -u +%FT%TZ > $V/wp.start
kubectl --kubeconfig $KC wait --for=condition=Ready pod/mariadb-0 --timeout=300s > $V/wp-wait.out 2>&1
kubectl --kubeconfig $KC wait --for=condition=Available deployment/pehelypress --timeout=300s >> $V/wp-wait.out 2>&1
IP=$(kubectl --kubeconfig $KC get svc pehelypress -o jsonpath='{.spec.clusterIP}')
for i in $(seq 1 30); do curl -s -o /dev/null -m 10 -w '%{http_code} ' http://$IP/; done > $V/wp-curl.out
sleep 300
bash $V/2026-11-04-mayor-adwea-collect.sh $V/m-wp > /dev/null 2>&1
date -u +%FT%TZ > $V/done
bash /var/tmp/2026-11-04-mayor-adwea-s20.sh
