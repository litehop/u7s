#!/usr/bin/env bash
# Lima e2e for `u7s migrate cutover` / `rollback` on a single k3s host.
#
#   1. seeds k3s with a stateful workload (local-path PVC holding a marker),
#   2. runs a cutover that fails after k3s is stopped (install.sh is given a
#      tarball that does not exist), then rolls back: k3s must serve the
#      workload again with the marker intact,
#   3. runs a real cutover: u7s must serve the workload with the marker
#      intact and the k3s data directory untouched,
#   4. with --rollback-after-success, rolls that cutover back as well.
#
# The clusters are driven from inside the VM (both listen on 6443 there).
# Usage: cutover-lima.sh --vm <name> --u7s-bin <path> --tarball <path>
#          [--rollback-after-success] [--out <dir>]
# --u7s-bin and --tarball are a linux build matching the VM's architecture
# (scripts/release-gate/build-arm64-tarball.sh for aarch64).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VM=""
U7S_BIN=""
TARBALL=""
ROLLBACK_AFTER=0
OUT="$REPO/temp/e2e/te4sn4-$(date +%Y%m%d-%H%M%S)"

usage() {
  echo "usage: $0 --vm <name> --u7s-bin <path> --tarball <path> [--rollback-after-success] [--out <dir>]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vm) VM="${2:?}"; shift 2 ;;
    --u7s-bin) U7S_BIN="${2:?}"; shift 2 ;;
    --tarball) TARBALL="${2:?}"; shift 2 ;;
    --rollback-after-success) ROLLBACK_AFTER=1; shift ;;
    --out) OUT="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$VM" ] && [ -n "$U7S_BIN" ] && [ -n "$TARBALL" ] || usage
[ -f "$U7S_BIN" ] || { echo "error: $U7S_BIN not found" >&2; exit 2; }
[ -f "$TARBALL" ] || { echo "error: $TARBALL not found" >&2; exit 2; }

mkdir -p "$OUT"
LOG="$OUT/run.log"
exec > >(tee "$LOG") 2>&1

K3S_KC=/etc/rancher/k3s/k3s.yaml
U7S_KC=/var/lib/u7s/kubeconfig
GUEST=/var/tmp/te4sn4
MARKER="te4sn4-$(date +%s)"

vm() { limactl shell "$VM" -- "$@"; }
k3s() { vm sudo kubectl --kubeconfig "$K3S_KC" "$@"; }
u7s() { vm sudo kubectl --kubeconfig "$U7S_KC" "$@"; }
step() { echo; echo "=== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# wait_for <seconds> <description> <command...>
wait_for() {
  local secs="$1" what="$2" i
  shift 2
  for ((i = 0; i < secs; i += 3)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 3
  done
  fail "timed out after ${secs}s: $what"
}

# The workload prints what it read back from the persisted volume.
logs_have() {
  local out
  out="$("$1" -n app logs deploy/writer --tail=20)" || return 1
  [[ "$out" == *"read:$MARKER"* ]]
}

ready_on() {
  local out
  out="$("$1" -n app get deploy writer -o jsonpath='{.status.readyReplicas}')" || return 1
  [ "$out" = "1" ]
}

step "stage artifacts in $VM"
# install.sh apt-installs CRI-O and fails when unattended-upgrades holds the dpkg lock.
vm sudo systemctl stop unattended-upgrades.service
vm sudo mkdir -p "$GUEST"
vm sudo rm -rf "$GUEST/work" "$GUEST/gate"
vm sudo chmod 777 "$GUEST"
limactl cp "$U7S_BIN" "$VM:$GUEST/u7s"
limactl cp "$TARBALL" "$VM:$GUEST/u7s.tar.gz"
limactl cp "$REPO/scripts/install.sh" "$VM:$GUEST/install.sh"
vm sudo chmod +x "$GUEST/u7s" "$GUEST/install.sh"

step "clear u7s left by an earlier run (cutover refuses a host that has u7s installed)"
for u in kubelet.service u7s-kcm-restart.path u7s-kcm.service u7s-apiserver.service; do
  vm sudo systemctl disable --now "$u" 2>/dev/null || true
done
vm sudo rm -rf /var/lib/u7s

step "k3s is the live cluster"
wait_for 120 "k3s API" k3s get nodes
k3s get nodes -o wide

step "seed stateful workload with marker $MARKER"
k3s delete namespace app --ignore-not-found --wait
k3s apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata: {name: app}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: data, namespace: app}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources: {requests: {storage: 100Mi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: writer, namespace: app}
spec:
  replicas: 1
  selector: {matchLabels: {app: writer}}
  template:
    metadata: {labels: {app: writer}}
    spec:
      containers:
      - name: w
        image: docker.io/library/busybox:1.36
        command: [sh, -c]
        args:
        - |
          [ -f /data/marker ] || echo "$MARKER" > /data/marker
          echo "read:\$(cat /data/marker)"
          sleep 86400
        volumeMounts: [{name: d, mountPath: /data}]
      volumes: [{name: d, persistentVolumeClaim: {claimName: data}}]
EOF
wait_for 240 "writer ready on k3s" ready_on k3s
logs_have k3s || fail "marker not readable on k3s"
PV="$(k3s get pvc -n app data -o jsonpath='{.spec.volumeName}')"
PVDIR="$(k3s get pv "$PV" -o jsonpath='{.spec.local.path}')"
policy_on() { "$1" get pv "$PV" -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'; }
echo "PV=$PV dir=$PVDIR policy=$(policy_on k3s)"
[ "$(vm sudo cat "$PVDIR/marker")" = "$MARKER" ] || fail "marker file missing on host volume"
k3s get all,pvc -n app

cutover() {
  vm sudo "$GUEST/u7s" migrate cutover --work-dir "$GUEST/work" --confirm-retain \
    --install-script "$GUEST/install.sh" -- --tarball "$1"
}

step "confirmation gate: cutover without --confirm-retain must change nothing"
if vm sudo "$GUEST/u7s" migrate cutover --work-dir "$GUEST/gate" \
  --install-script "$GUEST/install.sh" -- --tarball "$GUEST/u7s.tar.gz"; then
  fail "cutover ran without --confirm-retain"
fi
[ "$(policy_on k3s)" = Delete ] || fail "PV policy changed without confirmation"
vm sudo rm -rf "$GUEST/gate"
echo "PASS gate: source PV still $(policy_on k3s)"

step "1/3 forced failure: install fails after k3s was stopped, then rollback"
if cutover "$GUEST/does-not-exist.tar.gz"; then
  fail "cutover with a missing tarball unexpectedly succeeded"
fi
echo "k3s active after the failed cutover: $(vm systemctl is-active k3s || true)"
vm sudo test -d /var/lib/rancher/k3s/storage || fail "k3s data dir lost"
if vm pgrep -f containerd-shim >/dev/null; then fail "k3s containerd-shims survived cutover's k3s-killall"; fi
for nic in cni0 flannel.1; do
  if vm ip link show "$nic" >/dev/null 2>&1; then fail "$nic survived cutover's k3s-killall"; fi
done
echo "PASS killall: no containerd-shim processes, cni0 and flannel.1 gone, k3s data dir present"
vm sudo "$GUEST/u7s" migrate rollback --work-dir "$GUEST/work"
wait_for 180 "writer ready on k3s after rollback" ready_on k3s
logs_have k3s || fail "marker not readable after rollback"
[ "$(vm sudo cat "$PVDIR/marker")" = "$MARKER" ] || fail "marker file lost by rollback"
POL="$(policy_on k3s)"
[ "$POL" = Delete ] || fail "rollback left policy $POL, wanted Delete"
ANN="$(k3s get pv "$PV" -o jsonpath='{.metadata.annotations.migrate\.u7s\.dev/original-reclaim-policy}')"
[ -z "$ANN" ] || fail "annotation left behind: $ANN"
echo "PASS rollback: k3s serves the workload, marker intact, policy $POL"
k3s get all,pvc -n app
vm sudo rm -rf "$GUEST/work"

step "2/3 full cutover k3s -> u7s"
cutover "$GUEST/u7s.tar.gz"
if vm sudo systemctl is-active --quiet k3s; then fail "k3s still active after cutover"; fi
vm sudo test -d /var/lib/rancher/k3s/storage || fail "k3s data dir lost by cutover"
wait_for 240 "writer ready on u7s" ready_on u7s
logs_have u7s || fail "marker not readable on u7s"
[ "$(vm sudo cat "$PVDIR/marker")" = "$MARKER" ] || fail "marker file changed"
echo "PASS cutover: u7s serves the workload with the marker from the migrated volume"
u7s get nodes -o wide
u7s get deploy,pod,pvc -n app
echo "u7s PV $PV policy=$(policy_on u7s)"

if [ "$ROLLBACK_AFTER" = 1 ]; then
  step "3/3 rollback after a successful cutover"
  vm sudo "$GUEST/u7s" migrate rollback --work-dir "$GUEST/work"
  wait_for 180 "writer ready on k3s after rollback" ready_on k3s
  logs_have k3s || fail "marker not readable after late rollback"
  [ "$(vm sudo cat "$PVDIR/marker")" = "$MARKER" ] || fail "marker file lost by late rollback"
  echo "PASS late rollback: k3s serving, u7s-apiserver $(vm systemctl is-active u7s-apiserver || true)"
  k3s get all,pvc -n app
fi

echo; echo "ALL PASS (logs: $LOG)"
