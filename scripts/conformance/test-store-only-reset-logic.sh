#!/usr/bin/env bash
# Regression test: reset.sh --store-only makes the next bring-up a first boot without
# reprovisioning the VM, and run-all.sh does that by default.
#
# A gate on a warm VM that reuses the persisted apiserver DB never runs boot-time code
# against an empty store (manifest apply, allocator seeding, migrations), so a bug that
# breaks every fresh install passes the gate. --store-only must therefore (a) delete the
# whole store, (b) keep CA/kubeconfig/keys and the VM (a delete costs 15-20 min and
# invalidates the kubelet's certs), and (c) clear guest state that would mask first boot:
# pod sandboxes and /var/lib/kubelet.
#
# limactl, pkill and pgrep are stubbed on PATH; rm is real but confined to a sandbox repo.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$REPO/scripts/conformance/reset.sh"
RUN_ALL="$REPO/scripts/conformance/run-all.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

TMPROOT="$(cd "$(mktemp -d)" && pwd -P)"
trap 'rm -rf "$TMPROOT"' EXIT

STUBS="$TMPROOT/stubs"
CALLS="$TMPROOT/calls.log"
mkdir -p "$STUBS"
printf '#!/bin/sh\nexit 1\n' >"$STUBS/pgrep"
printf '#!/bin/sh\nexit 0\n' >"$STUBS/pkill"
cat >"$STUBS/limactl" <<EOF
#!/bin/bash
echo "limactl \$*" >>"$CALLS"
case "\$1" in
  list)
    case "\$*" in
      *Status*) echo "lima-node \${FAKE_VM_STATUS:-Running}" ;;
      *) echo "lima-node" ;;
    esac ;;
  shell) shift 2; echo "GUEST: \$*" >>"$CALLS" ;;
esac
exit 0
EOF
chmod +x "$STUBS"/*

SB="$TMPROOT/repo"
mkdir -p "$SB/temp/u7s"
git -C "$SB" init -q
git -C "$SB" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
WD="$SB/temp/u7s"
seed() { : >"$CALLS"; mkdir -p "$WD/manifests"; touch "$WD/state.db" "$WD/state.db-wal" "$WD/state.db-shm" "$WD/ca.crt" "$WD/sa.key" "$WD/kubeconfig" "$WD/manifests/coredns.yaml"; }

seed
(cd "$SB" && PATH="$STUBS:$PATH" bash "$SCRIPT" --store-only --vm lima-node --workdir "$WD" >"$TMPROOT/out" 2>&1) \
  || { bad "--store-only exited non-zero: $(cat "$TMPROOT/out")"; }

if ls "$WD"/state.db* >/dev/null 2>&1; then
  bad "--store-only left apiserver store files behind; the next boot would reuse them: $(ls "$WD")"
else
  ok "--store-only deletes state.db and its -wal/-shm"
fi
if ls "$WD"/manifests/*.yaml >/dev/null 2>&1; then
  bad "--store-only kept staged manifests; a run with different --service-cidr boot-applies a Service IP outside the new range and the apiserver exits"
else
  ok "--store-only removes staged manifests so a CIDR change cannot boot-apply stale ones"
fi
if [ -e "$WD/ca.crt" ] && [ -e "$WD/sa.key" ] && [ -e "$WD/kubeconfig" ]; then
  ok "--store-only keeps CA, SA key and kubeconfig (the VM's kubelet certs chain to them)"
else
  bad "--store-only removed CA/key/kubeconfig material"
fi
if grep -q '^limactl delete' "$CALLS"; then
  bad "--store-only deleted the VM; that is the 15-20 min reprovision it exists to avoid"
else
  ok "--store-only never deletes the VM"
fi
guest="$(cat "$CALLS")"
if [[ "$guest" == *"crictl rmp -fa"* ]]; then
  ok "--store-only removes pod sandboxes in the guest"
else
  bad "--store-only left pod sandboxes in the guest; old pods would outlive the empty store"
fi
if [[ "$guest" == *"rm -rf /var/lib/cni/networks /run/flannel/subnet.env"* && "$guest" == *"ip link delete flannel.1"* && "$guest" == *"ip link delete cni0"* ]]; then
  ok "--store-only clears CNI IPAM, flannel subnet.env and the cni0/flannel.1 links so a new --pod-cidr cannot hand pods addresses from the old range"
else
  bad "--store-only left CNI state in the guest; after a pod-CIDR change new pods get IPs from the previous range"
fi
if [[ "$guest" == *"find /var/lib/kubelet -mindepth 1 -maxdepth 1 -exec rm -rf"* && "$guest" != *"-name pki"* ]]; then
  ok "--store-only wipes all of /var/lib/kubelet, pki/ included, so no stale cert survives a reset (the kubelet's own certs live in /etc/u7s-rig)"
else
  bad "--store-only does not wipe /var/lib/kubelet entirely: $guest"
fi

seed
(cd "$SB" && FAKE_VM_STATUS=Stopped PATH="$STUBS:$PATH" bash "$SCRIPT" --store-only --vm lima-node --workdir "$WD" >/dev/null 2>&1) || true
if grep -q '^limactl start lima-node' "$CALLS" && grep -q '^GUEST:' "$CALLS"; then
  ok "--store-only starts a stopped VM so its guest state is wiped too"
else
  bad "--store-only skipped the guest wipe on a stopped VM; stale pods would survive"
fi

if grep -q 'reset.sh" --store-only' "$RUN_ALL" && grep -q '^elif \[ "\$KEEP_STORE" -eq 0 \]' "$RUN_ALL"; then
  ok "run-all.sh wipes the store by default and only --keep-store skips it"
else
  bad "run-all.sh no longer defaults to a fresh store; gates would again reuse a persisted DB"
fi

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
