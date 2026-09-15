# Flannel multi-node Lima rig scoping spike (2026-09-15)

Bead: mayor-4q2fj

**GO.** Flannel VXLAN + node-ipam + iptables kube-proxy works cross-node on
the aarch64 Lima pool, empirically verified: two pods on different nodes
completed a full TCP handshake (SYN/SYN-ACK/ACK/data/FIN) over the flannel
VXLAN overlay (udp/8472, VNI 1), captured live with tcpdump. Building the
full rig is plumbing, not new-territory risk — recommend committing to it.

## Method

Warm `--stack-only` 2-node bring-up (`lima-node-2` primary, `lima-node-3`
via `--extra-node`) on the baseline cri-o-bridge rig, then live-edited
(uncommitted, this worktree only) `scripts/conformance/04-start-kcm.sh`'s
KCM `--controllers` flag and manually disabled the crio-bridge conflist +
applied `manifests/flannel.yaml` (substituting `__IFACE__`→`eth0`,
`__POD_CLUSTER_CIDR__`→`10.244.0.0/16`, matching `install.sh`'s own
substitution). All raw output is under
`ai/findings/2026-09-15-mayor-4q2fj/`.

## Q1 — node-ipam-controller / node-route-controller re-enable

**Works cleanly; node-route-controller is a harmless no-op for flannel.**
Restarting KCM with `--controllers` no longer excluding
`node-ipam-controller`/`node-route-controller` and adding
`--cluster-cidr=10.244.0.0/16 --allocate-node-cidrs=true
--node-cidr-mask-size=24` populated `node.spec.podCIDR` on **both** nodes
within ~1s of KCM startup — no rig-specific breakage:

```
lima-node-2  podCIDR=10.244.0.0/24  podCIDRs=["10.244.0.0/24"]
lima-node-3  podCIDR=10.244.1.0/24  podCIDRs=["10.244.1.0/24"]
```
(`ai/findings/2026-09-15-mayor-4q2fj/01-node-podcidr.txt`,
`01-kcm-log-after-ipam-enable.txt` — `range_allocator.go:433 "Set node
PodCIDR"` for both nodes.)

`node-route-controller` itself never actually starts — kcm.log logs
`"Skipping a cloud provider controller" controller="node-route-controller"`
because it requires `--cloud-provider`, which this rig (correctly) never
sets. This is expected and harmless: node-route-controller programs cloud
VPC route tables (GCE/AWS), which flannel's own VXLAN encapsulation makes
unnecessary — flannel does not depend on it. The KCM flag change needed is
just re-enabling `node-ipam-controller` + the three cluster-cidr flags;
leaving `node-route-controller` un-excluded is a no-op, not a requirement.

## Q2 — flannel VXLAN cross-node on aarch64 Lima

**Yes, and it is the real gate finding of this spike: a rig retrofit onto
an already-crio-bridge-provisioned VM hits one blocker, cleanly fixed.**

flannel's DaemonSet came up `2/2 Running` immediately after applying the
manifest (`03-flannel-pods-t20s.txt`), created a `flannel.1` VXLAN device
(`vni 1`, `dstport 8472`, `mtu 1450`) on both nodes
(`05-flannel1-link-node2.txt`), and both nodes ended up with matching
peer routes (`10.244.1.0/24 via 10.244.1.0 dev flannel.1 onlink` on
node-2, `10.244.0.0/24 via 10.244.0.0 dev flannel.1 onlink` on node-3 —
`06-ip-route-node2.txt`, `06b-ip-route-node3.txt`).

**Blocker hit and fixed:** new pod sandboxes then failed with `plugin
type="flannel" failed (add): failed to set bridge addr: "cni0" already
has an IP address different from 10.244.0.1/24`
(`ai/findings/2026-09-15-mayor-4q2fj` kubelet journal excerpt, captured
inline in this doc's investigation — see command history). Cause: flannel's
own `cni-conf.json` delegates to the same `cni0` bridge device name the
prior cri-o-bridge CNI already created and addressed in the old
`10.85.x.0/24` range; flannel's bridge delegate cannot re-address a bridge
that already has a foreign IP. Fix: `ip link delete cni0` +
`rm -rf /var/lib/cni/networks/crio/*` + `systemctl restart crio` on both
nodes, then retry. After that, both test pods came up **Running** with
correct flannel-range IPs on the first try:

```
flannel-test-a   1/1   Running   10.244.0.16   lima-node-2
flannel-test-b   1/1   Running   10.244.1.8    lima-node-3
```
(`08-test-pods-retry.txt`)

This blocker is a **warm-VM retrofit artifact, not a flannel defect**: a
genuinely fresh VM never hits it, because `install.sh:692-696` disables the
crio-bridge conflist *before* crio's first start, so `cni0` never gets
created with a foreign address in the first place. The rig's `--reset`
(fresh-provision) path just needs the same ordering; only a warm
`--stack-only` reconnect onto a VM that already ran cri-o-bridge needs the
`cni0` teardown step.

**Cross-node reachability — empirical proof (the mandatory evidence):**

TCP connect from pod `flannel-test-a` (10.244.0.16, lima-node-2) to pod
`flannel-test-b` (10.244.1.8:8080, lima-node-3):
```
$ kubectl exec flannel-test-a -- nc -w 3 10.244.1.8 8080 -z -v
10.244.1.8 (10.244.1.8:8080) open
```
(`10-cross-node-nc-connect.txt`)

tcpdump on lima-node-2's `eth0` (VXLAN transport, udp/8472) captured the
full inner TCP handshake + data + teardown, encapsulated:
```
IP 192.168.108.4.43478 > 192.168.108.5.8472: VXLAN, flags [I], vni 1
  IP 10.244.0.16.43795 > 10.244.1.8.8080: Flags [S], ...
IP 192.168.108.5.39014 > 192.168.108.4.8472: VXLAN, flags [I], vni 1
  IP 10.244.1.8.8080 > 10.244.0.16.43795: Flags [S.], ...
IP 192.168.108.4.43478 > 192.168.108.5.8472: VXLAN, flags [I], vni 1
  IP 10.244.0.16.43795 > 10.244.1.8.8080: Flags [.], ack 1, ...
...
IP 192.168.108.5.39014 > 192.168.108.4.8472: VXLAN, flags [I], vni 1
  IP 10.244.1.8.8080 > 10.244.0.16.43795: Flags [P.], ..., length 13: HTTP
```
(full capture: `09-tcpdump-vxlan-node2.txt`, raw pcap:
`09-vxlan-node2.pcap`) — proves the outer VXLAN encapsulation (192.168.108.4
↔ 192.168.108.5, udp/8472, VNI 1) is the actual transport carrying the inner
pod-to-pod TCP session. This is the gate criterion this spike was scoped to
answer, and it passes.

No kernel VXLAN support gap, no MTU issue, no problem observed on aarch64
Lima (vz driver).

## Q3 — interaction with iptables kube-proxy mode and mayor-0c5no

**Both compose cleanly; mayor-0c5no's race class does not reproduce with
flannel.**

kube-proxy's `mode: iptables` (confirmed live:
`/etc/kube-proxy/config.conf` → `mode: iptables`) and flannel's own
iptables masquerade rules coexist in the same `nat` table without
collision — `iptables -t nat -L` shows flannel's `flanneld masq` rules
(scoped to `10.244.0.0/16`) and kube-proxy's `KUBE-SEP-*`/DNAT rules
(scoped to Service VIPs/backend pod IPs) as disjoint rule sets, both
active simultaneously (evidence inline in command history above this
doc's write-up; not separately filed since it's a single `iptables -L`
read, not a capture).

mayor-0c5no's race (systemd-networkd's late restart on the joining node
wiping the hand-rolled `ip route replace <peer-subnet> via <peer-ip>`
static route on `eth0`) is specific to the crio-bridge rig's
route-programming mechanism — that route is programmed by
`lima-start.sh` directly against `eth0`, an interface systemd-networkd
manages via DHCP. Flannel's cross-node routes, by contrast, are
programmed on the `flannel.1` VXLAN device by flanneld itself (a
long-running daemon that watches Node objects and holds its own kernel
route table entries), entirely independent of `eth0`'s
networkd-management lifecycle. **A flannel rig does not need the
hand-rolled inter-node static-route step at all** (`lima-start.sh`'s
`PEERS=...`/`ip route replace` block, ~lines 1016-1048) — flannel replaces
it outright — so mayor-0c5no's specific failure mode has no surface to
recur on. (Not independently re-verified with a live networkd-restart
repro in this spike — out of scope per the dispatch's "do NOT
re-diagnose" instruction — but the mechanism argument is direct: the
route mayor-0c5no describes losing does not exist in a flannel
configuration.)

## Q4 — effort estimate and GO/NO-GO

**GO.** All three scope questions came back clean or with an
understood, one-line fix. No aarch64/Lima-specific dead end found.

**Effort estimate: 1-2 focused days** for a follow-on to productionize
this into `scripts/conformance/`:
- Rig-script surgery only (no new unknowns) — cut the hand-assigned
  per-node `/24` bridge-subnet block, KCM controller-flag flip, add
  flannel-manifest apply, delete the now-dead manual route block and the
  now-dead 10.85.0.0/16 iptables rules.
- Needs re-verification on a **fresh `--reset` provision** (this spike
  only exercised a warm retrofit, which is why the `cni0`-conflict blocker
  showed up at all — a fresh VM per `install.sh`'s own ordering should
  not hit it, but that must be confirmed, not assumed).
- Needs a full certified-conformance sonobuoy pass on the new CNI to
  confirm no regression versus the cri-o-bridge baseline (this spike did
  not run sonobuoy — kubectl+tcpdump was the explicit gate per dispatch).
- Pre-existing daemon pods created before the CNI swap (konnectivity-agent,
  metrics-server, snapshot-controller) kept their stale `10.85.x.x`
  addresses and were not restarted in this spike (`12-all-pods-final.txt`)
  — a real rig build must either provision flannel before any other
  pod is scheduled (matching `install.sh`'s ordering) or force-restart
  everything after the CNI swap.

### Turnkey config diff (for the follow-on to adopt)

```diff
--- a/scripts/conformance/04-start-kcm.sh
+++ b/scripts/conformance/04-start-kcm.sh
@@
-  --controllers='*,-cloud-node-lifecycle-controller,-clusterrole-aggregation-controller,-device-taint-eviction-controller,-node-ipam-controller,-node-route-controller,-service-lb-controller,-service-cidr-controller' \
+  --controllers='*,-cloud-node-lifecycle-controller,-clusterrole-aggregation-controller,-device-taint-eviction-controller,-service-lb-controller,-service-cidr-controller' \
+  --cluster-cidr=10.244.0.0/16 \
+  --allocate-node-cidrs=true \
+  --node-cidr-mask-size=24 \
   --concurrent-gc-syncs=5 \
```

```diff
--- a/scripts/conformance/lima-start.sh
+++ b/scripts/conformance/lima-start.sh
@@ around the POD_SUBNET / crio-bridge-rewrite block (~lines 288-361)
- (remove the hand-assigned-per-node-/24 CRI-O bridge conflist rewrite,
-  the cni0-liveness guard, and the two cluster-wide 10.85.0.0/16
-  iptables ACCEPT/MASQUERADE rules)
+ # Disable crio-bridge before crio's first start on a FRESH VM
+ # (mirrors install.sh:692-696); on a WARM VM that already ran
+ # crio-bridge, also: ip link delete cni0; rm -rf
+ # /var/lib/cni/networks/crio/*; systemctl restart crio
+ for f in 10-crio-bridge.conf 10-crio-bridge.conflist; do
+   limactl shell "$VM_NAME" sudo bash -c "[ -f /etc/cni/net.d/$f ] && mv /etc/cni/net.d/$f /etc/cni/net.d/$f.disabled || true"
+ done
+ # Apply manifests/flannel.yaml (rendered with __IFACE__/__POD_CLUSTER_CIDR__,
+ # same sed as install.sh:930-932) once per cluster, after KCM/node-ipam is up.
@@ around the inter-node static-route block (~lines 1016-1048)
- (remove entirely: PEERS loop + `ip route replace` pairing — flannel's
-  flannel.1 VXLAN device owns cross-node routing instead)
```

Manifest: `manifests/flannel.yaml` needs no change — apply as-is with the
same `__IFACE__`/`__POD_CLUSTER_CIDR__` substitution `install.sh` already
does (`sed -e "s/__IFACE__/$IFACE/g" -e
"s#__POD_CLUSTER_CIDR__#10.244.0.0/16#g"`).

## Evidence index

All under `ai/findings/2026-09-15-mayor-4q2fj/`:
`00-baseline-nodes.txt`, `00-iface-lima-node-2.txt`, `01-node-podcidr.txt`,
`01-kcm-log-after-ipam-enable.txt`, `02-flannel-apply.txt`,
`03-flannel-pods-t20s.txt`, `04-flannel-log-node2.txt`,
`05-flannel1-link-node2.txt`, `06-ip-route-node2.txt`,
`06b-ip-route-node3.txt`, `07-test-pods.txt`, `08-test-pods-retry.txt`,
`09-tcpdump-vxlan-node2.txt`, `09-vxlan-node2.pcap`,
`10-cross-node-ping.txt` (superseded — busybox `ping` needs root, not
available unprivileged; `10-cross-node-nc-connect.txt` is the actual
successful evidence), `11-flannel-daemonset-status.txt`,
`12-all-pods-final.txt`.

No change was committed to `scripts/conformance/`, `scripts/install.sh`,
or `manifests/` — all edits described above were made and tested in this
worktree only, then discarded (not committed).
