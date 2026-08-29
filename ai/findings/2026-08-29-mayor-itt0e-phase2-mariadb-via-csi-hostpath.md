# Phase 2: MariaDB deploy via csi-hostpath

Bead: mayor-itt0e
Date: 2026-08-29
Shape: 3 (audit) — one fresh VM, findings only, no u7s code changes

## Verdict

MariaDB reached `Running` and is functionally alive end-to-end (`SELECT 1;`
over the `mariadb` Service from another pod succeeds) — but only after
working around **5 distinct u7s-should-own gaps**, one of which (a MariaDB
credential-bootstrap timeout that permanently wedges the readiness/liveness
probes into a crash loop) needed a manual live SQL patch, not just an RBAC
tweak. csi-hostpath's own integration (driver, StatefulSet, dynamic
provisioning) is usable end-to-end once those gaps are worked around, but
none of the 5 are csi-hostpath-specific — they are general-purpose platform
bugs that csi-hostpath's realistic I/O pattern happened to expose first.

## Timeline

1. **Deploy csi-hostpath** (v1.17.1, matching the tag the sonobuoy e2e
   conformance suite already exercises): ~5 min. `csi-hostpathplugin-0`
   reached 8/8 Running in 44s. Its own `deploy.sh` hard-fails applying
   `csi-hostpath-snapshotclass.yaml` (no VolumeSnapshot CRDs installed) —
   harmless for PVC provisioning, not a u7s gap (vanilla kubeadm lacks these
   CRDs too).
2. **Deploy MariaDB StatefulSet**: ~35 min (blocked twice on RBAC/networking
   gaps below before the PVC bound and the pod mounted).
3. **Verify functionally alive**: ~15 min (blocked by a MariaDB
   credential-bootstrap gap, worked around with a manual SQL patch).

## Gaps

| Symptom | Category | Fix |
|---|---|---|
| Kubelet FailedMount: `system:node:<node> is not allowed to get persistentvolumeclaims` | u7s-should-own (P0) | `system:node` ClusterRole (`crates/apiserver/src/lib.rs:~1354`) is missing `get` on `persistentvolumeclaims`/`persistentvolumes` and `volumeattachments` that upstream's real `NodeRules()` grants. Blocks **any** PVC-backed pod, not just csi-hostpath. Bead-worthy. |
| `kubectl get secret mariadb -o json` echoes `stringData` verbatim with no `data` field; container fails with "couldn't find key ... in Secret" | u7s-should-own (P0) | Secret create/update never merges `stringData` into base64 `data` and clears it, contradicting u7s's own OpenAPI doc (`handlers/discovery.rs:2373`: "never output when reading from the API"). Worked around with `--from-literal`. Bead-worthy. |
| CoreDNS SA denied `list namespaces/services/endpointslices` despite a byte-for-byte correct `ClusterRoleBinding` | u7s-should-own (P0) | SubjectAccessReview A/B test: removing the `kubernetes.io/bootstrapping: rbac-defaults` label (the standard label every vendored upstream RBAC manifest — including u7s's own `manifests/coredns.yaml` — carries) from the live binding flips `allowed: false → true`. No matching string in the auth code; needs a maintainer's dig. Broke CoreDNS since boot — would also break Phase 3's Service DNS lookup. Bead-worthy. |
| Same-node pod→pod Service ClusterIP traffic (e.g. DNS to `kube-dns` ClusterIP) silently times out; direct pod-IP access works fine | u7s-should-own (P1) | `install.sh` never loads `br_netfilter` / sets `net.bridge.bridge-nf-call-iptables=1`, a standard kube-proxy iptables-mode prerequisite. Confirmed: `modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1` fixed it live. Bead-worthy. |
| kube-proxy's own kubeconfig pointed `server:` at the ClusterIP itself (bootstrap deadlock: informer never syncs, so the DNAT rule that would make the ClusterIP reachable never gets programmed) | Already fixed on main | Confirmed fixed by commit `92e98dc3` (2026-08-26), 2 days after the `v0.2.0-snapshot.3` release Phase 1 used. Not re-filed — just a stale-release artifact. Worth noting for release cadence. |
| MariaDB's entrypoint temp-server bootstrap ("Waiting for server startup") times out (~36s) on first start against the csi-hostpath PVC; intended root/user/db-setup SQL never runs. Restarts skip re-bootstrap (data dir non-empty), launching mysqld with unconfigured (blank-password) defaults — probes (which use the *intended* password) fail forever, and liveness kill/restart repeats indefinitely | u7s-should-own, needs investigation (P1) | mysqld's own InnoDB init completes fast (~2s); only the entrypoint's startup-detection loop times out. Leading hypotheses: hostpath-CSI mount/stat latency, or the 250m/375m CPU limit — neither ruled out. Confirmed live: manually running the bootstrap SQL unblocks the probes. Bead-worthy. |

## Reproducible deploy recipe (Phase 3 baseline)

```
# csi-hostpath v1.17.1 (matches u7s's own sonobuoy e2e pin)
git clone --depth 1 --branch v1.17.1 https://github.com/kubernetes-csi/csi-driver-host-path.git
cd csi-driver-host-path/deploy/kubernetes-latest && ./deploy.sh   # ignores the snapshotclass failure
kubectl apply -f ../../examples/csi-storageclass.yaml             # StorageClass "csi-hostpath-sc"

# Workarounds for the gaps above (until fixed):
kubectl patch clusterrole system:node --type merge -p '{"rules":[...+pvc/pv/volumeattachments get...]}'
kubectl label clusterrolebinding system:coredns kubernetes.io/bootstrapping- ; kubectl delete pod -n kube-system -l k8s-app=coredns
sudo modprobe br_netfilter && sudo sysctl -w net.bridge.bridge-nf-call-iptables=1

# MariaDB: storageClassName -> csi-hostpath-sc, strip Linode nodeSelector/podAntiAffinity;
# create Secret via `kubectl create secret generic mariadb --from-literal=...` (not stringData);
# hand-author a minimal ConfigMap "mariadb" (unmounted but referenced); apply StatefulSet/Service/SA.
kubectl exec mariadb-0 -- mariadb -uroot -p'' -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('<pw>'); ..."
kubectl exec <any-pod> -- mariadb -h mariadb.default.svc.cluster.local -u root -p'<pw>' -e "SELECT 1;"
```

`lima-workload` left Running for Phase 3 (mayor-f3h0p).

## Follow-on beads

- mayor-u1g6k — `system:node` missing PVC/PV/VolumeAttachment RBAC rules (P0)
- mayor-l9oo0 — Secret `stringData` never merged into base64 `data` (P0)
- mayor-e78se — RBAC ignores ClusterRoleBindings labeled `kubernetes.io/bootstrapping=rbac-defaults` (P0)
- mayor-ilu9b — `install.sh` missing `br_netfilter`/`bridge-nf-call-iptables` (P1)
- mayor-22ygq — MariaDB temp-server credential bootstrap timeout → crash loop (P1, needs its own investigation)

All filed with `discovered-from: mayor-itt0e`.
