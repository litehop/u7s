# Wordpress+MariaDB+nginx workload scoping

Bead: mayor-kecvr
Date: 2026-08-29
Shape: 3 (audit) — read-only, cached fetches under `temp/research/` (gitignored)

## Verdict

Partially-gated: dispatchable today for Phases 1, 3, 4, but Phase 2 (MariaDB)
needs a manual static-PV workaround first — u7s ships no default StorageClass
or dynamic provisioner, and both charts assume one implicitly. No u7s code
change is required; this is an operator setup step for the follow-on bead.

## u7s features exercised

| Workload piece | Feature | Citation |
|---|---|---|
| WordPress pod | 2-container Deployment (nginx + php-fpm), shared volume w/ `subPath` | `pehelypress/templates/deployment.yaml:32-121` |
| WordPress pod | readinessProbe httpGet w/ header, livenessProbe tcpSocket | `deployment.yaml:46-65` |
| WordPress pod | ConfigMap volumes via `subPath` (nginx.conf, php ini) | `deployment.yaml:40-42,103-105`; `nginx.yaml:1-8`; `php.yaml:1-8` |
| WordPress pod | Secret env via `secretKeyRef` (DB creds) | `deployment.yaml:79-98`; `secret.yaml:1-14` |
| WordPress pod | PVC, no storageClassName set → "default provisioner" | `pvc.yaml:1-14`; `values.yaml:76-84` |
| WordPress | Service ClusterIP (NodePort/LB configurable), Ingress (disabled by default) | `service.yaml:1-16`; `ingress.yaml:1-52` |
| MariaDB | StatefulSet, 1 replica, `volumeClaimTemplates` | `sut-mariadb/statefulset.yaml:1-152,135-151` |
| MariaDB | governing Service is plain ClusterIP, not headless | `sut-mariadb/service.yaml:1-22` |
| MariaDB | exec probes (`mariadb-admin ping/status`) | `statefulset.yaml:65-86` |
| MariaDB | ServiceAccount, NetworkPolicy (ingress/egress) | `serviceaccount.yaml:1-11`; `networkpolicy.yaml:1-26` |
| MariaDB | Linode-specific nodeSelector + podAntiAffinity (must strip) | `statefulset.yaml:31-40,114-115` |
| MariaDB | Secret "mariadb" + ConfigMap "mariadb" referenced but **not present** in the fetched `mariadb/` folder | `statefulset.yaml:47-58,124-128` |

DNS: WordPress's default `database.hostname` is
`mariadb.default.svc.cluster.local` (`pehelypress/values.yaml:14`), matching
the plain Service name/namespace above — no headless service or per-pod DNS
needed since MariaDB runs a single replica.

## Likely-to-break list

- **StatefulSet/Deployment/DaemonSet reconciliation — known-solid.** u7s bundles upstream `kube-controller-manager` as a pre-built binary (`docs/decisions/upstream-component-shipping-shape.md:15-16`); u7s's own codecs round-trip these kinds (`crates/apiserver/src/apps_gen_adapter.rs:97-153`).
- **ConfigMap/Secret/PVC/PV as API objects — known-solid.** Decoders exist for all four (`crates/apiserver/src/core_gen_adapter.rs:1551-1554,2007,2332,2449-2452`). Actual volume-mount/env injection is upstream kubelet's job, also bundled.
- **Dynamic volume provisioning — known-missing by default.** `manifests/README.md:1-18` lists only CoreDNS/flannel/kube-proxy as auto-applied; no CSI driver ships. `StorageClass` decode/encode exists (`crates/apiserver/src/storage_node_flow_gen_adapter.rs:103-116`) but nothing binds a PVC referencing one to real storage. MariaDB hardcodes `storageClassName: linode-block-storage-retain` (`statefulset.yaml:150`), which will never exist here; WordPress's PVC leaves it unset. **Workaround (no code change):** create a placeholder `StorageClass` object plus statically pre-created PVs matching each PVC's size/accessMode/class — standard k8s static-PV binding via the already-solid PV/PVC binding controller in bundled KCM.
- **NetworkPolicy — known-partial.** apiserver stores/lists/watches correctly but nothing enforces by default (`docs/decisions/network-policy-engine.md:8`). Harmless here: the mariadb policy's ingress rule has no `from` selector (`networkpolicy.yaml:14-17`), so it permits all traffic regardless of enforcement.
- **Service ClusterIP + DNS — known-solid.** u7s runs real upstream kube-proxy in IPVS mode (bd memory `u7s-runs-upstream-kube-proxy-ipvs-and-crio-bridge-cni`) and auto-applies CoreDNS (`manifests/coredns.yaml`).
- **Probes (httpGet/tcpSocket/exec) — known-solid**, executed by the bundled upstream kubelet, not u7s code.
- **Reference-repo gap, not a u7s gap:** `sut/mariadb`'s Secret and ConfigMap are assumed pre-existing (`statefulset.yaml:47-58,124-128`) — Phase 2 must hand-author both.

## Phased execution plan

1. **Fresh Ubuntu Lima VM + release-tarball install.** Exercises: apt CRI-O install, systemd units for u7s-apiserver/u7s-kcm/kubelet, all *inside* the VM (not the split-host `scripts/conformance/lima-start.sh` topology). Known-good: `kubectl get nodes` shows `Ready`. ~15-20 min.
2. **MariaDB deploy.** Exercises: StorageClass+static-PV workaround, StatefulSet reconcile, exec probes, ServiceAccount, hand-authored Secret/ConfigMap. Known-good: `mariadb-0` Running, readiness probe passing. ~10 min.
3. **WordPress + nginx sidecar deploy.** Exercises: multi-container Deployment, ConfigMap `subPath` mounts, Secret env, Service ClusterIP. Known-good: pod Running, both containers Ready (nginx's `/wp-login.php` readinessProbe passing implies php-fpm reached MariaDB). ~10 min.
4. **End-to-end HTTP validation.** `kubectl port-forward svc/wordpress 8080:80` (per `pehelypress/templates/NOTES.txt:17-20`) and curl. Known-good: HTTP 200 with WordPress install/login HTML. ~5 min.
