# k3s system-component and finalizer provenance for migration

Bead: mayor-ffgal
Date: 2026-10-15
Follows: `2026-10-15-mayor-ffgal-k3s-k0s-migration.md` (sections 2, 2a, 7; decisions A4, A9)

**Answer:** on k3s the API itself records provenance: every distro-installed object traces to a `k3s.cattle.io/v1 Addon` CR through the wrangler `objectset.rio.cattle.io/owner-*` annotations, directly or via a Helm release whose `HelmChart` CR is Addon-owned, so the tool classifies by tracing ownership to an Addon (not by `managed-by: Helm` labels, which user charts carry identically) and attributes finalizers by the `managedFields` writer plus a fixed table of upstream strings; in the stock dump the 9 finalizer-bearing objects split into 3 upstream (class a), 6 distro-only (class c), and 0 third-party (class b, not exercised), with the Addon source filename being the one weak point because a user-dropped manifest is indistinguishable by annotation.

## Method and environment

- Stock k3s `v1.36.5+k3s1` (stable channel at 2026-10-15), arm64, Ubuntu 26.04 Lima VM, default flags, single node, SQLite. Install: `INSTALL_K3S_VERSION=v1.36.5+k3s1 sh k3s-install.sh`.
- Added: cert-manager v1.20.0 static manifest + `Issuer`/`Certificate` (ns `userapp`), user Deployment/Service/PVC (local-path) and a `type: LoadBalancer` Service in `userapp`, `helm install mychart oci://registry-1.docker.io/bitnamicharts/nginx` (ns `userhelm`, Helm v3.22.0), a user-created `HelmChart` CR `user-hc` (same chart), a user `HelmChartConfig` `traefik`, a user manifest dropped at `/var/lib/rancher/k3s/server/manifests/my-app.yaml`, and the PVC deleted with `--wait=false` (mid-deletion).
- Dump: `kubectl get <r> -A -o json --show-managed-fields` for every resource in `kubectl api-resources --verbs=list`: 953 objects, 0 list failures. Raw dump is archived (reference only) at `temp/e2e/ffgal-provenance-k3s-v1.36.5/` in the mayor checkout; all evidence used below is inlined.
- k0s: **not verified** (no time; see open risks).
- Not exercised: cert-manager v1.20.0 sets no finalizers on its objects here, so there is no third-party-CR finalizer in the dump. Class (b) is therefore argued by rule, not shown by instance.

## 1. Provenance signals

Where the dump shows `managedFields` manager `k3s`, that is the apiserver's own user-agent for every in-process write and is **not** a signal. The host-suffixed managers are: `deploy@<host>` (Addon/manifest applier), `helm-controller@<host>`, `k3s-supervisor@<host>`.

| Signal (verified live) | Carried by | Reliability | False-positive risk |
|---|---|---|---|
| `objectset.rio.cattle.io/owner-gvk: "k3s.cattle.io/v1, Kind=Addon"` + `owner-name` (annotations; label `objectset.rio.cattle.io/hash`); no `ownerReferences`. 41 objects | coredns Deployment/CM/SA/Service, local-path-provisioner Deployment/CM/SA/StorageClass/ClusterRole, metrics-server (Deployment, APIService, RBAC), the `traefik`/`traefik-crd` HelmChart CRs, 10 `RuntimeClass`es, `ccm` RBAC | High for "installed by the k3s manifest applier" | **Includes user files**: a ConfigMap from a user-dropped `manifests/my-app.yaml` carries the identical annotations (`owner-name: my-app`). Distinguish only by the Addon's `spec.source` filename vs the shipped set (below) |
| `Addon` CR itself (`addons.k3s.cattle.io`), `spec.source: /var/lib/rancher/k3s/server/manifests/<file>`, annotation `addon.k3s.cattle.io/gvks` | 13 CRs: aggregated-metrics-reader, auth-delegator, auth-reader, ccm, coredns, local-storage, metrics-apiservice, metrics-server-deployment, metrics-server-service, resource-reader, rolebindings, runtimes, traefik; plus `my-app` (user) | High as the authoritative index | Same: `my-app` is also an Addon. The shipped set per version is the only discriminator (`ccm.yaml coredns.yaml local-storage.yaml rolebindings.yaml runtimes.yaml traefik.yaml metrics-server/*.yaml`) |
| managedFields manager `deploy@<host>` (Update) | exactly the Addon-applied objects above, and the Addon CRs | High, but redundant with the objectset annotation; useful because it survives annotation stripping | Same user-file case (`dropped-in` ConfigMap: `deploy@lima-k3s-prov`) |
| Helm labels `app.kubernetes.io/managed-by: Helm` + `meta.helm.sh/release-name` + `helm.sh/chart` | traefik (Deployment/Service/SA/CRDs, 10+15+10 CRDs of `gateway.networking.k8s.io`, `hub.traefik.io`, `traefik.io`), **and equally** `mychart` (`userhelm`) and `user-hc` (`userhc`) | **Refuted as a distro signal.** Only proves "installed by Helm" | 100%: user `helm install` and a user `HelmChart` CR produce byte-identical label shapes (see snippet A) |
| HelmChart CR traced: release name == HelmChart name, and that HelmChart has `owner-gvk: Addon` (`traefik`, `traefik-crd`) | Everything Helm installed for traefik; its `sh.helm.release.v1.traefik*` Secrets (kube-system); `helm-<chart>` SA/ClusterRoleBinding/ConfigMap `chart-content-*`/Secret `chart-values-*`/Job `helm-install-*` | High | Low: user `HelmChart`s (`user-hc`) are not Addon-owned, so they fall out as user |
| HelmChart `spec.chart` starts `https://%{KUBERNETES_API}%/static/charts/` | `traefik`, `traefik-crd` | Medium (secondary) | A user may reference the same URL; independent of Addon ownership |
| `helmcharts.cattle.io/managed-by: helm-controller` annotation | all three HelmCharts including user `user-hc` | **Refuted** as distro marker (identifies the controller, not the owner) | 100% on user charts |
| `objectset.rio.cattle.io/owner-gvk: "/v1, Kind=Service"` + labels `svccontroller.k3s.cattle.io/{svcname,svcnamespace,nodeselector}` | servicelb `svclb-<svc>-<hash>` DaemonSet and its ControllerRevision in `kube-system`, one per LoadBalancer Service (traefik's and the user's `web-lb`) | High for "generated by servicelb" | Low. The owning **Service itself carries none of these** (labels null); the user Service is not marked |
| managedFields manager `k3s-supervisor@<host>` | Node, 4 CRDs (`addons`, `etcdsnapshotfiles`, `helmcharts`, `helmchartconfigs`), `kube-system` CM `cluster-dns`, Secrets `k3s-serving` and `<node>.node-password.k3s`, coredns CM (co-owner) | High for "k3s bootstrap state" | None seen |
| CRD group `k3s.cattle.io` / `helm.cattle.io` (annotation `controller-gen.kubebuilder.io/version`) | the 4 distro CRDs | High (CRD identity is stable) | CRs of these groups are user-writable (`HelmChart user-hc`, `HelmChartConfig traefik`); the CRD is distro, the instances may be user |
| `objectset.rio.cattle.io/owner-gvk: ...Kind=HelmChart` + `id: helm-controller-chart-registration` | scaffolding helm-controller makes per HelmChart: `helm-<name>` SA, ClusterRoleBinding, `chart-content-<name>` CM, `chart-values-<name>` Secret, `helm-install-<name>` Job | High for "helm-controller scaffolding" | Scaffolding exists for user HelmCharts too (`user-hc`); the HelmChart's own owner decides distro vs user |
| Upstream bootstrap: label `kubernetes.io/bootstrapping`, annotation `rbac.authorization.kubernetes.io/autoupdate` (135/134 objects), label `kube-aggregator.kubernetes.io/automanaged`, `apf.kubernetes.io/autoupdate-spec`, built-in Namespaces (`default`, `kube-system`, `kube-public`, `kube-node-lease`) | apiserver-reconciled RBAC/APIService/FlowSchema/PriorityLevel | High, and identical on u7s (it reconciles these itself) | None |
| `managedFields` absent (null) | 38 `kube-system` ServiceAccounts named `*-controller` (e.g. `deployment-controller`), per-namespace `default` ServiceAccounts | Medium: "created in-process by the control plane". Every user/Helm/kubectl-created SA has `managedFields` | A Secret/other in-process object may also lack it; only trusted combined with name+namespace for SAs |
| Server-side-apply `helm/Apply` manager | all Helm-installed objects from helm-controller's Helm 3.x and `helm install` alike | Not a distro signal | n/a |

Snippet A, traefik (distro) vs `mychart` (user `helm install`) vs `user-hc` (user `HelmChart`), identical:

```json
{"k":"Deployment","ns":"kube-system","n":"traefik","labels":{"app.kubernetes.io/instance":"traefik-kube-system","app.kubernetes.io/managed-by":"Helm","helm.sh/chart":"traefik-40.1.5_up40.1.0"},"ann":{"meta.helm.sh/release-name":"traefik","meta.helm.sh/release-namespace":"kube-system"},"mgr":["helm/Apply","k3s/Update"]}
{"k":"Deployment","ns":"userhc","n":"user-hc-nginx","labels":{"app.kubernetes.io/instance":"user-hc","app.kubernetes.io/managed-by":"Helm","helm.sh/chart":"nginx-25.2.5"},"ann":{"meta.helm.sh/release-name":"user-hc","meta.helm.sh/release-namespace":"userhc"},"mgr":["helm/Apply","k3s/Update"]}
{"k":"Deployment","ns":"userhelm","n":"mychart-nginx","labels":{"app.kubernetes.io/instance":"mychart","app.kubernetes.io/managed-by":"Helm","helm.sh/chart":"nginx-25.2.5"},"ann":{"meta.helm.sh/release-name":"mychart","meta.helm.sh/release-namespace":"userhelm"},"mgr":["helm/Update","k3s/Update"]}
```

Snippet B, the discriminating chain: the distro `HelmChart` is owned by an Addon, the user one is not:

```json
{"n":"traefik","annotations":{"helmcharts.cattle.io/managed-by":"helm-controller","objectset.rio.cattle.io/id":"","objectset.rio.cattle.io/owner-gvk":"k3s.cattle.io/v1, Kind=Addon","objectset.rio.cattle.io/owner-name":"traefik","objectset.rio.cattle.io/owner-namespace":"kube-system"},"fin":["wrangler.cattle.io/on-helm-chart-remove"],"mgr":["deploy@lima-k3s-prov","helm-controller@lima-k3s-prov"],"spec":{"chart":"https://%{KUBERNETES_API}%/static/charts/traefik-40.1.5+up40.1.0.tgz","forceConflicts":true}}
{"n":"user-hc","labels":null,"annotations":{"helmcharts.cattle.io/managed-by":"helm-controller"},"fin":["wrangler.cattle.io/on-helm-chart-remove"],"mgr":["helm-controller@lima-k3s-prov","kubectl-client-side-apply"],"spec":{"chart":"oci://registry-1.docker.io/bitnamicharts/nginx","targetNamespace":"userhc"}}
```

Snippet C, servicelb child of a USER Service (child is marked, owner is not):

```json
{"name":"svclb-web-lb-5ce57e93","namespace":"kube-system","labels":{"svccontroller.k3s.cattle.io/svcname":"web-lb","svccontroller.k3s.cattle.io/svcnamespace":"userapp"},"annotations":{"objectset.rio.cattle.io/owner-gvk":"/v1, Kind=Service","objectset.rio.cattle.io/owner-name":"web-lb","objectset.rio.cattle.io/owner-namespace":"userapp"},"ownerReferences":null}
```

Snippet D, a bundled addon (local-path-provisioner Deployment) and a user-dropped manifest object:

```json
{"name":"local-path-provisioner","labels":{"objectset.rio.cattle.io/hash":"183f35c6..."},"annotations":{"objectset.rio.cattle.io/id":"","objectset.rio.cattle.io/owner-gvk":"k3s.cattle.io/v1, Kind=Addon","objectset.rio.cattle.io/owner-name":"local-storage","objectset.rio.cattle.io/owner-namespace":"kube-system"},"ownerReferences":null,"mgr":["deploy@lima-k3s-prov","k3s"]}
{"k":"ConfigMap","n":"dropped-in","ann":{"objectset.rio.cattle.io/owner-gvk":"k3s.cattle.io/v1, Kind=Addon","objectset.rio.cattle.io/owner-name":"my-app"},"mgr":["deploy@lima-k3s-prov/Update"]}
```

Per-component verdict (k3s v1.36.5 defaults):

| Component | Objects | Marker |
|---|---|---|
| coredns | Deployment, CM, SA, Service `kube-dns`, RBAC | Addon `coredns` |
| local-path-provisioner | Deployment, CM `local-path-config`, SA, RBAC, StorageClass `local-path` (default; `reclaimPolicy: Delete`, `provisioner: rancher.io/local-path`) | Addon `local-storage` |
| metrics-server | Deployment, Service, APIService `v1beta1.metrics.k8s.io`, RBAC | Addons `metrics-*`, `auth-*`, `resource-reader` |
| ccm (embedded cloud controller) | RBAC only; **no Pod** | Addon `ccm` |
| traefik | HelmChart `traefik`, `traefik-crd`; release Secrets; Deployment/Service/SA; 35 CRDs; helm-controller scaffolding | HelmChart owned by Addon `traefik` |
| servicelb | per-LoadBalancer-Service DaemonSet + ControllerRevision in `kube-system`; the Service finalizer | `owner-gvk: Service` + `svccontroller.k3s.cattle.io/*` |
| helm-controller | HelmChart/HelmChartConfig CRDs; no Deployment (embedded); scaffolding objects | CRD group `helm.cattle.io`; manager `helm-controller@<host>` |
| runtimes | 10 `RuntimeClass` | Addon `runtimes` |

PV note: the local-path PV carries `pv.kubernetes.io/provisioned-by: rancher.io/local-path`, `local.path.provisioner/selected-node`, `persistentVolumeReclaimPolicy: Delete`, manager `local-path-provisioner`. It is user data, not a system component, despite the distro provisioner; classify by claim, never by provisioner.

## 2. Finalizer attribution

Every finalizer instance in the dump (9 objects; `jq '.[]|select(.metadata.finalizers)'`). "Writer" is the manager owning `f:finalizers` in `managedFields`, where one exists.

| Finalizer | Objects | Controller | Class | Evidence |
|---|---|---|---|---|
| `kubernetes.io/pvc-protection` | PVC `userapp/data` (mid-deletion, `deletionTimestamp: 2026-10-15T03:06:41Z`) | upstream KCM `pvc-protection-controller` (+ apiserver admission) | **a** | Well-known upstream string. No `managedFields` writer owns it (apiserver-stamped), so there is no k3s component to attribute it to |
| `kubernetes.io/pv-protection` | PV `pvc-bbb14296-...` | upstream KCM `pv-protection-controller` | **a** | As above; PV is local-path-provisioned but finalizer is upstream |
| `networking.k8s.io/service-cidr-finalizer` | `ServiceCIDR/kubernetes` | upstream service-CIDR controllers (managers `service-cidr-controller`, `kubernetes-service-cidr-controller`, Apply) | **a** | Upstream string; the `ServiceCIDR` object is apiserver-reconciled and not exported anyway |
| `service.kubernetes.io/load-balancer-cleanup` | Service `kube-system/traefik`, `userapp/web-lb` | cloud-provider service controller, which on k3s is the embedded `ccm` | **c** (upstream name, distro implementer) | `f:finalizers` owner: manager `k3s`, `Update`, subresource `status`. No cloud-controller Pod exists (`kubectl get pods -A` shows none); the Addon `ccm` ships only RBAC (`k3s-cloud-controller-manager`). On u7s no controller removes it unless a cloud-provider service controller runs |
| `wrangler.cattle.io/on-helm-chart-remove` | HelmChart `traefik`, `traefik-crd`, `user-hc` | k3s embedded helm-controller | **c** | Sole writer of `f:finalizers`: `helm-controller@lima-k3s-prov`; the `wrangler.cattle.io` domain is the wrangler library embedded in k3s |
| `wrangler.cattle.io/node` | Node `lima-k3s-prov` | k3s embedded node controller | **c** | Writer `k3s-supervisor@lima-k3s-prov`; Nodes are already excluded from import |

Counts by object instance: **a = 3 kinds / 3 objects** (pvc-protection, pv-protection, service-cidr-finalizer; the apiserver reconciles them on u7s too), **c = 3 kinds / 6 objects** (2 LB Services, 3 HelmCharts, 1 Node; distro-only), **b = 0** (see "not exercised": cert-manager v1.20.0 sets no finalizers in this dump). Classes are assigned by string, not by whether u7s has an implementer. Decisions: a = keep; c = strip and report; b = keep iff the controller's workload is migrated. `foregroundDeletion` and `orphan` were not present in the dump; they are in the upstream set by definition.

Rules for the third-party class (b), derived from the dump rather than observed: a finalizer is third-party iff it is not in the fixed upstream set {`kubernetes.io/pvc-protection`, `kubernetes.io/pv-protection`, `foregroundDeletion`, `orphan`, `networking.k8s.io/service-cidr-finalizer`}, not in the k3s set {`wrangler.cattle.io/*`, `svccontroller.k3s.cattle.io/*`, `service.kubernetes.io/load-balancer-cleanup` when no cloud controller runs on target}, and its domain equals the group of a CRD in the export or the `app.kubernetes.io/part-of`/name of an exported workload (cert-manager's controller does not use one here, which is the common pattern for operators that rely on ownerRef GC). Attribution to a specific controller beyond "CRD group X" is best-effort: when a CRD group has an exported Deployment whose name or label `app.kubernetes.io/name` shares the group's first label (`cert-manager.io` -> `cert-manager`), report it as the likely owner; otherwise report "unknown, strip" so a human decides.

## 3. Proposed classification algorithm

Ordered rules; the first match wins. Output is an object classification plus a per-finalizer decision. All inputs come from the source API.

0. **Skip non-stored**: aggregated APIs (`PodMetrics`/`NodeMetrics`), Events, `ComponentStatus`, Nodes, `VolumeAttachment`, mid-deletion objects (reported with their finalizers; section 2a of the main doc).
1. **apiserver-builtin** (`skip`, reconciled by u7s): `kubernetes.io/bootstrapping` label, system namespaces and their per-namespace `default` ServiceAccount and `kube-root-ca.crt`/`extension-apiserver-authentication` ConfigMaps, FlowSchema/PriorityLevelConfiguration, automanaged APIServices, `ServiceCIDR`/`IPAddress`/`Lease`/`Endpoints`/`EndpointSlice`, `Service default/kubernetes`, and `kube-system` ServiceAccounts with null `managedFields`.
2. **Child of a controller** (`skip`, parent regenerates): has `ownerReferences` to an exported object.
3. **Distro-installed** (`skip`, report "distro addon <name>, replacement on target: <u7s default or none>"): any of
   - `objectset.rio.cattle.io/owner-gvk` is `k3s.cattle.io/v1, Kind=Addon` **and** the Addon's `spec.source` basename is in the shipped-manifest set for the source k3s version (or the Addon CR exists with `deploy@` manager and the file is not in the set -> rule 6);
   - the object is a `HelmChart` owned by such an Addon, or Helm-labelled with a `meta.helm.sh/release-name` equal to such a HelmChart's name in `kube-system` (this catches traefik, its release Secrets and CRDs);
   - helm-controller scaffolding (`owner-gvk: HelmChart`) whose HelmChart is distro per the line above;
   - manager `k3s-supervisor@*`, or an instance of the k3s CRDs `Addon`, plus those CRDs themselves.
4. **Distro-generated from a user object** (`skip`, regenerated if the feature exists on target): `owner-gvk: ...Kind=Service` / `svccontroller.k3s.cattle.io/svcname` (servicelb DaemonSets). The user Service is imported; `status.loadBalancer` is dropped and the report says "no LoadBalancer implementation on target".
5. **Third-party/user, Helm**: Helm-labelled (`managed-by: Helm`) not matching rule 3, plus release Secrets `sh.helm.release.v1.*` in the same namespace -> `include` (import the rendered objects; report "Helm release state moves as Secret but charts are not re-rendered"; user `HelmChart`/`HelmChartConfig` CRs are included but inert without helm-controller; report).
6. **User-dropped manifest** (`include`, flagged `source=manifest-file`): Addon-owned (rule 3 test passes the objectset annotation but the source file is not shipped, e.g. `my-app.yaml`). Marked in the report for explicit review because the file still exists on the source host.
7. **Everything else** -> `include` (user and third-party: cert-manager, CRs, Secrets, PVCs, user Deployments).

Finalizers per included object: keep class a (`pvc/pv-protection`, `foregroundDeletion`, `orphan`); strip class c and report (`wrangler.cattle.io/*`, `service.kubernetes.io/load-balancer-cleanup` unless target runs a service controller); keep class b when its CRD group is exported, else strip and report; `--keep-finalizers` overrides.

Dry-run report (`u7s migrate --plan`), one line per decision, user-editable:

```
rule  class                     action   object                                   why
R3    distro-addon              exclude  Deployment kube-system/traefik           owned by Addon traefik (HelmChart traefik); u7s ships none
R3    distro-addon              exclude  Deployment kube-system/local-path-provisioner  Addon local-storage; target replacement: local-path (if bundled)
R4    servicelb-child           exclude  DaemonSet kube-system/svclb-web-lb-5ce57e93    child of Service userapp/web-lb
R5    user-helm                 include  Deployment userhelm/mychart-nginx        release mychart, no HelmChart owner
R6    user-manifest-file        include  ConfigMap default/dropped-in             Addon my-app from non-shipped file
R7    user                      include  Deployment userapp/web
fin   strip(c)  Service userapp/web-lb  service.kubernetes.io/load-balancer-cleanup  no service controller on target
fin   keep(a)   PVC userapp/data        kubernetes.io/pvc-protection  (object is mid-deletion: skipped, reported)
```

Overrides: a plan file (`include:`/`exclude:` lists of `kind/ns/name` or selectors such as `addon:traefik`, `helm-release:mychart`, `finalizer:<string>=keep|strip`) is the only way a rule's decision changes; any override is echoed back in the final report. Exit non-zero if the plan contains an unresolved class b finalizer or a Delete-reclaim PV (main doc 2b).

## 4. Open risks

- **k0s is unverified.** Expected signals (k0s stack applier labels, `k0s.k0sproject.io/stack`, checksum annotations) are from memory and must be re-run against a live k0s before the algorithm is shared between distros.
- **Shipped-manifest list drifts per k3s version** (new addons such as `ccm.yaml`, `runtimes.yaml`; metrics-server files). Rule 3's file-name test needs a versioned table keyed by k3s version, taken from the source node's `k3s.io/node-args`/version, or the tool should treat any Addon whose source file lives outside the shipped set as rule 6.
- **User edits of shipped manifests**: a user who edited `/var/lib/rancher/k3s/server/manifests/traefik.yaml` or overrode traefik via `HelmChartConfig` produces objects that look distro. The `HelmChartConfig traefik` the user applied has only `kubectl-client-side-apply`, no objectset annotation; it is a user object that targets a distro chart and must be reported, not excluded.
- **`--disable` and packaged addons**: with `--disable traefik` the Addons are absent and the tool must not fabricate them; rules are evidence-driven, so this holds, but the "replacement on target" text is distro-version-aware only when the table is.
- **`service.kubernetes.io/load-balancer-cleanup` on u7s**: not verified that u7s has no implementer; if a cloud-provider-style service controller is ever added, class c becomes class a. Same for whether u7s's apiserver stamps `pvc-protection` itself (the source has `resource.rs` comments that KCM stamps it) so that the finalizer is not lost on import.
- **Third-party finalizer attribution is heuristic.** No third-party finalizer was observed; the CRD-group rule is untested against real operators (Argo CD, external-secrets, Crossplane) and a finalizer whose domain matches no exported CRD (a finalizer left by a removed operator) becomes "strip and report", which is the safe direction but needs the human review the plan provides.
- **`managedFields` may be pruned** by a client that disables it (`--show-managed-fields` is required on export; rules 1, 3 and 4 do not depend on it except the `k3s-supervisor`/SA-null signal, which is secondary).
- **Wrangler annotations are internal to k3s/Rancher**: an unannounced change in their schema (object `owner-gvk` format) would silently degrade rule 3; the plan should fail loud when an Addon CR exists but no object references it.
