# Migration onto and off u7s from/to k3s and k0s

Bead: mayor-ffgal
Date: 2026-10-15
Status: Phase 1 (read-only research); nothing here is built until the operator decides.

**Answer: build an API-level export/import tool (kubectl-only, no k3s/k0s-internals coupling) as the one migration mechanism for both directions (operator-approved), MVP = single-node k3s -> u7s with workloads, Secrets, CRDs, Service ClusterIP/NodePort and PV data intact (PVs reused in place behind a mandatory `Retain` guard, no data copy) and rollback because the source is never modified; a kine->u7s datastore converter is rejected because it buys only resourceVersion/UID continuity, which an ownerReference/claimRef UID remap makes unnecessary, at the cost of a protobuf decoder, an encryption-at-rest decoder and tight coupling to two internal schemas.**

Evidence discipline: kine/k0s/k3s sources were read via `gh api` at pinned refs and are cited as upstream paths: kine `327f7d60748cfdc1ad1f8251de33445860962b9e` (`github.com/k3s-io/kine`), k3s docs `796d9524c077b3b912ea42ff6557cfdf5fe53722` (`k3s-io/docs`), k0s `0de757d6c217208165fe8a5049f78947240107ac` (`k0sproject/k0s`), k3s `d4d3dcde3705780ea08d37e38fd061c181858690` (`k3s-io/k3s`). Velero and the Rancher/community-script landscape were NOT fetched; those rows are from prior knowledge and marked "unverified". Nothing was run on Lima; the verification design in section 6 is a design only.

## 1. Existing-tooling survey

| Tool | What it does | Why it is not a friendly onto/off-u7s path |
|---|---|---|
| k3s datastore docs | SQLite backup = copy `/var/lib/rancher/k3s/server/db/`; SQLite -> embedded etcd by restarting with `--cluster-init` (`k3s-io/docs` `docs/datastore/ha-embedded.md:66`); etcd via `k3s etcd-snapshot` | All paths stay inside the k3s/kine family. Restoring requires the same server token because "the token is used to encrypt confidential data within the datastore itself" (`docs/datastore/backup-restore.md:10`). No export to a neutral format, no other-distro target. |
| k0s `backup`/`restore` | tar of `pki/`, etcd or kine/SQLite snapshot, `k0s.yaml`, manifests, helm config (`k0sproject/k0s` `docs/backup.md:10-18`) | Explicitly a same-distro restore: "aiming to back up and restore k0s managed parts" (`docs/backup.md:8`). Excludes PVs (`docs/backup.md:22`). Restore onto a different IP needs manual `etcd.peerAddress` edits. Output is a distro-private snapshot, not portable objects. |
| kubeadm -> k3s guides, community scripts | Typically `kubectl get -o yaml` loops plus re-apply (unverified; no authoritative source found) | Hand-rolled, no UID/ownerRef/status handling, no Secret/SA-token strategy, no PV story, no verification or rollback. |
| Velero (unverified, not fetched) | Backs up API objects through the API (`kubectl`-level), PVs via CSI snapshots/restic-kopia file-level | The closest in spirit and the proven shape: API-level, cross-distro. But needs object storage + a cluster-resident server + plugin per volume provider, is heavy for a 1 GiB VPS, and restores into a *running* target without node conversion. Not friendly for a single-box user; a useful design reference (what to skip, restore ordering, PV handling). |
| Rancher/SUSE tooling (unverified) | Rancher Backup operator = Rancher-managed CRs only | Tied to Rancher; not a k3s-to-other-distro tool. |
| etcd-level tools (`etcdctl`, auger) | Raw key dumps | Values are protobuf with k8s envelope (and possibly encrypted); needs the exact scheme. This is the datastore-conversion problem in section 3. |

Verdict: no tool provides a one-command, cross-distro, workload-preserving migration. Every distro-native tool is a same-distro snapshot; the only cross-distro precedent (Velero) is heavy. The gap is real, and the niche that fits u7s is "Velero-shaped semantics, kubectl-sized footprint".

## 2. State inventory

| State | How it moves (recommended) | Risk | How to verify |
|---|---|---|---|
| Namespaced/cluster API objects (Deployments, Services, ConfigMaps, Ingress, RBAC, ...) | API export (`kubectl get --raw` / typed GET + list-all-resources discovery), strip `metadata.{uid,resourceVersion,creationTimestamp,managedFields,selfLink}` and `status`; keep `ownerReferences` (old UIDs) and rewrite them on import (see the ownerRefs row and 2a); apply in dependency order | Server-assigned fields differ; built-in controllers (KCM) recreate their children, so skip those children (Pods, ReplicaSets, EndpointSlices, Job Pods) to avoid duplicates, and skip finished Jobs (with `status` stripped KCM would re-run them). Children of CR-owning operators are *imported* with remapped ownerRefs, not skipped: whether the operator regenerates them is not knowable. StatefulSet `volumeClaimTemplates` PVCs carry no ownerRef by default and are imported like any PVC (the recreated Pods reattach by name); with a `whenDeleted: Delete` retention policy they carry an ownerRef to the StatefulSet and are remapped | `kubectl get` object-count diff per kind; Deployments reach Available on target |
| CRDs and CRs | CRDs first, wait `Established`, then CRs | CR storage version, conversion webhooks, finalizers on CRs; operators re-reconcile on first sight | CRD `Established`, CR count diff, operator pod Ready |
| Secrets (incl. TLS, docker-registry) | API export, same-key `data` | Sensitive in transit and on disk (export file = secret material); k3s encrypts at rest only with `--secrets-encryption` but the API returns plaintext either way, so API export sidesteps the encryption-key coupling. `kubernetes.io/service-account-token` Secrets are not portable (bound to old signing key) | Byte-for-byte hash of each Secret `data`; export file written 0600, optionally piped through `age`/`gpg` (k0s's own pattern, `k0sproject/k0s` `docs/backup.md:85-114`) |
| ServiceAccount tokens | Do not move. Drop legacy SA-token Secrets; pods get projected tokens signed by the new issuer | Long-lived tokens stored *outside* the cluster (CI, external-secrets) stop working | Pod using in-cluster client works after restart; documented known break |
| ownerRefs / UIDs | UIDs are new on target (the apiserver overwrites any client-set `metadata.uid` on create). Every ownerReference, controller or not, is remapped by the two-pass algorithm in 2a. PV `spec.claimRef.uid` is remapped by the same map (2b) | A ref to an unresolved UID makes the target GC delete the dependent as orphaned, so an unresolvable ref is never written | Import report lists every dropped/rewritten ref; after import no object has an ownerRef whose UID is absent from the target |
| Finalizers | Policy in 2a: preserve those whose controller is migrated, strip and report the rest; objects mid-deletion are skipped and reported | Stripping silently disables external cleanup (operator finalizers on CRs, external resources); preserving with no controller leaves objects stuck on delete | Report lists every stripped finalizer (object, exact string) and every skipped mid-deletion object |
| PV data, PVs/PVCs, StorageClasses, CSIDrivers | PVs are **reused in place, data is not copied**: the migrated cluster re-points at the same backend volume. Order and guards in 2b. Node-local volumes (k3s `local-path`) on a same-host cutover are already on disk; PVs are recreated pointing at the same paths with the same node name | The riskiest class: a PV with `reclaimPolicy: Delete` plus PVC removal, or `k3s-uninstall.sh`, destroys the data. Hence the mandatory `Retain` guard and the uninstall guard in 2b | Quiesce (scale to 0) -> PV `Retain` verified on source -> import -> pod on target reads sentinel file with unchanged checksum |
| Cluster CA + certs | Do not carry. New cluster issues its own CA; kubeconfigs and node client certs are re-issued by join. Carrying the old CA is possible only for the on-disk k3s/k0s layout and buys little | Every external holder of the old kubeconfig/CA pin breaks (CI, GitOps agents) | New kubeconfig works; old one fails cleanly; report lists "re-distribute kubeconfig" |
| Node identity | Re-registered via Gate 6 `--join` CSR flow; node name reused, UID new. Node names and `topology.kubernetes.io/{zone,region}` / `kubernetes.io/hostname` labels must match the source, because PV `nodeAffinity` selects on them (2b) | Same-name node object already in imported set must not be imported (Nodes are excluded); a renamed node or missing zone label leaves node-affinity PVs unschedulable | `kubectl get nodes` Ready with the expected names and labels; every imported PV `nodeAffinity` matches at least one node |
| CNI/IPAM (flannel subnets) | Not moved. Pod CIDRs re-allocated by u7s node-ipam, Pods are recreated by drain | Pod IPs change; anything hardcoding Pod IPs breaks. Service-CIDR/pod-CIDR overlap with the old cluster if both live side by side | Pod-to-pod across nodes on target |
| Service ClusterIPs / NodePorts / LB IPs | **MVP:** preserve `spec.clusterIP` and `nodePort` on import. Both are client-settable on a stock create, so this needs no API fork and no UID continuity. u7s status: a preset clusterIP is accepted (`crates/apiserver/src/handlers/resource.rs:4886-4890` returns early when non-empty; a static-clusterIP create is exercised by the test near `resource.rs:23924`) and a preset nodePort is kept (`crates/apiserver/src/handlers/defaults.rs:936`), **but neither is reserved or validated**: the preset IP gets no allocator sentinel (`crates/apiserver/src/state.rs:1575` only reserves addresses it picks itself) and nodePorts have no cross-Service uniqueness or range check. Imports must therefore go in a single sequential pass before any new Service is created on target, and the bug is tracked as mayor-mpbip | If u7s's service CIDR differs from k3s's default 10.43.0.0/16 a preset clusterIP is out of range: the importer must detect this itself (u7s does not) and drop it so it re-allocates (DNS keeps working, hardcoded IPs break). Until mayor-mpbip lands, a Service created after import can be handed a preserved IP/nodePort. LB: k3s `servicelb` is a daemonset hostPort hack; u7s has no LB controller (ADR to confirm), so `type: LoadBalancer` imports as pending | Service count diff; ClusterIP/NodePort retained or reported-changed; no duplicate clusterIP/nodePort on target; DNS name resolves |
| Addons that differ (k3s traefik, servicelb, local-path, metrics-server, CoreDNS; k0s: konnectivity, kube-router/calico, metrics) | Detect by label `app.kubernetes.io/managed-by: Helm`/`objectset.rio.cattle.io` and k3s-owned `AddOn` CRs; exclude distro-managed objects from export. Report "your Ingresses assume traefik; u7s ships none" | Ingress objects import fine but nothing serves them; HelmChart CRs (k3s) become inert | Report is the verification: each excluded/changed addon listed with a suggested replacement |
| Workload runtime state (container images, logs, emptyDir) | Not moved; images re-pulled | Registry mirror/private-registry auth (`registries.yaml`) lives outside the API | Pods Running on target |

### 2a. ownerReference remap and finalizer policy

Non-controller ownerRefs exist on root objects too (a Secret owned by a cert-manager Certificate, a CR owned by another CR), so dropping refs with "regenerated children" is wrong. Import is a two-pass algorithm over an in-memory `old UID -> new UID` map (UID strings only, so it streams):

1. Build the owner graph from the export file (ref `uid` -> object). Order objects owners-first (topological); chains resolve in that order.
2. Pass 1: create each object in that order with `ownerReferences` rewritten from the map (the owner already exists, so its new UID is known), and record `old UID -> new UID` from the create response.
3. Cycles (A owns B owns A; legal, if rare): the members of a strongly-connected component are created in pass 1 with `ownerReferences` omitted; pass 2 PATCHes the rewritten refs onto them once every member has a new UID. Only SCC members take pass 2.
4. A ref whose owner is not in the export (skipped by rule, or already dangling on the source): the ref is dropped and listed in the report. If the skip was a *controller-regenerated owner*, the dependent is skipped too (transitive; it would be an orphan the target GC deletes). Otherwise the dependent is imported as a root. A ref to an unresolved UID is never written, because the target GC treats it as an absent owner and deletes the dependent.
5. `blockOwnerDeletion` and `controller` are preserved on rewritten refs.

Finalizers:

- **Mid-deletion objects** (`deletionTimestamp` set) are skipped and reported with their finalizers: a create cannot carry a deletionTimestamp, so importing would resurrect an object the user deleted; the pending cleanup stays on the source.
- **Preserve** finalizers whose controller is also being migrated. Built-in finalizers (`kubernetes.io/pvc-protection`, `kubernetes.io/pv-protection`, `foregroundDeletion`, `orphan`) are kept: KCM re-evaluates them. A custom finalizer is preserved when its domain matches the group of a CRD in the export or of an imported APIService/webhook-owning workload.
- **Strip and report** the rest (no matching controller in the export): each stripped finalizer is listed with object and exact string, so the operator can see which external cleanup is no longer guaranteed. `--keep-finalizers` preserves all (objects may then stick on delete until a controller appears). Nothing is stripped silently.

### 2b. Persistent volumes: reuse in place, no data copy

The operator direction is to reuse PVs as-is when the CSI driver (with its StorageClasses and referenced Secrets) is migrated. Rules, in order:

1. **Retain guard (mandatory, first).** Every in-scope PV must have `persistentVolumeReclaimPolicy: Retain` on the *source* before anything else runs; the tool refuses otherwise and lists the offenders. Why: with `Delete`, removing the PVC or tearing down the source makes the source's driver delete the backend volume. k3s's own `local-path` StorageClass is `reclaimPolicy: Delete` (`k3s-io/k3s` `manifests/local-storage.yaml:100`), so the default k3s case fails the guard until the operator patches the PVs.
2. **Order:** CSIDriver, StorageClass, and the Secrets they reference (CSI provisioner/node-publish secrets) first, then PV, then PVC, then workloads. This is in addition to the dependency order in section 6.
3. **VolumeAttachment objects are not migrated**; the target's attach-detach controller creates its own.
4. **claimRef remap.** `PV.spec.claimRef` carries the old PVC UID. PVs are created first with `claimRef.uid` cleared (name/namespace kept, which pre-binds the PV to that PVC by name); after the PVC is created, the new PVC UID from the two-pass map is patched into `claimRef.uid` if the binder has not already done it. A PV whose PVC is not exported is imported unbound (`claimRef` cleared, status `Available`) and reported.
5. **Node affinity.** PV `spec.nodeAffinity` and topology labels must match the new nodes: node names and zone labels need continuity (state inventory, node identity row).
6. **RWO sequencing.** The source detaches before u7s attaches: scale the consuming workloads to 0 on the source and wait for VolumeAttachment removal before starting them on target. Two attachments of an RWO volume corrupt it.
7. **k3s `local-path` (node-local hostPath).** The provisioner's default directory is `<data-dir>/storage`, i.e. `/var/lib/rancher/k3s/storage` (`k3s-io/k3s` `pkg/cli/server/server.go:410`, `filepath.Join(dataDir, "/storage")`; overridable by `--default-local-storage-path`, `pkg/cli/cmds/server.go:533`). On the MVP same-host cutover the data is already there: recreate the PVs (`local`/`hostPath` type) at the same paths with the same node name (affinity above); no copy. rsync remains only for cross-host moves of node-local volumes.
8. **Uninstall guard.** The k3s uninstall script it generates (`install.sh`, written as `${BIN_DIR}/k3s-uninstall.sh`) ends with `clean_mounted_directory ${K3S_DATA_DIR}` (`k3s-io/k3s` `install.sh:963`), which `rm -rf`s the data dir (`install.sh:937-957`), and the default storage path is inside it. Verified by reading the script at the pinned ref, not run. The migration must never invoke `k3s-uninstall.sh` (and refuses if the operator-supplied cutover plan does), or relocates `storage/` out of the data dir first. This is a loud guard: preflight prints the storage path and the uninstall hazard and requires an explicit acknowledgement.

## 3. Mechanism comparison

### 3a. kine->u7s datastore conversion (concrete)

kine's SQLite table (`k3s-io/kine` `pkg/drivers/sqlite/sqlite.go:26`):

```
kine(id INTEGER PK AUTOINCREMENT, name TEXT, created INT, deleted INT,
     create_revision INT, prev_revision INT, lease INT, value BLOB, old_value BLOB)
```

It is an etcd-v3 *revision log*: every write is a new row, `id` is the global revision, `name` is the etcd key (e.g. `/registry/pods/ns/pod`), `prev_revision` links versions, `deleted=1` is a tombstone, `lease` is a TTL id (Events, Leases), plus a `compact_rev_key` row holding the compaction floor (`pkg/drivers/generic/generic.go:42,261`). Current state = for each `name`, the row with `MAX(id)` and `deleted=0`.

u7s schema (`crates/store/src/sqlite.rs:428-448`):

```
objects(key TEXT PK, value BLOB, revision INTEGER, ns TEXT, obj_name TEXT) WITHOUT ROWID
meta(key, value)   -- 'revision' counter
```

One *current-state* row per key (no history; watch resumption is the 1000-event in-memory ring, `sqlite-over-lmdb.md`), key format identical to etcd (`/registry/...`), value is **JSON with `metadata.resourceVersion` stamped to the row revision** (`sqlite.rs:1140-1151`).

What a converter must translate:

| Aspect | kine | u7s | Translation |
|---|---|---|---|
| History | all revisions | latest only | take `MAX(id)` per name, drop `deleted` |
| Revision | `id` | `revision` + `meta.revision` | can preserve exactly (`revision = id`, `meta.revision = MAX(id)`); gaps are legal |
| Value encoding | etcd bytes = k8s protobuf envelope (`k8s\0` magic) for built-ins, JSON for CRs. **Verified:** k3s passes no `--storage-media-type` (a search of `k3s-io/k3s` for `storage-media-type` returns 0 hits; the only storage flag set is `storage-backend=etcd3`, `pkg/daemons/control/server.go`), so kube-apiserver's default (protobuf for built-ins) applies. Optionally AES-CBC/secretbox encrypted if `--secrets-encryption` | JSON only | needs a full protobuf-to-JSON decoder for every built-in kind. u7s already has prost types (`proto-typing.md`) but they decode *wire requests*, not an arbitrary versioned stored-object set incl. old API versions; plus a decrypt path keyed on the k3s token |
| resourceVersion in body | not stored in the value (etcd injects it from revision at read time) | must be stamped in JSON | stamp `id` |
| UID / creationTimestamp | in body | in body | preserved for free (they're in the value) |
| Leases/TTL | `lease` column, kine reaper deletes | none | Events: drop; node Leases: drop (re-created) |
| `ns`, `obj_name` | derived from key | columns + indexes | derive by key split, *not* a pure copy (the indexed `ns` comes from the object body, `shard_key` doc) |
| Distro-private keys | k3s bootstrap data, `/bootstrap/*`, k3s add-on state | n/a | filter |

What breaks / is preserved:

- **Preserved only if converted:** UIDs, creationTimestamps, resourceVersions, generations, ServiceAccount token Secrets (still invalid: signing key differs unless the SA key is also carried). ClusterIPs/NodePorts and ownerRef/claimRef integrity are *not* in this list: API import preserves the former (section 2) and the UID remap preserves the latter (2a, 2b). A converted cluster is "the same cluster": kubelets re-join with no workload restarts *if* the CA, SA signing key and node client certs are also carried.
- **Watchers/controllers:** the u7s ring buffer is empty on start; any client with a pre-conversion resourceVersion gets 410 Gone -> relist, the standard recovery (`sqlite-over-lmdb.md` Consequences). If revision is preserved, a post-conversion relist at RV >= old max is monotonic. If NOT preserved (API import), every client relists with a *new, lower or unrelated* RV; informers do not care (they relist on 410 or on reconnect to a new server), but a client that persists RVs across restarts (rare: some operators/GitOps agents checkpointing) would see an RV from the future/past and must be handled as 410. So RV/UID loss mostly hurts: (1) owner-reference graphs (resolved by the remap in 2a), (2) things that store UIDs externally (some CSI snapshot handles, external-dns TXT owner IDs, Argo CD app tracking by annotation not UID; low risk), (3) audit/provenance.
- **Coupling cost:** the converter needs kine's schema (stable but internal), the k8s protobuf storage format *per API group version*, the encryption config, and k3s-vs-k0s differences (k0s default is etcd, which has *no* SQLite file: k0s+etcd needs an etcd snapshot reader, a third, different format, or a running etcd to read through; k0s+kine/SQLite matches k3s). The u7s-store write side is also internal and moves (the `objects` shape is pre-alpha and changes freely), so the converter would be a maintained liability on both ends.
- **Reverse direction (u7s -> k3s/k0s):** writing kine rows means producing *protobuf-encoded* values (or accepting JSON values: the k3s apiserver can read JSON in etcd/kine since decoders recognise both, **unverified**) with consistent `id`/`prev_revision` chains and `compact_rev_key`; fragile, and k3s's own bootstrap (token-derived encryption, `/bootstrap`) must be reconciled. API import is trivially symmetric; datastore write is not.

### 3b. Comparison

| | API export/import | Datastore conversion | Hybrid (API import + a u7s-only UID-preserving write path) |
|---|---|---|---|
| Source coupling | `kubectl`-level; works for k3s sqlite/etcd/external DB, k0s etcd/kine, EKS, anything | kine SQLite only; separate path per k0s-etcd | API for objects; PKI file layout of k3s/k0s for CA/SA key |
| UID/RV preserved | no (UIDs remapped, 2a/2b) | yes | UIDs only, via the u7s-only path |
| ClusterIP/NodePort preserved | yes (client-settable on a stock create; u7s gap: mayor-mpbip) | yes | yes (same as API) |
| Secrets-at-rest | sidestepped (API returns plaintext) | must decrypt | sidestepped |
| Reverse (off-ramp) | symmetric, same tool | hard (section above) | asymmetric |
| Upstream-shape pressure | none; uses only the public API | pulls u7s toward mirroring etcd-style revision logs and internals | needs a u7s-only "preserve UID" create path = an API fork |
| Source safety | read-only against source | needs a stopped source or a consistent copy | read-only mostly |
| Failure blast radius | per-object, resumable, reportable | all-or-nothing database | per-object |
| Cost | M | L + permanent maintenance | M-L |

ClusterIP and NodePort preservation is *not* a differentiator: both are ordinary spec fields, so plain API import has them in the MVP. The only thing hybrid adds is UID continuity. A stock apiserver ignores a client-supplied `metadata.uid` on create (it overwrites it with a fresh one), so UID-preserving import cannot be done through a standard create at all and would need a u7s-private write path, i.e. an API fork. Its benefit is limited to external holders of UIDs (CSI snapshot handles, external-dns owner IDs), since the ownerRef/claimRef remap already removes the in-cluster need. Hybrid is rejected on UID alone.

**Recommendation: API export/import.** Make it a *standalone* tool (see 6), not a u7s-apiserver feature, so it needs nothing from the u7s API beyond stock behaviour.

### 3c. Node conversion and rollback

- **Drain-and-rejoin (recommended).** Per node: `kubectl drain`, stop `k3s-agent`/`k0sworker`, remove distro state, run `install.sh --join` (Gate 6 CSR flow), `kubectl uncordon`. Real upstream kubelet means the node reappears as a normal node; CRI-O vs k3s's containerd: images are re-pulled, no runtime state carries. Cost: one drain window per node, Pods re-created.
- **In-place conversion.** Swap control-plane while kubelets keep running needs the kubelets to trust the new CA and apiserver address: the old kubelet client cert is signed by the *old* CA, so either carry the CA (datastore/PKI path) or re-bootstrap each kubelet (`kubelet.conf` replace + restart) which is nearly the same work as a rejoin without the drain safety. k3s's agent is a wrapper process (kubelet inside the `k3s` binary), so "keep the kubelet, change the control plane" is not even available there; k0s workers run a vanilla kubelet but under k0s supervision. Net: not worth it.
- **Rollback.** Source cluster is never modified until the operator opts in node by node. The recommended order is: (1) fresh u7s control plane on a *new* host (or same host with separate ports, but RAM on the 1 GiB target makes side-by-side hard: documented risk), (2) import, (3) verify, (4) per-node convert. Until the last node converts, rollback = re-join converted nodes back to the old distro with its own agent installer. Single-node-on-one-VPS cannot run both control planes comfortably: there the rollback artifact is the *export file* + the untouched `/var/lib/rancher/k3s` (or `/var/lib/k0s`) directory, which the converter renames, never deletes; restoring = stop u7s, rename back, start k3s. Because the db dir is never written, this is as safe as the distro's own SQLite state.

## 4. The off-ramp (u7s -> k3s/k0s)

An export tool that reads a *stock* Kubernetes API and writes a neutral manifest set works against u7s as it does against k3s, so the off-ramp is the same code path with source=u7s, target=k3s/k0s (target side is just `kubectl apply`). It is a trust signal precisely because it needs nothing u7s-specific. What it implies for u7s:

- Keep the API upstream-shaped: discovery, list/watch, server-side field semantics. Anything u7s adds that is not expressible as ordinary objects is *off-ramp debt* and must be listed by the tool ("u7s-specific, will not transfer").
- The store must remain readable without u7s: `sqlite3 state.db` plus JSON values (the ADR's debugging argument) is already an off-ramp of last resort; a documented `sqlite3` one-liner is a weaker but free fallback and should be mentioned in the ADR, not built.
- Add a CI check that the export tool runs against a u7s cluster and the import applies cleanly into a vanilla (kind or k3s) cluster: this is a continuous conformance proxy for "we have not forked the API".

## 5. Dependencies

- **Gate 6 (audit PR #1792, mayor-3kp5u).** Node conversion *is* the `--join` flow. Dependencies from that audit: (a) join tokens never expire/single-use is false today (gap 1): a migration that mints one token per converted node would leave permanent credentials, so token hardening (2b) should precede or ship with the node-conversion step; (b) mint restarts the apiserver and needs node name/IP at mint time (gaps 2, 3): a fleet conversion wants the cluster-wide artifact (2c); (c) flannel `--iface` is baked from the control plane (gap 5): mixed-NIC k3s fleets (the very users migrating) hit this; (d) no automated two-VM `install.sh` e2e exists (gap 6): the migration verification rig in section 7 *is* that rig plus a source cluster, so build them together; (e) CA: new CA => all external kubeconfigs invalidated, so the CA/rotation answer from Gate 6 item 3 should say so.
- **Distribution (Gate 6 item 1).** `/install.sh` returns 404 until a stable tag exists; the migration tool should ship in the same tarball and be fetched the same way, so it cannot be the first thing to precede the stable tag.
- **Release gate** (bd memory `release-gate-1gib-burst-128mib-is-aspiration`: 1 GiB burst is the gate, 128 MiB aspirational for control-plane-node host processes). Consequences: the export/import tool must stream (never hold a whole cluster in memory; per-kind list with pagination `limit`/`continue`), and the migration must work on a 1 GiB VPS where k3s (typically 500+ MiB resident) and u7s cannot be co-resident under load: the single-host path is *sequential* (export -> stop k3s -> install u7s -> import), not side-by-side. Peak memory of the tool and of u7s while ingesting a bulk import must be measured against the gate (not measured here).
- **Not dependent:** CA rotation tooling, metrics-server, agent-facing install.

## 6. Phased plan

| Phase | Scope | Size | Gate |
|---|---|---|---|
| 0 (this doc) | Decide mechanism and decisions 1-10 | done | operator |
| 1 MVP: single-node k3s -> u7s | `u7s-migrate export` (read-only against source via kubeconfig): discovery of all served kinds, preflight guards (every in-scope PV `Retain`; uninstall-script hazard, 2b), skip list (distro-owned, Events, Endpoints/EndpointSlices of Services with selectors, children of built-in controllers, finished Jobs, mid-deletion objects, Nodes, leases, VolumeAttachments, SA-token Secrets, `kube-*` addon namespaces), strip server fields, write one NDJSON/tar file in dependency order (CRDs, namespaces, cluster RBAC, CSIDriver/StorageClass/their Secrets, PV, PVC, then workloads) plus a `report.md` of everything skipped/changed/stripped. `u7s-migrate import` applies it against a fresh u7s with retry-until-Established, runs the two-pass ownerRef/claimRef remap and finalizer policy (2a/2b), preserves ClusterIP/NodePort when valid (needs mayor-mpbip to be safe). PVs are reused in place; no data copy on the same-host cutover | M-L | none beyond existing install; mayor-mpbip for safe ClusterIP/NodePort |
| 2 | Multi-node conversion: drain-and-rejoin runbook + `--join` hardening (2b/2c) | M | Gate 6 token work |
| 3 | k0s source (etcd and kine) via the same API path (no code change expected; verification only) and u7s -> k3s/k0s off-ramp tests | S | Phase 1 |
| 4 | Cross-host moves of node-local volumes: optional rsync helper behind an explicit flag (same-host cutover needs none) | M | D5 |

Tool placement (D7): a subcommand of the existing `u7s` binary (zero new artifacts; zero-argument defaults: `u7s migrate export --kubeconfig ... > file`) vs. a separate binary. Prefer subcommand; the kubectl-level client must not link the apiserver crate.

### Lima verification design (design only; not run)

Two Lima VMs per scenario, driven by a new script under `scripts/e2e-migrate/` (name TBD, modelled on the planned two-node rig):

1. VM-A: install k3s (pinned version, SQLite default). Deploy a fixture: Deployment+Service+ConfigMap+Secret (random bytes, hash recorded), a StatefulSet with a local-path PVC holding a sentinel file with checksum (PV patched to `Retain`), a CRD + CR + a Secret owned by the CR (non-controller ownerRef) + a CR with a custom finalizer, a trivial controller-less operator-lookalike, an Ingress (traefik), RBAC, a CronJob.
2. `u7s migrate export` against VM-A's kubeconfig; fetch the file to the host.
3. VM-B: fresh u7s via the real `install.sh`; `import` on the same host (no data copy); assert: preflight refuses while a PV is `Delete`, object-count diff per kind equals the report, Deployment Available, Secret `data` hashes equal, sentinel file checksum unchanged and readable by the migrated StatefulSet, CR present, CR-owned Secret's ownerRef UID equals the new CR UID, finalizer policy matches the report, no dangling ownerRef, ClusterIP/NodePort preserved or reported, `report.md` lists traefik/servicelb exclusions.
4. Multi-node: add VM-C as a second k3s agent before export; after import, convert it with `install.sh --join`; assert node Ready, Pods schedule on it, cross-node ClusterIP works. This reuses the Gate 6 e2e assertions.
5. Rollback: stop u7s on VM-B, start k3s from the untouched DB dir; assert original workloads Ready and the sentinel checksum unchanged. The harness must never call `k3s-uninstall.sh` (2b rule 8).
6. Off-ramp: export from VM-B (u7s), import into a third vanilla k3s VM; assert the same fixture appears.
7. k0s variants of step 1 (kine/SQLite and default etcd) for Phase 3.
8. Memory: record peak RSS of the tool and u7s during import against the release gate.

Failure to compare: Secret hashes and PV checksums are the load-bearing checks (silent-corruption classes).

## 7. Operator decisions

1. **Mechanism: settled by the operator as API-based export/import.** Datastore conversion and hybrid are rejected: they add only UID/RV continuity (ClusterIP/NodePort are preserved by plain API import), couple to kine/protobuf/encryption internals and cannot serve as the off-ramp.
2. **Is UID/RV loss acceptable?** Yes if documented: kubectl-visible identity changes (new UIDs), external UID references break, informers relist normally; in-cluster references (ownerRefs, PV claimRef) are remapped. Option: refuse to migrate if the exporter sees UID-dependent objects (VolumeSnapshotContents, some operators). **Recommend accept + report.**
3. **MVP scope.** (a) single-node k3s -> u7s, API only, PVs reused in place behind the `Retain` guard, ClusterIP/NodePort preserved (recommended); (b) also automate cross-host volume copy; (c) also node conversion. Larger MVPs delay a verifiable release. New dependency for (a): mayor-mpbip (u7s does not reserve or validate preset clusterIP/nodePort).
4. **Finalizer policy.** (a) preserve those whose controller is migrated, strip and report the rest, skip mid-deletion objects (recommended); (b) preserve all (`--keep-finalizers`; objects may stick on delete); (c) strip all and report (silently disables external cleanup if the report is ignored).
5. **Off-ramp in the same release.** (a) same tool, source=u7s, in Phase 1 (cost ~S, it is the same code); (b) later. **Recommend (a)** as the trust signal.
6. **PV policy: reuse in place plus Retain guard (operator direction).** The tool refuses unless every in-scope PV is `Retain` on the source and never invokes `k3s-uninstall.sh` (loud guard, 2b). Open sub-choice: when a PV is `Delete`, refuse (recommended) or offer `--patch-retain` to patch it on the source (modifies the source; breaks the "source never modified" property for that field). Cross-host node-local copy (rsync helper) stays optional; CSI-snapshot integration (Velero-class) is not recommended on a 1 GiB target.
7. **Single-host sequencing.** Accept sequential cutover only (stop k3s, install u7s, import) given the RAM budget, with the source DB dir preserved as the rollback; or require a second host for side-by-side. **Recommend sequential with preserved dir.**
8. **Packaging.** `u7s migrate` subcommand in the existing binary (recommended) vs separate `u7s-migrate` artifact vs a script. Decide before any code to keep the north star's small-knob surface.
9. **Addon policy.** Report-only (recommended: tell the user traefik/servicelb/local-path have no u7s equivalent) vs translate (e.g. offer a traefik manifest). Translating grows scope into the product surface; **recommend report-only.**
10. **Ordering vs Gate 6.** Start the MVP now (API-only, no join dependency) or after join-token hardening. **Recommend start MVP now**; node conversion (Phase 2) waits for Gate 6 hardening.
