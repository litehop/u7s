# Migration onto and off u7s from/to k3s and k0s

Bead: mayor-ffgal
Date: 2026-10-15
Status: Phase 1 (read-only research); nothing here is built until the operator decides.

**Answer: build an API-level export/import tool (`u7s` side, kubectl-only, no k3s/k0s-internals coupling) as the one migration mechanism for both directions, MVP = single-node k3s -> u7s with workloads, Secrets, CRDs and PV data intact and a one-command rollback because the source is never modified; a kine->u7s datastore converter is rejected because it buys only resourceVersion/UID continuity that no real controller needs, at the cost of a protobuf decoder, an encryption-at-rest decoder and tight coupling to two internal schemas.**

Evidence discipline: kine/k0s/k3s docs below were read via `gh api` and cached in `temp/research/` (gitignored: `kine-generic.go`, `kine-sqlite.go`, `k0s-backup.md`, `k3s-backup-restore.md`, `k3s-ha-embedded.md`). Velero and the Rancher/community-script landscape were NOT fetched (no WebFetch); those rows are from prior knowledge and marked "unverified". Nothing was run on Lima; the verification design in section 7 is a design only.

## 1. Existing-tooling survey

| Tool | What it does | Why it is not a friendly onto/off-u7s path |
|---|---|---|
| k3s datastore docs | SQLite backup = copy `/var/lib/rancher/k3s/server/db/`; SQLite -> embedded etcd by restarting with `--cluster-init` (`k3s-ha-embedded.md:66`); etcd via `k3s etcd-snapshot` | All paths stay inside the k3s/kine family. Restoring requires the same server token because "the token is used to encrypt confidential data within the datastore itself" (`k3s-backup-restore.md:10`). No export to a neutral format, no other-distro target. |
| k0s `backup`/`restore` | tar of `pki/`, etcd or kine/SQLite snapshot, `k0s.yaml`, manifests, helm config (`k0s-backup.md:11-18`) | Explicitly a same-distro restore: "aiming to back up and restore k0s managed parts". Excludes PVs. Restore onto a different IP needs manual `etcd.peerAddress` edits. Output is a distro-private snapshot, not portable objects. |
| kubeadm -> k3s guides, community scripts | Typically `kubectl get -o yaml` loops plus re-apply (unverified; no authoritative source found) | Hand-rolled, no UID/ownerRef/status handling, no Secret/SA-token strategy, no PV story, no verification or rollback. |
| Velero (unverified, not fetched) | Backs up API objects through the API (`kubectl`-level), PVs via CSI snapshots/restic-kopia file-level | The closest in spirit and the proven shape: API-level, cross-distro. But needs object storage + a cluster-resident server + plugin per volume provider, is heavy for a 1 GiB VPS, and restores into a *running* target without node conversion. Not friendly for a single-box user; a useful design reference (what to skip, restore ordering, PV handling). |
| Rancher/SUSE tooling (unverified) | Rancher Backup operator = Rancher-managed CRs only | Tied to Rancher; not a k3s-to-other-distro tool. |
| etcd-level tools (`etcdctl`, auger) | Raw key dumps | Values are protobuf with k8s envelope (and possibly encrypted); needs the exact scheme. This is the datastore-conversion problem in section 3. |

Verdict: no tool provides a one-command, cross-distro, workload-preserving migration. Every distro-native tool is a same-distro snapshot; the only cross-distro precedent (Velero) is heavy. The gap is real, and the niche that fits u7s is "Velero-shaped semantics, kubectl-sized footprint".

## 2. State inventory

| State | How it moves (recommended) | Risk | How to verify |
|---|---|---|---|
| Namespaced/cluster API objects (Deployments, Services, ConfigMaps, Ingress, RBAC, ...) | API export (`kubectl get --raw` / typed GET + list-all-resources discovery), strip `metadata.{uid,resourceVersion,creationTimestamp,managedFields,selfLink,ownerReferences->re-map}` and `status`, apply in dependency order | Server-assigned fields differ; controllers recreate children, so export only *roots* (objects without a controller ownerRef) to avoid duplicate Pods/RS/EndpointSlices | `kubectl get` object-count diff per kind; Deployments reach Available on target |
| CRDs and CRs | CRDs first, wait `Established`, then CRs | CR storage version, conversion webhooks, finalizers on CRs; operators re-reconcile on first sight | CRD `Established`, CR count diff, operator pod Ready |
| Secrets (incl. TLS, docker-registry) | API export, same-key `data` | Sensitive in transit and on disk (export file = secret material); k3s encrypts at rest only with `--secrets-encryption` but the API returns plaintext either way, so API export sidesteps the encryption-key coupling. `kubernetes.io/service-account-token` Secrets are not portable (bound to old signing key) | Byte-for-byte hash of each Secret `data`; export file written 0600, optionally piped through `age`/`gpg` (k0s's own pattern, `k0s-backup.md:80`) |
| ServiceAccount tokens | Do not move. Drop legacy SA-token Secrets; pods get projected tokens signed by the new issuer | Long-lived tokens stored *outside* the cluster (CI, external-secrets) stop working | Pod using in-cluster client works after restart; documented known break |
| ownerRefs / UIDs / finalizers | UIDs are new on target; ownerRefs only exist for controller-created children, which are regenerated, so they are dropped with the children. Finalizers on roots: strip on import (record in report) | Orphan/GC surprises if a child is imported without its owner; finalizer on a root blocks later delete | Import report lists stripped finalizers; no object with dangling ownerRef after import |
| PV data, PVs/PVCs, StorageClasses | PV data is separate: k3s `local-path` data is a host directory (`/var/lib/rancher/k3s/storage/pvc-*`); copy files, recreate PVC bound to a pre-created hostPath/local PV pointing at the copied dir. Network PVs (NFS/CSI) are re-referenced as-is | The riskiest class: silent data loss/corruption (live DBs copied while writing). u7s ships no local-path provisioner by default (to be confirmed per `manifests/`), so StorageClass strategy is an operator decision | Quiesce (scale to 0) -> rsync -> checksum tree -> pod reads sentinel file |
| Cluster CA + certs | Do not carry. New cluster issues its own CA; kubeconfigs and node client certs are re-issued by join. Carrying the old CA is possible only for the on-disk k3s/k0s layout and buys little | Every external holder of the old kubeconfig/CA pin breaks (CI, GitOps agents) | New kubeconfig works; old one fails cleanly; report lists "re-distribute kubeconfig" |
| Node identity | Re-registered via Gate 6 `--join` CSR flow; node name reused, UID new | Same-name node object already in imported set must not be imported (Nodes are excluded) | `kubectl get nodes` Ready with the expected names |
| CNI/IPAM (flannel subnets) | Not moved. Pod CIDRs re-allocated by u7s node-ipam, Pods are recreated by drain | Pod IPs change; anything hardcoding Pod IPs breaks. Service-CIDR/pod-CIDR overlap with the old cluster if both live side by side | Pod-to-pod across nodes on target |
| Service ClusterIPs / NodePorts / LB IPs | Preserve `spec.clusterIP` and `nodePort` on import where non-colliding (both are plain spec fields u7s's allocator must accept when pre-set); u7s's service CIDR may differ from k3s's default 10.43.0.0/16 | If CIDR differs, a preset clusterIP is invalid -> drop and let it re-allocate (DNS keeps working, hardcoded IPs break). LB: k3s `servicelb` is a daemonset hostPort hack; u7s has no LB controller (ADR to confirm), so `type: LoadBalancer` imports as pending | Service count diff; ClusterIP/NodePort retained or reported-changed; DNS name resolves |
| Addons that differ (k3s traefik, servicelb, local-path, metrics-server, CoreDNS; k0s: konnectivity, kube-router/calico, metrics) | Detect by label `app.kubernetes.io/managed-by: Helm`/`objectset.rio.cattle.io` and k3s-owned `AddOn` CRs; exclude distro-managed objects from export. Report "your Ingresses assume traefik; u7s ships none" | Ingress objects import fine but nothing serves them; HelmChart CRs (k3s) become inert | Report is the verification: each excluded/changed addon listed with a suggested replacement |
| Workload runtime state (container images, logs, emptyDir) | Not moved; images re-pulled | Registry mirror/private-registry auth (`registries.yaml`) lives outside the API | Pods Running on target |

## 3. Mechanism comparison

### 3a. kine->u7s datastore conversion (concrete)

kine's SQLite table (`kine-sqlite.go:26-43`):

```
kine(id INTEGER PK AUTOINCREMENT, name TEXT, created INT, deleted INT,
     create_revision INT, prev_revision INT, lease INT, value BLOB, old_value BLOB)
```

It is an etcd-v3 *revision log*: every write is a new row, `id` is the global revision, `name` is the etcd key (e.g. `/registry/pods/ns/pod`), `prev_revision` links versions, `deleted=1` is a tombstone, `lease` is a TTL id (Events, Leases), plus a `compact_rev_key` row holding the compaction floor (`generic.go:42`). Current state = for each `name`, the row with `MAX(id)` and `deleted=0`.

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
| Value encoding | etcd bytes = k8s protobuf envelope (`k8s\0` magic) for built-ins, JSON for CRs (default apiserver storage media type; **unverified for k3s**, k3s does not document overriding it), optionally AES-CBC/secretbox encrypted if `--secrets-encryption` | JSON only | needs a full protobuf-to-JSON decoder for every built-in kind. u7s already has prost types (`proto-typing.md`) but they decode *wire requests*, not an arbitrary versioned stored-object set incl. old API versions; plus a decrypt path keyed on the k3s token |
| resourceVersion in body | not stored in the value (etcd injects it from revision at read time) | must be stamped in JSON | stamp `id` |
| UID / creationTimestamp | in body | in body | preserved for free (they're in the value) |
| Leases/TTL | `lease` column, kine reaper deletes | none | Events: drop; node Leases: drop (re-created) |
| `ns`, `obj_name` | derived from key | columns + indexes | derive by key split, *not* a pure copy (the indexed `ns` comes from the object body, `shard_key` doc) |
| Distro-private keys | k3s bootstrap data, `/bootstrap/*`, k3s add-on state | n/a | filter |

What breaks / is preserved:

- **Preserved if converted:** UIDs, creationTimestamps, ownerRef integrity, resourceVersions, generations, ServiceAccount token Secrets (still invalid: signing key differs unless the SA key is also carried), ClusterIPs/NodePorts. A converted cluster is "the same cluster": kubelets re-join with no workload restarts *if* the CA, SA signing key and node client certs are also carried.
- **Watchers/controllers:** the u7s ring buffer is empty on start; any client with a pre-conversion resourceVersion gets 410 Gone -> relist, the standard recovery (`sqlite-over-lmdb.md` Consequences). If revision is preserved, a post-conversion relist at RV >= old max is monotonic. If NOT preserved (API import), every client relists with a *new, lower or unrelated* RV; informers do not care (they relist on 410 or on reconnect to a new server), but a client that persists RVs across restarts (rare: some operators/GitOps agents checkpointing) would see an RV from the future/past and must be handled as 410. So RV/UID loss mostly hurts: (1) owner-reference graphs if only part of the objects are imported (mitigated by importing roots only), (2) things that store UIDs externally (some CSI snapshot handles, external-dns TXT owner IDs, Argo CD app tracking by annotation not UID; low risk), (3) audit/provenance.
- **Coupling cost:** the converter needs kine's schema (stable but internal), the k8s protobuf storage format *per API group version*, the encryption config, and k3s-vs-k0s differences (k0s default is etcd, which has *no* SQLite file: k0s+etcd needs an etcd snapshot reader, a third, different format, or a running etcd to read through; k0s+kine/SQLite matches k3s). The u7s-store write side is also internal and moves (the `objects` shape is pre-alpha and changes freely), so the converter would be a maintained liability on both ends.
- **Reverse direction (u7s -> k3s/k0s):** writing kine rows means producing *protobuf-encoded* values (or accepting JSON values: the k3s apiserver can read JSON in etcd/kine since decoders recognise both, **unverified**) with consistent `id`/`prev_revision` chains and `compact_rev_key`; fragile, and k3s's own bootstrap (token-derived encryption, `/bootstrap`) must be reconciled. API import is trivially symmetric; datastore write is not.

### 3b. Comparison

| | API export/import | Datastore conversion | Hybrid (API for roots + carry CA/SA key/UIDs by direct write) |
|---|---|---|---|
| Source coupling | `kubectl`-level; works for k3s sqlite/etcd/external DB, k0s etcd/kine, EKS, anything | kine SQLite only; separate path per k0s-etcd | API for objects; PKI file layout of k3s/k0s for CA/SA key |
| UID/RV preserved | no | yes | partially (UIDs only via a privileged import path u7s would have to expose; cutting against "conform to upstream API") |
| Secrets-at-rest | sidestepped (API returns plaintext) | must decrypt | sidestepped |
| Reverse (off-ramp) | symmetric, same tool | hard (section above) | asymmetric |
| Upstream-shape pressure | none; uses only the public API | pulls u7s toward mirroring etcd-style revision logs and internals | needs a u7s-only "preserve UID" create path = an API fork |
| Source safety | read-only against source | needs a stopped source or a consistent copy | read-only mostly |
| Failure blast radius | per-object, resumable, reportable | all-or-nothing database | per-object |
| Cost | M | L + permanent maintenance | M-L |

Hybrid's only gain over API export is UID continuity and non-regenerated node certs; its price is a u7s-private write path that accepts client-supplied `metadata.uid`, which is the kind of divergence the project avoids (upstream rejects client-set UID on create unless the request comes through restore-type tooling). Rejected.

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
| 0 (this doc) | Decide mechanism and decisions 1-9 | done | operator |
| 1 MVP: single-node k3s -> u7s | `u7s-migrate export` (read-only against source via kubeconfig): discovery of all served kinds, skip list (distro-owned, Events, Endpoints/EndpointSlices of Services with selectors, children with controller ownerRef, Nodes, leases, SA-token Secrets, `kube-*` addon namespaces), strip server fields, write one NDJSON/tar file in dependency order (CRDs, namespaces, cluster RBAC/SC, then namespaced) plus an `report.md` of everything skipped/changed. `u7s-migrate import` applies it against a fresh u7s with retry-until-Established, preserves ClusterIP/NodePort when valid. PV data: documented rsync recipe for local-path dirs, not automated | M-L | none beyond existing install |
| 2 | Multi-node conversion: drain-and-rejoin runbook + `--join` hardening (2b/2c) | M | Gate 6 token work |
| 3 | k0s source (etcd and kine) via the same API path (no code change expected; verification only) and u7s -> k3s/k0s off-ramp tests | S | Phase 1 |
| 4 | PV automation: local-path directory copy helper, optional, behind explicit flag | M | D5 |

Tool placement (D7): a subcommand of the existing `u7s` binary (zero new artifacts; zero-argument defaults: `u7s migrate export --kubeconfig ... > file`) vs. a separate binary. Prefer subcommand; the kubectl-level client must not link the apiserver crate.

### Lima verification design (design only; not run)

Two Lima VMs per scenario, driven by a new script under `scripts/e2e-migrate/` (name TBD, modelled on the planned two-node rig):

1. VM-A: install k3s (pinned version, SQLite default). Deploy a fixture: Deployment+Service+ConfigMap+Secret (random bytes, hash recorded), a StatefulSet with a local-path PVC holding a sentinel file with checksum, a CRD + CR + a trivial controller-less operator-lookalike, an Ingress (traefik), RBAC, a CronJob.
2. `u7s migrate export` against VM-A's kubeconfig; fetch the file to the host.
3. VM-B: fresh u7s via the real `install.sh`; `import`; rsync PV dir; assert: object-count diff per kind equals the report, Deployment Available, Secret `data` hashes equal, sentinel file readable by the migrated StatefulSet, CR present, ClusterIP/NodePort preserved or reported, `report.md` lists traefik/servicelb exclusions.
4. Multi-node: add VM-C as a second k3s agent before export; after import, convert it with `install.sh --join`; assert node Ready, Pods schedule on it, cross-node ClusterIP works. This reuses the Gate 6 e2e assertions.
5. Rollback: stop u7s on VM-B, start k3s from the untouched DB dir; assert original workloads Ready.
6. Off-ramp: export from VM-B (u7s), import into a third vanilla k3s VM; assert the same fixture appears.
7. k0s variants of step 1 (kine/SQLite and default etcd) for Phase 3.
8. Memory: record peak RSS of the tool and u7s during import against the release gate.

Failure to compare: Secret hashes and PV checksums are the load-bearing checks (silent-corruption classes).

## 7. Operator decisions

1. **Mechanism.** (a) API export/import only; (b) datastore conversion; (c) hybrid. Trade-off: (b)/(c) preserve UID/RV continuity but couple to kine/protobuf/encryption internals and cannot serve as the off-ramp. **Recommend (a).**
2. **Is UID/RV loss acceptable?** Yes if documented: kubectl-visible identity changes (new UIDs), external UID references break, informers relist normally. Option: refuse to migrate if the exporter sees UID-dependent objects (VolumeSnapshotContents, some operators). **Recommend accept + report.**
3. **MVP scope.** (a) single-node k3s -> u7s, API only, PV manual (recommended); (b) also automate PV copy; (c) also node conversion. Larger MVPs delay a verifiable release; PV automation is where data loss happens, so keep manual with a checksum recipe first.
4. **Off-ramp in the same release.** (a) same tool, source=u7s, in Phase 1 (cost ~S, it is the same code); (b) later. **Recommend (a)** as the trust signal.
5. **PV data policy.** (a) docs only (rsync recipe); (b) helper for local-path directories; (c) CSI-snapshot integration (Velero-class; not recommended on a 1 GiB target). **Recommend (a) then (b).**
6. **Single-host sequencing.** Accept sequential cutover only (stop k3s, install u7s, import) given the RAM budget, with the source DB dir preserved as the rollback; or require a second host for side-by-side. **Recommend sequential with preserved dir.**
7. **Packaging.** `u7s migrate` subcommand in the existing binary (recommended) vs separate `u7s-migrate` artifact vs a script. Decide before any code to keep the north star's small-knob surface.
8. **Addon policy.** Report-only (recommended: tell the user traefik/servicelb/local-path have no u7s equivalent) vs translate (e.g. offer a traefik manifest). Translating grows scope into the product surface; **recommend report-only.**
9. **Ordering vs Gate 6.** Start the MVP now (API-only, no join dependency) or after join-token hardening. **Recommend start MVP now**; node conversion (Phase 2) waits for Gate 6 hardening.
