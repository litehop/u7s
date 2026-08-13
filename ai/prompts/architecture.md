# u7s Architecture Overview

**Status:** RFC-grade implementation prompt. Last updated: 2026-05-18. Substantially
superseded by shipped code in places (see §10) — treat `roadmap.md` as the current
source of truth for what is and is not implemented.

---

## 1. Positioning and Goals

u7s is a Kubernetes-compatible control plane written from scratch in Rust, targeting severely resource-constrained environments where existing lightweight distributions are still too heavy. It is **not** a wrapper around the upstream kube-apiserver binary.

### What u7s is

- A Kubernetes API-compatible server (REST + watch semantics) implemented in Rust
- No controller manager of its own — every reconcile loop (Deployment, ReplicaSet, StatefulSet, EndpointSlice/EndpointSliceMirroring, ClusterRole aggregation, Namespace lifecycle, and the rest) runs in the real upstream `kube-controller-manager` (see §3.3)
- No node agent of its own — pods run under the real upstream kubelet (backed by CRI-O), which u7s provisions per node rather than building its own kubelet-equivalent binary (see §3.5)
- An embedded state store (SQLite or LMDB — see §9) behind a storage abstraction layer
- A scheduler boundary (pluggable, design TBD) that places pods on nodes

### What u7s is not

- It does not bundle etcd, kube-apiserver, or kube-scheduler — those are replaced by u7s's own Rust API server and scheduler (§3.1, §3.4). It does run the real upstream `kube-controller-manager` and `kubelet` (with CRI-O) as separate processes rather than reimplementing them — see §3.3 and §3.5
- It does not implement control plane HA (single control plane node topology only)
- It does not implement networking — CNI plugins are user-supplied
- It is not a general-purpose Kubernetes replacement; it targets the Argo CD GitOps compatibility milestone

### The Argo CD compatibility north star

Argo CD needs to: list/watch all API groups it cares about, apply resources via strategic merge patch or server-side apply, read Secrets and ConfigMaps, create its own CRDs (Application, AppProject, ApplicationSet), and enforce RBAC. Reaching this milestone means the following API surface is fully functional (see §5).

### Why k3s and k0s are insufficient

k3s idles at ~750 MB RSS on a 1 GB node; k0s at ~658 MB. On a 1 GB VPS this leaves under 300 MB for application workloads — unusable for anything real. Both bundle the upstream Go API server which carries the Go runtime, etcd, and reflection-heavy JSON codegen. Rust with an embedded database can hit the same API surface at a fraction of the cost. u7s targets <128 MB idle for the entire control plane, leaving >800 MB for workloads and the real upstream kubelet's own footprint — kubelet is not u7s-specific overhead, it's what any Kubernetes operator runs on a worker node regardless of control plane choice (see §3.5).

---

## 2. Memory Budget

**Hard constraint:** All control plane components combined must idle under **128 MB RSS** on the control plane node. The real upstream kubelet (not a u7s process — see §3.5) runs on data plane nodes and is not counted here.

### Breakdown

| Component | Estimated idle RSS | Notes |
|---|---|---|
| API server (axum + tokio) | 20–30 MB | Axum baseline ~34 MB in production; u7s is simpler (no TLS offload, smaller router). 20 MB is realistic with jemalloc. |
| State store (SQLite WAL) | 5–15 MB | Default page cache ~2 MB; with `cache_size=-8000` (8 MB) and WAL. mmap virtual address space is large but physical pages are OS-managed. |
| State store (LMDB) | 3–10 MB | mmap virtual space is pre-allocated at env open; physical RSS is only resident pages. An empty or small-data env will be near 3 MB RSS. |
| Controller manager | 8–15 MB | Three reconcile loops (Deployment, RS, StatefulSet) plus shared informer cache. The informer cache is the main risk — it grows with object count. |
| Scheduler | 5–10 MB | `crates/scheduler` (see §3.4). Watches all pods to maintain an in-memory per-node resource tally rather than issuing a live GET per candidate node on every decision. |
| Shared libraries, stack, misc | 5–10 MB | libc, TLS stack, signal handlers. |
| **Total (midpoint estimate)** | **~70 MB** | |
| **Headroom to 128 MB** | **~58 MB** | Informer caches and watch fan-out grow with object count. |

### Risk areas

- **Informer cache bloat:** Each controller maintains an in-memory cache of watched objects. With hundreds of Pods this grows. Mitigation: use field selectors and share a single watch stream per resource type.
- **SQLite page cache:** The default 2 MB cache is too small for any real workload. With `cache_size=-16000` (16 MB) the store is fast but at budget pressure. Tune conservatively.
- **LMDB mmap size declaration:** LMDB requires declaring a maximum map size at env open. The declared size is virtual, not physical — 1 GB virtual/10 MB RSS is fine. Do not confuse them.
- **Watch fan-out:** Each connected `kubectl` or Argo CD watch holds a channel. Channels are cheap but the goroutine-equivalent per watch (tokio task) and buffered event queues add up. Cap queue depth.

### Tokio runtime cost

Tokio itself adds ~400 bytes per task for the task header. With 100 active tasks (watches + reconcilers) that is 40 KB — negligible. The thread pool uses one stack per worker thread. With `worker_threads(2)` that is 2 MB of stack space by default. Use `RUST_MIN_STACK` or `builder.thread_stack_size()` to reduce to 512 KB per thread.

---

## 3. Component Map

### 3.1 API Server

Single binary, single process. Exposes the Kubernetes REST API over HTTPS on port 6443. Responsibilities:

- Route HTTP requests to typed handlers per API group/version/resource
- Validate requests against schemas (built-in types: struct validation; CRDs: stored OpenAPI v3 schema)
- Enforce RBAC on every request (see §4.3)
- Write accepted mutations to the state store and broadcast watch events to all registered watchers
- Serve watch streams as chunked HTTP responses (one JSON event per line, Content-Type: `application/json;stream=watch`)
- Implement strategic merge patch for built-in types and JSON merge patch for custom resources
- Implement server-side apply field tracking (stored in `metadata.managedFields`)
- Handle resource version optimistic concurrency — reject writes where the submitted `resourceVersion` does not match current
- Serve the `/apis` and `/api` discovery endpoints used by `kubectl` and Argo CD to enumerate API groups

HTTP framework: **axum** (lower idle RSS than actix-web; native tokio integration; no actor overhead).

### 3.2 State Store

An embedded key-value store behind the storage abstraction (see §6). Not a separate process — linked into the API server binary or accessed via a local socket from the controller manager and scheduler.

Responsibilities:
- Durably store all Kubernetes objects as serialized JSON (or MessagePack — decision deferred)
- Maintain a monotonically increasing global revision counter (the resource version)
- Deliver ordered, append-only change streams for watch (per resource type)
- Support prefix-scanned list operations efficiently

The storage layer is an abstract Rust trait. SQLite and LMDB are the two candidates (see §9.1).

### 3.3 Controller Manager

u7s does not ship a native controller-manager crate or binary. All ~30 reconcile loops —
Deployment, ReplicaSet, StatefulSet, Job, CronJob, DaemonSet, garbage collection, CSR
approving/signing, disruption, EndpointSlice/EndpointSliceMirroring, ClusterRole
aggregation, Namespace lifecycle, and the rest — run in the real upstream
`kube-controller-manager`. `scripts/conformance/04-start-kcm.sh` downloads the real binary
and runs it against u7s with `--controllers=*` (wrapped by
`scripts/conformance/kcm-supervisor.sh`, a crash-restart supervisor with backoff), disabling
only the controllers that assume a cloud provider or a node-lifecycle implementation u7s
doesn't have (cloud-node-lifecycle, node-ipam, node-route, service-lb, service-cidr).

Why delegate instead of reimplementing: running the real binary gets conformance-level
correctness — status/condition semantics, edge cases, and cross-controller interactions —
for dozens of controllers without u7s having to rebuild each one. `roadmap.md`'s guiding
principle states this directly: "conform, don't reinvent — this is what lets us run REAL
upstream components (KCM, kubelet, kube-scheduler) against u7s as conformance oracles."

This delegation still has one gap: KCM itself currently authenticates to u7s using a
`system:masters` admin cert shim rather than its own ServiceAccount-based kubeconfig. JWT
minting infra already exists (§4.3), but provisioning and wiring a real SA-based kubeconfig
for KCM specifically is deferred to Phase 4 under the "DB-05: KCM SA token provisioning"
EPIC — the least-privilege KCM identity is not yet in place.

### 3.4 Scheduler

A single binary, `crates/scheduler` (binary `u7s-scheduler`), shipped and running in the
conformance stack (`docs/decisions/custom-bin-spread-scheduler.md`). It opens one
cluster-wide watch on `v1/Pods`
(`GET /api/v1/pods?watch=true&allowWatchBookmarks=true&sendInitialEvents=true`) and, for
every event:

- Feeds it into an in-memory `NodeTally` — a running per-node tally of committed
  pod-count/cpu/memory/ephemeral-storage/extended-resource usage that scheduling decisions
  read instead of a live `GET` per candidate node. This closes a read-after-write race a
  per-decision GET had: it could observe a just-committed bind as stale and let a second pod
  be bound onto a node that was actually already full.
- If the pod is unscheduled (`spec.nodeName == ""`) and not blocked by a non-empty
  `spec.schedulingGates`, runs it through the scheduling cycle: filter nodes by
  nodeSelector/nodeAffinity and taint/toleration match, then by free pod-count and
  cpu/memory/ephemeral-storage capacity against the tally (the NodeResourcesFit/NodePorts
  predicates), pick the first node that fits, reserve it in `NodeTally` under the same lock
  acquisition as the fit check (so two decisions racing for the same just-freed slot can
  never both claim it), and bind via `POST /api/v1/namespaces/:ns/pods/:name/binding`.
- A gated pod instead gets its `PodScheduled` condition patched to
  `False`/`SchedulingGated` (mirrors upstream, so a `WaitForPodsSchedulingGated`-style wait
  observes the right reason) and reset once every gate clears.
- When no node fits, falls back to preemption: evicts lower-priority pods on the
  best-qualifying node rather than leaving a higher-priority pod Pending forever. The bind
  itself is deferred until the pod watch confirms every victim is actually gone — a graceful
  `DELETE` only stamps `deletionTimestamp`; the real, out-of-process kubelet running the
  victim keeps its capacity occupied until it finishes tearing the container down.
- On a failed scheduling attempt, patches `PodScheduled=False`/`Unschedulable` and emits a
  `FailedScheduling` Event; on success, emits `Scheduled`. An independent 30-second resync
  (mirroring upstream's `flushUnschedulablePodsLeftover`) re-lists all pods and retries
  anything still unscheduled, as a backstop against a dropped watch event or a status PATCH
  that itself failed to land.
- Stamps the `volume.kubernetes.io/selected-node` annotation on a bound pod's unbound
  `WaitForFirstConsumer` PVCs at bind time, so external-provisioner sees the node choice
  immediately rather than after.

No leader election: `--leader-elect` is accepted and silently ignored (u7s runs a single
control plane node — see §1). `crates/scheduler/src/lib.rs` and `src/main.rs` are the
authoritative implementation — they change independently of this document.

### 3.5 Node Runtime (Real Kubelet + CRI-O)

u7s does not ship a node agent binary. The node runtime is the real upstream `kubelet`
(1.36) talking CRI to real upstream CRI-O + `crun`, installed by `lima/kubelet.yaml`'s
provisioning script and run as an ordinary systemd service inside a Lima VM (Linux is
required for CRI-O/kubelet; the u7s API server itself runs natively on the Mac host — see
`scripts/conformance/lima-start.sh`'s header comment for the split). `kube-proxy` is the
same story: the real upstream binary, run as a systemd service in IPVS mode, not a u7s
reimplementation.

u7s's job is limited to what an operator would otherwise do by hand to join a node:
- Rewrite and inject the kubeconfig kubelet uses to reach the apiserver
- Copy the cluster CA (converted DER→PEM) into the VM so kubelet can verify the apiserver's
  mTLS client cert on exec/log/attach proxy connections
- Generate and sign a kubelet serving cert against that same CA so the apiserver can in turn
  verify kubelet's TLS on those proxied connections
- Rewrite the CRI-O bridge CNI's pod subnet per node and program static inter-node routes

All of this lives in `scripts/conformance/lima-start.sh`, not in a u7s crate — there is no
`ContainerRuntime` trait, no CRI client, and no custom node-registration protocol to
maintain. Node registration is the standard Kubernetes `Node` object kubelet creates on
startup; u7s's apiserver only serves and validates it like any other resource.

`scripts/conformance/06-run-sonobuoy.sh` runs the upstream conformance suite against this
exact kubelet+CRI-O node — that run, not this document, is the evidence the arrangement is
conformant.

### 3.6 CRI Shim / Container Runtime Interface

u7s has no CRI-side code of its own — no `ContainerRuntime` trait, no CRI client, no shim
process. The real upstream `kubelet` talks CRI directly to real upstream CRI-O + `crun`; see
§3.5 for the concrete arrangement (provisioning, TLS, `scripts/conformance/lima-start.sh`)
and `docs/decisions/crio-over-containerd.md` for why CRI-O was picked over containerd.

### 3.7 CNI Integration Point

u7s does not implement networking or invoke a CNI plugin — that happens inside real
upstream CRI-O, which execs the configured CNI plugin binary when it creates a pod sandbox
(per the CNI spec: environment variables + stdin config in, parsed stdout result out). In
the conformance environment this is the CRI-O bridge plugin's `10-crio-bridge.conflist`,
whose per-node pod subnet and cross-node routes `scripts/conformance/lima-start.sh` rewrites
directly on the VM filesystem (see §3.5) — there is no u7s abstraction over CNI to swap in
a different plugin; that remains CRI-O's own configuration surface.

---

## 4. Data Flows

### 4.1 `kubectl apply` → Running Container

```
kubectl apply -f deployment.yaml
  │
  ▼
API Server
  1. Authenticate (bearer token / client cert)
  2. Authorize (RBAC check: can this identity create/update Deployments in this namespace?)
  3. Validate (schema check against built-in Deployment type)
  4. Merge (strategic merge patch if updating; server-side apply field tracking if SSA)
  5. Write to state store (increment global revision; record new resourceVersion on object)
  6. Broadcast MODIFIED/ADDED watch event to all watchers of apps/v1/Deployments
  7. Return 200/201 to kubectl
  │
  ▼
Deployment Controller (watching apps/v1/Deployments)
  1. Receives ADDED/MODIFIED event; enqueues "default/my-deployment"
  2. Reconcile: compute desired ReplicaSet spec
  3. Creates or updates ReplicaSet via API server (→ repeat RBAC, validate, write, broadcast)
  │
  ▼
ReplicaSet Controller (watching apps/v1/ReplicaSets)
  1. Receives ADDED/MODIFIED event; enqueues "default/my-rs-xxxxx"
  2. Reconcile: current Pod count < desired → create N Pods with spec.nodeName=""
  │
  ▼
Scheduler (watching v1/Pods cluster-wide — see §3.4)
  1. Receives ADDED event for unscheduled Pod
  2. Filters nodes by nodeSelector/taints, checks fit against its in-memory tally
  3. POSTs .../pods/my-pod/binding to assign Pod to "node-1"
  │
  ▼
Kubelet on node-1 (real upstream kubelet, watching v1/Pods with spec.nodeName="node-1")
  1. Receives MODIFIED event (Pod now assigned to it)
  2. Calls CRI (to CRI-O): RunPodSandbox → CreateContainer → StartContainer
  3. CRI-O invokes the configured CNI plugin to set up the pod network namespace
  4. Probes liveness/readiness
  5. PATCHes Pod.status.phase = Running, sets containerStatuses
  │
  ▼
API Server persists Pod status update; broadcasts to watchers
```

**Performance note:** Each step issues at least one API server write (state store write + watch fanout). With many concurrent deployments, writes batch against the state store becomes critical. SQLite WAL mode handles this well up to ~1000 TPS; LMDB handles higher rates with lower latency but requires careful transaction sizing.

### 4.2 Watch / Informer Flow

Argo CD and controllers use the watch API. The flow:

1. Client issues `GET /apis/apps/v1/deployments?watch=true&resourceVersion=<rv>&allowWatchBookmarks=true`
2. API server opens a chunked HTTP response (no Content-Length; connection stays open)
3. API server registers the client in an in-memory fan-out registry keyed by (resource type, namespace filter, field selectors)
4. As writes arrive at the state store, the storage layer emits change events with the new revision
5. API server filters events per registered watcher (namespace/field selector matching), serializes to `{"type":"ADDED","object":{...}}`, and writes to the chunked response
6. Periodically (at minimum every 60 s with no events), the API server sends a BOOKMARK event: `{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"<latest-rv>"}}}`. This lets the client resume without a full relist after disconnect.
7. On disconnect, client relists from last bookmark rv. If the rv has been compacted away (watch history is bounded), the server returns `410 Gone` and the client must full-relist.

**Watch history:** u7s must maintain a bounded in-memory ring buffer of recent change events per resource type (e.g., last 1000 events or last 5 minutes, whichever is smaller). When a client reconnects with an rv within the ring buffer, it can resume without a list. This is the equivalent of the Kubernetes watch cache.

**Allocation note:** Every watch event is a heap-allocated JSON blob broadcast to N watchers. With N=10 watches on Pods and 100 Pod events/second, that is 1000 serializations/second. Pre-serialize once, then clone the `Bytes` (reference-counted). Flag this as a hot path.

### 4.3 RBAC Enforcement Path

Every API server request (excluding `/healthz`, `/readyz`, `/livez`) passes through the RBAC enforcer before any state store access.

1. **Authentication:** Extract identity from the request. u7s Phase 1 supports: bearer token (static token file mapping token→username/groups), and service account JWT tokens (signed with a cluster key). Client certificates are deferred.
2. **Authorization:** Given (username, groups, verb, resource, namespace, name), evaluate against the in-memory RBAC index:
   - Load all ClusterRoleBindings and RoleBindings that reference this user or their groups
   - For each binding, load the referenced Role or ClusterRole
   - Check if any rule matches (apiGroup, resource, verb, resourceName)
   - Short-circuit on first match (allow)
   - Default deny
3. The RBAC index is an in-memory structure rebuilt from the state store on startup and updated incrementally from watch events on Roles/ClusterRoles/Bindings. **Do not query the state store on the hot path.** The index must be read-lock-free for lookups; a write lock only on updates.

**Implementation note:** The RBAC index can be a `DashMap<SubjectKey, Vec<PolicyRule>>` or a flat sorted vec with binary search. Given the scale (hundreds of bindings), either is fine. Avoid O(n) scans of all bindings on every request.

### 4.4 CRD Registration and Custom Resource Lifecycle

1. User applies a `CustomResourceDefinition` object to the API server (via `kubectl apply` or Argo CD sync).
2. API server validates the CRD schema (valid OpenAPIv3, valid names/group/version).
3. CRD is written to the state store under the `apiextensions.k8s.io/v1/customresourcedefinitions` prefix.
4. API server's route table is updated **dynamically** to add new HTTP routes for the custom resource's group/version/kind. This requires a read-write-locked route registry; writes are infrequent.
5. The new routes validate incoming custom resources against the stored OpenAPI v3 schema. u7s uses CEL for validation rules if present; otherwise falls back to JSON schema structural validation. A third-party CEL evaluator crate (e.g., `cel-rust`) handles this.
6. Custom resources are stored in the same state store under `<group>/<version>/<plural>/<namespace>/<name>` (or cluster-scoped: `<group>/<version>/<plural>/<name>`).
7. Watch events on custom resources work identically to built-in types — same fan-out mechanism.
8. Argo CD's own CRDs (Application, AppProject, ApplicationSet) go through this path. After they are registered, Argo CD can create Application objects and u7s stores and serves them like any other resource.

---

## 5. API Surface

The API server must expose the following API groups and versions for the Argo CD milestone.

### Core group (`/api/v1`)

| Resource | Verbs |
|---|---|
| Pods | get, list, watch, create, update, patch, delete, deletecollection |
| Pods/status | get, patch, update |
| Pods/log | get |
| Namespaces | get, list, watch, create, update, patch, delete |
| Services | get, list, watch, create, update, patch, delete |
| ServiceAccounts | get, list, watch, create, update, patch, delete |
| ConfigMaps | get, list, watch, create, update, patch, delete |
| Secrets | get, list, watch, create, update, patch, delete |
| Events | get, list, watch, create, patch |
| Nodes | get, list, watch, create, update, patch (status subresource used by kubelet) |
| PersistentVolumes | get, list, watch, create, update, patch, delete |
| PersistentVolumeClaims | get, list, watch, create, update, patch, delete |

### `apps/v1` (`/apis/apps/v1`)

Deployments, ReplicaSets, StatefulSets — full CRUD + watch + status subresource.

### `rbac.authorization.k8s.io/v1`

Roles, ClusterRoles, RoleBindings, ClusterRoleBindings — full CRUD + watch. Required for Argo CD RBAC and for bootstrapping its own service account.

### `apiextensions.k8s.io/v1`

CustomResourceDefinitions — full CRUD + watch. This is the hook Argo CD uses to install its CRDs.

### Discovery endpoints

- `GET /api` — returns APIVersions listing core group versions
- `GET /apis` — returns APIGroupList
- `GET /apis/<group>/<version>` — returns APIResourceList for that group/version
- These are used by `kubectl`, Argo CD, and any client that auto-discovers the server's capabilities

### Required Kubernetes API mechanics

**Resource versions:** Every object has `metadata.resourceVersion`, a string encoding of the state store's global monotonic revision at the time of last write. Clients include `resourceVersion` in PUT/PATCH for optimistic concurrency — the server rejects if current != submitted (HTTP 409 Conflict). List responses include a `metadata.resourceVersion` reflecting the revision at which the list was consistent.

**Watch:** As described in §4.2. Clients must be able to start a watch from a `resourceVersion` returned by a prior list or watch. The `allowWatchBookmarks=true` query parameter enables BOOKMARK events.

**Strategic merge patch:** Used by `kubectl apply` for built-in types. The merge key for containers is `name`; for volumes, `name`. u7s must implement the merge-key-aware array merge for at minimum: `spec.containers`, `spec.initContainers`, `spec.volumes`. A hand-rolled merge using the field metadata embedded in type definitions is acceptable.

**JSON merge patch:** Used for custom resources (CRDs do not support SMP). Simpler: merge JSON objects recursively, null fields delete.

**Server-side apply (SSA):** Argo CD uses SSA (field manager `argocd-controller`) when it is available. u7s must implement SSA for the Argo CD milestone: accept `PATCH` with `Content-Type: application/apply-patch+yaml`, track `managedFields` per field manager, and detect conflicts. This is the most complex part of the API surface.

**Subresources:** At minimum: `pods/log` (GET, stream), `deployments/status`, `replicasets/status`, `statefulsets/status`, `nodes/status`.

**Pagination:** `continue` token for large list responses. Argo CD lists all resources; without pagination the API must handle the full result set in memory. Implement cursor-based pagination over the state store from Phase 2 onward.

---

## 6. Storage Interface

All components access state exclusively through a `Store` trait. Neither the API server nor any controller imports SQLite or LMDB directly — they use this trait. This allows the storage backend to be swapped at compile time or runtime (via feature flags).

```rust
/// A single stored object. The value is raw serialized bytes (JSON or MsgPack).
/// `revision` is the global store revision at which this version was written.
pub struct StoreObject {
    pub key: String,
    pub value: Bytes,
    pub revision: u64,
    pub deleted: bool,
}

/// A watch event delivered to subscribers.
pub enum WatchEvent {
    Put(StoreObject),
    Delete { key: String, revision: u64 },
    Bookmark { revision: u64 },
}

pub trait Store: Send + Sync + 'static {
    /// Get a single object by exact key.
    async fn get(&self, key: &str) -> Result<Option<StoreObject>>;

    /// List all objects with keys sharing the given prefix.
    /// Returns results at a consistent revision (snapshot read).
    /// `revision_out` is set to the revision of the snapshot.
    async fn list(&self, prefix: &str, revision_out: &mut u64) -> Result<Vec<StoreObject>>;

    /// Write an object. `expected_revision` is used for optimistic concurrency:
    /// - `None`: unconditional write (create or overwrite)
    /// - `Some(0)`: must not exist (create-only)
    /// - `Some(rv)`: must exist at exactly this revision (update-only)
    /// Returns the new revision on success, or `Err(RevisionMismatch)` on conflict.
    async fn put(
        &self,
        key: &str,
        value: Bytes,
        expected_revision: Option<u64>,
    ) -> Result<u64>;

    /// Delete an object. Same optimistic concurrency semantics as `put`.
    async fn delete(&self, key: &str, expected_revision: Option<u64>) -> Result<u64>;

    /// Subscribe to changes with keys sharing the given prefix, starting from
    /// `from_revision` (exclusive). If `from_revision` is within the bounded
    /// history window, events are replayed from there. If it has been compacted,
    /// the first event delivered is `WatchEvent::Bookmark` with the current revision,
    /// and the caller must relist. Returns a stream of events.
    async fn watch(
        &self,
        prefix: &str,
        from_revision: u64,
    ) -> Result<impl Stream<Item = WatchEvent> + Send>;
}
```

### How resource versions work

The state store maintains a single atomic `u64` counter, the **global revision**. Every successful `put` or `delete` increments this counter and stamps the object with the new value. The counter never resets; it is persisted alongside the data.

A Kubernetes `resourceVersion` is the decimal string encoding of this counter: `"42"`. List responses capture the counter value at snapshot time. Watch resumes from a revision (exclusive lower bound).

**SQLite implementation note:** Use a single-row `revision` table updated in the same transaction as the object write. WAL mode allows concurrent readers without blocking the writer. The change event log is a separate `events` table (key, revision, value_snapshot or tombstone) with a background goroutine-equivalent that broadcasts to in-memory watch subscribers and periodically truncates old rows beyond the history window.

**LMDB implementation note:** LMDB transactions provide snapshot isolation natively. The global revision is stored as a special key. Each write transaction atomically increments the revision and writes the new object. Watch subscription is an in-memory broadcast (LMDB has no built-in pub/sub); the write path notifies a tokio broadcast channel after committing.

---

## 7. Node Lifecycle

u7s does not implement node join/registration — see §3.5 for why (real upstream kubelet +
CRI-O; u7s ships no such binary itself). What brings a node up is exactly what an operator would
otherwise do by hand; for the local dev/CI environment, `scripts/conformance/lima-start.sh`
does it end to end:

- Provisions a Linux VM (Lima) running kubelet + CRI-O — both require a Linux kernel, while
  the u7s API server itself runs natively on the Mac host (see the script's own header
  comment for the split).
- Rewrites and injects the kubeconfig kubelet uses to reach the apiserver, and copies the
  cluster CA (DER→PEM) so kubelet can verify the apiserver's mTLS client cert on
  exec/log/attach proxy connections.
- Generates and signs a kubelet serving cert against that same CA so the apiserver can in
  turn verify kubelet's TLS on those proxied connections.
- Rewrites the CRI-O bridge CNI's pod subnet per node (each node gets a disjoint /24 out of
  CRI-O's default /16) and programs static inter-node routes, since nothing else in this
  arrangement runs a CNI/BGP control plane of its own.
- Installs and starts the real upstream `kube-proxy` binary (extracted from the kube-proxy
  container image) as a systemd service in IPVS mode — not a u7s reimplementation.

None of this lives in a u7s crate: there is no node-registration protocol, no bootstrap
token exchange, and no lifecycle state machine for u7s to maintain. Node registration
itself is the standard Kubernetes `Node` object kubelet creates on startup; u7s's apiserver
only serves and validates it like any other resource, exactly as §3.5 describes. This is
the same "conform, don't reinvent" rationale as §3.3's controller delegation: kubelet's own
join/registration/lifecycle machinery is substantial, and running the real binary gets it
for free instead of u7s re-deriving it.

---

## 8. Phased Implementation Plan

Each phase produces a cluster that can do something real. Do not start a phase until the previous one is demonstrably working end-to-end.

### Phase 1: Working API Server + State Store + Single Static Pod

**Goal:** `kubectl get pods` works. A pod can be created by directly writing it with `spec.nodeName` set (bypassing scheduler). Real kubelet + CRI-O run it (see §3.5) — there is nothing else here for u7s to build.

Deliverables:
- API server serving `/api/v1/{pods,namespaces,nodes}` with get/list/watch/create/update/patch/delete
- Storage trait + SQLite implementation (WAL mode, basic schema)
- Static bearer token auth, no RBAC (allow all)
- Real kubelet joins, registers the `Node` object, watches its own pods, and runs them via CRI-O — no u7s-built binary involved (see §3.5)
- `kubectl get pods/nodes/namespaces` works
- A Pod with `spec.nodeName` manually set runs a container

### Phase 2: RBAC + Controller Manager (Deployments)

**Goal:** `kubectl apply -f deployment.yaml` creates a running Deployment. RBAC is enforced.

Deliverables:
- RBAC enforcer (in-memory index, Role/ClusterRole/Binding resources served and enforced)
- Service account JWT token auth
- `apps/v1` API group: Deployments, ReplicaSets
- Deployment controller + ReplicaSet controller
- `kubectl apply` with strategic merge patch works for Deployments

### Phase 3: Scheduler + StatefulSets

**Goal:** Pods are placed automatically. StatefulSets with ordered rollout work.

Deliverables:
- Scheduler: resource request/limit awareness, taint/toleration support (shipped as `crates/scheduler` — see §3.4 for the actual design, which grew preemption and scheduling-gate support beyond this original scope)
- StatefulSet controller
- PersistentVolumeClaim handling (static provisioning only)
- Node resource reporting (kubelet reports `status.allocatable`/`status.capacity` itself — see §3.5)

### Phase 4: CRD Support + Argo CD Compatibility

**Goal:** Argo CD can be installed on the cluster and manage workloads via GitOps.

Deliverables:
- `apiextensions.k8s.io/v1` CRD registration and dynamic route generation
- CEL validation for CRDs
- Server-side apply (SSA) with field manager tracking and conflict detection
- Argo CD CRDs installable: Application, AppProject, ApplicationSet
- `argoproj.io/v1alpha1` custom resources servable
- Argo CD application-controller can sync a simple Deployment

### Phase 5: Hardening

- LMDB storage backend (validate performance vs SQLite, decide)
- Pagination (`continue` tokens on list)
- Watch bookmark periodic emission
- Pod log streaming (`pods/log`)
- Kubelet TLS bootstrap (upstream kubelet's own bootstrap-token flow — see §3.5)
- Metrics endpoint (`/metrics`, Prometheus scrape)

---

## 9. Open Decisions

### 9.1 State Store: SQLite vs LMDB

**SQLite (rusqlite or sqlx):**
- Simple SQL queries for list-by-prefix, range scans, revision tracking
- WAL mode gives concurrent readers + one writer; ~1000 TPS for small writes
- Excellent tooling (sqlite3 CLI, DB Browser for SQLite) for debugging
- Page cache grows with usage; 8–16 MB cache budget
- Write path: single write per transaction + event log insert (2 writes)
- Risk: WAL can grow unbounded if checkpoint is starved; requires `wal_autocheckpoint` tuning
- **Better if:** simplicity and debuggability matter more than write throughput; the cluster has moderate object churn (under 500 writes/second)

**LMDB (lmdb-rkv):**
- Zero-copy reads via mmap; reads do not block writes (MVCC)
- Write throughput higher than SQLite for small random writes (~10k TPS)
- No SQL; prefix scans require cursor iteration (more code, same performance)
- mmap size declared at open; must be larger than the largest expected DB; physical RAM is only resident pages
- Long-running read transactions block page reclaim — must bound transaction lifetime in watch subscribers
- No built-in event log; change fan-out is pure in-memory broadcast
- **Better if:** write throughput is the bottleneck or zero-copy reads are important; team is comfortable with cursor-based APIs

**Resolution trigger:** Benchmark both under a simulated Argo CD workload (100 Applications, 10 syncs/minute). If SQLite meets throughput targets (<10 ms p99 write latency), use SQLite for its tooling advantage. Switch to LMDB only if benchmarks show SQLite is a bottleneck.

### 9.2 Container Runtime

Resolved — CRI-O + crun, chosen over containerd for flat (not linear) RSS-per-pod and no
Go-runtime shim overhead. This is a real upstream kubelet's own
`--container-runtime-endpoint` choice, not a u7s trait to implement or a decision u7s
software makes at runtime — see §3.5 for the concrete arrangement and
`docs/decisions/crio-over-containerd.md` for the full rationale.

### 9.3 Scheduler Design

**Simple bin-packing (custom):**
- Score nodes by available CPU/memory, filter by taints/tolerations and node selector
- Fits in <200 lines of Rust
- No inter-node topology awareness; no custom plugin support
- **Better if:** workloads are simple; operator does not need advanced placement (affinity, anti-affinity, spread)

**Upstream kube-scheduler (Go binary):**
- Full implementation of the K8s scheduling framework (plugins, priorities, preemption)
- ~30–50 MB RSS for the Go binary — well within budget
- Talks to the u7s API server via the standard Kubernetes watch API
- No Rust code to write for scheduler logic
- **Better if:** operator needs production-grade scheduling (pod topology spread, node affinity, preemption)

**Resolution trigger:** Start with simple bin-packing to keep the dependency surface minimal. If operator finds scheduling features lacking, swap in upstream kube-scheduler — it requires only a working K8s API server watch endpoint, which u7s will have by Phase 3.

---

## 10. Out of Scope

The following are explicitly **not** implemented in u7s, at least through the Argo CD milestone:

- **etcd:** Off the table. The target memory budget makes it impossible (etcd itself idles at ~50–100 MB RSS, and requires a separate process).
- **Control plane HA:** Single control plane node only. No leader election, no distributed consensus between API servers.
- **Cluster Autoscaler:** No node provisioning or deprovisioning.
- **Cloud provider integration:** No CCM (Cloud Controller Manager), no LoadBalancer service type provisioning.
- **Network policies:** Policy objects can be stored (Argo CD may apply them) but enforcement is the CNI plugin's responsibility — u7s does not implement a network policy enforcement engine.
- **Volume plugins beyond hostPath and emptyDir:** No CSI driver integration in Phase 1–4. Static PV/PVC with hostPath is the limit.
- **Image registry mirroring or caching:** Kubelet delegates all image pulls to the CRI runtime (real upstream kubelet — see §3.5).
- **Audit logging:** Not implemented initially.
- **Multi-tenancy / virtual clusters:** Single flat cluster model.
- **Windows nodes:** Linux only.

The following were originally listed here as out of scope but are now implemented —
see `roadmap.md` for the shipped decision in each case:

- **Admission webhooks:** MutatingWebhookConfiguration and ValidatingWebhookConfiguration are implemented (`crates/apiserver/src/admission.rs`), not just built-in plugins.
- **Aggregated API server / API aggregation layer:** `apiregistration.k8s.io` APIService aggregation is implemented (`crates/apiserver/src/handlers/aggregation.rs`); CRDs are no longer the only extension mechanism.
- **Horizontal Pod Autoscaler (HPA):** A metrics-server addon is deployed by the API server (`seed_metrics_server`) and the `scale` subresource is implemented (`crates/apiserver/src/handlers/scale.rs`), unblocking CPU/memory HPA targets.

**Pod Disruption Budgets** remain accurately scoped above: u7s has no PDB *controller*
of its own (no reimplementation of `disruptionsAllowed` computation) — it delegates
that reconciliation to the real upstream kube-controller-manager's DisruptionController
and only enforces the resulting `status.disruptionsAllowed` at eviction time
(`crates/apiserver/src/handlers/pods.rs`).
