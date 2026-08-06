# u7s Scheduler Implementation Spec

**Status:** Implementation spec. Last updated: 2026-05-18. `crates/scheduler` has since
grown beyond this bootstrap spec in places (see the out-of-scope list below) — for
current scope and shipped decisions, treat `roadmap.md` and
`docs/decisions/custom-bin-spread-scheduler.md` as authoritative.
**Phase:** Phase 3 deliverable. Phase 1 bypasses scheduler entirely (manual `spec.nodeName`).

---

## 1. Scope and Decision

### What the scheduler does

The u7s scheduler is a custom bin-spreading scheduler written in Rust, approximately 200 lines of logic. It runs as a separate binary (or an in-process tokio task — same logic either way). It is an API client only: it reads Pods and Nodes from the API server and writes placement decisions back via the Kubernetes binding API.

**In scope:**
- Watch for unscheduled Pods and assign them to nodes
- Filter: NodeReady, ResourceFit, NodeSelector, TaintToleration
- Score: LeastAllocated (bin-spread)
- Binding via the standard Kubernetes binding subresource
- Failure events when no node passes filters
- Retry with exponential backoff

**Explicitly out of scope (deferred to escape hatch):**
- Pod affinity and anti-affinity (`spec.affinity`)
- Topology spread constraints (`spec.topologySpreadConstraints`)
- `VolumeBinding` (matching PVCs to PVs by storage class, access mode, topology)
- `PodTopologySpread` (zone/region awareness)
- Custom scheduler plugins

Preemption (evicting lower-priority pods) and `PodFitsHostPorts` (port conflict
detection) were originally deferred here too, but are now implemented in
`crates/scheduler` — see `find_preemption_plan`/`select_preemption_victims` and
`container_host_ports`/`host_ports_fit`, validated against SchedulerPreemption and
SchedulerPredicates conformance.

### Escape hatch: upstream kube-scheduler

See §8 for the full escape hatch spec. Summary: run the `kube-scheduler` binary pointed at the u7s API server. No Rust code changes required. Available from Phase 3 onward.

---

## 2. Scheduling Loop

The scheduler is a reconciliation loop, not a push-driven system. It maintains watches on Pods and Nodes and processes unscheduled Pods one at a time.

### Pod watch setup

```
GET /api/v1/pods?watch=true&fieldSelector=spec.nodeName=&resourceVersion=0
```

`fieldSelector=spec.nodeName=` matches Pods where `spec.nodeName` is the empty string (unscheduled). `resourceVersion=0` starts from the current state (no historical replay needed — the scheduler only acts on current unscheduled pods).

Filter further in-process: only act on Pods where `spec.schedulerName == "u7s-scheduler"` or `spec.schedulerName` is unset/empty. This is the standard Kubernetes scheduler name field.

### Node watch setup

```
GET /api/v1/nodes?watch=true&resourceVersion=0
```

No field selector. All nodes are relevant. This populates and maintains the in-memory `NodeCache`.

### Main loop structure

For each unscheduled Pod event (ADDED or MODIFIED with `spec.nodeName == ""`):

1. Read `NodeCache` (read lock).
2. Run filter pipeline: collect passing nodes.
3. If no nodes pass: emit a `FailedScheduling` event, enqueue the pod for retry.
4. If nodes pass: run score pipeline, select the highest-scoring node. On tie: stable sort by node name, take first.
5. Issue binding: `POST /api/v1/namespaces/{ns}/pods/{name}/binding`.
6. On binding success: done. The API server sets `spec.nodeName` atomically.
7. On binding conflict (409): another writer set `spec.nodeName` concurrently. Log and discard — the pod is no longer unscheduled.
8. On other binding error: re-queue with backoff.

### API calls the scheduler makes

| Purpose | Method | Path | Notes |
|---|---|---|---|
| Watch unscheduled pods | GET | `/api/v1/pods?watch=true&fieldSelector=spec.nodeName=` | Chunked response, persistent connection |
| Watch all nodes | GET | `/api/v1/nodes?watch=true` | Chunked response, persistent connection |
| Bind pod to node | POST | `/api/v1/namespaces/{ns}/pods/{name}/binding` | See §6 for body |
| Emit failure event | POST | `/api/v1/namespaces/{ns}/events` | See §7 for body |

The scheduler never PATCHes `spec.nodeName` directly. The binding subresource is the correct path — it triggers the API server's admission and sets `spec.nodeName` atomically.

---

## 3. Filter Pipeline

Filters are applied in order. A Pod fails as soon as any filter rejects all nodes — no need to run remaining filters for a fully-rejected set.

For each node, apply all four filters. Collect nodes that pass all four. Order of application does not affect correctness; apply cheapest checks first for efficiency: NodeReady → ResourceFit → NodeSelector → TaintToleration.

### 3.1 NodeReady

**Purpose:** Reject nodes that are not healthy.

**K8s fields checked:**
- `node.status.conditions`: array of `{type, status, ...}`. Find the entry where `type == "Ready"`. The node passes if `status == "True"`.
- Also reject nodes where `node.spec.unschedulable == true` (cordoned nodes).

**Rust sketch:**

```rust
fn check_node_ready(node: &NodeInfo) -> bool {
    !node.unschedulable && node.ready
}
```

`NodeInfo.ready` is maintained from the Node watch (see §5).

**Failure reason string:** `"node %s is not ready"` (used in FailedScheduling event).

### 3.2 ResourceFit

**Purpose:** Reject nodes that cannot accommodate the pod's resource requests.

**K8s fields checked:**
- Pod: `spec.containers[*].resources.requests.cpu` and `.memory` (sum across all containers including init containers — use max of init container requests, not sum, per Kubernetes semantics; for simplicity in Phase 3, sum all containers and ignore init containers).
- Node: `status.allocatable.cpu` and `status.allocatable.memory`.
- In-memory accounting: sum of `resources.requests` of all non-terminal Pods currently bound to this node (see §5 for how this is maintained).

**Rust sketch:**

```rust
fn check_resource_fit(pod: &Pod, node: &NodeInfo, allocated: &AllocatedResources) -> bool {
    let pod_cpu = sum_container_cpu_requests(pod);       // millicores
    let pod_mem = sum_container_memory_requests(pod);    // bytes

    let remaining_cpu = node.allocatable_cpu_m - allocated.cpu_m;
    let remaining_mem = node.allocatable_mem_bytes - allocated.mem_bytes;

    pod_cpu <= remaining_cpu && pod_mem <= remaining_mem
}
```

**Resource request parsing:**
- CPU: parse Kubernetes quantity strings. `"500m"` → 500 millicores. `"1"` or `"1.0"` → 1000 millicores. `"100u"` (microcores) → 0 millicores (round down). Use a small quantity-parsing utility — do not pull in a full Kubernetes client just for this.
- Memory: parse `"256Mi"` → 268435456 bytes. `"1Gi"` → 1073741824. `"512k"` → 512000. Standard SI and binary suffixes.

**Pods with no resource requests:** Treat as zero. They pass ResourceFit on any node.

**Failure reason string:** `"insufficient cpu"` or `"insufficient memory"` (or both).

### 3.3 NodeSelector

**Purpose:** Reject nodes that do not match the pod's required node labels.

**K8s fields checked:**
- Pod: `spec.nodeSelector` — a `map<string, string>`. All entries must match.
- Node: `metadata.labels` — a `map<string, string>`.

**Rust sketch:**

```rust
fn check_node_selector(pod: &Pod, node: &NodeInfo) -> bool {
    pod.node_selector.iter().all(|(k, v)| node.labels.get(k) == Some(v))
}
```

An empty `spec.nodeSelector` (no keys) passes all nodes.

**Failure reason string:** `"node(s) didn't match node selector"`.

### 3.4 TaintToleration

**Purpose:** Reject nodes whose taints are not tolerated by the pod.

**K8s fields checked:**
- Node: `spec.taints` — array of `{key, value, effect}`. Effect is one of `NoSchedule`, `PreferNoSchedule`, `NoExecute`.
- Pod: `spec.tolerations` — array of `{key, operator, value, effect, tolerationSeconds}`.

**Logic:** For each taint on the node with `effect == "NoSchedule"` or `effect == "NoExecute"`, the pod must have a matching toleration. `PreferNoSchedule` taints are skipped for filter purposes (they affect scoring, but u7s does not implement that nuance — treat them as no-ops).

A toleration matches a taint if:
- `toleration.key == taint.key` (or `toleration.key == ""` and `toleration.operator == "Exists"` — matches any key)
- `toleration.operator == "Exists"` (matches any value) OR (`toleration.operator == "Equal"` and `toleration.value == taint.value`)
- `toleration.effect == taint.effect` OR `toleration.effect == ""` (matches any effect)

**Rust sketch:**

```rust
fn check_taint_toleration(pod: &Pod, node: &NodeInfo) -> bool {
    node.taints.iter()
        .filter(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
        .all(|taint| pod.tolerations.iter().any(|tol| toleration_matches(tol, taint)))
}

fn toleration_matches(tol: &Toleration, taint: &Taint) -> bool {
    let key_match = tol.key.is_empty() && tol.operator == "Exists"
        || tol.key == taint.key;
    let val_match = tol.operator == "Exists"
        || (tol.operator == "Equal" && tol.value == taint.value);
    let effect_match = tol.effect.is_empty() || tol.effect == taint.effect;
    key_match && val_match && effect_match
}
```

**Failure reason string:** `"node(s) had untolerated taint {key}={value}:{effect}"`.

---

## 4. Score Pipeline

Applied only to nodes that pass all filters. Returns a score in [0.0, 1.0]. Highest wins. Tie-break: stable sort by node name (lexicographic ascending), select first.

### 4.1 Scoring recommendation: LeastAllocated (bin-spread)

**Decision: bin-spread (LeastAllocated).**

Rationale: u7s targets small clusters (1 GB VPS, few nodes). Bin-spreading distributes load across nodes so a single node failure is less catastrophic — the remaining nodes are not already at capacity. Bin-packing (MostAllocated) concentrates workloads on fewer nodes to idle others, which saves power in large clusters but provides no benefit and concentrates risk in a small cluster where you are not paying per-node-hour and cannot absorb a node loss cleanly.

If the operator later needs bin-packing behavior (e.g., to minimize cloud costs by draining nodes for scale-down), the escape hatch to upstream kube-scheduler is the right move — it supports both strategies via `NodeResourcesFit` plugin configuration.

### 4.2 Score formula

```
score(node) = (remaining_cpu_fraction + remaining_mem_fraction) / 2.0
```

Where:
- `remaining_cpu_fraction = (allocatable_cpu_m - allocated_cpu_m) / allocatable_cpu_m`
- `remaining_mem_fraction = (allocatable_mem_bytes - allocated_mem_bytes) / allocatable_mem_bytes`

Both fractions are clamped to [0.0, 1.0]. If a node has zero allocatable CPU or memory (unusual but guard against it), treat the fraction as 0.0.

**Rust sketch:**

```rust
fn score(node: &NodeInfo, allocated: &AllocatedResources) -> f64 {
    let cpu_frac = if node.allocatable_cpu_m == 0 { 0.0 } else {
        ((node.allocatable_cpu_m - allocated.cpu_m) as f64 / node.allocatable_cpu_m as f64)
            .clamp(0.0, 1.0)
    };
    let mem_frac = if node.allocatable_mem_bytes == 0 { 0.0 } else {
        ((node.allocatable_mem_bytes - allocated.mem_bytes) as f64 / node.allocatable_mem_bytes as f64)
            .clamp(0.0, 1.0)
    };
    (cpu_frac + mem_frac) / 2.0
}
```

The pod's own requests are not subtracted before scoring — the score reflects the node's current state before the prospective placement. This is consistent with upstream kube-scheduler behavior.

---

## 5. In-Memory Node State

The scheduler maintains a lightweight in-memory picture of the cluster. This is the only state it holds; everything else is derived from API server watches.

### Data structures

```rust
struct NodeCache {
    nodes: HashMap<String, NodeInfo>,          // key: node name
    allocated: HashMap<String, AllocatedResources>, // key: node name
}

struct NodeInfo {
    allocatable_cpu_m: u64,       // millicores
    allocatable_mem_bytes: u64,   // bytes
    labels: HashMap<String, String>,
    taints: Vec<Taint>,
    ready: bool,
    unschedulable: bool,
}

struct AllocatedResources {
    cpu_m: u64,
    mem_bytes: u64,
}
```

**Memory estimate:** 100 nodes × ~1 KB per NodeInfo (labels + taints + scalars) = ~100 KB. Negligible against the 5–10 MB scheduler RSS budget.

### Node watch event handling

Watch: `GET /api/v1/nodes?watch=true&resourceVersion=0`

| Event type | Action |
|---|---|
| ADDED | Insert `NodeInfo` built from `node.status.allocatable`, `node.metadata.labels`, `node.spec.taints`, `node.spec.unschedulable`, and the `Ready` condition. Insert `AllocatedResources{0, 0}` in `allocated` if not present. |
| MODIFIED | Update the existing `NodeInfo` in place. Do NOT reset `AllocatedResources` — resource accounting comes from the Pod watch, not the Node watch. |
| DELETED | Remove the node from both `nodes` and `allocated`. Any pods that were pending on this node's allocation will be re-evaluated on the next retry. |
| BOOKMARK | Update the stored `resourceVersion` for resuming the watch after disconnect. Take no other action. |

Parsing `status.allocatable.cpu`: standard Kubernetes quantity parsing. `"2"` → 2000m. `"500m"` → 500m.

### Pod watch event handling

Watch: `GET /api/v1/pods?watch=true&resourceVersion=0`

This is a **separate** watch from the unscheduled-pod watch used to trigger scheduling. This watch covers ALL pods on ALL nodes, used purely for resource accounting. Use a field selector to scope it if the cluster is large, but at Phase 3 scale, watching all pods is fine.

A pod contributes to `AllocatedResources` for a node if and only if:
- `pod.spec.nodeName` is non-empty (it has been scheduled), AND
- `pod.status.phase` is not `Succeeded` or `Failed` (it is not terminal), AND
- The pod is not in a `Terminating` state (`pod.metadata.deletionTimestamp` is set AND grace period has elapsed — for simplicity, treat any pod with `deletionTimestamp` set as terminal for accounting purposes).

| Event type | Action |
|---|---|
| ADDED | If pod is non-terminal and has a node name: add pod's CPU+memory requests to `allocated[node_name]`. Track in a `pod_allocations: HashMap<PodUID, (NodeName, Resources)>` map so DELETED can subtract correctly. |
| MODIFIED | Recompute: look up old allocation in `pod_allocations`. If the pod's node changed (e.g., rescheduled — unusual), subtract old, add new. More commonly: check if the pod transitioned to terminal (phase = Succeeded/Failed, or deletionTimestamp set). If so, subtract its resources from `allocated[node_name]` and remove from `pod_allocations`. |
| DELETED | Look up in `pod_allocations`. Subtract its resources from `allocated[node_name]`. Remove from `pod_allocations`. |
| BOOKMARK | Update stored resourceVersion. No other action. |

Add a `pod_allocations: HashMap<PodUID, (NodeName, AllocatedResources)>` field to `NodeCache` to support correct MODIFIED and DELETED handling.

### Watch reconnect

Both watches must reconnect on error:
1. On any error (connection reset, 410 Gone), re-issue the watch from the last known `resourceVersion`.
2. On `410 Gone` (the revision has been compacted): do a full relist (`GET /api/v1/nodes` without `?watch`), rebuild the cache from scratch, then start the watch from the resourceVersion returned by the list. This is the standard Kubernetes informer reconnect pattern.
3. Use exponential backoff on reconnect: start at 500ms, cap at 30s, reset on successful event receipt.

---

## 6. Binding

When the scheduler selects a node for a pod, it commits the decision via the Kubernetes binding subresource. It does NOT directly PATCH `spec.nodeName`.

### API call

```
POST /api/v1/namespaces/{namespace}/pods/{name}/binding
Content-Type: application/json

{
  "apiVersion": "v1",
  "kind": "Binding",
  "metadata": {
    "name": "{name}",
    "namespace": "{namespace}"
  },
  "target": {
    "apiVersion": "v1",
    "kind": "Node",
    "name": "{node-name}"
  }
}
```

The API server sets `spec.nodeName` on the Pod atomically as part of processing the binding. The scheduler does not need to do anything else.

### Race condition window

There is a window between the scheduler completing filter+score and issuing the binding POST during which cluster state can change: another pod could have been scheduled to the chosen node, consuming resources the scheduler thought were available. For a single-instance scheduler (which u7s always is), this window is the round-trip time of the binding request — typically under 5ms on a local API server. The practical risk is negligible.

**Do not run multiple scheduler replicas.** Two instances would both attempt to bind the same pod to potentially different nodes. The second binding would succeed (the API server does not prevent overwriting `spec.nodeName` via the binding subresource), resulting in an incorrect placement. u7s runs exactly one scheduler instance. This is not a limitation to work around — it is the correct architecture for a single-control-plane deployment (see §1 of architecture.md: no HA).

### Binding error handling

| HTTP status | Action |
|---|---|
| 201 Created | Success. |
| 409 Conflict | Pod already has a `spec.nodeName`. Another writer (or a previous scheduling attempt) got there first. Discard — the pod is no longer unscheduled. Log at debug level. |
| 404 Not Found | Pod was deleted between scheduling decision and binding. Discard. |
| 5xx | Transient API server error. Re-queue the pod with backoff. |

---

## 7. Failure Handling

When no node passes all four filters, the scheduler cannot place the pod. It must signal this to the user and retry.

### FailedScheduling event

```
POST /api/v1/namespaces/{namespace}/events
Content-Type: application/json

{
  "apiVersion": "v1",
  "kind": "Event",
  "metadata": {
    "name": "{pod-name}.{timestamp-hex}",
    "namespace": "{namespace}"
  },
  "involvedObject": {
    "apiVersion": "v1",
    "kind": "Pod",
    "name": "{pod-name}",
    "namespace": "{namespace}",
    "uid": "{pod-uid}"
  },
  "reason": "FailedScheduling",
  "message": "0/N nodes are available: M node(s) {filter-reason-1}, K node(s) {filter-reason-2}.",
  "type": "Warning",
  "eventTime": "{RFC3339}",
  "reportingComponent": "u7s-scheduler",
  "reportingInstance": "{scheduler-pod-name-or-hostname}",
  "action": "Scheduling",
  "count": 1,
  "firstTimestamp": "{RFC3339}",
  "lastTimestamp": "{RFC3339}"
}
```

The `message` field should aggregate filter failure reasons across all nodes: count how many nodes failed each filter and report them all. Example: `"0/3 nodes are available: 1 node(s) had untolerated taint node.kubernetes.io/not-ready:NoSchedule, 2 node(s) didn't match node selector."`.

Event names must be unique. Use `{pod-name}.{hex(current_time_nanos)}` or similar.

### Retry backoff

Maintain a retry queue (a `BinaryHeap<(Instant, PodKey)>` or similar) of pods that failed scheduling with the time at which they should next be retried.

- Initial backoff: 1 second.
- On each consecutive failure: double the backoff.
- Maximum backoff: 60 seconds.
- Reset: when a ADDED or MODIFIED Node event arrives, or any Pod event arrives (cluster state changed), flush the retry queue and re-attempt all waiting pods immediately. This ensures a newly added node triggers rapid rescheduling of pending pods.

The retry queue is purely in-memory. If the scheduler restarts, unscheduled pods will re-appear via the Pod watch ADDED events and re-enter the queue from scratch. No persistent state is needed.

---

## 8. Escape Hatch: Upstream kube-scheduler

**When to use:** The operator requires any of:
- Pod affinity or anti-affinity (`spec.affinity.podAffinity`, `spec.affinity.podAntiAffinity`)
- Node affinity beyond simple `nodeSelector` (`spec.affinity.nodeAffinity`)
- Topology spread constraints (`spec.topologySpreadConstraints`)
- Custom scheduler plugins via the K8s scheduling framework

(Preemption is no longer a reason to reach for this escape hatch — it is implemented
natively in `crates/scheduler`; see §1.)

**How to swap:**

1. Run the upstream `kube-scheduler` binary, pointing it at the u7s API server:
   ```
   kube-scheduler \
     --kubeconfig=/etc/u7s/scheduler.kubeconfig \
     --leader-elect=false
   ```
   `leader-elect=false` skips the Lease-based leader election, removing the `coordination.k8s.io/v1` dependency (see below).

2. Set `spec.schedulerName: default-scheduler` on pods that should use kube-scheduler. Pods with `spec.schedulerName: u7s-scheduler` or no scheduler name continue to use the u7s built-in scheduler (or disable the built-in scheduler entirely and route everything through kube-scheduler).

3. Disable the u7s built-in scheduler: run the u7s binary with `--no-scheduler` flag (to be implemented).

**What u7s API server must expose for kube-scheduler to work:**

| Requirement | Notes |
|---|---|
| Pod watch (`/api/v1/pods?watch=true`) | Available from Phase 1 |
| Node watch (`/api/v1/nodes?watch=true`) | Available from Phase 1 |
| Binding subresource (`POST /api/v1/namespaces/{ns}/pods/{name}/binding`) | Available from Phase 3 |
| Pod Events (`POST /api/v1/namespaces/{ns}/events`) | Available from Phase 1 |
| PV/PVC watch (for VolumeBinding plugin) | Available from Phase 3 |
| PDB watch (for disruption budget awareness) | Out of scope — disable PDB plugin |
| Leader election (`coordination.k8s.io/v1` Leases) | Only needed with `--leader-elect=true`. Run with `--leader-elect=false` to skip. |
| SubjectAccessReview | Only needed if kube-scheduler's authorization plugin is enabled. Disable it (`--authorization-always-allow-paths=*`) for Phase 3. |

All required endpoints are standard watch/list/create endpoints already in scope for the Phase 3 API surface.

**Memory cost:** kube-scheduler binary is ~30–50 MB RSS. Within the 128 MB total budget — it replaces the u7s built-in scheduler, not adds to it. Total scheduler budget in architecture.md is 5–10 MB; kube-scheduler consumes 25–40 MB more. Verify the full system stays under 128 MB RSS before committing to this path.

**The swap is cheap:** kube-scheduler speaks standard K8s watch API. It does not know or care whether the API server behind it is upstream or u7s. The only work required is ensuring u7s exposes the binding subresource and the Pod/Node watch endpoints, both of which are Phase 3 deliverables regardless of which scheduler is used.

---

## 9. Rust Implementation Sketch

### Crate recommendation: `kube`

Use the `kube` crate (client-side). Rationale: `kube` handles watch stream parsing, reconnect/relist on 410 Gone, `resourceVersion` tracking, and Kubernetes object deserialization. Writing this correctly with raw `reqwest` + `serde_json` requires reimplementing the watch reconnect logic, which is error-prone (the 410-Gone/relist cycle in particular). The `kube` crate is a client library only — it does not start any servers or impose process structure. Its runtime cost is negligible (it uses tokio, which the scheduler already needs).

If bundle size is a concern, `kube` with `default-features = false` and only the `client` feature reduces binary size significantly.

### Structs

```rust
pub struct Scheduler {
    node_cache: Arc<RwLock<NodeCache>>,
    client: kube::Client,
}

pub struct NodeCache {
    nodes: HashMap<String, NodeInfo>,
    allocated: HashMap<String, AllocatedResources>,
    pod_allocations: HashMap<String, (String, AllocatedResources)>, // uid → (node_name, resources)
}

pub struct NodeInfo {
    allocatable_cpu_m: u64,
    allocatable_mem_bytes: u64,
    labels: HashMap<String, String>,
    taints: Vec<Taint>,
    ready: bool,
    unschedulable: bool,
}

pub struct AllocatedResources {
    cpu_m: u64,
    mem_bytes: u64,
}
```

### Filter and score signatures

```rust
/// Returns Ok(()) if the node passes this filter for this pod.
/// Returns Err(reason) with a human-readable string if the node is rejected.
fn filter(pod: &Pod, node: &NodeInfo, allocated: &AllocatedResources) -> Result<(), String>;

/// Returns a score in [0.0, 1.0]. Higher is better.
fn score(pod: &Pod, node: &NodeInfo, allocated: &AllocatedResources) -> f64;
```

The outer loop calls `filter` for each (pod, node) pair and collects passing nodes, then calls `score` on each passing node.

### Main loop

```rust
async fn run(scheduler: Arc<Scheduler>) {
    let pod_watch = watch_unscheduled_pods(&scheduler.client);
    let node_watch = watch_all_nodes(&scheduler.client);
    let all_pod_watch = watch_all_pods(&scheduler.client); // for resource accounting
    let mut retry_queue: BinaryHeap<Reverse<(Instant, PodRef)>> = BinaryHeap::new();

    loop {
        tokio::select! {
            event = pod_watch.next() => {
                if let Some(WatchEvent::Added(pod) | WatchEvent::Modified(pod)) = event {
                    if is_unscheduled(&pod) {
                        schedule_pod(&scheduler, pod, &mut retry_queue).await;
                    }
                }
            }
            event = node_watch.next() => {
                handle_node_event(&scheduler.node_cache, event).await;
                // Cluster state changed — flush retry queue immediately
                drain_retry_queue(&scheduler, &mut retry_queue).await;
            }
            event = all_pod_watch.next() => {
                handle_pod_accounting_event(&scheduler.node_cache, event).await;
            }
            _ = next_retry_deadline(&retry_queue) => {
                drain_ready_retries(&scheduler, &mut retry_queue).await;
            }
        }
    }
}
```

### Scheduling a single pod

```rust
async fn schedule_pod(scheduler: &Scheduler, pod: Pod, retry_queue: &mut RetryQueue) {
    let cache = scheduler.node_cache.read().await;

    let candidates: Vec<(&str, f64)> = cache.nodes.iter()
        .filter_map(|(name, node_info)| {
            let allocated = cache.allocated.get(name).cloned().unwrap_or_default();
            if filter(&pod, node_info, &allocated).is_ok() {
                Some((name.as_str(), score(&pod, node_info, &allocated)))
            } else {
                None
            }
        })
        .collect();

    drop(cache); // release read lock before async I/O

    if candidates.is_empty() {
        emit_failed_scheduling_event(&scheduler.client, &pod).await;
        retry_queue.push(pod, backoff_duration(&pod));
        return;
    }

    // Sort by score descending, then by node name ascending for tie-break
    let chosen = candidates.iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)
            .then(b.0.cmp(a.0))) // note: reversed for name tie-break (ascending name = prefer lexicographically smaller)
        .map(|(name, _)| *name)
        .unwrap();

    match bind_pod(&scheduler.client, &pod, chosen).await {
        Ok(()) => { /* done */ }
        Err(BindError::AlreadyBound) => { /* discard */ }
        Err(BindError::NotFound) => { /* pod deleted, discard */ }
        Err(BindError::Transient(_)) => {
            retry_queue.push(pod, backoff_duration(&pod));
        }
    }
}
```

### Correctness risk: filter-to-bind window

**Flag:** Between the moment `schedule_pod` releases the read lock on `NodeCache` and the binding POST completes, another pod could be bound to the chosen node by a concurrent process (impossible in the single-scheduler u7s case) or the node's allocatable resources could change (possible if the node agent updates `status.allocatable`). The Pod accounting watch will catch the new pod on its next event, but there is a window.

For a single-instance scheduler, this window is the binding HTTP round-trip (~1–5ms). The consequence is a brief over-allocation: two pods are both scheduled to the same node, both expecting resource headroom. The node agent does not enforce CPU requests (those are set as cgroup limits at the container level by the runtime); memory requests are not enforced by the scheduler at all — they are just hints. In practice, a brief over-allocation at the scheduling level does not cause containers to be killed. The node's actual resource limits come from the cgroup configuration set by the container runtime, not from scheduler accounting.

**Resolution:** Document it, do not over-engineer it. A single-instance scheduler does not have the race condition between two scheduler instances. The node-state-change race is real but benign at this scale.

---

## 10. Phased Delivery

### Phase 1: No scheduler

`spec.nodeName` is set manually on all Pods. No scheduler binary exists. The API server accepts pods with `spec.nodeName` pre-set and the node agent picks them up.

### Phase 3: Scheduler enabled

Deliverables:
- `u7s-scheduler` binary (or in-process task)
- Watch setup for unscheduled pods, all nodes, all pods (for accounting)
- Filter pipeline: NodeReady, ResourceFit, NodeSelector, TaintToleration
- Score: LeastAllocated (bin-spread)
- Binding via `POST /api/v1/namespaces/{ns}/pods/{name}/binding`
- FailedScheduling event emission
- Retry queue with exponential backoff (1s → 60s cap)
- Retry flush on cluster state change (Node or Pod watch event)
- Reconnect/relist on watch disconnect

### Escape hatch: Phase 3 onward

The upstream `kube-scheduler` escape hatch is available from Phase 3 onward. It requires only the binding subresource and standard Pod/Node watch endpoints, which are Phase 3 deliverables. No additional API surface is needed beyond what Phase 3 already ships.

---

## Appendix: Kubernetes Quantity Parsing (Reference)

Kubernetes resource quantities use two suffix families:

**Binary (memory):** Ki=1024, Mi=1048576, Gi=1073741824, Ti, Pi, Ei
**Decimal (CPU, memory):** k=1000, M=1000000, G=1000000000, T, P, E

CPU is expressed in cores or millicores:
- `"1"` = 1000m
- `"0.5"` = 500m
- `"100m"` = 100m

Memory is expressed in bytes:
- `"256Mi"` = 268435456
- `"1Gi"` = 1073741824
- `"512k"` = 512000
- `"512Ki"` = 524288

Implement a small `parse_quantity(s: &str) -> Result<u64, ParseError>` utility that handles these cases. Return millicores for CPU, bytes for memory, based on context of the call site.
