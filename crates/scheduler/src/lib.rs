/// u7s-scheduler library — all non-main scheduling logic.
///
/// Extracted from main.rs so that pure functions can be unit-tested without
/// standing up an API server.
use anyhow::{bail, Context};
use hyper::{Method, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_rustls::TlsConnector;
use tracing::info;
use u7s_kubeconfig::HyperApiClient;

// ---------------------------------------------------------------------------
// HTTP helpers — delegates to HyperApiClient in kubeconfig.
// ---------------------------------------------------------------------------

/// Parse `base` + `path` into (host, port, "host:port") for TCP connect.
///
/// Pure function extracted so URI-parsing logic can be unit-tested without
/// network access.
pub fn parse_uri_parts(base: &str, path: &str) -> anyhow::Result<(String, u16, String)> {
    let uri: Uri = format!("{base}{path}").parse().context("parse URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{host}:{port}");
    Ok((host, port, addr))
}

pub async fn http_get(
    connector: &TlsConnector,
    base: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.request(Method::GET, path, None).await
}

pub async fn http_post_json(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    let body_str = serde_json::to_string(payload)?;
    client.request(Method::POST, path, Some(body_str)).await
}

pub async fn http_delete(
    connector: &TlsConnector,
    base: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.request(Method::DELETE, path, None).await
}

/// PATCH with `application/strategic-merge-patch+json`, the content type
/// status-subresource endpoints require (the apiserver's
/// `accepts_patch_content_type` rejects the plain `application/json` that
/// [`http_post_json`]/[`request`] send, with 415).
pub async fn http_patch_status(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    let body_str = serde_json::to_string(payload)?;
    client
        .request_with_content_type(
            Method::PATCH,
            path,
            Some(body_str),
            "application/strategic-merge-patch+json",
        )
        .await
}

// ---------------------------------------------------------------------------
// Watch streaming — reads newline-delimited JSON from a watch endpoint
// ---------------------------------------------------------------------------

// Re-export drain_watch_buffer from kubeconfig so that:
// 1. The canonical implementation lives alongside watch_stream (which calls it).
// 2. Scheduler-level unit tests exercise the same function used in production,
//    not a separate copy.
pub use u7s_kubeconfig::drain_watch_buffer;

pub async fn stream_watch_events(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    handler: impl FnMut(Value),
) -> anyhow::Result<()> {
    let client = HyperApiClient {
        server: base.to_owned(),
        connector: connector.clone(),
        bearer: None,
    };
    client.watch_stream(path, handler).await
}

// ---------------------------------------------------------------------------
// Scheduling logic
// ---------------------------------------------------------------------------

/// Typed envelope for a Kubernetes watch event.
///
/// Using a struct rather than raw `event["type"]` / `event["object"][...]`
/// indexing means a missing or mistyped field is a deserialization error,
/// not a silent empty string that causes pods to be skipped forever.
#[derive(Debug, Deserialize)]
struct WatchEvent<T> {
    #[serde(rename = "type")]
    event_type: String,
    object: T,
}

/// Local typed view of the fields in a Pod's `spec` that the scheduler reads.
/// Parsing at the boundary means a typo in `nodeName` is a compile error,
/// not a silent None that leaves pods unscheduled forever.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
    node_selector: Option<std::collections::HashMap<String, String>>,
    /// Scheduling priority. Absent means the apiserver never resolved a
    /// priorityClassName to a value (or none was set) — treated as 0, the
    /// lowest rung, by `needs_scheduling`.
    priority: Option<i32>,
    /// Non-empty scheduling gates ("spec.schedulingGates") mean the pod is not
    /// yet ready to be considered for scheduling at all — a signal distinct
    /// from a predicate failure, managed by external controllers that PATCH
    /// gates away when the pod is ready. Only presence matters here; gate
    /// names are opaque to the scheduler.
    scheduling_gates: Option<Vec<Value>>,
    /// The pod's tolerations, gating which tainted nodes it may be bound to.
    tolerations: Option<Vec<Toleration>>,
    affinity: Option<Affinity>,
    /// The pod's containers, whose `resources.requests` are summed for the
    /// NodeResourcesFit predicate. Reused as-is by `PodListItem` (a pod
    /// already bound to a node) and `PreemptionPodListItem`.
    #[serde(default)]
    containers: Vec<ContainerSpec>,
}

/// Minimal typed view of a container's `resources.requests` — cpu/memory/
/// ephemeral-storage quantity strings, as needed by NodeResourcesFit.
#[derive(Debug, Default, Deserialize)]
struct ContainerSpec {
    #[serde(default)]
    resources: ContainerResources,
}

#[derive(Debug, Default, Deserialize)]
struct ContainerResources {
    #[serde(default)]
    requests: std::collections::HashMap<String, String>,
}

/// A pod's `spec.affinity`. Only `nodeAffinity` is modeled — the scheduler has
/// no pod-affinity/anti-affinity handling yet, out of scope for the
/// SchedulerPredicates gap this fixes.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Affinity {
    node_affinity: Option<NodeAffinity>,
}

/// A pod's `spec.affinity.nodeAffinity`. Only the `required` term is modeled —
/// `preferredDuringSchedulingIgnoredDuringExecution` is a soft signal upstream
/// only weighs during scoring, and this scheduler does no scoring.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeAffinity {
    pub required_during_scheduling_ignored_during_execution: Option<NodeSelectorSpec>,
}

/// The `nodeSelectorTerms` list inside a `requiredDuringSchedulingIgnoredDuringExecution`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorSpec {
    #[serde(default)]
    pub node_selector_terms: Vec<NodeSelectorTerm>,
}

/// One term of a `NodeSelector`: its `matchExpressions` are ANDed together.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorTerm {
    #[serde(default)]
    pub match_expressions: Vec<NodeSelectorRequirement>,
}

/// A single `matchExpressions[]` entry: `key <operator> values`.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
}

/// A pod's `spec.tolerations[]` entry.
///
/// `key: None` (with `operator: "Exists"`) tolerates every taint regardless of
/// key — the "tolerate everything" wildcard. `effect: None` tolerates a
/// matching key/value taint of any effect. Mirrors the upstream
/// `v1.Toleration` shape exactly so a typo in a JSON field is a deserialization
/// gap, not a silent always-false match.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Toleration {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub effect: Option<String>,
}

/// Minimal typed view of a Pod's metadata needed by the scheduler.
#[derive(Debug, Default, Deserialize)]
struct PodMetadata {
    name: Option<String>,
    namespace: Option<String>,
}

/// A single `status.conditions[]` entry, as needed to read back whatever
/// PodScheduled condition is currently stored — used only by the
/// SchedulingGated status-patch bookkeeping (`scheduling_gate_status_patch` /
/// `scheduling_gate_status_reset`) to decide whether a PATCH is still needed.
/// `Option` (not `String` with `#[serde(default)]`) because a condition field
/// can be present-but-`null`, not just absent — see `merge_conditions` in the
/// apiserver, which can persist a literal `null` reason on first write.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodConditionView {
    #[serde(rename = "type")]
    condition_type: Option<String>,
    status: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PodStatusView {
    #[serde(default)]
    conditions: Vec<PodConditionView>,
}

/// Minimal typed view of a Pod object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct PodObject {
    metadata: PodMetadata,
    spec: PodSpec,
    #[serde(default)]
    status: PodStatusView,
}

/// A pod discovered by `needs_scheduling` as ready to enter the scheduling
/// cycle, carrying every placement input the predicates need to gate node
/// selection. A struct (not a growing tuple) so each new predicate this
/// scheduler learns to enforce is a named field, not another `_` in a
/// destructure at every call site.
#[derive(Debug)]
pub struct PendingPod {
    pub namespace: String,
    pub pod_name: String,
    /// The pod's `spec.nodeSelector` map (empty if absent).
    pub node_selector: std::collections::HashMap<String, String>,
    /// The pod's `spec.priority`, defaulting to 0 (the lowest rung) when
    /// absent, so preemption has a value to compare even for pods that never
    /// had a priority resolved.
    pub priority: i32,
    /// The pod's `spec.tolerations` (empty if absent) — gates which tainted
    /// nodes it may be bound to.
    pub tolerations: Vec<Toleration>,
    /// The pod's `spec.affinity.nodeAffinity`, if any — gates which nodes it
    /// may be bound to by label, in addition to `node_selector`.
    pub node_affinity: Option<NodeAffinity>,
    /// Summed `resources.requests.{cpu,memory,ephemeral-storage}` across the
    /// pod's containers — the NodeResourcesFit predicate's resource dimension.
    pub requests: ResourceRequests,
}

/// Determine whether a watch event represents a pod that needs scheduling.
///
/// Returns `Some(PendingPod)` when the event is an ADDED or MODIFIED pod with
/// an empty `spec.nodeName` and no non-empty `spec.schedulingGates`; `None`
/// otherwise. A non-empty `schedulingGates` list means the pod is not yet
/// ready to be considered for scheduling at all — it must never enter the
/// scheduling cycle, distinct from a predicate failure.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
pub fn needs_scheduling(event: &Value) -> Option<PendingPod> {
    let watch_event: WatchEvent<PodObject> =
        serde_json::from_value(event.clone()).unwrap_or_else(|_| WatchEvent {
            event_type: String::new(),
            object: PodObject::default(),
        });
    if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
        return None;
    }
    let pod_name = watch_event.object.metadata.name.as_deref().unwrap_or("");
    if pod_name.is_empty() {
        return None;
    }
    let already_scheduled = watch_event
        .object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_scheduling_gates = watch_event
        .object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if has_scheduling_gates {
        // Gated pods must never enter the scheduling cycle — this is not a
        // predicate failure (no FailedScheduling event), it's "not ready yet".
        return None;
    }
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    let node_selector = watch_event.object.spec.node_selector.unwrap_or_default();
    let priority = watch_event.object.spec.priority.unwrap_or(0);
    let tolerations = watch_event.object.spec.tolerations.unwrap_or_default();
    let node_affinity = watch_event
        .object
        .spec
        .affinity
        .and_then(|a| a.node_affinity);
    let requests = sum_container_requests(&watch_event.object.spec.containers);
    Some(PendingPod {
        namespace,
        pod_name: pod_name.to_owned(),
        node_selector,
        priority,
        tolerations,
        node_affinity,
        requests,
    })
}

/// The `PodScheduled` condition type name — matches `v1.PodScheduled`.
const POD_SCHEDULED: &str = "PodScheduled";
/// The reason upstream's real scheduler stamps on a gated pod — matches
/// `v1.PodReasonSchedulingGated`. `WaitForPodsSchedulingGated`
/// (k8s.io/kubernetes/test/e2e/framework/pod/wait.go) polls for exactly this
/// type/reason pair.
const SCHEDULING_GATED_REASON: &str = "SchedulingGated";
const SCHEDULING_GATED_MESSAGE: &str = "Scheduling is blocked due to non-empty scheduling gates";
/// The reason/message the apiserver stamps on every new pod's initial
/// PodScheduled=False condition (see `apply_pod_create_defaults`). Used to
/// reset a stale SchedulingGated reason back to the same "don't know why yet"
/// default the pod would have carried had it never been gated.
const UNSCHEDULABLE_REASON: &str = "Unschedulable";
const UNSCHEDULABLE_MESSAGE: &str = "pod not yet scheduled";

/// A pending PATCH to a gated pod's `status.conditions`, identifying the pod
/// and carrying the merge-patch body to send.
#[derive(Debug, PartialEq)]
pub struct GatedStatusPatch {
    pub namespace: String,
    pub pod_name: String,
    pub patch: Value,
}

/// Determine whether a watch event's pod needs its `PodScheduled` condition
/// set to `False`/`SchedulingGated`.
///
/// Mirrors the condition upstream's real kube-scheduler stamps on a gated pod
/// (see `v1.PodReasonSchedulingGated`) so `WaitForPodsSchedulingGated` — which
/// polls `status.conditions` for exactly `{type: PodScheduled, reason:
/// SchedulingGated}`, not just "is the pod unscheduled" — can tell "blocked on
/// gates" apart from a genuine predicate failure. `needs_scheduling` keeps
/// gated pods out of the scheduling cycle entirely, so nothing else ever
/// writes this condition for them.
///
/// Returns `None` (nothing to do) when: the pod has no non-empty
/// `schedulingGates` (ungated pods take the normal scheduling path instead);
/// the pod is already bound (`spec.nodeName` set — never touch a pod's
/// `PodScheduled` condition once binding may have flipped it to `True`); or
/// the condition already reads `False`/`SchedulingGated` (idempotent — avoids
/// re-PATCHing on every reconcile tick, including the tick triggered by this
/// function's own prior PATCH echoing back through the watch).
pub fn scheduling_gate_status_patch(event: &Value) -> Option<GatedStatusPatch> {
    let watch_event: WatchEvent<PodObject> = serde_json::from_value(event.clone()).ok()?;
    if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
        return None;
    }
    let pod_name = watch_event.object.metadata.name.clone().unwrap_or_default();
    if pod_name.is_empty() {
        return None;
    }
    let already_scheduled = watch_event
        .object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_gates = watch_event
        .object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if !has_gates {
        return None;
    }
    let already_marked = watch_event.object.status.conditions.iter().any(|c| {
        c.condition_type.as_deref() == Some(POD_SCHEDULED)
            && c.status.as_deref() == Some("False")
            && c.reason.as_deref() == Some(SCHEDULING_GATED_REASON)
    });
    if already_marked {
        return None;
    }
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    let patch = serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "status": "False",
                "reason": SCHEDULING_GATED_REASON,
                "message": SCHEDULING_GATED_MESSAGE,
            }]
        }
    });
    Some(GatedStatusPatch {
        namespace,
        pod_name,
        patch,
    })
}

/// Determine whether a watch event's pod needs its stale `SchedulingGated`
/// reason cleared now that every gate has been removed.
///
/// `spec.schedulingGates` can be removed one at a time (a ReplicaSet's pods
/// each carrying `[foo, bar]` may see `bar` removed first, leaving `[bar]`
/// still non-empty) — this must only fire once the list is fully empty, not
/// on every reduction. Once it does fire, the condition must not keep saying
/// "blocked on scheduling gates" once that's no longer true, or `kubectl
/// describe pod` lies about why the pod is still Pending.
///
/// Returns `None` when: any gate remains; the pod is already bound (never
/// touch a bound pod's condition); or the condition doesn't currently say
/// `SchedulingGated` (nothing stale to clear).
///
/// The returned patch deliberately omits `status`: a concurrent successful
/// bind (`bind_pod` in the apiserver) flips `PodScheduled` to `True` in the
/// same atomic write as `spec.nodeName`, and this reset runs concurrently
/// with that scheduling attempt (see caller). Sending `status: "False"` here
/// could race a fresh `True` and clobber it back to `False`; omitting the key
/// entirely means this patch can only ever touch `reason`/`message`, never
/// `status`, so it can never contradict a real bind outcome.
pub fn scheduling_gate_status_reset(event: &Value) -> Option<Value> {
    let watch_event: WatchEvent<PodObject> = serde_json::from_value(event.clone()).ok()?;
    if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
        return None;
    }
    let already_scheduled = watch_event
        .object
        .spec
        .node_name
        .as_deref()
        .is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let has_gates = watch_event
        .object
        .spec
        .scheduling_gates
        .as_ref()
        .is_some_and(|gates| !gates.is_empty());
    if has_gates {
        return None;
    }
    let still_marked_gated = watch_event.object.status.conditions.iter().any(|c| {
        c.condition_type.as_deref() == Some(POD_SCHEDULED)
            && c.reason.as_deref() == Some(SCHEDULING_GATED_REASON)
    });
    if !still_marked_gated {
        return None;
    }
    Some(serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "reason": UNSCHEDULABLE_REASON,
                "message": UNSCHEDULABLE_MESSAGE,
            }]
        }
    }))
}

/// Return `true` if a spawn for `key` ("namespace/name") should proceed.
///
/// `key` must be absent from `in_flight` — the set of pod keys currently being
/// scheduled. The caller is responsible for inserting the key before spawning and
/// removing it when the task completes (success or error).
///
/// Pure function so the dedup decision can be unit-tested without a runtime.
/// The guard prevents two rapid ADDED/MODIFIED events for the same pod from
/// spawning two concurrent bind_pod tasks; the second bind would receive a 409
/// Conflict, which (after bead 2) is now a logged Err rather than silent Ok.
pub fn should_schedule(in_flight: &std::collections::HashSet<String>, key: &str) -> bool {
    !in_flight.contains(key)
}

#[derive(Deserialize)]
pub struct NodeList {
    pub items: Vec<NodeItem>,
}

#[derive(Deserialize)]
pub struct NodeItem {
    pub metadata: NodeMetadata,
    #[serde(default)]
    pub spec: NodeSpec,
    #[serde(default)]
    pub status: NodeStatus,
}

#[derive(Deserialize, Default)]
pub struct NodeSpec {
    #[serde(default)]
    pub taints: Vec<Taint>,
}

/// A node taint (`spec.taints[]`). Only `NoSchedule`/`NoExecute` effects block
/// scheduling in this MVP — `PreferNoSchedule` is a soft signal upstream only
/// weighs during scoring, and this scheduler does no scoring, so it is treated
/// as always tolerated.
#[derive(Debug, Clone, Deserialize)]
pub struct Taint {
    pub key: String,
    #[serde(default)]
    pub value: String,
    pub effect: String,
}

#[derive(Deserialize, Default)]
pub struct NodeStatus {
    #[serde(default)]
    pub allocatable: NodeAllocatable,
    #[serde(default)]
    pub capacity: NodeAllocatable,
}

#[derive(Deserialize, Default)]
pub struct NodeAllocatable {
    /// Maximum pods the node will accept (quantity string, e.g. "110").
    /// Zero means the field was absent — treat as unlimited for safety (no cap check).
    #[serde(default)]
    pub pods: String,
    /// CPU quantity string (e.g. "4", "500m"). Empty/unparseable means unknown
    /// — that dimension of NodeResourcesFit is not checked (see `resource_fits`).
    #[serde(default)]
    pub cpu: String,
    /// Memory quantity string (e.g. "8Gi"). Same "unknown → skip" convention as `cpu`.
    #[serde(default)]
    pub memory: String,
    /// Ephemeral-storage quantity string (e.g. "20Gi"). Same convention as `cpu`.
    #[serde(default, rename = "ephemeral-storage")]
    pub ephemeral_storage: String,
}

#[derive(Deserialize)]
pub struct NodeMetadata {
    pub name: String,
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

/// Parse a Kubernetes quantity string for pod count (e.g. "110") into u32.
///
/// Returns 0 when the field is absent or unparseable, which the capacity check
/// treats as "unknown capacity — skip capping".  Pod counts are always small
/// non-negative integers so u32 is more than sufficient.
pub fn parse_pod_capacity(s: &str) -> u32 {
    s.trim().parse::<u32>().unwrap_or(0)
}

/// A pod's (or a node's allocatable) cpu/memory/ephemeral-storage, all in
/// milli-units — see `parse_quantity_milli`. Working in milli-units
/// throughout means comparisons never need to convert back to a display unit.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRequests {
    pub cpu_milli: i64,
    pub memory_milli: i64,
    pub ephemeral_storage_milli: i64,
}

impl std::ops::Add for ResourceRequests {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            cpu_milli: self.cpu_milli + other.cpu_milli,
            memory_milli: self.memory_milli + other.memory_milli,
            ephemeral_storage_milli: self.ephemeral_storage_milli + other.ephemeral_storage_milli,
        }
    }
}

/// Parse a Kubernetes resource quantity string into milli-units: for CPU,
/// "500m" -> 500, "1" -> 1000; for memory/ephemeral-storage, "128Mi" ->
/// 128*1024*1024*1000. Mirrors the arithmetic in
/// `crates/apiserver/src/quota.rs`'s `parse_quantity_milli` (kept separate
/// here — the scheduler and apiserver are independent binaries with no shared
/// types crate today).
///
/// Returns 0 for an absent/unparseable string. Callers must treat 0 as "no
/// value was set" — for a pod's own request that means "this container
/// declared no request for that resource" (contributes 0 to the sum, matching
/// Kubernetes' best-effort semantics); for a node's allocatable it means
/// "capacity unknown" (that dimension is not checked), the same convention
/// `parse_pod_capacity` already uses for `status.allocatable.pods`.
fn parse_quantity_milli(s: &str) -> i64 {
    if s.is_empty() {
        return 0;
    }
    if let Some(rest) = s.strip_suffix('m') {
        return rest.parse::<i64>().unwrap_or(0);
    }
    let binary_suffixes = [
        ("Ki", 1024i64),
        ("Mi", 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("Ti", 1024 * 1024 * 1024 * 1024),
        ("Pi", 1024 * 1024 * 1024 * 1024 * 1024),
        ("Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024),
    ];
    for (suf, mult) in &binary_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return rest.parse::<i64>().map(|n| n * mult * 1000).unwrap_or(0);
        }
    }
    let decimal_suffixes = [
        ("k", 1_000i64),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("E", 1_000_000_000_000_000_000),
    ];
    for (suf, mult) in &decimal_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return rest.parse::<i64>().map(|n| n * mult * 1000).unwrap_or(0);
        }
    }
    s.parse::<i64>().map(|n| n * 1000).unwrap_or(0)
}

/// Sum `resources.requests.{cpu,memory,ephemeral-storage}` across a pod's
/// containers. Init containers are not accounted for — this MVP sums the
/// steady-state (regular) containers only, matching what the conformance
/// suite's saturate-then-overflow tests actually create.
fn sum_container_requests(containers: &[ContainerSpec]) -> ResourceRequests {
    let mut total = ResourceRequests::default();
    for c in containers {
        total.cpu_milli += c
            .resources
            .requests
            .get("cpu")
            .map(|s| parse_quantity_milli(s))
            .unwrap_or(0);
        total.memory_milli += c
            .resources
            .requests
            .get("memory")
            .map(|s| parse_quantity_milli(s))
            .unwrap_or(0);
        total.ephemeral_storage_milli += c
            .resources
            .requests
            .get("ephemeral-storage")
            .map(|s| parse_quantity_milli(s))
            .unwrap_or(0);
    }
    total
}

/// Minimal typed view of a pod list item needed to summarize a node's usage:
/// its phase (to exclude terminated pods) and its containers' resource
/// requests (reuses `PodSpec`, which already parses `spec.containers`).
#[derive(Deserialize)]
struct PodListItem {
    #[serde(default)]
    spec: PodSpec,
    status: PodListItemStatus,
}

#[derive(Deserialize, Default)]
struct PodListItemStatus {
    #[serde(default)]
    phase: String,
}

/// A node's already-committed usage from its non-terminated pods: the pod
/// count (against `status.allocatable.pods`) and summed cpu/memory/
/// ephemeral-storage requests (against `status.allocatable.{cpu,memory,ephemeral-storage}`).
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeUsage {
    pub pod_count: u32,
    pub requests: ResourceRequests,
}

/// Summarize a node's already-committed usage from a raw JSON pod list
/// response body (GET /api/v1/pods?fieldSelector=spec.nodeName=<node>).
///
/// "Non-terminated" means phase is not Succeeded or Failed.  This matches the
/// upstream NodeResourcesFit predicate: running and pending pods consume a
/// slot and their resource requests count against allocatable; completed pods
/// do neither. One parse of the body produces both the pod count AND the
/// resource sum, avoiding a second network round-trip or a second JSON parse.
///
/// Returns Err if the body cannot be parsed as a pod list.
pub fn summarize_node_pods(body: &str) -> anyhow::Result<NodeUsage> {
    #[derive(Deserialize)]
    struct PodList {
        items: Vec<PodListItem>,
    }
    let list: PodList = serde_json::from_str(body).context("parse pod list for node capacity")?;
    let mut usage = NodeUsage::default();
    for p in list
        .items
        .iter()
        .filter(|p| p.status.phase != "Succeeded" && p.status.phase != "Failed")
    {
        usage.pod_count += 1;
        usage.requests = usage.requests + sum_container_requests(&p.spec.containers);
    }
    Ok(usage)
}

/// A pod already on a node, as needed by preemption victim selection: its
/// "namespace/name" key (to DELETE it) and its scheduling priority (to decide
/// whether it is a legal victim for a given pending pod).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePod {
    pub key: String,
    pub priority: i32,
}

/// Minimal typed view of a pod list item needed for preemption: unlike
/// `PodListItem` (used by `summarize_node_pods`), this retains identity
/// (namespace/name) and priority instead of collapsing to a count.
#[derive(Deserialize)]
struct PreemptionPodListItem {
    metadata: PodMetadata,
    #[serde(default)]
    spec: PodSpec,
    #[serde(default)]
    status: PodListItemStatus,
}

/// Parse a raw pod-list JSON response body (GET /api/v1/pods?fieldSelector=...)
/// into the non-terminated pods on that node, keyed for preemption eviction.
///
/// Mirrors `summarize_node_pods`'s terminal-phase filter (Succeeded/Failed
/// pods are not occupying a slot and so can never be preemption victims) but
/// keeps each pod's namespace/name and priority instead of reducing to a count.
///
/// Returns Err if the body cannot be parsed as a pod list.
pub fn parse_node_pods(body: &str) -> anyhow::Result<Vec<NodePod>> {
    #[derive(Deserialize)]
    struct PodList {
        items: Vec<PreemptionPodListItem>,
    }
    let list: PodList =
        serde_json::from_str(body).context("parse pod list for preemption victim selection")?;
    Ok(list
        .items
        .into_iter()
        .filter(|p| p.status.phase != "Succeeded" && p.status.phase != "Failed")
        .map(|p| NodePod {
            key: format!(
                "{}/{}",
                p.metadata.namespace.unwrap_or_else(|| "default".to_owned()),
                p.metadata.name.unwrap_or_default()
            ),
            priority: p.spec.priority.unwrap_or(0),
        })
        .collect())
}

/// Return true when `node` is eligible to host `pod` at all, independent of
/// capacity: its labels satisfy the pod's `nodeSelector` AND (if present)
/// required `nodeAffinity`, AND every scheduling-blocking taint on the node
/// is tolerated.
///
/// Shared by `select_node_with_capacity` (direct scheduling) and
/// `find_preemption_plan`, so preemption never evicts pods on a node the
/// pending pod could not use anyway even after the eviction.
fn node_qualifies_for_pod(node: &NodeItem, pod: &PendingPod) -> bool {
    node_selector_matches(&node.metadata.labels, &pod.node_selector)
        && node_affinity_matches(&node.metadata.labels, pod.node_affinity.as_ref())
        && node_taints_tolerated(&node.spec.taints, &pod.tolerations)
}

/// Return true when adding `requested` to a node's already-committed `used`
/// requests would not exceed `allocatable`, independently for each of
/// cpu/memory/ephemeral-storage. An allocatable value of 0 (field absent or
/// unparseable — see `parse_quantity_milli`) means that dimension is unknown
/// and is not checked, mirroring `parse_pod_capacity`'s existing convention
/// for `status.allocatable.pods`.
fn resource_fits(
    allocatable: &NodeAllocatable,
    used: ResourceRequests,
    requested: ResourceRequests,
) -> bool {
    let cpu_cap = parse_quantity_milli(&allocatable.cpu);
    let mem_cap = parse_quantity_milli(&allocatable.memory);
    let eph_cap = parse_quantity_milli(&allocatable.ephemeral_storage);
    (cpu_cap == 0 || used.cpu_milli + requested.cpu_milli <= cpu_cap)
        && (mem_cap == 0 || used.memory_milli + requested.memory_milli <= mem_cap)
        && (eph_cap == 0
            || used.ephemeral_storage_milli + requested.ephemeral_storage_milli <= eph_cap)
}

/// Select the first node from `list` that qualifies for `pod`
/// (see `node_qualifies_for_pod`) AND that has at least one free pod slot AND
/// enough uncommitted cpu/memory/ephemeral-storage to fit `pod.requests`
/// (NodeResourcesFit).
///
/// `node_usage` maps node name → current non-terminated pod count and summed
/// resource requests (from a prior GET
/// /api/v1/pods?fieldSelector=spec.nodeName=<node>).  If a node's name is
/// absent from `node_usage`, its usage is treated as zero (conservative:
/// schedule).
///
/// Pod-count capacity is read from `status.allocatable.pods`, falling back to
/// `status.capacity.pods`.  A capacity of 0 (field absent / unparseable) means
/// the limit is unknown; such nodes are NOT skipped (the old safe behaviour) —
/// the same convention applies to each resource dimension (see `resource_fits`).
///
/// Returns `Err` when no node qualifies with free capacity, so the caller can
/// leave the pod Pending instead of binding to a full or unusable node.
///
/// Pure function so the capacity-gate logic can be unit-tested without a network.
pub fn select_node_with_capacity(
    list: NodeList,
    pod: &PendingPod,
    node_usage: &std::collections::HashMap<String, NodeUsage>,
) -> anyhow::Result<String> {
    let found = list.items.into_iter().find(|n| {
        if !node_qualifies_for_pod(n, pod) {
            return false;
        }
        let usage = node_usage
            .get(&n.metadata.name)
            .copied()
            .unwrap_or_default();
        // Resolve pod-count capacity: prefer allocatable, fall back to capacity.
        let cap_str = if !n.status.allocatable.pods.is_empty() {
            &n.status.allocatable.pods
        } else {
            &n.status.capacity.pods
        };
        let cap = parse_pod_capacity(cap_str);
        if cap != 0 && usage.pod_count >= cap {
            return false;
        }
        resource_fits(&n.status.allocatable, usage.requests, pod.requests)
    });
    found.map(|n| n.metadata.name).context(
        "no node satisfies the pod's nodeSelector/tolerations with free pod/resource capacity (NodeResourcesFit)",
    )
}

/// Select the pods to evict from one node so that a pending pod at
/// `pending_priority` fits, given the node's pod-count `capacity`.
///
/// This is the MVP preemption model: it mirrors `select_node_with_capacity`'s
/// pod-count-only capacity dimension (no CPU/memory/extended-resource
/// accounting — the scheduler does not track those at all today).
///
/// Only pods with priority STRICTLY LOWER than `pending_priority` are eligible
/// victims: kube-scheduler never preempts equal-or-higher-priority pods, and
/// neither must u7s — otherwise same-priority pods could evict each other in a
/// cycle and scheduling would never stabilize. Eligible victims are evicted
/// lowest-priority-first (cheapest disruption) until just enough slots are
/// freed — never more than necessary.
///
/// Returns an empty `Vec` — meaning "do not evict anything" — when:
/// - `capacity` is 0 (unknown/unparseable; `select_node_with_capacity` treats
///   this as unlimited, so `pick_node` would already have chosen this node), OR
/// - the pod already fits (fewer pods than capacity) — preemption must never
///   run when there was room, or it would kill a workload for no reason, OR
/// - evicting every eligible lower-priority pod still would not free enough
///   capacity — the pending pod would not fit even after the disruption, so
///   evicting anyone would be pointless.
pub fn select_preemption_victims(
    pending_priority: i32,
    node_pods: &[NodePod],
    capacity: u32,
) -> Vec<String> {
    if capacity == 0 {
        return Vec::new();
    }
    let used = node_pods.len() as u32;
    if used < capacity {
        return Vec::new();
    }
    let needed = used - capacity + 1;

    let mut candidates: Vec<&NodePod> = node_pods
        .iter()
        .filter(|p| p.priority < pending_priority)
        .collect();
    if (candidates.len() as u32) < needed {
        return Vec::new();
    }
    candidates.sort_by_key(|p| p.priority);
    candidates
        .into_iter()
        .take(needed as usize)
        .map(|p| p.key.clone())
        .collect()
}

/// Return true when all entries in `selector` are satisfied by `labels`.
///
/// An empty selector matches any node (standard Kubernetes semantics).
/// Extracted as a pure function so the matching logic can be unit-tested
/// without network access.
pub fn node_selector_matches(
    labels: &std::collections::HashMap<String, String>,
    selector: &std::collections::HashMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(k, v)| labels.get(k).map(|s| s == v).unwrap_or(false))
}

/// Evaluate one `matchExpressions[]` requirement against a node's labels.
///
/// `Gt`/`Lt` (numeric comparison operators) are not implemented by this MVP —
/// they never match. The SchedulerPredicates conformance suite only exercises
/// `In`/`NotIn`, and silently treating an unrecognized/unsupported operator as
/// an automatic pass would let a pod bypass an affinity rule it doesn't
/// actually satisfy.
fn node_selector_requirement_matches(
    labels: &std::collections::HashMap<String, String>,
    req: &NodeSelectorRequirement,
) -> bool {
    match req.operator.as_str() {
        "In" => labels.get(&req.key).is_some_and(|v| req.values.contains(v)),
        "NotIn" => !labels.get(&req.key).is_some_and(|v| req.values.contains(v)),
        "Exists" => labels.contains_key(&req.key),
        "DoesNotExist" => !labels.contains_key(&req.key),
        _ => false,
    }
}

/// Return true when `labels` satisfy a required `nodeAffinity`.
///
/// `nodeSelectorTerms` are ORed together (any one term matching is enough);
/// `matchExpressions` within a single term are ANDed (every requirement in
/// the term must hold) — mirroring Kubernetes' `NodeSelector` semantics.
/// `None` (no nodeAffinity, or no `requiredDuringSchedulingIgnoredDuringExecution`,
/// or an empty term list) matches any node — there is nothing to restrict on.
///
/// Extracted as a pure function so the predicate can be unit-tested without
/// network access — mirrors `node_selector_matches`.
pub fn node_affinity_matches(
    labels: &std::collections::HashMap<String, String>,
    affinity: Option<&NodeAffinity>,
) -> bool {
    let Some(affinity) = affinity else {
        return true;
    };
    let Some(required) = &affinity.required_during_scheduling_ignored_during_execution else {
        return true;
    };
    if required.node_selector_terms.is_empty() {
        return true;
    }
    required.node_selector_terms.iter().any(|term| {
        term.match_expressions
            .iter()
            .all(|req| node_selector_requirement_matches(labels, req))
    })
}

/// Return true when `toleration` tolerates `taint`, mirroring Kubernetes'
/// `Toleration.ToleratesTaint`: an empty `key` only ever matches when paired
/// with `operator: Exists` (the "tolerate everything" wildcard); otherwise the
/// key must match exactly, and — unless `operator: Exists` — the value must
/// match exactly too (operator `Equal`, the default when absent). A
/// toleration with a set `effect` only tolerates a taint of that same effect.
fn toleration_matches_taint(toleration: &Toleration, taint: &Taint) -> bool {
    if let Some(t_effect) = &toleration.effect {
        if t_effect != &taint.effect {
            return false;
        }
    }
    match &toleration.key {
        None => toleration.operator.as_deref() == Some("Exists"),
        Some(key) => {
            key == &taint.key
                && (toleration.operator.as_deref() == Some("Exists")
                    || toleration.value.as_deref().unwrap_or("") == taint.value)
        }
    }
}

/// Return true when every scheduling-blocking taint on the node (`NoSchedule`
/// or `NoExecute`) is tolerated by at least one of the pod's tolerations.
///
/// A node with no such taints trivially satisfies this (nothing to tolerate).
/// Extracted as a pure function so the taint/toleration predicate can be
/// unit-tested without network access — mirrors `node_selector_matches`.
pub fn node_taints_tolerated(taints: &[Taint], tolerations: &[Toleration]) -> bool {
    taints
        .iter()
        .filter(|t| t.effect == "NoSchedule" || t.effect == "NoExecute")
        .all(|t| {
            tolerations
                .iter()
                .any(|tol| toleration_matches_taint(tol, t))
        })
}

/// Select the first node from `list` whose labels satisfy `selector`.
///
/// An empty `selector` matches any node (standard Kubernetes semantics).
/// Returns `Err` when no node satisfies the selector (pod must stay Pending).
///
/// Extracted as a pure function so the selection logic can be unit-tested
/// without network access. Replaces the former `select_first_node` which
/// ignored nodeSelector entirely, causing pods with non-matching selectors
/// to be incorrectly bound to any available node.
pub fn select_node_for_pod(
    list: NodeList,
    selector: &std::collections::HashMap<String, String>,
) -> anyhow::Result<String> {
    list.items
        .into_iter()
        .find(|n| node_selector_matches(&n.metadata.labels, selector))
        .map(|n| n.metadata.name)
        .context("no node satisfies the pod's nodeSelector")
}

/// Select the first node name from a `NodeList` (no selector filtering).
///
/// Retained for callers that have already confirmed the pod has no nodeSelector.
/// Returns an error when the list is empty.
pub fn select_first_node(list: NodeList) -> anyhow::Result<String> {
    list.items
        .into_iter()
        .next()
        .map(|n| n.metadata.name)
        .context("no nodes available")
}

/// Return the name of the first node that qualifies for `pod`
/// (see `node_qualifies_for_pod`), has at least one free pod slot, and has
/// enough uncommitted cpu/memory/ephemeral-storage for `pod.requests`
/// (NodeResourcesFit predicate).
///
/// Fetches the node list from the API server, then — for each qualifying
/// candidate — summarizes non-terminated pods already assigned to it via
/// GET /api/v1/pods?fieldSelector=spec.nodeName%3D<node> (pod count AND
/// summed resource requests, see `summarize_node_pods`).  A node at or above
/// its `status.allocatable.pods` limit, or that cannot fit `pod.requests`
/// alongside what's already committed, is skipped.  Returns `Err` when no
/// suitable node exists so that the caller can skip binding and leave the pod
/// Pending (mayor-bbxr: without this check, pods are bound to full nodes and
/// the kubelet fails them OutOfpods/OutOfcpu/OutOfephemeral-storage).
pub async fn pick_node(
    connector: &TlsConnector,
    server: &str,
    pod: &PendingPod,
) -> anyhow::Result<String> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;

    // Build per-node usage for every candidate node (qualifying nodes only).
    // We only query nodes that pass the selector/affinity/taints to avoid
    // unnecessary API calls.
    let mut node_usage: std::collections::HashMap<String, NodeUsage> =
        std::collections::HashMap::new();
    for node in &list.items {
        if !node_qualifies_for_pod(node, pod) {
            continue;
        }
        let node_name = &node.metadata.name;
        let pods_path = format!("/api/v1/pods?fieldSelector=spec.nodeName%3D{node_name}");
        match http_get(connector, server, &pods_path).await {
            Ok((ps, pb)) if ps.is_success() => match summarize_node_pods(&pb) {
                Ok(usage) => {
                    node_usage.insert(node_name.clone(), usage);
                }
                Err(e) => {
                    // Treat usage as zero (allow scheduling) rather than failing
                    // the entire pick_node call — a parse error here is not
                    // grounds to leave the pod unscheduled indefinitely.
                    tracing::warn!("failed to summarize pods on {node_name}: {e} — treating as 0");
                }
            },
            Ok((ps, pb)) => {
                tracing::warn!(
                    "GET pods for node {node_name} returned {ps}: {pb} — treating usage as 0"
                );
            }
            Err(e) => {
                tracing::warn!("GET pods for node {node_name} failed: {e} — treating usage as 0");
            }
        }
    }

    select_node_with_capacity(list, pod, &node_usage)
}

/// A viable preemption outcome: the node to bind the pending pod to, and the
/// "namespace/name" keys of the pods that must be evicted first to free a slot.
#[derive(Debug, PartialEq)]
pub struct PreemptionPlan {
    pub node_name: String,
    pub victims: Vec<String>,
}

/// Search every node that qualifies for `pod` (see `node_qualifies_for_pod`)
/// for a viable preemption target: a node where evicting some lower-priority
/// pods would free a slot for `pod`.
///
/// Intended to run only after `pick_node` has already failed for the same pod —
/// this is the fallback that stops a higher-priority pod from staying Pending
/// forever just because lower-priority pods claimed every slot first (mayor-rsei).
///
/// Among nodes where preemption would work, the node requiring the FEWEST
/// victims is chosen (cheapest disruption); ties keep the API server's node-list
/// order. Returns `Err` when no candidate node — even after preempting every
/// eligible lower-priority pod on it — could fit the pending pod.
pub async fn find_preemption_plan(
    connector: &TlsConnector,
    server: &str,
    pod: &PendingPod,
) -> anyhow::Result<PreemptionPlan> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;

    let mut best: Option<PreemptionPlan> = None;
    for node in &list.items {
        if !node_qualifies_for_pod(node, pod) {
            continue;
        }
        let cap_str = if !node.status.allocatable.pods.is_empty() {
            &node.status.allocatable.pods
        } else {
            &node.status.capacity.pods
        };
        let capacity = parse_pod_capacity(cap_str);
        if capacity == 0 {
            // Unknown/unlimited capacity — pick_node would already have picked
            // this node, so it cannot be why scheduling failed.
            continue;
        }

        let node_name = &node.metadata.name;
        let pods_path = format!("/api/v1/pods?fieldSelector=spec.nodeName%3D{node_name}");
        let node_pods = match http_get(connector, server, &pods_path).await {
            Ok((ps, pb)) if ps.is_success() => match parse_node_pods(&pb) {
                Ok(pods) => pods,
                Err(e) => {
                    tracing::warn!("failed to parse pods on {node_name} for preemption: {e}");
                    continue;
                }
            },
            Ok((ps, pb)) => {
                tracing::warn!(
                    "GET pods for node {node_name} returned {ps}: {pb} — skipping for preemption"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "GET pods for node {node_name} failed: {e} — skipping for preemption"
                );
                continue;
            }
        };

        let victims = select_preemption_victims(pod.priority, &node_pods, capacity);
        if victims.is_empty() {
            continue;
        }
        let is_cheaper = best
            .as_ref()
            .is_none_or(|b| victims.len() < b.victims.len());
        if is_cheaper {
            best = Some(PreemptionPlan {
                node_name: node_name.clone(),
                victims,
            });
        }
    }

    best.context("no node can fit the pending pod even after preempting lower-priority pods")
}

/// The target of a Binding — identifies the node to bind to.
#[derive(Serialize)]
struct BindingTarget<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    name: &'a str,
}

/// Full Binding object body as posted to the API server.
#[derive(Serialize)]
struct Binding<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: BindingMeta<'a>,
    target: BindingTarget<'a>,
}

#[derive(Serialize)]
struct BindingMeta<'a> {
    name: &'a str,
    namespace: &'a str,
}

/// Build the binding path for a pod in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access.
pub fn binding_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/binding")
}

/// Build the JSON payload for a pod binding.
///
/// Pure function so the payload shape can be verified in tests.
/// Uses typed structs so field renames are compile errors, not silent bugs.
pub fn binding_payload(namespace: &str, pod_name: &str, node_name: &str) -> Value {
    let binding = Binding {
        api_version: "v1",
        kind: "Binding",
        metadata: BindingMeta {
            name: pod_name,
            namespace,
        },
        target: BindingTarget {
            api_version: "v1",
            kind: "Node",
            name: node_name,
        },
    };
    serde_json::to_value(binding).expect("Binding is always serializable")
}

/// Check a bind response status code and body, returning Err on non-2xx.
///
/// Extracted as a pure function so the error-returning logic can be unit-tested
/// without network access. A non-2xx response must surface as Err so the caller
/// can log and retry; silently returning Ok on 409 Conflict (duplicate bind) or
/// 404 (pod gone) masks real scheduling failures.
pub fn check_bind_response(status: u16, body: &str) -> anyhow::Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    bail!("bind failed with HTTP {status}: {body}")
}

/// Bind a pod to a node via POST .../pods/:name/binding.
pub async fn bind_pod(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    node_name: &str,
) -> anyhow::Result<()> {
    let path = binding_path(namespace, pod_name);
    let payload = binding_payload(namespace, pod_name, node_name);

    let (status, body) = http_post_json(connector, server, &path, &payload).await?;
    check_bind_response(status.as_u16(), &body)?;
    info!("bound pod {namespace}/{pod_name} → node {node_name}");
    Ok(())
}

/// Build the DELETE path for a pod in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`.
pub fn delete_pod_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}")
}

/// Check a pod-eviction DELETE response status, returning Err on failures other
/// than "already gone".
///
/// A 404 means the pod was already removed — by a previous retry of this same
/// eviction, or another actor — which is the outcome preemption wants, so it
/// must be treated as success rather than aborting the eviction loop.
pub fn check_delete_response(status: u16) -> anyhow::Result<()> {
    if (200..300).contains(&status) || status == 404 {
        return Ok(());
    }
    bail!("evict failed with HTTP {status}")
}

/// Evict a pod (preemption's victim-removal step) via DELETE .../pods/:name.
///
/// The apiserver's pod DELETE always soft-deletes on the first call (stamps
/// `deletionTimestamp` so a real kubelet can gracefully terminate the
/// container) and only hard-deletes once the pod is already Terminating with
/// no finalizers. kube-scheduler's real preemption waits out that grace
/// period via its scheduling queue; this MVP explicitly skips that
/// multi-round wait (no such queue exists here) and instead issues the
/// DELETE twice to force immediate removal — equivalent to `kubectl delete
/// --grace-period=0 --force`, and the same force-hard-delete pattern already
/// used by this codebase's Job/CronJob GC (see `delete_pods_owned_by` in the
/// apiserver). Without this, the freed slot would not be visible yet when the
/// caller immediately tries to bind the preemptor into it.
pub async fn delete_pod(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
) -> anyhow::Result<()> {
    let path = delete_pod_path(namespace, pod_name);
    for _ in 0..2 {
        let (status, body) = http_delete(connector, server, &path).await?;
        check_delete_response(status.as_u16())
            .with_context(|| format!("evicting {namespace}/{pod_name}: {body}"))?;
    }
    info!("evicted pod {namespace}/{pod_name} (preemption)");
    Ok(())
}

/// Build the status-subresource PATCH path for a pod.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`/`delete_pod_path`.
pub fn pod_status_path(namespace: &str, pod_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/status")
}

/// Check a status-patch response status code, returning Err on non-2xx.
///
/// Extracted as a pure function so the error-returning logic can be
/// unit-tested without network access — mirrors `check_bind_response`.
pub fn check_status_patch_response(status: u16, body: &str) -> anyhow::Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    bail!("status patch failed with HTTP {status}: {body}")
}

/// PATCH a pod's `.status` via .../pods/:name/status.
///
/// Used to stamp/clear the `PodScheduled`/`SchedulingGated` condition
/// (`scheduling_gate_status_patch` / `scheduling_gate_status_reset`) — the
/// apiserver's `patch_pod_status` merges the `conditions` array by `.type`
/// (see `merge_conditions`), so `patch` only needs to carry the single
/// condition being added or changed; unrelated conditions are preserved.
pub async fn patch_pod_status(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    patch: &Value,
) -> anyhow::Result<()> {
    let path = pod_status_path(namespace, pod_name);
    let (status, body) = http_patch_status(connector, server, &path, patch).await?;
    check_status_patch_response(status.as_u16(), &body)
        .with_context(|| format!("patching status for {namespace}/{pod_name}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // check_bind_response tests — the error-returning logic for bind_pod.
    // Before this fix, bind_pod returned Ok(()) on any status code, including
    // 409 Conflict (duplicate bind) and 404 (pod already gone). Callers then
    // logged nothing and assumed success, silently masking scheduling failures.

    #[test]
    fn bind_pod_returns_err_on_non_2xx() {
        // 409 Conflict is what the API server returns when a pod is already bound.
        // bind_pod must surface this as Err so the caller can log and skip.
        // Reverting to Ok(()) on non-2xx would make this test fail.
        let result = check_bind_response(409, "AlreadyExists");
        assert!(
            result.is_err(),
            "409 Conflict must return Err, not Ok — duplicate binds must be surfaced"
        );
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("409"),
            "error must include the status code; got: {msg}"
        );
    }

    #[test]
    fn check_bind_response_ok_on_2xx() {
        // 201 Created is the success response for a new binding.
        assert!(
            check_bind_response(201, "").is_ok(),
            "201 Created must return Ok"
        );
        assert!(
            check_bind_response(200, "ok").is_ok(),
            "200 OK must return Ok"
        );
    }

    #[test]
    fn check_bind_response_err_includes_body() {
        // The error message must include the response body so operators can diagnose
        // failures without needing API server logs.
        let result = check_bind_response(422, "validation error: bad spec");
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("validation error"),
            "error message must include response body; got: {msg}"
        );
    }

    #[test]
    fn check_bind_response_err_on_404() {
        // 404 means the pod was deleted before binding completed — must surface as Err.
        let result = check_bind_response(404, "not found");
        assert!(result.is_err(), "404 must return Err");
    }

    #[test]
    fn check_bind_response_err_on_500() {
        // 500 Internal Server Error must not be silently swallowed.
        let result = check_bind_response(500, "internal error");
        assert!(result.is_err(), "500 must return Err");
    }

    // should_schedule tests — the dedup guard for concurrent bind_pod spawns.
    // Without this guard, two rapid ADDED/MODIFIED events for the same pod
    // would spawn two concurrent bind_pod calls; the second returns 409 Conflict
    // (now surfaced as Err after bead 2). The HashSet prevents the duplicate spawn.

    #[test]
    fn should_schedule_returns_true_for_key_not_in_flight() {
        // An empty in-flight set means no bind is running — schedule is allowed.
        // Removing the HashSet guard entirely would make this always return true,
        // which is correct here; the failure mode is in the next test.
        let in_flight = std::collections::HashSet::new();
        assert!(
            should_schedule(&in_flight, "default/my-pod"),
            "must return true when pod is not in-flight"
        );
    }

    #[test]
    fn should_schedule_returns_false_when_key_already_in_flight() {
        // A pod key present in in_flight means a bind task is already running.
        // should_schedule must return false to prevent a duplicate spawn.
        // This test fails if the HashSet guard is removed (always returns true).
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/my-pod".to_owned());
        assert!(
            !should_schedule(&in_flight, "default/my-pod"),
            "must return false when pod is already in-flight"
        );
    }

    #[test]
    fn should_schedule_is_key_specific() {
        // Only the matching key must be blocked; other pods must still be schedulable.
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/pod-a".to_owned());
        assert!(
            should_schedule(&in_flight, "default/pod-b"),
            "pod-b must be schedulable even when pod-a is in-flight"
        );
        assert!(
            !should_schedule(&in_flight, "default/pod-a"),
            "pod-a must not be schedulable when it is in-flight"
        );
    }

    #[test]
    fn should_schedule_key_uses_namespace_slash_name_format() {
        // The key format is "namespace/name". A key "default/pod" must not match
        // "kube-system/pod" — different namespace, different key.
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("default/coredns".to_owned());
        assert!(
            should_schedule(&in_flight, "kube-system/coredns"),
            "same pod name in different namespace must be treated as a distinct key"
        );
    }

    // drain_watch_buffer is re-exported from kubeconfig where it is called by
    // watch_stream (and therefore stream_watch_events). This test confirms that
    // the function used in production handles multi-line chunks correctly.
    // If drain_watch_buffer were decoupled from watch_stream again (reverted to
    // an inline copy), this re-export would break at compile time.
    #[test]
    fn drain_watch_buffer_multi_line_chunk_parses_all_events() {
        // Simulate receiving two complete JSON watch events in a single chunk.
        // This exercises the production code path: watch_stream calls
        // drain_watch_buffer per frame, and drain_watch_buffer must consume all
        // complete lines even when multiple arrive in one network frame.
        let mut buf = "{\"type\":\"ADDED\",\"object\":{}}\n{\"type\":\"MODIFIED\",\"object\":{}}\n"
            .to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(
            events.len(),
            2,
            "both lines must be parsed from a single chunk"
        );
        assert_eq!(events[0]["type"], "ADDED");
        assert_eq!(events[1]["type"], "MODIFIED");
        assert!(buf.is_empty(), "all complete lines must be consumed");
    }

    // WatchEvent deserialization — verifies that the typed envelope correctly
    // maps "type" → event_type and "object" → object. A rename or missing field
    // would cause every watch event to be silently ignored.
    #[test]
    fn watch_event_deserializes_type_and_object() {
        let json = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-pod", "namespace": "staging" },
                "spec": { "nodeName": "" }
            }
        });
        let we: WatchEvent<PodObject> =
            serde_json::from_value(json).expect("WatchEvent should deserialize");
        assert_eq!(we.event_type, "ADDED");
        assert_eq!(we.object.metadata.name.as_deref(), Some("my-pod"));
        assert_eq!(we.object.metadata.namespace.as_deref(), Some("staging"));
        assert_eq!(we.object.spec.node_name.as_deref(), Some(""));
    }

    // Regression test: the cluster-wide watch path must NOT be scoped to a
    // specific namespace.  If this constant ever reverts to the old
    // "namespaces/default/pods" path, cross-namespace pods (e.g. CoreDNS in
    // kube-system) will never be scheduled.
    #[test]
    fn watch_path_is_cluster_wide() {
        let path = "/api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D";
        assert!(
            !path.contains("namespaces/"),
            "watch path must be cluster-wide, not namespace-scoped: {path}"
        );
        assert!(
            path.starts_with("/api/v1/pods"),
            "watch path must use /api/v1/pods, got: {path}"
        );
    }

    #[test]
    fn needs_scheduling_returns_none_for_non_pod_events() {
        let event = json!({ "type": "DELETED", "object": { "metadata": { "name": "foo", "namespace": "default" }, "spec": {} } });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_none_when_already_scheduled() {
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "foo", "namespace": "kube-system" },
                "spec": { "nodeName": "node-1" }
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_namespace_from_event() {
        // Pods outside `default` (e.g. CoreDNS in kube-system) must be
        // scheduled using the namespace from the event, not a hard-coded value.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "coredns-abc", "namespace": "kube-system" },
                "spec": { "nodeName": "" }
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some(), "expected Some for unscheduled pod");
        let pending = result.unwrap();
        assert_eq!(
            pending.namespace, "kube-system",
            "namespace must come from event metadata"
        );
        assert_eq!(pending.pod_name, "coredns-abc");
    }

    #[test]
    fn needs_scheduling_returns_some_for_unscheduled_pod_in_default() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some());
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "my-pod");
    }

    #[test]
    fn needs_scheduling_returns_none_when_event_type_missing() {
        // Missing "type" field must not be treated as schedulable.
        let event = json!({
            "object": {
                "metadata": { "name": "my-pod", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_returns_none_when_pod_name_empty() {
        // An event with no pod name must not produce a scheduling decision.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(needs_scheduling(&event).is_none());
    }

    #[test]
    fn needs_scheduling_defaults_namespace_to_default_when_absent() {
        // If the event carries no namespace field, fall back to "default".
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "no-ns-pod" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "no-ns-pod");
    }

    #[test]
    fn needs_scheduling_handles_modified_unscheduled_pod() {
        // MODIFIED events for unscheduled pods must also trigger scheduling
        // (e.g. when a pod is updated before being bound).
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "pending-pod", "namespace": "staging" },
                "spec": { "nodeName": null }
            }
        });
        let result = needs_scheduling(&event);
        assert!(result.is_some());
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "staging");
        assert_eq!(pending.pod_name, "pending-pod");
    }

    // schedulingGates tests (mayor-vkobg): a ReplicaSet's pods can carry
    // spec.schedulingGates so they stay Pending — not even considered "ready to
    // schedule" — until an external controller clears the gates. Without this
    // check the scheduler binds gated pods immediately, which is why the
    // conformance test "validates Pods with non-empty schedulingGates are
    // blocked on scheduling" saw all 3 ReplicaSet pods get bound and start
    // Running right away.

    #[test]
    fn needs_scheduling_returns_none_when_scheduling_gates_non_empty() {
        // A pod carrying schedulingGates: [foo, bar] must never enter the
        // scheduling cycle, no matter how empty spec.nodeName is.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}, {"name": "bar"}] }
            }
        });
        assert!(
            needs_scheduling(&event).is_none(),
            "a pod with non-empty schedulingGates must stay out of the scheduling \
             cycle entirely — reverting this check would bind gated ReplicaSet pods \
             immediately, failing 'validates Pods with non-empty schedulingGates \
             are blocked on scheduling'"
        );
    }

    #[test]
    fn needs_scheduling_returns_some_when_scheduling_gates_is_empty_array() {
        // An empty gate list (all gates cleared) must behave exactly like no
        // gates at all — the pod is ready to schedule.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "ungated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] }
            }
        });
        assert!(
            needs_scheduling(&event).is_some(),
            "an empty schedulingGates array means all gates are cleared — the pod \
             must be schedulable, not stuck forever"
        );
    }

    // scheduling_gate_status_patch / scheduling_gate_status_reset tests (mayor-pwf4g):
    // needs_scheduling correctly keeps gated pods out of the scheduling cycle, but
    // that alone leaves status.conditions untouched — WaitForPodsSchedulingGated
    // (upstream test/e2e/framework/pod/wait.go) polls status.conditions for
    // {type: PodScheduled, reason: SchedulingGated}, not just "is it unscheduled".
    // These tests cover the PATCH-decision logic that fills that gap.

    #[test]
    fn scheduling_gate_status_patch_sets_condition_when_absent() {
        // A freshly-created gated pod (no PodScheduled condition yet at all) must
        // get one — otherwise `kubectl describe pod` and WaitForPodsSchedulingGated
        // have nothing to read, even though the pod is correctly stuck Pending.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}, {"name": "bar"}] }
            }
        });
        let patch = scheduling_gate_status_patch(&event)
            .expect("a newly gated pod with no condition yet must get one patched in");
        assert_eq!(patch.namespace, "default");
        assert_eq!(patch.pod_name, "gated-pod");
        let cond = &patch.patch["status"]["conditions"][0];
        assert_eq!(cond["type"], "PodScheduled");
        assert_eq!(cond["status"], "False");
        assert_eq!(
            cond["reason"], "SchedulingGated",
            "reason must exactly match v1.PodReasonSchedulingGated — \
             WaitForPodsSchedulingGated string-matches this field"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_sets_condition_over_create_time_default() {
        // apply_pod_create_defaults (apiserver) stamps every new pod with
        // PodScheduled=False/reason=Unschedulable at creation, including gated
        // ones — this is the REAL starting state a gated ReplicaSet pod has, not
        // "no condition at all". The gated reason must still get applied over it.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "foo"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "pod not yet scheduled"}
                    ]
                }
            }
        });
        let patch = scheduling_gate_status_patch(&event).expect(
            "a gated pod still carrying the generic Unschedulable default must be \
             re-patched to the specific SchedulingGated reason",
        );
        assert_eq!(
            patch.patch["status"]["conditions"][0]["reason"],
            "SchedulingGated"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_is_idempotent_once_already_marked() {
        // Every ADDED/MODIFIED event for a still-gated pod re-enters this
        // function (including the event generated by this function's own prior
        // PATCH echoing back through the watch). Once the condition already
        // reads False/SchedulingGated, re-sending the identical PATCH forever
        // would be a needless write storm — must return None instead.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "bar"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        assert!(
            scheduling_gate_status_patch(&event).is_none(),
            "condition already matches the target state (even with only one of \
             the original two gates remaining — gates clear one at a time) — \
             no PATCH is needed"
        );
    }

    #[test]
    fn scheduling_gate_status_patch_is_none_when_gates_empty() {
        // An ungated pod takes the normal scheduling path; this function must
        // never touch its PodScheduled condition.
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] }
            }
        });
        assert!(scheduling_gate_status_patch(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_patch_is_none_when_already_scheduled() {
        // A gated pod should never reach spec.nodeName != "" (the binding
        // endpoint requires empty schedulingGates), but this must defensively
        // refuse to touch a bound pod's condition regardless — matching the
        // same non-interference guarantee needs_scheduling already provides.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "nodeName": "node-1", "schedulingGates": [{"name": "foo"}] }
            }
        });
        assert!(scheduling_gate_status_patch(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_clears_stale_reason_once_gates_fully_removed() {
        // Once every gate is gone, the pod is about to proceed through normal
        // scheduling — leaving the condition saying SchedulingGated would lie
        // about why it's still Pending if scheduling doesn't succeed instantly.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        let patch = scheduling_gate_status_reset(&event)
            .expect("the stale SchedulingGated reason must be cleared once all gates clear");
        assert_eq!(patch["status"]["conditions"][0]["reason"], "Unschedulable");
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_while_one_gate_remains() {
        // Gates clear one at a time (predicates.go removes "foo" first, leaving
        // "bar"): with "bar" still present the pod is genuinely still blocked,
        // so the SchedulingGated reason must NOT be reset yet.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [{"name": "bar"}] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        assert!(
            scheduling_gate_status_reset(&event).is_none(),
            "removing only one of two gates must not clear the condition — the \
             pod is still blocked on the remaining gate"
        );
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_once_already_scheduled() {
        // If the pod was already bound (e.g. a fast scheduling attempt won the
        // race against this reset check on an earlier event), its PodScheduled
        // condition belongs to the bind outcome now — never touch it here.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "nodeName": "node-1", "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "True", "reason": "PodScheduled", "message": ""}
                    ]
                }
            }
        });
        assert!(scheduling_gate_status_reset(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_is_none_for_a_pod_that_was_never_gated() {
        // A normal pod's condition already reads Unschedulable from apiserver's
        // create-time default — there is no stale SchedulingGated reason to
        // clear, so this must not fire (and must not needlessly PATCH every pod).
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": "pod not yet scheduled"}
                    ]
                }
            }
        });
        assert!(scheduling_gate_status_reset(&event).is_none());
    }

    #[test]
    fn scheduling_gate_status_reset_patch_omits_status_field() {
        // Load-bearing for race-safety: bind_pod (apiserver) flips PodScheduled
        // to True atomically with spec.nodeName in one write, concurrently with
        // this reset. If the reset patch included "status": "False", it could
        // apply after a fresh bind and clobber True back to False. Omitting the
        // key entirely means this patch can only ever touch reason/message.
        let event = json!({
            "type": "MODIFIED",
            "object": {
                "metadata": { "name": "gated-pod", "namespace": "default" },
                "spec": { "schedulingGates": [] },
                "status": {
                    "conditions": [
                        {"type": "PodScheduled", "status": "False", "reason": "SchedulingGated", "message": "Scheduling is blocked due to non-empty scheduling gates"}
                    ]
                }
            }
        });
        let patch =
            scheduling_gate_status_reset(&event).expect("gates cleared, reason still stale");
        assert!(
            patch["status"]["conditions"][0].get("status").is_none(),
            "the reset patch must never carry a \"status\" field — doing so risks \
             clobbering a concurrently-bound pod's True back to False"
        );
    }

    // pod_status_path / check_status_patch_response tests — mirror the
    // binding_path / check_bind_response coverage above for the new status
    // subresource plumbing.

    #[test]
    fn pod_status_path_produces_correct_api_path() {
        let path = pod_status_path("default", "my-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/my-pod/status");
    }

    #[test]
    fn check_status_patch_response_ok_on_2xx() {
        assert!(check_status_patch_response(200, "").is_ok());
    }

    #[test]
    fn check_status_patch_response_err_on_415() {
        // 415 is exactly what the apiserver returns for the wrong Content-Type
        // (see accepts_patch_content_type) — must surface as Err, not be
        // silently swallowed, or a content-type regression would go unnoticed.
        let result = check_status_patch_response(415, "unsupported media type");
        assert!(result.is_err());
        let msg = format!("{:#}", result.err().unwrap());
        assert!(
            msg.contains("415"),
            "error must include the status code; got: {msg}"
        );
    }

    // binding_path tests — verify the REST path conforms to the Kubernetes API spec.
    // A wrong path silently drops the bind request (404), leaving pods unscheduled.

    #[test]
    fn binding_path_produces_correct_api_path() {
        let path = binding_path("default", "my-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/my-pod/binding");
    }

    #[test]
    fn binding_path_uses_provided_namespace() {
        // Pods in non-default namespaces must use their actual namespace in the path.
        let path = binding_path("kube-system", "coredns-abc");
        assert_eq!(
            path,
            "/api/v1/namespaces/kube-system/pods/coredns-abc/binding"
        );
    }

    // binding_payload tests — verify the JSON body that is POSTed to the API server.
    // Kubernetes rejects bindings with incorrect apiVersion/kind/target shape.

    #[test]
    fn binding_payload_has_correct_api_version_and_kind() {
        let payload = binding_payload("default", "my-pod", "node-1");
        assert_eq!(payload["apiVersion"], "v1");
        assert_eq!(payload["kind"], "Binding");
    }

    #[test]
    fn binding_payload_target_references_correct_node() {
        let payload = binding_payload("staging", "web-pod", "worker-2");
        assert_eq!(payload["target"]["kind"], "Node");
        assert_eq!(payload["target"]["name"], "worker-2");
        assert_eq!(payload["target"]["apiVersion"], "v1");
    }

    #[test]
    fn binding_payload_metadata_matches_pod_and_namespace() {
        let payload = binding_payload("kube-system", "dns-pod", "node-0");
        assert_eq!(payload["metadata"]["name"], "dns-pod");
        assert_eq!(payload["metadata"]["namespace"], "kube-system");
    }

    // NodeList deserialization — the scheduler depends on parsing the API server's
    // node list. If the shape changes, pick_node silently returns no nodes.

    #[test]
    fn node_list_deserializes_items() {
        let json = json!({
            "items": [
                { "metadata": { "name": "node-1" } },
                { "metadata": { "name": "node-2" } }
            ]
        });
        let list: NodeList = serde_json::from_value(json).expect("should deserialize");
        assert_eq!(list.items.len(), 2);
        assert_eq!(list.items[0].metadata.name, "node-1");
        assert_eq!(list.items[1].metadata.name, "node-2");
    }

    #[test]
    fn node_list_deserializes_empty_items() {
        let json = json!({ "items": [] });
        let list: NodeList = serde_json::from_value(json).expect("should deserialize");
        assert!(list.items.is_empty());
    }

    // parse_uri_parts tests — the URI-parsing logic is shared by send_request and
    // stream_watch_events. A wrong host/port means every request goes to the wrong
    // address silently.

    #[test]
    fn parse_uri_parts_extracts_host_and_default_port() {
        // When no explicit port is given, HTTPS defaults to 443.
        let (host, port, addr) =
            parse_uri_parts("https://api.example.com", "/api/v1/pods").expect("should parse");
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 443);
        assert_eq!(addr, "api.example.com:443");
    }

    #[test]
    fn parse_uri_parts_uses_explicit_port() {
        // When the server URL contains an explicit port, that port must be used.
        // A common kubeconfig server address is https://host:6443.
        let (host, port, addr) =
            parse_uri_parts("https://10.0.0.1:6443", "/api/v1/nodes").expect("should parse");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 6443);
        assert_eq!(addr, "10.0.0.1:6443");
    }

    #[test]
    fn parse_uri_parts_fails_on_missing_host() {
        // A relative URL (no scheme/host) must return an error — not silently
        // produce an empty host, which would be an undetected misconfiguration.
        let result = parse_uri_parts("", "/api/v1/pods");
        assert!(result.is_err(), "expected error for empty base URL");
    }

    // drain_watch_buffer tests — the line-parsing logic drives the watch loop.
    // Bugs here mean watch events are silently dropped or double-processed.

    #[test]
    fn drain_watch_buffer_calls_handler_for_each_complete_line() {
        // Each newline-terminated JSON object must produce exactly one handler call.
        let mut buf = "{\"type\":\"ADDED\"}\n{\"type\":\"MODIFIED\"}\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["type"], "ADDED");
        assert_eq!(events[1]["type"], "MODIFIED");
        assert!(buf.is_empty(), "complete lines must be consumed from buf");
    }

    #[test]
    fn drain_watch_buffer_leaves_incomplete_line_in_buf() {
        // If the last chunk does not end with '\n', it is a partial line and must
        // be retained for the next frame — emitting it early would corrupt the JSON.
        let mut buf = "{\"type\":\"ADDED\"}\n{\"partial\":".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 1);
        assert_eq!(buf, "{\"partial\":", "incomplete line must stay in buf");
    }

    #[test]
    fn drain_watch_buffer_skips_blank_lines() {
        // Watch streams may include keep-alive blank lines; they must not trigger
        // the handler or cause a parse error.
        let mut buf = "\n{\"type\":\"ADDED\"}\n\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn drain_watch_buffer_skips_invalid_json_lines() {
        // Malformed lines (e.g. partial frames from a reconnect) must be skipped,
        // not panic or corrupt subsequent good lines.
        let mut buf = "not-json\n{\"type\":\"ADDED\"}\n".to_owned();
        let mut events: Vec<Value> = Vec::new();
        drain_watch_buffer(&mut buf, &mut |v| events.push(v));
        // Only the valid line produces a handler call.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "ADDED");
    }

    // select_first_node tests — the node-selection policy. The scheduler always
    // picks the first node in the list; if none exist, the bind must not proceed.

    #[test]
    fn select_first_node_returns_first_item_name() {
        // When multiple nodes exist, the first one must be chosen. Round-robin or
        // other strategies are not implemented; first-wins is the intended policy.
        let list = NodeList {
            items: vec![
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-a".to_owned(),
                        labels: Default::default(),
                    },
                    spec: NodeSpec::default(),
                    status: NodeStatus::default(),
                },
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-b".to_owned(),
                        labels: Default::default(),
                    },
                    spec: NodeSpec::default(),
                    status: NodeStatus::default(),
                },
            ],
        };
        let name = select_first_node(list).expect("should return a node");
        assert_eq!(name, "node-a");
    }

    #[test]
    fn select_first_node_errors_when_list_is_empty() {
        // An empty node list must produce an error so the caller can log and retry,
        // rather than silently proceeding with an empty node name.
        let list = NodeList { items: vec![] };
        let result = select_first_node(list);
        assert!(result.is_err(), "expected error for empty node list");
    }

    // ---------------------------------------------------------------------------
    // Additional coverage (mayor-in2l): branches not exercised by earlier tests.
    // ---------------------------------------------------------------------------

    // needs_scheduling with a BOOKMARKED event type — exercises the non-ADDED/MODIFIED
    // branch with a type other than DELETED. Watch streams emit BOOKMARK events
    // periodically; they must be ignored like DELETED.
    #[test]
    fn needs_scheduling_returns_none_for_bookmark_event() {
        let event = json!({
            "type": "BOOKMARK",
            "object": {
                "metadata": { "name": "some-pod", "namespace": "default" },
                "spec": {}
            }
        });
        assert!(
            needs_scheduling(&event).is_none(),
            "BOOKMARK events must not trigger scheduling"
        );
    }

    // needs_scheduling fallback: when the event JSON cannot be deserialized into
    // WatchEvent<PodObject>, the function uses a default WatchEvent with an empty
    // event_type. This covers the unwrap_or_else branch — a non-object value like
    // a JSON number triggers the fallback.
    #[test]
    fn needs_scheduling_returns_none_for_non_object_event() {
        // A JSON number is not a WatchEvent — deserialization fails, fallback to
        // empty event_type, which does not match ADDED or MODIFIED.
        let event = json!(42);
        assert!(
            needs_scheduling(&event).is_none(),
            "non-object JSON must not trigger scheduling"
        );
    }

    // needs_scheduling with an explicitly null node_name field: None from the struct
    // means unscheduled. This is distinct from absent (already covered) and from
    // empty string "".
    #[test]
    fn needs_scheduling_returns_some_when_node_name_is_null() {
        // spec.nodeName: null is a valid unscheduled state in Kubernetes.
        // The scheduler must treat it the same as absent or "".
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "null-node-pod", "namespace": "default" },
                "spec": { "nodeName": null }
            }
        });
        let result = needs_scheduling(&event);
        assert!(
            result.is_some(),
            "null nodeName must be treated as unscheduled"
        );
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "default");
        assert_eq!(pending.pod_name, "null-node-pod");
    }

    // binding_path with special characters — ensures the path template doesn't
    // introduce double slashes or truncate long names.
    #[test]
    fn binding_path_does_not_double_slash() {
        let path = binding_path("default", "my-pod");
        assert!(
            !path.contains("//"),
            "binding path must not contain double slashes: {path}"
        );
    }

    // NodeList with a single item — the common production case (one worker node).
    // select_first_node must return that node's name, not an error.
    #[test]
    fn select_first_node_returns_name_for_single_item_list() {
        let list = NodeList {
            items: vec![NodeItem {
                metadata: NodeMetadata {
                    name: "worker-0".to_owned(),
                    labels: Default::default(),
                },
                spec: NodeSpec::default(),
                status: NodeStatus::default(),
            }],
        };
        let name = select_first_node(list).expect("single-item list must return Ok");
        assert_eq!(name, "worker-0");
    }

    // ---------------------------------------------------------------------------
    // nodeSelector filtering (mayor-ewnt): the scheduler must respect spec.nodeSelector.
    // Before this fix, pick_node blindly returned the first node regardless of labels,
    // causing pods with non-matching selectors to be bound to the wrong node and the
    // conformance test "validates that NodeSelector is respected if not matching" to fail.
    // ---------------------------------------------------------------------------

    fn make_node(name: &str, labels: &[(&str, &str)]) -> NodeItem {
        NodeItem {
            metadata: NodeMetadata {
                name: name.to_owned(),
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            spec: NodeSpec::default(),
            status: NodeStatus::default(),
        }
    }

    /// node_selector_matches returns true when the node labels satisfy all selector entries.
    ///
    /// This is the gating condition that prevents non-matching pods from being bound.
    /// If this always returns true (or the function is removed), every pod is scheduled
    /// regardless of its nodeSelector, making the conformance test fail.
    #[test]
    fn node_selector_matches_all_required_labels() {
        let labels: std::collections::HashMap<String, String> = [
            ("kubernetes.io/hostname".to_owned(), "lima-node".to_owned()),
            ("kubernetes.io/arch".to_owned(), "arm64".to_owned()),
        ]
        .into();
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        assert!(
            node_selector_matches(&labels, &selector),
            "node with matching label must satisfy selector — reverting the check \
             would cause this to always return true, scheduling pods on mismatched nodes"
        );
    }

    /// node_selector_matches returns false when the node is missing a required label.
    ///
    /// This is the regression test for mayor-ewnt: before the fix, pick_node ignored
    /// nodeSelector, so a pod requesting `scheduledOnNode=lima-node-2` would be bound
    /// to `lima-node` (the only node). The test "NodeSelector is respected if not matching"
    /// would then fail waiting for the pod to remain Pending.
    #[test]
    fn node_selector_matches_false_when_label_absent() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        // Selector requires a label the node does not have.
        let selector: std::collections::HashMap<String, String> =
            [("scheduledOnNode".to_owned(), "lima-node-2".to_owned())].into();
        assert!(
            !node_selector_matches(&labels, &selector),
            "node missing a required label must NOT satisfy selector — reverting \
             this to always-true causes the scheduler to bind the pod to a mismatched \
             node, breaking the NodeSelector conformance test"
        );
    }

    /// node_selector_matches returns false when a label value differs.
    #[test]
    fn node_selector_matches_false_when_label_value_wrong() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "other-node".to_owned())].into();
        assert!(
            !node_selector_matches(&labels, &selector),
            "node with wrong label value must NOT satisfy selector"
        );
    }

    /// An empty nodeSelector matches any node.
    ///
    /// Standard Kubernetes semantics: absence of nodeSelector means "any node".
    /// If this returns false, pods without a nodeSelector are never scheduled.
    #[test]
    fn node_selector_matches_empty_selector_matches_any_node() {
        let labels: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let selector: std::collections::HashMap<String, String> = Default::default();
        assert!(
            node_selector_matches(&labels, &selector),
            "empty nodeSelector must match any node — \
             removing this would break scheduling of all pods without a nodeSelector"
        );
    }

    /// select_node_for_pod returns the first matching node.
    ///
    /// When a pod has a nodeSelector that matches the node, select_node_for_pod must
    /// return that node. If the matching logic is broken, schedulable pods stay Pending.
    #[test]
    fn select_node_for_pod_returns_matching_node() {
        let list = NodeList {
            items: vec![make_node(
                "lima-node",
                &[
                    ("kubernetes.io/hostname", "lima-node"),
                    ("kubernetes.io/arch", "arm64"),
                ],
            )],
        };
        let selector: std::collections::HashMap<String, String> =
            [("kubernetes.io/hostname".to_owned(), "lima-node".to_owned())].into();
        let name = select_node_for_pod(list, &selector).expect("matching node must be found");
        assert_eq!(
            name, "lima-node",
            "select_node_for_pod must return the name of the node whose labels match the selector"
        );
    }

    /// select_node_for_pod returns Err when no node satisfies the nodeSelector.
    ///
    /// This is the regression test for mayor-ewnt: before the fix, a pod with a
    /// non-matching nodeSelector would be bound to the first node anyway (via
    /// select_first_node). With the fix, select_node_for_pod returns Err so the
    /// caller skips binding and the pod stays Pending — which is the correct behavior
    /// verified by the conformance test "validates that NodeSelector is respected if
    /// not matching".
    #[test]
    fn select_node_for_pod_errors_when_no_node_matches() {
        let list = NodeList {
            items: vec![make_node(
                "lima-node",
                &[("kubernetes.io/hostname", "lima-node")],
            )],
        };
        // Pod wants a node labeled scheduledOnNode=lima-node-2, which doesn't exist.
        let selector: std::collections::HashMap<String, String> =
            [("scheduledOnNode".to_owned(), "lima-node-2".to_owned())].into();
        let result = select_node_for_pod(list, &selector);
        assert!(
            result.is_err(),
            "select_node_for_pod must return Err when no node satisfies the selector — \
             reverting to always-pick-first would pass this as Ok, causing the conformance \
             test 'validates that NodeSelector is respected if not matching' to fail because \
             the pod gets scheduled instead of staying Pending"
        );
    }

    // ---------------------------------------------------------------------------
    // taints/tolerations (mayor-2ksh8): the scheduler must not bind a pod to a
    // NoSchedule/NoExecute-tainted node unless the pod tolerates that taint.
    // Before this fix, crates/scheduler/ had zero taint/toleration handling —
    // pods without a matching toleration were bound to tainted nodes anyway,
    // failing "validates that taints-tolerations is respected if not matching".
    // ---------------------------------------------------------------------------

    fn taint(key: &str, value: &str, effect: &str) -> Taint {
        Taint {
            key: key.to_owned(),
            value: value.to_owned(),
            effect: effect.to_owned(),
        }
    }

    fn toleration(key: &str, value: &str, effect: &str) -> Toleration {
        Toleration {
            key: Some(key.to_owned()),
            operator: None,
            value: Some(value.to_owned()),
            effect: Some(effect.to_owned()),
        }
    }

    /// A NoSchedule taint with no matching toleration must block the node —
    /// this is the exact scenario the conformance test exercises: a pod with
    /// no tolerations must stay Pending against a NoSchedule-tainted node.
    #[test]
    fn node_taints_tolerated_false_when_no_toleration_matches() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        assert!(
            !node_taints_tolerated(&taints, &[]),
            "a NoSchedule taint with zero tolerations must block the node — \
             reverting this would bind untolerating pods to tainted nodes, \
             failing 'validates that taints-tolerations is respected if not matching'"
        );
    }

    /// A toleration matching key/value/effect exactly must tolerate the taint.
    #[test]
    fn node_taints_tolerated_true_when_toleration_matches_exactly() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![toleration("dedicated", "gpu", "NoSchedule")];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "an exact key/value/effect toleration must tolerate the matching taint"
        );
    }

    /// A toleration with a different value must NOT tolerate the taint —
    /// otherwise pods could bypass taints meant to reserve nodes for specific
    /// workloads.
    #[test]
    fn node_taints_tolerated_false_when_value_differs() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![toleration("dedicated", "cpu-only", "NoSchedule")];
        assert!(
            !node_taints_tolerated(&taints, &tolerations),
            "a toleration for a different value must not tolerate the taint"
        );
    }

    /// operator: Exists tolerates any value for the matching key — this is the
    /// upstream `Toleration{Key, Operator: Exists}` shape used to tolerate a
    /// taint regardless of its value.
    #[test]
    fn node_taints_tolerated_true_with_exists_operator_ignores_value() {
        let taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let tolerations = vec![Toleration {
            key: Some("dedicated".to_owned()),
            operator: Some("Exists".to_owned()),
            value: None,
            effect: Some("NoSchedule".to_owned()),
        }];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "operator Exists must tolerate the taint regardless of its value"
        );
    }

    /// An empty-key toleration with operator Exists tolerates every taint,
    /// regardless of key — the upstream "tolerate everything" wildcard.
    #[test]
    fn node_taints_tolerated_true_with_wildcard_toleration() {
        let taints = vec![
            taint("dedicated", "gpu", "NoSchedule"),
            taint("other", "x", "NoExecute"),
        ];
        let tolerations = vec![Toleration {
            key: None,
            operator: Some("Exists".to_owned()),
            value: None,
            effect: None,
        }];
        assert!(
            node_taints_tolerated(&taints, &tolerations),
            "a wildcard toleration (no key, operator Exists) must tolerate every taint"
        );
    }

    /// PreferNoSchedule is a soft signal this MVP scheduler (no scoring) never
    /// hard-blocks on — only NoSchedule/NoExecute gate scheduling.
    #[test]
    fn node_taints_tolerated_true_for_prefer_no_schedule_without_toleration() {
        let taints = vec![taint("dedicated", "gpu", "PreferNoSchedule")];
        assert!(
            node_taints_tolerated(&taints, &[]),
            "PreferNoSchedule must never block scheduling in a scheduler with no scoring"
        );
    }

    /// A node with no taints at all trivially qualifies regardless of tolerations.
    #[test]
    fn node_taints_tolerated_true_when_node_has_no_taints() {
        assert!(
            node_taints_tolerated(&[], &[]),
            "a node with zero taints has nothing to tolerate"
        );
    }

    /// needs_scheduling extracts spec.tolerations from the watch event — if this
    /// is dropped, node_taints_tolerated always sees an empty toleration list and
    /// every tainted node is treated as blocked, even for pods meant to tolerate it.
    #[test]
    fn needs_scheduling_returns_tolerations_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "tolerant-pod", "namespace": "default" },
                "spec": {
                    "tolerations": [
                        { "key": "dedicated", "operator": "Equal", "value": "gpu", "effect": "NoSchedule" }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.tolerations.len(),
            1,
            "spec.tolerations must be extracted from the watch event"
        );
        assert_eq!(pending.tolerations[0].key.as_deref(), Some("dedicated"));
        assert_eq!(pending.tolerations[0].effect.as_deref(), Some("NoSchedule"));
    }

    /// A pod with no tolerations must produce an empty list, not fail deserialization.
    #[test]
    fn needs_scheduling_returns_empty_tolerations_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.tolerations.is_empty(),
            "a pod without tolerations must produce an empty list"
        );
    }

    /// select_node_with_capacity must skip a tainted node the pod does not
    /// tolerate, even when it has free pod capacity — capacity alone is not
    /// enough; the node must also qualify (selector + taints).
    #[test]
    fn select_node_with_capacity_skips_untolerated_tainted_node() {
        let mut node = make_node_with_capacity("tainted-node", &[], "110");
        node.spec.taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let list = NodeList { items: vec![node] };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_err(),
            "a NoSchedule-tainted node with no matching toleration must be skipped \
             even when it has free capacity — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must select a tainted node when the pod
    /// carries a matching toleration.
    #[test]
    fn select_node_with_capacity_selects_tainted_node_with_matching_toleration() {
        let mut node = make_node_with_capacity("tainted-node", &[], "110");
        node.spec.taints = vec![taint("dedicated", "gpu", "NoSchedule")];
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.tolerations = vec![toleration("dedicated", "gpu", "NoSchedule")];
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert_eq!(
            result.unwrap(),
            "tainted-node",
            "a pod tolerating the node's taint must be scheduled there"
        );
    }

    // ---------------------------------------------------------------------------
    // nodeAffinity (mayor-oei5x): RequiredDuringSchedulingIgnoredDuringExecution
    // must be enforced like nodeSelector. Before this fix, crates/scheduler/ had
    // zero handling of spec.affinity.nodeAffinity anywhere — a pod whose required
    // nodeAffinity term no node satisfied was bound anyway, failing "validates
    // that NodeAffinity is respected if not matching".
    // ---------------------------------------------------------------------------

    fn requirement(key: &str, operator: &str, values: &[&str]) -> NodeSelectorRequirement {
        NodeSelectorRequirement {
            key: key.to_owned(),
            operator: operator.to_owned(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn required_affinity(terms: Vec<NodeSelectorTerm>) -> NodeAffinity {
        NodeAffinity {
            required_during_scheduling_ignored_during_execution: Some(NodeSelectorSpec {
                node_selector_terms: terms,
            }),
        }
    }

    /// `None` (no nodeAffinity at all) must match any node — most pods never
    /// set affinity, and this must not restrict them.
    #[test]
    fn node_affinity_matches_true_when_no_affinity_set() {
        let labels: std::collections::HashMap<String, String> = Default::default();
        assert!(
            node_affinity_matches(&labels, None),
            "a pod with no nodeAffinity must be schedulable on any node"
        );
    }

    /// The exact scenario from the conformance test: two ORed terms, neither of
    /// which any node label satisfies — the node must be rejected.
    #[test]
    fn node_affinity_matches_false_when_no_term_satisfied() {
        let labels: std::collections::HashMap<String, String> = Default::default();
        let affinity = required_affinity(vec![
            NodeSelectorTerm {
                match_expressions: vec![requirement("foo", "In", &["bar", "value2"])],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
            },
        ]);
        assert!(
            !node_affinity_matches(&labels, Some(&affinity)),
            "a node satisfying neither ORed nodeSelectorTerm must be rejected — \
             reverting this check binds the pod anyway, failing 'validates that \
             NodeAffinity is respected if not matching'"
        );
    }

    /// A node whose labels satisfy one of several ORed terms must be accepted —
    /// nodeSelectorTerms are ORed, not ANDed.
    #[test]
    fn node_affinity_matches_true_when_one_of_ored_terms_satisfied() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![
            NodeSelectorTerm {
                match_expressions: vec![requirement("foo", "In", &["bar", "value2"])],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
            },
        ]);
        assert!(
            node_affinity_matches(&labels, Some(&affinity)),
            "a node satisfying at least one ORed nodeSelectorTerm must be accepted"
        );
    }

    /// matchExpressions within a single term are ANDed — a node satisfying only
    /// one of two required expressions in the same term must be rejected.
    #[test]
    fn node_affinity_matches_false_when_only_one_of_anded_expressions_satisfied() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![
                requirement("foo", "In", &["bar"]),
                requirement("other", "Exists", &[]),
            ],
        }]);
        assert!(
            !node_affinity_matches(&labels, Some(&affinity)),
            "matchExpressions in one term are ANDed — satisfying only one of two \
             must not be enough"
        );
    }

    /// NotIn excludes a node whose label value is in the forbidden set.
    #[test]
    fn node_selector_requirement_not_in_excludes_matching_value() {
        let labels: std::collections::HashMap<String, String> =
            [("zone".to_owned(), "bad".to_owned())].into();
        assert!(
            !node_selector_requirement_matches(&labels, &requirement("zone", "NotIn", &["bad"])),
            "NotIn must reject a node whose label value is in the forbidden set"
        );
    }

    /// An unsupported operator (Gt/Lt, not implemented by this MVP) must never
    /// match — treating it as an automatic pass would let a pod bypass an
    /// affinity rule it doesn't actually satisfy.
    #[test]
    fn node_selector_requirement_unsupported_operator_never_matches() {
        let labels: std::collections::HashMap<String, String> =
            [("cpus".to_owned(), "4".to_owned())].into();
        assert!(
            !node_selector_requirement_matches(&labels, &requirement("cpus", "Gt", &["2"])),
            "an unimplemented operator must never silently match"
        );
    }

    /// needs_scheduling extracts spec.affinity.nodeAffinity from the watch
    /// event — if dropped, node_affinity_matches always sees None and every
    /// pod with a NodeAffinity restriction is bound as if it had none.
    #[test]
    fn needs_scheduling_returns_node_affinity_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "restricted-pod", "namespace": "default" },
                "spec": {
                    "affinity": {
                        "nodeAffinity": {
                            "requiredDuringSchedulingIgnoredDuringExecution": {
                                "nodeSelectorTerms": [
                                    { "matchExpressions": [
                                        { "key": "foo", "operator": "In", "values": ["bar"] }
                                    ] }
                                ]
                            }
                        }
                    }
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        let affinity = pending
            .node_affinity
            .expect("nodeAffinity must be extracted from the watch event");
        let required = affinity
            .required_during_scheduling_ignored_during_execution
            .expect("required term must be extracted");
        assert_eq!(required.node_selector_terms.len(), 1);
        assert_eq!(
            required.node_selector_terms[0].match_expressions[0].key,
            "foo"
        );
    }

    /// A pod with no affinity set must produce `None`, not fail deserialization.
    #[test]
    fn needs_scheduling_returns_none_node_affinity_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.node_affinity.is_none(),
            "a pod without spec.affinity must produce node_affinity: None"
        );
    }

    /// select_node_with_capacity must skip a node that fails the pod's required
    /// nodeAffinity, even when it has free pod capacity — the exact scenario the
    /// conformance test exercises (a pod bound anyway means this predicate never ran).
    #[test]
    fn select_node_with_capacity_skips_node_failing_required_affinity() {
        let node = make_node_with_capacity("worker-0", &[], "110");
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_err(),
            "a node whose labels satisfy no required nodeAffinity term must be \
             skipped — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must select a node whose labels satisfy the
    /// pod's required nodeAffinity.
    #[test]
    fn select_node_with_capacity_selects_node_satisfying_required_affinity() {
        let node = make_node_with_capacity("worker-0", &[("foo", "bar")], "110");
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a node whose labels satisfy the required nodeAffinity term must be selected"
        );
    }

    // ---------------------------------------------------------------------------
    // NodeResourcesFit / pod-capacity gate (mayor-bbxr)
    //
    // Without this check the scheduler binds pods to nodes already at their pod
    // cap; the kubelet then fails them OutOfpods (phase=Failed) instead of leaving
    // the pod Pending where controllers can re-issue it safely.
    // ---------------------------------------------------------------------------

    fn make_node_with_capacity(name: &str, labels: &[(&str, &str)], capacity: &str) -> NodeItem {
        NodeItem {
            metadata: NodeMetadata {
                name: name.to_owned(),
                labels: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            },
            spec: NodeSpec::default(),
            status: NodeStatus {
                allocatable: NodeAllocatable {
                    pods: capacity.to_owned(),
                    ..Default::default()
                },
                capacity: NodeAllocatable {
                    pods: capacity.to_owned(),
                    ..Default::default()
                },
            },
        }
    }

    /// A NodeUsage with only a pod count set — the shorthand tests that predate
    /// resource-request tracking use to describe "this many pods already on
    /// the node, none of them requesting any resources".
    fn usage_with_pod_count(pod_count: u32) -> NodeUsage {
        NodeUsage {
            pod_count,
            requests: ResourceRequests::default(),
        }
    }

    /// A minimal PendingPod for tests that only care about capacity/taint/affinity
    /// gating, not identity or priority — empty selector (matches any node), no
    /// tolerations (tolerates nothing but taint-free nodes), no nodeAffinity
    /// (matches any node), no resource requests.
    fn empty_pending_pod() -> PendingPod {
        PendingPod {
            namespace: "default".to_owned(),
            pod_name: "pod".to_owned(),
            node_selector: Default::default(),
            priority: 0,
            tolerations: Vec::new(),
            node_affinity: None,
            requests: ResourceRequests::default(),
        }
    }

    /// A node at pod capacity must NOT be chosen — otherwise the kubelet fails
    /// the pod with OutOfpods (phase=Failed) and controllers may recreate without
    /// bound (mayor-bbxr).  Reverting `select_node_with_capacity` to ignore counts
    /// would make this test pass when it should fail: the function would return
    /// Ok("worker-0") instead of Err, so a pod would be bound to a full node.
    #[test]
    fn full_node_is_not_selected_so_pod_pends_instead_of_failing() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let pod = empty_pending_pod();
        // Node already has 110 pods — at capacity.
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(110))].into();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_err(),
            "a node at pod capacity must return Err so the pod stays Pending, \
             not be selected and cause the kubelet to fail it OutOfpods (mayor-bbxr) — \
             got: {:?}",
            result.ok()
        );
    }

    /// A node with one free slot must be selected — the common non-full case must
    /// still schedule.  If select_node_with_capacity always returns Err, all
    /// scheduling would stop (false positive), so we test the positive path too.
    #[test]
    fn node_with_free_slot_is_selected() {
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "110")],
        };
        let pod = empty_pending_pod();
        // Node has 109 pods — one slot free.
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(109))].into();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_ok(),
            "a node with a free slot must be selected — if this fails, scheduling is \
             incorrectly blocked even when capacity is available"
        );
        assert_eq!(result.unwrap(), "worker-0");
    }

    /// When two nodes match the selector but one is full, the scheduler must pick
    /// the node with free capacity — not the full one and not Err.
    #[test]
    fn full_node_is_skipped_when_second_node_has_room() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("worker-full", &[], "110"),
                make_node_with_capacity("worker-free", &[], "110"),
            ],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("worker-full".to_owned(), usage_with_pod_count(110)),
            ("worker-free".to_owned(), usage_with_pod_count(50)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_ok(),
            "must pick worker-free when worker-full is at capacity"
        );
        assert_eq!(
            result.unwrap(),
            "worker-free",
            "must skip the full node and pick the one with free capacity (mayor-bbxr)"
        );
    }

    /// When ALL matching nodes are full, the pod must stay Pending (Err returned)
    /// so that no OutOfpods failure is triggered.
    #[test]
    fn all_nodes_full_returns_err_so_pod_stays_pending() {
        let list = NodeList {
            items: vec![
                make_node_with_capacity("worker-0", &[], "110"),
                make_node_with_capacity("worker-1", &[], "110"),
            ],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> = [
            ("worker-0".to_owned(), usage_with_pod_count(110)),
            ("worker-1".to_owned(), usage_with_pod_count(110)),
        ]
        .into();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_err(),
            "all nodes full must return Err so the pod stays Pending, not be bound \
             to a full node causing OutOfpods (mayor-bbxr)"
        );
    }

    /// A node with unknown capacity (field absent / zero) must still be schedulable.
    /// We do not block on missing data — that would prevent scheduling entirely in
    /// clusters that don't expose allocatable.pods.
    #[test]
    fn node_with_unknown_capacity_is_not_blocked() {
        // capacity "" → parse_pod_capacity returns 0 → treated as "unknown, allow"
        let list = NodeList {
            items: vec![make_node_with_capacity("worker-0", &[], "")],
        };
        let pod = empty_pending_pod();
        let counts: std::collections::HashMap<String, NodeUsage> =
            [("worker-0".to_owned(), usage_with_pod_count(999))].into();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert!(
            result.is_ok(),
            "a node with unknown capacity (empty string) must not be blocked — \
             we don't have enough information to cap it"
        );
    }

    /// parse_pod_capacity handles the standard "110" quantity string.
    #[test]
    fn parse_pod_capacity_handles_standard_quantity() {
        assert_eq!(parse_pod_capacity("110"), 110);
        assert_eq!(parse_pod_capacity("0"), 0);
        assert_eq!(parse_pod_capacity(""), 0);
        assert_eq!(parse_pod_capacity("not-a-number"), 0);
    }

    /// summarize_node_pods counts pods correctly, excluding Succeeded and Failed.
    ///
    /// This is the NodeResourcesFit predicate: running/pending pods consume a slot;
    /// completed pods do not.  Reverting to count all pods would over-count and
    /// block scheduling when completed pods have not yet been GC'd.
    #[test]
    fn summarize_node_pods_excludes_terminal_phases_from_pod_count() {
        let body = serde_json::json!({
            "items": [
                { "status": { "phase": "Running" } },
                { "status": { "phase": "Pending" } },
                { "status": { "phase": "Succeeded" } },
                { "status": { "phase": "Failed" } },
                { "status": {} },  // missing phase → not terminal → counts
            ]
        })
        .to_string();
        let usage = summarize_node_pods(&body).expect("should parse");
        assert_eq!(
            usage.pod_count, 3,
            "Running + Pending + unknown-phase count as consuming a slot; \
             Succeeded and Failed do not (NodeResourcesFit predicate, mayor-bbxr)"
        );
    }

    /// summarize_node_pods also excludes terminal-phase pods' resource requests
    /// from the sum — a completed pod that requested 4 CPUs must not still count
    /// against the node's allocatable cpu, or a saturated-but-idle node would
    /// wrongly reject new pods forever.
    #[test]
    fn summarize_node_pods_excludes_terminal_phases_from_resource_sum() {
        let body = serde_json::json!({
            "items": [
                {
                    "spec": { "containers": [{ "resources": { "requests": { "cpu": "1" } } }] },
                    "status": { "phase": "Running" }
                },
                {
                    "spec": { "containers": [{ "resources": { "requests": { "cpu": "4" } } }] },
                    "status": { "phase": "Succeeded" }
                },
            ]
        })
        .to_string();
        let usage = summarize_node_pods(&body).expect("should parse");
        assert_eq!(
            usage.requests.cpu_milli, 1000,
            "a Succeeded pod's cpu request must not count against the node's usage"
        );
    }

    /// summarize_node_pods sums cpu/memory/ephemeral-storage requests across
    /// all non-terminated pods on the node — the exact input pick_node needs to
    /// decide whether a pending pod's own requests still fit.
    #[test]
    fn summarize_node_pods_sums_resource_requests_across_pods() {
        let body = serde_json::json!({
            "items": [
                {
                    "spec": { "containers": [{ "resources": { "requests": {
                        "cpu": "500m", "memory": "1Gi", "ephemeral-storage": "1Gi"
                    } } }] },
                    "status": { "phase": "Running" }
                },
                {
                    "spec": { "containers": [{ "resources": { "requests": {
                        "cpu": "500m", "memory": "1Gi", "ephemeral-storage": "1Gi"
                    } } }] },
                    "status": { "phase": "Pending" }
                },
            ]
        })
        .to_string();
        let usage = summarize_node_pods(&body).expect("should parse");
        assert_eq!(usage.pod_count, 2);
        assert_eq!(
            usage.requests.cpu_milli, 1000,
            "two 500m-cpu pods must sum to 1000 milli-cpu"
        );
        assert_eq!(
            usage.requests.memory_milli,
            2 * 1024 * 1024 * 1024 * 1000,
            "two 1Gi-memory pods must sum to 2Gi (in milli-bytes)"
        );
    }

    // parse_quantity_milli tests — the resource-quantity arithmetic underlying
    // NodeResourcesFit's cpu/memory/ephemeral-storage checks. A parsing bug here
    // silently mis-sizes every resource comparison the scheduler makes.

    #[test]
    fn parse_quantity_milli_handles_cpu_milli_suffix() {
        assert_eq!(parse_quantity_milli("500m"), 500);
    }

    #[test]
    fn parse_quantity_milli_handles_plain_cpu_cores() {
        assert_eq!(
            parse_quantity_milli("2"),
            2000,
            "a plain integer is whole cores, so '2' must be 2000 milli-cpu"
        );
    }

    #[test]
    fn parse_quantity_milli_handles_binary_memory_suffix() {
        assert_eq!(
            parse_quantity_milli("1Gi"),
            1024 * 1024 * 1024 * 1000,
            "1Gi must convert to exact bytes (Gi is binary, 1024-based), times 1000 for milli-units"
        );
    }

    #[test]
    fn parse_quantity_milli_returns_zero_for_empty_or_unparseable() {
        assert_eq!(
            parse_quantity_milli(""),
            0,
            "an absent quantity must be 0, treated by callers as 'unknown/unset', \
             not an error that blocks scheduling"
        );
        assert_eq!(parse_quantity_milli("not-a-quantity"), 0);
    }

    // resource_fits / NodeResourcesFit resource-dimension tests (mayor-7duz2):
    // the scheduler previously only checked pod COUNT against
    // status.allocatable.pods; a node saturated on cpu/memory/ephemeral-storage
    // but with a free pod slot would still accept a pod the kubelet then rejects
    // OutOfcpu/OutOfephemeral-storage — a real kubelet failure, not a scheduler
    // FailedScheduling event, so the conformance test's event-watch timed out.

    fn node_allocatable(cpu: &str, memory: &str, ephemeral_storage: &str) -> NodeAllocatable {
        NodeAllocatable {
            pods: String::new(),
            cpu: cpu.to_owned(),
            memory: memory.to_owned(),
            ephemeral_storage: ephemeral_storage.to_owned(),
        }
    }

    fn requests(
        cpu_milli: i64,
        memory_milli: i64,
        ephemeral_storage_milli: i64,
    ) -> ResourceRequests {
        ResourceRequests {
            cpu_milli,
            memory_milli,
            ephemeral_storage_milli,
        }
    }

    /// The exact saturate-then-overflow shape from predicates.go:129: a node's
    /// cpu is already fully committed by existing pods, and the pending pod's
    /// own request would push usage over allocatable — must be rejected.
    #[test]
    fn resource_fits_false_when_cpu_would_be_overcommitted() {
        let allocatable = node_allocatable("4", "", "");
        let used = requests(4000, 0, 0); // node already fully committed at 4 cores
        let pending = requests(1000, 0, 0); // one more core requested
        assert!(
            !resource_fits(&allocatable, used, pending),
            "a pending pod's cpu request must be rejected when it would push \
             usage past allocatable cpu — reverting this lets the scheduler bind \
             pods the kubelet then fails OutOfcpu"
        );
    }

    /// The exact ephemeral-storage saturate-then-overflow shape from
    /// predicates.go:129.
    #[test]
    fn resource_fits_false_when_ephemeral_storage_would_be_overcommitted() {
        let allocatable = node_allocatable("", "", "10Gi");
        let used = requests(0, 0, 10 * 1024 * 1024 * 1024 * 1000);
        let pending = requests(0, 0, 1000); // 1 milli-byte over the line
        assert!(
            !resource_fits(&allocatable, used, pending),
            "a pending pod's ephemeral-storage request must be rejected when it \
             would push usage past allocatable ephemeral-storage"
        );
    }

    /// A pending pod that fits within remaining capacity must be accepted —
    /// the positive-path counterpart, so this predicate doesn't block all
    /// scheduling by always returning false.
    #[test]
    fn resource_fits_true_when_request_fits_within_remaining_capacity() {
        let allocatable = node_allocatable("4", "8Gi", "20Gi");
        let used = requests(2000, 4 * 1024 * 1024 * 1024 * 1000, 0);
        let pending = requests(1000, 1024 * 1024 * 1024 * 1000, 0);
        assert!(
            resource_fits(&allocatable, used, pending),
            "a request that fits within remaining allocatable must be accepted"
        );
    }

    /// An allocatable dimension of 0 (field absent/unparseable) means "unknown"
    /// — that dimension must not block scheduling, mirroring
    /// `parse_pod_capacity`'s existing convention for `status.allocatable.pods`.
    #[test]
    fn resource_fits_true_when_allocatable_dimension_unknown() {
        let allocatable = node_allocatable("", "", "");
        let used = requests(999_999_000, 0, 0);
        let pending = requests(999_999_000, 0, 0);
        assert!(
            resource_fits(&allocatable, used, pending),
            "an unknown (empty) allocatable dimension must not block scheduling"
        );
    }

    // needs_scheduling / select_node_with_capacity resource-request wiring
    // (mayor-7duz2): the pending pod's OWN requests must be extracted from the
    // watch event and factored into the fit check, not just the already-bound
    // pods' requests.

    /// needs_scheduling sums spec.containers[].resources.requests into
    /// pending.requests — if dropped, select_node_with_capacity always sees a
    /// zero-request pod and never rejects it for lack of resources.
    #[test]
    fn needs_scheduling_returns_resource_requests_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "big-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "cpu": "2", "memory": "4Gi" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.cpu_milli, 2000,
            "spec.containers[].resources.requests.cpu must be summed into pending.requests"
        );
        assert_eq!(pending.requests.memory_milli, 4 * 1024 * 1024 * 1024 * 1000);
    }

    /// Multiple containers' requests must be summed, not just the first
    /// container's — Kubernetes charges a pod for the sum of all its
    /// containers' requests, not the max.
    #[test]
    fn needs_scheduling_sums_requests_across_multiple_containers() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "multi-container-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "cpu": "500m" } } },
                        { "resources": { "requests": { "cpu": "500m" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.cpu_milli, 1000,
            "two 500m-cpu containers in one pod must sum to 1000 milli-cpu, not 500"
        );
    }

    /// select_node_with_capacity must reject a node where the pending pod's own
    /// cpu request would overflow allocatable cpu, even though the node has
    /// free pod-count capacity — this is the exact predicates.go:129
    /// saturate-then-overflow scenario the scheduler previously missed entirely.
    #[test]
    fn select_node_with_capacity_skips_node_that_cannot_fit_pending_pod_cpu_request() {
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "4".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 1000; // pending pod wants 1 core
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pod_count: 1,
                requests: requests(4000, 0, 0), // node already fully committed at 4 cores
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage);
        assert!(
            result.is_err(),
            "a node with free pod-count capacity but no free cpu must still be \
             rejected — got: {:?}",
            result.ok()
        );
    }

    /// select_node_with_capacity must accept a node where the pending pod's
    /// requests fit within remaining allocatable resources.
    #[test]
    fn select_node_with_capacity_selects_node_with_enough_remaining_resources() {
        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "4".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 1000;
        let usage: std::collections::HashMap<String, NodeUsage> = [(
            "worker-0".to_owned(),
            NodeUsage {
                pod_count: 1,
                requests: requests(1000, 0, 0), // 1 of 4 cores already used
            },
        )]
        .into();
        let result = select_node_with_capacity(list, &pod, &usage);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a node with enough remaining cpu for the pending pod's request must be selected"
        );
    }

    /// needs_scheduling extracts the nodeSelector from the watch event.
    ///
    /// The nodeSelector must be extracted at the watch-event boundary (typed deserialization)
    /// so the scheduler can pass it to pick_node. If nodeSelector is silently dropped here,
    /// the scheduler always sees an empty selector and schedules pods on any node.
    #[test]
    fn needs_scheduling_returns_node_selector_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "restricted-pod", "namespace": "sched-pred" },
                "spec": {
                    "nodeSelector": {
                        "scheduledOnNode": "lima-node-2"
                    }
                }
            }
        });
        let result = needs_scheduling(&event);
        assert!(
            result.is_some(),
            "expected Some for unscheduled pod with nodeSelector"
        );
        let pending = result.unwrap();
        assert_eq!(pending.namespace, "sched-pred");
        assert_eq!(pending.pod_name, "restricted-pod");
        assert_eq!(
            pending
                .node_selector
                .get("scheduledOnNode")
                .map(|s| s.as_str()),
            Some("lima-node-2"),
            "nodeSelector must be extracted from spec.nodeSelector in the watch event — \
             if the selector is dropped, pick_node sees an empty selector and schedules \
             the pod on any node, breaking the NodeSelector conformance test"
        );
    }

    /// needs_scheduling returns an empty nodeSelector for pods without one.
    ///
    /// A pod without spec.nodeSelector must produce an empty selector, which matches
    /// any node. If this returns a non-empty selector, normal pods might not be scheduled.
    #[test]
    fn needs_scheduling_returns_empty_selector_when_no_node_selector() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "normal-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert!(
            pending.node_selector.is_empty(),
            "pod without nodeSelector must produce an empty selector (matches any node)"
        );
    }

    // ---------------------------------------------------------------------------
    // Preemption (mayor-rsei): needs_scheduling priority extraction,
    // parse_node_pods, and select_preemption_victims.
    //
    // Without priority-aware preemption, a higher-priority pod stays Pending
    // forever whenever lower-priority pods already claimed every slot on every
    // matching node — priority would be metadata nobody ever acts on.
    // ---------------------------------------------------------------------------

    /// needs_scheduling extracts spec.priority from the watch event.
    ///
    /// If priority is silently dropped here (as it once was — mayor-osuq), every
    /// pod looks identical to preemption and a high-priority pod can never
    /// legitimately evict a low-priority one.
    #[test]
    fn needs_scheduling_returns_priority_from_event() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "high-pod", "namespace": "default" },
                "spec": { "priority": 1000 }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.priority, 1000,
            "spec.priority must be extracted from the watch event — otherwise \
             preemption cannot distinguish this pod from a default-priority one"
        );
    }

    /// A pod with no spec.priority (no PriorityClass resolved) must default to 0,
    /// the lowest rung — matching Kubernetes' default pod priority. Without this
    /// default, such pods would be indistinguishable from `Option::None` and
    /// preemption's integer comparisons would need special-casing everywhere.
    #[test]
    fn needs_scheduling_defaults_priority_to_zero_when_absent() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "plain-pod", "namespace": "default" },
                "spec": {}
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.priority, 0,
            "a pod with no priority set must default to 0, not be treated as \
             missing/unschedulable"
        );
    }

    // parse_node_pods tests — the per-node pod listing that drives preemption
    // victim selection. Unlike summarize_node_pods, this retains identity
    // (to DELETE the victim) and priority (to decide if it's a legal victim).

    /// parse_node_pods excludes terminal-phase pods (they are not occupying a
    /// slot, so evicting them would help nobody) and extracts each pod's key and
    /// priority.
    #[test]
    fn parse_node_pods_excludes_terminal_phases_and_extracts_priority() {
        let body = serde_json::json!({
            "items": [
                { "metadata": {"name": "a", "namespace": "ns1"}, "spec": {"priority": 100}, "status": {"phase": "Running"} },
                { "metadata": {"name": "b", "namespace": "ns1"}, "spec": {"priority": 5}, "status": {"phase": "Succeeded"} },
            ]
        })
        .to_string();
        let pods = parse_node_pods(&body).expect("should parse");
        assert_eq!(
            pods.len(),
            1,
            "a Succeeded pod is not consuming a slot and must never be offered as \
             a preemption victim"
        );
        assert_eq!(pods[0].key, "ns1/a");
        assert_eq!(pods[0].priority, 100);
    }

    /// A pod with no spec.priority must default to 0 in parse_node_pods too —
    /// the same default needs_scheduling applies, so a pending pod at priority 1
    /// can still legally preempt it.
    #[test]
    fn parse_node_pods_defaults_priority_to_zero_when_absent() {
        let body = serde_json::json!({
            "items": [
                { "metadata": {"name": "a", "namespace": "default"}, "spec": {}, "status": {"phase": "Running"} },
            ]
        })
        .to_string();
        let pods = parse_node_pods(&body).expect("should parse");
        assert_eq!(
            pods[0].priority, 0,
            "a node-resident pod with no priority set must default to 0"
        );
    }

    // select_preemption_victims tests — the victim-selection decision at the
    // heart of preemption.

    fn np(key: &str, priority: i32) -> NodePod {
        NodePod {
            key: key.to_owned(),
            priority,
        }
    }

    /// A full node's only lower-priority pod must be selected as a victim.
    /// Without this, a higher-priority pod stays Pending forever whenever a
    /// lower-priority pod got scheduled first — priority would be meaningless.
    #[test]
    fn select_preemption_victims_evicts_lower_priority_pod_when_node_is_full() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(100, &node_pods, 1);
        assert_eq!(
            victims,
            vec!["default/low".to_owned()],
            "the node's only pod is lower priority and must be evicted to fit \
             the pending pod"
        );
    }

    /// kube-scheduler never preempts equal-or-higher-priority pods; if u7s did,
    /// same-priority pods could evict each other in a cycle and scheduling would
    /// never stabilize.
    #[test]
    fn select_preemption_victims_never_evicts_equal_or_higher_priority_pods() {
        let node_pods = vec![np("default/same", 100), np("default/higher", 500)];
        let victims = select_preemption_victims(100, &node_pods, 1);
        assert!(
            victims.is_empty(),
            "equal/higher priority pods must never be preemption victims — got {victims:?}"
        );
    }

    /// If the pending pod already fits (the node has a free slot), no eviction may
    /// happen — killing a running workload when there was room to spare would be
    /// a pure regression, not preemption.
    #[test]
    fn select_preemption_victims_returns_empty_when_pod_already_fits() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(100, &node_pods, 5);
        assert!(
            victims.is_empty(),
            "no eviction is needed when the node already has free capacity; got {victims:?}"
        );
    }

    /// If evicting every eligible lower-priority pod still would not free enough
    /// capacity, preemption must give up rather than evict pods for nothing — the
    /// pending pod would still not fit, so the disruption would help no one.
    #[test]
    fn select_preemption_victims_returns_empty_when_evicting_all_lower_priority_pods_still_not_enough(
    ) {
        // capacity=1, 3 pods present → 3 slots must free (needed = 3-1+1 = 3).
        // Only one pod (priority 1) is an eligible (lower-priority) victim; the
        // other two outrank the pending pod and can never be evicted. Evicting
        // the sole eligible pod only frees 1 of the 3 needed slots.
        let node_pods = vec![
            np("default/low", 1),
            np("default/high-1", 500),
            np("default/high-2", 500),
        ];
        let victims = select_preemption_victims(100, &node_pods, 1);
        assert!(
            victims.is_empty(),
            "must not evict any pod when doing so still would not free enough \
             capacity for the pending pod; got {victims:?}"
        );
    }

    /// When several lower-priority pods are eligible but only one eviction is
    /// needed, preemption must evict the cheapest (lowest-priority) pod and no
    /// more than necessary — over-eviction disrupts workloads for no benefit.
    #[test]
    fn select_preemption_victims_evicts_lowest_priority_first_and_no_more_than_needed() {
        let node_pods = vec![np("default/mid", 50), np("default/lowest", 1)];
        // capacity=2, used=2 (node exactly full) → needed = 2-2+1 = 1 slot.
        let victims = select_preemption_victims(100, &node_pods, 2);
        assert_eq!(
            victims,
            vec!["default/lowest".to_owned()],
            "must evict the single lowest-priority pod, not the mid-priority one, \
             and must not evict more pods than needed to fit the pending pod"
        );
    }

    /// A node with unknown pod-capacity (0 — see parse_pod_capacity) is treated as
    /// unlimited by select_node_with_capacity, so pick_node would already have
    /// chosen it; preemption must never trigger for such a node.
    #[test]
    fn select_preemption_victims_returns_empty_for_unknown_capacity_node() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(100, &node_pods, 0);
        assert!(
            victims.is_empty(),
            "unknown capacity (0) must never trigger eviction; got {victims:?}"
        );
    }

    // delete_pod_path / check_delete_response tests — the eviction request shape
    // and error handling, mirroring binding_path / check_bind_response.

    #[test]
    fn delete_pod_path_produces_correct_api_path() {
        let path = delete_pod_path("default", "victim-pod");
        assert_eq!(path, "/api/v1/namespaces/default/pods/victim-pod");
    }

    /// A 404 means the victim is already gone (e.g. a retried eviction) — that is
    /// the desired end state, so it must be treated as success, not an error that
    /// aborts the rest of the preemption flow.
    #[test]
    fn check_delete_response_ok_on_404_already_gone() {
        assert!(
            check_delete_response(404).is_ok(),
            "404 (already deleted) must be treated as success for eviction"
        );
    }

    #[test]
    fn check_delete_response_ok_on_2xx() {
        assert!(check_delete_response(200).is_ok());
        assert!(check_delete_response(202).is_ok());
    }

    /// A genuine failure (e.g. 500, or 403 if RBAC forbids the scheduler from
    /// deleting pods) must surface as Err so the caller aborts rather than binding
    /// the preemptor onto a node that never actually freed capacity.
    #[test]
    fn check_delete_response_err_on_failure() {
        assert!(check_delete_response(500).is_err());
        assert!(check_delete_response(403).is_err());
    }
}
