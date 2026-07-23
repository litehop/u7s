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

/// One term of a `NodeSelector`: its `matchExpressions` and `matchFields` are
/// ANDed together.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSelectorTerm {
    #[serde(default)]
    pub match_expressions: Vec<NodeSelectorRequirement>,
    /// Kubernetes only ever populates this with `metadata.name` — it's how the
    /// DaemonSet controller pins each per-node pod to a specific node while
    /// leaving `spec.nodeName` empty for the scheduler to fill in.
    #[serde(default)]
    pub match_fields: Vec<NodeSelectorRequirement>,
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

/// Build the `status.conditions` PATCH for a pod that just failed a
/// scheduling attempt (no node fit, even after preemption, or the bind
/// itself failed).
///
/// Mirrors upstream kube-scheduler, which patches `PodScheduled=False` with
/// reason `Unschedulable` on EVERY failed scheduling cycle, not just the
/// FailedScheduling Event `main.rs` already emits. Without this, a pod's
/// `status.conditions` stays frozen at the pod-creation-time default
/// forever, so anything polling for `{type: PodScheduled, reason:
/// Unschedulable}` (some conformance waits do exactly this) can never
/// observe the failure — and no self-generated MODIFIED event exists for it
/// either, since a status-only PATCH is the only thing that produces one.
pub fn failed_scheduling_status_patch(message: &str) -> Value {
    serde_json::json!({
        "status": {
            "conditions": [{
                "type": POD_SCHEDULED,
                "status": "False",
                "reason": UNSCHEDULABLE_REASON,
                "message": message,
            }]
        }
    })
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

/// Response body of `GET /api/v1/pods` — a full pod list, not a watch event.
/// Items are kept as raw `Value` (not deserialized into a `PodObject` up
/// front) so `pods_needing_resync` can wrap each one into the exact same
/// `{"type": "MODIFIED", "object": ...}` envelope `needs_scheduling` already
/// parses from a live watch event, without a second, parallel Pod type.
#[derive(Deserialize)]
pub struct PodList {
    pub items: Vec<Value>,
}

/// From a raw `/api/v1/pods` list's items, build the synthetic
/// `{"type": "MODIFIED", "object": <pod>}` watch events the periodic resync
/// loop should feed through the same per-event handler the live watch uses.
///
/// A pod that fails a scheduling attempt (e.g. exhausts preemption retries)
/// is otherwise stranded: `needs_scheduling` only fires on an ADDED/MODIFIED
/// event for the pod itself, a failed attempt never patches the pod's own
/// status, and the apiserver's watch replay is a bounded ring buffer that
/// can rotate past a stale pod's last event under unrelated churn long
/// before the next forced reconnect. The periodic resync exists to
/// manufacture that missing event from a fresh list, on a timer, independent
/// of whatever the watch stream has or hasn't delivered.
///
/// Delegates to `needs_scheduling`/`should_schedule` — the exact functions
/// the watch path already uses — so this can never diverge from what a real
/// watch event for the same pod would decide, and a pod already in
/// `in_flight` (a bind already running, from the watch or an earlier resync
/// tick) is excluded here exactly as it would be there. Pure so the
/// resync's core decision — which stranded pods get retried this tick — is
/// unit-testable without a live apiserver GET.
pub fn pods_needing_resync(
    items: &[Value],
    in_flight: &std::collections::HashSet<String>,
) -> Vec<Value> {
    items
        .iter()
        .map(|item| serde_json::json!({"type": "MODIFIED", "object": item}))
        .filter(|event| {
            needs_scheduling(event).is_some_and(|pending| {
                let key = format!("{}/{}", pending.namespace, pending.pod_name);
                should_schedule(in_flight, &key)
            })
        })
        .collect()
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
    /// Every other `status.allocatable`/`status.capacity` entry, keyed by
    /// resource name to its raw quantity string — extended resources (e.g.
    /// `scheduling.k8s.io/foo`, `nvidia.com/gpu`) and hugepages. The scheduler
    /// has no fixed list of extended-resource names (they are cluster-defined
    /// via `AddExtendedResource`-style PATCHes), so anything not already named
    /// above is captured here rather than silently dropped. Without this,
    /// `resource_fits`/preemption can never see that a node has (or lacks)
    /// capacity for a resource beyond cpu/memory/ephemeral-storage/pod-count,
    /// so a pod that only requests an extended resource always looks like it
    /// fits — the exact gap that leaves the SchedulerPreemption conformance
    /// suite's synthetic-resource tests unable to trigger eviction.
    #[serde(flatten)]
    pub extended: std::collections::BTreeMap<String, String>,
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
///
/// `extended` carries every OTHER requested resource (name -> milli-units),
/// e.g. `scheduling.k8s.io/foo` or `nvidia.com/gpu` — resource names the
/// scheduler has no fixed list for, so they cannot be dedicated struct fields
/// like cpu/memory. Without this, a pod requesting only an extended resource
/// always looks like it requests nothing, and can never be blocked (or
/// trigger preemption) by that resource being exhausted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResourceRequests {
    pub cpu_milli: i64,
    pub memory_milli: i64,
    pub ephemeral_storage_milli: i64,
    pub extended: std::collections::BTreeMap<String, i64>,
}

impl std::ops::Add for ResourceRequests {
    type Output = Self;
    fn add(mut self, other: Self) -> Self {
        self.cpu_milli += other.cpu_milli;
        self.memory_milli += other.memory_milli;
        self.ephemeral_storage_milli += other.ephemeral_storage_milli;
        for (name, amount) in other.extended {
            *self.extended.entry(name).or_insert(0) += amount;
        }
        self
    }
}

/// Subtract `victim`'s requests out of `total` in place — the inverse of
/// `Add`, used by `select_preemption_victims` to track how much of each
/// dimension remains committed as candidate victims are evicted one at a
/// time. Not a `Sub`/`SubAssign` impl: this is the only call site, and an
/// operator overload would need to decide what negative remainders mean
/// (they cannot occur here — a node's used total is always >= any single
/// pod's request already counted in it).
fn subtract_requests(total: &mut ResourceRequests, victim: &ResourceRequests) {
    total.cpu_milli -= victim.cpu_milli;
    total.memory_milli -= victim.memory_milli;
    total.ephemeral_storage_milli -= victim.ephemeral_storage_milli;
    for (name, amount) in &victim.extended {
        if let Some(remaining) = total.extended.get_mut(name) {
            *remaining -= amount;
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

/// Sum `resources.requests.{cpu,memory,ephemeral-storage}` plus every other
/// (extended) resource key across a pod's containers. Init containers are not
/// accounted for — this MVP sums the steady-state (regular) containers only,
/// matching what the conformance suite's saturate-then-overflow tests
/// actually create.
fn sum_container_requests(containers: &[ContainerSpec]) -> ResourceRequests {
    let mut total = ResourceRequests::default();
    for c in containers {
        for (name, quantity) in &c.resources.requests {
            let milli = parse_quantity_milli(quantity);
            match name.as_str() {
                "cpu" => total.cpu_milli += milli,
                "memory" => total.memory_milli += milli,
                "ephemeral-storage" => total.ephemeral_storage_milli += milli,
                _ => *total.extended.entry(name.clone()).or_insert(0) += milli,
            }
        }
    }
    total
}

#[derive(Deserialize, Default)]
struct PodListItemStatus {
    #[serde(default)]
    phase: String,
}

/// A node's already-committed usage from its non-terminated pods: the pod
/// count (against `status.allocatable.pods`) and summed cpu/memory/
/// ephemeral-storage requests (against `status.allocatable.{cpu,memory,ephemeral-storage}`).
/// Computed by `NodeTally::usage_by_node`.
#[derive(Debug, Default, Clone)]
pub struct NodeUsage {
    pub pod_count: u32,
    pub requests: ResourceRequests,
}

/// A pod already on a node, as needed by preemption victim selection: its
/// "namespace/name" key (to DELETE it), its scheduling priority (to decide
/// whether it is a legal victim for a given pending pod), and its own
/// resource requests (how much pod-count/cpu/memory/ephemeral-storage/
/// extended-resource capacity evicting it would actually free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePod {
    pub key: String,
    pub priority: i32,
    pub requests: ResourceRequests,
}

/// Minimal typed view of a pod watch event's object needed to maintain
/// `NodeTally`: identity (to key the tally), phase (to exclude terminated
/// pods), `spec.nodeName` (which node, if any, it occupies a slot on), and
/// its containers' resource requests.
#[derive(Deserialize)]
struct PreemptionPodListItem {
    metadata: PodMetadata,
    #[serde(default)]
    spec: PodSpec,
    #[serde(default)]
    status: PodListItemStatus,
}

/// One pod's contribution to `NodeTally`: which node it currently occupies a
/// slot on, its priority (preemption eligibility), and its resource requests.
#[derive(Debug, Clone)]
struct TalliedPod {
    node_name: String,
    priority: i32,
    requests: ResourceRequests,
}

/// An in-memory, watch-maintained running tally of every bound, non-terminal
/// pod's resource requests, keyed by "namespace/name".
///
/// Replaces a design where `pick_node`/`find_preemption_plan` issued a live
/// GET /api/v1/pods?fieldSelector=spec.nodeName=<node> per candidate node on
/// every scheduling decision. Besides being O(qualifying nodes) HTTP+DB round
/// trips per pod scheduled, that GET raced the scheduler's own writes: under
/// concurrent scheduling load, a just-committed bind's resource request was
/// not always visible to the very next GET (a read-after-write race between
/// the bind and the immediately-following capacity check), so a node could
/// look emptier than it really was and receive a second pod it did not
/// actually have room for — the kubelet then rejected it with OutOfcpu.
///
/// `main.rs` keeps this current two ways: (1) every pod watch event is fed
/// through `apply_event`, so the tally converges to cluster state the same
/// way a real kube-scheduler's informer cache does; (2) the scheduler's own
/// `assume`/`remove` calls update it immediately when it decides to bind or
/// evict a pod, before the HTTP call that makes the change durable even
/// completes — so a scheduling decision (possibly running concurrently, in a
/// different spawned task) can never read a snapshot older than the most
/// recent decision this process itself already made.
#[derive(Debug, Default)]
pub struct NodeTally {
    pods: std::collections::HashMap<String, TalliedPod>,
}

impl NodeTally {
    /// Update the tally from one raw pod watch event.
    ///
    /// A DELETED event, or an ADDED/MODIFIED event for a pod that is unbound
    /// (`spec.nodeName` empty) or in a terminal phase (Succeeded/Failed —
    /// mirrors the NodeResourcesFit predicate: a completed pod is not
    /// occupying a slot), removes any prior entry for that pod. Any other
    /// ADDED/MODIFIED event overwrites (never adds to) the entry, so
    /// replaying the same event twice — e.g. after a watch reconnect —
    /// is idempotent.
    pub fn apply_event(&mut self, event: &Value) {
        let Ok(watch_event) =
            serde_json::from_value::<WatchEvent<PreemptionPodListItem>>(event.clone())
        else {
            return;
        };
        let name = watch_event.object.metadata.name.unwrap_or_default();
        if name.is_empty() {
            return;
        }
        let namespace = watch_event
            .object
            .metadata
            .namespace
            .unwrap_or_else(|| "default".to_owned());
        let key = format!("{namespace}/{name}");

        if watch_event.event_type != "ADDED" && watch_event.event_type != "MODIFIED" {
            self.pods.remove(&key);
            return;
        }
        let terminal = matches!(
            watch_event.object.status.phase.as_str(),
            "Succeeded" | "Failed"
        );
        let priority = watch_event.object.spec.priority.unwrap_or(0);
        let requests = sum_container_requests(&watch_event.object.spec.containers);
        let node_name = watch_event.object.spec.node_name.filter(|n| !n.is_empty());
        match node_name {
            Some(node_name) if !terminal => {
                self.pods.insert(
                    key,
                    TalliedPod {
                        node_name,
                        priority,
                        requests,
                    },
                );
            }
            _ => {
                self.pods.remove(&key);
            }
        }
    }

    /// Record that `namespace/pod_name` now occupies a slot on `node_name` —
    /// called the instant the scheduler decides to bind, before the bind's
    /// HTTP call even completes. `remove` undoes this if the bind then fails.
    pub fn assume(
        &mut self,
        namespace: &str,
        pod_name: &str,
        node_name: &str,
        priority: i32,
        requests: ResourceRequests,
    ) {
        self.pods.insert(
            format!("{namespace}/{pod_name}"),
            TalliedPod {
                node_name: node_name.to_owned(),
                priority,
                requests,
            },
        );
    }

    /// Remove `namespace/pod_name` from the tally — called immediately after
    /// a preemption eviction succeeds (freeing its resources for the re-fit
    /// check that follows), or to roll back an `assume` when the bind it
    /// anticipated does not actually go through.
    pub fn remove(&mut self, namespace: &str, pod_name: &str) {
        self.pods.remove(&format!("{namespace}/{pod_name}"));
    }

    /// Drop all tallied state. Called on watch reconnect: the reconnected
    /// watch always replays the full ring-buffer history from scratch, and
    /// without clearing first, a pod deleted while disconnected (and since
    /// aged out of the ring buffer) would leave a phantom entry this tally
    /// could never otherwise correct.
    pub fn clear(&mut self) {
        self.pods.clear();
    }

    /// Non-terminal pod count and summed resource requests per node — the
    /// shape `select_node_with_capacity` consumes in place of a live GET.
    pub fn usage_by_node(&self) -> std::collections::HashMap<String, NodeUsage> {
        let mut usage: std::collections::HashMap<String, NodeUsage> =
            std::collections::HashMap::new();
        for pod in self.pods.values() {
            let entry = usage.entry(pod.node_name.clone()).or_default();
            entry.pod_count += 1;
            entry.requests = entry.requests.clone() + pod.requests.clone();
        }
        usage
    }

    /// Every tallied pod currently on `node_name`, for preemption victim
    /// selection — in place of a live GET.
    pub fn pods_on(&self, node_name: &str) -> Vec<NodePod> {
        self.pods
            .iter()
            .filter(|(_, p)| p.node_name == node_name)
            .map(|(key, p)| NodePod {
                key: key.clone(),
                priority: p.priority,
                requests: p.requests.clone(),
            })
            .collect()
    }
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
        && node_affinity_matches(
            &node.metadata.labels,
            &node.metadata.name,
            pod.node_affinity.as_ref(),
        )
        && node_taints_tolerated(&node.spec.taints, &pod.tolerations)
}

/// Return true when adding `requested` to a node's already-committed `used`
/// requests would not exceed `allocatable`, independently for each of
/// cpu/memory/ephemeral-storage/extended resources. An allocatable value of 0
/// (field absent or unparseable — see `parse_quantity_milli`) means that
/// cpu/memory/ephemeral-storage dimension is unknown and is not checked,
/// mirroring `parse_pod_capacity`'s existing convention for
/// `status.allocatable.pods`.
///
/// Extended resources are NOT given this "unknown means unlimited" treatment:
/// a node that does not advertise a given extended resource at all has none
/// of it to give, so requesting it must fail-closed, not be silently ignored
/// — otherwise a pod requesting a GPU (say) could be bound to a node with no
/// GPU, which the kubelet would then reject anyway (as the SchedulerPreemption
/// conformance suite's synthetic `scheduling.k8s.io/foo` resource does today).
fn resource_fits(
    allocatable: &NodeAllocatable,
    used: &ResourceRequests,
    requested: &ResourceRequests,
) -> bool {
    let cpu_cap = parse_quantity_milli(&allocatable.cpu);
    let mem_cap = parse_quantity_milli(&allocatable.memory);
    let eph_cap = parse_quantity_milli(&allocatable.ephemeral_storage);
    (cpu_cap == 0 || used.cpu_milli + requested.cpu_milli <= cpu_cap)
        && (mem_cap == 0 || used.memory_milli + requested.memory_milli <= mem_cap)
        && (eph_cap == 0
            || used.ephemeral_storage_milli + requested.ephemeral_storage_milli <= eph_cap)
        && requested.extended.iter().all(|(name, &want)| {
            if want == 0 {
                return true;
            }
            let cap = allocatable
                .extended
                .get(name)
                .map(|s| parse_quantity_milli(s))
                .unwrap_or(0);
            let have = used.extended.get(name).copied().unwrap_or(0);
            have + want <= cap
        })
}

/// Select the first node from `list` that qualifies for `pod`
/// (see `node_qualifies_for_pod`) AND that has at least one free pod slot AND
/// enough uncommitted cpu/memory/ephemeral-storage/extended resources to fit
/// `pod.requests` (NodeResourcesFit).
///
/// `node_usage` maps node name → current non-terminated pod count and summed
/// resource requests, as computed by `NodeTally::usage_by_node`.  If a node's
/// name is absent from `node_usage`, its usage is treated as zero
/// (conservative: schedule).
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
            .cloned()
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
        resource_fits(&n.status.allocatable, &usage.requests, &pod.requests)
    });
    found.map(|n| n.metadata.name).context(
        "no node satisfies the pod's nodeSelector/tolerations with free pod/resource capacity (NodeResourcesFit)",
    )
}

/// Select the pods to evict from one node so that a pending pod at
/// `pending_priority` requesting `pending_requests` fits, given the node's
/// pod-count `pod_count_capacity` and resource `allocatable` — the same
/// dimensions `resource_fits`/`select_node_with_capacity` check at bind time.
///
/// Generalizes the original pod-count-only MVP: a pending pod can be blocked
/// by pod-count OR by any resource dimension `select_node_with_capacity`
/// would reject it for — most notably an extended resource (e.g. a GPU, or
/// the SchedulerPreemption conformance suite's synthetic
/// `scheduling.k8s.io/foo`). Without accounting for resources here too, a
/// higher-priority pod whose only contention is an extended resource can
/// never trigger eviction — `pick_node` already returns `Ok` for such a node
/// (cpu/memory/pod-count all look free), so this function never even runs,
/// and the pending pod is bound onto a node the kubelet then rejects it from,
/// with no recourse.
///
/// Only pods with priority STRICTLY LOWER than `pending_priority` are eligible
/// victims: kube-scheduler never preempts equal-or-higher-priority pods, and
/// neither must u7s — otherwise same-priority pods could evict each other in a
/// cycle and scheduling would never stabilize. Eligible victims are evicted
/// lowest-priority-first (cheapest disruption), accumulating freed pod-count
/// and resource capacity one victim at a time, until the pending pod fits
/// every dimension — never evicting more than necessary.
///
/// Returns an empty `Vec` — meaning "do not evict anything" — when the pod
/// already fits (preemption must never run when there was room, or it would
/// kill a workload for no reason), or when evicting every eligible
/// lower-priority pod still would not free enough of some dimension — the
/// pending pod would not fit even after the disruption, so evicting anyone
/// would be pointless.
pub fn select_preemption_victims(
    pending_priority: i32,
    pending_requests: &ResourceRequests,
    node_pods: &[NodePod],
    pod_count_capacity: u32,
    allocatable: &NodeAllocatable,
) -> Vec<String> {
    let fits = |pod_count: u32, requests: &ResourceRequests| {
        (pod_count_capacity == 0 || pod_count < pod_count_capacity)
            && resource_fits(allocatable, requests, pending_requests)
    };

    let total_pod_count = node_pods.len() as u32;
    let total_requests = node_pods
        .iter()
        .fold(ResourceRequests::default(), |acc, p| {
            acc + p.requests.clone()
        });

    // Pod-count is a candidate-independent dimension: if it is short, EVERY
    // pod helps (each occupies exactly one slot). A resource dimension is
    // different: a pod that requests none of a specific short resource frees
    // none of it by being evicted, no matter how low its priority — e.g. on a
    // node short on the SchedulerPreemption suite's synthetic
    // `scheduling.k8s.io/foo`, evicting coredns (which requests none of it)
    // is pure collateral damage that helps nobody — reproduced live: before
    // this filter, u7s evicted kube-system/coredns and
    // kube-system/konnectivity-agent instead of the pod actually holding the
    // contended resource, because they happened to have lower/no priority.
    let pod_count_short = pod_count_capacity != 0 && total_pod_count >= pod_count_capacity;
    let mut candidates: Vec<&NodePod> = node_pods
        .iter()
        .filter(|p| p.priority < pending_priority)
        .filter(|p| {
            pod_count_short
                || resource_deficiency_relevant(
                    allocatable,
                    &total_requests,
                    pending_requests,
                    &p.requests,
                )
        })
        .collect();
    candidates.sort_by_key(|p| p.priority);

    let mut remaining_pod_count = total_pod_count;
    let mut remaining_requests = total_requests;
    let mut victims = Vec::new();
    for candidate in candidates {
        if fits(remaining_pod_count, &remaining_requests) {
            break;
        }
        remaining_pod_count -= 1;
        subtract_requests(&mut remaining_requests, &candidate.requests);
        victims.push(candidate.key.clone());
    }

    if fits(remaining_pod_count, &remaining_requests) {
        victims
    } else {
        Vec::new()
    }
}

/// Return true when evicting a pod requesting `candidate` could plausibly
/// help admit `pending` — i.e. some resource dimension is both short (adding
/// `pending`'s request to the node's `total_used` would exceed `allocatable`)
/// AND `candidate` itself requests a nonzero amount of that SAME dimension.
/// A pod holding none of the scarce resource cannot free any of it by being
/// evicted, however low its priority (see `select_preemption_victims`).
fn resource_deficiency_relevant(
    allocatable: &NodeAllocatable,
    total_used: &ResourceRequests,
    pending: &ResourceRequests,
    candidate: &ResourceRequests,
) -> bool {
    let short = |cap: i64, used: i64, want: i64| cap != 0 && used + want > cap;
    if short(
        parse_quantity_milli(&allocatable.cpu),
        total_used.cpu_milli,
        pending.cpu_milli,
    ) && candidate.cpu_milli > 0
    {
        return true;
    }
    if short(
        parse_quantity_milli(&allocatable.memory),
        total_used.memory_milli,
        pending.memory_milli,
    ) && candidate.memory_milli > 0
    {
        return true;
    }
    if short(
        parse_quantity_milli(&allocatable.ephemeral_storage),
        total_used.ephemeral_storage_milli,
        pending.ephemeral_storage_milli,
    ) && candidate.ephemeral_storage_milli > 0
    {
        return true;
    }
    pending.extended.iter().any(|(name, &want)| {
        if want == 0 {
            return false;
        }
        // Unlike cpu/memory/ephemeral-storage, a missing/0 capacity for an
        // extended resource is a real (exhausted) limit, not "unknown, don't
        // check" — matches resource_fits's fail-closed convention. So this
        // branch, unlike the three above, does NOT gate on `cap != 0`.
        let cap = allocatable
            .extended
            .get(name)
            .map(|s| parse_quantity_milli(s))
            .unwrap_or(0);
        let used = total_used.extended.get(name).copied().unwrap_or(0);
        let candidate_has = candidate.extended.get(name).copied().unwrap_or(0);
        used + want > cap && candidate_has > 0
    })
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

/// Return true when `labels`/`node_name` satisfy a required `nodeAffinity`.
///
/// `nodeSelectorTerms` are ORed together (any one term matching is enough);
/// within a single term, every `matchExpressions` requirement AND every
/// `matchFields` requirement must hold — mirroring Kubernetes' `NodeSelector`
/// semantics. `matchFields` is evaluated against a synthetic one-entry
/// `{"metadata.name": node_name}` map — the only field Kubernetes ever
/// populates `matchFields` with (it's how the DaemonSet controller pins each
/// per-node pod). `None` (no nodeAffinity, or no
/// `requiredDuringSchedulingIgnoredDuringExecution`, or an empty term list)
/// matches any node — there is nothing to restrict on.
///
/// Extracted as a pure function so the predicate can be unit-tested without
/// network access — mirrors `node_selector_matches`.
pub fn node_affinity_matches(
    labels: &std::collections::HashMap<String, String>,
    node_name: &str,
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
    let field_values: std::collections::HashMap<String, String> =
        [("metadata.name".to_owned(), node_name.to_owned())].into();
    required.node_selector_terms.iter().any(|term| {
        term.match_expressions
            .iter()
            .all(|req| node_selector_requirement_matches(labels, req))
            && term
                .match_fields
                .iter()
                .all(|req| node_selector_requirement_matches(&field_values, req))
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

/// Why `pick_node` failed to find a node for a pending pod.
///
/// The caller must treat these two causes very differently. `NoCapacity`
/// means every qualifying node was actually checked and none had room — a
/// legitimate reason to fall back to preemption (see `find_preemption_plan`).
/// `ApiError` means the GET /api/v1/nodes call itself failed, or its body
/// could not be parsed — no node was actually checked, so this says nothing
/// about real capacity. Collapsing `ApiError` into `NoCapacity` (the bug this
/// type replaces) would run preemption — evicting real lower-priority pods —
/// or mark the pod FailedScheduling, off a transient infra hiccup that the
/// next watch tick would otherwise have retried cleanly.
#[derive(Debug, thiserror::Error)]
pub enum PickNodeError {
    #[error(
        "no node satisfies the pod's nodeSelector/tolerations with free pod/resource capacity (NodeResourcesFit)"
    )]
    NoCapacity,
    #[error(transparent)]
    ApiError(#[from] anyhow::Error),
}

/// Return the name of the first node that qualifies for `pod`
/// (see `node_qualifies_for_pod`), has at least one free pod slot, and has
/// enough uncommitted cpu/memory/ephemeral-storage for `pod.requests`
/// (NodeResourcesFit predicate). On success, atomically reserves `pod` on
/// the chosen node in `tally` (see `NodeTally::assume`) before returning it.
///
/// Fetches the node list from the API server; per-node usage comes from
/// `tally` (see `NodeTally`) — an in-memory tally the scheduler's own pod
/// watch keeps current, not a live GET. A prior version issued a GET
/// /api/v1/pods?fieldSelector=spec.nodeName%3D<node> per qualifying candidate
/// node on every scheduling decision; besides being O(qualifying nodes) per
/// decision, that GET could read a just-committed bind's resource request as
/// stale (a read-after-write race under concurrent scheduling load), letting
/// a pod be bound onto a node that was actually already full. `tally` cannot
/// observe that race: the scheduler updates it synchronously the moment it
/// decides to bind, before the bind's HTTP call even completes.
///
/// The reservation happens under the SAME lock acquisition as the fit check,
/// not in a later, separate lock taken by the caller: two pods racing for the
/// same just-freed slot (e.g. a preemptor's post-eviction re-check racing a
/// controller's replacement pod for the capacity a preemption just freed —
/// reproduced live against the PreemptionExecutionPath conformance scenario)
/// could otherwise both read the slot as free before either reserved it, and
/// both bind — the kubelet then rejects whichever container it admits
/// second. Splitting the check and the reservation across two lock
/// acquisitions (as a prior version did, calling `NodeTally::assume`
/// separately after `pick_node` returned) reopens exactly the read-after-write
/// race this tally exists to close, just between two scheduling decisions
/// instead of between a GET and a bind.
///
/// A node at or above its `status.allocatable.pods` limit, or that cannot fit
/// `pod.requests` alongside what's already tallied, is skipped. Returns
/// `Err(PickNodeError::NoCapacity)` when no suitable node exists so the
/// caller can skip binding and leave the pod Pending (mayor-bbxr: without
/// this check, pods are bound to full nodes and the kubelet fails them
/// OutOfpods/OutOfcpu/OutOfephemeral-storage). Returns
/// `Err(PickNodeError::ApiError(_))` when the GET or its response body is
/// itself unusable — see `PickNodeError` for why the caller must not treat
/// that the same as `NoCapacity`.
pub async fn pick_node(
    connector: &TlsConnector,
    server: &str,
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> Result<String, PickNodeError> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        return Err(PickNodeError::ApiError(anyhow::anyhow!(
            "GET /api/v1/nodes returned {status}: {body}"
        )));
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;
    select_and_reserve_node(list, pod, tally)
}

/// The synchronous fit-check-and-reserve step behind `pick_node`, split out
/// so its atomicity (one `tally` lock acquisition covers both the check and
/// the reservation) can be exercised under real concurrent access in a unit
/// test, without a live API server — `pick_node` itself cannot be unit
/// tested that way since it needs a network round trip for the node list.
fn select_and_reserve_node(
    list: NodeList,
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> Result<String, PickNodeError> {
    let mut tally_guard = tally.lock().expect("tally lock poisoned");
    let node = select_node_with_capacity(list, pod, &tally_guard.usage_by_node())
        .map_err(|_| PickNodeError::NoCapacity)?;
    tally_guard.assume(
        &pod.namespace,
        &pod.pod_name,
        &node,
        pod.priority,
        pod.requests.clone(),
    );
    Ok(node)
}

/// Whether a `pick_node` failure should be treated as "leave this pod
/// Pending and let the watch retry" instead of falling through to
/// preemption.
///
/// Pure predicate over the typed error — no networking — so the exact
/// branch that was bugged before `PickNodeError` existed (every `pick_node`
/// failure fell through to preemption, so a transient GET failure could
/// evict real lower-priority pods, or mark an otherwise-healthy pod
/// FailedScheduling, for no actual capacity reason) can be unit-tested
/// without a fake API server — `main.rs`'s tokio::spawn body that acts on
/// this isn't otherwise reachable from a unit test.
pub fn should_retry_without_preempting(err: &PickNodeError) -> bool {
    matches!(err, PickNodeError::ApiError(_))
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
/// pods would free a slot for `pod`. On success, atomically reserves `pod`
/// on the chosen node in `tally` (see `NodeTally::assume`) — BEFORE any of
/// `victims` is actually evicted — so the caller can safely evict them and
/// bind without a second fit check.
///
/// Intended to run only after `pick_node` has already failed for the same pod —
/// this is the fallback that stops a higher-priority pod from staying Pending
/// forever just because lower-priority pods claimed every slot first (mayor-rsei).
///
/// Per-node pod identity/priority/requests come from `tally` (see
/// `NodeTally`), not a live GET — see `pick_node`'s doc comment for why.
/// Reserving `pod` before eviction, rather than checking fit again after it,
/// is deliberate: a live repro against the PreemptionExecutionPath
/// conformance scenario showed that evicting victims first and only then
/// re-checking leaves a window where a THIRD, concurrently-scheduled pod
/// (there, a ReplicaSet controller's replacement for a pod just evicted)
/// can repeatedly claim each freed slot before the actual preemptor's
/// re-check runs — fast enough that even a several-attempt bounded retry of
/// "evict, then re-check" never won. Reserving first means the tally already
/// shows the node as occupied by `pod` — on top of the not-yet-evicted
/// victims — for the entire eviction sequence, so no other scheduling
/// decision ever observes a free slot to steal.
///
/// The reservation happens under a single, fresh lock acquisition that also
/// re-verifies the plan against the CURRENT tally (not the possibly-stale
/// per-node snapshots the search loop below used): if some other reservation
/// has already consumed the room this plan counted on, this returns `Err` so
/// the caller can re-plan from scratch, instead of reserving `pod` onto a
/// node that a fresher read shows no longer fits.
///
/// Among nodes where preemption would work, the node requiring the FEWEST
/// victims is chosen (cheapest disruption); ties keep the API server's node-list
/// order. Returns `Err` when no candidate node — even after preempting every
/// eligible lower-priority pod on it — could fit the pending pod.
pub async fn find_preemption_plan(
    connector: &TlsConnector,
    server: &str,
    pod: &PendingPod,
    tally: &std::sync::Mutex<NodeTally>,
) -> anyhow::Result<PreemptionPlan> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;

    let mut best: Option<(usize, PreemptionPlan)> = None;
    for (index, node) in list.items.iter().enumerate() {
        if !node_qualifies_for_pod(node, pod) {
            continue;
        }
        let capacity = pod_count_capacity(node);
        let node_name = &node.metadata.name;
        let node_pods = tally
            .lock()
            .expect("tally lock poisoned")
            .pods_on(node_name);

        let victims = select_preemption_victims(
            pod.priority,
            &pod.requests,
            &node_pods,
            capacity,
            &node.status.allocatable,
        );
        if victims.is_empty() {
            continue;
        }
        let is_cheaper = best
            .as_ref()
            .is_none_or(|(_, b)| victims.len() < b.victims.len());
        if is_cheaper {
            best = Some((
                index,
                PreemptionPlan {
                    node_name: node_name.clone(),
                    victims,
                },
            ));
        }
    }

    let (index, plan) =
        best.context("no node can fit the pending pod even after preempting lower-priority pods")?;
    verify_and_reserve_preemption(pod, &list.items[index], &plan, tally)?;

    Ok(plan)
}

/// Resolve a node's pod-count capacity, preferring `status.allocatable.pods`
/// and falling back to `status.capacity.pods` — shared by
/// `select_node_with_capacity` and `find_preemption_plan` so both agree on
/// which field wins when both are present.
fn pod_count_capacity(node: &NodeItem) -> u32 {
    let cap_str = if !node.status.allocatable.pods.is_empty() {
        &node.status.allocatable.pods
    } else {
        &node.status.capacity.pods
    };
    parse_pod_capacity(cap_str)
}

/// The synchronous re-verify-and-reserve step behind `find_preemption_plan`,
/// split out so its atomicity (one `tally` lock acquisition covers both the
/// fresh fit re-check and the reservation) can be exercised under real
/// concurrent access in a unit test — mirrors `select_and_reserve_node`'s
/// relationship to `pick_node`, for the same reason (see `find_preemption_plan`'s
/// doc comment).
///
/// Re-derives remaining pod-count and resource usage on `node` from a FRESH
/// `tally` read with `plan.victims`' contributions subtracted out (rather
/// than trusting the possibly-stale snapshot the search loop in
/// `find_preemption_plan` used), so a reservation some other decision made in
/// the meantime is never missed.
fn verify_and_reserve_preemption(
    pod: &PendingPod,
    node: &NodeItem,
    plan: &PreemptionPlan,
    tally: &std::sync::Mutex<NodeTally>,
) -> anyhow::Result<()> {
    let capacity = pod_count_capacity(node);
    let mut tally_guard = tally.lock().expect("tally lock poisoned");
    let current_pods = tally_guard.pods_on(&plan.node_name);
    let mut remaining_pod_count = current_pods.len() as u32;
    let mut remaining_requests = current_pods
        .iter()
        .fold(ResourceRequests::default(), |acc, p| {
            acc + p.requests.clone()
        });
    for victim in &plan.victims {
        // A victim already absent from the fresh read (e.g. some other actor
        // deleted it independently) contributes nothing to subtract — its
        // capacity is already free, which only helps this check succeed.
        if let Some(p) = current_pods.iter().find(|p| &p.key == victim) {
            remaining_pod_count -= 1;
            subtract_requests(&mut remaining_requests, &p.requests);
        }
    }
    let still_fits = (capacity == 0 || remaining_pod_count < capacity)
        && resource_fits(&node.status.allocatable, &remaining_requests, &pod.requests);
    if !still_fits {
        bail!(
            "no node still fits after preemption \
             (capacity may have been claimed concurrently)"
        );
    }
    tally_guard.assume(
        &pod.namespace,
        &pod.pod_name,
        &plan.node_name,
        pod.priority,
        pod.requests.clone(),
    );
    Ok(())
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
/// than "already gone" or "already changing".
///
/// A 404 means the pod was already removed — by a previous retry of this same
/// eviction, or another actor — which is the outcome preemption wants, so it
/// must be treated as success rather than aborting the eviction loop.
///
/// A 409 means the eviction's own soft-delete PUT lost an optimistic-concurrency
/// race against a concurrent write to the same victim (e.g. the kubelet's
/// routine status sync while the pod is being torn down, or another scheduling
/// attempt evicting the same victim). `delete_pod` issues this DELETE twice
/// (soft-delete then force-delete) specifically to drive the pod to gone, so a
/// 409 here just means the current attempt lost that race, not that eviction
/// failed — the pod is already moving toward deletion. Treating it as fatal
/// would abort the whole preemption cycle via `?` and leave the preemptor
/// pod stuck Pending.
pub fn check_delete_response(status: u16) -> anyhow::Result<()> {
    if (200..300).contains(&status) || status == 404 || status == 409 {
        return Ok(());
    }
    bail!("evict failed with HTTP {status}")
}

// ---------------------------------------------------------------------------
// Scheduling Events — reports bind success/failure so `kubectl describe pod`
// and clients that watch Events (e.g. the SchedulerPredicates e2e suite's
// observeEventAfterAction) can see the outcome.
// ---------------------------------------------------------------------------

/// The `involvedObject` reference on a scheduling Event — always the pod.
#[derive(Serialize)]
struct EventInvolvedObject<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    namespace: &'a str,
    name: &'a str,
}

#[derive(Serialize)]
struct EventSource<'a> {
    component: &'a str,
}

#[derive(Serialize)]
struct EventMeta<'a> {
    name: &'a str,
    namespace: &'a str,
}

/// Full Event object body as posted to the API server.
#[derive(Serialize)]
struct SchedulingEvent<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    metadata: EventMeta<'a>,
    #[serde(rename = "involvedObject")]
    involved_object: EventInvolvedObject<'a>,
    reason: &'a str,
    message: &'a str,
    #[serde(rename = "type")]
    event_type: &'a str,
    count: u32,
    source: EventSource<'a>,
}

/// Build a unique Event object name for `pod_name`.
///
/// Real Kubernetes event recorders name events `<involvedObjectName>.<hex-suffix>`.
/// Upstream's e2e predicate (`scheduleFailureEvent`/`scheduleSuccessEvent` in
/// `test/e2e/scheduling/events.go`) matches on `strings.HasPrefix(e.Name, podName)`,
/// so the name MUST start with `pod_name` — any other shape makes the event
/// invisible to that check even though it was created correctly.
///
/// `nanos` is passed in (rather than read from `SystemTime::now()` here) so the
/// naming logic itself can be unit-tested without a clock dependency.
pub fn scheduling_event_name(pod_name: &str, nanos: u128) -> String {
    format!("{pod_name}.{nanos:x}")
}

/// Build the JSON payload for a Kubernetes Event recording a scheduling outcome
/// (bind success or failure) for a pod.
///
/// Pure function so the payload shape can be verified in tests without a network.
/// Uses typed structs so field renames are compile errors, not silent bugs —
/// mirrors `binding_payload`.
pub fn scheduling_event_payload(
    namespace: &str,
    pod_name: &str,
    event_name: &str,
    reason: &str,
    message: &str,
    event_type: &str,
) -> Value {
    let event = SchedulingEvent {
        api_version: "v1",
        kind: "Event",
        metadata: EventMeta {
            name: event_name,
            namespace,
        },
        involved_object: EventInvolvedObject {
            api_version: "v1",
            kind: "Pod",
            namespace,
            name: pod_name,
        },
        reason,
        message,
        event_type,
        count: 1,
        source: EventSource {
            component: "u7s-scheduler",
        },
    };
    serde_json::to_value(event).expect("SchedulingEvent is always serializable")
}

/// Build the POST path for Events in a given namespace.
///
/// Pure function extracted so callers can test path construction without
/// network access — mirrors `binding_path`.
pub fn events_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/events")
}

/// Post a scheduling-outcome Event (`reason` "Scheduled" or "FailedScheduling")
/// for `pod_name` to the API server.
///
/// Without this, `kubectl describe pod` never shows a scheduling event, and any
/// client watching Events for a scheduling decision (e.g. the SchedulerPredicates
/// e2e suite's `observeEventAfterAction`) times out waiting for one that was never
/// created — the scheduler made the right bind/reject decision but nobody outside
/// process memory ever heard about it.
pub async fn emit_scheduling_event(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    reason: &str,
    message: &str,
    event_type: &str,
) -> anyhow::Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let event_name = scheduling_event_name(pod_name, nanos);
    let payload = scheduling_event_payload(
        namespace,
        pod_name,
        &event_name,
        reason,
        message,
        event_type,
    );
    let path = events_path(namespace);
    let (status, body) = http_post_json(connector, server, &path, &payload).await?;
    if !status.is_success() {
        bail!("POST event failed with HTTP {status}: {body}");
    }
    Ok(())
}

/// The `DisruptionTarget` condition reason upstream's real kube-scheduler
/// stamps on a preemption victim before deleting it — matches
/// `v1.PodReasonPreemptionByScheduler` (`pkg/scheduler/framework/preemption/executor.go`).
const PREEMPTION_BY_SCHEDULER_REASON: &str = "PreemptionByScheduler";

/// Build the status-conditions PATCH that marks a preemption victim with the
/// `DisruptionTarget` condition, mirroring upstream kube-scheduler's
/// `Executor.PreemptPod`: it patches this condition onto the victim BEFORE
/// deleting it, so a client re-fetching the pod mid-termination (as the
/// `validates pod disruption condition is added to the preempted pod`
/// conformance test does) sees WHY it is being evicted, not just that it is
/// disappearing. `VerifyPodHasConditionWithType`
/// (test/e2e/framework/pod/resource.go) only checks the condition's `type`,
/// but a made-up reason would misrepresent to `kubectl describe pod` who
/// evicted the pod and why.
pub fn disruption_target_patch(pending_pod_name: &str) -> Value {
    serde_json::json!({
        "status": {
            "conditions": [{
                "type": "DisruptionTarget",
                "status": "True",
                "reason": PREEMPTION_BY_SCHEDULER_REASON,
                "message": format!(
                    "u7s-scheduler: preempting to accommodate higher priority pod {pending_pod_name}"
                ),
            }]
        }
    })
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

    // should_retry_without_preempting tests — before PickNodeError existed, a
    // transient GET /api/v1/nodes failure and a genuine full cluster produced
    // the same untyped Err, so main.rs treated an apiserver hiccup exactly
    // like "no capacity" and fell through to preemption: it could evict real
    // lower-priority pods, or mark the pod FailedScheduling, over a blip the
    // next watch tick would have retried cleanly.

    #[test]
    fn should_retry_without_preempting_is_false_for_no_capacity() {
        // A genuine NoCapacity means every qualifying node was actually
        // checked and none had room. If this returned true (retry instead of
        // preempt), a higher-priority pod stuck behind lower-priority ones
        // on a truly full cluster would stay Pending forever, since nothing
        // would ever try to preempt for it.
        assert!(
            !should_retry_without_preempting(&PickNodeError::NoCapacity),
            "a real NoCapacity must fall through to preemption, not a bare retry"
        );
    }

    #[test]
    fn should_retry_without_preempting_is_true_for_api_error() {
        // The GET /api/v1/nodes call itself failed — no node was actually
        // checked, so this says nothing about real cluster capacity. If this
        // returned false (the pre-fix behavior), main.rs would preempt real
        // lower-priority pods, or mark this pod FailedScheduling, over a
        // transient apiserver hiccup instead of just retrying next tick.
        let err = PickNodeError::ApiError(anyhow::anyhow!("GET /api/v1/nodes returned 503"));
        assert!(
            should_retry_without_preempting(&err),
            "a transient API error must not trigger preemption or FailedScheduling"
        );
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

    // pods_needing_resync tests — the periodic resync's core decision: which
    // pods from a fresh /api/v1/pods list get a fresh scheduling attempt this
    // tick. A pod that exhausts preemption retries and goes FailedScheduling
    // never produces another watch event by itself (mayor-d2242) — resync is
    // the only thing left that can ever pick it back up, so this decision
    // dropping such a pod, or ignoring in_flight, reintroduces the exact
    // stranding this fixes.

    #[test]
    fn pods_needing_resync_includes_a_still_unscheduled_pod() {
        // Mirrors a pod that lost a scheduling race (e.g. exhausted
        // preemption retries) and is still sitting Pending with no
        // nodeName — the exact shape of the pod stranded by mayor-d2242. If
        // this stopped returning such a pod, the periodic resync would never
        // re-attempt it and the stranding bug would be back.
        let items = vec![json!({
            "metadata": { "name": "stranded-pod", "namespace": "kube-system" },
            "spec": { "nodeName": "" }
        })];
        let in_flight = std::collections::HashSet::new();
        let events = pods_needing_resync(&items, &in_flight);
        assert_eq!(
            events.len(),
            1,
            "the unscheduled pod must produce exactly one synthetic event"
        );
        assert_eq!(events[0]["type"], "MODIFIED");
        assert_eq!(events[0]["object"]["metadata"]["name"], "stranded-pod");
    }

    #[test]
    fn pods_needing_resync_excludes_an_already_scheduled_pod() {
        // A pod that already has a nodeName is done. Resync must not keep
        // re-wrapping it as a "needs scheduling" event on every tick, or the
        // scheduler would spam pick_node calls and Scheduled/FailedScheduling
        // events for every bound pod in the cluster every 30s, forever.
        let items = vec![json!({
            "metadata": { "name": "bound-pod", "namespace": "default" },
            "spec": { "nodeName": "node-1" }
        })];
        let in_flight = std::collections::HashSet::new();
        assert!(
            pods_needing_resync(&items, &in_flight).is_empty(),
            "an already-scheduled pod must not be re-submitted for scheduling"
        );
    }

    #[test]
    fn pods_needing_resync_excludes_a_pod_already_in_flight() {
        // The watch may already have a bind task running for this exact pod
        // (e.g. it re-triggered scheduling milliseconds before this resync
        // tick fired). Without this check, resync would spawn a second,
        // concurrent bind_pod call for the same pod, racing the watch's own
        // attempt into a 409 Conflict — the exact double-schedule the
        // in_flight guard exists to prevent.
        let items = vec![json!({
            "metadata": { "name": "stranded-pod", "namespace": "kube-system" },
            "spec": { "nodeName": "" }
        })];
        let mut in_flight = std::collections::HashSet::new();
        in_flight.insert("kube-system/stranded-pod".to_owned());
        assert!(
            pods_needing_resync(&items, &in_flight).is_empty(),
            "a pod already in in_flight must be skipped by resync, not double-scheduled"
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

    #[test]
    fn failed_scheduling_status_patch_sets_pod_scheduled_false() {
        // Without this, a pod that fails every scheduling attempt keeps
        // whatever PodScheduled condition it had at creation forever — the
        // FailedScheduling Event main.rs emits is invisible to anything that
        // polls status.conditions instead of watching Events (some
        // conformance waits do exactly that), so this must actually flip the
        // condition, not just log/emit.
        let patch = failed_scheduling_status_patch("no node fits");
        let cond = &patch["status"]["conditions"][0];
        assert_eq!(cond["type"], "PodScheduled");
        assert_eq!(cond["status"], "False");
        assert_eq!(
            cond["reason"], "Unschedulable",
            "reason must match v1.PodReasonUnschedulable — upstream kube-scheduler \
             stamps this same reason on every failed scheduling cycle"
        );
        assert_eq!(cond["message"], "no node fits");
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

    /// A `status.allocatable` entry beyond the named cpu/memory/ephemeral-
    /// storage/pods fields (e.g. an extended resource added by
    /// `AddExtendedResource`, or hugepages) must be captured into `extended`,
    /// not silently dropped — without this, resource_fits/preemption can
    /// never see that a node has (or lacks) capacity for it.
    #[test]
    fn node_allocatable_captures_extended_resource_keys() {
        let json = json!({
            "pods": "110",
            "cpu": "4",
            "scheduling.k8s.io/foo": "5",
            "nvidia.com/gpu": "2"
        });
        let allocatable: NodeAllocatable =
            serde_json::from_value(json).expect("should deserialize");
        assert_eq!(
            allocatable.pods, "110",
            "named fields must still deserialize normally"
        );
        assert_eq!(
            allocatable.extended.get("scheduling.k8s.io/foo"),
            Some(&"5".to_owned()),
            "an extended-resource key must land in `extended`, keyed by its full name"
        );
        assert_eq!(
            allocatable.extended.get("nvidia.com/gpu"),
            Some(&"2".to_owned()),
            "every unrecognized key must be captured, not just the one the test set up first"
        );
        assert!(
            !allocatable.extended.contains_key("cpu"),
            "a named field (cpu) must not ALSO appear in `extended` — it would double-count"
        );
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
            node_affinity_matches(&labels, "node-1", None),
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
                match_fields: vec![],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
                match_fields: vec![],
            },
        ]);
        assert!(
            !node_affinity_matches(&labels, "node-1", Some(&affinity)),
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
                match_fields: vec![],
            },
            NodeSelectorTerm {
                match_expressions: vec![requirement("diffkey", "In", &["wrong", "value2"])],
                match_fields: vec![],
            },
        ]);
        assert!(
            node_affinity_matches(&labels, "node-1", Some(&affinity)),
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
            match_fields: vec![],
        }]);
        assert!(
            !node_affinity_matches(&labels, "node-1", Some(&affinity)),
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
            match_fields: vec![],
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
            match_fields: vec![],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert_eq!(
            result.unwrap(),
            "worker-0",
            "a node whose labels satisfy the required nodeAffinity term must be selected"
        );
    }

    /// The exact mechanism the DaemonSet controller uses to pin each per-node
    /// pod: a matchFields-only term on metadata.name, with spec.nodeName left
    /// empty for the scheduler to fill in. Before match_fields was modeled on
    /// NodeSelectorTerm, serde silently dropped the field, match_expressions
    /// was always empty, and `.all()` over an empty iterator is vacuously
    /// true — so the pod matched every node and select_node_with_capacity
    /// always returned the first one in list order, landing every DaemonSet
    /// pod on the same node instead of one per node.
    #[test]
    fn select_node_with_capacity_selects_pinned_node_via_match_fields() {
        let node_a = make_node_with_capacity("node-a", &[], "110");
        let node_b = make_node_with_capacity("node-b", &[], "110");
        let list = NodeList {
            items: vec![node_a, node_b],
        };
        let mut pod = empty_pending_pod();
        pod.node_affinity = Some(required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![],
            match_fields: vec![requirement("metadata.name", "In", &["node-b"])],
        }]));
        let counts: std::collections::HashMap<String, NodeUsage> = Default::default();
        let result = select_node_with_capacity(list, &pod, &counts);
        assert_eq!(
            result.unwrap(),
            "node-b",
            "a matchFields term pinning metadata.name to node-b must select node-b \
             even though it is listed after node-a — selecting node-a here means \
             matchFields was silently dropped and every node vacuously matched"
        );
    }

    /// A term with BOTH matchExpressions and matchFields must require both —
    /// matchFields is ANDed into the same per-term requirement as
    /// matchExpressions, not treated as an independent alternative that could
    /// let a node through on a name match alone (or vice versa).
    #[test]
    fn node_affinity_matches_requires_both_match_expressions_and_match_fields() {
        let labels: std::collections::HashMap<String, String> =
            [("foo".to_owned(), "bar".to_owned())].into();
        let affinity = required_affinity(vec![NodeSelectorTerm {
            match_expressions: vec![requirement("foo", "In", &["bar"])],
            match_fields: vec![requirement("metadata.name", "In", &["node-b"])],
        }]);
        assert!(
            !node_affinity_matches(&labels, "node-a", Some(&affinity)),
            "a node matching the label but not the pinned name must still fail \
             the term — matchExpressions and matchFields are ANDed, not ORed"
        );
        assert!(
            node_affinity_matches(&labels, "node-b", Some(&affinity)),
            "a node matching both the label and the pinned name must satisfy the term"
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

    /// A watch ADDED event for a pod bound (`spec.nodeName` set) to `node`,
    /// at `phase`, requesting `cpu` (a quantity string, or "" for none) —
    /// the shape `NodeTally::apply_event` consumes.
    fn bound_pod_added_event(name: &str, node: &str, phase: &str, cpu: &str) -> Value {
        let requests = if cpu.is_empty() {
            json!({})
        } else {
            json!({ "cpu": cpu })
        };
        json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": name, "namespace": "default" },
                "spec": {
                    "nodeName": node,
                    "containers": [{ "resources": { "requests": requests } }]
                },
                "status": { "phase": phase }
            }
        })
    }

    /// NodeTally counts pods correctly, excluding Succeeded and Failed.
    ///
    /// This is the NodeResourcesFit predicate: running/pending pods consume a slot;
    /// completed pods do not.  Reverting to count all pods would over-count and
    /// block scheduling when completed pods have not yet been GC'd.
    #[test]
    fn node_tally_excludes_terminal_phases_from_pod_count() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", ""));
        tally.apply_event(&bound_pod_added_event("b", "worker-0", "Pending", ""));
        tally.apply_event(&bound_pod_added_event("c", "worker-0", "Succeeded", ""));
        tally.apply_event(&bound_pod_added_event("d", "worker-0", "Failed", ""));
        tally.apply_event(&bound_pod_added_event("e", "worker-0", "", "")); // missing phase → not terminal → counts

        let usage = tally.usage_by_node();
        assert_eq!(
            usage["worker-0"].pod_count, 3,
            "Running + Pending + unknown-phase count as consuming a slot; \
             Succeeded and Failed do not (NodeResourcesFit predicate, mayor-bbxr)"
        );
    }

    /// NodeTally also excludes terminal-phase pods' resource requests from the
    /// sum — a completed pod that requested 4 CPUs must not still count
    /// against the node's allocatable cpu, or a saturated-but-idle node would
    /// wrongly reject new pods forever.
    #[test]
    fn node_tally_excludes_terminal_phases_from_resource_sum() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event(
            "running", "worker-0", "Running", "1",
        ));
        tally.apply_event(&bound_pod_added_event("done", "worker-0", "Succeeded", "4"));

        let usage = tally.usage_by_node();
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "a Succeeded pod's cpu request must not count against the node's usage"
        );
    }

    /// NodeTally sums cpu requests across all non-terminated pods on the same
    /// node — the exact input pick_node needs to decide whether a pending
    /// pod's own requests still fit.
    #[test]
    fn node_tally_sums_resource_requests_across_pods_on_the_same_node() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", "500m"));
        tally.apply_event(&bound_pod_added_event("b", "worker-0", "Pending", "500m"));

        let usage = tally.usage_by_node();
        assert_eq!(usage["worker-0"].pod_count, 2);
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "two 500m-cpu pods on the same node must sum to 1000 milli-cpu"
        );
    }

    /// The exact regression this tally exists to fix: a live
    /// per-node GET fan-out could read a just-committed bind's resource
    /// request as stale, undercounting the node's usage and letting the
    /// scheduler bind a second pod onto a node that was already full — the
    /// kubelet then rejected it with OutOfcpu. `assume` (called immediately
    /// after a bind decision, before the bind's HTTP call even completes)
    /// must make that bind visible to the very next capacity check, with no
    /// window where it can be read as stale.
    #[test]
    fn node_tally_assume_reflects_just_bound_pod_before_next_scheduling_decision() {
        let mut tally = NodeTally::default();
        // Mirrors pick_node: the tally is updated the instant a pod's node is
        // decided, not after its HTTP bind call returns.
        tally.assume("default", "filler", "worker-0", 0, requests(5600, 0, 0));

        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "8".to_owned(); // 8000m allocatable
        let list = NodeList { items: vec![node] };

        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 4000; // 5600 (tallied) + 4000 > 8000 allocatable

        let usage = tally.usage_by_node();
        let result = select_node_with_capacity(list, &pod, &usage);

        assert!(
            result.is_err(),
            "a node whose tally already reflects a just-bound 5600m-cpu pod must \
             reject a second 4000m pod on an 8000m-cpu node — reading stale (zero) \
             usage here is exactly the bug that let the scheduler bind onto an \
             already-full node, which the kubelet then OutOfcpu-rejected; got: {:?}",
            result.ok()
        );
    }

    /// The exact race reproduced live against the PreemptionExecutionPath
    /// SchedulerPreemption conformance scenario: a preemption's post-eviction
    /// re-check and a concurrently-scheduled pod (there, a ReplicaSet
    /// controller's replacement for the pod preemption just evicted) run in
    /// different tokio tasks, potentially on different OS threads, and both
    /// end up calling `select_and_reserve_node` for the same just-freed slot.
    ///
    /// Before `pick_node` committed the reservation itself, the fit check
    /// (`pick_node`) and the reservation (`NodeTally::assume`, called
    /// separately by the caller after `pick_node` returned) were two
    /// independent lock acquisitions. Two callers could each acquire the
    /// tally lock for the check, both see the slot as free, and both then
    /// separately commit — the kubelet then rejects whichever container it
    /// admits second, since the node never actually had room for both. This
    /// test spawns real OS threads racing for a slot that fits exactly one of
    /// them; reverting to two separate lock acquisitions reopens the window
    /// for more than one thread to see the slot as free before any of them
    /// reserves it.
    #[test]
    fn select_and_reserve_node_never_double_books_a_single_free_slot() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        const CONTENDERS: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));

        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Room for exactly one 1000m-cpu pod on this node, not two —
                // built fresh per thread rather than shared, since NodeList
                // is not Clone.
                let mut node = make_node_with_capacity("worker-0", &[], "110");
                node.status.allocatable.cpu = "1".to_owned();
                let list = NodeList { items: vec![node] };
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("pod-{i}");
                pod.requests.cpu_milli = 1000;
                std::thread::spawn(move || {
                    // Line every thread up so as many as possible call
                    // select_and_reserve_node at the same instant — this is
                    // what makes a split check/reserve likely to be caught,
                    // not just theoretically possible.
                    barrier.wait();
                    select_and_reserve_node(list, &pod, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} pods racing for a single 1000m-cpu \
             slot must win — splitting the fit check and the reservation \
             across two lock acquisitions lets more than one thread see the \
             slot as free and bind, which the kubelet then rejects; got \
             {ok_count} winners: {results:?}"
        );

        let usage = tally.lock().expect("tally lock poisoned").usage_by_node();
        assert_eq!(
            usage["worker-0"].requests.cpu_milli, 1000,
            "the tally must reflect exactly one reservation after the race \
             settles, not zero (a lost update) or more than one (double-booked)"
        );
    }

    /// The exact race reproduced live against the PreemptionExecutionPath
    /// SchedulerPreemption conformance scenario, one level up from
    /// `select_and_reserve_node_never_double_books_a_single_free_slot`:
    /// several pending pods each independently plan to preempt the SAME two
    /// victims on the SAME node (plausible when several pods are ready to
    /// preempt around the same time — e.g. a controller recreating several
    /// replacement pods at once). Before `find_preemption_plan` reserved the
    /// pending pod itself, the caller evicted the victims and only THEN
    /// re-checked fit — leaving a window where more than one such pod could
    /// see the node as free before any of them committed. Reserving under
    /// the SAME lock acquisition that re-reads current tally state (not the
    /// stale pre-eviction snapshot) means only the first caller to reach
    /// this function can ever win the shared capacity; every other caller's
    /// fresh read already includes the winner's reservation.
    #[test]
    fn verify_and_reserve_preemption_never_double_books_shared_victims() {
        let tally = std::sync::Arc::new(std::sync::Mutex::new(NodeTally::default()));
        {
            let mut guard = tally.lock().expect("tally lock poisoned");
            guard.assume("default", "victim-a", "worker-0", 0, requests(1000, 0, 0));
            guard.assume("default", "victim-b", "worker-0", 0, requests(1000, 0, 0));
        }

        const CONTENDERS: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CONTENDERS));
        let handles: Vec<_> = (0..CONTENDERS)
            .map(|i| {
                let tally = std::sync::Arc::clone(&tally);
                let barrier = std::sync::Arc::clone(&barrier);
                // Capacity for exactly one 2000m-cpu pod once BOTH 1000m
                // victims are gone — never for a victim's slot plus a new
                // pod on top, so at most one contender can ever fit.
                let mut node = make_node_with_capacity("worker-0", &[], "110");
                node.status.allocatable.cpu = "2".to_owned();
                let mut pod = empty_pending_pod();
                pod.pod_name = format!("preemptor-{i}");
                pod.requests.cpu_milli = 2000;
                let plan = PreemptionPlan {
                    node_name: "worker-0".to_owned(),
                    victims: vec!["default/victim-a".to_owned(), "default/victim-b".to_owned()],
                };
                std::thread::spawn(move || {
                    // Line every contender up so as many as possible call
                    // verify_and_reserve_preemption at the same instant.
                    barrier.wait();
                    verify_and_reserve_preemption(&pod, &node, &plan, &tally)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            ok_count, 1,
            "exactly one of {CONTENDERS} pods independently planning to \
             preempt the same two victims must win — checking fit and \
             reserving in two separate lock acquisitions lets more than one \
             thread see the (not-yet-evicted) victims' capacity as enough \
             and reserve, which strands the loser's evicted victims for \
             nothing or double-books the node; got {ok_count} winners: \
             {results:?}"
        );
    }

    /// `remove` must actually free the capacity it removes — used both to
    /// roll back a failed bind's `assume` and to account for a preemption
    /// eviction. If a removal were silently dropped, the tally would
    /// permanently overcount that node and leave pods Pending that could
    /// legitimately fit.
    #[test]
    fn node_tally_remove_frees_capacity_for_the_next_decision() {
        let mut tally = NodeTally::default();
        tally.assume("default", "filler", "worker-0", 0, requests(8000, 0, 0));
        tally.remove("default", "filler");

        let mut node = make_node_with_capacity("worker-0", &[], "110");
        node.status.allocatable.cpu = "8".to_owned();
        let list = NodeList { items: vec![node] };
        let mut pod = empty_pending_pod();
        pod.requests.cpu_milli = 4000;

        let usage = tally.usage_by_node();
        let result = select_node_with_capacity(list, &pod, &usage);
        assert!(
            result.is_ok(),
            "removing the filler pod's reservation must free its 8000m cpu — \
             a leaked reservation would leave this node wrongly looking full forever"
        );
    }

    /// A DELETED watch event must remove the pod from the tally — this is how
    /// a preemption victim's eviction becomes visible cluster-wide (not just
    /// via main.rs's own immediate `remove` call), and how any other actor's
    /// pod deletion is picked up.
    #[test]
    fn node_tally_apply_event_deleted_removes_the_pod() {
        let mut tally = NodeTally::default();
        tally.apply_event(&bound_pod_added_event("a", "worker-0", "Running", "1"));
        assert_eq!(tally.usage_by_node()["worker-0"].pod_count, 1);

        tally.apply_event(&json!({
            "type": "DELETED",
            "object": { "metadata": { "name": "a", "namespace": "default" } }
        }));

        assert!(
            !tally.usage_by_node().contains_key("worker-0"),
            "a DELETED event must remove the pod's tallied usage — otherwise a \
             real pod deletion would leave a phantom reservation that blocks \
             scheduling onto a node that actually has room"
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
            extended: Default::default(),
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
            extended: Default::default(),
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
            !resource_fits(&allocatable, &used, &pending),
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
            !resource_fits(&allocatable, &used, &pending),
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
            resource_fits(&allocatable, &used, &pending),
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
            resource_fits(&allocatable, &used, &pending),
            "an unknown (empty) allocatable dimension must not block scheduling"
        );
    }

    // resource_fits extended-resource tests: before this fix, resource_fits
    // only checked cpu/memory/ephemeral-storage, so a pod requesting an
    // extended resource (e.g. a GPU, or the SchedulerPreemption conformance
    // suite's synthetic `scheduling.k8s.io/foo`) always looked like it
    // requested nothing — NodeResourcesFit could never reject it, and
    // preemption could never see a shortage to act on.

    /// The exact SchedulerPreemption conformance shape: a node advertises 1
    /// unit of a fake extended resource, it is already fully used, and a
    /// pending pod wants 1 more — must be rejected, or the scheduler binds a
    /// pod the kubelet then fails OutOf<resource>.
    #[test]
    fn resource_fits_false_when_extended_resource_would_be_overcommitted() {
        let allocatable = node_allocatable_extended("scheduling.k8s.io/foo", "1");
        let used = extended_request("scheduling.k8s.io/foo", 1000); // already fully committed
        let pending = extended_request("scheduling.k8s.io/foo", 1000); // wants 1 more
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "a pending pod's extended-resource request must be rejected when it \
             would push usage past allocatable — reverting this is the root cause \
             of every SchedulerPreemption conformance failure: the scheduler binds \
             the pod anyway and the kubelet rejects it outright"
        );
    }

    /// Unlike cpu/memory/ephemeral-storage, a node that does not advertise an
    /// extended resource AT ALL must fail-closed, not be treated as
    /// "unknown/unlimited" — the node has none of a resource it never
    /// declared, so a pod requesting it can never be scheduled there.
    #[test]
    fn resource_fits_false_when_node_does_not_advertise_the_extended_resource() {
        let allocatable = NodeAllocatable::default(); // no scheduling.k8s.io/foo entry at all
        let used = ResourceRequests::default();
        let pending = extended_request("scheduling.k8s.io/foo", 1000);
        assert!(
            !resource_fits(&allocatable, &used, &pending),
            "requesting a resource the node never advertised must fail-closed, \
             not be silently ignored like an unset cpu/memory dimension"
        );
    }

    /// The positive-path counterpart: a pod requesting an extended resource
    /// that the node has enough spare capacity for must be accepted.
    #[test]
    fn resource_fits_true_when_extended_resource_fits_within_remaining_capacity() {
        let allocatable = node_allocatable_extended("scheduling.k8s.io/foo", "5");
        let used = extended_request("scheduling.k8s.io/foo", 2000); // 2 of 5 used
        let pending = extended_request("scheduling.k8s.io/foo", 1000); // wants 1 more
        assert!(
            resource_fits(&allocatable, &used, &pending),
            "a request that fits within remaining allocatable extended-resource \
             capacity must be accepted"
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

    /// An extended-resource request key (anything other than cpu/memory/
    /// ephemeral-storage) must be captured into pending.requests.extended — if
    /// dropped, a pod requesting only a GPU or the SchedulerPreemption suite's
    /// synthetic `scheduling.k8s.io/foo` always looks like it requests
    /// nothing, and NodeResourcesFit/preemption can never see it.
    #[test]
    fn needs_scheduling_captures_extended_resource_requests() {
        let event = json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "gpu-pod", "namespace": "default" },
                "spec": {
                    "containers": [
                        { "resources": { "requests": { "scheduling.k8s.io/foo": "2" } } }
                    ]
                }
            }
        });
        let pending = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            pending.requests.extended.get("scheduling.k8s.io/foo"),
            Some(&2000),
            "an extended-resource request must be summed into pending.requests.extended \
             in the same milli-unit convention as cpu/memory"
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
    // NodeTally.pods_on, and select_preemption_victims.
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

    // NodeTally.pods_on tests — the per-node pod listing that drives
    // preemption victim selection. Unlike usage_by_node, this retains
    // identity (to DELETE the victim) and priority (to decide if it's a
    // legal victim).

    /// NodeTally excludes terminal-phase pods from `pods_on` (they are not
    /// occupying a slot, so evicting them would help nobody) and extracts
    /// each pod's key and priority.
    #[test]
    fn node_tally_pods_on_excludes_terminal_phases_and_extracts_priority() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "a", "namespace": "ns1"},
                "spec": {"nodeName": "worker-0", "priority": 100},
                "status": {"phase": "Running"}
            }
        }));
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "b", "namespace": "ns1"},
                "spec": {"nodeName": "worker-0", "priority": 5},
                "status": {"phase": "Succeeded"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods.len(),
            1,
            "a Succeeded pod is not consuming a slot and must never be offered as \
             a preemption victim"
        );
        assert_eq!(pods[0].key, "ns1/a");
        assert_eq!(pods[0].priority, 100);
    }

    /// A pod with no spec.priority must default to 0 via `pods_on` too — the
    /// same default `needs_scheduling` applies, so a pending pod at priority
    /// 1 can still legally preempt it.
    #[test]
    fn node_tally_pods_on_defaults_priority_to_zero_when_absent() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "a", "namespace": "default"},
                "spec": {"nodeName": "worker-0"},
                "status": {"phase": "Running"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods[0].priority, 0,
            "a node-resident pod with no priority set must default to 0"
        );
    }

    /// NodeTally must also capture each pod's own resource requests
    /// (including extended resources) — without this, select_preemption_victims
    /// has no way to know how much capacity evicting a given pod would
    /// actually free, and can never select victims by resource shortage, only
    /// by pod-count.
    #[test]
    fn node_tally_pods_on_captures_resource_requests() {
        let mut tally = NodeTally::default();
        tally.apply_event(&json!({
            "type": "ADDED",
            "object": {
                "metadata": {"name": "victim", "namespace": "default"},
                "spec": {
                    "nodeName": "worker-0",
                    "priority": 1,
                    "containers": [
                        { "resources": { "requests": { "scheduling.k8s.io/foo": "1" } } }
                    ]
                },
                "status": {"phase": "Running"}
            }
        }));

        let pods = tally.pods_on("worker-0");
        assert_eq!(
            pods[0].requests.extended.get("scheduling.k8s.io/foo"),
            Some(&1000),
            "a preemption candidate's extended-resource request must be captured \
             so evicting it is known to free that resource"
        );
    }

    // select_preemption_victims tests — the victim-selection decision at the
    // heart of preemption.

    fn np(key: &str, priority: i32) -> NodePod {
        NodePod {
            key: key.to_owned(),
            priority,
            requests: ResourceRequests::default(),
        }
    }

    /// A NodePod that additionally requests `amount` of extended resource
    /// `name` — for the resource-dimension (not just pod-count) preemption
    /// tests below.
    fn np_extended(key: &str, priority: i32, name: &str, amount: i64) -> NodePod {
        let mut requests = ResourceRequests::default();
        requests.extended.insert(name.to_owned(), amount);
        NodePod {
            key: key.to_owned(),
            priority,
            requests,
        }
    }

    /// A full node's only lower-priority pod must be selected as a victim.
    /// Without this, a higher-priority pod stays Pending forever whenever a
    /// lower-priority pod got scheduled first — priority would be meaningless.
    #[test]
    fn select_preemption_victims_evicts_lower_priority_pod_when_node_is_full() {
        let node_pods = vec![np("default/low", 1)];
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
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
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
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
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            5,
            &NodeAllocatable::default(),
        );
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
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            1,
            &NodeAllocatable::default(),
        );
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
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            2,
            &NodeAllocatable::default(),
        );
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
        let victims = select_preemption_victims(
            100,
            &ResourceRequests::default(),
            &node_pods,
            0,
            &NodeAllocatable::default(),
        );
        assert!(
            victims.is_empty(),
            "unknown capacity (0) must never trigger eviction; got {victims:?}"
        );
    }

    fn node_allocatable_extended(name: &str, capacity: &str) -> NodeAllocatable {
        NodeAllocatable {
            extended: [(name.to_owned(), capacity.to_owned())].into(),
            ..Default::default()
        }
    }

    fn extended_request(name: &str, amount: i64) -> ResourceRequests {
        let mut r = ResourceRequests::default();
        r.extended.insert(name.to_owned(), amount);
        r
    }

    // select_preemption_victims extended-resource tests: the SchedulerPreemption
    // conformance suite exhausts a synthetic extended resource
    // (`scheduling.k8s.io/foo`), never pod-count or cpu/memory. Before this
    // fix, select_preemption_victims only understood pod-count, so a node
    // with 1 pod against a 110-pod cap always looked "not full", and a
    // higher-priority pod blocked purely by an exhausted extended resource
    // could never trigger eviction — it stayed unschedulable forever, and the
    // real kubelet then rejected it outright (OutOf<resource>) once bound.

    /// The exact SchedulerPreemption conformance shape: a node advertises 1
    /// unit of a fake extended resource, a low-priority pod holds it, and a
    /// higher-priority pod wants the same unit. Pod-count capacity is huge
    /// (110) and never binding — only the extended resource is scarce.
    #[test]
    fn select_preemption_victims_evicts_lower_priority_pod_for_extended_resource_shortage() {
        let node_pods = vec![np_extended(
            "default/victim",
            1,
            "scheduling.k8s.io/foo",
            1000,
        )];
        let victims = select_preemption_victims(
            1000,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "1"),
        );
        assert_eq!(
            victims,
            vec!["default/victim".to_owned()],
            "a pending pod blocked purely by an exhausted extended resource must \
             still evict the lower-priority pod holding it — pod-count alone is \
             not the only capacity dimension preemption must recognize"
        );
    }

    /// Live-reproduced regression: on a node short on an extended resource, a
    /// zero-priority pod that holds NONE of that resource (e.g. coredns,
    /// which never requests `scheduling.k8s.io/foo`) must never be evicted
    /// just because its priority happens to be lower than the actual
    /// resource-holding victim's — evicting it frees nothing relevant and
    /// only causes collateral damage. Caught by manually reproducing the
    /// SchedulerPreemption conformance scenario against a live stack: the
    /// first version of this fix evicted kube-system/coredns and
    /// kube-system/konnectivity-agent (priority 0, no `scheduling.k8s.io/foo`
    /// request) instead of the pod actually holding the contended resource.
    #[test]
    fn select_preemption_victims_never_evicts_a_pod_holding_none_of_the_short_resource() {
        let node_pods = vec![
            // Lower priority than the resource-holder, but requests nothing —
            // must be skipped even though it is the "cheapest" by priority.
            np("kube-system/irrelevant-system-pod", 0),
            np_extended("default/victim", 1, "scheduling.k8s.io/foo", 1000),
        ];
        let victims = select_preemption_victims(
            1000,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "1"),
        );
        assert_eq!(
            victims,
            vec!["default/victim".to_owned()],
            "must evict only the pod actually holding the contended resource, \
             never the lower-priority pod that holds none of it; got {victims:?}"
        );
    }

    /// If the extended resource the pending pod wants is not actually
    /// exhausted, no eviction may happen — mirrors
    /// `select_preemption_victims_returns_empty_when_pod_already_fits` for the
    /// extended-resource dimension specifically.
    #[test]
    fn select_preemption_victims_returns_empty_when_extended_resource_already_fits() {
        let node_pods = vec![np_extended("default/low", 1, "scheduling.k8s.io/foo", 1000)];
        let victims = select_preemption_victims(
            100,
            &extended_request("scheduling.k8s.io/foo", 1000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "5"),
        );
        assert!(
            victims.is_empty(),
            "1 of 5 units already used plus a 1-unit request still fits — no \
             pod should be evicted; got {victims:?}"
        );
    }

    /// When a single victim's extended-resource share is not enough, preemption
    /// must keep evicting (lowest priority first) until the deficit is
    /// actually cleared — mirrors the pod-count "minimal but sufficient"
    /// eviction test for the extended-resource dimension.
    #[test]
    fn select_preemption_victims_evicts_multiple_pods_to_clear_extended_resource_deficit() {
        let node_pods = vec![
            np_extended("default/lowest", 1, "scheduling.k8s.io/foo", 1000),
            np_extended("default/mid", 50, "scheduling.k8s.io/foo", 1000),
        ];
        // capacity=2 units, both used (2/2) — pending needs 2 more, so BOTH
        // existing pods must go; evicting only one frees just 1 of the 2 needed.
        let victims = select_preemption_victims(
            100,
            &extended_request("scheduling.k8s.io/foo", 2000),
            &node_pods,
            110,
            &node_allocatable_extended("scheduling.k8s.io/foo", "2"),
        );
        assert_eq!(
            victims,
            vec!["default/lowest".to_owned(), "default/mid".to_owned()],
            "evicting only the lowest-priority pod is not enough to clear a \
             2-unit deficit that needs both pods freed; got {victims:?}"
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

    /// `delete_pod` issues DELETE twice (soft-delete then force-delete) to drive a
    /// victim to gone; the second call races the first's resourceVersion bump
    /// against any concurrent write to the same pod (e.g. the kubelet's routine
    /// status sync while it terminates) and can lose with a 409. That is a benign
    /// "already changing" signal, not a real failure — treating it as a hard
    /// error aborts the entire preemption `?`-chain in main.rs's eviction loop,
    /// leaving the higher-priority preemptor pod stuck Pending until a passive
    /// watch reconnect minutes later, well past conformance test timeouts.
    #[test]
    fn check_delete_response_ok_on_409_conflict() {
        assert!(
            check_delete_response(409).is_ok(),
            "409 from delete_pod's own double-DELETE race must be tolerated, or a single \
             benign conflict aborts the whole preemption cycle and strands the preemptor"
        );
    }

    /// A genuine failure (e.g. 500, or 403 if RBAC forbids the scheduler from
    /// deleting pods) must surface as Err so the caller aborts rather than binding
    /// the preemptor onto a node that never actually freed capacity.
    #[test]
    fn check_delete_response_err_on_failure() {
        assert!(check_delete_response(500).is_err());
        assert!(check_delete_response(403).is_err());
    }

    // disruption_target_patch tests: upstream kube-scheduler stamps a
    // DisruptionTarget condition on a preemption victim before
    // deleting it. Before this fix u7s's preemption path deleted victims with
    // no condition at all, so `validates pod disruption condition is added to
    // the preempted pod` failed even when eviction itself worked correctly —
    // the eviction mechanism and the status bookkeeping are separate gaps.

    /// The condition type/status/reason must match what
    /// `VerifyPodHasConditionWithType` (test/e2e/framework/pod/resource.go)
    /// and `kubectl describe pod` expect from a real scheduler preemption:
    /// `DisruptionTarget`/`True`/`PreemptionByScheduler`.
    #[test]
    fn disruption_target_patch_sets_condition_type_status_and_reason() {
        let patch = disruption_target_patch("preemptor-pod");
        let condition = &patch["status"]["conditions"][0];
        assert_eq!(condition["type"], "DisruptionTarget");
        assert_eq!(condition["status"], "True");
        assert_eq!(
            condition["reason"], "PreemptionByScheduler",
            "the reason must match upstream's v1.PodReasonPreemptionByScheduler, \
             not a made-up string — it tells `kubectl describe pod` who evicted \
             the pod and why"
        );
    }

    /// The message must name the preemptor pod so a user reading `kubectl
    /// describe pod` on the victim can tell which pod displaced it.
    #[test]
    fn disruption_target_patch_message_names_the_preemptor() {
        let patch = disruption_target_patch("high-priority-pod");
        let message = patch["status"]["conditions"][0]["message"]
            .as_str()
            .expect("message must be a string");
        assert!(
            message.contains("high-priority-pod"),
            "the message must reference the preemptor pod by name; got {message:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // Scheduling Events (mayor-lafgk): scheduling_event_name/scheduling_event_payload
    // /events_path. Before this fix the scheduler never created an Event object on
    // bind success or failure, so `kubectl describe pod` showed nothing and the
    // SchedulerPredicates e2e suite's observeEventAfterAction watch timed out
    // waiting for a FailedScheduling/Scheduled event that was never posted.
    // ---------------------------------------------------------------------------

    /// scheduling_event_name must start with pod_name — upstream's
    /// scheduleFailureEvent/scheduleSuccessEvent predicates match on
    /// `strings.HasPrefix(e.Name, podName)`. A name that doesn't start with the
    /// pod name would make a correctly-created event invisible to that check.
    #[test]
    fn scheduling_event_name_starts_with_pod_name() {
        let name = scheduling_event_name("my-pod", 0x1234abcd);
        assert!(
            name.starts_with("my-pod"),
            "event name must start with pod_name for upstream's HasPrefix match; got {name}"
        );
    }

    /// Two events for the same pod at different times must get distinct names —
    /// otherwise the second POST would collide with (and be rejected as a
    /// duplicate of) the first.
    #[test]
    fn scheduling_event_name_is_unique_per_nanos() {
        let a = scheduling_event_name("my-pod", 1);
        let b = scheduling_event_name("my-pod", 2);
        assert_ne!(
            a, b,
            "distinct timestamps must produce distinct event names to avoid create collisions"
        );
    }

    /// scheduling_event_payload must set reason/type/message exactly as given —
    /// this is what upstream's predicate matches on (e.Type == "Warning" &&
    /// e.Reason == "FailedScheduling" for the failure case).
    #[test]
    fn scheduling_event_payload_sets_failure_fields() {
        let payload = scheduling_event_payload(
            "sched-pred",
            "unschedulable-pod",
            "unschedulable-pod.abc123",
            "FailedScheduling",
            "0/1 nodes are available: node(s) didn't match Pod's node affinity/selector.",
            "Warning",
        );
        assert_eq!(payload["kind"], "Event");
        assert_eq!(payload["apiVersion"], "v1");
        assert_eq!(payload["reason"], "FailedScheduling");
        assert_eq!(payload["type"], "Warning");
        assert_eq!(payload["metadata"]["name"], "unschedulable-pod.abc123");
        assert_eq!(payload["metadata"]["namespace"], "sched-pred");
    }

    /// scheduling_event_payload's involvedObject must reference the pod by name,
    /// namespace, and kind "Pod" — without this, the event exists but cannot be
    /// correlated back to the pod it reports on (`kubectl describe pod` filters
    /// events by involvedObject).
    #[test]
    fn scheduling_event_payload_involved_object_references_pod() {
        let payload = scheduling_event_payload(
            "staging",
            "web-pod",
            "web-pod.deadbeef",
            "Scheduled",
            "Successfully assigned staging/web-pod to worker-2",
            "Normal",
        );
        assert_eq!(payload["involvedObject"]["kind"], "Pod");
        assert_eq!(payload["involvedObject"]["name"], "web-pod");
        assert_eq!(payload["involvedObject"]["namespace"], "staging");
    }

    /// scheduling_event_payload's message must be preserved verbatim — upstream's
    /// scheduleSuccessEvent predicate checks
    /// `strings.Contains(e.Message, "Successfully assigned ns/pod to node")`.
    #[test]
    fn scheduling_event_payload_preserves_message() {
        let payload = scheduling_event_payload(
            "default",
            "my-pod",
            "my-pod.123",
            "Scheduled",
            "Successfully assigned default/my-pod to node-1",
            "Normal",
        );
        assert_eq!(
            payload["message"], "Successfully assigned default/my-pod to node-1",
            "message must be preserved verbatim for the success-event Contains() check"
        );
    }

    #[test]
    fn events_path_produces_correct_api_path() {
        let path = events_path("kube-system");
        assert_eq!(path, "/api/v1/namespaces/kube-system/events");
    }
}
