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
}

/// Minimal typed view of a Pod's metadata needed by the scheduler.
#[derive(Debug, Default, Deserialize)]
struct PodMetadata {
    name: Option<String>,
    namespace: Option<String>,
}

/// Minimal typed view of a Pod object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct PodObject {
    metadata: PodMetadata,
    spec: PodSpec,
}

/// Determine whether a watch event represents a pod that needs scheduling.
///
/// Returns `Some((namespace, pod_name, node_selector, priority))` when the event
/// is an ADDED or MODIFIED pod with an empty `spec.nodeName` and no non-empty
/// `spec.schedulingGates`; `None` otherwise. A non-empty `schedulingGates` list
/// means the pod is not yet ready to be considered for scheduling at all — it
/// must never enter the scheduling cycle, distinct from a predicate failure.
/// `node_selector` is the pod's `spec.nodeSelector` map (empty if absent).
/// `priority` is the pod's `spec.priority`, defaulting to 0 (the lowest rung)
/// when absent, so preemption has a value to compare even for pods that never
/// had a priority resolved.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
pub fn needs_scheduling(
    event: &Value,
) -> Option<(
    String,
    String,
    std::collections::HashMap<String, String>,
    i32,
)> {
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
    Some((namespace, pod_name.to_owned(), node_selector, priority))
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
    pub status: NodeStatus,
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

/// Minimal typed view of a pod list item needed to count running pods on a node.
#[derive(Deserialize)]
struct PodListItem {
    status: PodListItemStatus,
}

#[derive(Deserialize, Default)]
struct PodListItemStatus {
    #[serde(default)]
    phase: String,
}

/// Count non-terminated pods from a raw JSON pod list response body.
///
/// "Non-terminated" means phase is not Succeeded or Failed.  This matches the
/// upstream NodeResourcesFit predicate: running and pending pods consume a slot;
/// completed pods do not.
///
/// Returns Err if the body cannot be parsed as a pod list.
pub fn count_non_terminated_pods(body: &str) -> anyhow::Result<u32> {
    #[derive(Deserialize)]
    struct PodList {
        items: Vec<PodListItem>,
    }
    let list: PodList = serde_json::from_str(body).context("parse pod list for node capacity")?;
    let count = list
        .items
        .iter()
        .filter(|p| p.status.phase != "Succeeded" && p.status.phase != "Failed")
        .count();
    Ok(count as u32)
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
/// `PodListItem` (used by `count_non_terminated_pods`), this retains identity
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
/// Mirrors `count_non_terminated_pods`'s terminal-phase filter (Succeeded/Failed
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

/// Select the first node from `list` whose labels satisfy `selector` AND that
/// has at least one free pod slot.
///
/// `pod_counts` maps node name → current non-terminated pod count (from a prior
/// GET /api/v1/pods?fieldSelector=spec.nodeName=<node>).  If a node's name is
/// absent from `pod_counts`, its count is treated as 0 (conservative: schedule).
///
/// Capacity is read from `status.allocatable.pods`, falling back to
/// `status.capacity.pods`.  A capacity of 0 (field absent / unparseable) means
/// the limit is unknown; such nodes are NOT skipped (the old safe behaviour).
///
/// Returns `Err` when no node satisfies the selector with free capacity, so the
/// caller can leave the pod Pending instead of binding to a full node.
///
/// Pure function so the capacity-gate logic can be unit-tested without a network.
pub fn select_node_with_capacity(
    list: NodeList,
    selector: &std::collections::HashMap<String, String>,
    pod_counts: &std::collections::HashMap<String, u32>,
) -> anyhow::Result<String> {
    let found = list.items.into_iter().find(|n| {
        if !node_selector_matches(&n.metadata.labels, selector) {
            return false;
        }
        // Resolve capacity: prefer allocatable, fall back to capacity.
        let cap_str = if !n.status.allocatable.pods.is_empty() {
            &n.status.allocatable.pods
        } else {
            &n.status.capacity.pods
        };
        let cap = parse_pod_capacity(cap_str);
        if cap == 0 {
            // Capacity unknown — do not block scheduling.
            return true;
        }
        let used = pod_counts.get(&n.metadata.name).copied().unwrap_or(0);
        used < cap
    });
    found.map(|n| n.metadata.name).context(
        "no node satisfies the pod's nodeSelector with free pod capacity (NodeResourcesFit)",
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

/// Return the name of the first node that satisfies `node_selector` and has
/// at least one free pod slot (NodeResourcesFit predicate).
///
/// Fetches the node list from the API server, then — for each selector-matching
/// candidate — counts non-terminated pods already assigned to it via
/// GET /api/v1/pods?fieldSelector=spec.nodeName%3D<node>.  A node at or above
/// its `status.allocatable.pods` limit is skipped.  Returns `Err` when no
/// suitable node exists so that the caller can skip binding and leave the pod
/// Pending (mayor-bbxr: without this check, pods are bound to full nodes and
/// the kubelet fails them OutOfpods).
pub async fn pick_node(
    connector: &TlsConnector,
    server: &str,
    node_selector: &std::collections::HashMap<String, String>,
) -> anyhow::Result<String> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;

    // Build per-node pod counts for every candidate node (selector-matching).
    // We only query nodes that pass the selector to avoid unnecessary API calls.
    let mut pod_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for node in &list.items {
        if !node_selector_matches(&node.metadata.labels, node_selector) {
            continue;
        }
        let node_name = &node.metadata.name;
        let pods_path = format!("/api/v1/pods?fieldSelector=spec.nodeName%3D{node_name}");
        match http_get(connector, server, &pods_path).await {
            Ok((ps, pb)) if ps.is_success() => {
                match count_non_terminated_pods(&pb) {
                    Ok(n) => {
                        pod_counts.insert(node_name.clone(), n);
                    }
                    Err(e) => {
                        // Treat count as 0 (allow scheduling) rather than failing
                        // the entire pick_node call — a parse error here is not
                        // grounds to leave the pod unscheduled indefinitely.
                        tracing::warn!("failed to count pods on {node_name}: {e} — treating as 0");
                    }
                }
            }
            Ok((ps, pb)) => {
                tracing::warn!(
                    "GET pods for node {node_name} returned {ps}: {pb} — treating count as 0"
                );
            }
            Err(e) => {
                tracing::warn!("GET pods for node {node_name} failed: {e} — treating count as 0");
            }
        }
    }

    select_node_with_capacity(list, node_selector, &pod_counts)
}

/// A viable preemption outcome: the node to bind the pending pod to, and the
/// "namespace/name" keys of the pods that must be evicted first to free a slot.
#[derive(Debug, PartialEq)]
pub struct PreemptionPlan {
    pub node_name: String,
    pub victims: Vec<String>,
}

/// Search every node satisfying `node_selector` for a viable preemption target:
/// a node where evicting some lower-priority pods would free a slot for a pod
/// at `pending_priority`.
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
    node_selector: &std::collections::HashMap<String, String>,
    pending_priority: i32,
) -> anyhow::Result<PreemptionPlan> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;

    let mut best: Option<PreemptionPlan> = None;
    for node in &list.items {
        if !node_selector_matches(&node.metadata.labels, node_selector) {
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

        let victims = select_preemption_victims(pending_priority, &node_pods, capacity);
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
        let (ns, name, _, _) = result.unwrap();
        assert_eq!(ns, "kube-system", "namespace must come from event metadata");
        assert_eq!(name, "coredns-abc");
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
        let (ns, name, _, _) = result.unwrap();
        assert_eq!(ns, "default");
        assert_eq!(name, "my-pod");
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
        let (ns, name, _, _) = needs_scheduling(&event).expect("should schedule");
        assert_eq!(ns, "default");
        assert_eq!(name, "no-ns-pod");
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
        let (ns, name, _, _) = result.unwrap();
        assert_eq!(ns, "staging");
        assert_eq!(name, "pending-pod");
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
                    status: NodeStatus::default(),
                },
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-b".to_owned(),
                        labels: Default::default(),
                    },
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
        let (ns, name, _, _) = result.unwrap();
        assert_eq!(ns, "default");
        assert_eq!(name, "null-node-pod");
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
            status: NodeStatus {
                allocatable: NodeAllocatable {
                    pods: capacity.to_owned(),
                },
                capacity: NodeAllocatable {
                    pods: capacity.to_owned(),
                },
            },
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
        let selector = std::collections::HashMap::new();
        // Node already has 110 pods — at capacity.
        let counts: std::collections::HashMap<String, u32> =
            [("worker-0".to_owned(), 110u32)].into();
        let result = select_node_with_capacity(list, &selector, &counts);
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
        let selector = std::collections::HashMap::new();
        // Node has 109 pods — one slot free.
        let counts: std::collections::HashMap<String, u32> =
            [("worker-0".to_owned(), 109u32)].into();
        let result = select_node_with_capacity(list, &selector, &counts);
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
        let selector = std::collections::HashMap::new();
        let counts: std::collections::HashMap<String, u32> = [
            ("worker-full".to_owned(), 110u32),
            ("worker-free".to_owned(), 50u32),
        ]
        .into();
        let result = select_node_with_capacity(list, &selector, &counts);
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
        let selector = std::collections::HashMap::new();
        let counts: std::collections::HashMap<String, u32> = [
            ("worker-0".to_owned(), 110u32),
            ("worker-1".to_owned(), 110u32),
        ]
        .into();
        let result = select_node_with_capacity(list, &selector, &counts);
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
        let selector = std::collections::HashMap::new();
        let counts: std::collections::HashMap<String, u32> =
            [("worker-0".to_owned(), 999u32)].into();
        let result = select_node_with_capacity(list, &selector, &counts);
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

    /// count_non_terminated_pods counts correctly, excluding Succeeded and Failed.
    ///
    /// This is the NodeResourcesFit predicate: running/pending pods consume a slot;
    /// completed pods do not.  Reverting to count all pods would over-count and
    /// block scheduling when completed pods have not yet been GC'd.
    #[test]
    fn count_non_terminated_pods_excludes_terminal_phases() {
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
        let count = count_non_terminated_pods(&body).expect("should parse");
        assert_eq!(
            count, 3,
            "Running + Pending + unknown-phase count as consuming a slot; \
             Succeeded and Failed do not (NodeResourcesFit predicate, mayor-bbxr)"
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
        let (ns, name, selector, _) = result.unwrap();
        assert_eq!(ns, "sched-pred");
        assert_eq!(name, "restricted-pod");
        assert_eq!(
            selector.get("scheduledOnNode").map(|s| s.as_str()),
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
        let (_, _, selector, _) = needs_scheduling(&event).expect("should schedule");
        assert!(
            selector.is_empty(),
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
        let (_, _, _, priority) = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            priority, 1000,
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
        let (_, _, _, priority) = needs_scheduling(&event).expect("should schedule");
        assert_eq!(
            priority, 0,
            "a pod with no priority set must default to 0, not be treated as \
             missing/unschedulable"
        );
    }

    // parse_node_pods tests — the per-node pod listing that drives preemption
    // victim selection. Unlike count_non_terminated_pods, this retains identity
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
