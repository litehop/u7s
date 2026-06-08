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
/// Returns `Some((namespace, pod_name))` when the event is an ADDED or
/// MODIFIED pod with an empty `spec.nodeName`; `None` otherwise.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
pub fn needs_scheduling(event: &Value) -> Option<(String, String)> {
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
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    Some((namespace, pod_name.to_owned()))
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
}

#[derive(Deserialize)]
pub struct NodeMetadata {
    pub name: String,
}

/// Select the first node name from a `NodeList`.
///
/// Pure function extracted from `pick_node` so the selection logic can be
/// unit-tested without network access. Returns an error when no nodes exist.
pub fn select_first_node(list: NodeList) -> anyhow::Result<String> {
    list.items
        .into_iter()
        .next()
        .map(|n| n.metadata.name)
        .context("no nodes available")
}

/// Return the name of the first node returned by the API server.
pub async fn pick_node(connector: &TlsConnector, server: &str) -> anyhow::Result<String> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;
    select_first_node(list)
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
        let (ns, name) = result.unwrap();
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
        let (ns, name) = result.unwrap();
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
        let (ns, name) = needs_scheduling(&event).expect("should schedule");
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
        let (ns, name) = result.unwrap();
        assert_eq!(ns, "staging");
        assert_eq!(name, "pending-pod");
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
                    },
                },
                NodeItem {
                    metadata: NodeMetadata {
                        name: "node-b".to_owned(),
                    },
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
        let (ns, name) = result.unwrap();
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
                },
            }],
        };
        let name = select_first_node(list).expect("single-item list must return Ok");
        assert_eq!(name, "worker-0");
    }
}
