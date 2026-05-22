/// u7s-scheduler library — all non-main scheduling logic.
///
/// Extracted from main.rs so that pure functions can be unit-tested without
/// standing up an API server.
use anyhow::{bail, Context};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// HTTP helpers — one shot over a fresh TLS connection per request.
// This is a scaffold; connection reuse is a later optimization.
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
    let body = send_request(connector, base, Method::GET, path, None).await?;
    Ok(body)
}

pub async fn http_post_json(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let body_str = serde_json::to_string(payload)?;
    send_request(connector, base, Method::POST, path, Some(body_str)).await
}

pub async fn send_request(
    connector: &TlsConnector,
    base: &str,
    method: Method,
    path: &str,
    body: Option<String>,
) -> anyhow::Result<(StatusCode, String)> {
    let (host, _port, addr) = parse_uri_parts(base, path)?;

    let stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    let server_name = host.clone().try_into().context("invalid DNS name")?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake")?;

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake")?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("HTTP connection error: {e}");
        }
    });

    let body_bytes = match &body {
        Some(s) => bytes::Bytes::from(s.clone()),
        None => bytes::Bytes::new(),
    };

    let mut req_builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", &host)
        .header("Accept", "application/json");

    if body.is_some() {
        req_builder = req_builder
            .header("Content-Type", "application/json")
            .header("Content-Length", body_bytes.len().to_string());
    }

    let req = req_builder
        .body(http_body_util::Full::new(body_bytes))
        .context("build request")?;

    let resp: Response<Incoming> = sender.send_request(req).await.context("send request")?;
    let status = resp.status();

    use http_body_util::BodyExt;
    let bytes = resp
        .into_body()
        .collect()
        .await
        .context("read body")?
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();

    Ok((status, text))
}

// ---------------------------------------------------------------------------
// Watch streaming — reads newline-delimited JSON from a watch endpoint
// ---------------------------------------------------------------------------

/// Drain all complete newline-terminated JSON lines from `buf`, calling
/// `handler` for each successfully parsed value.
///
/// Lines that fail to parse are logged and skipped. Incomplete lines (no
/// trailing `\n`) are left in `buf` for the next call.
///
/// Pure function extracted so the line-parsing logic can be unit-tested
/// without a network connection.
pub fn drain_watch_buffer(buf: &mut String, handler: &mut impl FnMut(Value)) {
    while let Some(nl) = buf.find('\n') {
        let line = buf[..nl].trim().to_owned();
        *buf = buf[nl + 1..].to_owned();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => handler(v),
            Err(e) => warn!("failed to parse watch event: {e}: {line}"),
        }
    }
}

pub async fn stream_watch_events(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    mut handler: impl FnMut(Value),
) -> anyhow::Result<()> {
    let (host, _port, addr) = parse_uri_parts(base, path)?;

    let stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP connect to {addr}"))?;
    let server_name = host.clone().try_into().context("invalid DNS name")?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake")?;

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake")?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("watch connection error: {e}");
        }
    });

    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("Host", &host)
        .header("Accept", "application/json")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .context("build watch request")?;

    let resp: Response<Incoming> = sender
        .send_request(req)
        .await
        .context("send watch request")?;
    if !resp.status().is_success() {
        bail!("watch returned HTTP {}", resp.status());
    }

    // Stream the body as a series of newline-delimited JSON objects.
    // We convert the Incoming body into an async reader via a channel.
    use http_body_util::BodyExt;
    let mut body = resp.into_body();

    let mut buf = String::new();
    loop {
        match body.frame().await {
            None => break, // stream ended
            Some(Err(e)) => {
                warn!("watch stream error: {e}");
                break;
            }
            Some(Ok(frame)) => {
                // frame.into_data() returns Result<D, Frame<D>>; we need an explicit type.
                let frame: hyper::body::Frame<bytes::Bytes> = frame;
                if let Ok(data) = frame.into_data() {
                    buf.push_str(&String::from_utf8_lossy(&data));
                    drain_watch_buffer(&mut buf, &mut handler);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scheduling logic
// ---------------------------------------------------------------------------

/// Local typed view of the fields in a Pod's `spec` that the scheduler reads.
/// Parsing at the boundary means a typo in `nodeName` is a compile error,
/// not a silent None that leaves pods unscheduled forever.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
}

/// Determine whether a watch event represents a pod that needs scheduling.
///
/// Returns `Some((namespace, pod_name))` when the event is an ADDED or
/// MODIFIED pod with an empty `spec.nodeName`; `None` otherwise.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
pub fn needs_scheduling(event: &Value) -> Option<(String, String)> {
    let event_type = event["type"].as_str().unwrap_or("");
    if event_type != "ADDED" && event_type != "MODIFIED" {
        return None;
    }
    let pod_name = event["object"]["metadata"]["name"].as_str().unwrap_or("");
    if pod_name.is_empty() {
        return None;
    }
    let spec: PodSpec = serde_json::from_value(event["object"]["spec"].clone()).unwrap_or_default();
    let already_scheduled = spec.node_name.as_deref().is_some_and(|n| !n.is_empty());
    if already_scheduled {
        return None;
    }
    let namespace = event["object"]["metadata"]["namespace"]
        .as_str()
        .unwrap_or("default")
        .to_owned();
    Some((namespace, pod_name.to_owned()))
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
pub fn binding_payload(namespace: &str, pod_name: &str, node_name: &str) -> Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Binding",
        "metadata": { "name": pod_name, "namespace": namespace },
        "target": { "apiVersion": "v1", "kind": "Node", "name": node_name }
    })
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
    if status.is_success() {
        info!("bound pod {namespace}/{pod_name} → node {node_name}");
    } else {
        warn!("binding {namespace}/{pod_name} failed ({status}): {body}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
