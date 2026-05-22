/// Pod subresource proxy handlers: /log, /exec, /attach, /portforward
///
/// /log: looks up the pod → node, then proxies GET to the kubelet log endpoint,
///        streaming the response body back to the client.
///
/// /exec, /attach, /portforward: return 501 Not Implemented. These require a
///        SPDY 3.1 or WebSocket upgrade that axum does not natively support.
///        Returning 501 is more informative than 404 for kubectl users.
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use u7s_store::Store as _;

use crate::{
    keys::{cluster_object_key, object_key},
    state::AppState,
    status::Status,
};

// ---------------------------------------------------------------------------
// /log — query parameters forwarded to the kubelet
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogQuery {
    pub container: Option<String>,
    pub follow: Option<bool>,
    #[serde(rename = "tailLines")]
    pub tail_lines: Option<i64>,
    #[serde(rename = "sinceSeconds")]
    pub since_seconds: Option<i64>,
    pub timestamps: Option<bool>,
    pub previous: Option<bool>,
    #[serde(rename = "limitBytes")]
    pub limit_bytes: Option<i64>,
}

// ---------------------------------------------------------------------------
// Pure helper: resolve node IP from Node JSON
// ---------------------------------------------------------------------------

/// Extract the best address for the kubelet from a Node object.
///
/// Prefers InternalIP (routable within the cluster), falls back to Hostname.
/// Returns None if the node has no usable address — this would mean the node
/// object is incomplete, which is a bug in the scheduler/kubelet registration.
pub fn node_address(node: &serde_json::Value) -> Option<String> {
    let addresses = node["status"]["addresses"].as_array()?;
    // Prefer InternalIP — it's guaranteed routable inside the cluster.
    if let Some(addr) = addresses
        .iter()
        .find(|a| a["type"].as_str() == Some("InternalIP"))
    {
        return addr["address"].as_str().map(str::to_owned);
    }
    // Fall back to Hostname if InternalIP is absent.
    addresses
        .iter()
        .find(|a| a["type"].as_str() == Some("Hostname"))
        .and_then(|a| a["address"].as_str())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// /log handler
// ---------------------------------------------------------------------------

pub async fn pod_log(
    State(state): State<AppState>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<LogQuery>,
) -> Result<Response, crate::status::StatusError> {
    // 1. Look up the pod.
    let pod_key = object_key("pods", &raw_ns, &pod_name);
    let stored = state
        .store
        .get(&pod_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&pod_name, "Pod"))?;

    let pod: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored pod: {e}")))?;

    // 2. Extract spec.nodeName — empty means pod is not yet scheduled.
    let node_name = pod["spec"]["nodeName"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Status::bad_request(format!(
                "pod \"{pod_name}\" is not yet scheduled (spec.nodeName is empty)"
            ))
        })?;

    // 3. Look up the Node to get its address.
    let node_key = cluster_object_key("nodes", node_name);
    let node_stored = state
        .store
        .get(&node_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(node_name, "Node"))?;

    let node: serde_json::Value = serde_json::from_slice(&node_stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored node: {e}")))?;

    let node_ip = node_address(&node).ok_or_else(|| {
        Status::internal(format!(
            "node \"{node_name}\" has no usable address in status.addresses"
        ))
    })?;

    // 4. Determine which container to tail. Default to first container if unspecified.
    let container = match query.container.as_deref() {
        Some(c) if !c.is_empty() => c.to_owned(),
        _ => {
            // Use first container name as default — same behaviour as kubectl.
            pod["spec"]["containers"][0]["name"]
                .as_str()
                .unwrap_or("default")
                .to_owned()
        }
    };

    // 5. Build the kubelet URL.
    //    Kubelet log endpoint: https://<node-ip>:10250/containerLogs/<ns>/<pod>/<container>
    let mut kubelet_url =
        format!("https://{node_ip}:10250/containerLogs/{raw_ns}/{pod_name}/{container}");

    // Forward query parameters.
    let mut params: Vec<(&str, String)> = Vec::new();
    if let Some(true) = query.follow {
        params.push(("follow", "true".into()));
    }
    if let Some(n) = query.tail_lines {
        params.push(("tailLines", n.to_string()));
    }
    if let Some(n) = query.since_seconds {
        params.push(("sinceSeconds", n.to_string()));
    }
    if let Some(true) = query.timestamps {
        params.push(("timestamps", "true".into()));
    }
    if let Some(true) = query.previous {
        params.push(("previous", "true".into()));
    }
    if let Some(n) = query.limit_bytes {
        params.push(("limitBytes", n.to_string()));
    }

    if !params.is_empty() {
        let qs: String = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        kubelet_url = format!("{kubelet_url}?{qs}");
    }

    // 6. Proxy via reqwest.
    //    KNOWN GAP (pre-alpha): kubelet uses a self-signed certificate. We accept
    //    invalid certs here. In production this should verify against the cluster CA.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| Status::internal(format!("failed to build HTTP client: {e}")))?;

    let kubelet_resp = client
        .get(&kubelet_url)
        .send()
        .await
        .map_err(|e| Status::internal(format!("kubelet request failed: {e}")))?;

    let kubelet_status = kubelet_resp.status();

    // Stream the kubelet response body back to the client, preserving the status code.
    // Body::from_stream wraps any Stream<Item=Result<Bytes, E>> into an axum Body.
    let body = Body::from_stream(kubelet_resp.bytes_stream());

    Response::builder()
        .status(kubelet_status.as_u16())
        .header(axum::http::header::CONTENT_TYPE, "text/plain")
        .body(body)
        .map_err(|e| Status::internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// 501 stubs
// ---------------------------------------------------------------------------

/// exec requires SPDY 3.1 or WebSocket upgrade — not yet implemented.
/// Returns 501 so kubectl gets a clear error instead of 404.
pub async fn pod_exec(Path((_ns, _name)): Path<(String, String)>) -> impl IntoResponse {
    not_implemented("exec")
}

/// attach requires SPDY 3.1 or WebSocket upgrade — not yet implemented.
/// Returns 501 so kubectl gets a clear error instead of 404.
pub async fn pod_attach(Path((_ns, _name)): Path<(String, String)>) -> impl IntoResponse {
    not_implemented("attach")
}

/// portforward requires SPDY 3.1 or WebSocket upgrade — not yet implemented.
/// Returns 501 so kubectl gets a clear error instead of 404.
pub async fn pod_portforward(Path((_ns, _name)): Path<(String, String)>) -> impl IntoResponse {
    not_implemented("portforward")
}

fn not_implemented(subresource: &str) -> Response {
    let body = serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "message": format!(
            "{subresource} not yet implemented: requires SPDY/WebSocket upgrade"
        ),
        "reason": "NotImplemented",
        "code": 501
    });
    (StatusCode::NOT_IMPLEMENTED, axum::Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower_service::Service as _;
    use u7s_store::SqliteStore;

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    fn make_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}/log", get(pod_log))
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/exec",
                get(pod_exec).post(pod_exec),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/attach",
                get(pod_attach).post(pod_attach),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/portforward",
                get(pod_portforward).post(pod_portforward),
            )
            .with_state(state)
    }

    // -----------------------------------------------------------------------
    // pod_log: 404 when pod does not exist
    // -----------------------------------------------------------------------

    /// /log must return 404 when the pod is not in the store.
    ///
    /// Without this check, the proxy would attempt to contact a kubelet for a
    /// non-existent pod, producing a confusing 500 rather than a clear 404.
    #[tokio::test]
    async fn pod_log_missing_pod_returns_404() {
        let state = make_state();
        let mut router = make_router(state);

        let req = Request::builder()
            .uri("/api/v1/namespaces/default/pods/ghost/log")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/log on a non-existent pod must return 404, not 500 or 200"
        );
    }

    // -----------------------------------------------------------------------
    // pod_log: 400 when pod has no nodeName (not yet scheduled)
    // -----------------------------------------------------------------------

    /// /log must return 400 when the pod exists but spec.nodeName is empty.
    ///
    /// An unscheduled pod has no kubelet to proxy to; returning 400 tells the
    /// caller to wait for scheduling rather than producing a confusing 500.
    #[tokio::test]
    async fn pod_log_unscheduled_pod_returns_400() {
        let state = make_state();

        // Seed a pod with no nodeName (scheduler hasn't bound it yet).
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pending-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
                // no nodeName
            }
        });
        let key = crate::keys::object_key("pods", "default", "pending-pod");
        state
            .store
            .put(&key, bytes::Bytes::from(pod.to_string()), Some(0))
            .await
            .expect("seed pod must not fail");

        let mut router = make_router(state);
        let req = Request::builder()
            .uri("/api/v1/namespaces/default/pods/pending-pod/log")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "/log on an unscheduled pod must return 400 (not 500) — \
             there is no kubelet to proxy to until spec.nodeName is set"
        );
    }

    // -----------------------------------------------------------------------
    // pod_exec: 501 Not Implemented
    // -----------------------------------------------------------------------

    /// /exec must return 501 Not Implemented (not 404).
    ///
    /// kubectl exec fails with a confusing "command not found" error when it
    /// receives 404. A 501 clearly signals that the feature is unimplemented
    /// rather than that the resource does not exist.
    #[tokio::test]
    async fn pod_exec_returns_501() {
        let state = make_state();
        let mut router = make_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/mypod/exec")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_IMPLEMENTED,
            "/exec must return 501 Not Implemented — SPDY upgrade is not yet supported"
        );

        // Response body must include a clear message.
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("not yet implemented"),
            "501 body must explain that exec is not yet implemented"
        );
    }

    // -----------------------------------------------------------------------
    // pod_attach: 501 Not Implemented
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pod_attach_returns_501() {
        let state = make_state();
        let mut router = make_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/mypod/attach")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // -----------------------------------------------------------------------
    // pod_portforward: 501 Not Implemented
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pod_portforward_returns_501() {
        let state = make_state();
        let mut router = make_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/mypod/portforward")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // -----------------------------------------------------------------------
    // node_address: pure logic tests
    // -----------------------------------------------------------------------

    /// node_address prefers InternalIP over Hostname.
    ///
    /// The InternalIP is the routable address inside the cluster. Using Hostname
    /// would work only if DNS resolves it from the apiserver, which is not guaranteed.
    #[test]
    fn node_address_prefers_internal_ip() {
        let node = serde_json::json!({
            "status": {
                "addresses": [
                    {"type": "Hostname", "address": "node1.example.com"},
                    {"type": "InternalIP", "address": "10.0.0.1"}
                ]
            }
        });
        assert_eq!(
            node_address(&node).as_deref(),
            Some("10.0.0.1"),
            "InternalIP must be preferred over Hostname for kubelet proxy"
        );
    }

    /// node_address falls back to Hostname when InternalIP is absent.
    #[test]
    fn node_address_falls_back_to_hostname() {
        let node = serde_json::json!({
            "status": {
                "addresses": [
                    {"type": "Hostname", "address": "node1.example.com"}
                ]
            }
        });
        assert_eq!(
            node_address(&node).as_deref(),
            Some("node1.example.com"),
            "Hostname must be used when InternalIP is absent"
        );
    }

    /// node_address returns None when addresses array is empty.
    #[test]
    fn node_address_empty_addresses_returns_none() {
        let node = serde_json::json!({
            "status": { "addresses": [] }
        });
        assert!(
            node_address(&node).is_none(),
            "empty addresses must return None — proxy cannot proceed without an address"
        );
    }

    /// node_address returns None when status.addresses is missing.
    #[test]
    fn node_address_missing_status_returns_none() {
        let node = serde_json::json!({"metadata": {"name": "node1"}});
        assert!(node_address(&node).is_none());
    }
}
