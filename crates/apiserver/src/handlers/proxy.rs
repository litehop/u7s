/// Pod subresource proxy handlers: /log, /exec, /attach, /portforward
///
/// /log: looks up the pod → node, then proxies GET to the kubelet log endpoint,
///        streaming the response body back to the client.
///
/// /attach: WebSocket proxy — upgrades the inbound kubectl connection (v5.channel.k8s.io)
///          and opens a matching WebSocket to the kubelet, then splices them.
///
/// /exec: return 501 Not Implemented.
/// /portforward: fully implemented as a WebSocket proxy.
use axum::{
    body::Body,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use u7s_store::Store;

use crate::{
    handlers::stream::{splice, AxumWs, TungsteniteWs},
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

pub async fn pod_log<S: Store>(
    State(state): State<AppState<S>>,
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
    //    Verify the kubelet's TLS certificate against the cluster CA. The CA DER bytes
    //    are stored in AppState and loaded from disk at startup (stable across restarts).
    let ca_der = state.cluster_ca_der.as_deref().ok_or_else(|| {
        Status::internal("cluster CA not available — cannot verify kubelet TLS".to_owned())
    })?;
    let ca_cert = reqwest::Certificate::from_der(ca_der)
        .map_err(|e| Status::internal(format!("invalid cluster CA certificate: {e}")))?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(ca_cert)
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
// /attach — WebSocket proxy to kubelet attach endpoint
// ---------------------------------------------------------------------------

/// Query parameters for /attach, matching the Kubernetes API.
#[derive(Deserialize)]
pub struct AttachQuery {
    pub container: Option<String>,
    pub stdin: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub tty: Option<String>,
}

/// Kubernetes attach subprotocol negotiated with both kubectl and kubelet.
const ATTACH_SUBPROTOCOL: &str = "v5.channel.k8s.io";

/// Resolved kubelet attach target — returned by the pure lookup helper so the
/// handler can be tested without a real WebSocket upgrade.
pub struct AttachTarget {
    pub kubelet_ws_url: String,
    pub node_ip: String,
    pub tls_config: std::sync::Arc<rustls::ClientConfig>,
}

/// Pure lookup: pod → node → node_ip → kubelet WS URL + TLS config.
///
/// Extracted from `pod_attach` so the error paths (404, 400, 500) can be tested
/// without going through the WebSocket upgrade machinery.  All I/O is either
/// store reads (testable) or TLS config construction (deterministic).
pub async fn resolve_attach_target<S: Store>(
    state: &AppState<S>,
    raw_ns: &str,
    pod_name: &str,
    query: &AttachQuery,
) -> Result<AttachTarget, crate::status::StatusError> {
    // Look up the pod.
    let pod_key = object_key("pods", raw_ns, pod_name);
    let stored = state
        .store
        .get(&pod_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(pod_name, "Pod"))?;

    let pod: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored pod: {e}")))?;

    let node_name = pod["spec"]["nodeName"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Status::bad_request(format!(
                "pod \"{pod_name}\" is not yet scheduled (spec.nodeName is empty)"
            ))
        })?;

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

    // Determine container (first container if unspecified).
    let container = match query.container.as_deref() {
        Some(c) if !c.is_empty() => c.to_owned(),
        _ => pod["spec"]["containers"][0]["name"]
            .as_str()
            .unwrap_or("default")
            .to_owned(),
    };

    // Build kubelet attach URL.
    //   Kubelet attach endpoint: wss://<node-ip>:10250/attach/<ns>/<pod>/<container>
    let mut params: Vec<(&str, &str)> = vec![("container", container.as_str())];
    if query.stdin.as_deref() == Some("true") || query.stdin.as_deref() == Some("1") {
        params.push(("stdin", "1"));
    }
    if query.stdout.as_deref() == Some("true") || query.stdout.as_deref() == Some("1") {
        params.push(("stdout", "1"));
    }
    if query.stderr.as_deref() == Some("true") || query.stderr.as_deref() == Some("1") {
        params.push(("stderr", "1"));
    }
    if query.tty.as_deref() == Some("true") || query.tty.as_deref() == Some("1") {
        params.push(("tty", "1"));
    }
    let qs: String = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let kubelet_ws_url =
        format!("wss://{node_ip}:10250/attach/{raw_ns}/{pod_name}/{container}?{qs}");

    // Verify the kubelet TLS cert against the cluster CA.
    let ca_der = state.cluster_ca_der.as_deref().ok_or_else(|| {
        Status::internal("cluster CA not available — cannot verify kubelet TLS".to_owned())
    })?;

    let tls_config = build_kubelet_tls_config(ca_der)
        .map_err(|e| Status::internal(format!("failed to build kubelet TLS config: {e}")))?;

    Ok(AttachTarget {
        kubelet_ws_url,
        node_ip,
        tls_config,
    })
}

/// /attach — proxy kubectl's WebSocket attach session to the kubelet.
///
/// Flow:
///   1. Look up pod → node → node_ip (via resolve_attach_target).
///   2. Upgrade inbound request to WebSocket (kubectl side), subprotocol v5.channel.k8s.io.
///   3. Open outbound WebSocket to kubelet attach endpoint with the same subprotocol.
///   4. Splice the two connections bidirectionally via BiStream trait.
///
/// The v5 channel protocol multiplexes stdin/stdout/stderr/resize over a single
/// WebSocket using a 1-byte channel prefix per message. The splice passes bytes
/// through unchanged — kubelet handles the mux.
pub async fn pod_attach<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, crate::status::StatusError> {
    let target = resolve_attach_target(&state, &raw_ns, &pod_name, &query).await?;

    let resp =
        ws.protocols([ATTACH_SUBPROTOCOL])
            .on_upgrade(move |inbound: WebSocket| async move {
                if let Err(e) = run_attach_proxy(inbound, target).await {
                    tracing::warn!("attach proxy error: {e}");
                }
            });

    Ok(resp)
}

/// Build a rustls ClientConfig that trusts a single DER-encoded CA certificate.
///
/// Used to verify the kubelet's TLS certificate. A separate config per request
/// is cheap and keeps the logic self-contained (no shared mutable state).
fn build_kubelet_tls_config(ca_der: &[u8]) -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec()))?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(std::sync::Arc::new(config))
}

/// Open outbound WebSocket to kubelet and splice with inbound kubectl WebSocket.
async fn run_attach_proxy(inbound: WebSocket, target: AttachTarget) -> anyhow::Result<()> {
    use rustls::pki_types::ServerName;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_tungstenite::{client_async_with_config, tungstenite::client::IntoClientRequest};

    let AttachTarget {
        kubelet_ws_url,
        node_ip,
        tls_config,
    } = target;

    // Resolve node_ip → TCP stream.
    let addr = format!("{node_ip}:10250");
    let tcp = TcpStream::connect(&addr).await?;

    // TLS handshake.
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(node_ip.clone())
        .map_err(|_| anyhow::anyhow!("invalid server name: {node_ip}"))?;
    let tls_stream = connector.connect(server_name, tcp).await?;

    // WebSocket handshake over the TLS stream.
    let mut request = kubelet_ws_url.into_client_request()?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        ATTACH_SUBPROTOCOL.parse().unwrap(),
    );
    let (outbound_ws, _resp) = client_async_with_config(request, tls_stream, None).await?;

    // Splice the two WebSocket connections bidirectionally.
    splice(AxumWs(inbound), TungsteniteWs(outbound_ws)).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// 501 stubs
// ---------------------------------------------------------------------------

/// exec requires SPDY 3.1 or WebSocket upgrade — not yet implemented.
/// Returns 501 so kubectl gets a clear error instead of 404.
pub async fn pod_exec(Path((_ns, _name)): Path<(String, String)>) -> impl IntoResponse {
    not_implemented("exec")
}

/// Query parameters for portforward: only `ports` is required.
///
/// kubectl sends `?ports=<port>` (may repeat for multiple ports).
/// We forward it verbatim to the kubelet.
#[derive(Deserialize)]
pub struct PortforwardQuery {
    pub ports: Option<String>,
}

/// Validated portforward parameters after all pre-upgrade checks pass.
#[derive(Debug)]
pub(crate) struct PortforwardParams {
    pub kubelet_url: String,
    pub ca_der: Vec<u8>,
}

/// Validate portforward pre-conditions: pod exists, is scheduled, CA is present.
///
/// Returns the kubelet WebSocket URL and CA DER bytes if all checks pass.
/// Separated from the handler so this decision logic can be unit-tested without
/// a real HTTP connection (axum's WebSocketUpgrade extractor requires a live
/// connection, so the upgrade itself cannot be exercised in unit tests).
pub(crate) async fn validate_portforward<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod_name: &str,
    ports: Option<&str>,
) -> Result<PortforwardParams, crate::status::StatusError> {
    // 1. Look up the pod.
    let pod_key = object_key("pods", ns, pod_name);
    let stored = state
        .store
        .get(&pod_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(pod_name, "Pod"))?;

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
        })?
        .to_owned();

    // 3. Look up the Node to get its address.
    let node_key = cluster_object_key("nodes", &node_name);
    let node_stored = state
        .store
        .get(&node_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&node_name, "Node"))?;

    let node: serde_json::Value = serde_json::from_slice(&node_stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored node: {e}")))?;

    let node_ip = node_address(&node).ok_or_else(|| {
        Status::internal(format!(
            "node \"{node_name}\" has no usable address in status.addresses"
        ))
    })?;

    // 4. Require cluster CA for kubelet TLS verification.
    let ca_der = state
        .cluster_ca_der
        .as_deref()
        .ok_or_else(|| {
            Status::internal("cluster CA not available — cannot verify kubelet TLS".to_owned())
        })?
        .to_vec();

    // 5. Build the kubelet portForward URL.
    //    wss://<node-ip>:10250/portForward/<ns>/<pod>[?ports=<port>]
    let ports_qs = ports.map(|p| format!("?ports={p}")).unwrap_or_default();
    let kubelet_url = format!("wss://{node_ip}:10250/portForward/{ns}/{pod_name}{ports_qs}");

    Ok(PortforwardParams {
        kubelet_url,
        ca_der,
    })
}

/// portforward WebSocket proxy: kubectl → apiserver → kubelet.
///
/// Upgrades the inbound connection to WebSocket (subprotocol v5.portforward.k8s.io),
/// then opens an outbound WebSocket to the kubelet's portForward endpoint, and
/// bidirectionally splices the two streams.
pub async fn pod_portforward<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<PortforwardQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, crate::status::StatusError> {
    let params = validate_portforward(&state, &raw_ns, &pod_name, query.ports.as_deref()).await?;

    let resp =
        ws.protocols(["v5.portforward.k8s.io"])
            .on_upgrade(move |inbound_socket| async move {
                if let Err(e) =
                    portforward_proxy(inbound_socket, params.kubelet_url, params.ca_der).await
                {
                    tracing::warn!("portforward proxy error: {e}");
                }
            });
    Ok(resp)
}

/// Connect to the kubelet portForward endpoint and splice with the inbound socket.
///
/// Separated from the handler so errors can be logged without crashing the task.
async fn portforward_proxy(
    inbound: axum::extract::ws::WebSocket,
    kubelet_url: String,
    ca_der: Vec<u8>,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    // Build rustls ClientConfig trusting only our cluster CA.
    let ca_cert = rustls::pki_types::CertificateDer::from(ca_der);
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert)
        .map_err(|e| anyhow::anyhow!("invalid cluster CA: {e}"))?;
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

    // Build the request with the portforward subprotocol header.
    let mut req = kubelet_url
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "v5.portforward.k8s.io".parse().expect("valid header value"),
    );

    // Connect outbound WebSocket to the kubelet.
    let (outbound_stream, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow::anyhow!("kubelet portforward connect failed: {e}"))?;

    // Splice inbound ↔ outbound.
    splice(AxumWs(inbound), TungsteniteWs(outbound_stream)).await;
    Ok(())
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
    // pod_log: 500 when cluster CA is absent (prevents skipping cert verification)
    // -----------------------------------------------------------------------

    /// /log must return 500 when cluster_ca_der is None.
    ///
    /// This guards against accidentally disabling TLS certificate verification on
    /// the kubelet proxy: if the CA is not in AppState, the handler fails loudly
    /// rather than silently accepting any certificate (the old danger_accept_invalid_certs
    /// behaviour). The 500 is surfaced before any kubelet connection is attempted.
    #[tokio::test]
    async fn pod_log_missing_ca_returns_500_for_scheduled_pod() {
        let state = make_state(); // cluster_ca_der is None

        // Seed a pod that IS scheduled so execution reaches the reqwest client build.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "scheduled-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        let key = crate::keys::object_key("pods", "default", "scheduled-pod");
        state
            .store
            .put(&key, bytes::Bytes::from(pod.to_string()), Some(0))
            .await
            .expect("seed pod must not fail");

        // Seed a node so the node lookup succeeds and reaches the CA check.
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {
                "addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]
            }
        });
        let node_key = crate::keys::cluster_object_key("nodes", "node-1");
        state
            .store
            .put(&node_key, bytes::Bytes::from(node.to_string()), Some(0))
            .await
            .expect("seed node must not fail");

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/scheduled-pod/log")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "/log must return 500 when cluster CA is absent — \
             the old danger_accept_invalid_certs(true) must not be silently used"
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
    // pod_attach: resolve_attach_target pure-function tests
    //
    // resolve_attach_target contains all error-path logic (404, 400, 500).
    // We test it directly rather than through the router because the axum
    // WebSocketUpgrade extractor rejects non-WS requests before the handler
    // runs — making it impossible to reach the error paths via the router.
    // -----------------------------------------------------------------------

    /// /attach must return 404 when the pod does not exist.
    ///
    /// Without this, a request for a non-existent pod would proceed to the
    /// WebSocket upgrade and then fail with a confusing connection error.
    #[tokio::test]
    async fn pod_attach_missing_pod_returns_404() {
        let state = make_state();
        let query = AttachQuery {
            container: None,
            stdin: None,
            stdout: None,
            stderr: None,
            tty: None,
        };
        match resolve_attach_target(&state, "default", "ghost", &query).await {
            Ok(_) => panic!("expected error for missing pod"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::NOT_FOUND,
                "/attach on a non-existent pod must produce 404"
            ),
        };
    }

    /// /attach must return 400 when the pod exists but is not yet scheduled.
    ///
    /// An unscheduled pod has no kubelet — returning 400 tells the caller
    /// that the pod is pending rather than producing a confusing connect error.
    #[tokio::test]
    async fn pod_attach_unscheduled_pod_returns_400() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pending", "namespace": "default", "resourceVersion": "1"},
            "spec": { "containers": [{"name": "app", "image": "nginx"}] }
        });
        let key = crate::keys::object_key("pods", "default", "pending");
        state
            .store
            .put(&key, bytes::Bytes::from(pod.to_string()), Some(0))
            .await
            .expect("seed pod");

        let query = AttachQuery {
            container: None,
            stdin: None,
            stdout: None,
            stderr: None,
            tty: None,
        };
        match resolve_attach_target(&state, "default", "pending", &query).await {
            Ok(_) => panic!("expected error for unscheduled pod"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::BAD_REQUEST,
                "/attach on an unscheduled pod must produce 400"
            ),
        };
    }

    /// /attach must return 500 when cluster CA is absent.
    ///
    /// Without a CA, we cannot verify the kubelet's TLS certificate.
    /// Failing loudly here prevents accidentally skipping cert verification.
    #[tokio::test]
    async fn pod_attach_missing_ca_returns_500() {
        let state = make_state(); // cluster_ca_der is None

        // Seed a scheduled pod and its node.
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let query = AttachQuery {
            container: None,
            stdin: None,
            stdout: None,
            stderr: None,
            tty: None,
        };
        match resolve_attach_target(&state, "default", "mypod", &query).await {
            Ok(_) => panic!("expected error when CA is absent"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::INTERNAL_SERVER_ERROR,
                "/attach must fail with 500 when cluster CA is absent"
            ),
        };
    }

    /// kubelet_ws_url is constructed correctly for a scheduled pod.
    ///
    /// The URL format is what kubelet expects: wss://<ip>:10250/attach/<ns>/<pod>/<container>.
    /// An incorrect URL would silently connect to the wrong endpoint or fail opaquely.
    #[tokio::test]
    async fn resolve_attach_target_builds_correct_kubelet_url() {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        // Build a state WITH a cluster CA so resolve_attach_target succeeds.
        // Use a minimal self-signed DER cert produced by rcgen.
        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_ca(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
            Some(ca_der),
            None,
            None,
        );

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "ns1", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "ns1", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let query = AttachQuery {
            container: Some("app".into()),
            stdin: Some("1".into()),
            stdout: Some("1".into()),
            stderr: None,
            tty: None,
        };
        let target = match resolve_attach_target(&state, "ns1", "mypod", &query).await {
            Ok(t) => t,
            Err(_) => panic!("resolve must succeed for scheduled pod with CA"),
        };

        assert_eq!(target.node_ip, "10.0.0.1");
        assert!(
            target
                .kubelet_ws_url
                .starts_with("wss://10.0.0.1:10250/attach/ns1/mypod/app"),
            "kubelet URL must use wss scheme on port 10250: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("stdin=1"),
            "kubelet URL must include stdin param: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("stdout=1"),
            "kubelet URL must include stdout param: {}",
            target.kubelet_ws_url
        );
    }

    // -----------------------------------------------------------------------
    // pod_portforward: validate_portforward unit tests
    //
    // The upgrade path itself (101 Switching Protocols) requires a real HTTP
    // connection to be hijacked and cannot be exercised with axum's in-process
    // tower::Service test harness. We therefore test the decision logic
    // (validate_portforward) directly — this is the function that determines
    // 404/400/500 vs. "proceed with upgrade". If this logic is correct, the
    // upgrade will be offered to the right requests at runtime.
    // -----------------------------------------------------------------------

    /// validate_portforward must return Err(404) when the pod does not exist.
    ///
    /// Without this guard the handler would attempt the upgrade and then fail
    /// to connect to the kubelet, producing a confusing error instead of 404.
    #[tokio::test]
    async fn portforward_validation_missing_pod_returns_404() {
        let state = make_state();
        let result = validate_portforward(&state, "default", "ghost", None).await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "validate_portforward must return 404 for a pod that does not exist"
        );
    }

    /// validate_portforward must return Err(400) when pod has no nodeName.
    ///
    /// An unscheduled pod has no kubelet to proxy to; we must reject before
    /// upgrading the connection so the client gets a clear error code.
    #[tokio::test]
    async fn portforward_validation_unscheduled_pod_returns_400() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pending", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
            // no nodeName
        });
        let key = crate::keys::object_key("pods", "default", "pending");
        state
            .store
            .put(&key, bytes::Bytes::from(pod.to_string()), Some(0))
            .await
            .expect("seed pod");

        let err = validate_portforward(&state, "default", "pending", None)
            .await
            .unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            400,
            "validate_portforward must return 400 for an unscheduled pod (no nodeName)"
        );
    }

    /// validate_portforward must return Err(500) when cluster CA is absent.
    ///
    /// We refuse to open an unverified TLS connection to the kubelet.
    /// The 500 is returned before the upgrade so the client sees a clear error.
    #[tokio::test]
    async fn portforward_validation_missing_ca_returns_500() {
        let state = make_state(); // cluster_ca_der is None

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-1", "containers": [{"name": "app", "image": "nginx"}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let err = validate_portforward(&state, "default", "mypod", Some("8080"))
            .await
            .unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            500,
            "validate_portforward must return 500 when cluster CA is absent"
        );
    }

    /// validate_portforward returns Ok with correct kubelet URL on the happy path.
    ///
    /// Verifies that when pod is scheduled, node has an InternalIP, and CA is
    /// present, the returned kubelet URL uses the correct scheme, address, and
    /// path format expected by the kubelet portForward endpoint.
    #[tokio::test]
    async fn portforward_validation_happy_path_produces_correct_kubelet_url() {
        use rcgen::generate_simple_self_signed;

        let cert =
            generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate test cert");
        let ca_der = cert.cert.der().to_vec();

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_ca(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
            Some(ca_der),
            None,
            None,
        );

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-1", "containers": [{"name": "app", "image": "nginx"}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let result = validate_portforward(&state, "default", "mypod", Some("8080")).await;
        let params = match result {
            Ok(p) => p,
            Err(e) => panic!(
                "happy-path validation must succeed, got HTTP {}",
                e.0.as_u16()
            ),
        };

        assert_eq!(
            params.kubelet_url, "wss://10.0.0.1:10250/portForward/default/mypod?ports=8080",
            "kubelet URL must use wss:// scheme, InternalIP, port 10250, \
             /portForward/<ns>/<pod> path, and the ports query string"
        );
    }

    // -----------------------------------------------------------------------
    // node_address: pure logic tests
    // -----------------------------------------------------------------------

    /// resolve_attach_target must return 404 when the pod references a node that is not in store.
    ///
    /// The pod's spec.nodeName points to a node that was deleted (or never registered).
    /// Returning 404 is preferable to 500: it tells the caller the resource is gone
    /// rather than suggesting an internal error.
    #[tokio::test]
    async fn pod_attach_node_not_found_returns_404() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "missing-node",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        // Do NOT seed the node — it is deliberately absent.

        let query = AttachQuery {
            container: None,
            stdin: None,
            stdout: None,
            stderr: None,
            tty: None,
        };
        match resolve_attach_target(&state, "default", "mypod", &query).await {
            Ok(_) => panic!("expected error when node is absent from store"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::NOT_FOUND,
                "resolve_attach_target must return 404 when the referenced node is not in store"
            ),
        };
    }

    /// validate_portforward must return 404 when the pod references a node that is not in store.
    ///
    /// The pod's spec.nodeName points to a node that was deleted (or never registered).
    /// Returning 404 informs the caller the node is gone rather than producing a 500.
    #[tokio::test]
    async fn portforward_validation_node_not_found_returns_404() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "missing-node",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        // Do NOT seed the node — it is deliberately absent.

        let err = validate_portforward(&state, "default", "mypod", Some("8080"))
            .await
            .unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "validate_portforward must return 404 when the referenced node is not in store"
        );
    }

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
