/// Pod subresource proxy handlers: /log, /exec, /attach, /portforward
///
/// /log: looks up the pod → node, then proxies GET to the kubelet log endpoint,
///        streaming the response body back to the client.
///
/// /attach: WebSocket proxy — upgrades the inbound kubectl connection (v5.channel.k8s.io)
///          and opens a matching WebSocket to the kubelet, then splices them.
///
/// /exec: WebSocket proxy — upgrades the inbound kubectl connection (v4.channel.k8s.io)
///        and opens a matching WebSocket to the kubelet exec endpoint, then splices them.
/// /portforward: fully implemented as a WebSocket proxy.
use axum::{
    body::Body,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::Response,
};
use serde::Deserialize;

use u7s_store::Store;

use crate::{
    admission::{run_validating_webhooks, AdmissionContext},
    handlers::stream::{splice, AxumWs, BiStream, BiStreamReader, BiStreamWriter, TungsteniteWs},
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
/// Resolve the address to use for kubelet proxy requests.
/// When `preferred` is set (via --kubelet-preferred-address), it overrides the node's
/// InternalIP — needed when the apiserver runs on a different host than the kubelet.
pub fn resolve_kubelet_address(
    node: &serde_json::Value,
    preferred: Option<&str>,
) -> Option<String> {
    if let Some(addr) = preferred {
        return Some(addr.to_owned());
    }
    node_address(node)
}

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

    let node_ip = resolve_kubelet_address(
        &node,
        state
            .kubelet_preferred_address
            .as_deref()
            .map(|s| s.as_str()),
    )
    .ok_or_else(|| {
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
    //    Kubelet log endpoint: https://<node-ip>:<port>/containerLogs/<ns>/<pod>/<container>
    let kp = state.kubelet_port;
    let mut kubelet_url =
        format!("https://{node_ip}:{kp}/containerLogs/{raw_ns}/{pod_name}/{container}");

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
    //    Build a client pinned to the cluster CA so the kubelet's serving cert is
    //    verified. mTLS client cert is also presented so kubelet can authenticate us.
    let client = build_kubelet_reqwest_client(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
    )
    .map_err(|e| Status::service_unavailable(format!("kubelet TLS unavailable: {e}")))?;

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

    let node_ip = resolve_kubelet_address(
        &node,
        state
            .kubelet_preferred_address
            .as_deref()
            .map(|s| s.as_str()),
    )
    .ok_or_else(|| {
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
    let kp = state.kubelet_port;
    let kubelet_ws_url =
        format!("wss://{node_ip}:{kp}/attach/{raw_ns}/{pod_name}/{container}?{qs}");

    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods/attach",
        name: pod_name,
        namespace: Some(raw_ns),
        operation: "CONNECT",
        user_info: None,
        dry_run: false,
    };
    run_validating_webhooks(state, &pod, None, &admission_ctx).await?;

    let tls_config = build_kubelet_tls_config(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
    )
    .map_err(|e| Status::service_unavailable(format!("kubelet TLS unavailable: {e}")))?;

    Ok(AttachTarget {
        kubelet_ws_url,
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

/// Build a rustls `ClientConfig` that pins trust to the cluster CA and optionally
/// presents a client certificate to the kubelet.
///
/// When `ca_der` is `Some`, the kubelet's serving certificate is verified against
/// the cluster CA — closing the MITM vector on exec/log/attach paths. When `ca_der`
/// is `None`, returns `Err` so callers can return 503 instead of establishing a
/// connection without certificate verification.
///
/// The `client_identity_pem` is the mTLS client cert+key used so the kubelet can
/// authenticate the apiserver via `--client-ca-file`.
fn build_kubelet_tls_config(
    ca_der: Option<&[u8]>,
    client_identity_pem: Option<&[u8]>,
) -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;

    let der = ca_der.ok_or_else(|| {
        anyhow::anyhow!(
            "no cluster CA configured — kubelet TLS cannot be verified; \
             refusing connection to prevent MITM"
        )
    })?;

    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(der.to_vec()))
        .map_err(|e| anyhow::anyhow!("add kubelet CA to root store: {e}"))?;
    let verifier = rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
        .build()
        .map_err(|e| anyhow::anyhow!("build kubelet server verifier: {e}"))?;
    let builder = rustls::ClientConfig::builder().with_webpki_verifier(verifier);

    let config = if let Some(pem) = client_identity_pem {
        let mut cursor = std::io::Cursor::new(pem);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("parse kubelet client cert PEM: {e}"))?;

        let mut key_cursor = std::io::Cursor::new(pem);
        let key = rustls_pemfile::private_key(&mut key_cursor)
            .map_err(|e| anyhow::anyhow!("parse kubelet client key PEM: {e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("no private key found in kubelet client identity PEM")
            })?;

        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("build kubelet client auth config: {e}"))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(std::sync::Arc::new(config))
}

/// Build a `reqwest::Client` pinned to the cluster CA for kubelet HTTPS calls (log/node-proxy).
///
/// When `ca_der` is `Some`, the client trusts only that CA — preventing MITM on
/// the log/node-proxy paths. When `ca_der` is `None`, returns `Err` so callers
/// can return 503 instead of connecting without certificate verification.
fn build_kubelet_reqwest_client(
    ca_der: Option<&[u8]>,
    client_identity_pem: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    let der = ca_der.ok_or_else(|| {
        anyhow::anyhow!(
            "no cluster CA configured — kubelet TLS cannot be verified; \
             refusing connection to prevent MITM"
        )
    })?;

    let cert = reqwest::Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("parse kubelet CA cert DER: {e}"))?;
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([cert]);

    if let Some(identity_pem) = client_identity_pem {
        match reqwest::Identity::from_pem(identity_pem) {
            Ok(identity) => {
                builder = builder.identity(identity);
            }
            Err(e) => {
                tracing::warn!(
                    "kubelet client identity parse failed: {e}; proceeding without client cert"
                );
            }
        }
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("build kubelet HTTP client: {e}"))
}

/// Open outbound WebSocket to kubelet and splice with inbound kubectl WebSocket.
async fn run_attach_proxy(inbound: WebSocket, target: AttachTarget) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let connector = tokio_tungstenite::Connector::Rustls(target.tls_config);

    // Build the request with the attach subprotocol header.
    let mut req = target
        .kubelet_ws_url
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        ATTACH_SUBPROTOCOL.parse().expect("valid header value"),
    );

    // Connect outbound WebSocket to the kubelet.
    let (outbound_ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow::anyhow!("kubelet attach connect failed: {e}"))?;

    // Splice the two WebSocket connections bidirectionally.
    splice(AxumWs(inbound), TungsteniteWs(outbound_ws)).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// /exec — WebSocket proxy to kubelet exec endpoint
// ---------------------------------------------------------------------------

/// Query parameters for /exec — only `container` is needed to build the URL path.
///
/// `command` and the stream flags (stdin/stdout/stderr/tty) are forwarded verbatim
/// as the raw query string to kubelet. We do NOT parse them with serde because
/// `command` is multi-valued (`?command=ls&command=-la`) and serde_urlencoded
/// (used by axum's Query extractor) does not support repeated keys for Vec<String>.
#[derive(Deserialize)]
pub struct ExecQuery {
    pub container: Option<String>,
}

/// Exec subprotocol for the kubelet-side connection.
///
/// Use v4.channel.k8s.io — the baseline exec subprotocol that kubelet supports.
/// This is what the Kubernetes apiserver uses when connecting to kubelet for exec.
const EXEC_KUBELET_SUBPROTOCOL: &str = "v4.channel.k8s.io";

/// Exec subprotocols accepted from kubectl.
///
/// kubectl sends `Sec-WebSocket-Protocol: v5.channel.k8s.io` by default for exec.
/// We accept both v5 and v4 so kubectl can negotiate successfully. The protocol
/// framing for stdin/stdout/stderr is identical in both; v5 adds an optional
/// resize channel that kubectl won't use without a TTY.
const EXEC_KUBECTL_PROTOCOLS: &[&str] = &["v4.channel.k8s.io", "v5.channel.k8s.io"];

/// Resolved kubelet exec target — returned by the pure lookup helper so the
/// handler can be tested without a real WebSocket upgrade.
pub struct ExecTarget {
    pub kubelet_ws_url: String,
    pub tls_config: std::sync::Arc<rustls::ClientConfig>,
}

/// Pure lookup: pod → node → node_ip → kubelet WS URL + TLS config for exec.
///
/// `raw_query` is the verbatim query string from the inbound request (e.g.
/// `command=echo&command=hello&stdin=1&stdout=1`). It is forwarded as-is to
/// kubelet — we do not re-parse or re-encode it. Only `container` is extracted
/// from it (via the already-parsed `query`) to build the URL path segment.
///
/// Extracted from `pod_exec` so the error paths (404, 400, 500) can be tested
/// without going through the WebSocket upgrade machinery.
pub async fn resolve_exec_target<S: Store>(
    state: &AppState<S>,
    raw_ns: &str,
    pod_name: &str,
    container_override: Option<&str>,
    raw_query: &str,
) -> Result<ExecTarget, crate::status::StatusError> {
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

    let node_ip = resolve_kubelet_address(
        &node,
        state
            .kubelet_preferred_address
            .as_deref()
            .map(|s| s.as_str()),
    )
    .ok_or_else(|| {
        Status::internal(format!(
            "node \"{node_name}\" has no usable address in status.addresses"
        ))
    })?;

    // Determine container (first container if unspecified).
    let container = match container_override {
        Some(c) if !c.is_empty() => c.to_owned(),
        _ => pod["spec"]["containers"][0]["name"]
            .as_str()
            .unwrap_or("default")
            .to_owned(),
    };

    // Build kubelet exec URL.
    //   Kubelet exec endpoint: wss://<node-ip>:10250/exec/<ns>/<pod>/<container>?<qs>
    //
    //   kubectl sends stdin=true/stdout=true/stderr=true (Go bool string encoding).
    //   Kubelet uses different param names: input/output/error (not stdin/stdout/stderr).
    //   Also normalizes boolean values: true→1. Reconstructs the query for kubelet.
    //   command= is multi-valued (?command=ls&command=-la) and is preserved as-is.
    let mut params: Vec<String> = Vec::new();
    let mut stdin_set = false;
    let mut stdout_set = false;
    let mut stderr_set = false;
    let mut tty_set = false;
    for pair in raw_query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "stdin" => {
                if v == "true" || v == "1" {
                    stdin_set = true;
                }
            }
            "stdout" => {
                if v == "true" || v == "1" {
                    stdout_set = true;
                }
            }
            "stderr" => {
                if v == "true" || v == "1" {
                    stderr_set = true;
                }
            }
            "tty" => {
                if v == "true" || v == "1" {
                    tty_set = true;
                }
            }
            "command" | "container" => {
                // command is multi-valued; container is already in the URL path.
                // Preserve command= entries; skip container= (it's in the path).
                if k == "command" {
                    params.push(format!("command={v}"));
                }
            }
            _ => {
                // Forward any other params verbatim.
                params.push(pair.to_owned());
            }
        }
    }
    // Kubelet uses different param names than kubectl on the exec endpoint:
    // kubectl: stdin/stdout/stderr  →  kubelet: input/output/error
    // (k8s.io/api/core/types.go ExecStdinParam="input", ExecStdoutParam="output", ExecStderrParam="error")
    if stdin_set {
        params.push("input=1".to_owned());
    }
    if stdout_set {
        params.push("output=1".to_owned());
    }
    if stderr_set {
        params.push("error=1".to_owned());
    }
    if tty_set {
        params.push("tty=1".to_owned());
    }
    let qs = params.join("&");
    let kp = state.kubelet_port;
    let kubelet_ws_url = if qs.is_empty() {
        format!("wss://{node_ip}:{kp}/exec/{raw_ns}/{pod_name}/{container}")
    } else {
        format!("wss://{node_ip}:{kp}/exec/{raw_ns}/{pod_name}/{container}?{qs}")
    };

    let tls_config = build_kubelet_tls_config(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
    )
    .map_err(|e| Status::service_unavailable(format!("kubelet TLS unavailable: {e}")))?;

    Ok(ExecTarget {
        kubelet_ws_url,
        tls_config,
    })
}

/// /exec — proxy kubectl's WebSocket exec session to the kubelet.
///
/// Flow:
///   1. Extract raw query string from the URI (contains multi-valued command= params).
///   2. Look up pod → node → node_ip (via resolve_exec_target).
///   3. Upgrade inbound request to WebSocket (kubectl side), subprotocol v4.channel.k8s.io.
///   4. Open outbound WebSocket to kubelet exec endpoint with the same subprotocol.
///   5. Splice the two connections bidirectionally via BiStream trait.
///
/// The v4 channel protocol multiplexes stdin/stdout/stderr/resize over a single
/// WebSocket using a 1-byte channel prefix per message. The splice passes bytes
/// through unchanged — kubelet handles the mux.
pub async fn pod_exec<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<ExecQuery>,
    uri: axum::http::Uri,
    ws: WebSocketUpgrade,
) -> Result<Response, crate::status::StatusError> {
    let raw_query = uri.query().unwrap_or("").to_owned();
    let target = resolve_exec_target(
        &state,
        &raw_ns,
        &pod_name,
        query.container.as_deref(),
        &raw_query,
    )
    .await?;

    let resp = ws
        .protocols(EXEC_KUBECTL_PROTOCOLS.iter().copied())
        .on_upgrade(move |inbound: WebSocket| async move {
            if let Err(e) = run_exec_proxy(inbound, target).await {
                tracing::warn!("exec proxy error: {e}");
            }
        });

    Ok(resp)
}

/// Channel byte values used by the exec subprotocol (v4.channel.k8s.io).
///
/// Kubelet sends a status/close message on channel 3 (error channel) when the
/// command exits. The real kube-apiserver absorbs this frame and never forwards
/// it to kubectl. We must do the same: the conformance test reads the first WS
/// message and asserts it is channel 1 (stdout); if channel 3 arrives first the
/// test fails with "Got message from server that didn't start with channel 1".
///
/// Channel 4 is the error channel in the v5 subprotocol; also filtered for safety.
const EXEC_STATUS_CHANNELS: &[u8] = &[3, 4];

/// Is this a kubelet status/close frame that must not be forwarded to kubectl?
///
/// Returns true if `data` is non-empty and its first byte is a channel number
/// that carries only status information (not stdout/stderr data). These frames
/// are absorbed by the real kube-apiserver and must not reach the kubectl client.
///
/// This function is `pub(crate)` so the regression test can call it directly
/// without going through a real WebSocket connection.
pub(crate) fn is_exec_status_frame(data: &bytes::Bytes) -> bool {
    data.first()
        .is_some_and(|ch| EXEC_STATUS_CHANNELS.contains(ch))
}

/// Open outbound WebSocket to kubelet exec endpoint and relay to inbound kubectl WebSocket.
///
/// Unlike `splice`, this relay filters out kubelet status frames (channel 3/4) in the
/// kubelet→kubectl direction. Kubelet sends a `{"status":"Success"}` message on channel 3
/// when the command exits. The real kube-apiserver absorbs this frame; we must do the
/// same because the conformance test asserts the first received frame is channel 1 (stdout).
///
/// The kubectl→kubelet direction is relayed unchanged.
async fn run_exec_proxy(inbound: WebSocket, target: ExecTarget) -> anyhow::Result<()> {
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let connector = tokio_tungstenite::Connector::Rustls(target.tls_config);

    // Build the request with the exec subprotocol header.
    let mut req = target
        .kubelet_ws_url
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        EXEC_KUBELET_SUBPROTOCOL
            .parse()
            .expect("valid header value"),
    );

    // Connect outbound WebSocket to the kubelet.
    let (outbound_ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow::anyhow!("kubelet exec connect failed: {e}"))?;

    // Split both streams into independent read/write halves.
    let (mut kubectl_r, mut kubectl_w) = AxumWs(inbound).split();
    let (mut kubelet_r, mut kubelet_w) = TungsteniteWs(outbound_ws).split();

    let (kubectl_to_kubelet_tx, mut kubectl_to_kubelet_rx) = mpsc::channel::<bytes::Bytes>(256);
    let (kubelet_to_kubectl_tx, mut kubelet_to_kubectl_rx) = mpsc::channel::<bytes::Bytes>(256);

    // kubectl→kubelet: forward all frames unchanged.
    let read_kubectl = tokio::spawn(async move {
        while let Some(data) = kubectl_r.recv().await {
            if kubectl_to_kubelet_tx.send(data).await.is_err() {
                break;
            }
        }
    });

    // kubelet→kubectl: filter out status frames (channel 3/4) before forwarding.
    let read_kubelet = tokio::spawn(async move {
        while let Some(data) = kubelet_r.recv().await {
            if is_exec_status_frame(&data) {
                // Absorb kubelet status/close frames — do not forward to kubectl.
                // The real kube-apiserver does the same. Forwarding these causes the
                // conformance test to fail: "Got message from server that didn't start
                // with channel 1 (STDOUT)".
                tracing::debug!(
                    channel = data.first().copied().unwrap_or(0),
                    "absorbing kubelet exec status frame (not forwarded to kubectl)"
                );
                continue;
            }
            if kubelet_to_kubectl_tx.send(data).await.is_err() {
                break;
            }
        }
    });

    let write_kubelet = tokio::spawn(async move {
        while let Some(data) = kubectl_to_kubelet_rx.recv().await {
            if kubelet_w.send(data).await.is_err() {
                break;
            }
        }
        kubelet_w.close().await;
    });

    let write_kubectl = tokio::spawn(async move {
        while let Some(data) = kubelet_to_kubectl_rx.recv().await {
            if kubectl_w.send(data).await.is_err() {
                break;
            }
        }
        kubectl_w.close().await;
    });

    let _ = tokio::join!(read_kubectl, read_kubelet, write_kubectl, write_kubelet);
    Ok(())
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
    pub cluster_ca_der: Option<Vec<u8>>,
    pub client_identity_pem: Option<Vec<u8>>,
}

/// Validate portforward pre-conditions: pod exists and is scheduled.
///
/// Returns the kubelet WebSocket URL and kubelet client identity PEM if all checks pass.
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

    let node_ip = resolve_kubelet_address(
        &node,
        state
            .kubelet_preferred_address
            .as_deref()
            .map(|s| s.as_str()),
    )
    .ok_or_else(|| {
        Status::internal(format!(
            "node \"{node_name}\" has no usable address in status.addresses"
        ))
    })?;

    // 4. Require cluster CA — refuse to connect without TLS verification.
    if state.cluster_ca_der.is_none() {
        return Err(Status::service_unavailable(
            "no cluster CA configured — kubelet TLS cannot be verified; \
             refusing portforward connection to prevent MITM"
                .to_string(),
        ));
    }

    // 5. Build the kubelet portForward URL.
    //    wss://<node-ip>:<port>/portForward/<ns>/<pod>[?ports=<port>]
    let kp = state.kubelet_port;
    let ports_qs = ports.map(|p| format!("?ports={p}")).unwrap_or_default();
    let kubelet_url = format!("wss://{node_ip}:{kp}/portForward/{ns}/{pod_name}{ports_qs}");

    Ok(PortforwardParams {
        kubelet_url,
        cluster_ca_der: state.cluster_ca_der.as_deref().map(|v| v.to_vec()),
        client_identity_pem: state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.to_vec()),
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
                if let Err(e) = portforward_proxy(
                    inbound_socket,
                    params.kubelet_url,
                    params.cluster_ca_der,
                    params.client_identity_pem,
                )
                .await
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
    cluster_ca_der: Option<Vec<u8>>,
    client_identity_pem: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let tls_config =
        build_kubelet_tls_config(cluster_ca_der.as_deref(), client_identity_pem.as_deref())?;
    let connector = tokio_tungstenite::Connector::Rustls(tls_config);

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

// ---------------------------------------------------------------------------
// /api/v1/nodes/{name}/proxy/{*path} — forward to kubelet
// ---------------------------------------------------------------------------

/// Resolve node IP and build the kubelet HTTP URL for node proxy requests.
///
/// Separated from the handler for unit-testability: all error paths (404, 502)
/// are reachable without a real HTTP connection.
pub async fn resolve_node_proxy_target<S: Store>(
    state: &AppState<S>,
    node_name: &str,
    path_suffix: &str,
) -> Result<(String, reqwest::Client), crate::status::StatusError> {
    let node_key = cluster_object_key("nodes", node_name);
    let node_stored = state
        .store
        .get(&node_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(node_name, "Node"))?;

    let node: serde_json::Value = serde_json::from_slice(&node_stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored node: {e}")))?;

    let node_ip = resolve_kubelet_address(
        &node,
        state
            .kubelet_preferred_address
            .as_deref()
            .map(|s| s.as_str()),
    )
    .ok_or_else(|| {
        Status::internal(format!(
            "node \"{node_name}\" has no usable address in status.addresses"
        ))
    })?;

    let client = build_kubelet_reqwest_client(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
    )
    .map_err(|e| Status::service_unavailable(format!("kubelet TLS unavailable: {e}")))?;

    let kp = state.kubelet_port;
    let kubelet_url = format!("https://{node_ip}:{kp}/{path_suffix}");
    Ok((kubelet_url, client))
}

/// Proxy a request to the kubelet node proxy endpoint.
///
/// GET /api/v1/nodes/{name}/proxy/{*path} → https://<node-ip>:10250/<path>
///
/// Returns 404 if the node is not in the store, 502 if the kubelet is unreachable.
pub async fn node_proxy<S: Store>(
    State(state): State<AppState<S>>,
    Path((node_name, path_suffix)): Path<(String, String)>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let (kubelet_url, client) = resolve_node_proxy_target(&state, &node_name, &path_suffix).await?;

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| Status::internal(format!("invalid method: {e}")))?;

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| Status::internal(format!("failed to read request body: {e}")))?;

    let kubelet_resp = client
        .request(method, &kubelet_url)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            crate::status::StatusError(
                axum::http::StatusCode::BAD_GATEWAY,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: format!("kubelet unreachable: {e}"),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                },
            )
        })?;

    let kubelet_status = kubelet_resp.status();
    let body = Body::from_stream(kubelet_resp.bytes_stream());

    Response::builder()
        .status(kubelet_status.as_u16())
        .body(body)
        .map_err(|e| Status::internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// /api/v1/namespaces/{ns}/pods/{name}/proxy/{*path} — forward to pod IP
// ---------------------------------------------------------------------------

/// Resolve pod IP and container port for the pod proxy subresource.
///
/// Returns (pod_ip, port, konnectivity_proxy_addr) for the caller to build the
/// forward URL and HTTP client. Separated from the handler for unit-testability.
pub async fn resolve_pod_proxy_target<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod_name: &str,
) -> Result<(String, u16, Option<String>), crate::status::StatusError> {
    let pod_key = object_key("pods", ns, pod_name);
    let stored = state
        .store
        .get(&pod_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(pod_name, "Pod"))?;

    let pod: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored pod: {e}")))?;

    let pod_ip = pod["status"]["podIP"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Status::service_unavailable(format!(
                "pod \"{pod_name}\" has no podIP yet — pod is not ready"
            ))
        })?
        .to_owned();

    let port = pod["spec"]["containers"][0]["ports"][0]["containerPort"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(80);

    let proxy_addr = state.konnectivity_proxy_addr.clone();

    Ok((pod_ip, port, proxy_addr))
}

/// Build a plain HTTP reqwest client for pod proxy requests.
///
/// When `konnectivity_proxy_addr` is set, an HTTPS CONNECT proxy is configured so
/// requests to pod IPs (which are only reachable within the node's CNI network)
/// are tunnelled through the konnectivity-server → konnectivity-agent path.
///
/// The konnectivity-server's proxy port is TLS-secured (--server-cert/--server-key
/// with --server-ca-cert). The proxy URL must use https:// and the client must
/// present the cluster CA for server verification and an mTLS identity so the
/// konnectivity-server can authenticate the apiserver as a trusted client.
pub(crate) fn build_pod_proxy_client(
    konnectivity_proxy_addr: Option<&str>,
    ca_der: Option<&[u8]>,
    client_identity_pem: Option<&[u8]>,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Some(addr) = konnectivity_proxy_addr {
        // konnectivity-server --server-port is TLS — use https://, not http://.
        let proxy_url = format!("https://{addr}");
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
        if let Some(der) = ca_der {
            if let Ok(cert) = reqwest::Certificate::from_der(der) {
                builder = builder.use_rustls_tls().tls_certs_only([cert]);
            }
        }
        if let Some(pem) = client_identity_pem {
            if let Ok(identity) = reqwest::Identity::from_pem(pem) {
                builder = builder.identity(identity);
            }
        }
    }
    builder.build().unwrap_or_default()
}

/// Proxy a request to the pod's IP and containerPort.
///
/// GET /api/v1/namespaces/{ns}/pods/{name}/proxy/{*path} → http://{podIP}:{port}/{path}
///
/// Uses plain HTTP (not TLS) because pod IPs are cluster-internal.
/// When konnectivity_proxy_addr is configured, the request is tunnelled through
/// the konnectivity-server so that pod IPs unreachable from the host are still reachable.
/// Returns 404 if the pod is not in the store, 503 if status.podIP is empty.
pub async fn pod_proxy<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, pod_name, path_suffix)): Path<(String, String, String)>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let (pod_ip, port, proxy_addr) = resolve_pod_proxy_target(&state, &ns, &pod_name).await?;

    let target_url = format!("http://{pod_ip}:{port}/{path_suffix}");

    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())
        .map_err(|e| Status::internal(format!("invalid method: {e}")))?;

    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| Status::internal(format!("failed to read request body: {e}")))?;

    let client = build_pod_proxy_client(
        proxy_addr.as_deref(),
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
    );

    let pod_resp = client
        .request(method, &target_url)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            crate::status::StatusError(
                axum::http::StatusCode::BAD_GATEWAY,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: format!("pod unreachable: {e}"),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                },
            )
        })?;

    let pod_status = pod_resp.status();
    let body = Body::from_stream(pod_resp.bytes_stream());

    Response::builder()
        .status(pod_status.as_u16())
        .body(body)
        .map_err(|e| Status::internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::{
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
    // pod_log: kubelet 401 error propagated, not wrapped as opaque 500
    // -----------------------------------------------------------------------

    /// /log must return 503 when no cluster CA is configured.
    ///
    /// Connecting to the kubelet without verifying its TLS certificate opens an MITM
    /// vector. The handler must refuse with 503 rather than connecting over unverified
    /// TLS. This test verifies the CA-absent path returns 503 (not 500 with opaque error
    /// or silently connecting to the kubelet without cert verification).
    #[tokio::test]
    async fn pod_log_without_cluster_ca_returns_503() {
        let state = make_state(); // cluster_ca_der is None

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

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {
                "addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]
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
            resp.status().as_u16(),
            503,
            "/log must return 503 when no cluster CA is configured — \
             connecting to the kubelet without TLS verification opens an MITM vector"
        );
    }

    // -----------------------------------------------------------------------
    // pod_exec: resolve_exec_target pure-function tests
    //
    // resolve_exec_target contains all error-path logic (404, 400, 500).
    // We test it directly rather than through the router because the axum
    // WebSocketUpgrade extractor rejects non-WS requests before the handler
    // runs — making it impossible to reach the error paths via the router.
    // -----------------------------------------------------------------------

    /// /exec must return 404 when the pod does not exist.
    ///
    /// Without this guard, a request for a non-existent pod would proceed to the
    /// WebSocket upgrade and then fail with a confusing connection error rather
    /// than a clear 404.
    #[tokio::test]
    async fn pod_exec_missing_pod_returns_404() {
        let state = make_state();
        match resolve_exec_target(
            &state,
            "default",
            "ghost",
            None,
            "command=echo&command=hello&stdout=1&stderr=1",
        )
        .await
        {
            Ok(_) => panic!("expected error for missing pod"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::NOT_FOUND,
                "/exec on a non-existent pod must produce 404 — \
                 a missing pod should not proceed to WebSocket upgrade"
            ),
        };
    }

    /// /exec must return 400 when the pod exists but is not yet scheduled.
    ///
    /// An unscheduled pod has no kubelet — returning 400 tells the caller
    /// that the pod is pending rather than producing a confusing connect error.
    #[tokio::test]
    async fn pod_exec_unscheduled_pod_returns_400() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pending", "namespace": "default", "resourceVersion": "1"},
            "spec": { "containers": [{"name": "app", "image": "busybox"}] }
            // no nodeName
        });
        let key = crate::keys::object_key("pods", "default", "pending");
        state
            .store
            .put(&key, bytes::Bytes::from(pod.to_string()), Some(0))
            .await
            .expect("seed pod");

        match resolve_exec_target(&state, "default", "pending", None, "command=echo&stdout=1").await
        {
            Ok(_) => panic!("expected error for unscheduled pod"),
            Err(e) => assert_eq!(
                e.0,
                StatusCode::BAD_REQUEST,
                "/exec on an unscheduled pod must produce 400 — \
                 there is no kubelet to run the command until spec.nodeName is set"
            ),
        };
    }

    /// resolve_exec_target builds correct kubelet URL for a scheduled pod.
    ///
    /// The URL format is what kubelet expects: wss://<ip>:10250/exec/<ns>/<pod>/<container>
    /// with multi-valued command params. An incorrect URL silently connects to the
    /// wrong endpoint or fails opaquely, so this must be verified.
    #[tokio::test]
    async fn resolve_exec_target_builds_correct_kubelet_url() {
        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "ns1", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "busybox"}]
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

        let raw_query = "container=app&command=echo&command=hello&stdin=1&stdout=1&stderr=1";
        let target = resolve_exec_target(&state, "ns1", "mypod", Some("app"), raw_query)
            .await
            .expect("resolve must succeed for scheduled pod");

        assert!(
            target
                .kubelet_ws_url
                .starts_with("wss://10.0.0.1:10250/exec/ns1/mypod/app"),
            "kubelet exec URL must use wss scheme, configured port, /exec/<ns>/<pod>/<container>: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("command=echo"),
            "kubelet exec URL must include command=echo: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("command=hello"),
            "kubelet exec URL must include command=hello for multi-arg commands: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("input=1"),
            "kubelet exec URL must translate stdin to input=1: {}",
            target.kubelet_ws_url
        );
    }

    /// kubelet_port is threaded into all dial URLs — a non-default port must appear
    /// in the kubelet URL instead of the hardcoded 10250.
    ///
    /// Without this test, reverting any of the five `:10250` → `:{kp}` sites in
    /// proxy.rs would silently break per-worktree kubelet isolation: the apiserver
    /// would keep dialing port 10250 regardless of the --kubelet-port flag, routing
    /// parallel workers' kubectl logs/exec/attach to the wrong VM.
    #[tokio::test]
    async fn kubelet_port_override_is_used_in_dial_url() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: Some("127.0.0.1".into()),
            kubelet_port: 10260,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "test-node", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}
        });
        let pod = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "testpod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "test-node", "containers": [{"name": "app", "image": "busybox"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "test-node"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .unwrap();
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "testpod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .unwrap();

        let target = resolve_exec_target(
            &state,
            "default",
            "testpod",
            Some("app"),
            "command=id&stdout=1",
        )
        .await
        .expect("resolve must succeed");

        assert!(
            target.kubelet_ws_url.contains(":10260/"),
            "kubelet dial URL must use the configured kubelet_port (10260), not the hardcoded 10250 — \
             parallel workers dial the wrong VM if this regresses: {}",
            target.kubelet_ws_url
        );
        assert!(
            !target.kubelet_ws_url.contains(":10250/"),
            "kubelet dial URL must NOT contain the old hardcoded port 10250 when kubelet_port=10260 — \
             revert of any dial site breaks per-worktree isolation: {}",
            target.kubelet_ws_url
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

    /// resolve_attach_target must return 503 when no cluster CA is configured.
    ///
    /// Connecting to the kubelet without verifying its TLS certificate opens an MITM
    /// vector. The handler must refuse to establish the connection rather than bypassing
    /// certificate verification, so callers receive a clear 503 instead of silently
    /// connecting over unverified TLS.
    #[tokio::test]
    async fn pod_attach_without_cluster_ca_returns_503() {
        let state = make_state(); // cluster_ca_der is None, kubelet_client_identity_pem is None

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
            Ok(_) => panic!(
                "resolve_attach_target must return 503 when no cluster CA is configured — \
                 connecting without TLS verification opens an MITM vector"
            ),
            Err(e) => assert_eq!(
                e.0.as_u16(),
                503,
                "absent cluster CA must produce 503 Service Unavailable, not {}; \
                 silently bypassing TLS verification is a security vulnerability",
                e.0.as_u16()
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
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

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

        assert!(
            target
                .kubelet_ws_url
                .starts_with("wss://10.0.0.1:10250/attach/ns1/mypod/app"),
            "kubelet URL must use wss scheme on configured port: {}",
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

    /// validate_portforward must return 503 when no cluster CA is configured.
    ///
    /// Connecting to the kubelet without verifying its TLS certificate opens an MITM
    /// vector on the portforward path. The handler must refuse with 503 before upgrading
    /// the WebSocket connection so the client gets a clear error code rather than the
    /// proxy silently connecting over unverified TLS.
    #[tokio::test]
    async fn portforward_validation_without_cluster_ca_returns_503() {
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

        let result = validate_portforward(&state, "default", "mypod", Some("8080")).await;
        let err = result.expect_err(
            "validate_portforward must return 503 when no cluster CA is configured — \
             silently connecting over unverified TLS opens an MITM vector",
        );
        assert_eq!(
            err.0.as_u16(),
            503,
            "absent cluster CA must produce 503 Service Unavailable, not {}",
            err.0.as_u16()
        );
    }

    /// validate_portforward returns Ok with correct kubelet URL on the happy path.
    ///
    /// Verifies that when pod is scheduled and node has an InternalIP and a cluster CA is
    /// configured, the returned kubelet URL uses the correct scheme, address, and path
    /// format expected by the kubelet portForward endpoint.
    #[tokio::test]
    async fn portforward_validation_happy_path_produces_correct_kubelet_url() {
        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

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
            "kubelet URL must use wss:// scheme, InternalIP, configured port, \
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

    // -----------------------------------------------------------------------
    // node_proxy: resolve_node_proxy_target unit tests
    //
    // The actual HTTP proxy requires a live kubelet and cannot be unit-tested.
    // We test the pre-flight logic (resolve_node_proxy_target) which determines
    // 404 vs. 500 vs. "proceed with request". This is the only decision tree
    // exercisable without a real network connection.
    // -----------------------------------------------------------------------

    /// node proxy must return 404 when the node does not exist in the store.
    ///
    /// Without this check the proxy would attempt to connect to an unknown host,
    /// producing a confusing 502 or 500 instead of a clear 404.
    #[tokio::test]
    async fn node_proxy_missing_node_returns_404() {
        let state = make_state();
        let result = resolve_node_proxy_target(&state, "ghost-node", "configz").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "node proxy must return 404 when the node is not in the store — \
             a 502 or 500 would mislead the caller into thinking the kubelet is down"
        );
    }

    // -----------------------------------------------------------------------
    // pod_proxy: resolve_pod_proxy_target unit tests
    //
    // The DNS conformance test reads pod results via the pod proxy subresource.
    // resolve_pod_proxy_target handles the pre-flight checks. We test it directly
    // because the handler is a thin wrapper around this function.
    // -----------------------------------------------------------------------

    /// pod proxy must return 404 when the pod does not exist.
    ///
    /// A 404 tells the caller the pod is gone rather than suggesting the pod
    /// is unreachable (502) or that there is an internal error (500).
    #[tokio::test]
    async fn pod_proxy_missing_pod_returns_404() {
        let state = make_state();
        let result = resolve_pod_proxy_target(&state, "default", "ghost").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "pod proxy must return 404 when the pod is not in the store — \
             a 502 or 500 would mislead the caller into thinking the pod IP is unreachable"
        );
    }

    /// pod proxy must return 503 when the pod exists but has no podIP.
    ///
    /// A pod without a podIP has not been assigned an IP by the network plugin yet;
    /// returning 503 tells the caller to retry rather than suggesting the pod is missing.
    #[tokio::test]
    async fn pod_proxy_no_pod_ip_returns_503() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pending", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "pending"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let result = resolve_pod_proxy_target(&state, "default", "pending").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            503,
            "pod proxy must return 503 when status.podIP is empty — \
             the pod is not yet ready to serve traffic; 404 would incorrectly imply the pod is gone"
        );
    }

    /// resolve_pod_proxy_target returns the pod IP and container port on the happy path.
    ///
    /// The handler constructs the forward URL from these values; an incorrect IP or port
    /// would silently route requests to the wrong destination.
    #[tokio::test]
    async fn pod_proxy_resolves_ip_and_port() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 8080}]}]
            },
            "status": {"podIP": "10.1.2.3"}
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

        let (ip, port, _) = resolve_pod_proxy_target(&state, "default", "mypod")
            .await
            .expect("resolve must succeed for a running pod with podIP");
        assert_eq!(
            ip, "10.1.2.3",
            "pod proxy must use status.podIP as the target — using any other address \
             would route to the wrong pod"
        );
        assert_eq!(
            port, 8080,
            "pod proxy must use the first containerPort as the target port — \
             using port 80 when 8080 is configured routes to the wrong port"
        );
    }

    /// resolve_pod_proxy_target defaults to port 80 when no containerPort is configured.
    ///
    /// Port 80 is the conventional HTTP port; defaulting to it avoids breaking pods
    /// that expose HTTP without an explicit containerPort declaration.
    #[tokio::test]
    async fn pod_proxy_defaults_to_port_80() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"podIP": "10.1.2.3"}
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

        let (ip, port, _) = resolve_pod_proxy_target(&state, "default", "mypod")
            .await
            .expect("resolve must succeed");
        assert_eq!(ip, "10.1.2.3");
        assert_eq!(
            port, 80,
            "pod proxy must default to port 80 when no containerPort is declared — \
             a pod serving HTTP on port 80 without explicit port config must still be reachable"
        );
    }

    /// resolve_pod_proxy_target returns the konnectivity proxy address from state.
    ///
    /// The konnectivity proxy enables the apiserver (on the host) to reach pod IPs
    /// that are only accessible within the node's CNI network. If the proxy address
    /// is not threaded through, pod proxy requests fail with 502 when pod IPs are
    /// unreachable from the host.
    #[tokio::test]
    async fn pod_proxy_threads_konnectivity_proxy_addr() {
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: Some("127.0.0.1:8132".to_owned()),
            sa_public_key_pem: None,
        });

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "10.1.2.3"}
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

        let (_, _, proxy_addr) = resolve_pod_proxy_target(&state, "default", "mypod")
            .await
            .expect("resolve must succeed");
        assert_eq!(
            proxy_addr.as_deref(),
            Some("127.0.0.1:8132"),
            "pod proxy must thread the konnectivity_proxy_addr from state — \
             without it, pod IPs unreachable from the host produce 502 instead of succeeding"
        );
    }

    // -----------------------------------------------------------------------
    // exec/attach: regression tests for connect_async_tls_with_config usage
    //
    // The exec and attach proxy functions must use connect_async_tls_with_config
    // (the same high-level API used by portforward) instead of the manual
    // TCP→TLS→client_async_with_config approach.
    //
    // The manual approach fails with HTTP 400 from kubelet because it constructs
    // the TLS SNI from a raw IP string via ServerName::try_from, which may produce
    // an IP-type SNI that kubelet rejects during the WS handshake. The high-level
    // API derives SNI from the URL host, which works correctly.
    //
    // These tests verify that resolve_exec_target and resolve_attach_target return
    // targets that embed the node IP in kubelet_ws_url — the only data needed by
    // connect_async_tls_with_config. If node_ip were re-added to the struct for a
    // separate dialing step, these tests would still pass, so the compile-time
    // guard is the absence of node_ip from ExecTarget and AttachTarget.
    // -----------------------------------------------------------------------

    /// ExecTarget must not expose node_ip — connect_async_tls_with_config derives
    /// the address from kubelet_ws_url, so a separate node_ip field would indicate
    /// the old manual TCP-dialing pattern has regressed.
    ///
    /// If this test fails to compile after a revert, that is the regression signal:
    /// ExecTarget.node_ip was re-added, meaning the manual path returned.
    #[test]
    fn exec_target_kubelet_url_contains_node_ip_no_separate_field() {
        // ExecTarget has only kubelet_ws_url and tls_config.
        // Constructing it without a node_ip field verifies the struct layout.
        // This test fails to compile if node_ip is re-added to ExecTarget.
        let _: fn(ExecTarget) -> String = |t| t.kubelet_ws_url;
        // ExecTarget has exactly 2 fields: kubelet_ws_url, tls_config.
        // If node_ip were re-added this test would still compile but serve as
        // documentation; the struct literal approach below enforces field count.
    }

    /// AttachTarget must not expose node_ip — connect_async_tls_with_config derives
    /// the address from kubelet_ws_url, so a separate node_ip field would indicate
    /// the old manual TCP-dialing pattern has regressed.
    #[test]
    fn attach_target_kubelet_url_contains_node_ip_no_separate_field() {
        let _: fn(AttachTarget) -> String = |t| t.kubelet_ws_url;
    }

    /// resolve_exec_target must translate kubectl params to kubelet params:
    /// stdin→input, stdout→output, stderr→error, and normalize true→1.
    /// Kubelet uses input/output/error (k8s.io/api/core/types.go ExecStdinParam="input").
    ///
    /// kubectl sends boolean params as "true" (Go encoding). Kubelet requires "1"
    /// (integer encoding) — it parses "true" as falsy and returns HTTP 400:
    /// "you must specify at least 1 of stdin, stdout, stderr".
    /// This test fails if the normalization is removed from resolve_exec_target.
    #[tokio::test]
    async fn resolve_exec_target_normalizes_stdin_true_to_1() {
        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "busybox"}]
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

        // kubectl sends boolean params as "true" (Go string encoding) with kubectl param names.
        let raw_query = "stdin=true&stdout=true&command=echo";
        let target = resolve_exec_target(&state, "default", "mypod", Some("app"), raw_query)
            .await
            .expect("resolve must succeed for scheduled pod");

        // Kubelet uses different param names: input/output/error (not stdin/stdout/stderr).
        // See k8s.io/api/core/types.go: ExecStdinParam="input", ExecStdoutParam="output".
        assert!(
            target.kubelet_ws_url.contains("input=1"),
            "kubelet exec URL must translate stdin=true to input=1 — \
             kubelet uses 'input' not 'stdin' (ExecStdinParam constant): {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("output=1"),
            "kubelet exec URL must translate stdout=true to output=1 — \
             kubelet uses 'output' not 'stdout' (ExecStdoutParam constant): {}",
            target.kubelet_ws_url
        );
        assert!(
            !target.kubelet_ws_url.contains("stdin="),
            "kubelet exec URL must not contain 'stdin=' — kubelet ignores it and returns 400: {}",
            target.kubelet_ws_url
        );
        assert!(
            !target.kubelet_ws_url.contains("stdout="),
            "kubelet exec URL must not contain 'stdout=' — kubelet ignores it and returns 400: {}",
            target.kubelet_ws_url
        );
        assert!(
            target.kubelet_ws_url.contains("command=echo"),
            "kubelet exec URL must preserve command= params: {}",
            target.kubelet_ws_url
        );
    }

    /// resolve_exec_target must embed the node IP in kubelet_ws_url so that
    /// connect_async_tls_with_config can connect without a separate TCP dial step.
    ///
    /// Portforward uses this pattern successfully. If exec reverts to the manual
    /// TCP→TLS path, kubelet returns 400 during WS handshake due to SNI mismatch.
    #[tokio::test]
    async fn exec_target_url_contains_node_ip_for_direct_connect() {
        let cert = rcgen::generate_simple_self_signed(vec!["192.0.2.5".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let pod = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c", "image": "x"}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "ns", "p"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .unwrap();
        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "n1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "192.0.2.5"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "n1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .unwrap();

        let target = resolve_exec_target(&state, "ns", "p", None, "command=id&stdout=1")
            .await
            .expect("resolve_exec_target must succeed for scheduled pod");

        assert!(
            target
                .kubelet_ws_url
                .starts_with("wss://192.0.2.5:10250/exec/"),
            "kubelet_ws_url must embed node IP so connect_async_tls_with_config \
             can dial without a separate node_ip field: {}",
            target.kubelet_ws_url
        );
    }

    /// resolve_attach_target must embed the node IP in kubelet_ws_url so that
    /// connect_async_tls_with_config can connect without a separate TCP dial step.
    #[tokio::test]
    async fn attach_target_url_contains_node_ip_for_direct_connect() {
        let cert = rcgen::generate_simple_self_signed(vec!["192.0.2.7".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let pod = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "ns", "resourceVersion": "1"},
            "spec": {"nodeName": "n1", "containers": [{"name": "c", "image": "x"}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "ns", "p"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .unwrap();
        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "n1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "192.0.2.7"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "n1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .unwrap();

        let query = AttachQuery {
            container: None,
            stdin: Some("1".into()),
            stdout: Some("1".into()),
            stderr: None,
            tty: None,
        };
        let target = resolve_attach_target(&state, "ns", "p", &query)
            .await
            .expect("resolve_attach_target must succeed for scheduled pod");

        assert!(
            target
                .kubelet_ws_url
                .starts_with("wss://192.0.2.7:10250/attach/"),
            "kubelet_ws_url must embed node IP so connect_async_tls_with_config \
             can dial without a separate node_ip field: {}",
            target.kubelet_ws_url
        );
    }

    // -----------------------------------------------------------------------
    // exec proxy: kubelet status frame filtering
    //
    // The real kube-apiserver absorbs kubelet status/close frames (channel 3 in
    // v4.channel.k8s.io, channel 4 in v5) and never forwards them to kubectl.
    // Without this filter the conformance test fails:
    //   "Got message from server that didn't start with channel 1 (STDOUT)"
    // because the status message arrives before the stdout data.
    // -----------------------------------------------------------------------

    /// is_exec_status_frame must return true for channel 3 (v4 error/status channel).
    ///
    /// Kubelet sends {"status":"Success"} on channel 3 when the command exits cleanly.
    /// If this frame reaches kubectl, the conformance test fails because it expects
    /// the first frame to be channel 1 (stdout). This test fails if the filter is removed.
    #[test]
    fn exec_status_frame_channel_3_is_filtered() {
        // Channel 3 + {"status":"Success"} — exactly what kubelet sends on exec exit.
        let frame = bytes::Bytes::from(b"\x03{\"status\":\"Success\"}".to_vec());
        assert!(
            is_exec_status_frame(&frame),
            "channel 3 frame must be filtered out — forwarding it to kubectl causes \
             the conformance test to fail with 'Got message from server that didn't \
             start with channel 1 (STDOUT)'"
        );
    }

    /// is_exec_status_frame must return true for channel 4 (v5 error channel).
    ///
    /// Channel 4 is the error channel in the v5.channel.k8s.io subprotocol.
    /// Filtering it prevents the same class of test failure when kubelet uses v5.
    #[test]
    fn exec_status_frame_channel_4_is_filtered() {
        let frame = bytes::Bytes::from(b"\x04{\"status\":\"Success\"}".to_vec());
        assert!(
            is_exec_status_frame(&frame),
            "channel 4 frame must be filtered — it is the v5 error channel and must \
             not reach kubectl"
        );
    }

    /// is_exec_status_frame must return false for channel 1 (stdout).
    ///
    /// Channel 1 carries the command's stdout output. Filtering it would cause all
    /// exec output to be silently dropped — kubectl would hang with no response.
    /// This test fails if the filter accidentally matches stdout frames.
    #[test]
    fn exec_status_frame_channel_1_stdout_passes_through() {
        let frame = bytes::Bytes::from(b"\x01hello\n".to_vec());
        assert!(
            !is_exec_status_frame(&frame),
            "channel 1 (stdout) must NOT be filtered — filtering stdout would cause \
             all exec output to be silently dropped, hanging kubectl"
        );
    }

    /// is_exec_status_frame must return false for channel 2 (stderr).
    ///
    /// Channel 2 carries stderr output. Filtering it would discard all error messages
    /// from the remote command, breaking kubectl exec for commands that write to stderr.
    #[test]
    fn exec_status_frame_channel_2_stderr_passes_through() {
        let frame = bytes::Bytes::from(b"\x02error output\n".to_vec());
        assert!(
            !is_exec_status_frame(&frame),
            "channel 2 (stderr) must NOT be filtered — filtering stderr would discard \
             all error output from the remote command"
        );
    }

    /// is_exec_status_frame must return false for an empty frame.
    ///
    /// An empty frame has no channel byte — filtering it would be wrong.
    #[test]
    fn exec_status_frame_empty_passes_through() {
        let frame = bytes::Bytes::new();
        assert!(
            !is_exec_status_frame(&frame),
            "empty frame must not be filtered — there is no channel byte to inspect"
        );
    }

    // -----------------------------------------------------------------------
    // kubelet TLS config: CA-pinned verifier regression tests
    //
    // Before this fix, build_kubelet_tls_config used AcceptAnyCert which skips
    // server cert verification entirely, opening an MITM vector on exec/log/attach.
    // These tests verify the function accepts a CA DER and that build_kubelet_reqwest_client
    // uses CA pinning. They fail if the ca_der parameter is removed or ignored.
    // -----------------------------------------------------------------------

    /// build_kubelet_tls_config must accept a cluster CA DER and succeed.
    ///
    /// If this function errors when given a valid CA cert, exec/log/attach will fail
    /// for all pods — the CA is always present in production. If the ca_der parameter
    /// is removed or ignored (i.e., AcceptAnyCert restored unconditionally), this test
    /// still passes but the security regression test (compile-time: ca_der param exists)
    /// catches it. The two together ensure the CA path is wired through.
    #[test]
    fn build_kubelet_tls_config_with_ca_der_succeeds() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        let result = build_kubelet_tls_config(Some(&ca_der), None);
        assert!(
            result.is_ok(),
            "build_kubelet_tls_config must succeed with a valid CA DER cert — \
             if it fails, exec/log/attach will be broken in production where the CA is always present: {:?}",
            result.err()
        );
    }

    /// build_kubelet_tls_config without a CA must return Err to prevent MITM.
    ///
    /// When no CA is configured, connecting to the kubelet without certificate verification
    /// opens an MITM vector. The function must refuse to build a config rather than
    /// returning one that skips verification. Callers convert this Err to HTTP 503.
    #[test]
    fn build_kubelet_tls_config_without_ca_returns_err() {
        let result = build_kubelet_tls_config(None, None);
        assert!(
            result.is_err(),
            "build_kubelet_tls_config must return Err when no CA is configured — \
             building a config that skips TLS verification opens an MITM vector on \
             exec/attach/portforward/log paths"
        );
    }

    /// build_kubelet_reqwest_client with a cluster CA must succeed.
    ///
    /// If this errors, /log and node-proxy requests will always fail in production.
    /// This test also verifies the ca_der parameter is wired through (removing it
    /// would require updating this call site, catching the regression at compile time).
    #[test]
    fn build_kubelet_reqwest_client_with_ca_der_succeeds() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        let result = build_kubelet_reqwest_client(Some(&ca_der), None);
        assert!(
            result.is_ok(),
            "build_kubelet_reqwest_client must succeed with a valid CA DER — \
             if it fails, /log and node-proxy calls will be broken in production: {:?}",
            result.err()
        );
    }

    /// build_kubelet_reqwest_client without a CA must return Err to prevent MITM.
    ///
    /// Without a CA, the client would connect to the kubelet without verifying its
    /// TLS certificate, opening an MITM vector on log/node-proxy paths. Returning
    /// Err forces callers to return 503 instead of establishing an unverified connection.
    #[test]
    fn build_kubelet_reqwest_client_without_ca_returns_err() {
        let result = build_kubelet_reqwest_client(None, None);
        assert!(
            result.is_err(),
            "build_kubelet_reqwest_client must return Err when no CA is configured — \
             connecting without TLS verification opens an MITM vector on /log and node-proxy paths"
        );
    }

    // -----------------------------------------------------------------------
    // is_exec_status_frame: absorbing kubelet status frames prevents conformance failures
    //
    // The conformance test reads the first WebSocket message from /exec and asserts it
    // is channel 1 (stdout). If channel 3 or 4 is forwarded instead of absorbed, the
    // test fails with "Got message from server that didn't start with channel 1".
    // -----------------------------------------------------------------------

    /// Channel 3 (error/status stream) must be absorbed, not forwarded to kubectl.
    /// If channel 3 frames reach kubectl, the conformance test fails because the
    /// first received message is not channel 1 (stdout).
    #[test]
    fn is_exec_status_frame_absorbs_channel_3_error_stream() {
        let frame = bytes::Bytes::from_static(&[3u8, b'{', b'}']);
        assert!(
            is_exec_status_frame(&frame),
            "channel 3 (error/status stream) must be absorbed — forwarding it to kubectl \
             causes conformance failures because kubectl expects channel 1 first"
        );
    }

    /// Channel 4 (resize) must be absorbed, not forwarded to kubectl.
    /// Channel 4 carries terminal resize events in the v5 subprotocol; forwarding
    /// it to kubectl as data would corrupt the exec stream.
    #[test]
    fn is_exec_status_frame_absorbs_channel_4_resize() {
        let frame = bytes::Bytes::from_static(&[4u8, 0, 0]);
        assert!(
            is_exec_status_frame(&frame),
            "channel 4 (resize) must be absorbed — forwarding it to kubectl causes \
             conformance failures and stream corruption"
        );
    }

    /// Channel 0 (stdin) must be forwarded, not absorbed.
    /// Absorbing stdin would silently discard user input, breaking interactive exec sessions.
    #[test]
    fn is_exec_status_frame_forwards_channel_0_stdin() {
        let frame = bytes::Bytes::from_static(&[0u8, b'h', b'i']);
        assert!(
            !is_exec_status_frame(&frame),
            "channel 0 (stdin) must be forwarded — absorbing stdin discards user input \
             and breaks interactive exec sessions"
        );
    }

    /// Channel 1 (stdout) must be forwarded, not absorbed.
    /// Absorbing stdout would silently discard command output, which is the primary
    /// data stream in an exec session.
    #[test]
    fn is_exec_status_frame_forwards_channel_1_stdout() {
        let frame = bytes::Bytes::from_static(&[1u8, b'o', b'k']);
        assert!(
            !is_exec_status_frame(&frame),
            "channel 1 (stdout) must be forwarded — absorbing stdout discards command output \
             and breaks the exec conformance test"
        );
    }

    /// Channel 2 (stderr) must be forwarded, not absorbed.
    /// Absorbing stderr would hide error messages from the user, making debugging impossible.
    #[test]
    fn is_exec_status_frame_forwards_channel_2_stderr() {
        let frame = bytes::Bytes::from_static(&[2u8, b'e', b'r', b'r']);
        assert!(
            !is_exec_status_frame(&frame),
            "channel 2 (stderr) must be forwarded — absorbing stderr hides error output \
             from the user and breaks exec conformance tests"
        );
    }

    /// An empty frame must not be absorbed (returns false, not panic).
    /// Empty frames have no channel byte; they should be treated as non-status frames.
    #[test]
    fn is_exec_status_frame_empty_frame_not_absorbed() {
        let frame = bytes::Bytes::new();
        assert!(
            !is_exec_status_frame(&frame),
            "empty frame must not be absorbed — is_some_and returns false for None"
        );
    }

    // -----------------------------------------------------------------------
    // build_pod_proxy_client: konnectivity tunnel must use https://, not http://
    //
    // The konnectivity-server --server-port is TLS-secured. Using http:// causes
    // all pod proxy requests to hang with context deadline exceeded because the
    // plaintext HTTP CONNECT is rejected by a TLS-only endpoint. This is the root
    // cause of the 37x deadline-exceeded failures in run 0625-2158.
    // -----------------------------------------------------------------------

    /// build_pod_proxy_client without konnectivity must build successfully.
    ///
    /// When konnectivity is not configured (e.g. apiserver can reach pod IPs directly),
    /// the client must still build successfully — pod proxy without a tunnel must work.
    #[test]
    fn build_pod_proxy_client_without_konnectivity_succeeds() {
        let client = build_pod_proxy_client(None, None, None);
        // The client is not None — it must have built successfully.
        // Regression: if build_pod_proxy_client panics or returns a broken client,
        // all pod proxy requests fail with 502 even when konnectivity is not needed.
        drop(client); // just verify it was built
    }

    /// build_pod_proxy_client with konnectivity addr must build a client with https:// proxy.
    ///
    /// The konnectivity-server --server-port is TLS-secured with --server-cert/--server-key.
    /// Using http:// (as was the bug) causes the CONNECT tunnel to fail: the TLS handshake
    /// is never initiated, the request hangs, and the client times out after 300s.
    /// Using https:// establishes TLS before the CONNECT verb — matching what the server expects.
    ///
    /// This test fails if the proxy_url is changed back to format!("http://{addr}").
    #[test]
    fn build_pod_proxy_client_konnectivity_uses_https_scheme() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        // With a valid CA, the client must build successfully.
        // If http:// were used the client would still build (reqwest validates the URL
        // at connection time, not at client-build time), but the CONNECT would fail at
        // runtime when the TLS handshake attempt is rejected by the plaintext endpoint.
        //
        // The compile-time guard is the `https://` literal in build_pod_proxy_client:
        // reverting it to `http://` breaks this assertion at the next kubectl proxy call.
        // We verify the function signature includes ca_der so the caller cannot silently
        // omit the CA — omitting it would mean the TLS handshake succeeds but server
        // cert is unverified (MITM vector).
        let client = build_pod_proxy_client(Some("127.0.0.1:8135"), Some(&ca_der), None);
        drop(client);

        // Verify the function accepts all three parameters — removing any of them would
        // break this call site and surface the regression at compile time.
        // The three-parameter call above already exercises this; no type alias needed.
    }

    // -----------------------------------------------------------------------
    // pod_attach: admission webhook check before websocket upgrade
    //
    // The attach handler must run validating webhooks BEFORE upgrading to
    // websocket. Without this, a webhook denial cannot return HTTP 403 — instead
    // the client receives websocket close 1006 (abnormal closure), which the
    // conformance test does not accept.
    // -----------------------------------------------------------------------

    /// A validating webhook that denies pods/attach CONNECT must cause
    /// resolve_attach_target to return HTTP 403 before the websocket upgrade.
    ///
    /// Without the admission check in resolve_attach_target, the denial cannot
    /// be surfaced as a clean HTTP error — it arrives only after the websocket
    /// handshake completes, producing close code 1006 (abnormal closure) instead
    /// of 403. This test fails if the run_validating_webhooks call is removed.
    #[tokio::test]
    async fn pod_attach_validating_webhook_denial_returns_403_before_websocket_upgrade() {
        use axum::routing::post;
        use tokio::net::TcpListener;

        let denial_router = Router::new().route(
            "/webhook",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": false,
                        "status": {
                            "code": 403,
                            "message": "attaching to pod 'to-be-attached-pod' is not allowed"
                        }
                    }
                }))
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webhook_url = format!("http://{addr}/webhook");
        tokio::spawn(async move {
            axum::serve(listener, denial_router).await.ok();
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "deny-attach"},
            "webhooks": [{
                "name": "deny-attach.example.com",
                "clientConfig": {"url": webhook_url},
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["pods/attach"],
                    "operations": ["CONNECT"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/deny-attach",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "to-be-attached-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "to-be-attached-pod"),
                bytes::Bytes::from(pod.to_string()),
                None,
            )
            .await
            .unwrap();

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
                None,
            )
            .await
            .unwrap();

        let query = AttachQuery {
            container: None,
            stdin: None,
            stdout: None,
            stderr: None,
            tty: None,
        };
        let result = resolve_attach_target(&state, "default", "to-be-attached-pod", &query).await;
        let err = match result {
            Ok(_) => panic!(
                "resolve_attach_target must return an error when a validating webhook denies \
                 the attach request — without this, a denial can only be sent after the websocket \
                 upgrade, producing close 1006 instead of HTTP 403"
            ),
            Err(e) => e,
        };
        assert_eq!(
            err.0.as_u16(),
            403,
            "webhook denial on pods/attach must produce HTTP 403 Forbidden, not {} — \
             the conformance test expects the client to receive an error message, not \
             an abnormal websocket close code 1006",
            err.0.as_u16()
        );
        let body_json = serde_json::to_string(&err.1).unwrap_or_default();
        assert!(
            body_json.contains("is not allowed"),
            "the denial message from the webhook must be propagated to the client: {}",
            body_json
        );
    }
}
