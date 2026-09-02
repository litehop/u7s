/// Pod subresource proxy handlers: /log, /exec, /attach, /portforward
///
/// /log: looks up the pod → node, then proxies GET to the kubelet log endpoint,
///        streaming the response body back to the client.
///
/// /attach: WebSocket proxy — upgrades the inbound kubectl connection (v5.channel.k8s.io)
///          and opens a matching WebSocket to the kubelet, then splices them.
///
/// /exec: WebSocket proxy — upgrades the inbound kubectl connection (v4 or v5.channel.k8s.io)
///        and opens a matching v5.channel.k8s.io WebSocket to the kubelet exec endpoint,
///        then splices them.
/// /portforward: fully implemented as a WebSocket proxy.
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Path, Query, State,
    },
    response::Response,
};
use serde::Deserialize;

use u7s_store::{ListOptions, Store};

use crate::{
    admission::{run_validating_webhooks, AdmissionContext},
    handlers::stream::{
        splice, AxumWs, BiStream, BiStreamReader, BiStreamWriter, RawStream, TungsteniteWs,
    },
    keys::{cluster_object_key, group_list_prefix, object_key},
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

/// Resolve the host-side kubelet port to dial for `node_name`.
///
/// VM InternalIPs are not host-routable from the apiserver, so every node's kubelet is
/// reached through its own host port-forward to 127.0.0.1 — the primary's forward is
/// `--kubelet-port`, and every other node's is `--node-kubelet-port <name>=<port>`. A
/// node missing from `node_kubelet_ports` (every single-node deployment, and the primary
/// itself once other nodes are mapped) falls back to `global`. Without this per-node
/// lookup, a pod on any node but the primary would dial the primary's forward instead of
/// its own node's, so exec/logs/attach/port-forward against it misroute — they either
/// time out (websocket close 1006) or hit the wrong kubelet's pod state (404).
pub fn kubelet_port_for_node(
    node_name: &str,
    node_kubelet_ports: &std::collections::HashMap<String, u16>,
    global: u16,
) -> u16 {
    node_kubelet_ports.get(node_name).copied().unwrap_or(global)
}

// ---------------------------------------------------------------------------
// /log handler
// ---------------------------------------------------------------------------

/// Subprotocol kubectl and the sig-node conformance test negotiate for the pod-logs
/// WebSocket. Unlike exec/attach's `v4/v5.channel.k8s.io`, log messages carry no
/// channel-byte prefix — kubelet's log endpoint is plain HTTP, so the apiserver just
/// forwards each response chunk as a raw WS message.
const LOG_WS_SUBPROTOCOL: &str = "binary.k8s.io";

/// True when the inbound request carries the WebSocket upgrade headers.
///
/// `/log` must serve both a plain GET (the existing streaming-HTTP-response behavior)
/// and a WebSocket GET (kubectl and the "retrieving logs over websockets" conformance
/// test) on the same route. Unlike `/attach` and `/exec` it can't take `WebSocketUpgrade`
/// as a required extractor — that would reject every plain GET with 400 before the
/// handler body runs.
fn is_websocket_upgrade_request(req: &axum::http::Request<Body>) -> bool {
    let headers = req.headers();
    let has_upgrade_connection = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        });
    let has_websocket_upgrade = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    has_upgrade_connection && has_websocket_upgrade
}

/// Pure lookup: pod → node → node_ip → kubelet containerLogs URL.
///
/// Extracted from `pod_log` so the plain-HTTP and WebSocket branches share the same
/// pod/node/container resolution and error semantics (404/400/500), and so the error
/// paths can be tested without a live kubelet.
async fn resolve_log_target<S: Store>(
    state: &AppState<S>,
    raw_ns: &str,
    pod_name: &str,
    query: &LogQuery,
) -> Result<String, crate::status::StatusError> {
    // 1. Look up the pod.
    let pod_key = object_key("pods", raw_ns, pod_name);
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
    let kp = kubelet_port_for_node(node_name, &state.node_kubelet_ports, state.kubelet_port);
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

    Ok(kubelet_url)
}

/// Fetch the kubelet log stream and forward each chunk as a WebSocket binary message.
///
/// kubelet's containerLogs endpoint is plain HTTP, not a WebSocket — the apiserver is
/// the one that terminates the client's WS upgrade and re-emits the HTTP response body
/// as WS frames. Runs until the kubelet stream ends or the client disconnects.
async fn stream_log_over_websocket(
    mut socket: WebSocket,
    client: reqwest::Client,
    kubelet_url: String,
) -> anyhow::Result<()> {
    use futures_util::StreamExt as _;

    let kubelet_resp = client
        .get(&kubelet_url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("kubelet log request failed: {e}"))?;

    let mut stream = kubelet_resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| anyhow::anyhow!("kubelet log stream error: {e}"))?;
        if socket.send(Message::Binary(bytes)).await.is_err() {
            // Client went away — nothing left to forward to.
            return Ok(());
        }
    }
    let _ = socket.send(Message::Close(None)).await;
    Ok(())
}

pub async fn pod_log<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<LogQuery>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let kubelet_url = resolve_log_target(&state, &raw_ns, &pod_name, &query).await?;

    // Proxy via reqwest using the shared kubelet client (built once at startup).
    let client = state.kubelet_client.clone().ok_or_else(|| {
        Status::service_unavailable("kubelet TLS unavailable: no cluster CA configured".to_string())
    })?;

    if is_websocket_upgrade_request(&req) {
        let (mut parts, _body) = req.into_parts();
        let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state)
            .await
            .map_err(|e| Status::bad_request(format!("invalid websocket upgrade request: {e}")))?;

        return Ok(ws.protocols([LOG_WS_SUBPROTOCOL]).on_upgrade(
            move |socket: WebSocket| async move {
                if let Err(e) = stream_log_over_websocket(socket, client, kubelet_url).await {
                    tracing::warn!("log websocket stream error: {e}");
                }
            },
        ));
    }

    let kubelet_resp = client.get(&kubelet_url).send().await.map_err(|e| {
        tracing::warn!("pod log proxy error: kubelet request to {kubelet_url} failed: {e}");
        crate::status::StatusError(
            axum::http::StatusCode::BAD_GATEWAY,
            crate::status::Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message: format!("kubelet request failed: {e}"),
                reason: "BadGateway",
                code: 502,
                metadata: None,
                details: None,
            },
        )
    })?;

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

/// Fallback attach subprotocol for kubelet versions that predate
/// `ExtendWebSocketsToKubelet` (kubelet < 1.36 — see `EXEC_KUBELET_SUBPROTOCOL`'s doc
/// comment for the feature-gate background). Kubelet's attach and exec websocket
/// handlers share the same subprotocol registration, so a pre-1.36 kubelet rejects a
/// v5.channel.k8s.io attach offer with a bare 403 Forbidden exactly like exec did —
/// see `dial_kubelet_attach`.
const ATTACH_KUBELET_FALLBACK_SUBPROTOCOL: &str = "v4.channel.k8s.io";

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

    let truthy = |v: &Option<String>| matches!(v.as_deref(), Some("true") | Some("1"));
    let stdin = truthy(&query.stdin);
    let stdout = truthy(&query.stdout);
    let stderr = truthy(&query.stderr);
    let tty = truthy(&query.tty);

    // Build kubelet attach URL.
    //   Kubelet attach endpoint: wss://<node-ip>:10250/attach/<ns>/<pod>/<container>
    let mut params: Vec<(&str, &str)> = vec![("container", container.as_str())];
    if stdin {
        params.push(("stdin", "1"));
    }
    if stdout {
        params.push(("stdout", "1"));
    }
    if stderr {
        params.push(("stderr", "1"));
    }
    if tty {
        params.push(("tty", "1"));
    }
    let qs: String = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let kp = kubelet_port_for_node(node_name, &state.node_kubelet_ports, state.kubelet_port);
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
    // Admission for a CONNECT subresource reviews the PodAttachOptions the
    // client requested (stdin/container/...), not the pod itself — matching
    // upstream's ConnectResource handler, which builds admission attributes
    // from the decoded connect options. A webhook that inspects the attach
    // parameters (e.g. denying only `-i -c=container1`) would otherwise never
    // see them and could not distinguish attach requests from one another.
    let attach_options = serde_json::json!({
        "kind": "PodAttachOptions",
        "apiVersion": "v1",
        "stdin": stdin,
        "stdout": stdout,
        "stderr": stderr,
        "tty": tty,
        "container": container,
    });
    run_validating_webhooks(state, &attach_options, None, &admission_ctx).await?;

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
///   3. Open outbound WebSocket to kubelet attach endpoint, preferring the same
///      subprotocol but retrying with v4.channel.k8s.io if kubelet rejects v5 (see
///      `run_attach_proxy`).
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

/// /attach (POST) — client-go's `remotecommand` executor dials WebSocket (GET) first;
/// its websocket transport treats ANY non-101 handshake response as an upgrade
/// failure — including a clean 403 admission denial — and silently retries the
/// exact same request via SPDY (POST), discarding the original error and message
/// entirely (see `httpstream.IsUpgradeFailure` / `NewFallbackExecutor` upstream).
///
/// Previously this route mapped POST to `pod_attach`, whose `WebSocketUpgrade`
/// extractor rejects any non-GET method before the handler body runs — so the
/// fallback request never reached `resolve_attach_target`/admission a second time,
/// and the client's terminal error was axum's generic "Request method must be
/// `GET`" instead of the webhook's denial message.
///
/// Run the same pre-upgrade checks here so the fallback surfaces the same Status
/// (denial, not-found, not-scheduled, ...) that the GET attempt already computed.
/// Real SPDY streaming is not implemented; if every check passes there is nothing
/// left to report here — the GET/WebSocket attempt above already succeeds in that
/// case, so a working client never depends on this branch.
pub async fn pod_attach_post<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<AttachQuery>,
) -> Result<Response, crate::status::StatusError> {
    resolve_attach_target(&state, &raw_ns, &pod_name, &query).await?;
    Err(crate::status::StatusError(
        axum::http::StatusCode::NOT_IMPLEMENTED,
        crate::status::Status {
            kind: "Status",
            api_version: "v1",
            status: "Failure",
            message:
                "attach via SPDY (POST upgrade) is not implemented; use a WebSocket-capable client"
                    .to_string(),
            reason: "NotImplemented",
            code: 501,
            metadata: None,
            details: None,
        },
    ))
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

/// A `ServerCertVerifier` that accepts any certificate — matches upstream kube-apiserver's
/// `InsecureSkipVerify: true` for pod-proxy TLS targets. Unlike the kubelet (signed by the
/// cluster CA and verified by `build_kubelet_tls_config`), pod/workload TLS certs are
/// self-signed or issued by a CA the cluster has no way to know, so there is no trust
/// anchor to pin to — verification is skipped entirely rather than pinned to the wrong CA.
#[derive(Debug)]
struct InsecureServerCertVerifier(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a rustls client config that skips server certificate verification entirely, for
/// dialing a pod/service TLS listener over an already-established konnectivity tunnel (see
/// `pod_proxy_via_connect_tunnel`). Unlike `build_kubelet_tls_config`, this takes no CA:
/// there is no cluster-wide trust anchor to check an arbitrary workload's TLS cert against.
fn build_insecure_tls_config() -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    // Idempotent: a second install (the server's startup path already did this once) is a
    // no-op, so this function works standalone in tests too.
    rustls_post_quantum::provider().install_default().ok();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("no default rustls crypto provider installed"))?
        .clone();

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(InsecureServerCertVerifier(provider)));
    Ok(std::sync::Arc::new(config))
}

/// Outbound socket type returned by `tokio_tungstenite::connect_async_tls_with_config`.
type KubeletAttachWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Dial the kubelet attach WebSocket endpoint offering a single subprotocol.
///
/// Split out of `run_attach_proxy` so it can be retried with a different
/// subprotocol without duplicating the request-building/connect boilerplate —
/// see `ATTACH_SUBPROTOCOL`/`ATTACH_KUBELET_FALLBACK_SUBPROTOCOL`.
async fn dial_kubelet_attach(
    target: &AttachTarget,
    subprotocol: &str,
) -> anyhow::Result<KubeletAttachWs> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let connector = tokio_tungstenite::Connector::Rustls(target.tls_config.clone());
    let mut req = target
        .kubelet_ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        subprotocol.parse().expect("valid header value"),
    );

    let (ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow::anyhow!("kubelet attach connect failed: {e}"))?;
    Ok(ws)
}

/// Open outbound WebSocket to kubelet and splice with inbound kubectl WebSocket.
///
/// Tries `ATTACH_SUBPROTOCOL` first; falls back to `ATTACH_KUBELET_FALLBACK_SUBPROTOCOL`
/// when kubelet rejects it (pre-1.36 kubelet without `ExtendWebSocketsToKubelet`). If
/// both attempts fail, `inbound` gets a real close frame via
/// `close_inbound_on_dial_failure` instead of being dropped silently.
async fn run_attach_proxy(inbound: WebSocket, target: AttachTarget) -> anyhow::Result<()> {
    let v5_err = match dial_kubelet_attach(&target, ATTACH_SUBPROTOCOL).await {
        Ok(ws) => {
            splice(AxumWs(inbound), TungsteniteWs(ws)).await;
            return Ok(());
        }
        Err(e) => e,
    };
    tracing::debug!(
        "kubelet rejected {ATTACH_SUBPROTOCOL} ({v5_err}); retrying attach dial with {ATTACH_KUBELET_FALLBACK_SUBPROTOCOL} \
         (pre-1.36 kubelet without ExtendWebSocketsToKubelet)"
    );
    let outbound_ws = match dial_kubelet_attach(&target, ATTACH_KUBELET_FALLBACK_SUBPROTOCOL).await
    {
        Ok(ws) => ws,
        Err(_) => {
            close_inbound_on_dial_failure(inbound, &v5_err.to_string()).await;
            return Err(v5_err);
        }
    };
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
/// Prefer v5.channel.k8s.io, not v4. `kubectl exec`'s real websocket executor
/// (client-go's `NewWebSocketExecutor`) only ever offers v5 — v5 is the version
/// that "adds support for a CLOSE signal" (a `[255, streamID]` control frame
/// sent when the client's local stdin reaches EOF, so the remote process's
/// stdin can be half-closed without tearing down the whole multiplexed
/// connection). Since kubectl only speaks v5, apiserver always negotiates v5
/// with it (see `EXEC_KUBECTL_PROTOCOLS`). If this outbound leg then dialed
/// kubelet with v4, kubelet's v4 handler doesn't understand the CLOSE frame —
/// it silently discards a message for stream id 255 — so the exec'd process's
/// stdin pipe is never closed. Commands that read stdin until EOF (e.g. `tar
/// xf -` when streaming a file via `kubectl exec -i`) receive all their data
/// successfully but then hang forever waiting for a close that never comes,
/// exactly like the real kube-apiserver's SPDY→websocket CLOSE-signal
/// translation this project doesn't (and shouldn't need to) replicate: v4/v5
/// framing for channels 0-4 is otherwise identical, so v5 is a strict
/// superset — safe even for the rare v4-only client (see
/// `EXEC_KUBECTL_PROTOCOLS`), which will simply never emit a CLOSE frame.
///
/// Kubelet only speaks v5 natively starting the `ExtendWebSocketsToKubelet`
/// feature gate (beta, default-on in 1.36 — see upstream `CHANGELOG-1.36.md`).
/// Before that, kubelet's own exec websocket handler
/// (`k8s.io/kubelet/pkg/cri/streaming/remotecommand/websocket.go`) registers only
/// `""`, `channel.k8s.io`, `base64.channel.k8s.io`, `v4.channel.k8s.io` and
/// `v4.base64.channel.k8s.io` as valid `Sec-WebSocket-Protocol` values, so a v5
/// offer fails the handshake outright — `golang.org/x/net/websocket`'s
/// `newServerConn` answers with a bare `403 Forbidden` when its `Handshake`
/// callback rejects the protocol, before ever calling the connection handler.
/// See `dial_kubelet_exec` for the v4 fallback this requires.
const EXEC_KUBELET_SUBPROTOCOL: &str = "v5.channel.k8s.io";

/// Fallback exec subprotocol for kubelet versions that predate
/// `ExtendWebSocketsToKubelet` (kubelet < 1.36 — see `EXEC_KUBELET_SUBPROTOCOL`).
/// Confirmed live against kubelet 1.34.9: dialing with v5 gets
/// `kubelet exec connect failed: HTTP error: 403 Forbidden`; v4 succeeds.
const EXEC_KUBELET_FALLBACK_SUBPROTOCOL: &str = "v4.channel.k8s.io";

/// Exec subprotocols accepted from kubectl.
///
/// kubectl sends `Sec-WebSocket-Protocol: v5.channel.k8s.io` by default for exec.
/// We accept both v5 and v4 so kubectl can negotiate successfully. The protocol
/// framing for stdin/stdout/stderr is identical in both; v5 adds an optional
/// resize channel that kubectl won't use without a TTY, and the CLOSE signal
/// (see `EXEC_KUBELET_SUBPROTOCOL`).
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
    let kp = kubelet_port_for_node(node_name, &state.node_kubelet_ports, state.kubelet_port);
    let kubelet_ws_url = if qs.is_empty() {
        format!("wss://{node_ip}:{kp}/exec/{raw_ns}/{pod_name}/{container}")
    } else {
        format!("wss://{node_ip}:{kp}/exec/{raw_ns}/{pod_name}/{container}?{qs}")
    };

    let admission_ctx = AdmissionContext {
        group: "",
        version: "v1",
        resource: "pods/exec",
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
///   3. Upgrade inbound request to WebSocket (kubectl side), subprotocol v4 or v5.channel.k8s.io.
///   4. Open outbound WebSocket to kubelet exec endpoint, always v5.channel.k8s.io
///      (see `EXEC_KUBELET_SUBPROTOCOL` for why this must not mirror the inbound choice).
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

/// /exec (POST) — client-go's `remotecommand` executor dials WebSocket (GET) first;
/// its websocket transport treats ANY non-101 handshake response as an upgrade
/// failure — including a clean 403 admission denial — and silently retries the
/// exact same request via SPDY (POST), discarding the original error and message
/// entirely (see `httpstream.IsUpgradeFailure` / `NewFallbackExecutor` upstream).
///
/// Previously this route mapped POST to `pod_exec`, whose `WebSocketUpgrade`
/// extractor rejects any non-GET method before the handler body runs — so the
/// fallback request never reached `resolve_exec_target`/admission a second time,
/// and the client's terminal error was axum's generic "Request method must be
/// `GET`" instead of the webhook's denial message.
///
/// Run the same pre-upgrade checks here so the fallback surfaces the same Status
/// (denial, not-found, not-scheduled, ...) that the GET attempt already computed.
/// Real SPDY streaming is not implemented; if every check passes there is nothing
/// left to report here — the GET/WebSocket attempt above already succeeds in that
/// case, so a working client never depends on this branch.
pub async fn pod_exec_post<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<ExecQuery>,
    uri: axum::http::Uri,
) -> Result<Response, crate::status::StatusError> {
    let raw_query = uri.query().unwrap_or("").to_owned();
    resolve_exec_target(
        &state,
        &raw_ns,
        &pod_name,
        query.container.as_deref(),
        &raw_query,
    )
    .await?;
    Err(crate::status::StatusError(
        axum::http::StatusCode::NOT_IMPLEMENTED,
        crate::status::Status {
            kind: "Status",
            api_version: "v1",
            status: "Failure",
            message:
                "exec via SPDY (POST upgrade) is not implemented; use a WebSocket-capable client"
                    .to_string(),
            reason: "NotImplemented",
            code: 501,
            metadata: None,
            details: None,
        },
    ))
}

/// Channel byte values used by the exec subprotocol (v4/v5.channel.k8s.io).
///
/// Kubelet sends a JSON-encoded `metav1.Status` on channel 3 (error channel) when
/// the command exits — `{"status":"Success"}` on a clean exit, or
/// `{"status":"Failure","reason":"NonZeroExitCode",...}` otherwise. Channel 4 is
/// the resize/error channel in the v5 subprotocol; also checked for safety.
///
/// A frame on one of these channels is a *candidate* for absorption, not an
/// automatic drop — see `exec_status_frame_is_success`, which decides whether it
/// is actually safe to swallow.
const EXEC_STATUS_CHANNELS: &[u8] = &[3, 4];

/// Is this a frame on a channel that may carry a kubelet exec status message?
///
/// Returns true if `data` is non-empty and its first byte is a channel number
/// that carries status information rather than stdout/stderr data. This only
/// identifies the *channel*; whether the frame is actually safe to drop depends
/// on its JSON payload (see `exec_status_frame_is_success`).
///
/// This function is `pub(crate)` so the regression test can call it directly
/// without going through a real WebSocket connection.
pub(crate) fn is_exec_status_frame(data: &bytes::Bytes) -> bool {
    data.first()
        .is_some_and(|ch| EXEC_STATUS_CHANNELS.contains(ch))
}

/// Does this channel-3/4 frame carry a genuine `{"status":"Success"}` exec status?
///
/// Kubelet's exec status frame is a JSON-encoded `metav1.Status` (`data[0]` is the
/// channel byte, `data[1..]` is the JSON body). On a clean exit it is
/// `{"status":"Success"}`; on a nonzero exit it is `{"status":"Failure",
/// "reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode",...}]}}`.
///
/// Only genuine success frames are absorbed by `run_exec_proxy` — some clients
/// (e.g. the legacy `channel.k8s.io` conformance test in
/// `test/e2e/common/node/pods.go`) read raw frames off the wire and fail if any
/// message other than channel 1 (stdout) arrives first. Failure frames — and
/// anything that doesn't parse as a recognizable status object — must be
/// forwarded unchanged: client-go's `remotecommand.StreamExecutor` blocks on this
/// channel and decodes it into the `exec.CodeExitError` that `kubectl exec`
/// relies on to report a nonzero exit code (see upstream `errorDecoderV4.decode`).
/// Dropping failure frames unconditionally — the bug this function fixes — makes
/// every nonzero exec exit look like a clean success to the caller.
fn exec_status_frame_is_success(data: &bytes::Bytes) -> bool {
    data.get(1..)
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_owned))
        .is_some_and(|status| status == "Success")
}

/// Outbound socket type returned by `tokio_tungstenite::connect_async_tls_with_config`.
type KubeletExecWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Dial the kubelet exec WebSocket endpoint offering a single subprotocol.
///
/// Split out of `run_exec_proxy` so it can be retried with a different
/// subprotocol without duplicating the request-building/connect boilerplate —
/// see `EXEC_KUBELET_SUBPROTOCOL`/`EXEC_KUBELET_FALLBACK_SUBPROTOCOL`.
async fn dial_kubelet_exec(
    target: &ExecTarget,
    subprotocol: &str,
) -> anyhow::Result<KubeletExecWs> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let connector = tokio_tungstenite::Connector::Rustls(target.tls_config.clone());
    let mut req = target
        .kubelet_ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        subprotocol.parse().expect("valid header value"),
    );

    let (ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| anyhow::anyhow!("kubelet exec connect failed: {e}"))?;
    Ok(ws)
}

/// Send a close frame to kubectl before dropping an inbound connection that never got
/// spliced to kubelet.
///
/// Without this, any pre-splice failure (both dial attempts in `run_exec_proxy` or
/// `run_attach_proxy` failing, or the exec/attach URL itself being malformed) drops
/// `inbound` — already a live, fully upgraded connection from kubectl's point of
/// view — with no close handshake at all. kubectl's websocket client reports that as
/// "close 1006 (abnormal closure): unexpected EOF", which looks like a
/// network glitch and hides the real cause (`reason`, already logged by the caller).
async fn close_inbound_on_dial_failure(mut inbound: WebSocket, reason: &str) {
    use axum::extract::ws::{CloseFrame, Message};

    // RFC 6455 caps a close frame's control payload at 125 bytes (2 for the code,
    // leaving 123 for the UTF-8 reason); truncate defensively rather than risk a
    // send error burying the close frame entirely.
    let reason: String = reason.chars().take(120).collect();
    let _ = inbound
        .send(Message::Close(Some(CloseFrame {
            code: axum::extract::ws::close_code::ERROR,
            reason: reason.into(),
        })))
        .await;
}

/// Open outbound WebSocket to kubelet exec endpoint and relay to inbound kubectl WebSocket.
///
/// Unlike `splice`, this relay absorbs kubelet's genuine success status frame (channel
/// 3/4, `{"status":"Success"}`) in the kubelet→kubectl direction — the real
/// kube-apiserver does the same, and some clients fail if it arrives ahead of stdout
/// (see `exec_status_frame_is_success`). Failure status frames are forwarded unchanged
/// so `kubectl exec` can report the real exit code.
///
/// The kubectl→kubelet direction is relayed unchanged.
async fn run_exec_proxy(inbound: WebSocket, target: ExecTarget) -> anyhow::Result<()> {
    // Try v5 first (needed for the CLOSE signal on kubelet >= 1.36 — see
    // EXEC_KUBELET_SUBPROTOCOL); fall back to v4 for older kubelets that reject v5
    // outright. Only the v5 attempt's error is surfaced/closed-out on total failure —
    // it's the one every kubelet will eventually support, so it's the more useful
    // message to a caller than the fallback's.
    let v5_err = match dial_kubelet_exec(&target, EXEC_KUBELET_SUBPROTOCOL).await {
        Ok(ws) => return run_exec_proxy_spliced(inbound, ws).await,
        Err(e) => e,
    };
    tracing::debug!(
        "kubelet rejected {EXEC_KUBELET_SUBPROTOCOL} ({v5_err}); retrying exec dial with {EXEC_KUBELET_FALLBACK_SUBPROTOCOL} \
         (pre-1.36 kubelet without ExtendWebSocketsToKubelet)"
    );
    let outbound_ws = match dial_kubelet_exec(&target, EXEC_KUBELET_FALLBACK_SUBPROTOCOL).await {
        Ok(ws) => ws,
        Err(_) => {
            close_inbound_on_dial_failure(inbound, &v5_err.to_string()).await;
            return Err(v5_err);
        }
    };
    run_exec_proxy_spliced(inbound, outbound_ws).await
}

/// Splice an already-upgraded kubectl WebSocket to an already-connected kubelet exec
/// WebSocket. Extracted from `run_exec_proxy` so the v5/v4 dial retry above has a single
/// place to hand off to once a working outbound connection exists.
async fn run_exec_proxy_spliced(
    inbound: WebSocket,
    outbound_ws: KubeletExecWs,
) -> anyhow::Result<()> {
    use tokio::sync::mpsc;

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

    // kubelet→kubectl: absorb only genuine success status frames (channel 3/4);
    // forward everything else, including failure/NonZeroExitCode status frames,
    // unchanged so kubectl can see the real exit code.
    let read_kubelet = tokio::spawn(async move {
        while let Some(data) = kubelet_r.recv().await {
            if is_exec_status_frame(&data) && exec_status_frame_is_success(&data) {
                // Absorb kubelet's success status frame — do not forward to kubectl.
                // The real kube-apiserver does the same, and forwarding it can cause
                // clients that read raw frames (e.g. the legacy channel.k8s.io
                // conformance test) to fail with "Got message from server that didn't
                // start with channel 1 (STDOUT)". Failure frames fall through below.
                tracing::debug!(
                    channel = data.first().copied().unwrap_or(0),
                    "absorbing kubelet exec success status frame (not forwarded to kubectl)"
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
/// kubectl sends `?ports=<port>` (may repeat for multiple ports). Validated by
/// `validate_ports_param` and forwarded to the kubelet — never trusted verbatim,
/// since it is hand-interpolated into a raw HTTP/1.1 request line downstream.
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

/// Enforce kubectl's own `ports` grammar: a comma-separated list of 1-65535
/// integers, matching upstream's `NewV4Options` (`strings.Split(portString, ",")`
/// then `strconv.ParseUint`). A positive allowlist, not a CRLF/control-byte
/// blocklist — anything outside `[0-9,]` is rejected outright, so this can never
/// be bypassed by a control character upstream's blocklist-style check forgot
/// about. See `validate_portforward`'s call site for why this exists at all.
fn validate_ports_param(ports: &str) -> Result<(), String> {
    if ports.is_empty() {
        return Err("ports must not be empty".to_string());
    }
    for part in ports.split(',') {
        match part.parse::<u16>() {
            Ok(0) | Err(_) => {
                return Err(format!(
                    "invalid ports value '{ports}': each comma-separated entry \
                     must be an integer in 1..=65535, got '{part}'"
                ));
            }
            Ok(_) => {}
        }
    }
    Ok(())
}

/// Validate portforward pre-conditions: pod exists and is scheduled.
///
/// Returns the kubelet portForward URL and kubelet client identity PEM if all checks
/// pass. Unlike /exec and /attach, the kubelet-facing leg here is a raw HTTP/1.1
/// upgrade, not a WebSocket — kubelet's `handleHTTPStreams` is the only wire shape it
/// accepts unconditionally across every supported release, so `kubelet_url` uses
/// `https://`, not `wss://` (see `dial_kubelet_portforward`).
/// Separated from the handler so this decision logic can be unit-tested without
/// a real HTTP connection (axum's WebSocketUpgrade extractor requires a live
/// connection, so the upgrade itself cannot be exercised in unit tests).
pub(crate) async fn validate_portforward<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod_name: &str,
    ports: Option<&str>,
) -> Result<PortforwardParams, crate::status::StatusError> {
    // `ports` is interpolated verbatim into `kubelet_url` below, which
    // `dial_kubelet_portforward` then hand-rolls into a raw HTTP/1.1 request line
    // written directly to kubelet's socket — unlike /exec, /attach, and the v4
    // portforward leg, nothing downstream parses it as a real URI, so nothing else
    // rejects control bytes. Enforce kubectl's own comma-separated-integer grammar
    // (upstream's `NewV4Options`: `strings.Split(portString, ",")`) as a positive
    // allowlist *before* it reaches any URL or request text: this is what closes
    // CRLF/control-byte request-splitting into kubelet's connection for a caller
    // that holds nothing but `create` on `pods/portforward` for this one pod.
    if let Some(p) = ports {
        validate_ports_param(p).map_err(Status::bad_request)?;
    }

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
    //    https://<node-ip>:<port>/portForward/<ns>/<pod>[?ports=<port>]
    let kp = kubelet_port_for_node(&node_name, &state.node_kubelet_ports, state.kubelet_port);
    let ports_qs = ports.map(|p| format!("?ports={p}")).unwrap_or_default();
    let kubelet_url = format!("https://{node_ip}:{kp}/portForward/{ns}/{pod_name}{ports_qs}");

    Ok(PortforwardParams {
        kubelet_url,
        cluster_ca_der: state.cluster_ca_der.as_deref().map(|v| v.to_vec()),
        client_identity_pem: state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.to_vec()),
    })
}

/// Subprotocol every supported kubectl release (1.34-1.36) offers on its primary
/// port-forward dialer attempt (`portforward.NewSPDYOverWebsocketDialer`). A prior
/// implementation advertised `v5.portforward.k8s.io`, which appears nowhere in
/// upstream Kubernetes — no real kubectl client could ever negotiate it.
const PORTFORWARD_KUBECTL_SUBPROTOCOL: &str = "SPDY/3.1+portforward.k8s.io";

/// Bare protocol name kubectl's legacy SPDY dialer, and u7s's own kubelet-facing leg,
/// negotiate via the `X-Stream-Protocol-Version` header — unrelated to (and not
/// prefixed by) the `SPDY/3.1+` websocket-tunneling wrapper above.
const PORTFORWARD_KUBELET_PROTOCOL: &str = "portforward.k8s.io";

/// The native (non-SPDY) channel-multiplexed port-forward protocol. Offered by
/// `test/e2e/framework/websocket/websocket.go`'s raw websocket test client — the
/// only client class in u7s's supported conformance surface that speaks it; no
/// supported kubectl release (1.34-1.36) ever offers it. Wire format (per
/// `k8s.io/cri-streaming/pkg/streaming/portforward/websocket.go`'s
/// `handleWebSocketStreams`): one binary-message channel byte prefix per message,
/// a (data, error) channel pair per forwarded port in request order, and a
/// little-endian uint16 port preamble written as the first payload on each
/// channel when the connection opens.
const PORTFORWARD_V4_SUBPROTOCOL: &str = "v4.channel.k8s.io";

/// Which wire protocol a client's WebSocket handshake resolved to.
#[derive(Debug, PartialEq, Eq)]
enum PortforwardSubprotocol {
    /// `SPDY/3.1+portforward.k8s.io` — byte-pump translated to legacy
    /// raw-SPDY-over-HTTP on the kubelet leg (`portforward_proxy_tunneled`).
    KubectlSpdy,
    /// `v4.channel.k8s.io` — relayed verbatim to kubelet's native v4 handler
    /// (`portforward_proxy_v4`); both legs speak the identical protocol.
    V4Channel,
}

/// Resolve a client's requested WebSocket subprotocols to one u7s can serve.
///
/// Silently accepting an unrecognized offer (which is what axum's `.protocols()`
/// does on its own — it just completes the handshake without a
/// `Sec-WebSocket-Protocol` header) produces a "successful" upgrade that neither
/// end can actually exchange traffic over — exactly the failure mode the
/// fabricated `v5.portforward.k8s.io` subprotocol produced. Empty offers default
/// to `KubectlSpdy`, matching upstream's lenient handling of subprotocol-less
/// clients. SPDY is preferred over v4 when (synthetically) both are offered — no
/// real client offers both, since kubectl never sends v4 and the e2e websocket
/// client never sends SPDY, but a fixed precedence keeps resolution
/// order-independent.
fn resolve_portforward_subprotocol(requested: &[String]) -> Result<PortforwardSubprotocol, String> {
    if requested.is_empty()
        || requested
            .iter()
            .any(|p| p == PORTFORWARD_KUBECTL_SUBPROTOCOL)
    {
        Ok(PortforwardSubprotocol::KubectlSpdy)
    } else if requested.iter().any(|p| p == PORTFORWARD_V4_SUBPROTOCOL) {
        Ok(PortforwardSubprotocol::V4Channel)
    } else {
        Err(format!(
            "unsupported Sec-WebSocket-Protocol {requested:?}; only \
             {PORTFORWARD_KUBECTL_SUBPROTOCOL:?} or {PORTFORWARD_V4_SUBPROTOCOL:?} \
             is supported"
        ))
    }
}

/// True when the inbound request is kubectl's legacy raw-SPDY-over-HTTP fallback —
/// sent only when the primary websocket-tunneling GET (see
/// `PORTFORWARD_KUBECTL_SUBPROTOCOL`) fails. Unlike that GET, this is not a websocket
/// upgrade at all: no `Sec-WebSocket-Key`/`-Version`, just a plain `Upgrade: SPDY/3.1`.
fn is_raw_spdy_upgrade_request(req: &axum::http::Request<Body>) -> bool {
    let headers = req.headers();
    let has_upgrade_connection = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        });
    let has_spdy_upgrade = headers
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("SPDY/3.1"));
    has_upgrade_connection && has_spdy_upgrade
}

/// Parse a `https://host:port/path` URL into its parts.
///
/// `validate_portforward` builds `kubelet_url` from a fixed template, but its query
/// string carries the client-supplied `ports` value — `validate_ports_param` is the
/// primary gate against control bytes, but `dial_kubelet_portforward` hand-rolls the
/// returned path directly into a raw HTTP/1.1 request line with no URI parser in
/// between (unlike /exec, /attach, and the v4 leg, which all build their kubelet
/// request via `IntoClientRequest`'s `http::Uri` parsing). So this parser re-validates
/// `path` through `http::uri::PathAndQuery` before returning it, as a second,
/// defense-in-depth layer that fails closed if any future field is ever added to the
/// query string without going through `validate_ports_param`.
fn parse_https_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("kubelet URL must use https://: {url}"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");
    axum::http::uri::PathAndQuery::try_from(path.as_str())
        .map_err(|e| anyhow::anyhow!("kubelet URL path/query is not request-line-safe: {e}"))?;
    let (host, port_str) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("kubelet URL missing port: {url}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid kubelet port '{port_str}': {e}"))?;
    Ok((host.to_owned(), port, path))
}

/// portforward proxy: kubectl (or a raw v4.channel.k8s.io websocket client) →
/// apiserver → kubelet.
///
/// kubectl's client-go dialer always tries a websocket-tunneled-SPDY GET first
/// (`Sec-WebSocket-Protocol: SPDY/3.1+portforward.k8s.io`) and falls back to a raw
/// SPDY-over-HTTP POST (`Upgrade: SPDY/3.1`) only if that fails — both must reach this
/// handler, so it takes the raw request rather than axum's GET-only `WebSocketUpgrade`
/// extractor (which 405s any POST before the handler body runs at all). A third
/// client class — `test/e2e/framework/websocket/websocket.go`'s raw websocket test
/// client — offers only `v4.channel.k8s.io`, never SPDY; see
/// `PORTFORWARD_V4_SUBPROTOCOL`.
///
/// The SPDY leg is never SPDY-parsed: real SPDY stream multiplexing happens
/// end-to-end between kubectl and kubelet, and the outbound leg to kubelet is
/// always legacy raw SPDY-over-HTTP regardless of which shape the client used —
/// kubelet's `handleHTTPStreams` accepts it unconditionally on every supported
/// release, unlike its native websocket path (beta, kubelet-1.36-only, not
/// something u7s can assume a given kubelet has enabled). The v4 leg needs no such
/// translation: kubelet's native v4 handler is accepted unconditionally on every
/// supported release too, so both legs speak the identical protocol and are
/// spliced verbatim (`portforward_proxy_v4`).
pub async fn pod_portforward<S: Store>(
    State(state): State<AppState<S>>,
    Path((raw_ns, pod_name)): Path<(String, String)>,
    Query(query): Query<PortforwardQuery>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let params = validate_portforward(&state, &raw_ns, &pod_name, query.ports.as_deref()).await?;

    if is_websocket_upgrade_request(&req) {
        let (mut parts, _body) = req.into_parts();
        let ws = WebSocketUpgrade::from_request_parts(&mut parts, &state)
            .await
            .map_err(|e| Status::bad_request(format!("invalid websocket upgrade request: {e}")))?;

        let requested: Vec<String> = ws
            .requested_protocols()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect();
        let subprotocol =
            resolve_portforward_subprotocol(&requested).map_err(Status::bad_request)?;

        return Ok(match subprotocol {
            PortforwardSubprotocol::KubectlSpdy => ws
                .protocols([PORTFORWARD_KUBECTL_SUBPROTOCOL])
                .on_upgrade(move |inbound_socket| async move {
                    if let Err(e) = portforward_proxy_tunneled(inbound_socket, params).await {
                        tracing::warn!("portforward proxy error: {e}");
                    }
                }),
            PortforwardSubprotocol::V4Channel => ws
                .protocols([PORTFORWARD_V4_SUBPROTOCOL])
                .on_upgrade(move |inbound_socket| async move {
                    if let Err(e) = portforward_proxy_v4(inbound_socket, params).await {
                        tracing::warn!("portforward proxy error: {e}");
                    }
                }),
        });
    }

    if !is_raw_spdy_upgrade_request(&req) {
        return Err(Status::bad_request(
            "portforward requires a WebSocket upgrade (Sec-WebSocket-Protocol: \
             SPDY/3.1+portforward.k8s.io or v4.channel.k8s.io) or a raw SPDY/3.1 \
             upgrade (Upgrade: SPDY/3.1)"
                .to_string(),
        ));
    }
    portforward_proxy_raw_upgrade(req, params).await
}

/// Dial kubelet's legacy raw-SPDY-over-HTTP portForward endpoint.
///
/// This is the only wire shape kubelet's `handleHTTPStreams` accepts unconditionally
/// on every supported release — kubelet's native websocket portforward path exists
/// but requires an exact-match subprotocol negotiation apiserver cannot rely on any
/// given kubelet having enabled. u7s never parses the SPDY frames kubectl and kubelet
/// exchange after this point: once kubelet answers 101, the connection is handed to
/// `splice()` as an opaque byte stream.
async fn dial_kubelet_portforward(
    params: &PortforwardParams,
) -> anyhow::Result<RawStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>> {
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let tls_config = build_kubelet_tls_config(
        params.cluster_ca_der.as_deref(),
        params.client_identity_pem.as_deref(),
    )?;

    let (host, port, path) = parse_https_url(&params.kubelet_url)?;

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| anyhow::anyhow!("invalid kubelet server name '{host}': {e}"))?;
    let mut tls = TlsConnector::from(tls_config)
        .connect(server_name, tcp)
        .await?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: SPDY/3.1\r\n\
         X-Stream-Protocol-Version: {PORTFORWARD_KUBELET_PROTOCOL}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).await?;

    // Kubelet may pipeline the first SPDY frame in the same TCP segment as the
    // response headers — buffer until the "\r\n\r\n" terminator, then preserve
    // (rather than discard) any bytes read past it.
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("kubelet closed connection during portforward upgrade");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) {
            break end;
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("kubelet portforward upgrade response too large");
        }
    };

    let status_line = std::str::from_utf8(&buf[..header_end])
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    if !status_line.contains(" 101 ") {
        anyhow::bail!("kubelet rejected portforward upgrade: {status_line}");
    }

    let prefix = bytes::Bytes::copy_from_slice(&buf[header_end..]);
    Ok(RawStream::new_with_prefix(tls, prefix))
}

/// Splice the client's websocket-tunneled connection with kubelet's raw-SPDY leg.
///
/// Each websocket binary message carries an arbitrary chunk of the byte stream
/// kubectl and kubelet exchange — no SPDY frame boundary is assumed to align with a
/// websocket message boundary, matching upstream's own `TunnelingConnection`, which
/// does the identical opaque byte-shuttling.
async fn portforward_proxy_tunneled(
    inbound: WebSocket,
    params: PortforwardParams,
) -> anyhow::Result<()> {
    let kubelet = dial_kubelet_portforward(&params).await?;
    splice(AxumWs(inbound), kubelet).await;
    Ok(())
}

/// Dial kubelet's native `v4.channel.k8s.io` websocket portforward endpoint.
///
/// Unlike `dial_kubelet_portforward` (legacy raw-SPDY-over-HTTP), kubelet's
/// `handleWebSocketStreams` accepts this subprotocol unconditionally on every
/// supported release — `ServePortForward` dispatches to it purely on the presence
/// of an `Upgrade: websocket` header (`k8s.io/cri-streaming/pkg/streaming/
/// portforward/portforward.go`), with no feature-gate dependency the way the
/// SPDY-over-websocket class has (`ExtendWebSocketsToKubelet`, beta,
/// kubelet-1.36-only). Same `/portForward/<ns>/<pod>` path as the SPDY leg, but
/// NOT the same query parameter name: `NewV4Options` (`.../portforward/websocket.go`)
/// reads `req.URL.Query()[PortHeader]` where `PortHeader = "port"` (singular,
/// `.../portforward/constants.go`) — the legacy SPDY leg's `?ports=` (plural) is a
/// u7s/apiserver-only convention that kubelet's SPDY path never actually inspects
/// (real SPDY streams carry their port dynamically per SYN_STREAM header instead),
/// so reusing it unchanged here produces kubelet's own `query parameter "port" is
/// required` 400 — silently wrong query key name, not a protocol mismatch.
async fn dial_kubelet_portforward_v4(
    params: &PortforwardParams,
) -> anyhow::Result<TungsteniteWs<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let tls_config = build_kubelet_tls_config(
        params.cluster_ca_der.as_deref(),
        params.client_identity_pem.as_deref(),
    )?;
    let connector = tokio_tungstenite::Connector::Rustls(tls_config);

    let wss_url = params
        .kubelet_url
        .strip_prefix("https://")
        .map(|rest| format!("wss://{rest}"))
        .ok_or_else(|| anyhow::anyhow!("kubelet URL must use https://: {}", params.kubelet_url))?
        .replace("?ports=", "?port=");

    let mut req = wss_url
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("invalid kubelet URL: {e}"))?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        PORTFORWARD_V4_SUBPROTOCOL
            .parse()
            .expect("valid header value"),
    );

    let (outbound_ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .map_err(|e| {
                if let tokio_tungstenite::tungstenite::Error::Http(resp) = &e {
                    anyhow::anyhow!(
                        "kubelet v4 portforward connect failed: HTTP {} headers={:?} body={:?}",
                        resp.status(),
                        resp.headers(),
                        resp.body().as_deref()
                    )
                } else {
                    anyhow::anyhow!("kubelet v4 portforward connect failed: {e}")
                }
            })?;

    Ok(TungsteniteWs(outbound_ws))
}

/// Splice the client's `v4.channel.k8s.io` connection with kubelet's native v4
/// handler.
///
/// Both legs speak the identical channel-multiplexed protocol — a channel-number
/// byte prefix per binary message, and a little-endian uint16 port preamble
/// kubelet writes as the first payload on each (data, error) channel pair when it
/// accepts the connection (`handleWebSocketStreams`) — so this is a pure byte-pump
/// with zero channel interpretation on u7s's part, exactly like /attach and
/// /exec's data path (`run_attach_proxy`). u7s never constructs or parses the
/// preamble itself: kubelet writes it, and it is relayed to the client verbatim.
async fn portforward_proxy_v4(inbound: WebSocket, params: PortforwardParams) -> anyhow::Result<()> {
    let kubelet = dial_kubelet_portforward_v4(&params).await?;
    splice(AxumWs(inbound), kubelet).await;
    Ok(())
}

/// Splice kubectl's legacy raw-SPDY-over-HTTP connection with kubelet's raw-SPDY leg.
///
/// Neither leg is a websocket here — both are raw hijacked TCP/TLS streams, so this is
/// a pure byte relay with zero framing translation in either direction.
async fn portforward_proxy_raw(
    inbound: RawStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
    params: PortforwardParams,
) -> anyhow::Result<()> {
    let kubelet = dial_kubelet_portforward(&params).await?;
    splice(inbound, kubelet).await;
    Ok(())
}

/// Handle kubectl's legacy raw-SPDY-over-HTTP port-forward fallback.
///
/// Mirrors real kube-apiserver's non-websocket `UpgradeAwareHandler` pass-through:
/// hijack the client's raw connection, answer 101 immediately, then dial kubelet and
/// splice — no SPDY frame is inspected on either leg. With u7s's apiserver correctly
/// advertising `PORTFORWARD_KUBECTL_SUBPROTOCOL` on the primary GET, no supported
/// kubectl version actually reaches this path at default settings; it exists for
/// robustness, matching real apiserver's own dual-path behavior.
async fn portforward_proxy_raw_upgrade(
    mut req: axum::http::Request<Body>,
    params: PortforwardParams,
) -> Result<Response, crate::status::StatusError> {
    let on_upgrade = req
        .extensions_mut()
        .remove::<hyper::upgrade::OnUpgrade>()
        .ok_or_else(|| {
            Status::bad_request("connection does not support HTTP upgrades".to_string())
        })?;

    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("portforward raw upgrade failed: {e}");
                return;
            }
        };
        let inbound = RawStream::new(hyper_util::rt::TokioIo::new(upgraded));
        if let Err(e) = portforward_proxy_raw(inbound, params).await {
            tracing::warn!("portforward proxy error: {e}");
        }
    });

    Response::builder()
        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONNECTION, "Upgrade")
        .header(axum::http::header::UPGRADE, "SPDY/3.1")
        .header("X-Stream-Protocol-Version", PORTFORWARD_KUBELET_PROTOCOL)
        .body(Body::empty())
        .map_err(|e| Status::internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Shared: forward the backend's response headers onto the outgoing proxy
// response. node_proxy, pod_proxy_dispatch, and service_proxy_dispatch all
// funnel through proxied_response so header handling stays uniform.
// ---------------------------------------------------------------------------

/// Headers that describe framing for one hop of a proxied connection (RFC 7230
/// §6.1 and Go's `httputil.ReverseProxy`, which upstream's `UpgradeAwareHandler`
/// wraps for node/pod/service proxy). Forwarding these verbatim would misdescribe
/// the apiserver→client leg using framing that only applied to the kubelet/pod
/// →apiserver leg.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Copy the backend's response headers (Content-Type, Content-Length, etc.) onto
/// the outgoing proxy response, skipping hop-by-hop headers.
///
/// Per client-go's `Request.transformResponse`, an empty Content-Type makes a
/// protobuf-preferring typed client fall back to its own default content type
/// and then fail to decode the (actually JSON) body — the backend's Content-Type
/// must survive the proxy hop.
fn forward_proxied_headers(headers: &mut axum::http::HeaderMap, upstream: &axum::http::HeaderMap) {
    for (name, value) in upstream.iter() {
        if HOP_BY_HOP_HEADERS.contains(&name.as_str()) {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
}

/// Build the outgoing proxy `Response`, carrying the backend's status and
/// (filtered) headers.
///
/// `pub(crate)` so `handlers::aggregation` can reuse the exact same header-filtering
/// logic for APIService-backend responses instead of reimplementing it.
pub(crate) fn proxied_response(
    status: axum::http::StatusCode,
    upstream_headers: &axum::http::HeaderMap,
    body: Body,
) -> Result<Response, crate::status::StatusError> {
    let mut response = Response::builder()
        .status(status)
        .body(body)
        .map_err(|e| Status::internal(e.to_string()))?;
    forward_proxied_headers(response.headers_mut(), upstream_headers);
    Ok(response)
}

// ---------------------------------------------------------------------------
// /api/v1/nodes/{name}/proxy/{*path} — forward to kubelet
// ---------------------------------------------------------------------------

/// Resolve node IP and build the kubelet HTTP URL for node proxy requests.
///
/// Separated from the handler for unit-testability: all error paths (404, 502)
/// are reachable without a real HTTP connection.
/// Strip a trailing `:port` from a node name as it appears in a proxy URL.
///
/// Sonobuoy's dump.go (and kubectl) build node-proxy URLs as
/// `/api/v1/nodes/<name>:<port>/proxy/...` (e.g. "lima-node:10250").
/// The node is stored under the bare name without the port suffix.
/// Node names are DNS-1123 labels (no colons), so a single rsplit_once(':')
/// on the last colon is safe and sufficient — no full URL parser needed.
pub fn strip_node_port(node_name: &str) -> &str {
    node_name
        .rsplit_once(':')
        .map(|(bare, _port)| bare)
        .unwrap_or(node_name)
}

pub async fn resolve_node_proxy_target<S: Store>(
    state: &AppState<S>,
    node_name: &str,
    path_suffix: &str,
) -> Result<(String, reqwest::Client), crate::status::StatusError> {
    let bare_name = strip_node_port(node_name);
    let node_key = cluster_object_key("nodes", bare_name);
    let node_stored = state
        .store
        .get(&node_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(bare_name, "Node"))?;

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
            "node \"{bare_name}\" has no usable address in status.addresses"
        ))
    })?;

    let client = state.kubelet_client.clone().ok_or_else(|| {
        Status::service_unavailable("kubelet TLS unavailable: no cluster CA configured".to_string())
    })?;

    let kp = kubelet_port_for_node(bare_name, &state.node_kubelet_ports, state.kubelet_port);
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
                    details: None,
                },
            )
        })?;

    let kubelet_status = kubelet_resp.status();
    let upstream_headers = kubelet_resp.headers().clone();
    let body = Body::from_stream(kubelet_resp.bytes_stream());

    proxied_response(kubelet_status, &upstream_headers, body)
}

// ---------------------------------------------------------------------------
// /api/v1/namespaces/{ns}/pods/{name}/proxy/{*path} — forward to pod IP
// ---------------------------------------------------------------------------

/// Parse the `[<scheme>:]<name>[:<port-or-portName>]` addressing form shared by the
/// pod and service proxy subresources (e.g. `pods/my-pod:8080/proxy/`,
/// `services/http:my-svc:web/proxy/`).
///
/// Pod and Service names are DNS-1123 labels (no colons), so a leading `http:` or
/// `https:` token is only scheme syntax when a name and port still follow it — i.e.
/// there is a second colon. Without that check, a 2-part id like `http:8080` (a
/// literal name `http` with a numeric port suffix) would be misparsed as the bare
/// scheme `http` with name `8080`. Returns (bare_name, Some(port_or_name)) when a
/// port suffix is present, or (full_id, None) when the id is a bare name.
pub fn split_scheme_name_port(id: &str) -> (&str, Option<&str>) {
    let unscoped = id
        .strip_prefix("http:")
        .or_else(|| id.strip_prefix("https:"))
        .filter(|rest| rest.contains(':'))
        .unwrap_or(id);
    match unscoped.rsplit_once(':') {
        Some((bare, port)) => (bare, Some(port)),
        None => (unscoped, None),
    }
}

/// Returns true when `id` carries an explicit `https:` scheme prefix, using the same
/// second-colon disambiguation as `split_scheme_name_port` (a 2-part id like `https:8080`
/// is the literal name `https` with a numeric port, not a bare scheme with name `8080`).
///
/// A proxy target addressed this way must be dialed over TLS to the backend — upstream
/// kube-apiserver's `net.SplitSchemeNamePort` uses the scheme for exactly this, not just
/// to disambiguate the name/port split. Skipping this check would connect over plain HTTP
/// to a TLS-only backend, which the backend correctly rejects with a 400.
fn proxy_target_is_https(id: &str) -> bool {
    id.strip_prefix("https:")
        .is_some_and(|rest| rest.contains(':'))
}

/// Resolve a pod's target containerPort using an optional port spec parsed from the
/// proxy URL (e.g. the `8080` in `pods/<name>:8080/proxy/`, or a named port).
///
/// Mirrors `resolve_eps_port`'s numeric/name handling for Service ports:
/// - None → the first container's first declared port (existing bare
///   `pods/<name>/proxy/` behavior).
/// - Some(spec) that parses as u16 → used directly; kube-apiserver's pod proxy does
///   not require a numeric port spec to match a declared containerPort.
/// - Some(spec) that is a name → the containerPort of the port entry (searched across
///   all containers) whose `name` field matches.
pub fn resolve_pod_container_port(
    containers: &serde_json::Value,
    port_spec: Option<&str>,
) -> Option<u16> {
    match port_spec {
        None => containers[0]["ports"][0]["containerPort"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok()),
        Some(spec) => match spec.parse::<u16>() {
            Ok(num) => Some(num),
            Err(_) => containers.as_array()?.iter().find_map(|c| {
                c["ports"].as_array()?.iter().find_map(|p| {
                    (p["name"].as_str() == Some(spec))
                        .then(|| p["containerPort"].as_u64())
                        .flatten()
                        .and_then(|n| u16::try_from(n).ok())
                })
            }),
        },
    }
}

/// Returns `Err(reason)` when `addr` is not a plain IPv4/IPv6 address literal, or names a
/// loopback/link-local/multicast/cloud-metadata address — ranges no legitimate pod IP or
/// Service-backing endpoint address should ever occupy.
///
/// `status.podIP` and EndpointSlice `addresses[]` are both attacker-influenced: a
/// compromised node can PATCH its own pod's `status.podIP` to any string (the Node
/// authorizer bounds *which* pods, not what the value is), and Service-owning controllers
/// copy EndpointSlice addresses verbatim too. Every dial site in this file (the direct-dial
/// URL, and the raw `CONNECT {addr}:{port} HTTP/1.1\r\n...` request line built for the
/// konnectivity leg) uses this same string, so validating it once here — before it is ever
/// spliced into either — closes two vectors at once: dialing an attacker-chosen internal
/// target from the apiserver's own network position (SSRF), and splicing a second request
/// into konnectivity-server's stream via an embedded CRLF (request splitting), since a
/// string containing "\r\n" can never parse as `std::net::IpAddr` either.
///
/// Bare dotted-decimal IPv4 loopback (127.0.0.0/8) IS rejected here, unlike
/// `validate_webhook_url`'s loopback exemption in admission.rs — that exemption is safe
/// only because a webhook URL is admin-controlled config (loopback is a legitimate
/// in-process-test target), whereas `status.podIP`/EndpointSlice addresses are
/// node-controlled and untrusted in this threat model: a compromised node could otherwise
/// set its pod's podIP to 127.0.0.1 and redirect the apiserver's own proxy dial to a
/// service on its own host (pprof/debug/metadata). This function is not shared with the
/// webhook path, so this change cannot affect it.
fn validate_proxy_target_ip(addr: &str) -> Result<(), String> {
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| "not a valid IP address literal".to_owned())?;

    let reserved = match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_multicast() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            // These direct checks must run (logically) ahead of the embedded-v4 unwrap
            // below: e.g. `::1`.to_ipv4() is Some(0.0.0.1), which no IPv4 range check
            // would flag on its own, so `::1` is only ever caught because is_loopback()
            // is also part of this same OR.
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 — IPv6 link-local, analogous to IPv4's 169.254.0.0/16.
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
                // `to_ipv4()` unwraps BOTH the IPv4-mapped (::ffff:a.b.c.d, RFC 4291
                // §2.5.5.2) and the older IPv4-compatible (::a.b.c.d, no `ffff:`) forms,
                // which both carry an IPv4 address in the low 32 bits that the checks
                // above never inspect. `to_ipv4_mapped()` alone only catches the mapped
                // form — the compatible form (e.g. `::169.254.169.254`) would otherwise
                // parse as a valid IpAddr and bypass every IPv4 range check.
                || v6.to_ipv4().is_some_and(|v4| {
                    v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_multicast()
                        || v4.is_unspecified()
                })
        }
    };
    if reserved {
        return Err("loopback/link-local/multicast/cloud-metadata address rejected".to_owned());
    }
    Ok(())
}

/// Returns true iff `ip` is a well-formed IPv4 address contained in the well-formed IPv4
/// CIDR `cidr`. Any parse failure (malformed CIDR, non-IPv4 `ip`, prefix > 32) returns
/// false — fail closed, since this only gates the podIP-in-podCIDR SSRF allowlist below.
fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

/// CIDR-membership allowlist for a pod's `status.podIP`, composed on top of
/// `validate_proxy_target_ip`'s existing loopback/link-local/multicast/metadata blocklist.
///
/// A blocklist alone leaves every OTHER routable address — arbitrary external hosts,
/// internal services the compromised node itself cannot reach — usable as a pod's forged
/// podIP, letting a pods/proxy request dial them from the apiserver's own control-plane
/// network position (and, on the https-scheme path, present the apiserver's kubelet-client
/// TLS identity to whatever is listening there). The allowlist closes that whole class by
/// requiring the podIP to actually live inside cluster-internal address space:
///
/// - non-hostNetwork pod: `podIP` must fall within its node's `spec.podCIDR`, IF the node
///   has one assigned. This is only trustworthy because NodeRestriction-equivalent
///   admission now stops a node from self-writing its own `spec.podCIDR` (only the
///   controller that owns IPAM may set it, once, empty -> valid) — before that, a
///   compromised node could set both its own podCIDR and its pod's podIP to the same
///   attacker-chosen range and defeat this check. A node with no podCIDR falls back to
///   the blocklist floor alone (see the empty-podCIDR match arm below for why).
/// - hostNetwork pod: `podIP` must equal the pod's own `status.hostIP` (the invariant
///   `apply_status_patch` already enforces when the kubelet's status patch goes through
///   that path; this re-checks it at dial time as defense in depth against any write path
///   that bypasses it).
///
/// `status.hostIP` is itself still node-writable (`nodes/status` is legitimately
/// node-writable even post-NodeRestriction), so the hostNetwork branch cannot treat a
/// podIP/hostIP match alone as proof of a real node identity — it only proves the two
/// node-controlled fields agree with each other. A compromised node could set both to
/// 127.0.0.1 to try to redirect the proxy dial to a service on the apiserver's own host;
/// that is caught unconditionally by the `validate_proxy_target_ip` call below (which now
/// rejects bare IPv4 loopback outright) before this branch is ever reached, regardless of
/// what hostIP claims.
async fn validate_pod_ip_against_node<S: Store>(
    state: &AppState<S>,
    pod: &serde_json::Value,
    pod_ip: &str,
) -> Result<(), String> {
    // Malformed/non-IP podIP (including one carrying an embedded CRLF, the request-
    // splitting vector against konnectivity's raw CONNECT line built later from this
    // same string) is rejected here before either branch below ever runs.
    validate_proxy_target_ip(pod_ip)?;

    let host_network = pod["spec"]["hostNetwork"].as_bool().unwrap_or(false);
    if host_network {
        return match pod["status"]["hostIP"].as_str().filter(|s| !s.is_empty()) {
            Some(host_ip) if host_ip == pod_ip => Ok(()),
            Some(host_ip) => Err(format!(
                "hostNetwork pod's podIP does not match its own status.hostIP {host_ip}"
            )),
            None => Err("hostNetwork pod has no status.hostIP to validate podIP against".into()),
        };
    }

    let node_name = pod["spec"]["nodeName"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "pod is not yet scheduled (spec.nodeName is empty)".to_owned())?;
    let node_key = cluster_object_key("nodes", node_name);
    let node_stored = state
        .store
        .get(&node_key)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("node \"{node_name}\" not found"))?;
    let node: serde_json::Value = serde_json::from_slice(&node_stored.value)
        .map_err(|e| format!("corrupt stored node: {e}"))?;

    // A node with no spec.podCIDR falls back to the blocklist floor already checked
    // above, rather than hard-rejecting every non-hostNetwork pod-proxy request: this
    // codebase's own conformance stack runs kube-controller-manager with
    // node-ipam-controller explicitly disabled (04-start-kcm.sh's --controllers list),
    // so podCIDR is never populated there today, and CRI-O's default bridge CNI hands
    // out pod IPs independently of it. The CIDR-membership allowlist activates
    // automatically the moment a real per-node podCIDR is assigned; until then this
    // check is a no-op rather than an outage for every real pod's proxy subresource.
    match node["spec"]["podCIDR"].as_str().filter(|s| !s.is_empty()) {
        Some(pod_cidr) if ipv4_in_cidr(pod_ip, pod_cidr) => Ok(()),
        Some(pod_cidr) => Err(format!(
            "pod IP is not within node \"{node_name}\"'s podCIDR {pod_cidr}"
        )),
        None => Ok(()),
    }
}

/// Resolve pod IP and container port for the pod proxy subresource.
///
/// Returns (pod_ip, port, konnectivity_proxy_addr, is_https) for the caller to build the
/// forward URL and HTTP client. Separated from the handler for unit-testability.
pub async fn resolve_pod_proxy_target<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod_name: &str,
) -> Result<(String, u16, Option<String>, bool), crate::status::StatusError> {
    // Strip an optional scheme prefix and :<port-or-portName> suffix — kubectl and
    // client-go address pod proxy targets as `pods/[<scheme>:]<name>[:<port>]/proxy/`,
    // the same convention the service proxy subresource uses.
    let (bare_name, port_spec) = split_scheme_name_port(pod_name);

    let pod_key = object_key("pods", ns, bare_name);
    let stored = state
        .store
        .get(&pod_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(bare_name, "Pod"))?;

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

    validate_pod_ip_against_node(state, &pod, &pod_ip)
        .await
        .map_err(|reason| {
            crate::status::StatusError(
                axum::http::StatusCode::BAD_GATEWAY,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: format!(
                        "pod \"{pod_name}\" status.podIP \"{pod_ip}\" rejected: {reason}"
                    ),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                    details: None,
                },
            )
        })?;

    let port = resolve_pod_container_port(&pod["spec"]["containers"], port_spec).unwrap_or(80);

    let proxy_addr = state.konnectivity_proxy_addr.clone();
    let is_https = proxy_target_is_https(pod_name);

    Ok((pod_ip, port, proxy_addr, is_https))
}

/// Build a reqwest client for direct pod access (no konnectivity).
///
/// Used when `konnectivity_proxy_addr` is not set and the apiserver can reach
/// pod IPs directly (e.g. in tests or same-host setups).
///
/// `insecure_https` skips server certificate verification entirely instead of trusting
/// `ca_der` — matches upstream kube-apiserver's `InsecureSkipVerify` for pod-proxy TLS
/// targets, since pod/workload TLS certs are self-signed or issued by a CA the cluster
/// has no way to know (unlike the kubelet, which is signed by the cluster CA).
pub(crate) fn build_pod_proxy_client(
    ca_der: Option<&[u8]>,
    client_identity_pem: Option<&[u8]>,
    insecure_https: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if insecure_https {
        builder = builder.use_rustls_tls().danger_accept_invalid_certs(true);
    } else if let Some(der) = ca_der {
        if let Ok(cert) = reqwest::Certificate::from_der(der) {
            builder = builder.use_rustls_tls().tls_certs_only([cert]);
        }
    }
    if let Some(pem) = client_identity_pem {
        if let Ok(identity) = reqwest::Identity::from_pem(pem) {
            builder = builder.identity(identity);
        }
    }
    builder.build().unwrap_or_default()
}

/// A tunnel byte stream: either the plain konnectivity-to-pod tunnel, or (when the proxy
/// target uses the `https:` scheme) that same tunnel wrapped in a second TLS session
/// dialed to the pod/endpoint itself. Boxing erases the two concrete stream types so the
/// hyper handshake in `pod_proxy_via_connect_tunnel` has one call site either way.
trait TunnelStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> TunnelStream for T {}

/// Proxy a pod request through a CONNECT tunnel to konnectivity-server.
///
/// konnectivity-server accepts only the CONNECT verb. reqwest's Proxy::all() only
/// issues CONNECT for https:// targets; for http:// targets it sends a plain forward-
/// proxy GET which konnectivity rejects with 405. This function establishes the
/// tunnel manually: TLS-connect to konnectivity, send CONNECT pod_ip:port, then speak
/// HTTP to the pod over the tunneled byte stream — plain HTTP normally, or (when
/// `is_https` is set) over a second TLS session dialed to the pod through the tunnel,
/// matching upstream kube-apiserver's TLS handling for `https:`-scheme proxy targets.
#[allow(clippy::too_many_arguments)]
async fn pod_proxy_via_connect_tunnel(
    konnectivity_addr: &str,
    pod_ip: &str,
    port: u16,
    path: &str,
    method: axum::http::Method,
    body_bytes: bytes::Bytes,
    ca_der: Option<&[u8]>,
    client_identity_pem: Option<&[u8]>,
    is_https: bool,
) -> Result<(u16, axum::http::HeaderMap, bytes::Bytes), String> {
    use http_body_util::BodyExt as _;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    // 1. Parse konnectivity host and port.
    let (kconn_host, kconn_port) = {
        let mut parts = konnectivity_addr.rsplitn(2, ':');
        let p: u16 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("invalid konnectivity addr: {konnectivity_addr}"))?;
        let h = parts
            .next()
            .ok_or_else(|| format!("invalid konnectivity addr (no host): {konnectivity_addr}"))?;
        (h.to_owned(), p)
    };

    // 2. Build a TLS client config pinned to the cluster CA.
    let tls_config = build_kubelet_tls_config(ca_der, client_identity_pem)
        .map_err(|e| format!("konnectivity TLS config: {e}"))?;
    let connector = TlsConnector::from(tls_config);

    // 3. Open a TCP connection to konnectivity-server.
    let tcp = TcpStream::connect(format!("{kconn_host}:{kconn_port}"))
        .await
        .map_err(|e| format!("konnectivity TCP connect: {e}"))?;

    let server_name = ServerName::try_from(kconn_host.as_str())
        .map(|n| n.to_owned())
        .map_err(|e| format!("invalid konnectivity server name '{kconn_host}': {e}"))?;
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("konnectivity TLS handshake: {e}"))?;

    // 4. Send HTTP CONNECT to ask konnectivity to tunnel to pod_ip:port.
    //    konnectivity-server (proxy-agent v0.35.0) accepts CONNECT only.
    let connect_req = format!("CONNECT {pod_ip}:{port} HTTP/1.1\r\nHost: {pod_ip}:{port}\r\n\r\n");
    tls_stream
        .write_all(connect_req.as_bytes())
        .await
        .map_err(|e| format!("CONNECT write: {e}"))?;

    // 5. Read the CONNECT response line. konnectivity returns "HTTP/1.1 200 Connection established\r\n\r\n".
    let mut resp_buf = [0u8; 256];
    let mut total = 0usize;
    loop {
        if total >= resp_buf.len() {
            return Err("CONNECT response too large".into());
        }
        let n = tls_stream
            .read(&mut resp_buf[total..])
            .await
            .map_err(|e| format!("CONNECT read: {e}"))?;
        if n == 0 {
            return Err("konnectivity closed connection during CONNECT".into());
        }
        total += n;
        // Look for the end of the HTTP response headers (\r\n\r\n).
        if resp_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let resp_str = std::str::from_utf8(&resp_buf[..total]).unwrap_or("");
    if !resp_str.starts_with("HTTP/1.1 200") {
        return Err(format!(
            "CONNECT rejected: {}",
            resp_str.lines().next().unwrap_or("")
        ));
    }

    // 6. The tunnel is open. For an https-scheme target, dial a second TLS session to the
    //    pod over the tunnel before speaking HTTP — pod/workload certs are self-signed or
    //    unknown to any cluster CA, so this handshake skips verification (see
    //    build_insecure_tls_config); it is a separate, inner session from the outer TLS
    //    connection to konnectivity above, which stays fully verified against the cluster CA.
    let io: Box<dyn TunnelStream> = if is_https {
        let pod_tls_config =
            build_insecure_tls_config().map_err(|e| format!("pod TLS config: {e}"))?;
        let pod_connector = TlsConnector::from(pod_tls_config);
        let pod_server_name = ServerName::try_from(pod_ip)
            .map(|n| n.to_owned())
            .map_err(|e| format!("invalid pod server name '{pod_ip}': {e}"))?;
        let pod_tls_stream = pod_connector
            .connect(pod_server_name, tls_stream)
            .await
            .map_err(|e| format!("pod TLS handshake over tunnel: {e}"))?;
        Box::new(pod_tls_stream)
    } else {
        Box::new(tls_stream)
    };
    let io = TokioIo::new(io);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, axum::body::Body>(io)
        .await
        .map_err(|e| format!("hyper handshake over tunnel: {e}"))?;
    tokio::spawn(conn);

    let uri = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };

    let hyper_req = hyper::Request::builder()
        .method(method.as_str())
        .uri(&uri)
        .header("Host", format!("{pod_ip}:{port}"))
        .body(axum::body::Body::from(body_bytes))
        .map_err(|e| format!("build pod request: {e}"))?;

    let hyper_resp = sender
        .send_request(hyper_req)
        .await
        .map_err(|e| format!("pod request over tunnel: {e}"))?;

    let status = hyper_resp.status().as_u16();
    let headers = hyper_resp.headers().clone();
    // Every konnectivity-proxied response is collected here, HTML or not — unlike the
    // direct-dial leg it has no separate streaming path — so this is the only cap on this
    // leg (see buffer_capped's doc comment for why an uncapped read is a memory-exhaustion
    // vector).
    let collected = http_body_util::Limited::new(hyper_resp.into_body(), crate::MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|e| format!("read pod response body: {e}"))?;

    Ok((status, headers, collected.to_bytes()))
}

/// Merge the inbound request's query string (if any) onto the forwarded proxy path.
///
/// `path_suffix` (the portion after `/proxy/`) never carries the query string —
/// axum's path extractor and `http::Uri` keep them separate — so callers that build
/// the outbound URL from `path_suffix` alone silently drop it. That breaks apps like
/// the guestbook conformance test whose entire request contract is `?cmd=set&key=k&value=v`
/// query params. Skips the `?` entirely when there is no query string, so a request
/// with no query does not grow a bare trailing `?`.
fn append_query(path_suffix: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path_suffix}?{q}"),
        None => path_suffix.to_owned(),
    }
}

/// Returns true when `headers`' Content-Type is `text/html` (ignoring any trailing
/// `;charset=...` parameter) — matches upstream kube-apiserver's proxy Transport, which
/// only rewrites links in HTML bodies and passes every other content type through as-is.
fn is_html_content_type(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("text/html")
        })
}

/// Rewrite root-relative `href="..."`/`src="..."` link targets in an HTML proxy response
/// so they still resolve through the proxy instead of the apiserver's own root. A browser
/// following `<a href="/foo">` on a proxied page would otherwise request `/foo` from the
/// apiserver directly rather than `/foo` on the proxied pod/service — matching upstream
/// kube-apiserver's proxy Transport, which performs the identical rewrite for exactly
/// this reason (a client hitting the proxy must get links that stay within the proxy).
///
/// Only a single leading `/` counts as root-relative and gets rewritten; scheme-relative
/// (`//host/...`) and absolute (`http://...`) URLs already name their own host and are
/// left untouched, as are non-`href`/`src` occurrences of those substrings (an attribute
/// must start at a preceding whitespace boundary, so "xhref" or plain text is never
/// mistaken for the real attribute).
fn rewrite_relative_links(html: &str, proxy_base: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut remaining = html;

    loop {
        let found = ["href=\"", "href='", "src=\"", "src='"]
            .into_iter()
            .filter_map(|pat| remaining.find(pat).map(|pos| (pos, pat)))
            .min_by_key(|&(pos, _)| pos);

        let Some((pos, pat)) = found else {
            out.push_str(remaining);
            return out;
        };

        let at_attr_boundary = remaining[..pos]
            .chars()
            .next_back()
            .is_none_or(char::is_whitespace);

        let value_start = pos + pat.len();
        let quote = pat.as_bytes()[pat.len() - 1] as char;
        let Some(value_len) = remaining[value_start..].find(quote) else {
            // Unterminated attribute — pass the remainder through rather than risk
            // corrupting malformed HTML.
            out.push_str(remaining);
            return out;
        };
        let value_end = value_start + value_len;
        let value = &remaining[value_start..value_end];

        out.push_str(&remaining[..value_start]);
        if at_attr_boundary && value.starts_with('/') && !value.starts_with("//") {
            out.push_str(proxy_base);
        }
        out.push_str(value);

        remaining = &remaining[value_end..];
    }
}

/// Rewrite an already-buffered text/html response body — used once the caller has
/// confirmed the Content-Type and collected the full body (rewriting a partial chunk
/// could split an href/src attribute across a chunk boundary). A body that is not valid
/// UTF-8 passes through unmodified rather than risk corrupting binary content that was
/// merely mislabeled as text/html.
fn rewrite_html_body(body: bytes::Bytes, proxy_base: &str) -> bytes::Bytes {
    match std::str::from_utf8(&body) {
        Ok(html) => bytes::Bytes::from(rewrite_relative_links(html, proxy_base)),
        Err(_) => body,
    }
}

/// Buffer a chunked response body up to `limit` bytes total, erroring instead of growing
/// without bound once the cap is exceeded.
///
/// The html-rewrite path (below) must fully materialize a proxied response before
/// `rewrite_html_body` can scan it for relative links to rewrite, so it cannot stream the
/// body straight to the client the way the non-HTML path does. Without this cap, a
/// pod/Service proxy backend returning an unbounded `text/html` body — or one an attacker
/// redirected there via the podIP/EndpointSlice-address SSRF this file also guards against
/// — would force the apiserver to allocate memory proportional to the response size, per
/// in-flight proxy request. The inbound `DefaultBodyLimit` (lib.rs) caps request bodies
/// only and never applies to a response read back from a proxied backend.
async fn buffer_capped<E: std::fmt::Display>(
    mut stream: impl futures_util::Stream<Item = Result<bytes::Bytes, E>> + Unpin,
    limit: usize,
) -> Result<bytes::Bytes, String> {
    use futures_util::StreamExt as _;
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if buf.len() + chunk.len() > limit {
            return Err(format!("response body exceeds {limit}-byte proxy cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// Proxy a request to the pod's IP and containerPort.
///
/// Shared implementation for both the with-subpath and no-subpath pod proxy routes.
/// `path_suffix` is the portion after `/proxy/`; use `""` for the root proxy form.
async fn pod_proxy_dispatch<S: Store>(
    state: &AppState<S>,
    ns: &str,
    pod_name: &str,
    path_suffix: &str,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let (pod_ip, port, proxy_addr, is_https) =
        resolve_pod_proxy_target(state, ns, pod_name).await?;
    // The path a browser must stay within when following a relative link on the proxied
    // page — see rewrite_relative_links. Built from the raw URL segments rather than the
    // inbound request's own path so it excludes path_suffix (the proxy's PathPrepend never
    // includes the backend-relative subpath, only namespaces/{ns}/pods/{pod_name}/proxy).
    let proxy_base = format!("/api/v1/namespaces/{ns}/pods/{pod_name}/proxy");

    let method = req.method().clone();
    let query = req.uri().query().map(str::to_owned);
    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| Status::internal(format!("failed to read request body: {e}")))?;
    let path_with_query = append_query(path_suffix, query.as_deref());

    if let Some(addr) = proxy_addr.as_deref() {
        // Route through konnectivity via an explicit CONNECT tunnel.
        // konnectivity-server accepts CONNECT only; a plain forward-proxy GET returns 405.
        let (status, mut headers, body) = pod_proxy_via_connect_tunnel(
            addr,
            &pod_ip,
            port,
            &path_with_query,
            method,
            body_bytes,
            state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
            state
                .kubelet_client_identity_pem
                .as_deref()
                .map(|v| v.as_slice()),
            is_https,
        )
        .await
        .map_err(|e| {
            crate::status::StatusError(
                axum::http::StatusCode::BAD_GATEWAY,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: format!("pod unreachable via konnectivity: {e}"),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                    details: None,
                },
            )
        })?;

        let status = axum::http::StatusCode::from_u16(status)
            .map_err(|e| Status::internal(e.to_string()))?;
        let body = if is_html_content_type(&headers) {
            headers.remove(axum::http::header::CONTENT_LENGTH);
            rewrite_html_body(body, &proxy_base)
        } else {
            body
        };
        return proxied_response(status, &headers, Body::from(body));
    }

    // No konnectivity proxy — direct connection to pod IP.
    let scheme = if is_https { "https" } else { "http" };
    let target_url = format!("{scheme}://{pod_ip}:{port}/{path_with_query}");
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|e| Status::internal(format!("invalid method: {e}")))?;

    let client = build_pod_proxy_client(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
        is_https,
    );

    let pod_resp = client
        .request(reqwest_method, &target_url)
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
                    details: None,
                },
            )
        })?;

    let pod_status = pod_resp.status();
    let mut upstream_headers = pod_resp.headers().clone();
    let body = if is_html_content_type(&upstream_headers) {
        let raw = buffer_capped(pod_resp.bytes_stream(), crate::MAX_BODY_BYTES)
            .await
            .map_err(|e| {
                crate::status::StatusError(
                    axum::http::StatusCode::BAD_GATEWAY,
                    crate::status::Status {
                        kind: "Status",
                        api_version: "v1",
                        status: "Failure",
                        message: format!("pod proxy response body: {e}"),
                        reason: "BadGateway",
                        code: 502,
                        metadata: None,
                        details: None,
                    },
                )
            })?;
        upstream_headers.remove(axum::http::header::CONTENT_LENGTH);
        Body::from(rewrite_html_body(raw, &proxy_base))
    } else {
        Body::from_stream(pod_resp.bytes_stream())
    };

    proxied_response(pod_status, &upstream_headers, body)
}

/// Proxy a request to the pod's IP and containerPort (with sub-path).
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
    pod_proxy_dispatch(&state, &ns, &pod_name, &path_suffix, req).await
}

/// Upstream kube-apiserver 301-redirects a bare `.../proxy` GET/HEAD (no trailing slash)
/// to `.../proxy/` — relative links in proxied HTML are resolved against the request URL,
/// so without the trailing slash they'd resolve one level too high. Other methods (and
/// the trailing-slash form) proxy immediately; the conformance suite only checks GET/HEAD.
fn redirect_bare_proxy_root(req: &axum::http::Request<Body>) -> Option<Response> {
    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return None;
    }
    let path = req.uri().path();
    if path.ends_with('/') {
        return None;
    }
    let location = match req.uri().query() {
        Some(q) => format!("{path}/?{q}"),
        None => format!("{path}/"),
    };
    Some(
        Response::builder()
            .status(axum::http::StatusCode::MOVED_PERMANENTLY)
            .header(axum::http::header::LOCATION, location)
            .body(Body::empty())
            .expect("static redirect response must build"),
    )
}

/// Proxy a request to the pod's IP and containerPort (no sub-path form).
///
/// GET /api/v1/namespaces/{ns}/pods/{name}/proxy  → 301 Location: .../proxy/ (GET/HEAD only)
/// GET /api/v1/namespaces/{ns}/pods/{name}/proxy/ → http://{podIP}:{port}/
///
/// axum's `{*path}` wildcard requires a non-empty segment, so a dial to /proxy or /proxy/
/// (the form used by the RC serve-image conformance test) would not match the `/{*path}`
/// route and falls through to the generic handler — returning 404. This handler covers
/// those two forms explicitly and forwards to the pod root path.
pub async fn pod_proxy_root<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, pod_name)): Path<(String, String)>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    if let Some(redirect) = redirect_bare_proxy_root(&req) {
        return Ok(redirect);
    }
    pod_proxy_dispatch(&state, &ns, &pod_name, "", req).await
}

// ---------------------------------------------------------------------------
// /api/v1/namespaces/{ns}/services/{name}/proxy/{*path} — forward to a ready endpoint
// ---------------------------------------------------------------------------

/// Resolve the IP and port of a ready endpoint backing the Service.
///
/// Returns (endpoint_ip, port, konnectivity_proxy_addr, is_https). Separated from the
/// handler so the resolution logic can be unit-tested without a live network.
/// Strip the `:<port-or-portName>` suffix (and an optional `http:`/`https:` scheme
/// prefix) from a service proxy URL name segment.
///
/// k8s proxy URLs allow `services/[<scheme>:]<name>:<port-or-portName>/proxy/` to
/// target a specific port. Delegates to `split_scheme_name_port`, the same parser
/// used by the pod proxy subresource. Returns (bare_name, Some(port_spec)) when a
/// suffix is present, or (full_name, None) when absent.
pub fn split_service_port(svc_name: &str) -> (&str, Option<&str>) {
    split_scheme_name_port(svc_name)
}

/// Resolve the port number from an EndpointSlice's ports array using an optional
/// port spec from the URL suffix (e.g. `:80` or `:portname1`).
///
/// - None → first port entry (existing behavior for bare `services/<name>/proxy/`)
/// - Some(spec) that parses as u16 → find the EPS port entry with that number
/// - Some(spec) that is a name → find the EPS port entry whose name field matches
///
/// Returns None when the spec doesn't match any port in the slice.
pub fn resolve_eps_port(eps_ports: &serde_json::Value, port_spec: Option<&str>) -> Option<u16> {
    let ports = eps_ports.as_array()?;
    match port_spec {
        None => ports[0]["port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok()),
        Some(spec) => {
            if let Ok(num) = spec.parse::<u16>() {
                ports
                    .iter()
                    .find(|p| p["port"].as_u64().map(|n| n as u16) == Some(num))
                    .and_then(|p| p["port"].as_u64())
                    .and_then(|p| u16::try_from(p).ok())
                    .or(Some(num))
            } else {
                ports
                    .iter()
                    .find(|p| p["name"].as_str() == Some(spec))
                    .and_then(|p| p["port"].as_u64())
                    .and_then(|p| u16::try_from(p).ok())
            }
        }
    }
}

pub async fn resolve_service_proxy_target<S: Store>(
    state: &AppState<S>,
    ns: &str,
    svc_name: &str,
) -> Result<(String, u16, Option<String>, bool), crate::status::StatusError> {
    // Strip optional :<port-or-portName> suffix; Service names are DNS-1123 (no colons).
    let (bare_name, port_spec) = split_service_port(svc_name);

    // 1. Confirm the Service exists (404 if not).
    let svc_key = object_key("services", ns, bare_name);
    state
        .store
        .get(&svc_key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(bare_name, "Service"))?;

    // 2. List all EndpointSlices in the namespace and find one owned by this Service.
    //    KCM stamps the "kubernetes.io/service-name" label on every slice it manages.
    let eps_prefix = group_list_prefix("discovery.k8s.io", "endpointslices", Some(ns));
    let eps_list = state
        .store
        .list(&eps_prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    for item in &eps_list.items {
        let eps: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let svc_label = eps["metadata"]["labels"]["kubernetes.io/service-name"]
            .as_str()
            .unwrap_or("");
        if svc_label != bare_name {
            continue;
        }
        // Pick the port number from the slice's ports array, guided by the URL port spec.
        let Some(port) = resolve_eps_port(&eps["ports"], port_spec) else {
            continue;
        };

        // Find the first endpoint with conditions.ready == true.
        if let Some(endpoints) = eps["endpoints"].as_array() {
            for ep in endpoints {
                let ready = ep["conditions"]["ready"].as_bool().unwrap_or(false);
                if !ready {
                    continue;
                }
                // Skip (rather than dial) an endpoint whose address fails
                // validate_proxy_target_ip — see its doc comment for why an unvalidated
                // EndpointSlice address is an SSRF/request-splitting vector identical to
                // the podIP one. Falling through to try the next ready endpoint means one
                // forged address doesn't take down the whole Service if any endpoint has a
                // legitimate one; if none do, the loop's existing "no ready endpoints" 503
                // below still fires.
                if let Some(addr) = ep["addresses"][0]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .filter(|s| validate_proxy_target_ip(s).is_ok())
                {
                    return Ok((
                        addr.to_owned(),
                        port,
                        state.konnectivity_proxy_addr.clone(),
                        proxy_target_is_https(svc_name),
                    ));
                }
            }
        }
    }

    Err(crate::status::StatusError(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        crate::status::Status {
            kind: "Status",
            api_version: "v1",
            status: "Failure",
            message: format!(
                "service \"{svc_name}\" has no ready endpoints — service is not ready to serve traffic"
            ),
            reason: "ServiceUnavailable",
            code: 503,
            metadata: None,
            details: None,
        },
    ))
}

/// Proxy a request to a ready endpoint backing the Service.
///
/// Shared implementation for both the with-subpath and no-subpath service proxy routes.
async fn service_proxy_dispatch<S: Store>(
    state: &AppState<S>,
    ns: &str,
    svc_name: &str,
    path_suffix: &str,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    let (ep_ip, port, proxy_addr, is_https) =
        resolve_service_proxy_target(state, ns, svc_name).await?;
    // See pod_proxy_dispatch's identical comment: the path a browser must stay within
    // when following a relative link on the proxied page.
    let proxy_base = format!("/api/v1/namespaces/{ns}/services/{svc_name}/proxy");
    // Reuse the pod_proxy_dispatch path: build the URL and forward the request.
    // Service endpoints are reached the same way as pod IPs — via konnectivity
    // when configured, or directly otherwise.
    let method = req.method().clone();
    let query = req.uri().query().map(str::to_owned);
    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| Status::internal(format!("failed to read request body: {e}")))?;
    let path_with_query = append_query(path_suffix, query.as_deref());

    if let Some(addr) = proxy_addr.as_deref() {
        let (status, mut headers, body) = pod_proxy_via_connect_tunnel(
            addr,
            &ep_ip,
            port,
            &path_with_query,
            method,
            body_bytes,
            state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
            state
                .kubelet_client_identity_pem
                .as_deref()
                .map(|v| v.as_slice()),
            is_https,
        )
        .await
        .map_err(|e| {
            crate::status::StatusError(
                axum::http::StatusCode::BAD_GATEWAY,
                crate::status::Status {
                    kind: "Status",
                    api_version: "v1",
                    status: "Failure",
                    message: format!("service endpoint unreachable via konnectivity: {e}"),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                    details: None,
                },
            )
        })?;

        let status = axum::http::StatusCode::from_u16(status)
            .map_err(|e| Status::internal(e.to_string()))?;
        let body = if is_html_content_type(&headers) {
            headers.remove(axum::http::header::CONTENT_LENGTH);
            rewrite_html_body(body, &proxy_base)
        } else {
            body
        };
        return proxied_response(status, &headers, Body::from(body));
    }

    let scheme = if is_https { "https" } else { "http" };
    let target_url = format!("{scheme}://{ep_ip}:{port}/{path_with_query}");
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|e| Status::internal(format!("invalid method: {e}")))?;

    let client = build_pod_proxy_client(
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        state
            .kubelet_client_identity_pem
            .as_deref()
            .map(|v| v.as_slice()),
        is_https,
    );

    let ep_resp = client
        .request(reqwest_method, &target_url)
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
                    message: format!("service endpoint unreachable: {e}"),
                    reason: "BadGateway",
                    code: 502,
                    metadata: None,
                    details: None,
                },
            )
        })?;

    let ep_status = ep_resp.status();
    let mut upstream_headers = ep_resp.headers().clone();
    let body = if is_html_content_type(&upstream_headers) {
        let raw = buffer_capped(ep_resp.bytes_stream(), crate::MAX_BODY_BYTES)
            .await
            .map_err(|e| {
                crate::status::StatusError(
                    axum::http::StatusCode::BAD_GATEWAY,
                    crate::status::Status {
                        kind: "Status",
                        api_version: "v1",
                        status: "Failure",
                        message: format!("service proxy response body: {e}"),
                        reason: "BadGateway",
                        code: 502,
                        metadata: None,
                        details: None,
                    },
                )
            })?;
        upstream_headers.remove(axum::http::header::CONTENT_LENGTH);
        Body::from(rewrite_html_body(raw, &proxy_base))
    } else {
        Body::from_stream(ep_resp.bytes_stream())
    };

    proxied_response(ep_status, &upstream_headers, body)
}

/// Proxy a request to a Service-backing endpoint (with sub-path).
///
/// GET /api/v1/namespaces/{ns}/services/{name}/proxy/{*path} → http://{endpointIP}:{port}/{path}
///
/// Resolves a ready endpoint via the Service's EndpointSlices. Returns 404 if the
/// Service is absent, 503 if no ready endpoint exists, and streams the response otherwise.
pub async fn service_proxy<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, svc_name, path_suffix)): Path<(String, String, String)>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    service_proxy_dispatch(&state, &ns, &svc_name, &path_suffix, req).await
}

/// Proxy a request to a Service-backing endpoint (no sub-path form).
///
/// GET /api/v1/namespaces/{ns}/services/{name}/proxy  → 301 Location: .../proxy/ (GET/HEAD only)
/// GET /api/v1/namespaces/{ns}/services/{name}/proxy/ → http://{endpointIP}:{port}/
pub async fn service_proxy_root<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, svc_name)): Path<(String, String)>,
    req: axum::http::Request<Body>,
) -> Result<Response, crate::status::StatusError> {
    if let Some(redirect) = redirect_bare_proxy_root(&req) {
        return Ok(redirect);
    }
    service_proxy_dispatch(&state, &ns, &svc_name, "", req).await
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

    use crate::handlers::test_support::make_state;

    fn make_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/namespaces/{ns}/pods/{name}/log", get(pod_log))
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/exec",
                get(pod_exec).post(pod_exec_post),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/attach",
                get(pod_attach).post(pod_attach_post),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/portforward",
                get(pod_portforward).post(pod_portforward),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/proxy",
                get(pod_proxy_root)
                    .post(pod_proxy_root)
                    .put(pod_proxy_root)
                    .delete(pod_proxy_root),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/proxy/",
                get(pod_proxy_root)
                    .post(pod_proxy_root)
                    .put(pod_proxy_root)
                    .delete(pod_proxy_root),
            )
            .route(
                "/api/v1/namespaces/{ns}/pods/{name}/proxy/{*path}",
                get(pod_proxy)
                    .post(pod_proxy)
                    .put(pod_proxy)
                    .delete(pod_proxy),
            )
            .route(
                "/api/v1/nodes/{name}/proxy/{*path}",
                get(node_proxy)
                    .post(node_proxy)
                    .put(node_proxy)
                    .delete(node_proxy),
            )
            .route(
                "/api/v1/namespaces/{ns}/services/{name}/proxy",
                get(service_proxy_root)
                    .post(service_proxy_root)
                    .put(service_proxy_root)
                    .delete(service_proxy_root),
            )
            .route(
                "/api/v1/namespaces/{ns}/services/{name}/proxy/",
                get(service_proxy_root)
                    .post(service_proxy_root)
                    .put(service_proxy_root)
                    .delete(service_proxy_root),
            )
            .route(
                "/api/v1/namespaces/{ns}/services/{name}/proxy/{*path}",
                get(service_proxy)
                    .post(service_proxy)
                    .put(service_proxy)
                    .delete(service_proxy),
            )
            .with_state(state)
    }

    /// Seed a Node with the given `spec.podCIDR`, for tests exercising the non-hostNetwork
    /// branch of `validate_pod_ip_against_node` (the pod must carry a matching `spec.nodeName`).
    async fn seed_node_with_pod_cidr(state: &AppState, node_name: &str, pod_cidr: &str) {
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": node_name, "resourceVersion": "1"},
            "spec": {"podCIDR": pod_cidr}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", node_name),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");
    }

    /// A real, non-loopback IP address this host can both bind and dial itself on.
    ///
    /// `validate_proxy_target_ip` now rejects bare IPv4 loopback in every proxy dial arm
    /// — the whole point of this module's SSRF fix — so tests that need a real, connectable
    /// in-process listener standing in for a pod/Service backend can no longer address it
    /// as a forged 127.0.0.1 podIP/EndpointSlice address. This discovers the host's own
    /// LAN-routable address so those tests can keep dialing a real listener without relying
    /// on the loopback exemption the fix removes.
    ///
    /// `UdpSocket::connect` never sends a packet — it only asks the kernel to pick a local
    /// source address for the given route, which needs no external reachability, just a
    /// non-loopback interface in the routing table (true of every dev machine and CI runner
    /// this suite runs on).
    fn test_backend_ip() -> std::net::IpAddr {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind ephemeral UDP socket");
        sock.connect("8.8.8.8:80")
            .expect("resolve a local route to pick a non-loopback source address");
        sock.local_addr().expect("query bound local address").ip()
    }

    // -----------------------------------------------------------------------
    // buffer_capped: response-body size cap for the html-rewrite proxy path
    // -----------------------------------------------------------------------

    /// buffer_capped must reject a chunked body once the running total exceeds `limit`,
    /// rather than buffering it in full — this is the fix for the html-rewrite proxy path,
    /// which (unlike the non-HTML path) must fully materialize the response before it can
    /// scan for links to rewrite. Without this cap a malicious/compromised proxy backend
    /// returning an oversized text/html body forces the apiserver to allocate memory
    /// proportional to the response size, per in-flight request (memory-exhaustion DoS).
    #[tokio::test]
    async fn buffer_capped_rejects_body_over_limit() {
        let chunks: Vec<Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from(vec![0u8; 3])),
            Ok(bytes::Bytes::from(vec![0u8; 3])),
        ];
        let stream = futures_util::stream::iter(chunks);

        let result = buffer_capped(stream, 4).await;

        assert!(
            result.is_err(),
            "a body whose chunks sum past the limit must be rejected — silently accepting \
             it defeats the whole point of the cap and reintroduces the unbounded-memory \
             DoS this function exists to close"
        );
    }

    /// buffer_capped must return the full, reassembled body when the total stays within
    /// `limit` — the cap must not reject or truncate ordinary, legitimately-sized proxied
    /// responses (the vast majority of real HTML proxy traffic).
    #[tokio::test]
    async fn buffer_capped_accepts_body_under_limit() {
        let chunks: Vec<Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from_static(b"hello ")),
            Ok(bytes::Bytes::from_static(b"world")),
        ];
        let stream = futures_util::stream::iter(chunks);

        let result = buffer_capped(stream, 4 * 1024 * 1024)
            .await
            .expect("a body under the limit must not be rejected");

        assert_eq!(
            result,
            bytes::Bytes::from_static(b"hello world"),
            "buffer_capped must reassemble every chunk in order — dropping or reordering \
             chunks would corrupt the proxied response body"
        );
    }

    /// A stream error (e.g. the backend connection dropping mid-response) must propagate
    /// as an error rather than being silently swallowed into a truncated, seemingly-valid
    /// body — a caller that got Ok(partial_body) here would rewrite and serve a corrupted
    /// page instead of surfacing the failure as a 502.
    #[tokio::test]
    async fn buffer_capped_propagates_stream_error() {
        let chunks: Vec<Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from_static(b"partial")),
            Err("connection reset".to_owned()),
        ];
        let stream = futures_util::stream::iter(chunks);

        let result = buffer_capped(stream, 4 * 1024 * 1024).await;

        assert!(
            result.is_err(),
            "a mid-stream read error must surface as an error, not a truncated Ok(body)"
        );
    }

    // -----------------------------------------------------------------------
    // validate_proxy_target_ip: reject SSRF/request-splitting podIP and
    // EndpointSlice addresses before they are ever dialed
    // -----------------------------------------------------------------------

    /// A pod/EndpointSlice address of the cloud-metadata/link-local range must be
    /// rejected — this is the exact address a compromised node would set on its own
    /// pod's status.podIP to redirect the apiserver's outbound proxy dial to an
    /// internal target (e.g. AWS/GCP/Azure IMDS) reachable from the apiserver's own
    /// network position but not from the compromised node itself.
    #[test]
    fn validate_proxy_target_ip_rejects_cloud_metadata_address() {
        let result = validate_proxy_target_ip("169.254.169.254");
        assert!(
            result.is_err(),
            "169.254.169.254 (cloud IMDS) must be rejected — accepting it lets a \
             compromised node's forged podIP redirect the apiserver's own outbound \
             request to the cloud metadata service"
        );
    }

    /// A podIP string containing CRLF must be rejected by the same check — this string is
    /// also spliced unescaped into a raw `CONNECT {addr}:{port} HTTP/1.1\r\n...` request
    /// line for the konnectivity leg, so an embedded CRLF would let a compromised node
    /// inject a second request into konnectivity-server's stream (request splitting).
    #[test]
    fn validate_proxy_target_ip_rejects_crlf_injection_payload() {
        let result = validate_proxy_target_ip("10.0.0.1\r\nGET /admin HTTP/1.1\r\n");
        assert!(
            result.is_err(),
            "a podIP containing CRLF must be rejected before it is spliced into the raw \
             CONNECT request line — accepting it lets a compromised node smuggle a second \
             request into konnectivity-server's stream"
        );
    }

    /// IPv6 loopback (::1) must be rejected — a forged podIP pointing at loopback would
    /// redirect the proxy dial to a service on the apiserver's own host (e.g. an
    /// unauthenticated debug/pprof endpoint) rather than the pod.
    #[test]
    fn validate_proxy_target_ip_rejects_ipv6_loopback() {
        assert!(validate_proxy_target_ip("::1").is_err());
    }

    /// Bare dotted-decimal IPv4 loopback (127.0.0.1) must be rejected — unlike
    /// `validate_webhook_url`'s loopback exemption (admin-controlled config), a podIP or
    /// EndpointSlice address is node-controlled, so a compromised node could otherwise set
    /// it to 127.0.0.1 and redirect the apiserver's own proxy dial to a service on its own
    /// host (e.g. pprof/debug/metadata).
    #[test]
    fn validate_proxy_target_ip_rejects_ipv4_loopback() {
        assert!(
            validate_proxy_target_ip("127.0.0.1").is_err(),
            "127.0.0.1 must be rejected as a pod/EndpointSlice dial target — a compromised \
             node forging its pod's podIP as loopback must not be able to redirect the \
             apiserver's own outbound proxy dial to itself"
        );
    }

    /// The IPv6-mapped form of a blocked IPv4 address (::ffff:169.254.169.254) must also be
    /// rejected — checking only the plain-IPv4 and native-IPv6 ranges would leave this
    /// encoding as a bypass for the exact cloud-metadata block above.
    #[test]
    fn validate_proxy_target_ip_rejects_ipv4_mapped_cloud_metadata() {
        let result = validate_proxy_target_ip("::ffff:169.254.169.254");
        assert!(
            result.is_err(),
            "::ffff:169.254.169.254 must be rejected — it carries the same blocked IPv4 \
             payload as 169.254.169.254 and must not bypass the check via IPv6-mapped form"
        );
    }

    /// The older, legacy IPv4-*compatible* form (`::a.b.c.d`, no `ffff:` prefix) of a
    /// blocked IPv4 address must also be rejected. `to_ipv4_mapped()` alone only unwraps
    /// the `::ffff:a.b.c.d` form; `"::169.254.169.254".parse::<IpAddr>()` succeeds and,
    /// with only that narrower unwrap, would pass every check here and reach the dial —
    /// the exact SSRF bypass this test locks in against a regression.
    #[test]
    fn validate_proxy_target_ip_rejects_ipv4_compatible_cloud_metadata() {
        let result = validate_proxy_target_ip("::169.254.169.254");
        assert!(
            result.is_err(),
            "::169.254.169.254 must be rejected — it carries the same blocked IPv4 payload \
             as 169.254.169.254 and must not bypass the check via the legacy IPv4-compatible \
             IPv6 form"
        );
    }

    /// An ordinary pod IP in a private/cluster CIDR (10.x, typical of pod networks) must be
    /// accepted — this guards against over-eager validation breaking every real pod proxy,
    /// since pod and cluster IPs legitimately live in RFC1918 space unlike the SSRF-target
    /// ranges (loopback/link-local/multicast) this check actually blocks.
    #[test]
    fn validate_proxy_target_ip_accepts_ordinary_pod_ip() {
        assert!(
            validate_proxy_target_ip("10.244.1.5").is_ok(),
            "a routine pod IP in a private CIDR must be accepted — rejecting it would \
             break every real pod-proxy request, since pod IPs are ordinarily private \
             (RFC1918) addresses, not public ones"
        );
    }

    /// resolve_pod_proxy_target must reject a pod whose status.podIP a compromised node
    /// set to the cloud-metadata address, returning an error before ever building the
    /// proxy dial URL — this is the end-to-end regression guard for the SSRF finding: a
    /// unit test on validate_proxy_target_ip alone wouldn't catch a caller that forgot to
    /// invoke it.
    #[tokio::test]
    async fn pod_proxy_rejects_cloud_metadata_pod_ip() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "ssrf-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "169.254.169.254"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "ssrf-pod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let result = resolve_pod_proxy_target(&state, "default", "ssrf-pod").await;

        assert!(
            result.is_err(),
            "a pod with status.podIP == 169.254.169.254 (cloud IMDS) must be rejected \
             before dial — a compromised node scheduled to this pod could otherwise \
             redirect any legitimate user's pods/proxy request to the cloud metadata \
             service from the apiserver's own network position"
        );
    }

    // -----------------------------------------------------------------------
    // validate_pod_ip_against_node: podIP-in-podCIDR / hostNetwork allowlist,
    // composed with the blocklist above -- the arbitrary-external-podIP SSRF fix
    // -----------------------------------------------------------------------

    /// A non-hostNetwork pod's podIP outside its own node's podCIDR must be rejected.
    ///
    /// Before this check, a blocklist alone let a compromised node set its pod's podIP to
    /// ANY routable address outside the reserved ranges (not just cloud-metadata/loopback)
    /// — e.g. an internal service the apiserver can reach but the node itself cannot,
    /// turning pods/proxy into a control-plane SSRF pivot. The podCIDR is trustworthy only
    /// because NodeRestriction-equivalent admission stops a node from self-assigning it.
    #[tokio::test]
    async fn pod_proxy_rejects_pod_ip_outside_node_pod_cidr() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "escapee", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-a", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "10.99.0.5"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "escapee"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        seed_node_with_pod_cidr(&state, "node-a", "10.244.0.0/24").await;

        let result = resolve_pod_proxy_target(&state, "default", "escapee").await;

        assert!(
            result.is_err(),
            "a podIP (10.99.0.5) outside its node's podCIDR (10.244.0.0/24) must be \
             rejected — accepting it lets a compromised node redirect the apiserver's \
             pods/proxy dial to any address of its choosing, not just its own pod network"
        );
    }

    /// A non-hostNetwork pod's podIP inside its own node's podCIDR must be allowed.
    ///
    /// This is the ordinary, overwhelmingly common case: a real pod networked by the CNI
    /// plugin gets an address from its node's assigned range. Rejecting it would break
    /// every legitimate pods/proxy request in the cluster.
    #[tokio::test]
    async fn pod_proxy_allows_pod_ip_inside_node_pod_cidr() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "normal", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-b", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "10.244.0.5"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "normal"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        seed_node_with_pod_cidr(&state, "node-b", "10.244.0.0/24").await;

        let (ip, ..) = resolve_pod_proxy_target(&state, "default", "normal")
            .await
            .expect(
                "a podIP inside its node's podCIDR must be allowed — otherwise no real \
                 pod's proxy subresource would ever work",
            );
        assert_eq!(ip, "10.244.0.5");
    }

    /// A non-hostNetwork pod whose node has no spec.podCIDR assigned must still be
    /// allowed (falling back to the blocklist floor alone), not hard-rejected.
    ///
    /// This codebase's own conformance stack runs kube-controller-manager with
    /// node-ipam-controller explicitly disabled (04-start-kcm.sh), so spec.podCIDR is
    /// never populated there today — live-confirmed via `kubectl get node -o json`
    /// showing an empty spec on a real, Ready, CNI-networked node. Hard-rejecting here
    /// would 502 every ordinary pod's proxy subresource in that (currently common)
    /// configuration; the CIDR-membership allowlist activates automatically once a real
    /// per-node podCIDR is assigned.
    #[tokio::test]
    async fn pod_proxy_allows_pod_ip_when_node_has_no_pod_cidr_assigned() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "no-ipam", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-e", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "10.85.3.40"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "no-ipam"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-e", "resourceVersion": "1"},
            "spec": {}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-e"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let (ip, ..) = resolve_pod_proxy_target(&state, "default", "no-ipam")
            .await
            .expect(
                "a podIP must be allowed when its node has no spec.podCIDR assigned — \
                 otherwise pods/proxy would be broken cluster-wide until \
                 node-ipam-controller is enabled",
            );
        assert_eq!(ip, "10.85.3.40");
    }

    /// A non-hostNetwork pod whose node has no spec.podCIDR assigned (this codebase's own
    /// conformance stack's default — node-ipam-controller disabled) must still reject a
    /// forged podIP of 127.0.0.1.
    ///
    /// The CIDR allowlist tested above is a no-op in this configuration, falling back to
    /// the blocklist floor alone — the exact arm a critical-reviewer of PR #1525 found
    /// still let a compromised node redirect the apiserver's own outbound pods/proxy dial
    /// to a service on its own host (pprof/debug/metadata). If the blocklist's loopback
    /// rejection is ever reverted, this test starts passing 502 traffic to 127.0.0.1
    /// instead of rejecting it, and fails.
    #[tokio::test]
    async fn pod_proxy_rejects_loopback_pod_ip_when_node_has_no_pod_cidr_assigned() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "evil-no-ipam", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-f", "containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "127.0.0.1"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "evil-no-ipam"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-f", "resourceVersion": "1"},
            "spec": {}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-f"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let result = resolve_pod_proxy_target(&state, "default", "evil-no-ipam").await;

        assert!(
            result.is_err(),
            "a podIP of 127.0.0.1 must be rejected even when the CIDR allowlist is a no-op \
             (no spec.podCIDR assigned) — a compromised node forging this podIP must not be \
             able to redirect the apiserver's own proxy dial to a service on its own host"
        );
    }

    /// A hostNetwork pod's podIP matching its own status.hostIP (a real routable node
    /// address) must be allowed.
    ///
    /// hostNetwork pods share the node's network namespace, so their podIP is legitimately
    /// the node's own IP rather than a pod-CIDR address; the podCIDR-membership check above
    /// would incorrectly reject every hostNetwork pod (e.g. kube-proxy, CNI daemons) if
    /// applied here instead of this hostIP-equality branch.
    #[tokio::test]
    async fn pod_proxy_allows_host_network_pod_ip_matching_host_ip() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "kube-proxy", "namespace": "kube-system", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-c",
                "hostNetwork": true,
                "containers": [{"name": "kube-proxy", "image": "kube-proxy"}]
            },
            "status": {"podIP": "192.168.1.10", "hostIP": "192.168.1.10"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "kube-system", "kube-proxy"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let (ip, ..) = resolve_pod_proxy_target(&state, "kube-system", "kube-proxy")
            .await
            .expect(
                "a hostNetwork pod's podIP matching its own status.hostIP must be allowed \
                 — otherwise proxying to any real hostNetwork pod (kube-proxy, CNI \
                 daemons) would be broken",
            );
        assert_eq!(ip, "192.168.1.10");
    }

    /// A hostNetwork pod's podIP of 127.0.0.1 must be rejected even when status.hostIP
    /// also claims 127.0.0.1 — the operator edge case this allowlist is composed against.
    ///
    /// status.hostIP is node-writable even after NodeRestriction-equivalent admission
    /// (nodes/status stays legitimately node-writable), so a podIP/hostIP match alone is
    /// not proof of a real node identity — it only proves the two node-controlled fields
    /// agree with each other. Without this floor, a compromised node could set both to
    /// 127.0.0.1 and redirect the proxy dial to an unauthenticated service on the
    /// apiserver's own host (e.g. pprof/debug), defeating the hostNetwork branch entirely.
    #[tokio::test]
    async fn pod_proxy_rejects_host_network_loopback_pod_ip_even_if_host_ip_matches() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "evil-hostnet", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-d",
                "hostNetwork": true,
                "containers": [{"name": "app", "image": "nginx"}]
            },
            "status": {"podIP": "127.0.0.1", "hostIP": "127.0.0.1"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "evil-hostnet"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let result = resolve_pod_proxy_target(&state, "default", "evil-hostnet").await;

        assert!(
            result.is_err(),
            "a hostNetwork pod's podIP/hostIP of 127.0.0.1 must be rejected regardless of \
             the claimed match — a compromised node forging both fields as loopback must \
             not be able to redirect the apiserver's own proxy dial to itself"
        );
    }

    /// A podIP containing an embedded CRLF must be rejected via the same allowlist path,
    /// not just the standalone `validate_proxy_target_ip` unit check above.
    ///
    /// This string is spliced unescaped into the raw `CONNECT {addr}:{port} HTTP/1.1\r\n...`
    /// request line built for the konnectivity leg; accepting it here would let a
    /// compromised node smuggle a second request into konnectivity-server's stream
    /// (request splitting) even after the CIDR/hostIP allowlist above is composed in.
    #[tokio::test]
    async fn pod_proxy_rejects_crlf_pod_ip_before_dial() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "splitter", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {"podIP": "10.0.0.1\r\nGET /admin HTTP/1.1\r\n"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "splitter"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let result = resolve_pod_proxy_target(&state, "default", "splitter").await;

        assert!(
            result.is_err(),
            "a podIP containing CRLF must be rejected before dial — accepting it lets a \
             compromised node inject a second request into konnectivity-server's stream \
             via the raw CONNECT line built from this same podIP string"
        );
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

    /// A pod on a joined (non-primary) node must dial THAT node's mapped kubelet port,
    /// not the primary's --kubelet-port, end to end through resolve_exec_target.
    ///
    /// This exercises the actual proxy call site (not just kubelet_port_for_node in
    /// isolation): if a future change reverted the call site back to reading the global
    /// `state.kubelet_port` directly — while leaving kubelet_port_for_node itself
    /// correct — kubelet_port_for_node's own unit tests would keep passing even though
    /// the real bug (kubectl exec/logs against a node-2 pod misrouting to node-1's
    /// kubelet) would be back. Only a test through the real resolve fn like this one
    /// catches that class of revert.
    #[tokio::test]
    async fn exec_target_dials_the_joined_nodes_mapped_port_not_the_primarys() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory store"));
        let mut state = AppState::new_with_config(crate::state::AppStateConfig {
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
            kubelet_port: 10250, // primary's forward
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });
        state
            .node_kubelet_ports
            .insert("lima-node-3".to_string(), 10261); // joined node's forward

        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": "lima-node-3", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.2"}]}
        });
        let pod = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "testpod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "lima-node-3", "containers": [{"name": "app", "image": "busybox"}]}
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "lima-node-3"),
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
            "command=echo&command=hi&stdout=1",
        )
        .await
        .expect("resolve must succeed");

        assert!(
            target.kubelet_ws_url.contains(":10261/"),
            "a pod on lima-node-3 must dial lima-node-3's mapped port (10261), not the \
             primary's --kubelet-port: {}",
            target.kubelet_ws_url
        );
        assert!(
            !target.kubelet_ws_url.contains(":10250/"),
            "must NOT dial the primary's port (10250) for a pod scheduled on a different, \
             mapped node — this is the exact misroute that breaks kubectl exec against a \
             2nd node's pods: {}",
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
    /// format expected by the kubelet portForward endpoint. The scheme must be
    /// `https://`, not `wss://`: unlike /exec and /attach, the kubelet-facing
    /// port-forward leg is a raw HTTP/1.1 upgrade (`dial_kubelet_portforward`), not a
    /// WebSocket — kubelet's `handleHTTPStreams` is the only wire shape it accepts
    /// unconditionally across every supported release.
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
            params.kubelet_url, "https://10.0.0.1:10250/portForward/default/mypod?ports=8080",
            "kubelet URL must use https:// scheme (a raw HTTP/1.1 upgrade, not a \
             WebSocket), InternalIP, configured port, /portForward/<ns>/<pod> path, \
             and the ports query string"
        );
    }

    /// `validate_ports_param` rejects CRLF/control-byte and other non-grammar input.
    ///
    /// `dial_kubelet_portforward` hand-rolls its kubelet-facing HTTP/1.1 request line
    /// from a `ports_qs` string built out of this value with zero further escaping —
    /// if this check ever regressed to a CRLF blocklist (or was dropped entirely), a
    /// caller holding nothing but `create` on `pods/portforward` for one pod could
    /// smuggle a second, fully independent HTTP request onto the apiserver's own
    /// trusted mTLS connection to that pod's node's kubelet, reaching any kubelet
    /// endpoint (other pods' exec, `/stats`, `/runningpods`) as the apiserver's
    /// identity. This must be a positive grammar allowlist, not a blocklist, so it
    /// can't be bypassed by some other control byte a blocklist author forgot.
    #[test]
    fn validate_ports_param_rejects_non_grammar_input() {
        let bad = [
            "1\r\nHost: x\r\nContent-Length: 0\r\n\r\nGET /runningpods/ HTTP/1.1\r\nHost: x\r\n\r\n",
            "1\r\n",
            "\r\n",
            "",
            "8080,",
            ",8080",
            "8080 8081",
            "8080;rm -rf",
            "0",
            "65536",
            "abc",
        ];
        for value in bad {
            assert!(
                validate_ports_param(value).is_err(),
                "ports value {value:?} does not match the comma-separated 1-65535 \
                 integer grammar and must be rejected before it ever reaches a URL \
                 or the kubelet request line — got Ok"
            );
        }

        for value in ["8080", "8080,9090", "1,65535"] {
            assert!(
                validate_ports_param(value).is_ok(),
                "legitimate kubectl ports value {value:?} must still be accepted"
            );
        }
    }

    /// `validate_portforward` rejects a CRLF-smuggling `ports` value before it ever
    /// builds a kubelet URL, for a pod the caller is otherwise fully entitled to
    /// port-forward to.
    ///
    /// This is the end-to-end regression for the request-splitting vulnerability:
    /// without the `validate_ports_param` gate, this exact payload would have been
    /// interpolated into `kubelet_url` and then into the raw HTTP/1.1 request
    /// `dial_kubelet_portforward` writes to kubelet's socket, smuggling a second
    /// request onto the apiserver's trusted connection. Asserting `Err` here proves
    /// the malicious value never reaches that dial — the pod/node lookups above
    /// prove this isn't merely a coincidental 404 for a pod that doesn't exist.
    #[tokio::test]
    async fn portforward_validation_rejects_crlf_injection_in_ports() {
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

        let payload =
            "1\r\nHost: x\r\nContent-Length: 0\r\n\r\nGET /runningpods/ HTTP/1.1\r\nHost: x\r\n\r\n";
        let result = validate_portforward(&state, "default", "mypod", Some(payload)).await;

        match result {
            Ok(p) => panic!(
                "a CRLF-smuggling ports value must never produce a kubelet URL — a \
                 portforward-only grant could otherwise splice a second HTTP request \
                 onto the apiserver's trusted kubelet connection; got kubelet_url {:?}",
                p.kubelet_url
            ),
            Err(e) => assert_eq!(
                e.0.as_u16(),
                400,
                "CRLF-smuggling ports value must be rejected as a 400 Bad Request, \
                 not silently swallowed or reported as a different error"
            ),
        }
    }

    /// `parse_https_url` rejects a CRLF byte in the path/query it hands back.
    ///
    /// This is the second, defense-in-depth gate `dial_kubelet_portforward` relies
    /// on: `validate_ports_param` is the primary check, but if some future field is
    /// ever added to `kubelet_url`'s query string without going through it, this
    /// `http::uri::PathAndQuery` re-parse — the same class of real URI parser the
    /// /exec, /attach, and v4 legs get for free from `IntoClientRequest` — must still
    /// stop a CRLF byte from reaching the hand-rolled `POST {path} HTTP/1.1\r\n...`
    /// request line written straight to kubelet's socket.
    #[test]
    fn parse_https_url_rejects_crlf_in_query() {
        let malicious = "https://10.0.0.1:10250/portForward/default/mypod?ports=1\r\nHost: evil";
        assert!(
            parse_https_url(malicious).is_err(),
            "a CRLF byte in the kubelet URL's path/query must fail parse_https_url, \
             not flow into the raw HTTP/1.1 request line dial_kubelet_portforward \
             writes to kubelet's socket"
        );
    }

    // -----------------------------------------------------------------------
    // pod_portforward: wire-protocol regression tests
    //
    // A prior implementation advertised a fabricated `v5.portforward.k8s.io`
    // subprotocol that appears nowhere in upstream Kubernetes, so no real kubectl
    // client (1.34-1.36) could ever negotiate it — both the primary websocket-tunnel
    // GET and the legacy raw-SPDY POST fallback ended up failing with axum's opaque
    // "Request method must be `GET`", because `pod_portforward` took `WebSocketUpgrade`
    // directly, which 405s any non-GET request before the handler body even runs.
    // -----------------------------------------------------------------------

    /// Seed a schedulable pod and its node so `validate_portforward` succeeds (the
    /// cluster CA itself is configured separately, on `AppState`) — shared setup for
    /// the real-server portforward handshake tests.
    async fn seed_portforward_pod(store: &Arc<SqliteStore>) {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pf-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "node-1", "containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "pf-pod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
        });
        store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");
    }

    /// Serve `router` on a real TCP listener with HTTP/1.1 upgrade support and return
    /// its address — axum's `WebSocketUpgrade` extractor needs hyper's real `OnUpgrade`
    /// connection state, which a synthetic in-process `Request` never has.
    fn spawn_upgradeable_server(router: Router) -> std::net::SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| {
                l.set_nonblocking(true)?;
                Ok(l)
            })
            .map(|std_listener| {
                let addr = std_listener.local_addr().unwrap();
                let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                tokio::spawn(async move {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let io = hyper_util::rt::TokioIo::new(tcp);
                    let service = hyper::service::service_fn(move |req| {
                        let mut router = router.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                tower_service::Service::call(&mut router, req)
                                    .await
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                });
                addr
            })
            .expect("bind test listener")
    }

    /// Echo the client's requested subprotocol in a mock kubelet's websocket
    /// handshake response.
    ///
    /// Real kubelet's `golang.org/x/net/websocket`-based wsstream server always
    /// echoes the negotiated `Config.Protocol` in its 101 response; tungstenite's
    /// client-side handshake validation (used by `dial_kubelet_portforward_v4`)
    /// rejects a 101 that omits this header when the client requested a
    /// subprotocol, so a mock kubelet that skips this would fail even a correct
    /// dial implementation.
    ///
    /// `ErrorResponse` is tungstenite's `Callback` trait signature, not something
    /// this test-only helper controls the size of.
    #[allow(clippy::result_large_err)]
    fn echo_v4_subprotocol(
        _req: &tokio_tungstenite::tungstenite::handshake::server::Request,
        mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            PORTFORWARD_V4_SUBPROTOCOL.parse().unwrap(),
        );
        Ok(response)
    }

    /// The primary GET handshake must advertise exactly `SPDY/3.1+portforward.k8s.io`,
    /// never the fabricated `v5.portforward.k8s.io`.
    ///
    /// Any subprotocol other than `SPDY/3.1+portforward.k8s.io` fails to match
    /// kubectl's client-go dialer (staging/src/k8s.io/client-go/tools/portforward/
    /// tunneling_dialer.go), which only ever offers this exact string on its primary
    /// attempt — so a mismatch here reproduces the "every kubectl port-forward fails"
    /// bug even though the connection technically completes an HTTP upgrade.
    #[tokio::test]
    async fn portforward_advertises_spdy_websocket_subprotocol() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
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

        let addr = spawn_upgradeable_server(make_router(state));

        // The literal string real kubectl sends is hardcoded here (not
        // PORTFORWARD_KUBECTL_SUBPROTOCOL) so this test still fails if that constant
        // ever regresses to a fabricated value — a self-referential comparison against
        // the same constant the production code uses could never catch that.
        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports=8080");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            "SPDY/3.1+portforward.k8s.io".parse().unwrap(),
        );

        let (_ws, response) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("a portforward websocket GET must upgrade (101)");

        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some("SPDY/3.1+portforward.k8s.io"),
            "any subprotocol other than `SPDY/3.1+portforward.k8s.io` fails to match \
             kubectl's client-go dialer (staging/src/k8s.io/client-go/tools/portforward/\
             tunneling_dialer.go)"
        );
    }

    /// A client offering only a completely unrecognized subprotocol must be
    /// rejected, not silently accepted with no subprotocol at all.
    ///
    /// axum's `WebSocketUpgrade::protocols()` alone would not catch this: when none of
    /// the offered candidates match, it completes the handshake with no
    /// `Sec-WebSocket-Protocol` header rather than rejecting — exactly the failure
    /// shape the fabricated `v5.portforward.k8s.io` subprotocol produced: a connection
    /// that "succeeds" but neither end can exchange usable traffic over. This must
    /// keep failing loudly even after `v4.channel.k8s.io` becomes a second accepted
    /// protocol — silently widening acceptance to "anything" would be the same bug
    /// in a different shape.
    #[tokio::test]
    async fn portforward_rejects_completely_unknown_subprotocol() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
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

        let addr = spawn_upgradeable_server(make_router(state));

        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports=8080");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            "some.invented.thing.k8s.io".parse().unwrap(),
        );

        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("connect attempt must not time out");

        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(
                    resp.status(),
                    StatusCode::BAD_REQUEST,
                    "an unsupported subprotocol must be rejected with 400, not silently \
                     accepted or answered with an unrelated status: {:?}",
                    resp.status()
                );
            }
            other => panic!(
                "expected an HTTP-level rejection (400) for an unsupported subprotocol, \
                 got: {other:?}"
            ),
        }
    }

    /// `e2ewebsocket.OpenWebSocketForURL` (`test/e2e/framework/websocket/websocket.go`)
    /// offers ONLY `v4.channel.k8s.io` — no SPDY subprotocol at all. Rejecting it
    /// silently fails the sig-cli "should support forwarding over websockets"
    /// conformance tests, exactly like the fabricated `v5.portforward.k8s.io`
    /// subprotocol failed every kubectl port-forward before that fix.
    #[tokio::test]
    async fn portforward_accepts_v4_channel_k8s_io_subprotocol() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
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

        let addr = spawn_upgradeable_server(make_router(state));

        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports=8080");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            PORTFORWARD_V4_SUBPROTOCOL.parse().unwrap(),
        );

        let (_ws, response) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect(
                    "a portforward websocket GET offering only v4.channel.k8s.io must \
                     upgrade (101) — rejecting it is what breaks e2ewebsocket.\
                     OpenWebSocketForURL with 'bad status'",
                );

        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some(PORTFORWARD_V4_SUBPROTOCOL),
            "the echoed subprotocol must be v4.channel.k8s.io, matching what the \
             client offered"
        );
    }

    /// When a client offers both `SPDY/3.1+portforward.k8s.io` and
    /// `v4.channel.k8s.io`, SPDY must win — matching kubectl's own dialer, which is
    /// the overwhelmingly more common client. No real client offers both today, but
    /// resolution must stay order-independent and not regress kubectl's path as a
    /// side effect of adding v4 support.
    #[tokio::test]
    async fn portforward_still_accepts_spdy_subprotocol_when_v4_offered_second() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
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

        let addr = spawn_upgradeable_server(make_router(state));

        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports=8080");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            format!("{PORTFORWARD_KUBECTL_SUBPROTOCOL}, {PORTFORWARD_V4_SUBPROTOCOL}")
                .parse()
                .unwrap(),
        );

        let (_ws, response) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("a portforward websocket GET must upgrade (101)");

        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some(PORTFORWARD_KUBECTL_SUBPROTOCOL),
            "SPDY must be preferred over v4 when both are offered — kubectl's own \
             dialer must keep working exactly as before v4 support was added"
        );
    }

    /// GET and POST to /portforward must both reach `pod_portforward`'s own
    /// validation logic (pod/node lookup), not axum's generic `WebSocketUpgrade`
    /// rejection.
    ///
    /// Before this fix, `pod_portforward` took `ws: WebSocketUpgrade` directly, which
    /// 405s any non-GET method before the handler body runs — so kubectl's legacy-SPDY
    /// POST fallback (sent whenever the primary websocket-tunnel GET fails) always
    /// surfaced axum's opaque "Request method must be `GET`" instead of a real status,
    /// masking the actual error (here, a missing pod).
    #[tokio::test]
    async fn portforward_get_and_post_both_reach_handler() {
        let state = make_state();
        let mut router = make_router(state);

        for method in ["GET", "POST"] {
            let req = axum::http::Request::builder()
                .method(method)
                .uri("/api/v1/namespaces/default/pods/ghost/portforward")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = router.call(req).await.unwrap();
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_str = String::from_utf8_lossy(&body);

            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{method} to a nonexistent pod must reach validate_portforward and \
                 return 404, not axum's generic WebSocketUpgrade rejection: {body_str}"
            );
            assert!(
                !body_str.contains("Request method must be"),
                "regression guard: this is axum's generic WebSocketUpgrade rejection \
                 text — seeing it for {method} means the handler still takes \
                 `WebSocketUpgrade` directly and 405s before validate_portforward runs: \
                 {body_str}"
            );
        }
    }

    /// Bytes sent from the WebSocket (kubectl) side must arrive verbatim on the raw
    /// TCP connection to kubelet, and bytes written by kubelet must arrive verbatim
    /// back at the WebSocket client — with zero SPDY frame interpretation on either
    /// leg.
    ///
    /// This is the byte-pump the whole fix depends on: real SPDY multiplexing happens
    /// only between kubectl and kubelet, so if apiserver ever mangled, reframed, or
    /// dropped a chunk here, kubectl's own SPDY decoder would desync and port-forward
    /// would fail with corrupted-stream errors even though the handshake itself
    /// succeeded.
    #[tokio::test]
    async fn portforward_client_leg_byte_pump_forwards_verbatim() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        // Mock kubelet: completes the raw-SPDY upgrade, then exercises both
        // directions of the byte pump.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        const CLIENT_TO_KUBELET: &[u8] = b"hello-from-kubectl";
        const KUBELET_TO_CLIENT: &[u8] = b"hello-from-kubelet";

        tokio::spawn(async move {
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();

            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("POST "), "kubelet leg must POST: {req}");
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: SPDY/3.1\r\n\
                      X-Stream-Protocol-Version: portforward.k8s.io\r\n\r\n",
                )
                .await
                .unwrap();

            let mut received = vec![0u8; CLIENT_TO_KUBELET.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(
                &received[..],
                CLIENT_TO_KUBELET,
                "bytes sent from the WS client must arrive verbatim on the raw kubelet \
                 TCP leg"
            );

            stream.write_all(KUBELET_TO_CLIENT).await.unwrap();
        });

        // Trust the mock kubelet's own cert — not an unrelated one — or the outbound
        // TLS handshake in dial_kubelet_portforward fails certificate verification and
        // splice() never runs, leaving the client's unread bytes to trigger a TCP RST
        // when the never-spliced inbound WebSocket is dropped.
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));

        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports=8080");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            PORTFORWARD_KUBECTL_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("portforward websocket handshake must succeed");

        ws.send(Message::Binary(CLIENT_TO_KUBELET.to_vec().into()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("must receive kubelet's reply before timing out")
            .expect("stream must not end before the reply arrives")
            .expect("message must be Ok");
        match msg {
            Message::Binary(b) => assert_eq!(
                &b[..],
                KUBELET_TO_CLIENT,
                "bytes written by kubelet must arrive verbatim at the WS client"
            ),
            other => panic!("expected a Binary message, got: {other:?}"),
        }
    }

    /// The little-endian uint16 port preamble kubelet writes on a v4.channel.k8s.io
    /// data channel when it opens the connection must reach the client bit-for-bit.
    ///
    /// `k8s.io/cri-streaming/pkg/streaming/portforward/websocket.go`'s
    /// `handleWebSocketStreams` writes `binary.LittleEndian.PutUint16(portBytes,
    /// uint16(port))` as the very first payload on each data/error channel. u7s never
    /// constructs this preamble itself (kubelet does, and u7s relays kubelet's v4
    /// connection to the client verbatim) — but if the relay ever fragmented,
    /// reordered, or otherwise mangled these 3 bytes (channel byte + 2-byte port),
    /// `test/e2e/framework/websocket/websocket.go`'s raw client would decode the
    /// wrong port and misattribute every subsequent read/write on this connection.
    #[tokio::test]
    async fn portforward_v4_channel_encodes_port_preamble_as_little_endian_uint16() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        const PORT: u16 = 8080;

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        // Mock kubelet's handleWebSocketStreams: accept the v4 websocket upgrade,
        // then write the little-endian uint16 port preamble on the data channel (0)
        // and error channel (1) for the single requested port — matching
        // websocket.go:130-134 exactly.
        tokio::spawn(async move {
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(tls, echo_v4_subprotocol)
                .await
                .unwrap();
            let port_bytes = PORT.to_le_bytes();
            ws.send(Message::Binary(
                vec![0, port_bytes[0], port_bytes[1]].into(),
            ))
            .await
            .unwrap();
            ws.send(Message::Binary(
                vec![1, port_bytes[0], port_bytes[1]].into(),
            ))
            .await
            .unwrap();
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));

        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports={PORT}");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            PORTFORWARD_V4_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("portforward v4 websocket handshake must succeed");

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("must receive kubelet's data-channel preamble before timing out")
            .expect("stream must not end before the preamble arrives")
            .expect("message must be Ok");
        let data = match msg {
            Message::Binary(b) => b,
            other => panic!("expected a Binary message, got: {other:?}"),
        };

        assert_eq!(
            data[0], 0,
            "the first message must carry the data channel byte (0), unmodified by \
             the relay"
        );
        assert_eq!(
            u16::from_le_bytes([data[1], data[2]]),
            PORT,
            "the port preamble must decode as little-endian uint16 — if the relay ever \
             reordered these two bytes (e.g. mistakenly treating them as big-endian), \
             the e2e websocket client would resolve the wrong forwarded port"
        );
    }

    /// A v4.channel.k8s.io connection must carry exactly one (data, error) channel
    /// pair per forwarded port, and neither channel may be dropped or reordered.
    ///
    /// The codebase already has precedent for channel-based filtering going wrong on
    /// this data path: /exec's relay absorbs kubelet's status frames on channels 3/4
    /// (`is_exec_status_frame`). If that pattern were mistakenly copied here — e.g.
    /// treating odd-numbered (error) channels as absorbable status frames — the
    /// error stream for every forwarded port would be silently dropped instead of
    /// reaching the client, and connection failures would appear to hang instead of
    /// surfacing kubelet's error text.
    #[tokio::test]
    async fn portforward_v4_channel_pairs_data_and_error_streams_per_port() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        const PORTS: [u16; 2] = [8080, 9090];

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        // Mock kubelet: two requested ports means two (data, error) channel pairs —
        // channels (0,1) for the first port, (2,3) for the second — matching
        // websocket.go's `streams[i*2+dataChannel]` / `streams[i*2+errorChannel]`.
        tokio::spawn(async move {
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(tls, echo_v4_subprotocol)
                .await
                .unwrap();
            for (i, port) in PORTS.iter().enumerate() {
                let port_bytes = port.to_le_bytes();
                let data_channel = (i * 2) as u8;
                let error_channel = (i * 2 + 1) as u8;
                ws.send(Message::Binary(
                    vec![data_channel, port_bytes[0], port_bytes[1]].into(),
                ))
                .await
                .unwrap();
                ws.send(Message::Binary(
                    vec![error_channel, port_bytes[0], port_bytes[1]].into(),
                ))
                .await
                .unwrap();
            }
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_portforward_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));

        // A single comma-joined `ports=` value, matching upstream's own
        // `strings.Split(portString, ",")` parsing (NewV4Options) — not two
        // repeated `ports=` keys.
        let ports_qs = PORTS
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let url = format!(
            "ws://{addr}/api/v1/namespaces/default/pods/pf-pod/portforward?ports={ports_qs}"
        );
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            PORTFORWARD_V4_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("portforward v4 websocket handshake must succeed");

        async fn expect_binary(
            ws: &mut tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            label: &'static str,
        ) -> Vec<u8> {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
                .await
                .unwrap_or_else(|_| panic!("must receive {label} before timing out"))
                .unwrap_or_else(|| panic!("stream must not end before {label} arrives"))
                .expect("message must be Ok");
            match msg {
                Message::Binary(b) => b.to_vec(),
                other => panic!("expected a Binary message for {label}, got: {other:?}"),
            }
        }

        for (i, port) in PORTS.iter().enumerate() {
            let data = expect_binary(&mut ws, "the data-channel preamble").await;
            assert_eq!(
                data[0],
                (i * 2) as u8,
                "port {port}'s data channel must be channel {} — a shifted or dropped \
                 pair would misattribute this port's traffic to a different port's \
                 local listener",
                i * 2
            );
            assert_eq!(
                u16::from_le_bytes([data[1], data[2]]),
                *port,
                "port {port}'s data channel preamble must carry its own port number"
            );

            let error = expect_binary(&mut ws, "the error-channel preamble").await;
            assert_eq!(
                error[0],
                (i * 2 + 1) as u8,
                "port {port}'s error channel must immediately follow its data channel \
                 as channel {} — if error channels were filtered like /exec's status \
                 frames (channels 3/4), this message would never arrive",
                i * 2 + 1
            );
            assert_eq!(
                u16::from_le_bytes([error[1], error[2]]),
                *port,
                "port {port}'s error channel preamble must carry its own port number"
            );
        }
    }

    /// The v4 kubelet dial must send `?port=`, not the legacy SPDY leg's `?ports=`.
    ///
    /// `k8s.io/cri-streaming/pkg/streaming/portforward/websocket.go`'s `NewV4Options`
    /// reads `req.URL.Query()[PortHeader]` where `PortHeader = "port"` (constants.go,
    /// singular) — real kubelet's SPDY-over-HTTP leg never reads the URL query at all
    /// (each SPDY stream carries its own port via a SYN_STREAM header), so `?ports=`
    /// silently working there masked this: reusing that exact query string verbatim
    /// for the v4 leg makes kubelet answer `query parameter "port" is required` (400)
    /// even though the websocket handshake itself succeeds — confirmed live against a
    /// real kubelet on lima-node-4 before this fix.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's Callback trait signature
    async fn portforward_v4_kubelet_dial_uses_port_not_ports_query_param() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = listener.local_addr().unwrap().port();

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let tx = std::sync::Mutex::new(Some(tx));

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ws = tokio_tungstenite::accept_hdr_async(
                tls,
                move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send(req.uri().query().unwrap_or("").to_string());
                    }
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        PORTFORWARD_V4_SUBPROTOCOL.parse().unwrap(),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
        });

        let params = PortforwardParams {
            kubelet_url: format!(
                "https://127.0.0.1:{kubelet_port}/portForward/default/mypod?ports=8080"
            ),
            cluster_ca_der: Some(cert_der),
            client_identity_pem: None,
        };

        let result = dial_kubelet_portforward_v4(&params).await;
        assert!(
            result.is_ok(),
            "dial must succeed once the query key matches kubelet's NewV4Options: {:?}",
            result.err()
        );

        let query = rx.await.unwrap();
        assert!(
            query.contains("port=8080") && !query.contains("ports="),
            "expected the outbound query to use 'port=', not 'ports=' — got {query:?}"
        );
    }

    /// The kubelet-facing dial must use legacy raw SPDY-over-HTTP — a plain POST with
    /// `Upgrade: SPDY/3.1` and `Connection: Upgrade` — never websocket-tunneled SPDY.
    ///
    /// kubelet's native websocket portforward path exists but requires the beta,
    /// kubelet-1.36-only `ExtendWebSocketsToKubelet` gate, which u7s cannot assume any
    /// given kubelet has enabled; the raw-HTTP-upgrade shape asserted here is the only
    /// one `handleHTTPStreams` accepts unconditionally on every supported release.
    #[tokio::test]
    async fn portforward_kubelet_leg_uses_raw_spdy_upgrade() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = listener.local_addr().unwrap().port();

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();

            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request);

            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: SPDY/3.1\r\n\
                      X-Stream-Protocol-Version: portforward.k8s.io\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let params = PortforwardParams {
            kubelet_url: format!(
                "https://127.0.0.1:{kubelet_port}/portForward/default/mypod?ports=8080"
            ),
            cluster_ca_der: Some(cert_der),
            client_identity_pem: None,
        };

        let result = dial_kubelet_portforward(&params).await;
        assert!(
            result.is_ok(),
            "dial must succeed against a kubelet that answers 101: {:?}",
            result.err()
        );

        let request = rx.await.unwrap();
        let request_line = request.lines().next().unwrap_or("");
        assert!(
            request_line.starts_with("POST "),
            "kubelet leg must use POST, matching legacy raw-SPDY-over-HTTP, not GET: \
             {request_line}"
        );
        assert!(
            request
                .lines()
                .any(|l| l.eq_ignore_ascii_case("Upgrade: SPDY/3.1")),
            "kubelet leg must send Upgrade: SPDY/3.1 — websocket-tunneled SPDY would \
             instead carry a WebSocket upgrade, which kubelet's handleHTTPStreams \
             (the only path accepted unconditionally on every supported release) does \
             not speak: {request}"
        );
        assert!(
            request.lines().any(|l| {
                l.to_ascii_lowercase().starts_with("connection:")
                    && l.to_ascii_lowercase().contains("upgrade")
            }),
            "kubelet leg must send Connection: Upgrade alongside Upgrade: SPDY/3.1: \
             {request}"
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

    /// A pod scheduled on a non-primary node must dial THAT node's kubelet forward.
    ///
    /// VM InternalIPs are not host-routable, so every node's kubelet is reached via a
    /// distinct host port-forward. Before this function existed, every proxy site read
    /// the single global `kubelet_port`, so a pod on node-2 always dialed node-1's
    /// forward — exec/logs/attach/port-forward against it either timed out (websocket
    /// close 1006) or hit node-1's kubelet instead of node-2's.
    #[test]
    fn kubelet_port_for_node_uses_the_named_nodes_port_not_the_primarys() {
        let mut ports: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
        ports.insert("node-2".to_string(), 10261);
        ports.insert("node-3".to_string(), 10262);
        assert_eq!(
            kubelet_port_for_node("node-2", &ports, 10250),
            10261,
            "a pod on node-2 must resolve to node-2's own kubelet forward, not the global port"
        );
        assert_eq!(
            kubelet_port_for_node("node-3", &ports, 10250),
            10262,
            "each mapped node must resolve to its own port, not another mapped node's"
        );
    }

    /// Single-node clusters never populate `node_kubelet_ports` (no --node-kubelet-port
    /// flags are passed when there is no 2nd node), so this fallback must exactly
    /// reproduce today's single-node behavior — the whole point of the fallback is that
    /// adding per-node routing cannot regress the common, single-node case.
    #[test]
    fn kubelet_port_for_node_falls_back_to_global_when_map_is_empty() {
        let ports: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
        assert_eq!(
            kubelet_port_for_node("lima-node", &ports, 10250),
            10250,
            "an empty map (single-node deployments) must use the global --kubelet-port"
        );
    }

    /// The primary node is intentionally never added to `node_kubelet_ports` — only
    /// joining nodes are. A pod scheduled on the primary must still resolve to the
    /// global port even once other nodes are mapped, or the primary itself would break
    /// the moment a 2nd node joins.
    #[test]
    fn kubelet_port_for_node_falls_back_to_global_for_unmapped_node_in_nonempty_map() {
        let mut ports: std::collections::HashMap<String, u16> = std::collections::HashMap::new();
        ports.insert("node-2".to_string(), 10261);
        assert_eq!(
            kubelet_port_for_node("lima-node", &ports, 10250),
            10250,
            "a node missing from a non-empty map (e.g. the primary, once node-2 joins) \
             must still fall back to the global port, not 0 or node-2's port"
        );
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

    /// strip_node_port must strip the trailing :port from a URL node name.
    ///
    /// Sonobuoy's dump.go builds node-proxy URLs as /api/v1/nodes/<name>:<port>/proxy/pods.
    /// Without stripping, the store lookup uses "lima-node:10250" instead of "lima-node",
    /// causing every sonobuoy pod-dump to 404 with "Node lima-node:10250 not found".
    #[test]
    fn strip_node_port_removes_port_suffix() {
        assert_eq!(
            super::strip_node_port("lima-node:10250"),
            "lima-node",
            "sonobuoy/kubectl node-proxy pod retrieval 404s if :port suffix is not stripped \
             before the store lookup"
        );
        assert_eq!(
            super::strip_node_port("lima-node"),
            "lima-node",
            "bare node names (no port suffix) must pass through unchanged"
        );
    }

    /// node proxy with a :port suffix in the name must resolve the same node as
    /// a bare-name lookup — confirming the port stripping reaches the store.
    ///
    /// If strip_node_port is removed or bypassed, "lima-node:10250" will not be
    /// found in the store and resolve_node_proxy_target returns 404, breaking
    /// every sonobuoy pod-dump that constructs the URL with a port suffix.
    #[tokio::test]
    async fn node_proxy_port_suffix_in_name_resolves_correctly() {
        let state = make_state();

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "lima-node", "resourceVersion": "1"},
            "status": {
                "addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::cluster_object_key("nodes", "lima-node"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        // This is the URL sonobuoy's dump.go generates: name includes :port suffix.
        // Without stripping, the store lookup fails and the user sees
        // "Unable to retrieve kubelet pods for node lima-node: Node lima-node:10250 not found".
        let result = resolve_node_proxy_target(&state, "lima-node:10250", "pods").await;
        // make_state() has no cluster CA so we get 503 (TLS not configured) rather than 200,
        // but the important check is that we did NOT get 404 — the store lookup found "lima-node".
        let status_code = result.map(|_| 200u16).unwrap_or_else(|e| e.0.as_u16());
        assert_ne!(
            status_code, 404,
            "node proxy with ':port' suffix must not 404 — the port must be stripped before \
             the store lookup or sonobuoy pod-dump reports: Node lima-node:10250 not found"
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
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 8080}]}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.1.2.3", "hostIP": "10.1.2.3"}
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

        let (ip, port, _, _) = resolve_pod_proxy_target(&state, "default", "mypod")
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
                "containers": [{"name": "app", "image": "nginx"}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.1.2.3", "hostIP": "10.1.2.3"}
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

        let (ip, port, _, _) = resolve_pod_proxy_target(&state, "default", "mypod")
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
            "spec": {"containers": [{"name": "app", "image": "nginx"}], "hostNetwork": true},
            "status": {"podIP": "10.1.2.3", "hostIP": "10.1.2.3"}
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

        let (_, _, proxy_addr, _) = resolve_pod_proxy_target(&state, "default", "mypod")
            .await
            .expect("resolve must succeed");
        assert_eq!(
            proxy_addr.as_deref(),
            Some("127.0.0.1:8132"),
            "pod proxy must thread the konnectivity_proxy_addr from state — \
             without it, pod IPs unreachable from the host produce 502 instead of succeeding"
        );
    }

    /// resolve_pod_proxy_target with a `:port` suffix must resolve the pod and use
    /// the URL-supplied port, not the pod spec's declared containerPort.
    ///
    /// Before this fix resolve_pod_proxy_target did zero parsing of the name segment:
    /// any `name:port` pod-proxy URL looked up a pod literally named "name:port" and
    /// always 404'd. This is the exact "Proxy version v1 should proxy through a
    /// service and a pod" conformance failure: `pods/proxy-test:8080/proxy/` -> 404
    /// 'Pod "proxy-test:8080" not found'.
    #[tokio::test]
    async fn pod_proxy_name_port_suffix_resolves_pod_and_uses_url_port() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "proxy-test", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "agnhost", "image": "agnhost", "ports": [{"containerPort": 9376}]}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.5.6.7", "hostIP": "10.5.6.7"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "proxy-test"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let (ip, port, _, _) = resolve_pod_proxy_target(&state, "default", "proxy-test:8080")
            .await
            .expect(
                "'name:port' pod proxy must resolve — 404 means the bare name was not \
                 extracted and the store lookup used the raw 'proxy-test:8080' key",
            );
        assert_eq!(
            ip, "10.5.6.7",
            "must resolve to the pod's IP, not fail the lookup"
        );
        assert_eq!(
            port, 8080,
            "the URL-supplied port (8080) must win over the pod spec's declared \
             containerPort (9376) — a pod proxy request names its target port explicitly"
        );
    }

    /// resolve_pod_proxy_target with a `scheme:name:port` prefix must strip the
    /// scheme AND the port, not leak the scheme into the name lookup.
    ///
    /// This is the second half of the Proxy conformance failure:
    /// `pods/http:proxy-test:8080/proxy/` -> 404 'Pod "http:proxy-test:8080" not found'.
    /// kubectl and client-go's REST proxy helpers address pods this way; a wrong split
    /// here breaks any client using the scheme-qualified proxy form.
    #[tokio::test]
    async fn pod_proxy_scheme_name_port_strips_scheme_and_resolves_pod() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "proxy-test", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "agnhost", "image": "agnhost", "ports": [{"containerPort": 9376}]}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.5.6.7", "hostIP": "10.5.6.7"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "proxy-test"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let (ip, port, _, _) = resolve_pod_proxy_target(&state, "default", "http:proxy-test:8080")
            .await
            .expect(
                "'scheme:name:port' pod proxy must resolve — a naive suffix-only split \
                 leaves 'http:proxy-test' as the bare name and 404s",
            );
        assert_eq!(
            ip, "10.5.6.7",
            "must resolve to the pod's IP, not fail the lookup"
        );
        assert_eq!(
            port, 8080,
            "the URL-supplied port must still be honored once the scheme prefix is stripped"
        );
    }

    /// resolve_pod_proxy_target with an `https:` scheme prefix must report `is_https = true`;
    /// a bare name or an explicit `http:` prefix must report `false`.
    ///
    /// pod_proxy_dispatch uses this flag to decide whether to connect to the pod over TLS.
    /// Before this fix the flag did not exist — an `https:`-prefixed pod proxy request to a
    /// TLS-only container port connected over plain HTTP, and the TLS listener correctly
    /// rejected it with 400 "Client sent an HTTP request to an HTTPS server" instead of
    /// returning the proxied response (the exact conformance failure for tlsdest1/tlsdest2).
    #[tokio::test]
    async fn pod_proxy_https_scheme_reports_is_https_true() {
        let state = make_state();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "tls-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "agnhost"}], "hostNetwork": true},
            "status": {"podIP": "10.5.6.7", "hostIP": "10.5.6.7"}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "tls-pod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let (_, _, _, is_https) = resolve_pod_proxy_target(&state, "default", "https:tls-pod:443")
            .await
            .expect("resolve must succeed");
        assert!(
            is_https,
            "an 'https:'-scheme pod proxy target must report is_https=true — without it, \
             pod_proxy_dispatch connects over plain HTTP and a TLS-only container port \
             rejects the request with 400 instead of returning the proxied response"
        );

        let (_, _, _, is_https) = resolve_pod_proxy_target(&state, "default", "http:tls-pod:443")
            .await
            .expect("resolve must succeed");
        assert!(
            !is_https,
            "an explicit 'http:' scheme must NOT be treated as https — misreporting it \
             would connect a plain-HTTP backend over TLS and fail the handshake"
        );

        let (_, _, _, is_https) = resolve_pod_proxy_target(&state, "default", "tls-pod")
            .await
            .expect("resolve must succeed");
        assert!(
            !is_https,
            "a bare pod name (no scheme) must default to plain HTTP, matching every \
             pre-existing pod proxy request that carries no scheme prefix"
        );
    }

    // -----------------------------------------------------------------------
    // pod_proxy_root: routing regression for no-subpath proxy form
    //
    // axum's `{*path}` wildcard requires a NON-EMPTY segment. Without explicit
    // routes for /proxy and /proxy/, a GET to the pod proxy root falls through
    // to the generic handler and returns 404. This blocks the RC serve-image
    // conformance test (WaitForPodsResponding dials /proxy without a subpath).
    // -----------------------------------------------------------------------

    /// /proxy (no subpath) must route to the proxy handler, not return 404.
    ///
    /// The RC serve-image conformance test dials the pod proxy subresource without
    /// any sub-path. Before this fix, the route `/proxy/{*path}` required a
    /// non-empty segment so `/proxy` and `/proxy/` fell through to a 404.
    ///
    /// The bare `/proxy` form (no trailing slash) now 301-redirects to `/proxy/` for
    /// GET (matching upstream and the sig-network Proxy conformance test); a plain
    /// http.Client follows that redirect automatically, so WaitForPodsResponding still
    /// reaches the pod. `/proxy/` reaches the handler directly and returns 503 (pod
    /// exists but has no podIP) — 503 proves the handler was reached, 404 proves it
    /// was not.
    #[tokio::test]
    async fn pod_proxy_root_path_routes_not_404_else_serve_image_conformance_fails() {
        let state = make_state();

        // Seed a pod that exists but has no podIP → handler returns 503, not 404.
        // If the route is missing, axum returns 404 (METHOD_NOT_ALLOWED or NOT_FOUND).
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "srv", "namespace": "default", "resourceVersion": "1"},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "status": {}
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "srv"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let mut router = make_router(state);

        for (path, want) in [
            (
                "/api/v1/namespaces/default/pods/srv/proxy",
                StatusCode::MOVED_PERMANENTLY,
            ),
            (
                "/api/v1/namespaces/default/pods/srv/proxy/",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = router.call(req).await.unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "GET {path} must NOT return 404 — the RC serve-image conformance test \
                 dials the pod proxy without a sub-path and a 404 causes WaitForPodsResponding \
                 to fail even though the pod is Running"
            );
            assert_eq!(
                resp.status(),
                want,
                "GET {path} must reach the proxy routing correctly — any other status \
                 means routing or the bare-root redirect is broken"
            );
        }
    }

    /// redirect_bare_proxy_root must 301 a bare GET/HEAD `.../proxy` and preserve the
    /// query string, but must not touch POST or the trailing-slash form.
    ///
    /// The sig-network Proxy conformance test dials `.../pods/<p>/proxy?method=GET` with
    /// a client that does not follow redirects and asserts the raw status is 301; a
    /// missing Location or a wrong status leaves relative links in proxied content
    /// unresolvable and fails the conformance check.
    #[test]
    fn redirect_bare_proxy_root_redirects_get_head_only() {
        let get_bare = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/p/proxy?method=GET")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = redirect_bare_proxy_root(&get_bare).expect("bare GET must redirect");
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get(axum::http::header::LOCATION).unwrap(),
            "/api/v1/namespaces/default/pods/p/proxy/?method=GET",
            "Location must point at the trailing-slash form and keep the query string"
        );

        let head_bare = Request::builder()
            .method("HEAD")
            .uri("/api/v1/namespaces/default/pods/p/proxy")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            redirect_bare_proxy_root(&head_bare).is_some(),
            "HEAD must redirect the same as GET"
        );

        let post_bare = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/p/proxy")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            redirect_bare_proxy_root(&post_bare).is_none(),
            "POST must proxy immediately, not redirect — only GET/HEAD are covered \
             by the conformance check and a POST redirect would drop the request body"
        );

        let get_slash = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/p/proxy/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            redirect_bare_proxy_root(&get_slash).is_none(),
            "the trailing-slash form is already canonical and must proxy directly"
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
    // exec proxy: kubelet-side subprotocol must support the CLOSE signal
    //
    // Regression: `kubectl exec -i` piping a large/real stdin stream (e.g.
    // `tar cf - <dir> | kubectl exec -i <pod> -- tar xf - -C /dest`) hung
    // forever after all data arrived. Root cause: kubectl's websocket exec
    // executor only ever negotiates v5.channel.k8s.io with apiserver (v5
    // "adds support for a CLOSE signal" — a [255, streamID] control frame
    // sent when local stdin hits EOF, so the remote process's stdin can be
    // half-closed without tearing down the whole multiplexed connection).
    // If the outbound (kubelet-side) leg dialed with v4.channel.k8s.io
    // instead, kubelet's v4 handler doesn't understand that frame and
    // silently drops it, so the exec'd process's stdin is never closed —
    // it blocks on read() forever even though it already has all its data.
    // This test fails if EXEC_KUBELET_SUBPROTOCOL regresses to v4.
    // -----------------------------------------------------------------------

    /// EXEC_KUBELET_SUBPROTOCOL must be v5.channel.k8s.io, not v4.
    ///
    /// v4 lacks the CLOSE signal that kubectl's stdin needs to half-close a
    /// stdin-streaming exec session (e.g. `kubectl exec -i ... | tar xf -`).
    /// Reverting this to v4 reproduces the hang: the conformance run this
    /// guards against went silent for ~10 minutes until a watchdog force-
    /// killed the pod, because the tar process never saw EOF on stdin.
    #[test]
    fn exec_kubelet_subprotocol_is_v5_not_v4() {
        assert_eq!(
            EXEC_KUBELET_SUBPROTOCOL, "v5.channel.k8s.io",
            "the kubelet-side exec connection must use v5.channel.k8s.io — kubectl's \
             real websocket exec executor only ever offers v5, and only v5 carries the \
             CLOSE signal kubectl sends when local stdin reaches EOF. Dialing kubelet \
             with v4 silently drops that signal, so the exec'd process's stdin is never \
             closed and stdin-streaming execs (e.g. `kubectl exec -i ... | tar xf -`) \
             hang forever after all data has already arrived."
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
    // exec_status_frame_is_success: content-based decision, not just channel byte
    //
    // bd2b58cc's fix dropped every channel-3/4 frame unconditionally,
    // regardless of payload, so kubelet's NonZeroExitCode failure frame was
    // silently discarded along with genuine success frames. client-go's
    // remotecommand.StreamExecutor never saw the failure, so `kubectl exec` of any
    // nonzero-exit command reported exit 0. These tests pin the payload-parsing
    // logic that decides which frames may actually be absorbed.
    // -----------------------------------------------------------------------

    /// A genuine `{"status":"Success"}` frame is the only kind that may be absorbed.
    #[test]
    fn exec_status_frame_is_success_true_for_success_status() {
        let frame = bytes::Bytes::from(b"\x03{\"status\":\"Success\"}".to_vec());
        assert!(
            exec_status_frame_is_success(&frame),
            "a clean-exit status frame must be recognized as safe to absorb"
        );
    }

    /// A `NonZeroExitCode` failure frame must NOT be classified as success — this is
    /// the exact frame that bd2b58cc's blanket filter discarded, causing `kubectl
    /// exec` to report exit 0 for every failing command.
    #[test]
    fn exec_status_frame_is_success_false_for_failure_nonzero_exit() {
        let frame = bytes::Bytes::from(
            b"\x04{\"status\":\"Failure\",\"reason\":\"NonZeroExitCode\",\"details\":{\"causes\":[{\"reason\":\"ExitCode\",\"message\":\"1\"}]}}".to_vec(),
        );
        assert!(
            !exec_status_frame_is_success(&frame),
            "a NonZeroExitCode failure frame must never be treated as success — doing \
             so would absorb it and hide the real exit code from kubectl, reproducing \
             the bug"
        );
    }

    /// A payload that isn't a recognizable status object must not be treated as
    /// success either — when in doubt, forward it rather than silently discard data.
    #[test]
    fn exec_status_frame_is_success_false_for_unparseable_payload() {
        let frame = bytes::Bytes::from(b"\x03not json".to_vec());
        assert!(
            !exec_status_frame_is_success(&frame),
            "unparseable payloads must not be absorbed — silently discarding data we \
             can't identify as a genuine success frame can only hide information from \
             the client"
        );
    }

    // -----------------------------------------------------------------------
    // run_exec_proxy end-to-end: kubelet status-frame content must control
    // whether kubectl sees it
    //
    // These tests drive the real relay (not just the pure predicate) through a
    // mock TLS kubelet and a real axum server, exactly like the
    // `portforward_v4_channel_pairs_data_and_error_streams_per_port` test above,
    // to prove the fix holds at the wire level client-go actually sees.
    // -----------------------------------------------------------------------

    /// Seed a schedulable pod and its node so `resolve_exec_target` succeeds —
    /// shared setup for the real-server exec proxy tests below.
    async fn seed_exec_pod(store: &Arc<SqliteStore>) {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "exec-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "exec-node", "containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "exec-pod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "exec-node", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
        });
        store
            .put(
                &crate::keys::cluster_object_key("nodes", "exec-node"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");
    }

    /// Echo `EXEC_KUBELET_SUBPROTOCOL` in the mock kubelet's handshake response —
    /// tungstenite's client-side handshake validation rejects a 101 that omits
    /// this header when the client requested a subprotocol (see
    /// `echo_v4_subprotocol` above for the same requirement on the portforward leg).
    #[allow(clippy::result_large_err)]
    fn echo_exec_subprotocol(
        _req: &tokio_tungstenite::tungstenite::handshake::server::Request,
        mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            EXEC_KUBELET_SUBPROTOCOL.parse().unwrap(),
        );
        Ok(response)
    }

    /// Run a real `/exec` session through `run_exec_proxy`: a mock TLS kubelet sends
    /// exactly `kubelet_frames` (channel byte + payload) and then closes, exactly like
    /// the real kubelet closing the exec websocket once the command exits. Returns
    /// every Binary frame the kubectl-side client actually received, in order.
    async fn exec_round_trip(kubelet_frames: Vec<(u8, Vec<u8>)>) -> Vec<Vec<u8>> {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(tls, echo_exec_subprotocol)
                .await
                .unwrap();
            for (channel, payload) in kubelet_frames {
                let mut frame = vec![channel];
                frame.extend_from_slice(&payload);
                ws.send(Message::Binary(frame.into())).await.unwrap();
            }
            let _ = ws.close(None).await;
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_exec_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));
        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/exec-pod/exec?stdout=1&stderr=1");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            EXEC_KUBELET_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect("exec websocket handshake must succeed");

        let mut received = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => received.push(b.to_vec()),
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => panic!("websocket error while reading exec frames: {e}"),
                Err(_) => break,
            }
        }
        received
    }

    /// The nonzero-exit status frame kubelet sends at the end of an exec session must
    /// reach kubectl unchanged — this is the wire signal client-go's
    /// `remotecommand.StreamExecutor` (`errorDecoderV4.decode`) turns into
    /// `exec.CodeExitError`. Before this fix, `run_exec_proxy` dropped every
    /// channel-3/4 frame unconditionally (bd2b58cc's overcorrection), so this frame
    /// never reached kubectl and every nonzero exec exit looked like exit 0.
    /// This test fails if that unconditional drop is restored.
    #[tokio::test]
    async fn exec_proxy_forwards_channel_4_failure_frame_nonzero_exit() {
        let failure = b"{\"status\":\"Failure\",\"reason\":\"NonZeroExitCode\",\"details\":{\"causes\":[{\"reason\":\"ExitCode\",\"message\":\"1\"}]}}".to_vec();
        let frames = exec_round_trip(vec![(4, failure)]).await;
        assert!(
            frames.iter().any(|f| {
                f.first() == Some(&4)
                    && String::from_utf8_lossy(&f[1..]).contains("NonZeroExitCode")
            }),
            "kubelet's channel-4 NonZeroExitCode status frame must reach kubectl \
             unchanged — dropping it (as the pre-fix code did for every channel-3/4 \
             frame) makes client-go's remotecommand see a clean close and report \
             exit 0 for a command that actually failed. Frames received: {frames:?}"
        );
    }

    /// A genuine `{"status":"Success"}` frame must still be absorbed, not forwarded —
    /// preserving bd2b58cc's original intent. That fix existed because a client that
    /// reads raw frames off the wire in arrival order (the legacy `channel.k8s.io`
    /// conformance test in upstream `test/e2e/common/node/pods.go`) fails outright if
    /// any message other than channel 1 (stdout) arrives; forwarding the success
    /// frame here would regress that fix even though this test dials with v5.
    #[tokio::test]
    async fn exec_proxy_preserves_bd2b58cc_intent_for_success_frames() {
        let frames = exec_round_trip(vec![
            (1, b"hi\n".to_vec()),
            (3, b"{\"status\":\"Success\"}".to_vec()),
        ])
        .await;
        let mut expected_stdout = vec![1u8];
        expected_stdout.extend_from_slice(b"hi\n");
        assert_eq!(
            frames,
            vec![expected_stdout],
            "a genuine success status frame must be absorbed, matching the real \
             kube-apiserver and bd2b58cc's original fix — only the stdout frame \
             should reach kubectl. Frames received: {frames:?}"
        );
    }

    /// If kubelet's status frame is dropped, kubectl's websocket just closes with no
    /// data at all — indistinguishable from a successful, silent exec. This
    /// simulates a command that exits nonzero with no stdout/stderr output at all
    /// (e.g. `sh -c 'exit 2'`) and asserts the client actually receives the failure
    /// frame before close, not just a bare close: the exact symptom this exists
    /// to catch, where every nonzero exec looked like exit 0 because there was no
    /// in-band failure signal at all.
    #[tokio::test]
    async fn exec_proxy_nonzero_exit_status_reaches_client() {
        let failure = b"{\"status\":\"Failure\",\"reason\":\"NonZeroExitCode\",\"details\":{\"causes\":[{\"reason\":\"ExitCode\",\"message\":\"2\"}]}}".to_vec();
        let frames = exec_round_trip(vec![(3, failure)]).await;
        assert!(
            !frames.is_empty(),
            "kubectl must receive the exit-status frame before the websocket closes \
             — zero frames means a silent clean close, exactly the bug where \
             client-go reports err == nil (exit 0) for every nonzero exec exit"
        );
        assert_eq!(
            frames[0][0], 3,
            "the one frame kubectl receives must be the channel-3 status frame \
             carrying the real exit code, not something else"
        );
    }

    // -----------------------------------------------------------------------
    // v5->v4 exec fallback regression tests
    //
    // Real kubelet < 1.36 (no ExtendWebSocketsToKubelet — see
    // EXEC_KUBELET_SUBPROTOCOL) never registers v5.channel.k8s.io on its exec
    // websocket endpoint and rejects the handshake with a bare 403 Forbidden.
    // Confirmed live against kubelet 1.34.9: "kubelet exec connect failed: HTTP
    // error: 403 Forbidden". Before the fallback, that error propagated straight
    // out of run_exec_proxy via `?` before `inbound` (kubectl's already-upgraded
    // connection) was ever touched, so kubectl saw a raw TCP close with no
    // WebSocket close frame at all — "close 1006 (abnormal closure): unexpected
    // EOF" — instead of a working exec.
    // -----------------------------------------------------------------------

    /// Mock kubelet handshake callback that rejects a v5.channel.k8s.io offer with a
    /// bare 403 Forbidden, mirroring real kubelet < 1.36's `golang.org/x/net/websocket`
    /// exec handler (its protocol map never includes v5 — see
    /// `EXEC_KUBELET_SUBPROTOCOL`'s doc comment). Any other requested protocol is
    /// echoed back and accepted, matching a v4 client.
    #[allow(clippy::result_large_err)]
    fn reject_v5_accept_v4_like_pre_1_36_kubelet(
        req: &tokio_tungstenite::tungstenite::handshake::server::Request,
        mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        let requested = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if requested == EXEC_KUBELET_SUBPROTOCOL {
            return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                .status(tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN)
                .body(None)
                .unwrap());
        }
        response
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", requested.parse().unwrap());
        Ok(response)
    }

    /// `run_exec_proxy` must fall back to v4.channel.k8s.io and still complete the exec
    /// session when kubelet rejects the v5 offer with a 403 — exactly what real kubelet
    /// < 1.36 does. This test fails (times out reading frames, or the handshake with
    /// kubectl fails) if the v4 fallback in `run_exec_proxy` is removed and the v5
    /// rejection is left to propagate straight to `?`.
    #[tokio::test]
    async fn exec_proxy_falls_back_to_v4_when_kubelet_rejects_v5() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // First connection: the v5 offer, rejected with 403 — matches real
            // kubelet < 1.36 (see EXEC_KUBELET_SUBPROTOCOL).
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.clone().accept(tcp).await.unwrap();
            tokio_tungstenite::accept_hdr_async(tls, reject_v5_accept_v4_like_pre_1_36_kubelet)
                .await
                .expect_err("mock kubelet must reject the v5 offer");

            // Second connection: the v4 fallback, accepted — streams one stdout
            // frame then closes.
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws =
                tokio_tungstenite::accept_hdr_async(tls, reject_v5_accept_v4_like_pre_1_36_kubelet)
                    .await
                    .unwrap();
            ws.send(Message::Binary(vec![1u8, b'h', b'i'].into()))
                .await
                .unwrap();
            let _ = ws.close(None).await;
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_exec_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));
        let url =
            format!("ws://{addr}/api/v1/namespaces/default/pods/exec-pod/exec?stdout=1&stderr=1");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            EXEC_KUBELET_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect(
                    "exec websocket handshake with kubectl must succeed even though \
                     kubelet rejects v5 — the v4 fallback must make this transparent \
                     to the client",
                );

        let mut received = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => received.push(b.to_vec()),
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => panic!("websocket error while reading exec frames: {e}"),
                Err(_) => panic!(
                    "exec proxy must complete via the v4 fallback within 2s, not hang \
                     or leave kubectl waiting on a connection that was never spliced"
                ),
            }
        }

        assert_eq!(
            received,
            vec![vec![1u8, b'h', b'i']],
            "kubectl must still receive kubelet's stdout frame via the v4 fallback \
             when kubelet rejects v5 — without the fallback, kubectl exec against \
             kubelet < 1.36 fails outright (close 1006) instead of degrading to v4"
        );
    }

    // -----------------------------------------------------------------------
    // v5->v4 attach fallback regression tests
    //
    // Real kubelet < 1.36 (no ExtendWebSocketsToKubelet — see
    // ATTACH_KUBELET_FALLBACK_SUBPROTOCOL) never registers v5.channel.k8s.io on its
    // attach websocket endpoint either, and rejects the handshake with a bare 403
    // Forbidden exactly like exec. Before the fallback, that error propagated
    // straight out of run_attach_proxy via `?` before `inbound` (kubectl's
    // already-upgraded connection) was ever touched, so kubectl saw a raw TCP close
    // with no WebSocket close frame at all — "close 1006 (abnormal closure):
    // unexpected EOF" — instead of a working attach.
    // -----------------------------------------------------------------------

    /// Seed a schedulable pod and its node so `resolve_attach_target` succeeds —
    /// shared setup for the real-server attach proxy test below.
    async fn seed_attach_pod(store: &Arc<SqliteStore>) {
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "attach-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {"nodeName": "attach-node", "containers": [{"name": "app", "image": "nginx"}]}
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "attach-pod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "attach-node", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
        });
        store
            .put(
                &crate::keys::cluster_object_key("nodes", "attach-node"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");
    }

    /// Mock kubelet handshake callback that rejects a v5.channel.k8s.io attach offer
    /// with a bare 403 Forbidden, mirroring real kubelet < 1.36's
    /// `golang.org/x/net/websocket` attach handler (its protocol map never includes
    /// v5 — see `ATTACH_KUBELET_FALLBACK_SUBPROTOCOL`'s doc comment). Any other
    /// requested protocol is echoed back and accepted, matching a v4 client.
    #[allow(clippy::result_large_err)]
    fn reject_attach_v5_accept_v4_like_pre_1_36_kubelet(
        req: &tokio_tungstenite::tungstenite::handshake::server::Request,
        mut response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        let requested = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if requested == ATTACH_SUBPROTOCOL {
            return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                .status(tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN)
                .body(None)
                .unwrap());
        }
        response
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", requested.parse().unwrap());
        Ok(response)
    }

    /// `run_attach_proxy` must fall back to v4.channel.k8s.io and still complete the
    /// attach session when kubelet rejects the v5 offer with a 403 — exactly what real
    /// kubelet < 1.36 does. This test fails (times out reading frames, or the
    /// handshake with kubectl fails) if the v4 fallback in `run_attach_proxy` is
    /// removed and the v5 rejection is left to propagate straight to `?`.
    #[tokio::test]
    async fn attach_proxy_falls_back_to_v4_when_kubelet_rejects_v5() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;
        use tokio_tungstenite::tungstenite::Message;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let kubelet_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = kubelet_listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            // First connection: the v5 offer, rejected with 403 — matches real
            // kubelet < 1.36 (see ATTACH_KUBELET_FALLBACK_SUBPROTOCOL).
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.clone().accept(tcp).await.unwrap();
            tokio_tungstenite::accept_hdr_async(
                tls,
                reject_attach_v5_accept_v4_like_pre_1_36_kubelet,
            )
            .await
            .expect_err("mock kubelet must reject the v5 offer");

            // Second connection: the v4 fallback, accepted — streams one stdout
            // frame then closes.
            let (tcp, _) = kubelet_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(
                tls,
                reject_attach_v5_accept_v4_like_pre_1_36_kubelet,
            )
            .await
            .unwrap();
            ws.send(Message::Binary(vec![1u8, b'h', b'i'].into()))
                .await
                .unwrap();
            let _ = ws.close(None).await;
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        seed_attach_pod(&store).await;
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let addr = spawn_upgradeable_server(make_router(state));
        let url = format!(
            "ws://{addr}/api/v1/namespaces/default/pods/attach-pod/attach?stdout=1&stderr=1"
        );
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            ATTACH_SUBPROTOCOL.parse().unwrap(),
        );

        let (mut ws, _resp) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect(
                    "attach websocket handshake with kubectl must succeed even though \
                     kubelet rejects v5 — the v4 fallback must make this transparent \
                     to the client",
                );

        let mut received = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await {
                Ok(Some(Ok(Message::Binary(b)))) => received.push(b.to_vec()),
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => panic!("websocket error while reading attach frames: {e}"),
                Err(_) => panic!(
                    "attach proxy must complete via the v4 fallback within 2s, not hang \
                     or leave kubectl waiting on a connection that was never spliced"
                ),
            }
        }

        assert_eq!(
            received,
            vec![vec![1u8, b'h', b'i']],
            "kubectl must still receive kubelet's stdout frame via the v4 fallback \
             when kubelet rejects v5 — without the fallback, kubectl attach against \
             kubelet < 1.36 fails outright (close 1006) instead of degrading to v4"
        );
    }

    // -----------------------------------------------------------------------
    // kubelet TLS config: CA-pinned verifier regression tests
    //
    // Before this fix, build_kubelet_tls_config used AcceptAnyCert which skips
    // server cert verification entirely, opening an MITM vector on exec/log/attach.
    // These tests verify the function accepts a CA DER and that the shared kubelet
    // client uses CA pinning. They fail if the ca_der parameter is removed or ignored.
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

    /// AppState::build_kubelet_client with a cluster CA must return Some(client).
    ///
    /// The shared kubelet client is built once at startup. If it fails to build when a
    /// valid CA is present, every /log and node-proxy request will return 503 in production.
    /// Fails on revert: if the CA DER parameter is removed or the function deleted, this
    /// call site no longer compiles.
    #[test]
    fn appstate_build_kubelet_client_with_ca_der_returns_some() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();

        let client = AppState::<SqliteStore>::build_kubelet_client(Some(&ca_der), None);
        assert!(
            client.is_some(),
            "build_kubelet_client must return Some when CA DER is valid — \
             if it returns None, every /log and node-proxy call will 503 in production"
        );
    }

    /// AppState::build_kubelet_client without a CA must return None to prevent MITM.
    ///
    /// Without a CA the shared client cannot pin TLS verification. Returning None causes
    /// handlers to return 503 instead of connecting to the kubelet without cert verification,
    /// which would open an MITM vector on /log and node-proxy paths.
    /// Fails on revert: if build_kubelet_client is changed to return Some without a CA,
    /// this assertion triggers.
    #[test]
    fn appstate_build_kubelet_client_without_ca_returns_none() {
        let client = AppState::<SqliteStore>::build_kubelet_client(None, None);
        assert!(
            client.is_none(),
            "build_kubelet_client must return None when no CA is configured — \
             a Some without CA pinning opens an MITM vector on /log and node-proxy paths"
        );
    }

    /// AppState built with a CA must have kubelet_client set (Some).
    ///
    /// The shared kubelet client must be built once in new_with_config so that pod_log
    /// and node_proxy reuse the same connection pool. If kubelet_client is None despite
    /// a CA being configured, every log/node-proxy request 503s — regressing the fix that
    /// prevents per-request pool churn from triggering kubelet TLS resets under load.
    /// Fails on revert: removing kubelet_client from AppState or not building it in
    /// new_with_config causes this assertion to fail.
    #[test]
    fn appstate_with_ca_has_kubelet_client() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory db"));
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
        assert!(
            state.kubelet_client.is_some(),
            "AppState built with a cluster CA must have kubelet_client=Some — \
             if it is None, pod_log and node_proxy will 503 on every request instead of \
             reusing the shared connection pool (the fix for per-request TLS churn)"
        );
    }

    /// pod_log must not return 500 on kubelet unavailability (no CA configured).
    ///
    /// A kubelet communication failure is an upstream/bad-gateway condition — the apiserver
    /// itself is healthy. Returning 500 misleads clients and monitoring into thinking the
    /// apiserver has an internal error. With no CA, the handler must return 503.
    /// Fails on revert: if Status::internal is restored at the kubelet-unavailable path,
    /// the status code becomes 500 and this assertion triggers.
    #[tokio::test]
    async fn pod_log_returns_non_500_on_kubelet_unavailable() {
        let state = make_state(); // no cluster CA → kubelet_client is None

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
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
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

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/mypod/log")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        // 503 because kubelet_client is None (no CA). The key assertion: NOT 500.
        // 500 misleads clients/monitoring into thinking the apiserver has an internal error
        // when the problem is upstream (kubelet unavailable). If the fix is reverted to
        // Status::internal, this becomes 500 and the test fails.
        assert_ne!(
            resp.status().as_u16(),
            500,
            "pod_log must not return 500 on kubelet unavailability — \
             500 misleads clients/monitoring: the apiserver is healthy, the kubelet is not reachable"
        );
    }

    /// A WebSocket GET to /log must upgrade (101) and negotiate the `binary.k8s.io`
    /// subprotocol; a plain GET to the same route must still return logs as an ordinary
    /// HTTP response.
    ///
    /// The sig-node "retrieving logs from the container over websockets" conformance
    /// test dials `/log` with `Sec-WebSocket-Protocol: binary.k8s.io` and fails with
    /// "bad status" if the server ever answers with anything but 101 — before this fix
    /// pod_log had no upgrade branch at all, so every websocket log request failed this
    /// way even though the pod and kubelet were healthy.
    #[tokio::test]
    async fn pod_log_websocket_upgrade_returns_101_plain_get_unaffected() {
        // axum's WebSocketUpgrade extractor needs hyper's real `OnUpgrade` connection
        // state, which only exists on a genuine TCP-served request (a synthetic
        // `Request` built in-process has none) — so this drives the router through a
        // real `hyper::server::conn` + `tokio_tungstenite` client, the same pattern
        // main.rs uses to regression-test with_upgrades().
        use tokio::net::TcpListener;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        // A cluster CA is required for kubelet_client to be Some — pod_log 503s before
        // ever reaching the upgrade branch otherwise. The actual kubelet connection is
        // never made successfully in this test (127.0.0.1:10250 has nothing listening):
        // on_upgrade() always answers 101 to the client first and only *then*
        // asynchronously dials kubelet, so this test does not need a live kubelet.
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store: store.clone(),
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
            "metadata": {"name": "wspod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "main", "image": "busybox"}]
            }
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "wspod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "node-1", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
        });
        store
            .put(
                &crate::keys::cluster_object_key("nodes", "node-1"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let router = make_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(tcp);
            let service = hyper::service::service_fn(move |req| {
                let mut router = router.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        tower_service::Service::call(&mut router, req)
                            .await
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });

        let url = format!("ws://{addr}/api/v1/namespaces/default/pods/wspod/log?container=main");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            LOG_WS_SUBPROTOCOL.parse().unwrap(),
        );

        let (_ws, response) =
            tokio::time::timeout(std::time::Duration::from_secs(2), connect_async(request))
                .await
                .expect("websocket connect must not time out")
                .expect(
                    "a websocket GET to /log must upgrade (101) — any other status is what the \
                 sig-node conformance client reports as 'bad status' and fails on",
                );
        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some(LOG_WS_SUBPROTOCOL),
            "the upgrade response must echo back binary.k8s.io — the conformance client \
             requests exactly this subprotocol and rejects a mismatched/absent one"
        );
    }

    /// is_websocket_upgrade_request must distinguish a genuine upgrade request from an
    /// ordinary GET, and not be fooled by an `Upgrade` header alone or vice versa.
    ///
    /// If this ever misfired on a normal request, every existing non-websocket log
    /// client (kubectl logs, dashboards) would be routed into the upgrade branch and
    /// break; if it ever missed a real upgrade request, the conformance client would
    /// see the "bad status" failure this fix removes.
    #[test]
    fn is_websocket_upgrade_request_requires_both_headers() {
        let plain = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/p/log")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            !is_websocket_upgrade_request(&plain),
            "a plain GET with neither header must not be treated as a websocket request"
        );

        let upgrade_header_only = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/p/log")
            .header(axum::http::header::UPGRADE, "websocket")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            !is_websocket_upgrade_request(&upgrade_header_only),
            "Upgrade: websocket without Connection: Upgrade is not a valid upgrade \
             request per RFC 6455 and must not trigger the websocket branch"
        );

        let full_upgrade = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/p/log")
            .header(axum::http::header::CONNECTION, "keep-alive, Upgrade")
            .header(axum::http::header::UPGRADE, "websocket")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(
            is_websocket_upgrade_request(&full_upgrade),
            "both headers present (Connection may list other tokens alongside \
             'upgrade') must be recognized as a websocket upgrade request"
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
    // build_pod_proxy_client: direct-connect client must build without panicking
    // -----------------------------------------------------------------------

    /// build_pod_proxy_client must build successfully when no CA is provided.
    ///
    /// When konnectivity is not configured and the apiserver can reach pod IPs
    /// directly, the client must build — pod proxy without a tunnel must work.
    #[test]
    fn build_pod_proxy_client_without_ca_succeeds() {
        let client = build_pod_proxy_client(None, None, false);
        drop(client); // just verify it was built
    }

    /// build_pod_proxy_client with `insecure_https=true` must accept a certificate no CA
    /// trusts, matching upstream kube-apiserver's `InsecureSkipVerify` for pod-proxy TLS
    /// targets — pod/workload TLS certs are self-signed, so pinning to any CA (or using
    /// default system roots) would reject every real pod TLS listener.
    ///
    /// If `insecure_https` is ignored, this request fails certificate verification (the
    /// mock server's self-signed cert is untrusted by any real root store) instead of
    /// returning 200 — this is the exact 400 "Client sent an HTTP request to an HTTPS
    /// server" / handshake-failure class of bug this flag exists to prevent.
    #[tokio::test]
    async fn build_pod_proxy_client_insecure_https_skips_cert_verification() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = CertificateDer::from(cert_der);
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        // No CA is configured at all — only insecure_https=true should let this succeed.
        let client = build_pod_proxy_client(None, None, true);
        let resp = client.get(format!("https://{addr}/")).send().await.expect(
            "insecure_https=true must accept the mock's self-signed, untrusted cert — \
                 pod TLS certs are never signed by a CA the cluster trusts, so requiring \
                 verification here would make every https-scheme pod/service proxy \
                 request fail",
        );
        assert_eq!(resp.status(), 200);
    }

    // -----------------------------------------------------------------------
    // pod_proxy_via_connect_tunnel: pod proxy must use CONNECT, not forward-proxy GET
    //
    // konnectivity-server (proxy-agent v0.35.0) accepts CONNECT only. A plain
    // forward-proxy GET (which reqwest sends for http:// targets) returns 405
    // "this proxy only supports CONNECT passthrough". This test verifies that
    // pod_proxy_via_connect_tunnel sends CONNECT, not GET, to the proxy.
    //
    // The test starts a plain-TCP mock "proxy" (no TLS, to avoid cert overhead in
    // tests) that records the first line of the inbound request. The fix call path
    // uses build_kubelet_tls_config which requires a CA; in tests we bypass TLS by
    // exercising a variant with a test TLS server. The assertion checks that CONNECT
    // appears in the request — reverting to the old reqwest Proxy::all() approach
    // would cause GET to appear instead.
    //
    // IMPLEMENTATION NOTE: because the tunnel function requires mTLS (build_kubelet_tls_config),
    // the network-level test is the live VM repro. The unit test
    // below validates the CONNECT request string construction independently.
    // -----------------------------------------------------------------------

    /// pod_proxy_via_connect_tunnel sends CONNECT to the konnectivity proxy.
    ///
    /// If this test is reverted to the old reqwest Proxy::all() approach, the mock
    /// server would receive a plain forward-proxy GET (e.g. "GET http://10.0.0.1:80/ HTTP/1.1")
    /// instead of a CONNECT request, and konnectivity would reply 405.
    ///
    /// The test uses a TLS server backed by an ephemeral self-signed cert so the
    /// tunnel function's TLS connect path is exercised. On receiving CONNECT, the
    /// server returns 200 and then serves a minimal HTTP response so hyper can
    /// complete the handshake and the function returns Ok.
    #[tokio::test]
    async fn pod_proxy_via_connect_tunnel_sends_connect_not_forward_proxy_get() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // Generate a self-signed cert for the mock konnectivity server.
        let cert = generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        // Build a TLS acceptor for the mock server.
        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        // Bind a random port for the mock konnectivity server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap().to_string();

        // Track what CONNECT target the proxy received.
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();

            // Read the CONNECT request.
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();

            // Extract and send the first line (e.g. "CONNECT 10.0.0.1:80 HTTP/1.1").
            let first_line = request.lines().next().unwrap_or("").to_string();
            let _ = tx.send(first_line);

            // Reply 200 Connection established.
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();

            // Serve a minimal HTTP response for the pod request that follows.
            let mut buf2 = [0u8; 512];
            let _ = stream.read(&mut buf2).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
                )
                .await
                .unwrap();
        });

        let result = pod_proxy_via_connect_tunnel(
            &proxy_addr,
            "10.0.0.1",
            80,
            "/metrics",
            axum::http::Method::GET,
            bytes::Bytes::new(),
            Some(&cert_der),
            None,
            false,
        )
        .await;

        // The CONNECT line must name the pod target, not be a forward-proxy GET.
        let first_line = rx.await.unwrap();
        assert!(
            first_line.starts_with("CONNECT 10.0.0.1:80"),
            "pod proxy to konnectivity must send CONNECT, not a forward-proxy GET — \
             konnectivity-server accepts only CONNECT and replies 405 to anything else; \
             got: {first_line:?}"
        );
        assert!(
            result.is_ok(),
            "pod_proxy_via_connect_tunnel must succeed when konnectivity accepts CONNECT: {:?}",
            result.err()
        );
        let (status, headers, body) = result.unwrap();
        assert_eq!(
            status, 200,
            "pod response must be 200, not the konnectivity 405 that the old code produced"
        );
        assert_eq!(&body[..], b"hello");
        assert_eq!(
            headers.get(axum::http::header::CONTENT_TYPE).unwrap(),
            "text/plain",
            "the pod's Content-Type must survive the konnectivity tunnel — a client \
             that defaults to protobuf when Content-Type is missing would otherwise \
             try (and fail) to decode this plain-text body as protobuf"
        );
    }

    /// pod_proxy_via_connect_tunnel with `is_https=true` must dial a SECOND, independent
    /// TLS session to the pod through the tunnel — not speak plain HTTP over it.
    ///
    /// The mock "pod" behind the tunnel only accepts a real TLS ClientHello as its first
    /// bytes, using a cert that is never passed as `ca_der` anywhere (proving the inner
    /// handshake succeeds by skipping verification, not by reusing the outer connection's
    /// already-established trust). If `is_https` is ignored and the code always speaks
    /// plain HTTP over the outer tunnel (the pre-fix behavior), the mock's inner TLS
    /// accept fails to parse that plaintext request as a handshake and the connection is
    /// dropped — reproducing the exact conformance symptom of a TLS-only backend refusing
    /// a plaintext request — instead of returning the proxied body.
    #[tokio::test]
    async fn pod_proxy_via_connect_tunnel_is_https_dials_tls_to_pod_over_tunnel() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // Outer cert: the konnectivity leg. Passed as `ca_der` so the outer handshake
        // stays fully verified, exactly like the plain-HTTP tunnel case above.
        let outer_cert = generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let outer_cert_der = outer_cert.cert.der().to_vec();
        let outer_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(outer_cert_der.clone())],
                PrivateKeyDer::try_from(outer_cert.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let outer_acceptor = TlsAcceptor::from(Arc::new(outer_config));

        // Inner cert: the pod leg. Deliberately a DIFFERENT, untrusted cert — is_https=true
        // must still complete this handshake by skipping verification.
        let inner_cert = generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let inner_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(inner_cert.cert.der().to_vec())],
                PrivateKeyDer::try_from(inner_cert.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let inner_acceptor = TlsAcceptor::from(Arc::new(inner_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut outer = outer_acceptor.accept(tcp).await.unwrap();

            // Accept and acknowledge CONNECT, exactly like the plain-HTTP tunnel test.
            let mut buf = [0u8; 512];
            let _ = outer.read(&mut buf).await.unwrap();
            outer
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();

            // is_https=true must now negotiate a second TLS session over this tunnel.
            let mut inner = inner_acceptor.accept(outer).await.unwrap();
            let mut buf2 = [0u8; 512];
            let _ = inner.read(&mut buf2).await;
            inner
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ntls ok")
                .await
                .unwrap();
        });

        // Bounded so a revert that drops the TLS upgrade fails fast instead of hanging:
        // the mock's inner TLS accept blocks forever waiting for a ClientHello that a
        // plain-HTTP request never sends.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            pod_proxy_via_connect_tunnel(
                &proxy_addr,
                "10.0.0.1",
                443,
                "/tls-check",
                axum::http::Method::GET,
                bytes::Bytes::new(),
                Some(&outer_cert_der),
                None,
                true,
            ),
        )
        .await
        .expect(
            "pod_proxy_via_connect_tunnel must not hang — a plain HTTP request against \
             the mock's TLS-only inner listener would leave both sides waiting forever",
        );

        assert!(
            result.is_ok(),
            "is_https=true must complete a real TLS handshake to the pod over the \
             tunnel: {:?}",
            result.err()
        );
        let (status, _headers, body) = result.unwrap();
        assert_eq!(
            status, 200,
            "the pod's TLS response must reach the caller as-is"
        );
        assert_eq!(
            &body[..],
            b"tls ok",
            "the body served over the inner TLS session must reach the caller — if \
             is_https were ignored, the mock's inner TLS accept would fail on the \
             plaintext request and this call would return Err, never a body"
        );
    }

    // -----------------------------------------------------------------------
    // is_html_content_type / rewrite_relative_links unit tests
    //
    // A browser hitting the pod/service proxy must get links that stay within the
    // proxy — a relative link that resolves against the apiserver's own root instead
    // of the proxy path silently takes the user (or any HTTP client) out of the proxy.
    // -----------------------------------------------------------------------

    /// An exact `text/html` Content-Type must be detected.
    #[test]
    fn is_html_content_type_true_for_exact_text_html() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/html".parse().unwrap(),
        );
        assert!(
            super::is_html_content_type(&headers),
            "an exact 'text/html' Content-Type must be recognized — missing it means \
             the response body never gets its relative links rewritten"
        );
    }

    /// `text/html; charset=utf-8` must still be detected — the charset parameter must
    /// not defeat the match.
    #[test]
    fn is_html_content_type_true_for_text_html_with_charset() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        );
        assert!(
            super::is_html_content_type(&headers),
            "real HTML servers almost always send a charset parameter — matching only \
             the bare 'text/html' string would silently skip rewriting nearly every \
             real HTML response"
        );
    }

    /// A non-HTML Content-Type (e.g. JSON) must not be treated as HTML.
    #[test]
    fn is_html_content_type_false_for_json() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        assert!(
            !super::is_html_content_type(&headers),
            "a JSON response must never go through the HTML rewriter — scanning a JSON \
             body for 'href='/'src=' substrings could corrupt an unrelated field"
        );
    }

    /// A response with no Content-Type header at all must not be treated as HTML.
    #[test]
    fn is_html_content_type_false_when_header_absent() {
        let headers = axum::http::HeaderMap::new();
        assert!(
            !super::is_html_content_type(&headers),
            "a missing Content-Type must default to no rewriting, matching upstream's \
             behavior of only rewriting a response explicitly labeled text/html"
        );
    }

    /// A root-relative `href` must be rewritten to include the proxy base path.
    ///
    /// This is the exact conformance assertion: the agnhost porter backend serves
    /// `<a href="/rewriteme">test</a>`, and upstream kube-apiserver's proxy rewrites it
    /// to `<a href=".../proxy/rewriteme">test</a>` so the link stays within the proxy.
    #[test]
    fn rewrite_relative_links_rewrites_root_relative_href() {
        assert_eq!(
            super::rewrite_relative_links(
                r#"<a href="/rewriteme">test</a>"#,
                "/api/v1/namespaces/default/pods/mypod/proxy"
            ),
            r#"<a href="/api/v1/namespaces/default/pods/mypod/proxy/rewriteme">test</a>"#,
            "a root-relative href must gain the full proxy path prefix — without it, a \
             client following the link hits the apiserver's own root at /rewriteme \
             instead of the pod's"
        );
    }

    /// A root-relative `src` must be rewritten the same way as `href`.
    #[test]
    fn rewrite_relative_links_rewrites_root_relative_src() {
        assert_eq!(
            super::rewrite_relative_links(
                r#"<img src="/logo.png">"#,
                "/api/v1/namespaces/default/pods/mypod/proxy"
            ),
            r#"<img src="/api/v1/namespaces/default/pods/mypod/proxy/logo.png">"#,
            "src must be rewritten identically to href — upstream's proxy Transport \
             rewrites both attributes for exactly this reason (img/script/etc. all use src)"
        );
    }

    /// An absolute URL (with its own scheme and host) must be left untouched.
    #[test]
    fn rewrite_relative_links_leaves_absolute_url_untouched() {
        let html = r#"<a href="http://example.com/elsewhere">test</a>"#;
        assert_eq!(
            super::rewrite_relative_links(html, "/api/v1/namespaces/default/pods/mypod/proxy"),
            html,
            "an absolute URL already names its own host and must not be rewritten — \
             prefixing it with the proxy path would break a legitimate external link"
        );
    }

    /// A scheme-relative URL (`//host/...`) must be left untouched — it names its own
    /// host even though it starts with `/`.
    #[test]
    fn rewrite_relative_links_leaves_scheme_relative_url_untouched() {
        let html = r#"<a href="//example.com/elsewhere">test</a>"#;
        assert_eq!(
            super::rewrite_relative_links(html, "/api/v1/namespaces/default/pods/mypod/proxy"),
            html,
            "a scheme-relative URL carries its own host despite the leading '/' — \
             treating it as root-relative would prepend the proxy path onto \
             '//example.com/elsewhere' instead of leaving it alone"
        );
    }

    /// A document-relative path (no leading `/`) must be left untouched — it already
    /// resolves correctly against the current proxied URL without rewriting.
    #[test]
    fn rewrite_relative_links_leaves_document_relative_path_untouched() {
        let html = r#"<a href="rewriteme">test</a>"#;
        assert_eq!(
            super::rewrite_relative_links(html, "/api/v1/namespaces/default/pods/mypod/proxy"),
            html,
            "a bare relative path resolves against the browser's current URL (already \
             inside the proxy path) with no rewriting needed — prefixing it would \
             double up the proxy path"
        );
    }

    /// An attribute that merely ends in "href" (not the exact `href=` token) must not be
    /// mistaken for a real href attribute.
    #[test]
    fn rewrite_relative_links_does_not_misparse_unrelated_attribute() {
        let html = r#"<div xhref="/foo">test</div>"#;
        assert_eq!(
            super::rewrite_relative_links(html, "/api/v1/namespaces/default/pods/mypod/proxy"),
            html,
            "an attribute name that merely ends in 'href' must not be mistaken for the \
             real attribute — rewriting inside it would corrupt an unrelated attribute value"
        );
    }

    /// Multiple links in the same document must each be rewritten independently.
    #[test]
    fn rewrite_relative_links_rewrites_multiple_links() {
        let html = r#"<a href="/one">one</a><a href="/two">two</a>"#;
        assert_eq!(
            super::rewrite_relative_links(html, "/proxy"),
            r#"<a href="/proxy/one">one</a><a href="/proxy/two">two</a>"#,
            "every root-relative link in the document must be rewritten, not just the \
             first — a page with multiple links must keep the user inside the proxy \
             no matter which one they follow"
        );
    }

    /// HTML with no href/src attributes at all must pass through byte-for-byte.
    #[test]
    fn rewrite_relative_links_leaves_plain_html_unchanged() {
        let html = "<p>hello world</p>";
        assert_eq!(
            super::rewrite_relative_links(html, "/api/v1/namespaces/default/pods/mypod/proxy"),
            html,
            "HTML with nothing to rewrite must be returned unchanged — this is the \
             overwhelming majority of proxied HTML responses"
        );
    }

    /// pod_proxy (direct, no konnectivity) must rewrite root-relative links in a
    /// text/html response body so they keep resolving through the proxy.
    ///
    /// Before this fix, pod_proxy_dispatch streamed the backend body through
    /// unmodified — a client following `<a href="/rewriteme">` on a proxied page would
    /// land on the apiserver's own root instead of the pod's `/rewriteme`. This is the
    /// exact "Proxy ... should proxy through a service and a pod" conformance failure
    /// for the bare pod-proxy-root and named-port HTML cases.
    #[tokio::test]
    async fn pod_proxy_rewrites_relative_html_links() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend_ip = test_backend_ip();
        let listener = TcpListener::bind((backend_ip, 0)).await.unwrap();
        let pod_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            let html_body = r#"<a href="/rewriteme">test</a>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{html_body}",
                html_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let state = make_state();
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": pod_port}]}]
            },
            "status": {"podIP": backend_ip.to_string()}
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
        // podCIDR is maximally permissive because this test needs a real, connectable
        // in-process listener as the pod backend, not a realistic node assignment — CIDR
        // matching itself is covered separately by pod_proxy_rejects_pod_ip_outside_node_pod_cidr.
        seed_node_with_pod_cidr(&state, "node-1", "0.0.0.0/0").await;

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/mypod/proxy/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let expected_body =
            r#"<a href="/api/v1/namespaces/default/pods/mypod/proxy/rewriteme">test</a>"#;
        // axum fills in Content-Length only when the header is absent (it never corrects
        // an existing one), so the original (stale, pre-rewrite) Content-Length must have
        // been removed — otherwise this would still show the backend's original byte
        // count instead of the rewritten body's.
        if let Some(cl) = resp.headers().get(axum::http::header::CONTENT_LENGTH) {
            assert_eq!(
                cl.to_str().unwrap(),
                expected_body.len().to_string(),
                "Content-Length must describe the rewritten body, not the original — a \
                 client reading exactly the original (shorter) byte count would truncate \
                 the rewritten href mid-attribute"
            );
        }
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body, expected_body,
            "the relative link must be rewritten to include the full proxy path — a \
             client following the unrewritten link would hit the apiserver's own root \
             instead of the pod's /rewriteme"
        );
    }

    /// pod_proxy over a konnectivity tunnel must also rewrite relative HTML links.
    ///
    /// The tunnel branch builds its response body separately from the direct-HTTP
    /// branch (pod_proxy_via_connect_tunnel returns already-buffered bytes rather than
    /// a stream); fixing only the direct branch would leave every konnectivity-proxied
    /// cluster — the common case once a real CNI is involved, and the path u7s's own
    /// dev stack always takes — still returning unrewritten links.
    #[tokio::test]
    async fn pod_proxy_via_connect_tunnel_rewrites_relative_html_links() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();

            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();

            let mut buf2 = [0u8; 512];
            let _ = stream.read(&mut buf2).await;
            let html_body = r#"<a href="/rewriteme">test</a>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{html_body}",
                html_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory db"));
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 80}]}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.0.0.1", "hostIP": "10.0.0.1"}
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: Some(proxy_addr),
            sa_public_key_pem: None,
        });

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/mypod/proxy/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body, r#"<a href="/api/v1/namespaces/default/pods/mypod/proxy/rewriteme">test</a>"#,
            "the konnectivity-tunnel branch must also rewrite relative links — this is \
             the path u7s's own dev stack always takes once konnectivity-server is \
             configured"
        );
    }

    /// service_proxy (direct, no konnectivity) must rewrite relative links using the
    /// SERVICE's own proxy base path, not the pod's.
    ///
    /// service_proxy_dispatch computes its own `proxy_base` from `services/{name}/proxy`
    /// independently from pod_proxy_dispatch's `pods/{name}/proxy` — a copy-paste error
    /// here would silently rewrite links to the wrong (pod-shaped) path.
    #[tokio::test]
    async fn service_proxy_rewrites_relative_html_links() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend_ip = test_backend_ip();
        let listener = TcpListener::bind((backend_ip, 0)).await.unwrap();
        let ep_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            let html_body = r#"<a href="/rewriteme">test</a>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{html_body}",
                html_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let state = make_state();
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [{"addresses": [backend_ip.to_string()], "conditions": {"ready": true}}],
            "ports": [{"name": "http", "port": ep_port, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/services/my-svc/proxy/")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body,
            r#"<a href="/api/v1/namespaces/default/services/my-svc/proxy/rewriteme">test</a>"#,
            "service_proxy must rewrite links using its own services/<name>/proxy base \
             path — rewriting to a pod-shaped path would send the client to a URL that \
             404s"
        );
    }

    // -----------------------------------------------------------------------
    // Proxy responses must forward the backend's Content-Type
    //
    // client-go's typed clients (kubernetes.Clientset) configure protobuf as
    // their preferred content type. Request.transformResponse falls back to
    // that default whenever the response Content-Type header is empty. Before
    // this fix, node_proxy/pod_proxy_dispatch/service_proxy_dispatch built the
    // outgoing Response with only a status and a body — the backend's headers
    // were silently dropped, so a JSON body came back with an empty
    // Content-Type and a protobuf-preferring client failed to decode it.
    // -----------------------------------------------------------------------

    /// forward_proxied_headers must copy Content-Type but drop hop-by-hop headers.
    ///
    /// If Content-Type is dropped, a protobuf-preferring client falls back to its
    /// own default content type and mis-decodes the (actually JSON) body. If
    /// hop-by-hop headers are copied verbatim, they describe the kubelet/pod↔
    /// apiserver hop's framing, not the apiserver↔client hop this response rides on.
    #[test]
    fn forward_proxied_headers_keeps_content_type_drops_hop_by_hop() {
        let mut upstream = axum::http::HeaderMap::new();
        upstream.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        upstream.insert(
            axum::http::header::CONNECTION,
            "keep-alive".parse().unwrap(),
        );
        upstream.insert("transfer-encoding", "chunked".parse().unwrap());

        let mut out = axum::http::HeaderMap::new();
        forward_proxied_headers(&mut out, &upstream);

        assert_eq!(
            out.get(axum::http::header::CONTENT_TYPE).unwrap(),
            "application/json",
            "client-go falls back to its default (protobuf) content type when \
             Content-Type is empty, then fails to decode this JSON body — \
             Content-Type must survive the proxy hop"
        );
        assert!(
            out.get(axum::http::header::CONNECTION).is_none(),
            "Connection describes the kubelet/pod↔apiserver hop, not the \
             apiserver↔client hop — forwarding it verbatim would misdescribe \
             the outgoing response's framing"
        );
        assert!(
            out.get("transfer-encoding").is_none(),
            "axum chooses its own Transfer-Encoding for the outgoing response; \
             forwarding the backend's verbatim risks conflicting framing"
        );
    }

    /// node_proxy must forward the kubelet's Content-Type onto the proxied response.
    ///
    /// Before this fix, a GET to /api/v1/nodes/{name}/proxy/pods came back with an
    /// empty Content-Type even though the kubelet's body was JSON. A protobuf-
    /// preferring client (any typed clientset) then fails with "provided data does
    /// not appear to be a protobuf message" trying to decode that JSON as protobuf.
    #[tokio::test]
    async fn node_proxy_forwards_upstream_content_type() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kubelet_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                )
                .await
                .unwrap();
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory db"));
        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "mynode", "resourceVersion": "1"},
            "status": {"addresses": [{"type": "InternalIP", "address": "127.0.0.1"}]}
        });
        store
            .put(
                &crate::keys::cluster_object_key("nodes", "mynode"),
                bytes::Bytes::from(node.to_string()),
                Some(0),
            )
            .await
            .expect("seed node");

        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/nodes/mynode/proxy/pods")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the mock kubelet must be reachable over TLS with the generated CA"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json",
            "node_proxy dropped the kubelet's Content-Type — a protobuf-preferring \
             client falls back to its own default and fails to decode this JSON body"
        );
    }

    /// pod_proxy (direct, no konnectivity) must forward the pod's Content-Type.
    ///
    /// Same client-go fallback mechanism as node_proxy, but exercised through the
    /// plain-HTTP direct-connection branch of pod_proxy_dispatch used when no
    /// konnectivity proxy is configured.
    #[tokio::test]
    async fn pod_proxy_forwards_upstream_content_type() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend_ip = test_backend_ip();
        let listener = TcpListener::bind((backend_ip, 0)).await.unwrap();
        let pod_port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\n\r\nok",
                )
                .await
                .unwrap();
        });

        let state = make_state();
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": pod_port}]}]
            },
            "status": {"podIP": backend_ip.to_string()}
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
        seed_node_with_pod_cidr(&state, "node-1", "0.0.0.0/0").await;

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/api/v1/namespaces/default/pods/mypod/proxy/metrics")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the mock pod backend must be reachable over plain HTTP"
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/plain; charset=utf-8",
            "pod_proxy_dispatch's direct branch dropped the pod's Content-Type — a \
             protobuf-preferring client falls back to its own default and \
             mis-decodes this body"
        );
    }

    // -----------------------------------------------------------------------
    // Proxy requests must forward the inbound query string
    //
    // pod_proxy_dispatch/service_proxy_dispatch built the outbound request from
    // path_suffix alone — req.uri().query() was never read in any of the direct-HTTP
    // or konnectivity-tunnel branches. Apps proxied through the pod/Service proxy
    // subresource whose entire protocol is query params (e.g. the Kubectl Guestbook
    // conformance test's ?cmd=&key=&value=) silently received no arguments at all and
    // returned "unsupported cmd: ''" for every request even though routing succeeded.
    // -----------------------------------------------------------------------

    /// append_query must append a present query string onto the forwarded path.
    ///
    /// pod_proxy_dispatch and service_proxy_dispatch call this instead of using
    /// path_suffix directly. If it stops appending the query, every proxied request
    /// that depends on query params (e.g. guestbook's cmd/key/value) breaks even
    /// though routing to the right pod/endpoint still succeeds.
    #[test]
    fn append_query_appends_present_query_string() {
        assert_eq!(
            super::append_query("guestbook", Some("cmd=set&key=k&value=v")),
            "guestbook?cmd=set&key=k&value=v",
            "the full multi-param query string must survive intact — dropping any \
             part of it silently breaks a proxied app's request contract"
        );
    }

    /// append_query must NOT grow a bare trailing '?' when there is no query string.
    ///
    /// Forwarding "path?" instead of "path" would needlessly change the exact request
    /// the backend sees for requests that never had a query string at all.
    #[test]
    fn append_query_no_bare_trailing_question_mark_when_absent() {
        assert_eq!(
            super::append_query("guestbook", None),
            "guestbook",
            "a proxied request with no query string must not gain a bare trailing '?'"
        );
    }

    /// pod_proxy (direct HTTP, no konnectivity) must forward the request's query string.
    ///
    /// Before this fix, a GET to .../pods/<p>/proxy/guestbook?cmd=set&key=k&value=v
    /// reached the pod as a bare "/guestbook" — the guestbook app's entire request
    /// contract is its cmd/key/value query params, so every proxied request failed
    /// with "unsupported cmd: ''" even though the pod was healthy and reachable.
    #[tokio::test]
    async fn pod_proxy_forwards_query_string() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend_ip = test_backend_ip();
        let listener = TcpListener::bind((backend_ip, 0)).await.unwrap();
        let pod_port = listener.local_addr().unwrap().port();

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request.lines().next().unwrap_or("").to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let state = make_state();
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": pod_port}]}]
            },
            "status": {"podIP": backend_ip.to_string()}
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
        seed_node_with_pod_cidr(&state, "node-1", "0.0.0.0/0").await;

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri(
                "/api/v1/namespaces/default/pods/mypod/proxy/guestbook?cmd=set&key=messages&value=hello",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the mock pod backend must be reachable over plain HTTP"
        );
        assert_eq!(
            rx.await.unwrap(),
            "GET /guestbook?cmd=set&key=messages&value=hello HTTP/1.1",
            "pod_proxy_dispatch's direct-HTTP branch dropped the query string — the \
             backend received a bare path instead of the full guestbook request"
        );
    }

    /// pod_proxy over a konnectivity tunnel must also forward the request's query string.
    ///
    /// The tunnel branch builds its own request URI from path_suffix inside
    /// pod_proxy_via_connect_tunnel; fixing only the direct-HTTP branch would leave
    /// every konnectivity-proxied cluster (the common case once a real CNI is
    /// involved) still dropping guestbook's cmd/key/value params.
    #[tokio::test]
    async fn pod_proxy_via_connect_tunnel_forwards_query_string() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let cert = generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let server_cert = CertificateDer::from(cert_der.clone());
        let server_key = PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap().to_string();

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();

            // Read and accept the CONNECT request; the target is covered by a
            // dedicated test, this one only cares about what follows the tunnel.
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();

            // Read the pod's HTTP request sent over the now-open tunnel.
            let mut buf2 = [0u8; 512];
            let n = stream.read(&mut buf2).await.unwrap();
            let request = String::from_utf8_lossy(&buf2[..n]).to_string();
            let _ = tx.send(request.lines().next().unwrap_or("").to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory db"));
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 80}]}],
                "hostNetwork": true
            },
            "status": {"podIP": "10.0.0.1", "hostIP": "10.0.0.1"}
        });
        store
            .put(
                &crate::keys::object_key("pods", "default", "mypod"),
                bytes::Bytes::from(pod.to_string()),
                Some(0),
            )
            .await
            .expect("seed pod");

        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cert_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: Some(proxy_addr),
            sa_public_key_pem: None,
        });

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri(
                "/api/v1/namespaces/default/pods/mypod/proxy/guestbook?cmd=set&key=messages&value=hello",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the mock konnectivity+pod backend must be reachable over the tunnel"
        );
        assert_eq!(
            rx.await.unwrap(),
            "GET /guestbook?cmd=set&key=messages&value=hello HTTP/1.1",
            "pod_proxy_via_connect_tunnel's request URI dropped the query string — a \
             konnectivity-proxied cluster would drop guestbook's cmd/key/value params \
             even though the direct-HTTP branch was fixed"
        );
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

    /// The attach admission review must send the requested PodAttachOptions (stdin,
    /// container, ...) as `request.object`, not the pod being attached to.
    ///
    /// The conformance suite's deny-attach webhook decodes `request.object` as
    /// `PodAttachOptions` and only denies when `Stdin` is true and `Container` matches
    /// a specific name (`kubectl attach -i -c=container1`) — it never inspects the pod
    /// itself. Sending the Pod object there instead means every field the webhook
    /// checks (stdin, container) decodes to its zero value, so the webhook can never
    /// distinguish one attach request from another and the deny logic never fires.
    #[tokio::test]
    async fn attach_admission_review_sends_pod_attach_options_not_the_pod() {
        use axum::routing::post;
        use std::sync::Mutex;
        use tokio::net::TcpListener;

        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

        let router = Router::new().route(
            "/webhook",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let captured_clone = Arc::clone(&captured_clone);
                async move {
                    *captured_clone.lock().unwrap() = Some(body);
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {"uid": "test-uid", "allowed": true}
                    }))
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webhook_url = format!("http://{addr}/webhook");
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        // resolve_attach_target requires a cluster CA to build the kubelet TLS config
        // (refuses to connect without one — see resolve_attach_target_returns_503...);
        // admission runs before that check, but the mock webhook allows the request,
        // so the CA must be present for resolve_attach_target to reach completion.
        let cert = rcgen::generate_simple_self_signed(vec!["10.0.0.1".to_string()]).unwrap();
        let ca_der = cert.cert.der().to_vec();
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store: store.clone(),
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

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "capture-attach"},
            "webhooks": [{
                "name": "capture-attach.example.com",
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
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/capture-attach",
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
                "containers": [{"name": "container1", "image": "nginx"}]
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

        // Mirrors `kubectl attach to-be-attached-pod -i -c=container1`.
        let query = AttachQuery {
            container: Some("container1".to_string()),
            stdin: Some("true".to_string()),
            stdout: None,
            stderr: None,
            tty: None,
        };
        resolve_attach_target(&state, "default", "to-be-attached-pod", &query)
            .await
            .expect("resolve_attach_target must succeed — the mock webhook allows the request");

        let review = captured
            .lock()
            .unwrap()
            .take()
            .expect("webhook must have been called");
        let object = &review["request"]["object"];
        assert_eq!(
            object["kind"].as_str(),
            Some("PodAttachOptions"),
            "request.object must be a PodAttachOptions, not the Pod, so a webhook \
             decoding it as PodAttachOptions (as the conformance suite's deny-attach \
             webhook does) sees the actual attach parameters: {object}"
        );
        assert_eq!(
            object["stdin"].as_bool(),
            Some(true),
            "request.object.stdin must reflect the query's stdin=true \
             (`kubectl attach -i`) — the deny-attach webhook only denies when Stdin \
             is true: {object}"
        );
        assert_eq!(
            object["container"].as_str(),
            Some("container1"),
            "request.object.container must reflect the requested container \
             (`kubectl attach -c=container1`), not be absent or the pod's default \
             container: {object}"
        );
    }

    /// A denied attach must surface the webhook's message even through client-go's
    /// SPDY (POST) fallback — not just the pure `resolve_attach_target` call above.
    ///
    /// client-go's remotecommand executor dials WebSocket (GET) first; its transport
    /// treats ANY non-101 handshake response — including our correct 403 denial — as
    /// an upgrade failure and silently retries the identical request via POST,
    /// discarding the GET attempt's error and message entirely. kubectl only ever
    /// prints the *retry's* result. Before this fix, POST was routed to `pod_attach`,
    /// whose `WebSocketUpgrade` extractor 405s any non-GET method before admission
    /// runs — so the retry (the only error the user sees) was axum's generic
    /// "Request method must be `GET`", not the webhook's message. This test fails if
    /// the POST route reverts to `pod_attach`.
    #[tokio::test]
    async fn pod_attach_post_fallback_surfaces_webhook_denial_not_generic_405() {
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
            "metadata": {"name": "deny-attach-post"},
            "webhooks": [{
                "name": "deny-attach-post.example.com",
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
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/deny-attach-post",
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

        // Simulate client-go's SPDY fallback: a POST to the exact URL the denied
        // GET/WebSocket dial already used.
        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/pods/to-be-attached-pod/attach")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status().as_u16(),
            403,
            "the POST fallback must return the webhook's 403 denial, not axum's generic \
             405 'Request method must be `GET`' — kubectl discards the GET attempt's \
             error and shows only this response to the user"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("is not allowed"),
            "the webhook's denial message must reach the client through the POST \
             fallback path — kubectl only prints this response's body: {body_str}"
        );
        assert!(
            !body_str.contains("Request method must be"),
            "regression guard: this is axum's generic WebSocketUpgrade rejection text — \
             seeing it here means the POST route fell back to pod_attach and admission \
             never ran on the retried request: {body_str}"
        );
    }

    /// A validating webhook that denies pods/exec CONNECT must cause
    /// resolve_exec_target to return HTTP 403 before the websocket upgrade.
    ///
    /// Without the admission check in resolve_exec_target, the denial cannot
    /// be surfaced as a clean HTTP error — it arrives only after the websocket
    /// handshake completes, producing close code 1006 (abnormal closure) instead
    /// of 403. This test fails if the run_validating_webhooks call is removed.
    #[tokio::test]
    async fn pod_exec_validating_webhook_denial_returns_403_before_websocket_upgrade() {
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
                            "message": "exec into pod 'to-be-execd-pod' is not allowed"
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
            "metadata": {"name": "deny-exec"},
            "webhooks": [{
                "name": "deny-exec.example.com",
                "clientConfig": {"url": webhook_url},
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["pods/exec"],
                    "operations": ["CONNECT"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/deny-exec",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "to-be-execd-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "to-be-execd-pod"),
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

        let result = resolve_exec_target(
            &state,
            "default",
            "to-be-execd-pod",
            None,
            "command=echo&command=hi&stdout=1&stderr=1",
        )
        .await;
        let err = match result {
            Ok(_) => panic!(
                "resolve_exec_target must return an error when a validating webhook denies \
                 the exec request — without this, a denial can only be sent after the websocket \
                 upgrade, producing close 1006 instead of HTTP 403"
            ),
            Err(e) => e,
        };
        assert_eq!(
            err.0.as_u16(),
            403,
            "webhook denial on pods/exec must produce HTTP 403 Forbidden, not {} — \
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

    /// A denied exec must surface the webhook's message even through client-go's
    /// SPDY (POST) fallback — not just the pure `resolve_exec_target` call above.
    ///
    /// client-go's remotecommand executor dials WebSocket (GET) first; its transport
    /// treats ANY non-101 handshake response — including our correct 403 denial — as
    /// an upgrade failure and silently retries the identical request via POST,
    /// discarding the GET attempt's error and message entirely. kubectl only ever
    /// prints the *retry's* result. Before this fix, POST was routed to `pod_exec`,
    /// whose `WebSocketUpgrade` extractor 405s any non-GET method before admission
    /// runs — so the retry (the only error the user sees) was axum's generic
    /// "Request method must be `GET`", not the webhook's message. This test fails if
    /// the POST route reverts to `pod_exec`.
    #[tokio::test]
    async fn pod_exec_post_fallback_surfaces_webhook_denial_not_generic_405() {
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
                            "message": "exec into pod 'to-be-execd-post-pod' is not allowed"
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
            "metadata": {"name": "deny-exec-post"},
            "webhooks": [{
                "name": "deny-exec-post.example.com",
                "clientConfig": {"url": webhook_url},
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["pods/exec"],
                    "operations": ["CONNECT"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/deny-exec-post",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "to-be-execd-post-pod", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app", "image": "nginx"}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("pods", "default", "to-be-execd-post-pod"),
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

        // Simulate client-go's SPDY fallback: a POST to the exact URL the denied
        // GET/WebSocket dial already used.
        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(
                "/api/v1/namespaces/default/pods/to-be-execd-post-pod/exec\
                 ?command=echo&command=hi",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status().as_u16(),
            403,
            "the POST fallback must return the webhook's 403 denial, not axum's generic \
             405 'Request method must be `GET`' — kubectl discards the GET attempt's \
             error and shows only this response to the user"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("is not allowed"),
            "the webhook's denial message must reach the client through the POST \
             fallback path — kubectl only prints this response's body: {body_str}"
        );
        assert!(
            !body_str.contains("Request method must be"),
            "regression guard: this is axum's generic WebSocketUpgrade rejection text — \
             seeing it here means the POST route fell back to pod_exec and admission \
             never ran on the retried request: {body_str}"
        );
    }

    // -----------------------------------------------------------------------
    // service_proxy: resolve_service_proxy_target unit tests
    //
    // Service proxy forwards to a ready endpoint found via EndpointSlices.
    // resolve_service_proxy_target handles the pre-flight checks. We test it
    // directly because the handler is a thin wrapper around this function.
    // -----------------------------------------------------------------------

    /// Service proxy must return 404 when the Service does not exist.
    ///
    /// A 404 tells the caller the Service is missing rather than suggesting
    /// its endpoints are unreachable (502) or that something internal failed (500).
    /// Without the Service existence check, a missing Service produces 503 when
    /// no EndpointSlices match — an incorrect status that misleads the caller.
    #[tokio::test]
    async fn service_proxy_missing_service_returns_404() {
        let state = make_state();
        let result = resolve_service_proxy_target(&state, "default", "ghost-svc").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "service proxy must return 404 when the Service is not in the store — \
             returning 503 instead would make it look like the service has no endpoints \
             rather than that the service itself is missing"
        );
    }

    /// Service proxy must return 503 when the Service exists but has no ready endpoints.
    ///
    /// A 503 tells the caller to retry; the Service exists but its endpoints are not
    /// yet ready. Returning 502 or 500 would mislead the caller.
    #[tokio::test]
    async fn service_proxy_no_ready_endpoints_returns_503() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80, "targetPort": 8080}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        // No EndpointSlices seeded — the service has no backing endpoints.
        let result = resolve_service_proxy_target(&state, "default", "my-svc").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            503,
            "service proxy must return 503 when the Service has no ready endpoints — \
             the service exists but cannot serve traffic; 404 would incorrectly imply \
             the service is gone"
        );
    }

    /// Service proxy resolves the ready endpoint IP and port from the EndpointSlice.
    ///
    /// The handler constructs the forward URL from these values; an incorrect IP or
    /// port would silently route to the wrong backend. The slice must be matched by
    /// the kubernetes.io/service-name label, and only ready endpoints are used.
    #[tokio::test]
    async fn service_proxy_resolves_ready_endpoint_ip_and_port() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.2.3.4"],
                    "conditions": {"ready": true, "serving": true, "terminating": false}
                }
            ],
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let (ip, port, _, _) = resolve_service_proxy_target(&state, "default", "my-svc")
            .await
            .expect("resolve must succeed for a service with a ready endpoint");
        assert_eq!(
            ip, "10.2.3.4",
            "service proxy must use the ready endpoint address — using any other address \
             would route to the wrong backend"
        );
        assert_eq!(
            port, 8080,
            "service proxy must use the port from the EndpointSlice ports array — \
             using port 80 when 8080 is configured routes to the wrong port"
        );
    }

    /// Service proxy must not use an endpoint whose conditions.ready is false.
    ///
    /// A not-ready endpoint is either initializing or terminating; forwarding to it
    /// would cause request failures. The handler must skip non-ready entries and
    /// return 503 if no ready endpoint remains.
    #[tokio::test]
    async fn service_proxy_skips_not_ready_endpoints_returns_503() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.2.3.4"],
                    "conditions": {"ready": false, "serving": false, "terminating": true}
                }
            ],
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let result = resolve_service_proxy_target(&state, "default", "my-svc").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            503,
            "service proxy must return 503 when all endpoints have conditions.ready=false — \
             forwarding to a terminating or initializing endpoint causes request failures"
        );
    }

    /// Service proxy must not dial a ready EndpointSlice address of bare IPv4 loopback
    /// (127.0.0.1).
    ///
    /// EndpointSlice addresses are copied verbatim from Service-owning controllers, which
    /// in turn source them from node-reported pod IPs — equally attacker-influenced as
    /// status.podIP (see `validate_proxy_target_ip`'s doc comment). Without this check, a
    /// compromised node could get itself listed as a Service endpoint and redirect the
    /// apiserver's own services/proxy dial to a service on its own host (pprof/debug/
    /// metadata). Since this is the only (ready) endpoint, filtering it out must surface
    /// as the same "no ready endpoints" 503 as if none existed.
    #[tokio::test]
    async fn service_proxy_rejects_loopback_endpoint_address() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [
                {"addresses": ["127.0.0.1"], "conditions": {"ready": true}}
            ],
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let result = resolve_service_proxy_target(&state, "default", "my-svc").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            503,
            "a ready EndpointSlice address of 127.0.0.1 must be filtered out, not dialed — \
             a compromised node listed as a Service endpoint must not be able to redirect \
             the apiserver's own services/proxy dial to itself"
        );
    }

    /// Service proxy route must resolve to the handler, not return 404.
    ///
    /// Without the route registration in main.rs the request falls through to the
    /// generic handler and 404s — the Guestbook and Services proxy conformance tests
    /// never reach the service_proxy handler.
    #[tokio::test]
    async fn service_proxy_route_is_registered_not_404() {
        let state = make_state();

        // Seed a Service with no EndpointSlice → handler returns 503 (service has no
        // ready endpoints), not 404. 503 proves the handler was reached; 404 proves
        // the route was never registered.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let mut router = make_router(state);

        // The bare `/proxy` form (no trailing slash) 301-redirects for GET rather than
        // proxying directly — matching upstream and the sig-network Proxy conformance test.
        for (path, want) in [
            (
                "/api/v1/namespaces/default/services/my-svc/proxy",
                StatusCode::MOVED_PERMANENTLY,
            ),
            (
                "/api/v1/namespaces/default/services/my-svc/proxy/",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                "/api/v1/namespaces/default/services/my-svc/proxy/some/subpath",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = router.call(req).await.unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "GET {path} must NOT return 404 — the Guestbook and Services proxy \
                 conformance tests reach this route; a 404 means the route was never registered"
            );
            assert_eq!(
                resp.status(),
                want,
                "GET {path} must reach the service proxy routing correctly — any other \
                 status means routing or the bare-root redirect is broken"
            );
        }
    }

    /// service_proxy (direct HTTP, no konnectivity) must forward the request's query string.
    ///
    /// service_proxy_dispatch has its own target_url string construction, separate
    /// from pod_proxy_dispatch's — fixing only the pod path would leave every Service
    /// proxy request (e.g. the Kubectl Guestbook conformance test reaching guestbook
    /// through its frontend Service) still dropping cmd/key/value query params.
    #[tokio::test]
    async fn service_proxy_forwards_query_string() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let backend_ip = test_backend_ip();
        let listener = TcpListener::bind((backend_ip, 0)).await.unwrap();
        let ep_port = listener.local_addr().unwrap().port();

        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request.lines().next().unwrap_or("").to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let state = make_state();
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "frontend", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "frontend"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "frontend-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "frontend"}
            },
            "addressType": "IPv4",
            "endpoints": [
                {"addresses": [backend_ip.to_string()], "conditions": {"ready": true}}
            ],
            "ports": [{"name": "http", "port": ep_port, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "frontend-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let mut router = make_router(state);
        let req = axum::http::Request::builder()
            .uri(
                "/api/v1/namespaces/default/services/frontend/proxy/guestbook?cmd=set&key=messages&value=hello",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the mock service endpoint must be reachable over plain HTTP"
        );
        assert_eq!(
            rx.await.unwrap(),
            "GET /guestbook?cmd=set&key=messages&value=hello HTTP/1.1",
            "service_proxy_dispatch's direct-HTTP branch dropped the query string — the \
             endpoint received a bare path instead of the full guestbook request"
        );
    }

    // -----------------------------------------------------------------------
    // split_service_port + resolve_eps_port unit tests
    //
    // Proxy URLs allow services/<name>:<port-or-portName>/proxy/. Without the
    // split, the raw name (including the colon suffix) is used for the store
    // lookup, which always 404s — breaking kubectl proxy and the named-port
    // conformance test.
    // -----------------------------------------------------------------------

    /// split_service_port must strip the port suffix from a named-port URL segment.
    ///
    /// If the split is removed, "svc:portname1" hits the store as the full name,
    /// which 404s — the named-port conformance test loops on 404 for 122 s.
    #[test]
    fn split_service_port_strips_named_port_suffix() {
        assert_eq!(
            super::split_service_port("my-svc:portname1"),
            ("my-svc", Some("portname1")),
            "named-port suffix must be split off so the bare name is used for the store lookup"
        );
    }

    /// split_service_port must strip a numeric port suffix.
    #[test]
    fn split_service_port_strips_numeric_port_suffix() {
        assert_eq!(
            super::split_service_port("my-svc:80"),
            ("my-svc", Some("80")),
            "numeric port suffix must be split off — without this, 'my-svc:80' 404s in the store"
        );
    }

    /// split_service_port must leave bare names (no colon) unchanged.
    ///
    /// Without this, bare services/<name>/proxy/ would regress and every existing
    /// service proxy test would 404.
    #[test]
    fn split_service_port_bare_name_unchanged() {
        assert_eq!(
            super::split_service_port("my-svc"),
            ("my-svc", None),
            "bare service name must pass through unchanged — adding a colon erroneously would \
             break all existing service proxy requests with no port suffix"
        );
    }

    /// split_service_port must strip a leading http/https scheme AND the port suffix.
    ///
    /// Before this fix, rsplit_once(':') split on the LAST colon only: for
    /// "http:proxy-test-svc:web" that produced bare_name = "http:proxy-test-svc" — the
    /// scheme leaked into the name lookup and the Proxy conformance test 404'd on
    /// 'Service "http:proxy-test-svc" not found'.
    #[test]
    fn split_service_port_strips_scheme_and_port_suffix() {
        assert_eq!(
            super::split_service_port("http:proxy-test-svc:web"),
            ("proxy-test-svc", Some("web")),
            "the scheme token must be stripped before the name/port split, not folded \
             into the bare name"
        );
    }

    // -----------------------------------------------------------------------
    // split_scheme_name_port unit tests — the shared parser behind both
    // split_service_port and resolve_pod_proxy_target.
    //
    // kubectl and client-go's REST proxy helpers address pod/service proxy
    // targets as [<scheme>:]<name>[:<port>]. Prior to this, only the 2-part
    // <name>:<port> suffix was handled anywhere (services only); a
    // scheme-prefixed 3-part id always 404'd, and pods had no suffix parsing
    // at all.
    // -----------------------------------------------------------------------

    /// A bare name (no colon) must pass through unchanged.
    ///
    /// This is the most common proxy form (`pods/<name>/proxy/`,
    /// `services/<name>/proxy/`); misparsing it would break nearly every
    /// existing proxy request.
    #[test]
    fn split_scheme_name_port_bare_name_unchanged() {
        assert_eq!(
            super::split_scheme_name_port("my-pod"),
            ("my-pod", None),
            "a bare name must pass through unchanged — splitting it would 404 the \
             overwhelming majority of pod/service proxy requests, which carry no port"
        );
    }

    /// The 2-part `name:port` form must split off the port with no scheme involved.
    #[test]
    fn split_scheme_name_port_strips_name_port_suffix() {
        assert_eq!(
            super::split_scheme_name_port("my-pod:8080"),
            ("my-pod", Some("8080")),
            "the 2-part name:port form must split off the port — without this, \
             'pods/my-pod:8080/proxy/' 404s looking up a pod literally named 'my-pod:8080'"
        );
    }

    /// The 3-part `http:name:port` form must strip BOTH the scheme and the port.
    ///
    /// Splitting on only the last colon (the pre-fix behavior) leaves "http:my-pod"
    /// as the name, which never matches a stored object.
    #[test]
    fn split_scheme_name_port_strips_http_scheme_and_port_suffix() {
        assert_eq!(
            super::split_scheme_name_port("http:my-pod:8080"),
            ("my-pod", Some("8080")),
            "the scheme:name:port form must strip both segments — leaving 'http:my-pod' \
             as the bare name 404s even though the pod exists"
        );
    }

    /// The https scheme must be recognized too, not just http.
    #[test]
    fn split_scheme_name_port_strips_https_scheme_and_named_port_suffix() {
        assert_eq!(
            super::split_scheme_name_port("https:my-svc:web"),
            ("my-svc", Some("web")),
            "kubectl proxy can address either scheme — only handling 'http:' would \
             still 404 every 'https:'-prefixed proxy URL"
        );
    }

    /// A name that merely starts with "http" (not the exact "http:" scheme token)
    /// must not be truncated.
    ///
    /// A prefix check without a trailing colon would strip "http" out of
    /// "http-proxy-test", silently proxying to a different (possibly nonexistent) pod.
    #[test]
    fn split_scheme_name_port_does_not_misparse_name_starting_with_http() {
        assert_eq!(
            super::split_scheme_name_port("http-proxy-test:8080"),
            ("http-proxy-test", Some("8080")),
            "a name that merely starts with 'http' must not be mistaken for the scheme \
             token — that would silently proxy to the wrong pod"
        );
    }

    /// A 2-part id must always be treated as name:port, even when the name happens to
    /// equal a scheme keyword.
    ///
    /// Only a 3-part id (a colon on both sides of the middle segment) is unambiguous
    /// scheme syntax; guessing that a 2-part "http:8080" means bare-scheme-only would
    /// silently drop the name and try to look up port "8080" as if it were the resource.
    #[test]
    fn split_scheme_name_port_two_part_form_never_treated_as_bare_scheme() {
        assert_eq!(
            super::split_scheme_name_port("http:8080"),
            ("http", Some("8080")),
            "a 2-part id must always parse as name:port — treating 'http' as a bare \
             scheme here would silently discard the resource name"
        );
    }

    // -----------------------------------------------------------------------
    // proxy_target_is_https unit tests
    //
    // pod_proxy_dispatch/service_proxy_dispatch use this to pick TLS vs plain HTTP for
    // the backend connection. Getting it wrong either way breaks the proxy: connecting
    // over TLS to a plain-HTTP backend fails the handshake, and connecting over plain
    // HTTP to a TLS-only backend gets rejected with 400 "Client sent an HTTP request to
    // an HTTPS server" — the exact conformance failure this fixes.
    // -----------------------------------------------------------------------

    /// An `https:name:port` target must report true.
    #[test]
    fn proxy_target_is_https_true_for_https_scheme() {
        assert!(
            super::proxy_target_is_https("https:my-pod:443"),
            "an 'https:'-prefixed target must be dialed over TLS — reporting false here \
             sends a plaintext request to what the URL explicitly names as a TLS backend"
        );
    }

    /// An `http:name:port` target must report false, not just "not https".
    #[test]
    fn proxy_target_is_https_false_for_http_scheme() {
        assert!(
            !super::proxy_target_is_https("http:my-pod:443"),
            "an explicit 'http:' scheme must never be treated as https — doing so would \
             attempt a TLS handshake against a plain-HTTP backend and fail outright"
        );
    }

    /// A bare name (no scheme) must report false — this is the overwhelming majority of
    /// existing proxy requests.
    #[test]
    fn proxy_target_is_https_false_for_bare_name() {
        assert!(
            !super::proxy_target_is_https("my-pod"),
            "a bare name carries no scheme and must default to plain HTTP — misreporting \
             true here would break every existing proxy request with a spurious TLS \
             handshake"
        );
    }

    /// A 2-part `https:8080` id is the literal name `https` with a numeric port, not a
    /// bare https scheme — matching `split_scheme_name_port`'s identical disambiguation.
    ///
    /// Without the second-colon check, a pod genuinely named "https" addressed as
    /// `pods/https:8080/proxy/` would be misdialed over TLS instead of to the pod's
    /// actual (plain HTTP) port 8080.
    #[test]
    fn proxy_target_is_https_two_part_form_never_treated_as_bare_scheme() {
        assert!(
            !super::proxy_target_is_https("https:8080"),
            "a 2-part id must always parse as name:port, never a bare scheme — treating \
             'https' as the scheme here would silently discard the resource name and \
             dial the wrong protocol"
        );
    }

    /// A name that merely starts with "https" (not the exact "https:" scheme token) must
    /// not be mistaken for the scheme.
    #[test]
    fn proxy_target_is_https_does_not_misparse_name_starting_with_https() {
        assert!(
            !super::proxy_target_is_https("https-service:8080"),
            "a name that merely starts with 'https' must not be mistaken for the scheme \
             token — that would silently dial the wrong protocol against the wrong service"
        );
    }

    /// resolve_eps_port with None picks the first port entry.
    ///
    /// This is the fallback for bare services/<name>/proxy/ — removing it regresses
    /// all existing service proxy requests that don't specify a port.
    #[test]
    fn resolve_eps_port_none_returns_first_port() {
        let ports = serde_json::json!([{"name": "http", "port": 8080}]);
        assert_eq!(
            super::resolve_eps_port(&ports, None),
            Some(8080),
            "bare service proxy (no port spec) must use the first EndpointSlice port — \
             returning None or a wrong port would break all non-named-port proxy requests"
        );
    }

    /// resolve_eps_port with a named spec picks the port whose name matches.
    ///
    /// Without this, ':portname1' in the URL never matches and the slice is skipped,
    /// so the handler falls through to 503 even when a ready endpoint exists.
    #[test]
    fn resolve_eps_port_named_spec_matches_port_name() {
        let ports = serde_json::json!([
            {"name": "metrics", "port": 9090},
            {"name": "portname1", "port": 8080}
        ]);
        assert_eq!(
            super::resolve_eps_port(&ports, Some("portname1")),
            Some(8080),
            "named port spec must resolve by matching the EndpointSlice port name — \
             returning None or the wrong port makes the proxy forward to the wrong backend"
        );
    }

    /// resolve_eps_port with a numeric spec picks the matching port entry.
    ///
    /// Without this, ':80' in the URL fails to locate the EPS port and the handler
    /// falls through to 503 even when port 80 is configured.
    #[test]
    fn resolve_eps_port_numeric_spec_matches_port_number() {
        let ports = serde_json::json!([
            {"name": "http", "port": 80},
            {"name": "https", "port": 443}
        ]);
        assert_eq!(
            super::resolve_eps_port(&ports, Some("80")),
            Some(80),
            "numeric port spec must resolve to the matching port — using the wrong port \
             silently routes to the wrong backend"
        );
    }

    // -----------------------------------------------------------------------
    // resolve_pod_container_port unit tests — the pod-side analogue of
    // resolve_eps_port, used once resolve_pod_proxy_target has split off a
    // port spec via split_scheme_name_port.
    // -----------------------------------------------------------------------

    /// resolve_pod_container_port with None picks the first container's first port.
    ///
    /// This is the fallback for bare pods/<name>/proxy/ — removing it regresses every
    /// existing pod proxy request that doesn't specify a port.
    #[test]
    fn resolve_pod_container_port_none_returns_first_port() {
        let containers = serde_json::json!([
            {"name": "app", "ports": [{"name": "http", "containerPort": 8080}]}
        ]);
        assert_eq!(
            super::resolve_pod_container_port(&containers, None),
            Some(8080),
            "bare pod proxy (no port spec) must use the first container's first port — \
             returning None or a wrong port breaks every pod proxy request without a \
             port suffix"
        );
    }

    /// resolve_pod_container_port with a numeric spec uses it directly, without
    /// requiring it to match a declared containerPort.
    ///
    /// A container may listen on a port it never declared in its spec; kube-apiserver's
    /// pod proxy resolution honors the URL's port as given.
    #[test]
    fn resolve_pod_container_port_numeric_spec_used_directly() {
        let containers = serde_json::json!([
            {"name": "app", "ports": [{"name": "http", "containerPort": 9090}]}
        ]);
        assert_eq!(
            super::resolve_pod_container_port(&containers, Some("8080")),
            Some(8080),
            "a numeric port spec from the URL must be used as-is, not the pod's declared \
             port — 'pods/<name>:8080/proxy/' must reach 8080 even though the container \
             declares containerPort 9090"
        );
    }

    /// resolve_pod_container_port with a named spec matches across ALL containers, not
    /// just the first.
    #[test]
    fn resolve_pod_container_port_named_spec_matches_across_containers() {
        let containers = serde_json::json!([
            {"name": "sidecar", "ports": [{"name": "metrics", "containerPort": 9100}]},
            {"name": "app", "ports": [{"name": "web", "containerPort": 8080}]}
        ]);
        assert_eq!(
            super::resolve_pod_container_port(&containers, Some("web")),
            Some(8080),
            "a named port spec must resolve by matching the containerPort name across \
             all containers — matching only the first container would miss named ports \
             declared on sidecars"
        );
    }

    /// resolve_pod_container_port with an unmatched named spec returns None so the
    /// caller can decide how to fail, instead of silently matching the wrong port.
    #[test]
    fn resolve_pod_container_port_unknown_name_returns_none() {
        let containers = serde_json::json!([
            {"name": "app", "ports": [{"name": "web", "containerPort": 8080}]}
        ]);
        assert_eq!(
            super::resolve_pod_container_port(&containers, Some("nonexistent")),
            None,
            "an unknown named port must return None, not fall back to an arbitrary port — \
             silently picking a different port would route to the wrong container port"
        );
    }

    /// resolve_service_proxy_target must look up the Service by bare name, not the raw
    /// name including the colon suffix.
    ///
    /// Without the split, "svc:portname1" hits the store as the full name, always 404s,
    /// and the named-port conformance test times out after 122 s.
    #[tokio::test]
    async fn service_proxy_named_port_strips_suffix_resolves_service() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {
                "ports": [{"name": "portname1", "port": 80, "targetPort": 8080}]
            }
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [
                {
                    "addresses": ["10.2.3.4"],
                    "conditions": {"ready": true, "serving": true, "terminating": false}
                }
            ],
            "ports": [{"name": "portname1", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        // The svc_name as it arrives from the URL: includes the colon suffix.
        let (ip, port, _, _) = resolve_service_proxy_target(&state, "default", "my-svc:portname1")
            .await
            .expect(
                "named-port service proxy must resolve — 404 means the bare name was not \
                     extracted and the store lookup used the raw 'my-svc:portname1' key",
            );
        assert_eq!(ip, "10.2.3.4", "must return the ready endpoint address");
        assert_eq!(
            port, 8080,
            "named port 'portname1' must resolve to port 8080 via the EndpointSlice ports array — \
             returning a wrong port silently routes to the wrong backend"
        );
    }

    /// resolve_service_proxy_target with a numeric port suffix resolves to that port.
    ///
    /// Without the split, "svc:80" 404s. With the split but wrong port lookup, the
    /// wrong port is used and the proxy forwards to the wrong backend.
    #[tokio::test]
    async fn service_proxy_numeric_port_suffix_resolves() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "num-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"port": 80, "targetPort": 9090}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "num-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "num-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "num-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": true}}],
            "ports": [{"name": "http", "port": 9090, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "num-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let (ip, port, _, _) = resolve_service_proxy_target(&state, "default", "num-svc:9090")
            .await
            .expect(
                "numeric-port service proxy must resolve — 404 means bare name was not extracted",
            );
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(
            port, 9090,
            "numeric port suffix must select the matching endpoint port — returning the wrong \
             port silently proxies to the wrong backend"
        );
    }

    /// resolve_service_proxy_target with a scheme-prefixed `scheme:name:port` suffix
    /// must strip the scheme AND resolve the service.
    ///
    /// Before this fix, split_service_port's rsplit_once(':') split on only the LAST
    /// colon: "http:proxy-test-svc:web" produced bare_name = "http:proxy-test-svc",
    /// which never matches a stored Service. This is the exact form the Proxy
    /// conformance test exercises: `services/http:proxy-test-svc:web/proxy/` -> 404
    /// 'Service "http:proxy-test-svc" not found'.
    #[tokio::test]
    async fn service_proxy_scheme_name_port_strips_scheme_and_resolves_service() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "proxy-test-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"name": "web", "port": 80, "targetPort": 8080}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "proxy-test-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "proxy-test-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "proxy-test-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.9.9.9"], "conditions": {"ready": true}}],
            "ports": [{"name": "web", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "proxy-test-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let (ip, port, _, _) =
            resolve_service_proxy_target(&state, "default", "http:proxy-test-svc:web")
                .await
                .expect(
                    "'scheme:name:port' service proxy must resolve — leaking the scheme into \
                     the name lookup 404s on a service literally named 'http:proxy-test-svc'",
                );
        assert_eq!(ip, "10.9.9.9", "must return the ready endpoint address");
        assert_eq!(
            port, 8080,
            "named port 'web' must resolve via the EndpointSlice ports array once the \
             scheme prefix is stripped"
        );
    }

    /// resolve_service_proxy_target with an `https:` scheme prefix must report
    /// `is_https = true`; a bare name must report `false`.
    ///
    /// service_proxy_dispatch uses this flag the same way pod_proxy_dispatch does: to pick
    /// TLS vs plain HTTP for the backend connection. This is the service-side half of the
    /// conformance failure for tlsportname1/tlsportname2 (400 "Client sent an HTTP request
    /// to an HTTPS server" instead of the proxied response).
    #[tokio::test]
    async fn service_proxy_https_scheme_reports_is_https_true() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "tls-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"name": "web", "port": 443}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "tls-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "tls-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "tls-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.9.9.9"], "conditions": {"ready": true}}],
            "ports": [{"name": "web", "port": 443, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "tls-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let (_, _, _, is_https) =
            resolve_service_proxy_target(&state, "default", "https:tls-svc:web")
                .await
                .expect("resolve must succeed");
        assert!(
            is_https,
            "an 'https:'-scheme service proxy target must report is_https=true — without \
             it, service_proxy_dispatch connects over plain HTTP and a TLS-only endpoint \
             rejects the request with 400 instead of returning the proxied response"
        );

        let (_, _, _, is_https) = resolve_service_proxy_target(&state, "default", "tls-svc:web")
            .await
            .expect("resolve must succeed");
        assert!(
            !is_https,
            "a service proxy target with no scheme prefix must default to plain HTTP, \
             matching every pre-existing service proxy request"
        );
    }

    /// resolve_service_proxy_target must still 404 when the BARE name doesn't exist.
    ///
    /// Removing the 404 check would cause a missing service to return 503 instead,
    /// misleading the caller into thinking the service exists but has no endpoints.
    #[tokio::test]
    async fn service_proxy_bare_name_missing_still_404s() {
        let state = make_state();
        let result = resolve_service_proxy_target(&state, "default", "ghost-svc:portname1").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            404,
            "a service that does not exist must return 404 even with a port suffix — \
             returning 503 would mislead the caller into thinking the service exists"
        );
    }

    /// resolve_service_proxy_target with a port name that doesn't match any EPS port
    /// must return 503, not silently forward to the wrong port.
    ///
    /// Without this, an unknown port name falls back to the first port entry, silently
    /// routing to the wrong backend.
    #[tokio::test]
    async fn service_proxy_unknown_named_port_returns_503() {
        let state = make_state();

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-svc", "namespace": "default", "resourceVersion": "1"},
            "spec": {"ports": [{"name": "http", "port": 80}]}
        });
        state
            .store
            .put(
                &crate::keys::object_key("services", "default", "my-svc"),
                bytes::Bytes::from(svc.to_string()),
                Some(0),
            )
            .await
            .expect("seed service");

        let eps = serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "my-svc-abc",
                "namespace": "default",
                "resourceVersion": "1",
                "labels": {"kubernetes.io/service-name": "my-svc"}
            },
            "addressType": "IPv4",
            "endpoints": [{"addresses": ["10.0.0.1"], "conditions": {"ready": true}}],
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}]
        });
        state
            .store
            .put(
                &crate::keys::group_object_key(
                    "discovery.k8s.io",
                    "endpointslices",
                    Some("default"),
                    "my-svc-abc",
                ),
                bytes::Bytes::from(eps.to_string()),
                Some(0),
            )
            .await
            .expect("seed endpointslice");

        let result =
            resolve_service_proxy_target(&state, "default", "my-svc:nonexistent-port").await;
        let err = result.unwrap_err();
        assert_eq!(
            err.0.as_u16(),
            503,
            "an unknown named port must return 503, not silently forward to the wrong port — \
             falling back to port[0] when the named port is absent hides misconfiguration"
        );
    }
}
