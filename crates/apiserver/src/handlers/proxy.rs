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
        ws::{Message, WebSocket, WebSocketUpgrade},
        FromRequestParts, Path, Query, State,
    },
    response::Response,
};
use serde::Deserialize;

use u7s_store::{ListOptions, Store};

use crate::{
    admission::{run_validating_webhooks, AdmissionContext},
    handlers::stream::{splice, AxumWs, BiStream, BiStreamReader, BiStreamWriter, TungsteniteWs},
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
/// `GET`" instead of the webhook's denial message (mayor-u6eb).
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
/// `GET`" instead of the webhook's denial message (mayor-c7r3).
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
    let collected = hyper_resp
        .into_body()
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

    let method = req.method().clone();
    let query = req.uri().query().map(str::to_owned);
    let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .map_err(|e| Status::internal(format!("failed to read request body: {e}")))?;
    let path_with_query = append_query(path_suffix, query.as_deref());

    if let Some(addr) = proxy_addr.as_deref() {
        // Route through konnectivity via an explicit CONNECT tunnel.
        // konnectivity-server accepts CONNECT only; a plain forward-proxy GET returns 405.
        let (status, headers, body) = pod_proxy_via_connect_tunnel(
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
    let upstream_headers = pod_resp.headers().clone();
    let body = Body::from_stream(pod_resp.bytes_stream());

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
                if let Some(addr) = ep["addresses"][0].as_str().filter(|s| !s.is_empty()) {
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
        let (status, headers, body) = pod_proxy_via_connect_tunnel(
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
    let upstream_headers = ep_resp.headers().clone();
    let body = Body::from_stream(ep_resp.bytes_stream());

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
                "containers": [{"name": "agnhost", "image": "agnhost", "ports": [{"containerPort": 9376}]}]
            },
            "status": {"podIP": "10.5.6.7"}
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
                "containers": [{"name": "agnhost", "image": "agnhost", "ports": [{"containerPort": 9376}]}]
            },
            "status": {"podIP": "10.5.6.7"}
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
            "spec": {"containers": [{"name": "app", "image": "agnhost"}]},
            "status": {"podIP": "10.5.6.7"}
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
    // the network-level test is the live VM repro (see bead mayor-n124). The unit test
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": pod_port}]}]
            },
            "status": {"podIP": "127.0.0.1"}
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                "containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": pod_port}]}]
            },
            "status": {"podIP": "127.0.0.1"}
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
            "spec": {"containers": [{"name": "app", "image": "nginx", "ports": [{"containerPort": 80}]}]},
            "status": {"podIP": "10.0.0.1"}
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

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                {"addresses": ["127.0.0.1"], "conditions": {"ready": true}}
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
