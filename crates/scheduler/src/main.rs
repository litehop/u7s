/// u7s-scheduler — minimal scheduler scaffold.
///
/// Watches unscheduled pods (spec.nodeName absent) in the default namespace
/// via a long-poll watch on the API server, picks the first available node,
/// and binds via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// No leader election logic is implemented; the --leader-elect flag is
/// accepted and silently ignored.
use std::sync::Arc;

use anyhow::{bail, Context};
use base64::Engine;
use clap::Parser;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "u7s-scheduler", about = "Minimal u7s pod scheduler")]
struct Args {
    /// Path to kubeconfig file.
    #[arg(long, default_value = "./kubeconfig")]
    kubeconfig: String,

    /// Address for the health/metrics listener (not yet implemented; flag accepted).
    #[arg(long, default_value = "0.0.0.0:10259")]
    listen: String,

    /// API server address override. When set, takes precedence over kubeconfig server.
    #[arg(long)]
    server: Option<String>,

    /// Accept leader-elect flag; silently ignored.
    #[arg(long)]
    leader_elect: bool,
}

// ---------------------------------------------------------------------------
// Kubeconfig parsing (minimal — only the fields we need)
// ---------------------------------------------------------------------------

/// Parsed credentials extracted from a kubeconfig file.
struct ClientCreds {
    /// Base URL of the API server, e.g. "https://127.0.0.1:6443"
    server: String,
    /// DER-encoded CA certificate used to verify the server.
    ca_cert: CertificateDer<'static>,
    /// DER-encoded client certificate.
    client_cert: CertificateDer<'static>,
    /// DER-encoded client private key.
    client_key: PrivateKeyDer<'static>,
}

fn parse_kubeconfig(path: &str) -> anyhow::Result<ClientCreds> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading kubeconfig {path}"))?;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Manual YAML extraction — no serde_yaml dependency.
    // The format is the fixed structure written by u7s-apiserver's tls.rs.
    let server = extract_yaml_value(&raw, "server:")
        .context("kubeconfig: missing server")?;
    let ca_data = extract_yaml_value(&raw, "certificate-authority-data:")
        .context("kubeconfig: missing certificate-authority-data")?;
    let cert_data = extract_yaml_value(&raw, "client-certificate-data:")
        .context("kubeconfig: missing client-certificate-data")?;
    let key_data = extract_yaml_value(&raw, "client-key-data:")
        .context("kubeconfig: missing client-key-data")?;

    let ca_der = b64.decode(ca_data.trim()).context("decode CA cert")?;
    let cert_der = b64.decode(cert_data.trim()).context("decode client cert")?;
    let key_pem = b64.decode(key_data.trim()).context("decode client key")?;

    let client_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse client key PEM")?
        .context("no private key in kubeconfig client-key-data")?;

    Ok(ClientCreds {
        server: server.trim().to_owned(),
        ca_cert: CertificateDer::from(ca_der),
        client_cert: CertificateDer::from(cert_der),
        client_key,
    })
}

/// Extract the first occurrence of a YAML scalar value for `key` in `text`.
/// Handles both "  key: value" and "key: value" with arbitrary leading whitespace.
fn extract_yaml_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(key) {
            return Some(rest.trim());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TLS client setup
// ---------------------------------------------------------------------------

fn build_tls_connector(creds: &ClientCreds) -> anyhow::Result<TlsConnector> {
    use rustls::ClientConfig;

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(creds.ca_cert.clone())
        .context("add CA cert to root store")?;

    let client_cert_chain = vec![creds.client_cert.clone()];
    let client_key = creds.client_key.clone_key();

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_cert_chain, client_key)
        .context("configure mTLS client cert")?;

    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// HTTP helpers — one shot over a fresh TLS connection per request.
// This is a scaffold; connection reuse is a later optimization.
// ---------------------------------------------------------------------------

async fn http_get(
    connector: &TlsConnector,
    base: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let body = send_request(connector, base, Method::GET, path, None).await?;
    Ok(body)
}

async fn http_post_json(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(StatusCode, String)> {
    let body_str = serde_json::to_string(payload)?;
    send_request(connector, base, Method::POST, path, Some(body_str)).await
}

async fn send_request(
    connector: &TlsConnector,
    base: &str,
    method: Method,
    path: &str,
    body: Option<String>,
) -> anyhow::Result<(StatusCode, String)> {
    let uri: Uri = format!("{base}{path}").parse().context("parse URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{host}:{port}");

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
    let bytes = resp.into_body().collect().await.context("read body")?.to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();

    Ok((status, text))
}

// ---------------------------------------------------------------------------
// Watch streaming — reads newline-delimited JSON from a watch endpoint
// ---------------------------------------------------------------------------

async fn stream_watch_events(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    mut handler: impl FnMut(Value),
) -> anyhow::Result<()> {
    let uri: Uri = format!("{base}{path}").parse().context("parse watch URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{host}:{port}");

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

    let resp: Response<Incoming> = sender.send_request(req).await.context("send watch request")?;
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
                    // Process complete lines
                    while let Some(nl) = buf.find('\n') {
                        let line = buf[..nl].trim().to_owned();
                        buf = buf[nl + 1..].to_owned();
                        if line.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<Value>(&line) {
                            Ok(v) => handler(v),
                            Err(e) => warn!("failed to parse watch event: {e}: {line}"),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scheduling logic
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NodeList {
    items: Vec<NodeItem>,
}

#[derive(Deserialize)]
struct NodeItem {
    metadata: Metadata,
}

#[derive(Deserialize)]
struct Metadata {
    name: String,
}

/// Return the name of the first node returned by the API server.
async fn pick_node(connector: &TlsConnector, server: &str) -> anyhow::Result<String> {
    let (status, body) = http_get(connector, server, "/api/v1/nodes").await?;
    if !status.is_success() {
        bail!("GET /api/v1/nodes returned {status}: {body}");
    }
    let list: NodeList = serde_json::from_str(&body).context("parse NodeList")?;
    list.items
        .into_iter()
        .next()
        .map(|n| n.metadata.name)
        .context("no nodes available")
}

/// Bind a pod to a node via POST .../pods/:name/binding.
async fn bind_pod(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    pod_name: &str,
    node_name: &str,
) -> anyhow::Result<()> {
    let path = format!(
        "/api/v1/namespaces/{namespace}/pods/{pod_name}/binding"
    );
    let payload = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Binding",
        "metadata": { "name": pod_name, "namespace": namespace },
        "target": { "apiVersion": "v1", "kind": "Node", "name": node_name }
    });

    let (status, body) = http_post_json(connector, server, &path, &payload).await?;
    if status.is_success() {
        info!("bound pod {namespace}/{pod_name} → node {node_name}");
    } else {
        warn!("binding {namespace}/{pod_name} failed ({status}): {body}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    if args.leader_elect {
        info!("--leader-elect flag set; leader election is not implemented, running as leader");
    }

    let mut creds = parse_kubeconfig(&args.kubeconfig)?;
    if let Some(ref server_override) = args.server {
        info!("API server overridden to {server_override}");
        creds.server = server_override.clone();
    }

    let server = creds.server.clone();
    info!("connecting to API server at {server}");

    let connector = build_tls_connector(&creds)?;

    // Watch loop — reconnect on error with a short backoff.
    loop {
        info!("starting pod watch on /api/v1/namespaces/default/pods?watch=true&fieldSelector=spec.nodeName%3D");
        let path = "/api/v1/namespaces/default/pods?watch=true&fieldSelector=spec.nodeName%3D";

        // Collect events; for each ADDED/MODIFIED pod with empty nodeName, schedule it.
        // We clone connector per loop iteration (cheap Arc clone inside).
        let connector_ref = &connector;
        let server_ref = &server;

        let result = stream_watch_events(connector_ref, server_ref, path, |event| {
            let event_type = event["type"].as_str().unwrap_or("").to_owned();
            if event_type != "ADDED" && event_type != "MODIFIED" {
                return;
            }
            let pod_name = event["object"]["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let namespace = event["object"]["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_owned();
            let node_name_val = &event["object"]["spec"]["nodeName"];
            let already_scheduled = node_name_val.is_string()
                && !node_name_val.as_str().unwrap_or("").is_empty();

            if already_scheduled || pod_name.is_empty() {
                return;
            }

            info!("unscheduled pod detected: {namespace}/{pod_name}");

            // Schedule asynchronously — spawn a task so we don't block the stream.
            let connector_clone = connector_ref.clone();
            let server_clone = server_ref.to_string();
            tokio::spawn(async move {
                match pick_node(&connector_clone, &server_clone).await {
                    Err(e) => error!("failed to list nodes: {e}"),
                    Ok(node) => {
                        if let Err(e) =
                            bind_pod(&connector_clone, &server_clone, &namespace, &pod_name, &node)
                                .await
                        {
                            error!("bind error: {e}");
                        }
                    }
                }
            });
        })
        .await;

        if let Err(e) = result {
            error!("watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
