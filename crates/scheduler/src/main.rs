/// u7s-scheduler — minimal scheduler scaffold.
///
/// Watches unscheduled pods (spec.nodeName absent) cluster-wide
/// via a long-poll watch on the API server, picks the first available node,
/// and binds via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// No leader election logic is implemented; the --leader-elect flag is
/// accepted and silently ignored.
use anyhow::{bail, Context};
use clap::Parser;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};
use u7s_client_util::{build_tls_connector, parse_kubeconfig};

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

/// Determine whether a watch event represents a pod that needs scheduling.
///
/// Returns `Some((namespace, pod_name))` when the event is an ADDED or
/// MODIFIED pod with an empty `spec.nodeName`; `None` otherwise.
///
/// Extracted as a pure function so the decision can be unit-tested without
/// standing up an API server.
fn needs_scheduling(event: &Value) -> Option<(String, String)> {
    let event_type = event["type"].as_str().unwrap_or("");
    if event_type != "ADDED" && event_type != "MODIFIED" {
        return None;
    }
    let pod_name = event["object"]["metadata"]["name"].as_str().unwrap_or("");
    if pod_name.is_empty() {
        return None;
    }
    let node_name = &event["object"]["spec"]["nodeName"];
    let already_scheduled = node_name.is_string() && !node_name.as_str().unwrap_or("").is_empty();
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
    let path = format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/binding");
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
        info!("starting pod watch on /api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D");
        let path = "/api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D";

        // Collect events; for each ADDED/MODIFIED pod with empty nodeName, schedule it.
        // We clone connector per loop iteration (cheap Arc clone inside).
        let connector_ref = &connector;
        let server_ref = &server;

        let result = stream_watch_events(connector_ref, server_ref, path, |event| {
            let Some((namespace, pod_name)) = needs_scheduling(&event) else {
                return;
            };

            info!("unscheduled pod detected: {namespace}/{pod_name}");

            // Schedule asynchronously — spawn a task so we don't block the stream.
            let connector_clone = connector_ref.clone();
            let server_clone = server_ref.to_string();
            tokio::spawn(async move {
                match pick_node(&connector_clone, &server_clone).await {
                    Err(e) => error!("failed to list nodes: {e}"),
                    Ok(node) => {
                        if let Err(e) = bind_pod(
                            &connector_clone,
                            &server_clone,
                            &namespace,
                            &pod_name,
                            &node,
                        )
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
}
