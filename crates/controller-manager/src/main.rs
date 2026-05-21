/// u7s-controller-manager — minimal SA token provisioning controller.
///
/// Watches ServiceAccount objects via a long-poll watch on the API server.
/// For each ADDED event, mints a JWT via the token endpoint and stores it
/// in a Secret of type kubernetes.io/service-account-token.
///
/// Uses the same kubeconfig/TLS stack as u7s-scheduler. The --token-file
/// flag provides an alternative bearer-token bootstrap path when kubeconfig
/// is unavailable (e.g. early cluster bootstrap).
use std::sync::Arc;

use anyhow::{bail, Context};
use base64::Engine;
use clap::Parser;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "u7s-controller-manager",
    about = "Minimal u7s controller manager"
)]
struct Args {
    /// Path to kubeconfig file.
    #[arg(long, default_value = "./kubeconfig")]
    kubeconfig: String,

    /// Bearer token file for bootstrap (alternative to kubeconfig client cert).
    #[arg(long)]
    token_file: Option<String>,

    /// API server address override. Takes precedence over kubeconfig server.
    #[arg(long)]
    server: Option<String>,
}

// ---------------------------------------------------------------------------
// Kubeconfig parsing — identical to scheduler
// ---------------------------------------------------------------------------

struct ClientCreds {
    server: String,
    ca_cert: CertificateDer<'static>,
    client_cert: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
}

fn parse_kubeconfig(path: &str) -> anyhow::Result<ClientCreds> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading kubeconfig {path}"))?;
    let b64 = base64::engine::general_purpose::STANDARD;

    let server = extract_yaml_value(&raw, "server:").context("kubeconfig: missing server")?;
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

fn extract_yaml_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix(key) {
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
        .context("add CA cert")?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(
            vec![creds.client_cert.clone()],
            creds.client_key.clone_key(),
        )
        .context("configure mTLS")?;
    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// HTTP helpers — one connection per request (scaffold; reuse is a later opt)
// ---------------------------------------------------------------------------

async fn send_request(
    connector: &TlsConnector,
    base: &str,
    method: Method,
    path: &str,
    body: Option<String>,
    bearer: Option<&str>,
) -> anyhow::Result<(StatusCode, String)> {
    let uri: Uri = format!("{base}{path}").parse().context("parse URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);

    let stream = TcpStream::connect(format!("{host}:{port}"))
        .await
        .with_context(|| format!("TCP connect {host}:{port}"))?;
    let server_name = host.clone().try_into().context("invalid DNS name")?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .context("TLS")?;
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("connection error: {e}");
        }
    });

    let body_bytes = body
        .as_deref()
        .map(|s| bytes::Bytes::from(s.to_owned()))
        .unwrap_or_default();

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", &host)
        .header("Accept", "application/json");
    if body.is_some() {
        builder = builder
            .header("Content-Type", "application/json")
            .header("Content-Length", body_bytes.len().to_string());
    }
    if let Some(tok) = bearer {
        builder = builder.header("Authorization", format!("Bearer {tok}"));
    }
    let req = builder
        .body(http_body_util::Full::new(body_bytes))
        .context("build request")?;

    let resp: Response<Incoming> = sender.send_request(req).await.context("send")?;
    let status = resp.status();
    use http_body_util::BodyExt;
    let text = String::from_utf8_lossy(
        &resp
            .into_body()
            .collect()
            .await
            .context("read body")?
            .to_bytes(),
    )
    .into_owned();
    Ok((status, text))
}

async fn http_post_json(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    payload: &Value,
    bearer: Option<&str>,
) -> anyhow::Result<(StatusCode, String)> {
    send_request(
        connector,
        base,
        Method::POST,
        path,
        Some(serde_json::to_string(payload)?),
        bearer,
    )
    .await
}

// ---------------------------------------------------------------------------
// Secret construction — pure, testable
// ---------------------------------------------------------------------------

/// Build the Secret object that holds a service-account token.
pub fn build_sa_token_secret(namespace: &str, sa_name: &str, token_b64: &str) -> Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": format!("{sa_name}-token"),
            "namespace": namespace,
            "annotations": {
                "kubernetes.io/service-account.name": sa_name
            }
        },
        "type": "kubernetes.io/service-account-token",
        "data": {
            "token": token_b64
        }
    })
}

// ---------------------------------------------------------------------------
// Watch streaming — identical to scheduler
// ---------------------------------------------------------------------------

async fn stream_watch_events(
    connector: &TlsConnector,
    base: &str,
    path: &str,
    bearer: Option<&str>,
    mut handler: impl FnMut(Value),
) -> anyhow::Result<()> {
    let uri: Uri = format!("{base}{path}").parse().context("parse watch URI")?;
    let host = uri.host().context("URI missing host")?.to_owned();
    let port = uri.port_u16().unwrap_or(443);

    let stream = TcpStream::connect(format!("{host}:{port}"))
        .await
        .with_context(|| format!("TCP connect {host}:{port}"))?;
    let server_name = host.clone().try_into().context("invalid DNS name")?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .context("TLS")?;
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1.1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("watch connection error: {e}");
        }
    });

    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("Host", &host)
        .header("Accept", "application/json");
    if let Some(tok) = bearer {
        builder = builder.header("Authorization", format!("Bearer {tok}"));
    }
    let req = builder
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .context("build watch request")?;

    let resp: Response<Incoming> = sender.send_request(req).await.context("send watch")?;
    if !resp.status().is_success() {
        bail!("watch returned HTTP {}", resp.status());
    }

    use http_body_util::BodyExt;
    let mut body = resp.into_body();
    let mut buf = String::new();

    loop {
        match body.frame().await {
            None => break,
            Some(Err(e)) => {
                warn!("watch stream error: {e}");
                break;
            }
            Some(Ok(frame)) => {
                let frame: hyper::body::Frame<bytes::Bytes> = frame;
                if let Ok(data) = frame.into_data() {
                    buf.push_str(&String::from_utf8_lossy(&data));
                    while let Some(nl) = buf.find('\n') {
                        let line = buf[..nl].trim().to_owned();
                        buf = buf[nl + 1..].to_owned();
                        if line.is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<Value>(&line) {
                            Ok(v) => handler(v),
                            Err(e) => warn!("parse watch event: {e}: {line}"),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SA provisioning logic
// ---------------------------------------------------------------------------

/// Mint a token and store it in a Secret for the given ServiceAccount.
async fn provision_sa(
    connector: &TlsConnector,
    server: &str,
    namespace: &str,
    sa_name: &str,
    bearer: Option<&str>,
) -> anyhow::Result<()> {
    // 1. Mint a JWT.
    let token_path = format!("/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token");
    let token_req = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": { "expirationSeconds": 3600 }
    });
    let (status, body) = http_post_json(connector, server, &token_path, &token_req, bearer).await?;
    if !status.is_success() {
        bail!("TokenRequest for {namespace}/{sa_name} failed ({status}): {body}");
    }
    let token_resp: Value = serde_json::from_str(&body).context("parse TokenRequest response")?;
    let token = token_resp["status"]["token"]
        .as_str()
        .context("TokenRequest response missing status.token")?;

    // 2. Base64-encode the JWT for storage in Secret.data.
    let token_b64 = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());

    // 3. Store in a Secret.
    let secret = build_sa_token_secret(namespace, sa_name, &token_b64);
    let secret_path = format!("/api/v1/namespaces/{namespace}/secrets");
    let (status, body) = http_post_json(connector, server, &secret_path, &secret, bearer).await?;

    if status.is_success() {
        info!("provisioned token secret for {namespace}/{sa_name}");
    } else if status.as_u16() == 409 {
        // Secret already exists — idempotent, not an error.
        info!("token secret for {namespace}/{sa_name} already exists, skipping");
    } else {
        warn!("failed to create token secret for {namespace}/{sa_name} ({status}): {body}");
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

    let bearer_token: Option<String> = args
        .token_file
        .as_deref()
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading token file {p}")))
        .transpose()?
        .map(|s| s.trim().to_owned());

    let mut creds = parse_kubeconfig(&args.kubeconfig)?;
    if let Some(ref s) = args.server {
        creds.server = s.clone();
    }
    let server = creds.server.clone();
    info!("connecting to API server at {server}");

    let connector = build_tls_connector(&creds)?;

    loop {
        info!("starting ServiceAccount watch");
        let path = "/api/v1/serviceaccounts?watch=true";
        let bearer_ref = bearer_token.as_deref();
        let connector_ref = &connector;
        let server_ref = &server;

        let result = stream_watch_events(connector_ref, server_ref, path, bearer_ref, |event| {
            let event_type = event["type"].as_str().unwrap_or("").to_owned();
            if event_type != "ADDED" {
                return;
            }
            let sa_name = event["object"]["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            let namespace = event["object"]["metadata"]["namespace"]
                .as_str()
                .unwrap_or("default")
                .to_owned();
            if sa_name.is_empty() {
                return;
            }
            info!("new ServiceAccount: {namespace}/{sa_name}");

            let connector_clone = connector_ref.clone();
            let server_clone = server_ref.to_string();
            let bearer_clone = bearer_token.clone();
            tokio::spawn(async move {
                if let Err(e) = provision_sa(
                    &connector_clone,
                    &server_clone,
                    &namespace,
                    &sa_name,
                    bearer_clone.as_deref(),
                )
                .await
                {
                    error!("provision_sa {namespace}/{sa_name}: {e}");
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

    #[test]
    fn test_build_sa_token_secret_shape() {
        // The Secret must carry the right type, annotation, and data key.
        // This is the contract the API server and kubelet rely on.
        let secret = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(secret["kind"], "Secret");
        assert_eq!(secret["type"], "kubernetes.io/service-account-token");
        assert_eq!(secret["metadata"]["name"], "my-sa-token");
        assert_eq!(secret["metadata"]["namespace"], "default");
        assert_eq!(
            secret["metadata"]["annotations"]["kubernetes.io/service-account.name"],
            "my-sa"
        );
        assert_eq!(secret["data"]["token"], "dG9rZW4=");
    }

    #[test]
    fn test_build_sa_token_secret_name_format() {
        // Secret name must be "<sa-name>-token" — tools like kubectl rely on this.
        let secret = build_sa_token_secret("kube-system", "coredns", "abc");
        assert_eq!(secret["metadata"]["name"], "coredns-token");
        assert_eq!(secret["metadata"]["namespace"], "kube-system");
    }
}
