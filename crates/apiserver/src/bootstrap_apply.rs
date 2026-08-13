//! In-process YAML applier for bootstrap addons (e.g. CoreDNS).
//!
//! `run()` spawns [`apply_yaml_bundle`] once its own listen socket is bound, authenticating
//! as the `system:bootstrap-installer` x509 identity (see `tls.rs` / `mayor-1pwxi`) to
//! Server-Side-Apply a fixed manifest bundle against itself. This is deliberately not a
//! generic "apply any manifest" API: it understands only the small, fixed set of Kinds a
//! kubeadm-style addon bundle uses (see [`kind_to_resource`]).
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine;

/// `?fieldManager=` value stamped on every PATCH — distinguishes this applier's field
/// ownership from kubectl/other controllers in `managedFields`, matching the upstream SSA
/// field-manager convention.
const FIELD_MANAGER: &str = "bootstrap-installer";

/// Total time budget for retrying transient errors on a single document. The only realistic
/// cause of a transient error here is this apiserver's own listener having just bound but not
/// yet begun accepting — 30s is generous headroom for that one-time startup race.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Per-request timeout, independent of the retry budget above — bounds a single stuck
/// connection attempt rather than the whole retry loop.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Server-side-apply every YAML document in `yaml_bytes` against the apiserver identified by
/// the kubeconfig at `kubeconfig_path`, authenticating as `system:bootstrap-installer`.
///
/// Empty (or whitespace-only) input is a deliberate no-op: `run()`'s post-bind hook calls this
/// with a placeholder `b""` today, before any real manifest exists, to prove the wiring works
/// end to end. Path A [3/3] swaps that placeholder for real CoreDNS YAML.
///
/// A failure here is logged and counted (`u7s_bootstrap_apply_failures_total`) but never
/// propagated into a process abort — a missing bootstrap addon is degraded-mode, not
/// crash-worthy, since the apiserver itself is otherwise healthy.
pub async fn apply_yaml_bundle(kubeconfig_path: &Path, yaml_bytes: &[u8]) -> anyhow::Result<()> {
    if yaml_bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    match apply_yaml_bundle_inner(kubeconfig_path, yaml_bytes).await {
        Ok(()) => Ok(()),
        Err(e) => {
            crate::metrics::BOOTSTRAP_APPLY_FAILURES_TOTAL.inc();
            tracing::error!("bootstrap YAML apply failed: {e:#}");
            Err(e)
        }
    }
}

async fn apply_yaml_bundle_inner(kubeconfig_path: &Path, yaml_bytes: &[u8]) -> anyhow::Result<()> {
    let creds = read_kubeconfig_creds(kubeconfig_path)?;
    let client = build_client(&creds)?;
    let text =
        std::str::from_utf8(yaml_bytes).context("bootstrap manifest bundle is not valid UTF-8")?;
    for doc in split_yaml_documents(text) {
        let meta = extract_doc_meta(&doc)?;
        let url = ssa_url(&creds.server, &meta)?;
        apply_document(&client, &url, doc.as_bytes()).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-document YAML splitting + metadata extraction
// ---------------------------------------------------------------------------

/// Split a `---`-separated multi-document YAML bundle into its individual documents,
/// preserving each document's own raw bytes (rather than re-serializing) so the exact text the
/// manifest author wrote is what gets sent as the PATCH body.
fn split_yaml_documents(text: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim_end() == "---" {
            if !current.trim().is_empty() {
                docs.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            continue;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        docs.push(current);
    }
    docs
}

struct DocMeta {
    api_version: String,
    kind: String,
    name: String,
    namespace: Option<String>,
}

fn extract_doc_meta(doc: &str) -> anyhow::Result<DocMeta> {
    let parsed = yaml_rust2::YamlLoader::load_from_str(doc)
        .map_err(|e| anyhow::anyhow!("bootstrap manifest document is not valid YAML: {e}"))?;
    let y = parsed
        .first()
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest document is empty"))?;
    let api_version = y["apiVersion"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest document is missing apiVersion"))?
        .to_owned();
    let kind = y["kind"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest document is missing kind"))?
        .to_owned();
    let name = y["metadata"]["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("bootstrap manifest document is missing metadata.name"))?
        .to_owned();
    let namespace = y["metadata"]["namespace"].as_str().map(str::to_owned);
    Ok(DocMeta {
        api_version,
        kind,
        name,
        namespace,
    })
}

/// Maps a bootstrap manifest's `kind` to its REST resource plural + whether it's namespaced.
///
/// Deliberately a fixed, small table (the exact Kinds `mayor-1pwxi`'s RBAC role grants:
/// ClusterRole, ClusterRoleBinding, ServiceAccount, ConfigMap, Deployment, Service) rather than
/// a general kind-pluralization scheme — this applier is bootstrap-only, not a generic "apply
/// any manifest" client, so an unknown Kind is a configuration error worth failing loudly on
/// rather than guessing a plural that might be wrong.
fn kind_to_resource(kind: &str) -> anyhow::Result<(&'static str, bool)> {
    Ok(match kind {
        "ConfigMap" => ("configmaps", true),
        "Service" => ("services", true),
        "ServiceAccount" => ("serviceaccounts", true),
        "Deployment" => ("deployments", true),
        "ClusterRole" => ("clusterroles", false),
        "ClusterRoleBinding" => ("clusterrolebindings", false),
        other => anyhow::bail!(
            "bootstrap applier does not know the REST resource for kind {other:?} — it only \
             understands the fixed set of Kinds bootstrap manifest bundles use"
        ),
    })
}

fn ssa_url(server: &str, meta: &DocMeta) -> anyhow::Result<String> {
    let (resource, namespaced) = kind_to_resource(&meta.kind)?;
    let group_path = match meta.api_version.split_once('/') {
        Some((group, version)) => format!("/apis/{group}/{version}"),
        None => format!("/api/{}", meta.api_version),
    };
    let name = &meta.name;
    let resource_path = if namespaced {
        let ns = meta.namespace.as_deref().unwrap_or("default");
        format!("{group_path}/namespaces/{ns}/{resource}/{name}")
    } else {
        format!("{group_path}/{resource}/{name}")
    };
    Ok(format!(
        "{server}{resource_path}?fieldManager={FIELD_MANAGER}"
    ))
}

// ---------------------------------------------------------------------------
// Kubeconfig parsing + HTTP client construction
// ---------------------------------------------------------------------------

struct KubeconfigCreds {
    server: String,
    ca_pem: Vec<u8>,
    /// Concatenated client-certificate PEM + client-key PEM, the shape `reqwest::Identity`
    /// expects (same convention as `state.rs`'s `webhook_identity_pem`).
    identity_pem: Vec<u8>,
}

/// Parse the fixed kubeconfig shape `tls::write_component_kubeconfig` writes: manual
/// line-based field extraction, same approach as `u7s-kubeconfig`'s `parse_kubeconfig`
/// (duplicated here rather than depending on that crate, since it exists for the standalone
/// scheduler binary, not for in-process use by the apiserver itself).
fn read_kubeconfig_creds(path: &Path) -> anyhow::Result<KubeconfigCreds> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading bootstrap-installer kubeconfig {}", path.display()))?;

    let server = extract_kubeconfig_field(&raw, "server:")
        .context("bootstrap-installer kubeconfig missing server")?
        .to_owned();
    let ca_data = extract_kubeconfig_field(&raw, "certificate-authority-data:")
        .context("bootstrap-installer kubeconfig missing certificate-authority-data")?;
    let cert_data = extract_kubeconfig_field(&raw, "client-certificate-data:")
        .context("bootstrap-installer kubeconfig missing client-certificate-data")?;
    let key_data = extract_kubeconfig_field(&raw, "client-key-data:")
        .context("bootstrap-installer kubeconfig missing client-key-data")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let ca_pem = b64
        .decode(ca_data.trim())
        .context("decode kubeconfig certificate-authority-data")?;
    let mut identity_pem = b64
        .decode(cert_data.trim())
        .context("decode kubeconfig client-certificate-data")?;
    identity_pem.extend(
        b64.decode(key_data.trim())
            .context("decode kubeconfig client-key-data")?,
    );

    Ok(KubeconfigCreds {
        server,
        ca_pem,
        identity_pem,
    })
}

fn extract_kubeconfig_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
}

/// Build an mTLS `reqwest::Client` pinned to the kubeconfig's own CA (never the system trust
/// store — this client only ever talks to this apiserver's own listener), presenting the
/// bootstrap-installer identity as its client certificate.
fn build_client(creds: &KubeconfigCreds) -> anyhow::Result<reqwest::Client> {
    let ca_cert = reqwest::Certificate::from_pem(&creds.ca_pem)
        .context("bootstrap applier: parse kubeconfig CA certificate")?;
    let identity = reqwest::Identity::from_pem(&creds.identity_pem)
        .context("bootstrap applier: build mTLS identity from kubeconfig")?;
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_certs_only([ca_cert])
        .identity(identity)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("bootstrap applier: build HTTP client")
}

// ---------------------------------------------------------------------------
// PATCH + retry
// ---------------------------------------------------------------------------

fn is_transient_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

/// Server-side-apply a single YAML document at `url`, retrying transient failures
/// (connection-refused, 503, 504) with exponential backoff up to [`MAX_RETRY_WAIT`] total.
/// A 4xx (or any other non-transient) response fails immediately — that's a manifest or RBAC
/// bug, not something retrying will fix.
async fn apply_document(client: &reqwest::Client, url: &str, body: &[u8]) -> anyhow::Result<()> {
    let deadline = Instant::now() + MAX_RETRY_WAIT;
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match client
            .patch(url)
            .header("Content-Type", "application/apply-patch+yaml")
            .body(body.to_vec())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if is_transient_status(resp.status()) => {
                let status = resp.status();
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "bootstrap apply PATCH {url} still returning {status} after \
                         {MAX_RETRY_WAIT:?} of retries"
                    );
                }
                tracing::warn!("bootstrap apply PATCH {url} got {status}; retrying");
            }
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                anyhow::bail!("bootstrap apply PATCH {url} failed with {status}: {text}");
            }
            Err(e) if e.is_connect() => {
                if Instant::now() >= deadline {
                    return Err(e).with_context(|| {
                        format!(
                            "bootstrap apply PATCH {url} still refused after {MAX_RETRY_WAIT:?} \
                             of retries"
                        )
                    });
                }
                tracing::warn!("bootstrap apply PATCH {url} connection error: {e}; retrying");
            }
            Err(e) => return Err(e).with_context(|| format!("bootstrap apply PATCH {url}")),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(backoff.min(remaining)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use u7s_store::Store;

    // -----------------------------------------------------------------------
    // split_yaml_documents / kind_to_resource / ssa_url — pure-function coverage
    // -----------------------------------------------------------------------

    /// A bundle with a leading `---`, blank lines between documents, and a trailing
    /// separator (the exact shape kubeadm's vendored addon YAMLs use) must yield exactly the
    /// real documents — an off-by-one here would silently drop or duplicate a Kind from the
    /// bundle (e.g. CoreDNS's Deployment) with no error at apply time.
    #[test]
    fn split_yaml_documents_handles_leading_and_trailing_separators() {
        let bundle = "---\nkind: A\n---\n\nkind: B\n---\n";
        let docs = split_yaml_documents(bundle);
        assert_eq!(
            docs.len(),
            2,
            "expected exactly 2 documents, got {docs:?} — a wrong count means the bundle's \
             Kinds would be silently dropped or duplicated"
        );
        assert!(docs[0].contains("kind: A"));
        assert!(docs[1].contains("kind: B"));
    }

    /// An unknown Kind must fail loudly rather than guess a plural — this applier is
    /// bootstrap-only, and a silently-wrong URL would 404 with no indication why.
    #[test]
    fn kind_to_resource_rejects_unknown_kind() {
        assert!(kind_to_resource("Widget").is_err());
    }

    #[test]
    fn ssa_url_builds_core_group_namespaced_path() {
        let meta = DocMeta {
            api_version: "v1".into(),
            kind: "ConfigMap".into(),
            name: "coredns".into(),
            namespace: Some("kube-system".into()),
        };
        let url = ssa_url("https://127.0.0.1:6443", &meta).expect("known kind must build a URL");
        assert_eq!(
            url,
            "https://127.0.0.1:6443/api/v1/namespaces/kube-system/configmaps/coredns?fieldManager=bootstrap-installer"
        );
    }

    #[test]
    fn ssa_url_builds_named_group_cluster_scoped_path() {
        let meta = DocMeta {
            api_version: "rbac.authorization.k8s.io/v1".into(),
            kind: "ClusterRole".into(),
            name: "coredns".into(),
            namespace: None,
        };
        let url = ssa_url("https://127.0.0.1:6443", &meta).expect("known kind must build a URL");
        assert_eq!(
            url,
            "https://127.0.0.1:6443/apis/rbac.authorization.k8s.io/v1/clusterroles/coredns?fieldManager=bootstrap-installer"
        );
    }

    // -----------------------------------------------------------------------
    // apply_document — retry/backoff behavior against a plain-HTTP mock listener.
    //
    // apply_document is the shared per-document code path apply_yaml_bundle drives once per
    // manifest document; exercising it directly (rather than through the full
    // kubeconfig-parsing + mTLS-client-building path) is what makes the 503/403 scenarios
    // below fast, deterministic unit tests instead of ones needing a real TLS handshake.
    // -----------------------------------------------------------------------

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn parse_content_length(header_bytes: &[u8]) -> usize {
        String::from_utf8_lossy(header_bytes)
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Read one full HTTP/1.1 request (headers + Content-Length body) off `tcp`, discarding
    /// it. Draining the body before responding avoids racing a server-side close against the
    /// client still writing its PATCH body.
    async fn drain_one_http_request(tcp: &mut tokio::net::TcpStream) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut chunk)).await;
            match read {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(header_end) = find_header_end(&buf) {
                        let content_length = parse_content_length(&buf[..header_end]);
                        if buf.len() >= header_end + content_length {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Spawn a bare-bones plain-HTTP (no TLS) mock server that accepts one connection per
    /// entry in `status_sequence`, drains the request, and replies with that status code.
    /// Returns its address. `apply_document` doesn't care whether `url` is http or https, so
    /// this sidesteps needing a real TLS handshake to test retry/status-handling logic.
    async fn spawn_mock_http_server(status_sequence: Vec<u16>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock listener");
        let addr = listener.local_addr().expect("mock listener local addr");
        tokio::spawn(async move {
            for status in status_sequence {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                drain_one_http_request(&mut tcp).await;
                let body = format!("mock status {status}");
                let response = format!(
                    "HTTP/1.1 {status} mock\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(response.as_bytes()).await;
                let _ = tcp.shutdown().await;
            }
        });
        addr
    }

    /// A server that 503s twice before succeeding must still end in success — this is exactly
    /// the one-time startup race apply_yaml_bundle is meant to survive (its own apiserver's
    /// listener bound but not yet accepting). Without retry, `run()`'s post-bind hook would
    /// lose the CoreDNS install race on every single boot.
    #[tokio::test]
    async fn apply_yaml_bundle_retries_transient_5xx() {
        let addr = spawn_mock_http_server(vec![503, 503, 200]).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/api/v1/namespaces/kube-system/configmaps/coredns");

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            apply_document(&client, &url, b"kind: ConfigMap\n"),
        )
        .await
        .expect("two 503s then 200 must resolve well within 5s of backoff, not hang");

        assert!(
            result.is_ok(),
            "apply_document must succeed once the transient 503s clear; got {result:?}"
        );
    }

    /// A 403 (RBAC gap) must fail on the first attempt, not after burning the retry budget —
    /// retrying a permissions error can never succeed, and treating it as transient would
    /// make every misconfigured bootstrap RBAC role hang for 30s on every boot instead of
    /// failing fast with a log line an operator can act on.
    #[tokio::test]
    async fn apply_yaml_bundle_does_not_retry_4xx() {
        let addr = spawn_mock_http_server(vec![403]).await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/api/v1/namespaces/kube-system/configmaps/coredns");

        // If this regresses to retrying, the mock server (which only serves one connection)
        // stops accepting after the first request; the next connection attempt will be
        // refused, which is itself "transient" and would retry all the way to the real 30s
        // MAX_RETRY_WAIT. Bounding the test at 2s turns that hang into a fast, loud failure.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            apply_document(&client, &url, b"kind: ConfigMap\n"),
        )
        .await
        .expect("a 403 must fail within 2s, not silently retry toward the 30s budget");

        assert!(
            result.is_err(),
            "apply_document must not treat 403 as success; got {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // metric_increments_on_failure — through the public apply_yaml_bundle, since the
    // counter increment lives there, not in apply_document.
    // -----------------------------------------------------------------------

    /// A self-signed cert+key pair, PEM-encoded. `build_client` only needs syntactically
    /// valid PEM to construct `reqwest::Certificate`/`Identity` — since this test's target
    /// kubeconfig points at a plain http:// mock, the TLS material is never actually used in
    /// a handshake, so a throwaway self-signed pair (not chained to anything) is sufficient.
    fn dummy_pem_cert_and_key() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().expect("generate dummy key");
        let cert = CertificateParams::default()
            .self_signed(&key)
            .expect("self-sign dummy cert");
        let cert_pem = crate::tls::pem_encode("CERTIFICATE", cert.der());
        (cert_pem, key.serialize_pem().into_bytes())
    }

    fn write_test_kubeconfig(
        path: &Path,
        server: &str,
        ca_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) {
        let b64 = base64::engine::general_purpose::STANDARD;
        let yaml = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: {server}\n    certificate-authority-data: {}\n  name: u7s\nusers:\n- name: system:bootstrap-installer\n  user:\n    client-certificate-data: {}\n    client-key-data: {}\n",
            b64.encode(ca_pem),
            b64.encode(cert_pem),
            b64.encode(key_pem),
        );
        std::fs::write(path, yaml).expect("write test kubeconfig");
    }

    fn test_temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let tid = std::thread::current().id();
        let dir = std::env::temp_dir().join(format!("u7s-bootstrap-apply-{tag}-{nanos}-{tid:?}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// A target that always 500s must both fail `apply_yaml_bundle` AND bump
    /// `u7s_bootstrap_apply_failures_total` — that counter is the only signal an operator has
    /// that a bootstrap addon (e.g. CoreDNS) silently failed to install, since a failure here
    /// never aborts the apiserver itself.
    #[tokio::test]
    async fn metric_increments_on_failure() {
        let (cert_pem, key_pem) = dummy_pem_cert_and_key();
        let dir = test_temp_dir("metric");
        let addr = spawn_mock_http_server(vec![500]).await;
        let kubeconfig_path = dir.join("kubeconfig");
        write_test_kubeconfig(
            &kubeconfig_path,
            &format!("http://{addr}"),
            &cert_pem,
            &cert_pem,
            &key_pem,
        );

        let before = crate::metrics::BOOTSTRAP_APPLY_FAILURES_TOTAL.get();

        let manifest = b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: coredns\n  namespace: kube-system\n";
        let result = apply_yaml_bundle(&kubeconfig_path, manifest).await;

        assert!(
            result.is_err(),
            "a target that always 500s must make apply_yaml_bundle fail; got {result:?}"
        );
        let after = crate::metrics::BOOTSTRAP_APPLY_FAILURES_TOTAL.get();
        assert!(
            after > before,
            "u7s_bootstrap_apply_failures_total must increment on failure (before={before}, \
             after={after}) — without it, a silently-broken bootstrap install is invisible to \
             an operator"
        );
    }

    // -----------------------------------------------------------------------
    // apply_yaml_bundle_succeeds_on_valid_manifest / apply_yaml_bundle_is_idempotent —
    // through a real, full in-process apiserver (TLS + RBAC + AuthLayer), authenticating as
    // the actual system:bootstrap-installer identity these two tests exist to validate.
    // -----------------------------------------------------------------------

    struct TestApiserver {
        kubeconfig_path: std::path::PathBuf,
        store: std::sync::Arc<u7s_store::SqliteStore>,
    }

    async fn start_test_apiserver() -> TestApiserver {
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let dir = test_temp_dir("apiserver");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test apiserver listener");
        let port = listener.local_addr().expect("listener local addr").port();

        let args = crate::Args {
            db: dir.join("state.db").to_string_lossy().into_owned(),
            listen: format!("127.0.0.1:{port}"),
            kubeconfig: dir.join("kubeconfig").to_string_lossy().into_owned(),
            token_auth_file: None,
            sa_key: dir.join("sa.key").to_string_lossy().into_owned(),
            sa_pub: dir.join("sa.pub").to_string_lossy().into_owned(),
            ca_key: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert: dir.join("ca.crt").to_string_lossy().into_owned(),
            advertise_address: Some(format!("https://127.0.0.1:{port}")),
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
        };

        let tls = crate::tls::generate_tls(&args).expect("generate_tls must succeed");

        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory store"));
        crate::seed_namespaces(&store)
            .await
            .expect("seed_namespaces must not fail");
        crate::seed_rbac(&store)
            .await
            .expect("seed_rbac must not fail");

        let kubeconfig_path = dir.join("bootstrap-installer-kubeconfig");
        crate::tls::write_component_kubeconfig(
            &kubeconfig_path.to_string_lossy(),
            &tls,
            &args,
            &tls.bootstrap_installer_cert_der,
            &tls.bootstrap_installer_key_pem,
            "system:bootstrap-installer",
        )
        .expect("write bootstrap-installer kubeconfig");

        let state = crate::state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            format!("https://127.0.0.1:{port}"),
        );
        state.init().await;

        let app = crate::build_router(state.clone())
            .layer(crate::content_type::ContentTypeLayer)
            .layer(crate::auth::AuthLayer::new(
                Arc::clone(&state.rbac_index),
                (*state.token_map).clone(),
                state.sa_decoding_key.clone(),
                Arc::clone(&state.store),
                Arc::clone(&state.sa_sig_cache),
            ))
            .layer(crate::inflight::InflightLayer::new())
            .layer(axum::extract::DefaultBodyLimit::max(crate::MAX_BODY_BYTES));

        tokio::spawn(crate::serve_tls(listener, app, tls.server_config.clone()));

        TestApiserver {
            kubeconfig_path,
            store,
        }
    }

    /// The entire point of this applier: a valid bootstrap manifest document, applied against
    /// a real running apiserver authenticated as system:bootstrap-installer, must land in the
    /// store — this is the exact mechanism Path A [3/3] relies on to install CoreDNS at boot.
    #[tokio::test]
    async fn apply_yaml_bundle_succeeds_on_valid_manifest() {
        let server = start_test_apiserver().await;
        let manifest = b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: bootstrap-apply-test\n  namespace: kube-system\ndata:\n  foo: bar\n";

        apply_yaml_bundle(&server.kubeconfig_path, manifest)
            .await
            .expect(
                "apply_yaml_bundle must succeed against a live apiserver with the \
                 system:bootstrap-installer RBAC role in place",
            );

        let key = crate::keys::object_key("configmaps", "kube-system", "bootstrap-apply-test");
        let obj = server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect(
                "the ConfigMap must exist in the store after apply_yaml_bundle — this is the \
                 whole point of the bootstrap YAML applier: install an addon manifest at boot",
            );
        let body: serde_json::Value =
            serde_json::from_slice(&obj.value).expect("stored object must be valid JSON");
        assert_eq!(
            body["data"]["foo"], "bar",
            "the applied ConfigMap must carry the manifest's own data, not an empty object"
        );
    }

    /// Re-applying the identical manifest must succeed again and leave the object's data
    /// unchanged — SSA upsert semantics are what let `run()` call apply_yaml_bundle on every
    /// boot unconditionally, with no "already installed" check. If a second apply failed, or
    /// silently changed the resulting data, every restart after the first would break the
    /// installed addon.
    #[tokio::test]
    async fn apply_yaml_bundle_is_idempotent() {
        let server = start_test_apiserver().await;
        let manifest = b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: bootstrap-apply-test\n  namespace: kube-system\ndata:\n  foo: bar\n";

        apply_yaml_bundle(&server.kubeconfig_path, manifest)
            .await
            .expect("first apply must succeed");
        apply_yaml_bundle(&server.kubeconfig_path, manifest)
            .await
            .expect(
                "second apply of the identical manifest must also succeed — this is the SSA \
                 upsert guarantee run() relies on to call apply_yaml_bundle unconditionally on \
                 every boot",
            );

        let key = crate::keys::object_key("configmaps", "kube-system", "bootstrap-apply-test");
        let obj = server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect("ConfigMap must still exist after the second apply");
        let body: serde_json::Value =
            serde_json::from_slice(&obj.value).expect("stored object must be valid JSON");
        assert_eq!(
            body["data"]["foo"], "bar",
            "re-applying the same manifest must leave data unchanged, not corrupt or drop it"
        );
    }
}
