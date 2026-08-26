//! In-process YAML applier for the well-known manifest directory (`/etc/u7s/manifests`, see
//! `docs/decisions/well-known-manifest-folder.md`) — CoreDNS and any operator-supplied vendored
//! manifest both flow through this same mechanism, sourced from the real `.yaml` files under
//! the repo-root `manifests/` directory.
//!
//! `run()` spawns [`apply_well_known_manifest_dir`] once its own listen socket is bound,
//! authenticating as the `system:bootstrap-installer` x509 identity (see `tls.rs` /
//! `mayor-1pwxi`) to Server-Side-Apply every file in that directory (`--manifest-dir`,
//! defaulting to `/etc/u7s/manifests`), which in turn drives [`apply_yaml_bundle`] per file.
//! This is deliberately not a generic "apply any manifest" API: it understands only the small,
//! fixed set of Kinds a kubeadm-style addon bundle uses (see [`kind_to_resource`]).
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
/// Empty (or whitespace-only) input is a deliberate no-op — kept so callers (and tests) can
/// exercise the wiring without a real manifest bundle.
///
/// A failure here is logged and counted (`u7s_bootstrap_apply_failures_total`); whether that
/// additionally aborts the process is the caller's call, not this function's — see
/// [`apply_well_known_manifest_dir`], whose callers treat the same `Err` as fatal.
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
        let base_url = resource_url(&creds.server, &meta)?;
        // Every apiserver boot after the very first re-applies this same bundle onto objects
        // that already exist (this is what apply_yaml_bundle_is_idempotent below relies on) --
        // do_patch's strategic-merge engine only supports a single-field merge key per list
        // (matching upstream's own `patchMergeKey`), which corrupts kube-dns's Service ports
        // (both entries share `port: 53`, differing only by protocol) into two copies of
        // whichever entry the merge processes last. Skipping a document that's already
        // satisfied avoids ever re-running that merge on steady state.
        let desired = crate::handlers::json_patch::ssa_body_to_json(doc.as_bytes())
            .map_err(|e| anyhow::anyhow!("bootstrap manifest document {}: {e:?}", meta.kind))?;
        if already_applied_remote(&client, &base_url, &desired).await {
            continue;
        }
        let url = ssa_url(&creds.server, &meta)?;
        apply_document(&client, &url, doc.as_bytes()).await?;
    }
    Ok(())
}

/// Server-side-apply every manifest file directly inside `dir`, in lexicographic filename
/// order — deterministic, and lets a later file override fields an earlier one set on the same
/// object (e.g. an operator-supplied file sorting after u7s's own vendored `coredns.yaml`).
/// Entries
/// that are themselves directories, or whose extension isn't `.yaml`/`.yml` (case-insensitive),
/// are skipped, not applied — a `.DS_Store`, editor swap file, or stray `README.md` an operator
/// drops into this folder is not a Kubernetes resource and must not fatal-fail boot.
///
/// A missing `dir` is treated as an empty one — logged at info level, nothing applied — since an
/// operator using an alternate `--manifest-output-dir` legitimately leaves this well-known
/// folder absent (`docs/decisions/well-known-manifest-folder.md`). Any other failure (a file
/// that can't be read, isn't valid YAML, is missing required fields, or that the apiserver
/// itself rejects) stops the scan immediately and is wrapped with the offending file's path, so
/// a caller that treats this as fatal can name exactly which file an operator needs to fix.
pub async fn apply_well_known_manifest_dir(
    kubeconfig_path: &Path,
    dir: &Path,
) -> anyhow::Result<()> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                "well-known manifest directory {} does not exist; applying nothing",
                dir.display()
            );
            return Ok(());
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!("reading well-known manifest directory {}", dir.display())
            })
        }
    };

    let mut paths = Vec::new();
    for entry in read_dir {
        let entry = entry.with_context(|| {
            format!(
                "reading an entry of well-known manifest directory {}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase);
        if !matches!(ext.as_deref(), Some("yaml") | Some("yml")) {
            continue;
        }
        paths.push(path);
    }
    paths.sort();

    for path in &paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading manifest file {}", path.display()))?;
        apply_yaml_bundle(kubeconfig_path, &bytes)
            .await
            .with_context(|| format!("applying manifest file {}", path.display()))?;
    }
    Ok(())
}

/// True if `live` already contains everything `desired` specifies, recursively — i.e.
/// server-side-applying `desired` on top of `live` would be a pure no-op. Objects compare by
/// subset (every key `desired` sets must match in `live`; `live` may carry extra server-added
/// fields like `metadata.uid` or `spec.clusterIPs`); arrays compare pairwise in order, matching
/// how this applier's own bundle never carries `$patch:delete`/`$setElementOrder` directives
/// and never reorders a document's own arrays between one boot and the next.
fn already_applied(desired: &serde_json::Value, live: &serde_json::Value) -> bool {
    match (desired, live) {
        (serde_json::Value::Object(d), serde_json::Value::Object(l)) => d
            .iter()
            .all(|(k, v)| l.get(k).is_some_and(|lv| already_applied(v, lv))),
        (serde_json::Value::Array(d), serde_json::Value::Array(l)) => {
            d.len() == l.len() && d.iter().zip(l).all(|(dv, lv)| already_applied(dv, lv))
        }
        _ => desired == live,
    }
}

/// GET `url` and report whether the live object already satisfies `desired` (see
/// [`already_applied`]). Any failure to determine that (404, connection error, non-JSON body)
/// is treated as "not yet applied" so the caller falls through to the normal PATCH path, which
/// already handles those cases (create-on-404, retry-on-transient-error) — this check is purely
/// an optimization/corruption-avoidance short-circuit, never a new failure mode of its own.
async fn already_applied_remote(
    client: &reqwest::Client,
    url: &str,
    desired: &serde_json::Value,
) -> bool {
    let Ok(resp) = client.get(url).send().await else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(body) = resp.bytes().await else {
        return false;
    };
    let Ok(live) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return false;
    };
    already_applied(desired, &live)
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
/// Deliberately a fixed, small table (the exact Kinds `system:bootstrap-installer`'s RBAC role grants:
/// ClusterRole, ClusterRoleBinding, ServiceAccount, ConfigMap, Deployment, DaemonSet, Service,
/// Namespace) rather than a general kind-pluralization scheme — this applier is bootstrap-only,
/// not a generic "apply any manifest" client, so an unknown Kind is a configuration error worth
/// failing loudly on rather than guessing a plural that might be wrong. DaemonSet (apps/v1,
/// namespaced, mirroring Deployment) is here for kube-proxy and Flannel, which both ship as
/// DaemonSets once they migrate onto this well-known-folder mechanism. Namespace (cluster-scoped,
/// like ClusterRole) is here because Flannel's vendored manifest creates its own `kube-flannel`
/// namespace as the first document in the bundle — without this arm, every boot with that
/// manifest present in the well-known folder would fatal-crash on an unknown-Kind error.
fn kind_to_resource(kind: &str) -> anyhow::Result<(&'static str, bool)> {
    Ok(match kind {
        "ConfigMap" => ("configmaps", true),
        "Service" => ("services", true),
        "ServiceAccount" => ("serviceaccounts", true),
        "Deployment" => ("deployments", true),
        "DaemonSet" => ("daemonsets", true),
        "ClusterRole" => ("clusterroles", false),
        "ClusterRoleBinding" => ("clusterrolebindings", false),
        "Namespace" => ("namespaces", false),
        other => anyhow::bail!(
            "bootstrap applier does not know the REST resource for kind {other:?} — it only \
             understands the fixed set of Kinds bootstrap manifest bundles use"
        ),
    })
}

/// Build the bare (no query string) URL for the object `meta` describes — usable directly for
/// a GET, or as the base for [`ssa_url`]'s `?fieldManager=` PATCH URL.
fn resource_url(server: &str, meta: &DocMeta) -> anyhow::Result<String> {
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
    Ok(format!("{server}{resource_path}"))
}

fn ssa_url(server: &str, meta: &DocMeta) -> anyhow::Result<String> {
    Ok(format!(
        "{}?fieldManager={FIELD_MANAGER}",
        resource_url(server, meta)?
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

    /// kube-proxy and Flannel both ship as DaemonSets upstream; once either migrates its
    /// manifest onto the well-known-folder mechanism, a missing DaemonSet entry here would hit
    /// the fallback branch above and fatally abort apiserver boot instead of resolving the
    /// resource.
    #[test]
    fn kind_to_resource_supports_daemonset_so_kube_proxy_flannel_well_known_folder_migration_doesnt_fatal_boot(
    ) {
        assert_eq!(
            kind_to_resource("DaemonSet").expect("DaemonSet must be a known kind"),
            ("daemonsets", true),
            "DaemonSet must resolve to the namespaced 'daemonsets' resource, matching Deployment's \
             apps/v1 shape"
        );
    }

    /// `manifests/flannel.yaml` ships a `kind: Namespace` object (creating `kube-flannel`)
    /// as the first document in its bundle. Without this arm, `kind_to_resource` hits the
    /// fallback error branch, `apply_well_known_manifest_dir` returns `Err`, and — per
    /// `lib.rs`'s `tokio::select!` wiring — that `Err` fatal-crashes the apiserver on every
    /// boot that has this vendored manifest in the well-known folder.
    #[test]
    fn kind_to_resource_supports_namespace_so_flannels_kube_flannel_namespace_doesnt_fatal_boot() {
        assert_eq!(
            kind_to_resource("Namespace").expect("Namespace must be a known kind"),
            ("namespaces", false),
            "Namespace must resolve to the cluster-scoped 'namespaces' resource, matching \
             ClusterRole's non-namespaced shape"
        );
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
        // Two 500s: the first is the already-applied pre-check GET (also failing, so it falls
        // through to the real apply attempt), the second is the actual PATCH.
        let addr = spawn_mock_http_server(vec![500, 500]).await;
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
            proxy_client_ca_key: dir
                .join("proxy-client-ca.key")
                .to_string_lossy()
                .into_owned(),
            proxy_client_ca_cert: dir
                .join("proxy-client-ca.crt")
                .to_string_lossy()
                .into_owned(),
            advertise_address: Some(format!("https://127.0.0.1:{port}")),
            service_cluster_ip_range: "10.96.0.0/12".into(),
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            node_kubelet_port: vec![],
            konnectivity_proxy_addr: None,
            sa_sig_cache_size: None,
            manifest_dir: dir.join("manifests").to_string_lossy().into_owned(),
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
                Arc::clone(&state.flowcontrol_cache),
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

    // -----------------------------------------------------------------------
    // apply_well_known_manifest_dir — the /etc/u7s/manifests scan (see
    // docs/decisions/well-known-manifest-folder.md). The generic per-document apply mechanics
    // above (idempotency, SSA upsert) already cover a single manifest's correctness; these tests
    // cover the folder-scanning behavior itself: a missing directory is not fatal, files apply
    // in deterministic lexicographic order, and a bad file fails the whole scan naming itself.
    // -----------------------------------------------------------------------

    /// A missing well-known-manifest directory must not fail startup — an operator who points
    /// `--manifest-output-dir` elsewhere (mayor-94sz3) legitimately leaves this folder absent,
    /// and treating "absent" as fatal would break every install that redirects it.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_missing_directory_is_not_fatal() {
        let base = test_temp_dir("missing-dir");
        let dir = base.join("does-not-exist");
        // The scan must return before ever touching the kubeconfig, so a path that doesn't
        // exist on disk is fine here -- if this test needed a real kubeconfig, that alone would
        // prove the implementation touches the network on the "directory absent" path, which is
        // exactly the bug this test guards against.
        let unused_kubeconfig = base.join("unused-kubeconfig");

        apply_well_known_manifest_dir(&unused_kubeconfig, &dir)
            .await
            .expect("a missing well-known manifest directory must be treated as empty, not fatal");
    }

    /// A directory that exists but has no files in it must behave identically to a missing one
    /// (docs/decisions/well-known-manifest-folder.md is explicit that these two cases are
    /// equivalent) -- a fresh install with an empty /etc/u7s/manifests must not fail to boot.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_empty_directory_applies_nothing() {
        let dir = test_temp_dir("empty-dir");
        let unused_kubeconfig = dir.join("unused-kubeconfig");

        apply_well_known_manifest_dir(&unused_kubeconfig, &dir)
            .await
            .expect("an empty well-known manifest directory must be a no-op, not fatal");
    }

    /// Two files, applied against a live apiserver: the well-formed one must land before the
    /// scan hits the malformed one (proving lexicographic order, not directory-listing order),
    /// and the malformed one must fail the whole scan with its own filename named in the error
    /// -- the acceptance bar from docs/decisions/well-known-manifest-folder.md is "the error
    /// message must name the offending file", not just "startup fails".
    #[tokio::test]
    async fn apply_well_known_manifest_dir_applies_in_order_and_names_the_offending_file_on_failure(
    ) {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("well-known-order");
        std::fs::write(
            dir.join("00-good.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: well-known-good\n  namespace: kube-system\ndata:\n  foo: bar\n",
        )
        .expect("write 00-good.yaml");
        std::fs::write(dir.join("01-bad.yaml"), "this: is: not: valid: yaml: [\n")
            .expect("write 01-bad.yaml");

        let result = apply_well_known_manifest_dir(&server.kubeconfig_path, &dir).await;

        let err = result.expect_err(
            "a malformed manifest file must fail the whole scan -- an operator who dropped a \
             broken file into /etc/u7s/manifests needs the apiserver to refuse to start, not \
             silently skip the bad file and boot half-configured",
        );
        let message = format!("{err:#}");
        assert!(
            message.contains("01-bad.yaml"),
            "the error must name the offending file so an operator can actually find and fix \
             it; got: {message}"
        );

        let key = crate::keys::object_key("configmaps", "kube-system", "well-known-good");
        server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect(
                "00-good.yaml sorts before 01-bad.yaml, so it must already be applied by the \
                 time the scan reaches the malformed file -- this is what proves files are \
                 applied in lexicographic filename order, not e.g. directory-listing order",
            );
    }

    /// A non-YAML file (e.g. a `.DS_Store` an operator's Finder drops, or a stray `README.md`)
    /// sitting alongside a genuine manifest must be skipped, not fatal-parsed as "not valid
    /// YAML" — an operator debugging the folder shouldn't be able to break apiserver boot by
    /// leaving a non-resource file behind. The real manifest must still land, proving the filter
    /// doesn't also swallow genuine `.yaml` files.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_skips_non_yaml_files_so_operator_debugging_artifacts_dont_break_boot(
    ) {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("non-yaml-filter");
        std::fs::write(dir.join(".DS_Store"), b"not yaml at all\x00\x01\x02")
            .expect("write .DS_Store");
        std::fs::write(dir.join("README.md"), "# not a manifest\n").expect("write README.md");
        std::fs::write(
            dir.join("00-test.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: non-yaml-filter-test\n  namespace: kube-system\ndata:\n  foo: bar\n",
        )
        .expect("write 00-test.yaml");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect(
                "non-YAML files in the well-known manifest folder must be skipped, not treated \
                 as a fatal parse error — a .DS_Store is not a Kubernetes resource",
            );

        let key = crate::keys::object_key("configmaps", "kube-system", "non-yaml-filter-test");
        server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect(
                "00-test.yaml must still be applied even though .DS_Store and README.md sort \
                 before it lexicographically — the extension filter must skip non-YAML files, \
                 not accidentally skip real manifests too",
            );
    }

    /// An uppercase `.YAML`/`.YML` extension must be accepted, not silently skipped — the
    /// extension filter's case-insensitivity is only real if a test actually exercises a
    /// non-lowercase extension; without this, reverting the `.to_ascii_lowercase()` call in the
    /// walker would still pass every other test in this suite.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_treats_uppercase_yaml_extension_same_as_lowercase_because_operator_case_shouldnt_break_boot(
    ) {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("uppercase-ext");
        std::fs::write(
            dir.join("00-test.YAML"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: uppercase-ext-test\n  namespace: kube-system\ndata:\n  foo: bar\n",
        )
        .expect("write 00-test.YAML");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect("a file with an uppercase .YAML extension must be applied, not skipped");

        let key = crate::keys::object_key("configmaps", "kube-system", "uppercase-ext-test");
        server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect(
                "00-test.YAML must be applied even though its extension is uppercase — the \
                 filter's case-insensitivity claim is only real if a test actually exercises a \
                 non-lowercase extension",
            );
    }

    /// A DaemonSet manifest applied through the well-known-folder mechanism must actually
    /// install, not just resolve a REST path — `kind_to_resource` knowing about "daemonsets" is
    /// useless if `system:bootstrap-installer`'s RBAC role doesn't grant that resource, since the
    /// PATCH would 403 and, per this applier's fail-fast semantics, still fatal-boot the
    /// apiserver. This is the exact bug kube-proxy/Flannel's future well-known-folder migration
    /// would hit if the RBAC grant regressed.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_applies_daemonset_because_bootstrap_installer_rbac_grants_it(
    ) {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("daemonset");
        std::fs::write(
            dir.join("00-daemonset.yaml"),
            "apiVersion: apps/v1\nkind: DaemonSet\nmetadata:\n  name: bootstrap-apply-daemonset-test\n  namespace: kube-system\nspec:\n  selector:\n    matchLabels:\n      app: bootstrap-apply-daemonset-test\n  template:\n    metadata:\n      labels:\n        app: bootstrap-apply-daemonset-test\n    spec:\n      containers:\n      - name: c\n        image: nginx\n",
        )
        .expect("write 00-daemonset.yaml");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect(
                "a DaemonSet manifest must apply successfully -- kind_to_resource resolving \
                 \"daemonsets\" is not enough if the bootstrap-installer RBAC role doesn't also \
                 grant that resource, since the PATCH would then 403 and fatal-boot the apiserver",
            );

        let key = crate::keys::group_object_key(
            "apps",
            "daemonsets",
            Some("kube-system"),
            "bootstrap-apply-daemonset-test",
        );
        server
            .store
            .get(&key)
            .await
            .expect("store get must not fail")
            .expect("the DaemonSet must exist in the store after apply_well_known_manifest_dir");
    }

    /// `manifests/flannel.yaml` ships a `kind: Namespace` document (creating `kube-flannel`)
    /// followed by objects that live inside it — the exact shape this test reproduces. Before
    /// `kind_to_resource` grew a `Namespace` arm, this whole scan returned `Err` on the unknown
    /// Kind, and `apply_well_known_manifest_dir`'s callers treat that `Err` as fatal
    /// (`lib.rs`'s `tokio::select!`), so every boot with Flannel's vendored manifest in the
    /// well-known folder would crash the apiserver outright. This proves the fix end-to-end —
    /// through the real folder scan and a live apiserver, not just `kind_to_resource` in
    /// isolation — and that the namespace-scoped ConfigMap that follows it in the same file
    /// lands too, since it depends on the Namespace document having already been applied.
    #[tokio::test]
    async fn apply_well_known_manifest_dir_applies_namespace_then_object_within_it_because_flannel_yaml_ships_its_own_namespace(
    ) {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("namespace");
        std::fs::write(
            dir.join("00-namespace-bundle.yaml"),
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: bootstrap-apply-ns-test\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: bootstrap-apply-ns-test-cm\n  namespace: bootstrap-apply-ns-test\ndata:\n  foo: bar\n",
        )
        .expect("write 00-namespace-bundle.yaml");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect(
                "a manifest that creates its own Namespace, then an object inside it, must \
                 apply successfully -- this is exactly what manifests/flannel.yaml does, and a \
                 regression here fatal-crashes apiserver boot on every install that vendors it",
            );

        let ns_key = crate::keys::cluster_object_key("namespaces", "bootstrap-apply-ns-test");
        server
            .store
            .get(&ns_key)
            .await
            .expect("store get must not fail")
            .expect(
                "the Namespace must exist in the store after apply_well_known_manifest_dir -- \
                 without kind_to_resource's Namespace arm, this document would abort the scan \
                 before ever reaching the store",
            );

        let cm_key = crate::keys::object_key(
            "configmaps",
            "bootstrap-apply-ns-test",
            "bootstrap-apply-ns-test-cm",
        );
        server
            .store
            .get(&cm_key)
            .await
            .expect("store get must not fail")
            .expect(
                "the ConfigMap inside the newly-created namespace must also exist -- proving the \
             Namespace document was applied before the ConfigMap that depends on it, matching \
             flannel.yaml's own document order",
            );
    }

    // -----------------------------------------------------------------------
    // coredns_manifest_installs_every_kind / coredns_manifest_reapply_does_not_corrupt —
    // CoreDNS ships as a real file, repo-root `manifests/coredns.yaml` (mayor-fiq79), applied
    // through the exact same apply_well_known_manifest_dir path any other vendored or
    // operator-supplied manifest uses — no CoreDNS-specific code path remains. These tests read
    // that real file off disk (not include_bytes!'d, so a version bump needs no rebuild to be
    // picked up here either) and drive it through that generic mechanism, as the regression
    // backstop for "the vendored manifest still applies cleanly" and "reapplying it doesn't
    // corrupt kube-dns's ports".
    // -----------------------------------------------------------------------

    /// Reads the real, currently-vendored CoreDNS manifest straight off disk from the repo-root
    /// `manifests/` directory — never `include_bytes!`, so these tests exercise exactly the
    /// bytes an installed apiserver would read from `/etc/u7s/manifests/coredns.yaml`.
    fn read_coredns_manifest() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../manifests/coredns.yaml"
        ))
        .expect("repo-root manifests/coredns.yaml must exist and be readable")
    }

    #[tokio::test]
    async fn coredns_manifest_installs_every_kind_at_its_expected_key() {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("coredns-installs");
        std::fs::write(dir.join("coredns.yaml"), read_coredns_manifest())
            .expect("write coredns.yaml into well-known manifest dir");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect(
                "the vendored CoreDNS manifest must apply cleanly through the well-known-folder \
                 mechanism against a live apiserver with the system:bootstrap-installer RBAC \
                 role in place — a failure here means every u7s boot silently ships without \
                 in-cluster DNS",
            );

        for (key, kind) in [
            (
                crate::keys::object_key("serviceaccounts", "kube-system", "coredns"),
                "ServiceAccount",
            ),
            (
                crate::keys::group_object_key(
                    "rbac.authorization.k8s.io",
                    "clusterroles",
                    None,
                    "system:coredns",
                ),
                "ClusterRole",
            ),
            (
                crate::keys::group_object_key(
                    "rbac.authorization.k8s.io",
                    "clusterrolebindings",
                    None,
                    "system:coredns",
                ),
                "ClusterRoleBinding",
            ),
            (
                crate::keys::object_key("configmaps", "kube-system", "coredns"),
                "ConfigMap",
            ),
            (
                crate::keys::group_object_key(
                    "apps",
                    "deployments",
                    Some("kube-system"),
                    "coredns",
                ),
                "Deployment",
            ),
            (
                crate::keys::object_key("services", "kube-system", "kube-dns"),
                "Service",
            ),
        ] {
            let obj = server
                .store
                .get(&key)
                .await
                .expect("store get must not fail")
                .unwrap_or_else(|| {
                    panic!(
                        "{kind} at key {key} must exist after applying the CoreDNS bundle — \
                         a missing Kind here means kind_to_resource and this manifest have \
                         drifted apart"
                    )
                });
            let body: serde_json::Value =
                serde_json::from_slice(&obj.value).expect("stored object must be valid JSON");
            assert_eq!(
                body["kind"].as_str(),
                Some(kind),
                "object at {key} must be a {kind}"
            );
        }

        let deployment_key =
            crate::keys::group_object_key("apps", "deployments", Some("kube-system"), "coredns");
        let deployment_body: serde_json::Value = serde_json::from_slice(
            &server
                .store
                .get(&deployment_key)
                .await
                .unwrap()
                .unwrap()
                .value,
        )
        .unwrap();
        let image = deployment_body["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .expect("container image must be a string");
        assert!(
            image.starts_with("registry.k8s.io/coredns/coredns:"),
            "CoreDNS must run the registry.k8s.io/coredns/coredns image — a manifest edit that \
             swapped the image entirely (not just bumped its tag) would otherwise install a \
             DNS server that never even boots CoreDNS, got {image:?}"
        );
        let container_ports = deployment_body["spec"]["template"]["spec"]["containers"][0]["ports"]
            .as_array()
            .expect("container ports must be an array");
        assert!(
            container_ports
                .iter()
                .any(|p| p["containerPort"] == 9153 && p["name"] == "metrics"),
            "CoreDNS container must expose containerPort 9153 (named \"metrics\") — without it \
             the prometheus plugin's listener is unreachable even though it's bound inside the \
             pod (mayor-wclvi), got {container_ports:?}"
        );

        let configmap_key = crate::keys::object_key("configmaps", "kube-system", "coredns");
        let configmap_body: serde_json::Value = serde_json::from_slice(
            &server
                .store
                .get(&configmap_key)
                .await
                .unwrap()
                .unwrap()
                .value,
        )
        .unwrap();
        let corefile = configmap_body["data"]["Corefile"]
            .as_str()
            .expect("Corefile must be a string");
        assert!(
            corefile.contains("prometheus 0.0.0.0:9153"),
            "Corefile must load the prometheus plugin on :9153 — this is the only DNS-side \
             observability signal (query rate, cache hit/miss, plugin errors) available to \
             correlate against future CoreDNS RSS spikes (mayor-b1gz2); losing this line \
             silently regresses that diagnosis path. Corefile was:\n{corefile}"
        );

        let service_key = crate::keys::object_key("services", "kube-system", "kube-dns");
        let service_body: serde_json::Value =
            serde_json::from_slice(&server.store.get(&service_key).await.unwrap().unwrap().value)
                .unwrap();
        assert_eq!(
            service_body["spec"]["clusterIP"].as_str(),
            Some("10.96.0.10"),
            "kube-dns's ClusterIP must stay 10.96.0.10 — kubelet hardcodes this into every \
             pod's /etc/resolv.conf regardless of what the Service's own manifest says"
        );
        let service_ports = service_body["spec"]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(
            service_ports.len(),
            2,
            "kube-dns must expose exactly two ports (UDP and TCP), got {service_ports:?}"
        );
    }

    /// Regression test for mayor-6hog8: CoreDNS's "kubernetes" plugin logs "is not allowed to
    /// list services/endpointslices/namespaces" and every cluster.local lookup returns SERVFAIL
    /// if `system:serviceaccount:kube-system:coredns` can't actually list/watch those resources
    /// cluster-wide. `coredns_manifest_installs_every_kind_at_its_expected_key` above only checks
    /// that the ClusterRole/ClusterRoleBinding objects exist in the store — it never confirms
    /// they grant anything. This rebuilds the RBAC index from the same store the bundle was just
    /// applied to (the same step `run()` takes at boot via `AppState::init`) and asserts the
    /// coredns identity can actually perform every list/watch its "kubernetes" plugin depends on
    /// (pods are deliberately excluded: the vendored Corefile runs the plugin in `pods insecure`
    /// mode, which never calls the API for pods).
    #[tokio::test]
    async fn coredns_manifest_grants_coredns_serviceaccount_the_rbac_its_kubernetes_plugin_needs() {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("coredns-rbac");
        std::fs::write(dir.join("coredns.yaml"), read_coredns_manifest())
            .expect("write coredns.yaml into well-known manifest dir");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect("CoreDNS bundle must apply cleanly");

        let state = crate::state::AppState::new(
            std::sync::Arc::clone(&server.store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        state.init().await;

        let groups: Vec<String> = vec![];
        let coredns_sa = "system:serviceaccount:kube-system:coredns";
        for (api_group, resource) in [
            ("", "services"),
            ("", "namespaces"),
            ("discovery.k8s.io", "endpointslices"),
        ] {
            for verb in ["list", "watch"] {
                let req = crate::rbac::AuthzRequest {
                    username: coredns_sa,
                    groups: &groups,
                    verb,
                    api_group,
                    resource,
                    subresource: "",
                    namespace: None,
                    name: None,
                    non_resource_url: None,
                };
                assert!(
                    state.rbac_index.is_allowed(&req),
                    "{coredns_sa} must be allowed to {verb} {resource} (apiGroup {api_group:?}) \
                     cluster-wide after the CoreDNS bundle applies — without this, CoreDNS's \
                     \"kubernetes\" plugin never syncs and every cluster.local lookup returns \
                     SERVFAIL (mayor-6hog8)"
                );
            }
        }
    }

    /// Re-applying the CoreDNS manifest after it's already installed — the steady-state case on
    /// every apiserver restart after the very first, since `run()` calls
    /// `apply_well_known_manifest_dir` unconditionally on every boot — must not corrupt
    /// kube-dns's Service ports. `do_patch`'s strategic-merge engine only supports a
    /// single-field merge key per list (`port`, matching upstream's own `patchMergeKey`), so a
    /// genuine re-PATCH of a list where two entries share `port: 53` (UDP and TCP) collapses
    /// both into copies of whichever the merge processes last. This fails if the
    /// already-applied short-circuit in `apply_yaml_bundle_inner` — generic mechanism code, not
    /// CoreDNS-specific — is ever removed or broken; kube-dns's Service is the one vendored
    /// manifest that happens to exercise the same-port-number/different-protocol shape that
    /// triggers it, so this is the only regression coverage for that shape.
    #[tokio::test]
    async fn coredns_manifest_reapply_does_not_corrupt_kube_dns_ports() {
        let server = start_test_apiserver().await;
        let dir = test_temp_dir("coredns-reapply");
        std::fs::write(dir.join("coredns.yaml"), read_coredns_manifest())
            .expect("write coredns.yaml into well-known manifest dir");

        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect("first apply must succeed");
        apply_well_known_manifest_dir(&server.kubeconfig_path, &dir)
            .await
            .expect("second apply (every later boot) must also succeed");

        let service_key = crate::keys::object_key("services", "kube-system", "kube-dns");
        let service_body: serde_json::Value = serde_json::from_slice(
            &server
                .store
                .get(&service_key)
                .await
                .expect("store get must not fail")
                .expect("Service must still exist after a second apply")
                .value,
        )
        .expect("stored object must be valid JSON");
        let ports = service_body["spec"]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(
            ports.len(),
            2,
            "kube-dns must still have exactly two ports after a second apply, got {ports:?} — \
             a merge-key collision on port 53 would collapse both entries into duplicates of \
             the last one processed"
        );
        let protocols: Vec<&str> = ports
            .iter()
            .filter_map(|p| p["protocol"].as_str())
            .collect();
        assert!(
            protocols.contains(&"UDP"),
            "UDP port 53 must survive a second apply, got protocols {protocols:?}"
        );
        assert!(
            protocols.contains(&"TCP"),
            "TCP port 53 must survive a second apply, got protocols {protocols:?}"
        );
    }
}
