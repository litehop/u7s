mod auth;
mod handlers;
mod inflight;
mod keys;
mod patch;
mod proto;
mod rbac;
mod state;
mod status;
mod tls;
mod types;
mod util;

use std::sync::Arc;

use axum::{Router, routing::{get, post}};
use tower_service::Service;
use clap::Parser;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use u7s_store::SqliteStore;

use auth::{AuthLayer, PeerCertificate};
use inflight::InflightLayer;
use state::AppState;
use tls::{generate_tls, load_or_generate_sa_keys, write_kubeconfig};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "./state.db")]
    db: String,

    #[arg(long, default_value = "0.0.0.0:6443")]
    listen: String,

    /// Output path for the generated kubeconfig. Write-only on first run —
    /// not a read fixture. Generated fresh from TLS material each startup.
    #[arg(long, default_value = "./kubeconfig")]
    kubeconfig: String,

    /// Path to a bearer-token auth file (token,user,uid,group,...).
    /// Optional. When absent, only anonymous access is permitted unless
    /// RBAC grants it.
    #[arg(long)]
    token_auth_file: Option<String>,

    /// Path to the RSA private key used to sign service-account JWTs.
    /// Generated on first run; loaded on subsequent starts to keep tokens valid.
    #[arg(long, default_value = "./sa.key")]
    sa_key: String,

    /// Path to write the RSA public key (companion to --sa-key).
    #[arg(long, default_value = "./sa.pub")]
    sa_pub: String,

    /// Path to the CA private key (PEM). Generated on first run; loaded on
    /// subsequent starts so the CA stays stable across restarts.
    #[arg(long, default_value = "./ca.key")]
    ca_key: String,

    /// Path to the CA certificate (DER). Generated on first run; loaded on
    /// subsequent starts so kubelets trust the same CA after a restart.
    #[arg(long, default_value = "./ca.crt")]
    ca_cert: String,

    /// Address advertised to clients in /api discovery (e.g. "https://1.2.3.4:6443").
    /// Defaults to the listen address, substituting 0.0.0.0 with 127.0.0.1.
    #[arg(long)]
    advertise_address: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // 1. Parse CLI args.
    let args = Args::parse();

    // 2. Init tracing.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // 3. Open store.
    let store = Arc::new(SqliteStore::new(&args.db)?);
    seed_namespaces(&store).await?;
    seed_rbac(&store).await?;

    // 4. Generate TLS certs.
    let tls_material = generate_tls(&args)?;

    // 5. Write kubeconfig.
    write_kubeconfig(&args.kubeconfig, &tls_material, &args)?;

    // 6. Load optional static token map.
    let token_map = match &args.token_auth_file {
        Some(path) => {
            tracing::info!("loading token auth file: {path}");
            auth::load_token_file(path)?
        }
        None => std::collections::HashMap::new(),
    };

    // 7. Load or generate the SA signing key.
    let (sa_encoding_key, sa_decoding_key) = match load_or_generate_sa_keys(&args.sa_key, &args.sa_pub) {
        Ok(sa_keys) => {
            let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&sa_keys.private_key_pem)
                .map_err(|e| { tracing::error!("failed to load SA signing key: {e}"); e })
                .ok();
            let dec = jsonwebtoken::DecodingKey::from_rsa_pem(&sa_keys.public_key_pem)
                .map_err(|e| { tracing::error!("failed to load SA public key: {e}"); e })
                .ok();
            (enc, dec)
        }
        Err(e) => {
            tracing::error!("SA key gen/load failed: {e}");
            (None, None)
        }
    };

    // 8. Compute advertised server address.
    let server_address = match args.advertise_address {
        Some(addr) => addr,
        None => {
            // When listening on 0.0.0.0, default to loopback so local kubectl works.
            if args.listen.starts_with("0.0.0.0:") {
                let port = &args.listen["0.0.0.0:".len()..];
                format!("https://127.0.0.1:{port}")
            } else {
                format!("https://{}", args.listen)
            }
        }
    };
    tracing::info!("advertised server address: {server_address}");

    // 9. Build app state (shared with the auth layer).
    let state = AppState::new(Arc::clone(&store), sa_encoding_key, sa_decoding_key, token_map, server_address);

    // 9a. Populate RBAC index from persisted objects before serving.
    state.init().await;

    // 10. Build axum router and attach tower layers.
    //     Order (outermost first): inflight → auth → handler.
    let app = build_router(state.clone())
        .layer(AuthLayer::new(
            Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_decoding_key.clone(),
        ))
        .layer(InflightLayer::new());

    // 11. Bind TLS listener and serve.
    let listener = TcpListener::bind(&args.listen).await?;
    serve_tls(listener, app, tls_material.server_config).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        // Server version — no auth required (sonobuoy, kubectl version)
        .route("/version", get(handlers::discovery::version))

        // Core discovery
        .route("/api",    get(handlers::discovery::api_versions))
        .route("/api/v1", get(handlers::discovery::api_v1_resources))

        // Non-core group discovery
        .route("/apis",                    get(handlers::discovery::api_group_list))
        .route("/apis/{group}/{version}",    get(handlers::discovery::api_group_resources))

        // Namespaces — collection
        .route(
            "/api/v1/namespaces",
            get(handlers::namespaces::list_namespaces).post(handlers::namespaces::create_namespace),
        )

        // Namespaces — named resource
        .route(
            "/api/v1/namespaces/{name}",
            get(handlers::namespaces::get_namespace)
                .put(handlers::namespaces::replace_namespace)
                .patch(handlers::namespaces::patch_namespace)
                .delete(handlers::namespaces::delete_namespace),
        )

        // Pods — collection
        .route(
            "/api/v1/namespaces/{ns}/pods",
            get(handlers::pods::list_pods).post(handlers::pods::create_pod),
        )

        // Pods — named resource
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}",
            get(handlers::pods::get_pod)
                .put(handlers::pods::replace_pod)
                .delete(handlers::pods::delete_pod)
                .patch(handlers::pods::patch_pod),
        )

        // Pods — binding subresource (scheduler write path)
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/binding",
            axum::routing::post(handlers::pods::bind_pod),
        )

        // Pods — status subresource
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/status",
            get(handlers::pods::get_pod_status)
                .put(handlers::pods::replace_pod_status)
                .patch(handlers::pods::patch_pod_status),
        )

        // Core group (group="", apiVersion=v1) — cluster-scoped resources (e.g. nodes)
        .route(
            "/api/v1/{resource}",
            get(handlers::generic::core_list_resource)
                .post(handlers::generic::core_create_resource),
        )

        // Core group — cluster-scoped named resource
        .route(
            "/api/v1/{resource}/{name}",
            get(handlers::generic::core_get_resource)
                .put(handlers::generic::core_replace_resource)
                .delete(handlers::generic::core_delete_resource)
                .patch(handlers::generic::core_patch_resource),
        )

        // Core group — cluster-scoped status subresource
        .route(
            "/api/v1/{resource}/{name}/status",
            get(handlers::generic::core_get_resource_status)
                .put(handlers::generic::core_put_resource_status)
                .patch(handlers::generic::core_patch_resource_status),
        )

        // Core group — namespaced resources collection (e.g. services, configmaps)
        .route(
            "/api/v1/namespaces/{ns}/{resource}",
            get(handlers::generic::core_list_namespaced_resource)
                .post(handlers::generic::core_create_namespaced_resource),
        )

        // Core group — namespaced named resource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}",
            get(handlers::generic::core_get_namespaced_resource)
                .put(handlers::generic::core_replace_namespaced_resource)
                .delete(handlers::generic::core_delete_namespaced_resource)
                .patch(handlers::generic::core_patch_namespaced_resource),
        )

        // Core group — namespaced status subresource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::generic::core_get_namespaced_resource_status)
                .put(handlers::generic::core_put_namespaced_resource_status)
                .patch(handlers::generic::core_patch_namespaced_resource_status),
        )

        // CRDs — cluster-scoped, specific paths before generic catch-all
        .route(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            get(handlers::crd::list_crds).post(handlers::crd::create_crd),
        )
        .route(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}",
            get(handlers::crd::get_crd)
                .put(handlers::crd::replace_crd)
                .delete(handlers::crd::delete_crd),
        )

        // Authorization reviews (specific paths before generic catch-all)
        .route(
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            post(handlers::authorization::self_subject_access_review),
        )
        .route(
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            post(handlers::authorization::self_subject_rules_review),
        )
        .route(
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            post(handlers::authorization::subject_access_review),
        )
        .route(
            "/apis/authentication.k8s.io/v1/tokenreviews",
            post(handlers::authorization::token_review),
        )

        // ServiceAccounts — token subresource (TokenRequest API)
        .route(
            "/api/v1/namespaces/{ns}/serviceaccounts/{name}/token",
            axum::routing::post(handlers::tokens::create_token),
        )

        // Generic cluster-scoped resources — collection
        .route(
            "/apis/{group}/{version}/{resource}",
            get(handlers::generic::list_resource)
                .post(handlers::generic::create_resource),
        )

        // Generic cluster-scoped resources — named
        .route(
            "/apis/{group}/{version}/{resource}/{name}",
            get(handlers::generic::get_resource)
                .put(handlers::generic::replace_resource)
                .delete(handlers::generic::delete_resource)
                .patch(handlers::generic::patch_resource),
        )

        // Generic namespaced resources — collection
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}",
            get(handlers::generic::list_namespaced_resource)
                .post(handlers::generic::create_namespaced_resource),
        )

        // Scale subresource — apps/v1 workloads (deployments, replicasets, statefulsets)
        // Must be registered before the generic namespaced named-resource catch-all.
        .route(
            "/apis/apps/v1/namespaces/{ns}/{resource}/{name}/scale",
            get(handlers::scale::get_scale)
                .put(handlers::scale::put_scale)
                .patch(handlers::scale::patch_scale),
        )

        // Generic namespaced resources — named
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}",
            get(handlers::generic::get_namespaced_resource)
                .put(handlers::generic::replace_namespaced_resource)
                .delete(handlers::generic::delete_namespaced_resource)
                .patch(handlers::generic::patch_namespaced_resource),
        )

        // Generic cluster-scoped — status subresource
        .route(
            "/apis/{group}/{version}/{resource}/{name}/status",
            get(handlers::generic::get_resource_status)
                .put(handlers::generic::put_resource_status)
                .patch(handlers::generic::patch_resource_status),
        )

        // Generic namespaced — status subresource
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::generic::get_namespaced_resource_status)
                .put(handlers::generic::put_namespaced_resource_status)
                .patch(handlers::generic::patch_namespaced_resource_status),
        )

        .with_state(state)
}

async fn seed_namespaces(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;
    // Static UIDs — no uuid crate needed.
    const NS: &[(&str, &str)] = &[
        ("default",          "00000000-0000-0000-0000-000000000001"),
        ("kube-system",      "00000000-0000-0000-0000-000000000002"),
        ("kube-node-lease",  "00000000-0000-0000-0000-000000000003"),
        ("kube-public",      "00000000-0000-0000-0000-000000000004"),
    ];
    for (name, uid) in NS {
        let key = keys::cluster_object_key("namespaces", name);
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "uid": uid,
                "creationTimestamp": "2024-01-01T00:00:00Z",
                "labels": { "kubernetes.io/metadata.name": name }
            },
            "status": { "phase": "Active" }
        });
        let bytes = Bytes::from(body.to_string());
        match store.put(&key, bytes, Some(0)).await {
            Ok(_) => tracing::info!("seeded namespace: {name}"),
            Err(u7s_store::StoreError::AlreadyExists { .. }) => {
                // Already exists — idempotent, ignore.
            }
            Err(e) => return Err(anyhow::anyhow!("seed namespace {name}: {e}")),
        }
    }
    Ok(())
}

async fn seed_rbac(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const GROUP: &str = "rbac.authorization.k8s.io";

    // ClusterRole: system:node — permissions kubelet needs.
    let cr_key = keys::group_object_key(GROUP, "clusterroles", None, "system:node");
    let cr_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000010" },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"],        "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"],         "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods/status"],  "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods/log"],     "verbs": ["get"] },
            { "apiGroups": [""], "resources": ["events"],       "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["configmaps"],   "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["secrets"],      "verbs": ["get","list","watch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch"] }
        ]
    });
    store.put(&cr_key, Bytes::from(cr_body.to_string()), None).await
        .map_err(|e| anyhow::anyhow!("seed ClusterRole system:node: {e}"))?;
    tracing::info!("seeded ClusterRole: system:node");

    // ClusterRoleBinding: system:node — binds system:nodes group to the ClusterRole.
    let crb_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
    let crb_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000011" },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:nodes" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node" }
    });
    store.put(&crb_key, Bytes::from(crb_body.to_string()), None).await
        .map_err(|e| anyhow::anyhow!("seed ClusterRoleBinding system:node: {e}"))?;
    tracing::info!("seeded ClusterRoleBinding: system:node");

    Ok(())
}

async fn serve_tls(
    listener: TcpListener,
    app: Router,
    server_config: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    tracing::info!("listening on {}", listener.local_addr()?);

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => { tracing::warn!("TLS accept error: {e}"); return; }
            };

            // Extract the peer certificate once per connection, then share it
            // across all requests on this connection via an Arc.
            let peer_cert: Arc<Option<PeerCertificate>> = Arc::new(
                tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .map(|c| PeerCertificate(c.as_ref().to_vec())),
            );

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |mut req: axum::http::Request<_>| {
                let peer_cert = Arc::clone(&peer_cert);
                let mut app = app.clone();
                async move {
                    if let Some(cert) = peer_cert.as_ref().as_ref() {
                        req.extensions_mut().insert(cert.clone());
                    }
                    Ok::<_, std::convert::Infallible>(app.call(req).await.unwrap())
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use u7s_store::{Store, SqliteStore};

    fn make_store() -> SqliteStore {
        SqliteStore::new(":memory:").expect("open in-memory db")
    }

    #[tokio::test]
    async fn seed_namespaces_creates_default_and_kube_system() {
        // All four namespaces must exist after a single call — required by Kubernetes API contract.
        let store = make_store();
        seed_namespaces(&store).await.expect("seed must not fail");

        for name in ["default", "kube-system", "kube-node-lease", "kube-public"] {
            let key = keys::cluster_object_key("namespaces", name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "namespace '{name}' must exist after seeding"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(parsed["kind"].as_str(), Some("Namespace"));
            assert_eq!(parsed["metadata"]["name"].as_str(), Some(name));
            assert_eq!(parsed["status"]["phase"].as_str(), Some("Active"));
        }
    }

    #[tokio::test]
    async fn seed_namespaces_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        let store = make_store();
        seed_namespaces(&store).await.expect("first seed must not fail");
        seed_namespaces(&store).await.expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_rbac_creates_system_node_clusterrole() {
        // Ensures kubelet nodes using real RBAC credentials (CN=system:node:<name>,
        // O=system:nodes) get a non-empty RBAC policy on startup rather than 403.
        // The ClusterRole and ClusterRoleBinding must be stored under the same key
        // prefix that state::AppState::init() scans so the RBAC index is populated.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // ClusterRole must exist and have the expected structure.
        let cr_key = keys::group_object_key(GROUP, "clusterroles", None, "system:node");
        let cr_obj = store.get(&cr_key).await.expect("get must not fail");
        assert!(cr_obj.is_some(), "ClusterRole system:node must exist after seeding");
        let cr: serde_json::Value =
            serde_json::from_slice(&cr_obj.unwrap().value).expect("valid json");
        assert_eq!(cr["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(cr["metadata"]["name"].as_str(), Some("system:node"));
        // Must include rules for nodes, pods, events, configmaps, secrets.
        let rules = cr["rules"].as_array().expect("rules must be an array");
        assert!(!rules.is_empty(), "ClusterRole must have at least one rule");
        let resources: Vec<String> = rules.iter()
            .flat_map(|r| {
                r["resources"].as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect();
        for expected in ["nodes", "pods", "events", "configmaps", "secrets"] {
            assert!(
                resources.iter().any(|r| r == expected),
                "ClusterRole rules must cover resource '{expected}'"
            );
        }

        // ClusterRoleBinding must exist and bind system:nodes group.
        let crb_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
        let crb_obj = store.get(&crb_key).await.expect("get must not fail");
        assert!(crb_obj.is_some(), "ClusterRoleBinding system:node must exist after seeding");
        let crb: serde_json::Value =
            serde_json::from_slice(&crb_obj.unwrap().value).expect("valid json");
        assert_eq!(crb["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(crb["metadata"]["name"].as_str(), Some("system:node"));
        let subjects = crb["subjects"].as_array().expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(subjects[0]["name"].as_str(), Some("system:nodes"));
        assert_eq!(crb["roleRef"]["name"].as_str(), Some("system:node"));
        assert_eq!(crb["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn seed_rbac_is_idempotent() {
        // Unconditional puts must not fail on a second call — seed data can be overwritten.
        let store = make_store();
        seed_rbac(&store).await.expect("first seed must not fail");
        seed_rbac(&store).await.expect("second seed must not fail");
    }
}
