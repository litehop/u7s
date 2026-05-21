mod auth;
mod content_type;
mod handlers;
mod inflight;
mod keys;
mod patch;
mod proto;
mod rbac;
mod serializer;
mod state;
mod status;
mod tls;
mod types;
mod util;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use u7s_store::SqliteStore;

use auth::{AuthLayer, PeerCertificate};
use content_type::ContentTypeLayer;
use inflight::InflightLayer;
use state::AppState;
use tls::{generate_tls, load_or_generate_sa_keys, write_kubeconfig};

/// Maximum request body size in bytes. Applied as the outermost layer so
/// unauthenticated requests are rejected before auth processing, preventing
/// OOM attacks via large unauthenticated bodies. 4 MiB gives headroom above
/// etcd's 1.5 MiB object limit while staying well below OOM risk.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

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
    seed_services(&store).await?;
    seed_serviceaccounts(&store).await?;
    seed_coredns(&store).await?;

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
    let (sa_encoding_key, sa_decoding_key) =
        match load_or_generate_sa_keys(&args.sa_key, &args.sa_pub) {
            Ok(sa_keys) => {
                let enc = jsonwebtoken::EncodingKey::from_rsa_pem(&sa_keys.private_key_pem)
                    .map_err(|e| {
                        tracing::error!("failed to load SA signing key: {e}");
                        e
                    })
                    .ok();
                let dec = jsonwebtoken::DecodingKey::from_rsa_pem(&sa_keys.public_key_pem)
                    .map_err(|e| {
                        tracing::error!("failed to load SA public key: {e}");
                        e
                    })
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
    let state = AppState::new(
        Arc::clone(&store),
        sa_encoding_key,
        sa_decoding_key,
        token_map,
        server_address,
    );

    // 9a. Populate RBAC index from persisted objects before serving.
    state.init().await;

    // 10. Build axum router and attach tower layers.
    //     Order (outermost first): body_limit → inflight → auth → content_type → handler.
    //     DefaultBodyLimit must be outermost so unauthenticated requests are rejected before
    //     auth processing — this prevents OOM via large unauthenticated request bodies.
    //     4 MiB matches etcd's practical limit (~1.5 MiB) with headroom for kubectl manifests.
    let app = build_router(state.clone())
        .layer(ContentTypeLayer)
        .layer(AuthLayer::new(
            Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_decoding_key.clone(),
        ))
        .layer(InflightLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES));

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
        .route("/api", get(handlers::discovery::api_versions))
        .route("/api/v1", get(handlers::discovery::api_v1_resources))
        // Non-core group discovery
        .route("/apis", get(handlers::discovery::api_group_list))
        .route(
            "/apis/{group}/{version}",
            get(handlers::discovery::api_group_resources),
        )
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
            get(handlers::generic::list_resource).post(handlers::generic::create_resource),
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
        // Cluster-scoped status subresource — CR-aware handler falls through to
        // registry resources; generic GET/PATCH still handle non-CR resources.
        .route(
            "/apis/{group}/{version}/{resource}/{name}/status",
            get(handlers::cr::get_cr_status)
                .put(handlers::cr::put_cr_status)
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
        ("default", "00000000-0000-0000-0000-000000000001"),
        ("kube-system", "00000000-0000-0000-0000-000000000002"),
        ("kube-node-lease", "00000000-0000-0000-0000-000000000003"),
        ("kube-public", "00000000-0000-0000-0000-000000000004"),
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
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000010", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"],        "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"],         "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods/status"],  "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods/log"],     "verbs": ["get"] },
            { "apiGroups": [""], "resources": ["events"],       "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["configmaps"],   "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["secrets"],      "verbs": ["get","list","watch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csinodes"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csidrivers"], "verbs": ["get","list","watch"] }
        ]
    });
    store
        .put(&cr_key, Bytes::from(cr_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRole system:node: {e}"))?;
    tracing::info!("seeded ClusterRole: system:node");

    // ClusterRoleBinding: system:node — binds system:nodes group to the ClusterRole.
    let crb_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
    let crb_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000011", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:nodes" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node" }
    });
    store
        .put(&crb_key, Bytes::from(crb_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRoleBinding system:node: {e}"))?;
    tracing::info!("seeded ClusterRoleBinding: system:node");

    Ok(())
}

async fn seed_services(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    // default/kubernetes — reaches the API server from inside pods via
    // in-cluster DNS (kubernetes.default.svc.cluster.local:443 → 10.96.0.1).
    let k8s_key = keys::object_key("services", "default", "kubernetes");
    let k8s_body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": "00000000-0000-0000-0000-000000000020",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "component": "apiserver", "provider": "kubernetes" }
        },
        "spec": {
            "clusterIP": "10.96.0.1",
            "ports": [{ "name": "https", "port": 443, "targetPort": 6443, "protocol": "TCP" }],
            "sessionAffinity": "None",
            "type": "ClusterIP"
        }
    });
    match store
        .put(&k8s_key, Bytes::from(k8s_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Service: default/kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Service default/kubernetes: {e}")),
    }

    // kube-system/kube-dns — DNS resolver; kubelet advertises 10.96.0.10 as
    // the nameserver in /etc/resolv.conf inside every pod.
    let dns_key = keys::object_key("services", "kube-system", "kube-dns");
    let dns_body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "kube-dns",
            "namespace": "kube-system",
            "uid": "00000000-0000-0000-0000-000000000021",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "k8s-app": "kube-dns", "kubernetes.io/cluster-service": "true", "kubernetes.io/name": "CoreDNS" }
        },
        "spec": {
            "clusterIP": "10.96.0.10",
            "ports": [
                { "name": "dns", "port": 53, "targetPort": 53, "protocol": "UDP" },
                { "name": "dns-tcp", "port": 53, "targetPort": 53, "protocol": "TCP" }
            ],
            "sessionAffinity": "None",
            "type": "ClusterIP"
        }
    });
    match store
        .put(&dns_key, Bytes::from(dns_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Service: kube-system/kube-dns"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Service kube-system/kube-dns: {e}")),
    }

    Ok(())
}

async fn seed_serviceaccounts(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const NAMESPACES: &[&str] = &["default", "kube-system", "kube-node-lease", "kube-public"];
    for ns in NAMESPACES {
        let key = keys::object_key("serviceaccounts", ns, "default");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": ns
            }
        });
        match store
            .put(&key, Bytes::from(body.to_string()), Some(0))
            .await
        {
            Ok(_) => tracing::info!("seeded ServiceAccount: {ns}/default"),
            Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
            Err(e) => return Err(anyhow::anyhow!("seed ServiceAccount {ns}/default: {e}")),
        }
    }
    Ok(())
}

async fn seed_coredns(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    // kube-system/coredns Deployment — provides in-cluster DNS resolution.
    // kubelet injects 10.96.0.10 (kube-dns Service) into every pod's /etc/resolv.conf;
    // without a running CoreDNS pod behind that Service, DNS lookups fail inside pods.
    let key = keys::group_object_key("apps", "deployments", Some("kube-system"), "coredns");
    let body = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "coredns",
            "namespace": "kube-system",
            "uid": "00000000-0000-0000-0000-000000000030",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "k8s-app": "kube-dns" }
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "k8s-app": "kube-dns" } },
            "template": {
                "metadata": { "labels": { "k8s-app": "kube-dns" } },
                "spec": {
                    "containers": [{
                        "name": "coredns",
                        "image": "registry.k8s.io/coredns/coredns:v1.11.1",
                        "ports": [
                            { "containerPort": 53, "protocol": "UDP", "name": "dns" },
                            { "containerPort": 53, "protocol": "TCP", "name": "dns-tcp" }
                        ]
                    }]
                }
            }
        }
    });
    match store
        .put(&key, Bytes::from(body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Deployment: kube-system/coredns"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Deployment kube-system/coredns: {e}")),
    }

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
                Err(e) => {
                    tracing::warn!("TLS accept error: {e}");
                    return;
                }
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
    use u7s_store::{SqliteStore, Store};

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
            assert!(obj.is_some(), "namespace '{name}' must exist after seeding");
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
        seed_namespaces(&store)
            .await
            .expect("first seed must not fail");
        seed_namespaces(&store)
            .await
            .expect("second seed must not fail");
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
        assert!(
            cr_obj.is_some(),
            "ClusterRole system:node must exist after seeding"
        );
        let cr: serde_json::Value =
            serde_json::from_slice(&cr_obj.unwrap().value).expect("valid json");
        assert_eq!(cr["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(cr["metadata"]["name"].as_str(), Some("system:node"));
        // All Kubernetes objects must have a non-null creationTimestamp in metadata.
        assert!(
            !cr["metadata"]["creationTimestamp"].is_null(),
            "ClusterRole metadata must contain a non-null creationTimestamp"
        );
        // Must include rules for nodes, pods, events, configmaps, secrets, leases, and csinodes.
        // Missing csinodes causes kubelet to get 403 for CSINode PATCH/WATCH, which client-go
        // surfaces as "invalid JSON: expected value at line 1 column 1".
        let rules = cr["rules"].as_array().expect("rules must be an array");
        assert!(!rules.is_empty(), "ClusterRole must have at least one rule");
        let resources: Vec<String> = rules
            .iter()
            .flat_map(|r| {
                r["resources"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        for expected in [
            "nodes",
            "pods",
            "events",
            "configmaps",
            "secrets",
            "leases",
            "csinodes",
        ] {
            assert!(
                resources.iter().any(|r| r == expected),
                "ClusterRole rules must cover resource '{expected}'"
            );
        }

        // ClusterRoleBinding must exist and bind system:nodes group.
        let crb_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
        let crb_obj = store.get(&crb_key).await.expect("get must not fail");
        assert!(
            crb_obj.is_some(),
            "ClusterRoleBinding system:node must exist after seeding"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&crb_obj.unwrap().value).expect("valid json");
        assert_eq!(crb["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(crb["metadata"]["name"].as_str(), Some("system:node"));
        // All Kubernetes objects must have a non-null creationTimestamp in metadata.
        assert!(
            !crb["metadata"]["creationTimestamp"].is_null(),
            "ClusterRoleBinding metadata must contain a non-null creationTimestamp"
        );
        let subjects = crb["subjects"]
            .as_array()
            .expect("subjects must be an array");
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

    #[tokio::test]
    async fn seed_services_creates_kubernetes_and_kube_dns() {
        // Both Services are required for in-cluster communication:
        //   - default/kubernetes: pods reach the API server via kubernetes.default.svc.cluster.local
        //   - kube-system/kube-dns: kubelet advertises 10.96.0.10 as the nameserver in /etc/resolv.conf
        // Without them, any in-pod API call or DNS lookup fails.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store).await.expect("seed must not fail");

        // Verify default/kubernetes Service.
        let k8s_key = keys::object_key("services", "default", "kubernetes");
        let k8s_obj = store.get(&k8s_key).await.expect("get must not fail");
        assert!(
            k8s_obj.is_some(),
            "Service default/kubernetes must exist after seeding"
        );
        let k8s: serde_json::Value =
            serde_json::from_slice(&k8s_obj.unwrap().value).expect("valid json");
        assert_eq!(k8s["kind"].as_str(), Some("Service"));
        assert_eq!(k8s["metadata"]["name"].as_str(), Some("kubernetes"));
        assert_eq!(k8s["metadata"]["namespace"].as_str(), Some("default"));
        assert_eq!(k8s["spec"]["clusterIP"].as_str(), Some("10.96.0.1"));
        let k8s_ports = k8s["spec"]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(
            k8s_ports.len(),
            1,
            "kubernetes Service must have exactly one port"
        );
        assert_eq!(k8s_ports[0]["port"].as_u64(), Some(443));
        assert_eq!(k8s_ports[0]["targetPort"].as_u64(), Some(6443));
        assert_eq!(k8s_ports[0]["protocol"].as_str(), Some("TCP"));

        // Verify kube-system/kube-dns Service.
        let dns_key = keys::object_key("services", "kube-system", "kube-dns");
        let dns_obj = store.get(&dns_key).await.expect("get must not fail");
        assert!(
            dns_obj.is_some(),
            "Service kube-system/kube-dns must exist after seeding"
        );
        let dns: serde_json::Value =
            serde_json::from_slice(&dns_obj.unwrap().value).expect("valid json");
        assert_eq!(dns["kind"].as_str(), Some("Service"));
        assert_eq!(dns["metadata"]["name"].as_str(), Some("kube-dns"));
        assert_eq!(dns["metadata"]["namespace"].as_str(), Some("kube-system"));
        assert_eq!(dns["spec"]["clusterIP"].as_str(), Some("10.96.0.10"));
        let dns_ports = dns["spec"]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(
            dns_ports.len(),
            2,
            "kube-dns Service must have two ports (UDP and TCP)"
        );
        let protocols: Vec<&str> = dns_ports
            .iter()
            .filter_map(|p| p["protocol"].as_str())
            .collect();
        assert!(protocols.contains(&"UDP"), "kube-dns must have a UDP port");
        assert!(protocols.contains(&"TCP"), "kube-dns must have a TCP port");
        for port in dns_ports {
            assert_eq!(
                port["port"].as_u64(),
                Some(53),
                "kube-dns port number must be 53"
            );
        }
    }

    #[tokio::test]
    async fn seed_services_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        // This matches the startup guarantee: u7s may restart against an existing database.
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store)
            .await
            .expect("first seed must not fail");
        seed_services(&store)
            .await
            .expect("second seed must not fail");

        // Data must still be correct after two calls.
        let k8s_key = keys::object_key("services", "default", "kubernetes");
        let k8s_obj = store.get(&k8s_key).await.expect("get must not fail");
        assert!(
            k8s_obj.is_some(),
            "Service default/kubernetes must still exist"
        );
        let dns_key = keys::object_key("services", "kube-system", "kube-dns");
        let dns_obj = store.get(&dns_key).await.expect("get must not fail");
        assert!(
            dns_obj.is_some(),
            "Service kube-system/kube-dns must still exist"
        );
    }

    #[tokio::test]
    async fn seed_coredns_creates_deployment_in_kube_system() {
        // CoreDNS Deployment must exist after seeding so in-cluster DNS resolution works.
        // Without this Deployment, pods get an empty DNS response for service names
        // because no pod backs the kube-dns Service (10.96.0.10).
        let store = make_store();
        seed_coredns(&store).await.expect("seed must not fail");

        let key = keys::group_object_key("apps", "deployments", Some("kube-system"), "coredns");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "Deployment kube-system/coredns must exist after seeding"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("Deployment"));
        assert_eq!(parsed["apiVersion"].as_str(), Some("apps/v1"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("coredns"));
        assert_eq!(
            parsed["metadata"]["namespace"].as_str(),
            Some("kube-system")
        );
        // Selector must match kube-dns label so kubelet pod assignment reaches CoreDNS pods.
        assert_eq!(
            parsed["spec"]["selector"]["matchLabels"]["k8s-app"].as_str(),
            Some("kube-dns"),
            "selector must match k8s-app=kube-dns so the kube-dns Service selects CoreDNS pods"
        );
        // Container must use the expected image.
        let containers = parsed["spec"]["template"]["spec"]["containers"]
            .as_array()
            .expect("containers must be an array");
        assert_eq!(containers.len(), 1, "must have exactly one container");
        assert_eq!(
            containers[0]["image"].as_str(),
            Some("registry.k8s.io/coredns/coredns:v1.11.1"),
            "image must be pinned to a known CoreDNS version"
        );
        // DNS ports must be present.
        let ports = containers[0]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert_eq!(ports.len(), 2, "must expose both UDP and TCP port 53");
        let protocols: Vec<&str> = ports
            .iter()
            .filter_map(|p| p["protocol"].as_str())
            .collect();
        assert!(
            protocols.contains(&"UDP"),
            "CoreDNS must expose UDP port 53 for DNS queries"
        );
        assert!(
            protocols.contains(&"TCP"),
            "CoreDNS must expose TCP port 53 for large DNS responses"
        );
    }

    #[tokio::test]
    async fn seed_coredns_is_idempotent() {
        // A second call must not error — startup can happen against an existing database.
        // Without idempotency, every restart would fail after the first boot.
        let store = make_store();
        seed_coredns(&store)
            .await
            .expect("first seed must not fail");
        seed_coredns(&store)
            .await
            .expect("second seed must not fail — seed must be idempotent");

        // Data must still be correct after two calls.
        let key = keys::group_object_key("apps", "deployments", Some("kube-system"), "coredns");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "Deployment kube-system/coredns must still exist after second seed call"
        );
    }

    #[tokio::test]
    async fn seed_serviceaccounts_creates_default_sa_in_each_namespace() {
        // The default ServiceAccount must exist in every seeded namespace so that
        // pods can obtain a projected SA token via TokenRequest. Without it,
        // the TokenRequest handler returns 404 and in-cluster authentication fails.
        let store = make_store();
        seed_serviceaccounts(&store)
            .await
            .expect("seed must not fail");

        for ns in ["default", "kube-system", "kube-node-lease", "kube-public"] {
            let key = keys::object_key("serviceaccounts", ns, "default");
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "ServiceAccount {ns}/default must exist after seeding"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(parsed["kind"].as_str(), Some("ServiceAccount"));
            assert_eq!(parsed["metadata"]["name"].as_str(), Some("default"));
            assert_eq!(parsed["metadata"]["namespace"].as_str(), Some(ns));
        }
    }

    #[tokio::test]
    async fn seed_serviceaccounts_is_idempotent() {
        // A second call must not error — CAS rv=0 returns AlreadyExists which is silently ignored.
        let store = make_store();
        seed_serviceaccounts(&store)
            .await
            .expect("first seed must not fail");
        seed_serviceaccounts(&store)
            .await
            .expect("second seed must not fail");
    }

    /// The body size limit must be at least 1 MiB (to accommodate real kubectl
    /// manifests and ConfigMaps) and at most 8 MiB (to prevent OOM from a single
    /// large unauthenticated request). The current limit is 4 MiB.
    ///
    /// Without a body limit, an unauthenticated attacker can POST an arbitrarily
    /// large body to any endpoint and cause the server to OOM before auth runs.
    #[test]
    fn body_limit_is_within_safe_range() {
        // 1 MiB minimum: kubectl configmaps can be up to ~1 MiB in practice.
        // 8 MiB maximum: etcd's default value limit; no valid object exceeds this.
        const MIN_SAFE: usize = 1 * 1024 * 1024;
        const MAX_SAFE: usize = 8 * 1024 * 1024;
        assert!(
            MAX_BODY_BYTES >= MIN_SAFE,
            "body limit {} is too small; kubectl manifests can be up to 1 MiB",
            MAX_BODY_BYTES
        );
        assert!(
            MAX_BODY_BYTES <= MAX_SAFE,
            "body limit {} is too large; risk of OOM from a single request",
            MAX_BODY_BYTES
        );
    }
}
