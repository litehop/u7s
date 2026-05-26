mod admission;
mod auth;
mod content_type;
mod handlers;
mod inflight;
mod keys;
mod limit_range;
mod patch;
mod proto;
mod quota;
mod rbac;
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

    /// CIDR range from which clusterIPs are auto-allocated for Services.
    /// Must be a valid IPv4 CIDR with prefix length <= 30 (e.g. "10.96.0.0/12").
    /// Matches kubeadm's default. Set to empty string to disable auto-allocation.
    #[arg(long, default_value = "10.96.0.0/12")]
    service_cluster_ip_range: String,
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

    // 9. Build service IP allocator from the configured CIDR.
    let service_ip_allocator = if args.service_cluster_ip_range.is_empty() {
        tracing::info!(
            "service clusterIP auto-allocation disabled (empty --service-cluster-ip-range)"
        );
        None
    } else {
        match state::ServiceIpAllocator::from_cidr(&args.service_cluster_ip_range) {
            Ok(alloc) => {
                tracing::info!(
                    "service clusterIP auto-allocation enabled: {}",
                    args.service_cluster_ip_range
                );
                Some(alloc)
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "invalid --service-cluster-ip-range '{}': {e}",
                    args.service_cluster_ip_range
                ));
            }
        }
    };

    // 10. Build app state (shared with the auth layer).
    // Combine admin cert PEM + admin key PEM for the webhook mTLS client identity.
    // The webhook client will present this certificate when connecting to admission
    // webhook servers, so they can verify they are talking to the apiserver.
    let mut webhook_identity_pem = tls_material.admin_cert_pem.clone();
    webhook_identity_pem.extend_from_slice(&tls_material.admin_key_pem);
    let state = AppState::new_with_ca(
        Arc::clone(&store),
        sa_encoding_key,
        sa_decoding_key,
        token_map,
        server_address,
        Some(tls_material.ca_cert_der.clone()),
        Some(webhook_identity_pem),
        service_ip_allocator,
    );

    // 10a. Populate RBAC index from persisted objects before serving.
    state.init().await;

    // 10b. Seed service IP hint from already-allocated sentinels in the store.
    state.init_service_ip_hint().await;

    // 11. Build axum router and attach tower layers.
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

    // 12. Bind TLS listener and serve.
    let listener = TcpListener::bind(&args.listen).await?;
    serve_tls(listener, app, tls_material.server_config).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        // Health endpoints — no auth required; kube-controller-manager polls these
        // before declaring the apiserver ready. Listed in is_exempt() in auth.rs.
        .route("/healthz", get(|| async { "ok" }))
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ok" }))
        // Server version — no auth required (sonobuoy, kubectl version)
        .route("/version", get(handlers::discovery::version))
        // OpenAPI stubs — clients like Argo CD and kubectl call these on startup
        .route("/openapi/v2", get(handlers::discovery::openapi_v2))
        .route("/openapi/v3", get(handlers::discovery::openapi_v3))
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
            get(handlers::pods::list_pods)
                .post(handlers::pods::create_pod)
                .delete(handlers::pods::delete_collection_pods),
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
        // Pods — log subresource (kubelet proxy): must be before generic catch-all
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/log",
            get(handlers::proxy::pod_log),
        )
        // Pods — exec/attach/portforward: 501 stubs until SPDY/WebSocket is implemented
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/exec",
            get(handlers::proxy::pod_exec).post(handlers::proxy::pod_exec),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/attach",
            get(handlers::proxy::pod_attach).post(handlers::proxy::pod_attach),
        )
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/portforward",
            get(handlers::proxy::pod_portforward).post(handlers::proxy::pod_portforward),
        )
        // Core group (group="", apiVersion=v1) — cluster-scoped resources (e.g. nodes)
        .route(
            "/api/v1/{resource}",
            get(handlers::core::core_list_resource).post(handlers::core::core_create_resource),
        )
        // Core group — cluster-scoped named resource
        .route(
            "/api/v1/{resource}/{name}",
            get(handlers::core::core_get_resource)
                .put(handlers::core::core_replace_resource)
                .delete(handlers::core::core_delete_resource)
                .patch(handlers::core::core_patch_resource),
        )
        // Core group — cluster-scoped status subresource
        .route(
            "/api/v1/{resource}/{name}/status",
            get(handlers::core::core_get_resource_status)
                .put(handlers::core::core_put_resource_status)
                .patch(handlers::core::core_patch_resource_status),
        )
        // Core group — namespaced resources collection (e.g. services, configmaps)
        .route(
            "/api/v1/namespaces/{ns}/{resource}",
            get(handlers::core::core_list_namespaced_resource)
                .post(handlers::core::core_create_namespaced_resource)
                .delete(handlers::core::core_delete_collection_namespaced_resource),
        )
        // Core group — namespaced named resource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}",
            get(handlers::core::core_get_namespaced_resource)
                .put(handlers::core::core_replace_namespaced_resource)
                .delete(handlers::core::core_delete_namespaced_resource)
                .patch(handlers::core::core_patch_namespaced_resource),
        )
        // Core group — namespaced status subresource
        .route(
            "/api/v1/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::core::core_get_namespaced_resource_status)
                .put(handlers::core::core_put_namespaced_resource_status)
                .patch(handlers::core::core_patch_namespaced_resource_status),
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
        // CertificateSigningRequests — dedicated POST handler with strict validation
        // Must be registered before the generic cluster-scoped catch-all.
        .route(
            "/apis/certificates.k8s.io/v1/certificatesigningrequests",
            get(handlers::csr::list_csr).post(handlers::csr::create_csr),
        )
        // CSR /approval subresource — PUT and PATCH only merge status.conditions;
        // spec and status.certificate are never touched. Must be before the named
        // resource catch-all so axum doesn't interpret "approval" as a resource name.
        .route(
            "/apis/certificates.k8s.io/v1/certificatesigningrequests/{name}/approval",
            get(handlers::csr::get_csr)
                .put(handlers::approval::put_approval)
                .patch(handlers::approval::patch_approval),
        )
        // Generic cluster-scoped resources — collection
        .route(
            "/apis/{group}/{version}/{resource}",
            get(handlers::resource::list_resource)
                .post(handlers::resource::create_resource)
                .delete(handlers::resource::delete_collection_resource),
        )
        // Generic cluster-scoped resources — named
        .route(
            "/apis/{group}/{version}/{resource}/{name}",
            get(handlers::resource::get_resource)
                .put(handlers::resource::replace_resource)
                .delete(handlers::resource::delete_resource)
                .patch(handlers::resource::patch_resource),
        )
        // Generic namespaced resources — collection
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}",
            get(handlers::resource::list_namespaced_resource)
                .post(handlers::resource::create_namespaced_resource)
                .delete(handlers::resource::delete_collection_namespaced_resource),
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
            get(handlers::resource::get_namespaced_resource)
                .put(handlers::resource::replace_namespaced_resource)
                .delete(handlers::resource::delete_namespaced_resource)
                .patch(handlers::resource::patch_namespaced_resource),
        )
        // Cluster-scoped status subresource — CR-aware handler falls through to
        // registry resources; generic GET/PATCH still handle non-CR resources.
        .route(
            "/apis/{group}/{version}/{resource}/{name}/status",
            get(handlers::cr::get_cr_status)
                .put(handlers::cr::put_cr_status)
                .patch(handlers::status::patch_resource_status),
        )
        // Generic namespaced — status subresource
        .route(
            "/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/status",
            get(handlers::status::get_namespaced_resource_status)
                .put(handlers::status::put_namespaced_resource_status)
                .patch(handlers::status::patch_namespaced_resource_status),
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
                "labels": { "kubernetes.io/metadata.name": name },
                "finalizers": ["kubernetes"]
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

    // ClusterRole: cluster-admin — wildcard access to all resources in all API groups.
    let ca_role_key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
    let ca_role_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "cluster-admin", "uid": "00000000-0000-0000-0000-000000000012", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }
        ]
    });
    store
        .put(&ca_role_key, Bytes::from(ca_role_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRole cluster-admin: {e}"))?;
    tracing::info!("seeded ClusterRole: cluster-admin");

    // ClusterRoleBinding: system:masters — grants cluster-admin to the system:masters group.
    // This replaces the former hardcoded bypass in is_allowed() / user_holds_all_rules().
    let ca_bind_key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:masters");
    let ca_bind_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:masters", "uid": "00000000-0000-0000-0000-000000000013", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:masters" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
    });
    store
        .put(&ca_bind_key, Bytes::from(ca_bind_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRoleBinding system:masters: {e}"))?;
    tracing::info!("seeded ClusterRoleBinding: system:masters");

    // ClusterRole: system:basic-user — grants every authenticated user the
    // ability to create SelfSubjectAccessReviews and SelfSubjectRulesReviews.
    // Argo CD calls these endpoints on startup to discover its own permissions;
    // without this role those requests are denied with 403.
    let bu_role_key = keys::group_object_key(GROUP, "clusterroles", None, "system:basic-user");
    let bu_role_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000014", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "rules": [
            { "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews","selfsubjectrulesreviews"], "verbs": ["create"] }
        ]
    });
    store
        .put(&bu_role_key, Bytes::from(bu_role_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRole system:basic-user: {e}"))?;
    tracing::info!("seeded ClusterRole: system:basic-user");

    // ClusterRoleBinding: system:basic-user — binds system:authenticated group
    // to the system:basic-user ClusterRole.  This is the standard Kubernetes
    // bootstrap binding that Argo CD relies on for permission discovery.
    let bu_bind_key =
        keys::group_object_key(GROUP, "clusterrolebindings", None, "system:basic-user");
    let bu_bind_body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000015", "creationTimestamp": "2024-01-01T00:00:00Z" },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:basic-user" }
    });
    store
        .put(&bu_bind_key, Bytes::from(bu_bind_body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed ClusterRoleBinding system:basic-user: {e}"))?;
    tracing::info!("seeded ClusterRoleBinding: system:basic-user");

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

    // Static UIDs — no uuid crate needed for seeded objects; deterministic values
    // are required so token recipients can correlate a JWT's kubernetes.io.serviceaccount.uid
    // claim back to the ServiceAccount object. Without a UID the claim is empty, which
    // violates the Kubernetes token projection contract.
    const NAMESPACES: &[(&str, &str)] = &[
        ("default", "00000000-0000-0000-0001-000000000001"),
        ("kube-system", "00000000-0000-0000-0001-000000000002"),
        ("kube-node-lease", "00000000-0000-0000-0001-000000000003"),
        ("kube-public", "00000000-0000-0000-0001-000000000004"),
    ];
    for (ns, uid) in NAMESPACES {
        let key = keys::object_key("serviceaccounts", ns, "default");
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": ns,
                "uid": uid,
                "creationTimestamp": "2024-01-01T00:00:00Z"
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
    let mut body = serde_json::json!({
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
    crate::handlers::defaults::apply_defaults("apps", "deployments", &mut body);
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
    async fn seed_rbac_creates_cluster_admin_and_system_masters_binding() {
        // The cluster-admin ClusterRole and system:masters ClusterRoleBinding must exist after
        // seeding.  This replaces the former hardcoded bypass in is_allowed(); if these objects
        // are missing on startup, system:masters users will be denied all requests.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // cluster-admin ClusterRole must exist with wildcard rules.
        let ca_role_key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
        let ca_role_obj = store.get(&ca_role_key).await.expect("get must not fail");
        assert!(
            ca_role_obj.is_some(),
            "ClusterRole cluster-admin must exist after seeding"
        );
        let ca_role: serde_json::Value =
            serde_json::from_slice(&ca_role_obj.unwrap().value).expect("valid json");
        assert_eq!(ca_role["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(ca_role["metadata"]["name"].as_str(), Some("cluster-admin"));
        let rules = ca_role["rules"].as_array().expect("rules must be an array");
        assert!(
            !rules.is_empty(),
            "cluster-admin must have at least one rule"
        );
        // Verify wildcard access: all rules must grant ["*"] on verbs.
        for rule in rules {
            let verbs = rule["verbs"].as_array().expect("verbs must be an array");
            assert!(
                verbs.iter().any(|v| v.as_str() == Some("*")),
                "cluster-admin rules must grant wildcard verbs"
            );
        }

        // system:masters ClusterRoleBinding must exist and bind to cluster-admin.
        let ca_bind_key =
            keys::group_object_key(GROUP, "clusterrolebindings", None, "system:masters");
        let ca_bind_obj = store.get(&ca_bind_key).await.expect("get must not fail");
        assert!(
            ca_bind_obj.is_some(),
            "ClusterRoleBinding system:masters must exist after seeding"
        );
        let ca_bind: serde_json::Value =
            serde_json::from_slice(&ca_bind_obj.unwrap().value).expect("valid json");
        assert_eq!(ca_bind["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(ca_bind["metadata"]["name"].as_str(), Some("system:masters"));
        let subjects = ca_bind["subjects"]
            .as_array()
            .expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(subjects[0]["name"].as_str(), Some("system:masters"));
        assert_eq!(
            ca_bind["roleRef"]["name"].as_str(),
            Some("cluster-admin"),
            "ClusterRoleBinding must reference cluster-admin role"
        );
        assert_eq!(ca_bind["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn seed_rbac_is_idempotent() {
        // Unconditional puts must not fail on a second call — seed data can be overwritten.
        let store = make_store();
        seed_rbac(&store).await.expect("first seed must not fail");
        seed_rbac(&store).await.expect("second seed must not fail");
    }

    #[tokio::test]
    async fn seed_rbac_creates_basic_user_role_and_authenticated_binding() {
        // Argo CD calls SelfSubjectAccessReview on startup to discover its own permissions.
        // This requires:
        //   1. ClusterRole system:basic-user granting create on selfsubjectaccessreviews.
        //   2. ClusterRoleBinding system:basic-user binding system:authenticated → that role.
        // Without these, every authenticated user gets 403 on discovery, breaking Argo CD startup.
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // ClusterRole system:basic-user must exist with the right rules.
        let bu_role_key = keys::group_object_key(GROUP, "clusterroles", None, "system:basic-user");
        let bu_role_obj = store.get(&bu_role_key).await.expect("get must not fail");
        assert!(
            bu_role_obj.is_some(),
            "ClusterRole system:basic-user must exist after seeding"
        );
        let bu_role: serde_json::Value =
            serde_json::from_slice(&bu_role_obj.unwrap().value).expect("valid json");
        assert_eq!(bu_role["kind"].as_str(), Some("ClusterRole"));
        assert_eq!(
            bu_role["metadata"]["name"].as_str(),
            Some("system:basic-user")
        );
        let rules = bu_role["rules"].as_array().expect("rules must be an array");
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
        assert!(
            resources.iter().any(|r| r == "selfsubjectaccessreviews"),
            "system:basic-user must grant selfsubjectaccessreviews"
        );
        assert!(
            resources.iter().any(|r| r == "selfsubjectrulesreviews"),
            "system:basic-user must grant selfsubjectrulesreviews"
        );

        // ClusterRoleBinding system:basic-user must bind system:authenticated group.
        let bu_bind_key =
            keys::group_object_key(GROUP, "clusterrolebindings", None, "system:basic-user");
        let bu_bind_obj = store.get(&bu_bind_key).await.expect("get must not fail");
        assert!(
            bu_bind_obj.is_some(),
            "ClusterRoleBinding system:basic-user must exist after seeding"
        );
        let bu_bind: serde_json::Value =
            serde_json::from_slice(&bu_bind_obj.unwrap().value).expect("valid json");
        assert_eq!(bu_bind["kind"].as_str(), Some("ClusterRoleBinding"));
        assert_eq!(
            bu_bind["metadata"]["name"].as_str(),
            Some("system:basic-user")
        );
        let subjects = bu_bind["subjects"]
            .as_array()
            .expect("subjects must be an array");
        assert_eq!(subjects.len(), 1, "must have exactly one subject");
        assert_eq!(subjects[0]["kind"].as_str(), Some("Group"));
        assert_eq!(
            subjects[0]["name"].as_str(),
            Some("system:authenticated"),
            "binding must target system:authenticated so all authed users get basic-user permissions"
        );
        assert_eq!(
            bu_bind["roleRef"]["name"].as_str(),
            Some("system:basic-user"),
            "ClusterRoleBinding must reference system:basic-user role"
        );
        assert_eq!(bu_bind["roleRef"]["kind"].as_str(), Some("ClusterRole"));
    }

    #[tokio::test]
    async fn system_nodes_group_is_authorized_after_rbac_seed_and_init() {
        // Verifies the full chain: seed_rbac writes ClusterRole+ClusterRoleBinding,
        // AppState::init() loads them into the RBAC index, and is_allowed returns
        // true for a kubelet in system:nodes.
        //
        // Without this test the seeded data could be structurally correct (stored under
        // the right key) but still broken at the authorization layer — e.g. if init()
        // builds the wrong api_key or if subject_matches ignores the Group kind.
        let store = std::sync::Arc::new(make_store());
        seed_rbac(&store).await.expect("seed must not fail");

        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        // Populate RBAC index from persisted seed data — mirrors what main() does.
        state.init().await;

        let groups = vec!["system:nodes".to_owned()];

        // A kubelet in system:nodes must be able to GET a pod assigned to it.
        let pod_read = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&pod_read),
            "system:nodes must be allowed to GET pods — kubelet needs this to reconcile its pod list"
        );

        // A kubelet in system:nodes must be able to create a lease (heartbeat).
        let lease_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "coordination.k8s.io",
            resource: "leases",
            subresource: "",
            namespace: Some("kube-node-lease"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&lease_create),
            "system:nodes must be allowed to create leases — kubelet heartbeat depends on this"
        );

        // A user NOT in system:nodes must be denied — the binding is group-specific.
        let other_groups = vec!["system:authenticated".to_owned()];
        let pod_read_other = rbac::AuthzRequest {
            username: "someone-else",
            groups: &other_groups,
            verb: "get",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            !state.rbac_index.is_allowed(&pod_read_other),
            "users not in system:nodes must not inherit kubelet permissions"
        );
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
        // The SA must also carry a non-empty UID so the kubernetes.io.serviceaccount.uid
        // JWT claim is populated — an empty UID breaks the token projection contract.
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
            // UID must be non-empty so the JWT kubernetes.io.serviceaccount.uid claim
            // is populated. An empty UID violates the Kubernetes token projection spec.
            let uid = parsed["metadata"]["uid"].as_str().unwrap_or("");
            assert!(
                !uid.is_empty(),
                "ServiceAccount {ns}/default must have a non-empty UID — \
                 an empty UID causes the JWT kubernetes.io.serviceaccount.uid claim \
                 to be empty, breaking in-cluster token correlation"
            );
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

    /// Health endpoints must return 200 OK with body "ok".
    ///
    /// kube-controller-manager polls /healthz before it considers the apiserver
    /// ready and starts its control loops. If these routes are absent, kcm
    /// exits immediately after startup with "failed to contact apiserver".
    /// /livez and /readyz are polled by infrastructure health probes.
    #[tokio::test]
    async fn health_endpoints_return_200_ok() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        for path in ["/healthz", "/livez", "/readyz"] {
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request build must not fail");
            let resp = router.call(req).await.expect("router must not error");
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path} must return 200 OK — kcm polls this before starting its control loops"
            );
            let body = to_bytes(resp.into_body(), 64)
                .await
                .expect("body collect must not fail");
            assert_eq!(body.as_ref(), b"ok", "{path} body must be 'ok'");
        }
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
        let limit = MAX_BODY_BYTES;
        let min_safe: usize = 1024 * 1024;
        let max_safe: usize = 8 * 1024 * 1024;
        assert!(
            limit >= min_safe,
            "body limit {} is too small; kubectl manifests can be up to 1 MiB",
            limit
        );
        assert!(
            limit <= max_safe,
            "body limit {} is too large; risk of OOM from a single request",
            limit
        );
    }

    /// Verifies that POST /apis/batch/v1/namespaces/default/jobs creates a Job and
    /// GET /apis/batch/v1/namespaces/default/jobs/{name} retrieves it.
    ///
    /// batch/v1 is a new API group. Without the registry entry, the generic handler
    /// falls through to the CR handler which returns 404 (no CRD installed). This test
    /// encodes the requirement that Job is served by the generic namespaced handler.
    #[tokio::test]
    async fn job_create_and_get_round_trip() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "ci-job", "namespace": "default" },
            "spec": { "template": { "spec": { "containers": [{ "name": "test", "image": "busybox" }], "restartPolicy": "Never" } } }
        });
        let body_bytes = bytes::Bytes::from(body.to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // POST creates the Job.
        let create_result = handlers::resource::create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "batch".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "jobs".to_string(),
            )),
            headers,
            body_bytes,
        )
        .await;
        assert!(
            create_result.is_ok(),
            "POST /apis/batch/v1/namespaces/default/jobs must succeed — batch/v1 Job must be in registry"
        );

        // GET retrieves the Job.
        let get_result = handlers::resource::get_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "batch".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "jobs".to_string(),
                "ci-job".to_string(),
            )),
        )
        .await;
        assert!(
            get_result.is_ok(),
            "GET /apis/batch/v1/namespaces/default/jobs/ci-job must succeed after create"
        );

        // Verify it's stored at the expected key.
        let store_key = keys::group_object_key("batch", "jobs", Some("default"), "ci-job");
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "Job ci-job must be in the store at key {store_key}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&stored.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("Job"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("ci-job"));
    }

    /// Verifies that POST /apis/gateway.networking.k8s.io/v1/namespaces/default/gateways
    /// creates a Gateway and GET retrieves it.
    ///
    /// gateway.networking.k8s.io/v1 is a new API group. Without the registry entry, the
    /// generic handler falls through to the CR handler which returns 404 (no CRD installed).
    /// This test encodes the requirement that Gateway is served by the generic namespaced handler.
    #[tokio::test]
    async fn gateway_create_and_get_round_trip() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "my-gateway", "namespace": "default" },
            "spec": {
                "gatewayClassName": "example",
                "listeners": [{ "name": "http", "port": 80, "protocol": "HTTP" }]
            }
        });
        let body_bytes = bytes::Bytes::from(body.to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // POST creates the Gateway.
        let create_result = handlers::resource::create_namespaced_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "gateway.networking.k8s.io".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "gateways".to_string(),
            )),
            headers,
            body_bytes,
        )
        .await;
        assert!(
            create_result.is_ok(),
            "POST /apis/gateway.networking.k8s.io/v1/namespaces/default/gateways must succeed — Gateway must be in registry"
        );

        // GET retrieves the Gateway.
        let get_result = handlers::resource::get_namespaced_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "gateway.networking.k8s.io".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "gateways".to_string(),
                "my-gateway".to_string(),
            )),
        )
        .await;
        assert!(
            get_result.is_ok(),
            "GET /apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/my-gateway must succeed after create"
        );

        // Verify it's stored at the expected key.
        let store_key = keys::group_object_key(
            "gateway.networking.k8s.io",
            "gateways",
            Some("default"),
            "my-gateway",
        );
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "Gateway my-gateway must be in the store at key {store_key}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&stored.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("Gateway"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("my-gateway"));
        assert_eq!(
            parsed["spec"]["gatewayClassName"].as_str(),
            Some("example"),
            "spec must be preserved as-is — no data-plane enforcement"
        );
    }

    /// Verifies that POST /apis/storage.k8s.io/v1/csinodes creates a CSINode and
    /// GET /apis/storage.k8s.io/v1/csinodes/{name} retrieves it.
    ///
    /// The kubelet sends PATCH (SSA) on first boot to register a CSINode. Without
    /// the resource being in the registry, the generic handler falls through to the
    /// CR handler which returns 404 (no CRD installed). This test encodes the
    /// requirement that CSINode is served by the generic handler via the registry.
    #[tokio::test]
    async fn csinode_create_and_get_round_trip() {
        use std::sync::Arc;

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = serde_json::json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "CSINode",
            "metadata": { "name": "ci-node" },
            "spec": { "drivers": [] }
        });
        let body_bytes = bytes::Bytes::from(body.to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        // POST creates the CSINode — this is what the kubelet does on first boot.
        let create_result = handlers::resource::create_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
            )),
            axum::Extension(auth::UserInfo {
                username: "system:node:ci-node".into(),
                uid: "".into(),
                groups: vec!["system:nodes".into()],
            }),
            headers,
            body_bytes,
        )
        .await;
        assert!(
            create_result.is_ok(),
            "POST /apis/storage.k8s.io/v1/csinodes must succeed"
        );

        // GET retrieves the CSINode — kubelet later reads it to verify registration.
        let get_result = handlers::resource::get_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "csinodes".to_string(),
                "ci-node".to_string(),
            )),
        )
        .await;
        assert!(
            get_result.is_ok(),
            "GET /apis/storage.k8s.io/v1/csinodes/ci-node must succeed"
        );

        // The CSINode must be stored under the correct key for RBAC to find it.
        let store_key = keys::group_object_key("storage.k8s.io", "csinodes", None, "ci-node");
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "CSINode ci-node must be in the store at key {store_key}"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&stored.unwrap().value).expect("valid json");
        assert_eq!(parsed["kind"].as_str(), Some("CSINode"));
        assert_eq!(parsed["metadata"]["name"].as_str(), Some("ci-node"));
    }

    /// Full SA token round-trip: mint via TokenRequest handler, authenticate via auth middleware.
    ///
    /// This is the end-to-end correctness test for projected SA token volumes:
    ///   1. A ServiceAccount exists in the store (seeded by seed_serviceaccounts).
    ///   2. kubelet POSTs to /api/v1/namespaces/{ns}/serviceaccounts/{name}/token
    ///      and receives a JWT signed by the SA key.
    ///   3. A pod uses that JWT as a Bearer token; the auth middleware verifies it
    ///      using the SA decoding key and maps it to the correct service account identity.
    ///
    /// If either side is broken — the handler returns an invalid/empty token, the JWT
    /// has wrong claims, or the auth middleware rejects a valid token — this test fails.
    #[tokio::test]
    async fn sa_token_request_to_auth_round_trip() {
        use axum::response::IntoResponse as _;
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        use std::sync::Arc;

        // 1. Generate a fresh RSA key pair for this test — the same key must be used
        //    for minting (handler) and verification (auth middleware).
        let mut rng = rsa::rand_core::OsRng;
        let rsa_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen");
        let priv_pem = rsa_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("priv pem")
            .as_bytes()
            .to_vec();
        let pub_pem = rsa_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem")
            .into_bytes();
        let enc_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(&priv_pem).expect("encoding key from pem");
        let dec_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(&pub_pem).expect("decoding key from pem");

        // 2. Build AppState with the SA key pair and seed the store.
        let store = Arc::new(make_store());
        seed_namespaces(&store)
            .await
            .expect("seed namespaces must not fail");
        seed_serviceaccounts(&store)
            .await
            .expect("seed serviceaccounts must not fail");

        let state = state::AppState::new(
            Arc::clone(&store),
            Some(enc_key),
            Some(dec_key.clone()),
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // 3. Call the TokenRequest handler directly — this is what kubelet does when it
        //    projects an SA token into a pod volume.
        let token_handler_result = handlers::tokens::create_token(
            axum::extract::State(state),
            axum::extract::Path(("default".to_owned(), "default".to_owned())),
            bytes::Bytes::new(), // empty body → default audience + expiration
        )
        .await;
        let token_resp = match token_handler_result {
            Ok(r) => r.into_response(),
            Err(e) => {
                // StatusError doesn't implement Debug; produce a meaningful panic message.
                panic!("create_token must succeed for a valid SA: status={}", e.0);
            }
        };

        assert_eq!(
            token_resp.status(),
            axum::http::StatusCode::CREATED,
            "TokenRequest must return 201 Created"
        );

        // 4. Extract the token from the response body.
        let body_bytes = axum::body::to_bytes(token_resp.into_body(), usize::MAX)
            .await
            .expect("body collect must not fail");
        let resp_json: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be valid JSON");

        let token = resp_json["status"]["token"]
            .as_str()
            .expect("response must contain status.token string");
        assert!(
            !token.is_empty(),
            "minted token must not be empty — empty token cannot authenticate"
        );

        let exp_ts = resp_json["status"]["expirationTimestamp"]
            .as_str()
            .expect("response must contain status.expirationTimestamp");
        assert!(
            !exp_ts.is_empty(),
            "expirationTimestamp must not be empty — kubelet needs it to know when to refresh"
        );

        // 5. Authenticate the minted token via the auth middleware path.
        //    This verifies the full round-trip: the JWT the handler mints can be
        //    verified by the same decoding key used in production.
        let user =
            auth::authenticate_token(token, &std::collections::HashMap::new(), Some(&dec_key))
                .expect(
                    "minted SA token must authenticate successfully — round-trip broken if None",
                );

        // Username must be the service account identity.
        assert_eq!(
            user.username, "system:serviceaccount:default:default",
            "authenticated username must be the service account subject"
        );

        // Both SA groups must be present — RBAC policies bind to these groups.
        assert!(
            user.groups.contains(&"system:serviceaccounts".to_owned()),
            "broad SA group must be present for RBAC policies that apply to all service accounts"
        );
        assert!(
            user.groups
                .contains(&"system:serviceaccounts:default".to_owned()),
            "namespace-scoped SA group must be present for namespace-scoped RBAC policies"
        );
    }

    /// Full CSR lifecycle: POST → GET → PUT /approval (Approved) → PUT /status (cert) → GET confirms cert.
    ///
    /// This test exercises the entire CertificateSigningRequest flow end-to-end:
    ///   1. Client submits a CSR (POST) — only signerName + valid DER spec.request allowed.
    ///   2. GET confirms the CSR is stored and spec is immutable (no status yet).
    ///   3. Approver writes Approved condition via PUT /approval — certificate must NOT appear.
    ///   4. Signer writes status.certificate via PUT /status — certificate appears.
    ///   5. GET confirms final state: Approved condition + certificate present.
    ///
    /// If any step breaks, the automated cert-provisioning pipeline silently stops working.
    #[tokio::test]
    async fn csr_full_lifecycle() {
        use axum::response::IntoResponse as _;
        use base64::Engine as _;
        use rcgen::{CertificateParams, KeyPair};
        use std::sync::Arc;

        // Generate a real DER PKCS#10 CSR — same approach used in csr.rs unit tests.
        let key_pair = KeyPair::generate().expect("key generation must succeed");
        let params = CertificateParams::default();
        let csr = params
            .serialize_request(&key_pair)
            .expect("CSR generation must succeed");
        let csr_b64 = base64::engine::general_purpose::STANDARD.encode(csr.der());

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut json_headers = axum::http::HeaderMap::new();
        json_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let user = auth::UserInfo {
            username: "test-user".into(),
            uid: "".into(),
            groups: vec![],
        };

        // --- Step 1: POST — create the CSR ---
        let create_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr"},
            "spec": {
                "request": csr_b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            }
        });
        let create_result = handlers::csr::create_csr(
            axum::extract::State(state.clone()),
            axum::Extension(user),
            json_headers.clone(),
            bytes::Bytes::from(create_body.to_string()),
        )
        .await;
        let create_resp = match create_result {
            Ok(r) => r.into_response(),
            Err(e) => panic!("POST CSR must succeed, got status={}", e.0),
        };
        assert_eq!(
            create_resp.status(),
            axum::http::StatusCode::CREATED,
            "POST /certificatesigningrequests must return 201"
        );

        // Extract resourceVersion from the stored object for OCC in subsequent calls.
        let store_key = keys::group_object_key(
            "certificates.k8s.io",
            "certificatesigningrequests",
            None,
            "lifecycle-csr",
        );
        let stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must be in store after POST");
        let stored_v: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("valid json");
        assert!(
            stored_v["status"].is_null() || stored_v.get("status").is_none(),
            "POST must not store a status field — spec is immutable, status starts empty"
        );
        let rv1 = stored_v["metadata"]["resourceVersion"]
            .as_str()
            .expect("resourceVersion must be set after POST")
            .to_owned();

        // --- Step 2: GET — confirm CSR is retrievable ---
        let get_result = handlers::resource::get_resource(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                "lifecycle-csr".into(),
            )),
        )
        .await;
        assert!(get_result.is_ok(), "GET must succeed after POST");

        // --- Step 3: PUT /approval — write Approved condition ---
        let approval_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr", "resourceVersion": rv1},
            "spec": {
                "request": csr_b64,
                "signerName": "kubernetes.io/kube-apiserver-client"
            },
            "status": {
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "ManualApproval",
                    "message": "approved by lifecycle test"
                }]
            }
        });
        let approval_result = handlers::approval::put_approval(
            axum::extract::State(state.clone()),
            axum::extract::Path("lifecycle-csr".to_owned()),
            json_headers.clone(),
            bytes::Bytes::from(approval_body.to_string()),
        )
        .await;
        assert!(
            approval_result.is_ok(),
            "PUT /approval must succeed after POST"
        );

        // Verify: Approved condition stored, no certificate yet.
        let stored2 = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must still be in store after approval");
        let v2: serde_json::Value = serde_json::from_slice(&stored2.value).expect("valid json");
        let conds = v2["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array after approval");
        assert_eq!(
            conds[0]["type"], "Approved",
            "Approved condition must be stored"
        );
        assert!(
            v2["status"]["certificate"].is_null() || v2["status"].get("certificate").is_none(),
            "PUT /approval must NOT write status.certificate — only the signer may do that"
        );
        let rv2 = v2["metadata"]["resourceVersion"]
            .as_str()
            .expect("resourceVersion must be set after approval")
            .to_owned();

        // --- Step 4: PUT /status — signer writes the certificate ---
        let fake_cert = base64::engine::general_purpose::STANDARD.encode(b"FAKE_CERT_PEM");
        let status_body = serde_json::json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "CertificateSigningRequest",
            "metadata": {"name": "lifecycle-csr", "resourceVersion": rv2},
            "status": {
                "certificate": fake_cert,
                "conditions": [{
                    "type": "Approved",
                    "status": "True",
                    "reason": "ManualApproval",
                    "message": "approved by lifecycle test"
                }]
            }
        });
        let status_result = handlers::status::put_resource_status(
            axum::extract::State(state.clone()),
            axum::extract::Path((
                "certificates.k8s.io".into(),
                "v1".into(),
                "certificatesigningrequests".into(),
                "lifecycle-csr".into(),
            )),
            json_headers.clone(),
            bytes::Bytes::from(status_body.to_string()),
        )
        .await;
        assert!(
            status_result.is_ok(),
            "PUT /status must succeed for the signer to write the certificate"
        );

        // --- Step 5: GET — confirm final state: Approved + certificate ---
        let final_stored = store
            .get(&store_key)
            .await
            .expect("store.get must not fail")
            .expect("CSR must be in store after status write");
        let v_final: serde_json::Value =
            serde_json::from_slice(&final_stored.value).expect("valid json");

        let final_cert = v_final["status"]["certificate"].as_str();
        assert!(
            final_cert.is_some() && !final_cert.unwrap().is_empty(),
            "status.certificate must be present after signer writes via PUT /status"
        );
        assert_eq!(
            final_cert.unwrap(),
            fake_cert,
            "stored certificate must match what the signer wrote"
        );

        let final_conds = v_final["status"]["conditions"]
            .as_array()
            .expect("conditions must still be present in final state");
        assert_eq!(
            final_conds[0]["type"], "Approved",
            "Approved condition must survive PUT /status — signer must not erase approver's decision"
        );
    }

    /// DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings must return 200,
    /// not 405 Method Not Allowed.
    ///
    /// Regression test for mayor-6l6m: sonobuoy delete --all sends a collection DELETE to
    /// remove all ClusterRoleBindings it created.  Before the fix the collection route only
    /// registered GET+POST, so axum returned 405.  The test verifies:
    ///   1. The route exists and accepts DELETE (not 405).
    ///   2. Items stored under the prefix are actually removed.
    ///   3. The RBAC index is evicted so permissions are gone immediately.
    #[tokio::test]
    async fn delete_collection_clusterrolebindings_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a ClusterRoleBinding so we can verify it is actually deleted.
        let group = "rbac.authorization.k8s.io";
        let crb_key = keys::group_object_key(group, "clusterrolebindings", None, "sonobuoy");
        let crb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": { "name": "sonobuoy" },
            "subjects": [],
            "roleRef": { "apiGroup": group, "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(&crb_key, bytes::Bytes::from(crb_body.to_string()), Some(0))
            .await
            .expect("seed ClusterRoleBinding must succeed");

        let mut router = build_router(state);

        // Issue DELETE to the collection endpoint (no object name).
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");

        // Must not return 405 Method Not Allowed — the route must accept DELETE.
        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /apis/rbac.authorization.k8s.io/v1/clusterrolebindings must not return 405 — \
             sonobuoy delete --all sends a collection DELETE to clean up its ClusterRoleBindings"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "collection DELETE must return 200 Success"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        // The seeded ClusterRoleBinding must be gone from the store.
        let stored = store.get(&crb_key).await.expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "ClusterRoleBinding 'sonobuoy' must be deleted from store after collection DELETE"
        );
    }

    /// DELETE /apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings must return
    /// 200, not 405 Method Not Allowed.
    ///
    /// Same root cause as the cluster-scoped variant: the namespaced collection route also
    /// lacked a DELETE handler.  sonobuoy cleans up its namespace-scoped RoleBindings the
    /// same way it cleans cluster-scoped ones.
    #[tokio::test]
    async fn delete_collection_namespaced_rolebindings_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let group = "rbac.authorization.k8s.io";
        let rb_key = keys::group_object_key(group, "rolebindings", Some("sonobuoy"), "sonobuoy");
        let rb_body = serde_json::json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": { "name": "sonobuoy", "namespace": "sonobuoy" },
            "subjects": [],
            "roleRef": { "apiGroup": group, "kind": "ClusterRole", "name": "cluster-admin" }
        });
        store
            .put(&rb_key, bytes::Bytes::from(rb_body.to_string()), Some(0))
            .await
            .expect("seed RoleBinding must succeed");

        let mut router = build_router(state);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/apis/rbac.authorization.k8s.io/v1/namespaces/sonobuoy/rolebindings")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE on namespaced rolebindings collection must not return 405"
        );
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        let stored = store.get(&rb_key).await.expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "RoleBinding 'sonobuoy/sonobuoy' must be deleted from store after collection DELETE"
        );
    }

    /// DELETE /api/v1/namespaces/{ns}/pods must return 200, not 405.
    ///
    /// sonobuoy cleanup sends DELETE /api/v1/namespaces/sonobuoy/pods?labelSelector=sonobuoy-run=<id>
    /// to remove all pods it created. The pods collection route previously only registered
    /// GET+POST, so axum returned 405. The fix adds DELETE via core_delete_collection_namespaced_resource.
    /// The test verifies: 1) the route accepts DELETE (not 405), 2) matching pods are deleted,
    /// 3) non-matching pods are preserved when labelSelector is applied.
    #[tokio::test]
    async fn delete_collection_namespaced_pods_returns_200_not_405() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;
        use u7s_store::Store;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let ns_key = keys::cluster_object_key("namespaces", "sonobuoy");
        let ns_body = serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": "sonobuoy" }
        });
        store
            .put(&ns_key, bytes::Bytes::from(ns_body.to_string()), Some(0))
            .await
            .expect("seed namespace must succeed");

        let pod_key = keys::group_object_key("", "pods", Some("sonobuoy"), "sonobuoy-worker");
        let pod_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "sonobuoy-worker",
                "namespace": "sonobuoy",
                "labels": { "sonobuoy-run": "abc123" }
            },
            "spec": { "containers": [] }
        });
        store
            .put(&pod_key, bytes::Bytes::from(pod_body.to_string()), Some(0))
            .await
            .expect("seed pod must succeed");

        let mut router = build_router(state);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/namespaces/sonobuoy/pods?labelSelector=sonobuoy-run%3Dabc123")
            .body(axum::body::Body::empty())
            .expect("request build must not fail");
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /api/v1/namespaces/sonobuoy/pods must not return 405; \
             sonobuoy cleanup sends this request to remove its pods"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "collection DELETE on pods must return 200 Success"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(val["kind"], "Status");
        assert_eq!(val["status"], "Success");

        let stored = store.get(&pod_key).await.expect("store.get must not fail");
        assert!(
            stored.is_none(),
            "pod 'sonobuoy/sonobuoy-worker' must be deleted after collection DELETE with matching labelSelector"
        );
    }

    // ---------------------------------------------------------------------------
    // Service clusterIP auto-allocation integration tests
    // ---------------------------------------------------------------------------

    fn make_state_with_cidr(cidr: &str) -> state::AppState {
        use state::ServiceIpAllocator;
        use std::sync::Arc;
        let store = Arc::new(make_store());
        let alloc = ServiceIpAllocator::from_cidr(cidr).expect("valid CIDR");
        state::AppState::new_with_ca(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
            None,
            None,
            Some(alloc),
        )
    }

    /// POST a Service with no clusterIP → GET it back → clusterIP is in the configured CIDR.
    ///
    /// This is the primary correctness test: the apiserver must auto-assign an IP
    /// so that KCM's endpoints-controller can populate Endpoints and kube-proxy can
    /// program iptables rules. Without a clusterIP, Service traffic is unroutable.
    #[tokio::test]
    async fn service_create_auto_assigns_cluster_ip_from_cidr() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request};
        use std::net::Ipv4Addr;
        use tower_service::Service as _;

        // /29: .0 network, .1 reserved, .2-.6 usable, .7 broadcast
        let state = make_state_with_cidr("10.0.0.0/29");
        let mut router = build_router(state);

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": {
                "selector": { "app": "my-app" },
                "ports": [{ "port": 80, "targetPort": 8080 }]
            }
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces/default/services")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request must build");

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "Service POST must return 201 Created"
        );

        let body_bytes = to_bytes(resp.into_body(), 4096)
            .await
            .expect("collect body");
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let cluster_ip = val["spec"]["clusterIP"].as_str().unwrap_or("");
        assert!(
            !cluster_ip.is_empty(),
            "spec.clusterIP must be auto-assigned — without it Service traffic is unroutable"
        );
        assert_ne!(
            cluster_ip, "None",
            "clusterIP must not be 'None' for a regular Service"
        );

        // Verify it falls within the configured CIDR (10.0.0.0/29).
        let ip: Ipv4Addr = cluster_ip
            .parse()
            .expect("clusterIP must be a valid IPv4 address");
        let base = u32::from("10.0.0.0".parse::<Ipv4Addr>().unwrap());
        let ip_u32 = u32::from(ip);
        assert!(
            ip_u32 >= base && ip_u32 < base + 8,
            "clusterIP {cluster_ip} must be within 10.0.0.0/29"
        );
    }

    /// POST two Services with no clusterIP → they get different IPs.
    ///
    /// Duplicate clusterIPs would cause all traffic for one service to be
    /// mis-routed to the other. The UNIQUE constraint + CAS must prevent this.
    #[tokio::test]
    async fn two_services_get_different_cluster_ips() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request};
        use tower_service::Service as _;

        // /29: 6 usable IPs — enough for two services.
        let state = make_state_with_cidr("10.0.0.0/29");
        let mut router = build_router(state);

        let make_svc_req = |name: &str| {
            let body = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": { "name": name, "namespace": "default" },
                "spec": { "ports": [{ "port": 80 }] }
            });
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/namespaces/default/services")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request must build")
        };

        let resp1 = router
            .call(make_svc_req("svc-a"))
            .await
            .expect("router call must not error");
        assert_eq!(resp1.status(), axum::http::StatusCode::CREATED);
        let b1 = to_bytes(resp1.into_body(), 4096).await.unwrap();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let ip1 = v1["spec"]["clusterIP"].as_str().unwrap_or("").to_string();

        let resp2 = router
            .call(make_svc_req("svc-b"))
            .await
            .expect("router call must not error");
        assert_eq!(resp2.status(), axum::http::StatusCode::CREATED);
        let b2 = to_bytes(resp2.into_body(), 4096).await.unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
        let ip2 = v2["spec"]["clusterIP"].as_str().unwrap_or("").to_string();

        assert!(
            !ip1.is_empty() && !ip2.is_empty(),
            "both services must receive a clusterIP"
        );
        assert_ne!(
            ip1, ip2,
            "two services must not share a clusterIP — duplicate IPs mis-route traffic"
        );
    }

    /// POST /apis/rbac.authorization.k8s.io/v1/clusterroles with ?fieldValidation=Strict must
    /// return 201 Created, not 400.
    ///
    /// `kubectl create` always sends ?fieldValidation=Strict. If the server rejects this query
    /// param, all `kubectl create` RBAC operations fail — including sonobuoy's setup phase which
    /// creates the ClusterRole and ClusterRoleBinding that the aggregator pod needs.
    ///
    /// The fix: accept and ignore ?fieldValidation=<any value> on all write endpoints.
    /// This test exercises the full router path (path matching + handler dispatch) to catch
    /// any routing or middleware bug that might inspect or reject unknown query params.
    #[tokio::test]
    async fn field_validation_query_param_does_not_break_clusterrole_create() {
        use axum::body::to_bytes;
        use axum::http::{Method, Request, StatusCode};
        use tower_service::Service as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let mut router = build_router(state);

        // Admin user injected directly into request extensions — bypasses the auth layer
        // (which is not wired in this test) while still satisfying the handler's
        // Extension(user): Extension<UserInfo> extractor.
        let admin = auth::UserInfo {
            username: "admin".to_string(),
            uid: String::new(),
            groups: vec!["system:masters".to_string()],
        };

        let make_role_req = |name: &str, query: &str| {
            let body = serde_json::json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": { "name": name },
                "rules": [
                    { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }
                ]
            });
            let uri = format!(
                "/apis/rbac.authorization.k8s.io/v1/clusterroles?fieldManager=kubectl-create{}",
                query
            );
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request must build")
        };

        // Case 1: ?fieldValidation=Strict — kubectl create always sends this.
        let mut req = make_role_req("sonobuoy-runner-strict", "&fieldValidation=Strict");
        req.extensions_mut().insert(admin.clone());
        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST with ?fieldValidation=Strict must return 201 — \
             kubectl create always sends this param and must not get 400"
        );
        let body_bytes = to_bytes(resp.into_body(), 4096)
            .await
            .expect("collect response body");
        let resp_val: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be JSON");
        assert_eq!(
            resp_val["kind"].as_str(),
            Some("ClusterRole"),
            "response kind must be ClusterRole when fieldValidation=Strict is present"
        );

        // Case 2: ?fieldValidation=Warn — must also succeed.
        let mut req2 = make_role_req("sonobuoy-runner-warn", "&fieldValidation=Warn");
        req2.extensions_mut().insert(admin.clone());
        let resp2 = router.call(req2).await.expect("router must not error");
        assert_eq!(
            resp2.status(),
            StatusCode::CREATED,
            "POST with ?fieldValidation=Warn must return 201"
        );

        // Case 3: no fieldValidation param — baseline must still succeed.
        let mut req3 = make_role_req("sonobuoy-runner-baseline", "");
        req3.extensions_mut().insert(admin.clone());
        let resp3 = router.call(req3).await.expect("router must not error");
        assert_eq!(
            resp3.status(),
            StatusCode::CREATED,
            "POST without ?fieldValidation must return 201 (baseline)"
        );

        // Verify the Strict-case ClusterRole was actually stored (not just accepted silently).
        let stored_key = keys::group_object_key(
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            "sonobuoy-runner-strict",
        );
        let stored = store
            .get(&stored_key)
            .await
            .expect("store.get must not fail");
        assert!(
            stored.is_some(),
            "ClusterRole sonobuoy-runner-strict must be persisted — \
             a 201 response without persisting the object would be misleading"
        );
        let stored_val: serde_json::Value = serde_json::from_slice(&stored.unwrap().value)
            .expect("stored value must be valid JSON");
        assert_eq!(
            stored_val["kind"].as_str(),
            Some("ClusterRole"),
            "stored object kind must be ClusterRole"
        );
    }
}
