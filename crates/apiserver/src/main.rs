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

    /// Hostname or IP to use for all kubelet proxy requests (log, exec, attach, port-forward).
    /// When set, overrides the node's InternalIP from status.addresses. Useful when the
    /// apiserver runs on a different host than the kubelet (e.g. Mac host + Lima VM) and
    /// the node's InternalIP is not directly reachable from the apiserver.
    #[arg(long)]
    kubelet_preferred_address: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    // 1. Parse CLI args.
    let args = Args::parse();

    // 2. Init tracing.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 3. Open store.
    let store = Arc::new(SqliteStore::new(&args.db)?);
    seed_namespaces(&store).await?;
    seed_rbac(&store).await?;
    seed_flowcontrol(&store).await?;
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
    // Combine kubelet client cert PEM + key PEM for the kubelet proxy client identity.
    // The apiserver presents this certificate when proxying log/exec/attach requests to
    // the kubelet. Kubelet accepts certs with O=system:masters signed by the cluster CA.
    let mut kubelet_client_identity_pem = tls_material.kubelet_client_cert_pem.clone();
    kubelet_client_identity_pem.extend_from_slice(&tls_material.kubelet_client_key_pem);
    let state = state::AppState::new_with_config(state::AppStateConfig {
        store: Arc::clone(&store),
        sa_key: sa_encoding_key,
        sa_decoding_key,
        token_map,
        server_address,
        cluster_ca_der: Some(tls_material.ca_cert_der.clone()),
        webhook_identity_pem: Some(webhook_identity_pem),
        service_ip_allocator,
        kubelet_client_identity_pem: Some(kubelet_client_identity_pem),
        kubelet_preferred_address: args.kubelet_preferred_address,
        continue_token_key: None, // fresh random key generated at startup
    });

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
        // AggregatedDiscovery (k8s 1.27+ GA) — returns APIGroupDiscoveryList
        // Serves both the dedicated endpoint and the Accept-header-based negotiation on /apis.
        .route(
            "/discovery/v2",
            get(handlers::discovery::aggregated_discovery_v2),
        )
        // Non-core group discovery
        .route("/apis", get(handlers::discovery::api_group_list))
        .route("/apis/{group}", get(handlers::discovery::api_group))
        .route(
            "/apis/{group}/{version}",
            get(handlers::discovery::api_group_resources),
        )
        // Namespaces — collection
        .route(
            "/api/v1/namespaces",
            get(handlers::namespaces::list_namespaces).post(handlers::namespaces::create_namespace),
        )
        // Namespaces — finalize subresource (must be before the named-resource catch-all)
        // The KCM namespace controller calls PUT /api/v1/namespaces/{name}/finalize after
        // draining resources to remove the "kubernetes" finalizer. Without this route the
        // request hits 404 and the namespace stays stuck in Terminating forever.
        .route(
            "/api/v1/namespaces/{name}/finalize",
            axum::routing::put(handlers::namespaces::finalize_namespace),
        )
        // Namespaces — status subresource (must be before named-resource catch-all)
        // The KCM namespace controller PATCHes this to set status.conditions (e.g.
        // NamespaceDeletionContentFailure) during namespace deletion. Without it the
        // condition never gets set and conformance test OrderedNamespaceDeletion times out.
        .route(
            "/api/v1/namespaces/{name}/status",
            get(handlers::namespaces::get_namespace_status)
                .put(handlers::namespaces::put_namespace_status)
                .patch(handlers::namespaces::patch_namespace_status),
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
        // Pods — resize subresource (in-place resource update, GA k8s 1.33+)
        // Must be before the generic catch-all so axum doesn't interpret "resize" as a pod name.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/resize",
            axum::routing::patch(handlers::pods::patch_pod_resize)
                .put(handlers::pods::patch_pod_resize),
        )
        // Pods — ephemeralcontainers subresource (GA since k8s 1.25)
        // Must be before the generic catch-all.
        .route(
            "/api/v1/namespaces/{ns}/pods/{name}/ephemeralcontainers",
            axum::routing::patch(handlers::pods::patch_ephemeral_containers),
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
        // Nodes — proxy subresource: forward to kubelet at https://<node-ip>:10250/<path>
        .route(
            "/api/v1/nodes/{name}/proxy/{*path}",
            get(handlers::proxy::node_proxy)
                .post(handlers::proxy::node_proxy)
                .put(handlers::proxy::node_proxy)
                .delete(handlers::proxy::node_proxy),
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
                .patch(handlers::crd::patch_crd)
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
            "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
            post(handlers::authorization::local_subject_access_review),
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
    const TS: &str = "2024-01-01T00:00:00Z";

    // Helper closure: unconditional put for a single ClusterRole.
    // uid_suffix must be unique across all seeded objects.
    macro_rules! put {
        ($key:expr, $body:expr, $name:expr, $kind:expr) => {{
            store
                .put(&$key, Bytes::from($body.to_string()), None)
                .await
                .map_err(|e| anyhow::anyhow!("seed {} {}: {}", $kind, $name, e))?;
            tracing::info!("seeded {}: {}", $kind, $name);
        }};
    }

    // -----------------------------------------------------------------------
    // ClusterRole: system:node — permissions kubelet needs.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000010", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"],        "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"],         "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods/status"],  "verbs": ["get","update","patch"] },
            { "apiGroups": [""], "resources": ["pods/log"],     "verbs": ["get"] },
            { "apiGroups": [""], "resources": ["events"],       "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["configmaps"],          "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["secrets"],             "verbs": ["get","list","watch"] },
            // Kubelet calls TokenRequest to project SA tokens into pods (projected volumes).
            // Without this rule the kubelet's POST to serviceaccounts/{name}/token returns 403
            // and containers never get an SA token, breaking in-cluster API calls.
            { "apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csinodes"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["csidrivers"], "verbs": ["get","list","watch"] },
            // Kubelet webhook authorizer and authenticator call back to the apiserver via
            // SubjectAccessReview and TokenReview. Without these the kubelet denies all
            // proxy requests (logs, exec, attach) with "Authorization error".
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:node", "ClusterRole");

    // ClusterRoleBinding: system:node — binds system:nodes group to the ClusterRole.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node", "uid": "00000000-0000-0000-0000-000000000011", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:nodes" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node" }
    });
    put!(key, body, "system:node", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: cluster-admin — wildcard access to all resources.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "cluster-admin");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "cluster-admin", "uid": "00000000-0000-0000-0000-000000000012", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] },
            { "nonResourceURLs": ["*"], "verbs": ["*"] }
        ]
    });
    put!(key, body, "cluster-admin", "ClusterRole");

    // ClusterRoleBinding: system:masters → cluster-admin.
    // This replaces the former hardcoded bypass in is_allowed() / user_holds_all_rules().
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:masters");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:masters", "uid": "00000000-0000-0000-0000-000000000013", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:masters" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
    });
    put!(key, body, "system:masters", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:basic-user — grants every authenticated user the
    // ability to create SelfSubjectAccessReviews and SelfSubjectRulesReviews.
    // Argo CD calls these endpoints on startup to discover its own permissions;
    // without this role those requests are denied with 403.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:basic-user");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000014", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["authorization.k8s.io"], "resources": ["selfsubjectaccessreviews","selfsubjectrulesreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:basic-user", "ClusterRole");

    // ClusterRoleBinding: system:basic-user → system:authenticated.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:basic-user");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:basic-user", "uid": "00000000-0000-0000-0000-000000000015", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:basic-user" }
    });
    put!(key, body, "system:basic-user", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:discovery — read access to API discovery endpoints.
    // Grants get on /api, /apis, /openapi/v2, etc. so unauthenticated discovery works.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:discovery");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:discovery", "uid": "00000000-0000-0000-0000-000000000016", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/api","/api/*","/apis","/apis/*","/healthz","/readyz","/livez","/openapi","/openapi/*","/version"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:discovery", "ClusterRole");

    // ClusterRoleBinding: system:discovery → system:authenticated.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:discovery");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:discovery", "uid": "00000000-0000-0000-0000-000000000017", "creationTimestamp": TS },
        "subjects": [{ "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:discovery" }
    });
    put!(key, body, "system:discovery", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:public-info-viewer — health/liveness/version endpoints
    // for both authenticated and unauthenticated clients (e.g. load balancers).
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:public-info-viewer");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:public-info-viewer", "uid": "00000000-0000-0000-0000-000000000018", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/healthz","/readyz","/livez","/version","/version/"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:public-info-viewer", "ClusterRole");

    // ClusterRoleBinding: system:public-info-viewer → authenticated + unauthenticated.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:public-info-viewer",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:public-info-viewer", "uid": "00000000-0000-0000-0000-000000000019", "creationTimestamp": TS },
        "subjects": [
            { "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:authenticated" },
            { "kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "system:unauthenticated" }
        ],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:public-info-viewer" }
    });
    put!(key, body, "system:public-info-viewer", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:kube-controller-manager — KCM needs these to run its
    // reconciliation loops for deployments, replicasets, endpoints, etc.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:kube-controller-manager",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000020", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["endpoints","pods","replicationcontrollers","serviceaccounts","configmaps","secrets","services","namespaces","nodes","persistentvolumes","persistentvolumeclaims","resourcequotas"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles","clusterrolebindings","roles","rolebindings"], "verbs": ["get","list","watch","create","update","patch","escalate","bind"] },
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses","volumeattachments","csinodes","csidrivers","csistoragecapacities"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "system:kube-controller-manager", "ClusterRole");

    // ClusterRoleBinding: system:kube-controller-manager → user system:kube-controller-manager.
    let key = keys::group_object_key(
        GROUP,
        "clusterrolebindings",
        None,
        "system:kube-controller-manager",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000021", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-controller-manager" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:kube-controller-manager" }
    });
    put!(
        key,
        body,
        "system:kube-controller-manager",
        "ClusterRoleBinding"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:kube-scheduler — scheduler needs watch on pods/nodes
    // and update on pod bindings to place workloads.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:kube-scheduler", "uid": "00000000-0000-0000-0000-000000000022", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["pods/binding","pods/status"], "verbs": ["update","patch","create"] },
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": [""], "resources": ["services","replicationcontrollers","persistentvolumeclaims","persistentvolumes"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["statefulsets","replicasets"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses","csinodes","csidrivers","csistoragecapacities"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"] },
            { "apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"] }
        ]
    });
    put!(key, body, "system:kube-scheduler", "ClusterRole");

    // ClusterRoleBinding: system:kube-scheduler → user system:kube-scheduler.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:kube-scheduler", "uid": "00000000-0000-0000-0000-000000000023", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-scheduler" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:kube-scheduler" }
    });
    put!(key, body, "system:kube-scheduler", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:node-proxier — kube-proxy needs watch on services/endpoints.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node-proxier");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node-proxier", "uid": "00000000-0000-0000-0000-000000000024", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","services","nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "system:node-proxier", "ClusterRole");

    // ClusterRoleBinding: system:node-proxier → user system:kube-proxy.
    let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:node-proxier");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": { "name": "system:node-proxier", "uid": "00000000-0000-0000-0000-000000000025", "creationTimestamp": TS },
        "subjects": [{ "kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "system:kube-proxy" }],
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "system:node-proxier" }
    });
    put!(key, body, "system:node-proxier", "ClusterRoleBinding");

    // -----------------------------------------------------------------------
    // ClusterRole: system:monitoring — read-only access to health/metrics endpoints.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:monitoring");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:monitoring", "uid": "00000000-0000-0000-0000-000000000026", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/metrics","/metrics/slis","/healthz","/readyz","/livez"], "verbs": ["get"] }
        ]
    });
    put!(key, body, "system:monitoring", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:persistent-volume-provisioner — for external PV provisioners.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:persistent-volume-provisioner",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:persistent-volume-provisioner", "uid": "00000000-0000-0000-0000-000000000027", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["get","list","watch","create","delete"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","watch","update"] },
            { "apiGroups": [""], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:persistent-volume-provisioner",
        "ClusterRole"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: system:volume-scheduler — volume binding for scheduler.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:volume-scheduler");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:volume-scheduler", "uid": "00000000-0000-0000-0000-000000000028", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes"], "verbs": ["get","list","patch","update","watch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","patch","update","watch"] }
        ]
    });
    put!(key, body, "system:volume-scheduler", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:node-bootstrapper — TLS bootstrap for kubelets.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:node-bootstrapper");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:node-bootstrapper", "uid": "00000000-0000-0000-0000-000000000029", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["create","get","list","watch"] }
        ]
    });
    put!(key, body, "system:node-bootstrapper", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:heapster — legacy metrics aggregator.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "system:heapster");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:heapster", "uid": "00000000-0000-0000-0000-000000000030", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["events","namespaces","nodes","pods"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "system:heapster", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: system:service-account-issuer-discovery — allows token projections.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:service-account-issuer-discovery",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:service-account-issuer-discovery", "uid": "00000000-0000-0000-0000-000000000031", "creationTimestamp": TS },
        "rules": [
            { "nonResourceURLs": ["/.well-known/openid-configuration","/openid/v1/jwks"], "verbs": ["get"] }
        ]
    });
    put!(
        key,
        body,
        "system:service-account-issuer-discovery",
        "ClusterRole"
    );

    // -----------------------------------------------------------------------
    // ClusterRole: admin — namespace-scoped admin (aggregate-to-admin).
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "admin");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "admin",
            "uid": "00000000-0000-0000-0000-000000000032",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-cluster-admin": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","secrets","serviceaccounts","events","replicationcontrollers"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles","rolebindings"], "verbs": ["get","list","watch","create","update","patch","delete","bind","escalate"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies","ingresses"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(key, body, "admin", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: edit — namespace-scoped write access.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "edit");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "edit",
            "uid": "00000000-0000-0000-0000-000000000033",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-admin": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","secrets","serviceaccounts","events","replicationcontrollers"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(key, body, "edit", "ClusterRole");

    // -----------------------------------------------------------------------
    // ClusterRole: view — namespace-scoped read-only access.
    // -----------------------------------------------------------------------
    let key = keys::group_object_key(GROUP, "clusterroles", None, "view");
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": "view",
            "uid": "00000000-0000-0000-0000-000000000034",
            "creationTimestamp": TS,
            "labels": { "rbac.authorization.k8s.io/aggregate-to-edit": "true" }
        },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","persistentvolumeclaims","configmaps","serviceaccounts","events","replicationcontrollers","namespaces","nodes","resourcequotas","limitranges"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["apps"], "resources": ["daemonsets","deployments","replicasets","statefulsets","controllerrevisions"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["batch"], "resources": ["jobs","cronjobs"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(key, body, "view", "ClusterRole");

    // -----------------------------------------------------------------------
    // Controller ClusterRoles — each KCM sub-controller needs its own least-
    // privilege role so it only touches the resources it manages.
    // -----------------------------------------------------------------------

    // system:controller:attachdetach-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:attachdetach-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:attachdetach-controller", "uid": "00000000-0000-0000-0000-000000000035", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","nodes","pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["patch","update"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["volumeattachments","csinodes","csidrivers"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:attachdetach-controller",
        "ClusterRole"
    );

    // system:controller:certificate-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:certificate-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:certificate-controller", "uid": "00000000-0000-0000-0000-000000000036", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": ["certificates.k8s.io"], "resources": ["certificatesigningrequests/status","certificatesigningrequests/approval"], "verbs": ["update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:certificate-controller",
        "ClusterRole"
    );

    // system:controller:clusterrole-aggregation-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:clusterrole-aggregation-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:clusterrole-aggregation-controller", "uid": "00000000-0000-0000-0000-000000000037", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["get","list","watch","update","patch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:clusterrole-aggregation-controller",
        "ClusterRole"
    );

    // system:controller:cronjob-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:cronjob-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:cronjob-controller", "uid": "00000000-0000-0000-0000-000000000038", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["cronjobs","jobs"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:cronjob-controller",
        "ClusterRole"
    );

    // system:controller:daemon-set-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:daemon-set-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:daemon-set-controller", "uid": "00000000-0000-0000-0000-000000000039", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["daemonsets","daemonsets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["nodes","pods","podtemplates"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:daemon-set-controller",
        "ClusterRole"
    );

    // system:controller:deployment-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:deployment-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:deployment-controller", "uid": "00000000-0000-0000-0000-000000000040", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["deployments","deployments/status","replicasets"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:deployment-controller",
        "ClusterRole"
    );

    // system:controller:disruption-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:disruption-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:disruption-controller", "uid": "00000000-0000-0000-0000-000000000041", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["deployments","replicasets","statefulsets"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["policy"], "resources": ["poddisruptionbudgets","poddisruptionbudgets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:disruption-controller",
        "ClusterRole"
    );

    // system:controller:endpoint-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpoint-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpoint-controller", "uid": "00000000-0000-0000-0000-000000000042", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","pods","services"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpoint-controller",
        "ClusterRole"
    );

    // system:controller:expand-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:expand-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:expand-controller", "uid": "00000000-0000-0000-0000-000000000043", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","persistentvolumeclaims/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:expand-controller",
        "ClusterRole"
    );

    // system:controller:generic-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:generic-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:generic-garbage-collector", "uid": "00000000-0000-0000-0000-000000000044", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch","patch","update","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:generic-garbage-collector",
        "ClusterRole"
    );

    // system:controller:horizontal-pod-autoscaler
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:horizontal-pod-autoscaler",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:horizontal-pod-autoscaler", "uid": "00000000-0000-0000-0000-000000000045", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers","horizontalpodautoscalers/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods","replicationcontrollers","replicationcontrollers/scale"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": ["apps"], "resources": ["deployments","deployments/scale","replicasets","replicasets/scale","statefulsets","statefulsets/scale"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] },
            { "apiGroups": ["metrics.k8s.io"], "resources": ["pods","nodes"], "verbs": ["get","list"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:horizontal-pod-autoscaler",
        "ClusterRole"
    );

    // system:controller:job-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:job-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:job-controller", "uid": "00000000-0000-0000-0000-000000000046", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["jobs","jobs/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(key, body, "system:controller:job-controller", "ClusterRole");

    // system:controller:namespace-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:namespace-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:namespace-controller", "uid": "00000000-0000-0000-0000-000000000047", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch","delete","deletecollection"] },
            { "apiGroups": [""], "resources": ["namespaces","namespaces/status","namespaces/finalize"], "verbs": ["get","list","watch","update","patch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:namespace-controller",
        "ClusterRole"
    );

    // system:controller:node-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:node-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:node-controller", "uid": "00000000-0000-0000-0000-000000000048", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes","nodes/status"], "verbs": ["get","list","watch","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:node-controller",
        "ClusterRole"
    );

    // system:controller:persistent-volume-binder
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:persistent-volume-binder",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:persistent-volume-binder", "uid": "00000000-0000-0000-0000-000000000049", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumes","persistentvolumeclaims","persistentvolumeclaims/status","pods"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["namespaces","nodes","services"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update","watch","list","get"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:persistent-volume-binder",
        "ClusterRole"
    );

    // system:controller:pod-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:pod-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:pod-garbage-collector", "uid": "00000000-0000-0000-0000-000000000050", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:pod-garbage-collector",
        "ClusterRole"
    );

    // system:controller:pvc-protection-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:pvc-protection-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:pvc-protection-controller", "uid": "00000000-0000-0000-0000-000000000051", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["persistentvolumeclaims","persistentvolumeclaims/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:pvc-protection-controller",
        "ClusterRole"
    );

    // system:controller:replicaset-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:replicaset-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:replicaset-controller", "uid": "00000000-0000-0000-0000-000000000052", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["replicasets","replicasets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:replicaset-controller",
        "ClusterRole"
    );

    // system:controller:replication-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:replication-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:replication-controller", "uid": "00000000-0000-0000-0000-000000000053", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["replicationcontrollers","replicationcontrollers/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch","create","delete","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:replication-controller",
        "ClusterRole"
    );

    // system:controller:resourcequota-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:resourcequota-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:resourcequota-controller", "uid": "00000000-0000-0000-0000-000000000054", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["*"], "resources": ["*"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["resourcequotas","resourcequotas/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:resourcequota-controller",
        "ClusterRole"
    );

    // system:controller:route-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:route-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:route-controller", "uid": "00000000-0000-0000-0000-000000000055", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:route-controller",
        "ClusterRole"
    );

    // system:controller:service-account-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:service-account-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:service-account-controller", "uid": "00000000-0000-0000-0000-000000000056", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:service-account-controller",
        "ClusterRole"
    );

    // system:controller:service-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:service-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:service-controller", "uid": "00000000-0000-0000-0000-000000000057", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["services","services/status","nodes","endpoints"], "verbs": ["get","list","watch","update","patch","create","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:service-controller",
        "ClusterRole"
    );

    // system:controller:statefulset-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:statefulset-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:statefulset-controller", "uid": "00000000-0000-0000-0000-000000000058", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["apps"], "resources": ["statefulsets","statefulsets/status"], "verbs": ["get","list","watch","update","patch"] },
            { "apiGroups": [""], "resources": ["pods","persistentvolumeclaims"], "verbs": ["get","list","watch","create","delete","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:statefulset-controller",
        "ClusterRole"
    );

    // system:controller:ttl-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ttl-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ttl-controller", "uid": "00000000-0000-0000-0000-000000000059", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["nodes"], "verbs": ["get","list","watch","patch","update"] }
        ]
    });
    put!(key, body, "system:controller:ttl-controller", "ClusterRole");

    // system:controller:ttl-after-finished-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ttl-after-finished-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ttl-after-finished-controller", "uid": "00000000-0000-0000-0000-000000000060", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get","list","watch","delete"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:ttl-after-finished-controller",
        "ClusterRole"
    );

    // system:controller:endpointslice-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpointslice-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpointslice-controller", "uid": "00000000-0000-0000-0000-000000000061", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods","services","endpoints","nodes"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpointslice-controller",
        "ClusterRole"
    );

    // system:controller:endpointslicemirroring-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:endpointslicemirroring-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:endpointslicemirroring-controller", "uid": "00000000-0000-0000-0000-000000000062", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["endpoints","endpointslices","services"], "verbs": ["get","list","watch"] },
            { "apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["get","list","watch","create","update","patch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:endpointslicemirroring-controller",
        "ClusterRole"
    );

    // system:controller:ephemeral-volume-controller
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:ephemeral-volume-controller",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:ephemeral-volume-controller", "uid": "00000000-0000-0000-0000-000000000063", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get","list","watch"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:ephemeral-volume-controller",
        "ClusterRole"
    );

    // system:controller:storage-version-garbage-collector
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:storage-version-garbage-collector",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:storage-version-garbage-collector", "uid": "00000000-0000-0000-0000-000000000064", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": ["internal.apiserver.k8s.io"], "resources": ["storageversions","storageversions/status"], "verbs": ["get","list","watch","patch","update","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:storage-version-garbage-collector",
        "ClusterRole"
    );

    // system:controller:legacy-service-account-token-cleaner
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:legacy-service-account-token-cleaner",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:legacy-service-account-token-cleaner", "uid": "00000000-0000-0000-0000-000000000065", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["secrets"], "verbs": ["get","list","watch","delete"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:legacy-service-account-token-cleaner",
        "ClusterRole"
    );

    // system:controller:root-ca-cert-publisher
    let key = keys::group_object_key(
        GROUP,
        "clusterroles",
        None,
        "system:controller:root-ca-cert-publisher",
    );
    let body = serde_json::json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": { "name": "system:controller:root-ca-cert-publisher", "uid": "00000000-0000-0000-0000-000000000066", "creationTimestamp": TS },
        "rules": [
            { "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get","list","watch","create","update","patch"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["create","patch","update"] }
        ]
    });
    put!(
        key,
        body,
        "system:controller:root-ca-cert-publisher",
        "ClusterRole"
    );

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

    // default/kubernetes Endpoints — controllers (e.g. endpoint controller, admission webhooks)
    // watch this object to locate the apiserver. Without it they log errors and may fail to start.
    let ep_key = keys::object_key("endpoints", "default", "kubernetes");
    let ep_body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": "00000000-0000-0000-0000-000000000022",
            "creationTimestamp": "2024-01-01T00:00:00Z",
            "labels": { "endpointslice.kubernetes.io/skip-mirror": "true" }
        },
        "subsets": [{
            "addresses": [{ "ip": "127.0.0.1" }],
            "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
        }]
    });
    match store
        .put(&ep_key, Bytes::from(ep_body.to_string()), Some(0))
        .await
    {
        Ok(_) => tracing::info!("seeded Endpoints: default/kubernetes"),
        Err(u7s_store::StoreError::AlreadyExists { .. }) => {}
        Err(e) => return Err(anyhow::anyhow!("seed Endpoints default/kubernetes: {e}")),
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

/// Seed the default API Priority and Fairness resources.
///
/// A real kube-apiserver seeds these via its `priority-and-fairness-config-consumer`
/// post-start hook. We don't have that hook, so we seed them at startup instead.
/// Without these defaults, the APF conformance test times out waiting for the state
/// to converge (FlowSchema .status.conditions[Ready] never becomes True without the
/// PriorityLevelConfiguration it references existing).
async fn seed_flowcontrol(store: &SqliteStore) -> anyhow::Result<()> {
    use bytes::Bytes;
    use u7s_store::Store;

    const GROUP: &str = "flowcontrol.apiserver.k8s.io";
    const TS: &str = "2024-01-01T00:00:00Z";

    // Seed 8 default PriorityLevelConfigurations.
    // Uses unconditional put (None version) so the canonical values are
    // always written on startup, just like seed_rbac does for ClusterRoles.

    // exempt — system:masters requests bypass all queuing
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "exempt");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "exempt", "uid": "00000000-0000-0000-0000-000000000100",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Exempt", "exempt": {} },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration exempt: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: exempt");

    // catch-all — last-resort bucket for unclassified requests
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "catch-all");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "catch-all", "uid": "00000000-0000-0000-0000-000000000101",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 5,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration catch-all: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: catch-all");

    // system — for kube-system service accounts
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "system");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "system", "uid": "00000000-0000-0000-0000-000000000102",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 30,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 64, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration system: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: system");

    // leader-election — for controller leader elections
    let key = keys::group_object_key(
        GROUP,
        "prioritylevelconfigurations",
        None,
        "leader-election",
    );
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "leader-election", "uid": "00000000-0000-0000-0000-000000000103",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 10,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 16, "handSize": 4, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration leader-election: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: leader-election");

    // workload-high — for high-priority workload controllers
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "workload-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "workload-high", "uid": "00000000-0000-0000-0000-000000000104",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 40,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration workload-high: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: workload-high");

    // workload-low — for low-priority workload controllers
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "workload-low");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "workload-low", "uid": "00000000-0000-0000-0000-000000000105",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 100,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration workload-low: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: workload-low");

    // global-default — catch-most bucket for authenticated requests
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "global-default");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "global-default", "uid": "00000000-0000-0000-0000-000000000106",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 20,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 128, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration global-default: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: global-default");

    // node-high — for node-critical requests (node status, kubelet heartbeat)
    let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "node-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": { "name": "node-high", "uid": "00000000-0000-0000-0000-000000000107",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": { "type": "Limited", "limited": {
            "nominalConcurrencyShares": 40,
            "limitResponse": { "type": "Queue",
                "queuing": { "queues": 64, "handSize": 6, "queueLengthLimit": 50 } }
        } },
        "status": { "conditions": [{ "type": "Ready", "status": "True",
                                      "lastTransitionTime": TS,
                                      "reason": "Found",
                                      "message": "This PriorityLevelConfiguration is ensured." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed PriorityLevelConfiguration node-high: {e}"))?;
    tracing::info!("seeded PriorityLevelConfiguration: node-high");

    // Seed 13 default FlowSchemas.
    // Each references a PriorityLevelConfiguration by name.

    // exempt — for system:masters; no queuing at all
    let key = keys::group_object_key(GROUP, "flowschemas", None, "exempt");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "exempt", "uid": "00000000-0000-0000-0000-000000000200",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 1,
            "priorityLevelConfiguration": { "name": "exempt" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:masters" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema exempt: {e}"))?;
    tracing::info!("seeded FlowSchema: exempt");

    // probes — for unauthenticated health check probes
    let key = keys::group_object_key(GROUP, "flowschemas", None, "probes");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "probes", "uid": "00000000-0000-0000-0000-000000000201",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 2,
            "priorityLevelConfiguration": { "name": "exempt" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:unauthenticated" } }],
                        "nonResourceRules": [{ "verbs": ["get"],
                                               "nonResourceURLs": ["/healthz", "/readyz", "/livez"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema probes: {e}"))?;
    tracing::info!("seeded FlowSchema: probes");

    // system-leader-election — for kcm/scheduler leader elections
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-leader-election");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-leader-election", "uid": "00000000-0000-0000-0000-000000000202",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 100,
            "priorityLevelConfiguration": { "name": "leader-election" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["get", "create", "update"],
                                            "apiGroups": ["coordination.k8s.io"],
                                            "resources": ["leases"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-leader-election: {e}"))?;
    tracing::info!("seeded FlowSchema: system-leader-election");

    // endpoint-controller — endpoints/endpointslice controllers
    let key = keys::group_object_key(GROUP, "flowschemas", None, "endpoint-controller");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "endpoint-controller", "uid": "00000000-0000-0000-0000-000000000203",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 150,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpoint-controller", "namespace": "kube-system" } },
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpointslice-controller", "namespace": "kube-system" } },
                            { "kind": "ServiceAccount", "serviceAccount": { "name": "endpointslicemirroring-controller", "namespace": "kube-system" } }
                        ],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema endpoint-controller: {e}"))?;
    tracing::info!("seeded FlowSchema: endpoint-controller");

    // workload-leader-election — for workload-level leader elections
    let key = keys::group_object_key(GROUP, "flowschemas", None, "workload-leader-election");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "workload-leader-election", "uid": "00000000-0000-0000-0000-000000000204",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 200,
            "priorityLevelConfiguration": { "name": "leader-election" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["get", "create", "update"],
                                            "apiGroups": ["coordination.k8s.io"],
                                            "resources": ["leases"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema workload-leader-election: {e}"))?;
    tracing::info!("seeded FlowSchema: workload-leader-election");

    // system-node-high — high-priority node requests (heartbeat, status updates)
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-node-high");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-node-high", "uid": "00000000-0000-0000-0000-000000000205",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 400,
            "priorityLevelConfiguration": { "name": "node-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:nodes" } }],
                        "resourceRules": [
                            { "verbs": ["get", "create", "update", "patch"],
                              "apiGroups": [""], "resources": ["nodes", "nodes/status"] },
                            { "verbs": ["get", "create", "update", "patch"],
                              "apiGroups": ["coordination.k8s.io"], "resources": ["leases"] }
                        ] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-node-high: {e}"))?;
    tracing::info!("seeded FlowSchema: system-node-high");

    // system-nodes — general node requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "system-nodes");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "system-nodes", "uid": "00000000-0000-0000-0000-000000000206",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 500,
            "priorityLevelConfiguration": { "name": "system" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:nodes" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema system-nodes: {e}"))?;
    tracing::info!("seeded FlowSchema: system-nodes");

    // kube-controller-manager — KCM requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-controller-manager");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-controller-manager", "uid": "00000000-0000-0000-0000-000000000207",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 800,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "User", "user": { "name": "system:kube-controller-manager" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-controller-manager: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-controller-manager");

    // kube-scheduler — scheduler requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-scheduler");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-scheduler", "uid": "00000000-0000-0000-0000-000000000208",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 800,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "User", "user": { "name": "system:kube-scheduler" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-scheduler: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-scheduler");

    // kube-system-service-accounts — all service accounts in kube-system
    let key = keys::group_object_key(GROUP, "flowschemas", None, "kube-system-service-accounts");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "kube-system-service-accounts", "uid": "00000000-0000-0000-0000-000000000209",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 900,
            "priorityLevelConfiguration": { "name": "workload-high" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "ServiceAccount",
                                       "serviceAccount": { "name": "*", "namespace": "kube-system" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema kube-system-service-accounts: {e}"))?;
    tracing::info!("seeded FlowSchema: kube-system-service-accounts");

    // service-accounts — all service accounts in all namespaces
    let key = keys::group_object_key(GROUP, "flowschemas", None, "service-accounts");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "service-accounts", "uid": "00000000-0000-0000-0000-000000000210",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 9000,
            "priorityLevelConfiguration": { "name": "workload-low" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:serviceaccounts" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema service-accounts: {e}"))?;
    tracing::info!("seeded FlowSchema: service-accounts");

    // global-default — catch-most for authenticated users
    let key = keys::group_object_key(GROUP, "flowschemas", None, "global-default");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "global-default", "uid": "00000000-0000-0000-0000-000000000211",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 9900,
            "priorityLevelConfiguration": { "name": "global-default" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:authenticated" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema global-default: {e}"))?;
    tracing::info!("seeded FlowSchema: global-default");

    // catch-all — last resort for unauthenticated or unmatched requests
    let key = keys::group_object_key(GROUP, "flowschemas", None, "catch-all");
    let body = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": { "name": "catch-all", "uid": "00000000-0000-0000-0000-000000000212",
                       "creationTimestamp": TS,
                       "annotations": { "apf.kubernetes.io/autoupdate-spec": "true" } },
        "spec": {
            "matchingPrecedence": 10000,
            "priorityLevelConfiguration": { "name": "catch-all" },
            "distinguisherMethod": { "type": "ByUser" },
            "rules": [{ "subjects": [{ "kind": "Group", "group": { "name": "system:unauthenticated" } }],
                        "resourceRules": [{ "verbs": ["*"], "apiGroups": ["*"], "resources": ["*"] }],
                        "nonResourceRules": [{ "verbs": ["*"], "nonResourceURLs": ["*"] }] }]
        },
        "status": { "conditions": [{ "type": "Dangling", "status": "False",
                                      "lastTransitionTime": TS, "reason": "Found",
                                      "message": "This FlowSchema references a valid PriorityLevelConfiguration." }] }
    });
    store
        .put(&key, Bytes::from(body.to_string()), None)
        .await
        .map_err(|e| anyhow::anyhow!("seed FlowSchema catch-all: {e}"))?;
    tracing::info!("seeded FlowSchema: catch-all");

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
            // with_upgrades() is required for HTTP/1.1 WebSocket upgrades (exec/attach/portforward).
            // Without it, hyper sends the 101 Switching Protocols response but never hands the
            // connection off to the upgrade handler — the on_upgrade callback never runs, the
            // splice never starts, and kubectl times out with "unexpected output from server".
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
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
    async fn seed_rbac_seeds_at_least_49_clusterroles() {
        // SubjectAccessReview conformance requires ~80 default ClusterRoles (upstream k8s).
        // We seed a minimum of 49 so that `kubectl get clusterroles | wc -l` shows 50+
        // (49 rows + 1 header). If seed_rbac() is removed or reduced, this count drops
        // to 0 and all RBAC-gated conformance tests fail.
        use u7s_store::{ListOptions, Store};
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // Enumerate all keys under the clusterroles prefix and count them.
        let prefix = keys::group_list_prefix(GROUP, "clusterroles", None);
        let all = store
            .list(&prefix, ListOptions::default())
            .await
            .expect("list must not fail");
        let count = all.items.len();

        assert!(
            count >= 49,
            "seed_rbac must create at least 49 ClusterRoles so that \
             `kubectl get clusterroles | wc -l` shows 50+ (got {count}). \
             SubjectAccessReview conformance fails when default roles are absent."
        );

        // Spot-check the controller roles that KCM sub-controllers depend on.
        for name in [
            "system:controller:deployment-controller",
            "system:controller:replicaset-controller",
            "system:controller:endpoint-controller",
            "system:controller:namespace-controller",
            "system:controller:service-account-controller",
            "system:kube-controller-manager",
            "system:kube-scheduler",
            "cluster-admin",
            "admin",
            "edit",
            "view",
        ] {
            let key = keys::group_object_key(GROUP, "clusterroles", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "ClusterRole '{name}' must exist after seeding — \
                 KCM or scheduler depends on it for authorization"
            );
        }
    }

    #[tokio::test]
    async fn seed_rbac_seeds_discovery_and_public_info_viewer_with_correct_bindings() {
        // The SubjectAccessReview conformance test checks that unauthenticated users
        // can GET /healthz and /livez, and that authenticated users can hit /api and /apis.
        // This requires:
        //   1. ClusterRole system:public-info-viewer bound to system:unauthenticated.
        //   2. ClusterRole system:discovery bound to system:authenticated.
        // Without these, conformance fails with 403 on every health/discovery probe.
        use u7s_store::Store;
        const GROUP: &str = "rbac.authorization.k8s.io";

        let store = make_store();
        seed_rbac(&store).await.expect("seed must not fail");

        // system:public-info-viewer must exist.
        let key = keys::group_object_key(GROUP, "clusterroles", None, "system:public-info-viewer");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRole system:public-info-viewer must exist — needed for unauthenticated /healthz"
        );

        // system:public-info-viewer binding must include system:unauthenticated.
        let key = keys::group_object_key(
            GROUP,
            "clusterrolebindings",
            None,
            "system:public-info-viewer",
        );
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRoleBinding system:public-info-viewer must exist"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        let subjects = crb["subjects"].as_array().expect("subjects must be array");
        let has_unauthenticated = subjects
            .iter()
            .any(|s| s["name"].as_str() == Some("system:unauthenticated"));
        assert!(
            has_unauthenticated,
            "system:public-info-viewer binding must include system:unauthenticated \
             so load-balancer health probes can reach /healthz without credentials"
        );

        // system:discovery must exist.
        let key = keys::group_object_key(GROUP, "clusterroles", None, "system:discovery");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRole system:discovery must exist — needed for authenticated API discovery"
        );

        // system:discovery binding must include system:authenticated.
        let key = keys::group_object_key(GROUP, "clusterrolebindings", None, "system:discovery");
        let obj = store.get(&key).await.expect("get must not fail");
        assert!(
            obj.is_some(),
            "ClusterRoleBinding system:discovery must exist"
        );
        let crb: serde_json::Value =
            serde_json::from_slice(&obj.unwrap().value).expect("valid json");
        let subjects = crb["subjects"].as_array().expect("subjects must be array");
        let has_authenticated = subjects
            .iter()
            .any(|s| s["name"].as_str() == Some("system:authenticated"));
        assert!(
            has_authenticated,
            "system:discovery binding must include system:authenticated \
             so kubectl and other clients can discover the API"
        );
    }

    #[tokio::test]
    async fn seed_flowcontrol_creates_required_default_objects() {
        // The APF conformance test expects default FlowSchemas and PriorityLevelConfigurations
        // to exist on startup. Without them the test times out waiting for FlowSchema status
        // conditions to converge (they reference PLCs that must exist).
        const GROUP: &str = "flowcontrol.apiserver.k8s.io";

        let store = make_store();
        seed_flowcontrol(&store).await.expect("seed must not fail");

        // All 8 default PriorityLevelConfigurations must exist.
        for name in [
            "exempt",
            "catch-all",
            "system",
            "leader-election",
            "workload-high",
            "workload-low",
            "global-default",
            "node-high",
        ] {
            let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "PriorityLevelConfiguration '{name}' must exist — APF FlowSchemas reference it"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(
                parsed["kind"].as_str(),
                Some("PriorityLevelConfiguration"),
                "PriorityLevelConfiguration '{name}' must have correct kind"
            );
            assert_eq!(
                parsed["metadata"]["name"].as_str(),
                Some(name),
                "PriorityLevelConfiguration must have correct name"
            );
        }

        // All 13 default FlowSchemas must exist.
        for name in [
            "exempt",
            "probes",
            "system-leader-election",
            "endpoint-controller",
            "workload-leader-election",
            "system-node-high",
            "system-nodes",
            "kube-controller-manager",
            "kube-scheduler",
            "kube-system-service-accounts",
            "service-accounts",
            "global-default",
            "catch-all",
        ] {
            let key = keys::group_object_key(GROUP, "flowschemas", None, name);
            let obj = store.get(&key).await.expect("get must not fail");
            assert!(
                obj.is_some(),
                "FlowSchema '{name}' must exist — APF conformance test lists and checks these"
            );
            let parsed: serde_json::Value =
                serde_json::from_slice(&obj.unwrap().value).expect("valid json");
            assert_eq!(
                parsed["kind"].as_str(),
                Some("FlowSchema"),
                "FlowSchema '{name}' must have correct kind"
            );
        }
    }

    #[tokio::test]
    async fn seed_flowcontrol_exempt_plc_has_correct_type() {
        // The 'exempt' PriorityLevelConfiguration must have type=Exempt (not Limited).
        // system:masters requests must bypass all queuing; if type=Limited they get queued
        // and the apiserver may deadlock during bootstrap when it needs its own RBAC calls.
        const GROUP: &str = "flowcontrol.apiserver.k8s.io";

        let store = make_store();
        seed_flowcontrol(&store).await.expect("seed must not fail");

        let key = keys::group_object_key(GROUP, "prioritylevelconfigurations", None, "exempt");
        let obj = store.get(&key).await.expect("get must not fail").unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&obj.value).expect("valid json");
        assert_eq!(
            parsed["spec"]["type"].as_str(),
            Some("Exempt"),
            "exempt PriorityLevelConfiguration must have type=Exempt so system:masters requests bypass queuing"
        );
    }

    #[tokio::test]
    async fn seed_flowcontrol_is_idempotent() {
        // Unconditional puts must not fail on a second call.
        let store = make_store();
        seed_flowcontrol(&store)
            .await
            .expect("first seed must not fail");
        seed_flowcontrol(&store)
            .await
            .expect("second seed must not fail");
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

        // A kubelet in system:nodes must be able to create SubjectAccessReviews so its
        // webhook authorizer can call back to the apiserver (needed for logs/exec/attach).
        let sar_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "authorization.k8s.io",
            resource: "subjectaccessreviews",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&sar_create),
            "system:nodes must be allowed to create subjectaccessreviews — \
             kubelet webhook authorizer calls back to the apiserver for proxy requests (logs/exec/attach)"
        );

        // A kubelet in system:nodes must be able to create TokenReviews so its
        // webhook authenticator can validate bearer tokens.
        let tr_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "authentication.k8s.io",
            resource: "tokenreviews",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&tr_create),
            "system:nodes must be allowed to create tokenreviews — \
             kubelet webhook authenticator calls back to the apiserver"
        );

        // Regression test for mayor-7vbe: kubelet must be allowed to POST
        // /api/v1/namespaces/{ns}/serviceaccounts/{name}/token (TokenRequest subresource).
        // Without this rule the projected SA token volume never gets populated —
        // the kubelet's POST returns 403 and containers never receive an SA token,
        // breaking all in-cluster API calls.
        let sa_token_create = rbac::AuthzRequest {
            username: "system:node:my-node",
            groups: &groups,
            verb: "create",
            api_group: "",
            resource: "serviceaccounts",
            subresource: "token",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        };
        assert!(
            state.rbac_index.is_allowed(&sa_token_create),
            "system:nodes must be allowed to create serviceaccounts/token — \
             kubelet needs this to project SA tokens into pod volumes (mayor-7vbe)"
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

    /// seed_services must also create the 'kubernetes' Endpoints object in the default namespace.
    ///
    /// Controllers such as the endpoint controller and some admission webhooks watch this
    /// object to locate the apiserver IP/port. Without it they log errors on startup and
    /// may refuse to start. The corresponding Service (default/kubernetes) alone is not enough
    /// because older controllers resolve the apiserver address via Endpoints, not EndpointSlices.
    #[tokio::test]
    async fn seed_services_creates_kubernetes_endpoints() {
        let store = make_store();
        seed_namespaces(&store)
            .await
            .expect("namespaces must be seeded first");
        seed_services(&store).await.expect("seed must not fail");

        let ep_key = keys::object_key("endpoints", "default", "kubernetes");
        let ep_obj = store.get(&ep_key).await.expect("get must not fail");
        assert!(
            ep_obj.is_some(),
            "Endpoints default/kubernetes must exist after seeding — \
             controllers watch this object to locate the apiserver; \
             without it they log errors and may fail to start"
        );
        let ep: serde_json::Value =
            serde_json::from_slice(&ep_obj.unwrap().value).expect("valid json");
        assert_eq!(ep["kind"].as_str(), Some("Endpoints"));
        assert_eq!(ep["metadata"]["name"].as_str(), Some("kubernetes"));
        assert_eq!(ep["metadata"]["namespace"].as_str(), Some("default"));
        let subsets = ep["subsets"].as_array().expect("subsets must be an array");
        assert!(
            !subsets.is_empty(),
            "Endpoints must have at least one subset"
        );
        let addresses = subsets[0]["addresses"]
            .as_array()
            .expect("addresses must be an array");
        assert!(
            !addresses.is_empty(),
            "subset must have at least one address"
        );
        let ip = addresses[0]["ip"].as_str().unwrap_or("");
        assert!(!ip.is_empty(), "endpoint address must have a non-empty IP");
        let ports = subsets[0]["ports"]
            .as_array()
            .expect("ports must be an array");
        assert!(!ports.is_empty(), "subset must have at least one port");
        assert_eq!(
            ports[0]["port"].as_u64(),
            Some(443),
            "kubernetes Endpoints must expose port 443 — apiserver HTTPS port"
        );
        assert_eq!(
            ports[0]["protocol"].as_str(),
            Some("TCP"),
            "kubernetes Endpoints port must be TCP"
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

    /// GET /openapi/v2 and /openapi/v3 must return 200 (not 403) without credentials.
    ///
    /// Conformance tests poll these endpoints after creating a CRD to wait for the CRD
    /// schema to appear. The test client sends unauthenticated requests (no Bearer token,
    /// no client cert). If auth is required, anonymous users get 403 Forbidden and the
    /// test times out with "failed to wait for OpenAPI spec validating condition: unexpected
    /// response: 403". kube-apiserver serves these endpoints to unauthenticated callers.
    ///
    /// This test fails if the auth exemption for /openapi/v2 and /openapi/v3 is removed.
    #[tokio::test]
    async fn openapi_endpoints_return_200_without_credentials() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let store = std::sync::Arc::new(make_store());
        let state = state::AppState::new(
            std::sync::Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Build router with AuthLayer — this is the same stack as production.
        // Without the auth exemption for /openapi/v*, the anonymous request would
        // produce 403 Forbidden because system:anonymous has no RBAC grants.
        let app = build_router(state.clone()).layer(AuthLayer::new(
            std::sync::Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_decoding_key.clone(),
        ));

        for path in ["/openapi/v2", "/openapi/v3"] {
            // No Authorization header — anonymous request, like the conformance test client.
            let req = Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request build must not fail");
            let resp = app
                .clone()
                .oneshot(req)
                .await
                .expect("router must not error");
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{path} must return 200 OK for unauthenticated requests — \
                 conformance tests poll this without credentials after CRD creation; \
                 403 causes 'failed to wait for OpenAPI spec validating condition: \
                 unexpected response: 403'"
            );
        }
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
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
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

    /// POST /apis/storage.k8s.io/v1/storageclasses with proto body must return non-empty JSON.
    ///
    /// kubectl sends StorageClass with Content-Type: application/vnd.kubernetes.protobuf.
    /// Previously, decode_core_proto_by_kind returned None for "StorageClass", extract_body
    /// returned the raw proto bytes unchanged, Object::from_bytes failed with
    /// "invalid JSON: expected value at line 1 column 1", and the handler returned HTTP 400.
    /// The Go client then received a proper Status error body but the CREATE had failed,
    /// causing all StorageClasses e2e lifecycle tests to fail.
    ///
    /// This test fails if the StorageClass proto decoder is removed from decode_core_proto_by_kind:
    /// create_resource will return Err(Status::bad_request("invalid JSON: ...")) and the test
    /// assertion `create_result.is_ok()` will fail.
    #[tokio::test]
    async fn storageclass_create_via_proto_returns_non_empty_response() {
        use std::sync::Arc;

        // Proto encoding helpers (self-contained — no dependency on proto.rs test-only functions).
        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field_number << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // Build: StorageClass { metadata: ObjectMeta { name: "proto-fast" } }
        let mut obj_meta = encode_ld(1, b"proto-fast"); // ObjectMeta.name (field 1)
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // ObjectMeta.creationTimestamp (field 8, empty Time)
        let storageclass_proto = encode_ld(1, &obj_meta); // StorageClass.metadata (field 1)

        // Build the k8s proto envelope: magic + Unknown{TypeMeta, raw, no contentType}
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"storage.k8s.io/v1"); // TypeMeta.apiVersion
        type_meta.extend_from_slice(&encode_ld(2, b"StorageClass")); // TypeMeta.kind
        let mut unknown = encode_ld(1, &type_meta); // Unknown.TypeMeta (field 1)
        unknown.extend_from_slice(&encode_ld(2, &storageclass_proto)); // Unknown.raw (field 2)
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/vnd.kubernetes.protobuf"),
        );

        // POST with proto body — must succeed (not return 400 "invalid JSON").
        let create_result = handlers::resource::create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "storage.k8s.io".to_string(),
                "v1".to_string(),
                "storageclasses".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            axum::Extension(auth::UserInfo {
                username: "admin".into(),
                uid: "".into(),
                groups: vec!["system:masters".into()],
            }),
            headers,
            bytes::Bytes::from(proto_body),
        )
        .await;

        assert!(
            create_result.is_ok(),
            "POST /apis/storage.k8s.io/v1/storageclasses with proto body must succeed — \
             before the fix, decode_core_proto_by_kind returned None for 'StorageClass', \
             extract_body returned raw proto bytes, and the handler returned \
             HTTP 400 'invalid JSON: expected value at line 1 column 1'"
        );
    }

    /// POST /apis/flowcontrol.apiserver.k8s.io/v1/flowschemas with a proto body must return 201.
    ///
    /// The API priority and fairness conformance test sends FlowSchema with
    /// Content-Type: application/vnd.kubernetes.protobuf. Before the fix,
    /// decode_core_proto_by_kind returned None for "FlowSchema", extract_body returned raw
    /// proto bytes, and the handler returned HTTP 400 "invalid JSON: expected value at line 1
    /// column 1". This test fails if the FlowSchema proto decoder is removed.
    #[tokio::test]
    async fn flowschema_create_via_proto_returns_201() {
        use std::sync::Arc;

        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field_number: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field_number << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // Build: FlowSchema { metadata: ObjectMeta { name: "catch-all" } }
        let meta_bytes = encode_ld(1, b"catch-all"); // ObjectMeta.name (field 1)
        let flowschema_proto = encode_ld(1, &meta_bytes); // FlowSchema.metadata (field 1)

        // Build the k8s proto envelope: magic + Unknown{TypeMeta, raw, no contentType}
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"flowcontrol.apiserver.k8s.io/v1"); // TypeMeta.apiVersion
        type_meta.extend_from_slice(&encode_ld(2, b"FlowSchema")); // TypeMeta.kind
        let mut unknown = encode_ld(1, &type_meta); // Unknown.TypeMeta (field 1)
        unknown.extend_from_slice(&encode_ld(2, &flowschema_proto)); // Unknown.raw (field 2)
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let store = Arc::new(make_store());
        let state = state::AppState::new(
            Arc::clone(&store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/vnd.kubernetes.protobuf"),
        );

        let create_result = handlers::resource::create_resource(
            axum::extract::State(state),
            axum::extract::Path((
                "flowcontrol.apiserver.k8s.io".to_string(),
                "v1".to_string(),
                "flowschemas".to_string(),
            )),
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
            axum::Extension(auth::UserInfo {
                username: "admin".into(),
                uid: "".into(),
                groups: vec!["system:masters".into()],
            }),
            headers,
            bytes::Bytes::from(proto_body),
        )
        .await;

        assert!(
            create_result.is_ok(),
            "POST /apis/flowcontrol.apiserver.k8s.io/v1/flowschemas with proto body must \
             return 201 — before the fix, decode_core_proto_by_kind returned None for \
             'FlowSchema', extract_body returned raw proto bytes, and the handler returned \
             HTTP 400 'invalid JSON: expected value at line 1 column 1'"
        );
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
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
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
            axum::extract::Query(handlers::json_patch::CreateQuery::default()),
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

    /// GET /apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices must return an empty list,
    /// not 404, for a namespace that has no EndpointSlices yet.
    ///
    /// KCM's endpointslice-controller opens a LIST+WATCH on this path at startup. If the
    /// resource is unregistered the generic handler falls through to the CR handler which
    /// returns 404 (no CRD installed), causing the controller to enter exponential back-off
    /// and log "failed to list *v1.EndpointSlice: Resource not found" every ~45 s.
    #[tokio::test]
    async fn endpointslice_list_returns_empty_for_new_namespace() {
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

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/apis/discovery.k8s.io/v1/namespaces/default/endpointslices")
            .body(axum::body::Body::empty())
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_ne!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET /apis/discovery.k8s.io/v1/namespaces/default/endpointslices must not return 404 — \
             KCM's endpointslice-controller lists this path at startup; 404 causes log-spam back-off"
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "empty namespace must return 200 with an empty EndpointSliceList"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(
            val["kind"], "EndpointSliceList",
            "response kind must be EndpointSliceList — client-go informer requires this exact kind"
        );
        let items = val["items"].as_array().expect("items must be an array");
        assert!(
            items.is_empty(),
            "items must be empty for a namespace with no EndpointSlices"
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
        state::AppState::new_with_config(state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: None,
            webhook_identity_pem: None,
            service_ip_allocator: Some(alloc),
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            continue_token_key: None,
        })
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

    /// DELETE /api/v1/persistentvolumes/{name} must not return 405 MethodNotAllowed.
    ///
    /// PersistentVolumes are cluster-scoped (no namespace). The CSI conformance test
    /// creates a PV and then deletes it via DELETE /api/v1/persistentvolumes/{name}.
    /// Without the DELETE verb registered on the cluster-scoped named-resource route,
    /// axum returns 405 and the conformance test fails.
    ///
    /// This test fails (405) if the .delete(core_delete_resource) call is removed from
    /// the /api/v1/{resource}/{name} route in build_router.
    #[tokio::test]
    async fn persistent_volume_delete_returns_non_405() {
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

        let admin = auth::UserInfo {
            username: "admin".to_string(),
            uid: String::new(),
            groups: vec!["system:masters".to_string()],
        };

        // Create a PersistentVolume so the DELETE has something to act on.
        let pv_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": { "name": "test-pv" },
            "spec": {
                "capacity": { "storage": "1Gi" },
                "accessModes": ["ReadWriteOnce"],
                "hostPath": { "path": "/tmp/pv" }
            }
        });
        let mut create_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/persistentvolumes")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(pv_body.to_string()))
            .expect("POST request must build");
        create_req.extensions_mut().insert(admin.clone());
        let create_resp = router
            .call(create_req)
            .await
            .expect("router must not error on POST");
        assert_eq!(
            create_resp.status(),
            StatusCode::CREATED,
            "PersistentVolume POST must return 201 before we can test DELETE"
        );
        // Drain body to reclaim connection.
        let _ = to_bytes(create_resp.into_body(), 4096).await;

        // DELETE the PersistentVolume — must not return 405 MethodNotAllowed.
        // Before the fix: build_router omitted .delete() on /api/v1/{resource}/{name},
        // causing axum to return 405 because the path matched but DELETE was unregistered.
        let mut delete_req = Request::builder()
            .method(Method::DELETE)
            .uri("/api/v1/persistentvolumes/test-pv")
            .body(axum::body::Body::empty())
            .expect("DELETE request must build");
        delete_req.extensions_mut().insert(admin);
        let delete_resp = router
            .call(delete_req)
            .await
            .expect("router must not error on DELETE");
        let delete_status = delete_resp.status();
        assert_ne!(
            delete_status,
            StatusCode::METHOD_NOT_ALLOWED,
            "DELETE /api/v1/persistentvolumes/test-pv must not return 405 — \
             the CSI conformance test deletes PVs after the lifecycle test and \
             a 405 here means the route is not registered"
        );
        assert!(
            delete_status.is_success(),
            "DELETE /api/v1/persistentvolumes/test-pv must succeed (2xx), got {delete_status}"
        );
    }

    /// POST /api/v1/namespaces/default/secrets with a JSON body must return 201 Created.
    ///
    /// Regression test for mayor-l6u0: Secret creates returned HTTP 400
    /// "invalid JSON: expected value at line 1 column 1".  The conformance suite
    /// (webhook.go:1075 BeforeEach, secrets.go) creates Secrets via client-go which
    /// sends proto-encoded bodies.  This test verifies the JSON path also works — a
    /// broken JSON path means the server cannot accept Secrets from any client.
    ///
    /// Failing case: if the resource is not in the registry, create_namespaced_resource
    /// delegates to the CR handler, which falls through to 404.  If the proto decoder
    /// returns None, extract_body returns raw proto bytes and Object::from_bytes fails
    /// with "invalid JSON".  Both would break all ~31 webhook and secret-volume
    /// conformance tests that depend on Secret creation.
    #[tokio::test]
    async fn secret_create_json_returns_201() {
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

        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "sample-webhook-secret", "namespace": "default" },
            "type": "Opaque",
            "data": { "key": "dmFsdWU=" }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/secrets")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request build must not fail");

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /api/v1/namespaces/default/secrets must return 201 — \
             before the fix, Secret was not in the registry or the decode path was broken, \
             causing HTTP 400 'invalid JSON' which breaks all ~31 webhook conformance tests \
             that create sample-webhook-secret in BeforeEach"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Secret");
        assert_eq!(v["metadata"]["name"], "sample-webhook-secret");
    }

    /// POST /apis/batch/v1/namespaces/default/jobs with a JSON body must return 201 Created.
    ///
    /// Regression test for mayor-np42: batch/v1 Job creates returned HTTP 400
    /// "invalid JSON: expected value at line 1 column 1".  The conformance suite
    /// (job.go:502, job.go:621) creates Jobs via client-go which sends proto-encoded bodies.
    /// This test verifies the JSON path works — a broken JSON path means the server cannot
    /// accept Jobs from any client and all 6 Job/CronJob conformance tests fail immediately.
    #[tokio::test]
    async fn job_create_json_via_router_returns_201() {
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

        let body = serde_json::json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "ci-job", "namespace": "default" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{ "name": "test", "image": "busybox" }],
                        "restartPolicy": "Never"
                    }
                }
            }
        });

        let req = Request::builder()
            .method("POST")
            .uri("/apis/batch/v1/namespaces/default/jobs")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request build must not fail");

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /apis/batch/v1/namespaces/default/jobs must return 201 — \
             before the fix, batch/v1 Job was not in the registry or the decode path was \
             broken, causing HTTP 400 'invalid JSON' which breaks all Job conformance tests"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Job");
        assert_eq!(v["metadata"]["name"], "ci-job");
    }

    /// POST /api/v1/namespaces/default/secrets with a proto-encoded body must return 201.
    ///
    /// Regression test for mayor-l6u0: the conformance client sends Secrets with
    /// Content-Type: application/vnd.kubernetes.protobuf.  If decode_secret_proto returns
    /// None for any reason, extract_body falls back to returning the raw proto bytes, and
    /// Object::from_bytes fails with "invalid JSON: expected value at line 1 column 1".
    ///
    /// This test fails if:
    ///   - decode_secret_proto is removed from decode_core_proto_by_kind
    ///   - Secret::decode fails for a valid proto-encoded secret
    ///   - The proto envelope is not recognised (magic check fails)
    #[tokio::test]
    async fn secret_create_proto_returns_201() {
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

        // Build proto-encoded Secret.
        // Helpers (identical to those in util::tests — kept local to avoid test coupling).
        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }

        // ObjectMeta { name: "proto-secret", namespace: "default", creationTimestamp: Time{} }
        let mut obj_meta = encode_ld(1, b"proto-secret");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // empty Time{}

        // Secret { metadata (field 1), type (field 3) }
        // type is wire field 3 per the official k8s proto definition.
        let mut secret_proto = encode_ld(1, &obj_meta);
        secret_proto.extend_from_slice(&encode_ld(3, b"Opaque"));

        // k8s Unknown envelope
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"v1");
        type_meta.extend_from_slice(&encode_ld(2, b"Secret"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &secret_proto));
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/namespaces/default/secrets")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(axum::body::Body::from(proto_body))
            .expect("request build must not fail");

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /api/v1/namespaces/default/secrets with proto body must return 201 — \
             the conformance client sends Secrets as proto; if decode_secret_proto returns None \
             extract_body returns raw proto bytes causing 'invalid JSON: expected value at \
             line 1 column 1', breaking all ~31 webhook/secret-volume conformance tests"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "Secret", "response kind must be Secret");
        assert_eq!(v["metadata"]["name"], "proto-secret");
    }

    /// POST /apis/batch/v1/namespaces/default/cronjobs with a proto-encoded body must return 201.
    ///
    /// Regression test for mayor-np42: the conformance client (cronjob.go:106) creates CronJobs
    /// with Content-Type: application/vnd.kubernetes.protobuf.  If decode_cronjob_proto returns
    /// None, extract_body returns raw proto bytes and Object::from_bytes fails with
    /// "invalid JSON: expected value at line 1 column 1".
    ///
    /// This test fails if:
    ///   - decode_cronjob_proto is removed from decode_core_proto_by_kind
    ///   - CronJob::decode fails for a suspended CronJob proto (the exact conformance scenario)
    ///   - The batch/v1 group is not in the resource registry
    #[tokio::test]
    async fn cronjob_create_proto_suspended_returns_201() {
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

        fn encode_varint(mut v: u64) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let byte = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
            let tag = (field << 3) | 2;
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(payload.len() as u64));
            out.extend_from_slice(payload);
            out
        }
        fn encode_varint_field(field: u64, value: u64) -> Vec<u8> {
            let tag = field << 3; // wire type 0
            let mut out = encode_varint(tag);
            out.extend_from_slice(&encode_varint(value));
            out
        }

        // ObjectMeta { name: "test-suspended-cj", namespace: "default" }
        let mut obj_meta = encode_ld(1, b"test-suspended-cj");
        obj_meta.extend_from_slice(&encode_ld(3, b"default"));
        obj_meta.extend_from_slice(&encode_ld(8, &[])); // creationTimestamp

        // JobSpec { backoffLimit: 6 (field 6, wire type 0 = varint) }
        let job_spec = encode_varint_field(6, 6); // backoffLimit = 6

        // JobTemplateSpec sub-message bytes: field 2 = spec (JobSpec)
        // jt_bytes IS the complete sub-message content for JobTemplateSpec
        let jt_bytes = encode_ld(2, &job_spec); // field 2 of JobTemplateSpec = spec = job_spec

        // CronJobSpec { schedule (1), concurrencyPolicy (3), suspend=true (4), jobTemplate (5) }
        let mut cj_spec = encode_ld(1, b"*/5 * * * *"); // schedule
        cj_spec.extend_from_slice(&encode_ld(3, b"Allow")); // concurrencyPolicy
        cj_spec.extend_from_slice(&encode_varint_field(4, 1)); // suspend = true (field 4, wire type 0)
        cj_spec.extend_from_slice(&encode_ld(5, &jt_bytes)); // jobTemplate field 5 = JobTemplateSpec

        // CronJob { metadata (1), spec (2) }
        let mut cj_proto = encode_ld(1, &obj_meta);
        cj_proto.extend_from_slice(&encode_ld(2, &cj_spec));

        // k8s Unknown envelope
        const MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];
        let mut type_meta = encode_ld(1, b"batch/v1");
        type_meta.extend_from_slice(&encode_ld(2, b"CronJob"));
        let mut unknown = encode_ld(1, &type_meta);
        unknown.extend_from_slice(&encode_ld(2, &cj_proto));
        let mut proto_body = MAGIC.to_vec();
        proto_body.extend_from_slice(&unknown);

        let req = Request::builder()
            .method("POST")
            .uri("/apis/batch/v1/namespaces/default/cronjobs")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(axum::body::Body::from(proto_body))
            .expect("request build must not fail");

        let resp = router.call(req).await.expect("router must not error");
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "POST /apis/batch/v1/namespaces/default/cronjobs with proto body (suspend=true) \
             must return 201 — the conformance client at cronjob.go:106 creates a suspended \
             CronJob via proto; if decode_cronjob_proto returns None for this input, \
             extract_body returns raw proto bytes causing HTTP 400 'invalid JSON'"
        );

        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&resp_body).expect("response must be JSON");
        assert_eq!(v["kind"], "CronJob", "response kind must be CronJob");
        assert_eq!(v["metadata"]["name"], "test-suspended-cj");
        assert_eq!(
            v["spec"]["schedule"], "*/5 * * * *",
            "schedule must survive proto decode"
        );
        assert_eq!(
            v["spec"]["suspend"], true,
            "suspend=true must survive proto decode — this is the exact conformance scenario"
        );
    }

    /// GET /apis/flowcontrol.apiserver.k8s.io must return 200 with kind=APIGroup.
    ///
    /// The API priority and fairness conformance test discovers the group via GET /apis,
    /// then probes GET /apis/flowcontrol.apiserver.k8s.io. Before the fix, no route existed
    /// for /apis/{group} and the request returned 404, causing the conformance test to fail
    /// with "expected flowcontrol API group". This test fails if the /apis/{group} route is removed.
    #[tokio::test]
    async fn get_flowcontrol_api_group_route_returns_200() {
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

        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/apis/flowcontrol.apiserver.k8s.io")
            .body(axum::body::Body::empty())
            .expect("request must build");
        req.extensions_mut().insert(auth::UserInfo {
            username: "test".into(),
            uid: String::new(),
            groups: vec![],
        });
        let resp = router.call(req).await.expect("router must not error");

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /apis/flowcontrol.apiserver.k8s.io must return 200 — \
             the conformance test probes this endpoint after discovering the group in /apis; \
             404 causes the API priority and fairness test to abort"
        );

        let body = to_bytes(resp.into_body(), 4096)
            .await
            .expect("body collect must not fail");
        let val: serde_json::Value = serde_json::from_slice(&body).expect("response must be JSON");
        assert_eq!(
            val["kind"], "APIGroup",
            "response must have kind=APIGroup — clients use this to discover the preferred version"
        );
        assert_eq!(val["name"], "flowcontrol.apiserver.k8s.io");
    }

    // -----------------------------------------------------------------------
    // serve_connection with_upgrades regression test
    //
    // Without with_upgrades(), hyper's HTTP/1.1 server sends the 101 Switching
    // Protocols response but never hands the connection off to the upgrade
    // handler. The on_upgrade callback never runs, the WebSocket splice never
    // starts, and kubectl times out with "unexpected output from server".
    //
    // This test fails if with_upgrades() is removed from serve_connection:
    // the WebSocket client sends a message and expects to read it back, but
    // without with_upgrades() the echo handler never runs — the recv() blocks
    // and the timeout fires.
    // -----------------------------------------------------------------------

    /// serve_connection().with_upgrades() must allow WebSocket upgrade handlers to run.
    ///
    /// This is the regression test for the exec "unexpected output from server" bug.
    /// When with_upgrades() was absent from serve_connection(), hyper sent 101 but
    /// never drove the upgrade — the on_upgrade closure never ran, the splice was
    /// never started, and kubectl timed out at 60s with no output.
    ///
    /// This test MUST fail if with_upgrades() is removed: the WebSocket client will
    /// connect (101 received) but recv() will block indefinitely because the echo
    /// handler never runs, causing the 2-second timeout to fire.
    #[tokio::test]
    async fn serve_connection_with_upgrades_allows_websocket_handler_to_run() {
        use axum::{
            extract::ws::{WebSocket, WebSocketUpgrade},
            routing::get,
            Router,
        };
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest as _};

        // Build an axum router with a single WebSocket echo endpoint.
        let app = Router::new().route(
            "/ws",
            get(|ws: WebSocketUpgrade| async {
                ws.on_upgrade(|mut socket: WebSocket| async move {
                    // Echo one message back and close.
                    if let Some(Ok(msg)) = socket.recv().await {
                        let _ = socket.send(msg).await;
                    }
                })
            }),
        );

        // Bind a real TCP listener on a random port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the server using our serve_connection pattern WITH with_upgrades().
        // This mirrors what serve_tls() does (minus TLS) and is the exact code path
        // that had the missing with_upgrades() bug.
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(tcp);
            let service = hyper::service::service_fn(move |req| {
                let mut app = app.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        tower_service::Service::call(&mut app, req).await.unwrap(),
                    )
                }
            });
            // with_upgrades() is the fix — removing it causes this test to fail
            // because the on_upgrade closure never runs and the client recv() blocks.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await;
        });

        // Connect a WebSocket client and exchange one message.
        let url = format!("ws://{addr}/ws");
        let request = url.into_client_request().unwrap();
        let (mut ws, _) = connect_async(request)
            .await
            .expect("WebSocket connect must succeed");

        let payload = b"hello from websocket";
        ws.send(tokio_tungstenite::tungstenite::Message::Binary(
            payload.to_vec().into(),
        ))
        .await
        .expect("send must succeed");

        // The echo handler must reply within 2 seconds.
        // Without with_upgrades(), the handler never runs and this times out.
        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect(
                "WebSocket reply must arrive within 2s — if it times out, \
                 with_upgrades() is missing from serve_connection() and the \
                 on_upgrade callback never runs",
            )
            .expect("stream must not end without a reply")
            .expect("WebSocket recv must not error");

        match reply {
            tokio_tungstenite::tungstenite::Message::Binary(b) => {
                assert_eq!(
                    b.as_ref(),
                    payload,
                    "echoed bytes must match sent bytes — \
                     a mismatch means the upgrade handler ran but data was corrupted"
                );
            }
            other => {
                panic!(
                    "expected Binary frame with echo, got {other:?} — \
                     the WebSocket upgrade handler must echo the sent message"
                );
            }
        }
    }
}
