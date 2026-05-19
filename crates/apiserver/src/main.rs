mod auth;
mod handlers;
mod keys;
mod patch;
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

use auth::AuthLayer;
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

    // 4. Generate TLS certs.
    let tls_material = generate_tls(&args)?;

    // 5. Write kubeconfig.
    write_kubeconfig(&args.kubeconfig, &tls_material)?;

    // 6. Load optional static token map.
    let token_map = match &args.token_auth_file {
        Some(path) => {
            tracing::info!("loading token auth file: {path}");
            auth::load_token_file(path)?
        }
        None => std::collections::HashMap::new(),
    };

    // 7. Load or generate the SA signing key.
    let sa_encoding_key = match load_or_generate_sa_keys(&args.sa_key, &args.sa_pub) {
        Ok(sa_keys) => {
            match jsonwebtoken::EncodingKey::from_rsa_pem(&sa_keys.private_key_pem) {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::error!("failed to load SA signing key: {e}");
                    None
                }
            }
        }
        Err(e) => {
            tracing::error!("SA key gen/load failed: {e}");
            None
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
    let state = AppState::new(Arc::clone(&store), sa_encoding_key, server_address);

    // 9a. Populate RBAC index from persisted objects before serving.
    state.init().await;

    // 10. Build axum router and attach the auth tower layer.
    let app = build_router(state.clone())
        .layer(AuthLayer::new(Arc::clone(&state.rbac_index), token_map));

    // 11. Bind TLS listener and serve.
    let listener = TcpListener::bind(&args.listen).await?;
    serve_tls(listener, app, tls_material.server_config).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        // Core discovery
        .route("/api",    get(handlers::discovery::api_versions))
        .route("/api/v1", get(handlers::discovery::api_v1_resources))

        // Non-core group discovery
        .route("/apis",                    get(handlers::discovery::api_group_list))
        .route("/apis/:group/:version",    get(handlers::discovery::api_group_resources))

        // Namespaces — collection
        .route(
            "/api/v1/namespaces",
            get(handlers::namespaces::list_namespaces).post(handlers::namespaces::create_namespace),
        )

        // Namespaces — named resource
        .route(
            "/api/v1/namespaces/:name",
            get(handlers::namespaces::get_namespace)
                .put(handlers::namespaces::replace_namespace)
                .patch(handlers::namespaces::patch_namespace)
                .delete(handlers::namespaces::delete_namespace),
        )

        // Pods — collection
        .route(
            "/api/v1/namespaces/:ns/pods",
            get(handlers::pods::list_pods).post(handlers::pods::create_pod),
        )

        // Pods — named resource
        .route(
            "/api/v1/namespaces/:ns/pods/:name",
            get(handlers::pods::get_pod)
                .put(handlers::pods::replace_pod)
                .delete(handlers::pods::delete_pod)
                .patch(handlers::pods::patch_pod),
        )

        // Pods — binding subresource (scheduler write path)
        .route(
            "/api/v1/namespaces/:ns/pods/:name/binding",
            axum::routing::post(handlers::pods::bind_pod),
        )

        // Core group (group="", apiVersion=v1) — cluster-scoped resources (e.g. nodes)
        .route(
            "/api/v1/:resource",
            get(handlers::generic::core_list_resource)
                .post(handlers::generic::core_create_resource),
        )

        // Core group — cluster-scoped named resource
        .route(
            "/api/v1/:resource/:name",
            get(handlers::generic::core_get_resource)
                .put(handlers::generic::core_replace_resource)
                .delete(handlers::generic::core_delete_resource)
                .patch(handlers::generic::core_patch_resource),
        )

        // Core group — cluster-scoped status subresource
        .route(
            "/api/v1/:resource/:name/status",
            get(handlers::generic::core_get_resource_status)
                .put(handlers::generic::core_put_resource_status)
                .patch(handlers::generic::core_patch_resource_status),
        )

        // Core group — namespaced resources collection (e.g. services, configmaps)
        .route(
            "/api/v1/namespaces/:ns/:resource",
            get(handlers::generic::core_list_namespaced_resource)
                .post(handlers::generic::core_create_namespaced_resource),
        )

        // Core group — namespaced named resource
        .route(
            "/api/v1/namespaces/:ns/:resource/:name",
            get(handlers::generic::core_get_namespaced_resource)
                .put(handlers::generic::core_replace_namespaced_resource)
                .delete(handlers::generic::core_delete_namespaced_resource)
                .patch(handlers::generic::core_patch_namespaced_resource),
        )

        // Core group — namespaced status subresource
        .route(
            "/api/v1/namespaces/:ns/:resource/:name/status",
            get(handlers::generic::core_get_namespaced_resource_status)
                .put(handlers::generic::core_put_namespaced_resource_status)
                .patch(handlers::generic::core_patch_namespaced_resource_status),
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

        // ServiceAccounts — token subresource (TokenRequest API)
        .route(
            "/api/v1/namespaces/:ns/serviceaccounts/:name/token",
            axum::routing::post(handlers::tokens::create_token),
        )

        // Generic cluster-scoped resources — collection
        .route(
            "/apis/:group/:version/:resource",
            get(handlers::generic::list_resource)
                .post(handlers::generic::create_resource),
        )

        // Generic cluster-scoped resources — named
        .route(
            "/apis/:group/:version/:resource/:name",
            get(handlers::generic::get_resource)
                .put(handlers::generic::replace_resource)
                .delete(handlers::generic::delete_resource)
                .patch(handlers::generic::patch_resource),
        )

        // Generic namespaced resources — collection
        .route(
            "/apis/:group/:version/namespaces/:ns/:resource",
            get(handlers::generic::list_namespaced_resource)
                .post(handlers::generic::create_namespaced_resource),
        )

        // Generic namespaced resources — named
        .route(
            "/apis/:group/:version/namespaces/:ns/:resource/:name",
            get(handlers::generic::get_namespaced_resource)
                .put(handlers::generic::replace_namespaced_resource)
                .delete(handlers::generic::delete_namespaced_resource)
                .patch(handlers::generic::patch_namespaced_resource),
        )

        // Generic cluster-scoped — status subresource
        .route(
            "/apis/:group/:version/:resource/:name/status",
            get(handlers::generic::get_resource_status)
                .put(handlers::generic::put_resource_status)
                .patch(handlers::generic::patch_resource_status),
        )

        // Generic namespaced — status subresource
        .route(
            "/apis/:group/:version/namespaces/:ns/:resource/:name/status",
            get(handlers::generic::get_namespaced_resource_status)
                .put(handlers::generic::put_namespaced_resource_status)
                .patch(handlers::generic::patch_namespaced_resource_status),
        )

        .with_state(state)
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
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service = hyper::service::service_fn(move |req| {
                let mut app = app.clone();
                async move { Ok::<_, std::convert::Infallible>(app.call(req).await.unwrap()) }
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
