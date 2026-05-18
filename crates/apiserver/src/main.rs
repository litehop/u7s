mod handlers;
mod keys;
mod state;
mod status;
mod tls;
mod types;

use std::sync::Arc;

use axum::{Router, routing::get};
use tower_service::Service;
use clap::Parser;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use u7s_store::SqliteStore;

use state::AppState;
use tls::{generate_tls, write_kubeconfig};

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

    // 6. Build axum router.
    let app = build_router(Arc::clone(&store));

    // 7. Bind TLS listener and serve.
    let listener = TcpListener::bind(&args.listen).await?;
    serve_tls(listener, app, tls_material.server_config).await?;
    Ok(())
}

fn build_router(store: Arc<SqliteStore>) -> Router {

    let state = AppState::new(store);

    Router::new()
        // Core discovery
        .route("/api",    get(handlers::discovery::api_versions))
        .route("/api/v1", get(handlers::discovery::api_v1_resources))

        // Non-core group discovery
        .route("/apis",                    get(handlers::discovery::api_group_list))
        .route("/apis/:group/:version",    get(handlers::discovery::api_group_resources))

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
