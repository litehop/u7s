/// u7s-scheduler — minimal scheduler scaffold.
///
/// Watches unscheduled pods (spec.nodeName absent) cluster-wide
/// via a long-poll watch on the API server, picks the first available node,
/// and binds via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// No leader election logic is implemented; the --leader-elect flag is
/// accepted and silently ignored.
use clap::Parser;
use tracing::{error, info};
use u7s_client_util::{build_tls_connector, parse_kubeconfig};
use u7s_scheduler::{bind_pod, needs_scheduling, pick_node, stream_watch_events};

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
