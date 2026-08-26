/// u7s-scheduler — thin binary shell around `u7s_scheduler::run_scheduler`, the
/// scheduler's actual watch/schedule loop (see `run.rs` for the algorithm doc).
///
/// Kept as a standalone binary — not deprecated by `u7s-apiserver`'s
/// `--embedded-scheduler` — for the independent-restart use case: an
/// operator who wants restarting the apiserver to NOT also interrupt in-flight
/// scheduling still runs this binary against `--embedded-scheduler false`.
use clap::Parser;
use tracing::info;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    if args.leader_elect {
        info!("--leader-elect flag set; leader election is not implemented, running as leader");
    }

    u7s_scheduler::run_scheduler(&args.kubeconfig, args.server.as_deref()).await
}
