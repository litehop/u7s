/// u7s-controller-manager — minimal SA token provisioning controller.
///
/// Watches ServiceAccount objects via a long-poll watch on the API server.
/// For each ADDED event, mints a JWT via the token endpoint and stores it
/// in a Secret of type kubernetes.io/service-account-token.
///
/// Uses the same kubeconfig/TLS stack as u7s-scheduler. The --token-file
/// flag provides an alternative bearer-token bootstrap path when kubeconfig
/// is unavailable (e.g. early cluster bootstrap).
use anyhow::{bail, Context};
use base64::Engine;
use clap::Parser;
use hyper::Method;
use serde_json::Value;
use tracing::{error, info, warn};
use u7s_client_util::{build_tls_connector, parse_kubeconfig, HyperApiClient};
use u7s_controller_manager::{
    build_sa_token_secret, parse_sa_added_event, secrets_path, token_request_path,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "u7s-controller-manager",
    about = "Minimal u7s controller manager"
)]
struct Args {
    /// Path to kubeconfig file.
    #[arg(long, default_value = "./kubeconfig")]
    kubeconfig: String,

    /// Bearer token file for bootstrap (alternative to kubeconfig client cert).
    #[arg(long)]
    token_file: Option<String>,

    /// API server address override. Takes precedence over kubeconfig server.
    #[arg(long)]
    server: Option<String>,
}

// ---------------------------------------------------------------------------
// HTTP helpers — delegates to HyperApiClient in client-util.
// ---------------------------------------------------------------------------

async fn http_post_json(
    client: &HyperApiClient,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(hyper::StatusCode, String)> {
    client
        .request(Method::POST, path, Some(serde_json::to_string(payload)?))
        .await
}

// ---------------------------------------------------------------------------
// SA provisioning logic
// ---------------------------------------------------------------------------

/// Mint a token and store it in a Secret for the given ServiceAccount.
async fn provision_sa(
    client: &HyperApiClient,
    namespace: &str,
    sa_name: &str,
) -> anyhow::Result<()> {
    // 1. Mint a JWT.
    let token_path = token_request_path(namespace, sa_name);
    let token_req = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": { "expirationSeconds": 3600 }
    });
    let (status, body) = http_post_json(client, &token_path, &token_req).await?;
    if !status.is_success() {
        bail!("TokenRequest for {namespace}/{sa_name} failed ({status}): {body}");
    }
    let token_resp: Value = serde_json::from_str(&body).context("parse TokenRequest response")?;
    let token = token_resp["status"]["token"]
        .as_str()
        .context("TokenRequest response missing status.token")?;

    // 2. Base64-encode the JWT for storage in Secret.data.
    let token_b64 = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());

    // 3. Store in a Secret.
    let secret = build_sa_token_secret(namespace, sa_name, &token_b64);
    let secret_path = secrets_path(namespace);
    let (status, body) = http_post_json(client, &secret_path, &secret).await?;

    if status.is_success() {
        info!("provisioned token secret for {namespace}/{sa_name}");
    } else if status.as_u16() == 409 {
        // Secret already exists — idempotent, not an error.
        info!("token secret for {namespace}/{sa_name} already exists, skipping");
    } else {
        warn!("failed to create token secret for {namespace}/{sa_name} ({status}): {body}");
    }
    Ok(())
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

    let bearer_token: Option<String> = args
        .token_file
        .as_deref()
        .map(|p| std::fs::read_to_string(p).with_context(|| format!("reading token file {p}")))
        .transpose()?
        .map(|s| s.trim().to_owned());

    let mut creds = parse_kubeconfig(&args.kubeconfig)?;
    if let Some(ref s) = args.server {
        creds.server = s.clone();
    }
    let server = creds.server.clone();
    info!("connecting to API server at {server}");

    let connector = build_tls_connector(&creds)?;

    loop {
        info!("starting ServiceAccount watch");
        let path = "/api/v1/serviceaccounts?watch=true";

        let client = HyperApiClient {
            server: server.clone(),
            connector: connector.clone(),
            bearer: bearer_token.clone(),
        };

        let result = client
            .watch_stream(path, |event| {
                let Some((namespace, sa_name)) = parse_sa_added_event(&event) else {
                    return;
                };
                info!("new ServiceAccount: {namespace}/{sa_name}");

                let client_clone = HyperApiClient {
                    server: server.clone(),
                    connector: connector.clone(),
                    bearer: bearer_token.clone(),
                };
                tokio::spawn(async move {
                    if let Err(e) = provision_sa(&client_clone, &namespace, &sa_name).await {
                        error!("provision_sa {namespace}/{sa_name}: {e}");
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
