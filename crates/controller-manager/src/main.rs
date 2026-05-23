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
    build_sa_token_secret, cluster_role_patch_path, cluster_roles_watch_path,
    compute_aggregated_rules, namespace_controller, parse_cluster_role_event, parse_sa_added_event,
    secrets_path, token_request_path, ClusterRoleSnapshot,
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

async fn http_patch_json(
    client: &HyperApiClient,
    path: &str,
    payload: &Value,
) -> anyhow::Result<(hyper::StatusCode, String)> {
    client
        .request(Method::PATCH, path, Some(serde_json::to_string(payload)?))
        .await
}

// ---------------------------------------------------------------------------
// ClusterRole aggregation controller
// ---------------------------------------------------------------------------

/// Watch all ClusterRoles and recompute aggregated roles whenever any role changes.
///
/// Aggregated ClusterRoles (those with spec.aggregationRule) collect rules from
/// sub-roles selected by label. This mirrors the built-in Kubernetes
/// clusterrole-aggregation-controller and is required for Argo CD's aggregated
/// ClusterRoles (admin, edit, view) to function.
async fn run_clusterrole_aggregation_controller(
    server: String,
    connector: tokio_rustls::TlsConnector,
    bearer_token: Option<String>,
) {
    loop {
        info!("starting ClusterRole aggregation watch");
        let path = cluster_roles_watch_path();

        let client = HyperApiClient {
            server: server.clone(),
            connector: connector.clone(),
            bearer: bearer_token.clone(),
        };

        // Maintain a local map of all known ClusterRoles so we can recompute
        // aggregated roles on every change without a full re-list.
        let roles: std::sync::Arc<
            tokio::sync::Mutex<std::collections::HashMap<String, ClusterRoleSnapshot>>,
        > = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let result = client
            .watch_stream(path, |event| {
                let Some((event_type, snapshot)) = parse_cluster_role_event(&event) else {
                    return;
                };

                let roles = std::sync::Arc::clone(&roles);
                let client_clone = HyperApiClient {
                    server: server.clone(),
                    connector: connector.clone(),
                    bearer: bearer_token.clone(),
                };

                tokio::spawn(async move {
                    let mut map = roles.lock().await;

                    // Update in-memory map.
                    match event_type.as_str() {
                        "ADDED" | "MODIFIED" => {
                            map.insert(snapshot.name.clone(), snapshot);
                        }
                        "DELETED" => {
                            map.remove(&snapshot.name);
                        }
                        _ => return,
                    }

                    // After any change, recompute all aggregated roles.
                    let all_roles: Vec<ClusterRoleSnapshot> = map.values().cloned().collect();
                    let aggregated: Vec<&ClusterRoleSnapshot> = all_roles
                        .iter()
                        .filter(|r| !r.selectors.is_empty())
                        .collect();

                    for agg_role in aggregated {
                        let merged_rules = compute_aggregated_rules(agg_role, &all_roles);
                        let patch = serde_json::json!({
                            "rules": merged_rules
                        });
                        let patch_path = cluster_role_patch_path(&agg_role.name);
                        match http_patch_json(&client_clone, &patch_path, &patch).await {
                            Ok((status, _)) if status.is_success() => {
                                info!(
                                    "aggregated ClusterRole {}: merged {} rule(s)",
                                    agg_role.name,
                                    merged_rules.len()
                                );
                            }
                            Ok((status, body)) => {
                                warn!(
                                    "patch ClusterRole {} failed ({status}): {body}",
                                    agg_role.name
                                );
                            }
                            Err(e) => {
                                error!("patch ClusterRole {}: {e}", agg_role.name);
                            }
                        }
                    }
                });
            })
            .await;

        if let Err(e) = result {
            error!("ClusterRole aggregation watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
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

    // Spawn the ClusterRole aggregation controller as a background task.
    tokio::spawn(run_clusterrole_aggregation_controller(
        server.clone(),
        connector.clone(),
        bearer_token.clone(),
    ));

    // Spawn the namespace lifecycle controller in the background.
    {
        let server_ns = server.clone();
        let connector_ns = connector.clone();
        let bearer_ns = bearer_token.clone();
        tokio::spawn(async move {
            loop {
                info!("starting Namespace watch (lifecycle controller)");
                let client = HyperApiClient {
                    server: server_ns.clone(),
                    connector: connector_ns.clone(),
                    bearer: bearer_ns.clone(),
                };
                let path = "/api/v1/namespaces?watch=true";
                let result = client
                    .watch_stream(path, |event| {
                        let action = namespace_controller::parse_ns_event(&event);
                        match action {
                            namespace_controller::NsAction::AddFinalizer(name) => {
                                info!("namespace {name}: adding 'kubernetes' finalizer");
                                let client_clone = HyperApiClient {
                                    server: server_ns.clone(),
                                    connector: connector_ns.clone(),
                                    bearer: bearer_ns.clone(),
                                };
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        add_kubernetes_finalizer(&client_clone, &name).await
                                    {
                                        error!("add_kubernetes_finalizer {name}: {e}");
                                    }
                                });
                            }
                            namespace_controller::NsAction::Drain(name) => {
                                info!("namespace {name}: Terminating — draining resources");
                                let client_clone = HyperApiClient {
                                    server: server_ns.clone(),
                                    connector: connector_ns.clone(),
                                    bearer: bearer_ns.clone(),
                                };
                                tokio::spawn(async move {
                                    if let Err(e) = drain_namespace(&client_clone, &name).await {
                                        error!("drain_namespace {name}: {e}");
                                    }
                                });
                            }
                            namespace_controller::NsAction::None => {}
                        }
                    })
                    .await;
                if let Err(e) = result {
                    error!("namespace watch error: {e} — reconnecting in 5s");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

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

// ---------------------------------------------------------------------------
// Namespace lifecycle helpers
// ---------------------------------------------------------------------------

/// Fetch the current namespace object. Returns None when the namespace is already gone.
async fn get_namespace(
    client: &HyperApiClient,
    name: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    use anyhow::Context;
    let path = namespace_controller::namespace_patch_path(name);
    let (status, body) = client
        .request(Method::GET, &path, None)
        .await
        .with_context(|| format!("GET namespace {name}"))?;
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!("GET namespace {name} failed ({status}): {body}");
    }
    let ns: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("parse namespace {name}"))?;
    Ok(Some(ns))
}

/// Replace the namespace object via PUT.
async fn replace_namespace(
    client: &HyperApiClient,
    name: &str,
    body: &serde_json::Value,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let path = namespace_controller::namespace_patch_path(name);
    let (status, resp) = client
        .request(Method::PUT, &path, Some(serde_json::to_string(body)?))
        .await
        .with_context(|| format!("PUT namespace {name}"))?;
    if status.is_success() || status.as_u16() == 404 {
        Ok(())
    } else {
        anyhow::bail!("PUT namespace {name} failed ({status}): {resp}");
    }
}

/// Add the "kubernetes" finalizer to a namespace via GET + PUT.
async fn add_kubernetes_finalizer(client: &HyperApiClient, name: &str) -> anyhow::Result<()> {
    let Some(mut ns) = get_namespace(client, name).await? else {
        info!("namespace {name}: already deleted, skipping finalizer add");
        return Ok(());
    };

    // Build the new finalizers list, adding "kubernetes" if not already present.
    let existing: Vec<String> = ns["metadata"]["finalizers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_owned()))
        .collect();

    if existing.iter().any(|f| f == "kubernetes") {
        // Already present — idempotent.
        return Ok(());
    }

    let mut new_finalizers = existing;
    new_finalizers.push("kubernetes".to_owned());
    ns["metadata"]["finalizers"] = serde_json::to_value(&new_finalizers)?;

    replace_namespace(client, name, &ns).await?;
    info!("namespace {name}: 'kubernetes' finalizer added");
    Ok(())
}

/// Drain all core namespaced resources from a Terminating namespace,
/// then remove the "kubernetes" finalizer via GET + PUT to trigger hard-delete.
async fn drain_namespace(client: &HyperApiClient, namespace: &str) -> anyhow::Result<()> {
    use anyhow::Context;

    for resource in namespace_controller::CORE_DRAIN_RESOURCES {
        let list_path = namespace_controller::namespaced_resource_list_path(namespace, resource);
        let (status, body) = client
            .request(Method::GET, &list_path, None)
            .await
            .with_context(|| format!("list {resource} in {namespace}"))?;

        if !status.is_success() {
            // 404 means resource type doesn't exist in this namespace — skip.
            if status.as_u16() == 404 {
                continue;
            }
            warn!("list {resource} in {namespace}: HTTP {status} — skipping");
            continue;
        }

        let list: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parse {resource} list in {namespace}"))?;
        let items = list["items"].as_array().cloned().unwrap_or_default();

        for item in items {
            let item_name = item["metadata"]["name"].as_str().unwrap_or("").to_owned();
            if item_name.is_empty() {
                continue;
            }
            let del_path = namespace_controller::namespaced_resource_delete_path(
                namespace, resource, &item_name,
            );
            let (del_status, _) = client
                .request(Method::DELETE, &del_path, None)
                .await
                .with_context(|| format!("delete {resource}/{item_name} in {namespace}"))?;
            if del_status.is_success() || del_status.as_u16() == 404 {
                info!("namespace {namespace}: deleted {resource}/{item_name}");
            } else {
                warn!("namespace {namespace}: delete {resource}/{item_name} returned {del_status}");
            }
        }
    }

    // Remove the "kubernetes" finalizer via GET + PUT.
    let Some(mut ns) = get_namespace(client, namespace).await? else {
        // Already gone — nothing to do.
        info!("namespace {namespace}: already deleted");
        return Ok(());
    };

    let new_finalizers: Vec<String> = ns["metadata"]["finalizers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_owned()))
        .filter(|f| f != "kubernetes")
        .collect();

    ns["metadata"]["finalizers"] = serde_json::to_value(&new_finalizers)?;
    // Also clear null so merge-patch semantics work: set to empty array.

    replace_namespace(client, namespace, &ns).await?;
    info!("namespace {namespace}: 'kubernetes' finalizer removed, hard-delete triggered");
    Ok(())
}
