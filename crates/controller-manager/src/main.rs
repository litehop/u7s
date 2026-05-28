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
    compute_aggregated_rules, endpoint_slice_controller, endpoint_slice_mirroring_controller,
    namespace_controller, parse_cluster_role_event, parse_sa_added_event, secrets_path,
    token_request_path, ClusterRoleSnapshot,
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
// EndpointSlice controller (selector-based)
// ---------------------------------------------------------------------------

/// Reconcile EndpointSlices for all Services in a namespace by listing pods
/// and checking which match each Service's selector.
async fn reconcile_endpoint_slices_for_namespace(
    client: &HyperApiClient,
    namespace: &str,
) -> anyhow::Result<()> {
    use anyhow::Context;

    // List all services in the namespace.
    let svc_path = endpoint_slice_controller::services_list_path(namespace);
    let (status, body) = client
        .request(Method::GET, &svc_path, None)
        .await
        .with_context(|| format!("list services in {namespace}"))?;
    if !status.is_success() {
        return Ok(()); // namespace may not exist yet
    }
    let svc_list: Value = serde_json::from_str(&body)
        .with_context(|| format!("parse service list in {namespace}"))?;
    let services: Vec<Value> = svc_list["items"].as_array().cloned().unwrap_or_default();

    // List all pods in the namespace.
    let pod_path = endpoint_slice_controller::pods_list_path(namespace);
    let (pod_status, pod_body) = client
        .request(Method::GET, &pod_path, None)
        .await
        .with_context(|| format!("list pods in {namespace}"))?;
    let pods: Vec<endpoint_slice_controller::PodObject> = if pod_status.is_success() {
        let pod_list: Value = serde_json::from_str(&pod_body)
            .with_context(|| format!("parse pod list in {namespace}"))?;
        pod_list["items"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(endpoint_slice_controller::parse_pod)
            .collect()
    } else {
        vec![]
    };

    for svc_obj in &services {
        let Some(svc) = endpoint_slice_controller::parse_service(svc_obj) else {
            continue;
        };

        // Skip Services with no selector (those use EndpointSlice mirroring).
        let selector = match &svc.selector {
            Some(sel) if !sel.is_empty() => sel.clone(),
            _ => {
                // Create an empty EndpointSlice for no-selector Services so tests can observe it.
                upsert_endpoint_slice(client, &svc.name, &svc.namespace, &svc.ports, &[]).await;
                continue;
            }
        };

        // Find matching pods and extract endpoints.
        let endpoints: Vec<endpoint_slice_controller::PodEndpoint> = pods
            .iter()
            .filter(|pod| {
                endpoint_slice_controller::pod_matches_selector(&pod.metadata.labels, &selector)
            })
            .filter_map(endpoint_slice_controller::extract_pod_endpoint)
            .collect();

        upsert_endpoint_slice(client, &svc.name, &svc.namespace, &svc.ports, &endpoints).await;
    }
    Ok(())
}

/// Create or replace the EndpointSlice for a single Service.
async fn upsert_endpoint_slice(
    client: &HyperApiClient,
    service_name: &str,
    namespace: &str,
    ports: &[endpoint_slice_controller::ServicePort],
    endpoints: &[endpoint_slice_controller::PodEndpoint],
) {
    let slice =
        endpoint_slice_controller::build_endpoint_slice(service_name, namespace, ports, endpoints);
    let slice_name = endpoint_slice_controller::endpoint_slice_name(service_name);
    let slice_path = endpoint_slice_controller::endpoint_slice_path(namespace, &slice_name);
    let post_path = endpoint_slice_controller::endpoint_slices_post_path(namespace);

    let body_str = serde_json::to_string(&slice).expect("slice serializes");

    // Try PUT first (update). If 404, POST (create).
    match client
        .request(Method::PUT, &slice_path, Some(body_str.clone()))
        .await
    {
        Ok((status, _)) if status.is_success() => {
            info!("updated EndpointSlice {namespace}/{slice_name} for service {service_name}");
        }
        Ok((status, _)) if status.as_u16() == 404 || status.as_u16() == 405 => {
            // Slice doesn't exist yet — create it.
            match client
                .request(Method::POST, &post_path, Some(body_str))
                .await
            {
                Ok((post_status, _)) if post_status.is_success() || post_status.as_u16() == 409 => {
                    info!(
                        "created EndpointSlice {namespace}/{slice_name} for service {service_name}"
                    );
                }
                Ok((post_status, post_body)) => {
                    warn!(
                        "POST EndpointSlice {namespace}/{slice_name} failed ({post_status}): {post_body}"
                    );
                }
                Err(e) => {
                    error!("POST EndpointSlice {namespace}/{slice_name}: {e}");
                }
            }
        }
        Ok((status, body)) => {
            warn!("PUT EndpointSlice {namespace}/{slice_name} failed ({status}): {body}");
        }
        Err(e) => {
            error!("PUT EndpointSlice {namespace}/{slice_name}: {e}");
        }
    }
}

/// Watch Services across all namespaces and reconcile EndpointSlices.
/// Also watches Pods and re-reconciles when pods change.
async fn run_endpoint_slice_controller(
    server: String,
    connector: tokio_rustls::TlsConnector,
    bearer_token: Option<String>,
) {
    // Shared set of known namespaces to reconcile when pods change.
    // We collect namespaces from Service events.
    let known_namespaces: std::sync::Arc<tokio::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

    // Spawn a pod watcher that triggers re-reconcile of affected namespace.
    {
        let server_p = server.clone();
        let connector_p = connector.clone();
        let bearer_p = bearer_token.clone();
        let ns_map = std::sync::Arc::clone(&known_namespaces);
        tokio::spawn(async move {
            loop {
                info!("EndpointSlice controller: starting pod watch");
                let client = HyperApiClient {
                    server: server_p.clone(),
                    connector: connector_p.clone(),
                    bearer: bearer_p.clone(),
                };
                let result = client
                    .watch_stream(endpoint_slice_controller::pods_watch_path(), |event| {
                        let event_type = event["type"].as_str().unwrap_or("").to_owned();
                        if !matches!(event_type.as_str(), "ADDED" | "MODIFIED" | "DELETED") {
                            return;
                        }
                        let namespace = event["object"]["metadata"]["namespace"]
                            .as_str()
                            .unwrap_or("default")
                            .to_owned();
                        let ns_map_clone = std::sync::Arc::clone(&ns_map);
                        let server_clone = server_p.clone();
                        let connector_clone = connector_p.clone();
                        let bearer_clone = bearer_p.clone();
                        tokio::spawn(async move {
                            // Only reconcile if we know about this namespace.
                            let known = ns_map_clone.lock().await.contains(&namespace);
                            if known {
                                let client = HyperApiClient {
                                    server: server_clone,
                                    connector: connector_clone,
                                    bearer: bearer_clone,
                                };
                                if let Err(e) =
                                    reconcile_endpoint_slices_for_namespace(&client, &namespace)
                                        .await
                                {
                                    error!("reconcile namespace {namespace} on pod event: {e}");
                                }
                            }
                        });
                    })
                    .await;
                if let Err(e) = result {
                    error!("EndpointSlice pod watch error: {e} — reconnecting in 5s");
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Main loop: watch Services and reconcile on every change.
    loop {
        info!("EndpointSlice controller: starting service watch");
        let client = HyperApiClient {
            server: server.clone(),
            connector: connector.clone(),
            bearer: bearer_token.clone(),
        };
        let ns_map = std::sync::Arc::clone(&known_namespaces);
        let result = client
            .watch_stream(endpoint_slice_controller::services_watch_path(), |event| {
                let event_type = event["type"].as_str().unwrap_or("").to_owned();
                if !matches!(event_type.as_str(), "ADDED" | "MODIFIED" | "DELETED") {
                    return;
                }
                let namespace = event["object"]["metadata"]["namespace"]
                    .as_str()
                    .unwrap_or("default")
                    .to_owned();

                let ns_map_clone = std::sync::Arc::clone(&ns_map);
                let server_clone = server.clone();
                let connector_clone = connector.clone();
                let bearer_clone = bearer_token.clone();
                tokio::spawn(async move {
                    // Track this namespace for pod-triggered reconcile.
                    ns_map_clone.lock().await.insert(namespace.clone());

                    let client = HyperApiClient {
                        server: server_clone,
                        connector: connector_clone,
                        bearer: bearer_clone,
                    };
                    if let Err(e) =
                        reconcile_endpoint_slices_for_namespace(&client, &namespace).await
                    {
                        error!("reconcile namespace {namespace} on service event: {e}");
                    }
                });
            })
            .await;
        if let Err(e) = result {
            error!("EndpointSlice service watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

// ---------------------------------------------------------------------------
// EndpointSliceMirroring controller
// ---------------------------------------------------------------------------

/// Watch all Endpoints objects and mirror them to EndpointSlices.
async fn run_endpoint_slice_mirroring_controller(
    server: String,
    connector: tokio_rustls::TlsConnector,
    bearer_token: Option<String>,
) {
    loop {
        info!("EndpointSliceMirroring controller: starting endpoints watch");
        let client = HyperApiClient {
            server: server.clone(),
            connector: connector.clone(),
            bearer: bearer_token.clone(),
        };

        let result = client
            .watch_stream(
                endpoint_slice_mirroring_controller::endpoints_watch_path(),
                |event| {
                    let action = endpoint_slice_mirroring_controller::parse_endpoints_event(&event);

                    let server_clone = server.clone();
                    let connector_clone = connector.clone();
                    let bearer_clone = bearer_token.clone();

                    tokio::spawn(async move {
                        let client = HyperApiClient {
                            server: server_clone,
                            connector: connector_clone,
                            bearer: bearer_clone,
                        };
                        match action {
                            endpoint_slice_mirroring_controller::EndpointsAction::Upsert {
                                name,
                                namespace,
                                subsets,
                            } => {
                                upsert_mirrored_endpoint_slice(
                                    &client, &name, &namespace, &subsets,
                                )
                                .await;
                            }
                            endpoint_slice_mirroring_controller::EndpointsAction::Delete {
                                name,
                                namespace,
                            } => {
                                delete_mirrored_endpoint_slice(&client, &name, &namespace).await;
                            }
                            endpoint_slice_mirroring_controller::EndpointsAction::None => {}
                        }
                    });
                },
            )
            .await;

        if let Err(e) = result {
            error!("EndpointSliceMirroring watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Create or replace a mirrored EndpointSlice for an Endpoints object.
async fn upsert_mirrored_endpoint_slice(
    client: &HyperApiClient,
    endpoints_name: &str,
    namespace: &str,
    subsets: &[endpoint_slice_mirroring_controller::MirroredSubset],
) {
    let slice = endpoint_slice_mirroring_controller::build_mirrored_endpoint_slice(
        endpoints_name,
        namespace,
        subsets,
    );
    let slice_path =
        endpoint_slice_mirroring_controller::mirror_slice_path(namespace, endpoints_name);
    let post_path = endpoint_slice_mirroring_controller::mirror_slice_post_path(namespace);

    let body_str = serde_json::to_string(&slice).expect("slice serializes");

    match client
        .request(Method::PUT, &slice_path, Some(body_str.clone()))
        .await
    {
        Ok((status, _)) if status.is_success() => {
            info!("updated mirrored EndpointSlice for {namespace}/{endpoints_name}");
        }
        Ok((status, _)) if status.as_u16() == 404 || status.as_u16() == 405 => {
            match client
                .request(Method::POST, &post_path, Some(body_str))
                .await
            {
                Ok((post_status, _)) if post_status.is_success() || post_status.as_u16() == 409 => {
                    info!("created mirrored EndpointSlice for {namespace}/{endpoints_name}");
                }
                Ok((post_status, post_body)) => {
                    warn!("POST mirrored EndpointSlice {namespace}/{endpoints_name} failed ({post_status}): {post_body}");
                }
                Err(e) => {
                    error!("POST mirrored EndpointSlice {namespace}/{endpoints_name}: {e}");
                }
            }
        }
        Ok((status, body)) => {
            warn!(
                "PUT mirrored EndpointSlice {namespace}/{endpoints_name} failed ({status}): {body}"
            );
        }
        Err(e) => {
            error!("PUT mirrored EndpointSlice {namespace}/{endpoints_name}: {e}");
        }
    }
}

/// Delete the mirrored EndpointSlice for a deleted Endpoints object.
async fn delete_mirrored_endpoint_slice(
    client: &HyperApiClient,
    endpoints_name: &str,
    namespace: &str,
) {
    let slice_path =
        endpoint_slice_mirroring_controller::mirror_slice_path(namespace, endpoints_name);
    match client.request(Method::DELETE, &slice_path, None).await {
        Ok((status, _)) if status.is_success() || status.as_u16() == 404 => {
            info!("deleted mirrored EndpointSlice for {namespace}/{endpoints_name}");
        }
        Ok((status, body)) => {
            warn!(
                "DELETE mirrored EndpointSlice {namespace}/{endpoints_name} failed ({status}): {body}"
            );
        }
        Err(e) => {
            error!("DELETE mirrored EndpointSlice {namespace}/{endpoints_name}: {e}");
        }
    }
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

    // Spawn the EndpointSlice controller (selector-based).
    tokio::spawn(run_endpoint_slice_controller(
        server.clone(),
        connector.clone(),
        bearer_token.clone(),
    ));

    // Spawn the EndpointSliceMirroring controller.
    tokio::spawn(run_endpoint_slice_mirroring_controller(
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

    for (group, version, resource) in namespace_controller::NON_CORE_DRAIN_RESOURCES {
        let list_path = namespace_controller::non_core_namespaced_resource_list_path(
            namespace, group, version, resource,
        );
        let (status, body) = client
            .request(Method::GET, &list_path, None)
            .await
            .with_context(|| format!("list {group}/{resource} in {namespace}"))?;

        if !status.is_success() {
            // 404 means resource type not registered in this server — skip silently.
            if status.as_u16() == 404 {
                continue;
            }
            warn!("list {group}/{resource} in {namespace}: HTTP {status} — skipping");
            continue;
        }

        let list: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("parse {group}/{resource} list in {namespace}"))?;
        let items = list["items"].as_array().cloned().unwrap_or_default();

        for item in items {
            let item_name = item["metadata"]["name"].as_str().unwrap_or("").to_owned();
            if item_name.is_empty() {
                continue;
            }
            let del_path = namespace_controller::non_core_namespaced_resource_delete_path(
                namespace, group, version, resource, &item_name,
            );
            let (del_status, _) = client
                .request(Method::DELETE, &del_path, None)
                .await
                .with_context(|| format!("delete {group}/{resource}/{item_name} in {namespace}"))?;
            if del_status.is_success() || del_status.as_u16() == 404 {
                info!("namespace {namespace}: deleted {group}/{resource}/{item_name}");
            } else {
                warn!(
                    "namespace {namespace}: delete {group}/{resource}/{item_name} returned {del_status}"
                );
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
