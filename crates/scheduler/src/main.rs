/// u7s-scheduler — minimal scheduler scaffold.
///
/// Watches unscheduled pods (spec.nodeName absent) cluster-wide
/// via a long-poll watch on the API server, picks the first available node,
/// and binds via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// When no node has free capacity, falls back to preemption: evicts
/// lower-priority pods to make room rather than leaving a higher-priority pod
/// Pending forever (see `find_preemption_plan` in lib.rs for the MVP model —
/// pod-count capacity only, no CPU/memory/extended-resource accounting).
///
/// No leader election logic is implemented; the --leader-elect flag is
/// accepted and silently ignored.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use clap::Parser;
use tracing::{error, info};
use u7s_kubeconfig::{build_tls_connector, parse_kubeconfig};
use u7s_scheduler::{
    bind_pod, delete_pod, find_preemption_plan, needs_scheduling, patch_pod_status, pick_node,
    scheduling_gate_status_patch, scheduling_gate_status_reset, should_schedule,
    stream_watch_events,
};

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

    // in_flight tracks pod keys ("namespace/name") for which a bind task is already
    // running. Two rapid ADDED/MODIFIED events for the same pod must not spawn two
    // concurrent bind_pod calls — the second would receive 409 Conflict from the API
    // server. The key is inserted before spawn and removed when the task finishes.
    let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    // Watch loop — reconnect on error with a short backoff.
    loop {
        info!("starting pod watch on /api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D");
        let path = "/api/v1/pods?watch=true&fieldSelector=spec.nodeName%3D";

        // Collect events; for each ADDED/MODIFIED pod with empty nodeName, schedule it.
        // We clone connector per loop iteration (cheap Arc clone inside).
        let connector_ref = &connector;
        let server_ref = &server;
        let in_flight_ref = &in_flight;

        let result = stream_watch_events(connector_ref, server_ref, path, |event| {
            // A gated pod never enters the scheduling cycle below (needs_scheduling
            // returns None for it) — without this, its PodScheduled condition never
            // gets touched at all, and WaitForPodsSchedulingGated (which polls for
            // {type: PodScheduled, reason: SchedulingGated}, not just "unscheduled")
            // times out even though the pod correctly stays Pending.
            if let Some(gated) = scheduling_gate_status_patch(&event) {
                let connector_clone = connector_ref.clone();
                let server_clone = server_ref.to_string();
                tokio::spawn(async move {
                    if let Err(e) = patch_pod_status(
                        &connector_clone,
                        &server_clone,
                        &gated.namespace,
                        &gated.pod_name,
                        &gated.patch,
                    )
                    .await
                    {
                        error!(
                            "failed to set SchedulingGated status for {}/{}: {e}",
                            gated.namespace, gated.pod_name
                        );
                    }
                });
            }
            // Computed from this same event, before the pod potentially gets bound
            // below — cleared once bound (needs_scheduling's already_scheduled check
            // has no bearing here since this reads the same event, not a later one).
            let stale_gate_reset = scheduling_gate_status_reset(&event);

            let Some(pending) = needs_scheduling(&event) else {
                return;
            };

            let key = format!("{}/{}", pending.namespace, pending.pod_name);

            // Dedup: skip if a bind task for this pod is already in flight.
            {
                let mut guard = in_flight_ref.lock().expect("in_flight lock poisoned");
                if !should_schedule(&guard, &key) {
                    info!("skipping duplicate scheduling request for {key}");
                    return;
                }
                guard.insert(key.clone());
            }

            info!(
                "unscheduled pod detected: {}/{}",
                pending.namespace, pending.pod_name
            );

            // Schedule asynchronously — spawn a task so we don't block the stream.
            let connector_clone = connector_ref.clone();
            let server_clone = server_ref.to_string();
            let in_flight_clone = in_flight_ref.clone();
            tokio::spawn(async move {
                let namespace = pending.namespace.clone();
                let pod_name = pending.pod_name.clone();
                // Best-effort: clear the stale SchedulingGated reason before attempting
                // to schedule below. Not folded into `result` via `?` — a transient
                // failure here must not block the actual scheduling attempt that
                // follows, since getting the pod running matters more than tidying up
                // a status message.
                if let Some(reset) = stale_gate_reset {
                    if let Err(e) =
                        patch_pod_status(&connector_clone, &server_clone, &namespace, &pod_name, &reset)
                            .await
                    {
                        error!(
                            "failed to clear stale SchedulingGated status for {namespace}/{pod_name}: {e}"
                        );
                    }
                }
                let result: anyhow::Result<()> = async {
                    match pick_node(&connector_clone, &server_clone, &pending).await {
                        Ok(node) => {
                            bind_pod(
                                &connector_clone,
                                &server_clone,
                                &namespace,
                                &pod_name,
                                &node,
                            )
                            .await
                        }
                        Err(_no_capacity) => {
                            // No node has a free slot — try preemption before giving
                            // up: evict lower-priority pods to make room rather than
                            // leaving a higher-priority pod Pending forever (mayor-rsei).
                            let plan =
                                find_preemption_plan(&connector_clone, &server_clone, &pending)
                                    .await?;
                            info!(
                                "preempting {} pod(s) on {} to schedule higher-priority pod {namespace}/{pod_name}",
                                plan.victims.len(),
                                plan.node_name
                            );
                            for victim in &plan.victims {
                                let Some((v_ns, v_name)) = victim.split_once('/') else {
                                    continue;
                                };
                                delete_pod(&connector_clone, &server_clone, v_ns, v_name).await?;
                            }
                            bind_pod(
                                &connector_clone,
                                &server_clone,
                                &namespace,
                                &pod_name,
                                &plan.node_name,
                            )
                            .await
                        }
                    }
                }
                .await;
                // Always remove the key, whether binding succeeded or failed.
                in_flight_clone
                    .lock()
                    .expect("in_flight lock poisoned")
                    .remove(&key);
                if let Err(e) = result {
                    error!("scheduling error for {key}: {e}");
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
