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
    bind_pod, delete_pod, emit_scheduling_event, find_preemption_plan, needs_scheduling, pick_node,
    should_schedule, stream_watch_events,
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
                // Ok(node_name) on a successful bind, Err on any failure to schedule
                // (no node fits, even after preemption) or to bind. Distinguishing
                // the two lets us emit the matching Event below — without it,
                // `kubectl describe pod` and the SchedulerPredicates e2e suite's
                // observeEventAfterAction watch never see a Scheduled/FailedScheduling
                // event and the watch times out (mayor-lafgk).
                let outcome: anyhow::Result<String> = async {
                    match pick_node(&connector_clone, &server_clone, &pending).await {
                        Ok(node) => {
                            bind_pod(
                                &connector_clone,
                                &server_clone,
                                &namespace,
                                &pod_name,
                                &node,
                            )
                            .await?;
                            Ok(node)
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
                            .await?;
                            Ok(plan.node_name)
                        }
                    }
                }
                .await;
                // Always remove the key, whether binding succeeded or failed.
                in_flight_clone
                    .lock()
                    .expect("in_flight lock poisoned")
                    .remove(&key);

                let (reason, message, event_type) = match &outcome {
                    Ok(node) => (
                        "Scheduled",
                        format!("Successfully assigned {namespace}/{pod_name} to {node}"),
                        "Normal",
                    ),
                    Err(e) => {
                        error!("scheduling error for {key}: {e}");
                        ("FailedScheduling", format!("{e}"), "Warning")
                    }
                };
                if let Err(e) = emit_scheduling_event(
                    &connector_clone,
                    &server_clone,
                    &namespace,
                    &pod_name,
                    reason,
                    &message,
                    event_type,
                )
                .await
                {
                    error!("failed to emit {reason} event for {key}: {e}");
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
