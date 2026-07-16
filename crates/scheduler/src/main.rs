/// u7s-scheduler — minimal scheduler scaffold.
///
/// Watches ALL pods cluster-wide via a long-poll watch on the API server: an
/// unscheduled pod (spec.nodeName absent) enters the scheduling cycle below;
/// every other ADDED/MODIFIED/DELETED event instead feeds `NodeTally`, an
/// in-memory running tally of each node's committed resource usage that
/// `pick_node`/`find_preemption_plan` read instead of issuing a live GET per
/// candidate node. The scheduler picks the first available node and binds
/// via POST /api/v1/namespaces/:ns/pods/:name/binding.
///
/// When no node has free capacity, falls back to preemption: evicts
/// lower-priority pods to make room rather than leaving a higher-priority pod
/// Pending forever (see `find_preemption_plan`/`select_preemption_victims` in
/// lib.rs — pod-count, cpu/memory/ephemeral-storage, and extended resources
/// are all accounted for).
///
/// No leader election logic is implemented; the --leader-elect flag is
/// accepted and silently ignored.
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use clap::Parser;
use tokio_rustls::TlsConnector;
use tracing::{error, info};
use u7s_kubeconfig::{build_tls_connector, parse_kubeconfig};
use u7s_scheduler::{
    bind_pod, delete_pod, disruption_target_patch, emit_scheduling_event, find_preemption_plan,
    needs_scheduling, patch_pod_status, pick_node, scheduling_gate_status_patch,
    scheduling_gate_status_reset, should_retry_without_preempting, should_schedule,
    stream_watch_events, NodeTally, PendingPod,
};

/// Reserve `pending`'s slot on `node` in `tally` before binding, so a
/// concurrently-running scheduling decision cannot read stale (too-low)
/// usage for `node` while this bind's HTTP call is in flight — this is what
/// closes the read-after-write race a live per-node GET fan-out had. Rolls
/// the reservation back if the bind itself fails, so a failed bind never
/// permanently overcounts `node`'s tallied usage.
async fn assume_and_bind(
    connector: &TlsConnector,
    server: &str,
    tally: &Mutex<NodeTally>,
    pending: &PendingPod,
    node: &str,
) -> anyhow::Result<()> {
    tally.lock().expect("tally lock poisoned").assume(
        &pending.namespace,
        &pending.pod_name,
        node,
        pending.priority,
        pending.requests.clone(),
    );
    if let Err(e) = bind_pod(
        connector,
        server,
        &pending.namespace,
        &pending.pod_name,
        node,
    )
    .await
    {
        tally
            .lock()
            .expect("tally lock poisoned")
            .remove(&pending.namespace, &pending.pod_name);
        return Err(e);
    }
    Ok(())
}

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

    // The in-memory per-node resource tally pick_node/find_preemption_plan read
    // instead of a live GET fan-out (see NodeTally in lib.rs). Rebuilt from
    // scratch on every watch (re)connect below, since a fresh connect always
    // replays the full history the store still holds.
    let tally: Arc<Mutex<NodeTally>> = Arc::new(Mutex::new(NodeTally::default()));

    // Watch loop — reconnect on error with a short backoff.
    loop {
        info!("starting pod watch on /api/v1/pods?watch=true");
        let path = "/api/v1/pods?watch=true";
        tally.lock().expect("tally lock poisoned").clear();

        // Collect events; for each ADDED/MODIFIED pod with empty nodeName, schedule it.
        // We clone connector per loop iteration (cheap Arc clone inside).
        let connector_ref = &connector;
        let server_ref = &server;
        let in_flight_ref = &in_flight;
        let tally_ref = &tally;

        let result = stream_watch_events(connector_ref, server_ref, path, |event| {
            // Every pod in the cluster passes through here now (not just
            // unscheduled ones) so NodeTally can track already-bound pods'
            // resource usage. Must run unconditionally, before the
            // needs_scheduling early-return below, so a later event in this
            // same stream never reads a tally missing an earlier one.
            tally_ref.lock().expect("tally lock poisoned").apply_event(&event);

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
            let tally_clone = tally_ref.clone();
            tokio::spawn(async move {
                let namespace = pending.namespace.clone();
                let pod_name = pending.pod_name.clone();
                // Best-effort: clear the stale SchedulingGated reason before attempting
                // to schedule below. Not folded into `outcome` via `?` — a transient
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
                // Ok(node_name) on a successful bind, Err on any failure to schedule
                // (no node fits, even after preemption) or to bind. Distinguishing
                // the two lets us emit the matching Event below — without it,
                // `kubectl describe pod` and the SchedulerPredicates e2e suite's
                // observeEventAfterAction watch never see a Scheduled/FailedScheduling
                // event and the watch times out (mayor-lafgk).
                let first_pick =
                    pick_node(&connector_clone, &server_clone, &pending, &tally_clone).await;
                if let Err(e) = &first_pick {
                    if should_retry_without_preempting(e) {
                        // A GET /api/v1/nodes failure (or an unparseable
                        // response) says nothing about whether the cluster
                        // actually has room — unlike a genuine NoCapacity,
                        // treating it as one would run preemption (evicting
                        // real lower-priority pods) or mark this pod
                        // FailedScheduling off a transient infra hiccup.
                        // Leave the pod Pending: the watch redelivers a
                        // MODIFIED event for it, so pick_node simply runs
                        // again on the next tick.
                        error!(
                            "pick_node could not reach the API server while scheduling {key}: {e} — retrying on next watch tick"
                        );
                        in_flight_clone
                            .lock()
                            .expect("in_flight lock poisoned")
                            .remove(&key);
                        return;
                    }
                }
                let outcome: anyhow::Result<String> = async {
                    match first_pick {
                        Ok(node) => {
                            assume_and_bind(
                                &connector_clone,
                                &server_clone,
                                &tally_clone,
                                &pending,
                                &node,
                            )
                            .await?;
                            Ok(node)
                        }
                        Err(_no_capacity) => {
                            // No node has a free slot — try preemption before giving
                            // up: evict lower-priority pods to make room rather than
                            // leaving a higher-priority pod Pending forever (mayor-rsei).
                            let plan = find_preemption_plan(
                                &connector_clone,
                                &server_clone,
                                &pending,
                                &tally_clone,
                            )
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
                                // Best-effort: mirrors upstream kube-scheduler, which
                                // stamps DisruptionTarget on the victim before deleting
                                // it. A patch failure must not block the eviction
                                // itself — freeing the slot for the higher-priority
                                // pod matters more than the condition.
                                if let Err(e) = patch_pod_status(
                                    &connector_clone,
                                    &server_clone,
                                    v_ns,
                                    v_name,
                                    &disruption_target_patch(&pod_name),
                                )
                                .await
                                {
                                    error!(
                                        "failed to set DisruptionTarget condition on preemption victim {v_ns}/{v_name}: {e}"
                                    );
                                }
                                delete_pod(&connector_clone, &server_clone, v_ns, v_name).await?;
                                tally_clone
                                    .lock()
                                    .expect("tally lock poisoned")
                                    .remove(v_ns, v_name);
                            }
                            // Re-validate against the tally instead of trusting the
                            // pre-eviction plan: the evictions above already updated
                            // it, but a concurrently-running scheduling decision could
                            // have claimed the freed capacity during the eviction's own
                            // wall-clock DELETE round trips (see find_preemption_plan's
                            // doc comment). pick_node is cheap here — no per-node GET
                            // fan-out — so this re-check costs one extra
                            // GET /api/v1/nodes, not O(nodes).
                            let node = pick_node(
                                &connector_clone,
                                &server_clone,
                                &pending,
                                &tally_clone,
                            )
                            .await
                            .context(
                                "no node still fits after preemption \
                                 (capacity may have been claimed concurrently)",
                            )?;
                            assume_and_bind(
                                &connector_clone,
                                &server_clone,
                                &tally_clone,
                                &pending,
                                &node,
                            )
                            .await?;
                            Ok(node)
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
