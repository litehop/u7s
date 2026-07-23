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
    bind_pod, delete_pod, disruption_target_patch, emit_scheduling_event,
    failed_scheduling_status_patch, find_preemption_plan, http_get, needs_scheduling,
    patch_pod_status, pick_node, pods_needing_resync, scheduling_gate_status_patch,
    scheduling_gate_status_reset, should_retry_without_preempting, should_schedule,
    stream_watch_events, NodeTally, PendingPod, PodList,
};

/// Bind `pending` to `node`, which `pick_node` has already reserved in
/// `tally` atomically with its fit check (see `pick_node`'s doc comment for
/// why the reservation must not happen in a second, later lock acquisition
/// here instead). Rolls the reservation back if the bind itself fails, so a
/// failed bind never permanently overcounts `node`'s tallied usage.
async fn bind_reserved_node(
    connector: &TlsConnector,
    server: &str,
    tally: &Mutex<NodeTally>,
    pending: &PendingPod,
    node: &str,
) -> anyhow::Result<()> {
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

/// Maximum number of times `preempt_and_pick_node` re-plans preemption for
/// the same pending pod before giving up — bounds the retry below so a
/// pathological cluster that keeps recreating evicted pods can't stall this
/// pod's scheduling task forever.
const MAX_PREEMPTION_ATTEMPTS: u32 = 5;

/// Plan and execute preemption for `pending`, retrying up to
/// `MAX_PREEMPTION_ATTEMPTS` times if `find_preemption_plan`'s atomic
/// reservation loses to a fresher read, and returning the node name once one
/// succeeds.
///
/// `find_preemption_plan` reserves `pending` on the chosen node before this
/// function evicts anyone (see its doc comment for why: reserving only
/// AFTER eviction leaves a window where a third, concurrently-scheduled pod —
/// e.g. a controller's replacement for a pod just evicted — can repeatedly
/// claim each freed slot first; reproduced live against the
/// PreemptionExecutionPath conformance scenario, fast enough that even a
/// several-attempt "evict, then re-check" retry never won). So once a plan
/// comes back here, `pending`'s slot is already safely held — eviction
/// failing partway through is the only way this loop needs to retry, and if
/// it does, the reservation is rolled back first so the failed attempt does
/// not permanently strand that capacity.
async fn preempt_and_pick_node(
    connector: &TlsConnector,
    server: &str,
    pending: &PendingPod,
    tally: &Mutex<NodeTally>,
    namespace: &str,
    pod_name: &str,
) -> anyhow::Result<String> {
    let mut last_err = None;
    for _ in 0..MAX_PREEMPTION_ATTEMPTS {
        let plan = match find_preemption_plan(connector, server, pending, tally).await {
            Ok(plan) => plan,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        info!(
            "preempting {} pod(s) on {} to schedule higher-priority pod {namespace}/{pod_name}",
            plan.victims.len(),
            plan.node_name
        );
        match evict_victims(connector, server, &plan.victims, tally, pod_name).await {
            Ok(()) => return Ok(plan.node_name),
            Err(e) => {
                tally
                    .lock()
                    .expect("tally lock poisoned")
                    .remove(&pending.namespace, &pending.pod_name);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("loop runs at least once, so this is always Some")).context(
        "no node still fits after preemption, even after retrying \
         (capacity kept being claimed concurrently)",
    )
}

/// Evict every pod in `victims` ("namespace/name" keys), stamping the
/// DisruptionTarget condition on each first (best-effort, mirrors upstream
/// kube-scheduler). Split out of `preempt_and_pick_node` so a mid-loop
/// eviction failure is a single `?` there, making the reservation-rollback
/// path easy to see.
async fn evict_victims(
    connector: &TlsConnector,
    server: &str,
    victims: &[String],
    tally: &Mutex<NodeTally>,
    pod_name: &str,
) -> anyhow::Result<()> {
    for victim in victims {
        let Some((v_ns, v_name)) = victim.split_once('/') else {
            continue;
        };
        // Best-effort: mirrors upstream kube-scheduler, which stamps
        // DisruptionTarget on the victim before deleting it. A patch
        // failure must not block the eviction itself — freeing the slot
        // for the higher-priority pod matters more than the condition.
        if let Err(e) = patch_pod_status(
            connector,
            server,
            v_ns,
            v_name,
            &disruption_target_patch(pod_name),
        )
        .await
        {
            error!(
                "failed to set DisruptionTarget condition on preemption victim {v_ns}/{v_name}: {e}"
            );
        }
        delete_pod(connector, server, v_ns, v_name).await?;
        tally
            .lock()
            .expect("tally lock poisoned")
            .remove(v_ns, v_name);
    }
    Ok(())
}

/// How often the periodic resync (spawned in `main`) re-lists `/api/v1/pods`
/// and re-attempts scheduling for anything still unscheduled, independent of
/// whatever the watch stream has delivered. Matches upstream kube-scheduler's
/// `flushUnschedulablePodsLeftover`, which runs on this same 30s cadence: a
/// pod that fails a scheduling attempt (e.g. exhausts preemption retries)
/// never generates another watch event by itself — FailedScheduling only
/// emits a separate Event, it never patches the pod's own status — so
/// without a timer independent of the watch, such a pod stays Pending
/// forever even after capacity that would let it schedule frees up.
const RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Handle one pod watch event — a real one from the live watch, or a
/// synthetic `{"type": "MODIFIED", "object": ...}` manufactured by the
/// periodic resync loop from a fresh `/api/v1/pods` list (see
/// `RESYNC_INTERVAL`). Both callers feed events through this same function
/// so a resync-triggered scheduling attempt is handled identically to a
/// watch-triggered one — in particular, the `in_flight` dedup below is
/// shared between them, so a resync tick can never spawn a second,
/// concurrent `bind_pod` for a pod the watch is already scheduling.
fn handle_pod_event(
    event: serde_json::Value,
    connector: &TlsConnector,
    server: &str,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    tally: &Arc<Mutex<NodeTally>>,
) {
    // Every pod in the cluster passes through here now (not just
    // unscheduled ones) so NodeTally can track already-bound pods'
    // resource usage. Must run unconditionally, before the
    // needs_scheduling early-return below, so a later event in this
    // same stream never reads a tally missing an earlier one.
    tally
        .lock()
        .expect("tally lock poisoned")
        .apply_event(&event);

    // A gated pod never enters the scheduling cycle below (needs_scheduling
    // returns None for it) — without this, its PodScheduled condition never
    // gets touched at all, and WaitForPodsSchedulingGated (which polls for
    // {type: PodScheduled, reason: SchedulingGated}, not just "unscheduled")
    // times out even though the pod correctly stays Pending.
    if let Some(gated) = scheduling_gate_status_patch(&event) {
        let connector_clone = connector.clone();
        let server_clone = server.to_string();
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
        let mut guard = in_flight.lock().expect("in_flight lock poisoned");
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
    let connector_clone = connector.clone();
    let server_clone = server.to_string();
    let in_flight_clone = in_flight.clone();
    let tally_clone = tally.clone();
    tokio::spawn(async move {
        let namespace = pending.namespace.clone();
        let pod_name = pending.pod_name.clone();
        // Best-effort: clear the stale SchedulingGated reason before attempting
        // to schedule below. Not folded into `outcome` via `?` — a transient
        // failure here must not block the actual scheduling attempt that
        // follows, since getting the pod running matters more than tidying up
        // a status message.
        if let Some(reset) = stale_gate_reset {
            if let Err(e) = patch_pod_status(
                &connector_clone,
                &server_clone,
                &namespace,
                &pod_name,
                &reset,
            )
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
        let first_pick = pick_node(&connector_clone, &server_clone, &pending, &tally_clone).await;
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
                    bind_reserved_node(
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
                    let node = preempt_and_pick_node(
                        &connector_clone,
                        &server_clone,
                        &pending,
                        &tally_clone,
                        &namespace,
                        &pod_name,
                    )
                    .await?;
                    bind_reserved_node(
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
                let message = format!("{e}");
                // Best-effort, mirrors the DisruptionTarget/SchedulingGated
                // patches elsewhere in this file: the FailedScheduling Event
                // below is not enough on its own — upstream kube-scheduler
                // also patches the pod's own PodScheduled condition on every
                // failed cycle, which is what conformance waits actually poll.
                if let Err(patch_err) = patch_pod_status(
                    &connector_clone,
                    &server_clone,
                    &namespace,
                    &pod_name,
                    &failed_scheduling_status_patch(&message),
                )
                .await
                {
                    error!("failed to set PodScheduled=False status for {key}: {patch_err}");
                }
                ("FailedScheduling", message, "Warning")
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

    // Periodic re-sync, independent of the watch stream below: every
    // RESYNC_INTERVAL, re-list every pod and feed anything still unscheduled
    // back through handle_pod_event, exactly as a live watch event would.
    // This is what eventually retries a pod stranded by a failed scheduling
    // attempt (see RESYNC_INTERVAL's doc comment for why the watch alone
    // cannot be relied on to do that).
    {
        let connector = connector.clone();
        let server = server.clone();
        let in_flight = in_flight.clone();
        let tally = tally.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RESYNC_INTERVAL).await;
                let (status, body) = match http_get(&connector, &server, "/api/v1/pods").await {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("resync: GET /api/v1/pods failed: {e}");
                        continue;
                    }
                };
                if !status.is_success() {
                    error!("resync: GET /api/v1/pods returned {status}");
                    continue;
                }
                let list: PodList = match serde_json::from_str(&body) {
                    Ok(list) => list,
                    Err(e) => {
                        error!("resync: failed to parse pod list: {e}");
                        continue;
                    }
                };
                let in_flight_snapshot = in_flight.lock().expect("in_flight lock poisoned").clone();
                for event in pods_needing_resync(&list.items, &in_flight_snapshot) {
                    handle_pod_event(event, &connector, &server, &in_flight, &tally);
                }
            }
        });
    }

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
            handle_pod_event(event, connector_ref, server_ref, in_flight_ref, tally_ref);
        })
        .await;

        if let Err(e) = result {
            error!("watch error: {e} — reconnecting in 5s");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
