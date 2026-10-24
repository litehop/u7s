//! Makes certs that are about to expire (or failed to rotate) visible: `Warning` headers on
//! API responses, Events on Node objects, and the `u7s_certificate_expiration_seconds`
//! gauge. Everything is derived from the [`CertInventory`] and an injectable [`Clock`].
//!
//! Windows follow k3s's certificate monitor: 120 days for node/leaf certs and 365 days for
//! CAs, with its Event reasons verbatim. Leaves u7s rotates itself use a narrower window (see
//! [`leaf_window`]) because the 90-day serving cert would otherwise warn on every request.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration as StdDuration;

use axum::{extract::Request, extract::State, middleware::Next, response::Response};
use bytes::Bytes;
use time::{Duration, OffsetDateTime};
use u7s_store::{ListOptions, Store};

use crate::auth::{PeerCertificate, UserInfo};
use crate::pki::{cert_validity, CertInventory, CertRecord, CertRole, Clock, RENEW_FRACTION};
use crate::{keys, util, warnings};

const NODE_CERT_WINDOW: Duration = Duration::days(120);
const CA_WINDOW: Duration = Duration::days(365);
pub(crate) const MONITOR_INTERVAL: StdDuration = StdDuration::from_secs(30 * 60);
const RETRY_WITHOUT_NODES: StdDuration = StdDuration::from_secs(10);
const COMPONENT: &str = "u7s-apiserver";

pub(crate) const REASON_CERT_WARNING: &str = "CertificateExpirationWarning";
pub(crate) const REASON_CA_WARNING: &str = "CACertificateExpirationWarning";
pub(crate) const REASON_ROTATION_FAILED: &str = "CertificateRotationFailed";
pub(crate) const REASON_OK: &str = "CertificateExpirationOK";

#[derive(Clone, Default)]
pub struct CertWatch {
    pub(crate) inventory: CertInventory,
    pub(crate) clock: Clock,
}

/// How long before expiry a record counts as at risk. A root CA is never rotated
/// automatically. A leaf or an intermediate is renewed with a third of its lifetime left, so
/// it is at risk once half of that lead is gone (renewal overdue), capped at the 120-day
/// node-cert window.
fn leaf_window(lifetime: Duration) -> Duration {
    NODE_CERT_WINDOW.min(lifetime * ((1.0 - RENEW_FRACTION) / 2.0))
}

fn window(rec: &CertRecord) -> Duration {
    match rec.role {
        CertRole::Leaf | CertRole::Intermediate => leaf_window(rec.not_after - rec.not_before),
        CertRole::Root => CA_WINDOW,
    }
}

fn is_ca(rec: &CertRecord) -> bool {
    rec.role != CertRole::Leaf
}

fn at_risk(inv: &CertInventory, now: OffsetDateTime) -> Vec<CertRecord> {
    let mut recs: Vec<_> = inv
        .snapshot()
        .into_iter()
        .filter(|r| r.not_after - now <= window(r))
        .collect();
    recs.sort_by_key(|r| r.not_after);
    recs
}

fn when(not_after: OffsetDateTime, now: OffsetDateTime) -> String {
    let left = not_after - now;
    let date = util::secs_to_rfc3339(not_after.unix_timestamp());
    if left <= Duration::ZERO {
        format!("expired at {date}")
    } else if left < Duration::days(1) {
        format!("expires in {}h at {date}", left.whole_hours())
    } else {
        format!("expires in {}d at {date}", left.whole_days())
    }
}

/// Callers that act on cluster-wide certificate health: `system:masters` and kubectl. Everyone
/// else (controllers, service accounts) would log the CA warning on every request; Node Events
/// reach them instead.
fn is_operator(user: Option<&UserInfo>, user_agent: &str) -> bool {
    user_agent.starts_with("kubectl/")
        || user.is_some_and(|u| u.groups.iter().any(|g| g == "system:masters"))
}

/// Warnings to attach to a response: the caller's own client cert when it is inside its window
/// (the leaf window, scaled by that cert's lifetime), plus, for operators only, every inventory
/// cert that is at risk (CA, or a leaf whose rotation is overdue).
///
/// Also observes the caller's remaining cert lifetime in the upstream
/// `apiserver_client_certificate_expiration_seconds` histogram, since the cert is parsed here
/// anyway.
pub(crate) fn request_warnings(
    inv: &CertInventory,
    now: OffsetDateTime,
    peer_der: Option<&[u8]>,
    operator: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(der) = peer_der {
        if let Ok((not_before, not_after)) = cert_validity(der) {
            crate::metrics::CLIENT_CERT_EXPIRATION_SECONDS
                .observe((not_after - now).as_seconds_f64());
            if not_after - now <= leaf_window(not_after - not_before) {
                let who = crate::auth::extract_client_cert_identity(der)
                    .map_or_else(|| "unknown".to_owned(), |u| u.username);
                out.push(format!(
                    "your client certificate (CN={who}) {}; obtain a renewed kubeconfig \
                     before then",
                    when(not_after, now)
                ));
            }
        }
    }
    if !operator {
        return out;
    }
    for rec in at_risk(inv, now) {
        out.push(if is_ca(&rec) {
            format!(
                "cluster CA \"{}\" {}; kubeconfigs pinning it stop verifying this apiserver \
                 after that",
                rec.subject,
                when(rec.not_after, now)
            )
        } else {
            format!(
                "certificate \"{}\" {} and has not been rotated",
                rec.subject,
                when(rec.not_after, now)
            )
        });
    }
    out
}

pub async fn warn_requests(State(watch): State<CertWatch>, req: Request, next: Next) -> Response {
    let user_agent = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let operator = is_operator(req.extensions().get::<UserInfo>(), user_agent);
    let peer = req.extensions().get::<PeerCertificate>();
    for w in request_warnings(
        &watch.inventory,
        watch.clock.now(),
        peer.map(|c| c.0.as_slice()),
        operator,
    ) {
        warnings::warn(w);
    }
    next.run(req).await
}

/// Publish one gauge series per inventory cert. Series are keyed by cert name, subject and
/// usages, which are stable across rotation, so a rotated cert overwrites its own series and
/// two certs sharing a CN never collide.
pub(crate) fn sync_metrics(inv: &CertInventory, now: OffsetDateTime) {
    std::sync::LazyLock::force(&crate::metrics::CLIENT_CERT_EXPIRATION_SECONDS);
    for rec in inv.snapshot() {
        crate::metrics::CERT_EXPIRATION_SECONDS
            .with_label_values(&[rec.name, &rec.subject, &rec.usages.join(",")])
            .set((rec.not_after - now).as_seconds_f64());
        // Create the series at 0 so absence of failures is visible, not just unknown.
        crate::metrics::CERT_ROTATION_FAILURES.with_label_values(&[rec.name]);
    }
}

pub(crate) struct Finding {
    pub reason: &'static str,
    pub message: String,
}

/// What the Node Events should say right now. Empty means everything is healthy.
pub(crate) fn findings(inv: &CertInventory, now: OffsetDateTime) -> Vec<Finding> {
    let mut by_reason: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for rec in at_risk(inv, now) {
        let (reason, label) = if is_ca(&rec) {
            (REASON_CA_WARNING, "CA certificate")
        } else {
            (REASON_CERT_WARNING, "certificate")
        };
        by_reason.entry(reason).or_default().push(format!(
            "{label} \"{}\" {}",
            rec.subject,
            when(rec.not_after, now)
        ));
    }
    for (name, error) in inv.failures() {
        by_reason
            .entry(REASON_ROTATION_FAILED)
            .or_default()
            .push(format!("{name}: {error}"));
    }
    by_reason
        .into_iter()
        .map(|(reason, items)| Finding {
            reason,
            message: items.join("; "),
        })
        .collect()
}

fn event_type(reason: &str) -> &'static str {
    if reason == REASON_OK {
        "Normal"
    } else {
        "Warning"
    }
}

async fn upsert_event<S: Store>(
    store: &S,
    node: &serde_json::Value,
    finding: &Finding,
    now: OffsetDateTime,
) -> anyhow::Result<()> {
    let node_name = node["metadata"]["name"].as_str().unwrap_or_default();
    let name = event_name(node_name, finding.reason);
    let key = event_key(node_name, finding.reason);
    let ts = util::secs_to_rfc3339(now.unix_timestamp());
    let previous = match store.get(key.clone()).await? {
        Some(obj) => serde_json::from_slice::<serde_json::Value>(&obj.value).ok(),
        None => None,
    };
    let (uid, created, first, count) = match &previous {
        Some(p) => (
            p["metadata"]["uid"].clone(),
            p["metadata"]["creationTimestamp"].clone(),
            p["firstTimestamp"].clone(),
            p["count"].as_i64().unwrap_or(0) + 1,
        ),
        None => (
            serde_json::json!(uuid::Uuid::new_v4().to_string()),
            serde_json::json!(ts),
            serde_json::json!(ts),
            1,
        ),
    };
    let event = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {
            "name": name, "namespace": "default", "uid": uid, "creationTimestamp": created,
        },
        "involvedObject": {
            "apiVersion": "v1", "kind": "Node", "name": node_name,
            "uid": node["metadata"]["uid"],
        },
        "reason": finding.reason,
        "message": finding.message,
        "type": event_type(finding.reason),
        "count": count,
        "firstTimestamp": first,
        "lastTimestamp": ts,
        "source": { "component": COMPONENT },
        "reportingComponent": COMPONENT,
    });
    store
        .put(key, Bytes::from(serde_json::to_vec(&event)?), None)
        .await?;
    Ok(())
}

fn event_name(node_name: &str, reason: &str) -> String {
    format!("{node_name}.u7s-cert-{}", reason.to_lowercase())
}

fn event_key(node_name: &str, reason: &str) -> String {
    keys::group_object_key(
        "",
        "events",
        Some("default"),
        &event_name(node_name, reason),
    )
}

/// Remove the Warning Events of a node whose certificates are healthy again, so no stale
/// Warning sits next to the `CertificateExpirationOK` that superseded it.
async fn clear_warnings<S: Store>(store: &S, node_name: &str) -> anyhow::Result<()> {
    for reason in [
        REASON_CERT_WARNING,
        REASON_CA_WARNING,
        REASON_ROTATION_FAILED,
    ] {
        let key = event_key(node_name, reason);
        if store.get(key.clone()).await?.is_some() {
            store.delete(key, None).await?;
        }
    }
    Ok(())
}

fn is_control_plane(node: &serde_json::Value) -> bool {
    node["metadata"]["labels"]
        .get("node-role.kubernetes.io/control-plane")
        .is_some()
}

/// One monitor pass. CA findings go to every Node (every node trusts the CAs); leaf and
/// rotation-failure findings concern apiserver-held certs, so they go only to control-plane
/// Nodes (label `node-role.kubernetes.io/control-plane`). u7s's apiserver usually runs outside
/// the cluster with no such Node; then every Node gets them rather than nobody. A Node with
/// nothing to report gets `CertificateExpirationOK` once, replacing its Warning Events.
/// Returns the number of nodes found.
pub(crate) async fn emit_events<S: Store>(
    store: &S,
    watch: &CertWatch,
    ok_sent: &mut HashSet<String>,
) -> usize {
    let now = watch.clock.now();
    sync_metrics(&watch.inventory, now);
    let nodes = match store
        .list(
            keys::group_list_prefix("", "nodes", None),
            ListOptions::default(),
        )
        .await
    {
        Ok(resp) => resp.items,
        Err(e) => {
            tracing::warn!("cert expiry monitor: list nodes: {e}");
            return 0;
        }
    };
    let count = nodes.len();
    let nodes: Vec<serde_json::Value> = nodes
        .iter()
        .filter_map(|i| serde_json::from_slice(&i.value).ok())
        .collect();
    let any_control_plane = nodes.iter().any(is_control_plane);
    let found = findings(&watch.inventory, now);
    let ok = Finding {
        reason: REASON_OK,
        message: "all certificates are valid beyond their warning windows".to_owned(),
    };
    for node in &nodes {
        let name = node["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let holds_leaves = !any_control_plane || is_control_plane(node);
        let relevant: Vec<&Finding> = found
            .iter()
            .filter(|f| holds_leaves || f.reason == REASON_CA_WARNING)
            .collect();
        let to_emit: Vec<&Finding> = if !relevant.is_empty() {
            ok_sent.remove(&name);
            relevant
        } else if ok_sent.insert(name.clone()) {
            if let Err(e) = clear_warnings(store, &name).await {
                tracing::warn!("cert expiry monitor: clear warnings for node {name}: {e:#}");
            }
            vec![&ok]
        } else {
            vec![]
        };
        for finding in to_emit {
            if let Err(e) = upsert_event(store, node, finding, now).await {
                tracing::warn!("cert expiry monitor: event for node {name}: {e:#}");
            }
        }
    }
    count
}

/// Run [`emit_events`] every 30 minutes (k3s's certCheckInterval), retrying quickly until the
/// first Node exists so a fresh cluster gets its `CertificateExpirationOK`.
pub(crate) async fn run_monitor<S: Store>(store: std::sync::Arc<S>, watch: CertWatch) {
    let mut ok_sent = HashSet::new();
    loop {
        let nodes = emit_events(&*store, &watch, &mut ok_sent).await;
        tokio::time::sleep(if nodes == 0 {
            RETRY_WITHOUT_NODES
        } else {
            MONITOR_INTERVAL
        })
        .await;
    }
}

#[cfg(test)]
mod tests;
