use super::*;
use crate::pki::{CertSpec, Pki, Signer};
use axum::{body::Body, http::header::WARNING, routing::get, Router};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tower::ServiceExt as _;
use u7s_store::SqliteStore;

const DAY: i64 = 24 * 3600;

fn t0() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn after_days(d: i64) -> OffsetDateTime {
    t0() + Duration::days(d)
}

fn spec(name: &'static str, cn: &'static str, role: CertRole, days: u64) -> CertSpec<'static> {
    CertSpec {
        name,
        common_name: cn,
        organization: None,
        role,
        lifetime: StdDuration::from_secs(days * DAY as u64),
        usages: if role == CertRole::Leaf {
            &["client auth"]
        } else {
            &["cert sign"]
        },
        sans: vec![],
    }
}

/// A CA (10y) and an admin client leaf (1y) issued at `t0`, recorded in the returned inventory.
fn cluster() -> (CertInventory, Vec<u8>) {
    cluster_named("kubernetes-ca")
}

fn ca_only(ca_cn: &'static str) -> CertInventory {
    let pki = Pki {
        clock: Clock::new(t0),
        ..Pki::default()
    };
    pki.issue(&spec("ca", ca_cn, CertRole::Root, 3650), None)
        .unwrap();
    pki.inventory.clone()
}

/// `n` days before the CA (issued 5 minutes backdated) expires.
fn ca_expires_in(n: i64) -> OffsetDateTime {
    after_days(3650 - n) - Duration::minutes(5)
}

fn cluster_named(ca_cn: &'static str) -> (CertInventory, Vec<u8>) {
    let pki = Pki {
        clock: Clock::new(t0),
        ..Pki::default()
    };
    let ca_spec = spec("ca", ca_cn, CertRole::Root, 3650);
    let ca = pki.issue(&ca_spec, None).unwrap();
    let ca_not_after = t0() + Duration::days(3650);
    let issuer = rcgen::Issuer::new(pki.params(&ca_spec, t0(), ca_not_after), ca.key);
    let admin = pki
        .issue(
            &spec("admin", "admin", CertRole::Leaf, 365),
            Some(&Signer {
                issuer: &issuer,
                not_after: ca_not_after,
            }),
        )
        .unwrap();
    (pki.inventory.clone(), admin.cert.der().to_vec())
}

#[test]
fn caller_is_told_about_its_own_client_cert_only_inside_its_lifetime_scaled_window() {
    let (inv, admin_der) = cluster();
    let early = request_warnings(&inv, after_days(300), Some(&admin_der), false);
    assert!(
        early.is_empty(),
        "65 days left of a 1y cert (window 60d) must not nag the user: {early:?}"
    );
    let late = request_warnings(&inv, after_days(310), Some(&admin_der), false);
    assert_eq!(late.len(), 1, "{late:?}");
    assert!(
        late[0].contains("CN=admin") && late[0].contains("expires in 5"),
        "the user must see whose cert and how long is left: {late:?}"
    );
    assert!(
        request_warnings(&inv, after_days(310), None, false).is_empty(),
        "a caller without a client cert (token, anonymous) has no own cert to warn about"
    );
}

#[test]
fn operators_are_warned_when_the_ca_is_within_365_days() {
    let inv = ca_only("kubernetes-ca");
    assert!(request_warnings(&inv, ca_expires_in(366), None, true).is_empty());
    let w = request_warnings(&inv, ca_expires_in(300), None, true);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].contains("kubernetes-ca") && w[0].contains("expires in 300d"),
        "kubectl users pinning the CA must learn it is ending: {w:?}"
    );
}

#[test]
fn own_cert_window_scales_with_lifetime_so_short_lived_certs_do_not_nag_from_day_one() {
    let pki = Pki {
        clock: Clock::new(t0),
        ..Pki::default()
    };
    let short = pki
        .issue(&spec("short", "short-lived", CertRole::Leaf, 30), None)
        .unwrap();
    let der = short.cert.der().to_vec();
    let inv = CertInventory::default();
    assert!(
        request_warnings(&inv, after_days(10), Some(&der), false).is_empty(),
        "20 days left of a 30d cert is far outside its 5d window; a flat 120d would warn"
    );
    assert_eq!(
        request_warnings(&inv, after_days(27), Some(&der), false).len(),
        1
    );
}

#[test]
fn cluster_wide_warnings_go_only_to_operators() {
    let inv = ca_only("kubernetes-ca");
    let now = ca_expires_in(300);
    let user = |groups: &[&str]| UserInfo {
        username: "u".into(),
        uid: String::new(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        extra: Default::default(),
    };
    let sa = user(&["system:serviceaccounts", "system:authenticated"]);
    assert!(
        !is_operator(Some(&sa), "kube-controller-manager/v1.37"),
        "controllers would log the CA warning on every request"
    );
    assert!(request_warnings(&inv, now, None, false).is_empty());
    assert!(is_operator(Some(&user(&["system:masters"])), "client-go"));
    assert!(is_operator(Some(&sa), "kubectl/v1.37.1 (darwin/arm64)"));
    assert!(!is_operator(None, "curl/8"));
}

#[test]
fn client_cert_lifetime_is_observed_in_the_upstream_histogram() {
    let (inv, admin_der) = cluster();
    let h = &*crate::metrics::CLIENT_CERT_EXPIRATION_SECONDS;
    let before = h.get_sample_count();
    request_warnings(&inv, after_days(100), Some(&admin_der), false);
    assert!(
        h.get_sample_count() > before,
        "dashboards built for upstream's apiserver_client_certificate_expiration_seconds need it"
    );
    sync_metrics(&inv, after_days(100));
    let family = prometheus::gather()
        .into_iter()
        .find(|f| f.name() == "apiserver_client_certificate_expiration_seconds")
        .expect("histogram is exported under the upstream name");
    assert_eq!(
        family.get_metric()[0].get_histogram().get_bucket().len(),
        14
    );
}

#[test]
fn a_leaf_is_flagged_only_once_its_automatic_renewal_is_overdue() {
    let (inv, _) = cluster();
    assert!(
        findings(&inv, after_days(250)).is_empty(),
        "a healthy leaf renewed at 2/3 of life must not warn every request"
    );
    let late = findings(&inv, after_days(320));
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].reason, REASON_CERT_WARNING);
    assert!(late[0].message.contains("admin"), "{}", late[0].message);
}

#[test]
fn findings_use_k3s_reasons_per_cert_class_and_report_rotation_failures() {
    let inv = ca_only("kubernetes-ca");
    let f = findings(&inv, ca_expires_in(300));
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].reason, REASON_CA_WARNING);

    inv.record_failure("admin", "disk full");
    let f = findings(&inv, after_days(10));
    assert_eq!(
        f.len(),
        1,
        "a recorded failure alone must not read as healthy"
    );
    assert_eq!(f[0].reason, REASON_ROTATION_FAILED);
    assert!(f[0].message.contains("disk full"));
    inv.clear_failure("admin");
    assert!(findings(&inv, after_days(10)).is_empty());
}

async fn node_events(store: &SqliteStore) -> Vec<serde_json::Value> {
    store
        .list(
            keys::group_list_prefix("", "events", Some("default")),
            ListOptions::default(),
        )
        .await
        .unwrap()
        .items
        .iter()
        .map(|i| serde_json::from_slice(&i.value).unwrap())
        .collect()
}

fn by_reason(events: &[serde_json::Value], reason: &str) -> Option<serde_json::Value> {
    events.iter().find(|e| e["reason"] == reason).cloned()
}

#[tokio::test]
async fn operators_see_node_events_for_expiring_cas_and_failed_rotations_then_ok_once_clean() {
    let store = SqliteStore::new(":memory:").unwrap();
    let node = serde_json::json!({
        "apiVersion": "v1", "kind": "Node",
        "metadata": { "name": "worker-1", "uid": "uid-worker-1" }
    });
    store
        .put(
            keys::group_object_key("", "nodes", None, "worker-1"),
            Bytes::from(node.to_string()),
            None,
        )
        .await
        .unwrap();
    let (inv, _) = cluster();
    let now = Arc::new(AtomicI64::new(ca_expires_in(300).unix_timestamp()));
    let n = Arc::clone(&now);
    let watch = CertWatch {
        inventory: inv.clone(),
        clock: Clock::new(move || {
            OffsetDateTime::from_unix_timestamp(n.load(Ordering::SeqCst)).unwrap()
        }),
    };
    let mut ok_sent = HashSet::new();

    assert_eq!(emit_events(&store, &watch, &mut ok_sent).await, 1);
    inv.record_failure("kcm-client", "rewrite kcm.pem: read-only filesystem");
    emit_events(&store, &watch, &mut ok_sent).await;
    let events = node_events(&store).await;
    let ca = by_reason(&events, REASON_CA_WARNING).expect("CA inside 365d must raise an Event");
    assert_eq!(ca["type"], "Warning");
    assert_eq!(ca["involvedObject"]["kind"], "Node");
    assert_eq!(ca["involvedObject"]["name"], "worker-1");
    assert_eq!(ca["involvedObject"]["uid"], "uid-worker-1");
    assert_eq!(
        ca["count"], 2,
        "repeat ticks update one Event, not spam new ones"
    );
    let failed = by_reason(&events, REASON_ROTATION_FAILED)
        .expect("a failed kubeconfig rewrite must reach the operator as an Event");
    assert!(failed["message"]
        .as_str()
        .unwrap()
        .contains("read-only filesystem"));
    assert!(
        by_reason(&events, REASON_OK).is_none(),
        "no OK while anything is at risk"
    );

    inv.clear_failure("kcm-client");
    now.store(after_days(10).unix_timestamp(), Ordering::SeqCst);
    emit_events(&store, &watch, &mut ok_sent).await;
    emit_events(&store, &watch, &mut ok_sent).await;
    let ok = by_reason(&node_events(&store).await, REASON_OK).expect("clean cluster emits OK");
    assert_eq!(ok["type"], "Normal");
    assert_eq!(ok["count"], 1, "OK is emitted once, not every 30 minutes");
}

#[tokio::test]
async fn cert_warning_is_appended_next_to_the_handlers_own_warning() {
    let (inv, admin_der) = cluster();
    let watch = CertWatch {
        inventory: inv,
        clock: Clock::new(|| after_days(320)),
    };
    let app = Router::new()
        .route(
            "/",
            get(|| async { ([(WARNING, "299 - \"unknown field\"")], "ok") }),
        )
        .layer(axum::middleware::from_fn_with_state(watch, warn_requests))
        .layer(axum::middleware::from_fn(warnings::collect));
    let mut req = axum::http::Request::get("/").body(Body::empty()).unwrap();
    req.extensions_mut().insert(PeerCertificate(admin_der));
    let resp = app.oneshot(req).await.unwrap();
    let values: Vec<_> = resp
        .headers()
        .get_all(WARNING)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        values.len(),
        2,
        "field-validation and cert warnings must coexist: {values:?}"
    );
    assert!(values[0].contains("unknown field"), "{values:?}");
    assert!(
        values[1].starts_with("299 - ") && values[1].contains("CN=admin"),
        "{values:?}"
    );
}

#[test]
fn metric_has_one_series_per_inventory_cert_with_seconds_to_expiry() {
    let inv = ca_only("metric-test-ca");
    sync_metrics(&inv, ca_expires_in(1));
    let ca = crate::metrics::CERT_EXPIRATION_SECONDS
        .with_label_values(&["ca", "metric-test-ca", "cert sign"])
        .get();
    assert!(
        (ca - DAY as f64).abs() < 1.0,
        "one day left must read 86400s, got {ca}"
    );
    sync_metrics(&inv, ca_expires_in(-1));
    let expired = crate::metrics::CERT_EXPIRATION_SECONDS
        .with_label_values(&["ca", "metric-test-ca", "cert sign"])
        .get();
    assert!(
        expired < 0.0,
        "an expired cert must go negative, got {expired}"
    );
}

#[test]
fn two_certs_sharing_cn_and_usages_keep_separate_series() {
    let pki = Pki {
        clock: Clock::new(t0),
        ..Pki::default()
    };
    pki.issue(&spec("dup-a", "shared-cn", CertRole::Leaf, 10), None)
        .unwrap();
    pki.issue(&spec("dup-b", "shared-cn", CertRole::Leaf, 20), None)
        .unwrap();
    sync_metrics(&pki.inventory, t0());
    let get = |name: &str| {
        crate::metrics::CERT_EXPIRATION_SECONDS
            .with_label_values(&[name, "shared-cn", "client auth"])
            .get()
    };
    assert!(
        (get("dup-a") - 10.0 * DAY as f64).abs() < 600.0
            && (get("dup-b") - 20.0 * DAY as f64).abs() < 600.0,
        "one cert must not overwrite the other's expiry: {} / {}",
        get("dup-a"),
        get("dup-b")
    );
}

#[tokio::test]
async fn leaf_events_stay_off_worker_nodes_and_ok_replaces_stale_warnings() {
    let store = SqliteStore::new(":memory:").unwrap();
    for (name, labels) in [
        (
            "cp-1",
            serde_json::json!({"node-role.kubernetes.io/control-plane": ""}),
        ),
        ("worker-1", serde_json::json!({})),
    ] {
        let node = serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": { "name": name, "uid": format!("uid-{name}"), "labels": labels }
        });
        store
            .put(
                keys::group_object_key("", "nodes", None, name),
                Bytes::from(node.to_string()),
                None,
            )
            .await
            .unwrap();
    }
    let (inv, _) = cluster();
    let now = Arc::new(AtomicI64::new(ca_expires_in(300).unix_timestamp()));
    let n = Arc::clone(&now);
    let watch = CertWatch {
        inventory: inv.clone(),
        clock: Clock::new(move || {
            OffsetDateTime::from_unix_timestamp(n.load(Ordering::SeqCst)).unwrap()
        }),
    };
    let mut ok_sent = HashSet::new();
    inv.record_failure("kcm-client", "read-only filesystem");
    emit_events(&store, &watch, &mut ok_sent).await;
    let on = |events: &[serde_json::Value], node: &str, reason: &str| {
        events
            .iter()
            .any(|e| e["involvedObject"]["name"] == node && e["reason"] == reason)
    };
    let events = node_events(&store).await;
    assert!(on(&events, "cp-1", REASON_CA_WARNING));
    assert!(
        on(&events, "worker-1", REASON_CA_WARNING),
        "every node trusts the CA"
    );
    assert!(on(&events, "cp-1", REASON_ROTATION_FAILED));
    assert!(
        !on(&events, "worker-1", REASON_ROTATION_FAILED),
        "apiserver-held leaves are not on a kubelet-only worker; the Event would mislead"
    );

    inv.clear_failure("kcm-client");
    now.store(after_days(10).unix_timestamp(), Ordering::SeqCst);
    emit_events(&store, &watch, &mut ok_sent).await;
    let events = node_events(&store).await;
    for node in ["cp-1", "worker-1"] {
        assert!(on(&events, node, REASON_OK));
        assert!(
            !events
                .iter()
                .any(|e| e["involvedObject"]["name"] == node && e["type"] == "Warning"),
            "a stale Warning next to the OK would still look like an open problem on {node}"
        );
    }
}

#[test]
fn rotation_failure_counter_increments_so_alerts_can_fire() {
    let inv = CertInventory::default();
    let c = crate::metrics::CERT_ROTATION_FAILURES.with_label_values(&["counter-test"]);
    let before = c.get();
    inv.record_failure("counter-test", "boom");
    assert_eq!(c.get(), before + 1);
}
