use axum::body::to_bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Extension;
use serde_json::{json, Value};
use u7s_store::{SqliteStore, Store};

use super::{NODE_PORT_PREFIX, SERVICE_IP_PREFIX};
use crate::handlers::json_patch::{CreateQuery, PatchQuery, ReplaceQuery};
use crate::handlers::resource::{
    create_namespaced_resource, delete_namespaced_resource, get_namespaced_resource,
    patch_namespaced_resource, replace_namespaced_resource,
};
use crate::state::{AppState, AppStateConfig, ServiceIpAllocator};

const RANGE: &str = "10.96.0.0/24";

fn state() -> AppState<SqliteStore> {
    state_with(RANGE)
}

fn state_with(ranges: &str) -> AppState<SqliteStore> {
    let (primary, secondary) = crate::state::parse_service_cluster_ip_ranges(ranges).unwrap();
    let mut st = AppState::new_with_config(AppStateConfig {
        store: std::sync::Arc::new(SqliteStore::new(":memory:").expect("in-memory store")),
        sa_keys: None,
        token_map: std::collections::HashMap::new(),
        server_address: "https://localhost:6443".into(),
        cluster_ca_ders: None,
        service_ip_allocator: Some(primary),
        kubelet_client_identity_pem: None,
        kubelet_preferred_address: None,
        kubelet_port: 10250,
        continue_token_key: None,
        konnectivity_proxy_addr: None,
    });
    st.secondary_service_ip_allocator = secondary.map(std::sync::Arc::new);
    st
}

fn user() -> Extension<crate::auth::UserInfo> {
    Extension(crate::auth::UserInfo {
        username: "admin".into(),
        uid: String::new(),
        groups: vec![],
        extra: Default::default(),
    })
}

fn headers(content_type: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h
}

fn path(name: &str) -> Path<(String, String, String, String, String)> {
    Path((
        "".into(),
        "v1".into(),
        "default".into(),
        "services".into(),
        name.into(),
    ))
}

fn coll_path() -> Path<(String, String, String, String)> {
    Path(("".into(), "v1".into(), "default".into(), "services".into()))
}

type Reply = Result<(StatusCode, Value), (StatusCode, String)>;

async fn reply(r: Result<impl IntoResponse, crate::status::StatusError>) -> Reply {
    match r {
        Ok(resp) => {
            let resp = resp.into_response();
            let code = resp.status();
            let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            Ok((code, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
        }
        Err(e) => Err((e.0, e.1.message)),
    }
}

fn svc(name: &str, spec: Value) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    })
}

async fn create(st: &AppState<SqliteStore>, name: &str, spec: Value, dry: bool) -> Reply {
    let q = CreateQuery {
        dry_run: dry.then(|| "All".to_string()),
        ..Default::default()
    };
    reply(
        create_namespaced_resource(
            State(st.clone()),
            coll_path(),
            Query(q),
            user(),
            headers("application/json"),
            bytes::Bytes::from(serde_json::to_vec(&svc(name, spec)).unwrap()),
        )
        .await,
    )
    .await
}

async fn get(st: &AppState<SqliteStore>, name: &str) -> Value {
    reply(get_namespaced_resource(State(st.clone()), path(name), HeaderMap::new()).await)
        .await
        .expect("GET must succeed")
        .1
}

async fn put(st: &AppState<SqliteStore>, body: Value, dry: bool) -> Reply {
    let name = body["metadata"]["name"].as_str().unwrap().to_string();
    let q = ReplaceQuery {
        dry_run: dry.then(|| "All".to_string()),
        ..Default::default()
    };
    reply(
        replace_namespaced_resource(
            State(st.clone()),
            path(&name),
            Query(q),
            user(),
            headers("application/json"),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await,
    )
    .await
}

async fn patch(
    st: &AppState<SqliteStore>,
    name: &str,
    content_type: &'static str,
    body: Value,
) -> Reply {
    reply(
        patch_namespaced_resource(
            State(st.clone()),
            path(name),
            Query(PatchQuery {
                force: Some(true),
                ..Default::default()
            }),
            user(),
            headers(content_type),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await,
    )
    .await
}

async fn delete(st: &AppState<SqliteStore>, name: &str) {
    delete_namespaced_resource(
        State(st.clone()),
        path(name),
        user(),
        HeaderMap::new(),
        bytes::Bytes::new(),
    )
    .await
    .unwrap_or_else(|e| panic!("DELETE must succeed: {e:?}"));
}

async fn held(st: &AppState<SqliteStore>, key: &str) -> bool {
    st.store.get(key).await.unwrap().is_some()
}

fn ip_key(ip: &str) -> String {
    format!("{SERVICE_IP_PREFIX}{ip}")
}

fn port_key(p: i64) -> String {
    format!("{NODE_PORT_PREFIX}{p}")
}

/// A dropped transaction rolls back on a spawned task.
async fn eventually_free(st: &AppState<SqliteStore>, key: &str) {
    for _ in 0..400 {
        if !held(st, key).await {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("{key} is still reserved: a failed write leaked its reservation");
}

fn np_spec(port: i64, node_port: i64) -> Value {
    json!({"type": "NodePort", "ports": [{"port": port, "nodePort": node_port}]})
}

fn assert_422(r: Reply, needle: &str) {
    match r {
        Err((StatusCode::UNPROCESSABLE_ENTITY, msg)) => {
            assert!(
                msg.contains(needle),
                "422 message {msg:?} must contain {needle:?}"
            )
        }
        other => panic!("expected 422 containing {needle:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn two_services_cannot_silently_share_a_preset_cluster_ip() {
    let st = state();
    let spec = json!({"clusterIP": "10.96.0.50", "ports": [{"port": 80}]});
    let (code, _) = create(&st, "a", spec.clone(), false).await.unwrap();
    assert_eq!(code, StatusCode::CREATED);
    assert_422(
        create(&st, "b", spec, false).await,
        "provided IP is already allocated",
    );
    assert!(
        get_namespaced_resource(State(st.clone()), path("b"), HeaderMap::new())
            .await
            .is_err(),
        "rejected Service must not be stored"
    );
}

#[tokio::test]
async fn two_services_cannot_silently_share_a_preset_node_port() {
    let st = state();
    create(&st, "a", np_spec(80, 30080), false).await.unwrap();
    assert_422(
        create(&st, "b", np_spec(81, 30080), false).await,
        "spec.ports[0].nodePort: Invalid value: 30080: provided port is already allocated",
    );
}

#[tokio::test]
async fn preset_cluster_ip_outside_the_service_range_is_rejected() {
    let st = state();
    for bad in ["192.168.1.1", "10.96.0.0", "10.96.0.255"] {
        assert_422(
            create(
                &st,
                "a",
                json!({"clusterIP": bad, "ports": [{"port": 80}]}),
                false,
            )
            .await,
            "is not in the valid range. The range of valid IPs is 10.96.0.0/24",
        );
    }
}

#[tokio::test]
async fn preset_node_port_outside_30000_32767_is_rejected() {
    let st = state();
    for bad in [80, 29999, 32768, 70000] {
        assert_422(
            create(&st, "a", np_spec(80, bad), false).await,
            "provided port is not in the valid range. The range of valid ports is 30000-32767",
        );
    }
}

#[tokio::test]
async fn auto_allocation_never_hands_out_a_preset_reserved_ip() {
    let st = state();
    // 10.96.0.2 is where the sequential allocator starts.
    create(
        &st,
        "pinned",
        json!({"clusterIP": "10.96.0.2", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    for i in 0..5 {
        let (_, v) = create(
            &st,
            &format!("auto-{i}"),
            json!({"ports": [{"port": 80}]}),
            false,
        )
        .await
        .unwrap();
        assert_ne!(
            v["spec"]["clusterIP"], "10.96.0.2",
            "auto-allocation handed out a VIP another Service pinned"
        );
    }
}

#[tokio::test]
async fn auto_allocation_never_hands_out_a_preset_reserved_node_port() {
    let st = state();
    create(&st, "pinned", np_spec(80, 30000), false)
        .await
        .unwrap();
    let auto = json!({"type": "NodePort", "ports": [{"port": 80}]});
    let (_, v) = create(&st, "auto", auto.clone(), false).await.unwrap();
    let np = v["spec"]["ports"][0]["nodePort"].as_i64().unwrap();
    assert_ne!(
        np, 30000,
        "auto-assignment collided with another Service's nodePort"
    );
    assert!((30000..=32767).contains(&np));
    let (_, w) = create(&st, "auto2", auto, false).await.unwrap();
    assert_ne!(
        w["spec"]["ports"][0]["nodePort"], v["spec"]["ports"][0]["nodePort"],
        "auto-assigned ports must be unique across Services, not only within one object"
    );
}

#[tokio::test]
async fn deleting_a_service_releases_its_ip_and_node_port_for_reuse() {
    let st = state();
    let spec = json!({"type": "NodePort", "clusterIP": "10.96.0.60", "ports": [{"port": 80, "nodePort": 30060}]});
    create(&st, "a", spec.clone(), false).await.unwrap();
    assert_422(
        create(&st, "b", spec.clone(), false).await,
        "already allocated",
    );
    delete(&st, "a").await;
    create(&st, "b", spec, false)
        .await
        .expect("values of a deleted Service must be reusable");
}

#[tokio::test]
async fn dry_run_create_does_not_reserve_preset_values() {
    let st = state();
    let spec = json!({"type": "NodePort", "clusterIP": "10.96.0.70", "ports": [{"port": 80, "nodePort": 30070}]});
    let (code, _) = create(&st, "a", spec.clone(), true).await.unwrap();
    assert_eq!(code, StatusCode::CREATED);
    create(&st, "b", spec.clone(), false)
        .await
        .expect("a dry-run must not have reserved anything");
    assert_422(create(&st, "c", spec, true).await, "already allocated");
}

#[tokio::test]
async fn failed_create_does_not_leak_its_reservations() {
    let st = state();
    create(&st, "a", json!({"ports": [{"port": 80}]}), false)
        .await
        .unwrap();
    // Name conflict: the object write fails after the reservations were taken.
    let dup = create(&st, "a", np_spec(80, 30090), false).await;
    assert!(matches!(dup, Ok((StatusCode::CONFLICT, _))), "{dup:?}");
    eventually_free(&st, &port_key(30090)).await;

    // IP reserved first, then the port conflicts: the IP must be given back.
    create(&st, "p", np_spec(80, 30091), false).await.unwrap();
    let both = create(
        &st,
        "q",
        json!({"type": "NodePort", "clusterIP": "10.96.0.91", "ports": [{"port": 80, "nodePort": 30091}]}),
        false,
    )
    .await;
    assert_422(both, "already allocated");
    eventually_free(&st, &ip_key("10.96.0.91")).await;
}

#[tokio::test]
async fn put_type_change_away_from_node_port_frees_the_port() {
    let st = state();
    create(&st, "a", np_spec(80, 30100), false).await.unwrap();
    let mut a = get(&st, "a").await;
    a["spec"]["type"] = json!("ClusterIP");
    let (_, after) = put(&st, a, false).await.unwrap();
    assert_eq!(
        after["spec"]["ports"][0]["nodePort"].as_i64().unwrap_or(0),
        0,
        "ClusterIP Services carry no nodePort"
    );
    create(&st, "b", np_spec(80, 30100), false)
        .await
        .expect("NodePort -> ClusterIP must release the node port");

    let mut a = get(&st, "a").await;
    a["spec"]["type"] = json!("NodePort");
    a["spec"]["ports"][0]["nodePort"] = json!(30100);
    assert_422(
        put(&st, a, false).await,
        "provided port is already allocated",
    );
}

#[tokio::test]
async fn put_to_external_name_releases_ip_and_ports_and_back_allocates_fresh() {
    let st = state();
    create(
        &st,
        "a",
        json!({"type": "NodePort", "clusterIP": "10.96.0.110", "ports": [{"port": 80, "nodePort": 30110}]}),
        false,
    )
    .await
    .unwrap();
    let mut a = get(&st, "a").await;
    a["spec"]["type"] = json!("ExternalName");
    a["spec"]["externalName"] = json!("example.com");
    put(&st, a, false).await.unwrap();
    assert!(!held(&st, &ip_key("10.96.0.110")).await);
    assert!(!held(&st, &port_key(30110)).await);

    let mut a = get(&st, "a").await;
    a["spec"]["type"] = json!("ClusterIP");
    let (_, back) = put(&st, a, false).await.unwrap();
    let ip = back["spec"]["clusterIP"].as_str().unwrap().to_string();
    assert!(held(&st, &ip_key(&ip)).await);
}

#[tokio::test]
async fn put_dry_run_neither_reserves_nor_releases() {
    let st = state();
    create(&st, "a", np_spec(80, 30120), false).await.unwrap();
    let mut a = get(&st, "a").await;
    a["spec"]["ports"][0]["nodePort"] = json!(30121);
    put(&st, a, true).await.unwrap();
    assert!(held(&st, &port_key(30120)).await, "dry-run released");
    assert!(!held(&st, &port_key(30121)).await, "dry-run reserved");
}

#[tokio::test]
async fn patch_cannot_steal_another_services_node_port_in_any_patch_type() {
    let st = state();
    create(&st, "owner", np_spec(80, 30130), false)
        .await
        .unwrap();
    create(&st, "other", np_spec(80, 30131), false)
        .await
        .unwrap();
    let cases: [(&str, Value); 4] = [
        (
            "application/strategic-merge-patch+json",
            json!({"spec": {"ports": [{"port": 80, "nodePort": 30130}]}}),
        ),
        (
            "application/merge-patch+json",
            json!({"spec": {"ports": [{"port": 80, "nodePort": 30130, "protocol": "TCP", "targetPort": 80}]}}),
        ),
        (
            "application/json-patch+json",
            json!([{"op": "replace", "path": "/spec/ports/0/nodePort", "value": 30130}]),
        ),
        (
            "application/apply-patch+yaml",
            svc("other", np_spec(80, 30130)),
        ),
    ];
    for (ct, body) in cases {
        assert_422(
            patch(&st, "other", ct, body).await,
            "provided port is already allocated",
        );
    }
    assert!(
        held(&st, &port_key(30131)).await,
        "rejected patch released the old port"
    );
}

#[tokio::test]
async fn patch_type_change_reserves_and_releases_like_put() {
    let st = state();
    create(
        &st,
        "a",
        json!({"type": "ExternalName", "externalName": "x.example.com"}),
        false,
    )
    .await
    .unwrap();
    let (_, v) = patch(
        &st,
        "a",
        "application/merge-patch+json",
        json!({"spec": {"type": "NodePort", "externalName": null, "ports": [{"port": 80}]}}),
    )
    .await
    .unwrap();
    let ip = v["spec"]["clusterIP"].as_str().unwrap_or("").to_string();
    let np = v["spec"]["ports"][0]["nodePort"].as_i64().unwrap_or(0);
    assert!(
        !ip.is_empty(),
        "ExternalName -> NodePort via PATCH must allocate a clusterIP: {v}"
    );
    assert!(held(&st, &ip_key(&ip)).await);
    assert!(held(&st, &port_key(np)).await);

    patch(
        &st,
        "a",
        "application/merge-patch+json",
        json!({"spec": {"type": "ClusterIP"}}),
    )
    .await
    .unwrap();
    assert!(
        !held(&st, &port_key(np)).await,
        "NodePort -> ClusterIP must free the port"
    );
    assert!(held(&st, &ip_key(&ip)).await, "clusterIP is kept");
}

#[tokio::test]
async fn headless_service_reserves_no_ip() {
    let st = state();
    create(
        &st,
        "h",
        json!({"clusterIP": "None", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    assert!(!held(&st, &ip_key("None")).await);
    delete(&st, "h").await;
}

#[tokio::test]
async fn preset_health_check_node_port_is_validated_and_reserved() {
    let st = state();
    let lb = |p: i64| json!({"type": "LoadBalancer", "externalTrafficPolicy": "Local", "healthCheckNodePort": p, "ports": [{"port": 80}]});
    create(&st, "a", lb(30140), false).await.unwrap();
    assert_422(
        create(&st, "b", lb(30140), false).await,
        "provided port is already allocated",
    );
    assert_422(create(&st, "c", lb(80), false).await, "valid range");
    assert_422(
        create(&st, "d", np_spec(80, 30140), false).await,
        "already allocated",
    );
    let (_, v) = create(
        &st,
        "e",
        json!({"type": "LoadBalancer", "externalTrafficPolicy": "Local", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    assert!(
        v["spec"]["healthCheckNodePort"].as_i64().unwrap_or(0) >= 30000,
        "{v}"
    );
    delete(&st, "a").await;
    assert!(!held(&st, &port_key(30140)).await);
}

#[tokio::test]
async fn multi_protocol_port_shares_one_node_port_and_releases_it_once() {
    let st = state();
    let (_, v) = create(
        &st,
        "dns",
        json!({"type": "NodePort", "ports": [
            {"name": "t", "port": 53, "protocol": "TCP"},
            {"name": "u", "port": 53, "protocol": "UDP"},
        ]}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        v["spec"]["ports"][0]["nodePort"],
        v["spec"]["ports"][1]["nodePort"]
    );
    delete(&st, "dns").await;
    let left = st
        .store
        .list(NODE_PORT_PREFIX, u7s_store::ListOptions::default())
        .await
        .unwrap();
    assert!(left.items.is_empty());
}

/// The bootstrap reserves kube-dns's VIP before the CoreDNS manifest is applied. Without
/// owner-aware reservation the manifest's own create is refused as "already allocated",
/// the boot-time apply is fatal and no cluster ever comes up.
#[tokio::test]
async fn service_may_claim_its_own_pre_reserved_cluster_ip_but_nobody_else_can() {
    let st = state();
    st.store
        .put(
            &ip_key("10.96.0.50"),
            super::owned_ip_sentinel("default", "pre"),
            Some(0),
        )
        .await
        .unwrap();
    assert_422(
        create(&st, "thief", json!({"clusterIP": "10.96.0.50"}), false).await,
        "provided IP is already allocated",
    );
    let r = patch(
        &st,
        "pre",
        "application/apply-patch+yaml",
        svc(
            "pre",
            json!({"clusterIP": "10.96.0.50", "ports": [{"port": 53}]}),
        ),
    )
    .await;
    assert!(r.is_ok(), "owner's SSA create must succeed: {r:?}");
    assert_422(
        create(&st, "thief2", json!({"clusterIP": "10.96.0.50"}), false).await,
        "provided IP is already allocated",
    );
    assert!(held(&st, &ip_key("10.96.0.50")).await);
}

/// default/kubernetes is seeded straight into the store. If its VIP is not reserved, a
/// tenant Service can claim the apiserver's in-cluster address and kube-proxy programs a
/// second backend set on it, intercepting in-cluster API traffic.
#[tokio::test]
async fn user_service_cannot_claim_the_kubernetes_service_vip() {
    let st = state();
    let first = ServiceIpAllocator::from_cidr(RANGE)
        .unwrap()
        .nth_host(1)
        .unwrap()
        .to_string();
    crate::seed_services(&st.store, "127.0.0.1", 6443, RANGE, None)
        .await
        .unwrap();
    assert_422(
        create(&st, "thief", json!({"clusterIP": first}), false).await,
        "provided IP is already allocated",
    );
    let sentinel = st.store.get(&ip_key(&first)).await.unwrap().unwrap();
    assert!(
        String::from_utf8_lossy(&sentinel.value).contains("default/kubernetes"),
        "the VIP sentinel must be owned by default/kubernetes"
    );
}

/// A store seeded by an older build holds default/kubernetes without a VIP reservation; the
/// next boot must add it so existing clusters are protected too.
#[tokio::test]
async fn seed_services_reserves_the_kubernetes_vip_on_an_existing_store() {
    let st = state();
    let first = ServiceIpAllocator::from_cidr(RANGE)
        .unwrap()
        .nth_host(1)
        .unwrap()
        .to_string();
    crate::seed_services(&st.store, "127.0.0.1", 6443, RANGE, None)
        .await
        .unwrap();
    st.store.delete(&ip_key(&first), None).await.unwrap();
    crate::seed_services(&st.store, "127.0.0.1", 6443, RANGE, None)
        .await
        .unwrap();
    assert!(held(&st, &ip_key(&first)).await);
    let svc = get(&st, "kubernetes").await;
    assert_eq!(svc["spec"]["clusterIP"], first);
}

async fn store_without_sentinels(st: &AppState<SqliteStore>, ns: &str, name: &str, spec: Value) {
    let mut body = svc(name, spec);
    body["metadata"]["namespace"] = json!(ns);
    st.store
        .put(
            &format!("/registry/services/{ns}/{name}"),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            Some(0),
        )
        .await
        .unwrap();
}

/// Services stored before reservations existed hold values no sentinel records, so the
/// lowest-free auto-allocator would hand their nodePort or VIP to a new Service.
#[tokio::test]
async fn repair_backfills_reservations_so_auto_allocation_never_collides() {
    let st = state();
    store_without_sentinels(
        &st,
        "default",
        "old",
        json!({
            "type": "LoadBalancer", "externalTrafficPolicy": "Local",
            "clusterIP": "10.96.0.2", "clusterIPs": ["10.96.0.2"],
            "healthCheckNodePort": 30001,
            "ports": [{"port": 80, "nodePort": 30000}]
        }),
    )
    .await;
    let report = super::repair(&*st.store).await.unwrap();
    assert_eq!(report.seeded, 3, "{report:?}");
    for k in [ip_key("10.96.0.2"), port_key(30000), port_key(30001)] {
        assert!(held(&st, &k).await, "{k} must be reserved after repair");
    }

    let (_, v) = create(&st, "new", np_spec(80, 0), false).await.unwrap();
    assert_eq!(
        v["spec"]["ports"][0]["nodePort"], 30002,
        "auto-assigned nodePort must skip the ports the old Service holds"
    );
    assert_ne!(v["spec"]["clusterIP"], "10.96.0.2");

    delete(&st, "old").await;
    assert!(
        !held(&st, &port_key(30000)).await && held(&st, &port_key(30002)).await,
        "deleting the old Service releases only its own reservations"
    );
}

/// A crash between reserving and storing leaves sentinels no Service holds; they would
/// shrink the pool forever. Sentinels reserved ahead for a not-yet-created Service
/// (kube-dns, kubernetes) are not orphans.
#[tokio::test]
async fn repair_releases_orphans_but_keeps_pre_reserved_owned_sentinels() {
    let st = state();
    for key in [ip_key("10.96.0.77"), port_key(30077)] {
        st.store
            .put(&key, bytes::Bytes::from_static(b"{}"), Some(0))
            .await
            .unwrap();
    }
    st.store
        .put(
            &ip_key("10.96.0.10"),
            super::owned_ip_sentinel("kube-system", "kube-dns"),
            Some(0),
        )
        .await
        .unwrap();
    let report = super::repair(&*st.store).await.unwrap();
    assert_eq!(report.released, 2, "{report:?}");
    assert!(!held(&st, &ip_key("10.96.0.77")).await);
    assert!(!held(&st, &port_key(30077)).await);
    assert!(held(&st, &ip_key("10.96.0.10")).await);
}

/// Like upstream, two Services holding one value are reported and left untouched; a
/// corrupt store must not stop the apiserver from booting.
#[tokio::test]
async fn repair_reports_duplicates_without_failing_or_changing_services() {
    let st = state();
    let spec = json!({"type": "NodePort", "clusterIP": "10.96.0.5", "clusterIPs": ["10.96.0.5"],
        "ports": [{"port": 80, "nodePort": 30005}]});
    store_without_sentinels(&st, "default", "a", spec.clone()).await;
    store_without_sentinels(&st, "default", "b", spec).await;
    let report = super::repair(&*st.store).await.unwrap();
    assert_eq!(report.conflicts.len(), 2, "{report:?}");
    assert!(report
        .conflicts
        .iter()
        .all(|c| c.contains("default/a") && c.contains("default/b")));
    assert!(held(&st, &ip_key("10.96.0.5")).await && held(&st, &port_key(30005)).await);
    assert_eq!(get(&st, "b").await["spec"]["ports"][0]["nodePort"], 30005);
}

/// Repair must converge with owned sentinels: a Service holding the IP reserved for it is
/// consistent (no conflict, nothing released), and a second pass is a no-op.
#[tokio::test]
async fn repair_is_idempotent_and_agrees_with_owned_sentinels() {
    let st = state();
    crate::seed_services(&st.store, "127.0.0.1", 6443, RANGE, None)
        .await
        .unwrap();
    store_without_sentinels(
        &st,
        "kube-system",
        "kube-dns",
        json!({"clusterIP": "10.96.0.10", "clusterIPs": ["10.96.0.10"]}),
    )
    .await;
    let first = super::repair(&*st.store).await.unwrap();
    assert_eq!(
        (first.seeded, first.released, first.conflicts.len()),
        (0, 0, 0),
        "{first:?}"
    );
    let second = super::repair(&*st.store).await.unwrap();
    assert_eq!((second.seeded, second.released), (0, 0), "{second:?}");
    assert!(held(&st, &ip_key("10.96.0.1")).await);
}

async fn held_ips(st: &AppState<SqliteStore>) -> Vec<String> {
    let mut keys: Vec<String> = st
        .store
        .list(SERVICE_IP_PREFIX, u7s_store::ListOptions::default())
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|o| o.key)
        .collect();
    keys.sort();
    keys
}

/// The clusterIP is auto-allocated before quota admission runs; a Service the quota turns
/// away must not keep its VIP, or every rejected create permanently shrinks the pool.
#[tokio::test]
async fn quota_rejected_create_does_not_leak_its_auto_allocated_cluster_ip() {
    let st = state();
    let before = held_ips(&st).await;
    st.store
        .put(
            "/registry/resourcequotas/default/no-services",
            bytes::Bytes::from(
                json!({
                    "apiVersion": "v1", "kind": "ResourceQuota",
                    "metadata": {"name": "no-services", "namespace": "default"},
                    "spec": {"hard": {"services": "0"}},
                })
                .to_string(),
            ),
            Some(0),
        )
        .await
        .unwrap();

    let r = create(&st, "denied", json!({"ports": [{"port": 80}]}), false).await;
    assert!(matches!(r, Err((StatusCode::FORBIDDEN, _))), "{r:?}");
    for _ in 0..400 {
        if held_ips(&st).await == before {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!(
        "a create rejected by quota leaked its auto-allocated clusterIP: {:?}",
        held_ips(&st).await
    );
}

/// A client that disconnects while its Service is being written cancels the handler future,
/// but the store write still lands. The persisted Service must keep its VIP and node port:
/// freeing them would let the next Service be handed the same address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_during_create_keeps_reservations_of_the_persisted_service() {
    use std::future::Future;
    use std::task::{Context, Waker};

    let mut cancelled_after_persist = 0;
    for _ in 0..50 {
        let st = state();
        let body = svc("svc", np_spec(80, 0));
        let mut fut = Box::pin(create_namespaced_resource(
            State(st.clone()),
            coll_path(),
            Query(CreateQuery::default()),
            user(),
            headers("application/json"),
            bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if fut.as_mut().poll(&mut cx).is_ready() {
                break;
            }
            if st
                .store
                .get("/registry/services/default/svc")
                .await
                .unwrap()
                .is_some()
            {
                drop(fut);
                cancelled_after_persist += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                let stored = get(&st, "svc").await;
                let ip = stored["spec"]["clusterIP"].as_str().unwrap();
                let np = stored["spec"]["ports"][0]["nodePort"].as_i64().unwrap();
                assert!(
                    held(&st, &ip_key(ip)).await,
                    "persisted Service lost its clusterIP reservation on client disconnect"
                );
                assert!(
                    held(&st, &port_key(np)).await,
                    "persisted Service lost its nodePort reservation on client disconnect"
                );
                break;
            }
            tokio::task::yield_now().await;
        }
    }
    assert!(
        cancelled_after_persist > 0,
        "never cancelled a create after its write landed; the test did not exercise the window"
    );
}

// ---------------------------------------------------------------------------
// Dual-stack: one allocator per family behind the shared create/PUT/PATCH path.
// ---------------------------------------------------------------------------

const DUAL: &str = "10.96.0.0/24,fd00:96::/120";

fn cluster_ips(v: &Value) -> Vec<String> {
    v["spec"]["clusterIPs"]
        .as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn is_v6(ip: &str) -> bool {
    ip.contains(':')
}

#[tokio::test]
async fn require_dual_stack_create_gets_one_cluster_ip_per_family_primary_first() {
    let st = state_with(DUAL);
    let (code, v) = create(
        &st,
        "d",
        json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(code, StatusCode::CREATED);
    let ips = cluster_ips(&v);
    assert_eq!(
        ips.len(),
        2,
        "RequireDualStack must yield two clusterIPs: {v}"
    );
    assert!(
        !is_v6(&ips[0]) && is_v6(&ips[1]),
        "v4 primary first: {ips:?}"
    );
    assert_eq!(v["spec"]["clusterIP"], ips[0].as_str());
    assert_eq!(v["spec"]["ipFamilies"], json!(["IPv4", "IPv6"]));
    for ip in &ips {
        assert!(held(&st, &ip_key(ip)).await, "{ip} must be reserved");
    }
    let stored = get(&st, "d").await;
    assert_eq!(cluster_ips(&stored), ips, "the persisted object keeps both");
}

#[tokio::test]
async fn prefer_dual_stack_and_ipv6_single_stack_allocate_from_the_right_pool() {
    let st = state_with(DUAL);
    let (_, p) = create(
        &st,
        "p",
        json!({"ipFamilyPolicy": "PreferDualStack", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    assert_eq!(cluster_ips(&p).len(), 2);

    let (_, s6) = create(
        &st,
        "s6",
        json!({"ipFamilies": ["IPv6"], "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    let ips = cluster_ips(&s6);
    assert_eq!(
        ips.len(),
        1,
        "SingleStack IPv6 must hold exactly one IP: {s6}"
    );
    assert!(
        ips[0].starts_with("fd00:96::"),
        "an IPv6-only Service must come from the IPv6 range, got {ips:?}"
    );
    assert_eq!(s6["spec"]["ipFamilyPolicy"], "SingleStack");
    assert_eq!(s6["spec"]["clusterIP"], ips[0].as_str());
}

#[tokio::test]
async fn unconfigured_service_stays_single_stack_on_the_primary_family() {
    for (ranges, v6) in [(DUAL, false), ("fd00:96::/120,10.96.0.0/24", true)] {
        let st = state_with(ranges);
        let (_, v) = create(&st, "x", json!({"ports": [{"port": 80}]}), false)
            .await
            .unwrap();
        let ips = cluster_ips(&v);
        assert_eq!(
            ips.len(),
            1,
            "a plain Service must not become dual-stack: {v}"
        );
        assert_eq!(
            is_v6(&ips[0]),
            v6,
            "primary family follows range order: {ips:?}"
        );
    }
}

#[tokio::test]
async fn require_dual_stack_is_rejected_on_a_single_stack_cluster_without_leaking_an_ip() {
    let st = state();
    assert_422(
        create(
            &st,
            "d",
            json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
            false,
        )
        .await,
        "spec.ipFamilyPolicy: Invalid value: \"RequireDualStack\": this cluster is not configured for dual-stack services",
    );
    assert!(
        held_ips(&st).await.is_empty(),
        "a rejected create must not take an IP"
    );
}

#[tokio::test]
async fn explicit_cluster_ips_per_family_are_reserved_and_validated_against_their_own_range() {
    let st = state_with(DUAL);
    let spec = json!({
        "ipFamilyPolicy": "RequireDualStack",
        "clusterIPs": ["fd00:96::40", "10.96.0.40"],
        "ports": [{"port": 80}],
    });
    let (_, v) = create(&st, "a", spec.clone(), false).await.unwrap();
    assert_eq!(
        v["spec"]["ipFamilies"],
        json!(["IPv6", "IPv4"]),
        "user order defines family order"
    );
    assert_eq!(cluster_ips(&v), ["fd00:96::40", "10.96.0.40"]);
    assert!(held(&st, &ip_key("fd00:96::40")).await);

    assert_422(
        create(&st, "b", spec, false).await,
        "provided IP is already allocated",
    );
    assert_422(
        create(
            &st,
            "c",
            json!({"clusterIP": "fd00:97::5", "ports": [{"port": 80}]}),
            false,
        )
        .await,
        "The range of valid IPs is fd00:96::/120",
    );
    assert_422(
        create(
            &st,
            "e",
            json!({"ipFamilyPolicy": "RequireDualStack", "clusterIPs": ["10.96.0.41", "10.96.0.42"], "ports": [{"port": 80}]}),
            false,
        )
        .await,
        "may specify no more than one IP for each IP family",
    );
}

#[tokio::test]
async fn deleting_a_dual_stack_service_releases_both_addresses() {
    let st = state_with(DUAL);
    let (_, v) = create(
        &st,
        "d",
        json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    let ips = cluster_ips(&v);
    delete(&st, "d").await;
    for ip in &ips {
        assert!(!held(&st, &ip_key(ip)).await, "{ip} leaked after delete");
    }
}

/// An exhausted IPv6 pool is a 500 for IPv6 allocations only, and a dual-stack create that
/// fails on the second family must give the first family's address back.
#[tokio::test]
async fn exhausting_ipv6_fails_only_ipv6_and_leaks_no_ipv4_address() {
    let st = state_with("10.96.0.0/24,fd00:96::/126");
    let v6_only = json!({"ipFamilies": ["IPv6"], "ports": [{"port": 80}]});
    for n in ["a", "b"] {
        create(&st, n, v6_only.clone(), false).await.unwrap();
    }
    match create(&st, "c", v6_only, false).await {
        Err((StatusCode::INTERNAL_SERVER_ERROR, _)) => {}
        other => panic!("exhausted IPv6 pool must answer 500, got {other:?}"),
    }
    let before = held_ips(&st).await;
    match create(
        &st,
        "dual",
        json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
        false,
    )
    .await
    {
        Err((StatusCode::INTERNAL_SERVER_ERROR, _)) => {}
        other => panic!("dual-stack create needing the full pool must answer 500, got {other:?}"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        held_ips(&st).await,
        before,
        "the IPv4 half of a failed dual create leaked"
    );
    let (code, v) = create(&st, "v4", json!({"ports": [{"port": 80}]}), false)
        .await
        .expect("IPv4 must stay allocatable while IPv6 is full");
    assert_eq!(code, StatusCode::CREATED);
    assert!(!is_v6(&cluster_ips(&v)[0]));
}

async fn upgrade_then_downgrade(patch_kind: &str) {
    let st = state_with(DUAL);
    let (_, v) = create(&st, "u", json!({"ports": [{"port": 80}]}), false)
        .await
        .unwrap();
    let primary = cluster_ips(&v)[0].clone();

    for (policy, want_len) in [("RequireDualStack", 2), ("SingleStack", 1)] {
        let r = match patch_kind {
            "put" => {
                let mut body = get(&st, "u").await;
                body["spec"]["ipFamilyPolicy"] = json!(policy);
                put(&st, body, false).await
            }
            "merge" => {
                patch(
                    &st,
                    "u",
                    "application/merge-patch+json",
                    json!({"spec": {"ipFamilyPolicy": policy}}),
                )
                .await
            }
            "strategic" => {
                patch(
                    &st,
                    "u",
                    "application/strategic-merge-patch+json",
                    json!({"spec": {"ipFamilyPolicy": policy}}),
                )
                .await
            }
            "json" => {
                patch(
                    &st,
                    "u",
                    "application/json-patch+json",
                    json!([{"op": "add", "path": "/spec/ipFamilyPolicy", "value": policy}]),
                )
                .await
            }
            _ => unreachable!(),
        };
        let (_, after) = r.unwrap_or_else(|e| panic!("{patch_kind} {policy}: {e:?}"));
        let ips = cluster_ips(&after);
        assert_eq!(ips.len(), want_len, "{patch_kind} -> {policy}: {after}");
        assert_eq!(
            ips[0], primary,
            "{patch_kind}: the primary clusterIP must never move"
        );
        if want_len == 2 {
            assert!(is_v6(&ips[1]) && held(&st, &ip_key(&ips[1])).await);
            assert_eq!(after["spec"]["ipFamilies"], json!(["IPv4", "IPv6"]));
        } else {
            assert_eq!(after["spec"]["ipFamilies"], json!(["IPv4"]));
        }
    }
    let stored = get(&st, "u").await;
    assert_eq!(cluster_ips(&stored), [primary.as_str()]);
    assert_eq!(
        held_ips(&st).await,
        vec![ip_key(&primary)],
        "{patch_kind}: downgrading must release the secondary address"
    );
}

#[tokio::test]
async fn put_upgrade_and_downgrade_allocate_and_release_the_secondary() {
    upgrade_then_downgrade("put").await;
}

#[tokio::test]
async fn merge_patch_upgrade_and_downgrade_allocate_and_release_the_secondary() {
    upgrade_then_downgrade("merge").await;
}

#[tokio::test]
async fn strategic_patch_upgrade_and_downgrade_allocate_and_release_the_secondary() {
    upgrade_then_downgrade("strategic").await;
}

#[tokio::test]
async fn json_patch_upgrade_and_downgrade_allocate_and_release_the_secondary() {
    upgrade_then_downgrade("json").await;
}

/// `kubectl apply --server-side` creates and then updates through the apply branch of the
/// patch handler, which must resolve families and allocate exactly like POST and PUT.
#[tokio::test]
async fn server_side_apply_create_and_upgrade_allocate_per_family() {
    let st = state_with(DUAL);
    let applied = |policy: &str| {
        svc(
            "ssa",
            json!({"ipFamilyPolicy": policy, "ports": [{"port": 80}]}),
        )
    };
    let (_, v) = patch(
        &st,
        "ssa",
        "application/apply-patch+yaml",
        applied("PreferDualStack"),
    )
    .await
    .unwrap();
    assert_eq!(
        cluster_ips(&v).len(),
        2,
        "apply-create must allocate both: {v}"
    );

    let (_, one) = patch(
        &st,
        "ssa2",
        "application/apply-patch+yaml",
        svc(
            "ssa2",
            json!({"ipFamilyPolicy": "SingleStack", "ports": [{"port": 80}]}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(cluster_ips(&one).len(), 1);
    let (_, up) = patch(
        &st,
        "ssa2",
        "application/apply-patch+yaml",
        svc(
            "ssa2",
            json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
        ),
    )
    .await
    .unwrap();
    let ips = cluster_ips(&up);
    assert_eq!(
        ips.len(),
        2,
        "apply-update to RequireDualStack must allocate the secondary: {up}"
    );
    assert_eq!(ips[0], cluster_ips(&one)[0]);
}

#[tokio::test]
async fn primary_cluster_ip_cannot_change_and_secondary_release_needs_single_stack() {
    let st = state_with(DUAL);
    let (_, v) = create(
        &st,
        "i",
        json!({"ipFamilyPolicy": "RequireDualStack", "clusterIPs": ["10.96.0.40", "fd00:96::40"], "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    let ips = cluster_ips(&v);

    let mut moved = get(&st, "i").await;
    moved["spec"]["clusterIPs"] = json!(["10.96.0.99", ips[1]]);
    moved["spec"]["clusterIP"] = json!("10.96.0.99");
    assert_422(put(&st, moved, false).await, "may not change once set");
    assert_422(
        patch(
            &st,
            "i",
            "application/merge-patch+json",
            json!({"spec": {"clusterIPs": ["10.96.0.99", ips[1]], "clusterIP": "10.96.0.99"}}),
        )
        .await,
        "may not change once set",
    );

    assert_422(
        patch(
            &st,
            "i",
            "application/merge-patch+json",
            json!({"spec": {"clusterIPs": [ips[0]]}}),
        )
        .await,
        "must be 'SingleStack' to release the secondary cluster IP",
    );
    assert!(
        held(&st, &ip_key(&ips[1])).await,
        "a rejected downgrade must not release the IP"
    );
}

/// kubectl replace sends only what the user wrote; leaving out the allocated addresses
/// must keep them rather than allocate fresh ones that then trip the immutability check.
#[tokio::test]
async fn put_without_cluster_ips_keeps_both_allocated_addresses() {
    let st = state_with(DUAL);
    let (_, v) = create(
        &st,
        "k",
        json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    let ips = cluster_ips(&v);
    let mut body = svc(
        "k",
        json!({"ipFamilyPolicy": "RequireDualStack", "ports": [{"port": 8080}]}),
    );
    body["metadata"]["resourceVersion"] = v["metadata"]["resourceVersion"].clone();
    let (_, after) = put(&st, body, false).await.unwrap();
    assert_eq!(cluster_ips(&after), ips);
    assert_eq!(held_ips(&st).await.len(), 2);
}

#[tokio::test]
async fn kubernetes_service_stays_single_stack_on_the_primary_family_and_cidr_lists_both() {
    let st = state_with(DUAL);
    crate::seed_services(&st.store, "127.0.0.1", 6443, DUAL, None)
        .await
        .unwrap();
    crate::seed_servicecidrs(&st.store, DUAL).await.unwrap();
    let k = get(&st, "kubernetes").await;
    assert_eq!(k["spec"]["clusterIPs"], json!(["10.96.0.1"]));
    assert_eq!(k["spec"]["ipFamilies"], json!(["IPv4"]));
    assert_eq!(k["spec"]["ipFamilyPolicy"], "SingleStack");
    assert!(held(&st, &ip_key("10.96.0.1")).await);

    let cidr = st
        .store
        .get("/registry/networking.k8s.io/servicecidrs/kubernetes")
        .await
        .unwrap()
        .expect("ServiceCIDR must be seeded");
    let cidr: Value = serde_json::from_slice(&cidr.value).unwrap();
    assert_eq!(
        cidr["spec"]["cidrs"],
        json!(["10.96.0.0/24", "fd00:96::/120"]),
        "the default ServiceCIDR must list every configured range"
    );

    let v6_range = "fd00:96::/120,10.96.0.0/24";
    let v6 = state_with(v6_range);
    crate::seed_services(&v6.store, "127.0.0.1", 6443, v6_range, None)
        .await
        .unwrap();
    let k = get(&v6, "kubernetes").await;
    assert_eq!(k["spec"]["clusterIPs"], json!(["fd00:96::1"]));
    assert_eq!(k["spec"]["ipFamilies"], json!(["IPv6"]));
}

#[tokio::test]
async fn repair_reserves_ipv6_cluster_ips_under_their_canonical_key() {
    let st = state_with(DUAL);
    store_without_sentinels(
        &st,
        "default",
        "old",
        json!({
            "clusterIP": "10.96.0.2", "clusterIPs": ["10.96.0.2", "fd00:96::2"],
            "ipFamilies": ["IPv4", "IPv6"], "ipFamilyPolicy": "RequireDualStack",
        }),
    )
    .await;
    super::repair(&*st.store).await.unwrap();
    assert!(held(&st, &ip_key("fd00:96::2")).await);
    let (_, v) = create(
        &st,
        "new",
        json!({"ipFamilies": ["IPv6"], "ports": [{"port": 80}]}),
        false,
    )
    .await
    .unwrap();
    assert_ne!(
        cluster_ips(&v)[0],
        "fd00:96::2",
        "after a restart, auto-allocation must skip the IPv6 address an existing Service holds"
    );
}
