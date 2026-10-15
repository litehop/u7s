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
    AppState::new_with_config(AppStateConfig {
        store: std::sync::Arc::new(SqliteStore::new(":memory:").expect("in-memory store")),
        sa_key: None,
        sa_decoding_key: None,
        token_map: std::collections::HashMap::new(),
        server_address: "https://localhost:6443".into(),
        cluster_ca_der: None,
        webhook_identity_pem: None,
        service_ip_allocator: Some(ServiceIpAllocator::from_cidr(RANGE).unwrap()),
        kubelet_client_identity_pem: None,
        kubelet_preferred_address: None,
        kubelet_port: 10250,
        continue_token_key: None,
        konnectivity_proxy_addr: None,
        sa_public_key_pem: None,
    })
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
            Query(PatchQuery::default()),
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
