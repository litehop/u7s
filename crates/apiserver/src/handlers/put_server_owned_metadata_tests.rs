//! A full-object PUT takes server-managed metadata (creationTimestamp, deletionTimestamp,
//! deletionGracePeriodSeconds) from the stored object, never the request body (upstream
//! `rest.BeforeUpdate`). Clients that rebuild the body from scratch — beep's Lease renewals,
//! a hand-written `kubectl replace` manifest, any protobuf client (the decoder drops the
//! deletion fields) — must not erase an object's age or un-terminate it.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue},
    Extension,
};
use bytes::Bytes;
use serde_json::{json, Value};
use u7s_store::Store;

use crate::auth::UserInfo;
use crate::handlers::json_patch::ReplaceQuery;
use crate::handlers::namespaces::replace_namespace;
use crate::handlers::resource::{replace_namespaced_resource, replace_resource};
use crate::handlers::test_support::make_state;

const STORED_TS: &str = "2020-01-02T03:04:05Z";
const DELETING_TS: &str = "2021-01-01T00:00:00Z";

fn user() -> Extension<UserInfo> {
    Extension(UserInfo {
        username: "admin".into(),
        uid: String::new(),
        groups: vec![],
        extra: Default::default(),
    })
}

fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h
}

async fn seed(state: &crate::state::AppState, key: &str, body: Value) -> u64 {
    state
        .store
        .put(key, Bytes::from(body.to_string()), Some(0))
        .await
        .expect("seed")
}

async fn stored(state: &crate::state::AppState, key: &str) -> Option<Value> {
    let s = state.store.get(key).await.expect("get")?;
    Some(serde_json::from_slice(&s.value).unwrap())
}

#[tokio::test]
async fn namespaced_put_keeps_creation_and_deletion_metadata() {
    let state = make_state();
    let key = crate::keys::group_object_key("", "configmaps", Some("default"), "c1");
    seed(
        &state,
        &key,
        json!({"apiVersion":"v1","kind":"ConfigMap",
            "metadata":{"name":"c1","namespace":"default","uid":"u1",
                "creationTimestamp":STORED_TS,"finalizers":["x/y"],
                "deletionTimestamp":DELETING_TS,"deletionGracePeriodSeconds":0},
            "data":{"a":"1"}}),
    )
    .await;

    replace_namespaced_resource(
        State(state.clone()),
        Path((
            "".into(),
            "v1".into(),
            "default".into(),
            "configmaps".into(),
            "c1".into(),
        )),
        Query(ReplaceQuery::default()),
        user(),
        json_headers(),
        Bytes::from(
            json!({"apiVersion":"v1","kind":"ConfigMap",
                "metadata":{"name":"c1","namespace":"default","finalizers":["x/y"],
                    "creationTimestamp":"1999-01-01T00:00:00Z"},
                "data":{"a":"2"}})
            .to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("namespaced replace: {e:?}"));

    let m = &stored(&state, &key).await.unwrap()["metadata"];
    assert_eq!(
        m["creationTimestamp"], STORED_TS,
        "creationTimestamp is immutable"
    );
    assert_eq!(m["deletionTimestamp"], DELETING_TS);
    assert_eq!(m["deletionGracePeriodSeconds"], 0);
}

#[tokio::test]
async fn namespaced_put_without_creation_timestamp_keeps_it_for_leases() {
    let state = make_state();
    let key = crate::keys::group_object_key(
        "coordination.k8s.io",
        "leases",
        Some("kube-node-lease"),
        "n1",
    );
    let rv = seed(
        &state,
        &key,
        json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease",
            "metadata":{"name":"n1","namespace":"kube-node-lease","uid":"u1",
                "creationTimestamp":STORED_TS},
            "spec":{"holderIdentity":"n1"}}),
    )
    .await;

    replace_namespaced_resource(
        State(state.clone()),
        Path((
            "coordination.k8s.io".into(),
            "v1".into(),
            "kube-node-lease".into(),
            "leases".into(),
            "n1".into(),
        )),
        Query(ReplaceQuery::default()),
        user(),
        json_headers(),
        Bytes::from(
            json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease",
                "metadata":{"name":"n1","namespace":"kube-node-lease",
                    "resourceVersion":rv.to_string()},
                "spec":{"holderIdentity":"n1","renewTime":"2026-01-01T00:00:00.000000Z"}})
            .to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("lease replace: {e:?}"));

    assert_eq!(
        stored(&state, &key).await.unwrap()["metadata"]["creationTimestamp"],
        STORED_TS,
        "a Lease renewed by PUT must keep its age (kubectl get leases AGE)"
    );
}

#[tokio::test]
async fn cluster_scoped_put_keeps_creation_timestamp() {
    let state = make_state();
    let key = crate::keys::group_object_key("storage.k8s.io", "storageclasses", None, "s1");
    let rv = seed(
        &state,
        &key,
        json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass",
            "metadata":{"name":"s1","uid":"u2","creationTimestamp":STORED_TS},
            "provisioner":"p","reclaimPolicy":"Delete","volumeBindingMode":"Immediate"}),
    )
    .await;

    replace_resource(
        State(state.clone()),
        Path(("storage.k8s.io".into(), "v1".into(), "storageclasses".into(), "s1".into())),
        Query(ReplaceQuery::default()),
        user(),
        json_headers(),
        Bytes::from(
            json!({"apiVersion":"storage.k8s.io/v1","kind":"StorageClass",
                "metadata":{"name":"s1","resourceVersion":rv.to_string()},"provisioner":"p","reclaimPolicy":"Delete","volumeBindingMode":"Immediate"})
            .to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("cluster replace: {e:?}"));

    assert_eq!(
        stored(&state, &key).await.unwrap()["metadata"]["creationTimestamp"],
        STORED_TS
    );
}

/// A PUT body without deletionTimestamp (what a protobuf client's decoded body looks like) must
/// leave the namespace Terminating, so the later finalizer-removal PUT still completes the
/// delete; otherwise the namespace is stuck Terminating until deleted again.
#[tokio::test]
async fn namespace_put_keeps_deletion_timestamp_so_finalizer_removal_still_deletes() {
    let state = make_state();
    let key = crate::keys::cluster_object_key("namespaces", "term-ns");
    let rv = seed(
        &state,
        &key,
        json!({"apiVersion":"v1","kind":"Namespace",
            "metadata":{"name":"term-ns","uid":"u3","resourceVersion":"1",
                "creationTimestamp":STORED_TS,
                "deletionTimestamp":DELETING_TS,"deletionGracePeriodSeconds":0},
            "spec":{"finalizers":["kubernetes"]},
            "status":{"phase":"Terminating"}}),
    )
    .await;

    let put = |rv: u64, finalizers: Value| {
        let state = state.clone();
        async move {
            replace_namespace(
                State(state),
                Path("term-ns".to_string()),
                user(),
                HeaderMap::new(),
                Bytes::from(
                    json!({"apiVersion":"v1","kind":"Namespace",
                        "metadata":{"name":"term-ns","resourceVersion":rv.to_string()},
                        "spec":{"finalizers":finalizers}})
                    .to_string(),
                ),
            )
            .await
            .unwrap_or_else(|e| panic!("namespace replace: {e:?}"));
        }
    };

    put(rv, json!(["kubernetes"])).await;
    let v = stored(&state, &key).await.expect("still present");
    assert_eq!(v["metadata"]["deletionTimestamp"], DELETING_TS);
    assert_eq!(v["metadata"]["deletionGracePeriodSeconds"], 0);
    assert_eq!(v["metadata"]["creationTimestamp"], STORED_TS);

    let rv = state.store.get(&key).await.unwrap().unwrap().revision;
    put(rv, json!([])).await;
    assert!(
        stored(&state, &key).await.is_none(),
        "finalizer removal on a Terminating namespace must complete the deletion"
    );
}

fn merge_patch_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/merge-patch+json"),
    );
    h
}

/// A caller holding only `patch` must not start a delete by sending deletionTimestamp with empty
/// finalizers: the drain decision reads the stored object's deletionTimestamp, so the live
/// object survives and stays live (generic namespaced PATCH).
#[tokio::test]
async fn namespaced_patch_cannot_start_deletion_from_client_deletion_timestamp() {
    let state = make_state();
    let key = crate::keys::group_object_key("", "configmaps", Some("default"), "c1");
    seed(
        &state,
        &key,
        json!({"apiVersion":"v1","kind":"ConfigMap",
            "metadata":{"name":"c1","namespace":"default","uid":"u1"},"data":{"a":"1"}}),
    )
    .await;

    crate::handlers::resource::patch_namespaced_resource(
        State(state.clone()),
        Path((
            "".into(),
            "v1".into(),
            "default".into(),
            "configmaps".into(),
            "c1".into(),
        )),
        Query(Default::default()),
        user(),
        merge_patch_headers(),
        Bytes::from(
            json!({"metadata":{"deletionTimestamp":DELETING_TS,"finalizers":[]}}).to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("patch: {e:?}"));

    let v = stored(&state, &key)
        .await
        .expect("a deletionTimestamp patch must not hard-delete a live object");
    assert!(v["metadata"]["deletionTimestamp"].is_null());
}

/// Same invariant for pods.
#[tokio::test]
async fn pod_patch_cannot_start_deletion_from_client_deletion_timestamp() {
    let state = make_state();
    crate::handlers::test_support::seed_namespace(&state, "default").await;
    let key = crate::keys::object_key("pods", "default", "p1");
    seed(
        &state,
        &key,
        json!({"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":"p1","namespace":"default","uid":"u1"},
            "spec":{"containers":[{"name":"c","image":"i"}]}}),
    )
    .await;

    crate::handlers::pods::patch_pod(
        State(state.clone()),
        Path(("default".into(), "p1".into())),
        Query(Default::default()),
        user(),
        merge_patch_headers(),
        Bytes::from(
            json!({"metadata":{"deletionTimestamp":DELETING_TS,"finalizers":[]}}).to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("patch: {e:?}"));

    let v = stored(&state, &key)
        .await
        .expect("a deletionTimestamp patch must not hard-delete a live pod");
    assert!(v["metadata"]["deletionTimestamp"].is_null());
}

/// Same invariant for namespaces (spec.finalizers drain).
#[tokio::test]
async fn namespace_patch_cannot_start_deletion_from_client_deletion_timestamp() {
    let state = make_state();
    let key = crate::keys::cluster_object_key("namespaces", "live-ns");
    seed(
        &state,
        &key,
        json!({"apiVersion":"v1","kind":"Namespace",
            "metadata":{"name":"live-ns","uid":"u3"},
            "spec":{"finalizers":["kubernetes"]},"status":{"phase":"Active"}}),
    )
    .await;

    crate::handlers::namespaces::patch_namespace(
        State(state.clone()),
        Path("live-ns".into()),
        Query(Default::default()),
        user(),
        merge_patch_headers(),
        Bytes::from(
            json!({"metadata":{"deletionTimestamp":DELETING_TS},"spec":{"finalizers":[]}})
                .to_string(),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("patch: {e:?}"));

    let v = stored(&state, &key)
        .await
        .expect("a deletionTimestamp patch must not hard-delete a live namespace");
    assert!(v["metadata"]["deletionTimestamp"].is_null());
}
