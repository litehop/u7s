//! `DeleteOptions.preconditions` on every DELETE and DeleteCollection path: a uid or
//! resourceVersion the stored object does not have is a 409 with upstream's text and the object
//! is left untouched. The GC deletes by uid so that an owner recreated under the same name is
//! never removed; without the check it is.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Extension,
};
use bytes::Bytes;
use serde_json::{json, Value};

use super::test_support::MockStore;
use super::write_race_tests::{
    bump, bytes_of, cm_path, code, config_map, install_cluster_cr, json_headers, pod, pod_key,
    seed, state_of, stored_json, terminating, user, CM_KEY,
};
use crate::status::StatusError;

fn delete_options(preconditions: Value) -> Bytes {
    bytes_of(&json!({
        "apiVersion": "v1", "kind": "DeleteOptions", "preconditions": preconditions
    }))
}

fn wrong_uid() -> Bytes {
    delete_options(json!({"uid": "someone-else"}))
}

fn all() -> super::generic::CollectionQuery {
    serde_json::from_value(json!({})).unwrap()
}

fn no_grace() -> Query<super::pods::GracePeriodQuery> {
    Query(super::pods::GracePeriodQuery {
        grace_period_seconds: None,
    })
}

/// The request is a 409 with upstream's precondition text and the object is untouched: not
/// deleted and not stamped with a deletionTimestamp.
async fn assert_precondition_refused<T>(
    mock: &MockStore,
    key: &str,
    uid: &str,
    result: Result<T, StatusError>,
) {
    let Err(e) = result else {
        panic!("a delete whose uid precondition does not match must fail");
    };
    assert_eq!(e.0, StatusCode::CONFLICT, "{}", e.1.message);
    assert!(
        e.1.message.starts_with("Operation cannot be fulfilled on ")
            && e.1.message.ends_with(&format!(
                "StorageError: invalid object, Code: 4, Key: {key}, ResourceVersion: 0, \
                 AdditionalErrorMsg: Precondition failed: UID in precondition: someone-else, \
                 UID in object meta: {uid}"
            )),
        "not upstream's message: {}",
        e.1.message
    );
    let stored = stored_json(mock, key)
        .await
        .expect("a refused delete must leave the object");
    assert!(
        stored["metadata"]["deletionTimestamp"].is_null(),
        "a refused delete must not start the deletion"
    );
}

#[tokio::test]
async fn delete_namespaced_resource_honours_preconditions() {
    for finalizers in [json!([]), json!(["f"])] {
        let mock = Arc::new(MockStore::new());
        let mut cm = config_map("cm");
        cm["metadata"]["finalizers"] = finalizers;
        seed(&mock, CM_KEY, &cm).await;
        let r = super::resource::delete_namespaced_resource(
            State(state_of(&mock)),
            cm_path(),
            Extension(user()),
            HeaderMap::new(),
            wrong_uid(),
        )
        .await;
        assert_precondition_refused(&mock, CM_KEY, "cm-uid", r).await;
    }
}

fn storage_class() -> Value {
    json!({
        "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
        "metadata": {"name": "sc", "uid": "sc-uid"}, "provisioner": "example.io/p"
    })
}

const SC_KEY: &str = "/registry/storage.k8s.io/storageclasses/sc";

#[tokio::test]
async fn delete_resource_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    seed(&mock, SC_KEY, &storage_class()).await;
    let r = super::resource::delete_resource(
        State(state_of(&mock)),
        Path((
            "storage.k8s.io".into(),
            "v1".into(),
            "storageclasses".into(),
            "sc".into(),
        )),
        Extension(user()),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, SC_KEY, "sc-uid", r).await;
}

/// A resourceVersion pin is the client's "only if it is still what I read": once another
/// write lands the delete must fail instead of removing the newer object.
#[tokio::test]
async fn delete_namespaced_resource_pinned_to_a_replaced_revision_is_409() {
    let mock = Arc::new(MockStore::new());
    seed(&mock, CM_KEY, &config_map("cm")).await;
    let (stale, _) = bump(&mock, CM_KEY).await;
    let r = super::resource::delete_namespaced_resource(
        State(state_of(&mock)),
        cm_path(),
        Extension(user()),
        HeaderMap::new(),
        delete_options(json!({"resourceVersion": stale.to_string()})),
    )
    .await;
    assert_eq!(code(r), StatusCode::CONFLICT);
    assert!(stored_json(&mock, CM_KEY).await.is_some());
}

#[tokio::test]
async fn delete_pod_honours_preconditions_on_soft_and_hard_delete() {
    for terminating_pod in [false, true] {
        let mock = Arc::new(MockStore::new());
        let key = pod_key("p");
        let body = if terminating_pod {
            terminating(pod("p"), &[])
        } else {
            pod("p")
        };
        seed(&mock, &key, &body).await;
        let r = super::pods::delete_pod(
            State(state_of(&mock)),
            Path(("default".to_string(), "p".to_string())),
            Extension(user()),
            no_grace(),
            HeaderMap::new(),
            wrong_uid(),
        )
        .await;
        let Err(e) = r else {
            panic!("a mismatching uid must fail")
        };
        assert_eq!(e.0, StatusCode::CONFLICT);
        let after = stored_json(&mock, &key).await.expect("pod must survive");
        assert_eq!(
            after["metadata"]["deletionTimestamp"], body["metadata"]["deletionTimestamp"],
            "a refused delete must not stamp or move the deletionTimestamp"
        );
    }
}

#[tokio::test]
async fn delete_collection_pods_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    let r = super::pods::delete_collection_pods(
        State(state_of(&mock)),
        Path(("default".to_string(),)),
        Extension(user()),
        Query(all()),
        no_grace(),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, &key, "pod-uid", r).await;
}

#[tokio::test]
async fn delete_collection_namespaced_resource_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    seed(&mock, CM_KEY, &config_map("cm")).await;
    let r = super::resource::delete_collection_namespaced_resource(
        State(state_of(&mock)),
        Path((
            "".into(),
            "v1".into(),
            "default".into(),
            "configmaps".into(),
        )),
        Query(all()),
        Extension(user()),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, CM_KEY, "cm-uid", r).await;
}

#[tokio::test]
async fn delete_collection_resource_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    seed(&mock, SC_KEY, &storage_class()).await;
    let r = super::resource::delete_collection_resource(
        State(state_of(&mock)),
        Path((
            "storage.k8s.io".into(),
            "v1".into(),
            "storageclasses".into(),
        )),
        Query(all()),
        Extension(user()),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, SC_KEY, "sc-uid", r).await;
}

#[tokio::test]
async fn delete_cr_and_delete_collection_cr_honour_preconditions() {
    let mock = Arc::new(MockStore::new());
    let (state, key) = install_cluster_cr(&mock).await;
    let path = || {
        (
            "example.io".to_string(),
            "v1".to_string(),
            "widgets".to_string(),
        )
    };
    let (g, v, p) = path();
    let r = super::cr::delete_cr(
        State(state.clone()),
        Path((g, v, p, "w".to_string())),
        Extension(user()),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, &key, "w-uid", r).await;
    let r = super::cr::delete_collection_cr(
        State(state),
        Path(path()),
        Extension(user()),
        HeaderMap::new(),
        all(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, &key, "w-uid", r).await;
}

#[tokio::test]
async fn delete_namespace_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/namespaces/doomed";
    seed(
        &mock,
        key,
        &json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": "doomed", "uid": "ns-uid"}, "spec": {"finalizers": ["kubernetes"]}
        }),
    )
    .await;
    let r = super::namespaces::delete_namespace(
        State(state_of(&mock)),
        Path("doomed".into()),
        Extension(user()),
        HeaderMap::new(),
        wrong_uid(),
    )
    .await;
    assert_precondition_refused(&mock, key, "ns-uid", r).await;
}

async fn seed_default_namespace(mock: &MockStore) {
    seed(
        mock,
        "/registry/namespaces/default",
        &json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "default"}}),
    )
    .await;
}

async fn evict(
    mock: &Arc<MockStore>,
    name: &str,
    options: Value,
) -> Result<axum::response::Response, StatusError> {
    use axum::response::IntoResponse;
    super::pods::evict_pod(
        State(state_of(mock)),
        Path(("default".to_string(), name.to_string())),
        Extension(user()),
        json_headers(),
        bytes_of(&json!({
            "apiVersion": "policy/v1", "kind": "Eviction",
            "metadata": {"name": name, "namespace": "default"}, "deleteOptions": options
        })),
    )
    .await
    .map(IntoResponse::into_response)
}

#[tokio::test]
async fn evict_pod_honours_preconditions() {
    let mock = Arc::new(MockStore::new());
    seed_default_namespace(&mock).await;
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    let r = evict(
        &mock,
        "p",
        json!({"preconditions": {"uid": "someone-else"}}),
    )
    .await;
    assert_precondition_refused(&mock, &key, "pod-uid", r).await;
}

/// A kubelet status write racing the eviction must not fail it: upstream retries conflicts
/// on the fresh pod unless the client pinned a resourceVersion.
#[tokio::test]
async fn evict_pod_retries_over_a_concurrent_write() {
    let mock = Arc::new(MockStore::new());
    seed_default_namespace(&mock).await;
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    let mut kubelet = pod("p");
    kubelet["status"] = json!({"phase": "Running"});
    mock.arm_write_before_put(&key, bytes_of(&kubelet));
    let r = evict(&mock, "p", json!({})).await;
    assert_eq!(r.map(|r| r.status()).ok(), Some(StatusCode::CREATED));
    let after = stored_json(&mock, &key).await.unwrap();
    assert!(after["metadata"]["deletionTimestamp"].is_string());
    assert_eq!(
        after["status"]["phase"], "Running",
        "the kubelet's write must be kept, not overwritten by the retry"
    );
}

/// The hard-delete half of eviction (a terminating pod) retries the same way.
#[tokio::test]
async fn evict_terminating_pod_retries_over_a_concurrent_write() {
    let mock = Arc::new(MockStore::new());
    seed_default_namespace(&mock).await;
    let key = pod_key("p");
    seed(&mock, &key, &terminating(pod("p"), &[])).await;
    let mut kubelet = terminating(pod("p"), &[]);
    kubelet["status"] = json!({"phase": "Running"});
    mock.arm_write_before_delete(&key, bytes_of(&kubelet));
    let r = evict(&mock, "p", json!({})).await;
    assert_eq!(r.map(|r| r.status()).ok(), Some(StatusCode::CREATED));
    assert!(stored_json(&mock, &key).await.is_none());
}

#[tokio::test]
async fn evict_pod_pinned_to_a_replaced_revision_is_409_without_retry() {
    let mock = Arc::new(MockStore::new());
    seed_default_namespace(&mock).await;
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    let (stale, _) = bump(&mock, &key).await;
    let pin = json!({"preconditions": {"resourceVersion": stale.to_string()}});
    let r = evict(&mock, "p", pin).await;
    assert_eq!(code(r), StatusCode::CONFLICT);
    assert!(stored_json(&mock, &key).await.unwrap()["metadata"]["deletionTimestamp"].is_null());
}

/// Upstream's Delete of an object that another request deleted first is a 404, not a success.
#[tokio::test]
async fn deleting_an_object_deleted_mid_request_is_404() {
    let mock = Arc::new(MockStore::new());
    seed_default_namespace(&mock).await;
    let key = pod_key("p");
    seed(&mock, &key, &terminating(pod("p"), &[])).await;
    mock.arm_delete_before_delete(&key);
    let r = super::pods::delete_pod(
        State(state_of(&mock)),
        Path(("default".to_string(), "p".to_string())),
        Extension(user()),
        no_grace(),
        HeaderMap::new(),
        Bytes::new(),
    )
    .await;
    assert_eq!(code(r), StatusCode::NOT_FOUND, "delete_pod");

    seed(&mock, &key, &terminating(pod("p"), &[])).await;
    mock.arm_delete_before_delete(&key);
    let r = evict(&mock, "p", json!({})).await;
    assert_eq!(code(r), StatusCode::NOT_FOUND, "eviction of a vanished pod");

    seed(&mock, CM_KEY, &config_map("cm")).await;
    mock.arm_delete_before_delete(CM_KEY);
    let r = super::resource::delete_namespaced_resource(
        State(state_of(&mock)),
        cm_path(),
        Extension(user()),
        HeaderMap::new(),
        Bytes::new(),
    )
    .await;
    assert_eq!(code(r), StatusCode::NOT_FOUND, "delete_namespaced_resource");
}
