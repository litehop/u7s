//! An update that read an object must not write it back after a DELETE landed in between
//! (the client's delete would appear to have been ignored: a DeviceTaintRule whose delete
//! "never completes" while a controller keeps applying its status), and must not overwrite a
//! write it never saw. One test per handler family, each racing the handler's own write.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    Extension,
};
use bytes::Bytes;
use serde_json::{json, Value};
use u7s_store::Store;

use crate::auth::UserInfo;
use crate::handlers::test_support::{grant_signer_verb, MockStore};
use crate::state::AppState;
use crate::status::StatusError;

fn state_of(mock: &Arc<MockStore>) -> AppState<MockStore> {
    AppState::new(
        Arc::clone(mock),
        None,
        HashMap::new(),
        "https://localhost:6443".into(),
    )
}

fn user() -> UserInfo {
    UserInfo {
        username: "test-user".into(),
        uid: "test-uid".into(),
        groups: vec!["system:authenticated".into()],
        extra: Default::default(),
    }
}

fn headers(ct: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    h
}

fn json_headers() -> HeaderMap {
    headers("application/json")
}

fn bytes_of(v: &Value) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap())
}

async fn seed(mock: &MockStore, key: &str, body: &Value) {
    mock.inner.put(key, bytes_of(body), None).await.unwrap();
}

/// The handler must report NotFound and leave the key deleted.
async fn assert_stays_deleted<T>(mock: &MockStore, key: &str, result: Result<T, StatusError>) {
    match result {
        Err(e) => assert_eq!(
            e.0,
            StatusCode::NOT_FOUND,
            "an update racing a delete must be a 404, got {}",
            e.1.message
        ),
        Ok(_) => panic!("an update of an object deleted mid-request must not succeed"),
    }
    assert!(
        mock.inner.get(key).await.unwrap().is_none(),
        "the write must not recreate an object deleted after it was read"
    );
}

fn deployment(name: &str) -> Value {
    json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}}, "template": {
            "metadata": {"labels": {"app": name}},
            "spec": {"containers": [{"name": "c", "image": "i"}]}
        }}
    })
}

fn pod(name: &str) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "default", "uid": "pod-uid"},
        "spec": {"containers": [{"name": "c", "image": "i"}]}
    })
}

fn pod_key(name: &str) -> String {
    format!("/registry/pods/default/{name}")
}

#[tokio::test]
async fn main_put_cluster_scoped_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let sc = json!({
        "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
        "metadata": {"name": "sc"}, "provisioner": "example.io/p",
        "reclaimPolicy": "Delete", "volumeBindingMode": "Immediate"
    });
    let key = "/registry/storage.k8s.io/storageclasses/sc";
    seed(&mock, key, &sc).await;
    let state = state_of(&mock);
    mock.arm_delete_before_put(key);
    let result = crate::handlers::resource::replace_resource(
        State(state),
        Path((
            "storage.k8s.io".into(),
            "v1".into(),
            "storageclasses".into(),
            "sc".into(),
        )),
        Query(Default::default()),
        Extension(user()),
        json_headers(),
        bytes_of(&sc),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

#[tokio::test]
async fn main_put_namespaced_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let cm = json!({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "cm", "namespace": "default"}, "data": {"a": "b"}
    });
    let key = "/registry/configmaps/default/cm";
    seed(&mock, key, &cm).await;
    let state = state_of(&mock);
    mock.arm_delete_before_put(key);
    let result = crate::handlers::resource::replace_namespaced_resource(
        State(state),
        Path((
            "".into(),
            "v1".into(),
            "default".into(),
            "configmaps".into(),
            "cm".into(),
        )),
        Query(Default::default()),
        Extension(user()),
        json_headers(),
        bytes_of(&cm),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

/// The status PUT applies to the object as it is when written: a concurrent write (here a
/// label) survives it instead of being overwritten by the stale read, and a concurrent delete
/// stays deleted.
#[tokio::test]
async fn status_put_keeps_a_concurrent_write_and_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/persistentvolumes/pv";
    let pv = json!({
        "apiVersion": "v1", "kind": "PersistentVolume",
        "metadata": {"name": "pv"},
        "spec": {"capacity": {"storage": "1Gi"}, "accessModes": ["ReadWriteOnce"],
                 "hostPath": {"path": "/x"}}
    });
    seed(&mock, key, &pv).await;
    let state = state_of(&mock);
    let put = |state: AppState<MockStore>| {
        crate::handlers::status::put_resource_status(
            State(state),
            Path((
                "".into(),
                "v1".into(),
                "persistentvolumes".into(),
                "pv".into(),
            )),
            Extension(user()),
            json_headers(),
            bytes_of(&json!({"status": {"phase": "Available"}})),
        )
    };

    let mut concurrent = pv.clone();
    concurrent["metadata"]["labels"] = json!({"touched": "yes"});
    mock.arm_write_before_put(key, bytes_of(&concurrent));
    match put(state.clone()).await {
        Ok(_) => {}
        Err(e) => panic!("{}", e.1.message),
    }
    let stored: Value =
        serde_json::from_slice(&mock.inner.get(key).await.unwrap().unwrap().value).unwrap();
    assert_eq!(stored["status"]["phase"], "Available");
    assert_eq!(
        stored["metadata"]["labels"]["touched"], "yes",
        "the status write must be applied to the concurrently updated object, not overwrite it"
    );

    mock.arm_delete_before_put(key);
    let result = put(state).await;
    assert_stays_deleted(&mock, key, result).await;
}

#[tokio::test]
async fn namespaced_status_put_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/apps/deployments/default/d";
    seed(&mock, key, &deployment("d")).await;
    let state = state_of(&mock);
    mock.arm_delete_before_put(key);
    let result = crate::handlers::status::put_namespaced_resource_status(
        State(state),
        Path((
            "apps".into(),
            "v1".into(),
            "default".into(),
            "deployments".into(),
            "d".into(),
        )),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({"status": {"readyReplicas": 1}})),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

#[tokio::test]
async fn scale_put_and_patch_do_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/apps/deployments/default/d";
    let state = state_of(&mock);
    let scale = bytes_of(&json!({
        "apiVersion": "autoscaling/v1", "kind": "Scale",
        "metadata": {"name": "d", "namespace": "default"}, "spec": {"replicas": 3}
    }));

    seed(&mock, key, &deployment("d")).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::scale::put_scale(
        State(state.clone()),
        Path(("default".into(), "deployments".into(), "d".into())),
        Some(Extension(user())),
        json_headers(),
        scale,
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;

    seed(&mock, key, &deployment("d")).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::scale::patch_scale(
        State(state),
        Path(("default".into(), "deployments".into(), "d".into())),
        Some(Extension(user())),
        headers("application/merge-patch+json"),
        bytes_of(&json!({"spec": {"replicas": 5}})),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

/// An HPA scale PATCH must apply to the deployment as it is when written: a concurrent label
/// change survives, instead of being overwritten by the stale read.
#[tokio::test]
async fn scale_patch_keeps_a_concurrent_write() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/apps/deployments/default/d";
    seed(&mock, key, &deployment("d")).await;
    let state = state_of(&mock);
    let mut concurrent = deployment("d");
    concurrent["metadata"]["labels"] = json!({"touched": "yes"});
    mock.arm_write_before_put(key, bytes_of(&concurrent));
    crate::handlers::scale::patch_scale(
        State(state),
        Path(("default".into(), "deployments".into(), "d".into())),
        Some(Extension(user())),
        headers("application/merge-patch+json"),
        bytes_of(&json!({"spec": {"replicas": 5}})),
    )
    .await
    .expect("a lost race is retried, not surfaced");
    let stored: Value =
        serde_json::from_slice(&mock.inner.get(key).await.unwrap().unwrap().value).unwrap();
    assert_eq!(stored["spec"]["replicas"], 5);
    assert_eq!(stored["metadata"]["labels"]["touched"], "yes");
}

#[tokio::test]
async fn csr_approval_put_and_patch_do_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/certificates.k8s.io/certificatesigningrequests/csr";
    let csr = json!({
        "apiVersion": "certificates.k8s.io/v1", "kind": "CertificateSigningRequest",
        "metadata": {"name": "csr"},
        "spec": {"request": "dGVzdA==", "signerName": "kubernetes.io/kube-apiserver-client"},
        "status": {"conditions": []}
    });
    let state = state_of(&mock);
    grant_signer_verb(
        &state,
        "approver",
        "approve",
        "kubernetes.io/kube-apiserver-client",
    );
    let approver = || {
        Extension(UserInfo {
            username: "approver".into(),
            ..Default::default()
        })
    };
    let approve = json!({"status": {"conditions": [{
        "type": "Approved", "status": "True", "reason": "r", "message": "m"
    }]}});

    seed(&mock, key, &csr).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::approval::put_approval(
        State(state.clone()),
        approver(),
        Path("csr".into()),
        json_headers(),
        bytes_of(&approve),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;

    seed(&mock, key, &csr).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::approval::patch_approval(
        State(state),
        approver(),
        Path("csr".into()),
        headers("application/merge-patch+json"),
        bytes_of(&approve),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

#[tokio::test]
async fn namespace_replace_finalize_and_status_do_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/namespaces/doomed";
    let ns = json!({
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": "doomed", "uid": "ns-uid"},
        "spec": {"finalizers": ["kubernetes"]}, "status": {"phase": "Active"}
    });
    let state = state_of(&mock);

    seed(&mock, key, &ns).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::namespaces::replace_namespace(
        State(state.clone()),
        Path("doomed".into()),
        Extension(user()),
        json_headers(),
        bytes_of(&ns),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;

    seed(&mock, key, &ns).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::namespaces::finalize_namespace(
        State(state.clone()),
        Path("doomed".into()),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({"spec": {"finalizers": []}})),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;

    seed(&mock, key, &ns).await;
    mock.arm_delete_before_put(key);
    let result = crate::handlers::namespaces::put_namespace_status(
        State(state),
        Path("doomed".into()),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({"status": {"phase": "Terminating"}})),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

#[tokio::test]
async fn pod_replace_status_resize_and_ephemeral_do_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let state = state_of(&mock);
    let key = pod_key("p");
    let ns_path = || Path(("default".to_string(), "p".to_string()));

    seed(&mock, &key, &pod("p")).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::pods::replace_pod(
        State(state.clone()),
        ns_path(),
        Query(Default::default()),
        Extension(user()),
        json_headers(),
        bytes_of(&pod("p")),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    seed(&mock, &key, &pod("p")).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::pods::replace_pod_status(
        State(state.clone()),
        ns_path(),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({"status": {"phase": "Running"}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    let mut resizable = pod("p");
    resizable["spec"]["containers"][0]["resources"] =
        json!({"requests": {"cpu": "100m"}, "limits": {"cpu": "200m"}});
    seed(&mock, &key, &resizable).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::pods::patch_pod_resize(
        State(state.clone()),
        ns_path(),
        Some(Extension(user())),
        headers("application/strategic-merge-patch+json"),
        bytes_of(&json!({"spec": {"containers": [{
            "name": "c",
            "resources": {"requests": {"cpu": "150m"}, "limits": {"cpu": "200m"}}
        }]}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    seed(&mock, &key, &pod("p")).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::pods::put_ephemeral_containers(
        State(state),
        ns_path(),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({"spec": {"ephemeralContainers": [{"name": "dbg", "image": "busybox"}]}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;
}

/// A cluster-scoped CRD with status and scale, plus one CR of it.
async fn install_cluster_cr(mock: &Arc<MockStore>) -> (AppState<MockStore>, String) {
    let state = state_of(mock);
    let crd = json!({
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": "widgets.example.io"},
        "spec": {
            "group": "example.io",
            "names": {"plural": "widgets", "singular": "widget", "kind": "Widget",
                      "listKind": "WidgetList"},
            "scope": "Cluster",
            "versions": [{
                "name": "v1", "served": true, "storage": true,
                "schema": {"openAPIV3Schema": {
                    "type": "object", "x-kubernetes-preserve-unknown-fields": true
                }},
                "subresources": {"status": {}, "scale": {
                    "specReplicasPath": ".spec.replicas",
                    "statusReplicasPath": ".status.replicas"
                }}
            }]
        }
    });
    crate::handlers::crd::create_crd(
        State(state.clone()),
        Extension(user()),
        HeaderMap::new(),
        bytes_of(&crd),
    )
    .await
    .expect("install CRD");
    let key = "/registry/cr/example.io/widgets/w".to_string();
    seed(
        mock,
        &key,
        &json!({
            "apiVersion": "example.io/v1", "kind": "Widget",
            "metadata": {"name": "w", "uid": "w-uid"}, "spec": {"replicas": 1}
        }),
    )
    .await;
    (state, key)
}

#[tokio::test]
async fn cr_status_and_scale_do_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let (state, key) = install_cluster_cr(&mock).await;
    let path = || {
        Path((
            "example.io".to_string(),
            "v1".to_string(),
            "widgets".to_string(),
            "w".to_string(),
        ))
    };
    let stored = mock.inner.get(&key).await.unwrap().unwrap();
    let body: Value = serde_json::from_slice(&stored.value).unwrap();

    mock.arm_delete_before_put(&key);
    let result = crate::handlers::cr::put_cr_status(
        State(state.clone()),
        Extension(user()),
        path(),
        json_headers(),
        bytes_of(&json!({"metadata": {"resourceVersion": stored.revision.to_string()}, "status": {"ready": true}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    seed(&mock, &key, &body).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::cr::patch_cr_status(
        State(state.clone()),
        Extension(user()),
        path(),
        headers("application/merge-patch+json"),
        bytes_of(&json!({"status": {"ready": true}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    seed(&mock, &key, &body).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::cr::put_cr_scale(
        State(state.clone()),
        path(),
        Some(Extension(user())),
        json_headers(),
        bytes_of(&json!({
            "apiVersion": "autoscaling/v1", "kind": "Scale",
            "metadata": {"name": "w"}, "spec": {"replicas": 4}
        })),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;

    seed(&mock, &key, &body).await;
    mock.arm_delete_before_put(&key);
    let result = crate::handlers::cr::patch_cr_scale(
        State(state),
        path(),
        Some(Extension(user())),
        headers("application/merge-patch+json"),
        bytes_of(&json!({"spec": {"replicas": 4}})),
    )
    .await;
    assert_stays_deleted(&mock, &key, result).await;
}

#[tokio::test]
async fn crd_patch_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let (state, _) = install_cluster_cr(&mock).await;
    let key = "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.io";
    assert!(mock.inner.get(key).await.unwrap().is_some());
    mock.arm_delete_before_put(key);
    let result = crate::handlers::crd::patch_crd(
        State(state),
        Path("widgets.example.io".into()),
        Extension(user()),
        headers("application/merge-patch+json"),
        bytes_of(&json!({"metadata": {"labels": {"a": "b"}}})),
    )
    .await;
    assert_stays_deleted(&mock, key, result).await;
}

/// The quota usage recount is computed while the quota can still be deleted; writing its
/// status back must not recreate the quota (which would silently re-enforce limits the user
/// just removed).
#[tokio::test]
async fn quota_status_recount_does_not_resurrect_a_deleted_quota() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/resourcequotas/default/rq";
    seed(
        &mock,
        key,
        &json!({
            "apiVersion": "v1", "kind": "ResourceQuota",
            "metadata": {"name": "rq", "namespace": "default"},
            "spec": {"hard": {"pods": "10"}}
        }),
    )
    .await;
    let state = state_of(&mock);
    mock.arm_delete_before_put(key);
    crate::quota::update_quota_status(&state, "default").await;
    assert!(
        mock.inner.get(key).await.unwrap().is_none(),
        "a quota deleted after its usage was read must stay deleted"
    );
}

/// DeleteCollection decides each item's soft-delete from the list snapshot; an item deleted
/// since then must stay deleted.
#[tokio::test]
async fn delete_collection_soft_delete_does_not_resurrect() {
    let mock = Arc::new(MockStore::new());
    let key = "/registry/configmaps/default/held";
    seed(
        &mock,
        key,
        &json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "held", "namespace": "default", "finalizers": ["f"]}
        }),
    )
    .await;
    mock.arm_delete_before_put(key);
    let done = crate::handlers::generic::soft_delete_collection_item(
        Arc::clone(&mock),
        key,
        ("", "configmaps", "held", "ConfigMap"),
    )
    .await
    .expect("a vanished item is not an error");
    assert!(done, "nothing is left to hard-delete");
    assert!(mock.inner.get(key).await.unwrap().is_none());
}

const PATCH_TYPES: [&str; 3] = [
    "application/merge-patch+json",
    "application/strategic-merge-patch+json",
    "application/json-patch+json",
];

/// Rewrites the object so its revision moves on; returns `(stale, current)` revisions.
async fn bump(mock: &MockStore, key: &str) -> (u64, u64) {
    let stored = mock.inner.get(key).await.unwrap().unwrap();
    let mut v: Value = serde_json::from_slice(&stored.value).unwrap();
    v["metadata"]["annotations"] = json!({"bumped": stored.revision.to_string()});
    let current = mock.inner.put(key, bytes_of(&v), None).await.unwrap();
    (stored.revision, current)
}

/// A patch adding annotation `k` that pins `metadata.resourceVersion` to `rv`. A JSON Patch can
/// only pin through an op, never through the raw body.
fn pinned_patch(content_type: &str, rv: u64) -> Value {
    if content_type.contains("json-patch") {
        json!([
            {"op": "add", "path": "/metadata/annotations", "value": {"k": "v"}},
            {"op": "add", "path": "/metadata/resourceVersion", "value": rv.to_string()}
        ])
    } else {
        json!({"metadata": {"annotations": {"k": "v"}, "resourceVersion": rv.to_string()}})
    }
}

fn code<T>(r: Result<T, StatusError>) -> StatusCode {
    r.map_or_else(|e| e.0, |_| StatusCode::OK)
}

async fn assert_patch_not_applied(mock: &MockStore, key: &str, what: &str) {
    let stored = mock.inner.get(key).await.unwrap().unwrap();
    let v: Value = serde_json::from_slice(&stored.value).unwrap();
    assert!(
        v["metadata"]["annotations"]["k"].is_null(),
        "{what}: a patch pinned to a stale resourceVersion must not be applied"
    );
}

/// A client that pins `metadata.resourceVersion` in its patch asked for exactly that
/// revision: a stale pin must be a 409 for every patch type, not applied to the live object.
#[tokio::test]
async fn do_patch_stale_pinned_resource_version_is_409_for_every_patch_type() {
    let mock = Arc::new(MockStore::new());
    let state = state_of(&mock);
    let key = "/registry/configmaps/default/cm";
    seed(
        &mock,
        key,
        &json!({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "cm", "namespace": "default"}, "data": {"a": "b"}}),
    )
    .await;
    for ct in PATCH_TYPES {
        let (stale, current) = bump(&mock, key).await;
        let patch = |rv| {
            crate::handlers::resource::patch_namespaced_resource(
                State(state.clone()),
                Path((
                    "".into(),
                    "v1".into(),
                    "default".into(),
                    "configmaps".into(),
                    "cm".into(),
                )),
                Query(Default::default()),
                Extension(user()),
                headers(ct),
                bytes_of(&pinned_patch(ct, rv)),
            )
        };
        assert_eq!(code(patch(stale).await), StatusCode::CONFLICT, "{ct}");
        assert_patch_not_applied(&mock, key, ct).await;
        assert_eq!(code(patch(current).await), StatusCode::OK, "{ct}");
    }
}

#[tokio::test]
async fn patch_pod_stale_pinned_resource_version_is_409_for_every_patch_type() {
    let mock = Arc::new(MockStore::new());
    let state = state_of(&mock);
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    for ct in PATCH_TYPES {
        let (stale, current) = bump(&mock, &key).await;
        let patch = |rv| {
            crate::handlers::pods::patch_pod(
                State(state.clone()),
                Path(("default".to_string(), "p".to_string())),
                Query(Default::default()),
                Extension(user()),
                headers(ct),
                bytes_of(&pinned_patch(ct, rv)),
            )
        };
        assert_eq!(code(patch(stale).await), StatusCode::CONFLICT, "{ct}");
        assert_patch_not_applied(&mock, &key, ct).await;
        assert_eq!(code(patch(current).await), StatusCode::OK, "{ct}");
    }
}

/// The pin matched the revision read, but a writer landed before the commit: the patch must
/// not be re-applied onto the newer object the client never saw.
#[tokio::test]
async fn patch_pod_pin_lost_to_a_concurrent_write_is_409_not_a_blind_retry() {
    let mock = Arc::new(MockStore::new());
    let state = state_of(&mock);
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    let (_, current) = bump(&mock, &key).await;
    let mut raced = pod("p");
    raced["metadata"]["labels"] = json!({"raced": "1"});
    mock.arm_write_before_put(&key, bytes_of(&raced));
    let ct = "application/json-patch+json";
    let result = crate::handlers::pods::patch_pod(
        State(state),
        Path(("default".to_string(), "p".to_string())),
        Query(Default::default()),
        Extension(user()),
        headers(ct),
        bytes_of(&pinned_patch(ct, current)),
    )
    .await;
    assert_eq!(code(result), StatusCode::CONFLICT);
    assert_patch_not_applied(&mock, &key, ct).await;
}

#[tokio::test]
async fn patch_pod_status_stale_pinned_resource_version_is_409() {
    let mock = Arc::new(MockStore::new());
    let state = state_of(&mock);
    let key = pod_key("p");
    seed(&mock, &key, &pod("p")).await;
    for ct in &PATCH_TYPES[..2] {
        let (stale, current) = bump(&mock, &key).await;
        let patch = |rv: u64| {
            crate::handlers::pods::patch_pod_status(
                State(state.clone()),
                Path(("default".to_string(), "p".to_string())),
                Some(Extension(user())),
                headers(ct),
                bytes_of(&json!({
                    "metadata": {"resourceVersion": rv.to_string()},
                    "status": {"phase": ct}
                })),
            )
        };
        assert_eq!(code(patch(stale).await), StatusCode::CONFLICT, "{ct}");
        let stored: Value =
            serde_json::from_slice(&mock.inner.get(&key).await.unwrap().unwrap().value).unwrap();
        assert_ne!(
            stored["status"]["phase"], *ct,
            "{ct}: a status patch pinned to a stale resourceVersion must not be applied"
        );
        assert_eq!(code(patch(current).await), StatusCode::OK, "{ct}");
    }
}

#[tokio::test]
async fn patch_crd_stale_pinned_resource_version_is_409_for_every_patch_type() {
    let mock = Arc::new(MockStore::new());
    let (state, _) = install_cluster_cr(&mock).await;
    let key = "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.io";
    for ct in PATCH_TYPES {
        let (stale, current) = bump(&mock, key).await;
        let patch = |rv| {
            crate::handlers::crd::patch_crd(
                State(state.clone()),
                Path("widgets.example.io".into()),
                Extension(user()),
                headers(ct),
                bytes_of(&pinned_patch(ct, rv)),
            )
        };
        assert_eq!(code(patch(stale).await), StatusCode::CONFLICT, "{ct}");
        assert_patch_not_applied(&mock, key, ct).await;
        assert_eq!(code(patch(current).await), StatusCode::OK, "{ct}");
    }
}
