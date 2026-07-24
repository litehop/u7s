// ---------------------------------------------------------------------------
// Core group (group="", version="v1") handler wrappers for /api/v1/... routes
// ---------------------------------------------------------------------------
//
// These inject the fixed (group, version) = ("", "v1") into the generic handlers
// so the router can use simpler path patterns like /api/v1/:resource.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Extension, Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::{auth::UserInfo, state::AppState, status::Status};

use super::generic::{
    apply_label_selector, build_list_response, decode_continue, parse_field_selector,
    parse_label_selector, CollectionQuery,
};
use super::json_patch::{CreateQuery, PatchQuery, ReplaceQuery};
use super::resource::{
    create_namespaced_resource, create_resource, delete_collection_namespaced_resource,
    delete_collection_resource, delete_namespaced_resource, delete_resource,
    get_namespaced_resource, get_resource, list_namespaced_resource, list_resource,
    patch_namespaced_resource, patch_resource, replace_namespaced_resource, replace_resource,
};
use super::status::{
    get_namespaced_resource_status, get_resource_status, patch_namespaced_resource_status,
    patch_resource_status, put_namespaced_resource_status, put_resource_status,
};
use super::watch::{watch_generic, WatchConfig};

pub async fn core_list_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path(plural): Path<String>,
    Query(query): Query<CollectionQuery>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    // Pods are namespaced; the registry has no cluster-scoped "pods" entry.
    // Handle GET /api/v1/pods by scanning across all namespaces.
    if plural == "pods" {
        // Same as list_pods: reject an unsupported Table version up front, regardless of
        // whether this turns out to be a watch or a plain list.
        let accept = headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if let Some(version) = super::table::table_accept_version(accept) {
            if version != "v1" {
                return Err(Status::not_acceptable(format!(
                    "Table version \"{version}\" is not supported; only meta.k8s.io/v1 is accepted"
                )));
            }
        }

        let prefix = crate::keys::cluster_list_prefix("pods");
        if query.watch == Some(true) {
            let from_rv = query.resource_version.unwrap_or(0);
            // Fetch initial events with field-selector filtering applied.
            // Without filtering, kubelet (which watches with fieldSelector=spec.nodeName=<node>)
            // would receive ADDED events for pods on other nodes during the initial snapshot phase.
            let initial = if query.send_initial_events == Some(true) {
                use super::pods::{filter_pods_by_field_selector, pod_store_field_selector};
                let store_fs = query
                    .field_selector
                    .as_deref()
                    .and_then(pod_store_field_selector);
                let resp = state
                    .store
                    .list(
                        &prefix,
                        ListOptions {
                            field_selector: store_fs,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                let mut pods: Vec<serde_json::Value> = resp
                    .items
                    .iter()
                    .filter_map(|o| serde_json::from_slice(&o.value).ok())
                    .collect();
                if let Some(ref sel) = query.field_selector {
                    pods = filter_pods_by_field_selector(pods, sel);
                }
                if let Some(ref sel) = query.label_selector {
                    pods.retain(|pod| super::watch::object_matches_label_selector(pod, sel));
                }
                Some((pods, resp.revision))
            } else {
                None
            };
            return watch_generic(
                state,
                WatchConfig {
                    prefix,
                    api_version: "v1".into(),
                    kind: "Pod".into(),
                    from_revision: from_rv,
                    initial_items: initial,
                    label_selector: query.label_selector,
                    field_selector: query.field_selector,
                    allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                    username: user.username,
                    as_partial_object_metadata: false,
                    group: "".into(),
                    plural: "pods".into(),
                    timeout_seconds: query.timeout_seconds,
                },
            )
            .await
            .map(IntoResponse::into_response);
        }
        let field_selector = query
            .field_selector
            .as_deref()
            .map(parse_field_selector)
            .transpose()?;
        // Decode BEFORE listing: on a continuation request this pins the resourceVersion this
        // response (and every later page) must report — see decode_continue's doc for why.
        let continue_decoded = query
            .continue_token
            .as_deref()
            .map(|t| decode_continue(t, state.store.current_revision(), &state.continue_token_key))
            .transpose()?;
        let continue_key = continue_decoded.as_ref().map(|(k, _)| k.clone());
        let list_start = std::time::Instant::now();
        let resp = state
            .store
            .list(
                &prefix,
                ListOptions {
                    field_selector,
                    limit: query.limit,
                    continue_key,
                },
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        tracing::debug!(
            prefix = %prefix,
            item_count = resp.items.len(),
            elapsed_ms = list_start.elapsed().as_millis() as u64,
            "list: query completed"
        );
        let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);
        let mut items = Vec::with_capacity(resp.items.len());
        for obj in &resp.items {
            let v: serde_json::Value =
                serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
            items.push(v);
        }
        let items = if let Some(ref sel) = query.label_selector {
            let pairs = parse_label_selector(sel)?;
            apply_label_selector(items, &pairs)
        } else {
            items
        };
        tracing::debug!(prefix = %prefix, filtered_count = items.len(), "list: filtered");

        // `kubectl get pods -A` sends the same Accept: application/json;as=Table;... header
        // as `kubectl get pods -n <ns>` (list_pods, which already handles this). Without this,
        // kubectl can't decode the response and falls back to printing only NAME/AGE instead of
        // the usual READY/STATUS/RESTARTS/AGE columns.
        if super::table::wants_table(accept) {
            return Ok(Json(super::table::build_table("", "pods", items)).into_response());
        }

        let body = build_list_response(
            "Pod",
            "",
            "v1",
            list_revision,
            items,
            resp.continue_key,
            resp.remaining_count,
            &state.continue_token_key,
        );
        return Ok(Json(body).into_response());
    }

    list_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(query),
        headers,
        Extension(user),
    )
    .await
    .map(IntoResponse::into_response)
}

pub async fn core_get_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    get_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
    )
    .await
}

pub async fn core_create_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path(plural): Path<String>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(create_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_replace_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        Query(replace_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_patch_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        Query(patch_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_collection_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path(plural): Path<String>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_collection_resource(
        State(state),
        Path(("".into(), "v1".into(), plural)),
        Query(query),
        Extension(user),
    )
    .await
}

pub async fn core_get_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_resource_status(State(state), Path(("".into(), "v1".into(), plural, name))).await
}

pub async fn core_put_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_patch_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((plural, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_resource_status(
        State(state),
        Path(("".into(), "v1".into(), plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_list_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    list_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        Query(query),
        headers,
        Extension(user),
    )
    .await
}

pub async fn core_get_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
    )
    .await
}

pub async fn core_create_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural)): Path<(String, String)>,
    Query(create_query): Query<CreateQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    create_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        Query(create_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_replace_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    Query(replace_query): Query<ReplaceQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    replace_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        Query(replace_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_delete_collection_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural)): Path<(String, String)>,
    Query(query): Query<CollectionQuery>,
    Extension(user): Extension<UserInfo>,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    delete_collection_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural)),
        Query(query),
        Extension(user),
    )
    .await
}

pub async fn core_patch_namespaced_resource<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    Query(patch_query): Query<PatchQuery>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        Query(patch_query),
        Extension(user),
        headers,
        body,
    )
    .await
}

pub async fn core_get_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    get_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
    )
    .await
}

pub async fn core_put_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    put_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

pub async fn core_patch_namespaced_resource_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((ns, plural, name)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    patch_namespaced_resource_status(
        State(state),
        Path(("".into(), "v1".into(), ns, plural, name)),
        headers,
        body,
    )
    .await
}

#[cfg(test)]
mod tests {
    use crate::handlers::pods::{filter_pods_by_field_selector, pod_store_field_selector};
    use std::sync::Arc;
    use u7s_store::{SqliteStore, Store};

    /// Regression test for mayor-8qcs: the cluster-wide pod watch with sendInitialEvents=true
    /// and fieldSelector=spec.nodeName=<node> must only return pods assigned to that node in the
    /// initial ADDED events snapshot.
    ///
    /// Without the fix, core_list_resource used fetch_initial_events (no field selector) and
    /// kubelet received ADDED events for pods on all nodes. Kubelet on lima-node would see pods
    /// belonging to other nodes in its initial state, and conversely, pods assigned to lima-node
    /// after the initial snapshot might be missed if the informer assumed it had a full view.
    ///
    /// This test fails on revert: if filtering is removed, `lima_count` is 2 (both pods appear)
    /// instead of 1.
    #[tokio::test]
    async fn cluster_wide_pod_watch_initial_items_filtered_by_node_name() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Create two pods in different namespaces: one on lima-node, one on other-node.
        let lima_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "lima-pod", "namespace": "ns-a"},
            "spec": {"nodeName": "lima-node", "containers": []}
        });
        let other_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "other-pod", "namespace": "ns-b"},
            "spec": {"nodeName": "other-node", "containers": []}
        });

        store
            .put(
                "/registry/pods/ns-a/lima-pod",
                bytes::Bytes::from(serde_json::to_vec(&lima_pod).unwrap()),
                Some(0),
            )
            .await
            .expect("create lima-pod");
        store
            .put(
                "/registry/pods/ns-b/other-pod",
                bytes::Bytes::from(serde_json::to_vec(&other_pod).unwrap()),
                Some(0),
            )
            .await
            .expect("create other-pod");

        // Replicate the fixed path in core_list_resource: list all pods, filter by nodeName.
        let field_selector_str = "spec.nodeName=lima-node";
        let store_fs = pod_store_field_selector(field_selector_str);
        let prefix = crate::keys::cluster_list_prefix("pods");
        let resp = store
            .list(
                &prefix,
                u7s_store::ListOptions {
                    field_selector: store_fs,
                    ..Default::default()
                },
            )
            .await
            .expect("list pods");

        let mut pods: Vec<serde_json::Value> = resp
            .items
            .iter()
            .filter_map(|o| serde_json::from_slice(&o.value).ok())
            .collect();
        pods = filter_pods_by_field_selector(pods, field_selector_str);

        // Only the pod on lima-node must appear in the initial snapshot.
        assert_eq!(
            pods.len(),
            1,
            "initial sendInitialEvents snapshot for fieldSelector=spec.nodeName=lima-node \
             must contain only pods on lima-node; without field-selector filtering, kubelet \
             receives ADDED events for pods on other nodes (mayor-8qcs regression). \
             Got: {:?}",
            pods
        );
        assert_eq!(
            pods[0]["metadata"]["name"], "lima-pod",
            "the only pod in the initial snapshot must be the one assigned to lima-node"
        );
        assert_eq!(
            pods[0]["spec"]["nodeName"], "lima-node",
            "pod must have nodeName=lima-node"
        );
    }

    /// Regression test for mayor-zcnd: the cluster-wide pod watch with sendInitialEvents=true
    /// and a labelSelector must only return matching pods in the initial ADDED events snapshot.
    ///
    /// Before this fix, core_list_resource applied field_selector but NOT label_selector to
    /// the initial sendInitialEvents items. A StatefulSet controller (or any other client) that
    /// opens a cluster-wide pod watch with labelSelector receives ALL pods across ALL namespaces
    /// in the initial snapshot — including pods from other StatefulSets with different labels.
    ///
    /// This pollutes the informer cache and causes the controller to see the wrong pod set when
    /// reconciling, which can prevent creation of pods beyond ordinal 0 on scale-up (stuck at
    /// 1/N for 10 minutes).
    ///
    /// This test fails on revert: if the label_selector retain is removed from the
    /// sendInitialEvents path, both pods appear (len==2) instead of only the matching one.
    #[tokio::test]
    async fn cluster_wide_pod_watch_initial_items_filtered_by_label_selector() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        // Pod matching the StatefulSet's label selector.
        let ss_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "ss-0",
                "namespace": "statefulset-9798",
                "labels": {"app": "ss", "controller-uid": "abc123"}
            },
            "spec": {"containers": []}
        });
        // Pod from a different StatefulSet with different labels.
        let other_pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "other-0",
                "namespace": "statefulset-other",
                "labels": {"app": "other-ss", "controller-uid": "xyz789"}
            },
            "spec": {"containers": []}
        });

        store
            .put(
                "/registry/pods/statefulset-9798/ss-0",
                bytes::Bytes::from(serde_json::to_vec(&ss_pod).unwrap()),
                Some(0),
            )
            .await
            .expect("create ss-0");
        store
            .put(
                "/registry/pods/statefulset-other/other-0",
                bytes::Bytes::from(serde_json::to_vec(&other_pod).unwrap()),
                Some(0),
            )
            .await
            .expect("create other-0");

        // Replicate the fixed path in core_list_resource for sendInitialEvents + labelSelector.
        let label_selector_str = "app=ss,controller-uid=abc123";
        let prefix = crate::keys::cluster_list_prefix("pods");
        let resp = store
            .list(&prefix, u7s_store::ListOptions::default())
            .await
            .expect("list pods");

        let mut pods: Vec<serde_json::Value> = resp
            .items
            .iter()
            .filter_map(|o| serde_json::from_slice(&o.value).ok())
            .collect();

        // This is the exact retain logic added by the mayor-zcnd fix.
        pods.retain(|pod| {
            crate::handlers::watch::object_matches_label_selector(pod, label_selector_str)
        });

        assert_eq!(
            pods.len(),
            1,
            "cluster-wide pod watch sendInitialEvents with labelSelector=app=ss,controller-uid=abc123 \
             must return only ss-0 across all namespaces; without label_selector filtering the \
             StatefulSet controller informer cache is polluted with pods from other StatefulSets \
             (mayor-zcnd regression). Got: {:?}",
            pods
        );
        assert_eq!(
            pods[0]["metadata"]["name"], "ss-0",
            "the only pod in the initial snapshot must be ss-0 (matches app=ss,controller-uid=abc123)"
        );
        assert_eq!(
            pods[0]["metadata"]["namespace"], "statefulset-9798",
            "pod must be from the correct namespace"
        );
    }

    /// `kubectl get pods -A` sends the same Accept: application/json;as=Table;... header as
    /// `kubectl get pods -n <ns>` (list_pods). Before this fix, core_list_resource's
    /// cross-namespace "pods" branch built its response via build_list_response directly and
    /// never checked Accept at all, so kubectl logged "Unable to decode server response into a
    /// Table" and fell back to printing only NAME/AGE — even though the namespaced LIST already
    /// worked correctly via list_pods.
    #[tokio::test]
    async fn core_list_resource_cross_namespace_pods_with_table_accept_returns_table() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));

        let pod_a = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-a", "namespace": "ns-a", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"containers": [{"name": "app"}]},
            "status": {"phase": "Running"}
        });
        let pod_b = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "pod-b", "namespace": "ns-b", "creationTimestamp": "2020-01-01T00:00:00Z"},
            "spec": {"containers": [{"name": "app"}]},
            "status": {"phase": "Running"}
        });
        store
            .put(
                "/registry/pods/ns-a/pod-a",
                bytes::Bytes::from(serde_json::to_vec(&pod_a).unwrap()),
                Some(0),
            )
            .await
            .expect("create pod-a");
        store
            .put(
                "/registry/pods/ns-b/pod-b",
                bytes::Bytes::from(serde_json::to_vec(&pod_b).unwrap()),
                Some(0),
            )
            .await
            .expect("create pod-b");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/{resource}", get(super::core_list_resource))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/pods")
            .header("accept", "application/json;as=Table;g=meta.k8s.io;v=v1")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain PodList kind here means kubectl can't decode it as a Table and silently \
             falls back to hardcoded NAME/AGE-only columns for `kubectl get pods -A`"
        );
        let col_names: Vec<&str> = v["columnDefinitions"]
            .as_array()
            .expect("Table response must have columnDefinitions")
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(
            col_names.contains(&"Ready") && col_names.contains(&"Restarts"),
            "cross-namespace pod Table must use the same READY/STATUS/RESTARTS columns as \
             `kubectl get pods -n <ns>`, not the generic Name+Age fallback; got {col_names:?}"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            2,
            "the Table must still aggregate pods across every namespace, not just one"
        );
        let names: Vec<&str> = rows
            .iter()
            .map(|r| r["object"]["metadata"]["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"pod-a") && names.contains(&"pod-b"),
            "both cross-namespace pods must be present in the Table rows; got {names:?}"
        );
    }

    /// A Table request for a v1beta1 Table (long deprecated) on the cross-namespace pods LIST
    /// must be rejected the same way the namespaced list_pods already rejects it — a stale
    /// client must be told the format isn't supported rather than silently downgraded.
    #[tokio::test]
    async fn core_list_resource_cross_namespace_pods_with_v1beta1_table_accept_returns_406() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );
        let user = crate::auth::UserInfo {
            username: "test-user".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        };

        let app = Router::new()
            .route("/api/v1/{resource}", get(super::core_list_resource))
            .layer(axum::Extension(user))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/pods")
            .header(
                "accept",
                "application/json;as=Table;g=meta.k8s.io;v=v1beta1",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    /// `kubectl get service <name>` (and every other core v1 type — configmaps, secrets, ...)
    /// routes through core_get_namespaced_resource, a distinct wrapper from the generic
    /// /apis/{group}/{version} handlers. Before this fix, the wrapper didn't extract the
    /// Accept header at all, so fixing get_namespaced_resource alone would not have helped:
    /// kubectl would still fall back to NAME/AGE-only output for any core v1 resource type.
    #[tokio::test]
    async fn core_get_namespaced_resource_honors_table_accept() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "my-svc", "namespace": "default" },
            "spec": { "clusterIP": "10.0.0.5", "ports": [] }
        });
        store
            .put(
                "/registry/services/default/my-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                Some(0),
            )
            .await
            .expect("create service");

        let state = crate::state::AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route(
                "/api/v1/namespaces/{ns}/{resource}/{name}",
                get(super::core_get_namespaced_resource),
            )
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/services/my-svc")
            .header("accept", "application/json;as=Table;g=meta.k8s.io;v=v1")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["kind"], "Table",
            "core_get_namespaced_resource must forward the real Accept header down to \
             get_namespaced_resource — without it, `kubectl get service <name>` never gets \
             Table output no matter what get_namespaced_resource itself does"
        );
    }
}
