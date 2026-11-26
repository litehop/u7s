//! A request must complete on the stack a real worker thread has (`main.rs`
//! `thread_stack_size`, 512 KiB): a debug build whose pod create or PATCH needs more aborts
//! the whole apiserver with SIGSEGV, taking every other in-flight request with it.
//!
//! Process-wide lazies (compiled regexes) are paid by whichever request touches them first,
//! so the scenario runs in a fresh child process where every one of them is still cold.

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use tower::ServiceExt as _;

use super::test_support::{make_state, seed_namespace};

/// Worker stack less the room the HTTP server and TLS frames below the router take, which
/// this in-process router does not exercise.
const ROUTER_STACK: usize = (512 - 128) * 1024;

/// The router with the layers `run` stacks on it, so middleware frames count too.
async fn production_app(state: crate::state::AppState) -> Router {
    state.init().await;
    crate::build_router(state.clone())
        .layer(crate::content_type::ContentTypeLayer)
        .layer(crate::body_budget::BodyBudgetLayer::new())
        .layer(crate::inflight::InflightLayer::new())
        .layer(crate::auth::AuthLayer::new(
            std::sync::Arc::clone(&state.rbac_index),
            (*state.token_map).clone(),
            state.sa_keys.clone(),
            std::sync::Arc::clone(&state.store),
            std::sync::Arc::clone(&state.sa_sig_cache),
            std::sync::Arc::clone(&state.flowcontrol_cache),
            std::sync::Arc::clone(&state.node_graph),
            std::sync::Arc::clone(&state.resource_registry),
            std::sync::Arc::clone(&state.discovery_cache),
        ))
}

async fn send(app: &Router, method: &str, uri: &str, ct: &str, body: String) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, ct)
        .header(header::AUTHORIZATION, "Bearer root-token")
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

async fn labeled_create_then_patches(app: Router) {
    let pod = serde_json::json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": "p", "namespace": "default",
            "labels": {"app": "web", "pod-template-hash": "5d8f7c9b6d"},
            "ownerReferences": [{
                "apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "web",
                "uid": "1c9e3f5a-7d1c-4c55-9b0e-000000000001",
                "controller": true, "blockOwnerDeletion": true
            }]
        },
        "spec": {
            "containers": [
                {"name": "app", "image": "registry.k8s.io/pause:3.10",
                 "env": [{"name": "A", "value": "1"}],
                 "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}},
                {"name": "sidecar", "image": "registry.k8s.io/pause:3.10"}
            ],
            "volumes": [{"name": "scratch", "emptyDir": {}}]
        }
    });
    let created = send(
        &app,
        "POST",
        "/api/v1/namespaces/default/pods",
        "application/json",
        pod.to_string(),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);
    let uri = "/api/v1/namespaces/default/pods/p";
    for (ct, body) in [
        (
            "application/merge-patch+json",
            r#"{"metadata":{"labels":{"x":"1"}}}"#,
        ),
        (
            "application/strategic-merge-patch+json",
            r#"{"metadata":{"labels":{"y":"2"}}}"#,
        ),
        (
            "application/json-patch+json",
            r#"[{"op":"add","path":"/metadata/labels/z","value":"3"}]"#,
        ),
    ] {
        assert_eq!(
            send(&app, "PATCH", uri, ct, body.into()).await,
            StatusCode::OK,
            "{ct}"
        );
    }
}

/// The scenario itself. Handlers run as spawned tasks on a runtime worker thread, so the
/// future lives on the heap but every poll's frames land on that thread's stack.
#[test]
#[ignore = "run by labeled_pod_create_and_patch_fit_a_production_worker_stack in a fresh process"]
fn stack_budget_child() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_stack_size(ROUTER_STACK)
        .enable_all()
        .build()
        .unwrap();
    let mut state = make_state();
    let mut tokens = (*state.token_map).clone();
    tokens.insert(
        "root-token".to_owned(),
        crate::auth::UserInfo {
            username: "root".into(),
            uid: String::new(),
            groups: vec!["system:masters".into()],
            extra: Default::default(),
        },
    );
    state.token_map = std::sync::Arc::new(tokens);
    state.rbac_index.apply_object(
        "/apis/rbac.authorization.k8s.io/v1/clusterroles/test-creator",
        &serde_json::json!({"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}),
    );
    rt.block_on(async {
        seed_namespace(&state, "default").await;
        let app = production_app(state).await;
        tokio::spawn(labeled_create_then_patches(app))
            .await
            .unwrap();
    });
}

#[test]
fn labeled_pod_create_and_patch_fit_a_production_worker_stack() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "handlers::stack_budget_tests::stack_budget_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a labeled pod create or PATCH overflowed a {} KiB worker stack ({:?}): {}{}",
        ROUTER_STACK / 1024,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
