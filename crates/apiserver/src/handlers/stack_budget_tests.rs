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

/// The regex parser recurses once per group nesting level, so a deeply nested pattern is the
/// cheapest user input that makes a compile need far more stack than the pattern's length.
fn nested_group_pattern() -> String {
    format!("^{}a{}$", "(".repeat(200), ")".repeat(200))
}

/// Creates a CRD whose `spec.slug` has the given schema, then the first CR of it.
async fn create_widget_crd_then_cr(app: &Router, slug_schema: serde_json::Value) {
    let crd = serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "widgets.stack.example.com"},
        "spec": {
            "group": "stack.example.com",
            "names": {"plural": "widgets", "singular": "widget", "kind": "Widget", "listKind": "WidgetList"},
            "scope": "Namespaced",
            "versions": [{
                "name": "v1", "served": true, "storage": true,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "properties": {"spec": {
                        "type": "object",
                        "properties": {"slug": slug_schema}
                    }}
                }}
            }]
        }
    });
    assert_eq!(
        send(
            app,
            "POST",
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            "application/json",
            crd.to_string()
        )
        .await,
        StatusCode::CREATED
    );
    let widget = serde_json::json!({
        "apiVersion": "stack.example.com/v1", "kind": "Widget",
        "metadata": {"name": "w", "namespace": "default"},
        "spec": {"slug": "a"}
    });
    assert_eq!(
        send(
            app,
            "POST",
            "/apis/stack.example.com/v1/namespaces/default/widgets",
            "application/json",
            widget.to_string()
        )
        .await,
        StatusCode::CREATED
    );
}

/// A custom-resource create with no regex anywhere: its admission and schema frames alone
/// must fit the worker stack.
async fn plain_custom_resource_create(app: Router) {
    create_widget_crd_then_cr(&app, serde_json::json!({"type": "string"})).await;
}

/// A CRD `pattern` compiles when the first CR write against the CRD builds its schema, and a
/// CEL `matches()` compiles when an admission expression first uses its pattern; both
/// patterns come from users.
async fn user_regexes_compile_on_first_use(app: Router) {
    create_widget_crd_then_cr(
        &app,
        serde_json::json!({"type": "string", "pattern": nested_group_pattern()}),
    )
    .await;

    let env = crate::cel_runtime::Env::new(vec![]);
    assert_eq!(
        crate::cel_runtime::eval_bool(&env, &format!("'a'.matches('{}')", nested_group_pattern())),
        Ok(true)
    );
}

/// Runs `scenario` as a spawned task on a runtime worker thread, so the future lives on the
/// heap but every poll's frames land on that thread's stack.
fn run_on_production_stack<Fut>(stack: usize, scenario: fn(Router) -> Fut)
where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_stack_size(stack)
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
        tokio::spawn(scenario(app)).await.unwrap();
    });
}

#[test]
#[ignore = "run by labeled_pod_create_and_patch_fit_a_production_worker_stack in a fresh process"]
fn stack_budget_child() {
    run_on_production_stack(ROUTER_STACK, labeled_create_then_patches);
}

#[test]
#[ignore = "run by custom_resource_create_fits_a_production_worker_stack in a fresh process"]
fn plain_custom_resource_child() {
    run_on_production_stack(ROUTER_STACK, plain_custom_resource_create);
}

#[test]
#[ignore = "run by user_regexes_fit_a_production_worker_stack_on_first_use in a fresh process"]
fn user_regex_child() {
    run_on_production_stack(ROUTER_STACK, user_regexes_compile_on_first_use);
}

fn assert_child_fits(child: &str, what: &str, stack: usize) {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            &format!("handlers::stack_budget_tests::{child}"),
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{what} overflowed a {} KiB worker stack ({:?}): {}{}",
        stack / 1024,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn labeled_pod_create_and_patch_fit_a_production_worker_stack() {
    assert_child_fits(
        "stack_budget_child",
        "a labeled pod create or PATCH",
        ROUTER_STACK,
    );
}

#[test]
fn user_regexes_fit_a_production_worker_stack_on_first_use() {
    assert_child_fits(
        "user_regex_child",
        "a first-use CRD `pattern` or CEL `matches()` compile",
        ROUTER_STACK,
    );
}

#[test]
fn custom_resource_create_fits_a_production_worker_stack() {
    assert_child_fits(
        "plain_custom_resource_child",
        "a custom-resource create",
        ROUTER_STACK,
    );
}
