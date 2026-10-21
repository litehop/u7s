//! Router-level proof that subresource writes run the admission chain a policy author expects:
//! a webhook or ValidatingAdmissionPolicy registered for `<resource>/<subresource>` must see
//! (and be able to veto or mutate) the write, with upstream's `subResource`/`kind`/`operation`.

use std::sync::{Arc, Mutex};

use axum::{body::Body, http::Request, http::StatusCode, Router};
use bytes::Bytes;
use serde_json::{json, Value};
use tower::ServiceExt;
use u7s_store::{SqliteStore, Store};

use crate::{handlers::test_support::*, state::AppState};

pub(crate) struct Hook {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Value>>>,
}

impl Hook {
    pub(crate) fn requests(&self) -> Vec<Value> {
        self.seen.lock().unwrap().clone()
    }
}

/// Spawn an AdmissionReview endpoint. `respond` maps the request to the `response` body
/// (minus `uid`, which is echoed); every request it receives is recorded in `Hook::seen`.
pub(crate) async fn spawn_hook(respond: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Hook {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let respond = Arc::new(respond);
    let app = Router::new().route(
        "/webhook",
        axum::routing::post(move |axum::Json(review): axum::Json<Value>| {
            let recorded = recorded.clone();
            let respond = respond.clone();
            async move {
                let request = review["request"].clone();
                let mut response = respond(&request);
                response["uid"] = request["uid"].clone();
                recorded.lock().unwrap().push(request);
                axum::Json(json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": response,
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Hook {
        url: format!("http://{addr}/webhook"),
        seen,
    }
}

pub(crate) fn deny(message: &'static str) -> impl Fn(&Value) -> Value + Send + Sync + 'static {
    move |_| json!({"allowed": false, "status": {"code": 403, "message": message}})
}

pub(crate) fn allow() -> impl Fn(&Value) -> Value + Send + Sync + 'static {
    |_| json!({"allowed": true})
}

pub(crate) fn json_patch(ops: Value) -> impl Fn(&Value) -> Value + Send + Sync + 'static {
    move |_| {
        json!({
            "allowed": true,
            "patchType": "JSONPatch",
            "patch": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                ops.to_string(),
            ),
        })
    }
}

async fn put_registry(store: &Arc<SqliteStore>, path: &str, v: Value) {
    store
        .put(
            &format!("/registry/admissionregistration.k8s.io/{path}"),
            Bytes::from(v.to_string()),
            None,
        )
        .await
        .unwrap();
}

/// Register a webhook for `resources` (e.g. `["pods/status"]`) on `operations`.
pub(crate) async fn register_webhook(
    store: &Arc<SqliteStore>,
    mutating: bool,
    name: &str,
    url: &str,
    api_group: &str,
    resources: &[&str],
    operations: &[&str],
) {
    let (kind, plural) = if mutating {
        (
            "MutatingWebhookConfiguration",
            "mutatingwebhookconfigurations",
        )
    } else {
        (
            "ValidatingWebhookConfiguration",
            "validatingwebhookconfigurations",
        )
    };
    put_registry(
        store,
        &format!("{plural}/{name}"),
        json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": kind,
            "metadata": {"name": name},
            "webhooks": [{
                "name": format!("{name}.example.com"),
                "clientConfig": {"url": url},
                "rules": [{"apiGroups": [api_group], "apiVersions": ["*"],
                    "resources": resources, "operations": operations}],
                "failurePolicy": "Fail",
                "sideEffects": "None",
                "admissionReviewVersions": ["v1"]
            }]
        }),
    )
    .await;
}

/// Register a ValidatingAdmissionPolicy (+ Deny binding) denying with `message` unless
/// `expression` holds, for `resources` on UPDATE/CREATE.
pub(crate) async fn register_vap(
    store: &Arc<SqliteStore>,
    name: &str,
    api_group: &str,
    resources: &[&str],
    expression: &str,
    message: &str,
) {
    put_registry(
        store,
        &format!("validatingadmissionpolicies/{name}"),
        json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": name},
            "spec": {
                "matchConstraints": {"resourceRules": [{
                    "apiGroups": [api_group], "apiVersions": ["*"],
                    "operations": ["CREATE", "UPDATE"], "resources": resources
                }]},
                "validations": [{"expression": expression, "message": message}]
            }
        }),
    )
    .await;
    put_registry(
        store,
        &format!("validatingadmissionpolicybindings/{name}"),
        json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": name},
            "spec": {"policyName": name, "validationActions": ["Deny"]}
        }),
    )
    .await;
}

pub(crate) struct Cluster {
    pub router: Router,
    pub store: Arc<SqliteStore>,
}

impl Cluster {
    pub(crate) async fn new() -> Self {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state: AppState = make_state_with_store(store.clone());
        seed_namespace(&state, "default").await;
        Self {
            router: crate::build_router(state),
            store,
        }
    }

    pub(crate) async fn call(
        &self,
        method: &str,
        uri: &str,
        content_type: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(crate::auth::UserInfo {
            username: "alice".into(),
            uid: "uid-alice".into(),
            groups: vec!["devs".into()],
            extra: Default::default(),
        });
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub(crate) async fn create_pod(&self, name: &str) {
        let (status, body) = self
            .call(
                "POST",
                "/api/v1/namespaces/default/pods",
                "application/json",
                json!({
                    "apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": name},
                    "spec": {"containers": [{"name": "app", "image": "nginx",
                        "resources": {
                            "limits": {"cpu": "100m", "memory": "128Mi"},
                            "requests": {"cpu": "100m", "memory": "128Mi"}}}]}
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    pub(crate) async fn stored(&self, key: &str) -> Value {
        let stored = self.store.get(key).await.unwrap().unwrap();
        serde_json::from_slice(&stored.value).unwrap()
    }

    pub(crate) async fn stored_pod(&self, name: &str) -> Value {
        self.stored(&format!("/registry/pods/default/{name}")).await
    }
}

const STRATEGIC: &str = "application/strategic-merge-patch+json";

/// A mutating webhook scoped to pods/ephemeralcontainers may change the debug container
/// (that is what injecting a sidecar-style argument means), but upstream's
/// `dropNonEphemeralContainerUpdates` discards everything else it touched before the write is
/// stored. Persisting a webhook's edit to `spec.containers` here would let a debug-container
/// policy rewrite the running workload.
#[tokio::test]
async fn mutating_webhook_edits_to_ephemeral_containers_persist_and_edits_elsewhere_are_dropped() {
    let c = Cluster::new().await;
    c.create_pod("p").await;
    let hook = spawn_hook(json_patch(json!([
        {"op": "add", "path": "/spec/ephemeralContainers/0/args", "value": ["injected"]},
        {"op": "replace", "path": "/spec/containers/0/image", "value": "evil"},
        {"op": "add", "path": "/metadata/labels", "value": {"tampered": "yes"}}
    ])))
    .await;
    register_webhook(
        &c.store,
        true,
        "debug-mutator",
        &hook.url,
        "",
        &["pods/ephemeralcontainers"],
        &["UPDATE"],
    )
    .await;

    for (method, ct, name) in [
        ("PATCH", STRATEGIC, "dbg-patch"),
        ("PUT", "application/json", "dbg-put"),
    ] {
        let (status, body) = c
            .call(
                method,
                "/api/v1/namespaces/default/pods/p/ephemeralcontainers",
                ct,
                json!({"spec": {"ephemeralContainers": [{"name": name, "image": "busybox"}]}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{method}: {body}");
    }

    let pod = c.stored_pod("p").await;
    let ecs = pod["spec"]["ephemeralContainers"].as_array().unwrap();
    assert_eq!(ecs.len(), 2, "{pod}");
    assert_eq!(
        ecs[0]["args"],
        json!(["injected"]),
        "the webhook's edit to the debug container must be persisted"
    );
    assert_eq!(
        pod["spec"]["containers"][0]["image"], "nginx",
        "a webhook edit outside spec.ephemeralContainers must be dropped"
    );
    assert!(
        pod["metadata"]["labels"].is_null(),
        "a webhook label edit must be dropped on this subresource: {pod}"
    );
    let reqs = hook.requests();
    assert!(
        reqs.iter()
            .all(|r| r["subResource"] == "ephemeralcontainers"
                && r["resource"]["resource"] == "pods"
                && r["operation"] == "UPDATE"),
        "{reqs:?}"
    );
}

/// Upstream runs ValidatePodEphemeralContainersUpdate after mutating admission
/// (store.go: BeforeUpdate follows UpdatedObject). A mutating webhook must therefore not be
/// able to smuggle in a field ephemeral containers forbid, such as ports.
#[tokio::test]
async fn mutating_webhook_cannot_inject_an_invalid_ephemeral_container() {
    let c = Cluster::new().await;
    c.create_pod("p").await;
    let hook = spawn_hook(json_patch(json!([
        {"op": "add", "path": "/spec/ephemeralContainers/0/ports",
         "value": [{"containerPort": 80}]}
    ])))
    .await;
    register_webhook(
        &c.store,
        true,
        "bad-mutator",
        &hook.url,
        "",
        &["pods/ephemeralcontainers"],
        &["UPDATE"],
    )
    .await;

    let (status, body) = c
        .call(
            "PATCH",
            "/api/v1/namespaces/default/pods/p/ephemeralcontainers",
            STRATEGIC,
            json!({"spec": {"ephemeralContainers": [{"name": "dbg", "image": "busybox"}]}}),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("ports") && m.contains("Forbidden")),
        "{body}"
    );
    assert!(
        c.stored_pod("p").await["spec"]["ephemeralContainers"].is_null(),
        "an invalid mutated container must not be persisted"
    );
}
