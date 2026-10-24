//! Router-level proof that subresource writes run the admission chain a policy author expects:
//! a webhook or ValidatingAdmissionPolicy registered for `<resource>/<subresource>` must see
//! (and be able to veto or mutate) the write, with upstream's `subResource`/`kind`/`operation`.

mod cases {
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
    pub(crate) async fn spawn_hook(
        respond: impl Fn(&Value) -> Value + Send + Sync + 'static,
    ) -> Hook {
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
        register_webhook_for(
            store, mutating, name, url, api_group, "*", None, resources, operations,
        )
        .await;
    }

    /// Like `register_webhook`, with the rule pinned to `api_version` and an explicit
    /// `matchPolicy` (`None` leaves it unset, i.e. the API default).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn register_webhook_for(
        store: &Arc<SqliteStore>,
        mutating: bool,
        name: &str,
        url: &str,
        api_group: &str,
        api_version: &str,
        match_policy: Option<&str>,
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
        let mut webhook = json!({
            "name": format!("{name}.example.com"),
            "clientConfig": {"url": url},
            "rules": [{"apiGroups": [api_group], "apiVersions": [api_version],
                "resources": resources, "operations": operations}],
            "failurePolicy": "Fail",
            "sideEffects": "None",
            "admissionReviewVersions": ["v1"]
        });
        if let Some(policy) = match_policy {
            webhook["matchPolicy"] = json!(policy);
        }
        put_registry(
            store,
            &format!("{plural}/{name}"),
            json!({
                "apiVersion": "admissionregistration.k8s.io/v1",
                "kind": kind,
                "metadata": {"name": name},
                "webhooks": [webhook]
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
        pub state: AppState,
    }

    impl Cluster {
        pub(crate) async fn new() -> Self {
            let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
            let state: AppState = make_state_with_store(store.clone());
            seed_namespace(&state, "default").await;
            Self {
                router: crate::build_router(state.clone()),
                store,
                state,
            }
        }

        pub(crate) async fn create(&self, uri: &str, body: Value) {
            let (status, resp) = self.call("POST", uri, "application/json", body).await;
            assert_eq!(status, StatusCode::CREATED, "create {uri}: {resp}");
        }

        pub(crate) async fn call(
            &self,
            method: &str,
            uri: &str,
            content_type: &str,
            body: Value,
        ) -> (StatusCode, Value) {
            let uri = if content_type.contains("apply-patch") && !uri.contains('?') {
                format!("{uri}?fieldManager=tests&force=true")
            } else {
                uri.to_owned()
            };
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

    const MERGE: &str = "application/merge-patch+json";
    const STRATEGIC: &str = "application/strategic-merge-patch+json";

    /// A mutating webhook scoped to pods/ephemeralcontainers may change the debug container
    /// (that is what injecting a sidecar-style argument means), but upstream's
    /// `dropNonEphemeralContainerUpdates` discards everything else it touched before the write is
    /// stored. Persisting a webhook's edit to `spec.containers` here would let a debug-container
    /// policy rewrite the running workload.
    #[tokio::test]
    async fn mutating_webhook_edits_to_ephemeral_containers_persist_and_edits_elsewhere_are_dropped(
    ) {
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

    type Write = (&'static str, &'static str, &'static str, Value);

    /// Every verb/content-type combination pods/status accepts.
    fn pod_status_writes(phase: &str) -> Vec<Write> {
        let status = json!({"status": {"phase": phase}});
        vec![
            ("PUT", "PUT", "application/json", status.clone()),
            ("merge-PATCH", "PATCH", MERGE, status.clone()),
            ("strategic-PATCH", "PATCH", STRATEGIC, status),
            (
                "apply-PATCH",
                "PATCH",
                "application/apply-patch+yaml",
                json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p"},
                "status": {"phase": phase}}),
            ),
        ]
    }

    /// A policy author's webhook on pods/status (e.g. to stop a node marking pods Failed) is
    /// silently bypassed if only the main-resource write path runs admission. It must see every
    /// verb the kubelet and controllers use, with upstream's request shape.
    #[tokio::test]
    async fn validating_webhook_on_pod_status_vetoes_every_write_verb() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(deny("status writes are frozen")).await;
        register_webhook(
            &c.store,
            false,
            "freeze",
            &hook.url,
            "",
            &["pods/status"],
            &["UPDATE"],
        )
        .await;
        let before = c.stored_pod("p").await["status"].clone();

        let writes = pod_status_writes("Running");
        for (label, method, ct, body) in &writes {
            let (status, resp) = c
                .call(
                    method,
                    "/api/v1/namespaces/default/pods/p/status",
                    ct,
                    body.clone(),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {resp}");
            assert!(
                resp["message"]
                    .as_str()
                    .unwrap()
                    .contains("status writes are frozen"),
                "{label}: {resp}"
            );
        }
        assert_eq!(
            c.stored_pod("p").await["status"],
            before,
            "a denied write must not persist"
        );

        let reqs = hook.requests();
        assert_eq!(reqs.len(), writes.len(), "{reqs:?}");
        for r in &reqs {
            assert_eq!(r["subResource"], "status");
            assert_eq!(r["resource"]["resource"], "pods");
            assert_eq!(r["kind"]["kind"], "Pod");
            assert_eq!(r["operation"], "UPDATE");
            assert_eq!(r["userInfo"]["username"], "alice");
            assert_eq!(r["object"]["status"]["phase"], "Running");
            assert_eq!(r["oldObject"]["status"]["phase"], before["phase"]);
        }
    }

    /// A rule naming only `pods` must not start gating the kubelet's status writes (upstream
    /// matches a subresource only when the rule says so), or every such webhook would stall node
    /// heartbeats.
    #[tokio::test]
    async fn pods_only_webhook_does_not_fire_for_pod_status() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(deny("pods only")).await;
        register_webhook(
            &c.store,
            false,
            "pods-only",
            &hook.url,
            "",
            &["pods"],
            &["*"],
        )
        .await;
        for (label, method, ct, body) in pod_status_writes("Running") {
            let (status, resp) = c
                .call(method, "/api/v1/namespaces/default/pods/p/status", ct, body)
                .await;
            assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        }
        assert!(hook.requests().is_empty());
    }

    /// A ValidatingAdmissionPolicy on pods/status is the supported way to forbid a phase
    /// transition; it must deny with the policy's own message and still admit compliant writes.
    #[tokio::test]
    async fn vap_on_pod_status_denies_every_write_verb_and_admits_compliant_ones() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        register_vap(
            &c.store,
            "no-failed",
            "",
            &["pods/status"],
            "object.status.phase != 'Failed'",
            "pods may not be marked Failed",
        )
        .await;
        for (label, method, ct, body) in pod_status_writes("Failed") {
            let (status, resp) = c
                .call(method, "/api/v1/namespaces/default/pods/p/status", ct, body)
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {resp}");
            assert!(
                resp["message"]
                    .as_str()
                    .unwrap()
                    .contains("pods may not be marked Failed"),
                "{label}: {resp}"
            );
        }
        assert_ne!(c.stored_pod("p").await["status"]["phase"], "Failed");
        for (label, method, ct, body) in pod_status_writes("Running") {
            let (status, resp) = c
                .call(method, "/api/v1/namespaces/default/pods/p/status", ct, body)
                .await;
            assert_eq!(status, StatusCode::OK, "{label}: {resp}");
        }
    }

    /// Mutating webhooks on pods/status may stamp status and annotations; upstream's status
    /// strategy then discards spec edits. Persisting a spec edit would let a status-scoped
    /// webhook rewrite the workload; ignoring the status edit would make the hook useless.
    #[tokio::test]
    async fn mutating_webhook_on_pod_status_keeps_status_and_annotation_edits_but_drops_spec() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "add", "path": "/status/message", "value": "stamped"},
            {"op": "add", "path": "/metadata/annotations", "value": {"stamped": "yes"}},
            {"op": "replace", "path": "/spec/containers/0/image", "value": "evil"}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "stamp",
            &hook.url,
            "",
            &["pods/status"],
            &["UPDATE"],
        )
        .await;

        for (label, method, ct, body) in pod_status_writes("Running") {
            let (status, resp) = c
                .call(method, "/api/v1/namespaces/default/pods/p/status", ct, body)
                .await;
            assert_eq!(status, StatusCode::OK, "{label}: {resp}");
            let pod = c.stored_pod("p").await;
            assert_eq!(pod["status"]["message"], "stamped", "{label}: {pod}");
            assert_eq!(
                pod["metadata"]["annotations"]["stamped"], "yes",
                "{label}: {pod}"
            );
            assert_eq!(
                pod["spec"]["containers"][0]["image"], "nginx",
                "{label}: {pod}"
            );
        }
    }

    const RESIZE_URI: &str = "/api/v1/namespaces/default/pods/p/resize";

    fn resize_to(cpu: &str) -> Value {
        json!({"spec": {"containers": [{"name": "app", "resources": {
        "limits": {"cpu": cpu, "memory": "128Mi"},
        "requests": {"cpu": cpu, "memory": "128Mi"}}}]}})
    }

    /// A webhook or VAP on pods/resize is how a platform caps in-place vertical scaling
    /// (e.g. a CPU ceiling). Both verbs on /resize must reach it, or the cap is bypassed by
    /// resizing instead of recreating.
    #[tokio::test]
    async fn validating_webhook_and_vap_on_pod_resize_veto_put_and_patch() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(deny("resizes are frozen")).await;
        register_webhook(
            &c.store,
            false,
            "freeze",
            &hook.url,
            "",
            &["pods/resize"],
            &["UPDATE"],
        )
        .await;
        for method in ["PUT", "PATCH"] {
            let (status, body) = c.call(method, RESIZE_URI, MERGE, resize_to("200m")).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
        }
        let reqs = hook.requests();
        assert_eq!(reqs.len(), 2, "{reqs:?}");
        for r in &reqs {
            assert_eq!(r["subResource"], "resize");
            assert_eq!(r["kind"]["kind"], "Pod");
            assert_eq!(r["operation"], "UPDATE");
            assert_eq!(
                r["object"]["spec"]["containers"][0]["resources"]["requests"]["cpu"],
                "200m"
            );
            assert_eq!(
                r["oldObject"]["spec"]["containers"][0]["resources"]["requests"]["cpu"],
                "100m"
            );
        }
        assert_eq!(
            c.stored_pod("p").await["spec"]["containers"][0]["resources"]["requests"]["cpu"],
            "100m",
            "a denied resize must not persist"
        );
        c.store
            .delete(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/freeze",
                None,
            )
            .await
            .unwrap();

        register_vap(
            &c.store,
            "cpu-cap",
            "",
            &["pods/resize"],
            "object.spec.containers[0].resources.requests.cpu != '600m'",
            "cpu of 600m is not allowed",
        )
        .await;
        for method in ["PUT", "PATCH"] {
            let (status, body) = c.call(method, RESIZE_URI, MERGE, resize_to("600m")).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{method}: {body}");
            assert!(
                body["message"]
                    .as_str()
                    .unwrap()
                    .contains("cpu of 600m is not allowed"),
                "{method}: {body}"
            );
        }
        let (status, body) = c.call("PATCH", RESIZE_URI, MERGE, resize_to("400m")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// A mutating webhook on pods/resize may adjust the resources being resized but, as upstream's
    /// dropNonResizeUpdates does, nothing else; and its result is validated again, so it cannot
    /// push the pod into a different QoS class.
    #[tokio::test]
    async fn mutating_webhook_on_pod_resize_adjusts_resources_but_cannot_change_qos_or_image() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "replace", "path": "/spec/containers/0/resources/requests/cpu", "value": "250m"},
            {"op": "replace", "path": "/spec/containers/0/resources/limits/cpu", "value": "250m"},
            {"op": "replace", "path": "/spec/containers/0/image", "value": "evil"}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "clamp",
            &hook.url,
            "",
            &["pods/resize"],
            &["UPDATE"],
        )
        .await;
        let (status, body) = c.call("PATCH", RESIZE_URI, MERGE, resize_to("200m")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let pod = c.stored_pod("p").await;
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["requests"]["cpu"], "250m",
            "{pod}"
        );
        assert_eq!(pod["spec"]["containers"][0]["image"], "nginx", "{pod}");

        c.store
            .delete(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/clamp",
                None,
            )
            .await
            .unwrap();
        let hook = spawn_hook(json_patch(json!([
            {"op": "replace", "path": "/spec/containers/0/resources/requests/cpu", "value": "50m"}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "qos-breaker",
            &hook.url,
            "",
            &["pods/resize"],
            &["UPDATE"],
        )
        .await;
        let (status, body) = c.call("PATCH", RESIZE_URI, MERGE, resize_to("300m")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("QOS Class may not change"),
            "{body}"
        );
    }

    const BIND_URI: &str = "/api/v1/namespaces/default/pods/p/binding";

    fn binding_to(node: &str) -> Value {
        json!({"apiVersion": "v1", "kind": "Binding", "metadata": {"name": "p"},
        "target": {"apiVersion": "v1", "kind": "Node", "name": node}})
    }

    /// Binding is a CREATE of a Binding object upstream, so webhooks and policies see it. A
    /// placement policy ("never bind to node X") is bypassed entirely if the scheduler's write
    /// skips admission.
    #[tokio::test]
    async fn validating_webhook_and_vap_on_pod_binding_veto_placement() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(deny("node is cordoned by policy")).await;
        register_webhook(
            &c.store,
            false,
            "no-bind",
            &hook.url,
            "",
            &["pods/binding"],
            &["CREATE"],
        )
        .await;
        let (status, body) = c
            .call("POST", BIND_URI, "application/json", binding_to("node-1"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("node is cordoned by policy"),
            "{body}"
        );
        assert!(
            c.stored_pod("p").await["spec"]["nodeName"].is_null(),
            "a denied binding must leave the pod unscheduled"
        );
        let reqs = hook.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        let r = &reqs[0];
        assert_eq!(r["subResource"], "binding");
        assert_eq!(r["resource"]["resource"], "pods");
        assert_eq!(r["kind"]["kind"], "Binding");
        assert_eq!(r["operation"], "CREATE");
        assert_eq!(r["name"], "p");
        assert_eq!(r["object"]["target"]["name"], "node-1");
        assert_eq!(r["userInfo"]["username"], "alice");
        c.store
            .delete(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/no-bind",
                None,
            )
            .await
            .unwrap();

        register_vap(
            &c.store,
            "no-node-2",
            "",
            &["pods/binding"],
            "object.target.name != 'node-2'",
            "node-2 is reserved",
        )
        .await;
        let (status, body) = c
            .call("POST", BIND_URI, "application/json", binding_to("node-2"))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("node-2 is reserved"),
            "{body}"
        );
        let (status, body) = c
            .call("POST", BIND_URI, "application/json", binding_to("node-1"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(c.stored_pod("p").await["spec"]["nodeName"], "node-1");
    }

    /// A mutating webhook on pods/binding may retarget the binding (upstream admits the Binding
    /// object before storage assigns the node), and the bind uses what it returned.
    #[tokio::test]
    async fn mutating_webhook_on_pod_binding_retargets_the_node() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "replace", "path": "/target/name", "value": "mutated-node"}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "retarget",
            &hook.url,
            "",
            &["pods/binding"],
            &["CREATE"],
        )
        .await;
        let (status, body) = c
            .call("POST", BIND_URI, "application/json", binding_to("node-1"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(c.stored_pod("p").await["spec"]["nodeName"], "mutated-node");
    }

    /// Eviction is a CREATE of an Eviction (policy/v1) object, so a mutating webhook on
    /// pods/eviction must run before the validating one and see the policy/v1 kind; before this
    /// only validating webhooks were consulted.
    #[tokio::test]
    async fn mutating_webhook_on_pod_eviction_runs_and_validating_sees_its_result() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        let mutator = spawn_hook(json_patch(json!([
            {"op": "add", "path": "/metadata/labels", "value": {"mutated": "yes"}}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "evict-mutator",
            &mutator.url,
            "",
            &["pods/eviction"],
            &["CREATE"],
        )
        .await;
        let validator = spawn_hook(deny("evictions are frozen")).await;
        register_webhook(
            &c.store,
            false,
            "evict-freeze",
            &validator.url,
            "",
            &["pods/eviction"],
            &["CREATE"],
        )
        .await;
        let (status, body) = c
            .call(
                "POST",
                "/api/v1/namespaces/default/pods/p/eviction",
                "application/json",
                json!({"apiVersion": "policy/v1", "kind": "Eviction",
                "metadata": {"name": "p", "namespace": "default"}}),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let m = mutator.requests();
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0]["subResource"], "eviction");
        assert_eq!(m[0]["kind"]["group"], "policy");
        assert_eq!(m[0]["kind"]["kind"], "Eviction");
        assert_eq!(m[0]["operation"], "CREATE");
        let v = validator.requests();
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(
            v[0]["object"]["metadata"]["labels"]["mutated"], "yes",
            "the validating webhook must see the mutating webhook's output"
        );
        assert!(
            c.stored_pod("p").await["metadata"]["deletionTimestamp"].is_null(),
            "a denied eviction must not delete the pod"
        );
    }

    const JSON_PATCH: &str = "application/json-patch+json";
    const APPLY: &str = "application/apply-patch+yaml";

    /// One write against a subresource: `(label, method, uri, content type, body)`.
    type Cell = (String, &'static str, String, &'static str, Value);

    /// Every verb/content type a `/status` route accepts for the object at `base`.
    fn status_cells(
        base: &str,
        api_version: &str,
        kind: &str,
        name: &str,
        status: Value,
    ) -> Vec<Cell> {
        let uri = format!("{base}/status");
        let obj = json!({"apiVersion": api_version, "kind": kind,
            "metadata": {"name": name}, "status": status});
        let patch = json!({"status": status});
        let op = |s: &Value| {
            let (k, v) = s.as_object().unwrap().iter().next().unwrap();
            json!([{"op": "add", "path": format!("/status/{k}"), "value": v}])
        };
        vec![
            (
                "PUT".into(),
                "PUT",
                uri.clone(),
                "application/json",
                obj.clone(),
            ),
            (
                "merge-PATCH".into(),
                "PATCH",
                uri.clone(),
                MERGE,
                patch.clone(),
            ),
            (
                "strategic-PATCH".into(),
                "PATCH",
                uri.clone(),
                STRATEGIC,
                patch,
            ),
            (
                "json-PATCH".into(),
                "PATCH",
                uri.clone(),
                JSON_PATCH,
                op(&status),
            ),
            ("apply-PATCH".into(), "PATCH", uri, APPLY, obj),
        ]
    }

    /// Scale PUT and PATCH for the object at `base`.
    fn scale_cells(base: &str, name: &str, ns: &str, replicas: i64) -> Vec<Cell> {
        let uri = format!("{base}/scale");
        vec![
            (
                "scale PUT".into(),
                "PUT",
                uri.clone(),
                "application/json",
                json!({"apiVersion": "autoscaling/v1", "kind": "Scale",
                    "metadata": {"name": name, "namespace": ns},
                    "spec": {"replicas": replicas}}),
            ),
            (
                "scale merge-PATCH".into(),
                "PATCH",
                uri,
                MERGE,
                json!({"spec": {"replicas": replicas}}),
            ),
        ]
    }

    /// Register a deny webhook on `group`/`resource` (`<res>/<sub>`), fire every cell and
    /// assert each was vetoed by it with upstream's request shape. Returns the hook for
    /// further assertions.
    async fn assert_every_write_is_vetoed(
        c: &Cluster,
        group: &str,
        resource: &str,
        kind: &str,
        cells: &[Cell],
    ) -> Hook {
        let hook = spawn_hook(deny("frozen by policy")).await;
        register_webhook(
            &c.store,
            false,
            "freeze",
            &hook.url,
            group,
            &[resource],
            &["UPDATE"],
        )
        .await;
        for (label, method, uri, ct, body) in cells {
            let (status, resp) = c.call(method, uri, ct, body.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{resource} {label}: the webhook registered for {resource} must veto it: {resp}"
            );
            assert!(
                resp["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("frozen by policy")),
                "{resource} {label}: {resp}"
            );
        }
        let (base, sub) = resource.split_once('/').unwrap();
        let reqs = hook.requests();
        assert_eq!(reqs.len(), cells.len(), "{resource}: {reqs:?}");
        for r in &reqs {
            assert_eq!(r["subResource"], sub, "{resource}");
            assert_eq!(r["resource"]["resource"], base, "{resource}");
            assert_eq!(r["resource"]["group"], group, "{resource}");
            assert_eq!(r["kind"]["kind"], kind, "{resource}");
            assert_eq!(r["operation"], "UPDATE", "{resource}");
            assert_eq!(r["userInfo"]["username"], "alice", "{resource}");
        }
        hook
    }

    fn deployment(name: &str) -> Value {
        json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"a": "b"}},
                "template": {"metadata": {"labels": {"a": "b"}},
                    "spec": {"containers": [{"name": "c", "image": "nginx"}]}}}})
    }

    async fn stored_deployment(c: &Cluster) -> Value {
        c.stored("/registry/apps/deployments/default/d").await
    }

    /// Built-in namespaced kinds share one status route: a policy on deployments/status
    /// (e.g. blocking a rogue controller from marking rollouts complete) is bypassed if any
    /// of its five write verbs skips admission.
    #[tokio::test]
    async fn webhook_on_namespaced_builtin_status_vetoes_every_write_verb() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apps/v1/namespaces/default/deployments",
            deployment("d"),
        )
        .await;
        let before = stored_deployment(&c).await["status"].clone();
        let cells = status_cells(
            "/apis/apps/v1/namespaces/default/deployments/d",
            "apps/v1",
            "Deployment",
            "d",
            json!({"replicas": 2}),
        );
        let hook =
            assert_every_write_is_vetoed(&c, "apps", "deployments/status", "Deployment", &cells)
                .await;
        assert_eq!(stored_deployment(&c).await["status"], before);
        let first = &hook.requests()[0];
        assert_eq!(first["namespace"], "default");
        assert_eq!(first["name"], "d");
        assert_eq!(first["object"]["status"]["replicas"], 2);
    }

    /// Core-group workloads take a separate route wrapper than apps/*, and cluster-scoped
    /// kinds another; each must reach admission too.
    #[tokio::test]
    async fn webhook_on_core_namespaced_and_cluster_scoped_status_vetoes_every_write_verb() {
        let c = Cluster::new().await;
        c.create(
            "/api/v1/namespaces/default/replicationcontrollers",
            json!({"apiVersion": "v1", "kind": "ReplicationController", "metadata": {"name": "rc"},
                "spec": {"replicas": 1, "selector": {"a": "b"},
                    "template": {"metadata": {"labels": {"a": "b"}},
                        "spec": {"containers": [{"name": "c", "image": "nginx"}]}}}}),
        )
        .await;
        let cells = status_cells(
            "/api/v1/namespaces/default/replicationcontrollers/rc",
            "v1",
            "ReplicationController",
            "rc",
            json!({"replicas": 2}),
        );
        assert_every_write_is_vetoed(
            &c,
            "",
            "replicationcontrollers/status",
            "ReplicationController",
            &cells,
        )
        .await;

        let c = Cluster::new().await;
        c.create(
            "/api/v1/nodes",
            json!({"apiVersion": "v1", "kind": "Node", "metadata": {"name": "n1"}}),
        )
        .await;
        let cells = status_cells(
            "/api/v1/nodes/n1",
            "v1",
            "Node",
            "n1",
            json!({"allocatable": {"cpu": "2"}}),
        );
        assert_every_write_is_vetoed(&c, "", "nodes/status", "Node", &cells).await;
    }

    /// Namespace status and finalize are bespoke handlers; the namespace controller drives
    /// both, and a policy on namespaces/finalize is the only way to gate namespace teardown.
    #[tokio::test]
    async fn webhook_on_namespace_status_and_finalize_vetoes_every_write() {
        let c = Cluster::new().await;
        c.create(
            "/api/v1/namespaces",
            json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns1"}}),
        )
        .await;
        let status = status_cells(
            "/api/v1/namespaces/ns1",
            "v1",
            "Namespace",
            "ns1",
            json!({"phase": "Active"}),
        );
        assert_every_write_is_vetoed(&c, "", "namespaces/status", "Namespace", &status).await;

        let c = Cluster::new().await;
        c.create(
            "/api/v1/namespaces",
            json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns1"}}),
        )
        .await;
        let finalize: Vec<Cell> = vec![(
            "finalize PUT".into(),
            "PUT",
            "/api/v1/namespaces/ns1/finalize".into(),
            "application/json",
            json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns1"},
                "spec": {"finalizers": []}}),
        )];
        assert_every_write_is_vetoed(&c, "", "namespaces/finalize", "Namespace", &finalize).await;
        assert_eq!(
            c.stored("/registry/namespaces/ns1").await["spec"]["finalizers"],
            json!(["kubernetes"]),
            "a denied finalize must leave the finalizer in place"
        );
    }

    fn crd(plural: &str, kind: &str, scope: &str) -> Value {
        json!({
            "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
            "metadata": {"name": format!("{plural}.example.com")},
            "spec": {
                "group": "example.com",
                "names": {"plural": plural, "singular": plural, "kind": kind,
                    "listKind": format!("{kind}List")},
                "scope": scope,
                "versions": [{
                    "name": "v1", "served": true, "storage": true,
                    "schema": {"openAPIV3Schema": {"type": "object",
                        "x-kubernetes-preserve-unknown-fields": true}},
                    "subresources": {"status": {}, "scale": {
                        "specReplicasPath": ".spec.replicas",
                        "statusReplicasPath": ".status.replicas"}}
                }]
            }
        })
    }

    /// CRs are admitted like built-ins: operators gate their own APIs with the same
    /// subresource rules, for namespaced and cluster-scoped CRDs and for both /status
    /// and /scale.
    #[tokio::test]
    async fn webhook_on_custom_resource_status_and_scale_vetoes_every_write() {
        for (plural, kind, scope, base) in [
            (
                "widgets",
                "Widget",
                "Namespaced",
                "/apis/example.com/v1/namespaces/default/widgets",
            ),
            (
                "gadgets",
                "Gadget",
                "Cluster",
                "/apis/example.com/v1/gadgets",
            ),
        ] {
            let c = Cluster::new().await;
            c.create(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
                crd(plural, kind, scope),
            )
            .await;
            c.create(
                base,
                json!({"apiVersion": "example.com/v1", "kind": kind,
                    "metadata": {"name": "w"}, "spec": {"replicas": 1}}),
            )
            .await;
            let obj = format!("{base}/w");
            let status = status_cells(&obj, "example.com/v1", kind, "w", json!({"replicas": 2}));
            assert_every_write_is_vetoed(
                &c,
                "example.com",
                &format!("{plural}/status"),
                kind,
                &status,
            )
            .await;

            let c = Cluster::new().await;
            c.create(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
                crd(plural, kind, scope),
            )
            .await;
            c.create(
                base,
                json!({"apiVersion": "example.com/v1", "kind": kind,
                    "metadata": {"name": "w"}, "spec": {"replicas": 1}}),
            )
            .await;
            let ns = if scope == "Namespaced" { "default" } else { "" };
            let scale = scale_cells(&obj, "w", ns, 3);
            let hook = assert_every_write_is_vetoed(
                &c,
                "example.com",
                &format!("{plural}/scale"),
                "Scale",
                &scale,
            )
            .await;
            let r = &hook.requests()[0];
            assert_eq!(
                r["kind"]["group"], "autoscaling",
                "{plural}: request kind is the Scale"
            );
            assert_eq!(r["object"]["spec"]["replicas"], 3);
            assert_eq!(r["oldObject"]["spec"]["replicas"], 1);
        }
    }

    /// The CRD's own /status route is a separate handler from every other kind's.
    #[tokio::test]
    async fn webhook_on_crd_status_vetoes_every_write_verb() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            crd("widgets", "Widget", "Namespaced"),
        )
        .await;
        let cells = status_cells(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/widgets.example.com",
            "apiextensions.k8s.io/v1",
            "CustomResourceDefinition",
            "widgets.example.com",
            json!({"storedVersions": ["v1"]}),
        );
        assert_every_write_is_vetoed(
            &c,
            "apiextensions.k8s.io",
            "customresourcedefinitions/status",
            "CustomResourceDefinition",
            &cells,
        )
        .await;
    }

    /// Scale is how HPAs and `kubectl scale` change replicas; a replica-cap policy on
    /// deployments/scale must hold for apps workloads and ReplicationControllers, PUT and PATCH.
    #[tokio::test]
    async fn webhook_and_vap_on_workload_scale_veto_and_mutate_replicas() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apps/v1/namespaces/default/deployments",
            deployment("d"),
        )
        .await;
        let cells = scale_cells(
            "/apis/apps/v1/namespaces/default/deployments/d",
            "d",
            "default",
            3,
        );
        let hook =
            assert_every_write_is_vetoed(&c, "apps", "deployments/scale", "Scale", &cells).await;
        let r = &hook.requests()[0];
        assert_eq!(r["kind"]["group"], "autoscaling");
        assert_eq!(r["kind"]["version"], "v1");
        assert_eq!(r["object"]["spec"]["replicas"], 3);
        assert_eq!(r["oldObject"]["spec"]["replicas"], 1);
        assert_eq!(stored_deployment(&c).await["spec"]["replicas"], 1);

        let c = Cluster::new().await;
        c.create(
            "/api/v1/namespaces/default/replicationcontrollers",
            json!({"apiVersion": "v1", "kind": "ReplicationController", "metadata": {"name": "rc"},
                "spec": {"replicas": 1, "selector": {"a": "b"},
                    "template": {"metadata": {"labels": {"a": "b"}},
                        "spec": {"containers": [{"name": "c", "image": "nginx"}]}}}}),
        )
        .await;
        let cells = scale_cells(
            "/api/v1/namespaces/default/replicationcontrollers/rc",
            "rc",
            "default",
            3,
        );
        assert_every_write_is_vetoed(&c, "", "replicationcontrollers/scale", "Scale", &cells).await;

        let c = Cluster::new().await;
        c.create(
            "/apis/apps/v1/namespaces/default/deployments",
            deployment("d"),
        )
        .await;
        register_vap(
            &c.store,
            "max-replicas",
            "apps",
            &["deployments/scale"],
            "object.spec.replicas <= 5",
            "at most 5 replicas",
        )
        .await;
        for (label, method, uri, ct, body) in scale_cells(
            "/apis/apps/v1/namespaces/default/deployments/d",
            "d",
            "default",
            8,
        ) {
            let (status, resp) = c.call(method, &uri, ct, body).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {resp}");
            assert!(
                resp["message"]
                    .as_str()
                    .unwrap()
                    .contains("at most 5 replicas"),
                "{label}: {resp}"
            );
        }
        assert_eq!(stored_deployment(&c).await["spec"]["replicas"], 1);

        let hook = spawn_hook(json_patch(json!([
            {"op": "replace", "path": "/spec/replicas", "value": 4}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "clamp",
            &hook.url,
            "apps",
            &["deployments/scale"],
            &["UPDATE"],
        )
        .await;
        for (label, method, uri, ct, body) in scale_cells(
            "/apis/apps/v1/namespaces/default/deployments/d",
            "d",
            "default",
            2,
        ) {
            let (status, resp) = c.call(method, &uri, ct, body).await;
            assert_eq!(status, StatusCode::OK, "{label}: {resp}");
            assert_eq!(
                stored_deployment(&c).await["spec"]["replicas"],
                4,
                "{label}: the scale webhook's replicas must be what is stored"
            );
            assert_eq!(resp["spec"]["replicas"], 4, "{label}: {resp}");
            let (status, _) = c
                .call(
                    "PUT",
                    "/apis/apps/v1/namespaces/default/deployments/d/scale",
                    "application/json",
                    json!({"spec": {"replicas": 1}}),
                )
                .await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    /// Status mutators may stamp status but, as upstream's per-kind status strategies do,
    /// cannot change spec; the same must hold for generic kinds, not just pods.
    #[tokio::test]
    async fn mutating_webhook_on_generic_status_keeps_status_and_drops_spec_edits() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apps/v1/namespaces/default/deployments",
            deployment("d"),
        )
        .await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "add", "path": "/status/replicas", "value": 7},
            {"op": "replace", "path": "/spec/replicas", "value": 99}
        ])))
        .await;
        register_webhook(
            &c.store,
            true,
            "stamp",
            &hook.url,
            "apps",
            &["deployments/status"],
            &["UPDATE"],
        )
        .await;
        for (label, method, uri, ct, body) in status_cells(
            "/apis/apps/v1/namespaces/default/deployments/d",
            "apps/v1",
            "Deployment",
            "d",
            json!({"replicas": 2}),
        ) {
            let (status, resp) = c.call(method, &uri, ct, body).await;
            assert_eq!(status, StatusCode::OK, "{label}: {resp}");
            let d = stored_deployment(&c).await;
            assert_eq!(d["status"]["replicas"], 7, "{label}: {d}");
            assert_eq!(d["spec"]["replicas"], 1, "{label}: {d}");
        }
    }

    /// CSR approval is its own subresource with its own webhook rules upstream; approving
    /// must be gated by a policy on certificatesigningrequests/approval.
    #[tokio::test]
    async fn webhook_on_csr_approval_vetoes_put_and_patch() {
        let c = Cluster::new().await;
        grant_signer_verb(&c.state, "alice", "approve", "example.com/signer");
        c.store
            .put(
                "/registry/certificates.k8s.io/certificatesigningrequests/c1",
                Bytes::from(
                    json!({"apiVersion": "certificates.k8s.io/v1",
                        "kind": "CertificateSigningRequest", "metadata": {"name": "c1"},
                        "spec": {"request": "AAAA", "signerName": "example.com/signer",
                            "usages": ["digital signature"]}})
                    .to_string(),
                ),
                None,
            )
            .await
            .unwrap();
        let uri = "/apis/certificates.k8s.io/v1/certificatesigningrequests/c1/approval";
        let cond = json!({"status": {"conditions": [
            {"type": "Approved", "status": "True", "reason": "ok"}]}});
        let cells: Vec<Cell> = vec![
            (
                "PUT".into(),
                "PUT",
                uri.into(),
                "application/json",
                cond.clone(),
            ),
            ("merge-PATCH".into(), "PATCH", uri.into(), MERGE, cond),
        ];
        assert_every_write_is_vetoed(
            &c,
            "certificates.k8s.io",
            "certificatesigningrequests/approval",
            "CertificateSigningRequest",
            &cells,
        )
        .await;
    }

    /// With no mutating admission configured the status write skips the status strategy, so
    /// the handler's own field restriction is the only guard. A /status writer (e.g. a
    /// kubelet-scoped client) must never be able to change spec or labels by sneaking them into
    /// the body, for built-ins and for custom resources alike.
    #[tokio::test]
    async fn status_write_without_mutators_never_persists_spec_or_label_edits() {
        let c = Cluster::new().await;
        c.create_pod("p").await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            crd("widgets", "Widget", "Namespaced"),
        )
        .await;
        let widgets = "/apis/example.com/v1/namespaces/default/widgets";
        c.create(
            widgets,
            json!({"apiVersion": "example.com/v1", "kind": "Widget",
                "metadata": {"name": "w", "labels": {"owner": "team-a"}},
                "spec": {"size": 1}}),
        )
        .await;

        let cases = [
            (
                "pod",
                "/api/v1/namespaces/default/pods/p/status".to_string(),
                json!({"apiVersion": "v1", "kind": "Pod",
                    "metadata": {"name": "p", "labels": {"owner": "mallory"}},
                    "spec": {"containers": [{"name": "app", "image": "evil"}]},
                    "status": {"phase": "Running"}}),
                json!({"metadata": {"labels": {"owner": "mallory"}},
                    "spec": {"containers": [{"name": "app", "image": "evil"}]},
                    "status": {"phase": "Running"}}),
            ),
            (
                "custom resource",
                format!("{widgets}/w/status"),
                json!({"apiVersion": "example.com/v1", "kind": "Widget",
                    "metadata": {"name": "w", "labels": {"owner": "mallory"}},
                    "spec": {"size": 99}, "status": {"replicas": 5}}),
                json!({"metadata": {"labels": {"owner": "mallory"}},
                    "spec": {"size": 99}, "status": {"replicas": 5}}),
            ),
        ];
        for (what, uri, put_body, patch_body) in cases {
            for (verb, ct, body) in [
                ("PUT", "application/json", put_body),
                ("merge-PATCH", MERGE, patch_body),
            ] {
                let method = if verb == "PUT" { "PUT" } else { "PATCH" };
                let (status, resp) = c.call(method, &uri, ct, body).await;
                assert_eq!(status, StatusCode::OK, "{what} {verb}: {resp}");
                let stored = if what == "pod" {
                    c.stored_pod("p").await
                } else {
                    c.stored("/registry/cr/example.com/widgets/default/w").await
                };
                if what == "pod" {
                    assert_eq!(stored["status"]["phase"], "Running", "{what} {verb}");
                    assert_eq!(
                        stored["spec"]["containers"][0]["image"], "nginx",
                        "{what} {verb}: a /status write must not change spec: {stored}"
                    );
                    assert!(
                        stored["metadata"]["labels"].is_null(),
                        "{what} {verb}: a /status write must not set labels: {stored}"
                    );
                } else {
                    assert_eq!(stored["status"]["replicas"], 5, "{what} {verb}");
                    assert_eq!(
                        stored["spec"]["size"], 1,
                        "{what} {verb}: a /status write must not change spec: {stored}"
                    );
                    assert_eq!(
                        stored["metadata"]["labels"]["owner"], "team-a",
                        "{what} {verb}: a /status write must not change labels: {stored}"
                    );
                }
            }
        }
    }

    /// A CRD served at two versions where the storage version is not the one the client uses.
    fn two_version_crd() -> Value {
        let mut c = crd("widgets", "Widget", "Namespaced");
        let schema = c["spec"]["versions"][0]["schema"].clone();
        c["spec"]["versions"] = json!([
            {"name": "v1", "served": true, "storage": true, "schema": schema.clone(),
                "subresources": {"status": {}}},
            {"name": "v2", "served": true, "storage": false, "schema": schema,
                "subresources": {"status": {}}}
        ]);
        c
    }

    /// Webhooks dispatch on `request.kind`/`request.resource` versions. When a client writes a
    /// CR through a non-storage version, upstream sends that version (the version the rule
    /// matched, which for an exact match is the request's own): reporting the storage version
    /// would make a v2-only policy see an object shape the client never sent.
    #[tokio::test]
    async fn webhook_for_cr_written_at_non_storage_version_sees_the_requested_version() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            two_version_crd(),
        )
        .await;
        let widgets = "/apis/example.com/v2/namespaces/default/widgets";
        c.create(
            widgets,
            json!({"apiVersion": "example.com/v2", "kind": "Widget",
                "metadata": {"name": "w"}, "spec": {"size": 1}}),
        )
        .await;
        let hook = spawn_hook(|_| json!({"allowed": true})).await;
        register_webhook(
            &c.store,
            false,
            "seen",
            &hook.url,
            "example.com",
            &["widgets", "widgets/status"],
            &["CREATE", "UPDATE"],
        )
        .await;

        let (status, resp) = c
            .call(
                "POST",
                widgets,
                "application/json",
                json!({"apiVersion": "example.com/v2", "kind": "Widget",
                    "metadata": {"name": "w2"}, "spec": {"size": 1}}),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");
        let (status, resp) = c
            .call(
                "PUT",
                &format!("{widgets}/w/status"),
                "application/json",
                json!({"apiVersion": "example.com/v2", "kind": "Widget",
                    "metadata": {"name": "w"}, "status": {"replicas": 2}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let (status, resp) = c
            .call(
                "PATCH",
                &format!("{widgets}/w/status"),
                MERGE,
                json!({"status": {"replicas": 3}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");

        let reqs = hook.requests();
        assert_eq!(reqs.len(), 3, "{reqs:?}");
        for r in &reqs {
            assert_eq!(r["kind"]["version"], "v2", "kind version: {r}");
            assert_eq!(r["kind"]["kind"], "Widget", "{r}");
            assert_eq!(r["resource"]["version"], "v2", "resource version: {r}");
        }
    }

    /// Serves a ConversionReview endpoint for a CRD whose v1 shape is `spec.size` and whose v2
    /// shape is `spec.count`, so a webhook that sees the wrong version sees the wrong field.
    async fn spawn_size_count_converter() -> String {
        let app = Router::new().route(
            "/convert",
            axum::routing::post(|axum::Json(review): axum::Json<Value>| async move {
                let desired = review["request"]["desiredAPIVersion"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let objects: Vec<Value> = review["request"]["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| {
                        let mut o = o.clone();
                        o["apiVersion"] = json!(desired);
                        let (from, to) = if desired.ends_with("/v1") {
                            ("count", "size")
                        } else {
                            ("size", "count")
                        };
                        if let Some(v) = o["spec"].as_object_mut().and_then(|s| s.remove(from)) {
                            o["spec"][to] = v;
                        }
                        o
                    })
                    .collect();
                axum::Json(json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": review["request"]["uid"],
                        "result": {"status": "Success"},
                        "convertedObjects": objects,
                    }
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/convert")
    }

    /// Widgets served at v1 (storage) and v2, both with /status and /scale. With a
    /// `converter`, the CRD converts through that webhook; without, it uses the `None`
    /// strategy (apiVersion rewrite only).
    fn widgets_v1_v2_crd(converter: Option<&str>) -> Value {
        let mut c = crd("widgets", "Widget", "Namespaced");
        let version = |name: &str, storage: bool| {
            let mut v = c["spec"]["versions"][0].clone();
            v["name"] = json!(name);
            v["storage"] = json!(storage);
            v
        };
        c["spec"]["versions"] = json!([version("v1", true), version("v2", false)]);
        if let Some(url) = converter {
            c["spec"]["conversion"] = json!({"strategy": "Webhook", "webhook": {
                "conversionReviewVersions": ["v1"], "clientConfig": {"url": url}}});
        }
        c
    }

    const WIDGETS: &str = "/apis/example.com/{v}/namespaces/default/widgets";

    fn widgets_at(version: &str) -> String {
        WIDGETS.replace("{v}", version)
    }

    fn widget_at(version: &str, spec: Value) -> Value {
        json!({"apiVersion": format!("example.com/{version}"), "kind": "Widget",
            "metadata": {"name": "w"}, "spec": spec})
    }

    /// A webhook registered for v1 of a resource must also guard v2 requests (the default
    /// `matchPolicy: Equivalent`): otherwise writing through the other served version is a
    /// trivial bypass of any admission policy. It must be shown the object converted to the
    /// version its rule names, with the client's original recorded in `requestKind` etc.
    #[tokio::test]
    async fn equivalent_webhook_for_v1_is_called_for_a_v2_request_with_the_object_converted_to_v1()
    {
        let c = Cluster::new().await;
        let url = spawn_size_count_converter().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            widgets_v1_v2_crd(Some(&url)),
        )
        .await;
        let hook = spawn_hook(|_| json!({"allowed": true})).await;
        register_webhook_for(
            &c.store,
            false,
            "v1only",
            &hook.url,
            "example.com",
            "v1",
            None,
            &["widgets"],
            &["CREATE"],
        )
        .await;

        let (status, resp) = c
            .call(
                "POST",
                &widgets_at("v2"),
                "application/json",
                widget_at("v2", json!({"count": 7})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");

        let reqs = hook.requests();
        assert_eq!(
            reqs.len(),
            1,
            "the v1 rule must match a v2 request: {reqs:?}"
        );
        let r = &reqs[0];
        assert_eq!(r["kind"]["version"], "v1", "{r}");
        assert_eq!(r["resource"]["version"], "v1", "{r}");
        assert_eq!(r["requestKind"]["version"], "v2", "{r}");
        assert_eq!(r["requestKind"]["kind"], "Widget", "{r}");
        assert_eq!(r["requestResource"]["version"], "v2", "{r}");
        assert_eq!(r["requestResource"]["resource"], "widgets", "{r}");
        assert_eq!(r["object"]["apiVersion"], "example.com/v1", "{r}");
        assert_eq!(
            r["object"]["spec"],
            json!({"size": 7}),
            "the webhook must see the v1 shape, not the v2 one the client sent: {r}"
        );
        assert_eq!(
            resp["apiVersion"], "example.com/v2",
            "client keeps its version"
        );
        assert_eq!(resp["spec"], json!({"count": 7}));
    }

    /// `matchPolicy: Exact` is the opt-out: a v1-only webhook must not see v2 requests.
    #[tokio::test]
    async fn exact_policy_webhook_for_v1_is_not_called_for_a_v2_request() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            widgets_v1_v2_crd(None),
        )
        .await;
        let hook = spawn_hook(deny("v1 only")).await;
        register_webhook_for(
            &c.store,
            false,
            "exact",
            &hook.url,
            "example.com",
            "v1",
            Some("Exact"),
            &["widgets"],
            &["CREATE"],
        )
        .await;

        let (status, resp) = c
            .call(
                "POST",
                &widgets_at("v2"),
                "application/json",
                widget_at("v2", json!({})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "Exact must not match v2: {resp}"
        );
        assert!(hook.requests().is_empty());

        let (status, _) = c
            .call(
                "POST",
                &widgets_at("v1"),
                "application/json",
                json!({"apiVersion": "example.com/v1", "kind": "Widget",
                    "metadata": {"name": "w1"}, "spec": {}}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Exact still matches its own version"
        );
        assert_eq!(hook.requests().len(), 1);
    }

    /// A mutating webhook matched through v1 patches the v1-shaped object; the patch must
    /// reach the client and the store in the right shape (v2 response, v1 storage), or an
    /// Equivalent mutation silently corrupts objects written at the other version.
    #[tokio::test]
    async fn equivalent_mutating_patch_is_converted_back_and_persisted() {
        let c = Cluster::new().await;
        let url = spawn_size_count_converter().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            widgets_v1_v2_crd(Some(&url)),
        )
        .await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "replace", "path": "/spec/size", "value": 9},
            {"op": "add", "path": "/metadata/annotations", "value": {"mutated": "by-v1"}}
        ])))
        .await;
        register_webhook_for(
            &c.store,
            true,
            "mutate",
            &hook.url,
            "example.com",
            "v1",
            None,
            &["widgets"],
            &["CREATE"],
        )
        .await;

        let (status, resp) = c
            .call(
                "POST",
                &widgets_at("v2"),
                "application/json",
                widget_at("v2", json!({"count": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");
        assert_eq!(resp["apiVersion"], "example.com/v2", "{resp}");
        assert_eq!(
            resp["spec"],
            json!({"count": 9}),
            "patched size must come back as count: {resp}"
        );
        assert_eq!(resp["metadata"]["annotations"]["mutated"], "by-v1");

        let stored = c.stored("/registry/cr/example.com/widgets/default/w").await;
        assert_eq!(stored["apiVersion"], "example.com/v1", "{stored}");
        assert_eq!(stored["spec"], json!({"size": 9}), "{stored}");
        assert_eq!(stored["metadata"]["annotations"]["mutated"], "by-v1");
    }

    /// With the `None` conversion strategy the "conversion" is an apiVersion rewrite; the
    /// Equivalent webhook must still see (and answer in) the version its rule names.
    #[tokio::test]
    async fn equivalent_webhook_on_a_none_strategy_crd_sees_the_rewritten_api_version() {
        let c = Cluster::new().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            widgets_v1_v2_crd(None),
        )
        .await;
        let hook = spawn_hook(json_patch(json!([
            {"op": "add", "path": "/spec/seen", "value": true}
        ])))
        .await;
        register_webhook_for(
            &c.store,
            true,
            "mutate",
            &hook.url,
            "example.com",
            "v1",
            None,
            &["widgets"],
            &["CREATE"],
        )
        .await;
        let (status, resp) = c
            .call(
                "POST",
                &widgets_at("v2"),
                "application/json",
                widget_at("v2", json!({"size": 1})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{resp}");
        assert_eq!(hook.requests()[0]["object"]["apiVersion"], "example.com/v1");
        assert_eq!(resp["apiVersion"], "example.com/v2");
        assert_eq!(resp["spec"]["seen"], true);
    }

    /// A DELETE is stored at the storage version, but `kind` names the version the client
    /// addressed; the webhook must see an object of that same version, or a v2 policy reads
    /// a v1-shaped body labelled v2.
    #[tokio::test]
    async fn delete_at_a_non_storage_version_shows_the_webhook_a_body_matching_its_kind() {
        let c = Cluster::new().await;
        let url = spawn_size_count_converter().await;
        c.create(
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            widgets_v1_v2_crd(Some(&url)),
        )
        .await;
        c.create(&widgets_at("v1"), widget_at("v1", json!({"size": 4})))
            .await;
        let hook = spawn_hook(|_| json!({"allowed": true})).await;
        register_webhook_for(
            &c.store,
            false,
            "v2delete",
            &hook.url,
            "example.com",
            "v2",
            Some("Exact"),
            &["widgets"],
            &["DELETE"],
        )
        .await;

        let (status, resp) = c
            .call(
                "DELETE",
                &format!("{}/w", widgets_at("v2")),
                "application/json",
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");

        let reqs = hook.requests();
        assert_eq!(reqs.len(), 1, "{reqs:?}");
        let r = &reqs[0];
        assert_eq!(r["kind"]["version"], "v2", "{r}");
        assert_eq!(r["oldObject"]["apiVersion"], "example.com/v2", "{r}");
        assert_eq!(
            r["oldObject"]["spec"],
            json!({"count": 4}),
            "oldObject must be converted to the version kind names: {r}"
        );
    }

    /// Every cell of {mutating, validating} x {Exact, Equivalent} x {request at the rule's
    /// version, at an equivalent version} x {main resource, /status, /scale} x {CREATE, UPDATE,
    /// DELETE} (subresources only have UPDATE) must be called exactly when upstream calls it,
    /// and the review must name both the matched and the original version.
    #[tokio::test]
    async fn match_policy_matrix_calls_webhooks_exactly_when_upstream_does() {
        let mut cells = 0;
        for mutating in [false, true] {
            for policy in [Some("Exact"), Some("Equivalent"), None] {
                for request_version in ["v1", "v2"] {
                    for (resource, op) in [
                        ("widgets", "CREATE"),
                        ("widgets", "UPDATE"),
                        ("widgets", "DELETE"),
                        ("widgets/status", "UPDATE"),
                        ("widgets/scale", "UPDATE"),
                    ] {
                        // u7s never runs mutating webhooks on DELETE (upstream does); tracked separately.
                        if mutating && op == "DELETE" {
                            continue;
                        }
                        cells += 1;
                        let label = format!(
                            "mutating={mutating} policy={policy:?} request={request_version} \
                             {resource} {op}"
                        );
                        let c = Cluster::new().await;
                        let url = spawn_size_count_converter().await;
                        c.create(
                            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
                            widgets_v1_v2_crd(Some(&url)),
                        )
                        .await;
                        c.create(&widgets_at("v1"), widget_at("v1", json!({"size": 1})))
                            .await;
                        let hook = spawn_hook(|_| json!({"allowed": true})).await;
                        register_webhook_for(
                            &c.store,
                            mutating,
                            "matrix",
                            &hook.url,
                            "example.com",
                            "v1",
                            policy,
                            &[resource],
                            &[op],
                        )
                        .await;

                        let base = widgets_at(request_version);
                        let spec = if request_version == "v1" {
                            json!({"size": 2})
                        } else {
                            json!({"count": 2})
                        };
                        let (status, resp) = match (resource, op) {
                            ("widgets", "CREATE") => {
                                let mut body = widget_at(request_version, spec);
                                body["metadata"]["name"] = json!("w-new");
                                c.call("POST", &base, "application/json", body).await
                            }
                            ("widgets", "UPDATE") => {
                                c.call(
                                    "PUT",
                                    &format!("{base}/w"),
                                    "application/json",
                                    widget_at(request_version, spec),
                                )
                                .await
                            }
                            ("widgets", "DELETE") => {
                                c.call(
                                    "DELETE",
                                    &format!("{base}/w"),
                                    "application/json",
                                    json!({}),
                                )
                                .await
                            }
                            ("widgets/status", _) => {
                                c.call(
                                    "PUT",
                                    &format!("{base}/w/status"),
                                    "application/json",
                                    json!({"apiVersion": format!("example.com/{request_version}"),
                                        "kind": "Widget", "metadata": {"name": "w"},
                                        "status": {"replicas": 2}}),
                                )
                                .await
                            }
                            _ => {
                                c.call(
                                    "PUT",
                                    &format!("{base}/w/scale"),
                                    "application/json",
                                    json!({"apiVersion": "autoscaling/v1", "kind": "Scale",
                                        "metadata": {"name": "w", "namespace": "default"},
                                        "spec": {"replicas": 3}}),
                                )
                                .await
                            }
                        };
                        assert!(status.is_success(), "{label}: {status} {resp}");

                        let should_call = request_version == "v1" || policy != Some("Exact");
                        let reqs = hook.requests();
                        assert_eq!(
                            reqs.len(),
                            usize::from(should_call),
                            "{label}: webhook call count: {reqs:?}"
                        );
                        let Some(r) = reqs.first() else { continue };
                        let (base_resource, sub) = match resource.split_once('/') {
                            Some((b, s)) => (b, Some(s)),
                            None => (resource, None),
                        };
                        assert_eq!(r["operation"], op, "{label}");
                        assert_eq!(r["resource"]["version"], "v1", "{label}: {r}");
                        assert_eq!(r["resource"]["resource"], base_resource, "{label}");
                        assert_eq!(
                            r["requestResource"]["version"], request_version,
                            "{label}: {r}"
                        );
                        assert_eq!(r["requestResource"]["resource"], base_resource, "{label}");
                        assert_eq!(
                            r["subResource"],
                            sub.map_or(Value::Null, |s| json!(s)),
                            "{label}"
                        );
                        assert_eq!(
                            r["requestSubResource"],
                            sub.map_or(Value::Null, |s| json!(s)),
                            "{label}"
                        );
                        if sub == Some("scale") {
                            assert_eq!(r["kind"]["group"], "autoscaling", "{label}: {r}");
                            assert_eq!(r["requestKind"]["group"], "autoscaling", "{label}: {r}");
                        } else {
                            assert_eq!(r["kind"]["version"], "v1", "{label}: {r}");
                            assert_eq!(r["kind"]["kind"], "Widget", "{label}");
                            assert_eq!(
                                r["requestKind"]["version"], request_version,
                                "{label}: {r}"
                            );
                        }
                        if op != "DELETE" && sub.is_none() {
                            assert_eq!(r["object"]["apiVersion"], "example.com/v1", "{label}");
                            assert_eq!(r["object"]["spec"], json!({"size": 2}), "{label}: {r}");
                        }
                    }
                }
            }
        }
        assert_eq!(
            cells,
            (2 * 5 - 1) * 3 * 2,
            "every matrix cell must have run"
        );
    }
}
