//! LIST and WATCH must select the same objects through every handler that serves a kind, and
//! both must reject a label the kind does not declare. A watch that quietly ignores a selector
//! LIST honors (or vice versa) lets an informer cache objects its owner never asked for.

mod tests {
    use std::sync::Arc;

    use axum::extract::{Path, Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Extension;
    use serde_json::{json, Value};
    use u7s_store::{SqliteStore, Store};

    use crate::handlers::generic::CollectionQuery;
    use crate::handlers::test_support::make_state_with_store;
    use crate::state::AppState;
    use crate::status::StatusError;

    #[derive(Clone, Copy)]
    enum Route {
        CorePodsAllNamespaces,
        PodsInNamespace,
        Namespaces,
        Csr,
        Cluster(&'static str),
        Namespaced(&'static str),
    }

    struct Case {
        label: &'static str,
        route: Route,
        group: &'static str,
        plural: &'static str,
        selector: &'static str,
        matching: Value,
        other: Value,
    }

    fn user() -> Extension<crate::auth::UserInfo> {
        Extension(crate::auth::UserInfo {
            username: "tester".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    fn query(selector: &str, watch: bool) -> Query<CollectionQuery> {
        Query(CollectionQuery {
            watch: watch.then_some(true),
            resource_version: None,
            label_selector: None,
            field_selector: Some(selector.to_string()),
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: watch.then_some(1),
        })
    }

    fn named(name: &str, ns: Option<&str>, mut body: Value) -> Value {
        body["metadata"] = json!({"name": name});
        if let Some(ns) = ns {
            body["metadata"]["namespace"] = json!(ns);
        }
        body
    }

    async fn call(
        state: &AppState<SqliteStore>,
        case: &Case,
        selector: &str,
        watch: bool,
    ) -> Result<Response, StatusError> {
        let st = State(state.clone());
        let q = query(selector, watch);
        let group = case.group.to_string();
        match case.route {
            Route::CorePodsAllNamespaces => crate::handlers::core::core_list_resource(
                st,
                Path("pods".to_string()),
                q,
                HeaderMap::new(),
                user(),
            )
            .await
            .map(IntoResponse::into_response),
            Route::PodsInNamespace => {
                let pods_query = crate::handlers::pods::CollectionQuery {
                    watch: q.0.watch,
                    resource_version: None,
                    label_selector: None,
                    field_selector: q.0.field_selector,
                    send_initial_events: None,
                    allow_watch_bookmarks: None,
                    timeout_seconds: q.0.timeout_seconds,
                };
                crate::handlers::pods::list_pods(
                    st,
                    Path(("ns1".to_string(),)),
                    Query(pods_query),
                    HeaderMap::new(),
                    user(),
                )
                .await
            }
            Route::Namespaces => crate::handlers::namespaces::list_namespaces(st, q, user()).await,
            Route::Csr => crate::handlers::csr::list_csr(st, q, user(), HeaderMap::new()).await,
            Route::Cluster(version) => {
                crate::handlers::resource::list_resource(
                    st,
                    Path((group, version.to_string(), case.plural.to_string())),
                    q,
                    HeaderMap::new(),
                    user(),
                )
                .await
            }
            Route::Namespaced(version) => {
                crate::handlers::resource::list_namespaced_resource(
                    st,
                    Path((
                        group,
                        version.to_string(),
                        "ns1".to_string(),
                        case.plural.to_string(),
                    )),
                    q,
                    HeaderMap::new(),
                    user(),
                )
                .await
            }
        }
    }

    async fn names(resp: Response, watch: bool) -> Vec<String> {
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("body must finish within the watch timeout")
        .expect("body must be readable");
        let text = String::from_utf8(bytes.to_vec()).expect("utf8");
        let name_of = |o: &Value| o["metadata"]["name"].as_str().unwrap_or("").to_string();
        let mut out: Vec<String> = if watch {
            text.lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|e| e["type"] == "ADDED")
                .map(|e| name_of(&e["object"]))
                .collect()
        } else {
            serde_json::from_str::<Value>(&text).expect("list body is JSON")["items"]
                .as_array()
                .expect("items array")
                .iter()
                .map(name_of)
                .collect()
        };
        out.sort();
        out
    }

    fn cases() -> Vec<Case> {
        let pod = |phase: &str, restart: &str| {
            json!({"apiVersion": "v1", "kind": "Pod",
               "spec": {"nodeName": "n1", "restartPolicy": restart, "containers": []},
               "status": {"phase": phase}})
        };
        let case = |label, route, group, plural, selector, matching, other| Case {
            label,
            route,
            group,
            plural,
            selector,
            matching,
            other,
        };
        vec![
            case(
                "pods (cluster-wide)",
                Route::CorePodsAllNamespaces,
                "",
                "pods",
                "status.phase=Running",
                pod("Running", "Always"),
                pod("Pending", "Always"),
            ),
            case(
                "pods (namespaced)",
                Route::PodsInNamespace,
                "",
                "pods",
                "spec.restartPolicy=Never",
                pod("Running", "Never"),
                pod("Running", "Always"),
            ),
            case(
                "events",
                Route::Namespaced("v1"),
                "",
                "events",
                "involvedObject.name=web,reason!=Killing",
                json!({"involvedObject": {"name": "web"}, "reason": "Started"}),
                json!({"involvedObject": {"name": "web"}, "reason": "Killing"}),
            ),
            case(
                "events.k8s.io events stored in the events.k8s.io shape",
                Route::Namespaced("v1"),
                "events.k8s.io",
                "events",
                "regarding.name=web",
                json!({"regarding": {"name": "web"}}),
                json!({"regarding": {"name": "db"}}),
            ),
            case(
                "namespaces (status.phase filled in by defaulting)",
                Route::Namespaces,
                "",
                "namespaces",
                "status.phase=Active",
                json!({"spec": {}}),
                json!({"status": {"phase": "Terminating"}}),
            ),
            case(
                "nodes",
                Route::Cluster("v1"),
                "",
                "nodes",
                "spec.unschedulable=true",
                json!({"spec": {"unschedulable": true}}),
                json!({"spec": {}}),
            ),
            case(
                "secrets",
                Route::Namespaced("v1"),
                "",
                "secrets",
                "type=kubernetes.io/tls",
                json!({"type": "kubernetes.io/tls"}),
                json!({"type": "Opaque"}),
            ),
            case(
                "services",
                Route::Namespaced("v1"),
                "",
                "services",
                "spec.clusterIP=10.0.0.1",
                json!({"spec": {"clusterIP": "10.0.0.1"}}),
                json!({"spec": {"clusterIP": "10.0.0.2"}}),
            ),
            case(
                "jobs",
                Route::Namespaced("v1"),
                "batch",
                "jobs",
                "status.successful=1",
                json!({"status": {"succeeded": 1}}),
                json!({"status": {}}),
            ),
            case(
                "replicationcontrollers",
                Route::Namespaced("v1"),
                "",
                "replicationcontrollers",
                "status.replicas=2",
                json!({"status": {"replicas": 2}}),
                json!({"status": {"replicas": 3}}),
            ),
            case(
                "certificatesigningrequests",
                Route::Csr,
                "certificates.k8s.io",
                "certificatesigningrequests",
                "spec.signerName=example.com/a",
                json!({"spec": {"signerName": "example.com/a"}}),
                json!({"spec": {"signerName": "example.com/b"}}),
            ),
            case(
                "clustertrustbundles",
                Route::Cluster("v1"),
                "certificates.k8s.io",
                "clustertrustbundles",
                "spec.signerName=example.com/a",
                json!({"spec": {"signerName": "example.com/a"}}),
                json!({"spec": {"signerName": "example.com/b"}}),
            ),
            case(
                "podcertificaterequests",
                Route::Namespaced("v1"),
                "certificates.k8s.io",
                "podcertificaterequests",
                "spec.podName=p1",
                json!({"spec": {"podName": "p1"}}),
                json!({"spec": {"podName": "p2"}}),
            ),
            case(
                "resourceslices",
                Route::Cluster("v1"),
                "resource.k8s.io",
                "resourceslices",
                "spec.driver=d1",
                json!({"spec": {"driver": "d1"}}),
                json!({"spec": {"driver": "d2"}}),
            ),
            case(
                "configmaps (metadata-only default table)",
                Route::Namespaced("v1"),
                "",
                "configmaps",
                "metadata.name=match",
                json!({}),
                json!({}),
            ),
        ]
    }

    async fn seeded_state(case: &Case) -> AppState<SqliteStore> {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let ns = matches!(
            case.route,
            Route::CorePodsAllNamespaces | Route::PodsInNamespace | Route::Namespaced(_)
        )
        .then_some("ns1");
        if matches!(case.route, Route::PodsInNamespace) {
            let ns_obj =
                json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns1"}});
            store
                .put(
                    &crate::keys::cluster_object_key("namespaces", "ns1"),
                    bytes::Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                    Some(0),
                )
                .await
                .expect("seed namespace");
        }
        for (name, body) in [("match", &case.matching), ("other", &case.other)] {
            let obj = named(name, ns, body.clone());
            store
                .put(
                    &crate::keys::group_object_key(case.group, case.plural, ns, name),
                    bytes::Bytes::from(serde_json::to_vec(&obj).unwrap()),
                    Some(0),
                )
                .await
                .unwrap_or_else(|e| panic!("{}: seed {name}: {e:?}", case.label));
        }
        make_state_with_store(store)
    }

    #[tokio::test]
    async fn list_and_watch_select_the_same_objects_for_every_kind() {
        for case in cases() {
            let state = seeded_state(&case).await;
            // Test states carry the always-present namespaces; they are not under test here.
            let without_bootstrap = |mut v: Vec<String>| {
                v.retain(|n| {
                    !["default", "kube-system", "kube-public", "kube-node-lease"]
                        .contains(&n.as_str())
                });
                v
            };
            let listed = names(
                call(&state, &case, case.selector, false)
                    .await
                    .unwrap_or_else(|e| panic!("{}: LIST failed: {}", case.label, e.1.message)),
                false,
            )
            .await;
            let listed = without_bootstrap(listed);
            let watched = names(
                call(&state, &case, case.selector, true)
                    .await
                    .unwrap_or_else(|e| panic!("{}: WATCH failed: {}", case.label, e.1.message)),
                true,
            )
            .await;
            let watched = without_bootstrap(watched);
            assert_eq!(
                listed,
                vec!["match".to_string()],
                "{}: LIST with {:?} must return exactly the matching object",
                case.label,
                case.selector
            );
            assert_eq!(
                watched, listed,
                "{}: WATCH replay with {:?} must deliver exactly what LIST returns; a watch that \
             ignores the selector makes informers cache objects their controller never selected",
                case.label, case.selector
            );
        }
    }

    #[tokio::test]
    async fn unsupported_label_is_400_on_list_and_watch_for_every_kind() {
        for case in cases() {
            let state = seeded_state(&case).await;
            for watch in [false, true] {
                let err = call(&state, &case, "bogus.field=x", watch)
                    .await
                    .err()
                    .unwrap_or_else(|| {
                        panic!(
                            "{} (watch={watch}): an undeclared label must be rejected",
                            case.label
                        )
                    });
                assert_eq!(
                    err.0,
                    StatusCode::BAD_REQUEST,
                    "{} (watch={watch}): {}",
                    case.label,
                    err.1.message
                );
                assert!(
                    err.1.message.contains("bogus.field"),
                    "{}: message must name the offending label, got {:?}",
                    case.label,
                    err.1.message
                );
            }
        }
    }
}
