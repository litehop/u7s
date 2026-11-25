//! Every GET/LIST/WATCH route that serves an API object must honor a metadata-only Accept.
//!
//! Upstream's GC and namespace controller run metadata informers against every resource type;
//! a handler that skips the shared negotiator answers 200 with full objects, which those
//! informers cannot decode, so deletion stalls with no error on the server side. The probes
//! below go through the real router, and the route table is read from `build_routes`' source so
//! a handler added there without a probe fails this test instead of silently bypassing the
//! negotiator.

use std::collections::BTreeSet;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use serde_json::{json, Value};
use tower_service::Service as _;

use super::test_support::make_state_with_store;

const OBJECT_ACCEPT: &str = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1";
const LIST_ACCEPT: &str = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
const BAD_GV_ACCEPT: &str = "application/json;as=PartialObjectMetadata;g=wrong.example.io;v=v1";

/// Route handlers that do not return API objects, so metadata negotiation does not apply.
const NON_OBJECT_MODULES: &[&str] = &["health", "metrics", "oidc", "discovery", "proxy"];

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Object,
    Collection,
}
use Shape::{Collection, Object};

/// (handler, shape, uri). One handler may be reached through several routes or backends.
const PROBES: &[(&str, Shape, &str)] = &[
    (
        "namespaces::list_namespaces",
        Collection,
        "/api/v1/namespaces",
    ),
    (
        "namespaces::get_namespace",
        Object,
        "/api/v1/namespaces/pomns",
    ),
    (
        "namespaces::get_namespace_status",
        Object,
        "/api/v1/namespaces/pomns/status",
    ),
    (
        "pods::list_pods",
        Collection,
        "/api/v1/namespaces/pomns/pods",
    ),
    ("pods::get_pod", Object, "/api/v1/namespaces/pomns/pods/p1"),
    (
        "pods::get_pod_status",
        Object,
        "/api/v1/namespaces/pomns/pods/p1/status",
    ),
    (
        "pods::get_pod_resize",
        Object,
        "/api/v1/namespaces/pomns/pods/p1/resize",
    ),
    (
        "pods::get_ephemeral_containers",
        Object,
        "/api/v1/namespaces/pomns/pods/p1/ephemeralcontainers",
    ),
    ("core::core_list_resource", Collection, "/api/v1/nodes"),
    ("core::core_get_resource", Object, "/api/v1/nodes/n1"),
    (
        "core::core_get_resource_status",
        Object,
        "/api/v1/nodes/n1/status",
    ),
    (
        "core::core_list_namespaced_resource",
        Collection,
        "/api/v1/namespaces/pomns/configmaps",
    ),
    (
        "core::core_get_namespaced_resource",
        Object,
        "/api/v1/namespaces/pomns/configmaps/cm1",
    ),
    (
        "core::core_get_namespaced_resource_status",
        Object,
        "/api/v1/namespaces/pomns/services/svc1/status",
    ),
    (
        "scale::get_rc_scale",
        Object,
        "/api/v1/namespaces/pomns/replicationcontrollers/rc1/scale",
    ),
    (
        "scale::get_scale",
        Object,
        "/apis/apps/v1/namespaces/pomns/deployments/d1/scale",
    ),
    (
        "crd::list_crds",
        Collection,
        "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
    ),
    (
        "crd::get_crd",
        Object,
        "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/gadgets.example.io",
    ),
    (
        "crd::get_crd_status",
        Object,
        "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/gadgets.example.io/status",
    ),
    (
        "csr::list_csr",
        Collection,
        "/apis/certificates.k8s.io/v1/certificatesigningrequests",
    ),
    (
        "csr::get_csr",
        Object,
        "/apis/certificates.k8s.io/v1/certificatesigningrequests/csr1",
    ),
    (
        "csr::get_csr",
        Object,
        "/apis/certificates.k8s.io/v1/certificatesigningrequests/csr1/approval",
    ),
    (
        "certificates::list_cluster_trust_bundles",
        Collection,
        "/apis/certificates.k8s.io/v1/clustertrustbundles",
    ),
    (
        "resource::list_resource",
        Collection,
        "/apis/storage.k8s.io/v1/csinodes",
    ),
    (
        "resource::list_resource",
        Collection,
        "/apis/example.io/v1/gadgets",
    ),
    (
        "resource::get_resource",
        Object,
        "/apis/storage.k8s.io/v1/csinodes/worker-1",
    ),
    (
        "resource::get_resource",
        Object,
        "/apis/example.io/v1/gadgets/g1",
    ),
    (
        "resource::list_namespaced_resource",
        Collection,
        "/apis/apps/v1/namespaces/pomns/deployments",
    ),
    (
        "resource::list_namespaced_resource",
        Collection,
        "/apis/example.io/v1/namespaces/pomns/widgets",
    ),
    (
        "resource::get_namespaced_resource",
        Object,
        "/apis/apps/v1/namespaces/pomns/deployments/d1",
    ),
    (
        "resource::get_namespaced_resource",
        Object,
        "/apis/example.io/v1/namespaces/pomns/widgets/w1",
    ),
    (
        "cr::get_cr_status",
        Object,
        "/apis/example.io/v1/gadgets/g1/status",
    ),
    (
        "cr::get_cr_scale",
        Object,
        "/apis/example.io/v1/gadgets/g1/scale",
    ),
    (
        "cr::get_cr_namespaced_scale",
        Object,
        "/apis/example.io/v1/namespaces/pomns/widgets/w1/scale",
    ),
    (
        "status::get_namespaced_resource_status",
        Object,
        "/apis/apps/v1/namespaces/pomns/deployments/d1/status",
    ),
];

/// Handler paths (`module::function`) of every GET registered in `build_routes`.
fn registered_get_handlers() -> BTreeSet<String> {
    let src = include_str!("../lib.rs");
    let start = src.find("fn build_routes").expect("build_routes");
    let routes = &src[start..];
    let routes = &routes[..routes
        .find(".fallback(fallback_handler)")
        .expect("fallback")];
    let mut found = BTreeSet::new();
    let mut rest = routes;
    while let Some(i) = rest.find("get(handlers::") {
        let after = &rest[i + "get(handlers::".len()..];
        let end = after.find(')').expect("closing paren");
        found.insert(after[..end].to_string());
        rest = &after[end..];
    }
    found
}

async fn put_json(store: &u7s_store::SqliteStore, key: String, value: Value) {
    use u7s_store::Store as _;
    store
        .put(&key, bytes::Bytes::from(value.to_string()), None)
        .await
        .unwrap_or_else(|e| panic!("seed {key}: {e}"));
}

fn meta(name: &str, ns: Option<&str>) -> Value {
    let mut m = json!({"name": name, "uid": format!("uid-{name}"), "labels": {"app": "x"}});
    if let Some(ns) = ns {
        m["namespace"] = json!(ns);
    }
    m
}

async fn seeded_router() -> axum::Router {
    use crate::keys::{cluster_object_key, group_object_key, object_key};
    use std::sync::Arc;

    let store = Arc::new(u7s_store::SqliteStore::new(":memory:").expect("store"));
    let state = make_state_with_store(store.clone());
    super::test_support::seed_namespace(&state, "pomns").await;

    let st = &*store;
    put_json(
        st,
        object_key("pods", "pomns", "p1"),
        json!({"apiVersion":"v1","kind":"Pod","metadata":meta("p1",Some("pomns")),
               "spec":{"containers":[{"name":"c","image":"i"}]},"status":{"phase":"Pending"}}),
    )
    .await;
    put_json(
        st,
        cluster_object_key("nodes", "n1"),
        json!({"apiVersion":"v1","kind":"Node","metadata":meta("n1",None),
               "spec":{"podCIDR":"10.0.0.0/24"},"status":{"phase":"x"}}),
    )
    .await;
    put_json(
        st,
        object_key("configmaps", "pomns", "cm1"),
        json!({"apiVersion":"v1","kind":"ConfigMap","metadata":meta("cm1",Some("pomns")),
               "data":{"k":"v"}}),
    )
    .await;
    put_json(
        st,
        object_key("services", "pomns", "svc1"),
        json!({"apiVersion":"v1","kind":"Service","metadata":meta("svc1",Some("pomns")),
               "spec":{"clusterIP":"10.96.0.9"},"status":{"loadBalancer":{}}}),
    )
    .await;
    put_json(
        st,
        object_key("replicationcontrollers", "pomns", "rc1"),
        json!({"apiVersion":"v1","kind":"ReplicationController",
               "metadata":meta("rc1",Some("pomns")),"spec":{"replicas":1,"selector":{"a":"b"}}}),
    )
    .await;
    put_json(
        st,
        group_object_key("apps", "deployments", Some("pomns"), "d1"),
        json!({"apiVersion":"apps/v1","kind":"Deployment","metadata":meta("d1",Some("pomns")),
               "spec":{"replicas":2,"selector":{"matchLabels":{"a":"b"}}},"status":{"replicas":2}}),
    )
    .await;
    put_json(
        st,
        group_object_key("storage.k8s.io", "csinodes", None, "worker-1"),
        json!({"apiVersion":"storage.k8s.io/v1","kind":"CSINode","metadata":meta("worker-1",None),
               "spec":{"drivers":[]}}),
    )
    .await;
    put_json(
        st,
        group_object_key("certificates.k8s.io", "certificatesigningrequests", None, "csr1"),
        json!({"apiVersion":"certificates.k8s.io/v1","kind":"CertificateSigningRequest",
               "metadata":meta("csr1",None),
               "spec":{"request":"AA==","signerName":"example.com/s","usages":["digital signature"]},
               "status":{}}),
    )
    .await;
    put_json(
        st,
        group_object_key("certificates.k8s.io", "clustertrustbundles", None, "ctb1"),
        json!({"apiVersion":"certificates.k8s.io/v1","kind":"ClusterTrustBundle",
               "metadata":meta("ctb1",None),"spec":{"trustBundle":"x"}}),
    )
    .await;

    for (scope, plural, kind) in [
        ("Cluster", "gadgets", "Gadget"),
        ("Namespaced", "widgets", "Widget"),
    ] {
        let crd = json!({
            "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
            "metadata": {"name": format!("{plural}.example.io")},
            "spec": {
                "group": "example.io",
                "names": {"plural": plural, "singular": plural, "kind": kind,
                          "listKind": format!("{kind}List")},
                "scope": scope,
                "versions": [{
                    "name": "v1", "served": true, "storage": true,
                    "schema": {"openAPIV3Schema": {
                        "type": "object", "x-kubernetes-preserve-unknown-fields": true}},
                    "subresources": {
                        "status": {},
                        "scale": {"specReplicasPath": ".spec.replicas",
                                  "statusReplicasPath": ".status.replicas"}
                    }
                }]
            }
        });
        crate::handlers::crd::create_crd(
            axum::extract::State(state.clone()),
            axum::Extension(crate::auth::UserInfo {
                username: "admin".into(),
                uid: String::new(),
                groups: vec![],
                extra: Default::default(),
            }),
            axum::http::HeaderMap::new(),
            bytes::Bytes::from(crd.to_string()),
        )
        .await
        .unwrap_or_else(|e| panic!("install CRD {plural}: {}", e.1.message));
    }
    put_json(
        st,
        "/registry/cr/example.io/gadgets/g1".into(),
        json!({"apiVersion":"example.io/v1","kind":"Gadget","metadata":meta("g1",None),
               "spec":{"replicas":1},"status":{"replicas":1}}),
    )
    .await;
    put_json(
        st,
        "/registry/cr/example.io/widgets/pomns/w1".into(),
        json!({"apiVersion":"example.io/v1","kind":"Widget","metadata":meta("w1",Some("pomns")),
               "spec":{"replicas":1},"status":{"replicas":1}}),
    )
    .await;

    crate::build_router(state)
}

async fn get(router: &axum::Router, uri: &str, accept: &str) -> (StatusCode, String) {
    let mut req = Request::builder()
        .uri(uri)
        .header("accept", accept)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(crate::auth::UserInfo {
        username: "admin".into(),
        uid: String::new(),
        groups: vec![],
        extra: Default::default(),
    });
    let resp = router.clone().call(req).await.expect("router");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn assert_pom_shape(obj: &Value, ctx: &str) {
    let mut keys: Vec<_> = obj.as_object().expect(ctx).keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["apiVersion", "kind", "metadata"],
        "{ctx}: a metadata informer must receive nothing but type meta and metadata: {obj}"
    );
    assert_eq!(obj["apiVersion"], "meta.k8s.io/v1", "{ctx}");
    assert_eq!(obj["kind"], "PartialObjectMetadata", "{ctx}");
}

fn assert_406(status: StatusCode, body: &str, ctx: &str) {
    assert_eq!(
        status,
        StatusCode::NOT_ACCEPTABLE,
        "{ctx}: upstream refuses with 406 instead of serving a shape the client did not ask for: {body}"
    );
}

async fn probe(router: axum::Router, handler: &'static str, shape: Shape, uri: &'static str) {
    let ctx = format!("{handler} {uri}");
    let (watch_uri, bad_form) = match shape {
        Object => (None, LIST_ACCEPT),
        Collection => (
            Some(format!(
                "{uri}?watch=true&sendInitialEvents=true&allowWatchBookmarks=true&timeoutSeconds=1"
            )),
            OBJECT_ACCEPT,
        ),
    };

    let accept = if shape == Object {
        OBJECT_ACCEPT
    } else {
        LIST_ACCEPT
    };
    let (status, body) = get(&router, uri, accept).await;
    assert_eq!(status, StatusCode::OK, "{ctx}: {body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    match shape {
        Object => assert_pom_shape(&v, &ctx),
        Collection => {
            assert_eq!(v["kind"], "PartialObjectMetadataList", "{ctx}: {v}");
            let items = v["items"].as_array().expect(&ctx);
            assert!(!items.is_empty(), "{ctx}: probe must seed an item: {v}");
            for item in items {
                assert_pom_shape(item, &ctx);
            }
        }
    }

    let (status, body) = get(&router, uri, bad_form).await;
    assert_406(status, &body, &format!("{ctx} wrong form"));
    let (status, body) = get(&router, uri, BAD_GV_ACCEPT).await;
    assert_406(status, &body, &format!("{ctx} lone as= with bad g/v"));

    if let Some(watch_uri) = watch_uri {
        let (status, body) = get(&router, &watch_uri, OBJECT_ACCEPT).await;
        assert_eq!(status, StatusCode::OK, "{ctx} watch: {body}");
        let events: Vec<Value> = body
            .lines()
            .map(|l| serde_json::from_str(l).expect("watch event"))
            .collect();
        assert!(
            events.iter().any(|e| e["type"] == "ADDED"),
            "{ctx} watch: probe must see the seeded object: {body}"
        );
        for e in &events {
            assert_pom_shape(&e["object"], &format!("{ctx} watch {}", e["type"]));
        }
        let (status, body) = get(&router, &watch_uri, LIST_ACCEPT).await;
        assert_406(status, &body, &format!("{ctx} watch with list form"));
    }
}

/// A handler registered for GET without a probe here could bypass the negotiator unnoticed.
#[test]
fn every_registered_get_handler_is_probed_or_explicitly_not_an_object_endpoint() {
    let probed: BTreeSet<&str> = PROBES.iter().map(|(h, _, _)| *h).collect();
    let registered = registered_get_handlers();
    let unprobed: Vec<_> = registered
        .iter()
        .filter(|h| {
            !NON_OBJECT_MODULES.contains(&h.split("::").next().unwrap())
                && !probed.contains(h.as_str())
        })
        .collect();
    assert!(
        unprobed.is_empty(),
        "GET handlers with no PartialObjectMetadata probe in PROBES (route them through \
         generic::negotiate_* and add a probe): {unprobed:?}"
    );
    let stale: Vec<_> = probed
        .iter()
        .filter(|h| !registered.contains(**h))
        .collect();
    assert!(
        stale.is_empty(),
        "probes for handlers no longer routed: {stale:?}"
    );
}

/// Metadata informers (GC, namespace controller) list/get/watch every resource type with a
/// metadata-only Accept; each route must project to PartialObjectMetadata and refuse a form or
/// group/version it does not serve.
#[tokio::test]
async fn every_object_endpoint_serves_partial_object_metadata_and_406s_otherwise() {
    let router = seeded_router().await;
    let mut set = tokio::task::JoinSet::new();
    for (handler, shape, uri) in PROBES {
        set.spawn(probe(router.clone(), handler, *shape, uri));
    }
    let mut failures = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Err(e) = r {
            failures.push(
                e.into_panic()
                    .downcast::<String>()
                    .map(|s| *s)
                    .unwrap_or_else(|_| "panic".into()),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} probes failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
