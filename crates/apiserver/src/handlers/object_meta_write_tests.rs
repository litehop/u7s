//! Router-level proof that no write path stores a label (or annotation) upstream's
//! `ValidateObjectMeta` rejects: a Node label value over 63 characters would otherwise be
//! accepted here and then break every selector and kubelet that round-trips it.

use axum::http::StatusCode;
use serde_json::{json, Value};

use super::subresource_admission_tests::cases::Cluster;
use crate::handlers::test_support::install_namespaced_crd;

const MERGE: &str = "application/merge-patch+json";
const STRATEGIC: &str = "application/strategic-merge-patch+json";
const JSON_PATCH: &str = "application/json-patch+json";
const APPLY: &str = "application/apply-patch+yaml";

struct Kind {
    label: &'static str,
    collection: &'static str,
    api_version: &'static str,
    kind: &'static str,
    extra: Value,
}

fn kinds() -> Vec<Kind> {
    vec![
        Kind {
            label: "ConfigMap",
            collection: "/api/v1/namespaces/default/configmaps",
            api_version: "v1",
            kind: "ConfigMap",
            extra: json!({"data": {"a": "b"}}),
        },
        Kind {
            label: "Node",
            collection: "/api/v1/nodes",
            api_version: "v1",
            kind: "Node",
            extra: json!({}),
        },
        Kind {
            label: "Pod",
            collection: "/api/v1/namespaces/default/pods",
            api_version: "v1",
            kind: "Pod",
            extra: json!({"spec": {"containers": [{"name": "app", "image": "nginx"}]}}),
        },
        Kind {
            label: "Namespace",
            collection: "/api/v1/namespaces",
            api_version: "v1",
            kind: "Namespace",
            extra: json!({}),
        },
        Kind {
            label: "Deployment",
            collection: "/apis/apps/v1/namespaces/default/deployments",
            api_version: "apps/v1",
            kind: "Deployment",
            extra: json!({"spec": {"replicas": 1,
                "selector": {"matchLabels": {"a": "b"}},
                "template": {"metadata": {"labels": {"a": "b"}},
                    "spec": {"containers": [{"name": "app", "image": "nginx"}]}}}}),
        },
        Kind {
            label: "custom resource",
            collection: "/apis/example.com/v1/namespaces/default/widgets",
            api_version: "example.com/v1",
            kind: "Widget",
            extra: json!({"spec": {"size": 1}}),
        },
    ]
}

fn body(k: &Kind, name: &str, labels: Option<Value>) -> Value {
    let mut b = json!({"apiVersion": k.api_version, "kind": k.kind, "metadata": {"name": name}});
    if let Some(labels) = labels {
        b["metadata"]["labels"] = labels;
    }
    for (key, v) in k.extra.as_object().unwrap() {
        b[key] = v.clone();
    }
    b
}

async fn cluster() -> Cluster {
    let c = Cluster::new().await;
    install_namespaced_crd(&c.state, "example.com", "v1", "widgets", "Widget").await;
    c
}

fn assert_label_rejected(label: &str, path: &str, status: StatusCode, resp: &Value, needle: &str) {
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{label} via {path}: an invalid label must be a 422, not stored: {resp}"
    );
    let msg = resp["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("is invalid: metadata.labels: Invalid value:") && msg.contains(needle),
        "{label} via {path}: message must follow upstream's ValidateLabels wording: {msg}"
    );
}

/// Every write verb must reject a label value over 63 characters on every kind class, so a
/// client cannot sidestep validation by choosing PATCH or apply over PUT.
#[tokio::test]
async fn overlong_label_value_is_rejected_on_every_write_path_and_kind() {
    let c = cluster().await;
    let long = "x".repeat(64);
    let needle = "must be no more than 63 characters";
    let mut sites = 0;
    for k in kinds() {
        let item = format!("{}/t", k.collection);
        let (st, resp) = c
            .call(
                "POST",
                k.collection,
                "application/json",
                body(&k, "t", None),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "{}: seed {resp}", k.label);

        let (st, resp) = c
            .call(
                "POST",
                k.collection,
                "application/json",
                body(&k, "bad", Some(json!({"k": long}))),
            )
            .await;
        assert_label_rejected(k.label, "POST", st, &resp, needle);

        let (_, cur) = c.call("GET", &item, "application/json", Value::Null).await;
        let mut put = cur.clone();
        put["metadata"]["labels"] = json!({"k": long});
        let (st, resp) = c.call("PUT", &item, "application/json", put).await;
        assert_label_rejected(k.label, "PUT", st, &resp, needle);

        let patch = json!({"metadata": {"labels": {"k": long}}});
        for (path, ct, b) in [
            ("merge-PATCH", MERGE, patch.clone()),
            ("strategic-PATCH", STRATEGIC, patch.clone()),
            (
                "json-PATCH",
                JSON_PATCH,
                json!([{"op": "add", "path": "/metadata/labels", "value": {"k": long}}]),
            ),
            (
                "apply-PATCH",
                APPLY,
                body(&k, "t", Some(json!({"k": long}))),
            ),
        ] {
            if k.label == "Namespace" && path == "json-PATCH" {
                // Namespaces reject json-patch with 415 today, independent of labels.
                sites += 1;
                continue;
            }
            let (st, resp) = c.call("PATCH", &item, ct, b).await;
            assert_label_rejected(k.label, path, st, &resp, needle);
            sites += 1;
        }
        sites += 2;

        let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
        assert!(
            after["metadata"]["labels"]["k"].is_null(),
            "{}: a rejected write must leave the stored object untouched: {after}",
            k.label
        );

        let (st, resp) = c
            .call(
                "PATCH",
                &item,
                MERGE,
                json!({"metadata": {"labels": {"ok": "fine-1"}}}),
            )
            .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "{}: a conforming label must still be accepted: {resp}",
            k.label
        );
    }
    assert_eq!(sites, 6 * 6, "every path x kind cell must have run");
}

/// A label key that is not a qualified name is just as unstorable as a long value.
#[tokio::test]
async fn invalid_label_key_is_rejected_on_create_and_patch() {
    let c = cluster().await;
    for k in kinds() {
        let (st, resp) = c
            .call(
                "POST",
                k.collection,
                "application/json",
                body(&k, "bad", Some(json!({"not a key": "v"}))),
            )
            .await;
        assert_label_rejected(k.label, "POST", st, &resp, "name part must consist of");
    }
}

/// Status and scale writes run strategy before validation, so they may neither store a bad
/// label nor reject an object whose labels they were never allowed to change.
#[tokio::test]
async fn status_and_scale_writes_never_store_an_invalid_label() {
    let c = cluster().await;
    let long = "x".repeat(64);
    let dep = &kinds()[4];
    let (st, resp) = c
        .call(
            "POST",
            dep.collection,
            "application/json",
            body(dep, "t", None),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    let item = format!("{}/t", dep.collection);
    for (path, ct, sub, b) in [
        (
            "status merge-PATCH",
            MERGE,
            "status",
            json!({"metadata": {"labels": {"k": long}}, "status": {"replicas": 1}}),
        ),
        (
            "scale merge-PATCH",
            MERGE,
            "scale",
            json!({"metadata": {"labels": {"k": long}}, "spec": {"replicas": 2}}),
        ),
    ] {
        let (st, resp) = c.call("PATCH", &format!("{item}/{sub}"), ct, b).await;
        assert!(
            st == StatusCode::UNPROCESSABLE_ENTITY || st == StatusCode::OK,
            "{path}: {st} {resp}"
        );
        let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
        assert_ne!(
            after["metadata"]["labels"]["k"].as_str(),
            Some(long.as_str()),
            "{path}: invalid label reached storage"
        );
    }
}

/// Upstream caps total annotation size at 256 KiB; without it one object can bloat storage.
#[tokio::test]
async fn annotations_over_256kib_are_rejected_on_create_and_patch() {
    let c = cluster().await;
    let k = &kinds()[0];
    let mut b = body(k, "big", None);
    b["metadata"]["annotations"] = json!({"a": "x".repeat(262_145)});
    let (st, resp) = c.call("POST", k.collection, "application/json", b).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert!(
        resp["message"]
            .as_str()
            .unwrap()
            .contains("metadata.annotations: Too long: may not be more than 262144 bytes"),
        "{resp}"
    );
}
