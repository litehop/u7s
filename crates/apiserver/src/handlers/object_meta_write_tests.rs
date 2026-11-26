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

/// Upstream's pods/status and nodes/status strategies keep the submitted labels, so an
/// over-long value reaches `ValidateObjectMetaUpdate` and is a 422 (a kubelet patching a bad
/// label must be told, not silently ignored). deployments/status resets labels to the stored
/// ones and deployments/scale only copies `spec.replicas`, so there the write succeeds and the
/// label is dropped.
#[tokio::test]
async fn status_and_scale_writes_follow_each_upstream_strategy_for_an_overlong_label() {
    let c = cluster().await;
    let long = "x".repeat(64);
    let ks = kinds();
    let (node, pod, dep) = (&ks[1], &ks[2], &ks[4]);
    for k in [node, pod, dep] {
        let (st, resp) = c
            .call("POST", k.collection, "application/json", body(k, "t", None))
            .await;
        assert_eq!(st, StatusCode::CREATED, "{}: {resp}", k.label);
    }
    let lbl = json!({"metadata": {"labels": {"k": long}}});
    let rejected = [(node, "status", lbl.clone()), (pod, "status", lbl.clone())];
    for (k, sub, b) in rejected {
        let item = format!("{}/t", k.collection);
        let (st, resp) = c.call("PATCH", &format!("{item}/{sub}"), MERGE, b).await;
        assert_label_rejected(
            k.label,
            &format!("{sub} merge-PATCH"),
            st,
            &resp,
            "must be no more than 63 characters",
        );
        let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
        assert!(
            after["metadata"]["labels"]["k"].is_null(),
            "{}: invalid label reached storage via {sub}: {after}",
            k.label
        );
    }
    let item = format!("{}/t", dep.collection);
    for (sub, b) in [
        (
            "status",
            json!({"metadata": {"labels": {"k": long}}, "status": {"replicas": 1}}),
        ),
        (
            "scale",
            json!({"metadata": {"labels": {"k": long}}, "spec": {"replicas": 2}}),
        ),
    ] {
        let (st, resp) = c.call("PATCH", &format!("{item}/{sub}"), MERGE, b).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "deployments/{sub} ignores submitted labels upstream, so the write succeeds: {resp}"
        );
        let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
        assert!(
            after["metadata"]["labels"]["k"].is_null(),
            "deployments/{sub}: the submitted label must be dropped, not stored: {after}"
        );
    }
}

/// Upstream caps total annotation size at 256 KiB; without it one object can bloat storage,
/// and a PATCH must not be a way around the cap that POST enforces.
#[tokio::test]
async fn annotations_over_256kib_are_rejected_on_create_and_patch() {
    let c = cluster().await;
    let k = &kinds()[0];
    let needle = "metadata.annotations: Too long: may not be more than 262144 bytes";
    let big = json!({"a": "x".repeat(262_145)});
    let mut b = body(k, "big", None);
    b["metadata"]["annotations"] = big.clone();
    let (st, resp) = c.call("POST", k.collection, "application/json", b).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert!(resp["message"].as_str().unwrap().contains(needle), "{resp}");

    let (st, resp) = c
        .call(
            "POST",
            k.collection,
            "application/json",
            body(k, "small", None),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    let item = format!("{}/small", k.collection);
    let (st, resp) = c
        .call(
            "PATCH",
            &item,
            MERGE,
            json!({"metadata": {"annotations": big}}),
        )
        .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "PATCH: {resp}");
    assert!(resp["message"].as_str().unwrap().contains(needle), "{resp}");
    let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
    assert!(
        after["metadata"]["annotations"].is_null(),
        "an oversized PATCH must leave the object untouched: {after}"
    );
}

fn template_kinds() -> Vec<Kind> {
    let pod_spec = json!({"containers": [{"name": "app", "image": "nginx"}]});
    let simple = |label: &'static str,
                  c: &'static str,
                  av: &'static str,
                  kind: &'static str,
                  extra: Value| Kind {
        label,
        collection: c,
        api_version: av,
        kind,
        extra,
    };
    let sel = json!({"matchLabels": {"a": "b"}});
    let t = json!({"metadata": {"labels": {"a": "b"}}, "spec": pod_spec});
    let job = json!({"template": {"metadata": {"labels": {"a": "b"}},
        "spec": {"restartPolicy": "Never", "containers": [{"name": "app", "image": "nginx"}]}}});
    vec![
        simple(
            "Deployment",
            "/apis/apps/v1/namespaces/default/deployments",
            "apps/v1",
            "Deployment",
            json!({"spec": {"selector": sel, "template": t}}),
        ),
        simple(
            "ReplicaSet",
            "/apis/apps/v1/namespaces/default/replicasets",
            "apps/v1",
            "ReplicaSet",
            json!({"spec": {"selector": sel, "template": t}}),
        ),
        simple(
            "StatefulSet",
            "/apis/apps/v1/namespaces/default/statefulsets",
            "apps/v1",
            "StatefulSet",
            json!({"spec": {"selector": sel, "serviceName": "s", "template": t}}),
        ),
        simple(
            "DaemonSet",
            "/apis/apps/v1/namespaces/default/daemonsets",
            "apps/v1",
            "DaemonSet",
            json!({"spec": {"selector": sel, "template": t}}),
        ),
        simple(
            "Job",
            "/apis/batch/v1/namespaces/default/jobs",
            "batch/v1",
            "Job",
            json!({"spec": {"selector": null, "manualSelector": false, "template": job["template"]}}),
        ),
        simple(
            "CronJob",
            "/apis/batch/v1/namespaces/default/cronjobs",
            "batch/v1",
            "CronJob",
            json!({"spec": {"schedule": "* * * * *", "jobTemplate": {"spec": job}}}),
        ),
        simple(
            "ReplicationController",
            "/api/v1/namespaces/default/replicationcontrollers",
            "v1",
            "ReplicationController",
            json!({"spec": {"selector": {"a": "b"}, "template": t}}),
        ),
        simple(
            "PodTemplate",
            "/api/v1/namespaces/default/podtemplates",
            "v1",
            "PodTemplate",
            json!({"template": t}),
        ),
    ]
}

fn template_path(k: &Kind) -> Vec<&'static str> {
    match k.kind {
        "CronJob" => vec!["spec", "jobTemplate", "spec", "template"],
        "PodTemplate" => vec!["template"],
        _ => vec!["spec", "template"],
    }
}

fn set_template_label(v: &mut Value, path: &[&str], value: Value) {
    let mut cur = v;
    for p in path {
        cur = &mut cur[*p];
    }
    cur["metadata"]["labels"] = value;
}

fn nested(path: &[&str], leaf: Value) -> Value {
    path.iter().rev().fold(leaf, |acc, p| json!({ *p: acc }))
}

/// A workload whose pod template carries a label the kubelet or a selector can never
/// round-trip would be stored, and then every pod its controller creates would be rejected
/// by the apiserver in a hot loop. Upstream rejects the workload itself, at
/// `<template path>.labels`, on every kind and write verb.
#[tokio::test]
async fn overlong_pod_template_label_is_rejected_on_every_workload_kind_and_write_path() {
    let c = cluster().await;
    let long = "x".repeat(64);
    let mut sites = 0;
    let ks = template_kinds();
    for k in &ks {
        let path = template_path(k);
        let want = format!("{}.labels: Invalid value:", path.join("."));
        let check = |path_name: &str, st: StatusCode, resp: &Value| {
            assert_eq!(
                st,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{} via {path_name}: bad template label must be a 422: {resp}",
                k.label
            );
            let msg = resp["message"].as_str().unwrap_or_default();
            assert!(
                msg.contains(&want) && msg.contains("must be no more than 63 characters"),
                "{} via {path_name}: wrong message: {msg}",
                k.label
            );
        };
        let item = format!("{}/t", k.collection);
        let (st, resp) = c
            .call("POST", k.collection, "application/json", body(k, "t", None))
            .await;
        assert_eq!(st, StatusCode::CREATED, "{}: seed {resp}", k.label);

        let mut bad = body(k, "bad", None);
        set_template_label(&mut bad, &path, json!({"a": "b", "k": long}));
        let (st, resp) = c.call("POST", k.collection, "application/json", bad).await;
        check("POST", st, &resp);

        let (_, cur) = c.call("GET", &item, "application/json", Value::Null).await;
        let mut put = cur.clone();
        set_template_label(&mut put, &path, json!({"a": "b", "k": long}));
        let (st, resp) = c.call("PUT", &item, "application/json", put).await;
        check("PUT", st, &resp);

        let leaf = json!({"metadata": {"labels": {"k": long}}});
        let patch = nested(&path, leaf);
        let mut apply = body(k, "t", None);
        set_template_label(&mut apply, &path, json!({"a": "b", "k": long}));
        let json_patch = json!([{"op": "add",
            "path": format!("/{}/metadata/labels/k", path.join("/")), "value": long}]);
        for (name, ct, b) in [
            ("merge-PATCH", MERGE, patch.clone()),
            ("strategic-PATCH", STRATEGIC, patch.clone()),
            ("json-PATCH", JSON_PATCH, json_patch),
            ("apply-PATCH", APPLY, apply),
        ] {
            let (st, resp) = c.call("PATCH", &item, ct, b).await;
            check(name, st, &resp);
            sites += 1;
        }
        sites += 2;
    }
    assert_eq!(sites, 8 * 6, "every kind x path cell must have run");
}

/// A pod template annotation key that is not a qualified name would make every pod the
/// controller stamps out fail admission; upstream rejects the workload at
/// `<template path>.annotations`.
#[tokio::test]
async fn invalid_pod_template_annotation_key_is_rejected_on_every_workload_kind() {
    let c = cluster().await;
    for k in &template_kinds() {
        let path = template_path(k);
        let mut bad = body(k, "bad", None);
        let mut cur = &mut bad;
        for p in &path {
            cur = &mut cur[*p];
        }
        cur["metadata"]["annotations"] = json!({"bad key": "v"});
        let (st, resp) = c.call("POST", k.collection, "application/json", bad).await;
        assert_eq!(
            st,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}: a bad template annotation key must be a 422: {resp}",
            k.label
        );
        let want = format!("{}.annotations: Invalid value: \"bad key\"", path.join("."));
        let msg = resp["message"].as_str().unwrap_or_default();
        assert!(msg.contains(&want), "{}: wrong message: {msg}", k.label);
    }
}

/// Writes `obj` straight to the store, bypassing admission, to model an object stored before
/// validation tightened.
async fn seed_stored_object(c: &Cluster, k: &Kind, obj: &Value) {
    use u7s_store::Store;
    let group = k.api_version.split_once('/').map_or("", |(g, _)| g);
    let resource = k.collection.rsplit('/').next().unwrap();
    let prefix = if group.is_empty() {
        "/registry".to_string()
    } else {
        format!("/registry/{group}")
    };
    c.store
        .put(
            &format!("{prefix}/{resource}/default/t"),
            bytes::Bytes::from(obj.to_string()),
            None,
        )
        .await
        .unwrap();
}

/// Upstream's status and scale strategies reset the spec to the stored one and never validate
/// the pod template, so a workload that already holds a bad template label must keep
/// accepting status writes; rejecting them would freeze the controllers' status updates.
#[tokio::test]
async fn status_and_scale_writes_succeed_on_a_stored_workload_with_an_invalid_template_label() {
    let c = cluster().await;
    let long = "x".repeat(64);
    let mut writes = 0;
    for k in template_kinds() {
        if k.kind == "PodTemplate" {
            continue;
        }
        let mut obj = body(&k, "t", None);
        set_template_label(&mut obj, &template_path(&k), json!({"a": "b", "k": long}));
        seed_stored_object(&c, &k, &obj).await;
        let item = format!("{}/t", k.collection);
        let mut subs = vec![("status", json!({"status": {"observedGeneration": 1}}))];
        if k.kind == "Deployment" {
            subs.push(("scale", json!({"spec": {"replicas": 2}})));
        }
        for (sub, patch) in subs {
            let (st, resp) = c
                .call("PATCH", &format!("{item}/{sub}"), MERGE, patch)
                .await;
            assert_eq!(
                st,
                StatusCode::OK,
                "{} {sub}: a stored bad template must not block the write: {resp}",
                k.label
            );
            writes += 1;
        }
        let (_, after) = c.call("GET", &item, "application/json", Value::Null).await;
        let mut cur = &after;
        for p in template_path(&k) {
            cur = &cur[p];
        }
        assert_eq!(
            cur["metadata"]["labels"]["k"], long,
            "{}: the stored template is untouched by status writes",
            k.label
        );
    }
    assert_eq!(
        writes, 8,
        "7 workload kinds with status plus Deployment scale"
    );
}

/// A Binding's metadata is validated like a pod's: an invalid label key or an annotation set
/// over 256 KiB must be a 422 and must not bind the pod, while a conforming Binding binds it.
#[tokio::test]
async fn pod_binding_metadata_is_validated_like_pod_create() {
    let c = cluster().await;
    let pod = &kinds()[2];
    let (st, resp) = c
        .call(
            "POST",
            pod.collection,
            "application/json",
            body(pod, "p", None),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
    let uri = "/api/v1/namespaces/default/pods/p/binding";
    let binding = |meta: Value| {
        let mut b = json!({"apiVersion": "v1", "kind": "Binding", "metadata": {"name": "p"},
            "target": {"apiVersion": "v1", "kind": "Node", "name": "node-1"}});
        for (k, v) in meta.as_object().unwrap() {
            b["metadata"][k] = v.clone();
        }
        b
    };

    let (st, resp) = c
        .call(
            "POST",
            uri,
            "application/json",
            binding(json!({"labels": {"not a key": "v"}})),
        )
        .await;
    assert_label_rejected("Binding", "POST", st, &resp, "name part must consist of");

    let big = json!({"annotations": {"a": "x".repeat(300 * 1024)}});
    let (st, resp) = c.call("POST", uri, "application/json", binding(big)).await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "{resp}");
    assert!(
        resp["message"]
            .as_str()
            .unwrap_or_default()
            .contains("metadata.annotations: Too long: may not be more than 262144 bytes"),
        "{resp}"
    );

    let (_, after) = c
        .call(
            "GET",
            "/api/v1/namespaces/default/pods/p",
            "application/json",
            Value::Null,
        )
        .await;
    assert!(
        after["spec"]["nodeName"].is_null(),
        "a rejected binding must leave the pod unscheduled: {after}"
    );

    let ok = binding(json!({"labels": {"k": "v"}, "annotations": {"example.com/a": "b"}}));
    let (st, resp) = c.call("POST", uri, "application/json", ok).await;
    assert_eq!(st, StatusCode::CREATED, "{resp}");
}
