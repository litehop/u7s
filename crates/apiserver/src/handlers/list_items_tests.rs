use super::*;
use crate::handlers::generic::{parse_label_selector, LabelSelectorTerm};
use serde_json::json;

/// Stored form: what `SqliteStore::put` writes (a `Value` re-serialized by `to_vec`).
fn stored(v: Value) -> u7s_store::StoreObject {
    u7s_store::StoreObject {
        key: String::new(),
        value: bytes::Bytes::from(serde_json::to_vec(&v).unwrap()),
        revision: 1,
    }
}

fn pod(name: &str, ns: &str, labels: Value, node: &str, phase: &str) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": ns, "labels": labels,
            "uid": format!("uid-{name}"), "resourceVersion": "7",
            "creationTimestamp": "2026-01-02T03:04:05Z",
            "managedFields": [{
                "manager": "kubectl", "operation": "Update", "apiVersion": "v1",
                "time": "2026-01-02T03:04:05Z", "fieldsType": "FieldsV1",
                "fieldsV1": {"f:metadata": {"f:labels": {".": {}, "f:app": {}}}}
            }],
        },
        "spec": {
            "nodeName": node, "restartPolicy": "Always",
            "containers": [{"name": "c", "image": "pause", "resources": {"limits": {"cpu": "1.5"}}}],
        },
        "status": {"phase": phase, "podIP": "10.0.0.1", "qosClass": "Burstable"},
    })
}

/// Pods the raw-bytes skim cannot always decide on (non-string label values, null labels,
/// escaped label strings, missing metadata) next to ordinary ones.
fn pod_corpus() -> Vec<u7s_store::StoreObject> {
    vec![
        pod("p1", "ns1", json!({"app": "app-1", "tier": "web"}), "node-1", "Running"),
        pod("p2", "ns1", json!({"app": "app-2"}), "node-2", "Pending"),
        pod("p3", "ns2", json!({"app": "app-1"}), "node-1", "Running"),
        pod("p4", "ns2", json!({}), "", "Pending"),
        pod("p5", "ns2", json!({"tier": "web"}), "node-3", "Failed"),
        pod("p6", "ns3", json!({"app": "app\"1", "esc": "\u{e9}\u{2028}"}), "node-1", "Running"),
        pod("p7", "ns3", json!({"app": 1}), "node-1", "Running"),
        pod("p8", "ns3", Value::Null, "node-1", "Running"),
        json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "bare"}}),
        json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "n", "labels": {"app": "app-1"}}, "spec": {"nodeName": null}}),
    ]
    .into_iter()
    .map(stored)
    .collect()
}

fn labeled(kind: &str, name: &str, labels: Value, extra: Value) -> Value {
    let mut v = json!({
        "apiVersion": "v1", "kind": kind,
        "metadata": {"name": name, "namespace": "ns1", "labels": labels},
    });
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

struct Kind {
    group: &'static str,
    plural: &'static str,
    kind: &'static str,
    version: &'static str,
    items: Vec<u7s_store::StoreObject>,
}

/// Kinds with and without read-time defaults, including the one whose defaults rewrite labels.
fn kinds() -> Vec<Kind> {
    let app = |i: usize| json!({"app": format!("app-{}", i % 3), "n": "x"});
    let many = |kind: &str, prefix: &str, n: usize, extra: Value| -> Vec<u7s_store::StoreObject> {
        (0..n)
            .map(|i| {
                stored(labeled(
                    kind,
                    &format!("{prefix}-{i}"),
                    app(i),
                    extra.clone(),
                ))
            })
            .collect()
    };
    let mut deployments = many(
        "Deployment",
        "d",
        6,
        json!({"spec": {"selector": {"matchLabels": {"a": "b"}}, "template": {"metadata": {"labels": {"a": "b"}, "creationTimestamp": null}, "spec": {"containers": []}}}}),
    );
    deployments.push(stored(
        json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "bare"}}),
    ));
    vec![
        Kind {
            group: "",
            plural: "pods",
            kind: "Pod",
            version: "v1",
            items: pod_corpus(),
        },
        Kind {
            group: "",
            plural: "configmaps",
            kind: "ConfigMap",
            version: "v1",
            items: many("ConfigMap", "cm", 6, json!({"data": {"k": "v"}})),
        },
        Kind {
            group: "",
            plural: "secrets",
            kind: "Secret",
            version: "v1",
            items: many("Secret", "s", 6, json!({"data": {"k": "dg=="}})),
        },
        Kind {
            group: "apps",
            plural: "deployments",
            kind: "Deployment",
            version: "v1",
            items: deployments,
        },
        Kind {
            group: "",
            plural: "replicationcontrollers",
            kind: "ReplicationController",
            version: "v1",
            items: vec![
                stored(labeled(
                    "ReplicationController",
                    "rc-own",
                    json!({"app": "app-1"}),
                    json!({"spec": {"template": {"metadata": {"labels": {"app": "tpl"}}}}}),
                )),
                stored(labeled(
                    "ReplicationController",
                    "rc-inherit",
                    json!({}),
                    json!({"spec": {"template": {"metadata": {"labels": {"app": "app-1"}}}}}),
                )),
                stored(labeled(
                    "ReplicationController",
                    "rc-none",
                    json!({"app": "app-2"}),
                    json!({"spec": {}}),
                )),
            ],
        },
        Kind {
            group: "",
            plural: "namespaces",
            kind: "Namespace",
            version: "v1",
            items: many("Namespace", "n", 4, json!({})),
        },
        Kind {
            group: "",
            plural: "services",
            kind: "Service",
            version: "v1",
            items: many(
                "Service",
                "svc",
                4,
                json!({"spec": {"ports": [{"port": 80}], "selector": {"a": "b"}}}),
            ),
        },
    ]
}

const LABEL_SELECTORS: [&str; 11] = [
    "",
    "app=app-1",
    "app==app-1",
    "app!=app-1",
    "app",
    "!app",
    "app in (app-1,app-2)",
    "app notin (app-1)",
    "app=app-1,tier=web",
    "tier!=web,app",
    "n=x,app in (app-0)",
];

fn field_selectors(plural: &str) -> Vec<&'static str> {
    match plural {
        "pods" => vec![
            "",
            "metadata.name=p1",
            "metadata.namespace!=ns2",
            "spec.nodeName=node-1",
            "spec.nodeName=",
            "status.phase=Running",
            "spec.nodeName=node-1,status.phase!=Failed",
        ],
        "secrets" => vec!["", "metadata.name=s-1", "type=Opaque"],
        "namespaces" => vec!["", "metadata.name=n-1", "status.phase=Active"],
        _ => vec!["", "metadata.name=d-1", "metadata.namespace=ns1"],
    }
}

/// The pre-optimization per-item loop: full parse, defaults, `apply_label_selector`, then the
/// field selector, serialized with `to_writer`.
fn legacy_stream_list_json(
    k: &Kind,
    terms: &[LabelSelectorTerm<'_>],
    fs: &FieldSelector,
) -> Vec<u8> {
    let envelope = crate::handlers::generic::build_list_response(
        k.kind,
        k.group,
        k.version,
        9,
        Vec::new(),
        None,
        Some(4),
        &[3u8; 32],
    );
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let marker = b"\"items\":[]";
    let pos = envelope_bytes
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap();
    let mut body = envelope_bytes[..pos].to_vec();
    body.extend_from_slice(b"\"items\":[");
    let mut wrote = false;
    for obj in &k.items {
        let mut item: Value = serde_json::from_slice(&obj.value).unwrap();
        crate::handlers::defaults::apply_defaults(k.group, k.plural, &mut item);
        let Some(item) = crate::handlers::generic::apply_label_selector(vec![item], terms).pop()
        else {
            continue;
        };
        if !fs.matches(&item) {
            continue;
        }
        if wrote {
            body.push(b',');
        }
        wrote = true;
        serde_json::to_writer(&mut body, &item).unwrap();
    }
    body.push(b']');
    body.extend_from_slice(&envelope_bytes[pos + marker.len()..]);
    body
}

/// A LIST's bytes are what every client decodes: if the selector pre-filter ever dropped, kept,
/// reordered or rewrote an item differently from the full-parse path, an informer would silently
/// cache the wrong set of objects.
#[test]
fn list_output_is_byte_identical_to_the_full_parse_path() {
    let mut cases = 0;
    for k in kinds() {
        for ls in LABEL_SELECTORS {
            for fs in field_selectors(k.plural) {
                let terms = parse_label_selector(ls).unwrap();
                let field_selector = FieldSelector::parse(Some(fs), k.group, k.plural).unwrap();
                let expected = legacy_stream_list_json(&k, &terms, &field_selector);
                let filter = ListFilter::new(k.group, k.plural, &terms, &field_selector, None);
                let actual = crate::handlers::resource::stream_list_json(
                    k.kind,
                    k.group,
                    k.version,
                    9,
                    &k.items,
                    &filter,
                    None,
                    Some(4),
                    &[3u8; 32],
                )
                .unwrap();
                assert_eq!(
                    String::from_utf8(actual).unwrap(),
                    String::from_utf8(expected).unwrap(),
                    "{} labelSelector={ls:?} fieldSelector={fs:?}",
                    k.plural
                );
                cases += 1;
            }
        }
    }
    assert!(cases > 200, "corpus shrank to {cases} cases");
}

/// The skim may only exclude what the full matchers also exclude; anything it cannot read
/// (non-string label values, a ReplicationController whose defaults rewrite labels) must be left
/// to the full path or a matching object disappears from the LIST.
#[test]
fn prefilter_excludes_only_what_it_can_prove_and_defers_the_rest() {
    let terms = parse_label_selector("app=app-1").unwrap();
    let fs = FieldSelector::default();
    let filter = ListFilter::new("", "pods", &terms, &fs, None);
    let raw = |v: Value| serde_json::to_vec(&v).unwrap();
    assert!(filter.definitely_excluded(&raw(json!({"metadata": {"labels": {"app": "other"}}}))));
    assert!(!filter.definitely_excluded(&raw(json!({"metadata": {"labels": {"app": "app-1"}}}))));
    assert!(
        !filter.definitely_excluded(&raw(json!({"metadata": {"labels": {"app": 1}}}))),
        "a label the skim cannot read as a string is not a proof of exclusion"
    );
    assert!(!filter.definitely_excluded(br#"{"metadata":{"labels":{"app":"x""#));

    let rc = ListFilter::new("", "replicationcontrollers", &terms, &fs, None);
    assert!(
        !rc.definitely_excluded(&raw(json!({"metadata": {"labels": {}}}))),
        "RC defaults inherit template labels, so raw labels prove nothing"
    );
}

/// Defaults sit between stored bytes and what LIST matches selectors on; a new defaulting arm
/// that rewrites labels, name or namespace must be added to `defaults_may_alter_labels`, or the
/// skim would exclude objects that should match.
#[test]
fn only_listed_kinds_have_defaults_that_alter_selected_metadata() {
    let state = crate::handlers::test_support::make_state_with_store(std::sync::Arc::new(
        u7s_store::SqliteStore::new(":memory:").unwrap(),
    ));
    let sample = json!({
        "apiVersion": "v1",
        "metadata": {"name": "n", "namespace": "ns", "labels": {}},
        "spec": {"template": {"metadata": {"labels": {"t": "u"}}}},
    });
    for key in state.resource_registry.keys() {
        let mut defaulted = sample.clone();
        crate::handlers::defaults::apply_defaults(&key.group, &key.plural, &mut defaulted);
        let altered = ["labels", "name", "namespace"]
            .iter()
            .any(|f| defaulted["metadata"][f] != sample["metadata"][f]);
        assert!(
            !altered
                || crate::handlers::defaults::defaults_may_alter_labels(&key.group, &key.plural),
            "{}/{} defaults change labels/name/namespace; add it to defaults_may_alter_labels",
            key.group,
            key.plural
        );
    }
}
