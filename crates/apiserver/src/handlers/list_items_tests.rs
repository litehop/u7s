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
            items: {
                let mut secrets = many("Secret", "s", 6, json!({"data": {"k": "dg=="}}));
                secrets.push(stored(labeled(
                    "Secret",
                    "s-string-data",
                    json!({"app": "app-1"}),
                    json!({"stringData": {"plain": "text"}}),
                )));
                secrets
            },
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
        Kind {
            group: "",
            plural: "nodes",
            kind: "Node",
            version: "v1",
            items: many(
                "Node",
                "node",
                4,
                json!({
                    "spec": {"podCIDR": "10.0.0.0/24", "taints": [{"key": "k", "effect": "NoSchedule"}]},
                    "status": {
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "addresses": [{"type": "InternalIP", "address": "10.0.0.1"}],
                        "capacity": {"cpu": "4"},
                    },
                }),
            ),
        },
        Kind {
            group: "",
            plural: "endpoints",
            kind: "Endpoints",
            version: "v1",
            items: many(
                "Endpoints",
                "ep",
                4,
                json!({"subsets": [{"addresses": [{"ip": "10.0.0.2"}], "ports": [{"port": 80, "protocol": "TCP"}]}]}),
            ),
        },
        Kind {
            group: "",
            plural: "events",
            kind: "Event",
            version: "v1",
            items: many(
                "Event",
                "ev",
                4,
                json!({
                    "involvedObject": {"kind": "Pod", "name": "p", "namespace": "ns1"},
                    "reason": "Started", "message": "started", "type": "Normal", "count": 2,
                    "firstTimestamp": "2026-01-02T03:04:05Z", "lastTimestamp": "2026-01-02T03:04:06Z",
                }),
            ),
        },
        Kind {
            group: "discovery.k8s.io",
            plural: "endpointslices",
            kind: "EndpointSlice",
            version: "v1",
            items: many(
                "EndpointSlice",
                "es",
                4,
                json!({
                    "addressType": "IPv4",
                    "endpoints": [{"addresses": ["10.0.0.3"], "conditions": {"ready": true}}],
                    "ports": [{"name": "http", "port": 80, "protocol": "TCP"}],
                }),
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
        "deployments" | "services" | "endpoints" | "events" => {
            vec!["", "metadata.name=d-1", "metadata.namespace=ns1"]
        }
        _ => vec!["", "metadata.name=d-1"],
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
    for (i, item) in legacy_items(k, terms, fs).iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        serde_json::to_writer(&mut body, item).unwrap();
    }
    body.push(b']');
    body.extend_from_slice(&envelope_bytes[pos + marker.len()..]);
    body
}

/// The pre-optimization survivors: every item fully parsed, defaulted and then filtered.
fn legacy_items(k: &Kind, terms: &[LabelSelectorTerm<'_>], fs: &FieldSelector) -> Vec<Value> {
    let items: Vec<Value> = k
        .items
        .iter()
        .map(|obj| {
            let mut item: Value = serde_json::from_slice(&obj.value).unwrap();
            crate::handlers::defaults::apply_defaults(k.group, k.plural, &mut item);
            item
        })
        .collect();
    fs.filter(crate::handlers::generic::apply_label_selector(items, terms))
}

fn envelope(k: &Kind) -> ListEnvelope<'static> {
    ListEnvelope {
        kind: k.kind,
        version: k.version,
        revision: 9,
        continue_key: None,
        remaining_count: Some(4),
        signing_key: &[3u8; 32],
    }
}

async fn body_of(resp: axum::response::Response) -> (Option<String>, Vec<u8>) {
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (content_type, body.to_vec())
}

/// What the pre-optimization handlers returned for a non-JSON-stream LIST: every survivor
/// materialized, then handed to the per-format builders.
fn legacy_response(
    k: &Kind,
    accept: &str,
    format: &ListFormat,
    terms: &[LabelSelectorTerm<'_>],
    fs: &FieldSelector,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let items = legacy_items(k, terms, fs);
    match format {
        ListFormat::PartialObjectMetadata => axum::Json(json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": "9" },
            "items": items.iter().map(crate::handlers::watch::to_partial_object_metadata).collect::<Vec<_>>(),
        }))
        .into_response(),
        ListFormat::Table { api_version } => {
            let built = crate::handlers::table::build_table(k.group, k.plural, items);
            axum::Json(crate::handlers::table::finalize_table(
                built,
                api_version,
                Some("9"),
                None,
            ))
            .into_response()
        }
        ListFormat::Protobuf => crate::content_type::negotiated_response(
            accept,
            crate::handlers::generic::build_list_response(
                k.kind,
                k.group,
                k.version,
                9,
                items,
                None,
                Some(4),
                &[3u8; 32],
            ),
        ),
    }
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
                let actual = filter.render_json(&k.items, envelope(&k)).unwrap();
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

/// Protobuf maps (labels, annotations) are emitted in `HashMap` iteration order, which differs
/// between two encodes of the same object even within one process, so two encodings of the same
/// list are compared decoded. `content_type`'s builder test compares raw bytes on single-key maps.
fn protobuf_lists_equal(kind: &str, a: &[u8], b: &[u8]) -> bool {
    use prost::Message;
    use u7s_proto_generated::k8s::io::api::{core::v1 as core_v1, discovery::v1 as discovery_v1};
    let raw = |body: &[u8]| {
        crate::proto::decode_k8s_proto_envelope(body)
            .expect("a protobuf LIST body is a k8s envelope")
            .raw
    };
    let (a, b) = (raw(a), raw(b));
    macro_rules! decoded_eq {
        ($t:ty) => {
            <$t>::decode(a.as_slice()).unwrap() == <$t>::decode(b.as_slice()).unwrap()
        };
    }
    match kind {
        "Pod" => decoded_eq!(core_v1::PodList),
        "Service" => decoded_eq!(core_v1::ServiceList),
        "Node" => decoded_eq!(core_v1::NodeList),
        "Endpoints" => decoded_eq!(core_v1::EndpointsList),
        "Event" => decoded_eq!(core_v1::EventList),
        "EndpointSlice" => decoded_eq!(discovery_v1::EndpointSliceList),
        other => panic!("no protobuf list type registered for {other}"),
    }
}

/// kubelet and KCM decode protobuf, kubectl decodes Table and the GC reads
/// PartialObjectMetadata: each must stay byte-identical to what the materialize-everything
/// handlers produced, or an informer cache or `kubectl get` output silently changes.
#[tokio::test]
async fn protobuf_table_and_metadata_lists_are_byte_identical_to_the_materializing_path() {
    let proto_accept = "application/vnd.kubernetes.protobuf,application/json";
    let table_accept = "application/json;as=Table;v=v1;g=meta.k8s.io";
    let mut protobuf_kinds = 0;
    let mut cases = 0;
    for k in kinds() {
        let formats = [
            (ListFormat::PartialObjectMetadata, proto_accept),
            (
                ListFormat::negotiate(table_accept, false, true, k.group, k.version, k.kind)
                    .unwrap(),
                table_accept,
            ),
            (
                ListFormat::negotiate(proto_accept, false, false, k.group, k.version, k.kind)
                    .unwrap_or(ListFormat::PartialObjectMetadata),
                proto_accept,
            ),
        ];
        for ls in ["", "app=app-1", "app!=app-1,tier", "app in (app-1,app-2)"] {
            for fs in field_selectors(k.plural) {
                let terms = parse_label_selector(ls).unwrap();
                let field_selector = FieldSelector::parse(Some(fs), k.group, k.plural).unwrap();
                let filter = ListFilter::new(k.group, k.plural, &terms, &field_selector, None);
                for (format, accept) in &formats {
                    let format_name = match format {
                        ListFormat::PartialObjectMetadata => "partialObjectMetadata",
                        ListFormat::Table { .. } => "table",
                        ListFormat::Protobuf => "protobuf",
                    };
                    let expected =
                        body_of(legacy_response(&k, accept, format, &terms, &field_selector)).await;
                    let actual = body_of(
                        filter
                            .respond(Some(format.clone()), &k.items, envelope(&k))
                            .unwrap(),
                    )
                    .await;
                    assert_eq!(
                        actual.0, expected.0,
                        "{} {format_name} labelSelector={ls:?} fieldSelector={fs:?}: content type",
                        k.plural
                    );
                    let same = if matches!(format, ListFormat::Protobuf) {
                        protobuf_lists_equal(k.kind, &actual.1, &expected.1)
                    } else {
                        actual.1 == expected.1
                    };
                    assert!(
                        same,
                        "{} {format_name} labelSelector={ls:?} fieldSelector={fs:?}: bodies differ",
                        k.plural,
                    );
                    protobuf_kinds += usize::from(format_name == "protobuf");
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 300, "corpus shrank to {cases} cases");
    assert!(
        protobuf_kinds > 60,
        "protobuf was exercised in only {protobuf_kinds} cases; the registered-encoder kinds fell out of the corpus"
    );
}

/// The skim may only decide what the full matchers decide the same way; anything it cannot read
/// (non-string label values, a ReplicationController whose defaults rewrite labels) must be left
/// to the full path or a matching object disappears from the LIST.
#[test]
fn skim_decides_only_what_it_can_prove_and_defers_the_rest() {
    let terms = parse_label_selector("app=app-1").unwrap();
    let fs = FieldSelector::default();
    let filter = ListFilter::new("", "pods", &terms, &fs, None);
    let raw = |v: Value| serde_json::to_vec(&v).unwrap();
    assert!(matches!(
        filter.membership(&raw(json!({"metadata": {"labels": {"app": "other"}}}))),
        Membership::Excluded
    ));
    assert!(matches!(
        filter.membership(&raw(json!({"metadata": {"labels": {"app": "app-1"}}}))),
        Membership::Included
    ));
    assert!(
        matches!(
            filter.membership(&raw(json!({"metadata": {"labels": {"app": 1}}}))),
            Membership::Unknown
        ),
        "a label the skim cannot read as a string is not a proof either way"
    );
    assert!(matches!(
        filter.membership(br#"{"metadata":{"labels":{"app":"x""#),
        Membership::Unknown
    ));

    let rc = ListFilter::new("", "replicationcontrollers", &terms, &fs, None);
    assert!(
        matches!(
            rc.membership(&raw(json!({"metadata": {"labels": {}}}))),
            Membership::Unknown
        ),
        "RC defaults inherit template labels, so raw labels prove nothing"
    );

    let status = FieldSelector::parse(Some("status.phase=Running"), "", "pods").unwrap();
    let by_phase = ListFilter::new("", "pods", &[], &status, None);
    assert!(
        matches!(
            by_phase.membership(&raw(json!({"status": {"phase": "Running"}}))),
            Membership::Unknown
        ),
        "status.phase is outside the projection, so only the full object can answer"
    );
}

/// The speedup only exists if the cheap outcomes are actually taken: included items of a kind
/// with no defaults are served from their stored bytes, kinds with defaults and `on_item` hooks
/// still get a parsed (defaulted) object.
#[test]
fn included_items_are_served_raw_only_when_nothing_needs_the_parsed_object() {
    let fs = FieldSelector::default();
    let cm = stored(json!({"metadata": {"name": "a", "labels": {"app": "x"}}, "data": {"k": "v"}}));
    let terms = parse_label_selector("app=x").unwrap();

    let plain = ListFilter::new("", "configmaps", &terms, &fs, None);
    assert!(matches!(
        plain.select(&cm.value).unwrap(),
        Some(Selected::Raw(_))
    ));
    let none = ListFilter::new("", "configmaps", &[], &fs, None);
    assert!(matches!(
        none.select(&cm.value).unwrap(),
        Some(Selected::Raw(_))
    ));

    let defaulted = ListFilter::new("", "secrets", &terms, &fs, None);
    assert!(matches!(
        defaulted.select(&cm.value).unwrap(),
        Some(Selected::Parsed(_))
    ));

    fn hook(_: &Value) {}
    let hooked = ListFilter::new("", "configmaps", &terms, &fs, Some(hook));
    assert!(matches!(
        hooked.select(&cm.value).unwrap(),
        Some(Selected::Parsed(_))
    ));

    let miss = parse_label_selector("app=y").unwrap();
    let excluded = ListFilter::new("", "configmaps", &miss, &fs, None);
    assert!(excluded.select(&cm.value).unwrap().is_none());
}

/// `Selected::Raw` is only correct while stored bytes equal their own parse-and-reserialize.
/// The store stamps resourceVersion by re-serializing a `Value` on every put, so even a
/// client-formatted, unsorted body is persisted canonically; if that ever stopped, LIST would
/// start emitting key orders and number forms that differ from the parsed path.
#[tokio::test]
async fn the_store_persists_canonical_bytes() {
    use u7s_store::Store;
    let store = u7s_store::SqliteStore::new(":memory:").unwrap();
    let messy = br#"{ "metadata" : {"name":"a", "labels": {"z":"1","a":"2"}},
        "data": {"b": 1.0, "a": 10000000000000000000000, "e": 1e3, "u": "\u00e9\u003c"},   "kind":"ConfigMap" }"#;
    store
        .put(
            "/registry/configmaps/ns/a",
            bytes::Bytes::from_static(messy),
            Some(0),
        )
        .await
        .unwrap();
    let listed = store
        .list("/registry/configmaps/", Default::default())
        .await
        .unwrap();
    let bytes = &listed.items[0].value;
    let reserialized =
        serde_json::to_vec(&serde_json::from_slice::<Value>(bytes).unwrap()).unwrap();
    assert_eq!(bytes.as_ref(), reserialized.as_slice());
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

/// A kind missing from `defaults_apply` would be served from its stored bytes and silently lose
/// the defaulting `apply_defaults` performs (kubectl/KCM then read unset fields), so every
/// registered kind outside it must leave bare and typical objects untouched.
#[test]
fn kinds_without_defaults_are_untouched_by_apply_defaults() {
    let state = crate::handlers::test_support::make_state_with_store(std::sync::Arc::new(
        u7s_store::SqliteStore::new(":memory:").unwrap(),
    ));
    let samples = [
        json!({"apiVersion": "v1", "metadata": {"name": "n", "namespace": "ns"}}),
        json!({
            "apiVersion": "v1",
            "metadata": {"name": "n", "namespace": "ns", "labels": {"a": "b"}},
            "spec": {"selector": {}, "template": {"metadata": {}, "spec": {"containers": []}}},
            "status": {},
            "data": {},
            "stringData": {"k": "v"},
            "type": "",
        }),
    ];
    let mut with_defaults = 0;
    for key in state.resource_registry.keys() {
        if crate::handlers::defaults::defaults_apply(&key.group, &key.plural) {
            with_defaults += 1;
            continue;
        }
        for sample in &samples {
            let mut defaulted = sample.clone();
            crate::handlers::defaults::apply_defaults(&key.group, &key.plural, &mut defaulted);
            assert_eq!(
                &defaulted, sample,
                "{}/{} has defaults but is missing from defaults_apply",
                key.group, key.plural
            );
        }
    }
    assert!(
        with_defaults > 10,
        "registry walk found only {with_defaults} defaulting kinds"
    );
}
