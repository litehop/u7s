//! Server-owned metadata (creationTimestamp, deletionTimestamp, deletionGracePeriodSeconds) is
//! pinned to the stored object AFTER mutating admission on every PUT and PATCH site, as upstream
//! `rest.BeforeUpdate` does: a webhook patch or client edit cannot backdate, age-reset, or
//! terminate an object.

mod pin {
    use serde_json::{json, Value};

    use crate::handlers::generic::pin_server_owned_metadata;

    fn body(meta: Value) -> Value {
        json!({"metadata": meta})
    }

    /// Whatever the post-admission body carries, the stored value wins, so a client or webhook
    /// can neither backdate an object nor un-terminate it.
    #[test]
    fn pin_takes_every_server_owned_field_from_the_stored_object() {
        let stored = body(json!({
            "creationTimestamp": "2020-01-02T03:04:05Z",
            "deletionTimestamp": "2021-01-01T00:00:00Z",
            "deletionGracePeriodSeconds": 30,
        }));
        for (case, incoming) in [
            ("fields absent", json!({})),
            (
                "fields overwritten",
                json!({"creationTimestamp": "1999-01-01T00:00:00Z",
                    "deletionTimestamp": "1999-01-01T00:00:00Z",
                    "deletionGracePeriodSeconds": 0}),
            ),
            (
                "fields nulled",
                json!({"creationTimestamp": null, "deletionTimestamp": null,
                    "deletionGracePeriodSeconds": null}),
            ),
        ] {
            let mut obj = body(incoming);
            pin_server_owned_metadata(&mut obj, Some(&stored));
            assert_eq!(obj["metadata"], stored["metadata"], "{case}");
        }
    }

    /// A live stored object has no deletion fields: a body claiming them must lose them, or an
    /// update-only caller could terminate an object without the delete verb.
    #[test]
    fn pin_removes_deletion_fields_the_stored_object_does_not_have() {
        let stored = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z"}));
        let mut obj = body(json!({"deletionTimestamp": "2021-01-01T00:00:00Z",
            "deletionGracePeriodSeconds": 0, "name": "n"}));
        pin_server_owned_metadata(&mut obj, Some(&stored));
        assert_eq!(
            obj["metadata"],
            json!({"creationTimestamp": "2020-01-02T03:04:05Z", "name": "n"})
        );
    }

    /// Stored without creationTimestamp: the body's own value is left alone rather than erased.
    #[test]
    fn pin_keeps_body_creation_timestamp_when_stored_has_none() {
        let stored = body(json!({}));
        let mut obj = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z"}));
        pin_server_owned_metadata(&mut obj, Some(&stored));
        assert_eq!(obj["metadata"]["creationTimestamp"], "2020-01-02T03:04:05Z");
    }

    /// No stored object (create): deletion fields are cleared so nothing is born Terminating,
    /// while creationTimestamp is left for the create stamper.
    #[test]
    fn pin_without_stored_clears_deletion_fields_only() {
        let mut obj = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z",
            "deletionTimestamp": "2021-01-01T00:00:00Z", "deletionGracePeriodSeconds": 0}));
        pin_server_owned_metadata(&mut obj, None);
        assert_eq!(
            obj["metadata"],
            json!({"creationTimestamp": "2020-01-02T03:04:05Z"})
        );
    }
}

mod admission {
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    use crate::handlers::subresource_admission_tests::cases::{
        json_patch, register_webhook, spawn_hook, Cluster,
    };

    const MERGE: &str = "application/merge-patch+json";
    const JSON_PATCH: &str = "application/json-patch+json";
    const WEBHOOK_TS: &str = "1999-01-01T00:00:00Z";

    struct Target {
        name: &'static str,
        group: &'static str,
        resource: &'static str,
        uri: &'static str,
    }

    fn crd_body(plural: &str, kind: &str, name: &str, scope: &str) -> Value {
        json!({"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
            "metadata":{"name":name},
            "spec":{"group":"example.com","scope":scope,
                "names":{"plural":plural,"singular":plural,"kind":kind,
                    "listKind":format!("{kind}List")},
                "versions":[{"name":"v1","served":true,"storage":true,
                    "schema":{"openAPIV3Schema":{"type":"object",
                        "x-kubernetes-preserve-unknown-fields":true}}}]}})
    }

    async fn setup(t: &Target) -> Cluster {
        let c = Cluster::new().await;
        let crd = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions";
        match t.name {
            "pod" => c.create_pod("o").await,
            "configmap" => {
                c.create(
                    "/api/v1/namespaces/default/configmaps",
                    json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"o"},
                        "data":{"a":"1"}}),
                )
                .await
            }
            "priorityclass" => {
                c.create(
                    "/apis/scheduling.k8s.io/v1/priorityclasses",
                    json!({"apiVersion":"scheduling.k8s.io/v1","kind":"PriorityClass",
                        "metadata":{"name":"o"},"value":5}),
                )
                .await
            }
            "namespace" => {
                c.create(
                    "/api/v1/namespaces",
                    json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"o"}}),
                )
                .await
            }
            "cr" => {
                c.create(
                    crd,
                    crd_body("widgets", "Widget", "widgets.example.com", "Namespaced"),
                )
                .await;
                c.create(
                    "/apis/example.com/v1/namespaces/default/widgets",
                    json!({"apiVersion":"example.com/v1","kind":"Widget",
                        "metadata":{"name":"o"},"spec":{"a":1}}),
                )
                .await
            }
            "cluster-cr" => {
                c.create(
                    crd,
                    crd_body("gadgets", "Gadget", "gadgets.example.com", "Cluster"),
                )
                .await;
                c.create(
                    "/apis/example.com/v1/gadgets",
                    json!({"apiVersion":"example.com/v1","kind":"Gadget",
                        "metadata":{"name":"o"},"spec":{"a":1}}),
                )
                .await
            }
            "crd" => {
                c.create(crd, crd_body("os", "O", "os.example.com", "Namespaced"))
                    .await
            }
            other => unreachable!("{other}"),
        }
        c
    }

    fn targets() -> Vec<Target> {
        let t = |name, group, resource, uri| Target {
            name,
            group,
            resource,
            uri,
        };
        vec![
            t(
                "configmap",
                "",
                "configmaps",
                "/api/v1/namespaces/default/configmaps/o",
            ),
            t(
                "priorityclass",
                "scheduling.k8s.io",
                "priorityclasses",
                "/apis/scheduling.k8s.io/v1/priorityclasses/o",
            ),
            t("pod", "", "pods", "/api/v1/namespaces/default/pods/o"),
            t("namespace", "", "namespaces", "/api/v1/namespaces/o"),
            t(
                "cr",
                "example.com",
                "widgets",
                "/apis/example.com/v1/namespaces/default/widgets/o",
            ),
            t(
                "cluster-cr",
                "example.com",
                "gadgets",
                "/apis/example.com/v1/gadgets/o",
            ),
            t(
                "crd",
                "apiextensions.k8s.io",
                "customresourcedefinitions",
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/os.example.com",
            ),
        ]
    }

    async fn get(c: &Cluster, uri: &str) -> Value {
        c.call("GET", uri, "application/json", Value::Null).await.1
    }

    /// A mutating webhook that strips creationTimestamp and marks the object deleted must not
    /// win: the persisted object keeps its age and stays live. Covers every PUT and PATCH site
    /// that runs mutating webhooks (generic namespaced/cluster, pod, namespace, CR, CRD).
    #[tokio::test]
    async fn mutating_webhook_cannot_clear_creation_or_set_deletion_metadata() {
        let mut violations = Vec::new();
        for t in targets() {
            for verb in ["PUT", "PATCH"] {
                let c = setup(&t).await;
                let before = get(&c, t.uri).await;
                let created = before["metadata"]["creationTimestamp"].clone();
                assert!(
                    created.is_string(),
                    "{} {verb}: seeded object has an age",
                    t.name
                );

                let hook = spawn_hook(json_patch(json!([
                    {"op":"remove","path":"/metadata/creationTimestamp"},
                    {"op":"add","path":"/metadata/deletionTimestamp","value":WEBHOOK_TS},
                    {"op":"add","path":"/metadata/deletionGracePeriodSeconds","value":0},
                ])))
                .await;
                register_webhook(
                    &c.store,
                    true,
                    "strip",
                    &hook.url,
                    t.group,
                    &[t.resource],
                    &["UPDATE"],
                )
                .await;

                let (status, resp) = if verb == "PUT" {
                    let mut body = before.clone();
                    body["metadata"]["labels"] = json!({"x": "y"});
                    c.call("PUT", t.uri, "application/json", body).await
                } else {
                    c.call(
                        "PATCH",
                        t.uri,
                        MERGE,
                        json!({"metadata":{"labels":{"x":"y"}}}),
                    )
                    .await
                };
                assert_eq!(status, StatusCode::OK, "{} {verb}: {resp}", t.name);
                assert_eq!(hook.requests().len(), 1, "{} {verb}: webhook ran", t.name);

                let m = &get(&c, t.uri).await["metadata"];
                if m["labels"]["x"] != "y"
                    || m["creationTimestamp"] != created
                    || !m["deletionTimestamp"].is_null()
                    || !m["deletionGracePeriodSeconds"].is_null()
                {
                    violations.push(format!("{} {verb}: {m}", t.name));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "webhook overrode server-owned metadata: {violations:#?}"
        );
    }

    /// RFC 6902 `remove` of /metadata/creationTimestamp is a client trying to erase the
    /// object's age; the stored value wins.
    #[tokio::test]
    async fn json_patch_remove_of_creation_timestamp_keeps_the_stored_value() {
        // Namespaces only accept merge patches.
        for t in targets().into_iter().filter(|t| t.name != "namespace") {
            let c = setup(&t).await;
            let created = get(&c, t.uri).await["metadata"]["creationTimestamp"].clone();
            let (status, resp) = c
                .call(
                    "PATCH",
                    t.uri,
                    JSON_PATCH,
                    json!([{"op":"remove","path":"/metadata/creationTimestamp"}]),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{}: {resp}", t.name);
            assert_eq!(
                get(&c, t.uri).await["metadata"]["creationTimestamp"],
                created,
                "{}",
                t.name
            );
        }
    }
}
