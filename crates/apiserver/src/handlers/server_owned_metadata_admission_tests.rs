//! Server-owned metadata (creationTimestamp, deletionTimestamp, deletionGracePeriodSeconds) is
//! pinned to the stored object AFTER mutating admission on every PUT and PATCH site, as upstream
//! `rest.BeforeUpdate` does: a webhook patch or client edit cannot backdate, age-reset, or
//! terminate an object. What `BeforeUpdate` does not pin and `ValidateObjectMetaUpdate` rejects
//! (a changed uid, a deletionTimestamp or grace period on a live object) is a 422.

mod pin {
    use serde_json::{json, Value};

    use crate::handlers::generic::pin_server_owned_metadata;

    fn body(meta: Value) -> Value {
        json!({"metadata": meta})
    }

    fn pin(obj: &mut Value, stored: &Value) -> Result<(), crate::status::StatusError> {
        pin_server_owned_metadata(obj, Some(stored), "example.com", "Widget")
    }

    /// Whatever the post-admission body carries, the stored creation/deletion timestamps win, so
    /// a client or webhook can neither backdate an object nor un-terminate it.
    #[test]
    fn pin_takes_timestamps_from_the_stored_object() {
        let stored = body(json!({
            "creationTimestamp": "2020-01-02T03:04:05Z",
            "deletionTimestamp": "2021-01-01T00:00:00Z",
            "deletionGracePeriodSeconds": 30,
            "uid": "u1",
        }));
        for (case, incoming) in [
            ("fields absent", json!({})),
            (
                "timestamps overwritten",
                json!({"creationTimestamp": "1999-01-01T00:00:00Z",
                    "deletionTimestamp": "1999-01-01T00:00:00Z",
                    "deletionGracePeriodSeconds": 30}),
            ),
            (
                "fields nulled",
                json!({"creationTimestamp": null, "deletionTimestamp": null,
                    "deletionGracePeriodSeconds": null, "uid": null}),
            ),
        ] {
            let mut obj = body(incoming);
            pin(&mut obj, &stored).unwrap_or_else(|e| panic!("{case}: {e:?}"));
            assert_eq!(obj["metadata"], stored["metadata"], "{case}");
        }
    }

    /// A live stored object has no deletion fields: a body claiming them is upstream's 422, or an
    /// update-only caller could terminate an object without the delete verb.
    #[test]
    fn pin_rejects_deletion_fields_the_stored_object_does_not_have() {
        let stored = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z", "uid": "u1"}));
        for (field, value) in [
            ("deletionTimestamp", json!("2021-01-01T00:00:00Z")),
            ("deletionGracePeriodSeconds", json!(0)),
        ] {
            let mut obj = body(json!({ field: value, "name": "n" }));
            let err = pin(&mut obj, &stored).expect_err(field);
            assert_eq!(
                err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "{field}"
            );
            assert!(
                err.1.message.contains(&format!("metadata.{field}"))
                    && err.1.message.contains("field is immutable"),
                "{field}: {}",
                err.1.message
            );
        }
    }

    /// A different grace period on a terminating object is rejected, not overwritten: the client
    /// would otherwise believe it had shortened or extended the termination.
    #[test]
    fn pin_rejects_a_changed_grace_period() {
        let stored = body(json!({"deletionTimestamp": "2021-01-01T00:00:00Z",
            "deletionGracePeriodSeconds": 30}));
        let mut obj = body(json!({"deletionGracePeriodSeconds": 0}));
        let err = pin(&mut obj, &stored).expect_err("grace period change");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// A blank uid takes the stored one; a different uid is the 422 whose cause the scheduler
    /// and clients key on (`metadata.uid`, reason FieldValueInvalid).
    #[test]
    fn pin_fills_a_blank_uid_and_rejects_a_different_one() {
        let stored = body(json!({"uid": "u1", "name": "w"}));
        let mut blank = body(json!({"uid": ""}));
        pin(&mut blank, &stored).unwrap();
        assert_eq!(blank["metadata"]["uid"], "u1");

        let mut other = body(json!({"uid": "u2"}));
        let err = pin(&mut other, &stored).expect_err("changed uid");
        assert_eq!(err.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            err.1.message,
            "Widget.example.com \"w\" is invalid: metadata.uid: Invalid value: \"u2\": field is immutable"
        );
        let details = err.1.details.expect("details");
        assert_eq!(details["causes"][0]["field"], "metadata.uid");
        assert_eq!(details["causes"][0]["reason"], "FieldValueInvalid");
    }

    /// Stored without creationTimestamp: the body's own value is left alone rather than erased.
    #[test]
    fn pin_keeps_body_creation_timestamp_when_stored_has_none() {
        let stored = body(json!({}));
        let mut obj = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z"}));
        pin(&mut obj, &stored).unwrap();
        assert_eq!(obj["metadata"]["creationTimestamp"], "2020-01-02T03:04:05Z");
    }

    /// No stored object (create): deletion fields are cleared so nothing is born Terminating,
    /// while creationTimestamp is left for the create stamper.
    #[test]
    fn pin_without_stored_clears_deletion_fields_only() {
        let mut obj = body(json!({"creationTimestamp": "2020-01-02T03:04:05Z",
            "deletionTimestamp": "2021-01-01T00:00:00Z", "deletionGracePeriodSeconds": 0}));
        pin_server_owned_metadata(&mut obj, None, "", "Pod").unwrap();
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

    pub(super) struct Target {
        pub(super) name: &'static str,
        pub(super) group: &'static str,
        pub(super) resource: &'static str,
        pub(super) uri: &'static str,
    }

    fn crd_body(plural: &str, kind: &str, name: &str, scope: &str) -> Value {
        json!({"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
            "metadata":{"name":name},
            "spec":{"group":"example.com","scope":scope,
                "names":{"plural":plural,"singular":plural,"kind":kind,
                    "listKind":format!("{kind}List")},
                "versions":[{"name":"v1","served":true,"storage":true,
                    "schema":{"openAPIV3Schema":{"type":"object",
                        "x-kubernetes-preserve-unknown-fields":true}},
                    "subresources":{"status":{}}}]}})
    }

    pub(super) async fn setup(t: &Target) -> Cluster {
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
            "resourcequota" => {
                c.create(
                    "/api/v1/namespaces/default/resourcequotas",
                    json!({"apiVersion":"v1","kind":"ResourceQuota","metadata":{"name":"o"},
                        "spec":{"hard":{"pods":"10"}}}),
                )
                .await
            }
            "pv" => {
                c.create(
                    "/api/v1/persistentvolumes",
                    json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"o"},
                        "spec":{"capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"],
                            "hostPath":{"path":"/tmp/o"}}}),
                )
                .await
            }
            "node" => {
                c.create(
                    "/api/v1/nodes",
                    json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"o"}}),
                )
                .await
            }
            "service" => {
                c.create(
                    "/api/v1/namespaces/default/services",
                    json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"o"},
                        "spec":{"ports":[{"port":80}]}}),
                )
                .await
            }
            "deployment" => {
                let labels = json!({"app":"o"});
                c.create(
                    "/apis/apps/v1/namespaces/default/deployments",
                    json!({"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"o"},
                        "spec":{"selector":{"matchLabels":labels},
                            "template":{"metadata":{"labels":labels},
                                "spec":{"containers":[{"name":"c","image":"i"}]}}}}),
                )
                .await
            }
            other => unreachable!("{other}"),
        }
        c
    }

    pub(super) fn targets() -> Vec<Target> {
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
            t(
                "resourcequota",
                "",
                "resourcequotas",
                "/api/v1/namespaces/default/resourcequotas/o",
            ),
            t("pv", "", "persistentvolumes", "/api/v1/persistentvolumes/o"),
            t("node", "", "nodes", "/api/v1/nodes/o"),
            t(
                "service",
                "",
                "services",
                "/api/v1/namespaces/default/services/o",
            ),
            t(
                "deployment",
                "apps",
                "deployments",
                "/apis/apps/v1/namespaces/default/deployments/o",
            ),
        ]
    }

    pub(super) async fn get(c: &Cluster, uri: &str) -> Value {
        c.call("GET", uri, "application/json", Value::Null).await.1
    }

    /// A mutating webhook that strips creationTimestamp must not win: the persisted object keeps
    /// its age. Covers every PUT and PATCH site that runs mutating webhooks (generic
    /// namespaced/cluster, pod, namespace, CR, CRD).
    #[tokio::test]
    async fn mutating_webhook_cannot_clear_creation_timestamp() {
        webhook_edits_server_owned_metadata(
            json!([{"op":"remove","path":"/metadata/creationTimestamp"}]),
            StatusCode::OK,
        )
        .await;
    }

    /// A mutating webhook that marks the object deleted gets upstream's 422 from `BeforeUpdate`'s
    /// validation, and the object stays live.
    #[tokio::test]
    async fn mutating_webhook_setting_deletion_metadata_is_rejected() {
        webhook_edits_server_owned_metadata(
            json!([
                {"op":"add","path":"/metadata/deletionTimestamp","value":"1999-01-01T00:00:00Z"},
                {"op":"add","path":"/metadata/deletionGracePeriodSeconds","value":0},
            ]),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    /// A mutating webhook that rewrites uid would let an admission plugin re-identify an object;
    /// upstream's `BeforeUpdate` validation rejects it with a 422 and the stored uid stays.
    #[tokio::test]
    async fn mutating_webhook_rewriting_uid_is_rejected() {
        webhook_edits_server_owned_metadata(
            json!([{"op":"replace","path":"/metadata/uid","value":"forged-uid"}]),
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }

    async fn webhook_edits_server_owned_metadata(ops: Value, expected: StatusCode) {
        let mut violations = Vec::new();
        for t in targets() {
            for verb in ["PUT", "PATCH"] {
                let c = setup(&t).await;
                let before = get(&c, t.uri).await;
                let created = before["metadata"]["creationTimestamp"].clone();
                let uid = before["metadata"]["uid"].clone();
                assert!(
                    created.is_string(),
                    "{} {verb}: seeded object has an age",
                    t.name
                );

                let hook = spawn_hook(json_patch(ops.clone())).await;
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
                assert_eq!(status, expected, "{} {verb}: {resp}", t.name);
                assert_eq!(hook.requests().len(), 1, "{} {verb}: webhook ran", t.name);

                let m = &get(&c, t.uri).await["metadata"];
                if (expected == StatusCode::OK && m["labels"]["x"] != "y")
                    || m["creationTimestamp"] != created
                    || m["uid"] != uid
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

/// Upstream `rest.BeforeUpdate` + `ValidateObjectMetaUpdate`, applied to a client write on every
/// resource family x endpoint x verb: a changed `metadata.uid` is a 422 for a PATCH and a 409
/// precondition for a PUT; `deletionTimestamp` / `deletionGracePeriodSeconds` on a live object are
/// a 422. A strategy that resets the field before validation (custom-resource and pod status
/// writes) ignores it instead. In every case the stored object stays unchanged.
mod immutable {
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    use super::admission::{get, setup, targets, Target};

    const FORGED_UID: &str = "forged-uid";
    const DELETION_TS: &str = "2030-01-01T00:00:00Z";

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Verb {
        Put,
        Merge,
        Strategic,
        Json,
        Apply,
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Field {
        Uid,
        DeletionTimestamp,
        GracePeriod,
    }

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Want {
        /// 422 `field is immutable`.
        Invalid,
        /// 409 storage precondition (PUT's body uid).
        Conflict,
        /// 200, the strategy resets the field; the stored value is untouched.
        Ignored,
        /// The endpoint does not accept this verb: any 4xx but never a stored change.
        Unsupported,
    }

    const VERBS: [Verb; 5] = [
        Verb::Put,
        Verb::Merge,
        Verb::Strategic,
        Verb::Json,
        Verb::Apply,
    ];
    const FIELDS: [Field; 3] = [Field::Uid, Field::DeletionTimestamp, Field::GracePeriod];

    fn field_json(field: Field) -> (&'static str, Value) {
        match field {
            Field::Uid => ("uid", json!(FORGED_UID)),
            Field::DeletionTimestamp => ("deletionTimestamp", json!(DELETION_TS)),
            Field::GracePeriod => ("deletionGracePeriodSeconds", json!(0)),
        }
    }

    fn is_custom(t: &Target) -> bool {
        t.group == "example.com"
    }

    fn has_status(t: &Target) -> bool {
        !matches!(t.name, "configmap" | "priorityclass")
    }

    /// What upstream does, derived from `BeforeUpdate` and each status strategy's
    /// `PrepareForUpdate` (custom resources and `*/status` of kinds that reset `metadata`).
    fn want(t: &Target, status: bool, verb: Verb, field: Field) -> Want {
        if !status {
            let accepted = match t.name {
                // Namespaces accept merge patches only on this rig; CRs have no strategic merge.
                "namespace" => matches!(verb, Verb::Put | Verb::Merge),
                "cr" | "cluster-cr" => verb != Verb::Strategic,
                _ => true,
            };
            if !accepted {
                return Want::Unsupported;
            }
            return match (verb, field) {
                (Verb::Put, Field::Uid) => Want::Conflict,
                _ => Want::Invalid,
            };
        }
        if verb == Verb::Json {
            // A JSON Patch on /status may only target /status paths; pods/status takes none.
            return if t.name == "pod" {
                Want::Unsupported
            } else {
                Want::Invalid
            };
        }
        if is_custom(t) {
            return Want::Ignored;
        }
        match (verb, field) {
            (Verb::Put, Field::Uid) => Want::Conflict,
            (_, Field::DeletionTimestamp) if t.name == "pod" => Want::Ignored,
            _ => Want::Invalid,
        }
    }

    async fn write(
        c: &Cluster,
        t: &Target,
        status: bool,
        verb: Verb,
        field: Field,
    ) -> (StatusCode, Value) {
        let (name, value) = field_json(field);
        let uri = if status {
            format!("{}/status", t.uri)
        } else {
            t.uri.to_owned()
        };
        let live = get(c, t.uri).await;
        let meta_patch = json!({ "metadata": { name: value } });
        match verb {
            Verb::Put => {
                let mut body = live;
                body["metadata"][name] = value;
                c.call("PUT", &uri, "application/json", body).await
            }
            Verb::Merge => {
                c.call("PATCH", &uri, "application/merge-patch+json", meta_patch)
                    .await
            }
            Verb::Strategic => {
                c.call(
                    "PATCH",
                    &uri,
                    "application/strategic-merge-patch+json",
                    meta_patch,
                )
                .await
            }
            Verb::Json => {
                let ops = json!([{"op":"add","path":format!("/metadata/{name}"),"value":value}]);
                c.call("PATCH", &uri, "application/json-patch+json", ops)
                    .await
            }
            Verb::Apply => {
                let body = json!({"apiVersion": live["apiVersion"], "kind": live["kind"],
                    "metadata": { "name": live["metadata"]["name"], name: value }});
                c.call("PATCH", &uri, "application/apply-patch+yaml", body)
                    .await
            }
        }
    }

    use crate::handlers::subresource_admission_tests::cases::Cluster;

    /// The guard runs at the one convergence point every update site funnels through, so every
    /// cell must hold; a cell that regresses lets a client forge identity (stale ownerReference
    /// matching, recreate detection) or terminate an object without the delete verb.
    #[tokio::test]
    async fn client_changed_immutable_metadata_matrix() {
        let mut failures = Vec::new();
        let mut cells = 0;
        for t in targets() {
            let c = setup(&t).await;
            for status in [false, true] {
                if status && !has_status(&t) {
                    continue;
                }
                for verb in VERBS {
                    for field in FIELDS {
                        let before = get(&c, t.uri).await["metadata"].clone();
                        let (code, resp) = write(&c, &t, status, verb, field).await;
                        let want = want(&t, status, verb, field);
                        let ok = match want {
                            Want::Invalid => code == StatusCode::UNPROCESSABLE_ENTITY,
                            Want::Conflict => code == StatusCode::CONFLICT,
                            Want::Ignored => code == StatusCode::OK,
                            Want::Unsupported => code.is_client_error(),
                        };
                        let after = get(&c, t.uri).await["metadata"].clone();
                        let unchanged = ["uid", "deletionTimestamp", "deletionGracePeriodSeconds"]
                            .iter()
                            .all(|k| before[*k] == after[*k]);
                        let cell = format!(
                            "{} {} {verb:?} {field:?}",
                            t.name,
                            if status { "status" } else { "main" }
                        );
                        if !ok || !unchanged {
                            failures.push(format!(
                                "{cell}: want {want:?}, got {code} {resp} (unchanged={unchanged})"
                            ));
                        }
                        if want == Want::Invalid && ok {
                            let msg = resp["message"].as_str().unwrap_or_default();
                            let is_status_json = status && verb == Verb::Json;
                            if !is_status_json && !msg.contains("field is immutable") {
                                failures
                                    .push(format!("{cell}: 422 without immutable cause: {msg}"));
                            }
                        }
                        if want == Want::Conflict && ok {
                            let msg = resp["message"].as_str().unwrap_or_default();
                            let stored_uid = before["uid"].as_str().unwrap_or_default();
                            // /status PUT carries upstream's storage-precondition text; the main
                            // PUT sites still word the same 409 their own way.
                            let cause_ok = if status {
                                msg.starts_with("Operation cannot be fulfilled on ")
                                    && msg.contains(&format!(
                                        "Precondition failed: UID in precondition: \
                                         {FORGED_UID}, UID in object meta: {stored_uid}"
                                    ))
                            } else {
                                msg.contains(FORGED_UID) && msg.contains(stored_uid)
                            };
                            if resp["reason"] != "Conflict" || !cause_ok {
                                failures.push(format!(
                                    "{cell}: 409 without the uid precondition cause: {resp}"
                                ));
                            }
                        }
                        cells += 1;
                    }
                }
            }
        }
        assert!(cells > 200, "matrix shrank to {cells} cells");
        assert!(
            failures.is_empty(),
            "{} of {cells} cells:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// An unchanged uid or an absent metadata block must keep working: kubelet and controllers
    /// PATCH with the uid they read.
    #[tokio::test]
    async fn matching_uid_is_accepted_on_every_patch_endpoint() {
        for t in targets() {
            let c = setup(&t).await;
            for status in [false, true] {
                if status && !has_status(&t) {
                    continue;
                }
                let uri = if status {
                    format!("{}/status", t.uri)
                } else {
                    t.uri.to_owned()
                };
                let uid = get(&c, t.uri).await["metadata"]["uid"].clone();
                let key = if status { "from-status" } else { "from-main" };
                let (code, resp) = c
                    .call(
                        "PATCH",
                        &uri,
                        "application/merge-patch+json",
                        json!({"metadata": {"uid": uid, "annotations": {key: "v"}}}),
                    )
                    .await;
                assert_eq!(code, StatusCode::OK, "{} status={status}: {resp}", t.name);
                let stored = &get(&c, t.uri).await["metadata"];
                assert_eq!(
                    stored["uid"], uid,
                    "{} status={status}: identity must survive a write that echoes it",
                    t.name
                );
                // A custom resource's /status strategy resets metadata, so only the main
                // endpoint (and built-in status endpoints) may persist the annotation.
                let lands = !(status && is_custom(&t));
                assert_eq!(
                    stored["annotations"][key] == "v",
                    lands,
                    "{} status={status}: non-identity metadata in a matching-uid write must \
                     land exactly when the strategy keeps client metadata: {stored}",
                    t.name
                );
            }
        }
    }
}
