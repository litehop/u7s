//! Rejects namespaced writes whose body names a different namespace than the request path.
//!
//! Upstream returns 400 for a body `metadata.namespace` that differs from the URL; an empty
//! one is filled from the URL by the handlers. Enforcing it in one layer in front of every
//! route covers all present and future write handlers (built-ins, CRs, subresources, every
//! patch type and server-side apply) instead of relying on each handler to remember.

use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    handlers::json_patch::{json_pointer_segments, ssa_body_to_json},
    status::Status,
};

const MISMATCH: &str =
    "the namespace of the provided object does not match the namespace sent on the request";

/// The namespace segment of a namespaced object-write path, or `None` for paths whose body is
/// not an object in that namespace (the Namespace object itself and its status/finalize
/// subresources, and the opaque proxy/exec/attach/portforward streams).
fn request_namespace(path: &str) -> Option<&str> {
    let mut seg = path.trim_start_matches('/').split('/');
    match seg.next()? {
        "api" => seg.next()?,
        "apis" => {
            seg.next()?;
            seg.next()?
        }
        _ => return None,
    };
    if seg.next()? != "namespaces" {
        return None;
    }
    let ns = seg.next()?;
    let rest: Vec<&str> = seg.collect();
    match rest.as_slice() {
        [] | ["status"] | ["finalize"] => None,
        [_, _, "proxy" | "exec" | "attach" | "portforward", ..] => None,
        _ => Some(ns),
    }
}

fn namespace_conflicts(meta_ns: &serde_json::Value, ns: &str) -> bool {
    match meta_ns {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.is_empty() && s != ns,
        _ => true,
    }
}

fn object_conflicts(obj: &serde_json::Value, ns: &str) -> bool {
    namespace_conflicts(&obj["metadata"]["namespace"], ns)
}

/// Whether a patch body would set `metadata.namespace` to something other than `ns`.
/// A merge/strategic patch (or apply configuration) is an object that must not carry a
/// different namespace, nor null it out; a JSON patch is judged per operation target.
fn patch_conflicts(patch: &serde_json::Value, ns: &str) -> bool {
    let Some(ops) = patch.as_array() else {
        let meta = patch.get("metadata");
        return object_conflicts(patch, ns)
            || meta.is_some_and(|m| m.is_null())
            || meta
                .and_then(|m| m.get("namespace"))
                .is_some_and(|n| n.is_null());
    };
    ops.iter().any(|op| {
        let kind = op["op"].as_str().unwrap_or_default();
        if kind == "test" {
            return false;
        }
        let Some(path) = op["path"].as_str() else {
            return false;
        };
        let segs = json_pointer_segments(path);
        let value = &op["value"];
        let removes = kind == "remove";
        match segs.as_slice() {
            [] => removes || !value.is_object() || object_conflicts(value, ns),
            [m] if m == "metadata" => {
                removes
                    || !value.is_object()
                    || value
                        .as_object()
                        .is_some_and(|o| o.contains_key("namespace"))
                        && namespace_conflicts(&value["namespace"], ns)
            }
            [m, n] if m == "metadata" && n == "namespace" => removes || value.as_str() != Some(ns),
            _ => false,
        }
    })
}

fn body_conflicts(method: &Method, content_type: &str, body: &[u8], ns: &str) -> bool {
    let is_patch = *method == Method::PATCH;
    let value = if content_type.contains("application/apply-patch+yaml") {
        ssa_body_to_json(body).ok()
    } else if content_type.starts_with("application/vnd.kubernetes.protobuf") {
        let raw = bytes::Bytes::copy_from_slice(body);
        crate::util::extract_body_quiet(&raw, content_type)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    } else {
        serde_json::from_slice(body).ok()
    };
    let Some(value) = value else {
        // Unparseable bodies are the handler's to reject with its own precise error.
        return false;
    };
    if is_patch {
        patch_conflicts(&value, ns)
    } else {
        object_conflicts(&value, ns)
    }
}

pub(crate) async fn guard(req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::POST | Method::PUT | Method::PATCH) {
        return next.run(req).await;
    }
    let Some(ns) = request_namespace(req.uri().path()).map(str::to_owned) else {
        return next.run(req).await;
    };
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, crate::MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let content_type = crate::util::content_type(&parts.headers).to_owned();
    if body_conflicts(&parts.method, &content_type, &bytes, &ns) {
        return Status::bad_request(MISMATCH.into()).into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_object_write_paths_are_guarded() {
        assert_eq!(request_namespace("/api/v1/namespaces/a/pods"), Some("a"));
        assert_eq!(
            request_namespace("/api/v1/namespaces/a/pods/p/binding"),
            Some("a")
        );
        assert_eq!(
            request_namespace("/apis/rbac.authorization.k8s.io/v1/namespaces/a/rolebindings/x"),
            Some("a")
        );
        // The Namespace object's own metadata has no metadata.namespace; proxy bodies are opaque
        // payloads for the backend, so a guard there would reject legitimate traffic.
        assert_eq!(request_namespace("/api/v1/namespaces/a"), None);
        assert_eq!(request_namespace("/api/v1/namespaces/a/finalize"), None);
        assert_eq!(
            request_namespace("/api/v1/namespaces/a/pods/p/proxy/x"),
            None
        );
        assert_eq!(request_namespace("/api/v1/pods"), None);
    }

    #[test]
    fn json_patch_cannot_retarget_namespace() {
        let c = |p: serde_json::Value| patch_conflicts(&p, "a");
        assert!(c(
            json!([{"op":"replace","path":"/metadata/namespace","value":"b"}])
        ));
        assert!(c(json!([{"op":"remove","path":"/metadata/namespace"}])));
        assert!(c(
            json!([{"op":"replace","path":"/metadata","value":{"namespace":"b"}}])
        ));
        assert!(c(
            json!([{"op":"replace","path":"","value":{"metadata":{"namespace":"b"}}}])
        ));
        assert!(!c(
            json!([{"op":"replace","path":"/metadata/namespace","value":"a"}])
        ));
        assert!(!c(
            json!([{"op":"add","path":"/metadata/labels/x","value":"b"}])
        ));
    }

    #[test]
    fn merge_patch_cannot_null_or_change_namespace() {
        let c = |p: serde_json::Value| patch_conflicts(&p, "a");
        assert!(c(json!({"metadata":{"namespace":"b"}})));
        assert!(c(json!({"metadata":{"namespace":null}})));
        assert!(c(json!({"metadata":null})));
        assert!(!c(json!({"metadata":{"namespace":"a","labels":{"x":"y"}}})));
        assert!(!c(json!({"data":{"namespace":"b"}})));
    }

    mod routed {
        use super::*;
        use crate::handlers::test_support::{install_namespaced_crd, make_state, seed_namespace};
        use crate::rbac::AuthzRequest;
        use axum::http::{header::CONTENT_TYPE, Request};
        use tower::ServiceExt as _;

        const RBAC: &str = "rbac.authorization.k8s.io";

        async fn send(
            state: &crate::state::AppState,
            method: &str,
            uri: &str,
            content_type: &str,
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value) {
            let app =
                crate::build_router(state.clone()).layer(axum::Extension(crate::auth::UserInfo {
                    username: "carol".into(),
                    ..Default::default()
                }));
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header(CONTENT_TYPE, content_type)
                .body(Body::from(body.to_string()))
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, serde_json::from_slice(&bytes).unwrap_or_default())
        }

        fn rolebinding(meta_ns: Option<&str>) -> serde_json::Value {
            let mut meta = json!({"name": "rb"});
            if let Some(ns) = meta_ns {
                meta["namespace"] = json!(ns);
            }
            json!({"apiVersion": format!("{RBAC}/v1"), "kind": "RoleBinding", "metadata": meta,
                   "subjects": [{"kind": "User", "name": "carol"}],
                   "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": "r"}})
        }

        fn assert_mismatch(r: (StatusCode, serde_json::Value), what: &str) {
            assert_eq!(
                r.0,
                StatusCode::BAD_REQUEST,
                "{what}: a body naming another namespace must be rejected, else a namespace \
                 admin writes objects (e.g. RoleBindings) into kube-system: {}",
                r.1
            );
            assert_eq!(r.1["message"], MISMATCH, "{what}");
        }

        #[tokio::test]
        async fn rolebinding_body_namespace_mismatch_rejected_on_every_write_verb() {
            let state = make_state();
            seed_namespace(&state, "a").await;
            let url = format!("/apis/{RBAC}/v1/namespaces/a/rolebindings");
            let json_ct = "application/json";
            assert_mismatch(
                send(
                    &state,
                    "POST",
                    &url,
                    json_ct,
                    rolebinding(Some("kube-system")),
                )
                .await,
                "create",
            );
            let named = format!("{url}/rb");
            assert_mismatch(
                send(
                    &state,
                    "PUT",
                    &named,
                    json_ct,
                    rolebinding(Some("kube-system")),
                )
                .await,
                "update/create-via-PUT",
            );
            let ns_patch = json!({"metadata": {"namespace": "kube-system"}});
            assert_mismatch(
                send(
                    &state,
                    "PATCH",
                    &named,
                    "application/merge-patch+json",
                    ns_patch.clone(),
                )
                .await,
                "JSON merge patch",
            );
            assert_mismatch(
                send(
                    &state,
                    "PATCH",
                    &named,
                    "application/strategic-merge-patch+json",
                    ns_patch,
                )
                .await,
                "strategic merge patch",
            );
            assert_mismatch(
                send(
                    &state,
                    "PATCH",
                    &named,
                    "application/json-patch+json",
                    json!([{"op": "replace", "path": "/metadata/namespace", "value": "kube-system"}]),
                )
                .await,
                "JSON patch",
            );
            assert_mismatch(
                send(
                    &state,
                    "PATCH",
                    &format!("{named}?fieldManager=m"),
                    "application/apply-patch+yaml",
                    rolebinding(Some("kube-system")),
                )
                .await,
                "server-side apply",
            );
        }

        #[tokio::test]
        async fn body_namespace_mismatch_rejected_for_custom_resources_and_subresources() {
            let state = make_state();
            seed_namespace(&state, "a").await;
            install_namespaced_crd(&state, "ex.io", "v1", "widgets", "Widget").await;
            let cr = json!({"apiVersion": "ex.io/v1", "kind": "Widget",
                            "metadata": {"name": "w", "namespace": "kube-system"}});
            let base = "/apis/ex.io/v1/namespaces/a/widgets";
            assert_mismatch(
                send(&state, "POST", base, "application/json", cr.clone()).await,
                "CR create",
            );
            assert_mismatch(
                send(
                    &state,
                    "PUT",
                    &format!("{base}/w"),
                    "application/json",
                    cr.clone(),
                )
                .await,
                "CR update",
            );
            assert_mismatch(
                send(
                    &state,
                    "PUT",
                    &format!("{base}/w/status"),
                    "application/json",
                    cr.clone(),
                )
                .await,
                "CR status",
            );
            assert_mismatch(
                send(
                    &state,
                    "PATCH",
                    &format!("{base}/w"),
                    "application/apply-patch+yaml",
                    cr,
                )
                .await,
                "CR apply",
            );
            let binding = json!({"apiVersion": "v1", "kind": "Binding",
                "metadata": {"name": "p", "namespace": "kube-system"},
                "target": {"kind": "Node", "name": "n"}});
            assert_mismatch(
                send(
                    &state,
                    "POST",
                    "/api/v1/namespaces/a/pods/p/binding",
                    "application/json",
                    binding,
                )
                .await,
                "pods/binding subresource",
            );
        }

        #[tokio::test]
        async fn empty_or_matching_body_namespace_is_accepted_and_stamped_from_the_url() {
            let state = make_state();
            seed_namespace(&state, "a").await;
            for meta_ns in [None, Some(""), Some("a")] {
                let mut cm = json!({"apiVersion": "v1", "kind": "ConfigMap",
                                    "metadata": {"name": format!("cm-{}", meta_ns.unwrap_or("none").len())}});
                if let Some(ns) = meta_ns {
                    cm["metadata"]["namespace"] = json!(ns);
                }
                let (status, body) = send(
                    &state,
                    "POST",
                    "/api/v1/namespaces/a/configmaps",
                    "application/json",
                    cm,
                )
                .await;
                assert_eq!(status, StatusCode::CREATED, "{meta_ns:?}: {body}");
                assert_eq!(
                    body["metadata"]["namespace"], "a",
                    "{meta_ns:?}: an omitted namespace must be filled from the URL"
                );
            }
        }

        #[tokio::test]
        async fn namespace_admin_cannot_bind_a_clusterrole_in_another_namespace() {
            let state = make_state();
            seed_namespace(&state, "a").await;
            seed_namespace(&state, "b").await;
            let idx = &state.rbac_index;
            idx.apply_object(
                &format!("/apis/{RBAC}/v1/namespaces/a/roles/carol-role"),
                &json!({"rules": [
                    {"apiGroups": [RBAC], "resources": ["rolebindings"], "verbs": ["create"]},
                    {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}),
            );
            idx.apply_object(
                &format!("/apis/{RBAC}/v1/namespaces/a/rolebindings/carol-rb"),
                &json!({"subjects": [{"kind": "User", "name": "carol"}],
                        "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": "carol-role"}}),
            );
            idx.apply_object(
                &format!("/apis/{RBAC}/v1/clusterroles/secret-reader"),
                &json!({"rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}),
            );
            // Top-level `namespace` (not metadata.namespace) is what the RBAC index used to trust.
            let mut evil = rolebinding(None);
            evil["metadata"]["name"] = json!("evil");
            evil["namespace"] = json!("b");
            evil["roleRef"] =
                json!({"apiGroup": RBAC, "kind": "ClusterRole", "name": "secret-reader"});
            let (status, body) = send(
                &state,
                "POST",
                &format!("/apis/{RBAC}/v1/namespaces/a/rolebindings"),
                "application/json",
                evil,
            )
            .await;
            assert!(status.is_success(), "{status} {body}");
            let req = |ns| AuthzRequest {
                username: "carol",
                groups: &[],
                verb: "get",
                api_group: "",
                resource: "secrets",
                subresource: "",
                namespace: Some(ns),
                name: Some("x"),
                non_resource_url: None,
            };
            assert!(
                idx.is_allowed(&req("a")),
                "binding must apply in the URL namespace"
            );
            assert!(
                !idx.is_allowed(&req("b")),
                "a RoleBinding created in ns a must never grant rights in ns b"
            );
        }
    }
}
