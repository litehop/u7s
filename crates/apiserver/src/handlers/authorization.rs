use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use u7s_store::Store;

use crate::{
    auth::UserInfo,
    rbac::AuthzRequest,
    state::AppState,
    status::Status,
    util::{content_type, extract_body},
};

// ---------------------------------------------------------------------------
// SelfSubjectAccessReview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SelfSubjectAccessReviewRequest {
    spec: AccessReviewSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessReviewSpec {
    resource_attributes: Option<ResourceAttributes>,
    non_resource_attributes: Option<NonResourceAttributes>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceAttributes {
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    verb: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    subresource: String,
    #[serde(default)]
    name: String,
}

/// A non-resource-URL access check (e.g. `{path: "/apis/wardle.example.com/v1alpha1", verb:
/// "get"}`). Real apiservers issue these — not `resourceAttributes` — to authorize requests
/// against their own non-resource endpoints (discovery, openapi, healthz, ...). An aggregated
/// backend delegating authorization here (via `system:auth-delegator`) sends exactly this
/// shape for its own `/apis/{group}/{version}` discovery endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NonResourceAttributes {
    #[serde(default)]
    path: String,
    #[serde(default)]
    verb: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfSubjectAccessReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: AccessReviewStatus,
}

#[derive(Serialize)]
struct AccessReviewStatus {
    allowed: bool,
}

/// `resourceAttributes.resource` and `.subresource` are supposed to arrive pre-split
/// (e.g. `resource: "pods", subresource: "binding"`), but real clients — including
/// kubectl's `auth can-i pods/binding` path in some code paths — send the combined
/// `"pods/binding"` form in `resource` and leave `subresource` empty. The RBAC index's
/// `resource_matches` (see rbac.rs) only recognizes the split form, since that is what
/// the runtime authorizer always passes (it splits the URL path itself). Without this
/// normalization, SAR silently disagreed with the runtime authorizer for every named
/// subresource (`pods/binding`, `pods/status`, `pods/eviction`, ...): the real POST
/// succeeds but `kubectl auth can-i` / SelfSubjectAccessReview reports `allowed: false`.
fn split_combined_resource<'a>(resource: &'a str, subresource: &'a str) -> (&'a str, &'a str) {
    if subresource.is_empty() {
        if let Some((res, sub)) = resource.split_once('/') {
            return (res, sub);
        }
    }
    (resource, subresource)
}

pub async fn self_subject_access_review<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "selfsubjectaccessreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }
    let body = extract_body(&body, content_type(&headers));
    let req: SelfSubjectAccessReviewRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!("invalid request body: {e}"),
                    "reason": "BadRequest",
                    "code": 400
                })),
            )
                .into_response();
        }
    };
    let allowed = if let Some(attrs) = req.spec.resource_attributes {
        let ns = if attrs.namespace.is_empty() {
            None
        } else {
            Some(attrs.namespace.as_str())
        };
        let name = if attrs.name.is_empty() {
            None
        } else {
            Some(attrs.name.as_str())
        };
        let (resource, subresource) = split_combined_resource(&attrs.resource, &attrs.subresource);

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource,
            subresource,
            namespace: ns,
            name,
            non_resource_url: None,
        })
    } else if let Some(attrs) = req.spec.non_resource_attributes {
        state.rbac_index.is_allowed(&AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb: &attrs.verb,
            api_group: "",
            resource: "",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: Some(&attrs.path),
        })
    } else {
        false
    };

    let resp = SelfSubjectAccessReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "SelfSubjectAccessReview",
        status: AccessReviewStatus { allowed },
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// SelfSubjectRulesReview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SelfSubjectRulesReviewRequest {
    spec: RulesReviewSpec,
}

#[derive(Deserialize)]
struct RulesReviewSpec {
    #[serde(default)]
    namespace: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfSubjectRulesReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: RulesReviewStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RulesReviewStatus {
    resource_rules: Vec<ResourceRule>,
    non_resource_rules: Vec<NonResourceRule>,
    incomplete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceRule {
    verbs: Vec<String>,
    api_groups: Vec<String>,
    resources: Vec<String>,
}

#[derive(Serialize)]
struct NonResourceRule {
    verbs: Vec<String>,
    #[serde(rename = "nonResourceURLs")]
    non_resource_urls: Vec<String>,
}

pub async fn self_subject_rules_review<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "selfsubjectrulesreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }
    let body = extract_body(&body, content_type(&headers));
    let req: SelfSubjectRulesReviewRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!("invalid request body: {e}"),
                    "reason": "BadRequest",
                    "code": 400
                })),
            )
                .into_response();
        }
    };
    let namespace = &req.spec.namespace;
    let policy_rules = state
        .rbac_index
        .enumerate_rules(&user.username, &user.groups, namespace);

    let mut resource_rules: Vec<ResourceRule> = Vec::new();
    let mut non_resource_rules: Vec<NonResourceRule> = Vec::new();
    for r in policy_rules {
        if r.non_resource_urls.is_empty() {
            resource_rules.push(ResourceRule {
                verbs: r.verbs,
                api_groups: r.api_groups,
                resources: r.resources,
            });
        } else {
            non_resource_rules.push(NonResourceRule {
                verbs: r.verbs,
                non_resource_urls: r.non_resource_urls,
            });
        }
    }

    let resp = SelfSubjectRulesReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "SelfSubjectRulesReview",
        status: RulesReviewStatus {
            resource_rules,
            non_resource_rules,
            incomplete: false,
        },
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// SubjectAccessReview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SubjectAccessReviewRequest {
    spec: SubjectAccessReviewSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubjectAccessReviewSpec {
    #[serde(default)]
    user: String,
    #[serde(default)]
    groups: Vec<String>,
    resource_attributes: Option<ResourceAttributes>,
    non_resource_attributes: Option<NonResourceAttributes>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubjectAccessReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: AccessReviewStatus,
}

pub async fn subject_access_review<S: Store>(
    State(state): State<AppState<S>>,
    Extension(caller): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "subjectaccessreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }
    let body = extract_body(&body, content_type(&headers));
    let parsed: SubjectAccessReviewRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!("invalid request body: {e}"),
                    "reason": "BadRequest",
                    "code": 400
                })),
            )
                .into_response();
        }
    };

    // Defense-in-depth privilege check: only callers who have `create` on
    // `subjectaccessreviews` in the authorization.k8s.io group (or are in
    // system:masters) may use SAR to probe arbitrary subjects.
    //
    // The auth middleware already enforces this at the HTTP layer, but we also
    // check here so that the restriction is visible in the handler, and so it
    // remains in effect even if route ordering or middleware ever changes.
    let caller_allowed = caller.groups.iter().any(|g| g == "system:masters")
        || state.rbac_index.is_allowed(&crate::rbac::AuthzRequest {
            username: &caller.username,
            groups: &caller.groups,
            verb: "create",
            api_group: "authorization.k8s.io",
            resource: "subjectaccessreviews",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: None,
        });

    if !caller_allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "subjectaccessreviews.authorization.k8s.io is forbidden: User does not have create permission",
                "reason": "Forbidden",
                "code": 403
            })),
        )
            .into_response();
    }

    let spec = parsed.spec;
    let allowed = if let Some(attrs) = spec.resource_attributes {
        let ns = if attrs.namespace.is_empty() {
            None
        } else {
            Some(attrs.namespace.as_str())
        };
        let name = if attrs.name.is_empty() {
            None
        } else {
            Some(attrs.name.as_str())
        };
        let (resource, subresource) = split_combined_resource(&attrs.resource, &attrs.subresource);

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &spec.user,
            groups: &spec.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource,
            subresource,
            namespace: ns,
            name,
            non_resource_url: None,
        })
    } else if let Some(attrs) = spec.non_resource_attributes {
        // Real apiservers delegate authorization for their own non-resource endpoints
        // (discovery, openapi, ...) via exactly this shape instead of resourceAttributes.
        // An aggregated backend's DelegatingAuthorizationOptions sends this for its own
        // /apis/{group}/{version} discovery endpoint (system:auth-delegator's SAR call) —
        // without this branch every such check fell through to `allowed: false` below,
        // making aggregated discovery permanently 403 even for a cluster-admin caller.
        state.rbac_index.is_allowed(&AuthzRequest {
            username: &spec.user,
            groups: &spec.groups,
            verb: &attrs.verb,
            api_group: "",
            resource: "",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: Some(&attrs.path),
        })
    } else {
        false
    };

    let resp = SubjectAccessReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "SubjectAccessReview",
        status: AccessReviewStatus { allowed },
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// LocalSubjectAccessReview
// ---------------------------------------------------------------------------
//
// Identical to SubjectAccessReview but namespace-scoped.  The namespace from
// the URL path is injected into spec.resourceAttributes.namespace when absent
// in the request body (Kubernetes spec requirement).

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalSubjectAccessReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: AccessReviewStatus,
}

pub async fn local_subject_access_review<S: Store>(
    Path(namespace): Path<String>,
    State(state): State<AppState<S>>,
    Extension(caller): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "localsubjectaccessreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }
    let body = extract_body(&body, content_type(&headers));
    let mut parsed: SubjectAccessReviewRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!("invalid request body: {e}"),
                    "reason": "BadRequest",
                    "code": 400
                })),
            )
                .into_response();
        }
    };

    // Pre-fill namespace from the URL path if the body omits it.
    if let Some(ref mut attrs) = parsed.spec.resource_attributes {
        if attrs.namespace.is_empty() {
            attrs.namespace = namespace.clone();
        }
    }

    // Same privilege gate as SubjectAccessReview: only system:masters or
    // callers with `create localsubjectaccessreviews` may probe other subjects.
    let caller_allowed = caller.groups.iter().any(|g| g == "system:masters")
        || state.rbac_index.is_allowed(&crate::rbac::AuthzRequest {
            username: &caller.username,
            groups: &caller.groups,
            verb: "create",
            api_group: "authorization.k8s.io",
            resource: "localsubjectaccessreviews",
            subresource: "",
            namespace: Some(&namespace),
            name: None,
            non_resource_url: None,
        });

    if !caller_allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "localsubjectaccessreviews.authorization.k8s.io is forbidden: User does not have create permission",
                "reason": "Forbidden",
                "code": 403
            })),
        )
            .into_response();
    }

    let spec = parsed.spec;
    let allowed = if let Some(attrs) = spec.resource_attributes {
        let ns = if attrs.namespace.is_empty() {
            None
        } else {
            Some(attrs.namespace.as_str())
        };
        let name = if attrs.name.is_empty() {
            None
        } else {
            Some(attrs.name.as_str())
        };
        let (resource, subresource) = split_combined_resource(&attrs.resource, &attrs.subresource);

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &spec.user,
            groups: &spec.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource,
            subresource,
            namespace: ns,
            name,
            non_resource_url: None,
        })
    } else {
        false
    };

    let resp = LocalSubjectAccessReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "LocalSubjectAccessReview",
        status: AccessReviewStatus { allowed },
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// TokenReview
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenReviewRequest {
    spec: TokenReviewSpec,
}

#[derive(Deserialize)]
struct TokenReviewSpec {
    #[serde(default)]
    token: String,
    #[serde(default)]
    audiences: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: TokenReviewStatus,
}

#[derive(Serialize)]
struct TokenReviewStatus {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<TokenReviewUser>,
}

#[derive(Serialize)]
struct TokenReviewUser {
    username: String,
    uid: String,
    groups: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    extra: std::collections::HashMap<String, Vec<String>>,
}

pub async fn token_review<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "tokenreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }
    let body = extract_body(&body, content_type(&headers));
    let req: TokenReviewRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": format!("invalid request body: {e}"),
                    "reason": "BadRequest",
                    "code": 400
                })),
            )
                .into_response();
        }
    };
    let token = req.spec.token;
    let user_info = crate::auth::authenticate_token_with_audiences(
        &token,
        &state.token_map,
        state.sa_decoding_key.as_deref(),
        &req.spec.audiences,
        state.store.as_ref(),
        state.sa_sig_cache.as_ref(),
    )
    .await;

    let status = match user_info {
        Some(u) => TokenReviewStatus {
            authenticated: true,
            user: Some(TokenReviewUser {
                username: u.username,
                uid: u.uid,
                groups: u.groups,
                extra: u.extra,
            }),
        },
        None => TokenReviewStatus {
            authenticated: false,
            user: None,
        },
    };

    let resp = TokenReviewResponse {
        api_version: "authentication.k8s.io/v1",
        kind: "TokenReview",
        status,
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// SelfSubjectReview
// ---------------------------------------------------------------------------
//
// authentication.k8s.io/v1 "who am I" identity readback. Like the SAR/SSAR/SSRR
// family above, this is a create-only virtual resource with no persisted state:
// the server just mirrors the caller's already-authenticated identity (populated
// into request extensions by the auth middleware, including any impersonation
// substitution) back into status.userInfo. Upstream's SelfSubjectReview type has
// no spec field at all, so unlike its siblings this handler never reads the
// request body: client-go's generated clientset defaults to protobuf content
// negotiation for built-in types, and (unlike SAR/SSAR/SSRR/TokenReview, see
// rbac_gen_adapter.rs) there is no registered protobuf decoder for this kind
// because there are no spec fields to decode into JSON -- attempting to
// serde_json-parse a real protobuf-encoded body here would 400 every
// protobuf-negotiating client for no reason, since nothing in the body is ever
// used regardless of encoding.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfSubjectReviewResponse {
    api_version: &'static str,
    kind: &'static str,
    status: SelfSubjectReviewStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SelfSubjectReviewStatus {
    user_info: SelfSubjectReviewUserInfo,
}

#[derive(Serialize)]
struct SelfSubjectReviewUserInfo {
    username: String,
    uid: String,
    groups: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    extra: std::collections::HashMap<String, Vec<String>>,
}

pub async fn self_subject_review(
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if super::table::wants_table(accept) {
        return Status::not_acceptable(
            "selfsubjectreviews does not implement the Table conversion".into(),
        )
        .into_response();
    }

    let resp = SelfSubjectReviewResponse {
        api_version: "authentication.k8s.io/v1",
        kind: "SelfSubjectReview",
        status: SelfSubjectReviewStatus {
            user_info: SelfSubjectReviewUserInfo {
                username: user.username,
                uid: user.uid,
                groups: user.groups,
                extra: user.extra,
            },
        },
    };

    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::RbacIndex;
    use serde_json::json;
    use std::sync::Arc;

    fn make_index_with_cluster_role_binding(
        role_rules: serde_json::Value,
        username: &str,
    ) -> RbacIndex {
        let idx = RbacIndex::new();
        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/test-role";
        let role_val = json!({ "rules": role_rules });
        idx.apply_object(role_key, &role_val);

        let bind_key = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/test-binding";
        let bind_val = json!({
            "subjects": [{ "kind": "User", "name": username }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "test-role"
            }
        });
        idx.apply_object(bind_key, &bind_val);
        idx
    }

    #[test]
    fn test_enumerate_rules_system_masters_returns_wildcard() {
        // system:masters must return wildcard rules via the cluster-admin ClusterRoleBinding,
        // not via a hardcoded bypass.  Without the binding, rules are empty.
        let idx = RbacIndex::new();

        // Seed cluster-admin ClusterRole and the system:masters binding (as seed_rbac() does).
        let admin_role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin";
        let admin_role_val =
            json!({ "rules": [{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }] });
        idx.apply_object(admin_role_key, &admin_role_val);

        let admin_bind_key =
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system:masters";
        let admin_bind_val = json!({
            "subjects": [{ "kind": "Group", "name": "system:masters" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
        });
        idx.apply_object(admin_bind_key, &admin_bind_val);

        let groups = vec!["system:masters".to_owned()];
        let rules = idx.enumerate_rules("alice", &groups, "default");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].verbs, vec!["*"]);
        assert_eq!(rules[0].api_groups, vec!["*"]);
        assert_eq!(rules[0].resources, vec!["*"]);
    }

    #[test]
    fn test_enumerate_rules_specific_binding_allowed() {
        // A user with a cluster role binding must see those rules enumerated.
        let idx = make_index_with_cluster_role_binding(
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]),
            "alice",
        );
        let groups: Vec<String> = vec![];
        let rules = idx.enumerate_rules("alice", &groups, "default");
        assert_eq!(rules.len(), 1, "alice must see exactly her one bound rule");
        assert!(rules[0].verbs.contains(&"get".to_owned()));
        assert!(rules[0].resources.contains(&"pods".to_owned()));
    }

    #[test]
    fn test_enumerate_rules_no_binding_returns_empty() {
        // A user with no bindings must get an empty rule set — no implicit grants.
        let idx = make_index_with_cluster_role_binding(
            json!([{
                "apiGroups": [""],
                "resources": ["secrets"],
                "verbs": ["*"]
            }]),
            "alice",
        );
        let groups: Vec<String> = vec![];
        // bob has no binding — must receive empty rules
        let rules = idx.enumerate_rules("bob", &groups, "default");
        assert!(
            rules.is_empty(),
            "bob must see no rules when he has no bindings"
        );
    }

    #[test]
    fn test_is_allowed_via_rbac_index_direct() {
        // Verify the access check used by self_subject_access_review works correctly
        // for a user with a specific rule.
        let idx = Arc::new(make_index_with_cluster_role_binding(
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
            "alice",
        ));
        let groups: Vec<String> = vec![];

        // allowed: alice can get pods
        assert!(idx.is_allowed(&AuthzRequest {
            username: "alice",
            groups: &groups,
            verb: "get",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        }));

        // denied: alice cannot delete pods
        assert!(!idx.is_allowed(&AuthzRequest {
            username: "alice",
            groups: &groups,
            verb: "delete",
            api_group: "",
            resource: "pods",
            subresource: "",
            namespace: Some("default"),
            name: None,
            non_resource_url: None,
        }));
    }

    // ---------------------------------------------------------------------------
    // SubjectAccessReview tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_subject_access_review_allowed_for_bound_user() {
        // SubjectAccessReview must honor the `user` field from the request body,
        // not the calling user's identity. This is the key difference from
        // SelfSubjectAccessReview — it checks an arbitrary named subject.
        let idx = Arc::new(make_index_with_cluster_role_binding(
            json!([{
                "apiGroups": ["apps"],
                "resources": ["deployments"],
                "verbs": ["list"]
            }]),
            "argocd-bot",
        ));
        let groups: Vec<String> = vec![];

        assert!(
            idx.is_allowed(&AuthzRequest {
                username: "argocd-bot",
                groups: &groups,
                verb: "list",
                api_group: "apps",
                resource: "deployments",
                subresource: "",
                namespace: None,
                name: None,
                non_resource_url: None,
            }),
            "argocd-bot must be allowed to list deployments per its binding"
        );
        assert!(
            !idx.is_allowed(&AuthzRequest {
                username: "other-user",
                groups: &groups,
                verb: "list",
                api_group: "apps",
                resource: "deployments",
                subresource: "",
                namespace: None,
                name: None,
                non_resource_url: None,
            }),
            "a different user must not inherit argocd-bot's permissions"
        );
    }

    #[test]
    fn test_subject_access_review_system_masters_group_allowed_via_binding() {
        // A request whose groups include system:masters must be allowed when the
        // cluster-admin ClusterRoleBinding is seeded — access must come from RBAC
        // state, not from a hardcoded bypass.  Without the binding, access is denied.
        let idx = Arc::new(RbacIndex::new());
        let groups = vec!["system:masters".to_owned()];

        // Seed cluster-admin ClusterRole and the system:masters binding.
        let admin_role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/cluster-admin";
        let admin_role_val =
            json!({ "rules": [{ "apiGroups": ["*"], "resources": ["*"], "verbs": ["*"] }] });
        idx.apply_object(admin_role_key, &admin_role_val);

        let admin_bind_key =
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/system:masters";
        let admin_bind_val = json!({
            "subjects": [{ "kind": "Group", "name": "system:masters" }],
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" }
        });
        idx.apply_object(admin_bind_key, &admin_bind_val);

        assert!(
            idx.is_allowed(&AuthzRequest {
                username: "any-user",
                groups: &groups,
                verb: "delete",
                api_group: "",
                resource: "secrets",
                subresource: "",
                namespace: Some("kube-system"),
                name: None,
                non_resource_url: None,
            }),
            "system:masters must be allowed when the cluster-admin binding is present"
        );
    }

    // ---------------------------------------------------------------------------
    // TokenReview tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_authenticate_token_static_map_match() {
        // A token present in the static map must resolve to the correct UserInfo.
        // This is the primary use-case for TokenReview with --token-auth-file.
        use crate::auth::{authenticate_token_with_audiences, UserInfo};
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "argocd-token".to_owned(),
            UserInfo {
                username: "argocd-admin".to_owned(),
                uid: "42".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
                extra: Default::default(),
            },
        );

        let store = u7s_store::SqliteStore::new(":memory:").expect("in-memory sqlite store");
        let sig_cache =
            crate::sa_sig_cache::SigCache::new_with_capacity(crate::sa_sig_cache::DEFAULT_CAPACITY);
        let result =
            authenticate_token_with_audiences("argocd-token", &map, None, &[], &store, &sig_cache)
                .await;
        let user = result.expect("known token must resolve to a user");
        assert_eq!(user.username, "argocd-admin");
        assert!(user.groups.contains(&"system:authenticated".to_owned()));
    }

    #[tokio::test]
    async fn test_authenticate_token_unknown_returns_none() {
        // An unrecognized token must return None — TokenReview will respond with
        // authenticated: false. A bad token must NEVER return a user.
        use crate::auth::authenticate_token_with_audiences;
        use std::collections::HashMap;

        let map = HashMap::new();
        let store = u7s_store::SqliteStore::new(":memory:").expect("in-memory sqlite store");
        let sig_cache =
            crate::sa_sig_cache::SigCache::new_with_capacity(crate::sa_sig_cache::DEFAULT_CAPACITY);
        let result =
            authenticate_token_with_audiences("unknown-token", &map, None, &[], &store, &sig_cache)
                .await;
        assert!(result.is_none(), "unrecognized token must not authenticate");
    }

    // ---------------------------------------------------------------------------
    // SubjectAccessReview privilege gate tests
    // ---------------------------------------------------------------------------

    /// Extract the privilege-check logic from subject_access_review into a
    /// pure function so it can be unit-tested without spinning up a real handler.
    ///
    /// Returns `true` if the caller is permitted to use SAR (create on
    /// subjectaccessreviews in authorization.k8s.io, or system:masters).
    fn caller_may_use_sar(username: &str, groups: &[String], idx: &RbacIndex) -> bool {
        groups.iter().any(|g| g == "system:masters")
            || idx.is_allowed(&AuthzRequest {
                username,
                groups,
                verb: "create",
                api_group: "authorization.k8s.io",
                resource: "subjectaccessreviews",
                subresource: "",
                namespace: None,
                name: None,
                non_resource_url: None,
            })
    }

    #[test]
    fn sar_privilege_gate_denies_unprivileged_user() {
        // An authenticated user with no bindings must not be permitted to use SAR
        // to probe other users' permissions.  Allowing any authenticated user to
        // call SAR would leak authorization policy (can Alice delete secrets?  can
        // Bob create deployments?) to adversaries who have obtained any valid token.
        let idx = RbacIndex::new(); // no bindings — nobody is privileged
        let groups: Vec<String> = vec![];

        assert!(
            !caller_may_use_sar("unprivileged-user", &groups, &idx),
            "unprivileged user must not be allowed to use SAR — no binding grants create on subjectaccessreviews"
        );
    }

    #[test]
    fn sar_privilege_gate_denies_user_with_unrelated_binding() {
        // A user who has a legitimate binding (e.g. pod-reader) but no
        // `create subjectaccessreviews` permission must still be denied.
        // This ensures a narrow binding cannot be used to escalate to SAR probing.
        let idx = make_index_with_cluster_role_binding(
            serde_json::json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]),
            "pod-reader-user",
        );
        let groups: Vec<String> = vec![];

        assert!(
            !caller_may_use_sar("pod-reader-user", &groups, &idx),
            "pod-reader binding must not grant SAR access — create on subjectaccessreviews is distinct"
        );
    }

    #[test]
    fn sar_privilege_gate_permits_system_masters() {
        // system:masters bypasses all RBAC checks and must be allowed to use SAR
        // even with no bindings in the index.
        let idx = RbacIndex::new();
        let groups = vec!["system:masters".to_owned()];

        assert!(
            caller_may_use_sar("admin", &groups, &idx),
            "system:masters must always be permitted to use SAR"
        );
    }

    #[test]
    fn sar_privilege_gate_permits_user_with_explicit_sar_binding() {
        // A user explicitly granted `create subjectaccessreviews` in
        // authorization.k8s.io must be permitted to call SAR.
        let idx = RbacIndex::new();

        // Seed a ClusterRole + binding that grants SAR.
        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/sar-user";
        let role_val = serde_json::json!({
            "rules": [{
                "apiGroups": ["authorization.k8s.io"],
                "resources": ["subjectaccessreviews"],
                "verbs": ["create"]
            }]
        });
        idx.apply_object(role_key, &role_val);

        let bind_key = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/sar-user-binding";
        let bind_val = serde_json::json!({
            "subjects": [{ "kind": "User", "name": "sar-delegator" }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "sar-user"
            }
        });
        idx.apply_object(bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        assert!(
            caller_may_use_sar("sar-delegator", &groups, &idx),
            "user with explicit create subjectaccessreviews binding must be permitted"
        );
    }
}

// ---------------------------------------------------------------------------
// Handler-level tests — drive the actual Axum handlers end-to-end
// ---------------------------------------------------------------------------

#[cfg(test)]
mod handler_tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use bytes::Bytes;
    use tower::ServiceExt;

    use super::*;
    use crate::{auth::UserInfo, state::AppState};

    use crate::handlers::test_support::make_state;

    /// Build an AppState whose RBAC index has a ClusterRole + ClusterRoleBinding
    /// granting `username` the supplied `rules`.
    fn make_state_with_binding(role_rules: serde_json::Value, username: &str) -> AppState {
        let state = make_state();
        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/test-role";
        state
            .rbac_index
            .apply_object(role_key, &serde_json::json!({ "rules": role_rules }));
        let bind_key = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/test-binding";
        state.rbac_index.apply_object(
            bind_key,
            &serde_json::json!({
                "subjects": [{ "kind": "User", "name": username }],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "test-role"
                }
            }),
        );
        state
    }

    fn user(username: &str, groups: &[&str]) -> UserInfo {
        UserInfo {
            username: username.to_owned(),
            uid: String::new(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            extra: Default::default(),
        }
    }

    fn json_req(
        method: &str,
        uri: &str,
        body: serde_json::Value,
        user_info: UserInfo,
    ) -> Request<Body> {
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap();
        req.extensions_mut().insert(user_info);
        req
    }

    // -----------------------------------------------------------------------
    // self_subject_access_review
    // -----------------------------------------------------------------------

    /// The handler must return 201 CREATED and allowed=true when the calling
    /// user has a matching RBAC binding. This is the primary SSAR use-case:
    /// clients checking their own permissions (e.g. `kubectl auth can-i`).
    #[tokio::test]
    async fn ssar_returns_201_allowed_when_user_has_permission() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "resourceAttributes": {
                    "namespace": "default",
                    "verb": "get",
                    "group": "",
                    "resource": "pods"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            body,
            user("alice", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "SSAR must respond 201 CREATED"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], true,
            "alice must be allowed to get pods"
        );
        assert_eq!(val["kind"], "SelfSubjectAccessReview");
        assert_eq!(val["apiVersion"], "authorization.k8s.io/v1");
    }

    /// When resource_attributes is absent the handler must respond allowed=false.
    /// This is the only safe default: if we cannot determine what to check, deny.
    #[tokio::test]
    async fn ssar_returns_201_denied_when_no_resource_attributes() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": {} });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            body,
            user("nobody", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], false,
            "absent resourceAttributes must result in allowed=false"
        );
    }

    /// `kubectl auth can-i get /metrics` (and similar non-resource checks) send
    /// nonResourceAttributes, not resourceAttributes. Before this fix SSAR only ever read
    /// resourceAttributes, so this always reported allowed=false regardless of the caller's
    /// actual nonResourceURLs grants.
    #[tokio::test]
    async fn ssar_allows_non_resource_attributes_matching_rbac_rule() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "nonResourceURLs": ["/metrics"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "nonResourceAttributes": { "path": "/metrics", "verb": "get" }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            body,
            user("alice", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], true,
            "a nonResourceURL RBAC grant must authorize a matching SSAR nonResourceAttributes \
             check — otherwise `kubectl auth can-i get /metrics` always reports no for \
             every user, regardless of their actual grants"
        );
    }

    /// `kubectl auth can-i create pods/binding` sends the named subresource as a single
    /// combined `resource: "pods/binding"` string with `subresource` left empty. The
    /// runtime authorizer (which parses the URL path itself) already splits this
    /// correctly, so `system:kube-scheduler` can genuinely POST bindings — but before
    /// `split_combined_resource`, SAR passed the un-split "pods/binding" straight to
    /// `RbacIndex::is_allowed`, which never matches the `resources: ["pods/binding"]`
    /// rule split logic. That made `kubectl auth can-i create pods/binding
    /// --as=system:kube-scheduler` report `no` even though the scheduler could actually
    /// bind pods — a false negative for any tool (kubectl, RBAC auditors) that trusts SAR
    /// instead of just attempting the action. Covers pods/status and pods/eviction too,
    /// since any named subresource hit the same bug.
    #[tokio::test]
    async fn ssar_allows_combined_resource_subresource_string_matching_rbac_rule() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": [""],
                "resources": ["pods/binding", "pods/status", "pods/eviction"],
                "verbs": ["create"]
            }]),
            "system:kube-scheduler",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        for resource in ["pods/binding", "pods/status", "pods/eviction"] {
            let body = serde_json::json!({
                "spec": {
                    "resourceAttributes": {
                        "namespace": "default",
                        "verb": "create",
                        "group": "",
                        "resource": resource
                    }
                }
            });
            let req = json_req(
                "POST",
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                body,
                user("system:kube-scheduler", &[]),
            );

            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                val["status"]["allowed"], true,
                "system:kube-scheduler must be allowed to create {resource} — SAR must \
                 agree with the runtime authorizer, which already permits this action"
            );
        }
    }

    // -----------------------------------------------------------------------
    // self_subject_rules_review
    // -----------------------------------------------------------------------

    /// SSRR must return 201 CREATED and list the rules applicable to the
    /// calling user. This lets clients enumerate what they are permitted to do
    /// (e.g. ArgoCD permission discovery, `kubectl auth can-i --list`).
    #[tokio::test]
    async fn ssrr_returns_201_with_user_rules() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": ["apps"],
                "resources": ["deployments"],
                "verbs": ["list", "get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                post(self_subject_rules_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "namespace": "default" } });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            body,
            user("alice", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "SelfSubjectRulesReview");
        assert_eq!(val["apiVersion"], "authorization.k8s.io/v1");
        let rules = val["status"]["resourceRules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "alice must see exactly her one bound rule");
        assert!(
            rules[0]["verbs"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("list")),
            "list verb must appear in rules"
        );
    }

    /// SSRR for a user with no bindings must return an empty resourceRules array.
    /// Returning rules the user doesn't have would be an authorization information leak.
    #[tokio::test]
    async fn ssrr_returns_empty_rules_for_unbound_user() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                post(self_subject_rules_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "namespace": "default" } });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            body,
            user("unbound-user", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rules = val["status"]["resourceRules"].as_array().unwrap();
        assert!(rules.is_empty(), "unbound user must see no resource rules");
        assert_eq!(
            val["status"]["incomplete"], false,
            "incomplete must be false when enumeration completed normally"
        );
    }

    /// SSRR must populate nonResourceRules for a user whose ClusterRole grants
    /// nonResourceURLs. Without this, `kubectl auth can-i --list` silently
    /// underreports permissions for users who have e.g. GET /metrics access.
    #[tokio::test]
    async fn ssrr_populates_non_resource_rules_for_non_resource_url_grant() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "nonResourceURLs": ["/metrics"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                post(self_subject_rules_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "namespace": "default" } });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            body,
            user("alice", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let non_resource = val["status"]["nonResourceRules"].as_array().unwrap();
        assert_eq!(
            non_resource.len(),
            1,
            "a nonResourceURL grant must appear in nonResourceRules — \
             kubectl auth can-i --list would miss GET /metrics otherwise"
        );
        assert!(
            non_resource[0]["nonResourceURLs"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("/metrics")),
            "/metrics must appear in the nonResourceURLs of the returned rule"
        );
        assert!(
            non_resource[0]["verbs"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("get")),
            "get verb must appear in the returned non-resource rule"
        );
        let resource_rules = val["status"]["resourceRules"].as_array().unwrap();
        assert!(
            resource_rules.is_empty(),
            "a nonResourceURL-only rule must not leak into resourceRules"
        );
    }

    // -----------------------------------------------------------------------
    // subject_access_review
    // -----------------------------------------------------------------------

    /// SAR must return 403 Forbidden when the caller is not in system:masters
    /// and has no `create subjectaccessreviews` permission. Allowing any
    /// authenticated user to call SAR would let them probe other users'
    /// permissions — a serious authorization information leak.
    #[tokio::test]
    async fn sar_returns_403_for_unprivileged_caller() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                post(subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "resourceAttributes": {
                    "namespace": "default",
                    "verb": "get",
                    "group": "",
                    "resource": "secrets"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            body,
            user("unprivileged", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "unprivileged caller must get 403, not a result"
        );
    }

    /// A caller in system:masters must be able to use SAR — they can probe any
    /// subject's permissions. The handler must return 201 CREATED with the
    /// result of the RBAC check for the target user.
    #[tokio::test]
    async fn sar_returns_201_for_system_masters_caller() {
        // Seed a binding for the target user (alice can get pods).
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                post(subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "resourceAttributes": {
                    "namespace": "default",
                    "verb": "get",
                    "group": "",
                    "resource": "pods"
                }
            }
        });
        // Caller is in system:masters — must be permitted to call SAR.
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "system:masters caller must get 201 CREATED"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "SubjectAccessReview");
        assert_eq!(
            val["status"]["allowed"], true,
            "alice must be reported as allowed to get pods"
        );
    }

    /// SAR must return allowed=false (not 403) when the caller is privileged
    /// but the target subject has no matching permission. The 403 path is only
    /// for unprivileged callers — the target check is separate.
    #[tokio::test]
    async fn sar_returns_201_denied_when_no_resource_attributes() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                post(subject_access_review),
            )
            .with_state(state);

        // No resourceAttributes: result must be allowed=false.
        let body = serde_json::json!({
            "spec": {
                "user": "nobody",
                "groups": []
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], false,
            "absent resourceAttributes must produce allowed=false, not an error"
        );
    }

    /// Regression test: aggregated backends (e.g. sample-apiserver) authorize requests to
    /// their own non-resource endpoints (discovery, openapi, ...) by sending a SAR with
    /// `nonResourceAttributes`, not `resourceAttributes` — via their `system:auth-delegator`
    /// identity, on behalf of the original caller. Before this fix, `subject_access_review`
    /// only ever read `spec.resourceAttributes`; a nonResourceAttributes-only request fell
    /// through to `allowed: false` unconditionally, so an aggregated backend's own discovery
    /// endpoint was permanently 403 even for a cluster-admin caller — this silently emptied
    /// that group out of `/apis` discovery (aggregator conformance:
    /// "could not find group version resource for dynamic client and wardle/flunders"),
    /// while the resource endpoints (which use resourceAttributes) worked fine. Revert the
    /// nonResourceAttributes branch and this must fail again.
    #[tokio::test]
    async fn sar_allows_non_resource_attributes_matching_rbac_rule() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "nonResourceURLs": ["/apis/wardle.example.com/v1alpha1"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                post(subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "nonResourceAttributes": {
                    "path": "/apis/wardle.example.com/v1alpha1",
                    "verb": "get"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], true,
            "a nonResourceURL RBAC grant must authorize a matching nonResourceAttributes \
             SAR check, or every aggregated backend's own discovery endpoint stays 403 \
             forever regardless of the caller's actual permissions"
        );
    }

    /// A nonResourceAttributes check for a path the subject has no grant for must be denied,
    /// not accidentally allowed (e.g. by falling back to some permissive default).
    #[tokio::test]
    async fn sar_denies_non_resource_attributes_without_matching_rbac_rule() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "nonResourceURLs": ["/healthz"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/subjectaccessreviews",
                post(subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "nonResourceAttributes": {
                    "path": "/apis/wardle.example.com/v1alpha1",
                    "verb": "get"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["allowed"], false,
            "a grant for a different nonResourceURL must not authorize an unrelated path"
        );
    }

    // -----------------------------------------------------------------------
    // token_review
    // -----------------------------------------------------------------------

    /// TokenReview with a recognized static token must respond 201 CREATED with
    /// authenticated=true and the correct user identity. This is the primary
    /// use-case for --token-auth-file (e.g. kubelets authenticating with a
    /// bootstrap token).
    #[tokio::test]
    async fn token_review_returns_authenticated_for_known_token() {
        let store =
            Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory sqlite store"));
        let mut token_map = std::collections::HashMap::new();
        token_map.insert(
            "my-static-token".to_owned(),
            UserInfo {
                username: "kubelet-node1".to_owned(),
                uid: "7".to_owned(),
                groups: vec!["system:nodes".to_owned()],
                extra: Default::default(),
            },
        );
        let state = AppState::new(
            store,
            None,
            None,
            token_map,
            "https://localhost:6443".into(),
        );

        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/tokenreviews",
                post(token_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "token": "my-static-token" } });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let req = Request::builder()
            .method("POST")
            .uri("/apis/authentication.k8s.io/v1/tokenreviews")
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "TokenReview");
        assert_eq!(val["apiVersion"], "authentication.k8s.io/v1");
        assert_eq!(
            val["status"]["authenticated"], true,
            "known token must be authenticated"
        );
        assert_eq!(
            val["status"]["user"]["username"], "kubelet-node1",
            "username must match the token map entry"
        );
    }

    /// TokenReview with an unknown token must respond 201 CREATED with
    /// authenticated=false and no user field. The handler must NOT return an
    /// error status — the spec says to respond with authenticated=false.
    #[tokio::test]
    async fn token_review_returns_unauthenticated_for_unknown_token() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/tokenreviews",
                post(token_review),
            )
            .with_state(state);

        let body = serde_json::json!({ "spec": { "token": "completely-unknown-token" } });
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let req = Request::builder()
            .method("POST")
            .uri("/apis/authentication.k8s.io/v1/tokenreviews")
            .header("content-type", "application/json")
            .body(Body::from(bytes))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["authenticated"], false,
            "unknown token must not authenticate"
        );
        // user field must be absent when not authenticated (skip_serializing_if)
        assert!(
            val["status"]["user"].is_null(),
            "user field must be absent when not authenticated"
        );
    }

    // -----------------------------------------------------------------------
    // local_subject_access_review
    // -----------------------------------------------------------------------

    /// LSAR must return 201 CREATED with kind=LocalSubjectAccessReview and an
    /// `allowed` field.  This is the namespace-scoped SAR variant required by
    /// conformance (GET /apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews
    /// previously returned 404, breaking conformance tests).
    #[tokio::test]
    async fn lsar_returns_201_with_allowed_field_for_system_masters() {
        let state = make_state();

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
                post(local_subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "resourceAttributes": {
                    "verb": "get",
                    "group": "",
                    "resource": "pods"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "LSAR must return 201 CREATED — previously this endpoint returned 404"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["kind"], "LocalSubjectAccessReview",
            "response kind must be LocalSubjectAccessReview, not SubjectAccessReview"
        );
        assert_eq!(val["apiVersion"], "authorization.k8s.io/v1");
        assert!(
            val["status"]["allowed"].is_boolean(),
            "status.allowed must be present in the response body — conformance test checks for it"
        );
    }

    /// LSAR must pre-fill namespace from the URL into spec.resourceAttributes
    /// when the body omits it, so RBAC checks use the correct namespace scope.
    #[tokio::test]
    async fn lsar_prefills_namespace_from_url_when_body_omits_it() {
        // alice can get pods in "staging" only.
        let state = make_state();
        let role_key = "/apis/rbac.authorization.k8s.io/v1/clusterroles/pod-reader";
        state.rbac_index.apply_object(
            role_key,
            &serde_json::json!({
                "rules": [{ "apiGroups": [""], "resources": ["pods"], "verbs": ["get"] }]
            }),
        );
        let bind_key = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/alice-binding";
        state.rbac_index.apply_object(
            bind_key,
            &serde_json::json!({
                "subjects": [{ "kind": "User", "name": "alice" }],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "pod-reader"
                }
            }),
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
                post(local_subject_access_review),
            )
            .with_state(state);

        // Body has no namespace — handler must inject "default" from the URL.
        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "resourceAttributes": {
                    "verb": "get",
                    "group": "",
                    "resource": "pods"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews",
            body,
            user("admin", &["system:masters"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // alice has a cluster-wide binding for get pods, so it should be allowed
        // regardless of namespace.  The key assertion is that allowed is present.
        assert!(
            val["status"]["allowed"].is_boolean(),
            "namespace pre-fill must produce a valid allowed field"
        );
    }

    /// LSAR must return 403 Forbidden for an unprivileged caller — same gate
    /// as SubjectAccessReview.  Without this, any authenticated user could probe
    /// other subjects' permissions at a namespace scope.
    #[tokio::test]
    async fn lsar_returns_403_for_unprivileged_caller() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
                post(local_subject_access_review),
            )
            .with_state(state);

        let body = serde_json::json!({
            "spec": {
                "user": "alice",
                "groups": [],
                "resourceAttributes": {
                    "namespace": "default",
                    "verb": "get",
                    "group": "",
                    "resource": "secrets"
                }
            }
        });
        let req = json_req(
            "POST",
            "/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews",
            body,
            user("unprivileged", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "unprivileged caller must get 403 from LSAR — same privilege gate as SAR"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: LSAR with Content-Type: application/vnd.kubernetes.protobuf must return 201
    // -----------------------------------------------------------------------

    /// Build a protobuf varint (LEB128) encoding of v.
    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    /// Encode a length-delimited protobuf field (wire type 2).
    fn encode_ld(field: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field << 3) | 2;
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// Build a minimal k8s proto envelope for LocalSubjectAccessReview.
    ///
    /// Wire layout:
    ///   magic (4 bytes) | Unknown { typeMeta: TypeMeta, raw: SubjectAccessReview }
    ///
    /// SubjectAccessReview.spec.user = "alice" (no resourceAttributes → allowed=false).
    /// contentType field is absent (empty string default) so extract_body routes to
    /// decode_core_proto_by_kind("LocalSubjectAccessReview", ...) — the path that was broken.
    fn build_lsar_proto_envelope() -> Vec<u8> {
        // TypeMeta: field 1 = apiVersion, field 2 = kind
        let api_version_bytes = "authorization.k8s.io/v1".as_bytes();
        let kind_bytes = "LocalSubjectAccessReview".as_bytes();
        let mut type_meta = encode_ld(1, api_version_bytes);
        type_meta.extend(encode_ld(2, kind_bytes));

        // SubjectAccessReviewSpec: field 3 = user = "alice"
        let user_bytes = "alice".as_bytes();
        let spec_bytes = encode_ld(3, user_bytes);

        // SubjectAccessReview: field 2 = spec
        let sar_raw = encode_ld(2, &spec_bytes);

        // Unknown envelope: field 1 = TypeMeta, field 2 = raw (SubjectAccessReview proto)
        let mut envelope = encode_ld(1, &type_meta);
        envelope.extend(encode_ld(2, &sar_raw));

        // Prepend k8s proto magic
        let mut body = vec![0x6b, 0x38, 0x73, 0x00];
        body.extend(envelope);
        body
    }

    /// Sending a protobuf-encoded LocalSubjectAccessReview body must return 201, not 400.
    ///
    /// Before the fix, decode_core_proto_by_kind had no "LocalSubjectAccessReview" entry,
    /// so extract_body returned raw proto bytes, and serde_json::from_slice failed with
    /// "expected value at line 1 column 1" → 400 BadRequest. Conformance tests send LSAR
    /// via protobuf (Content-Type: application/vnd.kubernetes.protobuf) by default.
    #[tokio::test]
    async fn lsar_proto_body_returns_201_not_400() {
        let state = make_state();

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/namespaces/{ns}/localsubjectaccessreviews",
                post(local_subject_access_review),
            )
            .with_state(state);

        let proto_body = build_lsar_proto_envelope();
        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authorization.k8s.io/v1/namespaces/default/localsubjectaccessreviews")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(Body::from(proto_body))
            .unwrap();
        // Caller in system:masters passes the privilege gate.
        req.extensions_mut()
            .insert(user("admin", &["system:masters"]));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "LSAR with protobuf body must return 201 — before fix, missing LocalSubjectAccessReview \
             in decode_core_proto_by_kind caused extract_body to return raw proto bytes, \
             causing serde_json::from_slice to fail with 400"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "LocalSubjectAccessReview");
        assert!(
            val["status"]["allowed"].is_boolean(),
            "proto-decoded LSAR must produce a valid allowed field"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: SelfSubjectAccessReview/SelfSubjectRulesReview with
    // Content-Type: application/vnd.kubernetes.protobuf must return 201
    // -----------------------------------------------------------------------

    /// Build a minimal k8s proto envelope for SelfSubjectAccessReview with resourceAttributes
    /// set (verb=get, resource=pods, namespace=default).
    fn build_ssar_proto_envelope() -> Vec<u8> {
        // TypeMeta: field 1 = apiVersion, field 2 = kind
        let mut type_meta = encode_ld(1, "authorization.k8s.io/v1".as_bytes());
        type_meta.extend(encode_ld(2, "SelfSubjectAccessReview".as_bytes()));

        // ResourceAttributes: field 1 = namespace, field 2 = verb, field 5 = resource
        let mut resource_attrs = encode_ld(1, "default".as_bytes());
        resource_attrs.extend(encode_ld(2, "get".as_bytes()));
        resource_attrs.extend(encode_ld(5, "pods".as_bytes()));

        // SelfSubjectAccessReviewSpec: field 1 = resourceAttributes
        let spec_bytes = encode_ld(1, &resource_attrs);

        // SelfSubjectAccessReview: field 2 = spec
        let ssar_raw = encode_ld(2, &spec_bytes);

        // Unknown envelope: field 1 = TypeMeta, field 2 = raw (SelfSubjectAccessReview proto)
        let mut envelope = encode_ld(1, &type_meta);
        envelope.extend(encode_ld(2, &ssar_raw));

        let mut body = vec![0x6b, 0x38, 0x73, 0x00];
        body.extend(envelope);
        body
    }

    /// Sending a protobuf-encoded SelfSubjectAccessReview body must return 201, not 400, and
    /// the decoded resourceAttributes must actually reach the RBAC check.
    ///
    /// Before this fix, "SelfSubjectAccessReview" had no dispatch arm in
    /// decode_proto_by_kind_and_version, so extract_body returned raw protobuf bytes and
    /// this handler's serde_json::from_slice failed with 400 for every client-go typed
    /// clientset call — Argo CD calls SelfSubjectAccessReview on startup to discover its own
    /// permissions, so this blocked that workflow outright.
    #[tokio::test]
    async fn ssar_proto_body_returns_201_not_400() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(Body::from(build_ssar_proto_envelope()))
            .unwrap();
        req.extensions_mut().insert(user("alice", &[]));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "SelfSubjectAccessReview with a protobuf body must return 201, not 400 — a missing \
             dispatch arm previously made extract_body return undecoded bytes here"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "SelfSubjectAccessReview");
        assert_eq!(
            val["status"]["allowed"], true,
            "the decoded resourceAttributes (verb=get, resource=pods) must actually reach the \
             RBAC check, not just avoid a 400 — alice's binding authorizes exactly this"
        );
    }

    /// Build a minimal k8s proto envelope for SelfSubjectRulesReview with namespace=default.
    fn build_ssrr_proto_envelope() -> Vec<u8> {
        let mut type_meta = encode_ld(1, "authorization.k8s.io/v1".as_bytes());
        type_meta.extend(encode_ld(2, "SelfSubjectRulesReview".as_bytes()));

        // SelfSubjectRulesReviewSpec: field 1 = namespace
        let spec_bytes = encode_ld(1, "default".as_bytes());

        // SelfSubjectRulesReview: field 2 = spec
        let ssrr_raw = encode_ld(2, &spec_bytes);

        let mut envelope = encode_ld(1, &type_meta);
        envelope.extend(encode_ld(2, &ssrr_raw));

        let mut body = vec![0x6b, 0x38, 0x73, 0x00];
        body.extend(envelope);
        body
    }

    /// Sending a protobuf-encoded SelfSubjectRulesReview body must return 201, not 400, and the
    /// decoded namespace must actually reach rule enumeration.
    ///
    /// Same root cause as SelfSubjectAccessReview above: no dispatch arm meant every protobuf
    /// call (client-go's default content-type) hit a hard 400 instead of a result.
    #[tokio::test]
    async fn ssrr_proto_body_returns_201_not_400() {
        let state = make_state_with_binding(
            serde_json::json!([{
                "apiGroups": ["apps"],
                "resources": ["deployments"],
                "verbs": ["list"]
            }]),
            "alice",
        );

        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                post(self_subject_rules_review),
            )
            .with_state(state);

        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(Body::from(build_ssrr_proto_envelope()))
            .unwrap();
        req.extensions_mut().insert(user("alice", &[]));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "SelfSubjectRulesReview with a protobuf body must return 201, not 400 — a missing \
             dispatch arm previously made extract_body return undecoded bytes here"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "SelfSubjectRulesReview");
        let rules = val["status"]["resourceRules"].as_array().unwrap();
        assert_eq!(
            rules.len(),
            1,
            "the decoded namespace must actually reach enumerate_rules, not just avoid a 400 \
             — alice's one bound rule must be enumerated"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: Content-Type: application/json must not produce 415
    // -----------------------------------------------------------------------

    /// Conformance test "should return a 406 for a backend which does not implement metadata"
    /// POSTs a SelfSubjectAccessReview with Accept: application/json;as=Table;v=v1;g=meta.k8s.io
    /// and expects HTTP 406.  Before the fix the handler ignored Accept entirely, returning 201.
    /// Without this check, clients that request Table representation receive success with a
    /// non-Table body, breaking the conformance test and any client that relies on 406 to
    /// detect resources with no table form.
    #[tokio::test]
    async fn selfsubjectaccessreview_with_table_accept_returns_406_so_clients_know_no_table_form_exists(
    ) {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let body_bytes =
            Bytes::from(serde_json::to_vec(&serde_json::json!({ "spec": {} })).unwrap());
        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
            .header("content-type", "application/json")
            .header("accept", "application/json;as=Table;v=v1;g=meta.k8s.io")
            .body(Body::from(body_bytes))
            .unwrap();
        req.extensions_mut().insert(user("any-user", &[]));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_ACCEPTABLE,
            "SSAR with Accept: as=Table must return 406 — selfsubjectaccessreviews has no table form; \
             clients use 406 to detect this and fall back to normal JSON"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["code"], 406,
            "Status.code must be 406 so client-go's error parsing maps it correctly"
        );
        assert_eq!(val["reason"], "NotAcceptable");
    }

    /// `kubectl auth can-i` sends POST with Content-Type: application/json and expects
    /// 201 CREATED. Before this fix the axum Json extractor rejected these requests with
    /// 415 UnsupportedMediaType because it required a content-type match that was more
    /// strict than the handler needed. The handler must accept any JSON-compatible body.
    #[tokio::test]
    async fn ssar_post_with_application_json_content_type_returns_201_not_415() {
        let state = make_state();
        let app = Router::new()
            .route(
                "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
                post(self_subject_access_review),
            )
            .with_state(state);

        let body_bytes =
            Bytes::from(serde_json::to_vec(&serde_json::json!({ "spec": {} })).unwrap());
        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
            .header("content-type", "application/json")
            .body(Body::from(body_bytes))
            .unwrap();
        req.extensions_mut().insert(user("any-user", &[]));

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type: application/json must not produce 415 — kubectl auth can-i would be broken"
        );
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "SelfSubjectAccessReview POST with application/json must return 201 CREATED"
        );
    }

    // -----------------------------------------------------------------------
    // self_subject_review
    // -----------------------------------------------------------------------

    /// SelfSubjectReview exists so a client can confirm which identity the apiserver
    /// actually assigned it -- e.g. right after exchanging a short-lived token via
    /// TokenRequest, when the client has no other way to read its own resolved identity
    /// back. The handler must mirror the caller's authenticated username and groups
    /// verbatim into status.userInfo.
    #[tokio::test]
    async fn selfsubjectreview_returns_authenticated_user_because_clients_need_identity_readback_after_token_exchange(
    ) {
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                post(self_subject_review),
            )
            .with_state(make_state());

        let req = json_req(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            serde_json::json!({}),
            user("alice", &["developers"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "SelfSubjectReview must respond 201 CREATED"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["kind"], "SelfSubjectReview");
        assert_eq!(val["apiVersion"], "authentication.k8s.io/v1");
        assert_eq!(
            val["status"]["userInfo"]["username"], "alice",
            "status.userInfo.username must echo the caller's own authenticated identity, \
             not some other user"
        );
    }

    /// Dashboard-style clients (and anything correlating a request with its issuing
    /// credential) read uid, groups, and extra out of SelfSubjectReview -- e.g. a service
    /// account token's bound-pod JTI lives in `extra`. If any of these were dropped on
    /// the way from the auth context into the response, such tooling would silently
    /// under-render or lose the correlation.
    #[tokio::test]
    async fn selfsubjectreview_populates_groups_and_extra_fields_from_auth_context_because_dashboard_clients_render_them(
    ) {
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                post(self_subject_review),
            )
            .with_state(make_state());

        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "authentication.kubernetes.io/credential-id".to_owned(),
            vec!["JTI=abc123".to_owned()],
        );
        let caller = UserInfo {
            username: "system:serviceaccount:default:builder".to_owned(),
            uid: "sa-uid-42".to_owned(),
            groups: vec![
                "system:serviceaccounts".to_owned(),
                "system:authenticated".to_owned(),
            ],
            extra,
        };

        let req = json_req(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            serde_json::json!({}),
            caller,
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["userInfo"]["uid"], "sa-uid-42",
            "uid must be forwarded so callers can distinguish a recreated identity of the \
             same name from the original"
        );
        assert_eq!(
            val["status"]["userInfo"]["groups"],
            serde_json::json!(["system:serviceaccounts", "system:authenticated"]),
            "all of the caller's groups must be forwarded, not just the first"
        );
        assert_eq!(
            val["status"]["userInfo"]["extra"]["authentication.kubernetes.io/credential-id"],
            serde_json::json!(["JTI=abc123"]),
            "extra attributes must be forwarded verbatim so audit/dashboard tooling can \
             correlate the request with its issuing credential"
        );
    }

    /// A request with no credentials authenticates as system:anonymous in the
    /// system:unauthenticated group (see auth.rs's anonymous fallback). SelfSubjectReview
    /// must report that identity verbatim -- silently substituting some other identity
    /// would let an unauthenticated caller believe it is signed in when it is not.
    #[tokio::test]
    async fn selfsubjectreview_with_anonymous_request_returns_system_anonymous_because_that_is_the_actual_identity(
    ) {
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                post(self_subject_review),
            )
            .with_state(make_state());

        let req = json_req(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            serde_json::json!({}),
            user("system:anonymous", &["system:unauthenticated"]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["userInfo"]["username"], "system:anonymous",
            "an unauthenticated caller must see its real (anonymous) identity, never a \
             masked or defaulted one"
        );
        assert_eq!(
            val["status"]["userInfo"]["groups"],
            serde_json::json!(["system:unauthenticated"])
        );
    }

    /// Upstream's SelfSubjectReview type has no `spec` field at all -- it is a pure
    /// create-only readback. A client that (incorrectly) sends SAR-shaped `spec` content
    /// must still get back its own identity unaffected, not a 400 or a response
    /// influenced by that content.
    #[tokio::test]
    async fn selfsubjectreview_ignores_spec_field_because_upstream_resource_has_no_spec() {
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                post(self_subject_review),
            )
            .with_state(make_state());

        let req = json_req(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            serde_json::json!({
                "spec": {
                    "resourceAttributes": { "verb": "delete", "resource": "secrets" }
                }
            }),
            user("bob", &[]),
        );

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "an unused spec field must not cause a 400 -- it simply isn't part of this resource"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            val["status"]["userInfo"]["username"], "bob",
            "spec content must have zero influence on the identity readback"
        );
    }

    /// client-go's generated clientset (used by `kubectl auth whoami` and the upstream
    /// `AuthenticationV1().SelfSubjectReviews()` client) defaults to protobuf content
    /// negotiation for built-in types. Since SelfSubjectReview has no spec to decode,
    /// there is deliberately no registered protobuf decoder for it (see
    /// rbac_gen_adapter.rs's Kind->decoder map in proto.rs) -- the handler must never
    /// attempt to serde_json-parse the body, or every protobuf-negotiating client would
    /// get a spurious 400 even though nothing in the body is ever used.
    #[tokio::test]
    async fn selfsubjectreview_does_not_attempt_to_decode_the_body_because_protobuf_clients_have_no_registered_decoder_for_this_kind(
    ) {
        let app = Router::new()
            .route(
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                post(self_subject_review),
            )
            .with_state(make_state());

        // Bytes that are neither valid JSON nor a decodable k8s protobuf envelope --
        // representative of what extract_body falls back to returning unchanged when no
        // Kind-specific decoder exists for a protobuf-negotiated request.
        let garbage = Bytes::from_static(&[0xff, 0x00, 0x01, 0x02, 0x7f]);
        let mut req = Request::builder()
            .method("POST")
            .uri("/apis/authentication.k8s.io/v1/selfsubjectreviews")
            .header("content-type", "application/vnd.kubernetes.protobuf")
            .body(Body::from(garbage))
            .unwrap();
        req.extensions_mut().insert(user("carol", &[]));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "an undecodable protobuf-negotiated body must not produce a 400 -- the handler \
             never needs to read the body at all, so real client-go callers (which default \
             to protobuf for built-in types) must still succeed"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(val["status"]["userInfo"]["username"], "carol");
    }
}
