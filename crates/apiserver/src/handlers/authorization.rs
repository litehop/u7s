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

pub async fn self_subject_access_review<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
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

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &user.username,
            groups: &user.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource: &attrs.resource,
            subresource: &attrs.subresource,
            namespace: ns,
            name,
            non_resource_url: None,
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
    non_resource_rules: Vec<serde_json::Value>,
    incomplete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceRule {
    verbs: Vec<String>,
    api_groups: Vec<String>,
    resources: Vec<String>,
}

pub async fn self_subject_rules_review<S: Store>(
    State(state): State<AppState<S>>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
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

    let resource_rules = policy_rules
        .into_iter()
        .map(|r| ResourceRule {
            verbs: r.verbs,
            api_groups: r.api_groups,
            resources: r.resources,
        })
        .collect();

    let resp = SelfSubjectRulesReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "SelfSubjectRulesReview",
        status: RulesReviewStatus {
            resource_rules,
            non_resource_rules: vec![],
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

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &spec.user,
            groups: &spec.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource: &attrs.resource,
            subresource: &attrs.subresource,
            namespace: ns,
            name,
            non_resource_url: None,
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

        state.rbac_index.is_allowed(&AuthzRequest {
            username: &spec.user,
            groups: &spec.groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource: &attrs.resource,
            subresource: &attrs.subresource,
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
}

pub async fn token_review<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
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
    let user_info =
        crate::auth::authenticate_token(&token, &state.token_map, state.sa_decoding_key.as_deref());

    let status = match user_info {
        Some(u) => TokenReviewStatus {
            authenticated: true,
            user: Some(TokenReviewUser {
                username: u.username,
                uid: u.uid,
                groups: u.groups,
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

    #[test]
    fn test_authenticate_token_static_map_match() {
        // A token present in the static map must resolve to the correct UserInfo.
        // This is the primary use-case for TokenReview with --token-auth-file.
        use crate::auth::{authenticate_token, UserInfo};
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "argocd-token".to_owned(),
            UserInfo {
                username: "argocd-admin".to_owned(),
                uid: "42".to_owned(),
                groups: vec!["system:authenticated".to_owned()],
            },
        );

        let result = authenticate_token("argocd-token", &map, None);
        let user = result.expect("known token must resolve to a user");
        assert_eq!(user.username, "argocd-admin");
        assert!(user.groups.contains(&"system:authenticated".to_owned()));
    }

    #[test]
    fn test_authenticate_token_unknown_returns_none() {
        // An unrecognized token must return None — TokenReview will respond with
        // authenticated: false. A bad token must NEVER return a user.
        use crate::auth::authenticate_token;
        use std::collections::HashMap;

        let map = HashMap::new();
        let result = authenticate_token("unknown-token", &map, None);
        assert!(result.is_none(), "unrecognized token must not authenticate");
    }

    // ---------------------------------------------------------------------------
    // SubjectAccessReview privilege gate tests (mayor-mzcw)
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

    /// Build a minimal AppState with an empty RBAC index and no SA key.
    fn make_state() -> AppState {
        let store =
            Arc::new(u7s_store::SqliteStore::new(":memory:").expect("in-memory sqlite store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

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
    // Regression: Content-Type: application/json must not produce 415
    // -----------------------------------------------------------------------

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
}
