use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};

use crate::{auth::UserInfo, rbac::AuthzRequest, state::AppState};

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

pub async fn self_subject_access_review(
    State(state): State<AppState>,
    Extension(user): Extension<UserInfo>,
    Json(body): Json<SelfSubjectAccessReviewRequest>,
) -> impl IntoResponse {
    let allowed = if let Some(attrs) = body.spec.resource_attributes {
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
        })
    } else {
        false
    };

    let resp = SelfSubjectAccessReviewResponse {
        api_version: "authorization.k8s.io/v1",
        kind: "SelfSubjectAccessReview",
        status: AccessReviewStatus { allowed },
    };

    (StatusCode::CREATED, Json(resp))
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

pub async fn self_subject_rules_review(
    State(state): State<AppState>,
    Extension(user): Extension<UserInfo>,
    Json(body): Json<SelfSubjectRulesReviewRequest>,
) -> impl IntoResponse {
    let namespace = &body.spec.namespace;
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

    (StatusCode::CREATED, Json(resp))
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

pub async fn subject_access_review(
    State(state): State<AppState>,
    Extension(caller): Extension<UserInfo>,
    Json(body): Json<SubjectAccessReviewRequest>,
) -> impl IntoResponse {
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

    let spec = body.spec;
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

pub async fn token_review(
    State(state): State<AppState>,
    Json(body): Json<TokenReviewRequest>,
) -> impl IntoResponse {
    let token = body.spec.token;
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

    (StatusCode::CREATED, Json(resp))
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
        // system:masters must always return a single wildcard rule, not per-binding enumeration.
        // This ensures the caller can discover they have full access without revealing policy internals.
        let idx = RbacIndex::new();
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
            }),
            "a different user must not inherit argocd-bot's permissions"
        );
    }

    #[test]
    fn test_subject_access_review_system_masters_group_bypasses_rbac() {
        // A request whose groups include system:masters must always be allowed,
        // matching the same bypass used everywhere in the RBAC stack.
        let idx = Arc::new(RbacIndex::new()); // no bindings at all
        let groups = vec!["system:masters".to_owned()];

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
            }),
            "system:masters group must bypass RBAC regardless of bindings"
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
