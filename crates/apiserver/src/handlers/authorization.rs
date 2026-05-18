use axum::{
    Extension,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::UserInfo,
    rbac::AuthzRequest,
    state::AppState,
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

pub async fn self_subject_access_review(
    State(state): State<AppState>,
    Extension(user): Extension<UserInfo>,
    Json(body): Json<SelfSubjectAccessReviewRequest>,
) -> impl IntoResponse {
    let allowed = if let Some(attrs) = body.spec.resource_attributes {
        let ns = if attrs.namespace.is_empty() { None } else { Some(attrs.namespace.as_str()) };
        let name = if attrs.name.is_empty() { None } else { Some(attrs.name.as_str()) };

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
    let policy_rules = state.rbac_index.enumerate_rules(&user.username, &user.groups, namespace);

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
        assert!(rules.is_empty(), "bob must see no rules when he has no bindings");
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
}
