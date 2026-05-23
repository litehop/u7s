/// Pure, testable logic extracted from u7s-controller-manager.
///
/// All async I/O stays in main.rs. This module contains only functions
/// that can be exercised without a live API server.
use serde::Deserialize;
use serde_json::Value;

pub mod namespace_controller;

// ---------------------------------------------------------------------------
// Secret construction
// ---------------------------------------------------------------------------

/// Typed `data` field for a `kubernetes.io/service-account-token` Secret.
///
/// Using a struct rather than a raw `json!` literal ensures that field names
/// are checked at compile time — a typo like `"tokne"` would silently produce
/// a wrong Secret that no client can consume.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SecretData {
    pub token: String,
}

/// Build the Secret object that holds a service-account token.
///
/// The Secret type and annotation are required by the Kubernetes SA token
/// controller contract; tools like kubectl rely on the `<sa-name>-token`
/// naming convention.
pub fn build_sa_token_secret(namespace: &str, sa_name: &str, token_b64: &str) -> Value {
    let data = SecretData {
        token: token_b64.to_owned(),
    };
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": format!("{sa_name}-token"),
            "namespace": namespace,
            "annotations": {
                "kubernetes.io/service-account.name": sa_name
            }
        },
        "type": "kubernetes.io/service-account-token",
        "data": serde_json::to_value(data).expect("SecretData serializes")
    })
}

// ---------------------------------------------------------------------------
// Watch event parsing
// ---------------------------------------------------------------------------

/// Typed envelope for a Kubernetes watch event.
///
/// Using a struct rather than raw `event["type"]` / `event["object"][...]`
/// indexing means a missing or mistyped field is a deserialization error,
/// not a silent empty string that causes service accounts to be skipped.
#[derive(Debug, Deserialize)]
struct WatchEvent<T> {
    #[serde(rename = "type")]
    event_type: String,
    object: T,
}

/// Minimal typed view of a ServiceAccount's metadata in a watch event.
#[derive(Debug, Default, Deserialize)]
struct SaMetadata {
    name: Option<String>,
    namespace: Option<String>,
}

/// Minimal typed view of a ServiceAccount object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct SaObject {
    metadata: SaMetadata,
}

/// Extract (namespace, sa_name) from a ServiceAccount ADDED watch event.
///
/// Returns `None` if:
/// - the event type is not "ADDED", or
/// - the SA name is missing/empty.
///
/// Namespace defaults to "default" when missing, matching Kubernetes behaviour.
pub fn parse_sa_added_event(event: &Value) -> Option<(String, String)> {
    let watch_event: WatchEvent<SaObject> =
        serde_json::from_value(event.clone()).unwrap_or_else(|_| WatchEvent {
            event_type: String::new(),
            object: SaObject::default(),
        });
    if watch_event.event_type != "ADDED" {
        return None;
    }
    let sa_name = watch_event.object.metadata.name.as_deref().unwrap_or("");
    if sa_name.is_empty() {
        return None;
    }
    let namespace = watch_event
        .object
        .metadata
        .namespace
        .unwrap_or_else(|| "default".to_owned());
    Some((namespace, sa_name.to_owned()))
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Path for the TokenRequest sub-resource of a ServiceAccount.
pub fn token_request_path(namespace: &str, sa_name: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token")
}

/// Path for the Secrets collection in a namespace.
pub fn secrets_path(namespace: &str) -> String {
    format!("/api/v1/namespaces/{namespace}/secrets")
}

// ---------------------------------------------------------------------------
// ClusterRole aggregation controller — pure logic (mayor-5u0r)
// ---------------------------------------------------------------------------

/// Minimal typed view of a ClusterRole's metadata in a watch event.
#[derive(Debug, Default, Deserialize)]
struct ClusterRoleMetadata {
    name: Option<String>,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
}

/// Minimal typed view of a LabelSelector for aggregation rule matching.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct LabelSelector {
    #[serde(rename = "matchLabels", default)]
    pub match_labels: std::collections::HashMap<String, String>,
}

/// Minimal typed view of a ClusterRole's aggregationRule.
#[derive(Debug, Default, Deserialize)]
struct AggregationRule {
    #[serde(rename = "clusterRoleSelectors", default)]
    cluster_role_selectors: Vec<LabelSelector>,
}

/// Minimal typed view of a single PolicyRule — mirrors the RBAC API.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct PolicyRule {
    #[serde(rename = "apiGroups", default)]
    pub api_groups: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(rename = "resourceNames", default)]
    pub resource_names: Vec<String>,
    #[serde(rename = "nonResourceURLs", default)]
    pub non_resource_urls: Vec<String>,
}

/// Minimal typed view of a ClusterRole object in a watch event.
#[derive(Debug, Default, Deserialize)]
struct ClusterRoleObject {
    metadata: ClusterRoleMetadata,
    #[serde(default)]
    rules: Vec<PolicyRule>,
    #[serde(rename = "aggregationRule")]
    aggregation_rule: Option<AggregationRule>,
}

/// An immutable snapshot of a ClusterRole: name, labels, rules, and whether
/// it is itself an aggregated role.
#[derive(Debug, Clone)]
pub struct ClusterRoleSnapshot {
    pub name: String,
    pub labels: std::collections::HashMap<String, String>,
    pub rules: Vec<PolicyRule>,
    pub selectors: Vec<LabelSelector>,
}

/// Parse a ClusterRole watch event (ADDED / MODIFIED / DELETED) into a
/// `(event_type, ClusterRoleSnapshot)` pair.
///
/// Returns `None` if the event is malformed or the ClusterRole has no name.
pub fn parse_cluster_role_event(event: &Value) -> Option<(String, ClusterRoleSnapshot)> {
    let watch_event: WatchEvent<ClusterRoleObject> = serde_json::from_value(event.clone())
        .unwrap_or_else(|_| WatchEvent {
            event_type: String::new(),
            object: ClusterRoleObject::default(),
        });
    let name = watch_event.object.metadata.name?;
    if name.is_empty() {
        return None;
    }
    let selectors = watch_event
        .object
        .aggregation_rule
        .map(|ar| ar.cluster_role_selectors)
        .unwrap_or_default();
    Some((
        watch_event.event_type,
        ClusterRoleSnapshot {
            name,
            labels: watch_event.object.metadata.labels,
            rules: watch_event.object.rules,
            selectors,
        },
    ))
}

/// Return true if `labels` satisfies all constraints in `selector`.
///
/// A selector matches when every key/value pair in `match_labels` is present
/// in the target's labels with the exact same value.  An empty selector
/// (no matchLabels) matches every ClusterRole.
pub fn selector_matches(
    selector: &LabelSelector,
    labels: &std::collections::HashMap<String, String>,
) -> bool {
    selector
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k).map(String::as_str) == Some(v.as_str()))
}

/// Compute the merged rules for an aggregated ClusterRole.
///
/// For each selector in `aggregated_role.selectors`, collect every
/// ClusterRole in `all_roles` whose labels match that selector (excluding the
/// aggregated role itself to avoid self-referential loops), and merge their
/// rules into a single deduplicated list.
///
/// The aggregated role itself is identified by name: we skip any snapshot
/// whose name equals `aggregated_role.name`.
pub fn compute_aggregated_rules(
    aggregated_role: &ClusterRoleSnapshot,
    all_roles: &[ClusterRoleSnapshot],
) -> Vec<PolicyRule> {
    let mut merged: Vec<PolicyRule> = Vec::new();
    for role in all_roles {
        if role.name == aggregated_role.name {
            continue; // skip self
        }
        let matches = aggregated_role
            .selectors
            .iter()
            .any(|sel| selector_matches(sel, &role.labels));
        if matches {
            merged.extend_from_slice(&role.rules);
        }
    }
    merged
}

/// Path for the ClusterRoles collection.
pub fn cluster_roles_watch_path() -> &'static str {
    "/apis/rbac.authorization.k8s.io/v1/clusterroles?watch=true"
}

/// Path to PATCH a specific ClusterRole (strategic merge patch).
pub fn cluster_role_patch_path(name: &str) -> String {
    format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SecretData ---

    /// SecretData must serialize to {"token":"<value>"} so that the SA token
    /// controller stores data the kubelet and clients can read back.
    /// A field rename regression ("tokne", "Token") silently breaks all SA auth.
    #[test]
    fn secret_data_serializes_token_field() {
        let d = SecretData {
            token: "dG9rZW4=".to_owned(),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["token"], "dG9rZW4=");
        assert_eq!(
            v.as_object().unwrap().len(),
            1,
            "SecretData must only emit 'token'"
        );
    }

    /// SecretData must round-trip through JSON so stored values can be read back.
    #[test]
    fn secret_data_round_trips() {
        let original = SecretData {
            token: "abc123".to_owned(),
        };
        let v = serde_json::to_value(&original).unwrap();
        let restored: SecretData = serde_json::from_value(v).unwrap();
        assert_eq!(restored.token, "abc123");
    }

    // --- build_sa_token_secret ---

    #[test]
    fn secret_has_correct_kind_and_type() {
        // The API server relies on kind=Secret and the SA token type to
        // route the object to the right storage backend.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(s["kind"], "Secret");
        assert_eq!(s["type"], "kubernetes.io/service-account-token");
    }

    #[test]
    fn secret_name_follows_convention() {
        // kubectl and tooling expect "<sa-name>-token" naming.
        let s = build_sa_token_secret("kube-system", "coredns", "abc");
        assert_eq!(s["metadata"]["name"], "coredns-token");
    }

    #[test]
    fn secret_namespace_is_set() {
        let s = build_sa_token_secret("kube-system", "coredns", "abc");
        assert_eq!(s["metadata"]["namespace"], "kube-system");
    }

    #[test]
    fn secret_annotation_links_to_sa() {
        // The annotation is the machine-readable link back to the owning SA.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(
            s["metadata"]["annotations"]["kubernetes.io/service-account.name"],
            "my-sa"
        );
    }

    #[test]
    fn secret_data_token_field_set() {
        // The token must be stored under the "token" key in data.
        let s = build_sa_token_secret("default", "my-sa", "dG9rZW4=");
        assert_eq!(s["data"]["token"], "dG9rZW4=");
    }

    #[test]
    fn secret_api_version_is_v1() {
        let s = build_sa_token_secret("default", "svc", "x");
        assert_eq!(s["apiVersion"], "v1");
    }

    // --- WatchEvent deserialization ---

    // Verifies that the typed envelope correctly maps "type" → event_type and
    // "object" → object. A rename or missing field would cause every watch event
    // to be silently ignored (parse failure falls back to empty event_type).
    #[test]
    fn watch_event_deserializes_type_and_object() {
        let json = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-sa", "namespace": "production" }
            }
        });
        let we: WatchEvent<SaObject> =
            serde_json::from_value(json).expect("WatchEvent should deserialize");
        assert_eq!(we.event_type, "ADDED");
        assert_eq!(we.object.metadata.name.as_deref(), Some("my-sa"));
        assert_eq!(we.object.metadata.namespace.as_deref(), Some("production"));
    }

    // --- parse_sa_added_event ---

    #[test]
    fn parse_added_event_returns_namespace_and_name() {
        // Happy path: ADDED event with both fields populated.
        let event = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "my-sa", "namespace": "production" }
            }
        });
        assert_eq!(
            parse_sa_added_event(&event),
            Some(("production".to_owned(), "my-sa".to_owned()))
        );
    }

    #[test]
    fn parse_added_event_ignores_non_added_types() {
        // MODIFIED and DELETED events must not trigger provisioning — doing so
        // would cause duplicate or spurious secret creation.
        for event_type in &["MODIFIED", "DELETED", "BOOKMARK", "ERROR"] {
            let event = serde_json::json!({
                "type": event_type,
                "object": {
                    "metadata": { "name": "my-sa", "namespace": "default" }
                }
            });
            assert_eq!(
                parse_sa_added_event(&event),
                None,
                "expected None for event type {event_type}"
            );
        }
    }

    #[test]
    fn parse_added_event_returns_none_for_empty_name() {
        // An SA with no name is malformed; skip to avoid creating
        // a secret named "-token".
        let event = serde_json::json!({
            "type": "ADDED",
            "object": {
                "metadata": { "name": "", "namespace": "default" }
            }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    #[test]
    fn parse_added_event_returns_none_for_missing_name() {
        let event = serde_json::json!({
            "type": "ADDED",
            "object": { "metadata": { "namespace": "default" } }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    #[test]
    fn parse_added_event_defaults_namespace_to_default() {
        // Kubernetes defaults namespace to "default" when not specified.
        let event = serde_json::json!({
            "type": "ADDED",
            "object": { "metadata": { "name": "my-sa" } }
        });
        assert_eq!(
            parse_sa_added_event(&event),
            Some(("default".to_owned(), "my-sa".to_owned()))
        );
    }

    #[test]
    fn parse_added_event_returns_none_for_missing_type() {
        // An event with no type field must not be treated as ADDED.
        let event = serde_json::json!({
            "object": { "metadata": { "name": "my-sa", "namespace": "default" } }
        });
        assert_eq!(parse_sa_added_event(&event), None);
    }

    // --- URL helpers ---

    #[test]
    fn token_request_path_format() {
        // The path must match the Kubernetes API exactly — wrong paths return 404.
        assert_eq!(
            token_request_path("production", "my-sa"),
            "/api/v1/namespaces/production/serviceaccounts/my-sa/token"
        );
    }

    #[test]
    fn secrets_path_format() {
        assert_eq!(
            secrets_path("kube-system"),
            "/api/v1/namespaces/kube-system/secrets"
        );
    }

    // --- ClusterRole aggregation controller (mayor-5u0r) ---

    fn make_rule(verbs: &[&str], resources: &[&str]) -> PolicyRule {
        PolicyRule {
            api_groups: vec!["".to_owned()],
            resources: resources.iter().map(|s| s.to_string()).collect(),
            verbs: verbs.iter().map(|s| s.to_string()).collect(),
            resource_names: vec![],
            non_resource_urls: vec![],
        }
    }

    fn make_role(
        name: &str,
        labels: &[(&str, &str)],
        rules: Vec<PolicyRule>,
        selectors: Vec<LabelSelector>,
    ) -> ClusterRoleSnapshot {
        ClusterRoleSnapshot {
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            rules,
            selectors,
        }
    }

    fn selector(labels: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn aggregation_merges_rules_from_matching_sub_roles() {
        // An aggregated ClusterRole (e.g. "edit") must collect and merge rules from
        // all sub-roles whose labels match its selectors. Without this, the aggregated
        // role remains empty and grants nothing, breaking Argo CD's RBAC model which
        // depends on aggregation to compose the admin/edit/view roles.
        let sub_role_a = make_role(
            "argocd-view",
            &[("rbac.authorization.k8s.io/aggregate-to-edit", "true")],
            vec![make_rule(&["get", "list"], &["applications"])],
            vec![],
        );
        let sub_role_b = make_role(
            "argocd-edit",
            &[("rbac.authorization.k8s.io/aggregate-to-edit", "true")],
            vec![make_rule(
                &["create", "update", "delete"],
                &["applications"],
            )],
            vec![],
        );
        let aggregated = make_role(
            "edit",
            &[],
            vec![], // starts empty
            vec![selector(&[(
                "rbac.authorization.k8s.io/aggregate-to-edit",
                "true",
            )])],
        );

        let all_roles = vec![sub_role_a, sub_role_b, aggregated.clone()];
        let merged = compute_aggregated_rules(&aggregated, &all_roles);

        assert_eq!(
            merged.len(),
            2,
            "merged rules must contain one rule from each matching sub-role; got {merged:?}"
        );

        // Verify both verb sets are present.
        let all_verbs: Vec<&str> = merged
            .iter()
            .flat_map(|r| r.verbs.iter().map(|v| v.as_str()))
            .collect();
        assert!(
            all_verbs.contains(&"get"),
            "merged rules must include 'get' from argocd-view"
        );
        assert!(
            all_verbs.contains(&"create"),
            "merged rules must include 'create' from argocd-edit"
        );
    }

    #[test]
    fn aggregation_does_not_include_self() {
        // The aggregated role itself must never contribute rules to its own computation.
        // Without this guard, a self-referential loop would double-count the aggregated
        // role's existing rules on every reconcile cycle.
        let sub_role = make_role(
            "sub",
            &[("rbac.authorization.k8s.io/aggregate-to-view", "true")],
            vec![make_rule(&["get"], &["pods"])],
            vec![],
        );
        // The aggregated role also carries the matching label — must be excluded.
        let aggregated = make_role(
            "view",
            &[("rbac.authorization.k8s.io/aggregate-to-view", "true")],
            vec![make_rule(&["watch"], &["pods"])], // pre-existing rule on self
            vec![selector(&[(
                "rbac.authorization.k8s.io/aggregate-to-view",
                "true",
            )])],
        );

        let all_roles = vec![sub_role, aggregated.clone()];
        let merged = compute_aggregated_rules(&aggregated, &all_roles);

        // Only the sub-role's rules must appear, not the aggregated role's own rules.
        assert_eq!(
            merged.len(),
            1,
            "aggregated role must not include its own rules to avoid self-referential duplication"
        );
        assert!(
            merged[0].verbs.contains(&"get".to_owned()),
            "only sub-role rules must appear in merged output"
        );
    }

    #[test]
    fn aggregation_empty_when_no_sub_roles_match() {
        // An aggregated role with no matching sub-roles must produce an empty rule set.
        // This is the correct initial state and means "no permissions granted" —
        // not an error condition.
        let unrelated = make_role(
            "unrelated",
            &[("some-other-label", "true")],
            vec![make_rule(&["get"], &["secrets"])],
            vec![],
        );
        let aggregated = make_role(
            "admin",
            &[],
            vec![],
            vec![selector(&[(
                "rbac.authorization.k8s.io/aggregate-to-admin",
                "true",
            )])],
        );

        let all_roles = vec![unrelated, aggregated.clone()];
        let merged = compute_aggregated_rules(&aggregated, &all_roles);

        assert!(
            merged.is_empty(),
            "no matching sub-roles must produce empty merged rules — \
             aggregate-to-admin label is absent on the unrelated role"
        );
    }

    #[test]
    fn selector_matches_requires_all_labels_to_match() {
        // A selector with multiple match_labels must require ALL of them to be
        // present on the target. A partial match (one label matches, another doesn't)
        // must NOT select the role — partial matching would grant excessive access.
        let mut full_labels = std::collections::HashMap::new();
        full_labels.insert("app".to_owned(), "argocd".to_owned());
        full_labels.insert(
            "rbac.authorization.k8s.io/aggregate-to-admin".to_owned(),
            "true".to_owned(),
        );

        let mut partial_labels = std::collections::HashMap::new();
        partial_labels.insert("app".to_owned(), "argocd".to_owned());
        // Missing the aggregate label — must NOT match.

        let sel = selector(&[
            ("app", "argocd"),
            ("rbac.authorization.k8s.io/aggregate-to-admin", "true"),
        ]);

        assert!(
            selector_matches(&sel, &full_labels),
            "selector must match when all required labels are present"
        );
        assert!(
            !selector_matches(&sel, &partial_labels),
            "selector must NOT match when any required label is missing — \
             partial match would be a privilege escalation"
        );
    }

    #[test]
    fn parse_cluster_role_event_returns_none_for_missing_name() {
        // A ClusterRole watch event with no metadata.name must return None.
        // Silently accepting nameless roles could corrupt the aggregation map.
        let event = serde_json::json!({
            "type": "ADDED",
            "object": { "metadata": {} }
        });
        assert!(
            parse_cluster_role_event(&event).is_none(),
            "events with no name must return None to avoid inserting nameless roles"
        );
    }

    #[test]
    fn parse_cluster_role_event_parses_aggregation_rule() {
        // A ClusterRole watch event with an aggregationRule must be parsed correctly.
        // The selectors must be preserved so the controller can recompute the aggregated
        // role when sub-roles change.
        let event = serde_json::json!({
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "name": "admin",
                    "labels": {}
                },
                "aggregationRule": {
                    "clusterRoleSelectors": [
                        { "matchLabels": { "rbac.authorization.k8s.io/aggregate-to-admin": "true" } }
                    ]
                },
                "rules": []
            }
        });
        let result = parse_cluster_role_event(&event);
        assert!(result.is_some(), "aggregated ClusterRole event must parse");
        let (event_type, snap) = result.unwrap();
        assert_eq!(event_type, "MODIFIED");
        assert_eq!(snap.name, "admin");
        assert_eq!(snap.selectors.len(), 1);
        assert_eq!(
            snap.selectors[0]
                .match_labels
                .get("rbac.authorization.k8s.io/aggregate-to-admin"),
            Some(&"true".to_owned())
        );
    }
}
