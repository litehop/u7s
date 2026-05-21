// This module provides the RBAC engine; callers (handlers) are added by other workers.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyRule {
    #[serde(rename = "apiGroups", default)]
    pub api_groups: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(rename = "resourceNames", default)]
    pub resource_names: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Subject {
    pub kind: String,
    pub name: String,
    // Part of the RBAC Subject schema; used for ServiceAccount namespace scoping
    // when RBAC evaluation is extended beyond name-only matching.
    #[allow(dead_code)]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoleRef {
    #[serde(rename = "apiGroup")]
    pub api_group: String,
    pub kind: String,
    pub name: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RbacRole {
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RbacBinding {
    pub subjects: Vec<Subject>,
    #[serde(rename = "roleRef")]
    pub role_ref: RoleRef,
    pub namespace: Option<String>,
}

pub struct AuthzRequest<'a> {
    pub username: &'a str,
    pub groups: &'a [String],
    pub verb: &'a str,
    pub api_group: &'a str,
    pub resource: &'a str,
    pub subresource: &'a str,
    pub namespace: Option<&'a str>,
    pub name: Option<&'a str>,
}

pub struct RbacIndex {
    inner: Arc<RwLock<RbacInner>>,
}

struct RbacInner {
    cluster_roles: HashMap<String, Vec<PolicyRule>>,
    roles: HashMap<(String, String), Vec<PolicyRule>>,
    cluster_bindings: Vec<(String, RbacBinding)>, // (key, binding)
    namespace_bindings: Vec<(String, RbacBinding)>,
}

impl RbacIndex {
    pub fn new() -> Self {
        RbacIndex {
            inner: Arc::new(RwLock::new(RbacInner {
                cluster_roles: HashMap::new(),
                roles: HashMap::new(),
                cluster_bindings: Vec::new(),
                namespace_bindings: Vec::new(),
            })),
        }
    }

    /// Load or update a role or binding object from its store key and JSON value.
    pub fn apply_object(&self, key: &str, value: &serde_json::Value) {
        // Key format expected:
        //   /apis/rbac.authorization.k8s.io/v1/clusterroles/<name>
        //   /apis/rbac.authorization.k8s.io/v1/namespaces/<ns>/roles/<name>
        //   /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/<name>
        //   /apis/rbac.authorization.k8s.io/v1/namespaces/<ns>/rolebindings/<name>
        let mut inner = self.inner.write().unwrap();

        if key.contains("/clusterroles/") {
            if let Ok(role) = serde_json::from_value::<RbacRole>(value.clone()) {
                let name = extract_last_segment(key);
                inner.cluster_roles.insert(name, role.rules);
            }
        } else if key.contains("/clusterrolebindings/") {
            if let Ok(binding) = serde_json::from_value::<RbacBinding>(value.clone()) {
                // Remove old entry with this key first, then push.
                inner.cluster_bindings.retain(|(k, _)| k != key);
                inner.cluster_bindings.push((key.to_owned(), binding));
            }
        } else if key.contains("/roles/") {
            if let Ok(role) = serde_json::from_value::<RbacRole>(value.clone()) {
                let ns = extract_namespace(key).unwrap_or_default();
                let name = extract_last_segment(key);
                inner.roles.insert((ns, name), role.rules);
            }
        } else if key.contains("/rolebindings/") {
            if let Ok(binding) = serde_json::from_value::<RbacBinding>(value.clone()) {
                inner.namespace_bindings.retain(|(k, _)| k != key);
                inner.namespace_bindings.push((key.to_owned(), binding));
            }
        }
    }

    /// Remove a role or binding when its store object is deleted.
    pub fn remove_object(&self, key: &str) {
        let mut inner = self.inner.write().unwrap();

        if key.contains("/clusterroles/") {
            let name = extract_last_segment(key);
            inner.cluster_roles.remove(&name);
        } else if key.contains("/clusterrolebindings/") {
            inner.cluster_bindings.retain(|(k, _)| k != key);
        } else if key.contains("/roles/") {
            let ns = extract_namespace(key).unwrap_or_default();
            let name = extract_last_segment(key);
            inner.roles.remove(&(ns, name));
        } else if key.contains("/rolebindings/") {
            inner.namespace_bindings.retain(|(k, _)| k != key);
        }
    }

    /// Return all PolicyRules that apply to the caller in the given namespace.
    ///
    /// Includes rules from cluster bindings (always) and namespace bindings
    /// whose namespace matches `namespace`.
    pub fn enumerate_rules(
        &self,
        username: &str,
        groups: &[String],
        namespace: &str,
    ) -> Vec<PolicyRule> {
        let inner = self.inner.read().unwrap();
        let mut rules: Vec<PolicyRule> = Vec::new();

        // Cluster bindings apply in any namespace.
        for (_, binding) in &inner.cluster_bindings {
            if !subject_matches(binding, username, groups) {
                continue;
            }
            let r = resolve_cluster_role_rules(&inner, &binding.role_ref);
            rules.extend_from_slice(r);
        }

        // Namespace bindings scoped to the requested namespace.
        for (_, binding) in &inner.namespace_bindings {
            let binding_ns = binding.namespace.as_deref().unwrap_or("");
            if binding_ns != namespace {
                continue;
            }
            if !subject_matches(binding, username, groups) {
                continue;
            }
            let r = resolve_role_rules(&inner, &binding.role_ref, namespace);
            rules.extend_from_slice(r);
        }

        rules
    }

    /// Return a copy of the rules for the named ClusterRole, or empty if unknown.
    // Used by escalation-prevention callers and tests; wiring into generic.rs
    // handler is tracked separately (out of scope for this bead).
    #[allow(dead_code)]
    pub fn cluster_role_rules(&self, name: &str) -> Vec<PolicyRule> {
        let inner = self.inner.read().unwrap();
        inner.cluster_roles.get(name).cloned().unwrap_or_default()
    }

    pub fn is_allowed(&self, req: &AuthzRequest<'_>) -> bool {
        let inner = self.inner.read().unwrap();

        // Check cluster bindings first (namespace-agnostic).
        for (_, binding) in &inner.cluster_bindings {
            if !subject_matches(binding, req.username, req.groups) {
                continue;
            }
            let rules = resolve_cluster_role_rules(&inner, &binding.role_ref);
            if rules_allow(rules, req) {
                return true;
            }
        }

        // Check namespace-scoped bindings only when the request has a namespace.
        if let Some(req_ns) = req.namespace {
            for (_, binding) in &inner.namespace_bindings {
                // The binding's namespace must match the request namespace.
                let binding_ns = binding.namespace.as_deref().unwrap_or("");
                if binding_ns != req_ns {
                    continue;
                }
                if !subject_matches(binding, req.username, req.groups) {
                    continue;
                }
                let rules = resolve_role_rules(&inner, &binding.role_ref, req_ns);
                if rules_allow(rules, req) {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for RbacIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether `username`/`groups` already hold every permission enumerated
/// in `role_rules`.  Used by escalation prevention: a caller may only bind
/// themselves to a ClusterRole if they already have all of its rules.
// Wiring this into the HTTP create/update handler for ClusterRoleBindings is
// tracked separately — that handler (generic.rs) is out of scope for this bead.
#[allow(dead_code)]
///
/// Returns `true` if every rule in `role_rules` is already allowed for the
/// caller.  An empty rule set is trivially held (returns `true`).
pub fn user_holds_all_rules(
    username: &str,
    groups: &[String],
    role_rules: &[PolicyRule],
    rbac: &RbacIndex,
) -> bool {
    for rule in role_rules {
        // For each (api_group, resource, verb) combination in the rule, verify
        // the caller already has that permission.
        for api_group in &rule.api_groups {
            for resource in &rule.resources {
                for verb in &rule.verbs {
                    // Wildcard entries in the rule mean "all": we check a
                    // concrete representative.  If the caller has the wildcard
                    // grant themselves, is_allowed will cover it.
                    let req = AuthzRequest {
                        username,
                        groups,
                        verb,
                        api_group,
                        resource,
                        subresource: "",
                        namespace: None,
                        name: None,
                    };
                    if !rbac.is_allowed(&req) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

// --- helpers ---

fn extract_last_segment(key: &str) -> String {
    key.split('/')
        .rfind(|s| !s.is_empty())
        .unwrap_or("")
        .to_owned()
}

/// Extract namespace from key segments like .../namespaces/<ns>/roles/<name>
fn extract_namespace(key: &str) -> Option<String> {
    let parts: Vec<&str> = key.split('/').filter(|s| !s.is_empty()).collect();
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i] == "namespaces" {
            return Some(parts[i + 1].to_owned());
        }
    }
    None
}

fn subject_matches(binding: &RbacBinding, username: &str, groups: &[String]) -> bool {
    binding.subjects.iter().any(|s| match s.kind.as_str() {
        "User" => s.name == username,
        "Group" => groups.iter().any(|g| g == &s.name),
        "ServiceAccount" => s.name == username,
        _ => false,
    })
}

fn resolve_cluster_role_rules<'a>(inner: &'a RbacInner, role_ref: &RoleRef) -> &'a [PolicyRule] {
    if role_ref.kind == "ClusterRole" && role_ref.api_group == "rbac.authorization.k8s.io" {
        inner
            .cluster_roles
            .get(&role_ref.name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    } else {
        &[]
    }
}

fn resolve_role_rules<'a>(
    inner: &'a RbacInner,
    role_ref: &RoleRef,
    namespace: &str,
) -> &'a [PolicyRule] {
    if role_ref.api_group != "rbac.authorization.k8s.io" {
        return &[];
    }
    match role_ref.kind.as_str() {
        "Role" => inner
            .roles
            .get(&(namespace.to_owned(), role_ref.name.clone()))
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        "ClusterRole" => inner
            .cluster_roles
            .get(&role_ref.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        _ => &[],
    }
}

fn rules_allow(rules: &[PolicyRule], req: &AuthzRequest<'_>) -> bool {
    rules.iter().any(|rule| rule_covers(rule, req))
}

fn rule_covers(rule: &PolicyRule, req: &AuthzRequest<'_>) -> bool {
    // 1. api_groups
    if !rule
        .api_groups
        .iter()
        .any(|g| g == "*" || g == req.api_group)
    {
        return false;
    }

    // 2. verbs
    if !rule.verbs.iter().any(|v| v == "*" || v == req.verb) {
        return false;
    }

    // 3. resources (with subresource matching)
    if !resource_matches(&rule.resources, req.resource, req.subresource) {
        return false;
    }

    // 4. resource_names — empty means all names
    if !rule.resource_names.is_empty() {
        match req.name {
            Some(n) => {
                if !rule.resource_names.iter().any(|rn| rn == n) {
                    return false;
                }
            }
            None => return false, // name required but not provided
        }
    }

    true
}

/// Match rule resource strings against a (resource, subresource) pair.
///
/// - `"*"` matches any resource+subresource combination.
/// - `"pods"` matches resource=pods, subresource="" only.
/// - `"pods/log"` matches resource=pods, subresource=log.
/// - `"pods/*"` matches resource=pods with any non-empty subresource.
fn resource_matches(rule_resources: &[String], resource: &str, subresource: &str) -> bool {
    rule_resources.iter().any(|r| {
        if r == "*" {
            return true;
        }
        if let Some((res, sub)) = r.split_once('/') {
            // e.g. "pods/log" or "pods/*"
            if res != resource {
                return false;
            }
            sub == "*" || sub == subresource
        } else {
            // Plain resource, no subresource separator.
            r == resource && subresource.is_empty()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_cluster_role(name: &str, rules: serde_json::Value) -> (String, serde_json::Value) {
        let key = format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}");
        let val = json!({ "rules": rules });
        (key, val)
    }

    fn make_cluster_binding(
        name: &str,
        role_name: &str,
        subjects: serde_json::Value,
    ) -> (String, serde_json::Value) {
        let key = format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}");
        let val = json!({
            "subjects": subjects,
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": role_name
            }
        });
        (key, val)
    }

    fn make_role(ns: &str, name: &str, rules: serde_json::Value) -> (String, serde_json::Value) {
        let key = format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{name}");
        let val = json!({ "rules": rules });
        (key, val)
    }

    fn make_role_binding(
        ns: &str,
        name: &str,
        role_name: &str,
        subjects: serde_json::Value,
    ) -> (String, serde_json::Value) {
        let key = format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}");
        let val = json!({
            "subjects": subjects,
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": role_name
            },
            "namespace": ns
        });
        (key, val)
    }

    fn req<'a>(
        username: &'a str,
        groups: &'a [String],
        verb: &'a str,
        resource: &'a str,
        subresource: &'a str,
        namespace: Option<&'a str>,
        name: Option<&'a str>,
    ) -> AuthzRequest<'a> {
        AuthzRequest {
            username,
            groups,
            verb,
            api_group: "",
            resource,
            subresource,
            namespace,
            name,
        }
    }

    #[test]
    fn test_system_masters_via_rbac() {
        // system:masters access must be granted via a cluster-admin ClusterRoleBinding,
        // NOT via a hardcoded bypass.  Removing the binding must cause denial — this test
        // will fail if the bypass is re-introduced in code rather than through RBAC data.
        let idx = RbacIndex::new();

        // Without any bindings, system:masters must be denied.
        let groups = vec!["system:masters".to_owned()];
        let r = req(
            "alice",
            &groups,
            "delete",
            "secrets",
            "",
            Some("kube-system"),
            None,
        );
        assert!(
            !idx.is_allowed(&r),
            "system:masters must be DENIED when no ClusterRoleBinding exists — \
             the bypass must come from RBAC data, not from hardcoded logic"
        );

        // Seed cluster-admin ClusterRole and the system:masters binding.
        let (admin_role_key, admin_role_val) = make_cluster_role(
            "cluster-admin",
            json!([{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"]
            }]),
        );
        let (admin_bind_key, admin_bind_val) = make_cluster_binding(
            "system:masters",
            "cluster-admin",
            json!([{ "kind": "Group", "name": "system:masters" }]),
        );
        idx.apply_object(&admin_role_key, &admin_role_val);
        idx.apply_object(&admin_bind_key, &admin_bind_val);

        // Now system:masters must be allowed — via RBAC, not a bypass.
        assert!(
            idx.is_allowed(&r),
            "system:masters must be allowed after the cluster-admin ClusterRoleBinding is loaded"
        );

        // Remove the binding — must go back to denied.
        idx.remove_object(&admin_bind_key);
        assert!(
            !idx.is_allowed(&r),
            "system:masters must be denied again after the ClusterRoleBinding is removed — \
             proves access comes from RBAC state, not hardcoded logic"
        );
    }

    #[test]
    fn test_default_deny() {
        // With no bindings at all, every request must be denied.
        let idx = RbacIndex::new();
        let groups: Vec<String> = vec![];
        let r = req("bob", &groups, "get", "pods", "", Some("default"), None);
        assert!(!idx.is_allowed(&r), "no bindings must result in deny");
    }

    #[test]
    fn test_cluster_role_binding() {
        // A ClusterRoleBinding grants get/list on pods/* in any namespace.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods/*"],
                "verbs": ["get", "list"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "alice-pod-reader",
            "pod-reader",
            json!([{ "kind": "User", "name": "alice" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // get pods in namespace "production" — must be allowed
        let r = req(
            "alice",
            &groups,
            "get",
            "pods",
            "",
            Some("production"),
            None,
        );
        assert!(
            idx.is_allowed(&r),
            "cluster binding must grant access in any namespace"
        );

        // list pods in namespace "staging" — must be allowed
        let r2 = req("alice", &groups, "list", "pods", "", Some("staging"), None);
        assert!(
            idx.is_allowed(&r2),
            "list must also be allowed via cluster binding"
        );

        // delete pods — must be denied (not in verbs)
        let r3 = req(
            "alice",
            &groups,
            "delete",
            "pods",
            "",
            Some("default"),
            None,
        );
        assert!(
            !idx.is_allowed(&r3),
            "delete must be denied — not in rule verbs"
        );
    }

    #[test]
    fn test_role_binding_namespace_scoped() {
        // A RoleBinding in "foo" must not grant access in "bar".
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_role(
            "foo",
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_role_binding(
            "foo",
            "alice-binding",
            "pod-reader",
            json!([{ "kind": "User", "name": "alice" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // allowed in "foo"
        let r_foo = req("alice", &groups, "get", "pods", "", Some("foo"), None);
        assert!(
            idx.is_allowed(&r_foo),
            "must be allowed in bound namespace 'foo'"
        );

        // denied in "bar" — binding is namespace-scoped
        let r_bar = req("alice", &groups, "get", "pods", "", Some("bar"), None);
        assert!(
            !idx.is_allowed(&r_bar),
            "must be denied in different namespace 'bar'"
        );
    }

    #[test]
    fn test_wildcard_verb() {
        // A rule with verb "*" must allow any verb.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "all-pods",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["*"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "bob-all-pods",
            "all-pods",
            json!([{ "kind": "User", "name": "bob" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        for verb in &[
            "get", "list", "create", "update", "patch", "delete", "watch",
        ] {
            let r = req("bob", &groups, verb, "pods", "", Some("default"), None);
            assert!(idx.is_allowed(&r), "wildcard verb must allow '{verb}'");
        }
    }

    #[test]
    fn test_subresource_matching() {
        // Rule for "pods/log" allows pods/log but must NOT allow plain pods.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-log-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods/log"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "carol-log",
            "pod-log-reader",
            json!([{ "kind": "User", "name": "carol" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // pods/log — must be allowed
        let r_log = req(
            "carol",
            &groups,
            "get",
            "pods",
            "log",
            Some("default"),
            None,
        );
        assert!(idx.is_allowed(&r_log), "pods/log must be allowed");

        // plain pods — must be denied (rule only covers pods/log)
        let r_pods = req("carol", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&r_pods),
            "plain pods must be denied when rule only covers pods/log"
        );
    }

    #[test]
    fn rolebinding_namespace_mismatch_denies() {
        // A RoleBinding in namespace "foo" must NOT grant access to a request in
        // namespace "bar". Failing this check would be a silent authz bypass:
        // any user bound in one namespace could escalate to another.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_role(
            "foo",
            "secret-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["secrets"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_role_binding(
            "foo",
            "dave-secret-reader",
            "secret-reader",
            json!([{ "kind": "User", "name": "dave" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Allowed in the bound namespace.
        let r_foo = req("dave", &groups, "get", "secrets", "", Some("foo"), None);
        assert!(
            idx.is_allowed(&r_foo),
            "must be allowed in bound namespace 'foo'"
        );

        // Must be denied in a different namespace — the binding does not cross ns boundaries.
        let r_bar = req("dave", &groups, "get", "secrets", "", Some("bar"), None);
        assert!(
            !idx.is_allowed(&r_bar),
            "RoleBinding in 'foo' must not grant access in 'bar' — namespace boundary violation"
        );
    }

    #[test]
    fn clusterrolebinding_grants_in_namespace_scope() {
        // A ClusterRoleBinding must grant access even when the request specifies a
        // namespace. ClusterRoleBindings are namespace-agnostic by design; failing to
        // honor them for namespaced requests would silently deny legitimate cluster-wide
        // admin access.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "configmap-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get", "list"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "eve-configmap-reader",
            "configmap-reader",
            json!([{ "kind": "User", "name": "eve" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Request is namespace-scoped but the ClusterRoleBinding must still allow it.
        let r = req(
            "eve",
            &groups,
            "get",
            "configmaps",
            "",
            Some("production"),
            None,
        );
        assert!(
            idx.is_allowed(&r),
            "ClusterRoleBinding must grant access for namespace-scoped requests"
        );

        // Also works in a different namespace — cluster-wide binding is not namespace-restricted.
        let r2 = req(
            "eve",
            &groups,
            "list",
            "configmaps",
            "",
            Some("kube-system"),
            None,
        );
        assert!(
            idx.is_allowed(&r2),
            "ClusterRoleBinding must grant access in any namespace"
        );
    }

    #[test]
    fn resource_names_empty_matches_all() {
        // A rule with resourceNames: [] (empty) must match a request for any resource
        // name. Empty resourceNames means "no restriction" in Kubernetes RBAC. If this
        // were treated as "no names allowed" it would silently deny all named-resource
        // requests, which would be a correctness bug.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-getter",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"],
                "resourceNames": []
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "frank-pod-getter",
            "pod-getter",
            json!([{ "kind": "User", "name": "frank" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Request for a specific named pod — must be allowed because resourceNames is empty.
        let r = req(
            "frank",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            Some("my-pod"),
        );
        assert!(
            idx.is_allowed(&r),
            "empty resourceNames must match any name — treating it as a deny-all would be a bug"
        );

        // Request without a name — also must be allowed.
        let r2 = req("frank", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            idx.is_allowed(&r2),
            "empty resourceNames must also match requests that supply no name"
        );
    }

    #[test]
    fn resource_names_non_empty_restricts() {
        // A rule with resourceNames: ["allowed-pod"] must deny a request for a
        // different name. Failing this check would be an escalation: a user granted
        // access to one named resource could access any resource of that type.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "named-pod-getter",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"],
                "resourceNames": ["allowed-pod"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "grace-named-pod",
            "named-pod-getter",
            json!([{ "kind": "User", "name": "grace" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Allowed name — must be permitted.
        let r_ok = req(
            "grace",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            Some("allowed-pod"),
        );
        assert!(
            idx.is_allowed(&r_ok),
            "request for the explicitly listed resourceName must be allowed"
        );

        // Different name — must be denied (not in the resourceNames list).
        let r_deny = req(
            "grace",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            Some("other-pod"),
        );
        assert!(
            !idx.is_allowed(&r_deny),
            "request for a name not in resourceNames must be denied — would be an escalation"
        );

        // No name supplied — must be denied when resourceNames is non-empty.
        let r_no_name = req("grace", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&r_no_name),
            "request with no name must be denied when resourceNames is non-empty"
        );
    }

    #[test]
    fn subresource_rule_does_not_bleed_across_subresources() {
        // A rule granting ["pods", "pods/log"] must allow pods and pods/log but must
        // NOT allow pods/status. Subresource rules are explicit — bleeding across
        // subresources would let a user escalate from log access to status/exec/etc.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-and-log",
            json!([{
                "apiGroups": [""],
                "resources": ["pods", "pods/log"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "hank-pod-log",
            "pod-and-log",
            json!([{ "kind": "User", "name": "hank" }]),
        );

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Plain pods — must be allowed.
        let r_pods = req("hank", &groups, "get", "pods", "", Some("default"), None);
        assert!(idx.is_allowed(&r_pods), "plain pods must be allowed");

        // pods/log — must be allowed.
        let r_log = req("hank", &groups, "get", "pods", "log", Some("default"), None);
        assert!(idx.is_allowed(&r_log), "pods/log must be allowed");

        // pods/status — must be denied (not in the rule's resource list).
        let r_status = req(
            "hank",
            &groups,
            "get",
            "pods",
            "status",
            Some("default"),
            None,
        );
        assert!(
            !idx.is_allowed(&r_status),
            "pods/status must be denied — pods/log rule must not bleed to other subresources"
        );

        // pods/exec — must also be denied.
        let r_exec = req(
            "hank",
            &groups,
            "get",
            "pods",
            "exec",
            Some("default"),
            None,
        );
        assert!(
            !idx.is_allowed(&r_exec),
            "pods/exec must be denied — pods/log rule must not bleed to other subresources"
        );
    }

    #[test]
    fn escalation_check_denies_unprivileged_user_binding_to_cluster_admin() {
        // A user who can create ClusterRoleBindings but does NOT already hold
        // cluster-admin permissions must NOT pass the escalation check when
        // binding to cluster-admin.  This is Kubernetes RBAC escalation
        // prevention (v1.17+): you cannot grant permissions you don't already
        // have.
        let idx = RbacIndex::new();

        // Seed cluster-admin ClusterRole with wildcard rules.
        let (admin_role_key, admin_role_val) = make_cluster_role(
            "cluster-admin",
            json!([{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"]
            }]),
        );
        idx.apply_object(&admin_role_key, &admin_role_val);

        // Give "carol" only create on clusterrolebindings — NOT cluster-admin.
        let (carol_role_key, carol_role_val) = make_cluster_role(
            "crb-creator",
            json!([{
                "apiGroups": ["rbac.authorization.k8s.io"],
                "resources": ["clusterrolebindings"],
                "verbs": ["create"]
            }]),
        );
        let (carol_bind_key, carol_bind_val) = make_cluster_binding(
            "carol-crb-creator",
            "crb-creator",
            json!([{ "kind": "User", "name": "carol" }]),
        );
        idx.apply_object(&carol_role_key, &carol_role_val);
        idx.apply_object(&carol_bind_key, &carol_bind_val);

        // The rules in cluster-admin that carol would be granting.
        let admin_rules = idx.cluster_role_rules("cluster-admin");
        let groups: Vec<String> = vec![];

        // Escalation check: carol cannot grant permissions she doesn't hold.
        assert!(
            !user_holds_all_rules("carol", &groups, &admin_rules, &idx),
            "carol must fail the escalation check: she does not hold cluster-admin rules"
        );
    }

    #[test]
    fn escalation_check_permits_user_who_already_holds_all_rules() {
        // A user who already has all permissions in a ClusterRole must pass
        // the escalation check and be allowed to create a binding to it.
        // This is required so that admins can manage bindings for roles they
        // already hold.
        let idx = RbacIndex::new();

        // A limited role: get/list pods.
        let (pod_role_key, pod_role_val) = make_cluster_role(
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]),
        );
        idx.apply_object(&pod_role_key, &pod_role_val);

        // "dave" already holds get/list pods via his own binding.
        let (dave_role_key, dave_role_val) = make_cluster_role(
            "dave-role",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]),
        );
        let (dave_bind_key, dave_bind_val) = make_cluster_binding(
            "dave-binding",
            "dave-role",
            json!([{ "kind": "User", "name": "dave" }]),
        );
        idx.apply_object(&dave_role_key, &dave_role_val);
        idx.apply_object(&dave_bind_key, &dave_bind_val);

        let pod_reader_rules = idx.cluster_role_rules("pod-reader");
        let groups: Vec<String> = vec![];

        // Dave already has all of pod-reader's rules — escalation check passes.
        assert!(
            user_holds_all_rules("dave", &groups, &pod_reader_rules, &idx),
            "dave must pass the escalation check: he already holds all pod-reader rules"
        );
    }

    #[test]
    fn escalation_check_system_masters_always_passes() {
        // Members of system:masters pass escalation checks because they hold all
        // permissions via the cluster-admin ClusterRoleBinding — not via a hardcoded bypass.
        let idx = RbacIndex::new();

        let (admin_role_key, admin_role_val) = make_cluster_role(
            "cluster-admin",
            json!([{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"]
            }]),
        );
        idx.apply_object(&admin_role_key, &admin_role_val);

        // Bind system:masters to cluster-admin (as seed_rbac() does at startup).
        let (admin_bind_key, admin_bind_val) = make_cluster_binding(
            "system:masters",
            "cluster-admin",
            json!([{ "kind": "Group", "name": "system:masters" }]),
        );
        idx.apply_object(&admin_bind_key, &admin_bind_val);

        let admin_rules = idx.cluster_role_rules("cluster-admin");
        let groups = vec!["system:masters".to_owned()];

        // system:masters holds all rules via RBAC — escalation check passes.
        assert!(
            user_holds_all_rules("admin-user", &groups, &admin_rules, &idx),
            "system:masters members must pass the escalation check via their cluster-admin binding"
        );
    }

    #[test]
    fn clusterrolebinding_wrong_api_group_denies() {
        // A ClusterRoleBinding whose roleRef.apiGroup is not "rbac.authorization.k8s.io"
        // must NOT grant access even when the role name matches. Kubernetes only resolves
        // roleRefs in the RBAC API group; accepting bindings from other groups would allow
        // privilege escalation by crafting a binding with an arbitrary group name.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
        );
        idx.apply_object(&role_key, &role_val);

        // Binding with a wrong apiGroup — must be ignored even though role name matches.
        let bind_key =
            "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/wrong-group-binding".to_owned();
        let bind_val = json!({
            "subjects": [{ "kind": "User", "name": "mallory" }],
            "roleRef": {
                "apiGroup": "wrong.group",
                "kind": "ClusterRole",
                "name": "pod-reader"
            }
        });
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        let r = req("mallory", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&r),
            "roleRef with wrong apiGroup must not grant access — accepting any apiGroup would be a privilege escalation"
        );
    }
}
