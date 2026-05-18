// This module provides the RBAC engine; callers (handlers) are added by other workers.
#![allow(dead_code)]

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
    /// whose namespace matches `namespace`.  If the caller is in system:masters,
    /// returns a single wildcard rule instead of enumerating.
    pub fn enumerate_rules(
        &self,
        username: &str,
        groups: &[String],
        namespace: &str,
    ) -> Vec<PolicyRule> {
        // system:masters fast path.
        if groups.iter().any(|g| g == "system:masters") {
            return vec![PolicyRule {
                api_groups: vec!["*".to_owned()],
                resources: vec!["*".to_owned()],
                verbs: vec!["*".to_owned()],
                resource_names: vec![],
            }];
        }

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

    pub fn is_allowed(&self, req: &AuthzRequest<'_>) -> bool {
        // system:masters unconditional bypass
        if req.groups.iter().any(|g| g == "system:masters") {
            return true;
        }

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

// --- helpers ---

fn extract_last_segment(key: &str) -> String {
    key.split('/').rfind(|s| !s.is_empty()).unwrap_or("").to_owned()
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

fn resolve_cluster_role_rules<'a>(
    inner: &'a RbacInner,
    role_ref: &RoleRef,
) -> &'a [PolicyRule] {
    if role_ref.kind == "ClusterRole" {
        inner.cluster_roles.get(&role_ref.name).map(Vec::as_slice).unwrap_or(&[])
    } else {
        &[]
    }
}

fn resolve_role_rules<'a>(
    inner: &'a RbacInner,
    role_ref: &RoleRef,
    namespace: &str,
) -> &'a [PolicyRule] {
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
    if !rule.api_groups.iter().any(|g| g == "*" || g == req.api_group) {
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
        let key =
            format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}");
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

    fn make_role(
        ns: &str,
        name: &str,
        rules: serde_json::Value,
    ) -> (String, serde_json::Value) {
        let key = format!(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{name}"
        );
        let val = json!({ "rules": rules });
        (key, val)
    }

    fn make_role_binding(
        ns: &str,
        name: &str,
        role_name: &str,
        subjects: serde_json::Value,
    ) -> (String, serde_json::Value) {
        let key = format!(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}"
        );
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
    fn test_system_masters_bypass() {
        // system:masters group must bypass ALL policy checks — even with no bindings.
        let idx = RbacIndex::new();
        let groups = vec!["system:masters".to_owned()];
        let r = req("alice", &groups, "delete", "secrets", "", Some("kube-system"), None);
        assert!(
            idx.is_allowed(&r),
            "system:masters must always be allowed regardless of policy"
        );
    }

    #[test]
    fn test_default_deny() {
        // With no bindings at all, every request must be denied.
        let idx = RbacIndex::new();
        let groups: Vec<String> = vec![];
        let r = req("bob", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&r),
            "no bindings must result in deny"
        );
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
        let r = req("alice", &groups, "get", "pods", "", Some("production"), None);
        assert!(idx.is_allowed(&r), "cluster binding must grant access in any namespace");

        // list pods in namespace "staging" — must be allowed
        let r2 = req("alice", &groups, "list", "pods", "", Some("staging"), None);
        assert!(idx.is_allowed(&r2), "list must also be allowed via cluster binding");

        // delete pods — must be denied (not in verbs)
        let r3 = req("alice", &groups, "delete", "pods", "", Some("default"), None);
        assert!(!idx.is_allowed(&r3), "delete must be denied — not in rule verbs");
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
        let (bind_key, bind_val) =
            make_role_binding("foo", "alice-binding", "pod-reader", json!([{ "kind": "User", "name": "alice" }]));

        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // allowed in "foo"
        let r_foo = req("alice", &groups, "get", "pods", "", Some("foo"), None);
        assert!(idx.is_allowed(&r_foo), "must be allowed in bound namespace 'foo'");

        // denied in "bar" — binding is namespace-scoped
        let r_bar = req("alice", &groups, "get", "pods", "", Some("bar"), None);
        assert!(!idx.is_allowed(&r_bar), "must be denied in different namespace 'bar'");
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
        for verb in &["get", "list", "create", "update", "patch", "delete", "watch"] {
            let r = req("bob", &groups, verb, "pods", "", Some("default"), None);
            assert!(
                idx.is_allowed(&r),
                "wildcard verb must allow '{verb}'"
            );
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
        let r_log = req("carol", &groups, "get", "pods", "log", Some("default"), None);
        assert!(idx.is_allowed(&r_log), "pods/log must be allowed");

        // plain pods — must be denied (rule only covers pods/log)
        let r_pods = req("carol", &groups, "get", "pods", "", Some("default"), None);
        assert!(!idx.is_allowed(&r_pods), "plain pods must be denied when rule only covers pods/log");
    }
}
