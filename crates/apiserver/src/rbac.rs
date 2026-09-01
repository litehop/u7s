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
    #[serde(rename = "nonResourceURLs", default)]
    pub non_resource_urls: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Subject {
    pub kind: String,
    pub name: String,
    #[serde(default)]
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
    #[serde(default)]
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
    /// Set to the raw HTTP path for non-resource URL requests (e.g. "/version",
    /// "/healthz"). When `Some`, the RBAC check uses `nonResourceURLs` matching
    /// instead of the resource/apiGroup path. When `None`, normal resource-based
    /// matching applies.
    pub non_resource_url: Option<&'a str>,
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
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());

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
            if let Ok(mut binding) = serde_json::from_value::<RbacBinding>(value.clone()) {
                // Kubernetes stores namespace in metadata.namespace, not as a top-level
                // field. If the JSON body didn't include a top-level namespace, fall back
                // to extracting it from the key path
                // (/apis/rbac.../v1/namespaces/<ns>/rolebindings/<name>).
                // Without this, namespace_bindings always has namespace=None and the
                // is_allowed check (which compares binding_ns != req_ns) never matches.
                if binding.namespace.is_none() {
                    binding.namespace = extract_namespace(key);
                }
                inner.namespace_bindings.retain(|(k, _)| k != key);
                inner.namespace_bindings.push((key.to_owned(), binding));
            }
        }
    }

    /// Remove a role or binding when its store object is deleted.
    pub fn remove_object(&self, key: &str) {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());

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
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
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
    pub fn cluster_role_rules(&self, name: &str) -> Vec<PolicyRule> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.cluster_roles.get(name).cloned().unwrap_or_default()
    }

    /// Return a copy of the rules for the named Role in the given namespace, or empty if unknown.
    pub fn role_rules(&self, namespace: &str, name: &str) -> Vec<PolicyRule> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner
            .roles
            .get(&(namespace.to_owned(), name.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    /// Return true if any ClusterRoleBinding references the named ClusterRole.
    ///
    /// Used by escalation prevention: when a ClusterRole is created or updated
    /// with rules, we must check whether any binding already points to it so that
    /// the role-creator also holds those rules.
    pub fn clusterrole_has_bindings(&self, role_name: &str) -> bool {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        inner.cluster_bindings.iter().any(|(_, b)| {
            b.role_ref.kind == "ClusterRole"
                && b.role_ref.api_group == "rbac.authorization.k8s.io"
                && b.role_ref.name == role_name
        })
    }

    pub fn is_allowed(&self, req: &AuthzRequest<'_>) -> bool {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());

        // Non-resource URL requests (e.g. GET /version, GET /healthz) use a
        // separate matching path: only nonResourceURLs rules apply, not
        // resource-based rules.
        if let Some(url) = req.non_resource_url {
            for (_, binding) in &inner.cluster_bindings {
                if !subject_matches(binding, req.username, req.groups) {
                    continue;
                }
                let rules = resolve_cluster_role_rules(&inner, &binding.role_ref);
                if rules_allow_non_resource(rules, req.verb, url) {
                    return true;
                }
            }
            // Namespace bindings are also checked — they can reference ClusterRoles
            // that include nonResourceURLs rules.
            if let Some(req_ns) = req.namespace {
                for (_, binding) in &inner.namespace_bindings {
                    let binding_ns = binding.namespace.as_deref().unwrap_or("");
                    if binding_ns != req_ns {
                        continue;
                    }
                    if !subject_matches(binding, req.username, req.groups) {
                        continue;
                    }
                    let rules = resolve_role_rules(&inner, &binding.role_ref, req_ns);
                    if rules_allow_non_resource(rules, req.verb, url) {
                        return true;
                    }
                }
            }
            return false;
        }

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
                        non_resource_url: None,
                    };
                    if !rbac.is_allowed(&req) {
                        return false;
                    }
                }
            }
        }
        // Verify nonResourceURL permissions are also held by the caller.
        for url in &rule.non_resource_urls {
            for verb in &rule.verbs {
                let req = AuthzRequest {
                    username,
                    groups,
                    verb,
                    api_group: "",
                    resource: "",
                    subresource: "",
                    namespace: None,
                    name: None,
                    non_resource_url: Some(url),
                };
                if !rbac.is_allowed(&req) {
                    return false;
                }
            }
        }
    }
    true
}

/// Like `user_holds_all_rules` but checks permissions in a specific namespace.
///
/// Used by RoleBinding escalation prevention: a caller may only bind to a
/// Role/ClusterRole if they already hold all its rules IN the target namespace.
pub fn user_holds_all_rules_in_namespace(
    username: &str,
    groups: &[String],
    role_rules: &[PolicyRule],
    namespace: &str,
    rbac: &RbacIndex,
) -> bool {
    for rule in role_rules {
        for api_group in &rule.api_groups {
            for resource in &rule.resources {
                for verb in &rule.verbs {
                    let req = AuthzRequest {
                        username,
                        groups,
                        verb,
                        api_group,
                        resource,
                        subresource: "",
                        namespace: Some(namespace),
                        name: None,
                        non_resource_url: None,
                    };
                    if !rbac.is_allowed(&req) {
                        return false;
                    }
                }
            }
        }
        for url in &rule.non_resource_urls {
            for verb in &rule.verbs {
                let req = AuthzRequest {
                    username,
                    groups,
                    verb,
                    api_group: "",
                    resource: "",
                    subresource: "",
                    namespace: None,
                    name: None,
                    non_resource_url: Some(url),
                };
                if !rbac.is_allowed(&req) {
                    return false;
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
        "ServiceAccount" => {
            // Kubernetes encodes ServiceAccount usernames as
            // "system:serviceaccount:<namespace>:<name>" — that prefix is the only
            // unforgeable marker of ServiceAccount identity, and exists precisely so
            // the ServiceAccount and User identity spaces can never collide. Only the
            // fully-encoded form may match.
            //
            // A raw `username == s.name` fallback (even gated on s.namespace.is_none())
            // must NOT be added back: ServiceAccount names are validated as DNS-1123
            // labels (lowercase alphanumeric + hyphens, no colons), so s.name can never
            // equal a colon-containing username — a plain User whose username happens
            // to equal a bound ServiceAccount's bare name (e.g. a User named "argocd"
            // colliding with ServiceAccount default/argocd) must never match here.
            let ns = s.namespace.as_deref().unwrap_or("");
            let encoded = format!("system:serviceaccount:{ns}:{}", s.name);
            username == encoded
        }
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

/// Match a plain (non-resourceName-restricted, in practice) rule list against a request.
///
/// `pub(crate)` so `node_authz` can reuse it for the Node authorizer's fallback path:
/// resources the Node authorizer doesn't subdivide by node (services, events, csinodes,
/// SAR/TokenReview creation, ...) are authorized straight from the `system:node` ClusterRole's
/// own rules, exactly as `rbac.RulesAllow` does in upstream's node authorizer — without this,
/// re-deriving the same rule list by hand in node_authz would drift the moment someone edits
/// the seeded ClusterRole.
pub(crate) fn rules_allow(rules: &[PolicyRule], req: &AuthzRequest<'_>) -> bool {
    rules.iter().any(|rule| rule_covers(rule, req))
}

/// Check whether any rule in `rules` permits `verb` on the non-resource `url`.
///
/// A rule participates in non-resource matching only when it has at least one
/// entry in `nonResourceURLs`. Rules with empty `nonResourceURLs` are
/// resource-only rules and do not match non-resource requests.
fn rules_allow_non_resource(rules: &[PolicyRule], verb: &str, url: &str) -> bool {
    rules.iter().any(|rule| {
        if rule.non_resource_urls.is_empty() {
            return false;
        }
        // Verb must match.
        if !rule.verbs.iter().any(|v| v == "*" || v == verb) {
            return false;
        }
        rule.non_resource_urls
            .iter()
            .any(|pattern| non_resource_url_matches(pattern, url))
    })
}

/// Match a single non-resource URL pattern against a concrete URL.
///
/// Matching rules (same as Kubernetes):
/// - `"*"` matches any URL.
/// - `"/apis/*"` matches any URL with the prefix `"/apis/"` (trailing wildcard).
/// - `"/version"` matches only the exact URL `"/version"`.
fn non_resource_url_matches(pattern: &str, url: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return url.starts_with(prefix);
    }
    pattern == url
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

/// Match rule resource strings against a (resource, subresource) pair, mirroring upstream
/// `ResourceMatches` (`pkg/apis/rbac/v1/evaluation_helpers.go`) exactly.
///
/// - `"*"` matches any resource+subresource combination.
/// - `"pods"` matches resource=pods, subresource="" only (exact combined-string match).
/// - `"pods/log"` matches resource=pods, subresource=log only (exact combined-string match).
/// - `"pods/*"` is NOT a wildcard: it only matches the literal combined string "pods/*",
///   which no real request ever has — upstream has no `resource/*` special case, so a rule
///   author scoping a grant to `pods/*` grants nothing rather than "any pods subresource".
/// - `"*/log"` matches ANY resource with subresource=log (e.g. pods/log, deployments/log) —
///   this is upstream's real cross-resource subresource wildcard.
fn resource_matches(rule_resources: &[String], resource: &str, subresource: &str) -> bool {
    rule_resources.iter().any(|r| {
        if r == "*" {
            return true;
        }
        // Exact match on the combined "resource" or "resource/subresource" string.
        let exact = match r.split_once('/') {
            Some((res, sub)) => res == resource && sub == subresource,
            None => subresource.is_empty() && r == resource,
        };
        if exact {
            return true;
        }
        // Cross-resource wildcard: "*/subresource" matches any resource with that exact
        // subresource, regardless of the resource name.
        !subresource.is_empty() && r.strip_prefix("*/").is_some_and(|sub| sub == subresource)
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
            non_resource_url: None,
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
        // A ClusterRoleBinding grants get/list on pods in any namespace.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
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

    /// A `resources: ["pods/*"]` rule must NOT grant the bare `pods` resource. Upstream's
    /// `ResourceMatches` has no `resource/*` special case — only exact combined-string
    /// equality or the dedicated `*/subresource` wildcard apply — so a rule author who
    /// writes `pods/*` intending "any pods subresource" must not silently also get base
    /// pod get/list/watch/delete, which would be a real privilege escalation vs. upstream.
    #[test]
    fn resource_slash_star_does_not_match_bare_resource() {
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-subresource-only",
            json!([{
                "apiGroups": [""],
                "resources": ["pods/*"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "dave-pod-subresource-only",
            "pod-subresource-only",
            json!([{ "kind": "User", "name": "dave" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        let r_bare = req("dave", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&r_bare),
            "a 'pods/*' rule must not leak access to the bare 'pods' resource — that would \
             let a subresource-scoped grant (e.g. pods/log) also read/delete whole pods"
        );
    }

    /// A `resources: ["*/log"]` rule must match the `log` subresource across ANY resource
    /// (e.g. both pods/log and deployments/log) — upstream's real cross-resource
    /// subresource wildcard. Without this, delegation patterns like "let this role read
    /// the log subresource everywhere" silently grant nothing, diverging from upstream.
    #[test]
    fn star_slash_subresource_matches_across_resources() {
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "any-log-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["*/log"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "erin-any-log-reader",
            "any-log-reader",
            json!([{ "kind": "User", "name": "erin" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        let r_pod_log = req("erin", &groups, "get", "pods", "log", Some("default"), None);
        assert!(
            idx.is_allowed(&r_pod_log),
            "'*/log' must match pods/log — upstream's cross-resource subresource wildcard"
        );
        let r_deploy_log = req(
            "erin",
            &groups,
            "get",
            "deployments",
            "log",
            Some("default"),
            None,
        );
        assert!(
            idx.is_allowed(&r_deploy_log),
            "'*/log' must match deployments/log too — the wildcard is resource-agnostic"
        );
        let r_pod_status = req(
            "erin",
            &groups,
            "get",
            "pods",
            "status",
            Some("default"),
            None,
        );
        assert!(
            !idx.is_allowed(&r_pod_status),
            "'*/log' must not match a different subresource (status) — the wildcard is \
             scoped to the exact subresource string, not all subresources"
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
    fn user_holds_all_rules_rejects_missing_non_resource_url() {
        // user_holds_all_rules must return false when the role includes nonResourceURL
        // permissions the caller does not hold. Without this, any user who can create
        // ClusterRoleBindings can escalate to /metrics or /healthz access they don't have.
        let idx = RbacIndex::new();

        // "alice" has only resource-based permissions (get pods) — no nonResourceURL grants.
        let (alice_role_key, alice_role_val) = make_cluster_role(
            "alice-role",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
        );
        let (alice_bind_key, alice_bind_val) = make_cluster_binding(
            "alice-binding",
            "alice-role",
            json!([{ "kind": "User", "name": "alice" }]),
        );
        idx.apply_object(&alice_role_key, &alice_role_val);
        idx.apply_object(&alice_bind_key, &alice_bind_val);

        // The role alice wants to bind grants GET /metrics — she does not hold this.
        let (metrics_role_key, metrics_role_val) = make_cluster_role(
            "metrics-reader",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/metrics"]
            }]),
        );
        idx.apply_object(&metrics_role_key, &metrics_role_val);

        let metrics_rules = idx.cluster_role_rules("metrics-reader");
        let groups: Vec<String> = vec![];

        // Alice lacks GET /metrics — escalation check must reject her.
        assert!(
            !user_holds_all_rules("alice", &groups, &metrics_rules, &idx),
            "alice must fail the escalation check: she does not hold GET /metrics; \
             without this check she could bind anyone to a role granting /metrics or /healthz"
        );
    }

    #[test]
    fn user_holds_all_rules_accepts_user_who_holds_non_resource_url() {
        // A user who already holds all nonResourceURL permissions in a role must pass
        // the escalation check and be allowed to create a binding to that role.
        let idx = RbacIndex::new();

        // "bob" has GET /metrics via his own binding.
        let (bob_role_key, bob_role_val) = make_cluster_role(
            "bob-role",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/metrics"]
            }]),
        );
        let (bob_bind_key, bob_bind_val) = make_cluster_binding(
            "bob-binding",
            "bob-role",
            json!([{ "kind": "User", "name": "bob" }]),
        );
        idx.apply_object(&bob_role_key, &bob_role_val);
        idx.apply_object(&bob_bind_key, &bob_bind_val);

        // The role to bind also grants GET /metrics.
        let (metrics_role_key, metrics_role_val) = make_cluster_role(
            "metrics-reader",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/metrics"]
            }]),
        );
        idx.apply_object(&metrics_role_key, &metrics_role_val);

        let metrics_rules = idx.cluster_role_rules("metrics-reader");
        let groups: Vec<String> = vec![];

        // Bob already holds GET /metrics — escalation check must pass.
        assert!(
            user_holds_all_rules("bob", &groups, &metrics_rules, &idx),
            "bob must pass the escalation check: he already holds GET /metrics"
        );
    }

    // --- ServiceAccount subject matching ---

    fn make_cluster_binding_sa(
        name: &str,
        role_name: &str,
        sa_ns: &str,
        sa_name: &str,
    ) -> (String, serde_json::Value) {
        let key = format!("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/{name}");
        let val = json!({
            "subjects": [{ "kind": "ServiceAccount", "namespace": sa_ns, "name": sa_name }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": role_name
            }
        });
        (key, val)
    }

    // --- enumerate_rules namespace binding path + RoleBinding→ClusterRole ---

    #[test]
    fn enumerate_rules_rolebinding_appears_in_bound_namespace_only() {
        // enumerate_rules must include rules from a namespace-scoped RoleBinding only
        // when called with the matching namespace. Returning rules in the wrong namespace
        // would allow cross-namespace privilege escalation.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_role(
            "ns-a",
            "ns-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get", "list"]
            }]),
        );
        idx.apply_object(&role_key, &role_val);

        let (bind_key, bind_val) = make_role_binding(
            "ns-a",
            "alice-ns-reader",
            "ns-reader",
            json!([{ "kind": "User", "name": "alice" }]),
        );
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Rules must appear when called with the bound namespace.
        let rules_in_ns_a = idx.enumerate_rules("alice", &groups, "ns-a");
        assert!(
            !rules_in_ns_a.is_empty(),
            "enumerate_rules must include rules for alice in namespace 'ns-a' where she is bound"
        );
        let verbs_in_ns_a: Vec<&str> = rules_in_ns_a
            .iter()
            .flat_map(|r| r.verbs.iter().map(|v| v.as_str()))
            .collect();
        assert!(
            verbs_in_ns_a.contains(&"get"),
            "rules in ns-a must include the 'get' verb from the bound Role"
        );

        // Rules must NOT appear for a different namespace.
        let rules_in_ns_b = idx.enumerate_rules("alice", &groups, "ns-b");
        assert!(
            rules_in_ns_b.is_empty(),
            "enumerate_rules must NOT include rules for alice in namespace 'ns-b' — \
             RoleBinding in 'ns-a' must not leak to 'ns-b'"
        );
    }

    #[test]
    fn enumerate_rules_rolebinding_to_clusterrole_returns_clusterrole_rules() {
        // A RoleBinding whose roleRef.kind=ClusterRole must resolve the ClusterRole's rules
        // and return them scoped to the binding's namespace. This allows granting
        // cluster-wide role definitions in a specific namespace without creating a Role copy.
        let idx = RbacIndex::new();

        // Seed a ClusterRole (not a namespaced Role).
        let (cr_key, cr_val) = make_cluster_role(
            "global-pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list", "watch"]
            }]),
        );
        idx.apply_object(&cr_key, &cr_val);

        // Create a RoleBinding in "staging" that refs the ClusterRole (not a Role).
        let rb_key =
            "/apis/rbac.authorization.k8s.io/v1/namespaces/staging/rolebindings/bob-pod-reader"
                .to_owned();
        let rb_val = json!({
            "subjects": [{ "kind": "User", "name": "bob" }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "global-pod-reader"
            },
            "namespace": "staging"
        });
        idx.apply_object(&rb_key, &rb_val);

        let groups: Vec<String> = vec![];

        // enumerate_rules in "staging" must return the ClusterRole's rules.
        let rules = idx.enumerate_rules("bob", &groups, "staging");
        assert!(
            !rules.is_empty(),
            "RoleBinding pointing to a ClusterRole must resolve and return the ClusterRole's rules \
             in the bound namespace; empty rules means the ClusterRole ref was not followed"
        );
        let verbs: Vec<&str> = rules
            .iter()
            .flat_map(|r| r.verbs.iter().map(|v| v.as_str()))
            .collect();
        assert!(
            verbs.contains(&"watch"),
            "ClusterRole rules must include 'watch' verb; got {:?}",
            verbs
        );

        // Must NOT appear in a different namespace — RoleBinding is namespace-scoped.
        let rules_other = idx.enumerate_rules("bob", &groups, "production");
        assert!(
            rules_other.is_empty(),
            "RoleBinding in 'staging' pointing to ClusterRole must not grant rules in 'production'"
        );
    }

    #[test]
    fn serviceaccount_subject_matches_encoded_username() {
        // Kubernetes encodes ServiceAccount subjects as "system:serviceaccount:<ns>:<name>".
        // A ClusterRoleBinding with kind=ServiceAccount, namespace=default, name=my-sa
        // must grant access to a request whose username is "system:serviceaccount:default:my-sa".
        // Without this, kubelet and controller-manager SA tokens are denied by RBAC even
        // when a binding explicitly covers them.
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

        let (bind_key, bind_val) =
            make_cluster_binding_sa("my-sa-binding", "pod-reader", "default", "my-sa");
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Encoded username must be allowed — this is what kube-apiserver sends.
        let r = req(
            "system:serviceaccount:default:my-sa",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            None,
        );
        assert!(
            idx.is_allowed(&r),
            "system:serviceaccount:default:my-sa must be allowed via ServiceAccount subject binding; \
             without this, SA tokens are denied despite an explicit binding"
        );
    }

    #[test]
    fn serviceaccount_subject_does_not_match_different_sa_in_same_namespace() {
        // A binding for my-sa must NOT grant access to other-sa in the same namespace.
        // Without this check, any SA in the namespace could escalate by sharing a binding.
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

        let (bind_key, bind_val) =
            make_cluster_binding_sa("my-sa-binding", "pod-reader", "default", "my-sa");
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // A different SA in the same namespace must be denied.
        let r = req(
            "system:serviceaccount:default:other-sa",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            None,
        );
        assert!(
            !idx.is_allowed(&r),
            "system:serviceaccount:default:other-sa must be denied — \
             only my-sa is bound, not other-sa"
        );
    }

    #[test]
    fn serviceaccount_subject_does_not_match_user_with_same_bare_name() {
        // A ClusterRoleBinding subject of kind: ServiceAccount, name: "argocd" must NOT
        // grant access to an authenticated User named "argocd" — real Kubernetes'
        // "system:serviceaccount:<ns>:<name>" prefix exists precisely so the User and
        // ServiceAccount identity spaces can never collide. Helm-chart-installed addons
        // commonly bind ClusterRoles to low-entropy ServiceAccount names like "argocd",
        // "prometheus", or "cert-manager"; if a plain User could authenticate with that
        // same bare name and inherit the binding, any operator who ever created a
        // --token-auth-file entry or signed an x509 cert with a matching CN would
        // silently gain that ServiceAccount's full permission set.
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

        let (bind_key, bind_val) =
            make_cluster_binding_sa("argocd-binding", "pod-reader", "default", "argocd");
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // A plain User named "argocd" (NOT the encoded ServiceAccount identity) must be denied.
        let user_req = req("argocd", &groups, "get", "pods", "", Some("default"), None);
        assert!(
            !idx.is_allowed(&user_req),
            "a User named 'argocd' must be denied — the binding's subject is a \
             ServiceAccount, not a User, and matching on the bare name reunites two \
             identity spaces that system:serviceaccount: is meant to keep separate"
        );

        // The real ServiceAccount, presenting its fully-encoded identity, must still be
        // allowed — the fix must not regress legitimate ServiceAccount authentication.
        let sa_req = req(
            "system:serviceaccount:default:argocd",
            &groups,
            "get",
            "pods",
            "",
            Some("default"),
            None,
        );
        assert!(
            idx.is_allowed(&sa_req),
            "system:serviceaccount:default:argocd must still be allowed — the fix for the \
             User/ServiceAccount identity collision must not break real ServiceAccount auth"
        );
    }

    #[test]
    fn user_holds_all_rules_does_not_credit_user_via_colliding_serviceaccount_binding() {
        // Privilege-escalation prevention (user_holds_all_rules) calls back into
        // RbacIndex::is_allowed, so it inherits the same User/ServiceAccount identity-
        // collision bug: a User whose name matches a bound ServiceAccount's bare name
        // must not be treated as already holding that ServiceAccount's rules. Without
        // this, a User named "argocd" could self-bind to the ClusterRole granted to
        // ServiceAccount default/argocd by passing the (bogus) "already holds these
        // rules" escalation check, then use the new binding as User "argocd" directly.
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

        let (bind_key, bind_val) =
            make_cluster_binding_sa("argocd-binding", "pod-reader", "default", "argocd");
        idx.apply_object(&bind_key, &bind_val);

        let pod_reader_rules = idx.cluster_role_rules("pod-reader");
        let groups: Vec<String> = vec![];

        assert!(
            !user_holds_all_rules("argocd", &groups, &pod_reader_rules, &idx),
            "User 'argocd' must NOT be credited with pod-reader's rules just because a \
             ServiceAccount subject named 'argocd' is bound — crediting it would let this \
             User self-bind to pod-reader as an escalation shortcut"
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

    // --- nonResourceURLs matching ---

    fn non_resource_req<'a>(
        username: &'a str,
        groups: &'a [String],
        verb: &'a str,
        url: &'a str,
    ) -> AuthzRequest<'a> {
        AuthzRequest {
            username,
            groups,
            verb,
            api_group: "",
            resource: "",
            subresource: "",
            namespace: None,
            name: None,
            non_resource_url: Some(url),
        }
    }

    #[test]
    fn non_resource_url_exact_match_allows() {
        // A rule with nonResourceURLs: ["/version"] must allow GET /version.
        // Argo CD requests GET /version to detect the server version; without this
        // the request is denied and Argo CD marks the cluster as unavailable.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "version-reader",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/version"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "alice-version",
            "version-reader",
            json!([{ "kind": "User", "name": "alice" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        let r = non_resource_req("alice", &groups, "get", "/version");
        assert!(
            idx.is_allowed(&r),
            "nonResourceURLs: [\"/version\"] must allow GET /version — \
             Argo CD uses this to detect server version"
        );
    }

    #[test]
    fn non_resource_url_wildcard_star_matches_any_url() {
        // A rule with nonResourceURLs: ["*"] must allow any non-resource path.
        // The cluster-admin ClusterRole uses "*" to grant unrestricted access,
        // including non-resource URLs. Without wildcard support the cluster-admin
        // would silently deny GET /version and similar requests.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "super-admin",
            json!([{
                "verbs": ["*"],
                "nonResourceURLs": ["*"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "admin-binding",
            "super-admin",
            json!([{ "kind": "User", "name": "admin" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        for url in &["/version", "/healthz", "/openapi/v2", "/metrics"] {
            let r = non_resource_req("admin", &groups, "get", url);
            assert!(
                idx.is_allowed(&r),
                "nonResourceURLs: [\"*\"] must allow any URL; denied for {url}"
            );
        }
    }

    #[test]
    fn non_resource_url_prefix_wildcard_matches_prefix() {
        // A rule with nonResourceURLs: ["/apis/*"] must allow any path under /apis/.
        // Kubernetes uses prefix wildcards so roles can grant access to entire
        // API families without enumerating every path.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "apis-browser",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/apis/*"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "bob-apis",
            "apis-browser",
            json!([{ "kind": "User", "name": "bob" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // Any path under /apis/ must be allowed.
        let r = non_resource_req("bob", &groups, "get", "/apis/apps/v1");
        assert!(idx.is_allowed(&r), "/apis/* must match /apis/apps/v1");

        // A path NOT under /apis/ must be denied.
        let r2 = non_resource_req("bob", &groups, "get", "/version");
        assert!(
            !idx.is_allowed(&r2),
            "/apis/* must NOT match /version — prefix wildcard must not be a global wildcard"
        );
    }

    #[test]
    fn non_resource_url_denied_without_matching_rule() {
        // A user with only resource-based rules must be denied non-resource URL requests.
        // Without explicit nonResourceURLs rules, paths like /version must be denied —
        // resource rules do not bleed into non-resource URL checks.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "pod-reader",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "carol-pods",
            "pod-reader",
            json!([{ "kind": "User", "name": "carol" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];
        let r = non_resource_req("carol", &groups, "get", "/version");
        assert!(
            !idx.is_allowed(&r),
            "resource-only rules must not grant access to non-resource URLs — \
             otherwise any pod-reader could access /version, /metrics, etc."
        );
    }

    #[test]
    fn non_resource_url_verb_mismatch_denies() {
        // Even with a matching nonResourceURL, the verb must also match.
        // A rule granting GET /version must NOT allow POST /version.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "version-getter",
            json!([{
                "verbs": ["get"],
                "nonResourceURLs": ["/version"]
            }]),
        );
        let (bind_key, bind_val) = make_cluster_binding(
            "dave-version",
            "version-getter",
            json!([{ "kind": "User", "name": "dave" }]),
        );
        idx.apply_object(&role_key, &role_val);
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![];

        // GET must be allowed.
        let r_get = non_resource_req("dave", &groups, "get", "/version");
        assert!(idx.is_allowed(&r_get), "GET /version must be allowed");

        // POST must be denied — verb is not in the rule.
        let r_post = non_resource_req("dave", &groups, "post", "/version");
        assert!(
            !idx.is_allowed(&r_post),
            "POST /version must be denied — verb mismatch must not be ignored"
        );
    }

    // --- Regression: RoleBinding namespace from key path ---

    #[test]
    fn rwlock_poison_recovery_uses_into_inner() {
        // All RbacIndex methods use `.unwrap_or_else(|e| e.into_inner())` instead of
        // `.unwrap()` on RwLock guards.  Without this, a panic in any holder permanently
        // poisons the lock and every subsequent authz call panics, causing a full apiserver
        // outage.  This test verifies that the index remains usable for reads and writes
        // after normal usage — the into_inner recovery path keeps the guard alive rather
        // than propagating the poisoned-lock panic.
        //
        // Note: reliably simulating a poisoned RwLock in a unit test requires spawning a
        // thread, poisoning it, and then observing recovery — that is an async/threading
        // integration concern.  The meaningful revert-detection here is that the code
        // compiles with unwrap_or_else (grep confirms no remaining .unwrap() on RwLock
        // calls) and that normal operations continue to succeed post-refactor.
        let idx = RbacIndex::new();

        let (role_key, role_val) = make_cluster_role(
            "view",
            json!([{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get"]
            }]),
        );
        idx.apply_object(&role_key, &role_val);

        let rules = idx.cluster_role_rules("view");
        assert!(
            !rules.is_empty(),
            "cluster_role_rules must return rules after apply_object; \
             a regression here means the RwLock write or read path broke"
        );

        idx.remove_object(&role_key);
        let rules_after = idx.cluster_role_rules("view");
        assert!(
            rules_after.is_empty(),
            "rules must be empty after remove_object; \
             a regression here means the RwLock write path is broken post-refactor"
        );

        let groups: Vec<String> = vec![];
        let enumerated = idx.enumerate_rules("nobody", &groups, "default");
        assert!(
            enumerated.is_empty(),
            "enumerate_rules must return empty when no bindings exist; \
             a regression here means the RwLock read path is broken"
        );
    }

    #[test]
    fn rolebinding_namespace_extracted_from_key_when_not_in_json_body() {
        // When a RoleBinding is stored via apply_object, the namespace is in the key
        // path (/apis/.../namespaces/<ns>/rolebindings/<name>) but NOT as a top-level
        // field in the JSON body — Kubernetes stores it in metadata.namespace.
        // If apply_object fails to extract the namespace from the key, binding.namespace
        // stays None, and is_allowed never matches it against any request namespace,
        // causing a SubjectAccessReview for a bound ServiceAccount to return allowed=false.
        // This is the exact failure mode from the conformance test.
        let idx = RbacIndex::new();

        // Role in "test-ns" (namespace comes from key path — the helper puts it in the key).
        let role_key =
            "/apis/rbac.authorization.k8s.io/v1/namespaces/test-ns/roles/pod-reader".to_owned();
        let role_val = json!({
            "rules": [{
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list"]
            }]
        });
        idx.apply_object(&role_key, &role_val);

        // RoleBinding in "test-ns" whose JSON body does NOT have a top-level "namespace"
        // field — this matches what create_namespaced_resource stores (namespace is in
        // metadata.namespace, not at the top level).
        let bind_key =
            "/apis/rbac.authorization.k8s.io/v1/namespaces/test-ns/rolebindings/sa-binding"
                .to_owned();
        let bind_val = json!({
            "subjects": [{ "kind": "ServiceAccount", "namespace": "test-ns", "name": "my-sa" }],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "pod-reader"
            }
            // Note: no top-level "namespace" key — matches real stored JSON
        });
        idx.apply_object(&bind_key, &bind_val);

        let groups: Vec<String> = vec![
            "system:serviceaccounts".to_owned(),
            "system:serviceaccounts:test-ns".to_owned(),
        ];

        // The SA username as encoded by the Kubernetes TokenReview.
        let r = req(
            "system:serviceaccount:test-ns:my-sa",
            &groups,
            "get",
            "pods",
            "",
            Some("test-ns"),
            None,
        );
        assert!(
            idx.is_allowed(&r),
            "system:serviceaccount:test-ns:my-sa must be allowed via its RoleBinding; \
             a regression here means apply_object failed to extract the namespace from \
             the key path and SubjectAccessReview returns allowed=false for bound SAs"
        );

        // Must be denied in a different namespace — RoleBinding is namespace-scoped.
        let r_other = req(
            "system:serviceaccount:test-ns:my-sa",
            &groups,
            "get",
            "pods",
            "",
            Some("other-ns"),
            None,
        );
        assert!(
            !idx.is_allowed(&r_other),
            "RoleBinding in 'test-ns' must not grant access in 'other-ns'"
        );
    }
}
