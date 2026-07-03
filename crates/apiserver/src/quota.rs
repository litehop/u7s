/// ResourceQuota admission plugin.
///
/// On object CREATE: fetch all ResourceQuota objects in the namespace, compute the
/// current usage by listing the store, and deny the request if creation would exceed
/// any quota.
///
/// Design:
/// - Usage is recomputed on every admission check by listing the store.  This is
///   correct for pre-alpha (no in-memory cache needed) and avoids a separate quota
///   controller.
/// - Quota decrements (delete) are not tracked here. The full Kubernetes quota
///   controller reconciliation loop is out of scope.
/// - Only object count quotas are implemented. Resource usage quotas (CPU/memory
///   sums across pods) would require parsing container specs and are left for a
///   future bead.
///
/// Kubernetes spec reference:
///   https://kubernetes.io/docs/concepts/policy/resource-quotas/
use serde_json::Value;
use u7s_store::{ListOptions, Store};

use crate::{keys::group_list_prefix, state::AppState, status::Status, status::StatusError};

// ---------------------------------------------------------------------------
// Supported quota resource names → (group, plural) pairs
// ---------------------------------------------------------------------------

/// Map a quota resource name (e.g. "count/pods") to the store list prefix
/// components (group, plural). Returns None for unknown resources.
fn quota_resource_to_group_plural(resource: &str) -> Option<(&'static str, &'static str)> {
    match resource {
        "pods" | "count/pods" => Some(("", "pods")),
        "services" | "count/services" => Some(("", "services")),
        "persistentvolumeclaims" | "count/persistentvolumeclaims" => {
            Some(("", "persistentvolumeclaims"))
        }
        "secrets" | "count/secrets" => Some(("", "secrets")),
        "configmaps" | "count/configmaps" => Some(("", "configmaps")),
        "replicationcontrollers" | "count/replicationcontrollers" => {
            Some(("", "replicationcontrollers"))
        }
        "resourcequotas" | "count/resourcequotas" => Some(("", "resourcequotas")),
        "deployments.apps" | "count/deployments.apps" => Some(("apps", "deployments")),
        "statefulsets.apps" | "count/statefulsets.apps" => Some(("apps", "statefulsets")),
        "daemonsets.apps" | "count/daemonsets.apps" => Some(("apps", "daemonsets")),
        "replicasets.apps" | "count/replicasets.apps" => Some(("apps", "replicasets")),
        "jobs.batch" | "count/jobs.batch" => Some(("batch", "jobs")),
        "cronjobs.batch" | "count/cronjobs.batch" => Some(("batch", "cronjobs")),
        _ => None,
    }
}

/// Parse a resource quantity string as a whole integer count.
/// Quota hard limits for object counts are always plain integers.
fn parse_count(s: &str) -> Option<u64> {
    s.parse::<u64>().ok()
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

/// Fetch all ResourceQuota objects in a namespace.
async fn fetch_resource_quotas<S: Store>(state: &AppState<S>, namespace: &str) -> Vec<Value> {
    // ResourceQuota is a core/v1 namespaced resource.
    let prefix = group_list_prefix("", "resourcequotas", Some(namespace));
    match state.store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("quota: failed to list ResourceQuotas in {namespace}: {e}");
            vec![]
        }
    }
}

/// Count the current number of objects of a given resource kind in a namespace.
async fn count_objects<S: Store>(
    state: &AppState<S>,
    namespace: &str,
    group: &str,
    plural: &str,
) -> u64 {
    let prefix = group_list_prefix(group, plural, Some(namespace));
    match state.store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items.len() as u64,
        Err(e) => {
            tracing::warn!("quota: failed to count {plural} in {namespace}: {e}");
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns true if a pod body is BestEffort QoS class.
///
/// A pod is BestEffort when ALL containers (including init containers) have
/// no `resources.requests` and no `resources.limits`. This matches the
/// Kubernetes QoS class definition for BestEffort pods.
pub fn pod_is_best_effort(pod: &Value) -> bool {
    let spec = &pod["spec"];
    // Check main containers and init containers.
    for containers_field in &["containers", "initContainers"] {
        if let Some(arr) = spec[containers_field].as_array() {
            for container in arr {
                let requests = &container["resources"]["requests"];
                let limits = &container["resources"]["limits"];
                // Any non-null, non-empty requests or limits means not BestEffort.
                if (requests.is_object() && !requests.as_object().unwrap().is_empty())
                    || (limits.is_object() && !limits.as_object().unwrap().is_empty())
                {
                    return false;
                }
            }
        }
    }
    true
}

/// Returns true if the pod has spec.activeDeadlineSeconds set (is a terminating pod).
///
/// A pod is Terminating-scoped when it has an active deadline — i.e. it will be
/// forcibly terminated after a finite time. This matches the Kubernetes definition:
/// https://kubernetes.io/docs/concepts/workloads/pods/#pod-termination
fn pod_is_terminating(pod: &Value) -> bool {
    pod["spec"]["activeDeadlineSeconds"].is_number()
}

/// Returns true if the object matches the given ResourceQuota scope.
///
/// Implemented scopes: BestEffort, NotBestEffort, Terminating, NotTerminating.
/// Unknown scopes are treated conservatively: the object is assumed to match
/// (quota applies), which is the safe default.
fn object_matches_scope(scope: &str, object: Option<&Value>) -> bool {
    match scope {
        "BestEffort" => object.is_some_and(pod_is_best_effort),
        "NotBestEffort" => object.is_none_or(|pod| !pod_is_best_effort(pod)),
        // A pod matches Terminating iff spec.activeDeadlineSeconds is set.
        "Terminating" => object.is_some_and(pod_is_terminating),
        "NotTerminating" => object.is_none_or(|pod| !pod_is_terminating(pod)),
        // Unknown scopes: assume match (conservative — don't silently skip quotas).
        _ => true,
    }
}

/// Returns true if the object matches all expressions in a scopeSelector.
///
/// Supported operators: Exists (pod must match scopeName), DoesNotExist (must not match).
/// In/NotIn with values are not implemented (unused by conformance tests); unknown operators
/// are treated as matching (conservative default).
fn object_matches_scope_selector(scope_selector: &Value, object: Option<&Value>) -> bool {
    let exprs = match scope_selector["matchExpressions"].as_array() {
        Some(arr) => arr,
        None => return true, // no expressions — matches everything
    };
    exprs.iter().all(|expr| {
        let scope_name = expr["scopeName"].as_str().unwrap_or("");
        let operator = expr["operator"].as_str().unwrap_or("");
        match operator {
            "Exists" => object_matches_scope(scope_name, object),
            "DoesNotExist" => !object_matches_scope(scope_name, object),
            // In/NotIn with values — not implemented; treat as match (conservative)
            _ => true,
        }
    })
}

/// Count pods in `namespace` that match all scopes on `quota`.
///
/// Scopes only apply to pods; other resources are counted without scope filtering.
/// Returns the number of pods that match every scope in `quota["spec"]["scopes"]`
/// AND every expression in `quota["spec"]["scopeSelector"]`.
async fn count_scope_filtered_pods<S: Store>(store: &S, namespace: &str, quota: &Value) -> u64 {
    let scopes: Vec<&str> = quota["spec"]["scopes"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
        .unwrap_or_default();
    let scope_selector = &quota["spec"]["scopeSelector"];

    let prefix = group_list_prefix("", "pods", Some(namespace));
    let items = match store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items,
        Err(e) => {
            tracing::warn!("quota: failed to list pods in {namespace}: {e}");
            return 0;
        }
    };

    items
        .iter()
        .filter(|item| {
            let pod: Value = match serde_json::from_slice(&item.value) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let matches_scopes = scopes
                .iter()
                .all(|scope| object_matches_scope(scope, Some(&pod)));
            let matches_selector = if scope_selector.is_object() {
                object_matches_scope_selector(scope_selector, Some(&pod))
            } else {
                true
            };
            matches_scopes && matches_selector
        })
        .count() as u64
}

/// Compute live usage counts for all hard-limit entries in a single ResourceQuota object.
///
/// Returns a map from quota resource name (e.g. `"pods"`, `"count/deployments.apps"`) to
/// a string count (e.g. `"3"`). Only entries whose resource name is known to
/// `quota_resource_to_group_plural` are counted; unknown entries are omitted.
///
/// Pod resources are scope-filtered using `quota["spec"]["scopes"]` so that a
/// Terminating-scoped quota does not count non-terminating pods (and vice versa).
///
/// This function is pure with respect to writes — it only reads from the store.
pub async fn count_quota_usage<S: Store>(
    store: &S,
    quota: &Value,
) -> std::collections::BTreeMap<String, String> {
    let namespace = match quota["metadata"]["namespace"].as_str() {
        Some(ns) => ns,
        None => return std::collections::BTreeMap::new(),
    };
    let hard = match quota["spec"]["hard"].as_object() {
        Some(m) => m,
        None => return std::collections::BTreeMap::new(),
    };

    // Is scope filtering needed? Only when the quota has scopes AND those scopes are pod-scopes.
    // Scope filtering applies when the quota has spec.scopes (pod-scope names) or
    // spec.scopeSelector (matchExpressions with pod-scope names like Terminating).
    let has_scopes_array = quota["spec"]["scopes"]
        .as_array()
        .map(|arr| {
            arr.iter().any(|s| {
                matches!(
                    s.as_str(),
                    Some("BestEffort" | "NotBestEffort" | "Terminating" | "NotTerminating")
                )
            })
        })
        .unwrap_or(false);
    let has_scope_selector = quota["spec"]["scopeSelector"]["matchExpressions"]
        .as_array()
        .map(|arr| {
            arr.iter().any(|expr| {
                matches!(
                    expr["scopeName"].as_str(),
                    Some("BestEffort" | "NotBestEffort" | "Terminating" | "NotTerminating")
                )
            })
        })
        .unwrap_or(false);
    let has_pod_scopes = has_scopes_array || has_scope_selector;

    let mut used = std::collections::BTreeMap::new();
    for (resource_name, _) in hard {
        if let Some((group, plural)) = quota_resource_to_group_plural(resource_name) {
            // Pod resources respect scope filtering; other resource types are always counted.
            let count = if has_pod_scopes && group.is_empty() && plural == "pods" {
                count_scope_filtered_pods(store, namespace, quota).await
            } else {
                let prefix = group_list_prefix(group, plural, Some(namespace));
                match store.list(&prefix, ListOptions::default()).await {
                    Ok(resp) => resp.items.len() as u64,
                    Err(e) => {
                        tracing::warn!("quota: failed to count {plural} in {namespace}: {e}");
                        0
                    }
                }
            };
            used.insert(resource_name.clone(), count.to_string());
        }
    }
    used
}

/// Check ResourceQuota constraints before a CREATE operation.
///
/// Fetches all ResourceQuota objects in `namespace` and, for each hard limit that
/// covers the incoming `resource` (by count), checks whether the current usage
/// plus one exceeds the hard limit.
///
/// `object` is the pod (or other object) being created; it is used for scope
/// matching. Pass `None` for non-pod resources — unrecognised scopes are
/// treated as matching (safe default).
///
/// Returns Ok(()) if all quotas allow the create, or a 403 StatusError if any
/// quota would be exceeded. Returns Ok(()) immediately for cluster-scoped
/// resources (no namespace) and when no ResourceQuota objects exist.
pub async fn check_resource_quota<S: Store>(
    state: &AppState<S>,
    namespace: &str,
    group: &str,
    resource: &str,
    object: Option<&Value>,
) -> Result<(), StatusError> {
    let quotas = fetch_resource_quotas(state, namespace).await;
    if quotas.is_empty() {
        return Ok(());
    }

    for quota in &quotas {
        let quota_name = quota["metadata"]["name"].as_str().unwrap_or("<unknown>");

        // Scope matching: if the quota has scopes, the object must match ALL of them.
        if let Some(scopes) = quota["spec"]["scopes"].as_array() {
            let matches = scopes
                .iter()
                .filter_map(|s| s.as_str())
                .all(|scope| object_matches_scope(scope, object));
            if !matches {
                // This quota does not apply to the incoming object — skip it entirely.
                continue;
            }
        }
        // scopeSelector matching: if the quota has a scopeSelector, the object must match it.
        let scope_selector = &quota["spec"]["scopeSelector"];
        if scope_selector.is_object() && !object_matches_scope_selector(scope_selector, object) {
            continue;
        }

        let hard = &quota["spec"]["hard"];
        if !hard.is_object() {
            continue;
        }

        if let Some(map) = hard.as_object() {
            for (quota_resource, limit_val) in map {
                // Does this quota entry cover the resource being created?
                let covers = quota_resource_covers(quota_resource, group, resource);
                if !covers {
                    continue;
                }

                let limit_str = limit_val.as_str().unwrap_or("");
                let hard_limit = match parse_count(limit_str) {
                    Some(l) => l,
                    None => continue, // non-count quota (e.g. CPU/memory sum) — skip
                };

                // Determine the (group, plural) pair for counting.
                let (count_group, count_plural) =
                    match quota_resource_to_group_plural(quota_resource) {
                        Some(p) => p,
                        None => {
                            // Try deriving from the incoming resource directly.
                            (group, resource)
                        }
                    };

                let current = count_objects(state, namespace, count_group, count_plural).await;
                if current >= hard_limit {
                    return Err(Status::forbidden(format!(
                        "exceeded quota: {quota_name}, requested: {quota_resource}=1, \
                         used: {current}, limited: {hard_limit}"
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Returns true if the quota resource name covers the given (group, plural) resource.
///
/// This is a pure function, unit-testable without I/O.
pub fn quota_resource_covers(quota_resource: &str, group: &str, resource: &str) -> bool {
    // Direct name match (e.g. "pods" covers pods in core group)
    if quota_resource == resource && group.is_empty() {
        return true;
    }
    // count/* pattern
    if let Some(suffix) = quota_resource.strip_prefix("count/") {
        // suffix may be "pods", "deployments.apps", etc.
        if suffix == resource && group.is_empty() {
            return true;
        }
        // "deployments.apps" → resource="deployments", group="apps"
        if let Some(dot) = suffix.rfind('.') {
            let r = &suffix[..dot];
            let g = &suffix[dot + 1..];
            if r == resource && g == group {
                return true;
            }
        }
    }
    // "deployments.apps" style (no count/ prefix)
    if let Some(dot) = quota_resource.rfind('.') {
        let r = &quota_resource[..dot];
        let g = &quota_resource[dot + 1..];
        if r == resource && g == group {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use serde_json::json;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    async fn seed(state: &AppState, key: &str, val: Value) {
        state
            .store
            .put(key, Bytes::from(serde_json::to_vec(&val).unwrap()), None)
            .await
            .unwrap();
    }

    // -- quota_resource_covers --

    /// "pods" quota entry covers core/v1 pods resource.
    /// Without this match, ResourceQuota for pods is silently skipped.
    #[test]
    fn quota_resource_covers_pods() {
        assert!(
            quota_resource_covers("pods", "", "pods"),
            "\"pods\" quota must cover core/v1 pods"
        );
    }

    /// "count/pods" covers core/v1 pods.
    #[test]
    fn quota_resource_covers_count_pods() {
        assert!(quota_resource_covers("count/pods", "", "pods"));
    }

    /// "count/deployments.apps" covers apps/deployments.
    #[test]
    fn quota_resource_covers_count_deployments_apps() {
        assert!(quota_resource_covers(
            "count/deployments.apps",
            "apps",
            "deployments"
        ));
        assert!(!quota_resource_covers(
            "count/deployments.apps",
            "",
            "deployments"
        ));
    }

    /// "secrets" quota does not cover "pods".
    #[test]
    fn quota_resource_covers_mismatch_returns_false() {
        assert!(!quota_resource_covers("secrets", "", "pods"));
    }

    // -- check_resource_quota --

    /// No ResourceQuota in namespace → creation must be allowed.
    /// Most namespaces have no quota; absence must never block writes.
    #[tokio::test]
    async fn check_quota_no_quota_objects_allows() {
        let state = make_state();
        let result = check_resource_quota(&state, "default", "", "pods", None).await;
        assert!(result.is_ok(), "no quota must allow creation");
    }

    /// Quota exists but is not yet reached → creation must be allowed.
    #[tokio::test]
    async fn check_quota_under_limit_allows() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Quota: max 5 pods
        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "default-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "5" } }
        });
        seed(
            &state,
            "/registry/resourcequotas/default/default-quota",
            quota,
        )
        .await;

        // 0 pods currently → should allow (0 < 5)
        let result = check_resource_quota(&state, "default", "", "pods", None).await;
        assert!(result.is_ok(), "quota under limit must allow creation");
    }

    /// Quota is exactly at the hard limit → creation must be denied.
    /// The new object would be the (limit+1)th — must be rejected.
    #[tokio::test]
    async fn check_quota_at_limit_denies() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Quota: max 2 pods
        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "tight", "namespace": "default" },
            "spec": { "hard": { "pods": "2" } }
        });
        seed(&state, "/registry/resourcequotas/default/tight", quota).await;

        // Seed 2 pods in the namespace (at the limit)
        for i in 0..2 {
            let pod = json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": { "name": format!("pod-{i}"), "namespace": "default" }
            });
            seed(&state, &format!("/registry/pods/default/pod-{i}"), pod).await;
        }

        let result = check_resource_quota(&state, "default", "", "pods", None).await;
        assert!(
            result.is_err(),
            "quota at hard limit must deny creation of additional pods"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::FORBIDDEN,
            "quota exceeded must return 403 Forbidden"
        );
    }

    /// Multiple quotas: ALL must pass. If any quota is exceeded, deny.
    /// This mirrors the Kubernetes spec: a namespace can have multiple ResourceQuotas
    /// and creation is only allowed when ALL are satisfied simultaneously.
    #[tokio::test]
    async fn check_quota_multiple_quotas_all_must_pass() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Quota A: max 10 pods (not reached)
        let quota_a = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "quota-a", "namespace": "ns1" },
            "spec": { "hard": { "pods": "10" } }
        });
        seed(&state, "/registry/resourcequotas/ns1/quota-a", quota_a).await;

        // Quota B: max 0 pods (already exceeded — no pods allowed)
        let quota_b = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "quota-b", "namespace": "ns1" },
            "spec": { "hard": { "pods": "0" } }
        });
        seed(&state, "/registry/resourcequotas/ns1/quota-b", quota_b).await;

        // Even though quota-a allows it, quota-b denies it.
        let result = check_resource_quota(&state, "ns1", "", "pods", None).await;
        assert!(
            result.is_err(),
            "if any quota is exceeded, creation must be denied"
        );
    }

    /// Quota in namespace A must not affect namespace B.
    /// Namespace isolation is fundamental.
    #[tokio::test]
    async fn check_quota_namespace_isolation() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Exhausted quota in ns-a
        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "q", "namespace": "ns-a" },
            "spec": { "hard": { "pods": "0" } }
        });
        seed(&state, "/registry/resourcequotas/ns-a/q", quota).await;

        // ns-b has no quota — must allow creation
        let result = check_resource_quota(&state, "ns-b", "", "pods", None).await;
        assert!(
            result.is_ok(),
            "exhausted quota in ns-a must not affect ns-b"
        );
    }

    // -- BestEffort scope filtering --

    /// A BestEffort-scoped ResourceQuota must only count BestEffort pods (no requests, no limits).
    /// A Burstable pod (has CPU requests) must NOT count against a BestEffort quota.
    /// Without scope filtering, any pod would be counted against a BestEffort quota,
    /// causing legitimate Burstable pods to be incorrectly rejected.
    #[tokio::test]
    async fn bestefffort_scoped_quota_only_counts_bestefffort_pods() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // BestEffort-scoped quota: max 1 pod
        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "be-quota", "namespace": "default" },
            "spec": {
                "scopes": ["BestEffort"],
                "hard": { "pods": "1" }
            }
        });
        seed(&state, "/registry/resourcequotas/default/be-quota", quota).await;

        // Seed 1 pod (at the limit) — simulates an existing BestEffort pod.
        let existing_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "be-pod-0", "namespace": "default" },
            "spec": { "containers": [{"name": "c"}] }
        });
        seed(&state, "/registry/pods/default/be-pod-0", existing_pod).await;

        // A BestEffort pod (no requests, no limits) must be denied — quota at limit.
        let be_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "be-pod-new", "namespace": "default" },
            "spec": {
                "containers": [{"name": "c", "image": "nginx"}]
            }
        });
        let result = check_resource_quota(&state, "default", "", "pods", Some(&be_pod)).await;
        assert!(
            result.is_err(),
            "BestEffort pod must be denied when BestEffort-scoped quota is at its limit"
        );
        assert_eq!(
            result.unwrap_err().0,
            axum::http::StatusCode::FORBIDDEN,
            "quota exceeded for BestEffort pod must return 403"
        );

        // A Burstable pod (has CPU requests) must NOT be counted against BestEffort quota.
        let burstable_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "burstable-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "nginx",
                    "resources": {
                        "requests": {"cpu": "100m"}
                    }
                }]
            }
        });
        let result =
            check_resource_quota(&state, "default", "", "pods", Some(&burstable_pod)).await;
        assert!(
            result.is_ok(),
            "Burstable pod must NOT be counted against a BestEffort-scoped quota — \
             it does not match the BestEffort scope and should be allowed"
        );
    }

    // -- Terminating / NotTerminating scope filtering --

    /// A pod WITH activeDeadlineSeconds must match Terminating (and NOT NotTerminating).
    /// A pod WITHOUT activeDeadlineSeconds must match NotTerminating (and NOT Terminating).
    ///
    /// If these cases fall through to the always-match default, terminating-scope quota
    /// accounting is wrong: non-terminating pods would be counted against a
    /// Terminating-scoped quota, causing the ResourceQuota conformance test
    /// `should verify ResourceQuota with terminating scopes` to fail.
    #[test]
    fn terminating_scope_matches_pod_with_active_deadline_seconds() {
        let terminating_pod = json!({
            "spec": {
                "activeDeadlineSeconds": 300,
                "containers": [{"name": "c", "image": "nginx"}]
            }
        });
        assert!(
            object_matches_scope("Terminating", Some(&terminating_pod)),
            "a pod's Terminating-scope membership must follow activeDeadlineSeconds — \
             else terminating-scope quota accounting is wrong (ResourceQuota conformance)"
        );
        assert!(
            !object_matches_scope("NotTerminating", Some(&terminating_pod)),
            "a pod's Terminating-scope membership must follow activeDeadlineSeconds — \
             else terminating-scope quota accounting is wrong (ResourceQuota conformance)"
        );
    }

    #[test]
    fn not_terminating_scope_matches_pod_without_active_deadline_seconds() {
        let non_terminating_pod = json!({
            "spec": {
                "containers": [{"name": "c", "image": "nginx"}]
            }
        });
        assert!(
            object_matches_scope("NotTerminating", Some(&non_terminating_pod)),
            "a pod's Terminating-scope membership must follow activeDeadlineSeconds — \
             else terminating-scope quota accounting is wrong (ResourceQuota conformance)"
        );
        assert!(
            !object_matches_scope("Terminating", Some(&non_terminating_pod)),
            "a pod's Terminating-scope membership must follow activeDeadlineSeconds — \
             else terminating-scope quota accounting is wrong (ResourceQuota conformance)"
        );
    }

    /// pod_is_best_effort returns true for a pod with no resource constraints.
    #[test]
    fn pod_is_best_effort_with_no_resources() {
        let pod = json!({
            "spec": {
                "containers": [{"name": "c", "image": "nginx"}]
            }
        });
        assert!(
            pod_is_best_effort(&pod),
            "pod with no requests or limits must be BestEffort"
        );
    }

    /// pod_is_best_effort returns false when any container has CPU requests.
    #[test]
    fn pod_is_best_effort_with_cpu_requests_returns_false() {
        let pod = json!({
            "spec": {
                "containers": [{
                    "name": "c",
                    "resources": {"requests": {"cpu": "100m"}}
                }]
            }
        });
        assert!(
            !pod_is_best_effort(&pod),
            "pod with CPU requests must NOT be BestEffort"
        );
    }
}
