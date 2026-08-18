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
/// - `status.used` is recomputed and written after every successful CREATE or DELETE
///   of a quota-covered object so that `kubectl get resourcequota` reflects live counts.
/// - Both count-based quotas (pods, services) and resource-request-based quotas
///   (cpu, memory, ephemeral-storage) are enforced at admission.
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
// Resource quantity arithmetic (for resource-request quotas)
// ---------------------------------------------------------------------------

/// Parse a Kubernetes quantity string into a raw integer in milli-units.
/// For CPU: "500m" → 500, "1" → 1000, "1.5" → 1500.
/// For memory/storage: "252Mi" → 252*1024*1024*1000, "30Gi" → 30*1024^3*1000.
/// For plain integers: "2" → 2000.
/// Returns None if the string cannot be parsed.
fn parse_quantity_milli(s: &str) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    // Milli suffix
    if let Some(rest) = s.strip_suffix('m') {
        return rest.parse::<i64>().ok();
    }
    // Binary suffixes (Ki, Mi, Gi, Ti, Pi, Ei)
    let binary_suffixes = [
        ("Ki", 1024i64),
        ("Mi", 1024 * 1024),
        ("Gi", 1024 * 1024 * 1024),
        ("Ti", 1024 * 1024 * 1024 * 1024),
        ("Pi", 1024 * 1024 * 1024 * 1024 * 1024),
        ("Ei", 1024 * 1024 * 1024 * 1024 * 1024 * 1024),
    ];
    for (suf, mult) in &binary_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return rest.parse::<i64>().ok().map(|n| n * mult * 1000);
        }
    }
    // Decimal SI suffixes (k, M, G, T, P, E)
    let decimal_suffixes = [
        ("k", 1_000i64),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("E", 1_000_000_000_000_000_000),
    ];
    for (suf, mult) in &decimal_suffixes {
        if let Some(rest) = s.strip_suffix(suf) {
            return rest.parse::<i64>().ok().map(|n| n * mult * 1000);
        }
    }
    // Plain integer
    s.parse::<i64>().ok().map(|n| n * 1000)
}

/// Format a milli-quantity back to a canonical Kubernetes quantity string.
/// For CPU use format_milli_cpu; for memory/storage use format_milli_bytes.
fn format_milli_cpu(milli: i64) -> String {
    if milli == 0 {
        return "0".to_string();
    }
    if milli % 1000 == 0 {
        (milli / 1000).to_string()
    } else {
        format!("{}m", milli)
    }
}

fn format_milli_bytes(milli: i64) -> String {
    if milli == 0 {
        return "0".to_string();
    }
    let bytes = milli / 1000;
    const EI: i64 = 1024 * 1024 * 1024 * 1024 * 1024 * 1024;
    const PI: i64 = 1024 * 1024 * 1024 * 1024 * 1024;
    const TI: i64 = 1024 * 1024 * 1024 * 1024;
    const GI: i64 = 1024 * 1024 * 1024;
    const MI: i64 = 1024 * 1024;
    const KI: i64 = 1024;
    for (unit, mult) in &[
        ("Ei", EI),
        ("Pi", PI),
        ("Ti", TI),
        ("Gi", GI),
        ("Mi", MI),
        ("Ki", KI),
    ] {
        if bytes % mult == 0 {
            return format!("{}{}", bytes / mult, unit);
        }
    }
    bytes.to_string()
}

fn format_milli_integer(milli: i64) -> String {
    (milli / 1000).to_string()
}

/// Classify a quota resource name into its resource-request category.
///
/// Returns (request_or_limits, resource_name_in_container) where:
/// - request_or_limits: "requests" or "limits"
/// - resource_name_in_container: the key to look up in container resources
///
/// Returns None for count-based resources (handled by `quota_resource_to_group_plural`).
fn quota_to_pod_resource(quota_resource: &str) -> Option<(&'static str, String)> {
    // "requests.cpu" → ("requests", "cpu")
    if let Some(rest) = quota_resource.strip_prefix("requests.") {
        return Some(("requests", rest.to_string()));
    }
    // "limits.cpu" → ("limits", "cpu")
    if let Some(rest) = quota_resource.strip_prefix("limits.") {
        return Some(("limits", rest.to_string()));
    }
    // Bare resource names that map to requests: cpu, memory, ephemeral-storage, hugepages-*
    // Also extended resources under other namespaced names are treated as requests.
    match quota_resource {
        "cpu" | "memory" | "ephemeral-storage" => Some(("requests", quota_resource.to_string())),
        // hugepages-* treated as requests
        s if s.starts_with("hugepages-") => Some(("requests", s.to_string())),
        _ => None,
    }
}

/// Classify a quota resource as CPU, memory/storage, or integer for output formatting.
fn quantity_format_type(resource_name: &str) -> &'static str {
    match resource_name {
        "cpu" => "cpu",
        r if r.ends_with("cpu") => "cpu",
        "memory" | "ephemeral-storage" => "bytes",
        r if r.ends_with("memory") || r.ends_with("storage") => "bytes",
        r if r.starts_with("hugepages-") => "bytes",
        _ => "integer",
    }
}

/// Extract the total milli-quantity of a resource from a single pod's containers.
/// Returns 0 if the pod is None or has no matching resource entries.
fn pod_resource_milli(pod: Option<&Value>, field: &str, resource: &str) -> i64 {
    let pod = match pod {
        Some(p) => p,
        None => return 0,
    };
    let mut total: i64 = 0;
    for containers_key in &["containers", "initContainers"] {
        if let Some(arr) = pod["spec"][containers_key].as_array() {
            for container in arr {
                if let Some(val) = container["resources"][field][resource].as_str() {
                    if let Some(milli) = parse_quantity_milli(val) {
                        total += milli;
                    }
                }
            }
        }
    }
    total
}

/// Sum resource requests or limits across all existing pods in a namespace for a given resource.
/// Returns the total in milli-units.
async fn sum_pod_resource_milli<S: Store>(
    store: &S,
    namespace: &str,
    quota: &Value,
    field: &str,
    resource: &str,
) -> i64 {
    let prefix = group_list_prefix("", "pods", Some(namespace));
    let items = match store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items,
        Err(_) => return 0,
    };

    let scopes: Vec<&str> = quota["spec"]["scopes"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|s| s.as_str()).collect())
        .unwrap_or_default();
    let scope_selector = &quota["spec"]["scopeSelector"];
    let has_scopes = !scopes.is_empty() || scope_selector.is_object();

    let mut total_milli: i64 = 0;
    for item in &items {
        let pod: Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if has_scopes {
            let matches = scopes.iter().all(|s| object_matches_scope(s, Some(&pod)));
            if !matches {
                continue;
            }
            if scope_selector.is_object()
                && !object_matches_scope_selector(scope_selector, Some(&pod))
            {
                continue;
            }
        }
        total_milli += pod_resource_milli(Some(&pod), field, resource);
    }
    total_milli
}

/// Sum resource requests or limits across all pods in a namespace for a given resource.
/// `field` is "requests" or "limits"; `resource` is e.g. "cpu", "memory", "example.com/dongle".
async fn sum_pod_resource<S: Store>(
    store: &S,
    namespace: &str,
    quota: &Value,
    field: &str,
    resource: &str,
    format: &str,
) -> String {
    let total_milli = sum_pod_resource_milli(store, namespace, quota, field, resource).await;
    match format {
        "cpu" => format_milli_cpu(total_milli),
        "bytes" => format_milli_bytes(total_milli),
        _ => format_milli_integer(total_milli),
    }
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

/// Returns true if `resource` is a service-type count quota (services.nodeports,
/// services.loadbalancers). These require filtering services by `spec.type` and
/// summing a per-service contribution, unlike a plain `services` count which
/// counts every service equally — so they cannot go through `count_objects`.
fn is_service_type_quota(resource: &str) -> bool {
    matches!(
        resource,
        "services.nodeports"
            | "count/services.nodeports"
            | "services.loadbalancers"
            | "count/services.loadbalancers"
    )
}

/// Units a single Service object contributes to a services.nodeports or
/// services.loadbalancers quota.
///
/// Mirrors upstream Kubernetes ResourceQuota service accounting: a NodePort
/// service consumes one nodeport per `spec.ports` entry; a LoadBalancer
/// service consumes the same (it gets allocated NodePorts too, unless
/// `allocateLoadBalancerNodePorts` is explicitly `false`) and separately
/// counts as 1 against services.loadbalancers. Without this split, a
/// NodePort service exhausting services.nodeports would not block a
/// subsequent LoadBalancer service from allocating more nodeports.
fn service_quota_units(service: &Value, resource: &str) -> u64 {
    let svc_type = service["spec"]["type"].as_str().unwrap_or("ClusterIP");
    let num_ports = service["spec"]["ports"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0) as u64;
    match resource {
        "services.nodeports" | "count/services.nodeports" => match svc_type {
            "NodePort" => num_ports,
            "LoadBalancer" => {
                let allocates_node_ports = service["spec"]["allocateLoadBalancerNodePorts"]
                    .as_bool()
                    .unwrap_or(true);
                if allocates_node_ports {
                    num_ports
                } else {
                    0
                }
            }
            _ => 0,
        },
        "services.loadbalancers" | "count/services.loadbalancers" => {
            u64::from(svc_type == "LoadBalancer")
        }
        _ => 0,
    }
}

/// Sum `service_quota_units` across all existing Services in `namespace` for the
/// given services.* quota resource.
async fn sum_service_quota_units<S: Store>(store: &S, namespace: &str, resource: &str) -> u64 {
    let prefix = group_list_prefix("", "services", Some(namespace));
    let items = match store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items,
        Err(_) => return 0,
    };
    items
        .iter()
        .filter_map(|item| serde_json::from_slice::<Value>(&item.value).ok())
        .map(|svc| service_quota_units(&svc, resource))
        .sum()
}

/// Count the current number of objects of a given resource kind in a namespace.
///
/// Tries the built-in-resource keyspace (`/registry/<group>/<plural>/<ns>/`) first, then
/// falls back to the CRD-backed keyspace (`/registry/cr/<group>/<plural>/<ns>/`, see
/// `handlers::cr::cr_store_key`) when that comes up empty. A given `(group, plural)` pair
/// is never both, so this is safe — without the fallback, a `count/<crd>.<group>` quota's
/// admission check always saw 0 existing CRs (the built-in prefix is structurally never
/// populated for CRD-backed resources), so the hard limit could never trigger.
async fn count_objects<S: Store>(
    state: &AppState<S>,
    namespace: &str,
    group: &str,
    plural: &str,
) -> u64 {
    let prefix = group_list_prefix(group, plural, Some(namespace));
    let count = match state.store.list(&prefix, ListOptions::default()).await {
        Ok(resp) => resp.items.len() as u64,
        Err(e) => {
            tracing::warn!("quota: failed to count {plural} in {namespace}: {e}");
            0
        }
    };
    if count > 0 || group.is_empty() {
        return count;
    }
    let cr_prefix = crate::handlers::cr::cr_list_prefix(group, plural, Some(namespace));
    match state.store.list(&cr_prefix, ListOptions::default()).await {
        Ok(resp) => resp.items.len() as u64,
        Err(e) => {
            tracing::warn!("quota: failed to count CR {plural} in {namespace}: {e}");
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

/// Returns true if a single PodAffinityTerm-shaped object declares cross-namespace
/// affinity — i.e. it sets a non-empty `namespaces` list or a non-null `namespaceSelector`.
///
/// Mirrors upstream `crossNamespacePodAffinityTerm`
/// (pkg/quota/v1/evaluator/core/pods.go, release-1.36).
fn affinity_term_is_cross_namespace(term: &Value) -> bool {
    term["namespaces"]
        .as_array()
        .is_some_and(|ns| !ns.is_empty())
        || term["namespaceSelector"].is_object()
}

/// Returns true if the pod declares at least one cross-namespace podAffinity or
/// podAntiAffinity term (required or preferred).
///
/// Mirrors upstream `usesCrossNamespacePodAffinity`
/// (pkg/quota/v1/evaluator/core/pods.go, release-1.36): a pod only "uses" cross-namespace
/// affinity when a term reaches beyond its own namespace via `namespaces` or
/// `namespaceSelector` — a same-namespace affinity/anti-affinity term (topologyKey only)
/// does not count.
fn pod_uses_cross_namespace_affinity(pod: &Value) -> bool {
    let affinity = &pod["spec"]["affinity"];
    for kind in ["podAffinity", "podAntiAffinity"] {
        let terms = &affinity[kind];
        if terms["requiredDuringSchedulingIgnoredDuringExecution"]
            .as_array()
            .is_some_and(|arr| arr.iter().any(affinity_term_is_cross_namespace))
        {
            return true;
        }
        if terms["preferredDuringSchedulingIgnoredDuringExecution"]
            .as_array()
            .is_some_and(|arr| {
                arr.iter()
                    .any(|w| affinity_term_is_cross_namespace(&w["podAffinityTerm"]))
            })
        {
            return true;
        }
    }
    false
}

/// Returns true if the object matches the given ResourceQuota scope.
///
/// Implemented scopes: BestEffort, NotBestEffort, Terminating, NotTerminating,
/// CrossNamespacePodAffinity. Unknown scopes are treated conservatively: the object is
/// assumed to match (quota applies), which is the safe default.
fn object_matches_scope(scope: &str, object: Option<&Value>) -> bool {
    match scope {
        "BestEffort" => object.is_some_and(pod_is_best_effort),
        "NotBestEffort" => object.is_none_or(|pod| !pod_is_best_effort(pod)),
        // A pod matches Terminating iff spec.activeDeadlineSeconds is set.
        "Terminating" => object.is_some_and(pod_is_terminating),
        "NotTerminating" => object.is_none_or(|pod| !pod_is_terminating(pod)),
        // A pod matches CrossNamespacePodAffinity iff it declares a podAffinity or
        // podAntiAffinity term with `namespaces` or `namespaceSelector` set — i.e. it is
        // genuinely cross-namespace, not just any pod with affinity/anti-affinity rules.
        "CrossNamespacePodAffinity" => object.is_some_and(pod_uses_cross_namespace_affinity),
        // Unknown scopes: assume match (conservative — don't silently skip quotas).
        _ => true,
    }
}

/// Returns true if the pod's `spec.priorityClassName` is one of `values`.
///
/// A pod with no `priorityClassName` set never matches any non-empty `values` list —
/// this makes `NotIn` correctly include unclassed pods (they're "not in" any named
/// priority class) and `In` correctly exclude them.
fn pod_matches_priority_class(object: Option<&Value>, values: &[&str]) -> bool {
    object.is_some_and(|pod| {
        pod["spec"]["priorityClassName"]
            .as_str()
            .is_some_and(|pc| values.contains(&pc))
    })
}

/// Returns true if the object matches all expressions in a scopeSelector.
///
/// Supported operators: Exists (pod must match scopeName), DoesNotExist (must not match),
/// and In/NotIn for the `PriorityClass` scope (pod's `priorityClassName` in/not-in
/// `values`). Without In/NotIn support, a quota scoped to e.g. `PriorityClass In
/// [pclass4]` degenerated to unscoped — every pod counted against it regardless of
/// priority class (upstream conformance: "should verify ResourceQuota's priority class
/// scope"). In/NotIn on any other scope name is unimplemented and treated as matching
/// (conservative default), as are unknown operators.
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
            "In" | "NotIn" if scope_name == "PriorityClass" => {
                let values: Vec<&str> = expr["values"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let in_values = pod_matches_priority_class(object, &values);
                if operator == "In" {
                    in_values
                } else {
                    !in_values
                }
            }
            // In/NotIn for scope names other than PriorityClass — not implemented;
            // treat as match (conservative default).
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
    // Any non-empty scopeSelector needs scope-aware counting, not just the enumerated
    // scope names below — e.g. `PriorityClass In [...]` (via `object_matches_scope_selector`'s
    // In/NotIn handling) must also exclude non-matching pods from status.used, or a
    // PriorityClass-scoped quota's status.used would report the raw unfiltered pod count.
    let has_scope_selector = quota["spec"]["scopeSelector"]["matchExpressions"]
        .as_array()
        .is_some_and(|arr| !arr.is_empty());
    let has_pod_scopes = has_scopes_array || has_scope_selector;

    let mut used = std::collections::BTreeMap::new();
    for (resource_name, _) in hard {
        if is_service_type_quota(resource_name) {
            let count = sum_service_quota_units(store, namespace, resource_name).await;
            used.insert(resource_name.clone(), count.to_string());
        } else if let Some((group, plural)) = quota_resource_to_group_plural(resource_name) {
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
        } else if let Some((field, resource_key)) = quota_to_pod_resource(resource_name) {
            let format = quantity_format_type(resource_name);
            let sum = sum_pod_resource(store, namespace, quota, field, &resource_key, format).await;
            used.insert(resource_name.clone(), sum);
        }
    }
    used
}

/// Recompute and persist `status.used` (and `status.hard`) for every ResourceQuota
/// in `namespace` whose `spec.hard` covers at least one known resource.
///
/// Called after a successful CREATE or DELETE of a quota-covered object. Errors are
/// logged and silently swallowed — the primary operation already succeeded and quota
/// status is best-effort observability, not a correctness gate.
pub async fn update_quota_status<S: Store>(state: &AppState<S>, namespace: &str) {
    let quotas = fetch_resource_quotas(state, namespace).await;
    if quotas.is_empty() {
        return;
    }

    for quota in quotas {
        let quota_name = match quota["metadata"]["name"].as_str() {
            Some(n) => n.to_string(),
            None => continue,
        };

        let used = count_quota_usage(&*state.store, &quota).await;
        if used.is_empty() {
            continue;
        }

        let key = crate::keys::group_object_key("", "resourcequotas", Some(namespace), &quota_name);

        let stored = match state.store.get(&key).await {
            Ok(Some(s)) => s,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("quota status: failed to fetch {quota_name}: {e}");
                continue;
            }
        };

        let mut obj: Value = match serde_json::from_slice(&stored.value) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("quota status: corrupt quota {quota_name}: {e}");
                continue;
            }
        };

        // status.hard mirrors spec.hard.
        let hard = obj["spec"]["hard"].clone();

        let used_map: serde_json::Map<String, Value> = used
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();

        obj["status"] = serde_json::json!({
            "hard": hard,
            "used": Value::Object(used_map),
        });

        let bytes =
            bytes::Bytes::from(serde_json::to_vec(&obj).expect("Value always serializable"));
        if let Err(e) = state.store.put(&key, bytes, None).await {
            tracing::warn!("quota status: failed to write status for {quota_name}: {e}");
        }
    }
}

/// Check ResourceQuota constraints before a CREATE operation.
///
/// Fetches all ResourceQuota objects in `namespace` and checks two quota types:
/// - Count-based: pods, services, configmaps, etc. — checks current count + 1 vs hard limit.
/// - Resource-request-based: cpu, memory, ephemeral-storage, etc. — sums existing pod
///   requests, adds the incoming pod's requests, and checks against the hard limit.
///
/// `object` is the pod (or other object) being created; it is used for scope matching
/// and for reading the incoming pod's resource requests. Pass `None` for non-pod resources.
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
                let limit_str = limit_val.as_str().unwrap_or("");

                // Path 0: service-type quotas (services.nodeports, services.loadbalancers).
                // These sum a per-port/per-type contribution rather than a flat 1-per-object
                // count, so they bypass the generic count-based path below.
                if resource == "services"
                    && group.is_empty()
                    && is_service_type_quota(quota_resource)
                {
                    let hard_limit = match parse_count(limit_str) {
                        Some(l) => l,
                        None => continue,
                    };
                    let existing =
                        sum_service_quota_units(&*state.store, namespace, quota_resource).await;
                    let incoming = object
                        .map(|o| service_quota_units(o, quota_resource))
                        .unwrap_or(0);
                    if existing + incoming > hard_limit {
                        tracing::debug!(
                            quota = %quota_name,
                            resource = %quota_resource,
                            requested = incoming,
                            used = existing,
                            limit = %limit_str,
                            "quota: request rejected — hard limit exceeded"
                        );
                        return Err(Status::forbidden(format!(
                            "exceeded quota: {quota_name}, requested: \
                             {quota_resource}={incoming}, used: {quota_resource}={existing}, \
                             limited: {quota_resource}={hard_limit}"
                        )));
                    }
                    continue;
                }

                // Path 1: count-based quota — covers the API resource type being created.
                if quota_resource_covers(quota_resource, group, resource) {
                    let hard_limit = match parse_count(limit_str) {
                        Some(l) => l,
                        None => continue,
                    };
                    let (count_group, count_plural) =
                        match quota_resource_to_group_plural(quota_resource) {
                            Some(p) => p,
                            None => (group, resource),
                        };
                    let current = count_objects(state, namespace, count_group, count_plural).await;
                    if current >= hard_limit {
                        tracing::debug!(
                            quota = %quota_name,
                            resource = %quota_resource,
                            requested = 1,
                            used = current,
                            limit = %limit_str,
                            "quota: request rejected — hard limit exceeded"
                        );
                        return Err(Status::forbidden(format!(
                            "exceeded quota: {quota_name}, requested: {quota_resource}=1, \
                             used: {quota_resource}={current}, limited: {quota_resource}={hard_limit}"
                        )));
                    }
                    continue;
                }

                // Path 2: resource-request quota (cpu, memory, ephemeral-storage, etc.).
                // Only applies when creating pods.
                if resource == "pods" && group.is_empty() {
                    if let Some((field, resource_key)) = quota_to_pod_resource(quota_resource) {
                        let hard_milli = match parse_quantity_milli(limit_str) {
                            Some(m) => m,
                            None => continue,
                        };
                        let existing_milli = sum_pod_resource_milli(
                            &*state.store,
                            namespace,
                            quota,
                            field,
                            &resource_key,
                        )
                        .await;
                        let incoming_milli = pod_resource_milli(object, field, &resource_key);
                        if existing_milli + incoming_milli > hard_milli {
                            let format = quantity_format_type(quota_resource);
                            let used_str = match format {
                                "cpu" => format_milli_cpu(existing_milli),
                                "bytes" => format_milli_bytes(existing_milli),
                                _ => format_milli_integer(existing_milli),
                            };
                            let req_str = match format {
                                "cpu" => format_milli_cpu(incoming_milli),
                                "bytes" => format_milli_bytes(incoming_milli),
                                _ => format_milli_integer(incoming_milli),
                            };
                            tracing::debug!(
                                quota = %quota_name,
                                resource = %quota_resource,
                                requested = %req_str,
                                used = %used_str,
                                limit = %limit_str,
                                "quota: request rejected — hard limit exceeded"
                            );
                            return Err(Status::forbidden(format!(
                                "exceeded quota: {quota_name}, requested: \
                                 {quota_resource}={req_str}, used: {quota_resource}={used_str}, \
                                 limited: {quota_resource}={limit_str}"
                            )));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Splits a `"<resource>.<group>"`-shaped quota resource name on the KNOWN `resource`
/// prefix (not the last dot) and compares the remainder to `group`.
///
/// CRD groups are conventionally domain-like (e.g. `example.com`) and DRA's built-in
/// group is `resource.k8s.io` — both contain dots themselves. Splitting on the LAST dot
/// (`rfind('.')`) instead mis-parses `"widgets.example.com"` as resource=`"widgets.example"`,
/// group=`"com"`, so it never matches the real `(resource="widgets", group="example.com")`
/// pair — silently making `count/widgets.example.com` (or `count/resourceclaims.resource.k8s.io`)
/// never cover its own resource, so ResourceQuota admission never enforces the hard limit at all
/// (upstream conformance: "capture the life of a custom resource",
/// "[DRA] ... count/resourceclaims.resource.k8s.io ResourceQuota").
fn resource_group_matches(quota_suffix: &str, resource: &str, group: &str) -> bool {
    quota_suffix
        .strip_prefix(resource)
        .and_then(|rest| rest.strip_prefix('.'))
        == Some(group)
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
        // suffix may be "pods", "deployments.apps", "widgets.example.com", etc.
        if suffix == resource && group.is_empty() {
            return true;
        }
        if resource_group_matches(suffix, resource, group) {
            return true;
        }
    }
    // "deployments.apps" style (no count/ prefix)
    if resource_group_matches(quota_resource, resource, group) {
        return true;
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

    /// "count/widgets.example.com" (a CRD count quota, group has its own dot) must cover
    /// (group="example.com", resource="widgets"). Splitting on the LAST dot instead of the
    /// known resource prefix would mis-parse this as resource="widgets.example", group="com",
    /// silently making the quota never apply — the exact bug behind upstream conformance's
    /// "should create a ResourceQuota and capture the life of a custom resource" (a second CR
    /// past the count/1 hard limit was admitted instead of rejected).
    #[test]
    fn quota_resource_covers_count_crd_with_dotted_group() {
        assert!(
            quota_resource_covers("count/widgets.example.com", "example.com", "widgets"),
            "count/<resource>.<group> must cover the resource even when <group> itself \
             contains dots (CRD groups are conventionally domain-like)"
        );
        assert!(
            !quota_resource_covers("count/widgets.example.com", "example.com", "gadgets"),
            "a mismatched resource name must still not match, even with a dotted group"
        );
    }

    /// "count/resourceclaims.resource.k8s.io" (DRA's built-in group has two dots) must cover
    /// (group="resource.k8s.io", resource="resourceclaims") — same root cause as the CRD case
    /// above, reproduces upstream conformance's "[DRA] control plane supports
    /// count/resourceclaims.resource.k8s.io ResourceQuota" (a second ResourceClaim past the
    /// count/1 hard limit was admitted instead of rejected).
    #[test]
    fn quota_resource_covers_count_dra_resourceclaims() {
        assert!(quota_resource_covers(
            "count/resourceclaims.resource.k8s.io",
            "resource.k8s.io",
            "resourceclaims"
        ));
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

    /// A `count/<crd>.<group>` quota at its hard limit must deny a new custom resource.
    /// CRs are stored under `/registry/cr/<group>/<plural>/<ns>/` (see
    /// `handlers::cr::cr_store_key`), NOT the built-in `/registry/<group>/<plural>/<ns>/`
    /// keyspace `count_objects` checks first — without the CR-keyspace fallback,
    /// `count_objects` always saw 0 existing CRs and the hard limit could never trigger.
    /// Reproduces upstream conformance's "should create a ResourceQuota and capture the
    /// life of a custom resource".
    #[tokio::test]
    async fn check_quota_count_crd_denies_when_cr_keyspace_at_limit() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "crd-quota", "namespace": "default" },
            "spec": { "hard": { "count/widgets.example.com": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/crd-quota", quota).await;

        // One existing CR, stored under the CR keyspace — not the built-in keyspace.
        seed(
            &state,
            "/registry/cr/example.com/widgets/default/widget-1",
            json!({
                "apiVersion": "example.com/v1",
                "kind": "Widget",
                "metadata": { "name": "widget-1", "namespace": "default" }
            }),
        )
        .await;

        let result = check_resource_quota(&state, "default", "example.com", "widgets", None).await;
        assert!(
            result.is_err(),
            "a second custom resource must be denied once count/widgets.example.com=1 is \
             already claimed by a CR stored in the CR keyspace"
        );
    }

    /// The exceeded-quota error message must repeat `<resource>=<value>` in ALL THREE of
    /// requested/used/limited — mirroring upstream's `ResourceList.String()` rendering —
    /// not bare numbers for used/limited. Upstream conformance tests assert on this exact
    /// substring (e.g. DRA's "supports count/resourceclaims.resource.k8s.io ResourceQuota":
    /// `ContainSubstring("exceeded quota: object-count, requested:
    /// count/resourceclaims.resource.k8s.io=1, used: count/resourceclaims.resource.k8s.io=1,
    /// limited: count/resourceclaims.resource.k8s.io=1")`) — a bare number there left the
    /// create correctly REJECTED but failed the test's message-content assertion.
    #[tokio::test]
    async fn check_quota_denial_message_repeats_resource_name_in_used_and_limited() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "object-count", "namespace": "default" },
            "spec": { "hard": { "count/resourceclaims.resource.k8s.io": "1" } }
        });
        seed(
            &state,
            "/registry/resourcequotas/default/object-count",
            quota,
        )
        .await;
        seed(
            &state,
            "/registry/resource.k8s.io/resourceclaims/default/claim-0",
            json!({
                "apiVersion": "resource.k8s.io/v1",
                "kind": "ResourceClaim",
                "metadata": { "name": "claim-0", "namespace": "default" }
            }),
        )
        .await;

        let err =
            check_resource_quota(&state, "default", "resource.k8s.io", "resourceclaims", None)
                .await
                .expect_err("quota at limit must deny the second claim");
        assert_eq!(
            err.1.message,
            "exceeded quota: object-count, requested: count/resourceclaims.resource.k8s.io=1, \
             used: count/resourceclaims.resource.k8s.io=1, \
             limited: count/resourceclaims.resource.k8s.io=1",
            "denial message must match upstream's exact ResourceList.String() format so \
             conformance tests asserting on message content (not just error-occurred) pass"
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

    // -- CrossNamespacePodAffinity scope matching --

    /// A pod whose podAffinity term sets a non-empty `namespaces` list is genuinely
    /// cross-namespace and must match the CrossNamespacePodAffinity scope. Before this
    /// fix, every scope name other than the four hard-coded ones fell through to the
    /// `_ => true` default, so this already passed for the wrong reason — the negative
    /// test below is what actually pins the fix down.
    #[test]
    fn cross_namespace_pod_affinity_scope_matches_pod_with_namespaces_on_pod_affinity() {
        let pod = json!({
            "spec": {
                "affinity": {
                    "podAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": [{
                            "topologyKey": "kubernetes.io/hostname",
                            "namespaces": ["ns1"]
                        }]
                    }
                }
            }
        });
        assert!(
            object_matches_scope("CrossNamespacePodAffinity", Some(&pod)),
            "a podAffinity term with a non-empty `namespaces` list reaches into another \
             namespace and must match CrossNamespacePodAffinity — else a genuinely \
             cross-namespace pod would be excluded from the scope's quota accounting"
        );
    }

    /// A pod whose podAntiAffinity term sets a `namespaceSelector` (not `namespaces`) is
    /// also cross-namespace and must match — upstream's `crossNamespacePodAffinityTerm`
    /// treats `namespaces` and `namespaceSelector` as equally sufficient.
    #[test]
    fn cross_namespace_pod_affinity_scope_matches_pod_with_namespace_selector_on_anti_affinity() {
        let pod = json!({
            "spec": {
                "affinity": {
                    "podAntiAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": [{
                            "topologyKey": "kubernetes.io/hostname",
                            "namespaceSelector": {
                                "matchLabels": {"team": "foo"}
                            }
                        }]
                    }
                }
            }
        });
        assert!(
            object_matches_scope("CrossNamespacePodAffinity", Some(&pod)),
            "a podAntiAffinity term with a `namespaceSelector` reaches into other \
             namespaces via label selection and must match CrossNamespacePodAffinity"
        );
    }

    /// A pod with a podAntiAffinity term that has NEITHER `namespaces` NOR
    /// `namespaceSelector` (single-namespace anti-affinity) must NOT match
    /// CrossNamespacePodAffinity. This is the exact bug reported by mayor-5vxfn: before
    /// this fix, `object_matches_scope`'s `_ => true` fall-through counted every pod with
    /// ANY affinity/anti-affinity rule against a CrossNamespacePodAffinity-scoped quota,
    /// so `status.used.pods` incremented for a pod that upstream's conformance test
    /// explicitly asserts "does not use cross namespace affinity" and must not count.
    #[test]
    fn cross_namespace_pod_affinity_scope_does_not_match_single_namespace_anti_affinity() {
        let pod = json!({
            "spec": {
                "affinity": {
                    "podAntiAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": [{
                            "topologyKey": "region",
                            "labelSelector": {
                                "matchExpressions": [{
                                    "key": "security",
                                    "operator": "In",
                                    "values": ["S2"]
                                }]
                            }
                        }]
                    }
                }
            }
        });
        assert!(
            !object_matches_scope("CrossNamespacePodAffinity", Some(&pod)),
            "a podAntiAffinity term scoped to topologyKey only (no `namespaces` or \
             `namespaceSelector`) stays within its own namespace and must NOT match \
             CrossNamespacePodAffinity — else every anti-affinity pod wrongly consumes a \
             CrossNamespacePodAffinity-scoped quota's hard limit (mayor-5vxfn)"
        );
    }

    // -- PriorityClass scopeSelector (In/NotIn) matching --

    /// A quota scoped to `PriorityClass In [pclass4]` must NOT match a pod using a
    /// different priority class (pclass3), and MUST match a pod using pclass4.
    ///
    /// Before this fix, `object_matches_scope_selector`'s `_ => true` catch-all made every
    /// In/NotIn expression match unconditionally, so a `PriorityClass In [...]` quota
    /// behaved as fully unscoped: pods with an unrelated priority class still counted
    /// against its hard pod-count limit. This reproduces upstream conformance's "should
    /// verify ResourceQuota's priority class scope" — a pod using pclass3 wrongly consumed
    /// the quota's `pods: 1` hard limit, causing a subsequent unrelated pod create to be
    /// rejected with "exceeded quota".
    #[test]
    fn scope_selector_in_priority_class_matches_only_listed_values() {
        let scope_selector = json!({
            "matchExpressions": [{
                "scopeName": "PriorityClass",
                "operator": "In",
                "values": ["pclass4"]
            }]
        });
        let pod_pclass3 = json!({ "spec": { "priorityClassName": "pclass3" } });
        let pod_pclass4 = json!({ "spec": { "priorityClassName": "pclass4" } });

        assert!(
            !object_matches_scope_selector(&scope_selector, Some(&pod_pclass3)),
            "a pod whose priorityClassName is NOT in the scopeSelector's In-list must not \
             match the quota's scope — else the quota behaves as unscoped"
        );
        assert!(
            object_matches_scope_selector(&scope_selector, Some(&pod_pclass4)),
            "a pod whose priorityClassName IS in the scopeSelector's In-list must match \
             the quota's scope"
        );
    }

    /// A quota scoped to `PriorityClass NotIn [pclass7]` must match a pod using a
    /// different priority class and must NOT match a pod using pclass7 itself —
    /// the exact inverse of the `In` case, both driven by the same operator branch.
    #[test]
    fn scope_selector_not_in_priority_class_excludes_only_listed_values() {
        let scope_selector = json!({
            "matchExpressions": [{
                "scopeName": "PriorityClass",
                "operator": "NotIn",
                "values": ["pclass7"]
            }]
        });
        let pod_pclass7 = json!({ "spec": { "priorityClassName": "pclass7" } });
        let pod_other = json!({ "spec": { "priorityClassName": "pclass-other" } });

        assert!(
            !object_matches_scope_selector(&scope_selector, Some(&pod_pclass7)),
            "a pod whose priorityClassName IS in the NotIn list must not match the scope"
        );
        assert!(
            object_matches_scope_selector(&scope_selector, Some(&pod_other)),
            "a pod whose priorityClassName is NOT in the NotIn list must match the scope"
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

    /// A `PriorityClass In [pclass4]`-scoped quota's status.used.pods must stay "0" when
    /// only non-matching (pclass3) pods exist in the namespace — `count_quota_usage` must
    /// route pod counting through the scope-filtered path for ANY non-empty scopeSelector,
    /// not just the four hard-coded scope names (BestEffort/NotBestEffort/Terminating/
    /// NotTerminating). Before this fix, a PriorityClass scopeSelector fell through to the
    /// unscoped raw pod count, so status.used.pods would wrongly report the pod as
    /// consuming the quota — reproduces the status half of upstream conformance's "should
    /// verify ResourceQuota's priority class scope".
    #[tokio::test]
    async fn count_quota_usage_excludes_non_matching_priority_class_pods() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "quota-priorityclass", "namespace": "default" },
            "spec": {
                "scopeSelector": {
                    "matchExpressions": [{
                        "scopeName": "PriorityClass",
                        "operator": "In",
                        "values": ["pclass4"]
                    }]
                },
                "hard": { "pods": "1" }
            }
        });
        seed(
            &state,
            "/registry/resourcequotas/default/quota-priorityclass",
            quota.clone(),
        )
        .await;

        // A pod using an unrelated priority class must not count against this quota.
        let non_matching_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "testpod-pclass3", "namespace": "default" },
            "spec": { "priorityClassName": "pclass3", "containers": [{"name": "c"}] }
        });
        seed(
            &state,
            "/registry/pods/default/testpod-pclass3",
            non_matching_pod,
        )
        .await;

        let used = count_quota_usage(&*state.store, &quota).await;
        assert_eq!(
            used.get("pods").map(String::as_str),
            Some("0"),
            "a pod using a priority class outside the quota's scopeSelector In-list must \
             not be counted in status.used.pods"
        );
    }

    // -- update_quota_status --

    /// After a pod is added to the store (simulating CREATE), update_quota_status must
    /// write status.used.pods = 1 to the ResourceQuota. Without this, the conformance
    /// test polling status.used.pods times out after 5 minutes.
    #[tokio::test]
    async fn update_quota_status_reflects_pod_count_after_create() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "test-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "10" } }
        });
        seed(&state, "/registry/resourcequotas/default/test-quota", quota).await;

        // Initially no pods → update should write used.pods = "0".
        update_quota_status(&state, "default").await;
        let stored = state
            .store
            .get("/registry/resourcequotas/default/test-quota")
            .await
            .unwrap()
            .unwrap();
        let obj: Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["status"]["used"]["pods"].as_str(),
            Some("0"),
            "status.used.pods must be 0 when no pods exist — \
             conformance test polls this field; absent or wrong value causes 5 min timeout"
        );
        assert_eq!(
            obj["status"]["hard"]["pods"].as_str(),
            Some("10"),
            "status.hard must mirror spec.hard so kubectl get resourcequota shows limits"
        );

        // Seed a pod → used.pods must become "1".
        let pod = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": "p1", "namespace": "default" }
        });
        seed(&state, "/registry/pods/default/p1", pod).await;

        update_quota_status(&state, "default").await;
        let stored = state
            .store
            .get("/registry/resourcequotas/default/test-quota")
            .await
            .unwrap()
            .unwrap();
        let obj: Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["status"]["used"]["pods"].as_str(),
            Some("1"),
            "status.used.pods must be 1 after a pod is created — \
             this is the field the conformance test 'capture the life of a pod' polls"
        );
    }

    /// After a pod is removed from the store (simulating hard-DELETE), update_quota_status
    /// must write status.used.pods = 0. Without this, the quota status is stale forever
    /// and any subsequent quota check would incorrectly count the deleted pod.
    #[tokio::test]
    async fn update_quota_status_reflects_pod_count_after_delete() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "test-quota", "namespace": "default" },
            "spec": { "hard": { "pods": "10" } }
        });
        seed(&state, "/registry/resourcequotas/default/test-quota", quota).await;

        let pod = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": "p1", "namespace": "default" }
        });
        seed(&state, "/registry/pods/default/p1", pod).await;

        update_quota_status(&state, "default").await;
        let stored = state
            .store
            .get("/registry/resourcequotas/default/test-quota")
            .await
            .unwrap()
            .unwrap();
        let obj: Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(obj["status"]["used"]["pods"].as_str(), Some("1"));

        // Delete the pod.
        state
            .store
            .delete("/registry/pods/default/p1", None)
            .await
            .unwrap();

        update_quota_status(&state, "default").await;
        let stored = state
            .store
            .get("/registry/resourcequotas/default/test-quota")
            .await
            .unwrap()
            .unwrap();
        let obj: Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["status"]["used"]["pods"].as_str(),
            Some("0"),
            "status.used.pods must decrement to 0 after the pod is hard-deleted — \
             stale counts prevent new pods from being created when the quota is tight"
        );
    }

    /// A pod whose CPU request would push total CPU usage over the hard limit must be denied.
    /// Without resource-request enforcement, cpu/memory/ephemeral-storage quotas are silently
    /// skipped at admission and pods can consume unbounded resources.
    #[tokio::test]
    async fn check_quota_cpu_request_exceeds_limit_denies() {
        let state = make_state();

        // Quota: max 1 CPU total
        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "cpu-quota", "namespace": "default" },
            "spec": { "hard": { "cpu": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/cpu-quota", quota).await;

        // Existing pod already using 500m CPU
        let existing_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "existing", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "resources": { "requests": { "cpu": "500m" } }
                }]
            }
        });
        seed(&state, "/registry/pods/default/existing", existing_pod).await;

        // Incoming pod requests 750m CPU — total would be 1250m > 1000m limit
        let new_pod = json!({
            "spec": {
                "containers": [{
                    "name": "c",
                    "resources": { "requests": { "cpu": "750m" } }
                }]
            }
        });
        let result = check_resource_quota(&state, "default", "", "pods", Some(&new_pod)).await;
        assert!(
            result.is_err(),
            "pod that pushes total CPU over quota limit must be denied at admission"
        );
        assert_eq!(
            result.unwrap_err().0,
            axum::http::StatusCode::FORBIDDEN,
            "cpu quota exceeded must return 403 Forbidden"
        );
    }

    /// A pod whose requests fit within remaining quota must be allowed.
    /// Verifies the enforcement is not overly strict (no false denials).
    #[tokio::test]
    async fn check_quota_cpu_request_within_limit_allows() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "cpu-quota", "namespace": "default" },
            "spec": { "hard": { "cpu": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/cpu-quota", quota).await;

        // Existing pod using 500m CPU
        let existing_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "existing", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "resources": { "requests": { "cpu": "500m" } }
                }]
            }
        });
        seed(&state, "/registry/pods/default/existing", existing_pod).await;

        // Incoming pod requests 499m CPU — total 999m < 1000m — must be allowed
        let new_pod = json!({
            "spec": {
                "containers": [{
                    "name": "c",
                    "resources": { "requests": { "cpu": "499m" } }
                }]
            }
        });
        let result = check_resource_quota(&state, "default", "", "pods", Some(&new_pod)).await;
        assert!(
            result.is_ok(),
            "pod within remaining CPU quota must be allowed"
        );
    }

    // -- services.nodeports / services.loadbalancers quotas --

    fn nodeport_service(name: &str, ns: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": name, "namespace": ns },
            "spec": { "type": "NodePort", "ports": [{"port": 80}] }
        })
    }

    fn loadbalancer_service(name: &str, ns: &str) -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": name, "namespace": ns },
            "spec": {
                "type": "LoadBalancer",
                "ports": [{"port": 80}],
                "allocateLoadBalancerNodePorts": true
            }
        })
    }

    /// A quota capping services.nodeports=1 must deny a 2nd NodePort service once the
    /// first has claimed the only allowed nodeport. Cluster nodeports are a finite,
    /// shared resource (30000-32767 range) — without this check a namespace could
    /// exhaust the whole cluster's nodeport range unbounded.
    #[tokio::test]
    async fn check_quota_second_nodeport_service_denied_when_nodeports_quota_at_limit() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "np-quota", "namespace": "default" },
            "spec": { "hard": { "services.nodeports": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/np-quota", quota).await;
        seed(
            &state,
            "/registry/services/default/svc-np-1",
            nodeport_service("svc-np-1", "default"),
        )
        .await;

        let incoming = nodeport_service("svc-np-2", "default");
        let result = check_resource_quota(&state, "default", "", "services", Some(&incoming)).await;
        assert!(
            result.is_err(),
            "2nd NodePort service must be denied once services.nodeports=1 is already claimed"
        );
        assert_eq!(
            result.unwrap_err().0,
            axum::http::StatusCode::FORBIDDEN,
            "services.nodeports exceeded must return 403 Forbidden"
        );
    }

    /// Matches the upstream conformance scenario directly: a NodePort service exhausts
    /// services.nodeports=1; a subsequent LoadBalancer service (which also allocates a
    /// nodeport by default) must then be denied even though services.loadbalancers=1
    /// alone would allow it. If u7s only checked services.loadbalancers and ignored
    /// that LoadBalancer services also consume nodeports, this would wrongly succeed.
    #[tokio::test]
    async fn check_quota_loadbalancer_service_denied_when_nodeports_exhausted_by_nodeport_service()
    {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "svc-quota", "namespace": "default" },
            "spec": { "hard": { "services.nodeports": "1", "services.loadbalancers": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/svc-quota", quota).await;
        seed(
            &state,
            "/registry/services/default/svc-np",
            nodeport_service("svc-np", "default"),
        )
        .await;

        let incoming = loadbalancer_service("svc-lb", "default");
        let result = check_resource_quota(&state, "default", "", "services", Some(&incoming)).await;
        assert!(
            result.is_err(),
            "LoadBalancer service creation must be denied when it would exceed the \
             remaining services.nodeports quota, even though services.loadbalancers alone \
             would allow it — matches k8s conformance 'capture the life of a service'"
        );
        assert_eq!(
            result.unwrap_err().0,
            axum::http::StatusCode::FORBIDDEN,
            "services.nodeports exceeded via a LoadBalancer service must return 403 Forbidden"
        );
    }

    /// A LoadBalancer service must be allowed and counted when the loadbalancers quota
    /// has room — verifies the check is not overly strict (no false denials for the
    /// first LoadBalancer service in a namespace).
    #[tokio::test]
    async fn check_quota_loadbalancer_service_within_limit_allows() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "lb-quota", "namespace": "default" },
            "spec": { "hard": { "services.loadbalancers": "1" } }
        });
        seed(&state, "/registry/resourcequotas/default/lb-quota", quota).await;

        let incoming = loadbalancer_service("svc-lb", "default");
        let result = check_resource_quota(&state, "default", "", "services", Some(&incoming)).await;
        assert!(
            result.is_ok(),
            "first LoadBalancer service must be allowed when services.loadbalancers quota has room"
        );
    }

    /// status.used must report services.nodeports and services.loadbalancers correctly
    /// split by service type — a NodePort service must not be counted against
    /// services.loadbalancers and vice versa. `kubectl get resourcequota` and the
    /// conformance test poll these exact fields.
    #[tokio::test]
    async fn update_quota_status_reflects_nodeport_and_loadbalancer_counts_separately() {
        let state = make_state();

        let quota = json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "svc-quota", "namespace": "default" },
            "spec": { "hard": { "services.nodeports": "10", "services.loadbalancers": "10" } }
        });
        seed(&state, "/registry/resourcequotas/default/svc-quota", quota).await;
        seed(
            &state,
            "/registry/services/default/svc-np",
            nodeport_service("svc-np", "default"),
        )
        .await;
        seed(
            &state,
            "/registry/services/default/svc-lb",
            loadbalancer_service("svc-lb", "default"),
        )
        .await;

        update_quota_status(&state, "default").await;
        let stored = state
            .store
            .get("/registry/resourcequotas/default/svc-quota")
            .await
            .unwrap()
            .unwrap();
        let obj: Value = serde_json::from_slice(&stored.value).unwrap();
        assert_eq!(
            obj["status"]["used"]["services.nodeports"].as_str(),
            Some("2"),
            "services.nodeports must count both the NodePort service's port AND the \
             LoadBalancer service's port (LB services also allocate nodeports by default) — \
             dropping this leaves nodeports unbounded"
        );
        assert_eq!(
            obj["status"]["used"]["services.loadbalancers"].as_str(),
            Some("1"),
            "services.loadbalancers must count only the LoadBalancer-type service, not \
             the NodePort-type one"
        );
    }
}
