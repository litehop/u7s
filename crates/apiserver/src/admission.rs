/// Admission webhook invocation pipeline.
///
/// Implements the MutatingWebhookConfiguration and ValidatingWebhookConfiguration
/// chains per the Kubernetes admission spec:
/// - Fetch all configurations from the store
/// - For each matching webhook POST an AdmissionReview
/// - Apply JSON patches from mutating webhooks
/// - Reject on failurePolicy: Fail if webhook is unreachable or returns denied
/// - Re-run mutating webhooks marked reinvocationPolicy: IfNeeded if any patch was applied
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use u7s_store::{ListOptions, Store as _};

use crate::state::AppState;
use crate::status::{Status, StatusError};

// ---------------------------------------------------------------------------
// AdmissionReview types (matches Kubernetes API schema)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionReview {
    pub api_version: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<AdmissionRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<AdmissionResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionRequest {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub resource: GroupVersionResource,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub operation: String,
    pub object: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AdmissionStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal webhook config shapes (only fields we need)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebhookConfig {
    #[serde(default)]
    webhooks: Vec<WebhookEntry>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebhookEntry {
    name: String,
    client_config: WebhookClientConfig,
    #[serde(default)]
    rules: Vec<RuleWithOperations>,
    #[serde(default = "default_failure_policy")]
    failure_policy: String,
    #[serde(default)]
    reinvocation_policy: String,
    #[serde(default)]
    namespace_selector: Option<LabelSelector>,
}

/// Kubernetes LabelSelector: both fields are optional; absence means match-all.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LabelSelector {
    #[serde(default)]
    match_labels: BTreeMap<String, String>,
    #[serde(default)]
    match_expressions: Vec<LabelSelectorRequirement>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LabelSelectorRequirement {
    key: String,
    operator: String, // In, NotIn, Exists, DoesNotExist
    #[serde(default)]
    values: Vec<String>,
}

fn default_failure_policy() -> String {
    "Fail".to_string()
}

/// Evaluate a Kubernetes LabelSelector against a set of labels.
///
/// Returns `true` if the selector matches (or if no selector is configured — None means
/// match-all, which is the correct Kubernetes default). A selector with both
/// `matchLabels` and `matchExpressions` must satisfy all conditions (logical AND).
///
/// This is a pure function, unit-testable without I/O.
pub(crate) fn label_selector_matches(
    selector: Option<&LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    let sel = match selector {
        None => return true, // absent selector matches everything
        Some(s) => s,
    };

    // matchLabels: every key=value pair must be present in labels
    for (k, v) in &sel.match_labels {
        if labels.get(k).map(|s| s.as_str()) != Some(v.as_str()) {
            return false;
        }
    }

    // matchExpressions: every requirement must be satisfied
    for req in &sel.match_expressions {
        let has_key = labels.contains_key(&req.key);
        let matches = match req.operator.as_str() {
            "Exists" => has_key,
            "DoesNotExist" => !has_key,
            "In" => {
                has_key
                    && req
                        .values
                        .iter()
                        .any(|v| Some(v.as_str()) == labels.get(&req.key).map(|s| s.as_str()))
            }
            "NotIn" => {
                !has_key
                    || req
                        .values
                        .iter()
                        .all(|v| Some(v.as_str()) != labels.get(&req.key).map(|s| s.as_str()))
            }
            _ => {
                tracing::warn!(
                    "admission: unknown labelSelector operator: {}",
                    req.operator
                );
                false
            }
        };
        if !matches {
            return false;
        }
    }

    true
}

/// Fetch the namespace object labels from the store.
///
/// Returns an empty map if the namespace is not found (cluster-scoped requests
/// have no namespace; the caller should skip namespace_selector evaluation in that case).
async fn fetch_namespace_labels(state: &AppState, namespace: &str) -> BTreeMap<String, String> {
    let key = format!("/registry/namespaces/{namespace}");
    match state.store.get(&key).await {
        Ok(Some(obj)) => {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
                val["metadata"]["labels"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                BTreeMap::new()
            }
        }
        _ => BTreeMap::new(),
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebhookClientConfig {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    service: Option<ServiceReference>,
}

/// In-cluster service reference for a webhook's clientConfig.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ServiceReference {
    namespace: String,
    name: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path: Option<String>,
}

/// Resolve a webhook's clientConfig to a URL string.
///
/// If `clientConfig.url` is set, returns it directly.
/// If `clientConfig.service` is set, looks up the Service object from the store by
/// namespace+name and builds `https://<clusterIP>:<port><path>`.
/// Returns an error if the service reference is set but the Service is not found.
async fn webhook_url(
    state: &AppState,
    config: &WebhookClientConfig,
    webhook_name: &str,
) -> Result<String, String> {
    if let Some(url) = &config.url {
        return Ok(url.clone());
    }

    if let Some(svc_ref) = &config.service {
        let key = format!(
            "/registry/services/{}/{}", // core/v1 Service: /registry/services/<ns>/<name>
            svc_ref.namespace, svc_ref.name
        );
        let obj = state.store.get(&key).await.map_err(|e| {
            format!(
                "store error looking up service {}/{}: {e}",
                svc_ref.namespace, svc_ref.name
            )
        })?;

        let svc = match obj {
            Some(o) => o,
            None => {
                return Err(format!(
                    "webhook \"{webhook_name}\": service {}/{} not found",
                    svc_ref.namespace, svc_ref.name
                ));
            }
        };

        let val: serde_json::Value = serde_json::from_slice(&svc.value)
            .map_err(|e| format!("webhook \"{webhook_name}\": failed to parse service: {e}"))?;

        let cluster_ip = val["spec"]["clusterIP"].as_str().ok_or_else(|| {
            format!(
                "webhook \"{webhook_name}\": service {}/{} has no clusterIP",
                svc_ref.namespace, svc_ref.name
            )
        })?;

        let port = svc_ref.port.unwrap_or(443);
        let path = svc_ref.path.as_deref().unwrap_or("/");

        return Ok(format!("https://{cluster_ip}:{port}{path}"));
    }

    Err(format!(
        "webhook \"{webhook_name}\" has neither url nor service in clientConfig"
    ))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RuleWithOperations {
    #[serde(default)]
    api_groups: Vec<String>,
    #[serde(default)]
    api_versions: Vec<String>,
    #[serde(default)]
    resources: Vec<String>,
    #[serde(default)]
    operations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Rule matching
// ---------------------------------------------------------------------------

/// Returns true if the webhook rule matches the given resource/operation/group/version.
///
/// Wildcard "*" matches anything. An empty rules list means no rules — does not match.
/// This is a pure function, testable without I/O.
pub fn matches_rule(
    rule: &serde_json::Value,
    group: &str,
    version: &str,
    resource: &str,
    namespace: Option<&str>,
    operation: &str,
) -> bool {
    let api_groups = rule["apiGroups"].as_array().cloned().unwrap_or_default();
    let api_versions = rule["apiVersions"].as_array().cloned().unwrap_or_default();
    let resources = rule["resources"].as_array().cloned().unwrap_or_default();
    let operations = rule["operations"].as_array().cloned().unwrap_or_default();

    let group_match = api_groups.iter().any(|g| {
        let s = g.as_str().unwrap_or("");
        s == "*" || s == group
    });
    let version_match = api_versions.iter().any(|v| {
        let s = v.as_str().unwrap_or("");
        s == "*" || s == version
    });
    let resource_match = resources.iter().any(|r| {
        let s = r.as_str().unwrap_or("");
        s == "*" || s == resource
    });
    let operation_match = operations.iter().any(|o| {
        let s = o.as_str().unwrap_or("");
        s == "*" || s == operation
    });

    let _ = namespace; // namespace scoping is handled separately via namespaceSelector evaluation

    group_match && version_match && resource_match && operation_match
}

// ---------------------------------------------------------------------------
// Resource context passed through the admission pipeline
// ---------------------------------------------------------------------------

/// Describes the resource being admitted. Passed through the pipeline to avoid
/// exceeding clippy's too_many_arguments limit.
pub struct AdmissionContext<'a> {
    pub group: &'a str,
    pub version: &'a str,
    pub resource: &'a str,
    pub name: &'a str,
    pub namespace: Option<&'a str>,
    pub operation: &'a str,
}

// ---------------------------------------------------------------------------
// Store helpers: fetch webhook configurations
// ---------------------------------------------------------------------------

async fn fetch_mutating_configs(state: &AppState) -> Vec<serde_json::Value> {
    let prefix = "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/";
    match state.store.list(prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("admission: failed to list MutatingWebhookConfigurations: {e}");
            vec![]
        }
    }
}

async fn fetch_validating_configs(state: &AppState) -> Vec<serde_json::Value> {
    let prefix = "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/";
    match state.store.list(prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("admission: failed to list ValidatingWebhookConfigurations: {e}");
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// Webhook invocation
// ---------------------------------------------------------------------------

fn build_review(
    uid: &str,
    ctx: &AdmissionContext<'_>,
    object: &serde_json::Value,
) -> AdmissionReview {
    AdmissionReview {
        api_version: "admission.k8s.io/v1".to_string(),
        kind: "AdmissionReview".to_string(),
        request: Some(AdmissionRequest {
            uid: uid.to_string(),
            kind: GroupVersionKind {
                group: ctx.group.to_string(),
                version: ctx.version.to_string(),
                kind: String::new(), // kind is not strictly required by webhooks
            },
            resource: GroupVersionResource {
                group: ctx.group.to_string(),
                version: ctx.version.to_string(),
                resource: ctx.resource.to_string(),
            },
            name: ctx.name.to_string(),
            namespace: ctx.namespace.map(|s| s.to_string()),
            operation: ctx.operation.to_string(),
            object: object.clone(),
        }),
        response: None,
    }
}

/// POST the AdmissionReview to the webhook URL and return the response.
/// Returns `None` on network/parse error (caller applies failurePolicy).
async fn call_webhook(
    client: &reqwest::Client,
    url: &str,
    review: &AdmissionReview,
) -> Option<AdmissionResponse> {
    let body = serde_json::to_vec(review).ok()?;
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .ok()?;

    let bytes = resp.bytes().await.ok()?;
    let review_resp: AdmissionReview = serde_json::from_slice(&bytes).ok()?;
    review_resp.response
}

/// Apply a JSON Patch (base64-encoded) from a mutating webhook to the object.
fn apply_webhook_patch(object: &mut serde_json::Value, patch_b64: &str) -> Result<(), StatusError> {
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, patch_b64)
        .map_err(|e| Status::bad_request(format!("webhook patch base64 decode error: {e}")))?;

    let patch: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|e| Status::bad_request(format!("webhook patch JSON parse error: {e}")))?;

    crate::handlers::json_patch::apply_json_patch(object, &patch)
}

/// Run one webhook entry against the object. Returns the (possibly mutated) object
/// and whether any patch was applied.
///
/// `is_reinvocation` controls whether we skip webhooks that don't have
/// `reinvocationPolicy: IfNeeded` during the reinvocation pass.
async fn invoke_mutating_webhook(
    state: &AppState,
    webhook: &WebhookEntry,
    object: &serde_json::Value,
    ctx: &AdmissionContext<'_>,
    is_reinvocation: bool,
) -> Result<(serde_json::Value, bool), StatusError> {
    // During reinvocation, skip webhooks that don't opt in.
    if is_reinvocation && webhook.reinvocation_policy != "IfNeeded" {
        return Ok((object.clone(), false));
    }

    // Check if this webhook matches any rule.
    if !webhook.rules.is_empty() {
        let has_match = webhook.rules.iter().any(|rule| {
            let rule_val = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
            matches_rule(
                &rule_val,
                ctx.group,
                ctx.version,
                ctx.resource,
                ctx.namespace,
                ctx.operation,
            )
        });
        if !has_match {
            return Ok((object.clone(), false));
        }
    }

    // namespaceSelector: skip this webhook if the request namespace's labels don't match.
    // Cluster-scoped requests (namespace == None) always pass the namespace selector.
    if webhook.namespace_selector.is_some() {
        if let Some(ns) = ctx.namespace {
            let ns_labels = fetch_namespace_labels(state, ns).await;
            if !label_selector_matches(webhook.namespace_selector.as_ref(), &ns_labels) {
                tracing::debug!(
                    "admission: mutating webhook \"{}\" skipped: namespace \"{}\" does not match namespaceSelector",
                    webhook.name, ns
                );
                return Ok((object.clone(), false));
            }
        }
    }

    let url = match webhook_url(state, &webhook.client_config, &webhook.name).await {
        Ok(u) => u,
        Err(e) => {
            if webhook.failure_policy == "Ignore" {
                tracing::warn!(
                    "admission: mutating webhook \"{}\" skipped (service not found, failurePolicy=Ignore): {e}",
                    webhook.name
                );
                return Ok((object.clone(), false));
            } else {
                return Err(Status::internal(format!(
                    "admission webhook \"{}\": {e}",
                    webhook.name
                )));
            }
        }
    };

    let uid = uuid::Uuid::new_v4().to_string();
    let review = build_review(&uid, ctx, object);

    let response = call_webhook(&state.webhook_client, &url, &review).await;

    match response {
        Some(resp) => {
            if !resp.allowed {
                let message = resp
                    .status
                    .as_ref()
                    .and_then(|s| s.message.as_deref())
                    .unwrap_or("admission webhook denied the request")
                    .to_string();
                return Err(Status::forbidden(format!(
                    "admission webhook \"{}\" denied the request: {message}",
                    webhook.name
                )));
            }
            // Apply patch if present.
            if let Some(patch_b64) = resp.patch.as_deref() {
                if !patch_b64.is_empty() {
                    let mut mutated = object.clone();
                    apply_webhook_patch(&mut mutated, patch_b64)?;
                    return Ok((mutated, true));
                }
            }
            Ok((object.clone(), false))
        }
        None => {
            // Webhook call failed (network/timeout/parse error).
            if webhook.failure_policy == "Ignore" {
                tracing::warn!(
                    "admission: mutating webhook \"{}\" failed, ignoring (failurePolicy=Ignore)",
                    webhook.name
                );
                Ok((object.clone(), false))
            } else {
                Err(Status::internal(format!(
                    "admission webhook \"{}\" failed to respond (failurePolicy=Fail)",
                    webhook.name
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run the mutating admission webhook chain.
///
/// Fetches all MutatingWebhookConfiguration objects from the store, filters by
/// rules, POSTs AdmissionReview to each matching webhook URL, applies patches.
/// Handles failurePolicy (Fail/Ignore) and reinvocationPolicy (IfNeeded).
///
/// Returns the (possibly mutated) object, or a StatusError if any Fail-policy
/// webhook denied or was unreachable.
pub async fn run_mutating_webhooks(
    state: &AppState,
    mut object: serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> Result<serde_json::Value, StatusError> {
    let configs = fetch_mutating_configs(state).await;
    if configs.is_empty() {
        return Ok(object);
    }

    // Collect all webhook entries from all configurations.
    let mut all_webhooks: Vec<WebhookEntry> = Vec::new();
    for config in &configs {
        if let Ok(wc) = serde_json::from_value::<WebhookConfig>(config.clone()) {
            all_webhooks.extend(wc.webhooks);
        }
    }

    if all_webhooks.is_empty() {
        return Ok(object);
    }

    // First pass: run all webhooks.
    let mut any_patched = false;
    for webhook in &all_webhooks {
        let (new_obj, patched) =
            invoke_mutating_webhook(state, webhook, &object, ctx, false).await?;
        if patched {
            any_patched = true;
        }
        object = new_obj;
    }

    // Reinvocation pass: if any patch was applied, re-run IfNeeded webhooks once.
    if any_patched {
        for webhook in &all_webhooks {
            let (new_obj, _) = invoke_mutating_webhook(state, webhook, &object, ctx, true).await?;
            object = new_obj;
        }
    }

    Ok(object)
}

/// Run the validating admission webhook chain.
///
/// Fetches all ValidatingWebhookConfiguration objects from the store, filters by
/// rules, POSTs AdmissionReview to each matching webhook URL.
/// Returns Ok(()) if all webhooks allow, or a StatusError if any deny or fail with Fail policy.
pub async fn run_validating_webhooks(
    state: &AppState,
    object: &serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> Result<(), StatusError> {
    let configs = fetch_validating_configs(state).await;
    if configs.is_empty() {
        return Ok(());
    }

    let mut all_webhooks: Vec<WebhookEntry> = Vec::new();
    for config in &configs {
        if let Ok(wc) = serde_json::from_value::<WebhookConfig>(config.clone()) {
            all_webhooks.extend(wc.webhooks);
        }
    }

    if all_webhooks.is_empty() {
        return Ok(());
    }

    for webhook in &all_webhooks {
        // Check rule match.
        if !webhook.rules.is_empty() {
            let has_match = webhook.rules.iter().any(|rule| {
                let rule_val = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
                matches_rule(
                    &rule_val,
                    ctx.group,
                    ctx.version,
                    ctx.resource,
                    ctx.namespace,
                    ctx.operation,
                )
            });
            if !has_match {
                continue;
            }
        }

        // namespaceSelector: skip if the request namespace's labels don't match.
        if webhook.namespace_selector.is_some() {
            if let Some(ns) = ctx.namespace {
                let ns_labels = fetch_namespace_labels(state, ns).await;
                if !label_selector_matches(webhook.namespace_selector.as_ref(), &ns_labels) {
                    tracing::debug!(
                        "admission: validating webhook \"{}\" skipped: namespace \"{}\" does not match namespaceSelector",
                        webhook.name, ns
                    );
                    continue;
                }
            }
        }

        let url = match webhook_url(state, &webhook.client_config, &webhook.name).await {
            Ok(u) => u,
            Err(e) => {
                if webhook.failure_policy == "Ignore" {
                    tracing::warn!(
                        "admission: validating webhook \"{}\" skipped (service not found, failurePolicy=Ignore): {e}",
                        webhook.name
                    );
                    continue;
                } else {
                    return Err(Status::internal(format!(
                        "admission webhook \"{}\": {e}",
                        webhook.name
                    )));
                }
            }
        };

        let uid = uuid::Uuid::new_v4().to_string();
        let review = build_review(&uid, ctx, object);

        let response = call_webhook(&state.webhook_client, &url, &review).await;

        match response {
            Some(resp) => {
                if !resp.allowed {
                    let message = resp
                        .status
                        .as_ref()
                        .and_then(|s| s.message.as_deref())
                        .unwrap_or("admission webhook denied the request")
                        .to_string();
                    return Err(Status::forbidden(format!(
                        "admission webhook \"{}\" denied the request: {message}",
                        webhook.name
                    )));
                }
            }
            None => {
                if webhook.failure_policy == "Ignore" {
                    tracing::warn!(
                        "admission: validating webhook \"{}\" failed, ignoring (failurePolicy=Ignore)",
                        webhook.name
                    );
                } else {
                    return Err(Status::internal(format!(
                        "admission webhook \"{}\" failed to respond (failurePolicy=Fail)",
                        webhook.name
                    )));
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::Router;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt as _;
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

    fn make_rule(group: &str, version: &str, resource: &str, operation: &str) -> serde_json::Value {
        json!({
            "apiGroups": [group],
            "apiVersions": [version],
            "resources": [resource],
            "operations": [operation]
        })
    }

    // -- matches_rule tests --

    /// Wildcard "*" in all fields matches any resource/operation.
    /// Without wildcard support, webhook configurations that use "*" (the most
    /// common pattern) would silently skip invocation.
    #[test]
    fn matches_rule_wildcard_matches_any_resource() {
        let rule = json!({
            "apiGroups": ["*"],
            "apiVersions": ["*"],
            "resources": ["*"],
            "operations": ["*"]
        });
        assert!(
            matches_rule(
                &rule,
                "apps",
                "v1",
                "deployments",
                Some("default"),
                "CREATE"
            ),
            "wildcard rule must match any resource"
        );
        assert!(
            matches_rule(&rule, "", "v1", "pods", None, "UPDATE"),
            "wildcard rule must match core group cluster-scoped"
        );
    }

    /// Specific resource match: only the named resource triggers the webhook.
    /// A webhook scoped to "deployments" must not fire on "pods".
    #[test]
    fn matches_rule_specific_resource_matches_only_that_resource() {
        let rule = make_rule("apps", "v1", "deployments", "CREATE");
        assert!(
            matches_rule(
                &rule,
                "apps",
                "v1",
                "deployments",
                Some("default"),
                "CREATE"
            ),
            "specific resource rule must match the named resource"
        );
        assert!(
            !matches_rule(&rule, "apps", "v1", "pods", Some("default"), "CREATE"),
            "specific resource rule must not match a different resource"
        );
    }

    /// Operation mismatch: webhook for CREATE must not fire on UPDATE.
    /// Admission chains can be operation-specific; firing on wrong op is incorrect.
    #[test]
    fn matches_rule_operation_mismatch_does_not_match() {
        let rule = make_rule("apps", "v1", "deployments", "CREATE");
        assert!(
            !matches_rule(
                &rule,
                "apps",
                "v1",
                "deployments",
                Some("default"),
                "UPDATE"
            ),
            "rule for CREATE must not match UPDATE operation"
        );
    }

    /// Group mismatch: a rule for "apps" must not fire for core group resources.
    #[test]
    fn matches_rule_group_mismatch_does_not_match() {
        let rule = make_rule("apps", "v1", "pods", "CREATE");
        assert!(
            !matches_rule(&rule, "", "v1", "pods", None, "CREATE"),
            "rule for group 'apps' must not match core group ''"
        );
    }

    /// Empty rules list must not match — a webhook with no rules is misconfigured
    /// and must be skipped rather than matching everything.
    #[test]
    fn matches_rule_empty_lists_do_not_match() {
        let rule = json!({
            "apiGroups": [],
            "apiVersions": [],
            "resources": [],
            "operations": []
        });
        assert!(
            !matches_rule(
                &rule,
                "apps",
                "v1",
                "deployments",
                Some("default"),
                "CREATE"
            ),
            "empty lists must not match anything"
        );
    }

    // -- run_mutating_webhooks: no webhooks configured → object passes through unchanged --

    /// If no MutatingWebhookConfigurations exist, the object must be returned unchanged.
    /// This is the common case during cluster bootstrap.
    #[tokio::test]
    async fn run_mutating_webhooks_no_configs_returns_object_unchanged() {
        let state = make_state();
        let obj = json!({"kind": "Pod", "metadata": {"name": "test"}});
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "pods",
            name: "test",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;
        assert!(result.is_ok(), "no webhooks must not fail");
        let returned = result.unwrap_or_else(|_| panic!("no webhooks must not fail"));
        assert_eq!(returned, obj, "object must be unchanged when no webhooks");
    }

    // -- run_validating_webhooks: no webhooks configured → returns Ok --

    /// If no ValidatingWebhookConfigurations exist, must return Ok immediately.
    #[tokio::test]
    async fn run_validating_webhooks_no_configs_returns_ok() {
        let state = make_state();
        let obj = json!({"kind": "Pod", "metadata": {"name": "test"}});
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "pods",
            name: "test",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_validating_webhooks(&state, &obj, &ctx).await;
        assert!(result.is_ok(), "no webhooks must return Ok");
    }

    // -- Mock webhook server helpers --

    /// Build an in-process mock webhook handler that always allows.
    fn allow_handler() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                let resp = json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": true
                    }
                });
                axum::Json(resp)
            }),
        )
    }

    /// Build an in-process mock webhook handler that always denies.
    fn deny_handler() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                let resp = json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": false,
                        "status": {
                            "code": 403,
                            "message": "test denial"
                        }
                    }
                });
                axum::Json(resp)
            }),
        )
    }

    /// Build an in-process mock webhook handler that applies a label patch.
    fn patch_handler() -> Router {
        Router::new().route(
            "/webhook",
            post(|| async {
                // JSON Patch: add label env=injected
                let patch = serde_json::json!([
                    {"op": "add", "path": "/metadata/labels", "value": {"env": "injected"}}
                ]);
                let patch_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_string(&patch).unwrap(),
                );
                let resp = json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "test-uid",
                        "allowed": true,
                        "patch": patch_b64,
                        "patchType": "JSONPatch"
                    }
                });
                axum::Json(resp)
            }),
        )
    }

    /// Invoke a mock axum router as an in-process HTTP server and return
    /// the AdmissionResponse. This allows testing the webhook protocol without
    /// network I/O.
    async fn mock_call_webhook(
        router: Router,
        review: &AdmissionReview,
    ) -> Option<AdmissionResponse> {
        use axum::body::Body;

        let body_bytes = serde_json::to_vec(review).unwrap();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body_bytes))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .ok()?;
        let review_resp: AdmissionReview = serde_json::from_slice(&bytes).ok()?;
        review_resp.response
    }

    // -- mock webhook protocol tests --

    /// An allow response from a mock webhook must parse as allowed=true.
    /// This validates the AdmissionReview round-trip and response deserialization.
    #[tokio::test]
    async fn mock_allow_webhook_returns_allowed() {
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "test-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let review = build_review(
            "uid-1",
            &ctx,
            &json!({"kind": "Deployment", "metadata": {"name": "test-deploy"}}),
        );
        let resp = mock_call_webhook(allow_handler(), &review).await;
        assert!(resp.is_some(), "allow webhook must return a response");
        assert!(
            resp.unwrap().allowed,
            "allow webhook response must be allowed=true"
        );
    }

    /// A deny response from a mock webhook must parse as allowed=false.
    #[tokio::test]
    async fn mock_deny_webhook_returns_denied() {
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "test-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let review = build_review(
            "uid-2",
            &ctx,
            &json!({"kind": "Deployment", "metadata": {"name": "test-deploy"}}),
        );
        let resp = mock_call_webhook(deny_handler(), &review).await;
        assert!(resp.is_some(), "deny webhook must return a response");
        let r = resp.unwrap();
        assert!(!r.allowed, "deny webhook response must be allowed=false");
        assert!(
            r.status.as_ref().and_then(|s| s.message.as_deref()) == Some("test denial"),
            "deny response must include status message"
        );
    }

    /// A patch response from a mock webhook must round-trip: the patch must be
    /// parseable and applicable to the object.
    #[tokio::test]
    async fn mock_patch_webhook_returns_applicable_patch() {
        let obj = json!({"kind": "Pod", "metadata": {"name": "test"}});
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "pods",
            name: "test",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let review = build_review("uid-3", &ctx, &obj);
        let resp = mock_call_webhook(patch_handler(), &review).await;
        assert!(resp.is_some(), "patch webhook must return a response");
        let r = resp.unwrap();
        assert!(r.allowed, "patch webhook must allow the request");
        assert!(r.patch.is_some(), "patch webhook must include a patch");

        // Apply the patch to the object and verify the label was injected.
        let mut mutated = obj.clone();
        apply_webhook_patch(&mut mutated, r.patch.as_deref().unwrap())
            .unwrap_or_else(|_| panic!("webhook patch must apply successfully"));
        assert_eq!(
            mutated["metadata"]["labels"]["env"], "injected",
            "patch must inject the env label"
        );
    }

    // -- run_mutating_webhooks with a stored config + mock URL --
    // We can't do real HTTP without a listener, but we test with non-existent URL
    // and failurePolicy=Ignore to ensure the pipeline completes.

    /// A mutating webhook with failurePolicy=Ignore and an unreachable URL must
    /// not block the write — the object passes through unchanged.
    #[tokio::test]
    async fn run_mutating_webhooks_unreachable_with_ignore_policy_passes_through() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a MutatingWebhookConfiguration with failurePolicy=Ignore and an unreachable URL.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mwc"},
            "webhooks": [{
                "name": "test.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1" // port 1 is never open
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Ignore"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_ok(),
            "failurePolicy=Ignore must not fail when webhook is unreachable"
        );
        let returned = result.unwrap_or_else(|_| panic!("failurePolicy=Ignore must not fail"));
        assert_eq!(
            returned, obj,
            "object must be unchanged when webhook is unreachable with Ignore policy"
        );
    }

    /// A mutating webhook with failurePolicy=Fail and an unreachable URL must
    /// reject the write with an internal server error.
    #[tokio::test]
    async fn run_mutating_webhooks_unreachable_with_fail_policy_returns_error() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "test-mwc-fail"},
            "webhooks": [{
                "name": "fail.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/test-mwc-fail",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_err(),
            "failurePolicy=Fail must reject when webhook is unreachable"
        );
    }

    /// A validating webhook with failurePolicy=Ignore and unreachable URL must allow.
    #[tokio::test]
    async fn run_validating_webhooks_unreachable_with_ignore_policy_allows() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let vwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-vwc"},
            "webhooks": [{
                "name": "test.validating.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Ignore"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-vwc",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_validating_webhooks(&state, &obj, &ctx).await;

        assert!(
            result.is_ok(),
            "failurePolicy=Ignore must allow when webhook is unreachable"
        );
    }

    /// A validating webhook with failurePolicy=Fail and unreachable URL must deny.
    #[tokio::test]
    async fn run_validating_webhooks_unreachable_with_fail_policy_returns_error() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let vwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "test-vwc-fail"},
            "webhooks": [{
                "name": "fail.validating.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/test-vwc-fail",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_validating_webhooks(&state, &obj, &ctx).await;

        assert!(
            result.is_err(),
            "failurePolicy=Fail must reject when webhook is unreachable"
        );
    }

    /// A webhook with rules that don't match the resource must be skipped.
    /// This ensures namespace-scoped webhooks don't fire for unrelated resources.
    #[tokio::test]
    async fn run_mutating_webhooks_non_matching_rule_skips_webhook() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Webhook scoped to "secrets" but we write a "deployment" — must be skipped.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "secret-mwc"},
            "webhooks": [{
                "name": "secrets.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1" // would fail if called
                },
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["secrets"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/secret-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        // Writing a deployment — webhook scoped to secrets must be skipped.
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_ok(),
            "non-matching webhook must be skipped, not fail"
        );
        let returned = result.unwrap_or_else(|_| panic!("non-matching webhook must be skipped"));
        assert_eq!(
            returned, obj,
            "object must be unchanged when webhook is skipped due to rule mismatch"
        );
    }

    // -- label_selector_matches unit tests --

    /// None selector (absent namespaceSelector) must match all namespaces.
    /// This is the Kubernetes default: if namespaceSelector is not set, the webhook applies
    /// to all namespaces without restriction.
    #[test]
    fn label_selector_none_matches_any_labels() {
        let labels: BTreeMap<String, String> = [("env".into(), "prod".into())].into();
        assert!(
            label_selector_matches(None, &labels),
            "absent selector must match any namespace labels"
        );
        assert!(
            label_selector_matches(None, &BTreeMap::new()),
            "absent selector must match empty namespace labels"
        );
    }

    /// matchLabels: all key=value pairs must be present and equal in the namespace labels.
    /// A webhook scoped to env=prod must not fire in namespaces labelled env=dev.
    #[test]
    fn label_selector_match_labels_requires_exact_values() {
        let sel = LabelSelector {
            match_labels: [("env".into(), "prod".into())].into(),
            match_expressions: vec![],
        };
        let prod_labels: BTreeMap<String, String> =
            [("env".into(), "prod".into()), ("team".into(), "ops".into())].into();
        let dev_labels: BTreeMap<String, String> = [("env".into(), "dev".into())].into();
        let empty_labels: BTreeMap<String, String> = BTreeMap::new();

        assert!(
            label_selector_matches(Some(&sel), &prod_labels),
            "matchLabels env=prod must match namespace with env=prod"
        );
        assert!(
            !label_selector_matches(Some(&sel), &dev_labels),
            "matchLabels env=prod must not match namespace with env=dev"
        );
        assert!(
            !label_selector_matches(Some(&sel), &empty_labels),
            "matchLabels env=prod must not match namespace with no labels"
        );
    }

    /// matchExpressions with In: the label value must be one of the listed values.
    /// This is used to scope webhooks to a set of environments without listing every
    /// possible value explicitly.
    #[test]
    fn label_selector_match_expressions_in_operator() {
        let sel = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "env".into(),
                operator: "In".into(),
                values: vec!["prod".into(), "staging".into()],
            }],
        };
        let prod: BTreeMap<String, String> = [("env".into(), "prod".into())].into();
        let dev: BTreeMap<String, String> = [("env".into(), "dev".into())].into();

        assert!(
            label_selector_matches(Some(&sel), &prod),
            "In [prod, staging] must match env=prod"
        );
        assert!(
            !label_selector_matches(Some(&sel), &dev),
            "In [prod, staging] must not match env=dev"
        );
    }

    /// matchExpressions with NotIn: the label must not have the given values.
    /// A webhook configured to skip system namespaces uses NotIn: [kube-system, kube-public].
    #[test]
    fn label_selector_match_expressions_not_in_operator() {
        let sel = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "kubernetes.io/metadata.name".into(),
                operator: "NotIn".into(),
                values: vec!["kube-system".into(), "kube-public".into()],
            }],
        };
        let system: BTreeMap<String, String> =
            [("kubernetes.io/metadata.name".into(), "kube-system".into())].into();
        let user_ns: BTreeMap<String, String> =
            [("kubernetes.io/metadata.name".into(), "default".into())].into();

        assert!(
            !label_selector_matches(Some(&sel), &system),
            "NotIn [kube-system, kube-public] must not match kube-system"
        );
        assert!(
            label_selector_matches(Some(&sel), &user_ns),
            "NotIn [kube-system, kube-public] must match default"
        );
    }

    /// matchExpressions with Exists/DoesNotExist: presence of a key, regardless of value.
    #[test]
    fn label_selector_match_expressions_exists_and_does_not_exist() {
        let exists_sel = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "managed-by".into(),
                operator: "Exists".into(),
                values: vec![],
            }],
        };
        let dne_sel = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "managed-by".into(),
                operator: "DoesNotExist".into(),
                values: vec![],
            }],
        };
        let with_key: BTreeMap<String, String> = [("managed-by".into(), "flux".into())].into();
        let without_key: BTreeMap<String, String> = BTreeMap::new();

        assert!(
            label_selector_matches(Some(&exists_sel), &with_key),
            "Exists must match when the key is present"
        );
        assert!(
            !label_selector_matches(Some(&exists_sel), &without_key),
            "Exists must not match when the key is absent"
        );
        assert!(
            label_selector_matches(Some(&dne_sel), &without_key),
            "DoesNotExist must match when the key is absent"
        );
        assert!(
            !label_selector_matches(Some(&dne_sel), &with_key),
            "DoesNotExist must not match when the key is present"
        );
    }

    /// A webhook with namespaceSelector must be skipped for namespaces whose labels don't match.
    /// This test stores a real Namespace object in the in-memory store and seeds a
    /// MutatingWebhookConfiguration with a namespaceSelector. The webhook points to an
    /// unreachable URL with failurePolicy=Fail — if the namespace selector evaluation is broken
    /// and the webhook is invoked, the pipeline would fail instead of succeeding.
    #[tokio::test]
    async fn namespace_selector_non_matching_namespace_skips_webhook() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a Namespace with label env=dev.
        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "dev-ns",
                "labels": {"env": "dev"}
            }
        });
        store
            .put(
                "/registry/namespaces/dev-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Webhook with namespaceSelector that requires env=prod. Should be skipped for env=dev.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "prod-only-mwc"},
            "webhooks": [{
                "name": "prod.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"  // would fail if called
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail",
                "namespaceSelector": {
                    "matchLabels": {"env": "prod"}
                }
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/prod-only-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("dev-ns"), // namespace labelled env=dev, not env=prod
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_ok(),
            "webhook with non-matching namespaceSelector must be skipped, not invoked"
        );
        assert_eq!(
            result.unwrap_or_else(|_| panic!("must succeed")),
            obj,
            "object must be unchanged when webhook is skipped by namespaceSelector"
        );
    }

    /// A webhook with namespaceSelector must fire (fail) for namespaces whose labels match.
    /// This test verifies the positive case: if the namespace matches, the webhook IS invoked.
    /// Since the URL is unreachable and failurePolicy=Fail, the pipeline must return an error.
    #[tokio::test]
    async fn namespace_selector_matching_namespace_invokes_webhook() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a Namespace with label env=prod.
        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "prod-ns",
                "labels": {"env": "prod"}
            }
        });
        store
            .put(
                "/registry/namespaces/prod-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Webhook with namespaceSelector env=prod. Must be invoked for env=prod namespace.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "prod-only-mwc"},
            "webhooks": [{
                "name": "prod.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"  // unreachable — causes Fail
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail",
                "namespaceSelector": {
                    "matchLabels": {"env": "prod"}
                }
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/prod-only-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("prod-ns"), // namespace labelled env=prod — selector matches
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_err(),
            "webhook with matching namespaceSelector must be invoked (and fail because URL is unreachable)"
        );
    }

    // -- service-based clientConfig tests --

    /// A webhook configured with clientConfig.service must resolve the Service clusterIP
    /// and build the correct HTTPS URL. When the Service exists, the webhook is invoked at
    /// https://<clusterIP>:<port><path>. Since the resolved IP is not actually listening,
    /// failurePolicy=Ignore causes the pipeline to succeed.
    #[tokio::test]
    async fn service_based_client_config_resolves_cluster_ip() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a Service with a clusterIP in the webhook's namespace.
        let svc = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-webhook-svc", "namespace": "webhook-ns"},
            "spec": {"clusterIP": "10.96.0.1"}
        });
        store
            .put(
                "/registry/services/webhook-ns/my-webhook-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // MutatingWebhookConfiguration with service-based clientConfig.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "service-mwc"},
            "webhooks": [{
                "name": "service.webhook.example.com",
                "clientConfig": {
                    "service": {
                        "namespace": "webhook-ns",
                        "name": "my-webhook-svc",
                        "port": 8443,
                        "path": "/mutate"
                    }
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Ignore"  // URL resolves but nothing listens; Ignore skips gracefully
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/service-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        // The webhook is invoked (URL resolved to https://10.96.0.1:8443/mutate), fails to
        // connect, but failurePolicy=Ignore means the pipeline succeeds.
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;
        assert!(
            result.is_ok(),
            "service-based webhook with failurePolicy=Ignore and unreachable IP must succeed"
        );
    }

    // -- apply_webhook_patch error branches (mayor-l3rh) --

    /// apply_webhook_patch must return Err when the patch string is not valid base64.
    /// Webhooks that accidentally base64-encode garbage must be rejected immediately
    /// rather than silently applying no patch or panicking.
    #[test]
    fn apply_webhook_patch_rejects_invalid_base64() {
        let mut obj = serde_json::json!({"metadata": {"name": "test"}});
        // "!!!" is not valid standard base64 — the decoder must return an error.
        let result = apply_webhook_patch(&mut obj, "!!!");
        assert!(
            result.is_err(),
            "apply_webhook_patch must return Err for invalid base64 input"
        );
        // The error must have been produced before patching, so the object is unchanged.
        assert_eq!(
            obj["metadata"]["name"], "test",
            "object must be unchanged when base64 decode fails"
        );
    }

    /// apply_webhook_patch must return Err when the base64 decodes to non-JSON bytes.
    /// A webhook that returns binary data or a string that isn't a JSON patch array
    /// must be detected and rejected before any mutation occurs.
    #[test]
    fn apply_webhook_patch_rejects_non_json_content() {
        let mut obj = serde_json::json!({"metadata": {"name": "test"}});
        // base64 of "not-json-at-all"
        let not_json_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not-json-at-all",
        );
        let result = apply_webhook_patch(&mut obj, &not_json_b64);
        assert!(
            result.is_err(),
            "apply_webhook_patch must return Err when base64 decodes to non-JSON"
        );
        // The object must be unchanged — no partial mutation.
        assert_eq!(
            obj["metadata"]["name"], "test",
            "object must be unchanged when JSON parse fails"
        );
    }

    // -- reinvocation pass tests (mayor-6jk5) --

    /// Start an axum router on a random local TCP port and return the base URL and handle.
    async fn start_mock_webhook_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock webhook server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    /// Reinvocation pass: when webhook A patches the object in pass 1, the
    /// reinvocation pass runs. Webhook B (reinvocationPolicy: IfNeeded) must fire
    /// in pass 2. A webhook WITHOUT IfNeeded must NOT be called in pass 2.
    ///
    /// This matters because reinvocation is the mechanism allowing sidecar-injecting
    /// webhooks to see final object state after other webhooks have run. If the pass-2
    /// skip logic is broken, IfNeeded webhooks silently fail to re-run, allowing the
    /// sidecar injector to miss injecting into mutated pods.
    #[tokio::test]
    async fn reinvocation_pass_fires_if_needed_and_skips_non_if_needed() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;
        use tokio::net::TcpListener;

        // Counter: how many times webhook A is called.
        let webhook_a_count = StdArc::new(AtomicUsize::new(0));
        let webhook_a_count_clone = webhook_a_count.clone();

        // Counter: how many times webhook B is called.
        let webhook_b_count = StdArc::new(AtomicUsize::new(0));
        let webhook_b_count_clone = webhook_b_count.clone();

        // Webhook A: patches the object in pass 1 (no IfNeeded).
        // It applies a label patch to trigger any_patched=true.
        let router_a = Router::new().route(
            "/webhook",
            post(move || {
                let count = webhook_a_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let patch = serde_json::json!([
                        {"op": "add", "path": "/metadata/labels", "value": {"injected": "true"}}
                    ]);
                    let patch_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        serde_json::to_string(&patch).unwrap(),
                    );
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {
                            "uid": "uid-a",
                            "allowed": true,
                            "patch": patch_b64,
                            "patchType": "JSONPatch"
                        }
                    }))
                }
            }),
        );

        // Webhook B: just allows (reinvocationPolicy: IfNeeded, no patch).
        let router_b = Router::new().route(
            "/webhook",
            post(move || {
                let count = webhook_b_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {
                            "uid": "uid-b",
                            "allowed": true
                        }
                    }))
                }
            }),
        );

        let (url_a, _handle_a) = start_mock_webhook_server(router_a).await;
        let (url_b, _handle_b) = start_mock_webhook_server(router_b).await;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Single MutatingWebhookConfiguration with two webhooks:
        // - webhook-a: no reinvocationPolicy (defaults to Never)
        // - webhook-b: reinvocationPolicy: IfNeeded
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "reinvoke-test"},
            "webhooks": [
                {
                    "name": "webhook-a.example.com",
                    "clientConfig": { "url": format!("{url_a}/webhook") },
                    "rules": [{"apiGroups": ["apps"], "apiVersions": ["v1"], "resources": ["deployments"], "operations": ["CREATE"]}],
                    "failurePolicy": "Fail"
                    // reinvocationPolicy defaults to "" (Never)
                },
                {
                    "name": "webhook-b.example.com",
                    "clientConfig": { "url": format!("{url_b}/webhook") },
                    "rules": [{"apiGroups": ["apps"], "apiVersions": ["v1"], "resources": ["deployments"], "operations": ["CREATE"]}],
                    "failurePolicy": "Fail",
                    "reinvocationPolicy": "IfNeeded"
                }
            ]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/reinvoke-test",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };

        let result = run_mutating_webhooks(&state, obj, &ctx).await;
        assert!(result.is_ok(), "mutating webhook pipeline must succeed");

        // Pass 1: both A and B fire once.
        // Pass 2 (reinvocation): webhook A has no reinvocationPolicy → must NOT fire again.
        //                       webhook B has IfNeeded → MUST fire again.
        let a_count = webhook_a_count.load(Ordering::SeqCst);
        let b_count = webhook_b_count.load(Ordering::SeqCst);

        assert_eq!(
            a_count, 1,
            "webhook-a (no IfNeeded) must be called exactly once; \
             calling it in pass 2 would allow duplicate mutations"
        );
        assert_eq!(
            b_count, 2,
            "webhook-b (IfNeeded) must be called in both pass 1 and pass 2; \
             skipping pass 2 would prevent sidecar injectors from seeing final object state"
        );

        // The patch from webhook-a must be present in the returned object.
        let returned = result.unwrap_or_else(|_| panic!("pipeline must succeed"));
        assert_eq!(
            returned["metadata"]["labels"]["injected"], "true",
            "patch from webhook-a pass 1 must be applied to the returned object"
        );
    }

    /// When no webhook patches the object (any_patched=false), the reinvocation
    /// pass must NOT run. Webhooks must not be called more than once when there
    /// was nothing to reinvoke for.
    #[tokio::test]
    async fn reinvocation_pass_skipped_when_no_patch_applied() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let call_count = StdArc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        // A webhook with IfNeeded that only allows (no patch) — must not trigger reinvocation.
        let router = Router::new().route(
            "/webhook",
            post(move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {"uid": "uid-c", "allowed": true}
                    }))
                }
            }),
        );

        let (url, _handle) = start_mock_webhook_server(router).await;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "no-patch-mwc"},
            "webhooks": [{
                "name": "no-patch.webhook.example.com",
                "clientConfig": { "url": format!("{url}/webhook") },
                "rules": [{"apiGroups": ["apps"], "apiVersions": ["v1"], "resources": ["deployments"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail",
                "reinvocationPolicy": "IfNeeded"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/no-patch-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "no-patch-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "no-patch-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };

        let result = run_mutating_webhooks(&state, obj, &ctx).await;
        assert!(
            result.is_ok(),
            "pipeline must succeed when no patch applied"
        );

        let count = call_count.load(Ordering::SeqCst);
        assert_eq!(
            count, 1,
            "webhook with IfNeeded must only be called once when no patch was applied in pass 1; \
             triggering pass 2 without any_patched=true wastes latency and causes duplicate calls"
        );
    }

    /// A webhook with clientConfig.service pointing to a non-existent Service must
    /// apply failurePolicy: Fail returns an error, Ignore skips gracefully.
    #[tokio::test]
    async fn service_based_client_config_missing_service_applies_failure_policy() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // No Service stored — webhook_url will return an error.
        let mwc_fail = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "missing-svc-fail"},
            "webhooks": [{
                "name": "missing.webhook.example.com",
                "clientConfig": {
                    "service": {
                        "namespace": "webhook-ns",
                        "name": "does-not-exist",
                        "port": 443,
                        "path": "/mutate"
                    }
                },
                "rules": [{
                    "apiGroups": ["apps"],
                    "apiVersions": ["v1"],
                    "resources": ["deployments"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/missing-svc-fail",
                bytes::Bytes::from(serde_json::to_vec(&mwc_fail).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({"kind": "Deployment", "metadata": {"name": "my-deploy"}});
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;
        assert!(
            result.is_err(),
            "service not found with failurePolicy=Fail must return an error"
        );
    }
}
