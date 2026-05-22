/// Admission webhook invocation pipeline.
///
/// Implements the MutatingWebhookConfiguration and ValidatingWebhookConfiguration
/// chains per the Kubernetes admission spec:
/// - Fetch all configurations from the store
/// - For each matching webhook POST an AdmissionReview
/// - Apply JSON patches from mutating webhooks
/// - Reject on failurePolicy: Fail if webhook is unreachable or returns denied
/// - Re-run mutating webhooks marked reinvocationPolicy: IfNeeded if any patch was applied
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
    // namespace_selector is captured for forward-compat but not yet evaluated
    #[allow(dead_code)]
    #[serde(default)]
    namespace_selector: serde_json::Value,
}

fn default_failure_policy() -> String {
    "Fail".to_string()
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct WebhookClientConfig {
    #[serde(default)]
    url: Option<String>,
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

    let _ = namespace; // namespaceSelector is not implemented in this initial pass

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
    client: &reqwest::Client,
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

    let url = match &webhook.client_config.url {
        Some(u) => u.clone(),
        None => {
            // service-based client config not yet implemented; skip
            tracing::debug!("admission: webhook {} has no URL, skipping", webhook.name);
            return Ok((object.clone(), false));
        }
    };

    let uid = uuid::Uuid::new_v4().to_string();
    let review = build_review(&uid, ctx, object);

    let response = call_webhook(client, &url, &review).await;

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

    let client = &state.webhook_client;

    // First pass: run all webhooks.
    let mut any_patched = false;
    for webhook in &all_webhooks {
        let (new_obj, patched) =
            invoke_mutating_webhook(client, webhook, &object, ctx, false).await?;
        if patched {
            any_patched = true;
        }
        object = new_obj;
    }

    // Reinvocation pass: if any patch was applied, re-run IfNeeded webhooks once.
    if any_patched {
        for webhook in &all_webhooks {
            let (new_obj, _) = invoke_mutating_webhook(client, webhook, &object, ctx, true).await?;
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

    let client = &state.webhook_client;

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

        let url = match &webhook.client_config.url {
            Some(u) => u.clone(),
            None => {
                tracing::debug!("admission: webhook {} has no URL, skipping", webhook.name);
                continue;
            }
        };

        let uid = uuid::Uuid::new_v4().to_string();
        let review = build_review(&uid, ctx, object);

        let response = call_webhook(client, &url, &review).await;

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
}
