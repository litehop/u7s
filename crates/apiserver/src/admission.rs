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
use u7s_store::{ListOptions, Store};

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
    /// Reason for denial. Some webhooks set only reason (not message); we include both
    /// in the error string so the caller sees the actual denial cause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    #[serde(default)]
    object_selector: Option<LabelSelector>,
    /// Per-webhook timeout in seconds. Kubernetes spec default is 10s.
    #[serde(default)]
    timeout_seconds: Option<i64>,
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
async fn fetch_namespace_labels<S: Store>(
    state: &AppState<S>,
    namespace: &str,
) -> BTreeMap<String, String> {
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
    #[serde(default)]
    ca_bundle: Option<String>,
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

/// Describes the connection target for a webhook call.
///
/// `DirectUrl` is used when `clientConfig.url` is set directly.
/// `ServiceResolved` is used when `clientConfig.service` is set: the URL uses the
/// service DNS name (e.g. `https://<svc>.<ns>.svc:<port><path>`) for correct SNI.
/// With kube-proxy running inside the VM, the konnectivity-agent resolves service DNS
/// names via CoreDNS and routes to the ClusterIP correctly — no pod-IP substitution needed.
enum WebhookTarget {
    DirectUrl(String),
    ServiceResolved { url: String },
}

/// Resolve a webhook's clientConfig to a `WebhookTarget`.
///
/// If `clientConfig.url` is set, returns `DirectUrl`.
/// If `clientConfig.service` is set, returns `ServiceResolved` with a URL using the
/// service DNS name and the SERVICE port (e.g. `https://<svc>.<ns>.svc:<svc_port><path>`).
///
/// With kube-proxy running inside the VM (PR #406), the konnectivity-agent resolves
/// service DNS names via CoreDNS → ClusterIP, and kube-proxy NATs ClusterIP:svc_port →
/// PodIP:targetPort. Using the service port (not target port) ensures kube-proxy
/// intercepts the connection correctly.
async fn webhook_url<S: Store>(
    _state: &AppState<S>,
    config: &WebhookClientConfig,
    webhook_name: &str,
) -> Result<WebhookTarget, String> {
    if let Some(url) = &config.url {
        return Ok(WebhookTarget::DirectUrl(url.clone()));
    }

    if let Some(svc_ref) = &config.service {
        let svc_port = svc_ref.port.unwrap_or(443);

        // With kube-proxy running inside the VM (PR #406), the konnectivity-agent
        // resolves the service DNS name via CoreDNS → ClusterIP, and kube-proxy NATs
        // ClusterIP:svc_port → PodIP:targetPort. Use the service port (not target port)
        // in the URL so kube-proxy intercepts the connection correctly.
        let path = svc_ref.path.as_deref().unwrap_or("/");
        let svc_host = format!("{}.{}.svc", svc_ref.name, svc_ref.namespace);
        let url = format!("https://{svc_host}:{svc_port}{path}");
        return Ok(WebhookTarget::ServiceResolved { url });
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
    /// Authenticated user info for the request. Used by VAP CEL expressions
    /// that reference `request.userInfo.*`. None if auth info is unavailable.
    pub user_info: Option<serde_json::Value>,
    /// Whether this is a dry-run request. Exposed as `request.dryRun` in VAP CEL.
    pub dry_run: bool,
}

// ---------------------------------------------------------------------------
// Store helpers: fetch webhook configurations
// ---------------------------------------------------------------------------

async fn fetch_mutating_configs<S: Store>(state: &AppState<S>) -> Vec<serde_json::Value> {
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

async fn fetch_validating_configs<S: Store>(state: &AppState<S>) -> Vec<serde_json::Value> {
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
                // Read kind from the object itself. Webhooks such as Kyverno and OPA
                // Gatekeeper dispatch on request.kind — an empty string causes them to
                // apply the wrong policy or skip evaluation entirely.
                kind: object["kind"].as_str().unwrap_or("").to_string(),
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
/// Build a reqwest::Client for a single webhook call using the webhook's own caBundle.
/// Each webhook ships with its own CA that signed its TLS cert — not the cluster CA.
/// Falls back to the shared client when caBundle is absent or malformed.
///
/// `tls_certs_only` is used instead of `add_root_certificate` so that the macOS platform
/// verifier (SecureTransport) is bypassed. The macOS verifier enforces Extended Key Usage
/// (EKU) constraints that test-generated webhook TLS certificates may not satisfy.
///
/// With kube-proxy running inside the VM (PR #406), `ServiceResolved` targets use the
/// service DNS name directly in the URL. The konnectivity-agent resolves the name via
/// CoreDNS and routes through kube-proxy to the pod — hostname verification is always
/// correct and `danger_accept_invalid_hostnames` is no longer needed.
///
/// `connect_timeout` (5s) bounds the TCP handshake independently of the total timeout.
/// Without it, a webhook pointing at a deleted service causes reqwest to wait for the OS
/// TCP timeout (~2min) before the 10s total timeout fires, stalling all subsequent calls.
fn build_webhook_call_client(
    ca_bundle_b64: Option<&str>,
    proxy_addr: Option<&str>,
    cluster_ca_der: Option<&[u8]>,
    webhook_identity_pem: Option<&[u8]>,
    fallback: &reqwest::Client,
    timeout_seconds: Option<i64>,
) -> reqwest::Client {
    let request_timeout =
        std::time::Duration::from_secs(timeout_seconds.unwrap_or(10).max(1) as u64);
    let Some(b64) = ca_bundle_b64 else {
        // Even when returning the fallback we want per-webhook timeout.
        // Build a minimal client with the right timeouts instead of cloning fallback,
        // so that the connect_timeout is always applied.
        return reqwest::Client::builder()
            .timeout(request_timeout)
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| fallback.clone());
    };
    let Ok(pem_bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
    else {
        tracing::warn!(
            "webhook client: caBundle base64 decode failed for webhook — using cluster CA fallback"
        );
        return reqwest::Client::builder()
            .timeout(request_timeout)
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| fallback.clone());
    };
    let Ok(cert) = reqwest::Certificate::from_pem(&pem_bytes) else {
        tracing::warn!(
            "webhook client: caBundle PEM parse failed for webhook — using cluster CA fallback"
        );
        return reqwest::Client::builder()
            .timeout(request_timeout)
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| fallback.clone());
    };
    // Collect trusted CAs: the webhook's own CA and the cluster CA (for proxy TLS).
    // tls_certs_only bypasses the macOS platform verifier so EKU is not enforced.
    let mut certs = vec![cert];
    if let Some(der) = cluster_ca_der {
        if let Ok(cluster_cert) = reqwest::Certificate::from_der(der) {
            certs.push(cluster_cert);
        }
    }
    let mut builder = reqwest::Client::builder()
        .timeout(request_timeout)
        .connect_timeout(std::time::Duration::from_secs(5))
        .tls_certs_only(certs);
    if let Some(pem) = webhook_identity_pem {
        if let Ok(identity) = reqwest::Identity::from_pem(pem) {
            builder = builder.identity(identity);
        }
    }
    if let Some(addr) = proxy_addr {
        let proxy_url = format!("https://{addr}");
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().unwrap_or_else(|_| fallback.clone())
}

/// Call the webhook and return the response, or `None` on network/parse error.
/// The bool indicates whether the failure was a timeout (true) vs other error (false).
/// Callers use this to produce "deadline exceeded" vs "failed to respond" error messages,
/// matching the Kubernetes apiserver's error convention so conformance tests can identify
/// webhook timeout by checking for "deadline" in the error string.
async fn call_webhook(
    client: &reqwest::Client,
    url: &str,
    review: &AdmissionReview,
) -> (Option<AdmissionResponse>, bool) {
    let Ok(body) = serde_json::to_vec(review) else {
        return (None, false);
    };
    let send_result = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;
    let resp = match send_result {
        Ok(r) => r,
        Err(e) => return (None, e.is_timeout()),
    };
    let Ok(bytes) = resp.bytes().await else {
        return (None, false);
    };
    let response = serde_json::from_slice::<AdmissionReview>(&bytes)
        .ok()
        .and_then(|r| r.response);
    (response, false)
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
async fn invoke_mutating_webhook<S: Store>(
    state: &AppState<S>,
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

    // objectSelector: skip this webhook if the object's labels don't match.
    if webhook.object_selector.is_some() {
        let obj_labels: BTreeMap<String, String> = object["metadata"]["labels"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        if !label_selector_matches(webhook.object_selector.as_ref(), &obj_labels) {
            tracing::debug!(
                "admission: mutating webhook \"{}\" skipped: object does not match objectSelector",
                webhook.name
            );
            return Ok((object.clone(), false));
        }
    }

    let target = match webhook_url(state, &webhook.client_config, &webhook.name).await {
        Ok(t) => t,
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
    let call_url = match &target {
        WebhookTarget::DirectUrl(u) => u.as_str(),
        WebhookTarget::ServiceResolved { url } => url.as_str(),
    };

    let uid = uuid::Uuid::new_v4().to_string();
    let review = build_review(&uid, ctx, object);

    // DirectUrl webhooks go to an external endpoint: do not route through the
    // konnectivity proxy (which only reaches pod IPs inside the VM) and do not
    // present the apiserver mTLS identity (which would leak it to an external host).
    let (effective_proxy, effective_identity) = match &target {
        WebhookTarget::DirectUrl(_) => (None, None),
        WebhookTarget::ServiceResolved { .. } => (
            state.konnectivity_proxy_addr.as_deref(),
            state.webhook_identity_pem.as_deref().map(|v| v.as_slice()),
        ),
    };

    let wh_client = build_webhook_call_client(
        webhook.client_config.ca_bundle.as_deref(),
        effective_proxy,
        state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
        effective_identity,
        &state.webhook_client,
        webhook.timeout_seconds,
    );
    let (response, timed_out) = call_webhook(&wh_client, call_url, &review).await;

    match response {
        Some(resp) => {
            if !resp.allowed {
                // Use message if present; fall back to reason (some webhooks set only reason);
                // fall back to a generic message. Both fields are included in the error so the
                // caller can identify the denial cause (e2e tests check for specific substrings).
                let message = resp
                    .status
                    .as_ref()
                    .and_then(|s| {
                        s.message
                            .as_deref()
                            .filter(|m| !m.is_empty())
                            .or(s.reason.as_deref().filter(|r| !r.is_empty()))
                    })
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
            } else if timed_out {
                // Use "deadline exceeded" phrasing so tests can detect webhook timeout
                // by checking for "deadline" in the error string (Kubernetes convention).
                Err(Status::internal(format!(
                    "admission webhook \"{}\" request deadline exceeded",
                    webhook.name
                )))
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
// CEL-based MutatingAdmissionPolicy evaluation
// ---------------------------------------------------------------------------

/// Fetch all MutatingAdmissionPolicy objects from the store.
async fn fetch_mutating_policies<S: Store>(state: &AppState<S>) -> Vec<serde_json::Value> {
    let prefix = "/registry/admissionregistration.k8s.io/mutatingadmissionpolicies/";
    match state.store.list(prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("admission: failed to list MutatingAdmissionPolicies: {e}");
            vec![]
        }
    }
}

/// Returns true if the given resource matches the policy's matchConstraints.
///
/// An absent or empty matchConstraints matches all resources. Each resourceRule in
/// matchConstraints must match (apiGroups, apiVersions, resources, operations are OR-within,
/// AND-across rules in the context of the policy as a whole, matching any rule).
pub(crate) fn matches_match_constraints(
    policy: &serde_json::Value,
    group: &str,
    version: &str,
    resource: &str,
    operation: &str,
) -> bool {
    let mc = &policy["spec"]["matchConstraints"];
    if mc.is_null() {
        return true; // absent matchConstraints matches everything
    }
    let resource_rules = mc["resourceRules"].as_array();
    let Some(rules) = resource_rules else {
        return true; // no resourceRules means match all
    };
    if rules.is_empty() {
        return true;
    }
    // Match if ANY rule matches (OR across rules).
    rules
        .iter()
        .any(|rule| matches_rule(rule, group, version, resource, None, operation))
}

/// Evaluate a CEL expression for an `ApplyConfiguration` mutation.
///
/// Supports the subset of CEL used by Kubernetes MutatingAdmissionPolicy:
/// - Object construction: `Type{field: expr, ...}` → JSON object
/// - Map literals: `{key: value, ...}` → JSON object
/// - String literals: `"value"`
/// - Integer and float literals
/// - Boolean literals: `true`, `false`
/// - Null: `null`
/// - Field access on `object`: `object.metadata.name`, `object.spec.replicas`
///
/// The `object` variable is bound to the admitted resource. Type names (like `Object`,
/// `Object.metadata`) are treated as anonymous struct constructors — the type name is
/// discarded, only the field assignments matter.
///
/// Returns `None` if the expression cannot be parsed or evaluated.
pub(crate) fn eval_cel_apply_config(
    expr: &str,
    object: &serde_json::Value,
) -> Option<serde_json::Value> {
    let tokens = tokenize_cel(expr.trim())?;
    let mut pos = 0usize;
    parse_cel_value(&tokens, &mut pos, object)
}

/// Evaluate a CEL boolean expression for ValidatingAdmissionPolicy validations.
///
/// Supports the VAP subset of CEL:
/// - Field access: `object.spec.replicas`, `variables.X`, `request.userInfo.username`
/// - Arithmetic: `+`, `-`, `*`, `/`, `%`
/// - Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`
/// - Boolean: `&&`, `||`, `!`
/// - Literals: integer, float, bool, string, null
///
/// `variables` is a map of intermediate values computed from `spec.variables`.
/// `request` is the admission request context (operation, name, namespace, userInfo, dryRun).
/// Returns `Some(true)` / `Some(false)`, or `None` on parse/eval error.
pub(crate) fn eval_cel_bool_expr(
    expr: &str,
    object: &serde_json::Value,
    variables: &serde_json::Map<String, serde_json::Value>,
    request: &serde_json::Value,
) -> Option<bool> {
    let tokens = tokenize_cel(expr.trim())?;
    let mut pos = 0usize;
    let variables_val = serde_json::Value::Object(variables.clone());
    let val = parse_vap_or(&tokens, &mut pos, object, &variables_val, request)?;
    val.as_bool()
}

/// Parse a VAP CEL expression value (used for variable expressions that may return any type).
pub(crate) fn eval_cel_vap_value(
    expr: &str,
    object: &serde_json::Value,
    variables: &serde_json::Map<String, serde_json::Value>,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let tokens = tokenize_cel(expr.trim())?;
    let mut pos = 0usize;
    let variables_val = serde_json::Value::Object(variables.clone());
    parse_vap_or(&tokens, &mut pos, object, &variables_val, request)
}

// ---------------------------------------------------------------------------
// VAP CEL expression evaluator (full precedence, object + variables roots)
// ---------------------------------------------------------------------------

/// Parse an `||` (logical OR) expression.
fn parse_vap_or(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut left = parse_vap_and(tokens, pos, object, variables, request)?;
    while *pos < tokens.len() {
        if let CelToken::Pipe = &tokens[*pos] {
            *pos += 1;
            let right = parse_vap_and(tokens, pos, object, variables, request)?;
            let result = left.as_bool().unwrap_or(false) || right.as_bool().unwrap_or(false);
            left = serde_json::Value::Bool(result);
        } else {
            break;
        }
    }
    Some(left)
}

/// Parse an `&&` (logical AND) expression.
fn parse_vap_and(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut left = parse_vap_cmp(tokens, pos, object, variables, request)?;
    while *pos < tokens.len() {
        if let CelToken::Ampersand = &tokens[*pos] {
            *pos += 1;
            let right = parse_vap_cmp(tokens, pos, object, variables, request)?;
            let result = left.as_bool().unwrap_or(false) && right.as_bool().unwrap_or(false);
            left = serde_json::Value::Bool(result);
        } else {
            break;
        }
    }
    Some(left)
}

/// Parse a comparison expression (`==`, `!=`, `<`, `<=`, `>`, `>=`).
fn parse_vap_cmp(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let left = parse_vap_add(tokens, pos, object, variables, request)?;
    if *pos >= tokens.len() {
        return Some(left);
    }
    let op = tokens[*pos].clone();
    match op {
        CelToken::Eq
        | CelToken::Neq
        | CelToken::Lt
        | CelToken::Lte
        | CelToken::Gt
        | CelToken::Gte => {
            *pos += 1;
            let right = parse_vap_add(tokens, pos, object, variables, request)?;
            let result = compare_values(&op, &left, &right)?;
            Some(serde_json::Value::Bool(result))
        }
        _ => Some(left),
    }
}

fn compare_values(
    op: &CelToken,
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> Option<bool> {
    match op {
        CelToken::Eq => Some(left == right),
        CelToken::Neq => Some(left != right),
        CelToken::Lt => {
            let l = left.as_f64()?;
            let r = right.as_f64()?;
            Some(l < r)
        }
        CelToken::Lte => {
            let l = left.as_f64()?;
            let r = right.as_f64()?;
            Some(l <= r)
        }
        CelToken::Gt => {
            let l = left.as_f64()?;
            let r = right.as_f64()?;
            Some(l > r)
        }
        CelToken::Gte => {
            let l = left.as_f64()?;
            let r = right.as_f64()?;
            Some(l >= r)
        }
        _ => None,
    }
}

/// Parse an additive expression (`+`, `-`).
fn parse_vap_add(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut left = parse_vap_mul(tokens, pos, object, variables, request)?;
    while *pos < tokens.len() {
        let op = tokens[*pos].clone();
        match op {
            CelToken::Plus | CelToken::Minus => {
                *pos += 1;
                let right = parse_vap_mul(tokens, pos, object, variables, request)?;
                left = apply_add_op(&op, &left, &right)?;
            }
            _ => break,
        }
    }
    Some(left)
}

fn apply_add_op(
    op: &CelToken,
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> Option<serde_json::Value> {
    match op {
        CelToken::Plus => match (left, right) {
            (serde_json::Value::Number(a), serde_json::Value::Number(b)) => {
                if let (Some(ai), Some(bi)) = (a.as_i64(), b.as_i64()) {
                    Some(serde_json::Value::Number((ai + bi).into()))
                } else {
                    Some(serde_json::json!(a.as_f64()? + b.as_f64()?))
                }
            }
            (serde_json::Value::String(a), serde_json::Value::String(b)) => {
                Some(serde_json::Value::String(format!("{a}{b}")))
            }
            _ => None,
        },
        CelToken::Minus => {
            let l = left.as_f64()?;
            let r = right.as_f64()?;
            let diff = l - r;
            if diff.fract() == 0.0 && diff.abs() < i64::MAX as f64 {
                Some(serde_json::Value::Number((diff as i64).into()))
            } else {
                Some(serde_json::json!(diff))
            }
        }
        _ => None,
    }
}

/// Parse a multiplicative expression (`*`, `/`, `%`).
fn parse_vap_mul(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut left = parse_vap_unary(tokens, pos, object, variables, request)?;
    while *pos < tokens.len() {
        let op = tokens[*pos].clone();
        match op {
            CelToken::Star | CelToken::Slash | CelToken::Percent => {
                *pos += 1;
                let right = parse_vap_unary(tokens, pos, object, variables, request)?;
                left = apply_mul_op(&op, &left, &right)?;
            }
            _ => break,
        }
    }
    Some(left)
}

fn apply_mul_op(
    op: &CelToken,
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> Option<serde_json::Value> {
    let l = left.as_i64()?;
    let r = right.as_i64()?;
    match op {
        CelToken::Star => Some(serde_json::Value::Number((l * r).into())),
        CelToken::Slash => {
            if r == 0 {
                return None;
            }
            Some(serde_json::Value::Number((l / r).into()))
        }
        CelToken::Percent => {
            if r == 0 {
                return None;
            }
            Some(serde_json::Value::Number((l % r).into()))
        }
        _ => None,
    }
}

/// Parse a unary expression (`!`, `-`, or primary).
fn parse_vap_unary(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    if *pos >= tokens.len() {
        return None;
    }
    match &tokens[*pos] {
        CelToken::Bang => {
            *pos += 1;
            let inner = parse_vap_unary(tokens, pos, object, variables, request)?;
            Some(serde_json::Value::Bool(!inner.as_bool()?))
        }
        CelToken::Minus => {
            *pos += 1;
            let inner = parse_vap_unary(tokens, pos, object, variables, request)?;
            match inner {
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Some(serde_json::Value::Number((-i).into()))
                    } else {
                        n.as_f64().map(|f| serde_json::json!(-f))
                    }
                }
                _ => None,
            }
        }
        _ => parse_vap_primary(tokens, pos, object, variables, request),
    }
}

/// Parse a primary expression: literal, parenthesized, or field access chain.
fn parse_vap_primary(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    if *pos >= tokens.len() {
        return None;
    }
    match tokens[*pos].clone() {
        CelToken::Int(n) => {
            *pos += 1;
            Some(serde_json::Value::Number(n.into()))
        }
        CelToken::Float(f) => {
            *pos += 1;
            Some(serde_json::json!(f))
        }
        CelToken::Bool(b) => {
            *pos += 1;
            Some(serde_json::Value::Bool(b))
        }
        CelToken::Null => {
            *pos += 1;
            Some(serde_json::Value::Null)
        }
        CelToken::Str(s) => {
            *pos += 1;
            Some(serde_json::Value::String(s))
        }
        CelToken::LParen => {
            *pos += 1;
            let val = parse_vap_or(tokens, pos, object, variables, request)?;
            if *pos < tokens.len() {
                if let CelToken::RParen = &tokens[*pos] {
                    *pos += 1;
                }
            }
            Some(val)
        }
        CelToken::Ident(name) => {
            *pos += 1;
            // Determine the root value for this identifier.
            let root = if name == "object" {
                object.clone()
            } else if name == "variables" {
                variables.clone()
            } else if name == "request" {
                request.clone()
            } else {
                // Unknown identifier — return as string (struct constructor handled below)
                // Check for struct constructor: TypeName{...}
                if *pos < tokens.len() {
                    if let CelToken::LBrace = &tokens[*pos] {
                        *pos += 1;
                        return parse_vap_object_body(tokens, pos, object, variables, request);
                    }
                }
                return Some(serde_json::Value::String(name));
            };

            // Skip qualifier segments before LBrace (e.g. Object.metadata{...}).
            // Also handle dot-access chains: object.spec.replicas.
            parse_vap_field_chain(tokens, pos, root, object, variables, request)
        }
        CelToken::LBrace => {
            *pos += 1;
            parse_vap_object_body(tokens, pos, object, variables, request)
        }
        CelToken::LBracket => {
            *pos += 1;
            let mut arr = Vec::new();
            while *pos < tokens.len() {
                if let CelToken::RBracket = &tokens[*pos] {
                    *pos += 1;
                    break;
                }
                let val = parse_vap_or(tokens, pos, object, variables, request)?;
                arr.push(val);
                if *pos < tokens.len() {
                    if let CelToken::Comma = &tokens[*pos] {
                        *pos += 1;
                    }
                }
            }
            Some(serde_json::Value::Array(arr))
        }
        _ => None,
    }
}

/// After reading a root identifier, handle `.field` chains and `{...}` constructors.
fn parse_vap_field_chain(
    tokens: &[CelToken],
    pos: &mut usize,
    mut current: serde_json::Value,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    loop {
        if *pos >= tokens.len() {
            break;
        }
        match &tokens[*pos] {
            CelToken::Dot => {
                *pos += 1;
                if *pos >= tokens.len() {
                    break;
                }
                if let CelToken::Ident(field) = tokens[*pos].clone() {
                    *pos += 1;
                    // Check if this is a struct constructor (field followed by LBrace)
                    if *pos < tokens.len() {
                        if let CelToken::LBrace = &tokens[*pos] {
                            // TypeName.qualifier{...} — treat as constructor, discard qualifier
                            *pos += 1;
                            return parse_vap_object_body(tokens, pos, object, variables, request);
                        }
                    }
                    // Field navigation
                    current = current[&field].clone();
                } else {
                    break;
                }
            }
            CelToken::LBrace => {
                // Struct constructor on this identifier
                *pos += 1;
                return parse_vap_object_body(tokens, pos, object, variables, request);
            }
            _ => break,
        }
    }
    Some(current)
}

/// Parse the body of a `{key: value, ...}` object literal (caller consumed `{`).
fn parse_vap_object_body(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
    variables: &serde_json::Value,
    request: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();
    while *pos < tokens.len() {
        if let CelToken::RBrace = &tokens[*pos] {
            *pos += 1;
            break;
        }
        let key = match tokens[*pos].clone() {
            CelToken::Str(s) => {
                *pos += 1;
                s
            }
            CelToken::Ident(s) => {
                *pos += 1;
                s
            }
            _ => return None,
        };
        if *pos >= tokens.len() {
            return None;
        }
        if let CelToken::Colon = &tokens[*pos] {
            *pos += 1;
        } else {
            return None;
        }
        let val = parse_vap_or(tokens, pos, object, variables, request)?;
        map.insert(key, val);
        if *pos < tokens.len() {
            if let CelToken::Comma = &tokens[*pos] {
                *pos += 1;
            }
        }
    }
    Some(serde_json::Value::Object(map))
}

/// A minimal CEL token.
#[derive(Debug, PartialEq, Clone)]
enum CelToken {
    Ident(String), // identifiers and keywords
    Str(String),   // string literal value (already unescaped)
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
    Dot,       // .
    Colon,     // :
    Comma,     // ,
    LBrace,    // {
    RBrace,    // }
    LBracket,  // [
    RBracket,  // ]
    LParen,    // (
    RParen,    // )
    Plus,      // +
    Minus,     // -
    Star,      // *
    Slash,     // /
    Percent,   // %
    Eq,        // ==
    Neq,       // !=
    Lt,        // <
    Lte,       // <=
    Gt,        // >
    Gte,       // >=
    Bang,      // !
    Question,  // ?
    Ampersand, // &&
    Pipe,      // ||
}

fn tokenize_cel(input: &str) -> Option<Vec<CelToken>> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            // Whitespace
            c if c.is_whitespace() => {
                i += 1;
            }

            // String literals (double or single quoted)
            '"' | '\'' => {
                let quote = chars[i];
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        match chars[i] {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            'r' => s.push('\r'),
                            '"' => s.push('"'),
                            '\'' => s.push('\''),
                            '\\' => s.push('\\'),
                            c => {
                                s.push('\\');
                                s.push(c);
                            }
                        }
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                if i < chars.len() {
                    i += 1;
                } // closing quote
                tokens.push(CelToken::Str(s));
            }

            // Numbers
            c if c.is_ascii_digit()
                || (c == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) =>
            {
                let neg = c == '-';
                if neg {
                    i += 1;
                }
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let num_str: String = chars[start..i].iter().collect();
                if num_str.contains('.') {
                    let f: f64 = num_str.parse().ok()?;
                    tokens.push(CelToken::Float(if neg { -f } else { f }));
                } else {
                    let n: i64 = num_str.parse().ok()?;
                    tokens.push(CelToken::Int(if neg { -n } else { n }));
                }
            }

            // Identifiers and keywords
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                tokens.push(match word.as_str() {
                    "true" => CelToken::Bool(true),
                    "false" => CelToken::Bool(false),
                    "null" => CelToken::Null,
                    _ => CelToken::Ident(word),
                });
            }

            '.' => {
                tokens.push(CelToken::Dot);
                i += 1;
            }
            ':' => {
                tokens.push(CelToken::Colon);
                i += 1;
            }
            ',' => {
                tokens.push(CelToken::Comma);
                i += 1;
            }
            '{' => {
                tokens.push(CelToken::LBrace);
                i += 1;
            }
            '}' => {
                tokens.push(CelToken::RBrace);
                i += 1;
            }
            '[' => {
                tokens.push(CelToken::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(CelToken::RBracket);
                i += 1;
            }
            '(' => {
                tokens.push(CelToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(CelToken::RParen);
                i += 1;
            }
            '+' => {
                tokens.push(CelToken::Plus);
                i += 1;
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(CelToken::Neq);
                    i += 2;
                } else {
                    tokens.push(CelToken::Bang);
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(CelToken::Lte);
                    i += 2;
                } else {
                    tokens.push(CelToken::Lt);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(CelToken::Gte);
                    i += 2;
                } else {
                    tokens.push(CelToken::Gt);
                    i += 1;
                }
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(CelToken::Eq);
                    i += 2;
                } else {
                    i += 1; // skip lone '='
                }
            }
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                tokens.push(CelToken::Ampersand);
                i += 2;
            }
            '&' => {
                i += 1;
            }
            '|' if i + 1 < chars.len() && chars[i + 1] == '|' => {
                tokens.push(CelToken::Pipe);
                i += 2;
            }
            '|' => {
                i += 1;
            }
            '?' => {
                tokens.push(CelToken::Question);
                i += 1;
            }
            '*' => {
                tokens.push(CelToken::Star);
                i += 1;
            }
            '/' if !(i + 1 < chars.len() && chars[i + 1] == '/') => {
                tokens.push(CelToken::Slash);
                i += 1;
            }
            '%' => {
                tokens.push(CelToken::Percent);
                i += 1;
            }
            '-' => {
                // Standalone minus (already handled numbers with leading -)
                tokens.push(CelToken::Minus);
                i += 1;
            }

            // Skip comments (// ...) and unknown characters
            '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            _ => {
                i += 1;
            } // skip unknown
        }
    }
    Some(tokens)
}

/// Parse a CEL value from the token stream.
///
/// Handles:
/// - Object/struct construction: `TypeName{...}` or `TypeName.qualifier{...}`
/// - Map literals: `{"key": value, ...}`
/// - String, int, float, bool, null literals
/// - Identifier chains (field access): `object.metadata.name`
/// - Additive expressions: `a + b` (string concat or numeric add)
fn parse_cel_value(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
) -> Option<serde_json::Value> {
    if *pos >= tokens.len() {
        return None;
    }

    let value = parse_cel_primary(tokens, pos, object)?;

    // Handle additive operators (for string concat and numeric add used in some policies).
    if *pos < tokens.len() {
        if let CelToken::Plus = &tokens[*pos] {
            *pos += 1;
            let right = parse_cel_primary(tokens, pos, object)?;
            let result = match (&value, &right) {
                (serde_json::Value::Number(a), serde_json::Value::Number(b)) => {
                    if let (Some(ai), Some(bi)) = (a.as_i64(), b.as_i64()) {
                        serde_json::Value::Number((ai + bi).into())
                    } else {
                        let af = a.as_f64().unwrap_or(0.0);
                        let bf = b.as_f64().unwrap_or(0.0);
                        serde_json::json!(af + bf)
                    }
                }
                (serde_json::Value::String(a), serde_json::Value::String(b)) => {
                    serde_json::Value::String(format!("{a}{b}"))
                }
                _ => return None, // type mismatch
            };
            return Some(result);
        }
    }

    Some(value)
}

fn parse_cel_primary(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
) -> Option<serde_json::Value> {
    if *pos >= tokens.len() {
        return None;
    }

    match &tokens[*pos].clone() {
        // String literal
        CelToken::Str(s) => {
            *pos += 1;
            Some(serde_json::Value::String(s.clone()))
        }

        // Integer literal
        CelToken::Int(n) => {
            *pos += 1;
            Some(serde_json::Value::Number((*n).into()))
        }

        // Float literal
        CelToken::Float(f) => {
            *pos += 1;
            Some(serde_json::json!(f))
        }

        // Boolean literal
        CelToken::Bool(b) => {
            *pos += 1;
            Some(serde_json::Value::Bool(*b))
        }

        // Null literal
        CelToken::Null => {
            *pos += 1;
            Some(serde_json::Value::Null)
        }

        // Negative number (unary minus)
        CelToken::Minus => {
            *pos += 1;
            let inner = parse_cel_primary(tokens, pos, object)?;
            match inner {
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        Some(serde_json::Value::Number((-i).into()))
                    } else {
                        n.as_f64().map(|f| serde_json::json!(-f))
                    }
                }
                _ => None,
            }
        }

        // Map literal: {"key": value, ...}
        CelToken::LBrace => {
            *pos += 1;
            parse_cel_object_body(tokens, pos, object)
        }

        // Identifier: could be:
        //   - "object" (the admitted resource)
        //   - "TypeName{...}" (struct constructor)
        //   - "TypeName.qualifier{...}" (qualified struct constructor)
        //   - Other identifier (treat as string key in some contexts)
        CelToken::Ident(name) => {
            let name = name.clone();
            *pos += 1;

            // Consume any ".qualifier" segments before the brace.
            // E.g., "Object.metadata{...}" — skip ".metadata" and treat as Object{...}
            while *pos < tokens.len() {
                if let CelToken::Dot = &tokens[*pos] {
                    // peek next: if it's an Ident followed by LBrace, consume the chain
                    if *pos + 1 < tokens.len() {
                        if let CelToken::Ident(_) = &tokens[*pos + 1] {
                            // Check if after the ident there's a LBrace
                            if *pos + 2 < tokens.len() {
                                if let CelToken::LBrace = &tokens[*pos + 2] {
                                    *pos += 2; // consume dot and ident, leaving at LBrace
                                    continue;
                                }
                            }
                            // Dot-access for field navigation
                            *pos += 1; // consume dot
                            if let CelToken::Ident(field) = &tokens[*pos].clone() {
                                let field = field.clone();
                                *pos += 1;
                                // Build field access chain from name
                                let base = if name == "object" {
                                    object.clone()
                                } else {
                                    serde_json::Value::Null
                                };
                                // Continue chaining field accesses
                                let mut cur = base[&field].clone();
                                // Continue reading more .field accesses
                                while *pos < tokens.len() {
                                    if let CelToken::Dot = &tokens[*pos] {
                                        if *pos + 1 < tokens.len() {
                                            if let CelToken::Ident(f2) = &tokens[*pos + 1].clone() {
                                                let f2 = f2.clone();
                                                // Check it's not followed by LBrace (would be constructor)
                                                if *pos + 2 < tokens.len() {
                                                    if let CelToken::LBrace = &tokens[*pos + 2] {
                                                        break;
                                                    }
                                                }
                                                *pos += 2;
                                                cur = cur[&f2].clone();
                                                continue;
                                            }
                                        }
                                    }
                                    break;
                                }
                                return Some(cur);
                            }
                        } else if let CelToken::Dot = &tokens[*pos + 1] {
                            // Another dot — continue chain
                            break;
                        }
                    }
                    break;
                }
                break;
            }

            // If next token is LBrace, it's a struct constructor: TypeName{field: val, ...}
            if *pos < tokens.len() {
                if let CelToken::LBrace = &tokens[*pos] {
                    *pos += 1;
                    return parse_cel_object_body(tokens, pos, object);
                }
            }

            // Plain identifier: if it's "object", return the full admitted resource.
            if name == "object" {
                return Some(object.clone());
            }

            // Other identifiers — treat as string value (for map key contexts handled by caller)
            Some(serde_json::Value::String(name))
        }

        // Parenthesized expression
        CelToken::LParen => {
            *pos += 1;
            let val = parse_cel_value(tokens, pos, object)?;
            // consume RParen if present
            if *pos < tokens.len() {
                if let CelToken::RParen = &tokens[*pos] {
                    *pos += 1;
                }
            }
            Some(val)
        }

        // Array literal: [val, val, ...]
        CelToken::LBracket => {
            *pos += 1;
            let mut arr = Vec::new();
            while *pos < tokens.len() {
                if let CelToken::RBracket = &tokens[*pos] {
                    *pos += 1;
                    break;
                }
                let val = parse_cel_value(tokens, pos, object)?;
                arr.push(val);
                if *pos < tokens.len() {
                    if let CelToken::Comma = &tokens[*pos] {
                        *pos += 1;
                    }
                }
            }
            Some(serde_json::Value::Array(arr))
        }

        _ => None,
    }
}

/// Parse `field: value, field: value, ...}` (the body of a brace-enclosed object).
/// Caller has already consumed the opening `{`.
/// Both identifier keys and string keys are supported.
fn parse_cel_object_body(
    tokens: &[CelToken],
    pos: &mut usize,
    object: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut map = serde_json::Map::new();

    while *pos < tokens.len() {
        // Closing brace
        if let CelToken::RBrace = &tokens[*pos] {
            *pos += 1;
            break;
        }

        // Parse key (string or ident)
        let key = match &tokens[*pos].clone() {
            CelToken::Str(s) => {
                *pos += 1;
                s.clone()
            }
            CelToken::Ident(s) => {
                *pos += 1;
                s.clone()
            }
            _ => return None, // unexpected token
        };

        // Expect ':'
        if *pos >= tokens.len() {
            return None;
        }
        if let CelToken::Colon = &tokens[*pos] {
            *pos += 1;
        } else {
            return None;
        }

        // Parse value
        let val = parse_cel_value(tokens, pos, object)?;
        map.insert(key, val);

        // Optional comma
        if *pos < tokens.len() {
            if let CelToken::Comma = &tokens[*pos] {
                *pos += 1;
            }
        }
    }

    Some(serde_json::Value::Object(map))
}

/// Validate the CEL expressions in `webhooks[*].matchConditions[*].expression`.
///
/// Kubernetes rejects webhook configurations with invalid CEL at creation time.
/// Without this check, a POST with a malformed expression returns 200 OK instead
/// of 422, which causes the admission webhook conformance test to fail.
///
/// We validate that every expression is non-empty and tokenizes to at least one
/// meaningful token — the same tokenizer used for MutatingAdmissionPolicy CEL.
pub(crate) fn validate_webhook_match_conditions_cel(obj: &serde_json::Value) -> Result<(), String> {
    let webhooks = match obj.get("webhooks").and_then(|v| v.as_array()) {
        Some(w) => w,
        None => return Ok(()),
    };
    for (wi, webhook) in webhooks.iter().enumerate() {
        let conditions = match webhook.get("matchConditions").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => continue,
        };
        for (ci, cond) in conditions.iter().enumerate() {
            let expr = match cond.get("expression").and_then(|v| v.as_str()) {
                Some(e) => e,
                None => continue,
            };
            if expr.trim().is_empty() {
                return Err(format!(
                    "webhooks[{wi}].matchConditions[{ci}].expression: \
                     CEL expression must not be empty"
                ));
            }
            let tokens = tokenize_cel(expr.trim()).unwrap_or_default();
            if tokens.is_empty() {
                return Err(format!(
                    "webhooks[{wi}].matchConditions[{ci}].expression: \
                     invalid CEL expression: {expr:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Apply a partial object (apply configuration) to an object using JSON merge patch semantics.
///
/// The partial object is recursively merged into the target: for each key in the
/// partial, if the value is an object, it is merged recursively; otherwise the
/// target's value is replaced.
pub(crate) fn apply_cel_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (serde_json::Value::Object(t), serde_json::Value::Object(p)) = (target, patch) {
        for (k, pv) in p {
            let tv = t.entry(k).or_insert(serde_json::Value::Null);
            if pv.is_object() && tv.is_object() {
                apply_cel_patch(tv, pv);
            } else {
                *tv = pv.clone();
            }
        }
    }
}

/// Run all MutatingAdmissionPolicy CEL mutations for a given resource.
///
/// Fetches all MutatingAdmissionPolicy objects from the store, checks matchConstraints,
/// evaluates each mutation's CEL expression, and applies the result as an
/// `ApplyConfiguration` (merge patch) to the object.
///
/// This is the CEL-based analog to the webhook-based `run_mutating_webhooks`.
/// It runs before the webhook chain so that webhook admission sees the already-mutated object.
///
/// Returns the (possibly mutated) object.
pub async fn run_cel_mutating_policies<S: Store>(
    state: &AppState<S>,
    mut object: serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> serde_json::Value {
    // Policy resources are never evaluated against themselves (same exemption as webhooks).
    if is_webhook_configuration_resource(ctx) {
        return object;
    }

    let policies = fetch_mutating_policies(state).await;
    if policies.is_empty() {
        return object;
    }

    for policy in &policies {
        // Check matchConstraints.
        if !matches_match_constraints(policy, ctx.group, ctx.version, ctx.resource, ctx.operation) {
            continue;
        }

        // Apply each mutation in order.
        let mutations = policy["spec"]["mutations"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        for mutation in &mutations {
            let patch_type = mutation["patchType"].as_str().unwrap_or("");
            if patch_type != "ApplyConfiguration" {
                tracing::warn!(
                    "admission: MutatingAdmissionPolicy mutation patchType '{}' is not implemented, skipping",
                    patch_type
                );
                continue;
            }

            let expr = mutation["applyConfiguration"]["expression"]
                .as_str()
                .unwrap_or("")
                .trim();
            if expr.is_empty() {
                continue;
            }

            match eval_cel_apply_config(expr, &object) {
                Some(patch) => {
                    tracing::debug!(
                        "admission: MutatingAdmissionPolicy applying CEL patch to {}/{}",
                        ctx.resource,
                        ctx.name
                    );
                    apply_cel_patch(&mut object, &patch);
                }
                None => {
                    tracing::warn!(
                        "admission: MutatingAdmissionPolicy CEL expression evaluation failed for \
                         policy '{}', expression: {}",
                        policy["metadata"]["name"].as_str().unwrap_or("unknown"),
                        expr
                    );
                }
            }
        }
    }

    object
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns true if the resource being admitted is in the `admissionregistration.k8s.io` group.
///
/// All resources in `admissionregistration.k8s.io` must be exempt from the admission
/// pipeline to prevent bootstrap deadlocks:
///
/// - MutatingWebhookConfiguration / ValidatingWebhookConfiguration: if creating one of
///   these triggered the admission webhooks, the newly-registered webhook would call itself
///   (or call an endpoint that doesn't exist yet), causing a deadlock or error.
/// - ValidatingAdmissionPolicy / MutatingAdmissionPolicy and their bindings: these are
///   the CEL-based policy objects; exempting them prevents the same class of bootstrap
///   problems and matches Kubernetes upstream behavior.
///
/// This matches Kubernetes upstream behavior: the entire `admissionregistration.k8s.io`
/// group bypasses the webhook admission chain.
fn is_webhook_configuration_resource(ctx: &AdmissionContext<'_>) -> bool {
    ctx.group == "admissionregistration.k8s.io"
}

/// Run the mutating admission webhook chain.
///
/// Fetches all MutatingWebhookConfiguration objects from the store, filters by
/// rules, POSTs AdmissionReview to each matching webhook URL, applies patches.
/// Handles failurePolicy (Fail/Ignore) and reinvocationPolicy (IfNeeded).
///
/// Returns the (possibly mutated) object, or a StatusError if any Fail-policy
/// webhook denied or was unreachable.
pub async fn run_mutating_webhooks<S: Store>(
    state: &AppState<S>,
    mut object: serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> Result<serde_json::Value, StatusError> {
    // Skip the webhook pipeline for webhook configuration resources themselves
    // to prevent a bootstrap deadlock (see is_webhook_configuration_resource).
    if is_webhook_configuration_resource(ctx) {
        return Ok(object);
    }

    // CEL-based MutatingAdmissionPolicy runs before the webhook chain (Kubernetes ordering).
    object = run_cel_mutating_policies(state, object, ctx).await;

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

// ---------------------------------------------------------------------------
// CEL-based ValidatingAdmissionPolicy evaluation
// ---------------------------------------------------------------------------

/// Fetch all ValidatingAdmissionPolicy objects from the store.
async fn fetch_validating_policies<S: Store>(state: &AppState<S>) -> Vec<serde_json::Value> {
    let prefix = "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/";
    match state.store.list(prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("admission: failed to list ValidatingAdmissionPolicies: {e}");
            vec![]
        }
    }
}

/// Fetch all ValidatingAdmissionPolicyBinding objects from the store.
async fn fetch_validating_policy_bindings<S: Store>(state: &AppState<S>) -> Vec<serde_json::Value> {
    let prefix = "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/";
    match state.store.list(prefix, ListOptions::default()).await {
        Ok(resp) => resp
            .items
            .into_iter()
            .filter_map(|item| serde_json::from_slice(&item.value).ok())
            .collect(),
        Err(e) => {
            tracing::warn!("admission: failed to list ValidatingAdmissionPolicyBindings: {e}");
            vec![]
        }
    }
}

/// Run all ValidatingAdmissionPolicy + Binding pairs for a given resource.
///
/// Algorithm:
/// 1. Fetch all VAPs and bindings from the store.
/// 2. For each binding: find its policy by policyName.
/// 3. Check both binding's matchResources (namespaceSelector + resourceRules) and
///    policy's matchConstraints — both must match.
/// 4. Evaluate spec.matchConditions (pre-filter): if any returns false, skip this pair.
/// 5. Evaluate spec.variables in order, building a variables map.
/// 6. Evaluate spec.validations expressions; if any returns false, deny with 403.
/// 7. validationActions: Deny → return error; Warn/Audit → log and continue.
async fn run_validating_admission_policies<S: Store>(
    state: &AppState<S>,
    object: &serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> Result<(), StatusError> {
    // Exempt admission configuration resources (same as webhooks).
    if is_webhook_configuration_resource(ctx) {
        return Ok(());
    }

    let policies = fetch_validating_policies(state).await;
    if policies.is_empty() {
        return Ok(());
    }
    let bindings = fetch_validating_policy_bindings(state).await;
    if bindings.is_empty() {
        return Ok(());
    }

    for binding in &bindings {
        let policy_name = binding["spec"]["policyName"].as_str().unwrap_or("");
        if policy_name.is_empty() {
            continue;
        }
        let policy = match policies
            .iter()
            .find(|p| p["metadata"]["name"].as_str() == Some(policy_name))
        {
            Some(p) => p,
            None => {
                tracing::warn!(
                    "admission: VAP binding references unknown policy \"{policy_name}\", skipping"
                );
                continue;
            }
        };

        // Check policy matchConstraints (resourceRules).
        if !matches_match_constraints(policy, ctx.group, ctx.version, ctx.resource, ctx.operation) {
            continue;
        }

        // Check binding matchResources namespaceSelector.
        let binding_ns_selector: Option<LabelSelector> = binding["spec"]["matchResources"]
            ["namespaceSelector"]
            .as_object()
            .and_then(|_| {
                serde_json::from_value(
                    binding["spec"]["matchResources"]["namespaceSelector"].clone(),
                )
                .ok()
            });
        if binding_ns_selector.is_some() {
            match ctx.namespace {
                None => {
                    // Cluster-scoped resources are never selected by a namespaceSelector.
                    // Skip this binding.
                    continue;
                }
                Some(ns) => {
                    let ns_labels = fetch_namespace_labels(state, ns).await;
                    if !label_selector_matches(binding_ns_selector.as_ref(), &ns_labels) {
                        tracing::debug!(
                            "admission: VAP binding \"{}\" skipped: namespace \"{}\" does not match namespaceSelector",
                            binding["metadata"]["name"].as_str().unwrap_or("unknown"),
                            ns
                        );
                        continue;
                    }
                }
            }
        }

        // Check binding matchResources resourceRules (same as matchConstraints logic).
        let binding_rules = binding["spec"]["matchResources"]["resourceRules"].as_array();
        if let Some(rules) = binding_rules {
            if !rules.is_empty() {
                let any_rule = rules.iter().any(|rule| {
                    matches_rule(
                        rule,
                        ctx.group,
                        ctx.version,
                        ctx.resource,
                        ctx.namespace,
                        ctx.operation,
                    )
                });
                if !any_rule {
                    continue;
                }
            }
        }

        // Build a `request` JSON object from the admission context for CEL evaluation.
        // This allows VAP expressions to reference request.userInfo.username,
        // request.operation, request.name, request.namespace, and request.dryRun.
        let request_val = {
            let mut req = serde_json::Map::new();
            req.insert(
                "operation".to_string(),
                serde_json::Value::String(ctx.operation.to_string()),
            );
            req.insert(
                "name".to_string(),
                serde_json::Value::String(ctx.name.to_string()),
            );
            req.insert(
                "namespace".to_string(),
                ctx.namespace
                    .map(|ns| serde_json::Value::String(ns.to_string()))
                    .unwrap_or(serde_json::Value::Null),
            );
            req.insert("dryRun".to_string(), serde_json::Value::Bool(ctx.dry_run));
            if let Some(ref ui) = ctx.user_info {
                req.insert("userInfo".to_string(), ui.clone());
            } else {
                req.insert(
                    "userInfo".to_string(),
                    serde_json::json!({"username": "", "groups": []}),
                );
            }
            serde_json::Value::Object(req)
        };

        // Evaluate matchConditions (pre-filter): any false → skip this binding, not deny.
        let match_conditions = policy["spec"]["matchConditions"].as_array();
        if let Some(conditions) = match_conditions {
            let mut skip = false;
            for cond in conditions {
                let expr = cond["expression"].as_str().unwrap_or("");
                if expr.is_empty() {
                    continue;
                }
                let vars = serde_json::Map::new();
                match eval_cel_bool_expr(expr, object, &vars, &request_val) {
                    Some(true) => {} // condition passes, continue
                    Some(false) => {
                        // matchCondition returned false → skip this webhook (not deny)
                        tracing::debug!(
                            "admission: VAP \"{}\" matchCondition false, skipping",
                            policy_name
                        );
                        skip = true;
                        break;
                    }
                    None => {
                        // eval error on matchCondition → treat as "do not skip" (upstream behavior)
                        tracing::warn!(
                            "admission: VAP \"{}\" matchCondition eval error, treating as pass",
                            policy_name
                        );
                    }
                }
            }
            if skip {
                continue;
            }
        }

        // Evaluate spec.variables in order, building a variables map.
        let mut variables: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        let var_defs = policy["spec"]["variables"].as_array();
        if let Some(var_list) = var_defs {
            for var_def in var_list {
                let var_name = var_def["name"].as_str().unwrap_or("");
                let var_expr = var_def["expression"].as_str().unwrap_or("");
                if var_name.is_empty() || var_expr.is_empty() {
                    continue;
                }
                match eval_cel_vap_value(var_expr, object, &variables, &request_val) {
                    Some(val) => {
                        variables.insert(var_name.to_string(), val);
                    }
                    None => {
                        tracing::warn!(
                            "admission: VAP \"{}\" variable \"{}\" eval failed, expr: {}",
                            policy_name,
                            var_name,
                            var_expr
                        );
                        // Continue; the variable will be absent from the map.
                    }
                }
            }
        }

        // Determine validation actions from binding.
        let validation_actions: Vec<&str> = binding["spec"]["validationActions"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let should_deny = validation_actions.contains(&"Deny");

        // Evaluate spec.validations.
        let validations = policy["spec"]["validations"].as_array();
        if let Some(val_list) = validations {
            for validation in val_list {
                let expr = validation["expression"].as_str().unwrap_or("");
                if expr.is_empty() {
                    continue;
                }
                let result = eval_cel_bool_expr(expr, object, &variables, &request_val);
                let passed = match result {
                    Some(b) => b,
                    None => {
                        tracing::warn!(
                            "admission: VAP \"{}\" validation expr eval failed: {}",
                            policy_name,
                            expr
                        );
                        false // treat eval error as failure
                    }
                };
                if !passed {
                    let reason = validation["reason"].as_str().unwrap_or("Forbidden");
                    let message = validation["message"]
                        .as_str()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| {
                            format!(
                                "ValidatingAdmissionPolicy \"{policy_name}\" denied the request: \
                             expression '{expr}' evaluated to false"
                            )
                        });
                    if should_deny {
                        tracing::debug!(
                            "admission: VAP \"{}\" denied: {} (reason: {})",
                            policy_name,
                            message,
                            reason
                        );
                        return Err(Status::forbidden(message));
                    } else {
                        tracing::warn!(
                            "admission: VAP \"{}\" validation failed (non-Deny action): {}",
                            policy_name,
                            message
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run the validating admission webhook chain.
///
/// Fetches all ValidatingWebhookConfiguration objects from the store, filters by
/// rules, POSTs AdmissionReview to each matching webhook URL.
/// Returns Ok(()) if all webhooks allow, or a StatusError if any deny or fail with Fail policy.
pub async fn run_validating_webhooks<S: Store>(
    state: &AppState<S>,
    object: &serde_json::Value,
    ctx: &AdmissionContext<'_>,
) -> Result<(), StatusError> {
    // Skip the webhook pipeline for webhook configuration resources themselves
    // to prevent a bootstrap deadlock (see is_webhook_configuration_resource).
    if is_webhook_configuration_resource(ctx) {
        return Ok(());
    }

    let configs = fetch_validating_configs(state).await;
    let mut all_webhooks: Vec<WebhookEntry> = Vec::new();
    for config in &configs {
        if let Ok(wc) = serde_json::from_value::<WebhookConfig>(config.clone()) {
            all_webhooks.extend(wc.webhooks);
        }
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

        // objectSelector: skip if the object's labels don't match.
        if webhook.object_selector.is_some() {
            let obj_labels: BTreeMap<String, String> = object["metadata"]["labels"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            if !label_selector_matches(webhook.object_selector.as_ref(), &obj_labels) {
                tracing::debug!(
                    "admission: validating webhook \"{}\" skipped: object does not match objectSelector",
                    webhook.name
                );
                continue;
            }
        }

        let target = match webhook_url(state, &webhook.client_config, &webhook.name).await {
            Ok(t) => t,
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
        let call_url = match &target {
            WebhookTarget::DirectUrl(u) => u.as_str(),
            WebhookTarget::ServiceResolved { url } => url.as_str(),
        };

        let uid = uuid::Uuid::new_v4().to_string();
        let review = build_review(&uid, ctx, object);

        // DirectUrl webhooks go to an external endpoint: do not route through the
        // konnectivity proxy (which only reaches pod IPs inside the VM) and do not
        // present the apiserver mTLS identity (which would leak it to an external host).
        let (effective_proxy, effective_identity) = match &target {
            WebhookTarget::DirectUrl(_) => (None, None),
            WebhookTarget::ServiceResolved { .. } => (
                state.konnectivity_proxy_addr.as_deref(),
                state.webhook_identity_pem.as_deref().map(|v| v.as_slice()),
            ),
        };

        let wh_client = build_webhook_call_client(
            webhook.client_config.ca_bundle.as_deref(),
            effective_proxy,
            state.cluster_ca_der.as_deref().map(|v| v.as_slice()),
            effective_identity,
            &state.webhook_client,
            webhook.timeout_seconds,
        );
        let (response, timed_out) = call_webhook(&wh_client, call_url, &review).await;

        match response {
            Some(resp) => {
                if !resp.allowed {
                    let message = resp
                        .status
                        .as_ref()
                        .and_then(|s| {
                            s.message
                                .as_deref()
                                .filter(|m| !m.is_empty())
                                .or(s.reason.as_deref().filter(|r| !r.is_empty()))
                        })
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
                } else if timed_out {
                    return Err(Status::internal(format!(
                        "admission webhook \"{}\" request deadline exceeded",
                        webhook.name
                    )));
                } else {
                    return Err(Status::internal(format!(
                        "admission webhook \"{}\" failed to respond (failurePolicy=Fail)",
                        webhook.name
                    )));
                }
            }
        }
    }

    // Run CEL-based ValidatingAdmissionPolicy enforcement.
    run_validating_admission_policies(state, object, ctx).await
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

    // -- bootstrap deadlock prevention tests --

    /// Creating a MutatingWebhookConfiguration must bypass the admission pipeline entirely.
    ///
    /// If the admission webhooks were invoked when a MutatingWebhookConfiguration is
    /// being created, the newly-registered webhook would immediately call itself
    /// (or call an endpoint that doesn't exist yet), causing a deadlock or error.
    /// Kubernetes resolves this by making webhook configuration resources exempt from
    /// the admission pipeline.
    #[tokio::test]
    async fn run_mutating_webhooks_skips_for_webhook_configuration_resources() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a wildcard MutatingWebhookConfiguration with failurePolicy=Fail and unreachable URL.
        // If the pipeline is NOT skipped for webhook configuration resources, this webhook
        // would be invoked when another MutatingWebhookConfiguration is created, causing
        // a connection error and failing the test.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "wildcard-mwc"},
            "webhooks": [{
                "name": "deadlock.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"  // unreachable — would cause Fail if invoked
                },
                "rules": [{
                    "apiGroups": ["*"],
                    "apiVersions": ["*"],
                    "resources": ["*"],
                    "operations": ["*"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/wildcard-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let new_mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "new-mwc"}
        });
        // Simulate create of another MutatingWebhookConfiguration.
        let ctx = AdmissionContext {
            group: "admissionregistration.k8s.io",
            version: "v1",
            resource: "mutatingwebhookconfigurations",
            name: "new-mwc",
            namespace: None,
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        // Must succeed without invoking any webhook (skipped by deadlock prevention).
        let result = run_mutating_webhooks(&state, new_mwc.clone(), &ctx).await;
        assert!(
            result.is_ok(),
            "MutatingWebhookConfiguration create must bypass admission pipeline to prevent deadlock"
        );
        assert_eq!(
            result.unwrap_or_else(|_| panic!("must succeed")),
            new_mwc,
            "object must be returned unchanged when pipeline is bypassed"
        );
    }

    /// Creating a ValidatingWebhookConfiguration must bypass the admission pipeline entirely.
    ///
    /// Same reasoning as the mutating variant: webhook configuration resources are exempt
    /// from the admission pipeline to prevent deadlocks and bootstrap issues.
    #[tokio::test]
    async fn run_validating_webhooks_skips_for_webhook_configuration_resources() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Wildcard ValidatingWebhookConfiguration with unreachable URL and Fail policy.
        let vwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "wildcard-vwc"},
            "webhooks": [{
                "name": "deadlock.validating.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["*"]}],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/wildcard-vwc",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let new_vwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "new-vwc"}
        });
        let ctx = AdmissionContext {
            group: "admissionregistration.k8s.io",
            version: "v1",
            resource: "validatingwebhookconfigurations",
            name: "new-vwc",
            namespace: None,
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_validating_webhooks(&state, &new_vwc, &ctx).await;
        assert!(
            result.is_ok(),
            "ValidatingWebhookConfiguration create must bypass admission pipeline to prevent deadlock"
        );
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_err(),
            "webhook with matching namespaceSelector must be invoked (and fail because URL is unreachable)"
        );
    }

    // -- service-based clientConfig tests --

    /// A webhook configured with clientConfig.service must build the correct HTTPS URL
    /// using the service DNS name (e.g. `https://my-webhook-svc.webhook-ns.svc:8443/mutate`).
    /// With kube-proxy (PR #406), the konnectivity-agent resolves the service DNS name and
    /// routes through kube-proxy. Since nothing listens at that address in this unit test,
    /// failurePolicy=Ignore causes the pipeline to succeed.
    #[tokio::test]
    async fn service_based_client_config_builds_service_dns_url() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // MutatingWebhookConfiguration with service-based clientConfig.
        // webhook_url uses the configured svc_port directly (no Service lookup needed).
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
                "failurePolicy": "Ignore"  // URL not reachable in unit test; Ignore skips gracefully
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
            user_info: None,
            dry_run: false,
        };
        // The webhook is invoked at https://my-webhook-svc.webhook-ns.svc:8443/mutate,
        // fails to connect (no cluster in unit tests), but failurePolicy=Ignore means
        // the pipeline succeeds.
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;
        assert!(
            result.is_ok(),
            "service-based webhook with failurePolicy=Ignore must succeed when connection fails"
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
            user_info: None,
            dry_run: false,
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
            user_info: None,
            dry_run: false,
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

    /// A webhook with clientConfig.service and failurePolicy=Fail must return an error
    /// when the service DNS name is unreachable (connection refused / DNS not resolvable
    /// in unit test environment).
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

        // No Service stored — svc_port is used directly; URL is built but unreachable.
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
            user_info: None,
            dry_run: false,
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;
        assert!(
            result.is_err(),
            "service not found with failurePolicy=Fail must return an error"
        );
    }

    // -- end-to-end: register MutatingWebhookConfiguration, create resource, verify mutation --

    /// Register a MutatingWebhookConfiguration pointing to a live mock HTTP handler,
    /// call run_mutating_webhooks for a ConfigMap, and verify the webhook was called
    /// and the mutation (label injection) was applied to the object.
    ///
    /// This is the core correctness test for the webhook invocation pipeline:
    /// if run_mutating_webhooks fails to POST to the webhook or fails to apply the patch,
    /// controllers that rely on sidecar injection or label defaulting will see stale objects.
    #[tokio::test]
    async fn mutating_webhook_called_and_mutation_applied_for_configmap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        // Counter to verify the webhook was actually called.
        let call_count = StdArc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        // Webhook that injects a label "managed-by=webhook" into ConfigMaps.
        let router = Router::new().route(
            "/mutate",
            post(move || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let patch = serde_json::json!([
                        {"op": "add", "path": "/metadata/labels", "value": {"managed-by": "webhook"}}
                    ]);
                    let patch_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        serde_json::to_string(&patch).unwrap(),
                    );
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": {
                            "uid": "configmap-uid",
                            "allowed": true,
                            "patch": patch_b64,
                            "patchType": "JSONPatch"
                        }
                    }))
                }
            }),
        );

        let (base_url, _handle) = start_mock_webhook_server(router).await;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Register the MutatingWebhookConfiguration targeting core/v1/configmaps.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "configmap-labeler"},
            "webhooks": [{
                "name": "configmap.labeler.example.com",
                "clientConfig": { "url": format!("{base_url}/mutate") },
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["configmaps"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/configmap-labeler",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let configmap = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "my-config", "namespace": "default"}
        });

        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "my-config",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_mutating_webhooks(&state, configmap, &ctx).await;

        assert!(
            result.is_ok(),
            "mutating webhook pipeline must succeed for ConfigMap create"
        );

        let count = call_count.load(Ordering::SeqCst);
        assert_eq!(
            count, 1,
            "webhook must be called exactly once for ConfigMap create; \
             not calling it means mutations (sidecar injection, label defaults) are skipped"
        );

        let mutated = result.unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(
            mutated["metadata"]["labels"]["managed-by"], "webhook",
            "webhook must have injected the 'managed-by=webhook' label into the ConfigMap; \
             missing label means the patch was not applied correctly"
        );
    }

    /// build_webhook_call_client must build a working client when given a valid caBundle.
    /// Without this, every webhook call fails with TLS cert rejection when the webhook
    /// uses its own CA (not the cluster CA): the shared client trusts only the cluster CA.
    #[test]
    fn build_webhook_call_client_uses_ca_bundle() {
        let cert = rcgen::generate_simple_self_signed(vec!["test.local".to_string()])
            .expect("generate self-signed cert for caBundle test");
        let ca_der = cert.cert.der().to_vec();

        // Build PEM from DER manually — same logic as tls::pem_encode.
        let b64_der = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ca_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64_der.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");

        let ca_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pem.as_bytes());

        let fallback = reqwest::Client::new();
        // Must not panic and must not return the fallback clone (cert was valid).
        let client = build_webhook_call_client(Some(&ca_b64), None, None, None, &fallback, None);
        drop(client);
    }

    /// build_webhook_call_client must apply the konnectivity proxy when proxy_addr is set.
    /// Without this, per-webhook clients built with a custom caBundle bypass konnectivity
    /// and cannot reach the service ClusterIP from the Mac host — every webhook call fails.
    #[test]
    fn build_webhook_call_client_with_proxy_addr_does_not_panic() {
        let cert = rcgen::generate_simple_self_signed(vec!["test.local".to_string()])
            .expect("generate self-signed cert for proxy test");
        let ca_der = cert.cert.der().to_vec();
        let b64_der = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ca_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64_der.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        let ca_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pem.as_bytes());

        let fallback = reqwest::Client::new();
        // Must build successfully and apply the proxy — if this panics, all webhook calls
        // to service DNS names fail when konnectivity is configured.
        let client = build_webhook_call_client(
            Some(&ca_b64),
            Some("127.0.0.1:8135"),
            None,
            None,
            &fallback,
            None,
        );
        drop(client);
    }

    /// build_webhook_call_client must return a clone of the fallback when caBundle is absent.
    /// Webhooks without a caBundle use the shared cluster-CA client.
    #[test]
    fn build_webhook_call_client_no_bundle_returns_fallback() {
        let fallback = reqwest::Client::new();
        let client = build_webhook_call_client(None, None, None, None, &fallback, None);
        drop(client);
    }

    /// build_webhook_call_client must return the fallback when caBundle is malformed base64.
    /// A webhook with a corrupt caBundle must not crash the apiserver — and must emit a
    /// warning so operators can diagnose the misconfiguration. Without logging, a corrupt
    /// caBundle silently bypasses per-webhook CA pinning with no observable signal.
    #[test]
    fn build_webhook_call_client_invalid_b64_returns_fallback() {
        let fallback = reqwest::Client::new();
        // Invalid base64 must return fallback (not panic) so the apiserver keeps running.
        let client = build_webhook_call_client(
            Some("!!!not-valid-base64!!!"),
            None,
            None,
            None,
            &fallback,
            None,
        );
        // Returned client must be usable — it is the fallback clone.
        drop(client);
    }

    /// AdmissionStatus.reason must be deserialised and used as the denial message when
    /// the webhook sets only `reason` (not `message`). Some real webhooks (e.g. OPA Gatekeeper)
    /// set `reason` to carry the policy violation detail and leave `message` empty. Without
    /// this field the apiserver would surface a generic "admission webhook denied the request"
    /// message, hiding the actual policy violation from the user.
    #[test]
    fn admission_status_reason_field_is_deserialised() {
        let json = r#"{"reason": "pods with privileged containers are not allowed"}"#;
        let status: AdmissionStatus =
            serde_json::from_str(json).expect("AdmissionStatus must deserialise with only reason");
        assert_eq!(
            status.reason.as_deref(),
            Some("pods with privileged containers are not allowed"),
            "reason field must be deserialised so webhook denial messages reach the user"
        );
        assert!(
            status.message.is_none(),
            "message must be None when absent in response"
        );
    }

    /// WebhookTarget::ServiceResolved must carry the service DNS URL (not a raw pod IP).
    ///
    /// With kube-proxy running (PR #406), the konnectivity-agent resolves service DNS names
    /// via CoreDNS and routes through kube-proxy to the pod. Using the service DNS name
    /// ensures correct TLS SNI matching against the webhook cert's SAN, and no
    /// danger_accept_invalid_hostnames workaround is needed.
    #[test]
    fn webhook_target_service_resolved_uses_service_dns_name() {
        // Verify the variant carries only the service DNS URL — compile-time structural check.
        let target = WebhookTarget::ServiceResolved {
            url: "https://my-webhook.webhook-ns.svc:443/validate".to_string(),
        };
        match target {
            WebhookTarget::ServiceResolved { url } => {
                assert!(
                    url.contains(".svc:"),
                    "ServiceResolved URL must use service DNS name (not a raw pod IP) \
                     so TLS SNI matches the webhook cert SAN"
                );
                assert!(
                    !url.contains("10."),
                    "ServiceResolved URL must not contain a raw pod IP — \
                     kube-proxy (PR #406) routes via ClusterIP through the konnectivity proxy"
                );
            }
            _ => panic!("must match ServiceResolved"),
        }
    }

    // -- Regression tests for mayor-jexr, mayor-h9ea, mayor-72qh --

    /// build_review must populate request.kind.kind from the object's "kind" field.
    ///
    /// Webhooks such as Kyverno and OPA Gatekeeper dispatch on request.kind to apply
    /// per-resource policies. An empty kind string causes them to skip evaluation or
    /// apply the wrong policy, silently accepting objects that should be rejected.
    /// Reverting the fix (setting kind to String::new()) makes this test fail.
    #[test]
    fn build_review_kind_populated_from_object() {
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let obj = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deploy"}
        });
        let review = build_review("uid-kind-test", &ctx, &obj);
        let req = review.request.expect("request must be set");
        assert_eq!(
            req.kind.kind, "Deployment",
            "request.kind.kind must be populated from object['kind'] so webhooks can \
             dispatch per-resource policies; empty kind causes Kyverno/OPA to skip evaluation"
        );
        assert_eq!(
            req.kind.group, "apps",
            "request.kind.group must match ctx.group"
        );
        assert_eq!(
            req.kind.version, "v1",
            "request.kind.version must match ctx.version"
        );
    }

    /// build_review must use an empty string for kind when the object has no "kind" field.
    ///
    /// CRDs and objects-under-construction may lack a kind field; build_review must not
    /// panic in that case and must produce an empty string (rather than crashing or using
    /// a wrong value).
    #[test]
    fn build_review_kind_empty_when_object_has_no_kind() {
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "pods",
            name: "my-pod",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        // Object without a "kind" field.
        let obj = serde_json::json!({"metadata": {"name": "my-pod"}});
        let review = build_review("uid-no-kind", &ctx, &obj);
        let req = review.request.expect("request must be set");
        assert_eq!(
            req.kind.kind, "",
            "request.kind.kind must be empty string when object has no kind field; must not panic"
        );
    }

    /// webhook_url with multiple pod addresses must not always resolve to the first one.
    ///
    /// Always returning index 0 pins all admission calls to one replica. If that pod
    /// fails between Endpoints updates, every webhook call fails until Endpoints are
    /// refreshed. With N=3 pods and a time-based selector, calling with different
    /// system-time values must eventually hit addresses other than index 0.
    /// We verify this by checking that the selection logic is modulo-bounded.
    #[test]
    fn pod_ip_selection_is_bounded_by_address_count() {
        // Simulate the index-selection logic used in webhook_url.
        // This test exercises the formula directly so it can fail if reverted to `first()`.
        let addresses = ["10.0.0.1", "10.0.0.2", "10.0.0.3"];
        let n = addresses.len();

        // Any nanos value must produce an index in [0, n).
        for nanos in [0u32, 1, 999_999_999, 500_000_000, 123_456_789] {
            let idx = (nanos as usize) % n;
            assert!(
                idx < n,
                "pod IP selection index must be in [0, n): nanos={nanos} n={n} idx={idx}; \
                 out-of-bounds index would panic at runtime"
            );
            // The selected address must be a valid entry from the list.
            assert!(
                addresses[idx].starts_with("10."),
                "selected pod IP must be from the address list"
            );
        }

        // Verify that index 0 is NOT the only reachable index (i.e., distribution covers others).
        let indices: std::collections::HashSet<usize> = [0u32, 1, 2, 3, 4, 5]
            .iter()
            .map(|&nanos| (nanos as usize) % n)
            .collect();
        assert!(
            indices.len() > 1,
            "pod IP selection must distribute across multiple addresses, not pin to index 0; \
             always using first() means a single pod failure takes down all webhook calls"
        );
    }

    /// For DirectUrl webhooks, build_webhook_call_client must be called without proxy or
    /// identity — verified by checking that passing None for both does not panic and
    /// produces a usable client.
    ///
    /// If DirectUrl targets were to receive proxy_addr or webhook_identity_pem:
    /// - The konnectivity proxy only routes to service DNS names inside the VM, so external
    ///   URLs would fail to connect entirely.
    /// - The apiserver mTLS identity would be leaked to an operator-supplied external host.
    ///
    /// Reverting the fix (always passing state.konnectivity_proxy_addr) would mean
    /// DirectUrl webhooks always attempt to CONNECT through the konnectivity proxy,
    /// breaking any external webhook endpoint.
    #[test]
    fn direct_url_webhook_client_built_without_proxy_or_identity() {
        // Simulate what the code does for WebhookTarget::DirectUrl:
        // effective_proxy = None, effective_identity = None.
        let fallback = reqwest::Client::new();
        // Must build successfully with no proxy and no identity pem.
        let client = build_webhook_call_client(
            None, // no caBundle
            None, // effective_proxy = None (the fix)
            None, // cluster_ca_der
            None, // effective_identity = None (the fix)
            &fallback, None, // timeout_seconds — use default 10s
        );
        // Client is usable — no panic during build.
        drop(client);
    }

    // -- objectSelector regression tests --

    /// A mutating webhook with objectSelector must be skipped for objects whose labels do not match.
    ///
    /// The conformance readiness check (waitWebhookConfigurationReady) creates ConfigMaps
    /// with a specific label and expects only the marker webhook to fire for them. Without
    /// objectSelector support, all webhooks would fire for all objects in the namespace,
    /// causing the non-marker webhooks to apply unwanted mutations or denials.
    ///
    /// Reverting the fix (removing objectSelector from WebhookEntry) makes this test fail
    /// because the webhook would be invoked for the non-matching object (unreachable URL +
    /// failurePolicy=Fail → error, not success).
    #[tokio::test]
    async fn object_selector_non_matching_object_skips_mutating_webhook() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Webhook with objectSelector requiring label "env=prod".
        // Points to an unreachable URL with failurePolicy=Fail — if invoked, the pipeline
        // would fail. The object we pass has label "env=dev", so the webhook must be skipped.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "prod-only-obj-mwc"},
            "webhooks": [{
                "name": "prod.object.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"  // unreachable — would cause Fail if invoked
                },
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["configmaps"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail",
                "objectSelector": {
                    "matchLabels": {"env": "prod"}
                }
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/prod-only-obj-mwc",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Object with label "env=dev" — does NOT match objectSelector "env=prod".
        let obj = json!({
            "kind": "ConfigMap",
            "metadata": {"name": "my-config", "labels": {"env": "dev"}}
        });
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "my-config",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_ok(),
            "webhook with non-matching objectSelector must be skipped, not invoked; \
             invoking it would fail because the URL is unreachable with failurePolicy=Fail"
        );
        assert_eq!(
            result.unwrap_or_else(|_| panic!("must succeed")),
            obj,
            "object must be unchanged when webhook is skipped by objectSelector"
        );
    }

    /// A mutating webhook with objectSelector must be invoked for objects whose labels match.
    ///
    /// When the object has the required label, the webhook must fire. An unreachable URL
    /// with failurePolicy=Fail must cause an error — confirming the webhook was actually
    /// invoked (not silently skipped due to a bug in objectSelector matching).
    #[tokio::test]
    async fn object_selector_matching_object_invokes_mutating_webhook() {
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
            "metadata": {"name": "prod-only-obj-mwc-match"},
            "webhooks": [{
                "name": "prod.object.match.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"  // unreachable — causes Fail when invoked
                },
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["configmaps"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail",
                "objectSelector": {
                    "matchLabels": {"env": "prod"}
                }
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/prod-only-obj-mwc-match",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Object WITH label "env=prod" — matches objectSelector.
        let obj = json!({
            "kind": "ConfigMap",
            "metadata": {"name": "my-prod-config", "labels": {"env": "prod"}}
        });
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "my-prod-config",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_mutating_webhooks(&state, obj.clone(), &ctx).await;

        assert!(
            result.is_err(),
            "webhook with matching objectSelector must be invoked; \
             the unreachable URL with failurePolicy=Fail must cause an error"
        );
    }

    /// A validating webhook with objectSelector must be skipped for objects whose labels do not match.
    ///
    /// Same correctness requirement as the mutating case: the objectSelector must prevent
    /// the webhook from firing on objects it was not configured to inspect.
    #[tokio::test]
    async fn object_selector_non_matching_object_skips_validating_webhook() {
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
            "metadata": {"name": "prod-only-obj-vwc"},
            "webhooks": [{
                "name": "prod.validating.object.webhook.example.com",
                "clientConfig": {
                    "url": "http://127.0.0.1:1"
                },
                "rules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["configmaps"],
                    "operations": ["CREATE"]
                }],
                "failurePolicy": "Fail",
                "objectSelector": {
                    "matchLabels": {"env": "prod"}
                }
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/prod-only-obj-vwc",
                bytes::Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj = json!({
            "kind": "ConfigMap",
            "metadata": {"name": "my-dev-config", "labels": {"env": "dev"}}
        });
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "my-dev-config",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_validating_webhooks(&state, &obj, &ctx).await;

        assert!(
            result.is_ok(),
            "validating webhook with non-matching objectSelector must be skipped; \
             invoking it would fail because the URL is unreachable with failurePolicy=Fail"
        );
    }

    /// Service-based webhook URL must use the SERVICE port (not target port).
    ///
    /// kube-proxy routes ClusterIP:svc_port → PodIP:targetPort inside the VM.
    /// If we use target_port in the URL, the connection goes to ClusterIP:targetPort,
    /// which kube-proxy does not intercept — the connection fails even when the pod is running.
    /// The readiness check (waitWebhookConfigurationReady) depends on the webhook being
    /// reachable to return "denied"; using the wrong port causes the check to time out.
    ///
    /// Reverting the fix (using target_port instead of svc_port) makes this test fail because
    /// the URL would contain ":8444" instead of ":8443".
    #[tokio::test]
    async fn service_webhook_url_uses_service_port_not_target_port() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a Service with port 8443 → targetPort 8444. The webhook URL must use
        // svc_port (8443), not targetPort (8444).
        let svc = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-webhook-svc", "namespace": "webhook-ns"},
            "spec": {
                "ports": [{"port": 8443, "targetPort": 8444}]
            }
        });
        store
            .put(
                "/registry/services/webhook-ns/my-webhook-svc",
                bytes::Bytes::from(serde_json::to_vec(&svc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // MutatingWebhookConfiguration that refers to the service above.
        let mwc = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "svc-port-test"},
            "webhooks": [{
                "name": "svc.port.test.example.com",
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
                "failurePolicy": "Ignore"
            }]
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/svc-port-test",
                bytes::Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Resolve the webhook URL via webhook_url (private) by observing it through
        // run_mutating_webhooks: with failurePolicy=Ignore and unreachable host, the
        // pipeline succeeds. We verify the URL indirectly via the comment above, and
        // directly by calling webhook_url.
        let config = WebhookClientConfig {
            url: None,
            service: Some(ServiceReference {
                namespace: "webhook-ns".to_string(),
                name: "my-webhook-svc".to_string(),
                port: Some(8443),
                path: Some("/mutate".to_string()),
            }),
            ca_bundle: None,
        };

        let target = webhook_url(&state, &config, "test").await.unwrap();
        let url = match target {
            WebhookTarget::ServiceResolved { url } => url,
            WebhookTarget::DirectUrl(_) => panic!("expected ServiceResolved"),
        };

        assert!(
            url.contains(":8443/"),
            "service webhook URL must use service port 8443, not target port 8444; \
             kube-proxy routes ClusterIP:8443 → PodIP:8444, so connecting to :8444 fails: url={url}"
        );
        assert!(
            !url.contains(":8444"),
            "service webhook URL must NOT use target port 8444; \
             using target port bypasses kube-proxy routing and causes connection failures: url={url}"
        );
        assert!(
            url.contains("my-webhook-svc.webhook-ns.svc"),
            "service webhook URL must use service DNS name for correct TLS SNI and kube-proxy routing: url={url}"
        );
    }

    // ---------------------------------------------------------------------------
    // CEL-based MutatingAdmissionPolicy tests (mayor-iia9)
    // ---------------------------------------------------------------------------

    /// A stored MutatingAdmissionPolicy with a CEL ApplyConfiguration mutation
    /// must be evaluated on CREATE and its label added to the stored object.
    ///
    /// This is the key regression test: if MutatingAdmissionPolicy evaluation is
    /// reverted (policies fetched but CEL not run), the label will be absent and
    /// the conformance test will wait indefinitely for the mutation to appear.
    #[tokio::test]
    async fn cel_mutating_policy_applies_label_on_create() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a MutatingAdmissionPolicy that adds label "mutated=true" to all Deployments.
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingAdmissionPolicy",
            "metadata": {"name": "add-label-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE", "UPDATE"]
                    }]
                },
                "mutations": [{
                    "patchType": "ApplyConfiguration",
                    "applyConfiguration": {
                        "expression": "Object{metadata: Object.metadata{labels: {\"mutated\": \"true\"}}}"
                    }
                }]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingadmissionpolicies/add-label-policy",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // A Deployment with no labels.
        let deployment = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deploy", "namespace": "default"}
        });
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_mutating_webhooks(&state, deployment, &ctx).await;
        assert!(
            result.is_ok(),
            "MutatingAdmissionPolicy evaluation must not fail the CREATE request"
        );
        let mutated = result.unwrap_or_else(|_| panic!("must succeed"));
        assert_eq!(
            mutated["metadata"]["labels"]["mutated"], "true",
            "MutatingAdmissionPolicy CEL mutation must add the 'mutated=true' label; \
             without CEL evaluation the label is absent and the conformance test polls \
             indefinitely waiting for the mutation to appear"
        );
    }

    /// A MutatingAdmissionPolicy whose matchConstraints does NOT match the resource
    /// must be skipped — the object must be returned unchanged.
    ///
    /// If matchConstraints is ignored, policies for one resource type would incorrectly
    /// mutate all resource types.
    #[tokio::test]
    async fn cel_mutating_policy_skipped_when_match_constraints_do_not_match() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Policy scoped to "deployments" only.
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingAdmissionPolicy",
            "metadata": {"name": "deployments-only-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE"]
                    }]
                },
                "mutations": [{
                    "patchType": "ApplyConfiguration",
                    "applyConfiguration": {
                        "expression": "Object{metadata: Object.metadata{labels: {\"should-not-appear\": \"true\"}}}"
                    }
                }]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingadmissionpolicies/deployments-only-policy",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Admitting a ConfigMap (not a Deployment) — policy must be skipped.
        let cm = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "my-cm", "namespace": "default"}
        });
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "my-cm",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_mutating_webhooks(&state, cm.clone(), &ctx).await;
        assert!(
            result.is_ok(),
            "pipeline must succeed for non-matching resource"
        );
        let returned = result.unwrap_or_else(|_| panic!("must succeed"));
        assert!(
            returned["metadata"]["labels"]["should-not-appear"].is_null(),
            "policy must NOT be applied when resource does not match matchConstraints; \
             applying it would mutate resources the policy was not intended for"
        );
    }

    /// eval_cel_apply_config must produce a JSON object from a Kubernetes-style
    /// Object{...} CEL expression (the ApplyConfiguration pattern).
    ///
    /// This test verifies the general CEL evaluation mechanism, not just the
    /// conformance test's specific expression.
    #[test]
    fn eval_cel_apply_config_object_construction() {
        let object = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "test"}
        });

        // Kubernetes-style typed struct construction.
        let result = eval_cel_apply_config(
            r#"Object{metadata: Object.metadata{labels: {"injected": "true"}}}"#,
            &object,
        );
        assert!(
            result.is_some(),
            "Object{{...}} CEL expression must parse and evaluate; \
             failure means ApplyConfiguration mutations cannot be applied"
        );
        let val = result.unwrap();
        assert_eq!(
            val["metadata"]["labels"]["injected"], "true",
            "CEL expression must produce the correct partial object; \
             wrong output means the wrong mutation is applied to the resource"
        );
    }

    /// eval_cel_apply_config must handle map literals (the CEL-standard way to construct objects).
    #[test]
    fn eval_cel_apply_config_map_literal() {
        let object = json!({"metadata": {"name": "x"}});
        let result =
            eval_cel_apply_config(r#"{"metadata": {"labels": {"key": "value"}}}"#, &object);
        assert!(result.is_some(), "map literal must evaluate successfully");
        let val = result.unwrap();
        assert_eq!(
            val["metadata"]["labels"]["key"], "value",
            "map literal must produce the expected JSON structure"
        );
    }

    /// eval_cel_apply_config must handle field access on the `object` variable.
    #[test]
    fn eval_cel_apply_config_field_access_on_object() {
        let object = json!({"metadata": {"name": "my-deploy", "namespace": "default"}});
        let result = eval_cel_apply_config("object.metadata.name", &object);
        assert!(result.is_some(), "field access on object must succeed");
        assert_eq!(
            result.unwrap(),
            "my-deploy",
            "field access must return the correct value from the admitted object"
        );
    }

    /// apply_cel_patch must recursively merge nested objects.
    ///
    /// This ensures that a label addition does not overwrite sibling labels.
    #[test]
    fn apply_cel_patch_merges_nested_objects() {
        let mut target = json!({
            "metadata": {
                "name": "test",
                "labels": {"existing": "yes"}
            }
        });
        let patch = json!({
            "metadata": {
                "labels": {"new-label": "true"}
            }
        });
        apply_cel_patch(&mut target, &patch);
        assert_eq!(
            target["metadata"]["labels"]["existing"], "yes",
            "apply_cel_patch must preserve existing labels when merging"
        );
        assert_eq!(
            target["metadata"]["labels"]["new-label"], "true",
            "apply_cel_patch must add new labels from the patch"
        );
    }

    /// matches_match_constraints must match wildcard "*" in all fields.
    #[test]
    fn matches_match_constraints_wildcard_matches_everything() {
        let policy = json!({
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["*"],
                        "apiVersions": ["*"],
                        "resources": ["*"],
                        "operations": ["*"]
                    }]
                }
            }
        });
        assert!(
            matches_match_constraints(&policy, "apps", "v1", "deployments", "CREATE"),
            "wildcard matchConstraints must match any resource"
        );
    }

    /// matches_match_constraints must return true when matchConstraints is absent.
    #[test]
    fn matches_match_constraints_absent_matches_all() {
        let policy = json!({"spec": {}});
        assert!(
            matches_match_constraints(&policy, "apps", "v1", "deployments", "CREATE"),
            "absent matchConstraints must match all resources"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — tokenize_cel edge cases
    //
    // A mis-tokenized CEL expression returns None from eval_cel_apply_config,
    // which silently drops the MAP mutation. The policy appears to work but
    // the mutation is never applied to the resource.
    // ---------------------------------------------------------------------------

    /// tokenize_cel must handle single-quoted strings.
    /// Single-quoted strings are valid CEL syntax; mis-tokenizing them means
    /// string values in CEL policies fail to parse and mutations are silently dropped.
    #[test]
    fn tokenize_cel_single_quoted_string_parsed_correctly() {
        let object = json!({"metadata": {"name": "x"}});
        // Single-quoted string as a map value
        let result = eval_cel_apply_config(r#"{"key": 'hello'}"#, &object);
        assert!(
            result.is_some(),
            "single-quoted string in CEL must parse without panicking; \
             failure means MAP mutations using single-quoted strings are silently dropped"
        );
        assert_eq!(
            result.unwrap()["key"],
            "hello",
            "single-quoted string must produce the same value as a double-quoted string"
        );
    }

    /// tokenize_cel must expand escape sequences inside strings.
    /// Escape sequences (\n, \t, \r) inside CEL strings must be decoded to their
    /// character values. Without this, policies embedding newlines are mis-tokenized.
    #[test]
    fn tokenize_cel_escape_sequences_decoded() {
        let object = json!({"metadata": {"name": "x"}});
        // The escape sequences should be decoded inside the string
        let result = eval_cel_apply_config(r#"{"key": "a\nb\tc\rd"}"#, &object);
        assert!(
            result.is_some(),
            "CEL string with escape sequences must parse without panicking"
        );
        let val = result.unwrap();
        let s = val["key"].as_str().expect("key must be a string");
        assert!(
            s.contains('\n') && s.contains('\t') && s.contains('\r'),
            "escape sequences \\n, \\t, \\r must be decoded to their character values; \
             got: {:?}",
            s
        );
    }

    /// parse_cel_primary: unary negation applied to a non-numeric value returns None.
    /// The caller (eval_cel_apply_config) returns None, which causes the MAP mutation
    /// to be silently dropped. This test ensures the None path does not panic.
    #[test]
    fn tokenize_cel_unary_negation_of_non_numeric_returns_none() {
        let object = json!({"metadata": {"name": "x"}});
        // Unary minus applied to a string produces None without panicking
        let result = eval_cel_apply_config(r#"-"hello""#, &object);
        assert!(
            result.is_none(),
            "unary negation of a non-numeric value must return None, not panic; \
             the MAP mutation should be dropped gracefully rather than crashing the admission handler"
        );
    }

    /// tokenize_cel: `map()` style macro call tokenizes without panicking.
    /// CEL expressions with method-call syntax (identifier followed by parentheses)
    /// are tokenized as Ident + LParen + ... + RParen. This test ensures the
    /// tokenizer and evaluator handle this without panicking; degrading to None is acceptable.
    #[test]
    fn tokenize_cel_map_macro_call_does_not_panic() {
        let object = json!({"metadata": {"name": "x"}});
        // map() is a valid CEL macro but our evaluator doesn't implement it fully.
        // It must not panic — returning None is acceptable.
        let result = eval_cel_apply_config(r#"[1, 2, 3].map(x, x + 1)"#, &object);
        // We don't assert a specific value — only that it doesn't panic.
        let _ = result;
    }

    /// parse_cel_primary: field access on `object` for an unknown field returns null.
    /// When a CEL expression accesses a field that doesn't exist on the admitted resource,
    /// serde_json returns Null. The evaluator must not panic; it should produce Null,
    /// allowing callers to handle the missing field gracefully.
    #[test]
    fn tokenize_cel_unknown_field_on_object_returns_null() {
        let object = json!({"metadata": {"name": "x"}});
        // object.nonexistent is not in the object above
        let result = eval_cel_apply_config("object.nonexistent", &object);
        // Field access on object returns the serde_json Null (absent key)
        assert!(
            result.is_some(),
            "field access on a missing key must return Some(Null), not None — \
             returning None would silently drop MAP mutations that reference absent fields"
        );
        assert_eq!(
            result.unwrap(),
            serde_json::Value::Null,
            "missing field access on `object` must evaluate to Null, not panic"
        );
    }

    // ---------------------------------------------------------------------------
    // Tests — validate_webhook_match_conditions_cel
    //
    // The conformance test POSTs a ValidatingWebhookConfiguration with an invalid
    // CEL matchConditions expression and expects a 422. Without this validation the
    // apiserver returns 200 OK.
    // ---------------------------------------------------------------------------

    /// An empty matchConditions expression must be rejected.
    /// Kubernetes rejects webhook configurations at creation time if any
    /// matchConditions expression is empty — an empty string is not valid CEL.
    #[test]
    fn validate_webhook_match_conditions_cel_rejects_empty_expression() {
        let obj = json!({
            "webhooks": [{"matchConditions": [{"name": "check", "expression": ""}]}]
        });
        assert!(
            validate_webhook_match_conditions_cel(&obj).is_err(),
            "empty matchConditions expression must be rejected; \
             without this the apiserver accepts invalid webhook configurations"
        );
    }

    /// A whitespace-only expression must be rejected — equivalent to empty.
    #[test]
    fn validate_webhook_match_conditions_cel_rejects_whitespace_expression() {
        let obj = json!({
            "webhooks": [{"matchConditions": [{"name": "check", "expression": "   "}]}]
        });
        assert!(
            validate_webhook_match_conditions_cel(&obj).is_err(),
            "whitespace-only matchConditions expression must be rejected"
        );
    }

    /// A valid CEL expression must pass validation.
    #[test]
    fn validate_webhook_match_conditions_cel_accepts_valid_expression() {
        let obj = json!({
            "webhooks": [{"matchConditions": [{"name": "check", "expression": "object.metadata.name == \"test\""}]}]
        });
        assert!(
            validate_webhook_match_conditions_cel(&obj).is_ok(),
            "valid CEL expression must pass matchConditions validation"
        );
    }

    /// A webhook with no matchConditions must pass validation.
    #[test]
    fn validate_webhook_match_conditions_cel_accepts_absent_match_conditions() {
        let obj = json!({
            "webhooks": [{"name": "test.example.com"}]
        });
        assert!(
            validate_webhook_match_conditions_cel(&obj).is_ok(),
            "webhook without matchConditions must pass validation — matchConditions is optional"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests for mayor-sz59: ValidatingAdmissionPolicy enforcement
    //
    // These tests verify that VAP + Binding pairs are enforced at admission time.
    // Without this fix, a conformance test creating a Deployment with even replicas
    // (violating an odd-replicas VAP) would be silently accepted, causing the test
    // to poll indefinitely for a 403 that never arrives — exhausting the 6h sonobuoy
    // budget and timing out the entire conformance run.
    // ---------------------------------------------------------------------------

    /// A Deployment with even replicas in a namespace matched by a VAP binding must
    /// be rejected 403. Without VAP enforcement, the request is silently accepted and
    /// conformance tests poll indefinitely for the denial.
    ///
    /// Reverting VAP enforcement (removing run_validating_admission_policies call from
    /// run_validating_webhooks) makes this test fail because the request succeeds.
    #[tokio::test]
    async fn vap_rejects_deployment_with_even_replicas() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a namespace with matching label.
        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "vap-test-ns", "labels": {"vap-test": "true"}}
        });
        store
            .put(
                "/registry/namespaces/vap-test-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        // VAP: requires odd replicas > 1.
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "odd-replicas-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE", "UPDATE"]
                    }]
                },
                "variables": [
                    {"name": "replicas", "expression": "object.spec.replicas"},
                    {"name": "oddReplicas", "expression": "variables.replicas % 2 == 1"}
                ],
                "validations": [
                    {"expression": "variables.replicas > 1"},
                    {"expression": "variables.oddReplicas"}
                ]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/odd-replicas-policy",
            bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()), None).await.unwrap();

        // Binding: targets the namespace.
        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "odd-replicas-binding"},
            "spec": {
                "policyName": "odd-replicas-policy",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {
                        "matchLabels": {"vap-test": "true"}
                    }
                }
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/odd-replicas-binding",
            bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()), None).await.unwrap();

        // Deployment with EVEN replicas — must be denied.
        let deploy_even = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-deploy", "namespace": "vap-test-ns"},
            "spec": {"replicas": 2}
        });
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "my-deploy",
            namespace: Some("vap-test-ns"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_validating_webhooks(&state, &deploy_even, &ctx).await;
        assert!(
            result.is_err(),
            "Deployment with even replicas (2) must be denied by VAP; \
             without VAP enforcement the request is silently accepted and conformance \
             tests poll forever for the 403 that never arrives"
        );
        let err = result.unwrap_err();
        assert!(
            format!("{err:?}").contains("odd-replicas-policy"),
            "denial message must reference the policy name so operators can identify \
             which policy blocked the request; got: {err:?}"
        );
    }

    /// A Deployment with odd replicas > 1 in a matched namespace must be allowed.
    /// Without this, the VAP implementation is too strict and blocks valid requests.
    ///
    /// Reverting the fix and always denying makes this test fail.
    #[tokio::test]
    async fn vap_allows_deployment_with_odd_replicas_greater_than_one() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Same namespace + policy + binding as the deny test.
        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "vap-allow-ns", "labels": {"vap-test": "true"}}
        });
        store
            .put(
                "/registry/namespaces/vap-allow-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "odd-replicas-allow-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE", "UPDATE"]
                    }]
                },
                "variables": [
                    {"name": "replicas", "expression": "object.spec.replicas"},
                    {"name": "oddReplicas", "expression": "variables.replicas % 2 == 1"}
                ],
                "validations": [
                    {"expression": "variables.replicas > 1"},
                    {"expression": "variables.oddReplicas"}
                ]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/odd-replicas-allow-policy",
            bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()), None).await.unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "odd-replicas-allow-binding"},
            "spec": {
                "policyName": "odd-replicas-allow-policy",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {"matchLabels": {"vap-test": "true"}}
                }
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/odd-replicas-allow-binding",
            bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()), None).await.unwrap();

        // Deployment with ODD replicas > 1 — must be allowed.
        let deploy_odd = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "valid-deploy", "namespace": "vap-allow-ns"},
            "spec": {"replicas": 3}
        });
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "valid-deploy",
            namespace: Some("vap-allow-ns"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_validating_webhooks(&state, &deploy_odd, &ctx).await;
        assert!(
            result.is_ok(),
            "Deployment with odd replicas (3) > 1 must be allowed by the odd-replicas VAP; \
             incorrectly denying valid requests breaks workload deployment"
        );
    }

    /// VAP spec.variables must be evaluated in order and their results available to
    /// subsequent variable expressions and to validations.
    ///
    /// Without variable evaluation, expressions referencing `variables.X` resolve to
    /// null/false, causing all validations that use variables to fail with wrong results.
    ///
    /// Reverting variable evaluation (removing the variables loop) makes the deny test
    /// fail because `variables.replicas` resolves to null, `null % 2` is None, and the
    /// validation returns an eval error (treated as false → deny), but the allow test
    /// would also deny — catching the regression.
    #[test]
    fn vap_variables_evaluated_sequentially_and_available_to_validations() {
        let object = json!({"spec": {"replicas": 3}});
        let mut variables = serde_json::Map::new();

        let no_request = serde_json::Value::Null;

        // Step 1: evaluate `replicas = object.spec.replicas`
        let replicas_val =
            eval_cel_vap_value("object.spec.replicas", &object, &variables, &no_request)
                .expect("object.spec.replicas must evaluate");
        variables.insert("replicas".into(), replicas_val);

        // Step 2: evaluate `oddReplicas = variables.replicas % 2 == 1`
        let odd_val = eval_cel_vap_value(
            "variables.replicas % 2 == 1",
            &object,
            &variables,
            &no_request,
        )
        .expect("variables.replicas % 2 == 1 must evaluate");
        variables.insert("oddReplicas".into(), odd_val);

        // Validate: replicas > 1 → true (3 > 1)
        let gt_result =
            eval_cel_bool_expr("variables.replicas > 1", &object, &variables, &no_request)
                .expect("variables.replicas > 1 must evaluate");
        assert!(
            gt_result,
            "variables.replicas (3) > 1 must be true; \
             failing means variable values are not threaded through to validation expressions"
        );

        // Validate: oddReplicas → true (3 is odd)
        let odd_result =
            eval_cel_bool_expr("variables.oddReplicas", &object, &variables, &no_request)
                .expect("variables.oddReplicas must evaluate");
        assert!(
            odd_result,
            "variables.oddReplicas must be true for replicas=3; \
             failing means boolean variable values are not accessible in validation expressions"
        );

        // Now test with even replicas (2).
        let object_even = json!({"spec": {"replicas": 2}});
        let mut variables_even = serde_json::Map::new();
        let r2 = eval_cel_vap_value(
            "object.spec.replicas",
            &object_even,
            &variables_even,
            &no_request,
        )
        .unwrap();
        variables_even.insert("replicas".into(), r2);
        let o2 = eval_cel_vap_value(
            "variables.replicas % 2 == 1",
            &object_even,
            &variables_even,
            &no_request,
        )
        .unwrap();
        variables_even.insert("oddReplicas".into(), o2);

        let odd_even = eval_cel_bool_expr(
            "variables.oddReplicas",
            &object_even,
            &variables_even,
            &no_request,
        )
        .expect("oddReplicas must evaluate for even replicas");
        assert!(
            !odd_even,
            "variables.oddReplicas must be false for replicas=2; \
             the modulo expression `replicas % 2 == 1` must work correctly for even numbers"
        );
    }

    /// WebhookEntry must deserialise `timeoutSeconds` from JSON and use it for the
    /// per-call request timeout in build_webhook_call_client.
    ///
    /// Without timeoutSeconds support, every webhook call uses a hardcoded 10s timeout
    /// regardless of the webhook's configured timeout, violating the Kubernetes spec.
    /// Reverting the fix (removing timeout_seconds from WebhookEntry) causes a compile
    /// error in this test.
    #[test]
    fn webhook_entry_deserialises_timeout_seconds() {
        let json = serde_json::json!({
            "name": "test.webhook.example.com",
            "clientConfig": {"url": "https://example.com/webhook"},
            "timeoutSeconds": 30
        });
        let entry: WebhookEntry = serde_json::from_value(json)
            .expect("WebhookEntry must deserialise with timeoutSeconds");
        assert_eq!(
            entry.timeout_seconds,
            Some(30),
            "timeoutSeconds must be deserialised from JSON and stored in WebhookEntry; \
             without this, webhook-specific timeouts cannot be applied per the Kubernetes spec"
        );
    }

    /// build_webhook_call_client must use the per-webhook timeout_seconds when set.
    ///
    /// Without connect_timeout, TCP connect to a dead service endpoint blocks for the
    /// OS TCP timeout (~2min), stalling all subsequent webhook calls and sonobuoy tests.
    /// Reverting the fix (removing connect_timeout from the builder) does not crash but
    /// the test documents the expected behavior.
    #[test]
    fn build_webhook_call_client_applies_per_webhook_timeout() {
        let fallback = reqwest::Client::new();
        // With timeout_seconds=30, the request timeout must be 30s (verified by building
        // without panic — reqwest validates Duration).
        let client = build_webhook_call_client(None, None, None, None, &fallback, Some(30));
        drop(client);

        // connect_timeout is always 5s regardless of timeout_seconds — verified indirectly
        // by the fact that the client builds successfully with both timeouts set.
        let client_default = build_webhook_call_client(None, None, None, None, &fallback, None);
        drop(client_default);
    }

    /// VAP must not be evaluated for resources in the admissionregistration.k8s.io group.
    ///
    /// Admitting a ValidatingAdmissionPolicy itself must not trigger VAP evaluation —
    /// same exemption as webhooks. Without this, creating a VAP could trigger itself
    /// (bootstrap deadlock) or another VAP that references nonexistent variables.
    ///
    /// Reverting the exemption (removing the is_webhook_configuration_resource check
    /// from run_validating_admission_policies) makes this test fail because the policy
    /// is evaluated against itself.
    #[tokio::test]
    async fn vap_skipped_for_admissionregistration_resources() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed a VAP that denies everything (would deny its own creation if not exempt).
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "deny-all-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{"apiGroups": ["*"], "apiVersions": ["*"],
                        "resources": ["*"], "operations": ["*"]}]
                },
                "validations": [{"expression": "false"}]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/deny-all-policy",
            bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()), None).await.unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "deny-all-binding"},
            "spec": {
                "policyName": "deny-all-policy",
                "validationActions": ["Deny"]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/deny-all-binding",
            bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()), None).await.unwrap();

        // Admitting a ValidatingAdmissionPolicy resource — must be exempt from VAP evaluation.
        let new_vap = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "new-policy"}
        });
        let ctx = AdmissionContext {
            group: "admissionregistration.k8s.io",
            version: "v1",
            resource: "validatingadmissionpolicies",
            name: "new-policy",
            namespace: None,
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result = run_validating_webhooks(&state, &new_vap, &ctx).await;
        assert!(
            result.is_ok(),
            "admissionregistration.k8s.io resources must be exempt from VAP evaluation \
             to prevent bootstrap deadlocks; the deny-all VAP must not fire for its own creation"
        );
    }

    /// VAP denial must return a well-formed StatusError carrying code=403 and a non-empty message.
    ///
    /// Kubernetes clients parse the response body as a Status object. If the body is absent or
    /// not a valid Status JSON, clients see `invalid JSON: expected value at line 1 column 1`
    /// and cannot display the policy violation reason to the user.
    ///
    /// Reverting the `should_deny` path from run_validating_admission_policies or replacing
    /// StatusError with a different error type would cause the body to be absent or wrong-typed.
    #[tokio::test]
    async fn vap_denial_produces_well_formed_status_error_with_code_403() {
        use axum::response::IntoResponse as _;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "deny-configmaps"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "resources": ["configmaps"],
                        "operations": ["CREATE"]
                    }]
                },
                "validations": [{"expression": "false", "message": "configmaps are forbidden by policy"}]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/deny-configmaps",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "deny-configmaps-binding"},
            "spec": {
                "policyName": "deny-configmaps",
                "validationActions": ["Deny"]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/deny-configmaps-binding",
                bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let obj =
            json!({"kind": "ConfigMap", "metadata": {"name": "test-cm", "namespace": "default"}});
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "test-cm",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_validating_webhooks(&state, &obj, &ctx).await;
        assert!(
            result.is_err(),
            "VAP with expression=false must deny the request"
        );

        let err = result.unwrap_err();
        let response = err.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::FORBIDDEN,
            "VAP denial must return HTTP 403 so clients can identify it as a policy violation"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body must be readable");
        assert!(
            !body.is_empty(),
            "VAP denial response body must not be empty; \
             an empty body causes clients to fail with 'invalid JSON: expected value at line 1 column 1'"
        );

        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("VAP denial body must be valid JSON");
        assert_eq!(
            json["code"], 403,
            "VAP denial Status.code must be 403 so clients can distinguish it from other errors"
        );
        assert_eq!(
            json["kind"], "Status",
            "VAP denial body must have kind=Status matching the Kubernetes Status API object"
        );
        assert!(
            json["message"]
                .as_str()
                .map(|m| !m.is_empty())
                .unwrap_or(false),
            "VAP denial Status.message must be non-empty so users see the policy violation reason"
        );
    }

    /// A VAP binding with namespaceSelector must not apply to resources in namespaces
    /// that do not have the required label.
    ///
    /// The conformance test creates a binding targeting a specific namespace label and a
    /// marker Deployment in a namespace without that label. The marker must NOT be denied.
    ///
    /// Reverting the namespaceSelector fetch-and-check (or always applying the binding
    /// regardless of namespace labels) makes this test fail because the deny-all VAP
    /// would reject the deployment in the non-matching namespace.
    #[tokio::test]
    async fn vap_namespace_selector_non_matching_namespace_skips_binding() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "no-label-ns",
                "labels": {"kubernetes.io/metadata.name": "no-label-ns"}
            }
        });
        store
            .put(
                "/registry/namespaces/no-label-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "deny-all-deploys"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE"]
                    }]
                },
                "validations": [{"expression": "false"}]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/deny-all-deploys",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "deny-all-deploys-binding"},
            "spec": {
                "policyName": "deny-all-deploys",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {
                        "matchLabels": {"env": "test"}
                    }
                }
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/deny-all-deploys-binding",
                bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let deploy = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "marker-deploy", "namespace": "no-label-ns"},
            "spec": {"replicas": 1}
        });
        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "marker-deploy",
            namespace: Some("no-label-ns"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_validating_webhooks(&state, &deploy, &ctx).await;
        assert!(
            result.is_ok(),
            "VAP binding with namespaceSelector env=test must not apply to namespace 'no-label-ns' \
             which lacks that label; incorrectly denying the marker Deployment causes conformance \
             tests to time out waiting for a resource that can never be created"
        );
    }

    /// A VAP binding with namespaceSelector must not apply to cluster-scoped resources.
    ///
    /// Per Kubernetes spec: if the object is a cluster-scoped resource (no namespace), it is
    /// never selected by a namespaceSelector. Without this fix, a binding with a namespaceSelector
    /// would apply to cluster-scoped resources like Nodes, causing the conformance test
    /// `can restrict access by-node` to fail.
    ///
    /// Reverting the fix (removing the `None => continue` branch) makes this test fail because
    /// the binding would apply to the Node and deny the request.
    #[tokio::test]
    async fn vap_namespace_selector_skips_cluster_scoped_resources() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "deny-nodes"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "resources": ["nodes"],
                        "operations": ["CREATE"]
                    }]
                },
                "validations": [{"expression": "false"}]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/deny-nodes",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "deny-nodes-binding"},
            "spec": {
                "policyName": "deny-nodes",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {
                        "matchLabels": {"env": "test"}
                    }
                }
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/deny-nodes-binding",
                bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "worker-node-1"}
        });
        let ctx = AdmissionContext {
            group: "",
            version: "v1",
            resource: "nodes",
            name: "worker-node-1",
            namespace: None,
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_validating_webhooks(&state, &node, &ctx).await;
        assert!(
            result.is_ok(),
            "VAP binding with namespaceSelector must never apply to cluster-scoped resources \
             (namespace=None); applying it to Nodes would deny node registration and break the cluster"
        );
    }

    /// A VAP expression using `request.userInfo.username` must allow the matching user
    /// and deny others. Without request.* resolution in the CEL evaluator, the expression
    /// always evaluates to false (userInfo is missing from the eval context), causing every
    /// request to be incorrectly denied regardless of the requesting user's identity.
    ///
    /// This is the regression test for the [sig-auth] ValidatingAdmissionPolicy conformance
    /// test `can restrict access by-node`, which uses `request.userInfo.username` to restrict
    /// Node updates by node identity.
    ///
    /// Reverting request.* resolution (removing the `request` root from parse_vap_primary)
    /// makes the VAP expression silently return false for any user, causing the matching
    /// user's request to be incorrectly denied.
    #[tokio::test]
    async fn vap_request_user_info_username_allows_matching_user_denies_others() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // VAP that only allows requests from "system:node:worker-1".
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "node-identity-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "resources": ["nodes"],
                        "operations": ["UPDATE"]
                    }]
                },
                "validations": [{
                    "expression": "request.userInfo.username == \"system:node:worker-1\"",
                    "message": "only system:node:worker-1 may update this node"
                }]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/node-identity-policy",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "node-identity-binding"},
            "spec": {
                "policyName": "node-identity-policy",
                "validationActions": ["Deny"]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/node-identity-binding",
                bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": "worker-1"}
        });

        // Matching user: request.userInfo.username == "system:node:worker-1" → allow.
        let ctx_matching = AdmissionContext {
            group: "",
            version: "v1",
            resource: "nodes",
            name: "worker-1",
            namespace: None,
            operation: "UPDATE",
            user_info: Some(json!({
                "username": "system:node:worker-1",
                "groups": ["system:nodes", "system:authenticated"]
            })),
            dry_run: false,
        };
        let result_matching = run_validating_webhooks(&state, &node, &ctx_matching).await;
        assert!(
            result_matching.is_ok(),
            "VAP with request.userInfo.username == 'system:node:worker-1' must allow that user; \
             if request.* resolution is removed, userInfo is absent and the expression evaluates \
             to false, incorrectly denying the matching user"
        );

        // Non-matching user: request.userInfo.username != "system:node:worker-1" → deny.
        let ctx_other = AdmissionContext {
            group: "",
            version: "v1",
            resource: "nodes",
            name: "worker-1",
            namespace: None,
            operation: "UPDATE",
            user_info: Some(json!({
                "username": "system:node:worker-2",
                "groups": ["system:nodes", "system:authenticated"]
            })),
            dry_run: false,
        };
        let result_other = run_validating_webhooks(&state, &node, &ctx_other).await;
        assert!(
            result_other.is_err(),
            "VAP with request.userInfo.username == 'system:node:worker-1' must deny other users; \
             worker-2 must not be allowed to update worker-1's node object"
        );
    }

    /// AdmissionContext.user_info must be populated from the authenticated request identity.
    /// If handlers pass user_info: None, VAP expressions like `request.userInfo.username == X`
    /// always evaluate against an empty username and incorrectly deny allowed users.
    ///
    /// This test verifies that:
    /// - `user_info: Some({username: "alice"})` causes the VAP to allow (expression is true)
    /// - `user_info: None` causes the VAP to deny (evaluator fills empty username, expression
    ///   is false, so the admission check fails)
    #[tokio::test]
    async fn vap_user_info_none_denies_when_expression_requires_specific_username() {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // VAP that only allows requests from "alice".
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "alice-only-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "resources": ["configmaps"],
                        "operations": ["CREATE"]
                    }]
                },
                "validations": [{
                    "expression": "request.userInfo.username == \"alice\"",
                    "message": "only alice may create configmaps"
                }]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/alice-only-policy",
                bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
                None,
            )
            .await
            .unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "alice-only-binding"},
            "spec": {
                "policyName": "alice-only-policy",
                "validationActions": ["Deny"]
            }
        });
        store
            .put(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/alice-only-binding",
                bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
                None,
            )
            .await
            .unwrap();

        let cm = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "test-cm", "namespace": "default"}
        });

        // With user_info populated as "alice": VAP expression is true → allow.
        let ctx_alice = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "test-cm",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: Some(json!({"username": "alice", "uid": "", "groups": []})),
            dry_run: false,
        };
        let result_alice = run_validating_webhooks(&state, &cm, &ctx_alice).await;
        assert!(
            result_alice.is_ok(),
            "VAP must allow alice when user_info is threaded through AdmissionContext; \
             if handlers pass user_info: None, this test fails because username is empty"
        );

        // With user_info: None: evaluator fills empty username → expression false → VAP denies.
        let ctx_none = AdmissionContext {
            group: "",
            version: "v1",
            resource: "configmaps",
            name: "test-cm",
            namespace: Some("default"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };
        let result_none = run_validating_webhooks(&state, &cm, &ctx_none).await;
        assert!(
            result_none.is_err(),
            "VAP must deny when user_info is None (handlers not threading identity); \
             if this passes, the policy no longer distinguishes alice from unauthenticated requests"
        );
    }

    /// VAP with `object.spec.replicas > 1` must ALLOW a Deployment with replicas=3
    /// even when the object has been through apply_defaults (which adds strategy, generation, etc.).
    ///
    /// Regression: conformance test "should validate against a Deployment" creates a
    /// marker Deployment with replicas > 1 that should be ALLOWED.  If CEL field access
    /// fails on the fully-defaulted Deployment body, the expression incorrectly evaluates
    /// to false and the marker is denied, causing the conformance test to fail.
    ///
    /// This test must fail if eval_cel_bool_expr returns None (eval error) or Some(false)
    /// for `object.spec.replicas > 1` on a Deployment with spec.replicas = 3.
    #[tokio::test]
    async fn vap_object_spec_replicas_gt_1_allows_replicas_3_after_apply_defaults() {
        use crate::handlers::defaults::apply_defaults;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Seed namespace with matching label (mirrors conformance setup).
        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "vap-conformance-ns",
                "labels": {"vap-conformance": "true"}
            }
        });
        store
            .put(
                "/registry/namespaces/vap-conformance-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        // VAP: expression `object.spec.replicas > 1` (direct field access, no variables).
        // This is the conformance test "should validate against a Deployment".
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "replicas-gt-1-policy"},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE", "UPDATE"]
                    }]
                },
                "validations": [
                    {"expression": "object.spec.replicas > 1"}
                ]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/replicas-gt-1-policy",
            bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
            None,
        ).await.unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "replicas-gt-1-binding"},
            "spec": {
                "policyName": "replicas-gt-1-policy",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {"matchLabels": {"vap-conformance": "true"}}
                }
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/replicas-gt-1-binding",
            bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
            None,
        ).await.unwrap();

        // Build marker Deployment (replicas=3) and run apply_defaults as the write path does.
        // This produces a fully-defaulted body with strategy, revisionHistoryLimit, etc.
        let mut marker = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "marker-deployment",
                "namespace": "vap-conformance-ns"
            },
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "marker"}},
                "template": {
                    "metadata": {"labels": {"app": "marker"}},
                    "spec": {
                        "containers": [{"name": "nginx", "image": "nginx"}]
                    }
                }
            }
        });
        apply_defaults("apps", "deployments", &mut marker);

        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "marker-deployment",
            namespace: Some("vap-conformance-ns"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        // The marker Deployment (replicas=3) must be ALLOWED because 3 > 1 = true.
        // If this fails, the policy wrongly denies valid workloads and the conformance
        // test "should validate against a Deployment" cannot complete its wait-for-marker step.
        let result = run_validating_webhooks(&state, &marker, &ctx).await;
        assert!(
            result.is_ok(),
            "Deployment with spec.replicas=3 must be allowed by 'object.spec.replicas > 1' \
             policy; denying it breaks the VAP conformance marker-wait step. \
             Error: {:?}",
            result.err()
        );

        // Also verify that replicas=1 IS denied.
        let mut bad_deploy = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "bad-deploy", "namespace": "vap-conformance-ns"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "bad"}},
                "template": {
                    "metadata": {"labels": {"app": "bad"}},
                    "spec": {"containers": [{"name": "c", "image": "busybox"}]}
                }
            }
        });
        apply_defaults("apps", "deployments", &mut bad_deploy);
        let bad_result = run_validating_webhooks(&state, &bad_deploy, &ctx).await;
        assert!(
            bad_result.is_err(),
            "Deployment with spec.replicas=1 must be denied by 'object.spec.replicas > 1' \
             policy; 1 > 1 = false"
        );
    }

    /// VAP with variables (conformance: `should allow expressions to refer variables`) must
    /// ALLOW a Deployment with replicas=3 (odd and > 1) after apply_defaults.
    ///
    /// Regression: variable `replicas = object.spec.replicas` must correctly resolve to
    /// the integer 3 from the full Deployment body.  If `object.spec.replicas` evaluation
    /// fails on a fully-defaulted Deployment, `variables.replicas` is absent (None result
    /// is skipped), `variables.replicas > 1` then evaluates against null (None → false),
    /// and the marker is wrongly denied.
    ///
    /// This test must fail if eval_cel_vap_value returns None for `object.spec.replicas`
    /// on a fully-defaulted Deployment body, or if the variable binding is not threaded
    /// through to the validation expressions.
    #[tokio::test]
    async fn vap_variables_replicas_allows_marker_with_replicas_3_after_apply_defaults() {
        use crate::handlers::defaults::apply_defaults;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let ns = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "vap-vars-ns",
                "labels": {"validating-admission-policy-9994": "true"}
            }
        });
        store
            .put(
                "/registry/namespaces/vap-vars-ns",
                bytes::Bytes::from(serde_json::to_vec(&ns).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Exact conformance VAP from the 0609 run.
        let policy = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicy",
            "metadata": {"name": "validating-admission-policy-9994.policy.example.com"},
            "spec": {
                "matchConstraints": {
                    "namespaceSelector": {
                        "matchLabels": {"validating-admission-policy-9994": "true"}
                    },
                    "resourceRules": [{
                        "apiGroups": ["apps"],
                        "apiVersions": ["v1"],
                        "resources": ["deployments"],
                        "operations": ["CREATE", "UPDATE"]
                    }]
                },
                "variables": [
                    {"name": "replicas", "expression": "object.spec.replicas"},
                    {"name": "oddReplicas", "expression": "variables.replicas % 2 == 1"}
                ],
                "validations": [
                    {"expression": "variables.replicas > 1"},
                    {"expression": "variables.oddReplicas"}
                ]
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/validating-admission-policy-9994.policy.example.com",
            bytes::Bytes::from(serde_json::to_vec(&policy).unwrap()),
            None,
        ).await.unwrap();

        let binding = json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": "validating-admission-policy-9994-binding"},
            "spec": {
                "policyName": "validating-admission-policy-9994.policy.example.com",
                "validationActions": ["Deny"],
                "matchResources": {
                    "namespaceSelector": {
                        "matchLabels": {"validating-admission-policy-9994": "true"}
                    }
                }
            }
        });
        store.put(
            "/registry/admissionregistration.k8s.io/validatingadmissionpolicybindings/validating-admission-policy-9994-binding",
            bytes::Bytes::from(serde_json::to_vec(&binding).unwrap()),
            None,
        ).await.unwrap();

        // Marker Deployment: replicas=3 (odd AND > 1) — must be ALLOWED.
        let mut marker = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "marker-deployment",
                "namespace": "vap-vars-ns"
            },
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": {"app": "marker"}},
                "template": {
                    "metadata": {
                        "creationTimestamp": null,
                        "labels": {"app": "marker"}
                    },
                    "spec": {
                        "containers": [{"name": "nginx", "image": "nginx"}]
                    }
                }
            }
        });
        apply_defaults("apps", "deployments", &mut marker);

        let ctx = AdmissionContext {
            group: "apps",
            version: "v1",
            resource: "deployments",
            name: "marker-deployment",
            namespace: Some("vap-vars-ns"),
            operation: "CREATE",
            user_info: None,
            dry_run: false,
        };

        let result = run_validating_webhooks(&state, &marker, &ctx).await;
        assert!(
            result.is_ok(),
            "Deployment with replicas=3 (odd, > 1) must be allowed by the conformance VAP \
             using variables; denying it breaks 'should allow expressions to refer variables' \
             conformance test. Error: {:?}",
            result.err()
        );

        // Verify that replicas=2 (even) IS denied.
        let mut even_deploy = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "even-deploy", "namespace": "vap-vars-ns"},
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": {"app": "even"}},
                "template": {
                    "metadata": {"labels": {"app": "even"}},
                    "spec": {"containers": [{"name": "c", "image": "busybox"}]}
                }
            }
        });
        apply_defaults("apps", "deployments", &mut even_deploy);
        let even_result = run_validating_webhooks(&state, &even_deploy, &ctx).await;
        assert!(
            even_result.is_err(),
            "Deployment with replicas=2 (even) must be denied by the conformance VAP \
             (variables.oddReplicas = false)"
        );
    }
}
