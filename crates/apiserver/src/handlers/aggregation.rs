/// API aggregation: proxy requests for an `APIService`-registered group/version to its
/// `spec.service` backend, and track backend health in `status.conditions[type=Available]`.
///
/// Real kube-apiserver's aggregation layer has two pieces:
///   1. A dynamic proxy handler for `/apis/{group}/{version}/*` that forwards to the
///      backend, presenting a dedicated proxy-client certificate the backend trusts via
///      `requestheader-client-ca-file` (populated from the extension-apiserver-authentication
///      configmap). u7s does not populate that configmap with real CA data (the lookup is
///      only made to *tolerate* 404 instead of crashing), so an aggregated
///      backend such as sample-apiserver falls back to its other configured authenticator:
///      delegated TokenReview against this apiserver. This proxy therefore forwards the
///      caller's own Authorization header unchanged instead of minting an impersonation
///      identity — the backend authenticates the original caller itself.
///   2. An availability controller that periodically health-checks the backend and sets
///      `status.conditions[type=Available]`. u7s runs this as a fixed-interval sweep
///      (`reconcile_apiservice_availability`, spawned once in main.rs) rather than a full
///      informer/workqueue controller: this is a single-writer, pre-alpha apiserver with no
///      leader-election machinery to hook a real controller into, and conformance only
///      observes `status.conditions` well after the sweep interval has had time to run, so
///      the simpler polling loop is sufficient and easier to reason about.
///
/// Backend resolution reuses the exact "service DNS name + konnectivity proxy" pattern
/// already proven for admission webhooks (see `admission.rs`'s `webhook_url` /
/// `build_webhook_call_client`, PR #406): the URL targets `{svc}.{ns}.svc:{port}` and kube-proxy
/// running inside the VM NATs `ClusterIP:svcPort -> PodIP:targetPort`, so u7s never needs to
/// resolve a pod IP or target port itself — sidestepping the endpoint-slice controller's
/// existing target-port simplification (it copies the Service port verbatim; see
/// `endpoint_slice_controller.rs`), which would otherwise resolve to the wrong port whenever
/// `spec.service.port` differs from the backend's actual listening port (as it does here:
/// APIService port 7443 vs. the sample-apiserver's port 443).
use axum::{
    body::Body,
    extract::State,
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::keys::group_list_prefix;
use crate::state::AppState;
use crate::status::Status;

const APISERVICE_GROUP: &str = "apiregistration.k8s.io";
const APISERVICE_PLURAL: &str = "apiservices";

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Split `/apis/{group}/{version}[/tail]` into (group, version, tail).
///
/// Returns `None` for anything that isn't at least a group+version pair — this
/// excludes `/apis`, `/apis/`, and `/apis/{group}` (bare group discovery, which must be
/// synthesized locally from every matching `APIService` rather than proxied, because a
/// single group can span multiple versions backed by different services).
pub fn parse_apis_path(path: &str) -> Option<(&str, &str, &str)> {
    let rest = path.strip_prefix("/apis/")?;
    let mut parts = rest.splitn(3, '/');
    let group = parts.next().filter(|s| !s.is_empty())?;
    let version = parts.next().filter(|s| !s.is_empty())?;
    let tail = parts.next().unwrap_or("");
    Some((group, version, tail))
}

// ---------------------------------------------------------------------------
// APIService lookup
// ---------------------------------------------------------------------------

/// Look up the `APIService` named `{version}.{group}`, if any.
///
/// Reads `AppState::apiservice_cache` when warm, falling back to a direct store lookup only
/// when the cache is cold (first use, or a test that seeds the store directly without going
/// through the write handlers in `handlers/resource.rs`). This runs on every
/// `/apis/{group}/{version}/...` request via `proxy_middleware` — including every request for
/// a built-in or CRD-backed group, which never has a matching `APIService` — so avoiding the
/// store round-trip on that common case matters for all non-core apiserver traffic, not just
/// requests that actually hit an aggregated backend. See `ApiServiceCache` for the
/// write-through invalidation that keeps this cache correct.
pub async fn find_apiservice<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
) -> Option<serde_json::Value> {
    let name = format!("{version}.{group}");
    let cached = {
        let guard = state.apiservice_cache.apiservices.read().unwrap();
        guard.as_ref().cloned()
    };
    if let Some(map) = cached {
        return map.get(&name).cloned();
    }
    let key = crate::keys::group_object_key(APISERVICE_GROUP, APISERVICE_PLURAL, None, &name);
    let stored = state.store.get(&key).await.ok().flatten()?;
    serde_json::from_slice(&stored.value).ok()
}

/// Build the backend base URL (`https://{svc}.{ns}.svc:{port}`) from `spec.service`.
///
/// Returns `Ok(None)` when `spec.service` is absent, null, or missing its `name`/`namespace`
/// keys — a "local" `APIService` (the shape real kube-apiserver uses for CRD- and
/// built-in-backed groups), or simply an incomplete one. u7s never creates these itself,
/// but a user could `PUT` one by hand; treating it as "nothing to proxy to" (rather than
/// erroring) lets the caller fall back to normal CRD/built-in routing instead of hijacking
/// a group it has no way to actually serve.
///
/// Returns `Err` when `name`/`namespace` are present but fail `validate_name` (e.g. contain
/// `/` or `..`). Without this check, a crafted `spec.service.namespace` such as
/// `"ns/evil.example.com"` would break the intended host out of the URL authority (built
/// via a bare `format!`), redirecting the connection — and the caller's live bearer token,
/// which `proxy_to_backend` forwards unchanged — to an attacker-controlled destination.
/// Mirrors `admission.rs`'s `validate_service_reference`, which guards the identical
/// Service-DNS-URL construction for webhook `clientConfig.service` references; registering
/// an `APIService` requires the same cluster-admin-tier privilege as webhook configs, so
/// this is a defense against a privileged actor harvesting *other* callers' credentials,
/// not a low-privilege escalation.
fn backend_base_url(apiservice: &serde_json::Value) -> Result<Option<String>, String> {
    let Some(svc) = apiservice.get("spec").and_then(|s| s.get("service")) else {
        return Ok(None);
    };
    if svc.is_null() {
        return Ok(None);
    }
    let Some(name) = svc.get("name").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let Some(namespace) = svc.get("namespace").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    crate::handlers::generic::validate_name("spec.service.name", name).map_err(|e| e.1.message)?;
    crate::handlers::generic::validate_name("spec.service.namespace", namespace)
        .map_err(|e| e.1.message)?;
    let port = svc.get("port").and_then(|p| p.as_i64()).unwrap_or(443);
    Ok(Some(format!("https://{name}.{namespace}.svc:{port}")))
}

/// Build a `reqwest::Client` trusting `spec.caBundle` (or accepting any certificate when
/// `spec.insecureSkipTLSVerify` is set), routed through konnectivity when configured.
///
/// Mirrors `admission.rs`'s `build_webhook_call_client` for the identical problem: the
/// aggregated backend is reachable only from inside the VM's pod network. Two details
/// carried over from there, both load-bearing (confirmed by hand against a live backend —
/// omitting either makes every proxied call fail the *outer* TLS handshake to konnectivity,
/// before ever reaching the backend, which otherwise looks identical to the backend itself
/// being unreachable):
///   - `cluster_ca_der` must be trusted *alongside* `spec.caBundle`: konnectivity-server's
///     own serving certificate is signed by the cluster CA, not by the APIService's
///     backend-specific CA, and `tls_certs_only` replaces the trust store rather than
///     extending it.
///   - `webhook_identity_pem` (the apiserver's own mTLS identity) must be presented:
///     konnectivity-server requires client-cert authentication from callers.
fn build_backend_client<S: Store>(
    state: &AppState<S>,
    spec: &serde_json::Value,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5));

    let insecure = spec
        .get("insecureSkipTLSVerify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    } else {
        let mut certs = Vec::new();
        if let Some(ca_b64) = spec.get("caBundle").and_then(|v| v.as_str()) {
            if let Ok(pem) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ca_b64)
            {
                if let Ok(cert) = reqwest::Certificate::from_pem(&pem) {
                    certs.push(cert);
                }
            }
        }
        if let Some(der) = state.cluster_ca_der.as_deref() {
            if let Ok(cluster_cert) = reqwest::Certificate::from_der(der) {
                certs.push(cluster_cert);
            }
        }
        if !certs.is_empty() {
            builder = builder.tls_certs_only(certs);
        }
    }

    if let Some(pem) = state.webhook_identity_pem.as_deref() {
        if let Ok(identity) = reqwest::Identity::from_pem(pem) {
            builder = builder.identity(identity);
        }
    }

    if let Some(addr) = state.konnectivity_proxy_addr.as_deref() {
        if let Ok(proxy) = reqwest::Proxy::all(format!("https://{addr}")) {
            builder = builder.proxy(proxy);
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

// ---------------------------------------------------------------------------
// Request proxying
// ---------------------------------------------------------------------------

/// Proxy one request to the `APIService`'s backend and return its response verbatim.
///
/// Connection failures (backend not yet reachable, DNS/TLS errors) map to 503 Service
/// Unavailable — never 502 — because the aggregator conformance test's readiness poll
/// (`aggregator.go`) only tolerates 403 and 503 while waiting for the backend to come up;
/// any other status aborts the poll immediately as a fatal error.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_to_backend<S: Store>(
    state: &AppState<S>,
    apiservice: &serde_json::Value,
    group: &str,
    version: &str,
    tail: &str,
    query: Option<&str>,
    method: axum::http::Method,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let spec = apiservice
        .get("spec")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let base = match backend_base_url(apiservice) {
        Ok(Some(base)) => base,
        Ok(None) => {
            return Status::service_unavailable(format!(
                "apiservice \"{version}.{group}\" has no backing service"
            ))
            .into_response();
        }
        Err(e) => {
            return Status::internal(format!(
                "apiservice \"{version}.{group}\" has an invalid spec.service: {e}"
            ))
            .into_response();
        }
    };

    let mut url = format!("{base}/apis/{group}/{version}");
    if !tail.is_empty() {
        url.push('/');
        url.push_str(tail);
    }
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }

    let client = build_backend_client(state, &spec);
    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

    let mut outbound = client.request(reqwest_method, &url).body(body);
    // Forward only the headers the backend needs to authenticate/negotiate the request.
    // The backend has no requestheader-client-ca trust configured (see module doc), so it
    // authenticates the original caller itself via delegated TokenReview against this
    // apiserver — that requires the caller's own Authorization header, unmodified.
    for name in [
        axum::http::header::AUTHORIZATION,
        axum::http::header::ACCEPT,
        axum::http::header::CONTENT_TYPE,
    ] {
        if let Some(value) = headers.get(&name) {
            outbound = outbound.header(name, value.clone());
        }
    }

    match outbound.send().await {
        Ok(resp) => {
            let status = resp.status();
            let upstream_headers = resp.headers().clone();
            let response_body = Body::from_stream(resp.bytes_stream());
            super::proxy::proxied_response(status, &upstream_headers, response_body)
                .unwrap_or_else(IntoResponse::into_response)
        }
        Err(e) => Status::service_unavailable(format!("error trying to reach service: {e}"))
            .into_response(),
    }
}

/// Axum middleware: for any `/apis/{group}/{version}/*` request whose group+version matches
/// a registered `APIService` with a live backend, proxy it there instead of routing normally.
///
/// Runs as a layer inside `build_router`, so it sits *after* `AuthLayer` (authentication and
/// u7s's own RBAC check already happened) and *before* axum's route matching — the same
/// ordering every other route gets, just intercepted one step earlier so a single check
/// covers every verb and subpath uniformly (collection, named resource, status subresource,
/// ...) without touching the generic CR/built-in handlers at all.
///
/// Built-in and CRD-backed groups are unaffected: u7s never creates an `APIService` object
/// for them, so the lookup below simply misses and the request falls through to `next`.
pub async fn proxy_middleware<S: Store>(
    State(state): State<AppState<S>>,
    req: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    let Some((group, version, tail)) = parse_apis_path(&path) else {
        return next.run(req).await;
    };
    let group = group.to_owned();
    let version = version.to_owned();
    let tail = tail.to_owned();

    let Some(apiservice) = find_apiservice(&state, &group, &version).await else {
        return next.run(req).await;
    };
    match backend_base_url(&apiservice) {
        Ok(Some(_)) => {} // has a real backend -- proceed to proxy below
        Ok(None) => {
            // No spec.service (a "local" APIService u7s never creates itself) -- nothing to
            // proxy to; let CRD/built-in routing handle it as if this object didn't exist.
            return next.run(req).await;
        }
        Err(e) => {
            // spec.service is present but invalid (e.g. a crafted namespace/name breaking
            // out of the URL authority) -- reject outright, before reading the request body
            // or ever attempting to build/dial a URL from it.
            return Status::internal(format!(
                "apiservice \"{version}.{group}\" has an invalid spec.service: {e}"
            ))
            .into_response();
        }
    }

    let query = req.uri().query().map(str::to_owned);
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return Status::bad_request(format!("failed to read request body: {e}"))
                .into_response();
        }
    };

    proxy_to_backend(
        &state,
        &apiservice,
        &group,
        &version,
        &tail,
        query.as_deref(),
        method,
        &headers,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// Discovery integration
// ---------------------------------------------------------------------------

/// Fetch the backend's own `/apis/{group}/{version}` discovery document (its `APIResourceList`).
///
/// Used to populate the aggregated-discovery resource list for an `APIService`-backed group,
/// exactly like the classic `/apis/{group}/{version}` route would if it were reached — the
/// backend is the only source of truth for what resources it actually serves.
///
/// `authorization` must be the caller's own bearer token, forwarded unchanged: the backend
/// authenticates callers via delegated TokenReview against this apiserver (see module doc),
/// so an unauthenticated discovery request gets 401'd by the backend — which this function
/// would otherwise silently treat as "no resources", making every aggregated resource
/// invisible to `kubectl`/dynamic-client discovery even though the resource proxy itself
/// works fine.
pub async fn discovery_resources_for_apiservice<S: Store>(
    state: &AppState<S>,
    apiservice: &serde_json::Value,
    authorization: Option<&axum::http::HeaderValue>,
) -> Option<serde_json::Value> {
    let spec = apiservice.get("spec")?;
    let group = spec.get("group")?.as_str()?;
    let version = spec.get("version")?.as_str()?;
    // An invalid spec.service is treated the same as "no backend" here: this function's
    // contract is "give me resources or None", with no channel to surface a distinct error
    // to the discovery caller — the resource proxy path (proxy_middleware/proxy_to_backend)
    // is what surfaces the rejection explicitly.
    let base = backend_base_url(apiservice).ok().flatten()?;
    let client = build_backend_client(state, spec);
    let url = format!("{base}/apis/{group}/{version}");
    let mut req = client.get(&url);
    for (name, value) in discovery_request_headers(authorization) {
        req = req.header(name, value);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Headers attached to the backend discovery fetch. Split out as a pure function so a
/// regression test can assert Authorization is forwarded without a live network call --
/// see `discovery_resources_for_apiservice`'s doc for why forwarding it matters.
fn discovery_request_headers(
    authorization: Option<&axum::http::HeaderValue>,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    let mut headers = vec![(
        axum::http::header::ACCEPT,
        axum::http::HeaderValue::from_static("application/json"),
    )];
    if let Some(auth) = authorization {
        headers.push((axum::http::header::AUTHORIZATION, auth.clone()));
    }
    headers
}

/// Accumulate one `APIService`'s `spec.group`/`spec.version` (plus priority fields) into
/// `by_group`. Shared by both branches of `list_apiservice_groups` (cache warm or cold) so the
/// two data sources — the cached objects and a fresh store list — are folded identically.
fn accumulate_apiservice_group_version(
    by_group: &mut std::collections::HashMap<String, Vec<(String, i64, i64)>>,
    svc: &serde_json::Value,
) {
    let (Some(group), Some(version)) = (
        svc["spec"]["group"].as_str().map(str::to_owned),
        svc["spec"]["version"].as_str().map(str::to_owned),
    ) else {
        return;
    };
    let group_priority_min = svc["spec"]["groupPriorityMinimum"].as_i64().unwrap_or(0);
    let version_priority = svc["spec"]["versionPriority"].as_i64().unwrap_or(0);
    by_group
        .entry(group)
        .or_default()
        .push((version, group_priority_min, version_priority));
}

/// List every distinct `spec.group` among registered `APIService` objects, with the
/// preferred version (highest `versionPriority`, ties broken by `groupPriorityMinimum`
/// then name) and the full set of served versions — mirroring how `/apis` (APIGroupList)
/// reports a CRD group's versions today.
///
/// Reads `AppState::apiservice_cache` when warm (see `find_apiservice`'s doc for why this
/// matters: this runs on every plain `GET /apis`), falling back to a store list only when the
/// cache is cold.
pub async fn list_apiservice_groups<S: Store>(
    state: &AppState<S>,
) -> Vec<(String, String, Vec<String>)> {
    let cached = {
        let guard = state.apiservice_cache.apiservices.read().unwrap();
        guard.as_ref().cloned()
    };

    let mut by_group: std::collections::HashMap<String, Vec<(String, i64, i64)>> =
        std::collections::HashMap::new();
    match cached {
        Some(map) => {
            for svc in map.values() {
                accumulate_apiservice_group_version(&mut by_group, svc);
            }
        }
        None => {
            let prefix = group_list_prefix(APISERVICE_GROUP, APISERVICE_PLURAL, None);
            let Ok(resp) = state.store.list(&prefix, ListOptions::default()).await else {
                return Vec::new();
            };
            for item in &resp.items {
                if let Ok(svc) = serde_json::from_slice::<serde_json::Value>(&item.value) {
                    accumulate_apiservice_group_version(&mut by_group, &svc);
                }
            }
        }
    }

    by_group
        .into_iter()
        .map(|(group, mut versions)| {
            versions.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.cmp(&b.0)));
            let preferred = versions[0].0.clone();
            let served = versions.into_iter().map(|(v, _, _)| v).collect();
            (group, preferred, served)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Availability controller
// ---------------------------------------------------------------------------

/// Health-check every registered `APIService`'s backend and set
/// `status.conditions[type=Available]` accordingly.
///
/// Spawned once at startup on a fixed interval (see `main.rs`). This is a coarse safety
/// net that catches a backend going down (or coming back up) *after* its first check —
/// see `ensure_availability_checked` for the deterministic first-check path that the
/// conformance test's tight timing actually depends on. Best-effort: store errors and
/// unreachable backends are logged and left for the next sweep, never propagated.
pub async fn reconcile_apiservice_availability<S: Store>(state: &AppState<S>) {
    let prefix = group_list_prefix(APISERVICE_GROUP, APISERVICE_PLURAL, None);
    let Ok(resp) = state.store.list(&prefix, ListOptions::default()).await else {
        return;
    };

    for item in &resp.items {
        let Ok(apiservice) = serde_json::from_slice::<serde_json::Value>(&item.value) else {
            continue;
        };
        check_and_persist_availability(state, &item.key, item.revision, &apiservice).await;
    }
}

/// Run one health check against `apiservice`'s backend and persist the resulting
/// `Available` condition with optimistic concurrency, keyed off the revision the caller
/// already read. No-op when there is no backend to check, or the outcome is unchanged
/// from what is already stored (avoids churning `resourceVersion` on every sweep).
async fn check_and_persist_availability<S: Store>(
    state: &AppState<S>,
    key: &str,
    revision: u64,
    apiservice: &serde_json::Value,
) {
    if !matches!(backend_base_url(apiservice), Ok(Some(_))) {
        return; // local APIService, or an invalid spec.service -- nothing safe to health-check
    }

    let (status_str, reason, message) = match health_check_backend(state, apiservice).await {
        Ok(()) => ("True", "Passed", "all checks passed".to_owned()),
        Err(e) => ("False", "FailedDiscoveryCheck", e),
    };

    let mut updated = apiservice.clone();
    let now = crate::util::utc_now_rfc3339();
    if !upsert_available_condition(&mut updated, status_str, reason, &message, &now) {
        return; // unchanged -- skip the write so resourceVersion doesn't churn
    }
    if let Err(e) = state
        .store
        .put(key, bytes::Bytes::from(updated.to_string()), Some(revision))
        .await
    {
        tracing::debug!("apiservice availability: put {key} failed: {e}");
    }
}

/// Block a `.../apiservices/{name}/status` read on one health check when the object has
/// never been checked yet, instead of relying solely on the periodic sweep above.
///
/// The aggregator conformance test reads status milliseconds after its own readiness poll
/// succeeds (`aggregator.go:762` then `:524`, ~70ms apart in practice) — far tighter than
/// any reasonable periodic interval can reliably win. A `status.conditions[0]` index into
/// an empty slice panics the test outright (not a soft assertion failure), so "eventually
/// consistent" is not good enough for the *first* check specifically; every later
/// read/refresh is covered by the periodic sweep, which is fine to lag.
pub async fn ensure_availability_checked<S: Store>(state: &AppState<S>, name: &str) {
    let key = crate::keys::group_object_key(APISERVICE_GROUP, APISERVICE_PLURAL, None, name);
    let Ok(Some(stored)) = state.store.get(&key).await else {
        return;
    };
    let Ok(apiservice) = serde_json::from_slice::<serde_json::Value>(&stored.value) else {
        return;
    };
    let already_checked = apiservice["status"]["conditions"]
        .as_array()
        .is_some_and(|conditions| conditions.iter().any(|c| c["type"] == "Available"));
    if already_checked {
        return;
    }
    check_and_persist_availability(state, &key, stored.revision, &apiservice).await;
}

/// GET the backend's own discovery endpoint; any HTTP response at all (regardless of status
/// code) counts as reachable — this only asks "is something speaking HTTPS back there", the
/// same low bar real kube-apiserver's `AvailableConditionController` uses.
async fn health_check_backend<S: Store>(
    state: &AppState<S>,
    apiservice: &serde_json::Value,
) -> Result<(), String> {
    let spec = apiservice.get("spec").ok_or("apiservice has no spec")?;
    let group = spec
        .get("group")
        .and_then(|v| v.as_str())
        .ok_or("spec.group missing")?;
    let version = spec
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or("spec.version missing")?;
    let base = match backend_base_url(apiservice) {
        Ok(Some(base)) => base,
        Ok(None) => return Err("spec.service missing".to_string()),
        Err(e) => return Err(format!("invalid spec.service: {e}")),
    };
    let client = build_backend_client(state, spec);
    let url = format!("{base}/apis/{group}/{version}");
    client
        .get(&url)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| format!("failing or missing response from {url}: {e}"))
}

/// Merge the `Available` condition into `status.conditions`, keeping it at index 0.
///
/// The aggregator conformance test asserts `status.conditions[0].message == "all checks
/// passed"` — later steps in the same test only ever *append* further conditions (via
/// `append(existing, newCondition)`), so keeping `Available` first here is what keeps it
/// first for the rest of the test.
///
/// Returns `false` (and leaves `apiservice` unmodified in substance) when the condition
/// already matches, so callers can skip the store write entirely — writing on every sweep
/// would churn `resourceVersion` and could race the test's own status updates later on.
fn upsert_available_condition(
    apiservice: &mut serde_json::Value,
    status_str: &str,
    reason: &str,
    message: &str,
    now: &str,
) -> bool {
    if !apiservice["status"].is_object() {
        apiservice["status"] = serde_json::json!({});
    }
    if !apiservice["status"]["conditions"].is_array() {
        apiservice["status"]["conditions"] = serde_json::json!([]);
    }
    let conditions = apiservice["status"]["conditions"]
        .as_array_mut()
        .expect("just ensured this is an array");

    if let Some(existing) = conditions.iter_mut().find(|c| c["type"] == "Available") {
        let status_changed = existing["status"] != status_str;
        if !status_changed && existing["message"] == message {
            return false;
        }
        existing["status"] = serde_json::json!(status_str);
        existing["reason"] = serde_json::json!(reason);
        existing["message"] = serde_json::json!(message);
        if status_changed {
            existing["lastTransitionTime"] = serde_json::json!(now);
        }
    } else {
        conditions.insert(
            0,
            serde_json::json!({
                "type": "Available",
                "status": status_str,
                "reason": reason,
                "message": message,
                "lastTransitionTime": now,
            }),
        );
    }
    true
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("open in-memory db"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    // ---- parse_apis_path ---------------------------------------------------

    /// The exact shape the aggregator conformance test polls
    /// (`/apis/wardle.example.com/v1alpha1/namespaces/default/flunders`) must resolve to a
    /// group/version/tail split — if this regresses, the proxy never even attempts to look
    /// up the APIService and every aggregated request 404s from the CR fallback instead.
    #[test]
    fn parse_apis_path_splits_group_version_and_resource_tail() {
        let parsed =
            parse_apis_path("/apis/wardle.example.com/v1alpha1/namespaces/default/flunders");
        assert_eq!(
            parsed,
            Some((
                "wardle.example.com",
                "v1alpha1",
                "namespaces/default/flunders"
            )),
            "must split into (group, version, tail) so the proxy can rebuild the backend path"
        );
    }

    /// Bare `/apis/{group}/{version}` (no resource) must still parse with an empty tail —
    /// this is the discovery request the dynamic client's GVR resolution depends on, and it
    /// must be proxied to the backend too, not treated as "no match".
    #[test]
    fn parse_apis_path_bare_group_version_has_empty_tail() {
        assert_eq!(
            parse_apis_path("/apis/wardle.example.com/v1alpha1"),
            Some(("wardle.example.com", "v1alpha1", ""))
        );
    }

    /// `/apis/{group}` (no version) must NOT match — group-only discovery spans every
    /// version of the group, potentially backed by different services, and must be
    /// synthesized by `list_apiservice_groups` rather than proxied to a single backend.
    #[test]
    fn parse_apis_path_group_only_does_not_match() {
        assert_eq!(parse_apis_path("/apis/wardle.example.com"), None);
    }

    /// `/apis` and `/apis/` (the group list) must not match — a false positive here would
    /// make every APIGroupList request try an APIService lookup keyed on a garbage name.
    #[test]
    fn parse_apis_path_bare_apis_does_not_match() {
        assert_eq!(parse_apis_path("/apis"), None);
        assert_eq!(parse_apis_path("/apis/"), None);
    }

    /// Non-`/apis` paths (e.g. the core `/api/v1/...` group) must never match — only
    /// `/apis/` prefixed paths use APIService-based aggregation in Kubernetes.
    #[test]
    fn parse_apis_path_core_group_does_not_match() {
        assert_eq!(parse_apis_path("/api/v1/namespaces/default/pods"), None);
    }

    // ---- backend_base_url ---------------------------------------------------

    /// spec.service must resolve to the Service's DNS name (not a raw pod/cluster IP) at the
    /// SERVICE port — matching admission.rs's proven webhook-service resolution: kube-proxy
    /// inside the VM NATs ClusterIP:svcPort -> PodIP:targetPort, and the sample-apiserver's
    /// self-signed cert is only valid for the DNS name, not any IP (see aggregator e2e
    /// `certs.go`), so connecting by IP would fail TLS hostname verification.
    #[test]
    fn backend_base_url_uses_service_dns_name_and_port() {
        let apiservice = serde_json::json!({
            "spec": { "service": { "namespace": "agg-1", "name": "sample-api", "port": 7443 } }
        });
        assert_eq!(
            backend_base_url(&apiservice),
            Ok(Some("https://sample-api.agg-1.svc:7443".to_string()))
        );
    }

    /// ServiceReference.Port defaults to 443 per the Kubernetes API when omitted.
    #[test]
    fn backend_base_url_defaults_port_to_443() {
        let apiservice = serde_json::json!({
            "spec": { "service": { "namespace": "ns", "name": "svc" } }
        });
        assert_eq!(
            backend_base_url(&apiservice),
            Ok(Some("https://svc.ns.svc:443".to_string()))
        );
    }

    /// A "local" APIService (spec.service absent) must resolve to None so the caller falls
    /// back to CRD/built-in routing instead of trying (and failing) to proxy anywhere —
    /// u7s never creates these itself, but must not break routing if one exists by hand.
    #[test]
    fn backend_base_url_returns_none_for_local_apiservice() {
        let apiservice = serde_json::json!({ "spec": { "group": "x", "version": "v1" } });
        assert_eq!(backend_base_url(&apiservice), Ok(None));
    }

    /// Regression test (security): a crafted `spec.service.namespace` containing `/` must be
    /// rejected, not silently built into a URL. `format!("https://{name}.{namespace}.svc:{port}")`
    /// has no escaping — a namespace of `"ns/evil.example.com"` would build
    /// `https://svc.ns/evil.example.com.svc:443`, breaking `evil.example.com` out of the
    /// intended host and redirecting the connection (and the caller's live bearer token,
    /// which `proxy_to_backend` forwards unchanged) to an attacker-controlled destination.
    /// Revert the `validate_name` calls in `backend_base_url` and this fails again.
    #[test]
    fn backend_base_url_rejects_namespace_containing_slash() {
        let apiservice = serde_json::json!({
            "spec": { "service": { "namespace": "ns/evil.example.com", "name": "svc", "port": 443 } }
        });
        let result = backend_base_url(&apiservice);
        assert!(
            result.is_err(),
            "a namespace containing '/' must be rejected, not built into a URL: got {result:?}"
        );
    }

    /// Same attack surface via `spec.service.name` instead of `namespace`.
    #[test]
    fn backend_base_url_rejects_name_containing_slash() {
        let apiservice = serde_json::json!({
            "spec": { "service": { "namespace": "ns", "name": "svc/evil.example.com", "port": 443 } }
        });
        let result = backend_base_url(&apiservice);
        assert!(
            result.is_err(),
            "a service name containing '/' must be rejected, not built into a URL: got {result:?}"
        );
    }

    /// `..` is the other traversal/authority-escape vector `validate_name` rejects; confirm
    /// `backend_base_url` inherits that check rather than only checking for `/`.
    #[test]
    fn backend_base_url_rejects_namespace_containing_dot_dot() {
        let apiservice = serde_json::json!({
            "spec": { "service": { "namespace": "..", "name": "svc", "port": 443 } }
        });
        assert!(backend_base_url(&apiservice).is_err());
    }

    // ---- discovery_request_headers ---------------------------------------------------

    /// Regression test: a live sample-apiserver backend authenticates callers via delegated
    /// TokenReview against this apiserver (no requestheader-client-ca trust configured — see
    /// module doc), so an unauthenticated discovery fetch gets 401'd by the backend. Before
    /// this fix, `discovery_resources_for_apiservice` never attached the caller's
    /// Authorization header, so every APIService-backed group silently showed zero resources
    /// in `/apis` discovery — confirmed live against a real sample-apiserver, where the
    /// aggregator conformance test's dynamic-client GVR lookup failed with "could not find
    /// group version resource for dynamic client and wardle/flunders" even though the
    /// resource proxy itself worked. Revert the header-forwarding and this must fail again.
    #[test]
    fn discovery_request_headers_forwards_authorization_when_present() {
        let auth = axum::http::HeaderValue::from_static("Bearer test-token");
        let headers = discovery_request_headers(Some(&auth));
        assert!(
            headers
                .iter()
                .any(|(name, value)| *name == axum::http::header::AUTHORIZATION
                    && value == "Bearer test-token"),
            "the caller's Authorization header must be forwarded to the backend's discovery \
             endpoint, or an aggregated backend requiring auth 401s and its resources vanish \
             from discovery"
        );
    }

    /// No Authorization on the inbound request (e.g. an anonymous discovery call, if RBAC
    /// even allows one) must not synthesize one — forwarding a missing/None header as some
    /// placeholder would be worse than simply omitting it.
    #[test]
    fn discovery_request_headers_omits_authorization_when_absent() {
        let headers = discovery_request_headers(None);
        assert!(
            !headers
                .iter()
                .any(|(name, _)| *name == axum::http::header::AUTHORIZATION),
            "must not fabricate an Authorization header when the caller sent none"
        );
    }

    // ---- find_apiservice ---------------------------------------------------

    /// The store key for an APIService named "{version}.{group}" must round-trip through
    /// find_apiservice — this is the exact lookup the readiness poll depends on.
    #[tokio::test]
    async fn find_apiservice_locates_object_by_version_dot_group_name() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "metadata": { "name": "v1alpha1.wardle.example.com" },
            "spec": { "group": "wardle.example.com", "version": "v1alpha1" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        let found = find_apiservice(&state, "wardle.example.com", "v1alpha1")
            .await
            .expect("must find the seeded APIService");
        assert_eq!(found["spec"]["group"], "wardle.example.com");
    }

    /// No matching APIService must return None (not an error) so the middleware can fall
    /// through to normal routing for every built-in/CRD group, which never has one.
    #[tokio::test]
    async fn find_apiservice_returns_none_when_absent() {
        let state = make_state();
        assert!(find_apiservice(&state, "wardle.example.com", "v1alpha1")
            .await
            .is_none());
    }

    // ---- list_apiservice_groups ---------------------------------------------------

    /// When multiple versions of the same group are registered, the preferred version must
    /// be the one with the highest versionPriority — matching upstream's own tie-breaking so
    /// `kubectl get flunders` (no explicit version) resolves to the version the backend
    /// itself considers current.
    #[tokio::test]
    async fn list_apiservice_groups_prefers_highest_version_priority() {
        let state = make_state();
        for (name, version, priority) in [
            ("v1alpha1.wardle.example.com", "v1alpha1", 100),
            ("v1beta1.wardle.example.com", "v1beta1", 200),
        ] {
            let key =
                crate::keys::group_object_key("apiregistration.k8s.io", "apiservices", None, name);
            let body = serde_json::json!({
                "spec": {
                    "group": "wardle.example.com",
                    "version": version,
                    "versionPriority": priority,
                    "service": { "namespace": "ns", "name": "svc" }
                }
            });
            state
                .store
                .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
                .await
                .expect("seed apiservice");
        }

        let groups = list_apiservice_groups(&state).await;
        assert_eq!(groups.len(), 1, "both objects share one group");
        let (group, preferred, mut served) = groups.into_iter().next().unwrap();
        assert_eq!(group, "wardle.example.com");
        assert_eq!(
            preferred, "v1beta1",
            "v1beta1 has the higher versionPriority (200 > 100) and must be preferred"
        );
        served.sort();
        assert_eq!(served, vec!["v1alpha1".to_string(), "v1beta1".to_string()]);
    }

    // ---- apiservice_cache: eliminates the per-request store round-trip ---------------

    /// A `Store` wrapper that panics on `get`/`list` once armed, delegating to a real
    /// in-memory `SqliteStore` otherwise. Proves `find_apiservice`/`list_apiservice_groups`
    /// answer entirely from `AppState::apiservice_cache` once it is warm -- zero store calls --
    /// which is the whole point of the cache: both functions run on every single
    /// `/apis/{group}/{version}/...` request (via `proxy_middleware`) and every plain `GET
    /// /apis`, respectively, so a store round-trip there was paid by all non-core apiserver
    /// traffic, not just requests that actually hit an aggregated backend.
    struct PanicsOnReadWhenArmedStore {
        inner: Arc<SqliteStore>,
        armed: std::sync::atomic::AtomicBool,
    }

    impl PanicsOnReadWhenArmedStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(SqliteStore::new(":memory:").expect("open in-memory db")),
                armed: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// Arm the panic. Call only after seeding data and warming the cache -- both of
        /// which legitimately go through the store.
        fn arm(&self) {
            self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Store for PanicsOnReadWhenArmedStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let armed = self.armed.load(std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                assert!(
                    !armed,
                    "find_apiservice called store.get() while the apiservice cache was warm -- \
                     this is exactly the per-request store round-trip the cache exists to \
                     eliminate"
                );
                inner.get(&key).await
            }
        }

        fn list(
            &self,
            prefix: &str,
            opts: ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let armed = self.armed.load(std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move {
                assert!(
                    !armed,
                    "list_apiservice_groups called store.list() while the apiservice cache was \
                     warm -- this is exactly the per-request store round-trip the cache exists \
                     to eliminate"
                );
                inner.list(&prefix, opts).await
            }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.put(&key, value, expected_revision).await }
        }

        fn delete(
            &self,
            key: &str,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<(u64, Bytes)>> + Send {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.delete(&key, expected_revision).await }
        }

        fn watch(
            &self,
            _prefix: &str,
            _from_revision: u64,
        ) -> impl std::future::Future<
            Output = u7s_store::Result<
                impl futures_core::Stream<Item = u7s_store::WatchEvent> + Send + 'static,
            >,
        > + Send {
            std::future::ready(Ok(futures_util::stream::empty()))
        }

        fn list_namespace_objects(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.list_namespace_objects(&ns).await }
        }

        fn delete_namespace_resources(
            &self,
            namespace: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Vec<String>>> + Send {
            let inner = self.inner.clone();
            let ns = namespace.to_string();
            async move { inner.delete_namespace_resources(&ns).await }
        }

        fn compaction_horizon(&self) -> u64 {
            self.inner.compaction_horizon()
        }

        fn current_revision(&self) -> u64 {
            self.inner.current_revision()
        }

        fn watch_receiver_count(&self) -> usize {
            self.inner.watch_receiver_count()
        }
    }

    /// The common case this bead is about: with zero `APIService` objects ever registered
    /// (true for every u7s cluster that never installs an aggregated API), a request for an
    /// unrelated group (apps, batch, rbac, CRDs, ...) must resolve its "not aggregated" miss
    /// entirely from the (empty) warm cache. Before this cache existed, `find_apiservice` ran
    /// a real store lookup on every single `/apis/{group}/{version}/...` request regardless.
    #[tokio::test]
    async fn find_apiservice_with_none_registered_resolves_miss_without_store_round_trip() {
        let mock = Arc::new(PanicsOnReadWhenArmedStore::new());
        let state = AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        state.refresh_apiservice_cache().await; // warms to an empty cache -- nothing seeded
        mock.arm();

        assert!(
            find_apiservice(&state, "apps", "v1").await.is_none(),
            "a miss for an unrelated group must resolve from the warm (empty) cache, not a \
             fresh store round-trip"
        );
    }

    /// With an `APIService` registered, both a hit (the aggregated group itself) and a miss
    /// (any other group) must resolve from the warm cache -- proving the cache is consulted
    /// for the actual routing decision, not merely warmed and then bypassed.
    #[tokio::test]
    async fn find_apiservice_reads_warm_cache_for_hit_and_miss() {
        let mock = Arc::new(PanicsOnReadWhenArmedStore::new());
        let state = AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": { "group": "wardle.example.com", "version": "v1alpha1" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        state.refresh_apiservice_cache().await;
        mock.arm(); // any further store.get/store.list is the bug this test catches

        let found = find_apiservice(&state, "wardle.example.com", "v1alpha1")
            .await
            .expect("must still find the seeded APIService from the warm cache");
        assert_eq!(found["spec"]["group"], "wardle.example.com");

        assert!(
            find_apiservice(&state, "apps", "v1").await.is_none(),
            "a miss for an unrelated group/version must also resolve from the warm cache"
        );
    }

    /// `list_apiservice_groups` (the extra call `api_group_list_inner` makes on every plain
    /// `GET /apis`) must likewise answer from the warm cache instead of a fresh store list.
    #[tokio::test]
    async fn list_apiservice_groups_reads_warm_cache() {
        let mock = Arc::new(PanicsOnReadWhenArmedStore::new());
        let state = AppState::new(
            mock.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": { "namespace": "ns", "name": "svc" }
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        state.refresh_apiservice_cache().await;
        mock.arm();

        let groups = list_apiservice_groups(&state).await;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "wardle.example.com");
    }

    /// Regression test for the write-through invalidation itself: a create followed by a
    /// delete (both via `refresh_apiservice_cache`, exactly as `handlers/resource.rs`'s write
    /// handlers call it) must leave the cache reflecting the delete, not a stale hit -- a
    /// cache that only ever grows would silently keep proxying to a backend the admin removed.
    ///
    /// Asserts on `apiservice_cache`'s own contents directly (not just `find_apiservice`'s
    /// output) -- a `refresh_apiservice_cache` that silently no-ops would leave the cache cold,
    /// and `find_apiservice` transparently falls back to the store when cold, which would mask
    /// a broken refresh behind seemingly-correct behavior.
    #[tokio::test]
    async fn refresh_apiservice_cache_reflects_a_deletion() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": { "group": "wardle.example.com", "version": "v1alpha1" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");
        state.refresh_apiservice_cache().await;
        {
            let guard = state.apiservice_cache.apiservices.read().unwrap();
            let map = guard.as_ref().expect("cache must be warm after refresh");
            assert_eq!(
                map.len(),
                1,
                "the seeded apiservice must appear in the cache after refresh"
            );
        }

        state.store.delete(&key, None).await.expect("delete");
        state.refresh_apiservice_cache().await;

        let guard = state.apiservice_cache.apiservices.read().unwrap();
        let map = guard
            .as_ref()
            .expect("cache must still be warm after the second refresh");
        assert!(
            map.is_empty(),
            "a deleted APIService must disappear from the cache after refresh, or a request \
             for its group/version would keep proxying to a backend that no longer exists"
        );
    }

    // ---- upsert_available_condition ---------------------------------------------------

    /// A fresh APIService (no status.conditions yet) must get Available inserted as the
    /// FIRST condition — the conformance test reads `status.conditions[0]` specifically.
    #[test]
    fn upsert_available_condition_inserts_as_first_condition() {
        let mut apiservice = serde_json::json!({ "status": {} });
        let changed = upsert_available_condition(
            &mut apiservice,
            "True",
            "Passed",
            "all checks passed",
            "2024-01-01T00:00:00Z",
        );
        assert!(changed);
        let conditions = apiservice["status"]["conditions"].as_array().unwrap();
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0]["type"], "Available");
        assert_eq!(
            conditions[0]["message"], "all checks passed",
            "message must be exactly this string -- aggregator.go asserts on it verbatim"
        );
    }

    /// Re-running the reconcile sweep with the same outcome must report "unchanged" so the
    /// caller skips the store write — writing on every sweep would churn resourceVersion and
    /// could stomp a concurrent status update from elsewhere (e.g. the test's own PATCH).
    #[test]
    fn upsert_available_condition_reports_unchanged_when_nothing_differs() {
        let mut apiservice = serde_json::json!({
            "status": { "conditions": [
                { "type": "Available", "status": "True", "reason": "Passed", "message": "all checks passed", "lastTransitionTime": "2024-01-01T00:00:00Z" }
            ] }
        });
        let changed = upsert_available_condition(
            &mut apiservice,
            "True",
            "Passed",
            "all checks passed",
            "2024-01-02T00:00:00Z",
        );
        assert!(
            !changed,
            "identical status+message must not report a change, or every sweep would write"
        );
        assert_eq!(
            apiservice["status"]["conditions"][0]["lastTransitionTime"], "2024-01-01T00:00:00Z",
            "lastTransitionTime must not move when nothing actually changed"
        );
    }

    /// A later condition (e.g. the test's own "StatusUpdated" appended after Available) must
    /// be preserved by the upsert, not clobbered — only the Available entry is touched.
    #[test]
    fn upsert_available_condition_preserves_other_conditions() {
        let mut apiservice = serde_json::json!({
            "status": { "conditions": [
                { "type": "Available", "status": "False", "reason": "FailedDiscoveryCheck", "message": "not yet", "lastTransitionTime": "2024-01-01T00:00:00Z" },
                { "type": "StatusUpdated", "status": "True", "reason": "E2E", "message": "Set from e2e test" }
            ] }
        });
        upsert_available_condition(
            &mut apiservice,
            "True",
            "Passed",
            "all checks passed",
            "2024-01-02T00:00:00Z",
        );
        let conditions = apiservice["status"]["conditions"].as_array().unwrap();
        assert_eq!(conditions.len(), 2, "must not drop the other condition");
        assert_eq!(conditions[0]["type"], "Available");
        assert_eq!(conditions[0]["message"], "all checks passed");
        assert_eq!(
            conditions[1]["type"], "StatusUpdated",
            "unrelated condition must survive untouched"
        );
    }

    // ---- proxy_middleware (integration, via a real Router) ---------------------------

    use axum::{routing::get, Router};
    use tower::ServiceExt as _;

    async fn fallback_404() -> crate::status::StatusError {
        crate::status::Status::not_found("flunders", "Resource")
    }

    fn make_router(state: AppState) -> Router {
        Router::new()
            .route("/apis/{group}/{version}/{*rest}", get(fallback_404))
            .fallback(fallback_404)
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                proxy_middleware::<SqliteStore>,
            ))
            .with_state(state)
    }

    /// With no APIService registered for the group, the request must fall through to normal
    /// routing (here, the stub 404) instead of the middleware swallowing it — otherwise every
    /// unregistered `/apis/{group}/{version}/...` request would break.
    #[tokio::test]
    async fn proxy_middleware_passes_through_when_no_apiservice_registered() {
        let state = make_state();
        let router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/apis/wardle.example.com/v1alpha1/namespaces/default/flunders")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "must reach the downstream fallback handler, not a middleware-specific response"
        );
    }

    /// Once an APIService is registered, a request must be committed to the aggregation path
    /// even if the backend is unreachable -- and the failure MUST surface as 503, not 502 or
    /// a connection-level panic. The e2e readiness poll (aggregator.go:384-406) only tolerates
    /// 403/503 while waiting for the backend to come up; any other status (including 502)
    /// aborts the poll immediately as a fatal error instead of retrying for the full 60s.
    #[tokio::test]
    async fn proxy_middleware_returns_503_not_502_when_backend_unreachable() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": { "namespace": "agg-1", "name": "sample-api", "port": 7443 }
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        let router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/apis/wardle.example.com/v1alpha1/namespaces/default/flunders")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "an unreachable aggregated backend must surface as 503 so the e2e readiness poll \
             keeps retrying instead of aborting"
        );
    }

    /// An APIService with no spec.service (a "local"-style object) must NOT hijack the
    /// group — the request must still reach normal routing, since u7s has no aggregation
    /// backend to send it to and CRD/built-in dispatch is the only way it could ever work.
    #[tokio::test]
    async fn proxy_middleware_passes_through_for_local_apiservice_with_no_service() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": { "group": "wardle.example.com", "version": "v1alpha1" }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        let router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/apis/wardle.example.com/v1alpha1/namespaces/default/flunders")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    /// Regression test (security), end-to-end through the real middleware: a registered
    /// `APIService` with a crafted `spec.service.namespace` containing `/` must be rejected
    /// outright, not proxied. Without the `validate_name` check in `backend_base_url`, this
    /// would build `https://sample-api.agg-1/evil.example.com.svc:443` and attempt to dial
    /// it — forwarding whatever Authorization header the caller sent (see `proxy_to_backend`)
    /// to a host an attacker fully controls via the crafted namespace. Asserting a distinct
    /// status (not 503, which is what an *unreachable-but-well-formed* backend returns —
    /// see `proxy_middleware_returns_503_not_502_when_backend_unreachable`) proves the
    /// request was rejected before any connection attempt, not merely failed to connect.
    #[tokio::test]
    async fn proxy_middleware_rejects_apiservice_with_crafted_namespace() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": {
                    "namespace": "agg-1/evil.example.com",
                    "name": "sample-api",
                    "port": 7443
                }
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        let router = make_router(state);
        let req = axum::http::Request::builder()
            .uri("/apis/wardle.example.com/v1alpha1/namespaces/default/flunders")
            .header(
                axum::http::header::AUTHORIZATION,
                "Bearer super-secret-token",
            )
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "must be rejected as a bad configuration, not treated as merely 'unreachable' \
             (503) -- 503 would mean the code tried to dial the malformed host"
        );
        assert!(
            resp.status().is_client_error() || resp.status().is_server_error(),
            "a crafted spec.service.namespace must produce an error response, not a 2xx that \
             would mean the caller's bearer token was silently forwarded somewhere"
        );
    }

    // ---- reconcile_apiservice_availability (integration) ---------------------------

    /// The reconciler must persist an Available=True condition once it runs, even though the
    /// backend is unreachable in this test -- wait, unreachable backends must be False. This
    /// test instead verifies the *shape* of the write: reconciling an apiservice with no
    /// reachable backend must still produce a well-formed status.conditions entry (Available
    /// = False here), proving the sweep actually persists its result rather than silently
    /// dropping it on any error.
    #[tokio::test]
    async fn reconcile_apiservice_availability_persists_false_when_backend_unreachable() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": { "namespace": "agg-1", "name": "sample-api", "port": 7443 }
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        reconcile_apiservice_availability(&state).await;

        let stored = state.store.get(&key).await.unwrap().unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let conditions = updated["status"]["conditions"].as_array().expect(
            "reconcile must write status.conditions even when the backend is unreachable, \
             so kubectl/clients can see WHY aggregation isn't working yet",
        );
        assert_eq!(conditions[0]["type"], "Available");
        assert_eq!(conditions[0]["status"], "False");
    }

    // ---- ensure_availability_checked ---------------------------------------------------

    /// Regression test: the aggregator conformance test reads `.../status` roughly 70ms
    /// after its own readiness poll succeeds — the periodic sweep (every 5s in production)
    /// cannot reliably have run by then, and `status.conditions[0]` on an empty slice
    /// panics the test outright (`aggregator.go:534`, confirmed live: "index out of range
    /// [0] with length 0"). A status read must never observe an empty conditions array for
    /// an APIService that has a backend at all, regardless of sweep timing.
    #[tokio::test]
    async fn ensure_availability_checked_populates_conditions_before_first_status_read() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": { "namespace": "agg-1", "name": "sample-api", "port": 7443 }
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        // No periodic sweep has run -- simulates the race the fix closes.
        ensure_availability_checked(&state, "v1alpha1.wardle.example.com").await;

        let stored = state.store.get(&key).await.unwrap().unwrap();
        let updated: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let conditions = updated["status"]["conditions"].as_array().expect(
            "a status read must never see an absent conditions array — indexing \
             conditions[0] on an empty/missing array is exactly what panicked the \
             real conformance test",
        );
        assert!(
            !conditions.is_empty(),
            "conditions must be non-empty after the first status read, not just present-but-empty"
        );
        assert_eq!(conditions[0]["type"], "Available");
    }

    /// Once a condition already exists, a second call must not re-check the backend (and
    /// must not disturb the existing condition) — only the *first* read needs the
    /// deterministic block; subsequent reads rely on the periodic sweep like everything else.
    #[tokio::test]
    async fn ensure_availability_checked_is_a_noop_once_already_checked() {
        let state = make_state();
        let key = crate::keys::group_object_key(
            "apiregistration.k8s.io",
            "apiservices",
            None,
            "v1alpha1.wardle.example.com",
        );
        let body = serde_json::json!({
            "spec": {
                "group": "wardle.example.com",
                "version": "v1alpha1",
                "service": { "namespace": "agg-1", "name": "sample-api", "port": 7443 }
            },
            "status": {
                "conditions": [{
                    "type": "Available",
                    "status": "True",
                    "reason": "Passed",
                    "message": "all checks passed",
                    "lastTransitionTime": "2024-01-01T00:00:00Z"
                }]
            }
        });
        state
            .store
            .put(&key, bytes::Bytes::from(body.to_string()), Some(0))
            .await
            .expect("seed apiservice");

        ensure_availability_checked(&state, "v1alpha1.wardle.example.com").await;

        let stored = state.store.get(&key).await.unwrap().unwrap();
        assert_eq!(
            stored.revision, 1,
            "an already-checked apiservice must not be re-written — resourceVersion must \
             stay put, or every status read would churn it"
        );
    }
}
