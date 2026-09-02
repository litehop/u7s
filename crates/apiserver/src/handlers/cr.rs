use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use u7s_store::{ListOptions, Store};

use crate::{
    admission::{
        prepare_webhook_call, run_mutating_webhooks, run_validating_webhooks,
        send_webhook_request_with_retry, AdmissionContext,
    },
    auth::UserInfo,
    handlers::crd::{deleted_group_tombstone_key, CustomResourceDefinition},
    handlers::json_patch::is_dry_run_header,
    keys::cluster_object_key,
    state::AppState,
    status::Status,
    types::{DeleteOptions, Object},
    util::{content_type, extract_body, parse_resource_version, utc_now_rfc3339},
};

const CRD_LIST_PREFIX: &str = "/registry/apiextensions.k8s.io/customresourcedefinitions/";

/// Maximum conversion webhook response body size. Responses larger than this are
/// treated as a webhook failure (500). Prevents a malicious conversion webhook from
/// exhausting apiserver memory via unbounded allocation.
const MAX_CONVERSION_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB

// ---------------------------------------------------------------------------
// CRD conversion webhook
// ---------------------------------------------------------------------------

/// Call the CRD conversion webhook with a set of objects and a desired API version.
///
/// The ConversionReview protocol (apiextensions.k8s.io/v1):
///   request.objects      — the stored objects to convert
///   request.desiredAPIVersion — the target version (e.g. "example.com/v2")
///   response.convertedObjects — the converted objects returned by the webhook
///
/// Returns the converted objects on success, or an error if the webhook fails or
/// the response is malformed.
pub(crate) async fn call_conversion_webhook<S: Store>(
    state: &AppState<S>,
    client_config: &serde_json::Value,
    objects: Vec<serde_json::Value>,
    desired_api_version: &str,
) -> Result<Vec<serde_json::Value>, crate::status::StatusError> {
    // Resolve the URL and a client pinned to this webhook's own caBundle — every webhook
    // ships its own CA (not the cluster CA), and Service-based targets are only reachable
    // from the Mac host through the konnectivity proxy. Same rules as admission webhooks;
    // see admission::prepare_webhook_call. Without this, every real conversion webhook
    // fails its TLS handshake against the cluster-CA-only client.
    let (url, wh_client) = prepare_webhook_call(state, client_config, "conversion webhook")
        .await
        .map_err(|e| Status::internal(format!("conversion webhook: {e}")))?;

    let requested_len = objects.len();
    let uid = uuid::Uuid::new_v4().to_string();
    let review = serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "ConversionReview",
        "request": {
            "uid": uid,
            "desiredAPIVersion": desired_api_version,
            "objects": objects
        }
    });

    let body = serde_json::to_vec(&review).map_err(|e| Status::internal(e.to_string()))?;
    // send_webhook_request_with_retry absorbs a connect-refused/reset error with a short
    // bounded retry — a freshly created webhook Service's ClusterIP can see a few of these
    // in the first tens of milliseconds, before kube-proxy finishes programming its
    // IPVS/iptables NAT rule (see the function doc in admission.rs for the mechanism).
    let resp = send_webhook_request_with_retry(|| {
        wh_client
            .post(&url)
            .header("Content-Type", "application/json")
            // Real conversion webhooks (including the k8s conformance suite's sample
            // webhook) content-negotiate their response body from the Accept header,
            // falling back to an arbitrary (even non-JSON, e.g. YAML) encoding when it
            // doesn't name a type explicitly. Without this, reqwest's default
            // `Accept: */*` leaves that choice up to the webhook, and a response we can't
            // parse as JSON below is indistinguishable from a broken one. This mirrors
            // upstream apiserver's own webhook client (client-go's RESTClient with
            // ContentConfig.ContentType=json always sends `Accept: application/json, */*`).
            .header("Accept", "application/json, */*")
            .body(body.clone())
    })
    .await
    .map_err(|e| Status::internal(format!("conversion webhook call failed: {e}")))?;

    // Bounded read: treat oversized responses as a webhook failure so the apiserver
    // returns 500 rather than exhausting memory. The 1 MiB cap matches the admission
    // webhook limit in admission.rs.
    let mut buf = Vec::with_capacity(4096);
    let mut resp = resp;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk);
                if buf.len() > MAX_CONVERSION_RESPONSE_BYTES {
                    return Err(Status::internal(
                        "conversion webhook response exceeded 1 MiB size limit".into(),
                    ));
                }
            }
            Ok(None) => break,
            Err(e) => {
                return Err(Status::internal(format!(
                    "conversion webhook response read error: {e}"
                )))
            }
        }
    }
    let bytes = bytes::Bytes::from(buf);

    let resp_val: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        Status::internal(format!("conversion webhook response JSON parse error: {e}"))
    })?;

    // Check result status.
    let result_status = resp_val["response"]["result"]["status"]
        .as_str()
        .unwrap_or("Failure");
    if result_status != "Success" {
        let msg = resp_val["response"]["result"]["message"]
            .as_str()
            .unwrap_or("conversion webhook returned failure");
        return Err(Status::internal(format!(
            "conversion webhook failed: {msg}"
        )));
    }

    let converted = resp_val["response"]["convertedObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // Upstream's conversion webhook contract requires exactly one converted object per
    // requested object, in the same order. A short response used to slip through here as
    // "success" (only `is_empty()` was checked); the caller's `leader_indices.zip(converted)`
    // then silently truncated to the shorter side, leaving the un-zipped tail of leader keys
    // stuck in `CrConversionCache::in_flight` forever (the `LeaderClaimGuard::clear()` call
    // that would normally release them only runs after that same zip loop finishes). Returning
    // Err here instead makes the caller's `?` drop the still-armed guard, whose Drop impl
    // releases every claimed key — see `LeaderClaimGuard`.
    if converted.len() != requested_len {
        return Err(Status::internal(format!(
            "conversion webhook returned {} converted objects, expected {requested_len}",
            converted.len()
        )));
    }

    Ok(converted)
}

// ---------------------------------------------------------------------------
// CRD lookup
// ---------------------------------------------------------------------------

/// Information extracted from a CRD needed to serve a CR request.
pub struct CrContext {
    pub kind: String,
    pub namespaced: bool,
    /// True when at least one served version declares `subresources: {status: {}}`.
    /// Controls whether the main PUT/PATCH endpoint strips `.status` and whether
    /// the `/status` subresource endpoint is active.
    pub has_status_subresource: bool,
    /// The `openAPIV3Schema` from the matched version's schema field, if present.
    /// Used for server-side CR body validation on CREATE and UPDATE.
    pub schema: Option<serde_json::Value>,
    /// Conversion configuration from the CRD spec. Present only when
    /// `spec.conversion.strategy == "Webhook"`.
    pub conversion_webhook_client_config: Option<serde_json::Value>,
    /// Field paths (`x-kubernetes-selectable-fields`, leading '.' stripped) the matched
    /// version declared selectable, e.g. `["host", "port"]`. Each version may declare a
    /// different set, so this is scoped to the specific version a request named — never
    /// the CRD as a whole.
    pub selectable_fields: Vec<String>,
    /// (CRD group, matched version name, CRD's own resourceVersion) — the
    /// `cr_schema_cache` key for `schema`. See `state::CrSchemaCache` for why.
    pub schema_cache_key: crate::state::CrSchemaCacheKey,
    /// The matched version's `subresources.scale` configuration, if declared. Unlike
    /// `has_status_subresource` (a version-independent bool — status is always just the
    /// `.status` key), scale requires the three CRD-author-declared JSON paths, which are
    /// specific to the requested version's schema, so this is `None` unless the matched
    /// version itself declares `subresources.scale`.
    pub scale: Option<CrScaleConfig>,
}

/// The three JSONPath-ish field paths (leading `.` stripped) a CRD author declares under
/// `subresources.scale` for the `/scale` subresource. Mirrors upstream's
/// `apiextensions/v1.CustomResourceSubresourceScale`.
#[derive(Debug, Clone)]
pub struct CrScaleConfig {
    /// Where the desired replica count lives, e.g. "spec.replicas". Required by the CRD API.
    pub spec_replicas_path: String,
    /// Where the actual replica count lives, e.g. "status.replicas". Required by the CRD API.
    pub status_replicas_path: String,
    /// Where a pre-rendered label-selector string lives, e.g. "status.selector". Optional —
    /// HPA treats a missing selector as "" rather than erroring only when this itself is unset.
    pub label_selector_path: Option<String>,
}

/// Find the CRD whose spec.group == group and spec.names.plural == plural.
///
/// Returns:
/// - `Ok(CrContext)` when a matching, served CRD is found.
/// - `Err(410 Gone)` when the group was registered but its CRD has been deleted.
///   This signals informers (client-go reflector) to stop watching and clean up.
///   Without 410, informers treat the response as a transient 404 and retry
///   indefinitely, causing namespace deletion to hang.
/// - `Err(404 NotFound)` when the group/version/plural was never registered.
pub async fn find_crd<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<CrContext, crate::status::StatusError> {
    let prefix = CRD_LIST_PREFIX;
    let resp = state
        .store
        .list(prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    for obj in &resp.items {
        let crd: CustomResourceDefinition = match serde_json::from_slice(&obj.value) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(err = %e, key = %obj.key, "find_crd: skipping unparseable CRD in store");
                continue;
            }
        };
        if crd.spec.group != group || crd.spec.names.plural != plural {
            continue;
        }
        // Matching group + plural. Now check version is served.
        let Some(matched_version) = crd
            .spec
            .versions
            .iter()
            .find(|v| v.name == version && v.served)
        else {
            return Err(Status::not_found(
                &format!("{group}/{version}/{plural}"),
                "Resource",
            ));
        };
        // Extract openAPIV3Schema from the matched version's schema field.
        let schema = matched_version
            .schema
            .as_ref()
            .and_then(|s| s.get("openAPIV3Schema"))
            .cloned();
        // Selectable fields are declared per-version (see CrContext::selectable_fields) —
        // only the version this request named, never the whole CRD.
        let selectable_fields = matched_version
            .selectable_fields
            .iter()
            .map(|f| f.json_path.trim_start_matches('.').to_string())
            .collect();
        let namespaced = crd.spec.scope == "Namespaced";
        // A version has a status subresource when `subresources.status` is present
        // and non-null in the CRD spec. Check all versions; if any declares it, the
        // resource has a status subresource (all served versions must agree in practice).
        let has_status_subresource = crd.spec.versions.iter().any(|v| {
            v.subresources
                .as_ref()
                .and_then(|s| s.get("status"))
                .map(|st| !st.is_null())
                .unwrap_or(false)
        });
        // Scale config is read from the matched version only (not "any version" like
        // has_status_subresource above) because the JSON paths themselves are
        // version-specific: two served versions of the same CRD can shape spec/status
        // differently, so the wrong version's paths would resolve against the wrong fields.
        let scale = matched_version
            .subresources
            .as_ref()
            .and_then(|s| s.get("scale"))
            .filter(|sc| !sc.is_null())
            .and_then(|sc| {
                let spec_replicas_path = sc
                    .get("specReplicasPath")?
                    .as_str()?
                    .trim_start_matches('.')
                    .to_string();
                let status_replicas_path = sc
                    .get("statusReplicasPath")?
                    .as_str()?
                    .trim_start_matches('.')
                    .to_string();
                let label_selector_path = sc
                    .get("labelSelectorPath")
                    .and_then(|v| v.as_str())
                    .map(|p| p.trim_start_matches('.').to_string());
                Some(CrScaleConfig {
                    spec_replicas_path,
                    status_replicas_path,
                    label_selector_path,
                })
            });
        // Extract conversion webhook clientConfig if strategy is Webhook.
        let conversion_webhook_client_config = crd
            .spec
            .conversion
            .as_ref()
            .filter(|c| c["strategy"].as_str() == Some("Webhook"))
            .and_then(|c| c["webhook"]["clientConfig"].as_object())
            .map(|cfg| serde_json::Value::Object(cfg.clone()));
        let schema_cache_key = (
            crd.spec.group.clone(),
            matched_version.name.clone(),
            crd.metadata.resource_version.clone(),
        );
        return Ok(CrContext {
            kind: crd.spec.names.kind.clone(),
            namespaced,
            has_status_subresource,
            schema,
            conversion_webhook_client_config,
            selectable_fields,
            schema_cache_key,
            scale,
        });
    }

    // No live CRD found. Check whether this group was previously deleted.
    // If a tombstone exists, return 410 Gone so informers stop retrying.
    let tombstone_key = deleted_group_tombstone_key(group);
    let tombstone_exists = state
        .store
        .get(&tombstone_key)
        .await
        .unwrap_or(None)
        .is_some();

    if tombstone_exists {
        return Err(Status::gone(format!(
            "the custom resource definition for {group}/{version}/{plural} has been deleted"
        )));
    }

    Err(Status::not_found(
        &format!("{group}/{version}/{plural}"),
        "Resource",
    ))
}

/// Like `find_crd`, but downgrades a tombstoned group's 410 Gone to 404 Not Found.
///
/// Only DELETE and deleteCollection should call this. Upstream kube-controller-manager's
/// namespace deletion controller (`deleteCollection()` in
/// `pkg/controller/namespace/deletion/namespaced_resources_deleter.go`) only treats
/// 404/405 as "resource gone, skip gracefully" — any other error, including 410, is fatal
/// and aborts the whole `deleteAllContent` pass, leaving the namespace stuck in Terminating.
/// Upstream never needed to handle 410 here because a deleted CRD's route is unregistered
/// from the real apiserver's mux, so the client gets a plain 404. LIST and WATCH must keep
/// the 410 from `find_crd` untouched — that is the informer re-list path the original 410
/// targeted (see `find_crd`'s doc comment).
async fn find_crd_for_delete<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
    plural: &str,
) -> Result<CrContext, crate::status::StatusError> {
    match find_crd(state, group, version, plural).await {
        Err(err) if err.0 == StatusCode::GONE => Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        )),
        result => result,
    }
}

// ---------------------------------------------------------------------------
// Conversion webhook dispatch decision
// ---------------------------------------------------------------------------

/// Whether a stored CR must go through the conversion webhook to be served at
/// `desired_api_version`.
///
/// This compares the OBJECT'S OWN stored `apiVersion` — never the CRD's current
/// storage-version pointer (`spec.versions[].storage`) — because that pointer can
/// move (e.g. a CRD patch flips `storage: true` from v1 to v2) after objects were
/// already written under the old one. An object's stored bytes never move when that
/// happens (see cr_store_key), so comparing against the live storage-version pointer
/// instead of the object's own version would send an object that already matches the
/// request through the webhook as a version-to-itself conversion — which real
/// conversion webhooks (and the conformance suite's sample webhook) correctly reject
/// as a client bug.
///
/// Takes the conversion config directly (rather than `&CrContext`) so callers that only
/// carry that config — like the watch path's `CrFieldSelectorContext` — can share this
/// exact check instead of re-deriving it.
///
/// `apiVersion` lives at the object root, not under `metadata`, so it isn't covered by
/// `types::ObjectMeta`; this gets its own tiny typed view rather than a raw Value index
/// for the field that gates whether a real network call (the webhook) fires.
#[derive(serde::Deserialize)]
struct StoredApiVersion {
    #[serde(rename = "apiVersion", default)]
    api_version: Option<String>,
}

fn object_needs_conversion(
    obj: &serde_json::Value,
    desired_api_version: &str,
    conversion_webhook_client_config: Option<&serde_json::Value>,
) -> bool {
    if conversion_webhook_client_config.is_none() {
        return false;
    }
    let stored = <StoredApiVersion as serde::Deserialize>::deserialize(obj)
        .unwrap_or(StoredApiVersion { api_version: None });
    stored.api_version.as_deref() != Some(desired_api_version)
}

/// Derive the `state.cr_conversion_cache` key for `item` at `desired_api_version` — the
/// item's own stored `metadata.resourceVersion` paired with the target version. A
/// missing/unparseable resourceVersion (should not happen — the store stamps it on every
/// write, see `CrConversionCache`'s doc comment) yields `None`, which callers treat as
/// "always miss, never claim/cache" rather than risking a key collision.
fn conversion_cache_key(
    item: &serde_json::Value,
    desired_api_version: &str,
) -> Option<crate::state::CrConversionCacheKey> {
    item["metadata"]["resourceVersion"]
        .as_str()
        .map(|rv| (rv.to_string(), desired_api_version.to_string()))
}

/// Releases every not-yet-resolved key in `keys` (via `CrConversionCache::resolve(_, None)`)
/// when dropped. Guards the span from a successful `claim` to the matching `resolve` so a
/// leader that never reaches its own `resolve` call — an early `?` return from the webhook
/// call, or a panic inside it — cannot leave concurrent followers registered on that key's
/// `Notify` waiting forever. Callers `clear()` the keys they resolved normally so the drop
/// only cleans up the ones actually left outstanding.
struct LeaderClaimGuard<'a> {
    cache: &'a crate::state::CrConversionCache,
    keys: Vec<crate::state::CrConversionCacheKey>,
}

impl Drop for LeaderClaimGuard<'_> {
    fn drop(&mut self) {
        for key in self.keys.drain(..) {
            self.cache.resolve(&key, None);
        }
    }
}

/// Convert only the items whose own stored apiVersion differs from `desired_api_version`,
/// leaving already-matching items untouched. Used for LIST pages and, via a one-element
/// slice, for a single CR watch event (see `watch::convert_watched_cr_object`) — both need
/// the identical per-item version check and batched webhook call.
///
/// A page (or a watch's sendInitialEvents backlog) can be a non-homogeneous mix of objects
/// written under different versions (e.g. some created before, some after a CRD
/// storage-version change); see object_needs_conversion for why every item must be checked
/// individually rather than converting (or skipping) the whole batch based on one CRD-level
/// flag.
///
/// Takes the conversion config directly (rather than `&CrContext`) so callers that only carry
/// that config — like the watch path's `CrFieldSelectorContext` — don't need a full CrContext.
///
/// Items needing conversion are first checked against `state.cr_conversion_cache` keyed on
/// (the item's own stored `metadata.resourceVersion`, `desired_api_version`) — see
/// `CrConversionCache` for why that key is safe to reuse across LIST requests and watchers.
/// Cache misses go through `CrConversionCache::claim`: within this call, every miss that
/// isn't claimed elsewhere is batched into one webhook call (unchanged from before); a miss
/// whose key another *concurrent* call already claimed instead waits on that call's result
/// instead of independently invoking the webhook — this is what stops N watchers/LIST
/// requests racing one write's first conversion from becoming N webhook calls. If the other
/// call's leader fails, a waiter wakes to a fresh cache miss and re-claims the key itself on
/// the next round.
pub(crate) async fn convert_cr_list_items<S: Store>(
    state: &AppState<S>,
    conversion_webhook_client_config: Option<&serde_json::Value>,
    items: &mut [serde_json::Value],
    desired_api_version: &str,
) -> Result<(), crate::status::StatusError> {
    let Some(cfg) = conversion_webhook_client_config else {
        return Ok(());
    };

    let mut pending: Vec<usize> = Vec::new();
    for (i, item) in items.iter_mut().enumerate() {
        if !object_needs_conversion(item, desired_api_version, Some(cfg)) {
            continue;
        }
        let key = conversion_cache_key(item, desired_api_version);
        if let Some(cached) = key.as_ref().and_then(|k| state.cr_conversion_cache.get(k)) {
            *item = (*cached).clone();
            continue;
        }
        pending.push(i);
    }

    while !pending.is_empty() {
        let mut leader_indices = Vec::new();
        let mut leader_keys: Vec<Option<crate::state::CrConversionCacheKey>> = Vec::new();
        let mut waiters: Vec<(
            usize,
            crate::state::CrConversionCacheKey,
            tokio::sync::futures::OwnedNotified,
        )> = Vec::new();

        for i in pending.drain(..) {
            match conversion_cache_key(&items[i], desired_api_version) {
                None => {
                    leader_indices.push(i);
                    leader_keys.push(None);
                }
                Some(key) => match state.cr_conversion_cache.claim(&key) {
                    crate::state::ConversionClaim::Leader => {
                        leader_indices.push(i);
                        leader_keys.push(Some(key));
                    }
                    crate::state::ConversionClaim::Follow(notified) => {
                        waiters.push((i, key, notified));
                    }
                },
            }
        }

        if !leader_indices.is_empty() {
            let to_convert: Vec<serde_json::Value> =
                leader_indices.iter().map(|&i| items[i].clone()).collect();
            let mut guard = LeaderClaimGuard {
                cache: &state.cr_conversion_cache,
                keys: leader_keys.iter().flatten().cloned().collect(),
            };
            let converted =
                call_conversion_webhook(state, cfg, to_convert, desired_api_version).await?;
            for ((i, converted_item), key) in
                leader_indices.into_iter().zip(converted).zip(leader_keys)
            {
                if let Some(k) = key {
                    state
                        .cr_conversion_cache
                        .resolve(&k, Some(std::sync::Arc::new(converted_item.clone())));
                }
                items[i] = converted_item;
            }
            guard.keys.clear();
        }

        for (i, key, notified) in waiters {
            notified.await;
            match state.cr_conversion_cache.get(&key) {
                Some(cached) => items[i] = (*cached).clone(),
                None => pending.push(i),
            }
        }
    }

    Ok(())
}

/// Evict `state.cr_conversion_cache` entries keyed on `superseded_resource_version` (any
/// target apiVersion) — every entry keyed on it can never be looked up again, since a
/// resourceVersion is never reused and, the instant a newer one exists, is no longer
/// reachable via normal API access (Kubernetes has no notion of a read pinned to a stale
/// rv). Called both when a CR is hard-deleted (its own final rv) and, just as importantly,
/// after every successful UPDATE (the object's PREVIOUS rv) — without the latter, a CRD
/// that is never deleted (the common case) never has any of its historical entries
/// cleaned up, even though each one is orphaned the moment the update that superseded it
/// commits. Memory hygiene only: correctness never depended on this (see
/// `CrConversionCache`'s doc comment).
fn evict_cr_conversion_cache<S: Store>(
    state: &AppState<S>,
    superseded_resource_version: Option<&str>,
) {
    if let Some(rv) = superseded_resource_version {
        state.cr_conversion_cache.invalidate_by_rv(rv);
        tracing::debug!(
            rv,
            "cr conversion cache: evicted entries for superseded resourceVersion"
        );
    }
}

// ---------------------------------------------------------------------------
// Store key helpers
// ---------------------------------------------------------------------------

// A CR's storage location must not depend on which served version a request names —
// only on its (group, resource, namespace, name) identity, exactly like upstream
// etcd keys. A CRD's storage-version pointer (`spec.versions[].storage`) can move
// between served versions over the CRD's lifetime (e.g. a v1 -> v2 storage migration);
// if the key embedded that pointer's *current* value, every object written before the
// move would become unreachable the instant it moved, regardless of which version a
// later request targets. Version-specific behaviour (schema, conversion) is applied
// on top of this single stored representation, never by relocating it.
fn cr_store_key(group: &str, plural: &str, namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("/registry/cr/{group}/{plural}/{ns}/{name}"),
        None => format!("/registry/cr/{group}/{plural}/{name}"),
    }
}

/// `pub(crate)` so `quota::count_objects` can fall back to this keyspace when counting
/// CRD-backed resources for `count/<crd>.<group>` ResourceQuota admission — CRs live under
/// `/registry/cr/...`, not the generic `/registry/<group>/<plural>/...` built-in layout, so
/// the quota module needs this exact prefix rather than re-deriving (and risking drift from)
/// its own copy.
pub(crate) fn cr_list_prefix(group: &str, plural: &str, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) => format!("/registry/cr/{group}/{plural}/{ns}/"),
        None => format!("/registry/cr/{group}/{plural}/"),
    }
}

// ---------------------------------------------------------------------------
// Metadata stamping on create
// ---------------------------------------------------------------------------

/// Stamp server-owned identity fields on a newly-created CR. `uid` is ALWAYS assigned
/// fresh here, unconditionally overwriting any client-supplied value — same invariant as
/// the built-in resource create path (`stamp_metadata`). A client-chosen uid on a CR would
/// let it forge object identity just as easily as on a built-in resource: matching a
/// stale/foreign `ownerReference.uid` to manipulate GC's owner-liveness check, or defeating
/// controllers' "same name, different uid ⇒ different object" recreate-detection.
fn stamp_cr_fields(obj: &mut serde_json::Value, group: &str, version: &str, kind: &str) {
    let api_version = format!("{group}/{version}");
    obj["apiVersion"] = serde_json::Value::String(api_version);
    obj["kind"] = serde_json::Value::String(kind.to_string());
    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.uid = Some(new_cr_uid());
    if meta
        .creation_timestamp
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        meta.creation_timestamp = Some(utc_now_rfc3339());
    }
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
}

fn stamp_cr_envelope(obj: &mut serde_json::Value, group: &str, version: &str, kind: &str) {
    obj["apiVersion"] = serde_json::Value::String(format!("{group}/{version}"));
    obj["kind"] = serde_json::Value::String(kind.to_string());
}

fn validate_cr_name(name: &str) -> Result<(), crate::status::StatusError> {
    if name.is_empty() {
        return Err(Status::bad_request(
            "metadata.name must not be empty".into(),
        ));
    }
    // DNS label: lowercase alphanumeric and hyphens, must start/end with alphanumeric.
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        return Err(Status::bad_request(format!(
            "metadata.name \"{name}\" contains invalid characters (must be a DNS label)"
        )));
    }
    let is_alnum = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    if !name.starts_with(is_alnum) || !name.ends_with(is_alnum) {
        return Err(Status::bad_request(format!(
            "metadata.name \"{name}\" must start and end with an alphanumeric character"
        )));
    }
    Ok(())
}

/// Reconcile server-owned metadata on a CR PUT (replace).
///
/// uid is immutable identity, exactly like the built-in resource replace path
/// (`replace_resource`/`replace_namespaced_resource`): a blank incoming uid is restored
/// from the stored object, but a non-blank incoming uid that mismatches the stored one is
/// rejected with 409 rather than silently persisted — accepting it would let a client forge
/// a CR's identity to match a stale/foreign ownerReference (corrupting GC's owner-liveness
/// check) or defeat controllers' "same name, different uid ⇒ different object"
/// recreate-detection.
fn resolve_cr_metadata(
    stored: &serde_json::Value,
    incoming: &mut serde_json::Value,
    name: &str,
    kind: &str,
) -> Result<(), crate::status::StatusError> {
    let stored_meta: crate::types::ObjectMeta =
        serde_json::from_value(stored["metadata"].clone()).unwrap_or_default();
    let mut incoming_meta: crate::types::ObjectMeta =
        serde_json::from_value(incoming["metadata"].take()).unwrap_or_default();
    let incoming_uid_blank = incoming_meta
        .uid
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true);
    if incoming_uid_blank {
        if stored_meta.uid.is_some() {
            incoming_meta.uid = stored_meta.uid;
        }
    } else if let Some(stored_uid) = stored_meta.uid.as_deref().filter(|s| !s.is_empty()) {
        let incoming_uid = incoming_meta.uid.as_deref().unwrap_or("");
        if incoming_uid != stored_uid {
            // Restore incoming["metadata"] before erroring so a caller that ignores the
            // Err still observes a consistent object rather than one missing metadata
            // (take() above emptied it).
            incoming["metadata"] = serde_json::to_value(&incoming_meta).unwrap_or_default();
            return Err(Status::conflict(format!(
                "{kind} \"{name}\": the object was updated with a mismatched uid \
                 (got {incoming_uid}, expected {stored_uid}) — uid is immutable"
            )));
        }
    }
    if incoming_meta
        .creation_timestamp
        .as_deref()
        .map(|s| s.is_empty())
        .unwrap_or(true)
        && stored_meta.creation_timestamp.is_some()
    {
        incoming_meta.creation_timestamp = stored_meta.creation_timestamp;
    }
    incoming["metadata"] = serde_json::to_value(incoming_meta).unwrap_or_default();
    Ok(())
}

fn new_cr_uid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn store_err_cr(err: u7s_store::StoreError, name: &str, kind: &str) -> crate::status::StatusError {
    match err {
        u7s_store::StoreError::NotFound { .. } => Status::not_found(name, kind),
        u7s_store::StoreError::AlreadyExists { .. } => Status::already_exists(name, kind),
        u7s_store::StoreError::RevisionMismatch { expected, current } => Status::conflict(format!(
            "{kind} \"{name}\" cannot be updated: resource version mismatch (expected {expected}, current {current})"
        )),
        other => Status::internal(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// openAPIV3Schema validation
// ---------------------------------------------------------------------------

/// Validate `obj` against the CRD schema in `ctx`, if a schema is present.
/// Uses boon for full openAPIV3Schema keyword coverage (enum, pattern, minimum,
/// maximum, format, items, oneOf, allOf, etc.), then evaluates any
/// `x-kubernetes-validations` CEL rules the schema declares.
///
/// `old_object` is the previously-stored object on UPDATE (for binding `oldSelf` in CEL
/// rules), or `None` on CREATE — upstream only makes `oldSelf` available on UPDATE.
/// Returns `Err(StatusError)` with HTTP 422 if validation fails.
fn validate_cr_schema(
    obj: &serde_json::Value,
    ctx: &CrContext,
    cache: &crate::state::CrSchemaCache,
    old_object: Option<&serde_json::Value>,
) -> Result<(), crate::status::StatusError> {
    let Some(schema) = &ctx.schema else {
        return Ok(());
    };
    // Defense in depth: CRD admission (crd.rs::validate_crd_schema) already rejects
    // oversized patterns and patternProperties, but a CRD that bypassed that check
    // (installed before it existed, restored from backup, or written directly to the
    // store) must not still be able to trigger boon's O(n^2) ECMA-compat rewrite on
    // every CR write against it. This runs on every call, cache hit or miss.
    crate::handlers::crd::walk_schema_dos_bounds(schema, "openAPIV3Schema")?;

    let compiled = match cache.get(&ctx.schema_cache_key) {
        Some(compiled) => compiled,
        None => {
            let mut schemas = boon::Schemas::new();
            let mut compiler = boon::Compiler::new();
            compiler
                .add_resource("schema.json", schema.clone())
                .map_err(|e| Status::internal(e.to_string()))?;
            let index = compiler
                .compile("schema.json", &mut schemas)
                .map_err(|e| Status::internal(e.to_string()))?;
            let mut cel_programs = std::collections::HashMap::new();
            collect_cel_programs(schema, &mut cel_programs);
            #[cfg(test)]
            cache.record_cel_compiles(cel_programs.len());
            let compiled = std::sync::Arc::new(crate::state::CompiledCrSchema {
                schemas,
                index,
                cel_programs,
            });
            cache.insert(ctx.schema_cache_key.clone(), compiled.clone());
            compiled
        }
    };

    compiled
        .schemas
        .validate(obj, compiled.index)
        .map_err(|e| {
            Status::unprocessable_entity(format!(
                "CR schema validation failed: {}",
                enum_violation_message(&e, obj)
                    .or_else(|| required_violation_message(&e))
                    .unwrap_or_else(|| e.to_string())
            ))
        })?;

    // Only run CEL rules once the object is already structurally valid — evaluating a
    // rule like `self.foo > 0` against a body that doesn't even have `foo` typed as a
    // number yet produces confusing CEL runtime errors instead of the clearer boon
    // "wrong type" error above.
    validate_cel_rules(schema, obj, old_object, "", &compiled.cel_programs)
}

/// Walks `schema` collecting a pre-compiled `cel::Program` for every unique
/// `x-kubernetes-validations` `rule`/`messageExpression` CEL source string reachable from
/// it, so `validate_cel_rules`'s per-request walk never needs to call
/// `cel::Program::compile` for a schema whose CRD generation is already cached — see
/// `CrSchemaCache`/`CompiledCrSchema::cel_programs`. Compiling is a pure function of the
/// source text, so two rules with identical text (anywhere in the schema, including
/// across different `oneOf`/`anyOf` branches) share one compiled program.
///
/// Unlike `validate_cel_rules`'s data-driven walk (which only follows the `oneOf`/`anyOf`
/// branch(es) a given object actually matches), this walks every branch of every
/// combinator unconditionally — it has no object to test against, and a request against a
/// different branch later must still hit a warm cache. A source string that fails to
/// compile is simply omitted here; `evaluate_cel_rule`/`evaluate_message_expression`
/// re-attempt (and re-fail with the same message) on the resulting cache miss, so error
/// behavior is unaffected by this being a best-effort prewarm.
fn collect_cel_programs(
    schema: &serde_json::Value,
    out: &mut std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
) {
    if let Some(rules) = schema
        .get("x-kubernetes-validations")
        .and_then(|v| v.as_array())
    {
        for rule in rules {
            for key in ["rule", "messageExpression"] {
                if let Some(text) = rule.get(key).and_then(|v| v.as_str()) {
                    if !out.contains_key(text) {
                        if let Ok(program) = cel::Program::compile(text) {
                            out.insert(text.to_string(), std::sync::Arc::new(program));
                        }
                    }
                }
            }
        }
    }
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for sub_schema in props.values() {
            collect_cel_programs(sub_schema, out);
        }
    }
    if let Some(items_schema) = schema.get("items") {
        collect_cel_programs(items_schema, out);
    }
    for combinator in ["allOf", "oneOf", "anyOf"] {
        if let Some(branches) = schema.get(combinator).and_then(|v| v.as_array()) {
            for branch in branches {
                collect_cel_programs(branch, out);
            }
        }
    }
}

/// Returns the pre-compiled program for `text` from `programs` — the common case once a
/// CRD generation's schema is cached, see `collect_cel_programs` — or compiles it fresh.
/// The fallback only runs on a genuine cache miss, or when `text` failed to compile during
/// the schema walk (in which case the same compile error is reproduced here rather than
/// silently swallowed).
fn resolve_cel_program(
    programs: &std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
    text: &str,
) -> Result<std::sync::Arc<cel::Program>, cel::ParseErrors> {
    if let Some(program) = programs.get(text) {
        return Ok(std::sync::Arc::clone(program));
    }
    cel::Program::compile(text).map(std::sync::Arc::new)
}

/// Recursively evaluate `x-kubernetes-validations` CEL rules declared anywhere in
/// `schema`, walking `obj` (and `old_node`, when present) in lockstep with the schema
/// shape — mirrors `apply_crd_schema_defaults`'s recursion (`properties` for objects,
/// `items` for arrays) rather than `walk_schema_dos_bounds`'s schema-only walk, because
/// a CEL rule's `self`/`oldSelf` bindings need the *data* at each schema node, not just
/// the schema node itself. Also recurses into `oneOf`/`anyOf`/`allOf` branches — a rule
/// reachable only through one of these combinators (e.g. cert-manager's Issuer
/// backend union, Gateway API's filter-type union) previously never fired at all.
///
/// A rule under a property that is absent from `obj` is not evaluated — matches
/// upstream: `self` must exist for a rule to run at all.
fn validate_cel_rules(
    schema: &serde_json::Value,
    obj: &serde_json::Value,
    old_node: Option<&serde_json::Value>,
    field_path: &str,
    programs: &std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
) -> Result<(), crate::status::StatusError> {
    if let Some(rules) = schema
        .get("x-kubernetes-validations")
        .and_then(|v| v.as_array())
    {
        for rule in rules {
            evaluate_cel_rule(rule, schema, obj, old_node, field_path, programs)?;
        }
    }

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        if let Some(map) = obj.as_object() {
            for (key, sub_schema) in props {
                if let Some(child) = map.get(key) {
                    let child_old = old_node.and_then(|o| o.get(key));
                    validate_cel_rules(
                        sub_schema,
                        child,
                        child_old,
                        &join_cr_field_path(field_path, key),
                        programs,
                    )?;
                }
            }
        }
    } else if let Some(items_schema) = schema.get("items") {
        if let Some(arr) = obj.as_array() {
            for (i, item) in arr.iter().enumerate() {
                let item_old = old_node.and_then(|o| o.as_array()).and_then(|a| a.get(i));
                validate_cel_rules(
                    items_schema,
                    item,
                    item_old,
                    &format!("{field_path}[{i}]"),
                    programs,
                )?;
            }
        }
    }

    // `allOf` branches must all hold simultaneously, so every branch's rules apply
    // unconditionally. `oneOf`/`anyOf` branches are alternatives — boon has already
    // confirmed `obj` satisfies the combinator as a whole (exactly one branch for
    // `oneOf`, at least one for `anyOf`) by the time this runs, so only the branch(es)
    // `obj` actually conforms to are evaluated; running a rule against a branch it
    // doesn't match would misfire on fields the branch assumes exist but don't (e.g. a
    // "no such key" CEL error), not produce a meaningful pass/fail.
    if let Some(branches) = schema.get("allOf").and_then(|v| v.as_array()) {
        for branch in branches {
            validate_cel_rules(branch, obj, old_node, field_path, programs)?;
        }
    }
    for combinator in ["oneOf", "anyOf"] {
        if let Some(branches) = schema.get(combinator).and_then(|v| v.as_array()) {
            for branch in branches {
                if schema_branch_structurally_matches(branch, obj) {
                    validate_cel_rules(branch, obj, old_node, field_path, programs)?;
                }
            }
        }
    }
    Ok(())
}

/// Best-effort check for whether `obj` conforms to `branch`, used to pick which
/// `oneOf`/`anyOf` branch(es) a CEL rule should evaluate against. This deliberately
/// does not re-implement full JSON Schema validation — boon already did that for the
/// whole document before `validate_cel_rules` ever runs — it only checks the
/// constraints real CRDs use to discriminate between branches (`type`, `required`,
/// `enum`), e.g. cert-manager's Issuer backend union or Gateway API's filter-type union.
fn schema_branch_structurally_matches(branch: &serde_json::Value, obj: &serde_json::Value) -> bool {
    if let Some(want_type) = branch.get("type").and_then(|v| v.as_str()) {
        let matches = match want_type {
            "object" => obj.is_object(),
            "array" => obj.is_array(),
            "string" => obj.is_string(),
            "boolean" => obj.is_boolean(),
            "integer" => obj.is_i64() || obj.is_u64(),
            "number" => obj.is_number(),
            "null" => obj.is_null(),
            _ => true,
        };
        if !matches {
            return false;
        }
    }
    if let Some(required) = branch.get("required").and_then(|v| v.as_array()) {
        let Some(map) = obj.as_object() else {
            return false;
        };
        let all_present = required
            .iter()
            .all(|k| k.as_str().is_some_and(|k| map.contains_key(k)));
        if !all_present {
            return false;
        }
    }
    if let Some(allowed) = branch.get("enum").and_then(|v| v.as_array()) {
        if !allowed.contains(obj) {
            return false;
        }
    }
    true
}

/// CEL lexer reserved words (google/cel-spec langdef.md `RESERVED`) that a structural
/// schema field name collides with most often — `namespace` above all, since it's a
/// property on nearly every Kubernetes object. Mirrors
/// `k8s.io/apiserver/pkg/cel.celReservedSymbols` exactly.
const CEL_RESERVED_WORDS: &[&str] = &[
    "true",
    "false",
    "null",
    "in",
    "as",
    "break",
    "const",
    "continue",
    "else",
    "for",
    "function",
    "if",
    "import",
    "let",
    "loop",
    "package",
    "namespace",
    "return",
    "var",
    "void",
    "while",
];

/// Escapes `ident` into a valid CEL identifier (`[a-zA-Z_][a-zA-Z0-9_]*`), matching
/// Kubernetes' structural-schema field escaping exactly
/// (https://kubernetes.io/docs/reference/using-api/cel/#escaping,
/// `k8s.io/apiserver/pkg/cel.Escape`): a name that is itself a CEL reserved word (e.g.
/// `namespace`) becomes `__namespace__`; `.`, `-`, `/`, and a literal `__` become
/// `__dot__`, `__dash__`, `__slash__`, `__underscores__` respectively (in that priority
/// order — a run of exactly two underscores is one `__underscores__` substitution, not
/// two single-underscore ones). Returns `None` if `ident` cannot be represented as a CEL
/// identifier at all (empty, leading digit, or a character outside
/// `[a-zA-Z0-9_.\-/]`) — such a field is simply unreachable from any CEL rule, matching
/// upstream's `common.SchemaDeclType`, which silently omits it from the generated CEL
/// struct type rather than exposing it under some fallback name.
fn cel_escape_ident(ident: &str) -> Option<String> {
    if ident.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if CEL_RESERVED_WORDS.contains(&ident) {
        return Some(format!("__{ident}__"));
    }

    let chars: Vec<char> = ident.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(ident.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '_' && chars.get(i + 1) == Some(&'_') {
            out.push_str("__underscores__");
            i += 2;
            continue;
        }
        match c {
            '.' => out.push_str("__dot__"),
            '-' => out.push_str("__dash__"),
            '/' => out.push_str("__slash__"),
            c if c.is_ascii_alphanumeric() || c == '_' => out.push(c),
            _ => return None,
        }
        i += 1;
    }
    Some(out)
}

/// Recursively renames `value`'s object keys that `schema` declares under a structural
/// `properties` map to their CEL-escaped form (`cel_escape_ident`), so binding `value`
/// as a CEL `self`/`oldSelf` variable lets a rule reach a reserved-word or special-char
/// field the way its author wrote it — e.g. upstream external-snapshotter's
/// VolumeSnapshotContent CRD ships `rule: has(self.name) && has(self.__namespace__)` on
/// a field literally named `namespace`. Without this, `self.__namespace__` can never
/// resolve (the bound object only ever has a `namespace` key), so `has()` is always
/// false and the rule spuriously rejects every write, however the CR is populated.
///
/// A key under an `additionalProperties` map schema is left untouched: Kubernetes only
/// escapes/unescapes property names declared in a structural schema's `properties`,
/// never arbitrary map keys (`k8s.io/apiserver/pkg/cel/common.unstructuredMap.Find` only
/// unescapes when `schema.Properties() != nil`) — a map key literally named `namespace`
/// is reachable only via index syntax (`self.m['namespace']`), which needs no escaping
/// since it's a string literal, not an identifier.
fn cel_escape_self_keys(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> serde_json::Value {
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        let Some(map) = value.as_object() else {
            return value.clone();
        };
        let mut out = serde_json::Map::with_capacity(map.len());
        for (key, v) in map {
            match props.get(key) {
                Some(sub_schema) => {
                    if let Some(escaped) = cel_escape_ident(key) {
                        out.insert(escaped, cel_escape_self_keys(sub_schema, v));
                    }
                    // else: unescapable field name — omit, matching upstream (see doc
                    // comment above): such a field is never declared in the CEL type.
                }
                // Not a declared property (e.g. data kept only via
                // x-kubernetes-preserve-unknown-fields) — untyped, so not reachable
                // from a CEL rule either way; keep it verbatim rather than drop data.
                None => {
                    out.insert(key.clone(), v.clone());
                }
            }
        }
        return serde_json::Value::Object(out);
    }
    if let Some(items_schema) = schema.get("items") {
        return match value.as_array() {
            Some(arr) => serde_json::Value::Array(
                arr.iter()
                    .map(|item| cel_escape_self_keys(items_schema, item))
                    .collect(),
            ),
            None => value.clone(),
        };
    }
    if let Some(ap_schema) = schema.get("additionalProperties").filter(|v| v.is_object()) {
        return match value.as_object() {
            Some(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), cel_escape_self_keys(ap_schema, v)))
                    .collect(),
            ),
            None => value.clone(),
        };
    }
    value.clone()
}

/// Wall-clock budget for evaluating a single CEL rule or `messageExpression`. Upstream
/// kube-apiserver rejects over-budget CEL rules at CRD admission time via a static
/// per-rule "estimated cost" analysis (k8s.io/apiserver/pkg/cel cost estimation); u7s has
/// no equivalent static cost estimator, so this bounds the same risk — a CRD-author-
/// supplied rule with unbounded runtime cost (e.g. a `.matches()` call against a
/// pathological regex, or a nested `.all()`/`.filter()` comprehension over a large
/// CR-author-controlled list) — at the point it actually runs, on every CR write, rather
/// than trying to predict its cost statically. Mirrors `walk_schema_dos_bounds` (crd.rs),
/// which bounds the equivalent risk for boon schema compilation.
const CEL_RULE_EVAL_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// Caps how many `execute_cel_with_budget` threads may be alive at once. Each thread
/// that outlives `CEL_RULE_EVAL_BUDGET` is abandoned (see below) rather than joined, so
/// without a cap a flood of concurrent writes carrying a pathological CEL rule could
/// still exhaust host threads/CPU even though each individual request keeps returning
/// in ~`CEL_RULE_EVAL_BUDGET`. A legitimate cluster should essentially never hit this —
/// it only bounds a sustained attempt to spawn many over-budget evaluations at once.
const MAX_CONCURRENT_CEL_EVAL_THREADS: usize = 24;

/// Bounds how many owners may hold a slot at once, rejecting new acquisitions outright
/// once the cap is reached instead of letting the count grow without bound. A plain
/// struct (rather than a bare static counter) so the bounding behavior can be exercised
/// directly in a test with its own small, local cap — the real, process-wide gate below
/// is shared by every concurrent request's CEL evaluation, so a test that saturated it
/// (even briefly) would spuriously reject unrelated evaluations running at the same time.
struct ConcurrencyGate {
    in_flight: std::sync::atomic::AtomicUsize,
    cap: usize,
}

impl ConcurrencyGate {
    const fn new(cap: usize) -> Self {
        Self {
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            cap,
        }
    }

    /// Reserves a slot and returns `true`, or returns `false` if the cap has already
    /// been reached. On `false` no slot is held, so the caller must not call `release`.
    fn try_acquire(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.in_flight.fetch_add(1, Ordering::SeqCst) >= self.cap {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            false
        } else {
            true
        }
    }

    fn release(&self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The process-wide gate every `execute_cel_with_budget` call reserves a slot from.
static CEL_EVAL_THREAD_GATE: ConcurrencyGate =
    ConcurrencyGate::new(MAX_CONCURRENT_CEL_EVAL_THREADS);

/// Releases a `ConcurrencyGate` slot on `Drop`, so the slot is freed whether the guarded
/// scope returns normally or unwinds from a panic. `execute_cel_with_budget`'s spawned
/// thread runs an untrusted, CRD-author-supplied CEL rule via `cel::Program::execute`,
/// which has reachable `panic!` sites in the `cel` crate's evaluator (e.g. cel 0.14.3
/// `objects.rs:1546`, `:1467`). A manually-placed `gate.release()` call *after*
/// `execute()` would be skipped by such a panic, permanently leaking the slot -- enough
/// leaked panics wedge `CEL_EVAL_THREAD_GATE` for every future CR write's CEL
/// validation, the exact DoS this file exists to prevent, just triggered by malformed
/// input instead of slow input.
struct GateGuard<'a>(&'a ConcurrencyGate);

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Marker: a CEL evaluation was rejected without running to completion — either it did
/// not finish within `CEL_RULE_EVAL_BUDGET`, or evaluation was refused outright because
/// `MAX_CONCURRENT_CEL_EVAL_THREADS` other over-budget evaluations are already in flight.
enum CelEvalOverBudget {
    TimedOut,
    TooManyInFlight,
}

/// Runs `program` against `cel_ctx` on a dedicated thread, bounded by `budget` wall-clock
/// time, so a CEL expression with unbounded runtime cost cannot hang the request-handling
/// thread indefinitely (see `CEL_RULE_EVAL_BUDGET`). The `cel` crate's interpreter has no
/// cooperative cancellation hook, so this is the only way to bound wall-clock time without
/// risking undefined behavior from force-killing a thread; every CEL expression is
/// guaranteed to terminate (the language has no unbounded loops), so an abandoned
/// over-budget thread still exits on its own eventually — this only bounds how long a
/// single request waits for it. `gate` (production callers always pass
/// `CEL_EVAL_THREAD_GATE`) separately bounds how many such abandoned threads may
/// accumulate at once; it's a parameter rather than reaching for that static directly so
/// tests can inject a small, local gate instead of saturating the real, process-wide one
/// (which every concurrently-running request's CEL evaluation also relies on).
fn execute_cel_with_budget(
    program: &std::sync::Arc<cel::Program>,
    cel_ctx: cel::Context<'static>,
    budget: std::time::Duration,
    gate: &'static ConcurrencyGate,
) -> Result<Result<cel::Value, cel::ExecutionError>, CelEvalOverBudget> {
    if !gate.try_acquire() {
        return Err(CelEvalOverBudget::TooManyInFlight);
    }

    let program = std::sync::Arc::clone(program);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _guard = GateGuard(gate);
        let result = program.execute(&cel_ctx);
        let _ = tx.send(result);
    });
    rx.recv_timeout(budget)
        .map_err(|_| CelEvalOverBudget::TimedOut)
}

/// Evaluate a single `x-kubernetes-validations` entry (`{rule, message,
/// messageExpression, reason, fieldPath, optionalOldSelf}`, per the CRD-storage
/// round-trip in `apiextensions_gen_adapter.rs`) against `self_value`, optionally
/// binding `oldSelf` to `old_self_value`. `schema` is the schema node `self_value` was
/// validated against (i.e. `self`'s own type) — used to escape reserved-word/special-char
/// property names (`cel_escape_self_keys`) before binding, so a rule can reach a field
/// like `namespace` as `self.__namespace__`, matching how the CRD author wrote it.
fn evaluate_cel_rule(
    rule: &serde_json::Value,
    schema: &serde_json::Value,
    self_value: &serde_json::Value,
    old_self_value: Option<&serde_json::Value>,
    field_path: &str,
    programs: &std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
) -> Result<(), crate::status::StatusError> {
    let Some(rule_text) = rule.get("rule").and_then(|v| v.as_str()) else {
        return Ok(());
    };

    let program = resolve_cel_program(programs, rule_text).map_err(|e| {
        Status::unprocessable_entity(format!(
            "{field_path}: x-kubernetes-validations rule does not compile: {e} (rule: {rule_text})"
        ))
    })?;

    let escaped_self = cel_escape_self_keys(schema, self_value);
    let escaped_old_self = old_self_value.map(|v| cel_escape_self_keys(schema, v));

    let mut cel_ctx = cel::Context::default();
    register_cel_string_extensions(&mut cel_ctx);
    cel_ctx
        .add_variable("self", &escaped_self)
        .map_err(|e| Status::internal(format!("CEL: failed to bind self: {e}")))?;
    if let Some(old) = &escaped_old_self {
        cel_ctx
            .add_variable("oldSelf", old)
            .map_err(|e| Status::internal(format!("CEL: failed to bind oldSelf: {e}")))?;
    }

    let result = match execute_cel_with_budget(
        &program,
        cel_ctx,
        CEL_RULE_EVAL_BUDGET,
        &CEL_EVAL_THREAD_GATE,
    ) {
        Err(CelEvalOverBudget::TimedOut) => {
            return Err(Status::unprocessable_entity(format!(
                "{field_path}: x-kubernetes-validations rule exceeded its evaluation time \
                 budget of {CEL_RULE_EVAL_BUDGET:?} — rejecting to bound CEL evaluation cost \
                 (rule: {rule_text})"
            )));
        }
        Err(CelEvalOverBudget::TooManyInFlight) => {
            return Err(Status::unprocessable_entity(format!(
                "{field_path}: too many x-kubernetes-validations rules are currently \
                 exceeding their evaluation time budget — rejecting to bound concurrent CEL \
                 evaluation cost (rule: {rule_text})"
            )));
        }
        Ok(Ok(v)) => v,
        // `oldSelf` is only meaningful on UPDATE, when the field being validated also
        // existed in the previous object — upstream skips (does not fail) a rule that
        // references `oldSelf` in every other case, e.g. CREATE, or a newly-added field.
        // We don't bind `oldSelf` in those cases, so the interpreter reports it as an
        // undeclared reference; that specific error means "not applicable here", not
        // "the rule failed".
        Ok(Err(cel::ExecutionError::UndeclaredReference(ref name)))
            if old_self_value.is_none() && name.as_str() == "oldSelf" =>
        {
            return Ok(());
        }
        Ok(Err(e)) => {
            return Err(Status::unprocessable_entity(format!(
                "{field_path}: x-kubernetes-validations rule failed to evaluate: {e} (rule: {rule_text})"
            )));
        }
    };

    let passed = match result {
        cel::Value::Bool(b) => b,
        other => {
            return Err(Status::unprocessable_entity(format!(
                "{field_path}: x-kubernetes-validations rule must evaluate to a bool \
                 (rule: {rule_text}, got: {other:?})"
            )));
        }
    };
    if passed {
        return Ok(());
    }

    let detail = cel_rule_failure_detail(
        rule,
        rule_text,
        &escaped_self,
        escaped_old_self.as_ref(),
        programs,
    );
    let value_prefix = match self_value {
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => String::new(),
        other => format!("\"{}\": ", json_value_as_display_string(other)),
    };
    Err(Status::unprocessable_entity(format!(
        "{field_path}: Invalid value: {value_prefix}{detail}"
    )))
}

/// The message to report for a failed CEL rule: the CRD-declared `message`, or the
/// result of evaluating `messageExpression` if that's what the CRD author supplied
/// instead, or `"failed rule: <rule>"` as upstream's own default
/// (`ruleMessageOrDefault` in apiextensions-apiserver's cel/validation.go).
fn cel_rule_failure_detail(
    rule: &serde_json::Value,
    rule_text: &str,
    self_value: &serde_json::Value,
    old_self_value: Option<&serde_json::Value>,
    programs: &std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
) -> String {
    if let Some(msg) = rule
        .get("message")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return msg.to_string();
    }
    if let Some(expr) = rule.get("messageExpression").and_then(|v| v.as_str()) {
        if let Some(rendered) =
            evaluate_message_expression(expr, self_value, old_self_value, programs)
        {
            return rendered;
        }
    }
    format!("failed rule: {rule_text}")
}

/// Evaluates a `messageExpression` CEL string against the same `self`/`oldSelf`
/// bindings as the rule it belongs to. Returns `None` (falling back to the CRD's
/// `message` or the default "failed rule: ..." text) on any compile/runtime error, or
/// if the result isn't a non-empty single-line string — matches upstream's requirement
/// that a `messageExpression` "should evaluate to a non-empty string" with "no line
/// breaks".
fn evaluate_message_expression(
    expr: &str,
    self_value: &serde_json::Value,
    old_self_value: Option<&serde_json::Value>,
    programs: &std::collections::HashMap<String, std::sync::Arc<cel::Program>>,
) -> Option<String> {
    let program = resolve_cel_program(programs, expr).ok()?;
    let mut cel_ctx = cel::Context::default();
    register_cel_string_extensions(&mut cel_ctx);
    cel_ctx.add_variable("self", self_value).ok()?;
    if let Some(old) = old_self_value {
        cel_ctx.add_variable("oldSelf", old).ok()?;
    }
    match execute_cel_with_budget(
        &program,
        cel_ctx,
        CEL_RULE_EVAL_BUDGET,
        &CEL_EVAL_THREAD_GATE,
    )
    .ok()?
    .ok()?
    {
        cel::Value::String(s) => {
            let s = s.trim();
            (!s.is_empty() && !s.contains('\n')).then(|| s.to_string())
        }
        _ => None,
    }
}

/// Registers CEL string-extension functions the vendored `cel` crate's stdlib doesn't
/// implement but real-world CRDs rely on. Kubernetes' own CEL library adds `.split()`,
/// `.lowerAscii()`, `.upperAscii()`, `.replace()`, and `.join()` as the `strings` extension;
/// the `cel` crate's `Env::stdlib()` only covers the base spec's `contains`/`startsWith`/
/// `endsWith`/`matches`/`size`. Without these, e.g. Gateway API's annotation-key-prefix rule
/// (`self.split("/")[0].size() < 253`, `gateway.networking.k8s.io_gateways.yaml` L262) or
/// Crossplane's `self.plural == self.plural.lowerAscii()` would fail every CR write with an
/// "undeclared reference" CEL error instead of evaluating as the CRD author intended.
fn register_cel_string_extensions(ctx: &mut cel::Context) {
    ctx.add_function("split", cel_split);
    ctx.add_function("lowerAscii", cel_lower_ascii);
    ctx.add_function("upperAscii", cel_upper_ascii);
    ctx.add_function("replace", cel_replace);
    ctx.add_function("join", cel_join);
}

fn cel_split(
    cel::extractors::This(this): cel::extractors::This<std::sync::Arc<String>>,
    sep: std::sync::Arc<String>,
) -> Result<cel::Value, cel::ExecutionError> {
    Ok(cel::Value::List(std::sync::Arc::new(
        this.split(sep.as_str())
            .map(|part| cel::Value::String(std::sync::Arc::new(part.to_string())))
            .collect(),
    )))
}

fn cel_lower_ascii(
    cel::extractors::This(this): cel::extractors::This<std::sync::Arc<String>>,
) -> Result<cel::Value, cel::ExecutionError> {
    Ok(cel::Value::String(std::sync::Arc::new(
        this.to_ascii_lowercase(),
    )))
}

fn cel_upper_ascii(
    cel::extractors::This(this): cel::extractors::This<std::sync::Arc<String>>,
) -> Result<cel::Value, cel::ExecutionError> {
    Ok(cel::Value::String(std::sync::Arc::new(
        this.to_ascii_uppercase(),
    )))
}

fn cel_replace(
    cel::extractors::This(this): cel::extractors::This<std::sync::Arc<String>>,
    old: std::sync::Arc<String>,
    new: std::sync::Arc<String>,
) -> Result<cel::Value, cel::ExecutionError> {
    Ok(cel::Value::String(std::sync::Arc::new(
        this.replace(old.as_str(), new.as_str()),
    )))
}

/// `self.join()` concatenates a list of strings with no separator; `self.join(sep)` joins
/// with `sep` — Kubernetes' CEL library exposes these as two overloads of the same name,
/// collapsed here into one function since `Context::add_function` registers a single
/// implementation per name and dispatches by receiver type, not by argument count.
fn cel_join(
    cel::extractors::This(this): cel::extractors::This<cel::Value>,
    cel::extractors::Arguments(args): cel::extractors::Arguments,
) -> Result<cel::Value, cel::ExecutionError> {
    let cel::Value::List(items) = this else {
        return Err(cel::ExecutionError::function_error(
            "join",
            "target is not a list",
        ));
    };
    let sep = match args.first() {
        None => String::new(),
        Some(cel::Value::String(s)) => s.as_str().to_string(),
        Some(_) => {
            return Err(cel::ExecutionError::function_error(
                "join",
                "separator must be a string",
            ));
        }
    };
    let mut parts = Vec::with_capacity(items.len());
    for item in items.iter() {
        match item {
            cel::Value::String(s) => parts.push(s.as_str().to_string()),
            other => {
                return Err(cel::ExecutionError::function_error(
                    "join",
                    format!("list element is not a string: {other:?}"),
                ));
            }
        }
    }
    Ok(cel::Value::String(std::sync::Arc::new(parts.join(&sep))))
}

/// Depth-first search for an `enum` keyword violation in a boon validation-error tree,
/// rendered in the k8s `field.Error` "Unsupported value" phrasing
/// (`Unsupported value: "<bad>": supported values: "<a>", "<b>"`) instead of boon's own
/// wording (`value must be one of 'a', 'b'`). kubectl and the upstream CRD-with-validation
/// conformance test match on this exact phrasing, so a differently-worded rejection is
/// treated as "did not reject" even though the CR was in fact rejected.
///
/// boon's `ErrorKind::Enum` carries only the allowed set, not the offending value, so the
/// value is recovered by walking `instance_location` back into the original `obj`.
fn enum_violation_message(e: &boon::ValidationError, obj: &serde_json::Value) -> Option<String> {
    if let boon::ErrorKind::Enum { want } = &e.kind {
        let got = resolve_instance_location(obj, &e.instance_location)
            .map(json_value_as_display_string)
            .unwrap_or_else(|| "<value>".to_string());
        let supported = want
            .iter()
            .map(|v| format!("\"{}\"", json_value_as_display_string(v)))
            .collect::<Vec<_>>()
            .join(", ");
        return Some(format!(
            "Unsupported value: \"{got}\": supported values: {supported}"
        ));
    }
    e.causes
        .iter()
        .find_map(|cause| enum_violation_message(cause, obj))
}

/// Depth-first search for a `required` keyword violation in a boon validation-error tree,
/// rendered in the k8s `field.Error` "Required value" phrasing (`<path>: Required value`)
/// instead of boon's own wording (`missing properties 'name'`). kubectl and the upstream
/// CRD-with-validation conformance test match on this exact phrasing (or the legacy
/// client-side-validation wording `missing required field "name"`), so a differently-worded
/// rejection is treated as "did not reject" even though the CR was in fact rejected.
fn required_violation_message(e: &boon::ValidationError) -> Option<String> {
    if let boon::ErrorKind::Required { want } = &e.kind {
        let field = want.first()?;
        let base = instance_location_as_field_path(&e.instance_location);
        let path = if base.is_empty() {
            (*field).to_string()
        } else {
            format!("{base}.{field}")
        };
        return Some(format!("{path}: Required value"));
    }
    e.causes.iter().find_map(required_violation_message)
}

/// Renders a boon `InstanceLocation` as a k8s `field.Path`-style dotted/bracketed path
/// (`spec.bars[0]`) rather than boon's JSON-pointer form (`/spec/bars/0`).
fn instance_location_as_field_path(loc: &boon::InstanceLocation) -> String {
    let mut path = String::new();
    for tok in &loc.tokens {
        match tok {
            boon::InstanceToken::Prop(p) => {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(p);
            }
            boon::InstanceToken::Item(i) => {
                path.push_str(&format!("[{i}]"));
            }
        }
    }
    path
}

/// Follows a boon `InstanceLocation`'s JSON-pointer tokens into `obj` to recover the value
/// that failed validation at that location.
fn resolve_instance_location<'a>(
    obj: &'a serde_json::Value,
    loc: &boon::InstanceLocation,
) -> Option<&'a serde_json::Value> {
    let mut cur = obj;
    for tok in &loc.tokens {
        cur = match tok {
            boon::InstanceToken::Prop(p) => cur.get(p.as_ref())?,
            boon::InstanceToken::Item(i) => cur.get(i)?,
        };
    }
    Some(cur)
}

/// Renders a JSON value the way k8s's `field.Error` does for its `%q`/`%v` BadValue
/// formatting: strings unquoted here (the caller adds the surrounding quotes), everything
/// else via its normal JSON representation.
fn json_value_as_display_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// CRD structural-schema defaulting (openAPIV3Schema `default:` values)
// ---------------------------------------------------------------------------

/// Apply `default:` values declared in `schema` to `obj`, in place.
///
/// Matches upstream structural-schema defaulting
/// (apiextensions-apiserver/pkg/apiserver/schema/defaulting): a key is only filled in when
/// it is entirely absent from its parent object — an explicit `null` or any client-supplied
/// value is left untouched. Recursion follows the schema shape rather than a flat path:
///   - `type: object` (has `properties`): for each declared property missing from the
///     object, insert its `default`; for each property present, recurse into it.
///   - `type: array` (has `items`): recurse into every element already present in the
///     array, using the `items` schema. A default nested under an array item (e.g.
///     `list.items.properties.color.default`) must be applied per-element — the array
///     index is a position in an existing slice, never a key to create.
///
/// Called on every write (defaults are baked into what gets stored, matching upstream) and
/// on every read (a default added to the schema after an object was created must still show
/// up on GET/LIST against the *current* schema, since it was never persisted for that object).
pub(crate) fn apply_crd_schema_defaults(schema: &serde_json::Value, obj: &mut serde_json::Value) {
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        let Some(map) = obj.as_object_mut() else {
            return;
        };
        for (key, sub_schema) in props {
            match map.get_mut(key) {
                Some(existing) => apply_crd_schema_defaults(sub_schema, existing),
                None => {
                    if let Some(default) = sub_schema.get("default") {
                        map.insert(key.clone(), default.clone());
                    }
                }
            }
        }
        return;
    }
    if let Some(items_schema) = schema.get("items") {
        let Some(arr) = obj.as_array_mut() else {
            return;
        };
        for item in arr.iter_mut() {
            apply_crd_schema_defaults(items_schema, item);
        }
    }
}

// ---------------------------------------------------------------------------
// CR field validation (?fieldValidation=Strict/Warn/Ignore)
//
// Built-in resources get this from `json_patch::apply_field_validation`, which checks
// unknown fields against small hardcoded field lists per type. CRs have no fixed schema of
// their own — unknown-field detection must instead walk the CRD's openAPIV3Schema, honoring
// the structural-schema extensions x-kubernetes-preserve-unknown-fields (don't reject unknown
// fields under that subtree) and x-kubernetes-embedded-resource (the object carries its own
// implicit TypeMeta/ObjectMeta, so apiVersion/kind/metadata are allowed there even when the
// schema doesn't declare them). Without this, CRs silently accept typo'd/unknown fields and
// schema drift goes undetected — the whole point of fieldValidation=Strict.
// ---------------------------------------------------------------------------

/// The standard ObjectMeta JSON field names. Fixed regardless of what (if anything) the CRD
/// schema declares under `metadata`: CRD authors constrain existing ObjectMeta fields (e.g. a
/// `pattern` on `name`), they never add new ones, so schema-declared `metadata.properties`
/// are not consulted here.
const CR_KNOWN_METADATA_FIELDS: &[&str] = &[
    "name",
    "generateName",
    "namespace",
    "selfLink",
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "labels",
    "annotations",
    "ownerReferences",
    "finalizers",
    "managedFields",
    "clusterName",
];

/// Internal header used to thread the already-parsed `?fieldValidation=` query value from
/// resource.rs's CR-routing fallback (create_resource/patch_resource and their namespaced
/// variants) into this module. create_cr/patch_cr and their namespaced siblings are invoked
/// directly by resource.rs rather than dispatched by axum, so they have no `Query` extractor
/// of their own; resource.rs already parses the query string as `CreateQuery`/`PatchQuery`
/// for the built-in-resource path and forwards the value here instead of adding a parameter
/// to every one of these functions' dozens of existing call sites.
const FIELD_VALIDATION_HEADER: &str = "x-u7s-field-validation";

fn field_validation_mode(headers: &HeaderMap) -> Option<String> {
    headers
        .get(FIELD_VALIDATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Join a dot-path prefix with the next key, matching upstream `field.Path`'s `.String()`
/// (no leading dot: a top-level unknown field is reported as `"foo"`, not `".foo"`, so its
/// wording lines up with `unknown field "foo"`/`unknown field "spec.foo"` exactly as
/// `json_patch::apply_field_validation` and upstream's own strict-decoding errors do).
fn join_cr_field_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

/// Prune (remove) `value`'s object keys that `schema` does not declare, mirroring upstream
/// apiextensions-apiserver's `structuralpruning.PruneWithOptions`: for a structural schema,
/// removing fields the schema doesn't know about is UNCONDITIONAL — it runs regardless of
/// `?fieldValidation=`, which only controls whether the caller wants to be told what was
/// removed (`track_paths`), not whether removal happens. Without this, a CRD's schema is
/// purely advisory: unknown fields survive in storage forever, including ones a mutating
/// admission webhook added but the schema never declared.
///
/// `allow_type_meta` is true at the CR root and at any `x-kubernetes-embedded-resource`
/// object: both carry an implicit apiVersion/kind/metadata that the CRD author never
/// declares in `properties`, so those keys (and metadata's own fixed ObjectMeta fields) are
/// never pruned there. `x-kubernetes-preserve-unknown-fields: true` opts a subtree out of
/// pruning entirely (its whole point is to let CRDs like cert-manager keep free-form data).
fn prune_cr_unknown_fields(
    value: &mut serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
    allow_type_meta: bool,
    track_paths: bool,
    out: &mut Vec<String>,
) {
    let preserve_unknown = schema
        .get("x-kubernetes-preserve-unknown-fields")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if let Some(map) = value.as_object_mut() {
        let props = schema
            .get("properties")
            .and_then(serde_json::Value::as_object);
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            if allow_type_meta && (key == "apiVersion" || key == "kind") {
                continue;
            }
            if allow_type_meta && key == "metadata" {
                if let Some(meta) = map.get_mut(&key).and_then(serde_json::Value::as_object_mut) {
                    let mkeys: Vec<String> = meta.keys().cloned().collect();
                    for mkey in mkeys {
                        if !CR_KNOWN_METADATA_FIELDS.contains(&mkey.as_str()) {
                            if track_paths {
                                out.push(join_cr_field_path(path, &format!("metadata.{mkey}")));
                            }
                            meta.remove(&mkey);
                        }
                    }
                }
                continue;
            }
            match props.and_then(|p| p.get(&key)) {
                Some(sub_schema) => {
                    let embedded = sub_schema
                        .get("x-kubernetes-embedded-resource")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if let Some(sub_val) = map.get_mut(&key) {
                        prune_cr_unknown_fields(
                            sub_val,
                            sub_schema,
                            &join_cr_field_path(path, &key),
                            embedded,
                            track_paths,
                            out,
                        );
                    }
                }
                None if !preserve_unknown => {
                    if track_paths {
                        out.push(join_cr_field_path(path, &key));
                    }
                    map.remove(&key);
                }
                None => {}
            }
        }
        return;
    }
    if let Some(items_schema) = schema.get("items") {
        if let Some(arr) = value.as_array_mut() {
            for item in arr.iter_mut() {
                prune_cr_unknown_fields(
                    item,
                    items_schema,
                    path,
                    allow_type_meta,
                    track_paths,
                    out,
                );
            }
        }
    }
}

/// Prune `obj` against the CRD's structural schema with no path tracking, for the
/// post-admission re-prune every CR write applies right before storage: a mutating webhook
/// can add fields the schema doesn't declare (it has no notion of the CRD's schema), so the
/// object must be pruned again after webhooks run, not just once at decode time — matching
/// upstream's decode-then-mutate-then-convert-to-storage-version pipeline, where the
/// conversion step re-runs the same structural pruning. A no-op when the CRD has no schema.
fn prune_cr_for_storage(schema: Option<&serde_json::Value>, obj: &mut serde_json::Value) {
    if let Some(schema) = schema {
        prune_cr_unknown_fields(obj, schema, "", true, false, &mut Vec::new());
    }
}

/// Apply `?fieldValidation=` semantics against the CRD's structural schema, pruning `body`
/// in place along the way.
///
/// Detects unknown fields by walking the CRD's own openAPIV3Schema instead of a hardcoded
/// field list. Pruning itself happens regardless of `mode` (including `Ignore`/absent) —
/// only whether the removed paths are surfaced as a 422 (`Strict`) or a `Warning` header
/// (`Warn`) depends on `mode`. Returns `Ok(None)` without pruning when the CRD has no schema
/// at all — without one there is nothing to prune or validate field names against, matching
/// upstream's behaviour for schemaless CRDs.
///
/// `is_ssa` branches the wording upstream itself branches on by request type: an SSA
/// Apply-patch is validated by structured-merge-diff's typed-value walker, which reports
/// `.<path>: field not declared in schema` (its `fieldpath.PathElement.String()` always
/// renders a field name with a leading dot, so the accumulated path does too — see
/// sigs.k8s.io/structured-merge-diff's `typed/validate.go` and `fieldpath/element.go`).
/// Non-SSA Create/Update instead goes through strict decoding, mirrored by
/// `json_patch::apply_field_validation`, which reports `unknown field "<path>"`. Both
/// wordings are upstream-correct for their own request type — collapsing them to one
/// regresses the other: CustomResourcePublishOpenAPI asserts the non-dotted wording for a
/// plain create, while the FieldValidation Apply-patch tests assert the dotted one.
fn apply_cr_field_validation(
    body: &mut serde_json::Value,
    schema: Option<&serde_json::Value>,
    mode: Option<&str>,
    is_ssa: bool,
) -> Result<Option<HeaderValue>, crate::status::StatusError> {
    let Some(schema) = schema else {
        return Ok(None);
    };
    let mode = mode.unwrap_or("Ignore");
    let track_paths = mode != "Ignore";

    let mut unknown = Vec::new();
    prune_cr_unknown_fields(body, schema, "", true, track_paths, &mut unknown);
    if unknown.is_empty() {
        return Ok(None);
    }

    let joined = if is_ssa {
        unknown
            .iter()
            .map(|f| format!(".{f}: field not declared in schema"))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        unknown
            .iter()
            .map(|f| format!("unknown field \"{f}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };

    match mode {
        "Strict" if is_ssa => Err(Status::unprocessable_entity(joined)),
        "Strict" => Err(Status::unprocessable_entity(format!(
            "strict decoding error: {joined}"
        ))),
        "Warn" => {
            let msg = format!("299 - \"{joined}\"");
            let hv = HeaderValue::from_str(&msg).unwrap_or_else(|_| {
                HeaderValue::from_static("299 - \"unknown field(s) detected\"")
            });
            Ok(Some(hv))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// CR field selectors (CustomResourceFieldSelectors)
// ---------------------------------------------------------------------------

/// Test whether a CR object matches a `--field-selector` string, using the fields the CRD
/// author declared selectable for the requested version (`selectable_fields`) plus the
/// always-selectable `metadata.name`/`metadata.namespace`.
///
/// A field that is not in that allow-list resolves to "" regardless of what the object
/// actually contains, matching upstream's `fields.Set.Get()` fallback for an unrecognized
/// key: e.g. `spec.secret=x` on a field the CRD never declared selects nothing rather than
/// erroring. This allow-list is load-bearing, not cosmetic — CRs are schemaless JSON blobs,
/// so without it any body field an object happens to carry would become selectable, which
/// defeats the reason CustomResourceFieldSelectors requires fields to be explicitly declared.
///
/// Takes `namespaced`/`selectable_fields` rather than a whole `&CrContext` so the watch path
/// (`watch::watch_generic_for_cr`) can reuse this exact matching logic for CR watches without
/// pulling watch.rs's per-event filtering into a dependency on all of CrContext (schema,
/// conversion config, etc. are irrelevant to field-selector matching).
pub(crate) fn cr_matches_field_selector(
    obj: &serde_json::Value,
    selector: &str,
    namespaced: bool,
    selectable_fields: &[String],
) -> bool {
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let (field, expected, negated) = match term.split_once("!=") {
            Some((f, v)) => (f.trim(), v.trim(), true),
            None => match term.split_once('=') {
                Some((f, v)) => (f.trim(), v.trim(), false),
                None => continue,
            },
        };
        let selectable = field == "metadata.name"
            || (namespaced && field == "metadata.namespace")
            || selectable_fields.iter().any(|f| f == field);
        let equal = if selectable {
            u7s_store::json_path_equals(obj, field, expected)
        } else {
            expected.is_empty()
        };
        if equal == negated {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR handlers
// ---------------------------------------------------------------------------

/// Detect whether the Accept header requests PartialObjectMetadata or PartialObjectMetadataList.
/// The kcm metadatainformer sends Accept headers like:
///   application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
///   application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
fn wants_partial_object_metadata(accept: &str) -> bool {
    accept.contains("as=PartialObjectMetadata")
}

/// Strip spec/status from a full CR object, returning a PartialObjectMetadata-shaped value.
/// The GC only needs metadata (ownerReferences, finalizers, etc.) — spec/status are omitted.
fn to_partial_object_metadata(obj: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "PartialObjectMetadata",
        "metadata": obj.get("metadata").cloned().unwrap_or_default()
    })
}

pub async fn list_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    headers: axum::http::HeaderMap,
    query: super::generic::CollectionQuery,
    username: String,
) -> Result<Response, crate::status::StatusError> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // When no CRD exists for this group, return 406 if Table format was requested
    // (the resource is registered via APIService but Table is not implementable without
    // a CRD or proxy backend) rather than 404 Not Found.
    let ctx = match find_crd(&state, &group, &version, &plural).await {
        Ok(ctx) => ctx,
        Err(err) => {
            if super::table::wants_table(accept) {
                return Err(Status::not_acceptable(format!(
                    "the server does not support Table format for {group}/{version}/{plural}"
                )));
            }
            // A tombstoned CRD group returns 410 Gone. For non-watch requests (LIST, GET) this
            // is correct — informers that re-list after a watch 410 will also 410 and stop.
            // But for watch+sendInitialEvents=true, a bare HTTP 410 causes client-go to
            // re-list (which also 410s) and immediately retry, creating an infinite hot-loop
            // (~6000 req/s) that self-saturates the apiserver and kills conformance runs.
            // Instead, serve an empty sendInitialEvents watch stream (200 + BOOKMARK at rv=0)
            // so the informer parks at a valid resourceVersion rather than looping.
            if err.0 == StatusCode::GONE
                && query.watch == Some(true)
                && query.send_initial_events == Some(true)
            {
                let pom = wants_partial_object_metadata(accept);
                let (watch_api_version, watch_kind) = if pom {
                    (
                        "meta.k8s.io/v1".to_string(),
                        "PartialObjectMetadata".to_string(),
                    )
                } else {
                    (format!("{group}/{version}"), plural.clone())
                };
                let prefix = cr_list_prefix(&group, &plural, None);
                return super::watch::watch_generic(
                    state,
                    super::watch::WatchConfig {
                        prefix,
                        api_version: watch_api_version,
                        kind: watch_kind,
                        from_revision: query.resource_version.unwrap_or(0),
                        initial_items: Some((vec![], 0)),
                        label_selector: query.label_selector,
                        field_selector: query.field_selector,
                        allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                        username,
                        as_partial_object_metadata: pom,
                        group: group.clone(),
                        plural: plural.clone(),
                        timeout_seconds: query.timeout_seconds,
                    },
                )
                .await;
            }
            return Err(err);
        }
    };

    // For namespaced CRDs, the cluster-wide path lists across all namespaces.
    // Namespaced CRs are stored as /registry/cr/{group}/{plural}/{ns}/{name},
    // so prefix without namespace matches all of them.
    let prefix = cr_list_prefix(&group, &plural, None);

    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            (format!("{group}/{version}"), ctx.kind.clone())
        };
        let mut initial_items = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            &group,
            &plural,
        )
        .await?;
        // Convert the sendInitialEvents backlog to the requested version — independent of
        // `pom` (a PartialObjectMetadata watch still needs the full body converted first for
        // schema-declared fields to exist) — the same way LIST converts items, before
        // watch_generic_for_cr ever sees them. Without this, a field selector on a
        // requested-version-only field matches nothing (see convert_cr_list_items).
        let desired_api_version = format!("{group}/{version}");
        if let Some((items, _)) = initial_items.as_mut() {
            convert_cr_list_items(
                &state,
                ctx.conversion_webhook_client_config.as_ref(),
                items,
                &desired_api_version,
            )
            .await?;
        }
        return super::watch::watch_generic_for_cr(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: query.resource_version.unwrap_or(0),
                initial_items,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
            super::watch::CrFieldSelectorContext {
                namespaced: ctx.namespaced,
                selectable_fields: ctx.selectable_fields.clone(),
                conversion_webhook_client_config: ctx.conversion_webhook_client_config.clone(),
                desired_api_version,
            },
        )
        .await;
    }

    // Decode BEFORE listing: on a continuation request this pins the resourceVersion this
    // response (and every later page) must report — see decode_continue's doc for why.
    let continue_decoded = query
        .continue_token
        .as_deref()
        .map(|t| {
            super::generic::decode_continue(
                t,
                state.store.current_revision(),
                &state.continue_token_key,
            )
        })
        .transpose()?;
    let continue_key = continue_decoded.as_ref().map(|(k, _)| k.clone());
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                // CR field selectors can reference arbitrary CRD-declared JSON paths that only
                // exist after per-item conversion (see convert_cr_list_items below) — the store
                // has no way to evaluate those against raw stored bytes, so filtering happens
                // in-memory afterward instead (cr_matches_field_selector), same as this codebase
                // already does for "events" in resource.rs.
                field_selector: None,
                limit: query.limit,
                continue_key,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    // First page (no continue token yet): the fresh store revision becomes the pin for
    // subsequent pages. Continuation page: reuse the pin decoded above, not the store's
    // current (possibly-advanced) revision.
    let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    // Batch-convert only the items that actually need it (see convert_cr_list_items).
    let desired_api_version = format!("{group}/{version}");
    convert_cr_list_items(
        &state,
        ctx.conversion_webhook_client_config.as_ref(),
        &mut items,
        &desired_api_version,
    )
    .await?;

    if let Some(schema) = ctx.schema.as_ref() {
        for item in items.iter_mut() {
            apply_crd_schema_defaults(schema, item);
        }
    }

    if let Some(selector) = query.field_selector.as_deref() {
        items.retain(|item| {
            cr_matches_field_selector(item, selector, ctx.namespaced, &ctx.selectable_fields)
        });
    }

    if pom {
        let pom_items: Vec<serde_json::Value> =
            items.iter().map(to_partial_object_metadata).collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": list_revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, items)).into_response());
    }

    let body = super::generic::build_list_response(
        &ctx.kind,
        &group,
        &version,
        list_revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    // kubectl's default Accept header requests Table format; without this, kubectl can't
    // decode the response and falls back to printing only NAME/AGE (list_cr already handles
    // this for LIST — see above).
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    let key = cr_store_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;
    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // The key is version-independent (see cr_store_key); a conversion webhook is only
    // consulted when the object's own stored apiVersion differs from the request
    // (see object_needs_conversion).
    let desired_api_version = format!("{group}/{version}");
    if object_needs_conversion(
        &obj,
        &desired_api_version,
        ctx.conversion_webhook_client_config.as_ref(),
    ) {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let mut converted =
                call_conversion_webhook(&state, cfg, vec![obj], &desired_api_version).await?;
            let mut converted_obj = converted
                .pop()
                .ok_or_else(|| Status::internal("conversion webhook returned no objects".into()))?;
            stamp_cr_envelope(&mut converted_obj, &group, &version, &ctx.kind);
            if let Some(schema) = ctx.schema.as_ref() {
                apply_crd_schema_defaults(schema, &mut converted_obj);
            }
            if pom {
                return Ok(Json(to_partial_object_metadata(&converted_obj)).into_response());
            }
            if super::table::wants_table(accept) {
                return Ok(Json(super::table::build_table(
                    &group,
                    &plural,
                    vec![converted_obj],
                ))
                .into_response());
            }
            let bytes =
                serde_json::to_vec(&converted_obj).map_err(|e| Status::internal(e.to_string()))?;
            return Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response());
        }
    }

    stamp_cr_envelope(&mut obj, &group, &version, &ctx.kind);
    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }
    // kcm's GC verifies owner references via metadata-only Get() calls
    // (garbagecollector.go's isDangling); without this, it receives a typed CR object it
    // can't decode and retries the owner-check forever, so newly-orphaned dependents are
    // never identified as dangling and never collected.
    if pom {
        return Ok(Json(to_partial_object_metadata(&obj)).into_response());
    }
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, vec![obj])).into_response());
    }
    Ok(Json(obj).into_response())
}

pub async fn create_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let mut wrapped = crate::types::Object { body: obj };
    // Captured before resolve_name mutates metadata.name, so a store collision below
    // knows whether it's allowed to retry under a freshly generated name.
    let generate_name_prefix = crate::handlers::generic::wants_generate_name(&wrapped);
    let mut name = crate::handlers::generic::resolve_name(&mut wrapped)?;
    let mut obj = wrapped.body;
    validate_cr_name(&name)?;

    let warn_header = apply_cr_field_validation(
        &mut obj,
        ctx.schema.as_ref(),
        field_validation_mode(&headers).as_deref(),
        false,
    )?;

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, None)?;

    stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj, None, &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    // Counts store.put attempts made so far (the loop's first iteration is attempt 1).
    // Bounded at MAX_GENERATE_NAME_CREATE_ATTEMPTS TOTAL attempts, mirroring
    // create_resource/create_namespaced_resource's generateName-collision retry (see
    // resource.rs) — a controller mass-creating CRs via bare `metadata.generateName` must
    // not see a spurious 409 just because the server's random suffix landed on an existing
    // name.
    let mut attempts_made = 1u32;
    let rv = loop {
        let key = cr_store_key(&group, &plural, None, &name);
        let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
        match state.store.put(&key, Bytes::from(bytes), Some(0)).await {
            Ok(rv) => break rv,
            // The client never chose this name (it came from generateName) — a collision is
            // the server's random suffix landing on an existing object, not a real conflict
            // the client should see. Retry with a fresh suffix instead of surfacing a
            // spurious 409 on what the client experiences as a plain create.
            Err(u7s_store::StoreError::AlreadyExists { .. })
                if generate_name_prefix.is_some()
                    && attempts_made
                        < crate::handlers::generic::MAX_GENERATE_NAME_CREATE_ATTEMPTS =>
            {
                attempts_made += 1;
                name = format!(
                    "{}{}",
                    generate_name_prefix.as_deref().unwrap_or_default(),
                    crate::handlers::generic::generate_suffix()
                );
                obj["metadata"]["name"] = serde_json::Value::String(name.clone());
                // Re-validate the regenerated name — mirrors create_resource's retry, which
                // re-runs validating admission once per attempt, not just for the first
                // candidate name.
                let retry_ctx = AdmissionContext {
                    group: &group,
                    version: &version,
                    resource: &plural,
                    name: &name,
                    namespace: None,
                    operation: "CREATE",
                    user_info: Some(serde_json::json!({
                        "username": user.username,
                        "uid": user.uid,
                        "groups": user.groups,
                        "extra": user.extra,
                    })),
                    dry_run: is_dry_run_header(&headers),
                };
                run_validating_webhooks(&state, &obj, None, &retry_ctx).await?;
            }
            Err(e) => return Err(store_err_cr(e, &name, &ctx.kind)),
        }
    };

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    let mut resp = (StatusCode::CREATED, Json(obj)).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

pub async fn replace_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let obj_name = obj_meta.name.as_deref().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj_meta.resource_version.as_deref())?;

    let key = cr_store_key(&group, &plural, None, &name);

    // Must exist before replace.
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    // Stale-resourceVersion PUTs must 409, not fall through into the CEL
    // x-kubernetes-validations oldSelf comparison (validate_cr_schema below) against the
    // freshly-read `existing` — mirrors check_replace_resource_version_precondition's doc
    // comment in resource.rs and pods.rs's replace_pod, which fixed the identical race. A
    // CRD author's oldSelf-based immutability rule comparing the incoming PUT body against
    // `existing` (the object as it stands right now, not as of the client's own
    // resourceVersion) would otherwise misclassify a legitimate concurrent-write race as a
    // permanent 422 validation failure instead of the retryable 409 that tells client-go's
    // Update-on-conflict loop to re-GET and resubmit.
    if let Some(expected) = expected_revision {
        if expected != stored.revision {
            return Err(store_err_cr(
                u7s_store::StoreError::RevisionMismatch {
                    expected,
                    current: stored.revision,
                },
                &name,
                &ctx.kind,
            ));
        }
    }

    // Preserve uid + creationTimestamp from stored.
    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
    resolve_cr_metadata(&existing, &mut obj, &name, &ctx.kind)?;

    // When the CRD declares a status subresource, the main PUT endpoint must not
    // update .status — clients must use PUT /status for that. Restore whatever is
    // already stored rather than dropping it: a controller (e.g. csi-snapshotter)
    // that PUTs a spec-only change to VolumeSnapshotContent reads .status back off
    // the same response to extract snapshotHandle — wiping status here made that
    // read nil on every main-resource PUT after the first /status write.
    if ctx.has_status_subresource {
        let stored_status = existing["status"].clone();
        if stored_status.is_null() {
            if let Some(map) = obj.as_object_mut() {
                map.remove("status");
            }
        } else {
            obj["status"] = stored_status;
        }
    }

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, Some(&existing))?;

    // A PUT whose body has deletionTimestamp set and finalizers now empty is how a
    // controller that removes its own protection finalizer via Update rather than Patch
    // (e.g. external-snapshotter's snapshot-controller on VolumeSnapshotContent) completes
    // a delete. patch_cr already completes the delete instead of storing the update here;
    // replace_cr (PUT) did not, so the object sat forever with deletionTimestamp set and
    // no finalizers — never actually removed — and callers waiting for it to disappear
    // (e.g. the e2e client's WaitForGVRDeletion poll) timed out after 5 minutes.
    if crate::handlers::resource::finalizer_drain_complete(&obj) {
        complete_cr_finalizer_drain(&state, &key, &name, &ctx.kind, None).await?;
        return Ok(Json(obj));
    }

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    debug_assert_eq!(
        existing["metadata"]["uid"], obj["metadata"]["uid"],
        "old_object passed to run_validating_webhooks must be the same resource's pre-update \
         state, not a stray object — otherwise oldSelf/immutability checks compare unrelated UIDs"
    );
    run_validating_webhooks(&state, &obj, Some(&existing), &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_revision)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
    evict_cr_conversion_cache(&state, existing["metadata"]["resourceVersion"].as_str());

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

/// Scan all CRD-backed object storage and hard-delete dependents of the owner identified by
/// `owner_uid` (Background cascade semantics only).
///
/// Orphan propagation does NOT go through this function: `delete_cr`/`delete_cr_namespaced`
/// mark the owner with the `orphan` finalizer instead (see `add_orphan_finalizer`) and defer
/// to KCM's real GC controller, which strips each dependent's ownerReferences from its own
/// consistent view of the cluster before removing the finalizer — see `patch_cr`'s
/// finalizer-drain-complete check. This function previously also had an orphan branch that
/// stripped ownerReferences here, synchronously, right after the owner was already
/// hard-deleted from the store — racing KCM's GC controller, which could cascade-delete a
/// dependent before observing the ownerRef-stripped update (same class of bug already fixed
/// for the built-in RC/Deployment orphan-delete path).
///
/// All CRD instances are stored under `/registry/cr/`, so a single prefix scan finds
/// every CR regardless of group, version, or scope. We recurse to handle ownership chains
/// (owner → dependent → grand-dependent). Without recursion, orphaned intermediate nodes
/// would be left behind, leaking resources and failing the GC conformance chain test.
async fn cascade_delete_cr_dependents<S: Store>(state: &AppState<S>, owner_uid: &str) {
    const CR_ALL_PREFIX: &str = "/registry/cr/";

    let resp = match state
        .store
        .list(CR_ALL_PREFIX, ListOptions::default())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cascade_delete_cr: list all CRs failed: {e}");
            return;
        }
    };

    for item in resp.items {
        let obj: serde_json::Value = match serde_json::from_slice(&item.value) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check whether this object is owned by `owner_uid`.
        let owns = obj["metadata"]["ownerReferences"]
            .as_array()
            .map(|refs| refs.iter().any(|r| r["uid"].as_str() == Some(owner_uid)))
            .unwrap_or(false);

        if !owns {
            continue;
        }

        let child_key = item.key.clone();
        let child_uid = obj["metadata"]["uid"].as_str().unwrap_or("").to_string();

        // Background cascade: delete the dependent then recurse for its own dependents.
        if let Err(e) = state.store.delete(&child_key, None).await {
            tracing::warn!("cascade_delete_cr: delete {child_key}: {e}");
        }
        // Recurse: this child may itself own other CRs.
        if !child_uid.is_empty() {
            Box::pin(cascade_delete_cr_dependents(state, &child_uid)).await;
        }
    }
}

/// Hard-deletes a CR whose finalizer drain just completed (deletionTimestamp set, finalizers
/// now empty) — mirrors resource.rs's `complete_finalizer_drain` for built-in resources.
///
/// This is what makes the `orphan` finalizer added by `delete_cr`/`delete_cr_namespaced`
/// actually terminate: KCM's GC controller strips each dependent's ownerReferences, then
/// removes the finalizer via PATCH; `patch_cr`/`patch_cr_namespaced` detect that the patch
/// itself completed the drain and call this instead of storing the update — without it, the
/// owner CR would sit stuck Terminating forever once the finalizer is cleared.
async fn complete_cr_finalizer_drain<S: Store>(
    state: &AppState<S>,
    key: &str,
    name: &str,
    kind: &str,
    ns: Option<&str>,
) -> Result<(), crate::status::StatusError> {
    state
        .store
        .delete(key, None)
        .await
        .map_err(|e| store_err_cr(e, name, kind))?;
    if let Some(namespace) = ns {
        crate::quota::update_quota_status(state, namespace).await;
        crate::handlers::namespaces::maybe_finalize_terminating_namespace(state, namespace).await;
    }
    Ok(())
}

pub async fn delete_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd_for_delete(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &plural, None, &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    // Parse DeleteOptions from the request body (same pattern as built-in delete handlers).
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored CR: {e}")))?;

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    // This is what the conformance test "deny custom resource create/update/delete" exercises
    // for the delete case: a Fail-policy webhook must be able to reject the deletion.
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "DELETE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: false,
    };
    run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

    let owner_uid = obj.body["metadata"]["uid"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Orphan: signal via the `orphan` finalizer (added BEFORE the soft/hard-delete decision
    // below) instead of stripping dependent CRs ourselves. Mirrors the fix already applied to
    // the built-in RC/Deployment orphan-delete path — see add_orphan_finalizer for why:
    // hard-deleting the owner immediately and stripping dependents synchronously afterward
    // races KCM's real GC controller, which can cascade-delete a dependent whose
    // ownerReference hasn't been stripped from its point of view yet.
    if delete_opts.is_orphan() && !owner_uid.is_empty() {
        crate::handlers::resource::add_orphan_finalizer(&mut obj);
    }

    // apply_delete_policy: if the CR has finalizers (including the `orphan` one just added),
    // stamp deletionTimestamp and soft-delete instead of removing it outright.
    if let Some(soft) = crate::handlers::generic::apply_delete_policy(&mut obj) {
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
        let mut resp_body = Object { body: soft };
        resp_body.set_resource_version(new_rv);
        return Ok(Json(resp_body.body).into_response());
    }

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    evict_cr_conversion_cache(&state, obj.resource_version());

    // Background cascade-delete dependents after the owner is hard-deleted. Orphan-marked
    // owners never reach here — they returned above via the soft-delete branch and defer to
    // KCM's GC controller + patch_cr's finalizer-drain-complete check (complete_cr_finalizer_drain).
    if !owner_uid.is_empty() {
        cascade_delete_cr_dependents(&state, &owner_uid).await;
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

/// DeleteCollection fallback for cluster-scoped custom resources — what
/// `delete_collection_resource` calls when `plural` isn't a built-in registered type.
///
/// Mirrors `delete_collection_resource`'s inline per-object loop (admission, finalizer
/// soft-delete) rather than looping over `delete_cr`, matching how this codebase already
/// keeps collection-delete a self-contained loop instead of calling the single-object
/// handler per item. Unlike `delete_cr` (which 404s for a namespaced CRD requested at the
/// cluster route, since a bare name can't identify a namespaced object), this scans without
/// a namespace segment regardless of `ctx.namespaced` — exactly like `list_cr` already does
/// — because a collection scan matched by selector, not by name, is not ambiguous across
/// namespaces.
pub async fn delete_collection_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural)): Path<(String, String, String)>,
    Extension(user): Extension<UserInfo>,
    query: super::generic::CollectionQuery,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd_for_delete(&state, &group, &version, &plural).await?;

    let prefix = cr_list_prefix(&group, &plural, None);
    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(super::generic::parse_label_selector)
        .transpose()?;

    // Field selectors can name fields that only exist once an object is converted to the
    // requested version (see convert_cr_list_items) — build a converted+defaulted view purely
    // to decide which objects match, exactly like list_cr does. The delete below always acts
    // on the object's own stored bytes, never this converted view.
    let desired_api_version = format!("{group}/{version}");
    let mut filter_view: Vec<serde_json::Value> = resp
        .items
        .iter()
        .map(|obj| serde_json::from_slice(&obj.value).unwrap_or(serde_json::Value::Null))
        .collect();
    convert_cr_list_items(
        &state,
        ctx.conversion_webhook_client_config.as_ref(),
        &mut filter_view,
        &desired_api_version,
    )
    .await?;
    if let Some(schema) = ctx.schema.as_ref() {
        for item in filter_view.iter_mut() {
            apply_crd_schema_defaults(schema, item);
        }
    }

    for (obj, filter_item) in resp.items.into_iter().zip(filter_view) {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            let name = parsed["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();

            if let Some(ref pairs) = label_pairs {
                if super::generic::apply_label_selector(vec![filter_item.clone()], pairs).is_empty()
                {
                    continue;
                }
            }
            if let Some(ref selector) = query.field_selector {
                if !cr_matches_field_selector(
                    &filter_item,
                    selector,
                    ctx.namespaced,
                    &ctx.selectable_fields,
                ) {
                    continue;
                }
            }

            let admission_ctx = AdmissionContext {
                group: &group,
                version: &version,
                resource: &plural,
                name: &name,
                namespace: None,
                operation: "DELETE",
                user_info: Some(serde_json::json!({
                    "username": user.username,
                    "uid": user.uid,
                    "groups": user.groups,
                    "extra": user.extra,
                })),
                dry_run: false,
            };
            run_validating_webhooks(&state, &parsed, Some(&parsed), &admission_ctx).await?;

            let mut typed = Object { body: parsed };
            if let Some(soft) = crate::handlers::generic::apply_delete_policy(&mut typed) {
                state
                    .store
                    .put(&obj.key, Object { body: soft }.to_bytes(), None)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                continue;
            }
        }
        match state.store.delete(&obj.key, None).await {
            Ok(_) | Err(u7s_store::StoreError::NotFound { .. }) => {}
            Err(e) => return Err(Status::internal(e.to_string())),
        }
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Namespaced CR handlers
// ---------------------------------------------------------------------------

pub async fn list_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    headers: axum::http::HeaderMap,
    query: super::generic::CollectionQuery,
    username: String,
) -> Result<Response, crate::status::StatusError> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // When no CRD exists for this group, return 406 if Table format was requested
    // rather than 404 Not Found (the group may be registered via APIService but
    // Table is not implementable without a CRD or proxy backend).
    let ctx = match find_crd(&state, &group, &version, &plural).await {
        Ok(ctx) => ctx,
        Err(err) => {
            if super::table::wants_table(accept) {
                return Err(Status::not_acceptable(format!(
                    "the server does not support Table format for {group}/{version}/{plural}"
                )));
            }
            // Same guard as list_cr: for watch+sendInitialEvents on a tombstoned group,
            // return an empty watch stream (200 + BOOKMARK) instead of HTTP 410.
            // Without this, a namespaced watch+sendInitialEvents hot-loops identically
            // to the cluster-scoped path, killing conformance runs.
            if err.0 == StatusCode::GONE
                && query.watch == Some(true)
                && query.send_initial_events == Some(true)
            {
                let pom = wants_partial_object_metadata(accept);
                let (watch_api_version, watch_kind) = if pom {
                    (
                        "meta.k8s.io/v1".to_string(),
                        "PartialObjectMetadata".to_string(),
                    )
                } else {
                    (format!("{group}/{version}"), plural.clone())
                };
                let prefix = cr_list_prefix(&group, &plural, Some(&ns));
                return super::watch::watch_generic(
                    state,
                    super::watch::WatchConfig {
                        prefix,
                        api_version: watch_api_version,
                        kind: watch_kind,
                        from_revision: query.resource_version.unwrap_or(0),
                        initial_items: Some((vec![], 0)),
                        label_selector: query.label_selector,
                        field_selector: query.field_selector,
                        allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                        username,
                        as_partial_object_metadata: pom,
                        group: group.clone(),
                        plural: plural.clone(),
                        timeout_seconds: query.timeout_seconds,
                    },
                )
                .await;
            }
            return Err(err);
        }
    };

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let prefix = cr_list_prefix(&group, &plural, Some(&ns));

    let pom = wants_partial_object_metadata(accept);

    if query.watch == Some(true) {
        let (watch_api_version, watch_kind) = if pom {
            (
                "meta.k8s.io/v1".to_string(),
                "PartialObjectMetadata".to_string(),
            )
        } else {
            (format!("{group}/{version}"), ctx.kind.clone())
        };
        let mut initial_items = super::watch::fetch_initial_events(
            &state,
            &prefix,
            query.send_initial_events == Some(true),
            &group,
            &plural,
        )
        .await?;
        // Convert the sendInitialEvents backlog to the requested version — independent of
        // `pom` (a PartialObjectMetadata watch still needs the full body converted first for
        // schema-declared fields to exist) — the same way LIST converts items, before
        // watch_generic_for_cr ever sees them. Without this, a field selector on a
        // requested-version-only field matches nothing (see convert_cr_list_items).
        let desired_api_version = format!("{group}/{version}");
        if let Some((items, _)) = initial_items.as_mut() {
            convert_cr_list_items(
                &state,
                ctx.conversion_webhook_client_config.as_ref(),
                items,
                &desired_api_version,
            )
            .await?;
        }
        return super::watch::watch_generic_for_cr(
            state,
            super::watch::WatchConfig {
                prefix,
                api_version: watch_api_version,
                kind: watch_kind,
                from_revision: query.resource_version.unwrap_or(0),
                initial_items,
                label_selector: query.label_selector,
                field_selector: query.field_selector,
                allow_watch_bookmarks: query.allow_watch_bookmarks == Some(true),
                username,
                as_partial_object_metadata: pom,
                group: group.clone(),
                plural: plural.clone(),
                timeout_seconds: query.timeout_seconds,
            },
            super::watch::CrFieldSelectorContext {
                namespaced: ctx.namespaced,
                selectable_fields: ctx.selectable_fields.clone(),
                conversion_webhook_client_config: ctx.conversion_webhook_client_config.clone(),
                desired_api_version,
            },
        )
        .await;
    }

    // Decode BEFORE listing: on a continuation request this pins the resourceVersion this
    // response (and every later page) must report — see decode_continue's doc for why.
    let continue_decoded = query
        .continue_token
        .as_deref()
        .map(|t| {
            super::generic::decode_continue(
                t,
                state.store.current_revision(),
                &state.continue_token_key,
            )
        })
        .transpose()?;
    let continue_key = continue_decoded.as_ref().map(|(k, _)| k.clone());
    let resp = state
        .store
        .list(
            &prefix,
            ListOptions {
                // CR field selectors can reference arbitrary CRD-declared JSON paths that only
                // exist after per-item conversion (see convert_cr_list_items below) — the store
                // has no way to evaluate those against raw stored bytes, so filtering happens
                // in-memory afterward instead (cr_matches_field_selector), same as this codebase
                // already does for "events" in resource.rs.
                field_selector: None,
                limit: query.limit,
                continue_key,
            },
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    // First page (no continue token yet): the fresh store revision becomes the pin for
    // subsequent pages. Continuation page: reuse the pin decoded above, not the store's
    // current (possibly-advanced) revision.
    let list_revision = continue_decoded.map(|(_, rv)| rv).unwrap_or(resp.revision);

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(resp.items.len());
    for obj in &resp.items {
        let v: serde_json::Value =
            serde_json::from_slice(&obj.value).map_err(|e| Status::internal(e.to_string()))?;
        items.push(v);
    }

    // Batch-convert only the items that actually need it (see convert_cr_list_items).
    let desired_api_version = format!("{group}/{version}");
    convert_cr_list_items(
        &state,
        ctx.conversion_webhook_client_config.as_ref(),
        &mut items,
        &desired_api_version,
    )
    .await?;

    if let Some(schema) = ctx.schema.as_ref() {
        for item in items.iter_mut() {
            apply_crd_schema_defaults(schema, item);
        }
    }

    if let Some(selector) = query.field_selector.as_deref() {
        items.retain(|item| {
            cr_matches_field_selector(item, selector, ctx.namespaced, &ctx.selectable_fields)
        });
    }

    if pom {
        let pom_items: Vec<serde_json::Value> =
            items.iter().map(to_partial_object_metadata).collect();
        let body = serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": list_revision.to_string() },
            "items": pom_items
        });
        return Ok(Json(body).into_response());
    }

    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, items)).into_response());
    }

    let body = super::generic::build_list_response(
        &ctx.kind,
        &group,
        &version,
        list_revision,
        items,
        resp.continue_key,
        resp.remaining_count,
        &state.continue_token_key,
    );
    Ok(Json(body).into_response())
}

pub async fn get_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    // kubectl's default Accept header requests Table format; without this, kubectl can't
    // decode the response and falls back to printing only NAME/AGE (list_cr already handles
    // this for LIST — see above).
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pom = wants_partial_object_metadata(accept);

    let key = cr_store_key(&group, &plural, Some(&ns), &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;
    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // The key is version-independent (see cr_store_key); a conversion webhook is only
    // consulted when the object's own stored apiVersion differs from the request
    // (see object_needs_conversion).
    let desired_api_version = format!("{group}/{version}");
    if object_needs_conversion(
        &obj,
        &desired_api_version,
        ctx.conversion_webhook_client_config.as_ref(),
    ) {
        if let Some(cfg) = ctx.conversion_webhook_client_config.as_ref() {
            let mut converted =
                call_conversion_webhook(&state, cfg, vec![obj], &desired_api_version).await?;
            let mut converted_obj = converted
                .pop()
                .ok_or_else(|| Status::internal("conversion webhook returned no objects".into()))?;
            stamp_cr_envelope(&mut converted_obj, &group, &version, &ctx.kind);
            if let Some(schema) = ctx.schema.as_ref() {
                apply_crd_schema_defaults(schema, &mut converted_obj);
            }
            if pom {
                return Ok(Json(to_partial_object_metadata(&converted_obj)).into_response());
            }
            if super::table::wants_table(accept) {
                return Ok(Json(super::table::build_table(
                    &group,
                    &plural,
                    vec![converted_obj],
                ))
                .into_response());
            }
            let bytes =
                serde_json::to_vec(&converted_obj).map_err(|e| Status::internal(e.to_string()))?;
            return Ok((
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response());
        }
    }

    stamp_cr_envelope(&mut obj, &group, &version, &ctx.kind);
    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }
    // kcm's GC verifies owner references via metadata-only Get() calls
    // (garbagecollector.go's isDangling); without this, it receives a typed CR object it
    // can't decode and retries the owner-check forever, so newly-orphaned dependents are
    // never identified as dangling and never collected.
    if pom {
        return Ok(Json(to_partial_object_metadata(&obj)).into_response());
    }
    if super::table::wants_table(accept) {
        return Ok(Json(super::table::build_table(&group, &plural, vec![obj])).into_response());
    }
    Ok(Json(obj).into_response())
}

pub async fn create_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let mut wrapped = crate::types::Object { body: obj };
    // Captured before resolve_name mutates metadata.name, so a store collision below
    // knows whether it's allowed to retry under a freshly generated name.
    let generate_name_prefix = crate::handlers::generic::wants_generate_name(&wrapped);
    let mut name = crate::handlers::generic::resolve_name(&mut wrapped)?;
    let mut obj = wrapped.body;
    validate_cr_name(&name)?;

    let warn_header = apply_cr_field_validation(
        &mut obj,
        ctx.schema.as_ref(),
        field_validation_mode(&headers).as_deref(),
        false,
    )?;

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, None)?;

    obj["metadata"]["namespace"] = serde_json::Value::String(ns.clone());
    stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "CREATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    run_validating_webhooks(&state, &obj, None, &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    // ResourceQuota: ensure object count does not exceed hard limits (e.g. `count/<crd>.<group>`).
    // Custom resources went through admission webhooks above but were never checked against
    // ResourceQuota at all — a quota's count/* hard limit on a CRD-backed resource silently
    // never enforced. Held across check-then-write like resource.rs's generic create path:
    // without the lock, concurrent creates of the same CR type can each observe pre-write
    // usage, all pass the check, and collectively exceed the quota.
    let _quota_lock = state.quota_admission_locks.lock(&ns).await;
    crate::quota::check_resource_quota(&state, &ns, &group, &plural, Some(&obj)).await?;

    let ns_key = cluster_object_key("namespaces", &ns);
    // Namespace-Terminating check and the create are one atomic store transaction — matches
    // kube-apiserver behaviour: 403 Forbidden "unable to create new content in namespace <ns>
    // because it is being terminated".
    //
    // Counts store.create_if_namespace_active attempts made so far (the loop's first
    // iteration is attempt 1). Bounded at MAX_GENERATE_NAME_CREATE_ATTEMPTS TOTAL attempts,
    // mirroring create_resource/create_namespaced_resource's generateName-collision retry
    // (see resource.rs) — a controller mass-creating CRs via bare `metadata.generateName`
    // must not see a spurious 409 just because the server's random suffix landed on an
    // existing name.
    let mut attempts_made = 1u32;
    let rv = loop {
        let key = cr_store_key(&group, &plural, Some(&ns), &name);
        let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
        match state
            .store
            .create_if_namespace_active(Some(&ns_key), &key, Bytes::from(bytes))
            .await
        {
            Ok(rv) => break rv,
            Err(u7s_store::CreateNamespacedError::NamespaceTerminating) => {
                return Err(Status::forbidden(format!(
                    "unable to create new content in namespace {ns} because it is being terminated"
                )));
            }
            // The client never chose this name (it came from generateName) — a collision is
            // the server's random suffix landing on an existing object, not a real conflict
            // the client should see. Retry with a fresh suffix instead of surfacing a
            // spurious 409 on what the client experiences as a plain create.
            Err(u7s_store::CreateNamespacedError::Store(
                u7s_store::StoreError::AlreadyExists { .. },
            )) if generate_name_prefix.is_some()
                && attempts_made < crate::handlers::generic::MAX_GENERATE_NAME_CREATE_ATTEMPTS =>
            {
                attempts_made += 1;
                name = format!(
                    "{}{}",
                    generate_name_prefix.as_deref().unwrap_or_default(),
                    crate::handlers::generic::generate_suffix()
                );
                obj["metadata"]["name"] = serde_json::Value::String(name.clone());
                // Re-validate the regenerated name — mirrors create_resource's retry, which
                // re-runs validating admission once per attempt, not just for the first
                // candidate name.
                let retry_ctx = AdmissionContext {
                    group: &group,
                    version: &version,
                    resource: &plural,
                    name: &name,
                    namespace: Some(&ns),
                    operation: "CREATE",
                    user_info: Some(serde_json::json!({
                        "username": user.username,
                        "uid": user.uid,
                        "groups": user.groups,
                        "extra": user.extra,
                    })),
                    dry_run: is_dry_run_header(&headers),
                };
                run_validating_webhooks(&state, &obj, None, &retry_ctx).await?;
            }
            Err(u7s_store::CreateNamespacedError::Store(e)) => {
                return Err(store_err_cr(e, &name, &ctx.kind))
            }
        }
    };

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    let mut resp = (StatusCode::CREATED, Json(obj)).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

pub async fn replace_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let mut obj: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    let obj_meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].clone()).unwrap_or_default();
    let obj_name = obj_meta.name.as_deref().unwrap_or("").to_string();
    if obj_name != name {
        return Err(Status::bad_request(format!(
            "the name of the object ({obj_name}) does not match the name on the URL ({name})"
        )));
    }

    let expected_revision = parse_resource_version(obj_meta.resource_version.as_deref())?;

    let key = cr_store_key(&group, &plural, Some(&ns), &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    // Stale-resourceVersion PUTs must 409, not fall through into the CEL
    // x-kubernetes-validations oldSelf comparison (validate_cr_schema below) against the
    // freshly-read `existing` — mirrors check_replace_resource_version_precondition's doc
    // comment in resource.rs and pods.rs's replace_pod, which fixed the identical race. A
    // CRD author's oldSelf-based immutability rule comparing the incoming PUT body against
    // `existing` (the object as it stands right now, not as of the client's own
    // resourceVersion) would otherwise misclassify a legitimate concurrent-write race as a
    // permanent 422 validation failure instead of the retryable 409 that tells client-go's
    // Update-on-conflict loop to re-GET and resubmit.
    if let Some(expected) = expected_revision {
        if expected != stored.revision {
            return Err(store_err_cr(
                u7s_store::StoreError::RevisionMismatch {
                    expected,
                    current: stored.revision,
                },
                &name,
                &ctx.kind,
            ));
        }
    }

    let existing: serde_json::Value =
        serde_json::from_slice(&stored.value).unwrap_or(serde_json::Value::Null);
    resolve_cr_metadata(&existing, &mut obj, &name, &ctx.kind)?;

    // When the CRD declares a status subresource, the main PUT endpoint must not
    // update .status — clients must use PUT /status for that. Restore whatever is
    // already stored rather than dropping it: a controller (e.g. csi-snapshotter)
    // that PUTs a spec-only change to VolumeSnapshotContent reads .status back off
    // the same response to extract snapshotHandle — wiping status here made that
    // read nil on every main-resource PUT after the first /status write.
    if ctx.has_status_subresource {
        let stored_status = existing["status"].clone();
        if stored_status.is_null() {
            if let Some(map) = obj.as_object_mut() {
                map.remove("status");
            }
        } else {
            obj["status"] = stored_status;
        }
    }

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, Some(&existing))?;

    // A PUT whose body has deletionTimestamp set and finalizers now empty is how a
    // controller that removes its own protection finalizer via Update rather than Patch
    // (e.g. external-snapshotter's snapshot-controller on VolumeSnapshot) completes a
    // delete. patch_cr_namespaced already completes the delete instead of storing the
    // update here; replace_cr_namespaced (PUT) did not, so the object sat forever with
    // deletionTimestamp set and no finalizers — never actually removed — and callers
    // waiting for it to disappear (e.g. the e2e client's WaitForNamespacedGVRDeletion
    // poll) timed out after 5 minutes.
    if crate::handlers::resource::finalizer_drain_complete(&obj) {
        complete_cr_finalizer_drain(&state, &key, &name, &ctx.kind, Some(&ns)).await?;
        return Ok(Json(obj));
    }

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    debug_assert_eq!(
        existing["metadata"]["uid"], obj["metadata"]["uid"],
        "old_object passed to run_validating_webhooks must be the same resource's pre-update \
         state, not a stray object — otherwise oldSelf/immutability checks compare unrelated UIDs"
    );
    run_validating_webhooks(&state, &obj, Some(&existing), &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_revision)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
    evict_cr_conversion_cache(&state, existing["metadata"]["resourceVersion"].as_str());

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    Ok(Json(obj))
}

pub async fn delete_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd_for_delete(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &plural, Some(&ns), &name);

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    // Parse DeleteOptions from the request body (same pattern as built-in delete handlers).
    let body = extract_body(&body, content_type(&headers));
    let delete_opts: DeleteOptions = if body.is_empty() {
        DeleteOptions::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };

    let mut obj = Object::from_bytes(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored CR: {e}")))?;

    // Admission webhook pipeline (validating only — mutating webhooks do not apply to DELETE).
    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "DELETE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: false,
    };
    run_validating_webhooks(&state, &obj.body, Some(&obj.body), &admission_ctx).await?;

    let owner_uid = obj.body["metadata"]["uid"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Orphan: signal via the `orphan` finalizer (added BEFORE the soft/hard-delete decision
    // below) instead of stripping dependent CRs ourselves — see delete_cr for the full
    // rationale (mirrors the built-in RC/Deployment orphan-delete fix).
    if delete_opts.is_orphan() && !owner_uid.is_empty() {
        crate::handlers::resource::add_orphan_finalizer(&mut obj);
    }

    // apply_delete_policy: if the CR has finalizers (including the `orphan` one just added),
    // stamp deletionTimestamp and soft-delete instead of removing it outright.
    if let Some(soft) = crate::handlers::generic::apply_delete_policy(&mut obj) {
        let expected_rv = parse_resource_version(obj.resource_version())?;
        let new_rv = state
            .store
            .put(&key, obj.to_bytes(), expected_rv)
            .await
            .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
        let mut resp_body = Object { body: soft };
        resp_body.set_resource_version(new_rv);
        return Ok(Json(resp_body.body).into_response());
    }

    state
        .store
        .delete(&key, None)
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;

    evict_cr_conversion_cache(&state, obj.resource_version());

    // Background cascade-delete dependents after the owner is hard-deleted. Orphan-marked
    // owners never reach here — they returned above via the soft-delete branch and defer to
    // KCM's GC controller + patch_cr_namespaced's finalizer-drain-complete check.
    if !owner_uid.is_empty() {
        cascade_delete_cr_dependents(&state, &owner_uid).await;
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

/// DeleteCollection fallback for namespaced custom resources — what
/// `delete_collection_namespaced_resource` calls when `plural` isn't a built-in registered
/// type. Mirrors `delete_collection_namespaced_resource`'s inline per-object loop (admission,
/// finalizer soft-delete via `apply_delete_policy`) so a finalizer'd CR survives with
/// deletionTimestamp set exactly like a single `delete_cr_namespaced` call would — never
/// hard-deleted outright. Also honors `query.field_selector` via `cr_matches_field_selector`,
/// the same CRD-selectableFields-aware matcher LIST and watch already use, since the store's
/// generic single-field selector can't express CRD-declared JSON paths the way CR semantics
/// require.
pub async fn delete_collection_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    query: super::generic::CollectionQuery,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd_for_delete(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(
            &format!("{group}/{version}/{plural}"),
            "Resource",
        ));
    }

    let prefix = cr_list_prefix(&group, &plural, Some(&ns));
    let resp = state
        .store
        .list(&prefix, ListOptions::default())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let label_pairs = query
        .label_selector
        .as_deref()
        .map(super::generic::parse_label_selector)
        .transpose()?;

    // Field selectors can name fields that only exist once an object is converted to the
    // requested version (see convert_cr_list_items) — build a converted+defaulted view purely
    // to decide which objects match, exactly like list_cr_namespaced does. The delete below
    // always acts on the object's own stored bytes, never this converted view.
    let desired_api_version = format!("{group}/{version}");
    let mut filter_view: Vec<serde_json::Value> = resp
        .items
        .iter()
        .map(|obj| serde_json::from_slice(&obj.value).unwrap_or(serde_json::Value::Null))
        .collect();
    convert_cr_list_items(
        &state,
        ctx.conversion_webhook_client_config.as_ref(),
        &mut filter_view,
        &desired_api_version,
    )
    .await?;
    if let Some(schema) = ctx.schema.as_ref() {
        for item in filter_view.iter_mut() {
            apply_crd_schema_defaults(schema, item);
        }
    }

    for (obj, filter_item) in resp.items.into_iter().zip(filter_view) {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.value) {
            let name = parsed["metadata"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();

            if let Some(ref pairs) = label_pairs {
                if super::generic::apply_label_selector(vec![filter_item.clone()], pairs).is_empty()
                {
                    continue;
                }
            }
            if let Some(ref selector) = query.field_selector {
                if !cr_matches_field_selector(
                    &filter_item,
                    selector,
                    ctx.namespaced,
                    &ctx.selectable_fields,
                ) {
                    continue;
                }
            }

            let admission_ctx = AdmissionContext {
                group: &group,
                version: &version,
                resource: &plural,
                name: &name,
                namespace: Some(&ns),
                operation: "DELETE",
                user_info: Some(serde_json::json!({
                    "username": user.username,
                    "uid": user.uid,
                    "groups": user.groups,
                    "extra": user.extra,
                })),
                dry_run: false,
            };
            run_validating_webhooks(&state, &parsed, Some(&parsed), &admission_ctx).await?;

            let mut typed = Object { body: parsed };
            if let Some(soft) = crate::handlers::generic::apply_delete_policy(&mut typed) {
                state
                    .store
                    .put(&obj.key, Object { body: soft }.to_bytes(), None)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                continue;
            }
        }
        match state.store.delete(&obj.key, None).await {
            Ok(_) | Err(u7s_store::StoreError::NotFound { .. }) => {}
            Err(e) => return Err(Status::internal(e.to_string())),
        }
    }

    Ok(Json(serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Success",
        "code": 200
    }))
    .into_response())
}

// ---------------------------------------------------------------------------
// Cluster-scoped CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = crate::handlers::json_patch::detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
    let field_validation = field_validation_mode(&headers);

    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &plural, None, &name);
    let stored_opt = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // SSA (apply-patch+yaml) upsert: create the CR when it does not exist yet.
    // kubectl apply and conformance tests use apply-patch+yaml to create-or-update CRs;
    // returning 404 for a missing object breaks the apply flow.
    //
    // The k8s conformance client sends genuine YAML bytes (not JSON) in the body:
    //   "\napiVersion: mygroup.example.com/v1beta1\nkind: ...\nmetadata:\n  name: mytest\n..."
    // (verified by logging body_prefix on a live conformance run). Unlike resource.rs which
    // handles kubelet SSA bodies that happen to be JSON, CR SSA bodies from the conformance
    // test binary are real YAML. ssa_body_to_json (yaml-rust2) handles both JSON and YAML.
    if is_ssa && stored_opt.is_none() {
        let mut obj: serde_json::Value = crate::handlers::json_patch::ssa_body_to_json(&body)?;
        let warn_header = apply_cr_field_validation(
            &mut obj,
            ctx.schema.as_ref(),
            field_validation.as_deref(),
            is_ssa,
        )?;
        stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);
        if let Some(schema) = ctx.schema.as_ref() {
            apply_crd_schema_defaults(schema, &mut obj);
        }
        validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, None)?;
        let admission_ctx = AdmissionContext {
            group: &group,
            version: &version,
            resource: &plural,
            name: &name,
            namespace: None,
            operation: "CREATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(&headers),
        };
        obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
        run_validating_webhooks(&state, &obj, None, &admission_ctx).await?;
        prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);
        let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
        let rv = state
            .store
            .put(&key, Bytes::from(bytes), Some(0))
            .await
            .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
        let mut meta: crate::types::ObjectMeta =
            serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
        meta.resource_version = Some(rv.to_string());
        obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
        let mut resp = (StatusCode::CREATED, Json(obj)).into_response();
        if let Some(hv) = warn_header {
            resp.headers_mut().insert(axum::http::header::WARNING, hv);
        }
        return Ok(resp);
    }

    let stored = stored_opt.ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // apply-patch+yaml bodies are genuine YAML (same conformance client as the create path
    // above); every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        crate::handlers::json_patch::ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    // Snapshot .status before applying the patch: status is a separate RBAC subresource
    // (`<crd>/status`), so a main-endpoint patch must never change it — including via
    // JSON Patch, whose array shape slips past an object-key "status" strip.
    let stored_status = if ctx.has_status_subresource {
        Some(obj["status"].clone())
    } else {
        None
    };

    // obj is deserialized directly from the stored bytes above and the patch below mutates
    // it in place, so this clone is the only pre-patch snapshot available to pass as
    // old_object to run_validating_webhooks.
    let old = obj.clone();

    match patch_type {
        crate::handlers::json_patch::PatchType::Json => {
            crate::handlers::json_patch::apply_json_patch(&mut obj, &patch)?;
        }
        crate::handlers::json_patch::PatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch_for_cr(&mut obj, &patch, ctx.schema.as_ref())
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        crate::handlers::json_patch::PatchType::Merge => {
            crate::patch::merge_patch(&mut obj, &patch);
        }
    }

    if let Some(s) = stored_status {
        if s.is_null() {
            obj.as_object_mut().map(|m| m.remove("status"));
        } else {
            obj["status"] = s;
        }
    }

    let warn_header = apply_cr_field_validation(
        &mut obj,
        ctx.schema.as_ref(),
        field_validation.as_deref(),
        is_ssa,
    )?;

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, Some(&old))?;

    // A patch whose body has deletionTimestamp set and finalizers now empty is how KCM's GC
    // controller completes an Orphan-marked delete_cr: it strips ownerReferences from every
    // dependent CR, then removes the owner's `orphan` finalizer via PATCH. Complete the delete
    // instead of storing the update, or the CR stays stuck Terminating forever.
    if crate::handlers::resource::finalizer_drain_complete(&obj) {
        complete_cr_finalizer_drain(&state, &key, &name, &ctx.kind, None).await?;
        return Ok(Json(obj).into_response());
    }

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: None,
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    // metadata.uid is immutable identity: unconditionally restore it to the pre-patch
    // (stored) value here, after both the patch body and any mutating webhook have had a
    // chance to touch it — this used to be a debug_assert_eq! that panicked in debug builds
    // and was a silent no-op in release, meaning a caller with only ordinary CR `patch`
    // rights could forge uid to match a stale/foreign ownerReference (corrupting GC's
    // owner-liveness check) or defeat controllers' recreate-detection, in every release
    // build. Restoring (rather than rejecting with 409) matches do_patch's behavior for
    // built-in resources: a PATCH is not permitted to change uid at all, regardless of what
    // value it carries.
    obj["metadata"]["uid"] = old["metadata"]["uid"].clone();
    run_validating_webhooks(&state, &obj, Some(&old), &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(stored.revision))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
    evict_cr_conversion_cache(&state, old["metadata"]["resourceVersion"].as_str());

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(new_rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    // The stored object may still carry the apiVersion it was written under (e.g. the
    // CRD's storage version changed since); the response must reflect the version this
    // request actually targeted, same as get_cr already does.
    obj["apiVersion"] = serde_json::Value::String(format!("{group}/{version}"));
    let mut resp = Json(obj).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Namespaced CR patch handler
// ---------------------------------------------------------------------------

pub async fn patch_cr_namespaced<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    Extension(user): Extension<UserInfo>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let patch_type = crate::handlers::json_patch::detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");
    let field_validation = field_validation_mode(&headers);

    let ctx = find_crd(&state, &group, &version, &plural).await?;

    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }

    let key = cr_store_key(&group, &plural, Some(&ns), &name);
    let stored_opt = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // SSA upsert for namespaced CRs: mirrors patch_cr cluster-scoped path.
    // ssa_body_to_json (yaml-rust2) handles both JSON and genuine YAML bodies.
    if is_ssa && stored_opt.is_none() {
        let mut obj: serde_json::Value = crate::handlers::json_patch::ssa_body_to_json(&body)?;
        let warn_header = apply_cr_field_validation(
            &mut obj,
            ctx.schema.as_ref(),
            field_validation.as_deref(),
            is_ssa,
        )?;
        stamp_cr_fields(&mut obj, &group, &version, &ctx.kind);
        {
            let mut meta: crate::types::ObjectMeta =
                serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
            meta.namespace = Some(ns.clone());
            obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
        }
        if let Some(schema) = ctx.schema.as_ref() {
            apply_crd_schema_defaults(schema, &mut obj);
        }
        validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, None)?;
        let admission_ctx = AdmissionContext {
            group: &group,
            version: &version,
            resource: &plural,
            name: &name,
            namespace: Some(&ns),
            operation: "CREATE",
            user_info: Some(serde_json::json!({
                "username": user.username,
                "uid": user.uid,
                "groups": user.groups,
                "extra": user.extra,
            })),
            dry_run: is_dry_run_header(&headers),
        };
        obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
        run_validating_webhooks(&state, &obj, None, &admission_ctx).await?;
        prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);
        let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
        let ns_key = cluster_object_key("namespaces", &ns);
        // Reject object creation in a Terminating namespace, atomically with the create —
        // matches create_cr_namespaced/create_namespaced_resource/create_pod. Without this,
        // `kubectl apply --server-side` can create a new CR in a namespace mid-deletion by
        // going through PATCH+apply instead of POST+create.
        let rv = match state
            .store
            .create_if_namespace_active(Some(&ns_key), &key, Bytes::from(bytes))
            .await
        {
            Ok(rv) => rv,
            Err(u7s_store::CreateNamespacedError::NamespaceTerminating) => {
                return Err(Status::forbidden(format!(
                    "unable to create new content in namespace {ns} because it is being terminated"
                )));
            }
            Err(u7s_store::CreateNamespacedError::Store(e)) => {
                return Err(store_err_cr(e, &name, &ctx.kind))
            }
        };
        let mut meta: crate::types::ObjectMeta =
            serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
        meta.resource_version = Some(rv.to_string());
        obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
        let mut resp = (StatusCode::CREATED, Json(obj)).into_response();
        if let Some(hv) = warn_header {
            resp.headers_mut().insert(axum::http::header::WARNING, hv);
        }
        return Ok(resp);
    }

    let stored = stored_opt.ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // apply-patch+yaml bodies are genuine YAML (same conformance client as the create path
    // above); every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        crate::handlers::json_patch::ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    // Snapshot .status before applying the patch: status is a separate RBAC subresource
    // (`<crd>/status`), so a main-endpoint patch must never change it — including via
    // JSON Patch, whose array shape slips past an object-key "status" strip.
    let stored_status = if ctx.has_status_subresource {
        Some(obj["status"].clone())
    } else {
        None
    };

    // obj is deserialized directly from the stored bytes above and the patch below mutates
    // it in place, so this clone is the only pre-patch snapshot available to pass as
    // old_object to run_validating_webhooks.
    let old = obj.clone();

    match patch_type {
        crate::handlers::json_patch::PatchType::Json => {
            crate::handlers::json_patch::apply_json_patch(&mut obj, &patch)?;
        }
        crate::handlers::json_patch::PatchType::StrategicMerge => {
            crate::patch::strategic_merge_patch_for_cr(&mut obj, &patch, ctx.schema.as_ref())
                .map_err(|e| Status::bad_request(e.to_string()))?;
        }
        crate::handlers::json_patch::PatchType::Merge => {
            crate::patch::merge_patch(&mut obj, &patch);
        }
    }

    if let Some(s) = stored_status {
        if s.is_null() {
            obj.as_object_mut().map(|m| m.remove("status"));
        } else {
            obj["status"] = s;
        }
    }

    let warn_header = apply_cr_field_validation(
        &mut obj,
        ctx.schema.as_ref(),
        field_validation.as_deref(),
        is_ssa,
    )?;

    if let Some(schema) = ctx.schema.as_ref() {
        apply_crd_schema_defaults(schema, &mut obj);
    }

    validate_cr_schema(&obj, &ctx, &state.cr_schema_cache, Some(&old))?;

    // A patch whose body has deletionTimestamp set and finalizers now empty is how KCM's GC
    // controller completes an Orphan-marked delete_cr_namespaced: it strips ownerReferences
    // from every dependent CR, then removes the owner's `orphan` finalizer via PATCH. Complete
    // the delete instead of storing the update, or the CR stays stuck Terminating forever.
    if crate::handlers::resource::finalizer_drain_complete(&obj) {
        complete_cr_finalizer_drain(&state, &key, &name, &ctx.kind, Some(&ns)).await?;
        return Ok(Json(obj).into_response());
    }

    let admission_ctx = AdmissionContext {
        group: &group,
        version: &version,
        resource: &plural,
        name: &name,
        namespace: Some(&ns),
        operation: "UPDATE",
        user_info: Some(serde_json::json!({
            "username": user.username,
            "uid": user.uid,
            "groups": user.groups,
            "extra": user.extra,
        })),
        dry_run: is_dry_run_header(&headers),
    };
    obj = run_mutating_webhooks(&state, obj, None, &admission_ctx).await?;
    // metadata.uid is immutable identity: unconditionally restore it to the pre-patch
    // (stored) value here, after both the patch body and any mutating webhook have had a
    // chance to touch it — this used to be a debug_assert_eq! that panicked in debug builds
    // and was a silent no-op in release, meaning a caller with only ordinary CR `patch`
    // rights could forge uid to match a stale/foreign ownerReference (corrupting GC's
    // owner-liveness check) or defeat controllers' recreate-detection, in every release
    // build. Restoring (rather than rejecting with 409) matches do_patch's behavior for
    // built-in resources: a PATCH is not permitted to change uid at all, regardless of what
    // value it carries.
    obj["metadata"]["uid"] = old["metadata"]["uid"].clone();
    run_validating_webhooks(&state, &obj, Some(&old), &admission_ctx).await?;
    prune_cr_for_storage(ctx.schema.as_ref(), &mut obj);

    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), Some(stored.revision))
        .await
        .map_err(|e| store_err_cr(e, &name, &ctx.kind))?;
    evict_cr_conversion_cache(&state, old["metadata"]["resourceVersion"].as_str());

    let mut meta: crate::types::ObjectMeta =
        serde_json::from_value(obj["metadata"].take()).unwrap_or_default();
    meta.resource_version = Some(new_rv.to_string());
    obj["metadata"] = serde_json::to_value(meta).unwrap_or_default();
    // The stored object may still carry the apiVersion it was written under (e.g. the
    // CRD's storage version changed since); the response must reflect the version this
    // request actually targeted, same as get_cr_namespaced already does.
    obj["apiVersion"] = serde_json::Value::String(format!("{group}/{version}"));
    let mut resp = Json(obj).into_response();
    if let Some(hv) = warn_header {
        resp.headers_mut().insert(axum::http::header::WARNING, hv);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Status subresource handlers for cluster-scoped CRs
// ---------------------------------------------------------------------------

/// PUT /apis/{group}/{version}/{plural}/{name}/status
///
/// Handles both registry-backed resources (falls through to the same logic as
/// `generic::put_resource_status`) and custom resources (stored under
/// `/registry/cr/...`). Only updates the `.status` field; all other fields
/// including `.spec` are left unchanged.
pub async fn put_cr_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    use crate::{keys::group_object_key, types::ResourceKey, util::parse_resource_version};

    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let body = extract_body(&body, ct);
    let incoming: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| Status::bad_request(format!("invalid JSON: {e}")))?;

    // Determine the store key: registry resources use the group-object key;
    // CRs use the /registry/cr/... key.
    let registry_key = ResourceKey {
        group: group.clone(),
        version: version.clone(),
        plural: plural.clone(),
    };
    let (key, kind) = if let Some(meta) = state.resource_registry.get(&registry_key) {
        (
            group_object_key(&group, &plural, None, &name),
            meta.kind.clone(),
        )
    } else {
        // CR fallback: find the CRD to get the kind name, use CR storage key.
        let ctx = find_crd(&state, &group, &version, &plural).await?;
        if ctx.namespaced {
            return Err(Status::not_found(&name, &ctx.kind));
        }
        (cr_store_key(&group, &plural, None, &name), ctx.kind)
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &kind))?;

    let mut current: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // Replace .status and merge .metadata; leave .spec and identity fields unchanged.
    match &incoming["status"] {
        serde_json::Value::Null => {
            if let Some(map) = current.as_object_mut() {
                map.remove("status");
            }
        }
        v => {
            current["status"] = v.clone();
        }
    }

    crate::handlers::status::merge_incoming_metadata(&mut current, &incoming, &kind);

    let incoming_meta: crate::types::ObjectMeta =
        serde_json::from_value(incoming["metadata"].clone()).unwrap_or_default();
    let expected_rv = parse_resource_version(incoming_meta.resource_version.as_deref())?;
    let bytes = serde_json::to_vec(&current).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &kind))?;
    // `resourceVersion` is in merge_incoming_metadata's PROTECTED list, so `current`
    // still carries the pre-put (old) rv here, before it's overwritten below. A no-op
    // for the registry-resource branch above (its rv never appears in the CR conversion
    // cache), but frequent status-subresource updates on a webhook-converted CR are the
    // conversion cache's main growth driver, so this matters most exactly here.
    evict_cr_conversion_cache(&state, current["metadata"]["resourceVersion"].as_str());

    let mut current_meta: crate::types::ObjectMeta =
        serde_json::from_value(current["metadata"].take()).unwrap_or_default();
    current_meta.resource_version = Some(new_rv.to_string());
    current["metadata"] = serde_json::to_value(current_meta).unwrap_or_default();
    Ok(Json(current))
}

/// GET /apis/{group}/{version}/{plural}/{name}/status
///
/// Returns the full object (status is embedded). For CRs this is identical to
/// the main GET endpoint. For registry resources it delegates to get_resource.
pub async fn get_cr_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    use crate::types::ResourceKey;

    let registry_key = ResourceKey {
        group: group.clone(),
        version: version.clone(),
        plural: plural.clone(),
    };
    if state.resource_registry.contains_key(&registry_key) {
        // APIService is a registry resource whose /status a client may read moments after
        // it starts working (the aggregator conformance test does, ~70ms after its own
        // readiness poll succeeds) — far tighter than the periodic availability sweep
        // (main.rs) can reliably win. Block this one read on a single health check when
        // the object has never been checked yet, so the condition the caller reads back
        // is never a bare empty slice.
        if group == "apiregistration.k8s.io" && plural == "apiservices" {
            super::aggregation::ensure_availability_checked(&state, &name).await;
        }
        // Delegate to the generic get handler for registry resources. Table format is a
        // `kubectl get <resource>` concern, not applicable to the /status subresource, so
        // no Accept header is forwarded here.
        return super::resource::get_resource(
            State(state),
            Path((group, version, plural, name)),
            HeaderMap::new(),
        )
        .await;
    }

    // CR path.
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let key = cr_store_key(&group, &plural, None, &name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &ctx.kind))?;

    let mut obj: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;
    obj["apiVersion"] = serde_json::Value::String(format!("{group}/{version}"));
    obj["kind"] = serde_json::Value::String(ctx.kind.clone());
    Ok(Json(obj).into_response())
}

/// PATCH /apis/{group}/{version}/{plural}/{name}/status
///
/// Same registry/CR fallback as `put_cr_status`, but mirrors
/// `handlers::status::patch_resource_status`'s multi-patch-type handling (JSON Patch,
/// merge, strategic merge, and SSA). Before this fallback existed, the route wired PATCH
/// directly to `patch_resource_status`, whose `lookup()` 404s on anything absent from
/// `resource_registry` — every cluster-scoped CRD (e.g. VolumeSnapshotContent) — so a
/// CRD-backed controller's PATCH to its own `/status` subresource never landed.
pub async fn patch_cr_status<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    use crate::handlers::json_patch::{
        apply_json_patch, detect_patch_type, ssa_body_to_json, PatchType,
    };
    use crate::{keys::group_object_key, types::ResourceKey, util::parse_resource_version};

    let patch_type = detect_patch_type(&headers)?;
    let is_ssa = content_type(&headers).contains("apply-patch+yaml");

    // Determine the store key: registry resources use the group-object key;
    // CRs use the /registry/cr/... key. Same fallback as put_cr_status.
    let registry_key = ResourceKey {
        group: group.clone(),
        version: version.clone(),
        plural: plural.clone(),
    };
    let (key, kind) = if let Some(meta) = state.resource_registry.get(&registry_key) {
        (
            group_object_key(&group, &plural, None, &name),
            meta.kind.clone(),
        )
    } else {
        let ctx = find_crd(&state, &group, &version, &plural).await?;
        if ctx.namespaced {
            return Err(Status::not_found(&name, &ctx.kind));
        }
        (cr_store_key(&group, &plural, None, &name), ctx.kind)
    };

    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(&name, &kind))?;

    let mut current: serde_json::Value =
        serde_json::from_slice(&stored.value).map_err(|e| Status::internal(e.to_string()))?;

    // apply-patch+yaml bodies are genuine YAML; every other patch type here is JSON.
    let patch: serde_json::Value = if is_ssa {
        ssa_body_to_json(&body)?
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Status::bad_request(format!("invalid patch JSON: {e}")))?
    };

    match patch_type {
        PatchType::Json => {
            crate::handlers::status::validate_status_json_patch_paths(&patch)?;
            apply_json_patch(&mut current, &patch)?;
        }
        _ => {
            // Merge and strategic merge: apply status and metadata from the patch body.
            if let Some(status_patch) = patch.get("status") {
                let entry = current.as_object_mut().map(|m| {
                    m.entry("status")
                        .or_insert(serde_json::Value::Object(Default::default()))
                });
                if let Some(entry) = entry {
                    match patch_type {
                        PatchType::Merge => crate::patch::merge_patch(entry, status_patch),
                        PatchType::StrategicMerge => {
                            crate::patch::strategic_merge_patch(entry, status_patch)
                                .map_err(|e| Status::bad_request(e.to_string()))?;
                        }
                        PatchType::Json => unreachable!(),
                    }
                    crate::handlers::status::reject_non_object_status(entry)?;
                }
            }
            crate::handlers::status::merge_incoming_metadata(&mut current, &patch, &kind);
        }
    }

    let expected_rv = parse_resource_version(patch["metadata"]["resourceVersion"].as_str())?;
    let bytes = serde_json::to_vec(&current).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, &name, &kind))?;
    // Same ordering as put_cr_status: `current["metadata"]["resourceVersion"]` here is
    // still the pre-put (old) rv for the merge/strategic-merge branches (protected by
    // merge_incoming_metadata), which is what the conversion cache is keyed on.
    evict_cr_conversion_cache(&state, current["metadata"]["resourceVersion"].as_str());

    let mut current_meta: crate::types::ObjectMeta =
        serde_json::from_value(current["metadata"].take()).unwrap_or_default();
    current_meta.resource_version = Some(new_rv.to_string());
    current["metadata"] = serde_json::to_value(current_meta).unwrap_or_default();
    Ok(Json(current))
}

// ---------------------------------------------------------------------------
// CRD scale subresource
//
// Routes:
//   GET/PUT/PATCH /apis/{group}/{version}/{plural}/{name}/scale               (cluster-scoped)
//   GET/PUT/PATCH /apis/{group}/{version}/namespaces/{ns}/{plural}/{name}/scale (namespaced)
//
// Unlike the apps/v1 scale.rs handlers (hardcoded to spec.replicas/status.replicas), a CRD
// declares its own `specReplicasPath`/`statusReplicasPath`/`labelSelectorPath` under
// `subresources.scale` — these routes resolve those CRD-declared paths generically, which is
// what let this fall through to 404 for every CRD before this: there was no route at all.
// ---------------------------------------------------------------------------

/// Reads an integer at a CRD-declared dot path (e.g. "spec.replicas"). Mirrors upstream's
/// `unstructured.NestedInt64` fallback for the scale subresource (apiextensions-apiserver's
/// `CRToScale`): any missing segment or non-numeric value along the way silently resolves to
/// 0 rather than erroring, since statusReplicasPath in particular routinely points at a field
/// that hasn't been written yet (e.g. status before the CR's own controller first reconciles).
fn scale_path_get_i64(obj: &serde_json::Value, path: &str) -> i64 {
    let mut cur = obj;
    for seg in path.split('.') {
        match cur.get(seg) {
            Some(next) => cur = next,
            None => return 0,
        }
    }
    cur.as_i64().unwrap_or(0)
}

/// Reads a string at a CRD-declared dot path (labelSelectorPath), defaulting to "" when
/// absent. HPA's `validateAndParseSelector` treats an empty selector as a hard error, so this
/// default only matters when the CRD author never populates the field — the same failure mode
/// apps/v1's `label_selector_to_string` already documents.
fn scale_path_get_str<'a>(obj: &'a serde_json::Value, path: &str) -> &'a str {
    let mut cur = obj;
    for seg in path.split('.') {
        match cur.get(seg) {
            Some(next) => cur = next,
            None => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

/// Writes `new_value` at a CRD-declared dot path, creating intermediate objects as needed
/// (`serde_json::Value`'s `IndexMut` auto-vivifies a `Null` into an `Object` on indexing,
/// matching upstream's `unstructured.SetNestedField`). Only ever called with
/// `specReplicasPath` — `statusReplicasPath`/`labelSelectorPath` are read-only from the scale
/// subresource's perspective; the CR's own controller owns writing those.
fn scale_path_set_i64(obj: &mut serde_json::Value, path: &str, new_value: i64) {
    let segs: Vec<&str> = path.split('.').collect();
    let Some((last, parents)) = segs.split_last() else {
        return;
    };
    let mut cur = obj;
    for seg in parents {
        cur = &mut cur[*seg];
    }
    cur[*last] = serde_json::json!(new_value);
}

/// Identifies which stored CR a scale request targets. Grouped into one struct (rather than
/// four positional args) purely to keep `cr_scale_put_impl`/`cr_scale_patch_impl` under
/// clippy's `too_many_arguments` limit — mirrors `WatchConfig` elsewhere in this codebase,
/// which groups arguments for the same reason.
struct CrScaleTarget<'a> {
    group: &'a str,
    plural: &'a str,
    ns: Option<&'a str>,
    name: &'a str,
}

async fn cr_scale_get_impl<S: Store>(
    state: &AppState<S>,
    ctx: &CrContext,
    target: CrScaleTarget<'_>,
) -> Result<Response, crate::status::StatusError> {
    let scale_cfg = ctx.scale.as_ref().ok_or_else(|| {
        Status::not_found(
            target.name,
            &format!("scale subresource for {}", target.plural),
        )
    })?;

    let key = cr_store_key(target.group, target.plural, target.ns, target.name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(target.name, &ctx.kind))?;
    let obj: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let spec_replicas = scale_path_get_i64(&obj, &scale_cfg.spec_replicas_path);
    let status_replicas = scale_path_get_i64(&obj, &scale_cfg.status_replicas_path);
    let selector = scale_cfg
        .label_selector_path
        .as_deref()
        .map(|p| scale_path_get_str(&obj, p))
        .unwrap_or("");
    let rv = obj["metadata"]["resourceVersion"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(Json(super::scale::build_scale(
        target.name,
        target.ns.unwrap_or(""),
        spec_replicas,
        status_replicas,
        &rv,
        selector,
    ))
    .into_response())
}

async fn cr_scale_put_impl<S: Store>(
    state: &AppState<S>,
    ctx: &CrContext,
    target: CrScaleTarget<'_>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let scale_cfg = ctx.scale.as_ref().ok_or_else(|| {
        Status::not_found(
            target.name,
            &format!("scale subresource for {}", target.plural),
        )
    })?;

    let scale_body = super::scale::decode_scale_body(body, headers)?;
    let new_replicas = scale_body
        .spec
        .replicas
        .ok_or_else(|| Status::bad_request("spec.replicas must be an integer".into()))?;

    let key = cr_store_key(target.group, target.plural, target.ns, target.name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(target.name, &ctx.kind))?;
    let mut obj: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    // Capture actual pod count and selector before changing spec so the response reflects
    // reality — same ordering apps/v1's scale_put_impl uses, for the same reason.
    let status_replicas = scale_path_get_i64(&obj, &scale_cfg.status_replicas_path);
    let selector = scale_cfg
        .label_selector_path
        .as_deref()
        .map(|p| scale_path_get_str(&obj, p).to_string())
        .unwrap_or_default();

    scale_path_set_i64(&mut obj, &scale_cfg.spec_replicas_path, new_replicas as i64);

    let expected_rv = parse_resource_version(scale_body.metadata.resource_version.as_deref())?;
    let old_rv = obj["metadata"]["resourceVersion"]
        .as_str()
        .map(str::to_string);
    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, target.name, &ctx.kind))?;
    evict_cr_conversion_cache(state, old_rv.as_deref());

    Ok(Json(super::scale::build_scale(
        target.name,
        target.ns.unwrap_or(""),
        new_replicas as i64,
        status_replicas,
        &new_rv.to_string(),
        &selector,
    )))
}

async fn cr_scale_patch_impl<S: Store>(
    state: &AppState<S>,
    ctx: &CrContext,
    target: CrScaleTarget<'_>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let scale_cfg = ctx.scale.as_ref().ok_or_else(|| {
        Status::not_found(
            target.name,
            &format!("scale subresource for {}", target.plural),
        )
    })?;

    let scale_body = super::scale::decode_scale_body(body, headers)?;

    let key = cr_store_key(target.group, target.plural, target.ns, target.name);
    let stored = state
        .store
        .get(&key)
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(target.name, &ctx.kind))?;
    let mut obj: serde_json::Value = serde_json::from_slice(&stored.value)
        .map_err(|e| Status::internal(format!("corrupt stored object: {e}")))?;

    let status_replicas = scale_path_get_i64(&obj, &scale_cfg.status_replicas_path);
    let selector = scale_cfg
        .label_selector_path
        .as_deref()
        .map(|p| scale_path_get_str(&obj, p).to_string())
        .unwrap_or_default();

    // Mirrors apps/v1's scale_patch_impl: extract replicas from the patch body if present,
    // otherwise leave the stored value unchanged (a patch that doesn't touch spec.replicas
    // is a no-op write, not an error).
    let new_replicas = match scale_body.spec.replicas {
        Some(r) => {
            scale_path_set_i64(&mut obj, &scale_cfg.spec_replicas_path, r as i64);
            r as i64
        }
        None => scale_path_get_i64(&obj, &scale_cfg.spec_replicas_path),
    };

    let expected_rv = parse_resource_version(scale_body.metadata.resource_version.as_deref())?;
    let old_rv = obj["metadata"]["resourceVersion"]
        .as_str()
        .map(str::to_string);
    let bytes = serde_json::to_vec(&obj).map_err(|e| Status::internal(e.to_string()))?;
    let new_rv = state
        .store
        .put(&key, Bytes::from(bytes), expected_rv)
        .await
        .map_err(|e| store_err_cr(e, target.name, &ctx.kind))?;
    evict_cr_conversion_cache(state, old_rv.as_deref());

    Ok(Json(super::scale::build_scale(
        target.name,
        target.ns.unwrap_or(""),
        new_replicas,
        status_replicas,
        &new_rv.to_string(),
        &selector,
    )))
}

/// GET /apis/{group}/{version}/{plural}/{name}/scale (cluster-scoped)
pub async fn get_cr_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: None,
        name: &name,
    };
    cr_scale_get_impl(&state, &ctx, target).await
}

/// PUT /apis/{group}/{version}/{plural}/{name}/scale (cluster-scoped)
pub async fn put_cr_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: None,
        name: &name,
    };
    cr_scale_put_impl(&state, &ctx, target, &headers, &body).await
}

/// PATCH /apis/{group}/{version}/{plural}/{name}/scale (cluster-scoped)
pub async fn patch_cr_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, plural, name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: None,
        name: &name,
    };
    cr_scale_patch_impl(&state, &ctx, target, &headers, &body).await
}

/// GET /apis/{group}/{version}/namespaces/{ns}/{plural}/{name}/scale
pub async fn get_cr_namespaced_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
) -> Result<Response, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: Some(&ns),
        name: &name,
    };
    cr_scale_get_impl(&state, &ctx, target).await
}

/// PUT /apis/{group}/{version}/namespaces/{ns}/{plural}/{name}/scale
pub async fn put_cr_namespaced_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: Some(&ns),
        name: &name,
    };
    cr_scale_put_impl(&state, &ctx, target, &headers, &body).await
}

/// PATCH /apis/{group}/{version}/namespaces/{ns}/{plural}/{name}/scale
pub async fn patch_cr_namespaced_scale<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version, ns, plural, name)): Path<(String, String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, crate::status::StatusError> {
    let ctx = find_crd(&state, &group, &version, &plural).await?;
    if !ctx.namespaced {
        return Err(Status::not_found(&name, &ctx.kind));
    }
    let target = CrScaleTarget {
        group: &group,
        plural: &plural,
        ns: Some(&ns),
        name: &name,
    };
    cr_scale_patch_impl(&state, &ctx, target, &headers, &body).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    use crate::handlers::test_support::make_state;

    fn no_watch_query() -> super::super::generic::CollectionQuery {
        super::super::generic::CollectionQuery {
            watch: None,
            resource_version: None,
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        }
    }

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

    fn expect_err_status<T>(
        result: Result<T, crate::status::StatusError>,
        msg: &str,
    ) -> crate::status::StatusError {
        match result {
            Ok(_) => panic!("expected Err but got Ok: {msg}"),
            Err(e) => e,
        }
    }

    fn namespaced_crd_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "applications.argoproj.io" },
                "spec": {
                    "group": "argoproj.io",
                    "names": {
                        "plural": "applications",
                        "singular": "application",
                        "kind": "Application",
                        "listKind": "ApplicationList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1alpha1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    fn cluster_crd_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    async fn install_namespaced_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespaced_crd_bytes()
            )
            .await
            .is_ok(),
            "install namespaced CRD"
        );
    }

    async fn install_cluster_crd(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                cluster_crd_bytes()
            )
            .await
            .is_ok(),
            "install cluster CRD"
        );
    }

    fn app_body(name: &str, ns: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": name, "namespace": ns },
                "spec": { "destination": { "namespace": "default" } }
            })
            .to_string(),
        )
    }

    fn widget_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": name },
                "spec": { "color": "blue" }
            })
            .to_string(),
        )
    }

    // Create a namespaced CR then get it back — round-trip must return the stored object.
    #[tokio::test]
    async fn namespaced_create_and_get_round_trip() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name.clone())),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after create"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // `kubectl get <crd-plural> <name> -n <ns>` sends Accept: application/json;as=Table;...
    // by default, same as for built-in namespaced types. Before this fix, get_cr_namespaced
    // had no HeaderMap parameter at all and unconditionally returned the raw object, so
    // kubectl fell back to printing only NAME/AGE for every namespaced custom resource.
    #[tokio::test]
    async fn get_cr_namespaced_with_table_accept_returns_single_row_table() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let resp = get_cr_namespaced(
            State(state),
            Path((group, version, ns, plural, name)),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_cr_namespaced with Table accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain Application kind here means kubectl can't decode it as a Table and \
             silently falls back to hardcoded NAME/AGE-only columns for the namespaced \
             custom resource"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            1,
            "a single-object GET must produce exactly one Table row, not a full list"
        );
        assert_eq!(
            rows[0]["object"]["metadata"]["name"], "my-app",
            "kubectl reads the row's embedded object to resolve the resource on selection"
        );
    }

    // kcm's GC sends `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`
    // when verifying a namespaced CR owner reference still exists (garbagecollector.go:434-444
    // isDangling). Before this fix, get_cr_namespaced always returned the full typed object,
    // which the GC's metadata-only decoder rejects; the owner-check retries forever and
    // newly-orphaned custom resources leak indefinitely on any long-running u7s cluster.
    #[tokio::test]
    async fn get_cr_namespaced_returns_partial_object_metadata_when_requested() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            ),
        );

        let resp = get_cr_namespaced(
            State(state),
            Path((group, version, ns, plural, name)),
            headers,
        )
        .await
        .unwrap_or_else(|_| {
            panic!("get_cr_namespaced with PartialObjectMetadata accept must return 200")
        });

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadata",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("spec").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
    }

    // Request for an unknown group must return 404 (no CRD installed for that group).
    #[tokio::test]
    async fn unknown_group_returns_404() {
        let state = make_state();

        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "unknown.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "things".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "expected 404 for unknown group",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404, "must return 404 for unknown group");
        assert_eq!(json["reason"], "NotFound");
    }

    // Using a namespaced path for a cluster-scoped CRD must return 404.
    #[tokio::test]
    async fn namespaced_path_for_cluster_crd_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // widgets is cluster-scoped; using namespaces/:ns path must be rejected.
        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "cluster-scoped CRD must reject namespaced path",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // GET /apis/{group}/{version}/{plural} (no namespace segment) on a Namespaced CRD
    // must return 200 with an empty list, not 404. KCM GC informers watch this path to
    // garbage-collect custom resources cluster-wide; a 404 causes them to retry every 15s
    // and prevents namespace deletion from completing.
    #[tokio::test]
    async fn cluster_wide_list_for_namespaced_crd_returns_200() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "cluster-wide list on namespaced CRD must return 200, got: {}",
                    json
                );
            }
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "KCM informers watch cluster-wide path; 404 causes infinite retry"
        );
    }

    // GET /apis/{group}/{version}/{plural} on a Namespaced CRD with CRs in multiple
    // namespaces must return all of them. KCM GC needs the full cross-namespace view
    // to discover owner references and garbage-collect correctly.
    #[tokio::test]
    async fn cluster_wide_list_for_namespaced_crd_returns_all_namespaces() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        // Create CRs in two different namespaces.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "ns-a".to_string(),
                    "applications".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("app-in-ns-a", "ns-a"),
            )
            .await
            .is_ok(),
            "create in ns-a must succeed"
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "ns-b".to_string(),
                    "applications".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("app-in-ns-b", "ns-b"),
            )
            .await
            .is_ok(),
            "create in ns-b must succeed"
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!("cluster-wide list must succeed, got: {}", json);
            }
        };

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let items = list["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            2,
            "cluster-wide list must include CRs from all namespaces, got {}",
            items.len()
        );
    }

    // WATCH /apis/{group}/{version}/{plural} (no namespace) on a Namespaced CRD must
    // return 200 with chunked streaming. KCM informers use this watch path.
    #[tokio::test]
    async fn cluster_wide_watch_for_namespaced_crd_returns_200_chunked() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "cluster-wide watch on namespaced CRD must return 200, got: {}",
                    json
                );
            }
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "cluster-wide watch on namespaced CRD must use chunked transfer encoding"
        );
    }

    // Creating the same CR twice must return 409 AlreadyExists.
    #[tokio::test]
    async fn duplicate_create_returns_409() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "first create must succeed"
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns.clone(), plural)),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await,
            "duplicate create must fail with 409",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409, "duplicate create must return 409");
        assert_eq!(json["reason"], "AlreadyExists");
    }

    /// A store wrapper whose first `put()` call always fails with AlreadyExists,
    /// regardless of key — simulating a generateName suffix landing on some unrelated
    /// existing object. Delegates every other call to the inner SqliteStore.
    ///
    /// Used by create_cr/create_cr_namespaced's generateName-collision-retry regression
    /// tests. `create_if_namespace_active`'s default trait implementation calls `put()`
    /// internally, so this transparently exercises create_cr_namespaced's actual write
    /// path too.
    struct FirstPutAlreadyExistsStore {
        inner: Arc<SqliteStore>,
        fire_once: std::sync::atomic::AtomicBool,
    }

    impl FirstPutAlreadyExistsStore {
        fn new(inner: Arc<SqliteStore>) -> Self {
            Self {
                inner,
                fire_once: std::sync::atomic::AtomicBool::new(true),
            }
        }
    }

    impl u7s_store::Store for FirstPutAlreadyExistsStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            async move { inner.get(&key).await }
        }

        fn list(
            &self,
            prefix: &str,
            opts: u7s_store::ListOptions,
        ) -> impl std::future::Future<Output = u7s_store::Result<u7s_store::ListResponse>> + Send
        {
            let inner = self.inner.clone();
            let prefix = prefix.to_string();
            async move { inner.list(&prefix, opts).await }
        }

        fn put(
            &self,
            key: &str,
            value: Bytes,
            expected_revision: Option<u64>,
        ) -> impl std::future::Future<Output = u7s_store::Result<u64>> + Send {
            let inject = self
                .fire_once
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            let inner = self.inner.clone();
            let key = key.to_string();
            async move {
                if inject {
                    Err(u7s_store::StoreError::AlreadyExists { key })
                } else {
                    inner.put(&key, value, expected_revision).await
                }
            }
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

    /// A controller mass-creating cluster-scoped CRs via bare `metadata.generateName`
    /// must not see a spurious 409 just because the server's random name suffix happened
    /// to collide with an unrelated object. This forces that collision on the very first
    /// `put()` and asserts create_cr retries with a fresh suffix and succeeds, rather than
    /// surfacing the collision as AlreadyExists to the client.
    ///
    /// Fails on revert: without the retry, create_cr's single `store.put` call returns
    /// AlreadyExists and the handler maps it straight to 409.
    #[tokio::test]
    async fn create_cr_retries_generate_name_collision_instead_of_409ing() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        inner
            .put(
                &format!("{CRD_LIST_PREFIX}widgets.example.io"),
                cluster_crd_bytes(),
                None,
            )
            .await
            .expect("seed CRD");
        let collision_store = Arc::new(FirstPutAlreadyExistsStore::new(Arc::clone(&inner)));
        let state = AppState::new(
            Arc::clone(&collision_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "generateName": "widget-" },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        let resp = match create_cr(
            State(state),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        {
            Ok(r) => r.into_response(),
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "a generateName-based CR create must retry past a spurious store \
                     collision, not hard-error: {json}"
                );
            }
        };
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a generateName-based CR create must retry past a spurious store collision, \
             not hard-error with 409 — a controller mass-creating CRs via generateName \
             would otherwise see spurious create failures"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            created["metadata"]["name"]
                .as_str()
                .is_some_and(|n| n.starts_with("widget-")),
            "created CR must still carry the generateName prefix after the retry"
        );
    }

    /// Namespaced sibling of `create_cr_retries_generate_name_collision_instead_of_409ing`:
    /// create_cr_namespaced writes via `create_if_namespace_active` (not a bare `put`), a
    /// separate code path that needs its own generateName-collision-retry loop, so it must
    /// retry past a spurious store collision instead of surfacing a 409 to a controller
    /// mass-creating namespaced CRs via generateName.
    ///
    /// Fails on revert: without the retry, create_cr_namespaced's single
    /// `create_if_namespace_active` call returns AlreadyExists and the handler maps it
    /// straight to 409.
    #[tokio::test]
    async fn create_cr_namespaced_retries_generate_name_collision_instead_of_409ing() {
        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        inner
            .put(
                &format!("{CRD_LIST_PREFIX}applications.argoproj.io"),
                namespaced_crd_bytes(),
                None,
            )
            .await
            .expect("seed CRD");
        let collision_store = Arc::new(FirstPutAlreadyExistsStore::new(Arc::clone(&inner)));
        let state = AppState::new(
            Arc::clone(&collision_store),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "generateName": "app-", "namespace": "argocd" },
                "spec": { "destination": { "namespace": "default" } }
            })
            .to_string(),
        );

        let resp = match create_cr_namespaced(
            State(state),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        {
            Ok(r) => r.into_response(),
            Err(e) => {
                let json = serde_json::to_value(&e.1).unwrap();
                panic!(
                    "a generateName-based namespaced CR create must retry past a spurious \
                     store collision, not hard-error: {json}"
                );
            }
        };
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a generateName-based namespaced CR create must retry past a spurious store \
             collision, not hard-error with 409 — a controller mass-creating CRs via \
             generateName would otherwise see spurious create failures"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(
            created["metadata"]["name"]
                .as_str()
                .is_some_and(|n| n.starts_with("app-")),
            "created CR must still carry the generateName prefix after the retry"
        );
    }

    // Getting a missing CR must return 404.
    #[tokio::test]
    async fn get_missing_cr_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            get_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "argocd".to_string(),
                    "applications".to_string(),
                    "nonexistent".to_string(),
                )),
                axum::http::HeaderMap::new(),
            )
            .await,
            "missing CR must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // Cluster-scoped CR create + get round-trip.
    #[tokio::test]
    async fn cluster_scoped_create_and_get() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "cluster-scoped create must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after create"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // `kubectl get <crd-plural> <name>` sends Accept: application/json;as=Table;... by
    // default, same as for built-in types. Before this fix, get_cr had no HeaderMap
    // parameter at all and unconditionally returned the raw object, so kubectl fell back
    // to printing only NAME/AGE for every custom resource (list_cr already handled this
    // for LIST, leaving single-object GET as the last gap).
    #[tokio::test]
    async fn get_cr_with_table_accept_returns_single_row_table() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "cluster-scoped create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json;as=Table;g=meta.k8s.io;v=v1"),
        );

        let resp = get_cr(
            State(state),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_cr with Table accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Table",
            "a plain Widget kind here means kubectl can't decode it as a Table and silently \
             falls back to hardcoded NAME/AGE-only columns for the custom resource"
        );
        let rows = v["rows"].as_array().expect("Table response must have rows");
        assert_eq!(
            rows.len(),
            1,
            "a single-object GET must produce exactly one Table row, not a full list"
        );
        assert_eq!(
            rows[0]["object"]["metadata"]["name"], "my-widget",
            "kubectl reads the row's embedded object to resolve the resource on selection"
        );
    }

    // kcm's GC sends `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`
    // when verifying a cluster-scoped CR owner reference still exists
    // (garbagecollector.go:434-444 isDangling). Before this fix, get_cr always returned the
    // full typed object, which the GC's metadata-only decoder rejects; the owner-check
    // retries forever and newly-orphaned custom resources leak indefinitely on any
    // long-running u7s cluster.
    #[tokio::test]
    async fn get_cr_returns_partial_object_metadata_when_requested() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "cluster-scoped create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
            ),
        );

        let resp = get_cr(
            State(state),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_cr with PartialObjectMetadata accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["apiVersion"], "meta.k8s.io/v1",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert_eq!(
            v["kind"], "PartialObjectMetadata",
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
        assert!(
            v.get("spec").is_none(),
            "blocks vendored kcm GC's isDangling owner-reference verification \
             (garbagecollector.go:434-444); leaked orphans compound on any long-running \
             u7s cluster."
        );
    }

    // `kubectl get <crd-plural> <name> -o json` sends a plain Accept: application/json (no
    // as=Table) and must keep receiving the raw object. This guards against a broken
    // wants_table condition silently turning every CR GET into a Table response.
    #[tokio::test]
    async fn get_cr_with_plain_json_accept_returns_raw_object() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "cluster-scoped create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static("application/json"),
        );

        let resp = get_cr(
            State(state),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            headers,
        )
        .await
        .unwrap_or_else(|_| panic!("get_cr with plain JSON accept must return 200"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            v["kind"], "Widget",
            "`kubectl get widget <name> -o json` must still return the raw object, not a \
             Table, when Accept does not request Table format"
        );
        assert_eq!(v["metadata"]["name"], "my-widget");
    }

    // List after create must return one item.
    #[tokio::test]
    async fn list_returns_created_items() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("app-one", &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural)),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Regression test: `?limit`/`?continue` pagination for namespaced Custom Resources
    /// must walk every CR exactly once, in a stable order, while every page reports the
    /// SAME `metadata.resourceVersion`.
    ///
    /// Before this fix, `list_cr_namespaced` called `store.list()` with
    /// `ListOptions::default()`, silently ignoring `?limit`/`?continue` and always
    /// returning the full unpaginated list — so a controller doing paginated CR listing
    /// (or `kubectl get --chunk-size`) would get back every object on page one instead of
    /// a real page. Mirrors `list_namespaced_resource_paginates_all_items_once_with_stable_resource_version`
    /// in resource.rs, which encodes the same contract for built-in resources.
    #[tokio::test]
    async fn list_cr_namespaced_paginates_all_items_once_with_stable_resource_version() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();

        const TOTAL: usize = 25;
        for i in 0..TOTAL {
            let name = format!("app-{i:02}");
            assert!(
                create_cr_namespaced(
                    State(state.clone()),
                    Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    app_body(&name, &ns),
                )
                .await
                .is_ok(),
                "create must succeed"
            );
        }

        let mut collected_names: Vec<String> = Vec::new();
        let mut resource_versions: Vec<String> = Vec::new();
        let mut continue_token: Option<String> = None;
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(
                pages <= TOTAL + 1,
                "pagination did not terminate — likely stuck on one page"
            );

            let query = super::super::generic::CollectionQuery {
                watch: None,
                resource_version: None,
                label_selector: None,
                field_selector: None,
                limit: Some(7),
                continue_token: continue_token.take(),
                send_initial_events: None,
                allow_watch_bookmarks: None,
                timeout_seconds: None,
            };

            let resp = list_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                axum::http::HeaderMap::new(),
                query,
                "test-user".to_string(),
            )
            .await
            .unwrap_or_else(|e| panic!("paginated list must succeed, got {e:?}"));

            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

            let items = val["items"].as_array().expect("items must be an array");
            assert!(
                items.len() <= 7,
                "a page must never exceed the requested ?limit=7"
            );
            for item in items {
                collected_names.push(item["metadata"]["name"].as_str().unwrap().to_string());
            }
            resource_versions.push(val["metadata"]["resourceVersion"].as_str().unwrap().into());

            match val["metadata"]["continue"].as_str() {
                Some(tok) if !tok.is_empty() => continue_token = Some(tok.to_string()),
                _ => break,
            }

            // Simulate a concurrent, unrelated write landing between page fetches (e.g. a
            // Lease renewal from another controller). This bumps the store's live global
            // revision but must NOT change the resourceVersion this pagination walk
            // reports on the next page.
            state
                .store
                .put(
                    &format!("/registry/leases/kube-node-lease/unrelated-node-{pages}"),
                    Bytes::from_static(b"{}"),
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(
            collected_names.len(),
            TOTAL,
            "every created Application CR must be returned exactly once across all pages \
             combined — duplicates or gaps mean the continue cursor is mis-tracking position"
        );
        let mut expected: Vec<String> = (0..TOTAL).map(|i| format!("app-{i:02}")).collect();
        expected.sort();
        let mut actual = collected_names.clone();
        actual.sort();
        assert_eq!(
            actual, expected,
            "the set of names returned across all pages must equal the set created"
        );
        assert_eq!(
            collected_names, expected,
            "pages must be returned in stable ascending key order so that resuming from a \
             continue token never re-visits or skips an item"
        );
        assert!(
            resource_versions.windows(2).all(|w| w[0] == w[1]),
            "every page of one pagination pass must report the SAME resourceVersion ({:?}); \
             a mismatch means the response used the store's live (advancing) revision instead \
             of the revision pinned in the continue token, which would fail the Kubernetes \
             chunking conformance assertion `list.ResourceVersion == lastRV` if it applied to CRs",
            resource_versions
        );
    }

    /// Regression test: a CR LIST with `?fieldSelector=<CRD-declared field>=<value>` must
    /// return only the CRs whose value at that path matches — not every CR in the namespace.
    ///
    /// Before this fix, `list_cr_namespaced` hardcoded `ListOptions { field_selector: None,
    /// .. }` for the non-watch LIST path, silently discarding the client's selector. Clients
    /// that rely on server-side filtering by a CRD's declared `x-kubernetes-selectable-fields`
    /// — the CustomResourceFieldSelectors conformance suite, and any controller listing CRs
    /// with a field selector instead of filtering client-side — got back every object instead
    /// of the matching subset, either breaking outright (a watch+list pair built around the
    /// same filter disagreeing) or silently over-fetching.
    #[tokio::test]
    async fn list_cr_namespaced_honors_field_selector_on_declared_selectable_field() {
        let state = make_state();

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let ns = "default".to_string();
        let plural = "gadgets".to_string();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gadgets.example.io" },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": "gadgets",
                        "singular": "gadget",
                        "kind": "Gadget",
                        "listKind": "GadgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": version,
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": { "host": { "type": "string" } }
                                    }
                                }
                            }
                        },
                        "selectableFields": [{ "jsonPath": ".spec.host" }]
                    }]
                }
            })
            .to_string(),
        );
        {
            use crate::handlers::crd;
            assert!(
                crd::create_crd(
                    State(state.clone()),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    crd_bytes,
                )
                .await
                .is_ok(),
                "install CRD with a declared selectable field"
            );
        }

        let gadget_body = |name: &str, host: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Gadget",
                    "metadata": { "name": name, "namespace": ns },
                    "spec": { "host": host }
                })
                .to_string(),
            )
        };

        for (name, host) in [
            ("gadget-a", "host1"),
            ("gadget-b", "host1"),
            ("gadget-c", "host2"),
        ] {
            assert!(
                create_cr_namespaced(
                    State(state.clone()),
                    Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    gadget_body(name, host),
                )
                .await
                .is_ok(),
                "create gadget {name} must succeed"
            );
        }

        let query = super::super::generic::CollectionQuery {
            field_selector: Some("spec.host=host1".to_string()),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural)),
            axum::http::HeaderMap::new(),
            query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("field-selected list must succeed, got {e:?}"));

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut names: Vec<&str> = val["items"]
            .as_array()
            .expect("items must be an array")
            .iter()
            .map(|item| item["metadata"]["name"].as_str().unwrap())
            .collect();
        names.sort();

        assert_eq!(
            names,
            vec!["gadget-a", "gadget-b"],
            "LIST with fieldSelector=spec.host=host1 must return only the CRs whose spec.host \
             equals host1 — returning gadget-c (host2) too means the selector was ignored, and \
             missing gadget-a/b means declared-field resolution is broken"
        );
    }

    /// Regression test: a field selector on a path the CRD did NOT declare in
    /// `selectableFields` must not leak that field's value into filtering — even though the
    /// CR body actually contains it. Matches upstream's `fields.Set.Get()` fallback for an
    /// unrecognized key ("", which then fails an equality against a non-empty expectation):
    /// declaring `selectableFields` is how a CRD author opts specific fields into
    /// server-side filtering, so an undeclared field must behave as if it were never there.
    #[tokio::test]
    async fn list_cr_namespaced_ignores_selector_on_undeclared_field() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("app-one", &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // "destination.namespace" is a real field on the stored object (see app_body) but the
        // installed CRD (namespaced_crd_bytes) declares no selectableFields at all.
        let query = super::super::generic::CollectionQuery {
            field_selector: Some("spec.destination.namespace=default".to_string()),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural)),
            axum::http::HeaderMap::new(),
            query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("list must succeed, got {e:?}"));

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            val["items"]
                .as_array()
                .expect("items must be an array")
                .len(),
            0,
            "an undeclared field must resolve as absent regardless of the object's actual \
             content, so a non-empty equality against it can never match — if this returns \
             app-one, an arbitrary body field became selectable without the CRD author opting \
             it in via selectableFields"
        );
    }

    /// Regression test: a CR watch with `?fieldSelector=<CRD-declared field>=<value>` must
    /// exclude CRs that don't match — not stream every CR as ADDED regardless of its value.
    ///
    /// Before this fix, watch.rs's per-event filtering always used the generic
    /// name/namespace/nodeName-only matcher, which silently passes any other field (its
    /// `_ => {}` catch-all), so a CR watch with `fieldSelector=spec.host=host1` streamed
    /// every CR in the namespace regardless of `spec.host`. This is the exact live
    /// conformance mismatch: CustomResourceFieldSelectors' watch assertion expects only the
    /// matching CRs as ADDED and got all of them instead. Mirrors
    /// `list_cr_namespaced_honors_field_selector_on_declared_selectable_field`'s fixture but
    /// exercises the watch path (`sendInitialEvents=true`, the phase the live failure was in)
    /// instead of plain LIST.
    #[tokio::test]
    async fn list_cr_namespaced_watch_honors_field_selector_on_declared_selectable_field() {
        let state = make_state();

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let ns = "default".to_string();
        let plural = "gadgets".to_string();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gadgets.example.io" },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": "gadgets",
                        "singular": "gadget",
                        "kind": "Gadget",
                        "listKind": "GadgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": version,
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": { "host": { "type": "string" } }
                                    }
                                }
                            }
                        },
                        "selectableFields": [{ "jsonPath": ".spec.host" }]
                    }]
                }
            })
            .to_string(),
        );
        {
            use crate::handlers::crd;
            assert!(
                crd::create_crd(
                    State(state.clone()),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    crd_bytes,
                )
                .await
                .is_ok(),
                "install CRD with a declared selectable field"
            );
        }

        let gadget_body = |name: &str, host: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Gadget",
                    "metadata": { "name": name, "namespace": ns },
                    "spec": { "host": host }
                })
                .to_string(),
            )
        };

        for (name, host) in [
            ("gadget-a", "host1"),
            ("gadget-b", "host1"),
            ("gadget-c", "host2"),
        ] {
            assert!(
                create_cr_namespaced(
                    State(state.clone()),
                    Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    gadget_body(name, host),
                )
                .await
                .is_ok(),
                "create gadget {name} must succeed"
            );
        }

        // sendInitialEvents=true relists the 3 already-created CRs as ADDED before the live
        // phase — the exact shape of the live failure (all 3 delivered instead of the 2
        // matching gadget-a/b). timeout_seconds=2 closes the stream so the test doesn't hang.
        let watch_query = super::super::generic::CollectionQuery {
            watch: Some(true),
            send_initial_events: Some(true),
            field_selector: Some("spec.host=host1".to_string()),
            timeout_seconds: Some(2),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural)),
            axum::http::HeaderMap::new(),
            watch_query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("field-selected watch must succeed, got {e:?}"));
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            axum::body::to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("watch stream must complete within 15 seconds")
        .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            body_str.contains("\"gadget-a\"") && body_str.contains("\"gadget-b\""),
            "watch with fieldSelector=spec.host=host1 must still deliver the matching CRs \
             (got: {body_str})"
        );
        assert!(
            !body_str.contains("\"gadget-c\""),
            "watch with fieldSelector=spec.host=host1 must NOT deliver gadget-c \
             (spec.host=host2) as ADDED — the generic field-selector matcher treats any field \
             other than metadata.name/namespace/spec.nodeName as a no-op pass-through, which \
             regresses to exactly the live CustomResourceFieldSelectors watch failure if this \
             fix is reverted (got: {body_str})"
        );
    }

    // ---------------------------------------------------------------------------
    // CR watch cross-version conversion (CustomResourceFieldSelectors root-cause-2)
    //
    // Fixture mirrors the real conformance CRD (crd_selectable_fields.go): v1 declares a
    // root-level `hostPort` string field (selectable), v2 declares root-level `host`/`port`
    // (both selectable), and a webhook converts between them. Every CR below is created via
    // v2, exactly like the conformance test, which creates all CRs through its v2 client
    // regardless of which version a given watch later targets.
    // ---------------------------------------------------------------------------

    const HOSTPORT_CRD_GROUP: &str = "fieldconv.example.com";

    fn hostport_crd_bytes(base_url: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": format!("gizmos.{HOSTPORT_CRD_GROUP}") },
                "spec": {
                    "group": HOSTPORT_CRD_GROUP,
                    "names": {
                        "plural": "gizmos",
                        "singular": "gizmo",
                        "kind": "Gizmo",
                        "listKind": "GizmoList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        {
                            "name": "v1",
                            "served": true,
                            "storage": true,
                            "schema": {
                                "openAPIV3Schema": {
                                    "type": "object",
                                    "properties": { "hostPort": { "type": "string" } }
                                }
                            },
                            "selectableFields": [{ "jsonPath": ".hostPort" }]
                        },
                        {
                            "name": "v2",
                            "served": true,
                            "storage": false,
                            "schema": {
                                "openAPIV3Schema": {
                                    "type": "object",
                                    "properties": {
                                        "host": { "type": "string" },
                                        "port": { "type": "string" }
                                    }
                                }
                            },
                            "selectableFields": [{ "jsonPath": ".host" }, { "jsonPath": ".port" }]
                        }
                    ],
                    "conversion": {
                        "strategy": "Webhook",
                        "webhook": { "clientConfig": { "url": format!("{base_url}/convert") } }
                    }
                }
            })
            .to_string(),
        )
    }

    fn gizmo_v2_body(name: &str, ns: &str, host: &str, port: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": format!("{HOSTPORT_CRD_GROUP}/v2"),
                "kind": "Gizmo",
                "metadata": { "name": name, "namespace": ns },
                "host": host,
                "port": port
            })
            .to_string(),
        )
    }

    /// A conversion webhook that mirrors the real conformance suite's CRD converter closely
    /// enough to exercise the exact hostPort<->host+port scenario: v1's `hostPort` is
    /// `"{host}:{port}"`; converting to v2 splits it back apart.
    fn hostport_conversion_router(call_count: Arc<std::sync::atomic::AtomicUsize>) -> axum::Router {
        use axum::routing::post;
        use std::sync::atomic::Ordering;

        axum::Router::new().route(
            "/convert",
            post(move |axum::Json(review): axum::Json<serde_json::Value>| {
                let call_count = Arc::clone(&call_count);
                async move {
                    call_count.fetch_add(1, Ordering::SeqCst);
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let converted: Vec<serde_json::Value> = objects
                        .into_iter()
                        .map(|mut o| {
                            if desired.ends_with("/v1") {
                                if let (Some(host), Some(port)) = (
                                    o["host"].as_str().map(str::to_string),
                                    o["port"].as_str().map(str::to_string),
                                ) {
                                    o["hostPort"] =
                                        serde_json::Value::String(format!("{host}:{port}"));
                                }
                                if let Some(map) = o.as_object_mut() {
                                    map.remove("host");
                                    map.remove("port");
                                }
                            } else if desired.ends_with("/v2") {
                                if let Some((host, port)) = o["hostPort"]
                                    .as_str()
                                    .and_then(|hp| hp.split_once(':'))
                                    .map(|(h, p)| (h.to_string(), p.to_string()))
                                {
                                    o["host"] = serde_json::Value::String(host);
                                    o["port"] = serde_json::Value::String(port);
                                }
                                if let Some(map) = o.as_object_mut() {
                                    map.remove("hostPort");
                                }
                            }
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o
                        })
                        .collect();
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": { "status": "Success" },
                            "convertedObjects": converted
                        }
                    }))
                }
            }),
        )
    }

    /// Regression test for CustomResourceFieldSelectors root-cause-2 (Hook A: the
    /// sendInitialEvents backlog). A cross-version CR watch's initial backlog must be
    /// converted to the REQUESTED version before the field-selector filter runs, not served
    /// as raw stored bytes.
    ///
    /// Before this fix, `list_cr_namespaced`'s watch branch passed `fetch_initial_events`'s
    /// items straight into `watch_generic_for_cr` unconverted; `cr_matches_field_selector`
    /// (the #858 fix) then correctly evaluated `hostPort` — declared selectable on v1 — as
    /// absent on the raw v2 body (no `hostPort` key at all) and dropped every CR. A v1 watch
    /// with `fieldSelector=hostPort=host1:80` therefore delivered nothing: the exact
    /// `crd_selectable_fields.go:259` failure. This fails on revert because reverting Hook A
    /// removes the `convert_cr_list_items` call, so `hostPort` is never present on gizmo-a's
    /// delivered body and the selector never matches it.
    #[tokio::test]
    async fn list_cr_namespaced_watch_send_initial_events_converts_backlog_before_field_selector() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(hostport_conversion_router(Arc::clone(&call_count))).await;

        let state = make_state();
        let ns = "default";
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            hostport_crd_bytes(&base_url),
        )
        .await
        .expect("install v1{hostPort}/v2{host,port} CRD with conversion webhook");

        // Both CRs are created via v2 (their own stored apiVersion is v2) — only gizmo-a's
        // host:port matches the v1 selector below.
        for (name, host, port) in [("gizmo-a", "host1", "80"), ("gizmo-b", "host1", "8080")] {
            assert!(
                create_cr_namespaced(
                    State(state.clone()),
                    Path((
                        HOSTPORT_CRD_GROUP.to_string(),
                        "v2".to_string(),
                        ns.to_string(),
                        "gizmos".to_string(),
                    )),
                    test_user(),
                    axum::http::HeaderMap::new(),
                    gizmo_v2_body(name, ns, host, port),
                )
                .await
                .is_ok(),
                "create {name} via v2 must succeed"
            );
        }

        let watch_query = super::super::generic::CollectionQuery {
            watch: Some(true),
            send_initial_events: Some(true),
            field_selector: Some("hostPort=host1:80".to_string()),
            timeout_seconds: Some(2),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v1".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("v1 watch with sendInitialEvents must succeed, got {e:?}"));
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("watch stream must complete within 15 seconds")
        .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            call_count.load(Ordering::SeqCst) > 0,
            "gizmo-a/b are stored at v2 but the watch requested v1, so the conversion webhook \
             must have been called to convert the sendInitialEvents backlog (got: {body_str})"
        );
        assert!(
            body_str.contains("\"gizmo-a\"") && body_str.contains("\"hostPort\":\"host1:80\""),
            "a v1 watch's sendInitialEvents backlog must deliver gizmo-a CONVERTED to v1 shape \
             (with hostPort present) — if conversion is skipped, the field selector \
             hostPort=host1:80 is evaluated against the raw v2 body (no hostPort key) and \
             matches nothing, reproducing the CustomResourceFieldSelectors watch failure \
             (got: {body_str})"
        );
        assert!(
            !body_str.contains("\"gizmo-b\""),
            "gizmo-b converts to hostPort=host1:8080, which must NOT match the v1 selector \
             hostPort=host1:80 (got: {body_str})"
        );
    }

    /// Regression test for CustomResourceFieldSelectors root-cause-2 (Hook B: live events).
    /// A LIVE CR watch event — the broadcast path, not the sendInitialEvents backlog — must
    /// also be converted to the requested version before the field-selector filter runs.
    ///
    /// The watch is opened BEFORE the matching CR exists, reproducing what the conformance
    /// test's `v1hostPortWatch` does: it opens the v1 watch first, then the CRs are created
    /// afterward and must arrive as live ADDED events, not backlog. Before this fix,
    /// `watch_generic_impl`'s live-event handling restamped only apiVersion/kind on the raw
    /// stored v2 body and filtered THAT against the v1 selector — hostPort is never present
    /// on a v2 body, so nothing was ever delivered. This fails on revert because reverting
    /// Hook B removes the `convert_watched_cr_object` call, so the live ADDED event is
    /// filtered (and dropped) before conversion ever happens.
    #[tokio::test]
    async fn list_cr_namespaced_watch_converts_live_event_before_field_selector() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::time::{timeout, Duration};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(hostport_conversion_router(Arc::clone(&call_count))).await;

        let state = make_state();
        let ns = "default";
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            hostport_crd_bytes(&base_url),
        )
        .await
        .expect("install v1{hostPort}/v2{host,port} CRD with conversion webhook");

        // Open the v1 watch BEFORE the matching CR exists — a plain watch (no
        // sendInitialEvents), so the only way gizmo-a can be delivered is the LIVE path.
        let watch_query = super::super::generic::CollectionQuery {
            watch: Some(true),
            field_selector: Some("hostPort=host1:80".to_string()),
            timeout_seconds: Some(2),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v1".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("v1 watch must succeed, got {e:?}"));
        assert_eq!(resp.status(), StatusCode::OK);

        // Create the matching CR via v2 AFTER the watch is open, on a separate task so the
        // watch body reader below can run concurrently (mirrors
        // watch_generic_label_selector_newly_created_object_emits_added in watch.rs).
        let state_clone = state.clone();
        let ns_owned = ns.to_string();
        tokio::spawn(async move {
            create_cr_namespaced(
                State(state_clone),
                Path((
                    HOSTPORT_CRD_GROUP.to_string(),
                    "v2".to_string(),
                    ns_owned.clone(),
                    "gizmos".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                gizmo_v2_body("gizmo-a", &ns_owned, "host1", "80"),
            )
            .await
            .expect("create gizmo-a via v2 must succeed");
        });

        let body = timeout(
            Duration::from_secs(15),
            to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("watch stream must close within 15s")
        .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            call_count.load(Ordering::SeqCst) > 0,
            "gizmo-a is stored at v2 but the watch requested v1, so the live event must have \
             gone through the conversion webhook (got: {body_str})"
        );
        assert!(
            body_str.contains("\"gizmo-a\"") && body_str.contains("\"hostPort\":\"host1:80\""),
            "a live ADDED event on a cross-version CR watch must be delivered CONVERTED (with \
             hostPort present) — before this fix, watch_generic_impl only restamped \
             apiVersion/kind on the raw v2 body and filtered that against the v1 selector, so \
             a v2-stored CR never matched a v1 fieldSelector and was silently dropped, exactly \
             the CustomResourceFieldSelectors watch failure (got: {body_str})"
        );
    }

    /// Regression test: delete_collection_cr_namespaced's field-selector filter must apply
    /// the SAME conversion-before-filter step LIST already does
    /// (list_cr_namespaced_watch_send_initial_events_converts_backlog_before_field_selector).
    /// Without it, a DeleteCollection issued at a non-storage version with a field selector on
    /// that version's declared field silently matches nothing, because the raw stored body
    /// doesn't carry that field's name at all.
    ///
    /// Fails on revert: without the convert_cr_list_items call, gizmo-a's raw v2 body has no
    /// "hostPort" key, cr_matches_field_selector never matches it, and DeleteCollection
    /// deletes nothing instead of gizmo-a.
    #[tokio::test]
    async fn delete_collection_cr_namespaced_converts_before_field_selector() {
        use crate::handlers::crd;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(hostport_conversion_router(Arc::clone(&call_count))).await;

        let state = make_state();
        let ns = "default";
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            hostport_crd_bytes(&base_url),
        )
        .await
        .expect("install v1{hostPort}/v2{host,port} CRD with conversion webhook");

        for (name, host, port) in [("gizmo-a", "host1", "80"), ("gizmo-b", "host1", "8080")] {
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    HOSTPORT_CRD_GROUP.to_string(),
                    "v2".to_string(),
                    ns.to_string(),
                    "gizmos".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                gizmo_v2_body(name, ns, host, port),
            )
            .await
            .unwrap_or_else(|e| panic!("create {name} via v2 must succeed: {e:?}"));
        }

        let query = super::super::generic::CollectionQuery {
            field_selector: Some("hostPort=host1:80".to_string()),
            ..no_watch_query()
        };
        delete_collection_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v1".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
            )),
            test_user(),
            query,
        )
        .await
        .unwrap_or_else(|e| panic!("v1 DeleteCollection with fieldSelector must succeed: {e:?}"));

        assert!(
            call_count.load(Ordering::SeqCst) > 0,
            "gizmo-a/b are stored at v2 but DeleteCollection requested v1, so the conversion \
             webhook must have been called to evaluate hostPort against the converted view"
        );

        let a_gone = get_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v2".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
                "gizmo-a".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(
            a_gone.is_err(),
            "gizmo-a (host1:80) must be deleted by v1 DeleteCollection \
             fieldSelector=hostPort=host1:80"
        );

        let b_survives = get_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v2".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
                "gizmo-b".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await;
        assert!(
            b_survives.is_ok(),
            "gizmo-b (host1:8080) must survive — it does not match hostPort=host1:80"
        );
    }

    /// delete_collection_cr_namespaced must respect metadata.finalizers exactly like a single
    /// delete_cr_namespaced call: a CR with finalizers must be soft-deleted (deletionTimestamp
    /// stamped, kept alive), never hard-deleted outright. The analogous gap for BUILT-IN
    /// resources' DeleteCollection is tracked separately; this locks in that the new CR DeleteCollection
    /// path doesn't regress the guarantee single-object CR delete and the built-in
    /// DeleteCollection loop already provide.
    ///
    /// Fails on revert: reverting to an unconditional store.delete for every matched CR
    /// removes finalizer-app from the store instead of leaving it with deletionTimestamp set.
    #[tokio::test]
    async fn delete_collection_cr_namespaced_respects_finalizers() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io";
        let version = "v1alpha1";
        let ns = "argocd";
        let plural = "applications";

        let finalizer_key = cr_store_key(group, plural, Some(ns), "finalizer-app");
        let finalizer_body = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": "finalizer-app",
                "namespace": ns,
                "uid": "fin-uid-1",
                "resourceVersion": "1",
                "finalizers": ["example.io/protect"]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &finalizer_key,
                Bytes::from(serde_json::to_vec(&finalizer_body).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    group.to_string(),
                    version.to_string(),
                    ns.to_string(),
                    plural.to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("plain-app", ns),
            )
            .await
            .is_ok(),
            "create plain-app must succeed"
        );

        delete_collection_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            no_watch_query(),
        )
        .await
        .unwrap_or_else(|e| panic!("delete_collection_cr_namespaced must succeed: {e:?}"));

        let after_finalizer = state.store.get(&finalizer_key).await.unwrap().expect(
            "a CR with metadata.finalizers must NOT be removed by DeleteCollection — hard \
                 delete would bypass its finalizer and break cleanup controllers",
        );
        let after_obj: serde_json::Value = serde_json::from_slice(&after_finalizer.value).unwrap();
        assert!(
            after_obj["metadata"]["deletionTimestamp"]
                .as_str()
                .is_some(),
            "the finalizer'd CR must have deletionTimestamp set so its controller knows to \
             run cleanup and remove the finalizer"
        );

        let plain_key = cr_store_key(group, plural, Some(ns), "plain-app");
        assert!(
            state.store.get(&plain_key).await.unwrap().is_none(),
            "a CR without finalizers must be hard-deleted by DeleteCollection"
        );
    }

    /// A watch at the SAME version the CR is stored at must never call the conversion
    /// webhook — the free common case (controllers watch the storage version, not a
    /// different one). Guards `convert_watched_cr_object`'s short-circuit: a naive "always
    /// convert when a CRD has a webhook" implementation would call the webhook on every
    /// event even when no conversion is needed, and real conversion webhooks (including the
    /// conformance suite's) reject a version-to-itself conversion as a client bug — so
    /// failing to short-circuit would break EVERY CR watch on a CRD with a conversion
    /// webhook, not just cross-version ones. Fails on revert if the short-circuit check is
    /// removed (e.g. converting unconditionally whenever a webhook is configured).
    #[tokio::test]
    async fn list_cr_namespaced_watch_same_version_does_not_call_conversion_webhook() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(hostport_conversion_router(Arc::clone(&call_count))).await;

        let state = make_state();
        let ns = "default";
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            hostport_crd_bytes(&base_url),
        )
        .await
        .expect("install v1{hostPort}/v2{host,port} CRD with conversion webhook");

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    HOSTPORT_CRD_GROUP.to_string(),
                    "v2".to_string(),
                    ns.to_string(),
                    "gizmos".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                gizmo_v2_body("gizmo-a", ns, "host1", "80"),
            )
            .await
            .is_ok(),
            "create gizmo-a via v2 must succeed"
        );

        // Watch at v2 — the CR's own stored version — with sendInitialEvents so gizmo-a is
        // delivered from the backlog (Hook A), the same phase Hook A's conversion runs in.
        let watch_query = super::super::generic::CollectionQuery {
            watch: Some(true),
            send_initial_events: Some(true),
            field_selector: Some("host=host1".to_string()),
            timeout_seconds: Some(2),
            ..no_watch_query()
        };
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((
                HOSTPORT_CRD_GROUP.to_string(),
                "v2".to_string(),
                ns.to_string(),
                "gizmos".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query,
            "test-user".to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("v2 watch must succeed, got {e:?}"));
        assert_eq!(resp.status(), StatusCode::OK);

        let body = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            to_bytes(resp.into_body(), usize::MAX),
        )
        .await
        .expect("watch stream must complete within 15 seconds")
        .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            body_str.contains("\"gizmo-a\"") && body_str.contains("\"host\":\"host1\""),
            "a same-version watch must still deliver the matching CR (got: {body_str})"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "gizmo-a's own stored apiVersion already IS v2 — the requested version — so this \
             is a version-to-itself request; calling the conversion webhook for it is both \
             wasted work and something real conversion webhooks reject as a client bug \
             (got: {body_str})"
        );
    }

    // Delete then get must return 404.
    #[tokio::test]
    async fn delete_then_get_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "app-to-delete".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        let err = expect_err_status(
            get_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns, plural, name)),
                axum::http::HeaderMap::new(),
            )
            .await,
            "get after delete must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // PATCH applies the merge patch to the stored CR and returns 200 with the updated object.
    // This verifies that patch_cr_namespaced correctly mutates the stored value.
    #[tokio::test]
    async fn patch_cr_namespaced_applies_merge_patch() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "patch-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(serde_json::json!({ "spec": { "color": "red" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let result = patch_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            test_user(),
            headers,
            patch_body,
        )
        .await;
        assert!(result.is_ok(), "patch must succeed");

        // Verify the stored value has color: red under spec.
        let stored_resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after patch"),
        };
        assert_eq!(stored_resp.status(), StatusCode::OK);
    }

    /// A merge-patch PATCH on a cluster-scoped CR attempting to change metadata.uid must
    /// leave the stored uid unchanged. Before this fix, the only guard here was a
    /// `debug_assert_eq!` — a panic in debug builds, but a silent no-op in release, meaning
    /// a caller holding only ordinary CR `patch` rights could forge uid to match a
    /// stale/foreign ownerReference (corrupting GC's owner-liveness check) or defeat
    /// controllers' recreate-detection in every release build. This test runs in the
    /// harness's default (debug) test profile specifically so a revert of the restore back
    /// to the old debug_assert_eq! shows up as a hard panic, not just a silently-passing
    /// release-mode gap.
    #[tokio::test]
    async fn patch_cr_merge_patch_cannot_change_uid() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let name = "uid-forge-widget".to_string();
        assert!(
            create_cr(
                State(state.clone()),
                Path(("example.io".into(), "v1".into(), "widgets".into())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let before = get_cr(
            State(state.clone()),
            Path((
                "example.io".into(),
                "v1".into(),
                "widgets".into(),
                name.clone(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|_| panic!("get must succeed before patch"));
        let before_body = axum::body::to_bytes(before.into_body(), usize::MAX)
            .await
            .unwrap();
        let before_json: serde_json::Value = serde_json::from_slice(&before_body).unwrap();
        let real_uid = before_json["metadata"]["uid"]
            .as_str()
            .expect("create must assign a uid")
            .to_string();
        assert!(!real_uid.is_empty());

        let patch_body =
            Bytes::from(serde_json::json!({ "metadata": { "uid": "attacker-uid" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        assert!(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".into(),
                    "v1".into(),
                    "widgets".into(),
                    name.clone()
                )),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "a patch attempting to set uid must still succeed (uid is silently restored, \
             not rejected)"
        );

        let after = get_cr(
            State(state.clone()),
            Path(("example.io".into(), "v1".into(), "widgets".into(), name)),
            axum::http::HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|_| panic!("get must succeed after patch"));
        let after_body = axum::body::to_bytes(after.into_body(), usize::MAX)
            .await
            .unwrap();
        let after_json: serde_json::Value = serde_json::from_slice(&after_body).unwrap();
        assert_eq!(
            after_json["metadata"]["uid"], real_uid,
            "a merge-patch carrying metadata.uid must not change the stored uid"
        );
    }

    // PATCH on a group with no CRD installed must return 404.
    // This verifies that patch_cr_namespaced correctly propagates CRD-not-found as 404.
    #[tokio::test]
    async fn patch_cr_namespaced_returns_404_for_unknown_group() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({ "spec": {} }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    "unknown.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "things".to_string(),
                    "my-thing".to_string(),
                )),
                test_user(),
                headers,
                patch_body,
            )
            .await,
            "expected 404 for unknown group",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404, "unknown CRD must return 404");
        assert_eq!(json["reason"], "NotFound");
    }

    // PATCH with Content-Type: application/json must return 415 Unsupported Media Type.
    // This verifies that the content-type guard fires before any store access.
    #[tokio::test]
    async fn patch_cr_namespaced_rejects_wrong_content_type() {
        let state = make_state();

        let patch_body = Bytes::from(serde_json::json!({ "spec": {} }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "argocd".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                test_user(),
                headers,
                patch_body,
            )
            .await,
            "expected 415 for wrong content type",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 415, "wrong content type must return 415");
    }

    // stamp_cr_fields must assign uid and creationTimestamp when absent,
    // and must set apiVersion and kind unconditionally.
    #[test]
    fn stamp_cr_sets_uid_and_timestamp_when_absent() {
        let mut obj = serde_json::json!({ "metadata": {} });
        stamp_cr_fields(&mut obj, "example.io", "v1", "Widget");
        assert_eq!(obj["apiVersion"], "example.io/v1");
        assert_eq!(obj["kind"], "Widget");
        let uid = obj["metadata"]["uid"].as_str().unwrap_or("");
        assert!(!uid.is_empty(), "uid must be assigned when absent");
        let ts = obj["metadata"]["creationTimestamp"].as_str().unwrap_or("");
        assert!(
            !ts.is_empty(),
            "creationTimestamp must be assigned when absent"
        );
    }

    // stamp_cr_fields is only ever called on create (create_cr/create_cr_namespaced and
    // patch_cr's SSA-upsert-on-missing branch) — CR replace goes through
    // resolve_cr_metadata instead, which enforces uid immutability by rejecting a
    // mismatch. A client-supplied uid on create must therefore always be overwritten, the
    // same invariant stamp_metadata enforces for built-in resources: letting a create
    // request choose its own uid would let it forge identity to match a stale/foreign
    // ownerReference or defeat recreate-detection.
    #[test]
    fn stamp_cr_fields_overwrites_client_supplied_uid_on_create() {
        let mut obj = serde_json::json!({
            "metadata": {
                "uid": "attacker-chosen-uid",
                "creationTimestamp": "2024-01-01T00:00:00Z"
            }
        });
        stamp_cr_fields(&mut obj, "example.io", "v1", "Widget");
        assert_ne!(
            obj["metadata"]["uid"], "attacker-chosen-uid",
            "server must always overwrite a client-supplied uid on create — letting it \
             through would let any CR create request forge object identity"
        );
        assert_eq!(
            obj["metadata"]["creationTimestamp"], "2024-01-01T00:00:00Z",
            "existing creationTimestamp must still be preserved"
        );
    }

    // stamp_cr_fields's ObjectMeta round-trip must preserve ownerReferences — a
    // dependent created with an ownerReference (e.g. by a controller) must still be
    // findable by cascade_delete_cr_dependents after create/replace stamps the envelope.
    #[test]
    fn stamp_cr_fields_preserves_owner_references() {
        let mut obj = serde_json::json!({
            "metadata": {
                "name": "dep",
                "ownerReferences": [{
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "name": "owner",
                    "uid": "owner-uid",
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            }
        });
        stamp_cr_fields(&mut obj, "example.io", "v1", "Widget");
        let refs = obj["metadata"]["ownerReferences"].as_array();
        assert!(
            refs.is_some() && !refs.unwrap().is_empty(),
            "ownerReferences must survive stamp_cr_fields's ObjectMeta round-trip — if \
             dropped, cascade_delete_cr_dependents can never find this object by owner uid"
        );
    }

    // object_needs_conversion gates whether the conversion webhook — a real network call
    // with its own timeout — fires for a stored CR. It must compare the object's OWN
    // stored apiVersion against the requested one: an already-matching object must never
    // be sent through the webhook (real webhooks reject a version-to-itself request as a
    // client bug), and a drifted object must always be converted or clients requesting
    // the new version see stale-shaped data.
    #[test]
    fn object_needs_conversion_dispatches_on_the_objects_own_stored_api_version() {
        let cfg = serde_json::json!({ "url": "https://example.invalid/convert" });
        let obj = serde_json::json!({ "apiVersion": "example.io/v1", "kind": "Widget" });
        assert!(
            !object_needs_conversion(&obj, "example.io/v1", Some(&cfg)),
            "an object already stored at the requested apiVersion must not be sent \
             through the conversion webhook"
        );
        assert!(
            object_needs_conversion(&obj, "example.io/v2", Some(&cfg)),
            "an object stored under an older apiVersion than requested must be converted"
        );
    }

    // Without a configured conversion webhook there is nothing to dispatch to — most CRDs
    // never declare a `conversion` block — so a mismatched apiVersion alone must not
    // trigger a call that has nowhere to go.
    #[test]
    fn object_needs_conversion_returns_false_without_webhook_config() {
        let obj = serde_json::json!({ "apiVersion": "example.io/v1" });
        assert!(!object_needs_conversion(&obj, "example.io/v2", None));
    }

    // validate_cr_name must reject empty names — empty string is not a valid
    // Kubernetes resource name and must not be silently accepted.
    #[test]
    fn validate_cr_name_rejects_empty() {
        let result = validate_cr_name("");
        assert!(result.is_err(), "empty name must be rejected");
    }

    // validate_cr_name must accept a valid DNS label — the common case for CR names.
    #[test]
    fn validate_cr_name_accepts_valid_dns_label() {
        assert!(
            validate_cr_name("my-resource").is_ok(),
            "valid DNS label must be accepted"
        );
        assert!(
            validate_cr_name("foo123").is_ok(),
            "alphanumeric name must be accepted"
        );
    }

    // kube-apiserver rejects CR names whose first or last character is a hyphen or dot
    // because they violate DNS label rules and break label-selector round-trips.
    #[test]
    fn validate_cr_name_rejects_leading_hyphen() {
        let err = validate_cr_name("-foo").expect_err("leading hyphen in CR name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "leading hyphen must return 400");
    }

    #[test]
    fn validate_cr_name_rejects_trailing_hyphen() {
        let err =
            validate_cr_name("foo-").expect_err("trailing hyphen in CR name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "trailing hyphen must return 400");
    }

    #[test]
    fn validate_cr_name_rejects_leading_dot() {
        let err = validate_cr_name(".bar").expect_err("leading dot in CR name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "leading dot must return 400");
    }

    // kube-apiserver rejects CR names with uppercase letters because DNS labels
    // are case-insensitive by spec but Kubernetes requires lowercase to avoid
    // objects that differ only by case, which would collide on case-insensitive filesystems.
    #[test]
    fn validate_cr_name_rejects_uppercase() {
        let err = validate_cr_name("MyWidget")
            .expect_err("uppercase letters in CR name must be rejected");
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 400, "uppercase name must return 400");
    }

    #[test]
    fn validate_cr_name_accepts_lowercase_with_version() {
        assert!(
            validate_cr_name("widget-v2").is_ok(),
            "lowercase name with digit suffix must be accepted"
        );
    }

    // resolve_cr_metadata must copy uid from stored into incoming when incoming
    // has no uid set — replace handlers must preserve object identity.
    #[test]
    fn resolve_cr_metadata_copies_uid() {
        let stored = serde_json::json!({
            "metadata": {
                "uid": "stored-uid-xyz",
                "creationTimestamp": "2024-06-01T00:00:00Z"
            }
        });
        let mut incoming = serde_json::json!({ "metadata": {} });
        resolve_cr_metadata(&stored, &mut incoming, "widget-1", "Widget").unwrap();
        assert_eq!(
            incoming["metadata"]["uid"], "stored-uid-xyz",
            "uid must be copied from stored into incoming"
        );
        assert_eq!(
            incoming["metadata"]["creationTimestamp"], "2024-06-01T00:00:00Z",
            "creationTimestamp must be copied from stored into incoming"
        );
    }

    /// A PUT that carries a non-blank uid mismatching the stored one is identity forgery,
    /// not a legitimate update: without this rejection a caller with ordinary CR update
    /// rights could rewrite a CR's uid to match a stale/foreign ownerReference and corrupt
    /// GC's owner-liveness check, or defeat controllers' recreate-detection.
    #[test]
    fn resolve_cr_metadata_rejects_mismatched_uid() {
        let stored = serde_json::json!({
            "metadata": { "uid": "real-uid", "creationTimestamp": "2024-06-01T00:00:00Z" }
        });
        let mut incoming = serde_json::json!({ "metadata": { "uid": "attacker-uid" } });
        let result = resolve_cr_metadata(&stored, &mut incoming, "widget-1", "Widget");
        assert!(
            result.is_err(),
            "a mismatched non-blank uid must be rejected, not silently overwritten or accepted"
        );
        assert_eq!(result.unwrap_err().0, axum::http::StatusCode::CONFLICT);
    }

    fn watch_query() -> super::super::generic::CollectionQuery {
        super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: None,
        }
    }

    // When ?watch=true, list_cr must route to the watch stream rather than returning
    // a normal list. A CRD must exist for the request to succeed; without one, find_crd
    // returns 404 before reaching the watch branch.
    #[tokio::test]
    async fn list_cr_watch_returns_chunked_stream() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        // watch_generic always sets transfer-encoding: chunked — verifies the watch
        // branch was taken, not the normal list path.
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "cluster-scoped CR watch must use chunked transfer encoding"
        );
    }

    // When ?watch=true, list_cr_namespaced must route to the watch stream for a
    // namespaced CRD. This verifies the watch branch in the namespaced list handler.
    #[tokio::test]
    async fn list_cr_namespaced_watch_returns_chunked_stream() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let resp = match list_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch must not error"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "namespaced CR watch must use chunked transfer encoding"
        );
    }

    // validate_patch_content_type must accept application/strategic-merge-patch+json.
    // Conformance tests (label/annotation patches on Namespaces and DaemonSets) send
    // this content type; rejecting it with 415 breaks those tests. For CRDs the
    // strategic-merge array directives are not meaningful, but the JSON merge-patch
    // semantics (scalar overwrite, object recurse, null remove) are identical, so
    // we apply merge-patch logic regardless of which of the two types is sent.
    #[test]
    fn strategic_merge_patch_accepted_for_cr() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/strategic-merge-patch+json".parse().unwrap(),
        );
        assert!(
            crate::handlers::json_patch::detect_patch_type(&headers).is_ok(),
            "strategic-merge-patch must be accepted — conformance tests patch CRs with this type"
        );
    }

    // detect_patch_type must still reject genuinely unsupported types with 415.
    // Clients that accidentally send application/json get a clear 415, not a cryptic error.
    #[test]
    fn application_json_content_type_rejected_with_415() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let err = crate::handlers::json_patch::detect_patch_type(&headers).unwrap_err();
        assert_eq!(
            err.0,
            axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json must be rejected with 415 Unsupported Media Type"
        );
    }

    // new_cr_uid must produce valid RFC-4122 v4 UUIDs. Non-standard UIDs break
    // kubectl tools that parse UIDs (e.g. owner references, garbage collection).
    #[test]
    fn new_cr_uid_produces_valid_uuids() {
        for _ in 0..100 {
            let uid = new_cr_uid();
            let parsed = uuid::Uuid::parse_str(&uid)
                .unwrap_or_else(|_| panic!("new_cr_uid returned non-UUID: {uid}"));
            assert_eq!(
                parsed.get_version(),
                Some(uuid::Version::Random),
                "UID must be UUID v4 (Random), got: {uid}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // Status subresource tests
    // ---------------------------------------------------------------------------

    /// Builds a namespaced CRD body with `subresources: {status: {}}` on the version.
    fn namespaced_crd_with_status_subresource_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "applications.argoproj.io" },
                "spec": {
                    "group": "argoproj.io",
                    "names": {
                        "plural": "applications",
                        "singular": "application",
                        "kind": "Application",
                        "listKind": "ApplicationList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        {
                            "name": "v1alpha1",
                            "served": true,
                            "storage": true,
                            "subresources": { "status": {} }
                        }
                    ]
                }
            })
            .to_string(),
        )
    }

    /// Builds a cluster-scoped CRD body with `subresources: {status: {}}`.
    fn cluster_crd_with_status_subresource_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        {
                            "name": "v1",
                            "served": true,
                            "storage": true,
                            "subresources": { "status": {} }
                        }
                    ]
                }
            })
            .to_string(),
        )
    }

    async fn install_crd_with_status_subresource(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespaced_crd_with_status_subresource_bytes(),
            )
            .await
            .is_ok(),
            "install namespaced CRD with status subresource"
        );
    }

    async fn install_cluster_crd_with_status_subresource(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                cluster_crd_with_status_subresource_bytes(),
            )
            .await
            .is_ok(),
            "install cluster CRD with status subresource"
        );
    }

    // PUT to the main endpoint for a CR whose CRD declares a status subresource must
    // NOT update .status. Only .spec changes must be persisted.
    // This is the Kubernetes contract: controllers write spec via the main endpoint
    // and status via the /status subresource endpoint — mixing the two causes races.
    #[tokio::test]
    async fn namespaced_main_put_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        // Create without status so the stored object has no .status.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to the main endpoint with both spec and status changes.
        // The CRD has a status subresource, so only spec must be persisted.
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "production" } },
                "status": { "phase": "Injected" }
            })
            .to_string(),
        );

        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        // Get the stored object and verify .status was NOT updated.
        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["spec"]["destination"]["namespace"], "production",
            "spec must be updated by main PUT"
        );
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be persisted by main PUT when status subresource is declared"
        );
    }

    // Regression: a controller (e.g. csi-snapshotter's sidecar) that already published
    // .status via the /status subresource must not have that status wiped by a later
    // spec-only PUT to the main endpoint. Before this fix, replace_cr_namespaced
    // unconditionally *removed* .status from the object on every main PUT once the CRD
    // declared a status subresource — instead of preserving whatever was already
    // stored — so a controller that reads .status back off its own PUT response (as
    // upstream's CreateSnapshotResource does for VolumeSnapshotContent.status.snapshotHandle)
    // saw nil forever after the first /status write, panicking with a nil map assertion.
    #[tokio::test]
    async fn namespaced_main_put_preserves_status_set_via_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Publish .status via the /status subresource, the same way a real controller does.
        let status_put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "staging" } },
                "status": { "phase": "Synced" }
            })
            .to_string(),
        );
        assert!(
            crate::handlers::status::put_namespaced_resource_status(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                status_put_body,
            )
            .await
            .is_ok(),
            "PUT /status must succeed"
        );

        // A later spec-only PUT to the main endpoint must not wipe the status just set.
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "production" } }
            })
            .to_string(),
        );
        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["spec"]["destination"]["namespace"], "production",
            "spec must still be updated by the main PUT"
        );
        assert_eq!(
            obj["status"]["phase"], "Synced",
            "status set via the /status subresource must survive a later spec-only main \
             PUT — a controller that reads .status back off the PUT response (as \
             CreateSnapshotResource does for snapshotHandle) must never see it wiped"
        );
    }

    // Regression: A CRD WITHOUT a status subresource must persist .status normally
    // on the main PUT endpoint. This verifies the guard fires only when declared.
    #[tokio::test]
    async fn namespaced_main_put_persists_status_without_subresource() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "default" } },
                "status": { "phase": "Running" }
            })
            .to_string(),
        );

        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["phase"], "Running",
            "status must be persisted when no status subresource is declared"
        );
    }

    // PUT to the /status endpoint for a namespaced CR must update ONLY .status;
    // the .spec must remain unchanged. This is tested via put_namespaced_resource_status
    // (the generic handler with CR fallback).
    //
    // The generic handler is tested here using its CR fallback path, which stores to
    // /registry/cr/... This verifies the Argo CD use-case: Application controller writes
    // Application.status via the status subresource.
    #[tokio::test]
    async fn namespaced_status_put_updates_only_status() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        // Create with a spec field so we can verify it's unchanged after status PUT.
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "default" } }
            })
            .to_string(),
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to /status: only .status should change.
        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "SHOULD_NOT_CHANGE" } },
                "status": { "phase": "Healthy", "ready": true }
            })
            .to_string(),
        );

        assert!(
            super::super::status::put_namespaced_resource_status(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "status PUT must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["phase"], "Healthy",
            "status.phase must be updated by status PUT"
        );
        assert_eq!(
            obj["status"]["ready"], true,
            "status.ready must be updated by status PUT"
        );
        assert_eq!(
            obj["spec"]["destination"]["namespace"], "default",
            "spec must NOT be changed by status PUT"
        );
    }

    // PUT to /status for a cluster-scoped CR must update ONLY .status.
    // This tests put_cr_status which adds the CR fallback missing from put_resource_status.
    #[tokio::test]
    async fn cluster_scoped_status_put_updates_only_status() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        // Create with a spec field.
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );
        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT to /status: only .status should change.
        let status_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "SHOULD_NOT_CHANGE" },
                "status": { "ready": true, "replicas": 3 }
            })
            .to_string(),
        );

        assert!(
            put_cr_status(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone(),)),
                axum::http::HeaderMap::new(),
                status_body,
            )
            .await
            .is_ok(),
            "cluster-scoped status PUT must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["status"]["ready"], true,
            "status.ready must be updated by status PUT"
        );
        assert_eq!(
            obj["status"]["replicas"], 3,
            "status.replicas must be updated by status PUT"
        );
        assert_eq!(
            obj["spec"]["color"], "blue",
            "spec must NOT be changed by status PUT"
        );
    }

    // find_crd must detect has_status_subresource=true when the CRD spec declares
    // subresources.status on any version.
    #[tokio::test]
    async fn find_crd_detects_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let ctx = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed"),
        };

        assert!(
            ctx.has_status_subresource,
            "has_status_subresource must be true when subresources.status is declared"
        );
    }

    // find_crd must return has_status_subresource=false when the CRD does not declare
    // the status subresource.
    #[tokio::test]
    async fn find_crd_no_status_subresource_when_not_declared() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let ctx = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed"),
        };

        assert!(
            !ctx.has_status_subresource,
            "has_status_subresource must be false when subresources.status is absent"
        );
    }

    // Main PUT for a namespaced CR with status subresource must strip .status
    // even when patched via merge-patch (PATCH /apis/...).
    #[tokio::test]
    async fn namespaced_main_patch_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_crd_with_status_subresource(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "patch-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "spec": { "color": "green" },
                "status": { "phase": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let resp = match get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PATCH when status subresource declared"
        );
    }

    // ---------------------------------------------------------------------------
    // openAPIV3Schema validation tests (boon-based)
    // ---------------------------------------------------------------------------

    /// Helper: call validate_cr_schema with an inline schema value, as a CREATE (no
    /// previous object — `oldSelf` is unavailable, same as every real CREATE request).
    fn check_schema(
        obj: &serde_json::Value,
        schema: serde_json::Value,
    ) -> Result<(), crate::status::StatusError> {
        check_schema_with_old(obj, schema, None)
    }

    /// Helper: call validate_cr_schema with an inline schema value and an optional
    /// previous object, for tests that exercise `oldSelf` (UPDATE-only CEL rules).
    fn check_schema_with_old(
        obj: &serde_json::Value,
        schema: serde_json::Value,
        old_object: Option<&serde_json::Value>,
    ) -> Result<(), crate::status::StatusError> {
        let ctx = CrContext {
            kind: "Test".into(),
            namespaced: false,
            has_status_subresource: false,
            schema: Some(schema),
            conversion_webhook_client_config: None,
            selectable_fields: vec![],
            schema_cache_key: ("test".into(), "v1".into(), "0".into()),
            scale: None,
        };
        // Fresh cache per call: these tests exercise schema-correctness, not caching, and
        // every call here uses the same fixed schema_cache_key — sharing one cache across
        // calls with different schemas would return the wrong compiled schema.
        let cache = crate::state::CrSchemaCache::new();
        validate_cr_schema(obj, &ctx, &cache, old_object)
    }

    // type:object with valid object passes.
    // This is the happy path — a properly typed CR body must not be rejected.
    #[test]
    fn schema_valid_object_passes() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "spec": {} });
        assert!(
            check_schema(&value, schema).is_ok(),
            "valid object must pass schema validation"
        );
    }

    // type:object with spec as string fails.
    // Ensures the type constraint is actually enforced — wrong types must be caught.
    #[test]
    fn schema_wrong_type_for_property_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "spec": "not-an-object" });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("spec"),
            "error must name the offending field (got: {msg})"
        );
    }

    // required field missing causes an error.
    // Controllers rely on required fields being present — silent acceptance would
    // allow incomplete CRs that break the controller's assumptions.
    #[test]
    fn schema_required_field_missing_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["spec"],
            "properties": {
                "spec": { "type": "object" }
            }
        });
        let value = serde_json::json!({ "metadata": { "name": "foo" } });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("spec"),
            "error must mention the missing required field (got: {msg})"
        );
    }

    // additionalProperties:false rejects unknown keys.
    // Strict schemas should prevent typos in field names from being silently stored.
    #[test]
    fn schema_additional_properties_false_rejects_unknown_key() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": { "type": "object" }
            },
            "additionalProperties": false
        });
        let value = serde_json::json!({ "spec": {}, "unknownField": "oops" });
        assert!(
            check_schema(&value, schema).is_err(),
            "additional property must be rejected"
        );
    }

    /// Defense in depth: a CRD schema with an oversized `pattern` that somehow bypassed
    /// crd.rs::validate_crd_schema (installed before that check existed, restored from
    /// backup, or written directly to the store) must still be rejected here, before
    /// boon::Compiler::compile ever sees it — otherwise every CR write against that CRD
    /// retriggers boon's O(n^2) ECMA-compat rewrite, pinning a CPU core per request.
    #[test]
    fn validate_cr_schema_defense_in_depth_rejects_oversized_pattern_that_bypassed_crd_admission() {
        let oversized = "a".repeat(crate::handlers::crd::MAX_CRD_PATTERN_BYTES + 1);
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "field": { "type": "string", "pattern": oversized } }
        });
        let err = match check_schema(&serde_json::json!({ "field": "x" }), schema) {
            Ok(()) => panic!(
                "an oversized pattern must be rejected before boon::Compiler::compile runs, \
                 even when it reached validate_cr_schema without going through CRD admission"
            ),
            Err(e) => e,
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422);
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("exceeds maximum length"),
            "error must identify the oversized-pattern ReDoS defense, not a generic failure: {json}"
        );
    }

    // A single high-privilege CRD install must not turn into a repeatable amplification
    // vector: without a cache, every CR create/update/patch against that CRD pays boon's
    // parse-and-regex-compile cost again (measured ~657ms for the max-allowed 1024-byte
    // pattern) even though the schema never changed. This asserts the second write against
    // the same CRD generation reuses the compiled schema instead of recompiling — a compile
    // counter, not timing, because a real compile is slow enough to make timing-based
    // assertions flaky under CI load.
    #[test]
    fn cr_schema_cache_avoids_boon_recompile_on_repeated_writes_against_same_crd_version() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": { "type": "object" } }
        });
        let ctx = CrContext {
            kind: "Test".into(),
            namespaced: false,
            has_status_subresource: false,
            schema: Some(schema),
            conversion_webhook_client_config: None,
            selectable_fields: vec![],
            schema_cache_key: ("group.example.com".into(), "v1".into(), "1".into()),
            scale: None,
        };
        // Local to this test (not a shared/global counter) so parallel test execution in
        // the same process cannot pollute the count.
        let cache = crate::state::CrSchemaCache::new();
        let value = serde_json::json!({ "spec": {} });

        assert!(
            validate_cr_schema(&value, &ctx, &cache, None).is_ok(),
            "first write must validate"
        );
        assert!(
            validate_cr_schema(&value, &ctx, &cache, None).is_ok(),
            "second write must validate"
        );

        assert_eq!(
            cache.compile_count(),
            1,
            "a second CR write against the same CRD generation (same group/version/resourceVersion) \
             must reuse the cached compiled schema, not pay boon::Compiler::compile's cost again"
        );
    }

    // The same amplification risk applies to x-kubernetes-validations CEL rules: without
    // caching the pre-parsed cel::Program, a CRD with even a handful of CEL rules would
    // re-run cel::Program::compile (and the schema walk that finds every rule) on every
    // single CR create/update/patch, forever, even though the CRD's schema never changed.
    // A dedicated CEL compile counter (not the boon one above, and not timing — a real CEL
    // parse is fast enough that a timing assertion would be flaky) so a regression that
    // moves CEL compilation back onto the per-request path is caught even if it doesn't
    // touch boon compilation at all.
    #[test]
    fn cr_schema_cache_avoids_cel_reparse_on_repeated_writes_against_same_crd_version() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": { "type": "object" } },
            "x-kubernetes-validations": [
                { "rule": "self.spec == self.spec" }
            ]
        });
        let ctx = CrContext {
            kind: "Test".into(),
            namespaced: false,
            has_status_subresource: false,
            schema: Some(schema),
            conversion_webhook_client_config: None,
            selectable_fields: vec![],
            schema_cache_key: ("group.example.com".into(), "v1".into(), "1".into()),
            scale: None,
        };
        let cache = crate::state::CrSchemaCache::new();
        let value = serde_json::json!({ "spec": {} });

        assert!(
            validate_cr_schema(&value, &ctx, &cache, None).is_ok(),
            "first write must validate"
        );
        assert!(
            validate_cr_schema(&value, &ctx, &cache, None).is_ok(),
            "second write must validate"
        );

        assert_eq!(
            cache.cel_compile_count(),
            1,
            "a second CR write against the same CRD generation must reuse the CEL program \
             pre-parsed during the first write's schema walk, not call cel::Program::compile \
             again for every rule on every write"
        );
    }

    // `resolve_cel_program` is the single choke point every rule/messageExpression
    // evaluation goes through to obtain a `cel::Program` (see `evaluate_cel_rule`,
    // `evaluate_message_expression`). This unit-tests that choke point directly: given a
    // pre-parsed entry, it must hand back that SAME `Arc` rather than silently parsing a
    // lookalike — `Arc::ptr_eq`, not just value equality (`cel::Program` has no
    // `PartialEq`), is the only way to observe "no fresh compile happened" here.
    #[test]
    fn resolve_cel_program_reuses_cached_arc_instead_of_reparsing() {
        let text = "self == self";
        let cached = std::sync::Arc::new(cel::Program::compile(text).unwrap());
        let mut programs = std::collections::HashMap::new();
        programs.insert(text.to_string(), std::sync::Arc::clone(&cached));

        let resolved = resolve_cel_program(&programs, text)
            .expect("a cache-hit lookup for already-compiled text must not fail");

        assert!(
            std::sync::Arc::ptr_eq(&cached, &resolved),
            "a cache hit must return the exact Arc<cel::Program> collected during the schema \
             walk, not a freshly re-parsed one — otherwise every CR write would still pay \
             cel::Program::compile's cost despite CompiledCrSchema::cel_programs existing"
        );
    }

    // If the cache ever failed to distinguish CRD generations (e.g. keyed on group+version
    // only, ignoring resourceVersion), a CR write following a legitimate CRD schema update
    // would silently validate against the OLD schema forever — a correctness bug, not just a
    // missed optimization. Two different resourceVersions (as a real CRD update produces) must
    // each force their own compile.
    #[test]
    fn cr_schema_cache_rebuilds_on_crd_schema_update() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": { "type": "object" } }
        });
        let make_ctx = |rv: &str| CrContext {
            kind: "Test".into(),
            namespaced: false,
            has_status_subresource: false,
            schema: Some(schema.clone()),
            conversion_webhook_client_config: None,
            selectable_fields: vec![],
            schema_cache_key: ("group.example.com".into(), "v1".into(), rv.into()),
            scale: None,
        };
        let cache = crate::state::CrSchemaCache::new();
        let value = serde_json::json!({ "spec": {} });

        assert!(validate_cr_schema(&value, &make_ctx("1"), &cache, None).is_ok());
        assert!(validate_cr_schema(&value, &make_ctx("2"), &cache, None).is_ok());

        assert_eq!(
            cache.compile_count(),
            2,
            "a CRD update (new resourceVersion) must force a fresh compile — reusing the old \
             compiled schema after the CRD's schema changed would silently validate CRs against \
             stale rules"
        );
    }

    // Without eviction, a CRD's compiled schema stays in the cache map forever even after the
    // CRD is deleted and can never be looked up again (a fresh resourceVersion after a later
    // recreate would never collide with the deleted one) — an unbounded memory leak for any
    // workload that repeatedly creates and deletes CRDs (e.g. CI test churn, operators that
    // recreate CRDs on upgrade). This asserts delete_crd's eviction actually removes the entry.
    #[tokio::test]
    async fn cr_schema_cache_evicts_on_crd_delete() {
        let state = make_state();
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": { "spec": { "type": "object" } }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with schema"
        );

        let ctx = find_crd(&state, "example.io", "v1", "widgets")
            .await
            .expect("CRD must be found right after installing it");
        let key = ctx.schema_cache_key.clone();

        // Populate the cache via the real validation path (same code every CR write uses).
        validate_cr_schema(
            &serde_json::json!({ "spec": {} }),
            &ctx,
            &state.cr_schema_cache,
            None,
        )
        .expect("CR body must validate against the installed schema");
        assert!(
            state.cr_schema_cache.contains(&key),
            "sanity check: the cache must be populated before delete for this test to mean anything"
        );

        assert!(
            crd::delete_crd(
                State(state.clone()),
                Path("widgets.example.io".to_string()),
                test_user()
            )
            .await
            .is_ok(),
            "delete CRD"
        );

        assert!(
            !state.cr_schema_cache.contains(&key),
            "deleting a CRD must evict its compiled schema from the cache — otherwise the map \
             grows by one entry per CRD generation forever, even for CRDs that can never be \
             looked up again"
        );
    }

    // Unknown extension keywords must not cause a compile error (permissive).
    // openAPIV3Schema CRDs use x-kubernetes-* extensions; boon must not reject them.
    #[test]
    fn schema_unknown_extension_keywords_do_not_fail_compile() {
        let schema = serde_json::json!({
            "type": "object",
            "x-kubernetes-preserve-unknown-fields": true,
            "description": "some doc"
        });
        let value = serde_json::json!({ "anything": "here" });
        assert!(
            check_schema(&value, schema).is_ok(),
            "schema with extension keywords must not cause compile or validation error"
        );
    }

    // scalar types are correctly checked.
    // These are the leaf types that CRD schemas declare for individual fields.
    #[test]
    fn schema_scalar_type_checks() {
        let string_schema = serde_json::json!({ "type": "string" });
        assert!(check_schema(&serde_json::json!("hello"), string_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!(42), string_schema).is_err());

        let int_schema = serde_json::json!({ "type": "integer" });
        assert!(check_schema(&serde_json::json!(7), int_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!("7"), int_schema).is_err());

        let bool_schema = serde_json::json!({ "type": "boolean" });
        assert!(check_schema(&serde_json::json!(true), bool_schema.clone()).is_ok());
        assert!(check_schema(&serde_json::json!(1), bool_schema).is_err());
    }

    // enum violation: value not in the allowed set must be rejected.
    // The old hand-rolled validator silently accepted enum violations — this test
    // ensures boon enforces enum correctly.
    #[test]
    fn schema_enum_violation_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["Issuer", "ClusterIssuer"] }
            }
        });
        let value = serde_json::json!({ "kind": "BadValue" });
        assert!(
            check_schema(&value, schema).is_err(),
            "enum violation must be rejected by boon"
        );
    }

    // enum violation must render in the k8s field.Error "Unsupported value" phrasing, not
    // boon's own wording. kubectl and the upstream CRD-with-validation-schema conformance
    // test match the rejection error string against `Unsupported value: "<bad>"` — a
    // differently-worded (even if equally-rejecting) message makes those checks treat the
    // CR as accepted.
    #[test]
    fn schema_enum_violation_uses_upstream_unsupported_value_phrasing() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "feeling": { "type": "string", "enum": ["Great", "Down"] }
            }
        });
        let value = serde_json::json!({ "feeling": "NonExistentValue" });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains(r#"Unsupported value: "NonExistentValue""#),
            "message must use upstream's field.Error phrasing so kubectl/conformance error-string matches succeed (got: {msg})"
        );
        assert!(
            msg.contains(r#""Great""#) && msg.contains(r#""Down""#),
            "message must list the supported values so clients can see what was expected (got: {msg})"
        );
    }

    // required-field violation nested inside an array item must render in the k8s
    // `field.Error` "Required value" phrasing (`spec.bars[0].name: Required value`), not
    // boon's own wording (`missing properties 'name'`). The upstream CRD-with-validation-
    // schema conformance test matches the rejection error string against exactly this
    // phrasing (or the legacy `missing required field "name"` wording) — a differently-
    // worded (even if equally-rejecting) message makes that check treat the CR as accepted.
    #[test]
    fn schema_required_violation_in_array_item_uses_upstream_required_value_phrasing() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "bars": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            }
        });
        let value = serde_json::json!({ "spec": { "bars": [{ "age": "10" }] } });
        let err = check_schema(&value, schema).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("spec.bars[0].name: Required value"),
            "message must use upstream's field.Error phrasing so kubectl/conformance error-string matches succeed (got: {msg})"
        );
    }

    // pattern violation: string not matching regex must be rejected.
    // The old hand-rolled validator silently accepted pattern violations — this test
    // ensures boon enforces pattern correctly.
    #[test]
    fn schema_pattern_violation_fails() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "duration": { "type": "string", "pattern": "^[0-9]+(h|m|s)$" }
            }
        });
        let value = serde_json::json!({ "duration": "90days" });
        assert!(
            check_schema(&value, schema).is_err(),
            "pattern violation must be rejected by boon"
        );
    }

    // ---------------------------------------------------------------------------
    // x-kubernetes-validations (CEL) tests
    //
    // Before this bead, boon-only structural validation meant x-kubernetes-validations
    // rules were stored and round-tripped but never evaluated: a CR that violated every
    // CEL rule its CRD declared was still accepted. Fixtures below are drawn from the
    // real-world CEL surface an audit sampled (Gateway API, cert-manager,
    // prometheus-operator) to check the crate actually covers what production CRDs use.
    // ---------------------------------------------------------------------------

    // Real fixture: cert-manager's ClusterIssuer requires exactly one of tpp/cloud/ngts
    // to be set, via has()+ternary+arithmetic. A CR that honors this must not be
    // rejected — otherwise wiring CEL enforcement would break every valid ClusterIssuer.
    fn cluster_issuer_style_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "(has(self.tpp) ? 1 : 0) + (has(self.cloud) ? 1 : 0) + (has(self.ngts) ? 1 : 0) == 1",
                        "message": "exactly one of tpp, cloud, or ngts must be set"
                    }],
                    "properties": {
                        "tpp": { "type": "object" },
                        "cloud": { "type": "object" },
                        "ngts": { "type": "object" }
                    }
                }
            }
        })
    }

    #[test]
    fn cel_has_macro_accepts_cr_with_exactly_one_alternative_set() {
        let value = serde_json::json!({ "spec": { "cloud": {} } });
        assert!(
            check_schema(&value, cluster_issuer_style_schema()).is_ok(),
            "a CR that sets exactly one issuer backend must pass the has()-based rule — a \
             false positive here would reject every valid ClusterIssuer once CEL is enforced"
        );
    }

    // Setting zero alternatives must be rejected, and the client must see the CRD
    // author's own message (not a generic CEL error) — kubectl surfaces this message
    // verbatim to the operator who wrote the bad manifest.
    #[test]
    fn cel_has_macro_rejects_cr_with_no_alternative_set_and_reports_crd_message() {
        let value = serde_json::json!({ "spec": {} });
        let err = check_schema(&value, cluster_issuer_style_schema()).unwrap_err();
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "a CEL rule violation must be a 422 Unprocessable Entity, matching the boon \
             structural-validation failures this file already reports"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("exactly one of tpp, cloud, or ngts must be set"),
            "the CRD author's declared `message` must reach the client verbatim, not a \
             generic CEL evaluation error (got: {json})"
        );
    }

    // Setting more than one alternative must also be rejected — the arithmetic sum
    // exceeds 1, not just falls short of it.
    #[test]
    fn cel_has_macro_rejects_cr_with_two_alternatives_set() {
        let value = serde_json::json!({ "spec": { "cloud": {}, "ngts": {} } });
        assert!(
            check_schema(&value, cluster_issuer_style_schema()).is_err(),
            "setting two issuer backends at once must be rejected, same as upstream \
             kube-apiserver would reject it"
        );
    }

    // self == oldSelf is the standard CEL immutability idiom (used extensively by e.g.
    // Crossplane's CompositeResourceDefinition). On UPDATE, a changed value must be
    // rejected — without oldSelf wired up, u7s would silently accept any change to a
    // field the CRD author declared immutable.
    fn immutable_field_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "immutableField": {
                            "type": "string",
                            "x-kubernetes-validations": [{
                                "rule": "self == oldSelf",
                                "message": "immutableField is immutable"
                            }]
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn cel_old_self_immutability_rule_rejects_update_that_changes_the_field() {
        let old = serde_json::json!({ "spec": { "immutableField": "a" } });
        let new = serde_json::json!({ "spec": { "immutableField": "b" } });
        let err = check_schema_with_old(&new, immutable_field_schema(), Some(&old)).unwrap_err();
        let msg = &err.1.message;
        assert!(
            msg.contains("immutableField is immutable"),
            "changing an immutable field on UPDATE must be rejected with the CRD's own \
             message (got: {msg})"
        );
    }

    // On CREATE there is no old object to compare against — upstream skips (does not
    // fail) a rule that references oldSelf in this case, since "immutable" only has
    // meaning relative to a previous value. If u7s instead errored (or worse, always
    // passed a null oldSelf), CREATE would behave differently from real kube-apiserver.
    #[test]
    fn cel_old_self_referencing_rule_is_skipped_on_create_since_there_is_no_old_object() {
        let new = serde_json::json!({ "spec": { "immutableField": "b" } });
        assert!(
            check_schema(&new, immutable_field_schema()).is_ok(),
            "a rule that references oldSelf must be skipped (not evaluated, not failed) \
             on CREATE, matching upstream's UPDATE-only oldSelf semantics"
        );
    }

    // .all(): every element of a list must satisfy the predicate. Real CRDs use this for
    // per-element cross-field checks (e.g. Gateway API's listener validation); this
    // isolates the macro itself with a minimal predicate.
    #[test]
    fn cel_all_macro_rejects_cr_with_one_bad_element_so_operator_gets_specific_message() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "counts": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "x-kubernetes-validations": [{
                        "rule": "self.all(x, x > 0)",
                        "message": "all counts must be positive"
                    }]
                }
            }
        });
        let value = serde_json::json!({ "counts": [1, 2, -1] });
        let err = check_schema(&value, schema).unwrap_err();
        assert!(
            err.1.message.contains("all counts must be positive"),
            "a single negative element must fail the all() rule with the CRD's message \
             (got: {})",
            err.1.message
        );
    }

    // .exists_one(): exactly one element must satisfy the predicate — used by e.g.
    // HTTPRoute/Gateway for cross-element uniqueness checks (L328-330, L133-139 in the
    // audit). Two matching elements must fail just as surely as zero.
    #[test]
    fn cel_exists_one_macro_rejects_list_with_two_matching_elements() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "x-kubernetes-validations": [{
                        "rule": "self.exists_one(x, x == 1)",
                        "message": "exactly one id must equal 1"
                    }]
                }
            }
        });
        assert!(
            check_schema(&serde_json::json!({ "ids": [1, 2, 3] }), schema.clone()).is_ok(),
            "exactly one matching element must pass exists_one()"
        );
        assert!(
            check_schema(&serde_json::json!({ "ids": [1, 1, 3] }), schema).is_err(),
            "two matching elements must fail exists_one() — it means \"exactly one\", not \
             \"at least one\""
        );
    }

    // .filter(): real fixture from prometheus-operator's ScrapeConfig (audit L12826-12827)
    // — at most one of several optional auth methods may be configured. This exercises
    // filter() together with has() and size(), the exact combination the real rule uses.
    #[test]
    fn cel_filter_macro_rejects_cr_with_more_than_one_optional_auth_method_set() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "[has(self.basicAuth), has(self.authorization), has(self.oauth2)]\
                                 .filter(x, x).size() <= 1",
                        "message": "at most one auth method may be configured"
                    }],
                    "properties": {
                        "basicAuth": { "type": "object" },
                        "authorization": { "type": "object" },
                        "oauth2": { "type": "object" }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "basicAuth": {} } }),
                schema.clone()
            )
            .is_ok(),
            "a single configured auth method must pass the filter()-based rule"
        );
        let err = check_schema(
            &serde_json::json!({ "spec": { "basicAuth": {}, "oauth2": {} } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("at most one auth method may be configured"),
            "configuring two auth methods at once must be rejected with the CRD's message \
             (got: {})",
            err.1.message
        );
    }

    // size(): CRD authors use this to forbid blank strings that a JSON-Schema `pattern`
    // alone can't express cleanly (HTTPRoute audit L995 uses size() the same way).
    #[test]
    fn cel_size_function_rejects_empty_string_field() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "x-kubernetes-validations": [{
                        "rule": "size(self) > 0",
                        "message": "name must not be empty"
                    }]
                }
            }
        });
        assert!(check_schema(&serde_json::json!({ "name": "widget" }), schema.clone()).is_ok());
        let err = check_schema(&serde_json::json!({ "name": "" }), schema).unwrap_err();
        assert!(
            err.1.message.contains("name must not be empty"),
            "an empty string must fail the size() rule (got: {})",
            err.1.message
        );
    }

    // .matches(): regex checks CRD authors express in CEL rather than JSON-Schema
    // `pattern` when the constraint depends on other fields (HTTPRoute audit L3003-3006).
    #[test]
    fn cel_matches_function_rejects_string_not_matching_regex() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "slug": {
                    "type": "string",
                    "x-kubernetes-validations": [{
                        "rule": "self.matches('^[a-z]+$')",
                        "message": "slug must be lowercase letters only"
                    }]
                }
            }
        });
        assert!(check_schema(&serde_json::json!({ "slug": "widget" }), schema.clone()).is_ok());
        let err = check_schema(&serde_json::json!({ "slug": "Widget1" }), schema).unwrap_err();
        assert!(
            err.1
                .message
                .contains("slug must be lowercase letters only"),
            "an uppercase/digit slug must fail the matches() rule (got: {})",
            err.1.message
        );
    }

    // duration(): HTTPRoute (audit L3145-3146) compares two duration-typed fields to
    // enforce that a per-attempt timeout doesn't exceed the overall request timeout.
    #[test]
    fn cel_duration_function_rejects_backend_request_timeout_exceeding_overall_timeout() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "duration(self.backendRequest) <= duration(self.request)",
                        "message": "backendRequest timeout must not exceed request timeout"
                    }],
                    "properties": {
                        "request": { "type": "string" },
                        "backendRequest": { "type": "string" }
                    }
                }
            }
        });
        let ok = serde_json::json!({ "spec": { "request": "30s", "backendRequest": "10s" } });
        assert!(check_schema(&ok, schema.clone()).is_ok());
        let bad = serde_json::json!({ "spec": { "request": "10s", "backendRequest": "30s" } });
        let err = check_schema(&bad, schema).unwrap_err();
        assert!(
            err.1
                .message
                .contains("backendRequest timeout must not exceed request timeout"),
            "a backendRequest timeout longer than the overall request timeout must be \
             rejected (got: {})",
            err.1.message
        );
    }

    // `in`: CRDs enumerate allowed values via `self in [...]` when a plain JSON-Schema
    // `enum` isn't expressive enough (e.g. combined with other conditions) — HTTPRoute
    // audit L3003-3006 uses this pattern.
    #[test]
    fn cel_in_operator_rejects_value_outside_allowed_list() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "x-kubernetes-validations": [{
                        "rule": "self in ['HTTP', 'HTTPS']",
                        "message": "protocol must be HTTP or HTTPS"
                    }]
                }
            }
        });
        assert!(check_schema(&serde_json::json!({ "protocol": "HTTP" }), schema.clone()).is_ok());
        let err = check_schema(&serde_json::json!({ "protocol": "FTP" }), schema).unwrap_err();
        assert!(
            err.1.message.contains("protocol must be HTTP or HTTPS"),
            "a protocol outside the allowed list must be rejected (got: {})",
            err.1.message
        );
    }

    // ---------------------------------------------------------------------------
    // x-kubernetes-validations reserved-word / special-char field escaping
    // (https://kubernetes.io/docs/reference/using-api/cel/#escaping)
    //
    // `namespace` is a CEL lexer reserved word, so a rule can only reach a field
    // literally named `namespace` by spelling it `self.__namespace__`. Upstream
    // external-snapshotter's VolumeSnapshotContent CRD ships exactly this
    // (`has(self.name) && has(self.__namespace__)` on `spec.volumeSnapshotRef`) —
    // without escaping-aware binding, `__namespace__` never resolves to the object's
    // real `namespace` field, so the rule is always false and every VolumeSnapshotContent
    // create is spuriously rejected regardless of whether namespace is actually set.
    // ---------------------------------------------------------------------------

    #[test]
    fn cel_rule_referencing_reserved_word_field_sees_the_real_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "volumeSnapshotRef": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "namespace": { "type": "string" }
                    },
                    "x-kubernetes-validations": [{
                        "rule": "has(self.name) && has(self.__namespace__)",
                        "message": "both name and namespace must be set"
                    }]
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({
                    "volumeSnapshotRef": { "name": "snap-1", "namespace": "default" }
                }),
                schema.clone(),
            )
            .is_ok(),
            "a reserved-word field (namespace) that IS set must not be spuriously \
             rejected — this is the VolumeSnapshotContent bug: without escaping-aware \
             binding this write was rejected even with namespace set"
        );
        let err = check_schema(
            &serde_json::json!({ "volumeSnapshotRef": { "name": "snap-1" } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("both name and namespace must be set"),
            "an unset reserved-word field must still fail the rule — escaping must not \
             make the rule vacuously true (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_rule_referencing_dash_field_sees_the_real_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "foo-bar": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.foo__dash__bar)",
                "message": "foo-bar must be set"
            }]
        });
        assert!(
            check_schema(&serde_json::json!({ "foo-bar": "x" }), schema.clone()).is_ok(),
            "a dash-containing field name that IS set must not be spuriously rejected \
             (self.foo__dash__bar must resolve to the real 'foo-bar' field)"
        );
        let err = check_schema(&serde_json::json!({}), schema).unwrap_err();
        assert!(
            err.1.message.contains("foo-bar must be set"),
            "an unset dash-containing field must still fail the rule (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_rule_referencing_dot_field_sees_the_real_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "foo.bar": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.foo__dot__bar)",
                "message": "foo.bar must be set"
            }]
        });
        assert!(
            check_schema(&serde_json::json!({ "foo.bar": "x" }), schema.clone()).is_ok(),
            "a dot-containing field name that IS set must not be spuriously rejected \
             (self.foo__dot__bar must resolve to the real 'foo.bar' field)"
        );
        let err = check_schema(&serde_json::json!({}), schema).unwrap_err();
        assert!(
            err.1.message.contains("foo.bar must be set"),
            "an unset dot-containing field must still fail the rule (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_rule_referencing_slash_field_sees_the_real_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "foo/bar": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.foo__slash__bar)",
                "message": "foo/bar must be set"
            }]
        });
        assert!(
            check_schema(&serde_json::json!({ "foo/bar": "x" }), schema.clone()).is_ok(),
            "a slash-containing field name that IS set must not be spuriously rejected \
             (self.foo__slash__bar must resolve to the real 'foo/bar' field)"
        );
        let err = check_schema(&serde_json::json!({}), schema).unwrap_err();
        assert!(
            err.1.message.contains("foo/bar must be set"),
            "an unset slash-containing field must still fail the rule (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_rule_referencing_double_underscore_field_sees_the_real_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "foo__bar": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.foo__underscores__bar)",
                "message": "foo__bar must be set"
            }]
        });
        assert!(
            check_schema(&serde_json::json!({ "foo__bar": "x" }), schema.clone()).is_ok(),
            "a field literally named with a double underscore that IS set must not be \
             spuriously rejected (self.foo__underscores__bar must resolve to the real \
             'foo__bar' field) — without this substitution 'foo__bar' would pass through \
             unescaped, so a rule copied from upstream (which always escapes '__') would \
             reference a field that doesn't exist and never match"
        );
        let err = check_schema(&serde_json::json!({}), schema).unwrap_err();
        assert!(
            err.1.message.contains("foo__bar must be set"),
            "an unset double-underscore field must still fail the rule (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_escape_priority_double_underscore_before_dot_dash_slash() {
        // "a__.b" mixes a literal '__' immediately followed by '.'. The '__' must be
        // consumed as one __underscores__ substitution *before* the scan reaches the
        // '.', giving "a__underscores____dot__b". If '__' detection instead ran after
        // (or lost priority to) plain single-underscore pass-through, both underscores
        // would be emitted as themselves and the escaped name would come out as
        // "a____dot__b" — a different, wrong identifier that no CRD-authored rule using
        // the real (correct) escaped name would ever match.
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a__.b": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.a__underscores____dot__b)",
                "message": "a__.b must be set"
            }]
        });
        assert!(
            check_schema(&serde_json::json!({ "a__.b": "x" }), schema.clone()).is_ok(),
            "self.a__underscores____dot__b must resolve to the real 'a__.b' field — this \
             only holds if '__' is escaped with priority over the following '.', matching \
             upstream's escaping order"
        );
        let err = check_schema(&serde_json::json!({}), schema).unwrap_err();
        assert!(
            err.1.message.contains("a__.b must be set"),
            "an unset field must still fail the rule (got: {})",
            err.1.message
        );
    }

    #[test]
    fn cel_rule_omits_unescapable_field_name_instead_of_exposing_it_verbatim() {
        // "1bad" starts with a digit, so it can never be a valid CEL identifier under
        // any escaping scheme — upstream's SchemaDeclType simply never declares such a
        // field on the generated CEL struct type. If u7s instead leaked it into `self`
        // under its raw name (rather than dropping it), a rule could observe data that
        // upstream's compiled CEL type says doesn't exist, diverging from upstream
        // evaluation semantics.
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "keep": { "type": "string" },
                "1bad": { "type": "string" }
            },
            "x-kubernetes-validations": [{
                "rule": "has(self.keep) && !('1bad' in self)",
                "message": "unescapable field must not be exposed to self"
            }]
        });
        let err = check_schema(&serde_json::json!({ "keep": "x", "1bad": "y" }), schema);
        assert!(
            err.is_ok(),
            "an unescapable field name (leading digit) must be dropped from the CEL-bound \
             self object, not exposed under its raw name — got: {err:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // CEL string-extension overloads (split/lowerAscii/upperAscii/replace/join)
    //
    // The vendored `cel` crate's stdlib doesn't implement these (only base-spec
    // contains/startsWith/endsWith/matches/size), but real CRDs use them, e.g.
    // Gateway API's `self.split("/")[0].size() < 253` annotation-key-prefix rule and
    // Crossplane's `self.plural == self.plural.lowerAscii()`. Without the overloads
    // registered, evaluating such a rule fails with an "undeclared reference" CEL
    // error on every CR write instead of the rule ever actually running.
    // ---------------------------------------------------------------------------

    /// Helper: compile and evaluate a boolean CEL expression with the string-extension
    /// overloads registered, same as `evaluate_cel_rule` does for every CRD rule.
    fn eval_cel_bool(expr: &str) -> bool {
        let program = cel::Program::compile(expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        let mut ctx = cel::Context::default();
        register_cel_string_extensions(&mut ctx);
        match program.execute(&ctx) {
            Ok(cel::Value::Bool(b)) => b,
            other => panic!("{expr} did not evaluate to a bool: {other:?}"),
        }
    }

    #[test]
    fn cel_split_overload_evaluates_gateway_annotation_key_prefix_rule() {
        assert!(
            eval_cel_bool(r#"'example.com/name'.split('/')[0] == 'example.com'"#),
            "split() must break a string on every separator occurrence, matching the \
             Gateway API annotation-key-prefix rule this overload exists for"
        );
    }

    #[test]
    fn cel_lower_ascii_overload_evaluates_crossplane_plural_rule() {
        assert!(
            eval_cel_bool("'Widgets'.lowerAscii() == 'widgets'"),
            "lowerAscii() must lowercase ASCII letters, matching Crossplane's \
             `self.plural == self.plural.lowerAscii()` CompositeResourceDefinition rule"
        );
    }

    #[test]
    fn cel_upper_ascii_overload_uppercases_ascii_letters() {
        assert!(
            eval_cel_bool("'Widgets'.upperAscii() == 'WIDGETS'"),
            "upperAscii() must uppercase ASCII letters"
        );
    }

    #[test]
    fn cel_replace_overload_replaces_every_occurrence() {
        assert!(
            eval_cel_bool("'a-b-c'.replace('-', '_') == 'a_b_c'"),
            "replace() must replace every occurrence of the old substring, not just the first"
        );
    }

    #[test]
    fn cel_join_overload_with_separator_joins_list_elements() {
        assert!(
            eval_cel_bool("['a', 'b', 'c'].join('-') == 'a-b-c'"),
            "join(separator) must concatenate list elements with the given separator"
        );
    }

    #[test]
    fn cel_join_overload_without_separator_concatenates_with_no_delimiter() {
        assert!(
            eval_cel_bool("['a', 'b', 'c'].join() == 'abc'"),
            "join() with no argument must concatenate list elements with no delimiter, \
             matching Kubernetes' CEL strings library's zero-arg join overload"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression fixtures: real-world CRD CEL rules from the audit
    // (ai/findings/cel-cr-admission-audit-2026-08-25.md), verifying enforcement
    // against the workloads that actually motivated it, not just synthetic rules.
    //
    // cert-manager ClusterIssuer's has()+ternary exactly-one-of rule and
    // prometheus-operator ScrapeConfig's filter()+size() rule are already covered
    // verbatim by `cel_has_macro_*`/`cel_filter_macro_*` above (the landed
    // suite) — not duplicated here.
    // ---------------------------------------------------------------------------

    // HTTPRoute CORS rules (audit L495-498/557-560/635-638): the wildcard '*' must not
    // be combined with any other entry. Exercises the `in` operator together with
    // size() in one rule, on a list rather than a single scalar.
    #[test]
    fn cel_in_operator_and_size_rejects_wildcard_combined_with_other_origins() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "allowOrigins": {
                    "type": "array",
                    "items": { "type": "string" },
                    "x-kubernetes-validations": [{
                        "rule": "!('*' in self && self.size() > 1)",
                        "message": "wildcard '*' must not be combined with other allowOrigins entries"
                    }]
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "allowOrigins": ["*"] }),
                schema.clone()
            )
            .is_ok(),
            "wildcard alone must be accepted"
        );
        assert!(
            check_schema(
                &serde_json::json!({ "allowOrigins": ["https://a.example", "https://b.example"] }),
                schema.clone()
            )
            .is_ok(),
            "multiple non-wildcard origins must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "allowOrigins": ["*", "https://a.example"] }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("wildcard '*' must not be combined with other allowOrigins entries"),
            "combining '*' with another origin must be rejected with the CRD's message \
             (got: {})",
            err.1.message
        );
    }

    // HTTPRoute has() mutual exclusivity (audit L1039): percent and fraction are
    // alternate ways to express the same weight and must not both be set. Distinct
    // from the ClusterIssuer has()-count fixture above: this is a plain boolean
    // mutual-exclusivity check, not a "sum to exactly one" arithmetic rule.
    #[test]
    fn cel_has_macro_rejects_both_percent_and_fraction_set() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "weight": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "!(has(self.percent) && has(self.fraction))",
                        "message": "percent and fraction are mutually exclusive"
                    }],
                    "properties": {
                        "percent": { "type": "integer" },
                        "fraction": { "type": "object" }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "weight": { "percent": 50 } }),
                schema.clone()
            )
            .is_ok(),
            "setting only percent must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "weight": { "percent": 50, "fraction": {} } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("percent and fraction are mutually exclusive"),
            "setting both percent and fraction must be rejected (got: {})",
            err.1.message
        );
    }

    // HTTPRoute baseline cross-field rule (audit L1020): plain `self.a`/`self.b`
    // comparison with no macros involved — this should pass even without any CEL
    // macro support, so a regression here means the basic `self` binding itself broke.
    #[test]
    fn cel_baseline_cross_field_rule_rejects_numerator_exceeding_denominator() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.numerator <= self.denominator",
                        "message": "numerator must not exceed denominator"
                    }],
                    "properties": {
                        "numerator": { "type": "integer" },
                        "denominator": { "type": "integer" }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "numerator": 1, "denominator": 2 } }),
                schema.clone()
            )
            .is_ok(),
            "numerator <= denominator must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "spec": { "numerator": 3, "denominator": 2 } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("numerator must not exceed denominator"),
            "numerator exceeding denominator must be rejected (got: {})",
            err.1.message
        );
    }

    // Gateway listener-name uniqueness (audit L901-918): a genuinely 2-variable
    // comprehension over a single list — `l1`/`l2` both range over `self`. Two
    // listeners sharing a name means `exists_one` finds two matches for that name,
    // not one, so `all()` must fail on the first offending element.
    #[test]
    fn cel_two_variable_all_exists_one_rejects_duplicate_listener_names() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "listeners": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": { "name": { "type": "string" } }
                    },
                    "x-kubernetes-validations": [{
                        "rule": "self.all(l1, self.exists_one(l2, l1.name == l2.name))",
                        "message": "listener names must be unique"
                    }]
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "listeners": [{ "name": "http" }, { "name": "https" }] }),
                schema.clone()
            )
            .is_ok(),
            "distinct listener names must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "listeners": [{ "name": "http" }, { "name": "http" }] }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1.message.contains("listener names must be unique"),
            "duplicate listener names must be rejected (got: {})",
            err.1.message
        );
    }

    // A different shape of 2-variable comprehension than the Gateway fixture above:
    // the two variables range over two *different* collections
    // (`self.foo.all(x, self.bar.all(y, ...))`), not the same list twice. Flagged
    // by critical-reviewer as missing from the landed suite.
    #[test]
    fn cel_two_variable_nested_comprehension_across_two_collections_rejects_overlap() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.reservedPorts.all(x, self.dynamicPorts.all(y, x < y))",
                        "message": "every reserved port must be lower than every dynamic port"
                    }],
                    "properties": {
                        "reservedPorts": { "type": "array", "items": { "type": "integer" } },
                        "dynamicPorts": { "type": "array", "items": { "type": "integer" } }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({
                    "spec": { "reservedPorts": [80, 443], "dynamicPorts": [30000, 30001] }
                }),
                schema.clone()
            )
            .is_ok(),
            "reserved ports strictly below every dynamic port must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({
                "spec": { "reservedPorts": [80, 30000], "dynamicPorts": [30000, 30001] }
            }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("every reserved port must be lower than every dynamic port"),
            "a reserved port overlapping the dynamic range must be rejected (got: {})",
            err.1.message
        );
    }

    // Gateway API annotation-key-prefix rule (audit L262, `gateway.networking.k8s.io_\
    // gateways.yaml`): `self.split("/")[0].size() < 253`. This is the exact rule
    // `.split()` was registered for — without that overload this rule would
    // fail every evaluation with an "undeclared reference" CEL error, not evaluate the
    // length check at all.
    #[test]
    fn cel_split_function_enforces_gateway_annotation_key_prefix_length() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "annotations": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "x-kubernetes-validations": [{
                        "rule": "self.all(key, key.split('/')[0].size() < 253)",
                        "message": "annotation key prefix must be under 253 characters"
                    }]
                }
            }
        });
        let mut ok = serde_json::json!({ "annotations": {} });
        ok["annotations"]["example.com/name"] = serde_json::json!("widget");
        assert!(
            check_schema(&ok, schema.clone()).is_ok(),
            "an annotation key with a short prefix must be accepted"
        );

        let long_prefix = "a".repeat(253);
        let mut bad = serde_json::json!({ "annotations": {} });
        bad["annotations"][format!("{long_prefix}/name")] = serde_json::json!("widget");
        let err = check_schema(&bad, schema).unwrap_err();
        assert!(
            err.1
                .message
                .contains("annotation key prefix must be under 253 characters"),
            "a 253+ byte annotation-key prefix must be rejected (got: {})",
            err.1.message
        );
    }

    // messageExpression path: the CRD author builds a formatted error string from the
    // failing values instead of a static `message`. The rendered string, not a generic
    // CEL error or the raw rule text, must reach the client in the 422 body.
    #[test]
    fn cel_message_expression_builds_formatted_error_surfaced_in_422_body() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.replicas <= self.maxReplicas",
                        "messageExpression": "'replicas (' + string(self.replicas) + \
                            ') must not exceed maxReplicas (' + string(self.maxReplicas) + ')'"
                    }],
                    "properties": {
                        "replicas": { "type": "integer" },
                        "maxReplicas": { "type": "integer" }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "replicas": 2, "maxReplicas": 5 } }),
                schema.clone()
            )
            .is_ok(),
            "replicas within the max must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "spec": { "replicas": 10, "maxReplicas": 5 } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1
                .message
                .contains("replicas (10) must not exceed maxReplicas (5)"),
            "the messageExpression-rendered string (built from the actual failing values) \
             must reach the client, not a generic CEL failure or the raw rule text \
             (got: {})",
            err.1.message
        );
    }

    // CEL error branches must all fail closed (reject the CR), matching the
    // stated design intent — a rule the interpreter can't safely evaluate is not the
    // same as a rule that evaluated to "no violation".
    //
    // Runtime failure: division by zero. This differs from a compile error (below) —
    // the rule parses and type-checks, it only fails while executing against this
    // specific CR body.
    #[test]
    fn cel_division_by_zero_runtime_error_fails_closed_instead_of_silently_accepting() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.numerator / self.denominator > 0",
                        "message": "ratio must be positive"
                    }],
                    "properties": {
                        "numerator": { "type": "integer" },
                        "denominator": { "type": "integer" }
                    }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "numerator": 4, "denominator": 2 } }),
                schema.clone()
            )
            .is_ok(),
            "a rule that evaluates cleanly to true must still be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "spec": { "numerator": 4, "denominator": 0 } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1.message.contains("failed to evaluate"),
            "division by zero mid-rule must reject the CR (fail closed), not silently \
             accept it as if the rule had passed (got: {})",
            err.1.message
        );
    }

    // A rule that evaluates successfully but to a non-bool value is an authoring bug
    // in the CRD, not a "no violation" signal — every input must be rejected, since
    // there is no CR body for which this rule could ever mean "passed".
    #[test]
    fn cel_non_bool_result_rule_fails_closed_instead_of_silently_accepting() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.numerator",
                        "message": "malformed rule"
                    }],
                    "properties": { "numerator": { "type": "integer" } }
                }
            }
        });
        let err =
            check_schema(&serde_json::json!({ "spec": { "numerator": 1 } }), schema).unwrap_err();
        assert!(
            err.1.message.contains("must evaluate to a bool"),
            "a rule returning a non-bool value must reject every CR body, not accept it \
             (got: {})",
            err.1.message
        );
    }

    // A rule that fails to even compile (malformed CEL syntax) must reject the CR at
    // admission time, not be silently skipped — the CRD author has a broken rule, and
    // the operator writing the CR needs to know their write was rejected, not that it
    // silently bypassed validation.
    #[test]
    fn cel_malformed_rule_fails_to_compile_and_rejects_instead_of_silently_accepting() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-validations": [{
                        "rule": "self.foo((",
                        "message": "malformed rule"
                    }]
                }
            }
        });
        let err = check_schema(&serde_json::json!({ "spec": {} }), schema).unwrap_err();
        assert!(
            err.1.message.contains("does not compile"),
            "malformed CEL must reject the CR with a compile-error message, not silently \
             accept it (got: {})",
            err.1.message
        );
    }

    // A CRD author's rule has no static cost bound (unlike upstream, which rejects an
    // over-cost rule at CRD admission via a static estimator). A nested
    // list comprehension (`.all()` inside `.all()`) is O(n^2) in the length of a
    // CR-author-controlled list, so any tenant that can write a CR against this CRD could
    // grow that list until the rule takes arbitrarily long to evaluate — without a budget
    // this would hang the request-handling thread indefinitely instead of ever responding.
    // This proves the write is REJECTED once evaluation exceeds CEL_RULE_EVAL_BUDGET,
    // mirroring `validate_cr_schema_defense_in_depth_rejects_oversized_pattern...` above
    // for the equivalent boon-schema risk. The hard wall-clock cap on the assertion below
    // is what makes this a safe regression test: the list is sized so the full O(n^2)
    // comparison would take single-digit seconds if ever finished (calibrated separately),
    // but the budget must abandon it and return within CEL_RULE_EVAL_BUDGET, so the test
    // itself finishes in a small fraction of a second — a test that took as long as the
    // full computation would defeat the point of having a budget at all.
    #[test]
    fn cel_rule_exceeding_evaluation_budget_is_rejected_not_left_to_hang() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "x-kubernetes-validations": [
                        { "rule": "self.all(x, self.all(y, x + y >= 0))" }
                    ]
                }
            }
        });
        // Calibrated to take ~4s to run to completion uninstrumented (n=2000, 4,000,000
        // comprehension steps) — comfortably over CEL_RULE_EVAL_BUDGET (250ms) even on
        // slower CI hardware, while the abandoned evaluation thread never blocks this test.
        let items: Vec<i64> = (0..2000).collect();
        let value = serde_json::json!({ "items": items });

        let start = std::time::Instant::now();
        let err = check_schema(&value, schema).expect_err(
            "a CEL rule whose cost scales with a CR-author-controlled list must be rejected \
             once it exceeds the evaluation time budget, not accepted after silently running \
             unbounded work",
        );
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the whole point of the budget is to bound how long a single request waits for a \
             runaway CEL rule — this took {elapsed:?}, which means the timeout mechanism \
             itself did not fire (it should reject in ~CEL_RULE_EVAL_BUDGET, not run the full \
             O(n^2) comprehension to completion)"
        );
        assert!(
            err.1.message.contains("evaluation time budget"),
            "the rejection must identify itself as the CEL cost-budget defense, not a \
             generic validation failure (got: {})",
            err.1.message
        );
    }

    // Before this fix, `execute_cel_with_budget` spawned a brand-new OS thread for every
    // over-budget rule with no cap on how many could be alive at once -- each individual
    // request still returned in ~CEL_RULE_EVAL_BUDGET, but a flood of concurrent writes
    // each carrying a pathological CEL rule left one abandoned, CPU-bound thread running
    // per rejection, unboundedly. `ConcurrencyGate` is what now bounds that. Uses a small
    // local cap (not the real, process-wide `CEL_EVAL_THREAD_GATE`, which every
    // concurrently-running request's CEL evaluation -- including every other test in this
    // file -- also relies on) so this test can't spuriously reject unrelated evaluations.
    #[test]
    fn concurrency_gate_bounds_holders_and_rejects_excess_acquires() {
        use std::sync::Barrier;

        static GATE: ConcurrencyGate = ConcurrencyGate::new(3);
        const N: usize = 3 + 5; // deliberately oversubscribe the cap by 5

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    GATE.try_acquire()
                })
            })
            .collect();
        let acquired = handles
            .into_iter()
            .map(|h| h.join().expect("racer thread must not panic"))
            .filter(|ok| *ok)
            .count();

        assert_eq!(
            acquired, 3,
            "{N} concurrent racers against a cap of 3 must result in exactly 3 successful \
             acquisitions, no more -- if more succeed, the check-then-increment isn't \
             atomic and the cap is meaningless under real concurrency; if fewer, \
             legitimate callers under the cap are being turned away for no reason"
        );

        // A released slot must be available to a later caller -- otherwise the gate would
        // only ever fill up and eventually reject every future evaluation, not just ones
        // concurrent with an existing backlog.
        GATE.release();
        assert!(
            GATE.try_acquire(),
            "releasing a held slot must make the gate accept a new acquisition again"
        );
    }

    // `execute_cel_with_budget` is the function the reviewed finding was raised against
    // directly: it must refuse to spawn another thread once its gate is saturated
    // (returning `TooManyInFlight` instead of ever calling `std::thread::spawn`), and
    // must resume normal evaluation as soon as a slot frees up. Exercised with a small,
    // local gate injected via the `gate` parameter, for the same reason as the test
    // above: this must not touch the real, process-wide `CEL_EVAL_THREAD_GATE`.
    #[test]
    fn execute_cel_with_budget_rejects_outright_once_its_gate_is_saturated() {
        static GATE: ConcurrencyGate = ConcurrencyGate::new(1);
        let program = std::sync::Arc::new(cel::Program::compile("true").unwrap());

        // Saturate the gate directly -- the gate doesn't care who holds the slot, so
        // there's no need to actually run a slow CEL rule to occupy it.
        assert!(GATE.try_acquire(), "gate must start with a free slot");

        let over_budget = execute_cel_with_budget(
            &program,
            cel::Context::default(),
            CEL_RULE_EVAL_BUDGET,
            &GATE,
        );
        assert!(
            matches!(over_budget, Err(CelEvalOverBudget::TooManyInFlight)),
            "with the gate already saturated, a new evaluation must be rejected outright \
             via TooManyInFlight -- this is the whole point of the fix: reject instead of \
             spawning yet another (potentially abandoned) thread once the cap is reached"
        );

        GATE.release();
        let result = execute_cel_with_budget(
            &program,
            cel::Context::default(),
            CEL_RULE_EVAL_BUDGET,
            &GATE,
        );
        assert!(
            matches!(result, Ok(Ok(cel::Value::Bool(true)))),
            "once the gate has a free slot again, evaluation must proceed and succeed \
             exactly as it did before this fix -- the cap must not permanently wedge \
             evaluation after a burst subsides"
        );
    }

    // Before this fix, `execute_cel_with_budget`'s spawned thread called `gate.release()`
    // manually *after* `program.execute()` returned. The `cel` crate has reachable
    // `panic!` sites in its evaluator (e.g. cel 0.14.3 objects.rs:1546, :1467), and a
    // panic there would unwind straight past that manual release call, leaking the slot
    // permanently. Enough leaked panics (up to `MAX_CONCURRENT_CEL_EVAL_THREADS`) would
    // wedge `CEL_EVAL_THREAD_GATE` for every future CR write's CEL validation
    // cluster-wide -- the exact DoS this file exists to prevent, just triggered by
    // malformed/panicking CEL input instead of slow input. `GateGuard` fixes this by
    // releasing on `Drop`, which Rust's unwind machinery runs even when the guarded
    // scope panics (this workspace does not set `panic = "abort"`). Exercises
    // `GateGuard` directly against a small local gate, mirroring the exact shape of the
    // real spawned-thread body, rather than relying on the `cel` crate's internal panic
    // sites to actually fire.
    #[test]
    fn gate_guard_releases_slot_even_when_guarded_scope_panics() {
        static GATE: ConcurrencyGate = ConcurrencyGate::new(1);
        assert!(GATE.try_acquire(), "gate must start with a free slot");

        let panicked = std::thread::spawn(|| {
            let _guard = GateGuard(&GATE);
            panic!("simulated cel::Program::execute panic, e.g. cel 0.14.3 objects.rs:1546");
        })
        .join();

        assert!(
            panicked.is_err(),
            "test setup bug: the spawned thread must actually panic to exercise the \
             unwind path this test is checking"
        );
        assert!(
            GATE.try_acquire(),
            "a slot leaked across a panic inside the guarded region -- GateGuard's Drop \
             must run gate.release() during unwinding, not only on normal return, or a \
             handful of panicking CEL rules permanently wedges the process-wide gate and \
             blocks every future CR write's CEL validation"
        );
    }

    // Before this fix, validate_cel_rules only recursed via `properties`/`items`, so a
    // rule reachable only through a `oneOf` branch never fired — a CR that violated it
    // was silently accepted. Modeled on cert-manager Issuer's real-world pattern of
    // using `oneOf` to discriminate between backend types (tpp vs cloud), with the CEL
    // rule nested one level further inside the matching branch (`oneOf` itself nested
    // under `properties.spec`, not at the schema root).
    #[test]
    fn cel_rule_under_oneof_branch_is_evaluated_instead_of_silently_skipped() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "oneOf": [
                        {
                            "required": ["tpp"],
                            "properties": {
                                "tpp": {
                                    "type": "object",
                                    "properties": { "url": { "type": "string" } },
                                    "x-kubernetes-validations": [{
                                        "rule": "self.url.startsWith('https://')",
                                        "message": "tpp.url must use https"
                                    }]
                                }
                            }
                        },
                        {
                            "required": ["cloud"],
                            "properties": { "cloud": { "type": "object" } }
                        }
                    ]
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "tpp": { "url": "https://secure.example" } } }),
                schema.clone()
            )
            .is_ok(),
            "an https tpp.url must be accepted"
        );
        let err = check_schema(
            &serde_json::json!({ "spec": { "tpp": { "url": "http://insecure.example" } } }),
            schema,
        )
        .unwrap_err();
        assert!(
            err.1.message.contains("tpp.url must use https"),
            "a rule nested under a oneOf branch must be evaluated and reject a violating \
             CR — before this fix it was never reached, so this body was silently \
             accepted (got: {})",
            err.1.message
        );
    }

    // `allOf` branches all apply simultaneously (unlike `oneOf`'s pick-one semantics),
    // so a rule on any `allOf` branch must fire unconditionally.
    #[test]
    fn cel_rule_under_allof_branch_is_evaluated_unconditionally() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "allOf": [
                        {
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "x-kubernetes-validations": [{
                                        "rule": "self.size() > 0",
                                        "message": "name must not be empty"
                                    }]
                                }
                            }
                        }
                    ],
                    "properties": { "name": { "type": "string" } }
                }
            }
        });
        assert!(
            check_schema(
                &serde_json::json!({ "spec": { "name": "widget" } }),
                schema.clone()
            )
            .is_ok(),
            "a non-empty name must be accepted"
        );
        let err = check_schema(&serde_json::json!({ "spec": { "name": "" } }), schema).unwrap_err();
        assert!(
            err.1.message.contains("name must not be empty"),
            "a rule nested under an allOf branch must be evaluated and reject a \
             violating CR (got: {})",
            err.1.message
        );
    }

    // CRD with schema: valid CR body accepted by create_cr_namespaced.
    // This is the integration path: schema extracted from CRD, CR body validated.
    #[tokio::test]
    async fn create_cr_namespaced_with_schema_accepts_valid_body() {
        let state = make_state();

        // Install CRD with openAPIV3Schema requiring spec to be an object.
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with schema"
        );

        // CR with spec as object — must pass validation.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "good-widget", "namespace": "default" },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "default".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "CR with valid spec object must be accepted by schema validation"
        );
    }

    // CRD with schema: CR body with wrong spec type rejected with 422.
    // Server-side validation must fire when the CRD has a schema — wrong types
    // must not be silently stored (the whole point of this feature).
    #[tokio::test]
    async fn create_cr_namespaced_with_schema_rejects_wrong_spec_type() {
        let state = make_state();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with schema"
        );

        // CR with spec as a string — must fail schema validation.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "bad-widget", "namespace": "default" },
                "spec": "not-an-object"
            })
            .to_string(),
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                cr_body,
            )
            .await,
            "CR with spec as string must be rejected",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "schema violation must return 422");
        assert_eq!(
            json["reason"], "Invalid",
            "schema violation must return reason=Invalid"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("schema validation failed"),
            "message must mention schema validation (got: {})",
            json["message"]
        );
    }

    // CRD with required field: CR missing that field is rejected with 422.
    // Required constraints protect controllers that always expect certain fields.
    #[tokio::test]
    async fn create_cr_namespaced_with_required_schema_rejects_missing_field() {
        let state = make_state();

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "required": ["spec"],
                                "properties": {
                                    "spec": { "type": "object" }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with required schema"
        );

        // CR without spec — must fail required constraint.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "no-spec-widget", "namespace": "default" }
            })
            .to_string(),
        );

        let err = expect_err_status(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "default".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                cr_body,
            )
            .await,
            "CR without required spec must be rejected",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "missing required field must return 422");
    }

    // CRD without schema: any CR body is accepted (permissive mode).
    // This preserves backward-compatible behaviour for CRDs that don't declare a schema.
    #[tokio::test]
    async fn create_cr_namespaced_without_schema_accepts_any_body() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        // Body with an unusual structure — must be accepted since no schema is declared.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": "any-body-app", "namespace": "argocd" },
                "weirdField": 42,
                "anotherField": [1, 2, 3]
            })
            .to_string(),
        );

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "CRD without schema must accept any body (permissive mode)"
        );
    }

    // A `count/<crd>.<group>` ResourceQuota at its hard limit must reject a second custom
    // resource create. Before this fix, `create_cr_namespaced` never called
    // `quota::check_resource_quota` at all — CR creation was completely unenforced by
    // ResourceQuota — reproducing upstream conformance's "should create a ResourceQuota and
    // capture the life of a custom resource" (a second CR past count/1 was admitted instead
    // of rejected).
    #[tokio::test]
    async fn create_cr_namespaced_denies_second_cr_when_count_quota_at_limit() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let quota = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "crd-quota", "namespace": "argocd" },
            "spec": { "hard": { "count/applications.argoproj.io": "1" } }
        });
        state
            .store
            .put(
                "/registry/resourcequotas/argocd/crd-quota",
                Bytes::from(serde_json::to_vec(&quota).unwrap()),
                None,
            )
            .await
            .expect("seed quota");

        let first = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("app-1", "argocd"),
        )
        .await;
        assert!(
            first.is_ok(),
            "first CR must be admitted (quota not yet at limit)"
        );

        let second = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("app-2", "argocd"),
        )
        .await;
        assert!(
            second.is_err(),
            "second CR must be denied once count/applications.argoproj.io=1 is already \
             claimed — without ResourceQuota admission wired into create_cr_namespaced, \
             CR creation is never checked against quota at all"
        );
    }

    // validate_cr_schema's `old_object` parameter is threaded by hand through 8 call
    // sites across create/replace/patch handlers; a single site accidentally left as
    // `None` would silently disable oldSelf immutability checks for that verb only. This
    // exercises the full replace_cr handler (not just validate_cr_schema directly) so a
    // regression in the *wiring*, not just the CEL evaluation logic, would be caught.
    #[tokio::test]
    async fn replace_cr_end_to_end_enforces_immutability_cel_rule_from_installed_crd() {
        let state = make_state();
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": {
                                            "color": {
                                                "type": "string",
                                                "x-kubernetes-validations": [{
                                                    "rule": "self == oldSelf",
                                                    "message": "color is immutable"
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with immutability CEL rule"
        );

        let name = "my-widget".to_string();
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": &name },
                        "spec": { "color": "blue" }
                    })
                    .to_string()
                ),
            )
            .await
            .is_ok(),
            "create with an initial color must succeed (no oldSelf on CREATE)"
        );

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": &name },
                        "spec": { "color": "red" }
                    })
                    .to_string(),
                ),
            )
            .await,
            "changing an immutable field through the real replace_cr handler must be \
             rejected — a wiring bug (e.g. old_object left as None) would instead let \
             this update through",
        );
        assert_eq!(
            err.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "the rejection must be a 422 Unprocessable Entity, matching the boon \
             structural-validation failures this file already reports"
        );
        assert!(
            err.1.message.contains("color is immutable"),
            "the rejection must carry the CRD's own message (got: {})",
            err.1.message
        );
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped replace_cr tests
    // ---------------------------------------------------------------------------

    // replace_cr (cluster-scoped) must update the stored object and return 200.
    // This is the happy-path for cluster-scoped CR updates — controllers call PUT
    // on the main endpoint to change spec.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_round_trip() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "red" }
            })
            .to_string(),
        );

        assert!(
            replace_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "cluster-scoped replace must succeed"
        );

        // Verify the update was persisted.
        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after replace"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "red",
            "spec must be updated by replace"
        );
    }

    // replace_cr on a non-existent object must return 404.
    // Cluster-scoped PUT must not create resources that don't exist — that is
    // only the job of POST (create).
    #[tokio::test]
    async fn cluster_scoped_replace_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": "nonexistent" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "replace on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // replace_cr with a name mismatch between URL and body must return 400.
    // Kubernetes enforces that the object name in the body matches the URL segment.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_name_mismatch_returns_400() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // First create the object.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("actual-name"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with body.metadata.name != URL segment.
        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "actual-name".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": "different-name" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "name mismatch must return 400",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 400,
            "name mismatch must return 400 Bad Request"
        );
    }

    // replace_cr with a namespaced CRD must return 404 (wrong scope).
    // The cluster-scoped endpoint must not serve namespaced CRDs.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "argoproj.io/v1alpha1",
                        "kind": "Application",
                        "metadata": { "name": "my-app" },
                        "spec": {}
                    })
                    .to_string(),
                ),
            )
            .await,
            "namespaced CRD on cluster-scoped replace must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // replace_cr strips .status when the CRD declares a status subresource.
    // This is symmetric to the namespaced case tested in
    // `namespaced_main_put_strips_status_when_has_status_subresource`.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "green" },
                "status": { "ready": true, "message": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );

        assert!(
            replace_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "replace must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PUT when status subresource is declared"
        );
    }

    // Regression: mirrors VolumeSnapshotContent's real lifecycle — csi-snapshotter PATCHes
    // .status.snapshotHandle via /status, then a later spec-only Update (PUT to the main
    // endpoint, e.g. flipping deletionPolicy to Retain) must not wipe that status. Before
    // this fix, replace_cr dropped .status from the object entirely on every main PUT once
    // the CRD declared a status subresource, instead of preserving what was already stored,
    // so upstream's CreateSnapshotResource (which reads .status.snapshotHandle straight off
    // its own Update response) panicked with `interface conversion: interface {} is nil,
    // not map[string]interface {}`.
    #[tokio::test]
    async fn cluster_scoped_replace_cr_preserves_status_set_via_status_subresource() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "my-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Publish .status via the /status subresource, the same way csi-snapshotter does.
        let status_put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "blue" },
                "status": { "snapshotHandle": "handle-123" }
            })
            .to_string(),
        );
        assert!(
            put_cr_status(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                axum::http::HeaderMap::new(),
                status_put_body,
            )
            .await
            .is_ok(),
            "PUT /status must succeed"
        );

        // A later spec-only Update (PUT to the main endpoint) must not wipe that status.
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name },
                "spec": { "color": "green" }
            })
            .to_string(),
        );
        let replace_resp = replace_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            test_user(),
            axum::http::HeaderMap::new(),
            update_body,
        )
        .await
        .expect("replace must succeed")
        .into_response();
        let replace_body = axum::body::to_bytes(replace_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let replace_obj: serde_json::Value = serde_json::from_slice(&replace_body).unwrap();
        assert_eq!(
            replace_obj["status"]["snapshotHandle"], "handle-123",
            "the PUT response itself must carry the preserved status — a controller like \
             CreateSnapshotResource reads .status straight off its own Update response, not \
             a fresh GET"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "green",
            "spec must still be updated by the main PUT"
        );
        assert_eq!(
            obj["status"]["snapshotHandle"], "handle-123",
            "status set via the /status subresource must survive a later spec-only main PUT"
        );
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped delete_cr tests
    // ---------------------------------------------------------------------------

    // delete_cr must remove the object from the store; a subsequent get must return 404.
    // This is the happy-path for cluster-scoped CR deletion.
    #[tokio::test]
    async fn cluster_scoped_delete_cr_success() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "to-delete".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        assert!(
            delete_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "delete must succeed"
        );

        // Subsequent get must return 404.
        let err = expect_err_status(
            get_cr(
                State(state.clone()),
                Path((group, version, plural, name)),
                axum::http::HeaderMap::new(),
            )
            .await,
            "get after delete must return 404",
        );
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // delete_cr on a non-existent object must return 404.
    // Deleting a missing cluster-scoped CR must not silently succeed.
    #[tokio::test]
    async fn cluster_scoped_delete_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            delete_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::new(),
            )
            .await,
            "delete on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // delete_cr with a namespaced CRD must return 404 (wrong scope).
    #[tokio::test]
    async fn cluster_scoped_delete_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            delete_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::new(),
            )
            .await,
            "namespaced CRD on cluster-scoped delete must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // ---------------------------------------------------------------------------
    // Cluster-scoped patch_cr tests
    // ---------------------------------------------------------------------------

    // patch_cr must apply the merge patch and return the updated object.
    // This verifies the cluster-scoped patch handler — symmetric to
    // `patch_cr_namespaced_applies_merge_patch`.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_applies_merge_patch() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "patch-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body =
            Bytes::from(serde_json::json!({ "spec": { "color": "purple" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "cluster-scoped patch must succeed"
        );

        // Verify the patch was applied.
        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after patch"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "purple",
            "spec.color must be updated by patch"
        );
    }

    // patch_cr on an EXISTING CR with a genuine multi-line YAML apply-patch+yaml body must
    // succeed, not 400 "invalid patch JSON".
    //
    // WHY this matters: the create path (ssa_apply_patch_creates_cluster_scoped_cr_when_absent
    // above) already handles real YAML via ssa_body_to_json, but the update path (this test)
    // fell through to an unconditional serde_json::from_slice regardless of content type —
    // so `kubectl apply --server-side` on a CR applied a SECOND time (the common case) 400'd
    // even though the first apply succeeded.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_ssa_accepts_real_yaml_body_on_existing_cr() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "ssa-yaml-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Genuine YAML block syntax — NOT JSON serialized to bytes.
        let yaml_patch = Bytes::from_static(b"spec:\n  color: purple\n");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/apply-patch+yaml".parse().unwrap(),
        );

        let result = patch_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            test_user(),
            headers,
            yaml_patch,
        )
        .await;
        assert!(
            result.is_ok(),
            "apply-patch+yaml with a genuine YAML body on an existing CR must succeed, not \
             400 'invalid patch JSON': {:?}",
            result.err()
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed after SSA patch"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "purple",
            "spec.color from the YAML SSA body must be applied to the existing CR"
        );
    }

    // patch_cr with wrong Content-Type must return 415.
    // This verifies validate_patch_content_type fires on the cluster-scoped path.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_rejects_wrong_content_type() {
        let state = make_state();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "my-widget".to_string(),
                )),
                test_user(),
                headers,
                Bytes::from(b"{}".to_vec()),
            )
            .await,
            "wrong content type must return 415",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 415, "wrong content type must return 415");
    }

    // patch_cr on a non-existent object must return 404.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_missing_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                test_user(),
                headers,
                Bytes::from(serde_json::json!({ "spec": {} }).to_string()),
            )
            .await,
            "patch on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // patch_cr with a namespaced CRD must return 404 (wrong scope).
    #[tokio::test]
    async fn cluster_scoped_patch_cr_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                test_user(),
                headers,
                Bytes::from(serde_json::json!({ "spec": {} }).to_string()),
            )
            .await,
            "namespaced CRD on cluster-scoped patch must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // patch_cr strips .status when the CRD declares a status subresource.
    // Controllers must use PATCH /status for status updates; the main patch endpoint
    // must silently drop any .status in the patch to prevent accidental overwrites.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_strips_status_when_has_status_subresource() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "status-patch-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "spec": { "color": "orange" },
                "status": { "ready": true, "message": "MUST_NOT_BE_STORED" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        assert!(
            patch_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "patch must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["status"].is_null() || obj.get("status").is_none(),
            "status must NOT be stored by main PATCH when status subresource is declared"
        );
    }

    // A JSON Patch to the MAIN cluster-scoped CR endpoint targeting /status must not
    // change status — `patch widgets` and `patch widgets/status` are separate RBAC
    // grants. JSON Patch is an array, so the object-key "status" strip used for
    // merge/strategic patches never sees it; the guard must snapshot/restore instead.
    #[tokio::test]
    async fn cluster_scoped_patch_cr_json_patch_cannot_forge_existing_status() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "json-patch-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // A controller legitimately sets status via /status first.
        assert!(
            put_cr_status(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                axum::http::HeaderMap::new(),
                Bytes::from(serde_json::json!({ "status": { "ready": false } }).to_string()),
            )
            .await
            .is_ok(),
            "put_cr_status must succeed"
        );

        // A caller with only `patch widgets` (no widgets/status grant) tries to
        // forge readiness via a JSON Patch on the main endpoint.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(
            serde_json::json!([{ "op": "replace", "path": "/status/ready", "value": true }])
                .to_string(),
        );

        assert!(
            patch_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "main-endpoint JSON Patch must succeed"
        );

        let resp = match get_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["status"]["ready"], false,
            "a JSON Patch on the main CR endpoint must not forge status.ready — status \
             is a separate RBAC subresource, letting a main-patch-only caller flip it \
             would let it lie about readiness to consumers watching the CR"
        );
    }

    // ---------------------------------------------------------------------------
    // get_cr_status tests
    // ---------------------------------------------------------------------------

    // get_cr_status must return the full object for a cluster-scoped CR.
    // The status field is embedded in the object — this handler is equivalent to
    // get_cr for CRs (there is no separate .status document).
    #[tokio::test]
    async fn get_cr_status_cluster_scoped_returns_object() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "status-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp =
            match get_cr_status(State(state.clone()), Path((group, version, plural, name))).await {
                Ok(r) => r,
                Err(_) => panic!("get_cr_status must succeed for existing cluster-scoped CR"),
            };
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "get_cr_status must return 200 for existing object"
        );
    }

    // get_cr_status for a missing cluster-scoped CR must return 404.
    #[tokio::test]
    async fn get_cr_status_missing_cluster_scoped_returns_404() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let err = expect_err_status(
            get_cr_status(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
            )
            .await,
            "get_cr_status on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    // get_cr_status for a namespaced CRD via the cluster-scoped path must return 404.
    // The cluster-scoped status endpoint must not serve namespaced CRDs.
    #[tokio::test]
    async fn get_cr_status_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let err = expect_err_status(
            get_cr_status(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
            )
            .await,
            "get_cr_status with namespaced CRD must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // ---------------------------------------------------------------------------
    // patch_cr_status tests
    // ---------------------------------------------------------------------------

    // patch_cr_status must update .status and leave .spec untouched for a cluster-scoped
    // CRD declaring subresources.status. Before patch_cr_status existed, the route wired
    // PATCH directly to the non-CR-aware patch_resource_status, which 404s on any group
    // absent from resource_registry — every CRD, including cluster-scoped ones like
    // VolumeSnapshotContent.
    #[tokio::test]
    async fn patch_cr_status_merge_patch_updates_status_not_spec() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "patch-status-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body =
            Bytes::from(serde_json::json!({ "status": { "readyToUse": true } }).to_string());

        let resp = match patch_cr_status(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            headers,
            patch_body,
        )
        .await
        {
            Ok(r) => r.into_response(),
            Err(e) => panic!(
                "patch_cr_status must return 200, not 404, for a cluster-scoped CRD's \
                 own status subresource — else a controller like csi-snapshotter can \
                 never publish readiness: {e:?}"
            ),
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["status"]["readyToUse"], true,
            "patch_cr_status must persist the status field from the patch body"
        );
        assert_eq!(
            obj["spec"]["color"], "blue",
            "patch_cr_status must not alter .spec — status is a separate subresource"
        );
    }

    /// patch_cr_status with a merge-patch body `{"status":"x"}` must be rejected with 422,
    /// not persisted. This is the cluster-scoped catch-all status route (covers every
    /// non-core-group cluster-scoped built-in resource, e.g. CSINode, plus cluster-scoped
    /// CRDs) — `status` is a message/object type for every resource, so a scalar `status`
    /// corrupts the object's schema and later panics `apply_delete_policy`'s in-place
    /// `status["field"] = ...` stamp on the next DELETE, crashing the apiserver for every
    /// other request in flight.
    #[tokio::test]
    async fn patch_cr_status_rejects_scalar_status_merge_patch() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "scalar-status-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        let patch_body = Bytes::from(serde_json::json!({ "status": "x" }).to_string());

        let err = expect_err_status(
            patch_cr_status(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone(), name.clone())),
                headers,
                patch_body,
            )
            .await,
            "a scalar status merge-patch must be rejected, not accepted — it would corrupt \
             the object's schema and later crash apply_delete_policy on DELETE",
        );
        assert_eq!(
            err.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a scalar status must be rejected with 422, matching upstream schema validation"
        );

        let resp = get_cr_status(State(state.clone()), Path((group, version, plural, name)))
            .await
            .expect("get_cr_status must still succeed")
            .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj.get("status").is_none() || obj["status"].is_object(),
            "the rejected patch must not have been persisted — status must remain absent \
             or an object, never the scalar \"x\""
        );
    }

    // patch_cr_status for a missing cluster-scoped CR must return 404, not silently
    // create or no-op — a controller PATCHing a deleted object's status must see the
    // object is gone, not a false success.
    #[tokio::test]
    async fn patch_cr_status_missing_cluster_scoped_returns_404() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_status(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "nonexistent".to_string(),
                )),
                headers,
                Bytes::from(serde_json::json!({ "status": {} }).to_string()),
            )
            .await,
            "patch_cr_status on missing object must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // patch_cr_status for a namespaced CRD via the cluster-scoped path must return 404.
    // The cluster-scoped status endpoint must not serve namespaced CRDs — mirrors
    // get_cr_status_with_namespaced_crd_returns_404.
    #[tokio::test]
    async fn patch_cr_status_with_namespaced_crd_returns_404() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );

        let err = expect_err_status(
            patch_cr_status(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "applications".to_string(),
                    "my-app".to_string(),
                )),
                headers,
                Bytes::from(serde_json::json!({ "status": {} }).to_string()),
            )
            .await,
            "patch_cr_status with namespaced CRD must return 404",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
    }

    // ---------------------------------------------------------------------------
    // Additional coverage for validate_cr_name and list_cr normal path
    // ---------------------------------------------------------------------------

    // validate_cr_name must reject names with invalid characters (e.g. spaces or underscores).
    // Only ASCII alphanumeric, hyphens, and dots are permitted in CR names; other characters
    // would create objects that can't be round-tripped through standard Kubernetes tooling.
    #[test]
    fn validate_cr_name_rejects_invalid_chars() {
        let err = match validate_cr_name("invalid name!") {
            Err(e) => e,
            Ok(_) => panic!("expected Err for name with invalid chars"),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 400,
            "invalid chars must return 400 Bad Request"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("invalid characters"),
            "error message must mention invalid characters"
        );
    }

    // list_cr (cluster-scoped, non-watch) must return an empty list when no CRs exist.
    // This tests the normal list path — distinct from the watch and 404 paths already
    // covered by other tests.
    #[tokio::test]
    async fn cluster_scoped_list_cr_empty() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed even when empty"),
        };

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cluster-scoped list must return 200"
        );
    }

    // list_cr (cluster-scoped, non-watch) must include created items.
    #[tokio::test]
    async fn cluster_scoped_list_cr_returns_created_items() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("listed-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed after create"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ---------------------------------------------------------------------------
    // Additional boon schema validation coverage
    // ---------------------------------------------------------------------------

    // type:string with null value must fail.
    // Ensures boon catches null values where a string is expected.
    #[test]
    fn schema_null_value_type_error() {
        let schema = serde_json::json!({ "type": "string" });
        assert!(
            check_schema(&serde_json::Value::Null, schema).is_err(),
            "type:string must reject null"
        );
    }

    // type:string with array value must fail.
    // Ensures boon catches array values where a string is expected.
    #[test]
    fn schema_array_value_type_error() {
        let schema = serde_json::json!({ "type": "string" });
        assert!(
            check_schema(&serde_json::json!([1, 2, 3]), schema).is_err(),
            "type:string must reject an array"
        );
    }

    // type:number accepts floats.
    // The type constraint "number" must accept floating-point values.
    #[test]
    fn schema_number_type_accepts_float() {
        let schema = serde_json::json!({ "type": "number" });
        assert!(
            check_schema(&serde_json::json!(1.5), schema).is_ok(),
            "type:number must accept a float value"
        );
    }

    // type:number rejects a string.
    #[test]
    fn schema_number_type_rejects_string() {
        let schema = serde_json::json!({ "type": "number" });
        assert!(
            check_schema(&serde_json::json!("not-a-number"), schema).is_err(),
            "type:number must reject a string"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: RevisionMismatch must return 409, not 500
    // ---------------------------------------------------------------------------

    // store_err_cr must map StoreError::RevisionMismatch to 409 Conflict.
    // Before the fix this arm fell through to the `other` branch and returned 500,
    // which misleads clients into thinking the server is broken rather than indicating
    // that they need to re-fetch and retry with the current resourceVersion.
    #[tokio::test]
    async fn replace_cr_with_wrong_resource_version_returns_409() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "rv-widget".to_string();

        // Create the CR — this assigns resourceVersion 1 (or similar).
        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with resourceVersion: "999" — a non-zero value that won't match.
        // The store will reject this with StoreError::RevisionMismatch, which must
        // produce HTTP 409 (Conflict), not 500 (Internal Server Error).
        // (resourceVersion "0" would produce AlreadyExists, not RevisionMismatch.)
        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name, "resourceVersion": "999" },
                "spec": { "color": "green" }
            })
            .to_string(),
        );

        let result = replace_cr(
            State(state.clone()),
            Path((group.clone(), version.clone(), plural.clone(), name.clone())),
            test_user(),
            axum::http::HeaderMap::new(),
            update_body,
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err for wrong resourceVersion"),
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 409,
            "revision mismatch must return 409 Conflict, not 500 (got: {json})"
        );
        assert_eq!(
            json["reason"], "Conflict",
            "reason must be Conflict (got: {json})"
        );
    }

    // A stale-resourceVersion replace_cr PUT whose body diverges from the freshly-stored CR on
    // a CEL-immutable field (because another writer's concurrent update changed it) must return
    // 409 Conflict, not 422 Unprocessable Entity. Mirrors pods.rs's
    // replace_pod_returns_409_not_422_when_stale_put_diverges_on_nodename and the original
    // resource.rs fix, applied to the identical CR-replace race. Without checking
    // resourceVersion before validate_cr_schema's CEL oldSelf comparison, a client that read
    // the widget before another writer's concurrent color change
    // — and PUTs its own now-stale copy back, never intending to touch color at all — gets its
    // stale color misclassified as a client-initiated violation of the CRD's `self == oldSelf`
    // rule. A 422 here is a permanent failure client-go's Update-on-conflict loop never retries;
    // 409 is the signal that tells it to re-GET and resubmit against the current object.
    #[tokio::test]
    async fn replace_cr_returns_409_not_422_when_stale_put_diverges_on_cel_immutable_field() {
        let state = make_state();
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": {
                                            "color": {
                                                "type": "string",
                                                "x-kubernetes-validations": [{
                                                    "rule": "self == oldSelf",
                                                    "message": "color is immutable"
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install CRD with immutability CEL rule"
        );

        let name = "race-widget".to_string();
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Widget",
                        "metadata": { "name": &name },
                        "spec": { "color": "blue" }
                    })
                    .to_string()
                ),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let key = cr_store_key("example.io", "widgets", None, &name);
        let rv0 = state.store.get(&key).await.unwrap().unwrap().revision;

        // Simulate a concurrent writer's legitimate update landing between the stale client's
        // GET (at rv0) and its PUT below: color changes from blue to green.
        let concurrent_update = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": &name, "resourceVersion": rv0.to_string() },
            "spec": { "color": "green" }
        });
        state
            .store
            .put(
                &key,
                Bytes::from(serde_json::to_vec(&concurrent_update).unwrap()),
                Some(rv0),
            )
            .await
            .expect("simulated concurrent update");

        // The stale client's PUT: still carries the pre-race color (blue) it read at rv0. It
        // never intended to touch color at all.
        let stale_put = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": &name, "resourceVersion": rv0.to_string() },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        let err = expect_err_status(
            replace_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                stale_put,
            )
            .await,
            "a stale-resourceVersion PUT racing a concurrent color change must be rejected",
        );

        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "a stale-resourceVersion PUT racing a concurrent CEL-immutable field change must \
             return 409 Conflict (retryable) — a 422 here permanently fails the caller instead \
             of letting it re-GET and resubmit against the now-current object"
        );
    }

    // replace_cr_namespaced with a stale resourceVersion must return 409 Conflict.
    // Optimistic concurrency control (OCC) protects against lost updates: if a client sends
    // a PUT with a resourceVersion that no longer matches the stored revision, the server
    // must reject the write with 409 rather than silently overwriting concurrent changes.
    #[tokio::test]
    async fn replace_cr_namespaced_with_stale_resource_version_returns_409() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "occ-app".to_string();

        // Create the CR — this assigns an initial resourceVersion.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Attempt replace with resourceVersion: "999" — a non-zero value that won't match
        // the actual stored revision. The store rejects this with RevisionMismatch, which
        // must produce HTTP 409 (not 500). Using "0" would yield AlreadyExists instead.
        let stale_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns, "resourceVersion": "999" },
                "spec": { "destination": { "namespace": "production" } }
            })
            .to_string(),
        );

        let err = expect_err_status(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    group.clone(),
                    version.clone(),
                    ns.clone(),
                    plural.clone(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                stale_body,
            )
            .await,
            "replace with stale resourceVersion must return 409",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 409,
            "stale resourceVersion must return 409 Conflict (got: {json})"
        );
        assert_eq!(
            json["reason"], "Conflict",
            "reason must be Conflict (got: {json})"
        );
    }

    // Namespaced counterpart of
    // replace_cr_returns_409_not_422_when_stale_put_diverges_on_cel_immutable_field: verifies
    // replace_cr_namespaced independently, since it is a distinct code path from replace_cr
    // (own key derivation, own stored-object read) that could regress separately even if
    // replace_cr's ordering is fixed.
    #[tokio::test]
    async fn replace_cr_namespaced_returns_409_not_422_when_stale_put_diverges_on_cel_immutable_field(
    ) {
        let state = make_state();
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gadgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "gadgets",
                        "singular": "gadget",
                        "kind": "Gadget",
                        "listKind": "GadgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "spec": {
                                        "type": "object",
                                        "properties": {
                                            "color": {
                                                "type": "string",
                                                "x-kubernetes-validations": [{
                                                    "rule": "self == oldSelf",
                                                    "message": "color is immutable"
                                                }]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        );
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                crd_bytes
            )
            .await
            .is_ok(),
            "install namespaced CRD with immutability CEL rule"
        );

        let ns = "default".to_string();
        let name = "race-gadget".to_string();
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    ns.clone(),
                    "gadgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::from(
                    serde_json::json!({
                        "apiVersion": "example.io/v1",
                        "kind": "Gadget",
                        "metadata": { "name": &name, "namespace": &ns },
                        "spec": { "color": "blue" }
                    })
                    .to_string()
                ),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let key = cr_store_key("example.io", "gadgets", Some(&ns), &name);
        let rv0 = state.store.get(&key).await.unwrap().unwrap().revision;

        // Simulate a concurrent writer's legitimate update landing between the stale client's
        // GET (at rv0) and its PUT below: color changes from blue to green.
        let concurrent_update = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Gadget",
            "metadata": { "name": &name, "namespace": &ns, "resourceVersion": rv0.to_string() },
            "spec": { "color": "green" }
        });
        state
            .store
            .put(
                &key,
                Bytes::from(serde_json::to_vec(&concurrent_update).unwrap()),
                Some(rv0),
            )
            .await
            .expect("simulated concurrent update");

        // The stale client's PUT: still carries the pre-race color (blue) it read at rv0. It
        // never intended to touch color at all.
        let stale_put = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Gadget",
                "metadata": { "name": &name, "namespace": &ns, "resourceVersion": rv0.to_string() },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        let err = expect_err_status(
            replace_cr_namespaced(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    ns.clone(),
                    "gadgets".to_string(),
                    name.clone(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                stale_put,
            )
            .await,
            "a stale-resourceVersion PUT racing a concurrent color change must be rejected",
        );

        assert_eq!(
            err.0,
            StatusCode::CONFLICT,
            "a stale-resourceVersion PUT racing a concurrent CEL-immutable field change must \
             return 409 Conflict (retryable) — a 422 here permanently fails the caller instead \
             of letting it re-GET and resubmit against the now-current object"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: empty-group list response must not produce "/v1alpha1" apiVersion
    // ---------------------------------------------------------------------------

    // build_list_response must produce apiVersion="v1alpha1" (not "/v1alpha1") when group="".
    // A leading slash in apiVersion is malformed and breaks kubectl and client-go parsing.
    // The old inlined `format!("{group}/{version}")` did not check for empty group; delegating
    // to build_list_response fixes this because that function has the guard:
    //   if group.is_empty() { version } else { format!("{}/{}", group, version) }
    #[test]
    fn build_list_response_empty_group_omits_slash() {
        let signing_key: &[u8; 32] = b"test-signing-key-32-bytes-padded";
        let body = super::super::generic::build_list_response(
            "Foo",
            "", // empty group
            "v1alpha1",
            42,
            vec![],
            None,
            None,
            signing_key,
        );
        let api_version = body["apiVersion"].as_str().unwrap_or("");
        assert_eq!(
            api_version, "v1alpha1",
            "empty group must produce apiVersion=\"v1alpha1\", not \"/v1alpha1\" (got: {api_version:?})"
        );
        assert_eq!(
            body["kind"].as_str().unwrap_or(""),
            "FooList",
            "kind must be <Kind>List"
        );
    }

    // Verify that list_cr routes through build_list_response by checking that a normal
    // (non-empty group) list response has the correct apiVersion format.
    // This is an integration smoke test for the code path — the unit test above verifies
    // the empty-group behavior directly.
    #[tokio::test]
    async fn list_cr_response_has_correct_api_version() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let api_version = body["apiVersion"].as_str().unwrap_or("");
        assert_eq!(
            api_version, "example.io/v1",
            "non-empty group must produce apiVersion=\"group/version\" (got: {api_version:?})"
        );
    }

    // -- CRD conversion webhook tests --

    /// When a CRD has only one version with storage:true and no conversion config,
    /// get_cr must return the stored object as-is even if the URL version differs.
    /// This is the no-conversion baseline: stored version == requested version.
    #[tokio::test]
    async fn get_cr_same_version_no_conversion() {
        let state = make_state();

        // Single-version CRD (v1 is both storage and requested).
        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
                "scope": "Cluster",
                "versions": [{"name": "v1", "served": true, "storage": true}]
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Store a widget under v1.
        let widget = serde_json::json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": {"name": "my-widget"},
            "spec": {"color": "blue"}
        });
        state
            .store
            .put(
                "/registry/cr/example.com/widgets/my-widget",
                bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
                None,
            )
            .await
            .unwrap();

        // GET the widget at v1 — same as storage version, no conversion needed.
        let resp = match get_cr(
            State(state),
            Path((
                "example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["spec"]["color"], "blue",
            "stored object must be returned unchanged"
        );
    }

    /// When a CRD has two versions (v1alpha1 as storage, v1 as served) and no conversion
    /// webhook is configured, GET for v1 must fall back to the v1alpha1 stored object
    /// and return it as-is. This is the no-webhook-conversion case.
    #[tokio::test]
    async fn get_cr_different_version_no_webhook_returns_stored_object() {
        let state = make_state();

        // CRD with v1alpha1 (storage) and v1 (served), no conversion webhook.
        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "widgets", "singular": "widget", "kind": "Widget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ]
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Store widget under v1alpha1 (the storage version).
        let widget = serde_json::json!({
            "apiVersion": "example.com/v1alpha1",
            "kind": "Widget",
            "metadata": {"name": "my-widget"},
            "spec": {"color": "blue"}
        });
        state
            .store
            .put(
                "/registry/cr/example.com/widgets/my-widget",
                bytes::Bytes::from(serde_json::to_vec(&widget).unwrap()),
                None,
            )
            .await
            .unwrap();

        // GET at v1 — no conversion webhook, falls through to stored v1alpha1 object.
        // The stored object is returned as-is (no conversion attempted without webhook).
        let resp = match get_cr(
            State(state),
            Path((
                "example.com".into(),
                "v1".into(),
                "widgets".into(),
                "my-widget".into(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("get must succeed when no conversion is needed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Without a conversion webhook, the v1alpha1 stored data is returned unchanged.
        assert_eq!(
            body["spec"]["color"], "blue",
            "stored v1alpha1 object must be returned when no webhook is configured"
        );
    }

    /// find_crd extracts conversion webhook clientConfig when strategy is Webhook.
    /// If this is wrong, the conversion webhook call is skipped or uses the wrong endpoint.
    #[tokio::test]
    async fn find_crd_extracts_conversion_webhook_config() {
        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "gadgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ],
                "conversion": {
                    "strategy": "Webhook",
                    "webhook": {
                        "clientConfig": {
                            "url": "https://converter.example.com/convert"
                        }
                    }
                }
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/gadgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ctx = match find_crd(&state, "example.com", "v1", "gadgets").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed for a matching CRD"),
        };
        assert!(
            ctx.conversion_webhook_client_config.is_some(),
            "find_crd must extract conversion webhook clientConfig when strategy=Webhook"
        );
        let cfg = ctx.conversion_webhook_client_config.unwrap();
        assert_eq!(
            cfg["url"].as_str(),
            Some("https://converter.example.com/convert"),
            "clientConfig URL must be extracted correctly"
        );
    }

    // ---------------------------------------------------------------------------
    // call_conversion_webhook error paths
    // ---------------------------------------------------------------------------

    /// Start an axum router on a random local TCP port and return the base URL.
    /// The server runs until the returned JoinHandle is dropped/aborted.
    async fn start_mock_conversion_server(
        router: axum::Router,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock server must not fail");
        });
        (format!("http://{addr}"), handle)
    }

    fn make_state_for_conversion() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(
            store,
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        )
    }

    /// call_conversion_webhook must return Err when the response includes
    /// result.status="Failure". Conversion webhooks that reject the request
    /// (e.g. unsupported conversion direction) must propagate as errors so
    /// the apiserver rejects the client request rather than returning corrupt data.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_failure_status() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": "test-uid",
                        "result": {
                            "status": "Failure",
                            "message": "unsupported conversion direction"
                        }
                    }
                }))
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when result.status=Failure"
        );
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("unsupported conversion direction"),
            "error must include the webhook's failure message"
        );
    }

    /// call_conversion_webhook must return Err when the webhook returns an empty
    /// convertedObjects array. Receiving 0 objects for N input objects is semantically
    /// invalid — the caller has no objects to serve and cannot proceed.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_when_converted_objects_empty() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                axum::Json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": "test-uid",
                        "result": { "status": "Success" },
                        "convertedObjects": []  // empty — must be rejected
                    }
                }))
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when convertedObjects is empty"
        );
    }

    /// call_conversion_webhook must return Err when the HTTP call fails (bad URL).
    /// Network errors must be propagated as errors — callers must not silently
    /// succeed with the unconverted objects.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_http_failure() {
        let state = make_state_for_conversion();
        // Port 1 is never open — connection will be refused immediately.
        let client_config = serde_json::json!({ "url": "http://127.0.0.1:1/convert" });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when HTTP call fails (bad URL)"
        );
    }

    /// Reproduces the conformance-test race this fix targets: a webhook Service's
    /// ClusterIP refuses connections for the first tens of milliseconds after creation,
    /// before kube-proxy finishes programming the ClusterIP -> PodIP NAT rule, then
    /// starts accepting once the rule lands. Without the bounded retry in
    /// `send_webhook_request_with_retry`, the call against a not-yet-routable target
    /// fails outright; with it, the call recovers within the retry budget.
    #[tokio::test]
    async fn call_conversion_webhook_recovers_from_transient_connect_refused() {
        use axum::routing::post;
        use axum::Router;
        use tokio::net::TcpListener;

        // Reserve a port, then release it immediately — nothing is listening yet, so
        // the first attempt(s) against it see connection-refused, mirroring a freshly
        // created Service whose ClusterIP NAT rule kube-proxy hasn't programmed yet.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let router = Router::new().route(
                "/convert",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": [{"apiVersion": "example.io/v2", "kind": "Widget"}]
                        }
                    }))
                }),
            );
            let listener = TcpListener::bind(addr)
                .await
                .expect("rebind the released port for the delayed webhook server");
            axum::serve(listener, router)
                .await
                .expect("delayed webhook server must not fail");
        });

        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("http://{addr}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;

        assert!(
            result.is_ok(),
            "call_conversion_webhook must retry through a transient connection-refused \
             window and succeed once the target becomes reachable within the retry \
             budget — without the retry, a webhook Service that refuses connections for \
             even a few tens of milliseconds after creation (the kube-proxy \
             IPVS-programming race) fails the call outright: {:?}",
            result.err()
        );
    }

    /// call_conversion_webhook must return Err when the response is not valid JSON.
    /// A webhook returning malformed bytes (e.g. a 500 HTML error page) must not
    /// panic or silently succeed — it must be detected and rejected.
    #[tokio::test]
    async fn call_conversion_webhook_returns_err_on_malformed_json_response() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                // Return plain text, not JSON — simulates an upstream error page.
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error (not JSON)",
                )
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when response is not valid JSON"
        );
    }

    /// call_conversion_webhook must ask the webhook for JSON via an explicit Accept header,
    /// not rely on the HTTP client's default (reqwest sends a bare `Accept: */*`).
    ///
    /// WHY this matters: real conversion webhooks — including the k8s conformance suite's
    /// sample webhook (test/images/agnhost/crd-conversion-webhook) — content-negotiate their
    /// response encoding from Accept, and treat a bare `*/*` as license to reply in whatever
    /// encoding they land on, including non-JSON (that webhook falls back to YAML). A LIST
    /// across CR versions sends every non-matching item to the webhook in ONE call; if the
    /// webhook picks a non-JSON encoding for that response, u7s can't parse it and the whole
    /// LIST 500s with "conversion webhook response JSON parse error" — even though every
    /// object was perfectly convertible. This is a live regression: a v1 LIST
    /// of CRs stored as v2 failed exactly this way. The mock below reproduces the real
    /// webhook's negotiation fork (JSON only on an explicit `application/json` Accept) so
    /// reverting the Accept header on the request re-triggers it here.
    #[tokio::test]
    async fn call_conversion_webhook_sends_explicit_json_accept_so_multi_object_list_conversion_succeeds(
    ) {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(
                |headers: HeaderMap, axum::Json(review): axum::Json<serde_json::Value>| async move {
                    let accept = headers
                        .get(axum::http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let converted: Vec<serde_json::Value> = objects
                        .into_iter()
                        .map(|mut o| {
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o
                        })
                        .collect();
                    // Only reply JSON when Accept explicitly names it — same fork the real
                    // sample webhook takes (it falls back to YAML for a bare `*/*`).
                    if accept
                        .split(',')
                        .any(|p| p.trim().starts_with("application/json"))
                    {
                        axum::Json(serde_json::json!({
                            "apiVersion": "apiextensions.k8s.io/v1",
                            "kind": "ConversionReview",
                            "response": {
                                "uid": "test-uid",
                                "result": {"status": "Success"},
                                "convertedObjects": converted
                            }
                        }))
                        .into_response()
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "application/yaml")],
                            "apiVersion: apiextensions.k8s.io/v1\nkind: ConversionReview\n"
                                .to_string(),
                        )
                            .into_response()
                    }
                },
            ),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        // Two objects — a LIST sends every item needing conversion in a single call.
        let objects = vec![
            serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget", "metadata": {"name": "a"}}),
            serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget", "metadata": {"name": "b"}}),
        ];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        let converted = result.expect(
            "call_conversion_webhook must send an explicit JSON Accept header so a real \
             webhook's content negotiation returns JSON instead of an arbitrary non-JSON \
             encoding — without it, every cross-version CR LIST/GET 500s with a JSON parse \
             error the moment the webhook picks something other than JSON",
        );
        assert_eq!(
            converted.len(),
            2,
            "both objects sent for conversion must come back, not just the first — a LIST's \
             conversion response covers every non-matching item in one call"
        );
        for obj in &converted {
            assert_eq!(obj["apiVersion"], "example.io/v2");
        }
    }

    /// call_conversion_webhook must return Err when the response body exceeds 1 MiB.
    ///
    /// Without the size cap, resp.bytes().await accumulates the full response — a
    /// compromised or misbehaving conversion webhook can return a gigabyte and exhaust
    /// apiserver memory. Returning Err here causes the CR request to fail with 500,
    /// which is safer than OOM-killing the apiserver.
    #[tokio::test]
    async fn call_conversion_webhook_rejects_oversized_response() {
        use axum::routing::post;
        use axum::Router;

        // Return 2 MiB of data to exceed the 1 MiB cap.
        let router = Router::new().route(
            "/convert",
            post(|| async {
                let two_mb = "x".repeat(2 * 1024 * 1024);
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    format!("\"{}\"", two_mb),
                )
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "call_conversion_webhook must return Err when response body exceeds 1 MiB — \
             without the size cap, a malicious webhook can exhaust apiserver memory"
        );
    }

    /// call_conversion_webhook must trust the conversion webhook's OWN caBundle, not just
    /// the u7s cluster CA. Real conversion webhooks (and the upstream conformance suite's
    /// converter pod) serve TLS with a self-signed CA carried in
    /// `clientConfig.caBundle` — if the conversion client only trusted the cluster CA (the
    /// bug), the TLS handshake against every such webhook fails and CRD conversion is
    /// 100% non-functional for any real backend, exactly as seen in the
    /// CustomResourceConversionWebhook conformance failures.
    #[tokio::test]
    async fn call_conversion_webhook_trusts_webhook_ca_bundle_over_cluster_ca() {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::ServerConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        // generate_tls() installs this at real startup; a test that builds a live
        // rustls::ServerConfig directly needs it too. Idempotent (see tls.rs).
        rustls_post_quantum::provider().install_default().ok();

        // The webhook's own self-signed cert — what a real conversion webhook presents.
        let webhook_cert = generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("generate self-signed webhook cert");
        let webhook_cert_der = webhook_cert.cert.der().to_vec();
        let webhook_key_der = webhook_cert.signing_key.serialize_der();

        // A *different* CA standing in for the u7s cluster CA. Pinning only to this one
        // (the pre-fix bug) must NOT be sufficient to complete the handshake below.
        let cluster_cert = generate_simple_self_signed(vec!["cluster.local".to_string()])
            .expect("generate stand-in cluster CA cert");
        let cluster_ca_der = cluster_cert.cert.der().to_vec();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(webhook_cert_der.clone())],
                PrivateKeyDer::try_from(webhook_key_der).expect("valid PKCS8 key"),
            )
            .expect("build server TLS config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let mut stream = acceptor.accept(tcp).await.expect("complete TLS handshake");
            let mut buf = [0u8; 8192];
            let _ = stream
                .read(&mut buf)
                .await
                .expect("read ConversionReview request");

            let body = serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "ConversionReview",
                "response": {
                    "uid": "test-uid",
                    "result": {"status": "Success"},
                    "convertedObjects": [{"apiVersion": "example.io/v2", "kind": "Widget"}]
                }
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write ConversionReview response");
        });

        // Base64(PEM) — the exact shape of CustomResourceConversion.webhook.clientConfig.caBundle.
        let pem = {
            let b64_der = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &webhook_cert_der,
            );
            let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64_der.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str("-----END CERTIFICATE-----\n");
            pem
        };
        let ca_bundle_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pem.as_bytes());

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new_with_config(crate::state::AppStateConfig {
            store,
            sa_key: None,
            sa_decoding_key: None,
            token_map: std::collections::HashMap::new(),
            server_address: "https://localhost:6443".into(),
            cluster_ca_der: Some(cluster_ca_der),
            webhook_identity_pem: None,
            service_ip_allocator: None,
            kubelet_client_identity_pem: None,
            kubelet_preferred_address: None,
            kubelet_port: 10250,
            continue_token_key: None,
            konnectivity_proxy_addr: None,
            sa_public_key_pem: None,
        });

        let client_config = serde_json::json!({
            "url": format!("https://{addr}/convert"),
            "caBundle": ca_bundle_b64,
        });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;

        assert!(
            result.is_ok(),
            "call_conversion_webhook must trust clientConfig.caBundle (the webhook's own \
             CA), not only the cluster CA — otherwise every real conversion webhook (which \
             ships its own serving cert) fails its TLS handshake and webhook-strategy CRD \
             conversion is 100% non-functional: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------------------
    // CrConversionCache
    // ---------------------------------------------------------------------------

    /// A conversion webhook that unconditionally sets every object's apiVersion to
    /// whatever `desiredAPIVersion` the caller asked for, counting invocations — so
    /// CrConversionCache tests can assert on the number of real HTTP round trips, not
    /// just on the cache's own internal bookkeeping.
    fn counting_conversion_router(call_count: Arc<std::sync::atomic::AtomicUsize>) -> axum::Router {
        use axum::routing::post;
        use std::sync::atomic::Ordering;

        axum::Router::new().route(
            "/convert",
            post(move |axum::Json(review): axum::Json<serde_json::Value>| {
                let call_count = Arc::clone(&call_count);
                async move {
                    call_count.fetch_add(1, Ordering::SeqCst);
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let converted: Vec<serde_json::Value> = objects
                        .into_iter()
                        .map(|mut o| {
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o
                        })
                        .collect();
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": converted
                        }
                    }))
                }
            }),
        )
    }

    /// Two independent conversion requests (e.g. two watchers, or a watcher plus a LIST)
    /// observing the SAME write (identical source resourceVersion) and asking for the SAME
    /// target version must share one webhook round trip, not pay for it twice — the entire
    /// point of CrConversionCache under N-way watch fan-out. Fails on revert: without the
    /// cache, convert_cr_list_items calls the webhook on every invocation regardless of
    /// whether an identical conversion was already computed, so N watchers of one write
    /// cost N webhook round trips instead of one.
    #[tokio::test]
    async fn cr_conversion_cache_shares_single_webhook_call_across_watchers_same_target_version_same_rv(
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(counting_conversion_router(Arc::clone(&call_count))).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        let source = || {
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "w", "resourceVersion": "5" }
            })
        };

        let mut items_a = vec![source()];
        convert_cr_list_items(&state, Some(&client_config), &mut items_a, "example.io/v2")
            .await
            .expect("first conversion must succeed");

        let mut items_b = vec![source()];
        convert_cr_list_items(&state, Some(&client_config), &mut items_b, "example.io/v2")
            .await
            .expect("second conversion must succeed");

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "a second caller converting the identical (resourceVersion, target apiVersion) \
             must hit the cache instead of re-invoking the webhook — this is the entire win \
             CrConversionCache exists to capture"
        );
        assert_eq!(
            state.cr_conversion_cache.entry_count(),
            1,
            "one (rv, target version) pair must produce exactly one cache entry"
        );
        assert!(
            state
                .cr_conversion_cache
                .contains(&("5".to_string(), "example.io/v2".to_string())),
            "the cache entry must be addressable by the exact (source rv, target version) \
             key convert_cr_list_items derives from the object's own stored fields"
        );
        assert_eq!(
            items_a[0]["apiVersion"], items_b[0]["apiVersion"],
            "both callers must observe the identical converted body, not just an identical \
             call count"
        );
    }

    /// The SAME source object+resourceVersion watched at two DIFFERENT target versions must
    /// convert independently — collapsing them into one cache entry would serve one
    /// client's v2 body to a client that asked for v3. Fails on revert to a key that omits
    /// (or mis-derives) target_api_version: the second call would wrongly hit the first
    /// call's cache entry, returning the wrong version's body without ever calling the
    /// webhook for v3.
    #[tokio::test]
    async fn cr_conversion_cache_uses_independent_entries_for_different_target_versions_same_source_object(
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(counting_conversion_router(Arc::clone(&call_count))).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        let source = || {
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "w", "resourceVersion": "5" }
            })
        };

        let mut items_v2 = vec![source()];
        convert_cr_list_items(&state, Some(&client_config), &mut items_v2, "example.io/v2")
            .await
            .expect("conversion to v2 must succeed");

        let mut items_v3 = vec![source()];
        convert_cr_list_items(&state, Some(&client_config), &mut items_v3, "example.io/v3")
            .await
            .expect("conversion to v3 must succeed");

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "two different target versions of the same source object must each call the \
             webhook — a shared cache entry would silently serve one version's body to \
             watchers of the other"
        );
        assert_eq!(
            state.cr_conversion_cache.entry_count(),
            2,
            "each (rv, target version) pair must own a distinct cache entry"
        );
        assert_eq!(items_v2[0]["apiVersion"], "example.io/v2");
        assert_eq!(items_v3[0]["apiVersion"], "example.io/v3");
    }

    /// A later write to the same object (a new resourceVersion) must never reuse the
    /// previous write's cached conversion — otherwise a watcher observing the update would
    /// be served stale pre-write content under the guise of a fresh conversion. Fails on
    /// revert to a key that omits resourceVersion (or ignores it): the second call would
    /// wrongly hit the first write's entry and never re-invoke the webhook for the new
    /// content.
    #[tokio::test]
    async fn cr_conversion_cache_invalidates_on_write_new_rv_triggers_fresh_conversion() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(counting_conversion_router(Arc::clone(&call_count))).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        let mut items_rv5 = vec![serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "w", "resourceVersion": "5" },
            "spec": { "color": "blue" }
        })];
        convert_cr_list_items(
            &state,
            Some(&client_config),
            &mut items_rv5,
            "example.io/v2",
        )
        .await
        .expect("conversion of rv 5 must succeed");

        // Simulate a subsequent write: the store stamps a new resourceVersion on every
        // write (see CrConversionCache's doc comment), so a real second write produces a
        // body whose own metadata.resourceVersion has advanced past "5".
        let mut items_rv6 = vec![serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "w", "resourceVersion": "6" },
            "spec": { "color": "red" }
        })];
        convert_cr_list_items(
            &state,
            Some(&client_config),
            &mut items_rv6,
            "example.io/v2",
        )
        .await
        .expect("conversion of rv 6 must succeed");

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "a write producing a new resourceVersion must trigger a fresh webhook call, \
             not reuse the previous write's cached conversion"
        );
        assert_eq!(
            state.cr_conversion_cache.entry_count(),
            2,
            "the old and new resourceVersion must each own an independent cache entry — \
             no cross-entry contamination"
        );
        assert_eq!(
            items_rv5[0]["spec"]["color"], "blue",
            "the rv-5 entry must still reflect rv 5's own content"
        );
        assert_eq!(
            items_rv6[0]["spec"]["color"], "red",
            "the rv-6 entry must reflect rv 6's own content, not rv 5's cached body"
        );
    }

    /// Belt-and-suspenders precondition check backing CrConversionCache's cache-key
    /// rationale: after a real CR write, the object's OWN stored metadata.resourceVersion
    /// (what convert_cr_list_items keys the cache on) must equal the store's revision
    /// counter for the write that produced it. If this ever drifted — e.g. a future
    /// storage refactor stopped stamping it on write — the cache would key on a value that
    /// no longer identifies "this exact write", and a hit could silently serve a
    /// conversion computed for different content. See `crates/store/src/sqlite.rs`'s
    /// `stamp_resource_version`, called from `put_sync` on every write independent of
    /// anything the CR handler itself puts in the body.
    #[tokio::test]
    async fn cr_conversion_cache_precondition_stored_metadata_rv_matches_store_counter() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = create_cr(
            State(state.clone()),
            Path(("example.io".into(), "v1".into(), "widgets".into())),
            test_user(),
            axum::http::HeaderMap::new(),
            widget_body("precondition-widget"),
        )
        .await
        .expect("create must succeed")
        .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let response_rv = response_val["metadata"]["resourceVersion"]
            .as_str()
            .expect("create response must include resourceVersion");

        let key = "/registry/cr/example.io/widgets/precondition-widget";
        let stored = state
            .store
            .get(key)
            .await
            .unwrap()
            .expect("object must exist in the store after create");
        let stored_obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let stamped_rv = stored_obj["metadata"]["resourceVersion"]
            .as_str()
            .expect("stored bytes must carry a stamped metadata.resourceVersion");

        assert_eq!(
            stamped_rv, response_rv,
            "the raw bytes actually persisted by the write must carry the SAME \
             metadata.resourceVersion the write's own HTTP response reported — a later \
             LIST/watch reads this exact field back off stored bytes, so a mismatch here \
             would mean CrConversionCache keys on a value the write itself never produced"
        );
        assert_eq!(
            stamped_rv,
            stored.revision.to_string(),
            "the stamped resourceVersion must equal the store's own revision counter for \
             this key — the invariant CrConversionCache's cache-key safety depends on (see \
             bd memory store-revision-counter-monotonic-never-reused)"
        );
    }

    /// Deleting a CR must evict every `cr_conversion_cache` entry keyed on its own rv —
    /// without this, a long-running cluster with heavy CR churn accumulates one
    /// unreachable cache entry per (write, watched target version) forever, since a
    /// deleted object's rv can never be looked up again (see
    /// `store-revision-counter-monotonic-never-reused`). Fails on revert: without the
    /// eviction call, the entries inserted below survive the delete untouched.
    #[tokio::test]
    async fn cr_conversion_cache_evicts_on_cr_delete_removes_matching_rv_entries() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            widget_body("evict-on-delete-widget"),
        )
        .await
        .expect("create must succeed")
        .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let rv = created["metadata"]["resourceVersion"]
            .as_str()
            .expect("create response must include resourceVersion")
            .to_string();

        // Two entries under the deleted object's own rv, at different target versions —
        // exactly what two watchers of different served versions would have cached for
        // this write.
        state.cr_conversion_cache.insert(
            (rv.clone(), "example.io/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v2"})),
        );
        state.cr_conversion_cache.insert(
            (rv.clone(), "example.io/v3".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v3"})),
        );
        // An entry under a DIFFERENT rv (a different write) must survive this delete —
        // eviction must be scoped to the deleted object's own rv, not a blanket clear.
        state.cr_conversion_cache.insert(
            ("999".to_string(), "example.io/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v2"})),
        );

        delete_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "evict-on-delete-widget".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete must succeed");

        assert!(
            !state
                .cr_conversion_cache
                .contains(&(rv.clone(), "example.io/v2".to_string())),
            "deleting the CR must evict every cache entry keyed on its own rv — otherwise \
             this entry can never be reclaimed even though it can never be served again"
        );
        assert!(
            !state
                .cr_conversion_cache
                .contains(&(rv, "example.io/v3".to_string())),
            "eviction on delete must cover every target-version entry cached under the \
             deleted object's rv, not just the first one found"
        );
        assert!(
            state
                .cr_conversion_cache
                .contains(&("999".to_string(), "example.io/v2".to_string())),
            "an entry cached under a DIFFERENT write's rv must survive this delete — \
             eviction must be scoped to the deleted object's own rv only, never a blanket \
             clear of the whole cache"
        );
    }

    /// An ordinary UPDATE (not just hard-delete) must evict `cr_conversion_cache` entries
    /// keyed on the object's PREVIOUS rv. Without this, a CRD that is never deleted (the
    /// common case) never has any of its historical entries cleaned up: every write mints
    /// a new rv, permanently orphaning the previous one's cache entries for the life of
    /// the process. Fails on revert: without the eviction call, the entry inserted below
    /// under the pre-update rv survives the replace untouched.
    #[tokio::test]
    async fn cr_conversion_cache_evicts_previous_rv_on_replace_cr_update() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            widget_body("evict-on-update-widget"),
        )
        .await
        .expect("create must succeed")
        .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let old_rv = created["metadata"]["resourceVersion"]
            .as_str()
            .expect("create response must include resourceVersion")
            .to_string();

        // What a watcher of a different served version would have cached for the create.
        state.cr_conversion_cache.insert(
            (old_rv.clone(), "example.io/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v2"})),
        );
        // An entry under a DIFFERENT rv (a different write) must survive this update —
        // eviction must be scoped to the superseded rv only, never a blanket clear.
        state.cr_conversion_cache.insert(
            ("999".to_string(), "example.io/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v2"})),
        );

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "evict-on-update-widget" },
                "spec": { "color": "red" }
            })
            .to_string(),
        );
        replace_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "evict-on-update-widget".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            update_body,
        )
        .await
        .expect("replace must succeed");

        assert!(
            !state
                .cr_conversion_cache
                .contains(&(old_rv, "example.io/v2".to_string())),
            "a successful UPDATE must evict cache entries keyed on the object's PREVIOUS \
             rv — otherwise a CRD that is never deleted never has any of its historical \
             entries cleaned up, even though the update just made this one unreachable"
        );
        assert!(
            state
                .cr_conversion_cache
                .contains(&("999".to_string(), "example.io/v2".to_string())),
            "an entry cached under a DIFFERENT write's rv must survive this update — \
             eviction must be scoped to the superseded rv only"
        );
    }

    /// Same as the replace_cr case above, but for PATCH — a distinct code path (captures
    /// its pre-patch snapshot differently) that must independently evict the superseded
    /// rv's cache entries on a successful merge-patch UPDATE.
    #[tokio::test]
    async fn cr_conversion_cache_evicts_previous_rv_on_patch_cr_update() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let resp = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            widget_body("evict-on-patch-widget"),
        )
        .await
        .expect("create must succeed")
        .into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let old_rv = created["metadata"]["resourceVersion"]
            .as_str()
            .expect("create response must include resourceVersion")
            .to_string();

        state.cr_conversion_cache.insert(
            (old_rv.clone(), "example.io/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "example.io/v2"})),
        );

        let patch_body =
            Bytes::from(serde_json::json!({ "spec": { "color": "purple" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        patch_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "evict-on-patch-widget".to_string(),
            )),
            test_user(),
            headers,
            patch_body,
        )
        .await
        .expect("patch must succeed");

        assert!(
            !state
                .cr_conversion_cache
                .contains(&(old_rv, "example.io/v2".to_string())),
            "a successful PATCH update must evict cache entries keyed on the object's \
             PREVIOUS rv, exactly like replace_cr — this is a separate code path with its \
             own pre-patch snapshot and must not be missed"
        );
    }

    /// Deleting a CRD must evict every `cr_conversion_cache` entry whose target apiVersion
    /// is one of that CRD's own versions — once a CRD is gone, none of its versions can
    /// ever be requested (or converted to) again, so those entries are permanently
    /// unreachable. Fails on revert: without the eviction call, entries A/v1 and A/v2
    /// below survive CRD A's deletion untouched.
    #[tokio::test]
    async fn cr_conversion_cache_evicts_on_crd_delete_removes_all_entries_for_that_crds_versions() {
        use crate::handlers::crd;

        let state = make_state();

        let crd_a = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gizmos.multiver.example.com" },
                "spec": {
                    "group": "multiver.example.com",
                    "names": {
                        "plural": "gizmos",
                        "singular": "gizmo",
                        "kind": "Gizmo",
                        "listKind": "GizmoList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true },
                        { "name": "v2", "served": true, "storage": false }
                    ]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_a,
        )
        .await
        .expect("install CRD A");

        let crd_b = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.other.example.com" },
                "spec": {
                    "group": "other.example.com",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_b,
        )
        .await
        .expect("install CRD B");

        state.cr_conversion_cache.insert(
            ("10".to_string(), "multiver.example.com/v1".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "multiver.example.com/v1"})),
        );
        state.cr_conversion_cache.insert(
            ("10".to_string(), "multiver.example.com/v2".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "multiver.example.com/v2"})),
        );
        state.cr_conversion_cache.insert(
            ("20".to_string(), "other.example.com/v1".to_string()),
            Arc::new(serde_json::json!({"apiVersion": "other.example.com/v1"})),
        );

        crd::delete_crd(
            State(state.clone()),
            Path("gizmos.multiver.example.com".to_string()),
            test_user(),
        )
        .await
        .expect("delete CRD A must succeed");

        assert!(
            !state
                .cr_conversion_cache
                .contains(&("10".to_string(), "multiver.example.com/v1".to_string())),
            "deleting CRD A must evict cache entries targeting its v1 — that version can \
             never be requested again once the CRD is gone"
        );
        assert!(
            !state
                .cr_conversion_cache
                .contains(&("10".to_string(), "multiver.example.com/v2".to_string())),
            "deleting CRD A must evict cache entries for EVERY one of its versions, not \
             just the first"
        );
        assert!(
            state
                .cr_conversion_cache
                .contains(&("20".to_string(), "other.example.com/v1".to_string())),
            "CRD B's entry must survive CRD A's deletion — eviction must be scoped to the \
             deleted CRD's own versions, never a blanket clear of the whole cache"
        );
    }

    /// Positive control for eviction: after an entry is evicted, converting the same
    /// (rv, target version) again must still work and produce the identical result as
    /// before — just via a fresh webhook call instead of a cache hit. This guards against
    /// an eviction bug that corrupts the cache-miss path itself (as opposed to evicting
    /// the wrong keys, which the other two eviction tests already cover).
    #[tokio::test]
    async fn cr_conversion_cache_no_regression_on_conversion_correctness_after_eviction() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(counting_conversion_router(Arc::clone(&call_count))).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        let source = || {
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "w", "resourceVersion": "5" }
            })
        };

        let mut items_before = vec![source()];
        convert_cr_list_items(
            &state,
            Some(&client_config),
            &mut items_before,
            "example.io/v2",
        )
        .await
        .expect("first conversion must succeed");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "first call must miss and webhook-convert"
        );

        state.cr_conversion_cache.invalidate_by_rv("5");
        assert!(
            !state
                .cr_conversion_cache
                .contains(&("5".to_string(), "example.io/v2".to_string())),
            "eviction must have actually removed the entry for this positive control to \
             mean anything"
        );

        let mut items_after = vec![source()];
        convert_cr_list_items(
            &state,
            Some(&client_config),
            &mut items_after,
            "example.io/v2",
        )
        .await
        .expect("conversion after eviction must still succeed");

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "with the entry evicted, the second call must be a fresh cache miss that \
             re-invokes the webhook rather than silently returning stale/absent data"
        );
        assert_eq!(
            items_before[0], items_after[0],
            "eviction must never change the CONTENT a client observes — the same source \
             object converted to the same target version must produce an identical body \
             whether served from cache or freshly computed after an eviction"
        );
    }

    /// Like `counting_conversion_router`, but sleeps `delay_ms` before responding — models
    /// a real conversion webhook's non-zero round-trip cost, needed so concurrent callers
    /// actually overlap the leader's in-flight window instead of racing so fast that one
    /// finishes (and populates the cache) before the next one even starts.
    fn delayed_counting_conversion_router(
        call_count: Arc<std::sync::atomic::AtomicUsize>,
        delay_ms: u64,
    ) -> axum::Router {
        use axum::routing::post;
        use std::sync::atomic::Ordering;

        axum::Router::new().route(
            "/convert",
            post(move |axum::Json(review): axum::Json<serde_json::Value>| {
                let call_count = Arc::clone(&call_count);
                async move {
                    call_count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let converted: Vec<serde_json::Value> = objects
                        .into_iter()
                        .map(|mut o| {
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o
                        })
                        .collect();
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": converted
                        }
                    }))
                }
            }),
        )
    }

    /// N concurrent callers racing the identical cold (rv, target version) key must produce
    /// exactly ONE webhook call, not N. This is the thundering-herd pathology
    /// this benchmark measured empirically (100% herd: N callers -> N calls, at every
    /// N and delay tested, zero exceptions) — a plain `RwLock<HashMap>` cache like
    /// `CrConversionCache`'s eliminates redundant calls for STAGGERED callers (see the test
    /// above) but does nothing for callers that all miss before any of them has inserted.
    /// A real conversion webhook is not free like the mock's `tokio::time::sleep` here — it
    /// is a real HTTP round trip against a service u7s doesn't control, so N-for-1 redundant
    /// calls is real load amplification, not just wasted CPU. Fails on revert: disabling the
    /// single-flight claim (verified manually by making `CrConversionCache::claim` always
    /// return `Leader`, so no caller ever waits on another's in-flight computation) reproduces
    /// the bench's 100-calls-for-100-racers result here too.
    #[tokio::test]
    async fn cr_conversion_cache_single_flight_coalesces_concurrent_gets_on_cold_key() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Barrier;

        const N: usize = 100;
        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) = start_mock_conversion_server(delayed_counting_conversion_router(
            Arc::clone(&call_count),
            20,
        ))
        .await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let barrier = Arc::new(Barrier::new(N));

        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let state = state.clone();
            let client_config = client_config.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut items = vec![serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "metadata": { "name": "w", "resourceVersion": "5" }
                })];
                convert_cr_list_items(&state, Some(&client_config), &mut items, "example.io/v2")
                    .await
                    .expect("conversion must succeed");
                items[0]["apiVersion"]
                    .as_str()
                    .expect("converted body must have a string apiVersion")
                    .to_string()
            }));
        }

        let mut results = Vec::with_capacity(N);
        for h in handles {
            results.push(h.await.expect("racer task must not panic"));
        }

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "{N} concurrent callers racing the identical cold (rv, target version) key must \
             coalesce into ONE webhook call via single-flight, not {N} — without this, every \
             watcher/LIST request observing one write's first conversion pays its own real \
             round trip against the (possibly rate-limited, non-free) conversion webhook"
        );
        assert!(
            results.iter().all(|v| v == "example.io/v2"),
            "every one of the {N} racers must still observe the correctly converted body, \
             not just a reduced call count — coalescing must never trade correctness for \
             fewer webhook calls"
        );
        assert_eq!(
            state.cr_conversion_cache.in_flight_count(),
            0,
            "once every racer has resolved, the single-flight registry must have no leaked \
             entry for this key — an orphaned entry would permanently stall any future \
             caller for this (rv, target version) pair"
        );
    }

    /// A leader whose webhook call fails must still release every waiter blocked on it —
    /// otherwise a single conversion failure would hang every concurrent watcher/LIST
    /// request observing the same write forever, turning a normal webhook error into a
    /// full request-handling deadlock. Bounded via `tokio::time::timeout`: an unbounded
    /// hang here is exactly the bug (a leader that errors without calling
    /// `notify_waiters` first) this test exists to catch, and the timeout makes such a
    /// regression a fast, obvious test failure rather than a wedged CI job.
    #[tokio::test]
    async fn cr_conversion_cache_leader_error_releases_waiters_without_hanging() {
        use axum::routing::post;
        use axum::Router;
        use tokio::sync::Barrier;

        const N: usize = 10;

        let router = Router::new().route(
            "/convert",
            post(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                axum::Json(serde_json::json!({
                    "apiVersion": "apiextensions.k8s.io/v1",
                    "kind": "ConversionReview",
                    "response": {
                        "uid": "test-uid",
                        "result": {
                            "status": "Failure",
                            "message": "conversion always fails in this test"
                        }
                    }
                }))
            }),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });
        let barrier = Arc::new(Barrier::new(N));

        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let state = state.clone();
            let client_config = client_config.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut items = vec![serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "metadata": { "name": "w", "resourceVersion": "5" }
                })];
                convert_cr_list_items(&state, Some(&client_config), &mut items, "example.io/v2")
                    .await
            }));
        }

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut results = Vec::with_capacity(N);
            for h in handles {
                results.push(h.await.expect("racer task must not panic"));
            }
            results
        })
        .await;

        let results = outcome.expect(
            "N callers racing a key whose leader always errors must all resolve (either by \
             seeing the error directly, or by waking from a failed leader's release and \
             re-claiming/re-erroring themselves) within a bounded time — a leader that errors \
             without notifying its waiters would leave every follower's `notified().await` \
             parked forever",
        );

        assert!(
            results.iter().all(|r| r.is_err()),
            "every caller must observe the webhook's failure — silently treating a \
             resolved-but-still-empty cache slot as success would serve stale/unconverted \
             objects to a client instead of surfacing the conversion error"
        );
        assert_eq!(
            state.cr_conversion_cache.in_flight_count(),
            0,
            "every leader across every retry round must release its slot on failure — a \
             leaked in_flight entry here would permanently orphan any future caller for \
             this key even after the webhook recovers"
        );
    }

    /// A conversion webhook that returns FEWER `convertedObjects` than requested (but still
    /// non-empty) must be rejected outright, not accepted as a partial success. Two items
    /// needing conversion collapse into one webhook call whose response the leader-resolve
    /// loop pairs up via `leader_indices.zip(converted).zip(leader_keys)` — `zip` silently
    /// truncates to the shortest iterator, so a 1-of-2 response used to leave the second
    /// leader key never reaching `resolve`/`guard.keys.clear()`. Fails on revert to
    /// `converted.is_empty()`: this response is non-empty, so the old check let it through,
    /// `convert_cr_list_items` returned `Ok(())`, and the second key (rv 11) was orphaned in
    /// `in_flight` — any future watcher/LIST racing that same (resourceVersion, target
    /// apiVersion) key would then `claim` a `Follow` and block on a `Notify` nobody will ever
    /// fire, hanging that request forever.
    #[tokio::test]
    async fn call_conversion_webhook_short_response_errors_and_releases_in_flight_keys() {
        use axum::routing::post;
        use axum::Router;

        let router = Router::new().route(
            "/convert",
            post(
                |axum::Json(review): axum::Json<serde_json::Value>| async move {
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    // Malformed webhook: only converts the first of the N requested objects.
                    let short: Vec<serde_json::Value> = objects
                        .into_iter()
                        .take(1)
                        .map(|mut o| {
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o
                        })
                        .collect();
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": short
                        }
                    }))
                },
            ),
        );

        let (base_url, _handle) = start_mock_conversion_server(router).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        // Two items, distinct resourceVersions, so both are cold (Leader) claims on the
        // same webhook call — the scenario the zip-truncation bug needs to fire.
        let mut items = vec![
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "a", "resourceVersion": "10" }
            }),
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "b", "resourceVersion": "11" }
            }),
        ];

        let result =
            convert_cr_list_items(&state, Some(&client_config), &mut items, "example.io/v2").await;

        let err = result.expect_err(
            "a webhook returning 1 converted object for 2 requested must be rejected — \
             silently accepting it truncates the leader-resolve loop and serves item 'b' \
             back unconverted to whatever LIST/watch triggered this call",
        );
        assert_eq!(
            err.0,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "a shape-mismatched webhook response must surface as a 500, the same failure \
             mode as every other conversion webhook error"
        );
        assert!(
            err.1.message.contains("returned 1") && err.1.message.contains("expected 2"),
            "the error must name the exact shape mismatch (1 returned vs 2 expected) so an \
             operator debugging a broken conversion webhook sees the discrepancy instead of \
             a generic failure: got {:?}",
            err.1.message
        );
        assert_eq!(
            state.cr_conversion_cache.in_flight_count(),
            0,
            "both (resourceVersion, target apiVersion) keys claimed as leader for this call \
             must be released on the error path — an entry left behind here means any future \
             concurrent caller for that same key (a second watcher, a retried LIST) blocks \
             forever on a Notify that nobody will ever fire"
        );
    }

    /// Positive control: a cache HIT must still be served purely from the plain
    /// `RwLock<HashMap>` fast path — the single-flight `claim`/`resolve` machinery added to
    /// coalesce cold-key misses must never be touched on a warm key. A regression that ran
    /// every lookup through `claim` (even redundantly, immediately followed by finding the
    /// fast-path hit) would add lock traffic and latency to the dominant, already-optimized
    /// hit path for no benefit — see `cr_conversion_fanout.rs`'s `cr_conversion_fanout_with_cache`
    /// bench group, whose numbers this change must not move since its code path is byte-for-byte
    /// unchanged by this fix.
    #[tokio::test]
    async fn cr_conversion_cache_no_regression_on_cache_hit_path() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let (base_url, _handle) =
            start_mock_conversion_server(counting_conversion_router(Arc::clone(&call_count))).await;
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({ "url": format!("{base_url}/convert") });

        let key = ("5".to_string(), "example.io/v2".to_string());
        let pre_converted = serde_json::json!({
            "apiVersion": "example.io/v2",
            "kind": "Widget",
            "metadata": { "name": "w", "resourceVersion": "5" }
        });
        state
            .cr_conversion_cache
            .insert(key.clone(), std::sync::Arc::new(pre_converted.clone()));

        let mut items = vec![serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "w", "resourceVersion": "5" }
        })];
        convert_cr_list_items(&state, Some(&client_config), &mut items, "example.io/v2")
            .await
            .expect("a pre-warmed cache entry must serve the request without error");

        assert_eq!(
            items[0], pre_converted,
            "a cache hit must return the exact cached body"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "a cache hit must never invoke the webhook — it should never even reach the \
             claim/resolve single-flight path"
        );
        assert_eq!(
            state.cr_conversion_cache.in_flight_count(),
            0,
            "a cache hit must never touch the single-flight registry — claim/resolve exist \
             only for the miss path, and any in-flight bookkeeping on a hit would be pure \
             unneeded overhead on the dominant request path"
        );
        assert_eq!(
            state.cr_conversion_cache.entry_count(),
            1,
            "a cache hit must not write a duplicate/redundant entry back into the cache"
        );
    }

    /// find_crd must NOT extract conversion config when strategy is None (no conversion).
    #[tokio::test]
    async fn find_crd_no_conversion_config_when_strategy_is_none() {
        let state = make_state();

        let crd = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "gadgets.example.com"},
            "spec": {
                "group": "example.com",
                "names": {"plural": "gadgets", "singular": "gadget", "kind": "Gadget"},
                "scope": "Cluster",
                "versions": [
                    {"name": "v1alpha1", "served": true, "storage": true},
                    {"name": "v1", "served": true, "storage": false}
                ],
                "conversion": {
                    "strategy": "None"
                }
            }
        });
        state
            .store
            .put(
                "/registry/apiextensions.k8s.io/customresourcedefinitions/gadgets.example.com",
                bytes::Bytes::from(serde_json::to_vec(&crd).unwrap()),
                None,
            )
            .await
            .unwrap();

        let ctx = match find_crd(&state, "example.com", "v1", "gadgets").await {
            Ok(c) => c,
            Err(_) => panic!("find_crd must succeed for a matching CRD"),
        };
        assert!(
            ctx.conversion_webhook_client_config.is_none(),
            "find_crd must not extract conversion config when strategy is not Webhook"
        );
    }

    // ---------------------------------------------------------------------------
    // PartialObjectMetadata media type negotiation
    // ---------------------------------------------------------------------------

    /// wants_partial_object_metadata must detect the kcm metadatainformer Accept header.
    /// The GC sends: application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,
    ///               application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json
    /// Without this detection the reflector gets full CR objects it can't decode as PartialObjectMetadata,
    /// causing it to restart without ever receiving the initial-events-end BOOKMARK.
    #[test]
    fn wants_pom_detects_partial_object_metadata_accept_header() {
        // Real kcm metadatainformer Accept header.
        let accept = "application/vnd.kubernetes.protobuf;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json";
        assert!(
            wants_partial_object_metadata(accept),
            "must detect as=PartialObjectMetadata in kcm metadatainformer Accept header"
        );
    }

    #[test]
    fn wants_pom_detects_partial_object_metadata_list() {
        let accept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
        assert!(
            wants_partial_object_metadata(accept),
            "must detect as=PartialObjectMetadataList"
        );
    }

    #[test]
    fn wants_pom_returns_false_for_plain_json() {
        assert!(
            !wants_partial_object_metadata("application/json"),
            "plain application/json must NOT trigger POM transformation"
        );
    }

    /// to_partial_object_metadata must strip spec/status and set the correct apiVersion/kind.
    /// The GC needs metadata (ownerReferences, finalizers) but not spec/status — sending full
    /// objects causes the reflector to fail decoding and never receive the initial-events-end BOOKMARK.
    #[test]
    fn to_pom_strips_spec_and_sets_correct_kind() {
        let full_cr = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "w1", "uid": "abc", "ownerReferences": [] },
            "spec": { "color": "blue" },
            "status": { "ready": true }
        });
        let pom = to_partial_object_metadata(&full_cr);
        assert_eq!(pom["apiVersion"], "meta.k8s.io/v1");
        assert_eq!(pom["kind"], "PartialObjectMetadata");
        assert_eq!(pom["metadata"]["name"], "w1");
        assert_eq!(pom["metadata"]["uid"], "abc");
        // spec and status must be absent — GC does not need them.
        assert!(
            pom.get("spec").is_none() || pom["spec"].is_null(),
            "spec must be absent in POM"
        );
        assert!(
            pom.get("status").is_none() || pom["status"].is_null(),
            "status must be absent in POM"
        );
    }

    /// LIST with as=PartialObjectMetadataList Accept header must return PartialObjectMetadataList
    /// with each item as PartialObjectMetadata (no spec). This is the critical path for the kcm
    /// garbage collector — it lists resources using this media type.
    #[tokio::test]
    async fn list_cr_with_pom_accept_returns_partial_object_metadata_list() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // Create a widget with spec so we can verify spec is stripped.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("pom-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let mut accept_headers = axum::http::HeaderMap::new();
        accept_headers.insert(
            axum::http::header::ACCEPT,
            "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
                .parse()
                .unwrap(),
        );

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            accept_headers,
            no_watch_query(),
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("list with POM accept must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(
            body["kind"], "PartialObjectMetadataList",
            "kind must be PartialObjectMetadataList when Accept requests POM"
        );
        assert_eq!(
            body["apiVersion"], "meta.k8s.io/v1",
            "apiVersion must be meta.k8s.io/v1 for POM list"
        );

        let items = body["items"].as_array().expect("items must be an array");
        assert_eq!(items.len(), 1, "must have exactly one item");
        assert_eq!(
            items[0]["kind"], "PartialObjectMetadata",
            "each item kind must be PartialObjectMetadata"
        );
        assert_eq!(
            items[0]["apiVersion"], "meta.k8s.io/v1",
            "each item apiVersion must be meta.k8s.io/v1"
        );
        assert_eq!(
            items[0]["metadata"]["name"], "pom-widget",
            "item metadata.name must be preserved"
        );
        assert!(
            items[0].get("spec").is_none() || items[0]["spec"].is_null(),
            "spec must be absent in PartialObjectMetadata item — GC does not need it \
             and its presence causes the reflector to fail decoding"
        );
    }

    /// WATCH with as=PartialObjectMetadata Accept header must emit ADDED events shaped as
    /// PartialObjectMetadata. Without this, the kcm reflector fails to decode the objects
    /// and the metadatainformer never syncs, blocking all GC-dependent controllers.
    #[tokio::test]
    async fn list_cr_watch_with_pom_accept_emits_partial_object_metadata_events() {
        let state = make_state();
        install_cluster_crd(&state).await;

        // Write a widget BEFORE subscribing so the ring buffer replays it.
        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("watch-pom-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Accept header as sent by kcm metadatainformer.
        let mut accept_headers = axum::http::HeaderMap::new();
        accept_headers.insert(
            axum::http::header::ACCEPT,
            "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1,application/json"
                .parse()
                .unwrap(),
        );

        // Use timeout_seconds=1 so the stream closes after 1s, allowing to_bytes to return
        // with the ring-buffer events. The stream stays open (correct behavior: the store
        // is kept alive for the stream's lifetime), so we need a bounded timeout.
        let query_with_timeout = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: Some(1),
        };

        let resp = match list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            accept_headers,
            query_with_timeout,
            "test-user".to_string(),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => panic!("watch with POM accept must succeed"),
        };

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "watch response must use chunked encoding"
        );

        // Read all events until the stream closes (timeout_seconds=1) or the 3-second guard.
        // The ring buffer replays the pre-existing widget as ADDED before the live-event wait.
        let body = resp.into_body();
        let bytes = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            axum::body::to_bytes(body, usize::MAX),
        )
        .await
        .unwrap_or(Ok(bytes::Bytes::new()))
        .unwrap_or_default();

        let text = std::str::from_utf8(&bytes).unwrap_or("");
        let events: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        // The ring buffer must replay the ADDED event for the pre-existing widget.
        let added: Vec<_> = events.iter().filter(|e| e["type"] == "ADDED").collect();
        assert!(
            !added.is_empty(),
            "POM watch must emit at least one ADDED event from ring buffer; \
             without it the GC metadatainformer cache never syncs"
        );
        assert_eq!(
            added[0]["object"]["kind"], "PartialObjectMetadata",
            "ADDED event object kind must be PartialObjectMetadata, not the full CR kind — \
             full objects cause the kcm reflector to fail decoding and restart"
        );
        assert_eq!(
            added[0]["object"]["apiVersion"], "meta.k8s.io/v1",
            "ADDED event object apiVersion must be meta.k8s.io/v1"
        );
        assert_eq!(
            added[0]["object"]["metadata"]["name"], "watch-pom-widget",
            "ADDED event metadata.name must match"
        );
        assert!(
            added[0]["object"].get("spec").is_none() || added[0]["object"]["spec"].is_null(),
            "spec must be absent in POM ADDED event — the kcm scheme does not know Gateway, Widget etc."
        );
    }

    // ---------------------------------------------------------------------------
    // store_err_cr unit tests — all four branches must map to the right status code
    // ---------------------------------------------------------------------------

    /// store_err_cr must map NotFound to 404. This is the error users see when a
    /// CR they try to GET or DELETE does not exist — returning 500 would mislead them.
    #[test]
    fn store_err_cr_not_found_returns_404() {
        let err = store_err_cr(
            u7s_store::StoreError::NotFound {
                key: "/registry/cr/example.io/v1/widgets/my-widget".into(),
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 404);
        assert_eq!(json["reason"], "NotFound");
    }

    /// store_err_cr must map AlreadyExists to 409. This is the error users see when
    /// they try to create a CR that already exists — 409 Conflict is the correct code.
    #[test]
    fn store_err_cr_already_exists_returns_409() {
        let err = store_err_cr(
            u7s_store::StoreError::AlreadyExists {
                key: "/registry/cr/example.io/v1/widgets/my-widget".into(),
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409);
        assert_eq!(json["reason"], "AlreadyExists");
    }

    /// store_err_cr must map RevisionMismatch to 409 Conflict with a message that
    /// explains the resource-version mismatch. This is the OCC guard — clients that
    /// send a stale resourceVersion receive a clear conflict error, not a silent failure.
    #[test]
    fn store_err_cr_revision_mismatch_returns_409() {
        let err = store_err_cr(
            u7s_store::StoreError::RevisionMismatch {
                expected: 42,
                current: 99,
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 409);
        // Message must mention the version numbers so the client knows what happened.
        let msg = json["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("42") && msg.contains("99"),
            "conflict message must contain expected (42) and current (99) revisions, got: {msg}"
        );
    }

    /// store_err_cr maps RevisionMismatch to 409 with a message explaining the OCC conflict.
    /// The message must contain both expected and current revision numbers so the client
    /// can understand what version it should use for the retry.
    #[test]
    fn store_err_cr_revision_mismatch_message_contains_revisions() {
        let err = store_err_cr(
            u7s_store::StoreError::RevisionMismatch {
                expected: 1,
                current: 5,
            },
            "my-widget",
            "Widget",
        );
        assert_eq!(err.0, axum::http::StatusCode::CONFLICT);
        let json = serde_json::to_value(&err.1).unwrap();
        let msg = json["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("1") && msg.contains("5"),
            "conflict message must contain expected (1) and current (5) revision numbers, got: {msg}"
        );
    }

    // ---------------------------------------------------------------------------
    // cr_store_key and cr_list_prefix unit tests
    // ---------------------------------------------------------------------------

    /// cr_store_key must use the namespace segment for namespaced resources and
    /// omit it for cluster-scoped resources. The key structure is relied upon by
    /// list (prefix scan), get, put, and delete — a wrong key silently stores or
    /// retrieves data under an unexpected path.
    #[test]
    fn cr_store_key_namespaced_includes_namespace() {
        let key = cr_store_key("example.io", "widgets", Some("default"), "my-widget");
        assert_eq!(
            key, "/registry/cr/example.io/widgets/default/my-widget",
            "namespaced key must include the namespace segment"
        );
    }

    #[test]
    fn cr_store_key_cluster_scoped_omits_namespace() {
        let key = cr_store_key("example.io", "widgets", None, "my-widget");
        assert_eq!(
            key, "/registry/cr/example.io/widgets/my-widget",
            "cluster-scoped key must omit the namespace segment"
        );
    }

    /// cr_store_key must not take a served version at all — a CRD's storage-version
    /// pointer can move to a different served version after an object is written, and a
    /// key that embedded it would orphan every object already written under the old
    /// pointer value the instant it moved (see
    /// cr_survives_storage_version_change_and_is_reachable_via_new_storage_version for
    /// the end-to-end regression this would otherwise cause).
    #[test]
    fn cr_store_key_has_no_version_parameter() {
        let key = cr_store_key("example.io", "widgets", Some("default"), "my-widget");
        assert!(
            !key.contains("v1") && !key.contains("v2"),
            "the key must be built from (group, resource, namespace, name) only: {key}"
        );
    }

    /// cr_list_prefix must produce a prefix that correctly scopes the list scan.
    /// A prefix that is too broad (e.g. missing trailing slash) could scan across
    /// all namespaces or all resource types.
    #[test]
    fn cr_list_prefix_namespaced_ends_with_namespace_slash() {
        let prefix = cr_list_prefix("example.io", "widgets", Some("default"));
        assert_eq!(
            prefix, "/registry/cr/example.io/widgets/default/",
            "namespaced prefix must end with namespace and slash"
        );
    }

    #[test]
    fn cr_list_prefix_cluster_scoped_ends_with_plural_slash() {
        let prefix = cr_list_prefix("example.io", "widgets", None);
        assert_eq!(
            prefix, "/registry/cr/example.io/widgets/",
            "cluster-scoped prefix must end with plural and slash"
        );
    }

    // ---------------------------------------------------------------------------
    // call_conversion_webhook clientConfig resolution — service-based and error paths
    //
    // These exercise the shared admission::prepare_webhook_call path:
    // conversion webhooks now resolve clientConfig exactly like admission webhooks —
    // no more bespoke store lookup for the `service` case.
    // ---------------------------------------------------------------------------

    /// call_conversion_webhook must return an error when clientConfig has neither a url
    /// nor a service field. Without a reachable endpoint the conversion cannot proceed,
    /// and silently returning an empty URL would call a bogus address.
    #[tokio::test]
    async fn call_conversion_webhook_errs_when_client_config_has_neither_url_nor_service() {
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({});
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "clientConfig with neither url nor service must return Err, not silently \
             proceed with an empty/invalid webhook target"
        );
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            err_msg.contains("neither url nor service"),
            "error must mention missing url/service, got: {err_msg}"
        );
    }

    /// call_conversion_webhook must resolve `service`-based clientConfig into a service
    /// DNS name (`<name>.<namespace>.svc:<port>`), exactly like admission webhooks — it
    /// must NOT look up the Service object's clusterIP from the store. The old clusterIP
    /// lookup produced a URL only reachable from inside the cluster network, never from
    /// the Mac-hosted apiserver process, and bypassed the konnectivity proxy entirely.
    ///
    /// There is no CoreDNS in this unit test, so the call must still fail overall — but
    /// it must fail as a *connection* error, not a "service/clusterIP not found in store"
    /// error, proving the store is never consulted for Service-based conversion webhooks.
    #[tokio::test]
    async fn call_conversion_webhook_service_config_resolves_without_store_lookup() {
        let state = make_state_for_conversion();
        let client_config = serde_json::json!({
            "service": {
                "namespace": "kube-system",
                "name": "webhook-svc",
                "port": 9443,
                "path": "/convert"
            }
        });
        let objects = vec![serde_json::json!({"apiVersion": "example.io/v1", "kind": "Widget"})];

        let result =
            call_conversion_webhook(&state, &client_config, objects, "example.io/v2").await;
        assert!(
            result.is_err(),
            "no CoreDNS/konnectivity is available in a unit test, so the call must fail"
        );
        let err_msg = serde_json::to_string(&result.unwrap_err().1).unwrap();
        assert!(
            !err_msg.contains("not found") && !err_msg.contains("clusterIP"),
            "error must not mention a store lookup failure (service/clusterIP) — the fixed \
             path never queries the store for Service-based conversion webhooks, matching \
             admission webhook parity; got: {err_msg}"
        );
    }

    /// POST a namespaced CR to a namespace whose status.phase is "Terminating" must return 403.
    /// Real kube-apiserver rejects all new object creation in a Terminating namespace;
    /// without this check our apiserver would allow CRs to be created in dying namespaces,
    /// breaking the namespace GC lifecycle.
    #[tokio::test]
    async fn create_cr_namespaced_rejects_terminating_namespace() {
        use axum::extract::State;
        use bytes::Bytes;
        use std::sync::Arc;
        use u7s_store::SqliteStore;

        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        let state = AppState::new(
            store.clone(),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        // Install a namespaced CRD so we have a real resource to try to create.
        install_namespaced_crd(&state).await;

        // Seed the namespace object with status.phase = "Terminating".
        let ns_key = "/registry/namespaces/dying-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "dying-ns" },
            "status": { "phase": "Terminating" }
        });
        store
            .put(
                ns_key,
                Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let result = create_cr_namespaced(
            State(state),
            axum::extract::Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "dying-ns".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("my-app", "dying-ns"),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "POST CR to Terminating namespace must be rejected — namespace GC would leave orphaned CRs otherwise"
            ),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 403,
            "Terminating namespace must return 403 Forbidden"
        );
        assert_eq!(json["reason"], "Forbidden");
        assert!(
            json["message"].as_str().unwrap_or("").contains("dying-ns"),
            "error message must name the namespace"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("being terminated"),
            "error message must say namespace is being terminated"
        );
    }

    /// patch_cr_namespaced's SSA-upsert branch (is_ssa && stored_opt.is_none()) had no
    /// Terminating-namespace gate, unlike create_cr_namespaced — so `kubectl apply
    /// --server-side` creating a brand-new CR instance could inject content into a namespace
    /// mid-deletion just by going through PATCH+apply instead of POST+create.
    ///
    /// Fails on revert: without the gate, this SSA apply-create of a not-yet-existing CR into
    /// a Terminating namespace returns 201 instead of 403.
    #[tokio::test]
    async fn patch_cr_namespaced_ssa_create_rejects_terminating_namespace() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let ns_key = "/registry/namespaces/dying-ns";
        let ns_obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "dying-ns" },
            "status": { "phase": "Terminating" }
        });
        state
            .store
            .put(
                ns_key,
                Bytes::from(serde_json::to_vec(&ns_obj).unwrap()),
                None,
            )
            .await
            .expect("seed terminating namespace");

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let result = patch_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "dying-ns".to_string(),
                "applications".to_string(),
                "new-app".to_string(),
            )),
            test_user(),
            headers,
            app_body("new-app", "dying-ns"),
        )
        .await;

        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "SSA apply-create of a not-yet-existing CR in a Terminating namespace must be \
                 rejected, matching what POST-create already does — otherwise a controller can \
                 keep injecting new CRs mid-deletion just by using server-side apply"
            ),
        };
        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 403,
            "SSA apply-create into a Terminating namespace must 403"
        );
        assert!(
            json["message"]
                .as_str()
                .unwrap_or("")
                .contains("being terminated"),
            "error message must say namespace is being terminated"
        );

        let key = cr_store_key("argoproj.io", "applications", Some("dying-ns"), "new-app");
        assert!(
            state.store.get(&key).await.unwrap().is_none(),
            "the CR must not have been created in the store"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: deleted CRD group must return 410 Gone, not 404
    //
    // When a CRD is deleted, client-go informers watching its endpoints keep
    // retrying on 404 (treats it as transient) but stop on 410 Gone. Without 410,
    // namespace deletion hangs because the GC informer keeps the resource type
    // "alive" from its perspective, preventing the namespace controller from
    // draining all resources and removing the kubernetes finalizer.
    // ---------------------------------------------------------------------------

    // After a CRD is deleted, LIST for its group/version/plural must return 410 Gone.
    // If the fix is reverted (tombstone not written, or find_crd ignores it), this
    // test returns 404 instead of 410 and fails.
    #[tokio::test]
    async fn deleted_crd_group_returns_410_gone_not_404() {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        // Verify the CRD is reachable before deletion.
        assert!(
            find_crd(&state, "argoproj.io", "v1alpha1", "applications")
                .await
                .is_ok(),
            "find_crd must succeed before deletion"
        );

        // Delete the CRD — this must write the tombstone.
        assert!(
            crd::delete_crd(
                State(state.clone()),
                axum::extract::Path("applications.argoproj.io".to_string()),
                test_user(),
            )
            .await
            .is_ok(),
            "delete_crd must succeed"
        );

        // Now find_crd must return 410 Gone, not 404 Not Found.
        let err = match find_crd(&state, "argoproj.io", "v1alpha1", "applications").await {
            Ok(_) => panic!("find_crd must fail after CRD deletion"),
            Err(e) => e,
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "deleted CRD group must return 410 Gone so informers stop retrying — \
             404 causes infinite retry loops and namespace deletion hangs"
        );
        assert_eq!(
            json["reason"], "Gone",
            "reason must be 'Gone' to match Kubernetes informer semantics"
        );
    }

    // A group that was never registered must still return 404 (not 410).
    // 410 is only valid for groups that existed — an unknown group is a genuine 404.
    #[tokio::test]
    async fn never_registered_group_returns_404_not_410() {
        let state = make_state();

        let err = match find_crd(&state, "never-existed.example.com", "v1", "things").await {
            Ok(_) => panic!("find_crd must fail for unknown group"),
            Err(e) => e,
        };

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 404,
            "never-registered group must return 404 Not Found — \
             returning 410 would mislead informers about a group that was never installed"
        );
        assert_eq!(json["reason"], "NotFound");
    }

    // DeleteCollection against a tombstoned CRD group must return 404, not 410. Upstream
    // kube-controller-manager's namespace deletion controller (deleteCollection() in
    // namespaced_resources_deleter.go) only treats 404/405 as "resource gone, skip
    // gracefully" — any other error, including 410, is fatal and aborts the whole
    // deleteAllContent pass, leaving the namespace stuck in Terminating forever. If this
    // verb-scoping is reverted (find_crd_for_delete falls back to find_crd's blanket 410),
    // this test fails with "expected 404, got 410".
    #[tokio::test]
    async fn deletecollection_returns_404_not_410_so_kcm_namespaced_resources_deleter_treats_it_as_gone_gracefully(
    ) {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("applications.argoproj.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        let err = expect_err_status(
            delete_collection_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "default".to_string(),
                    "applications".to_string(),
                )),
                test_user(),
                no_watch_query(),
            )
            .await,
            "deleteCollection must error after CRD deletion",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 404,
            "deleteCollection on a tombstoned CRD group must return 404, not 410 — kcm's \
             deleteCollection() only skips gracefully on 404/405; a 410 propagates as a fatal \
             error and the namespace controller requeues forever instead of finishing the \
             deleteAllContent pass"
        );
        assert_eq!(json["reason"], "NotFound");
    }

    // LIST against a tombstoned CRD group must still return 410 Gone (unchanged by the
    // deleteCollection verb-scoping above). This is the informer re-list path the original
    // 410 targeted: client-go's reflector only ever issues LIST and WATCH, never DELETE, so
    // narrowing the 410 downgrade to delete verbs must not affect LIST.
    #[tokio::test]
    async fn list_returns_410_so_informer_reflector_rebuilds_watch_cleanly() {
        use crate::handlers::crd;

        let state = make_state();
        install_cluster_crd(&state).await;

        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("widgets.example.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        let err = expect_err_status(
            list_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "list_cr must error after CRD deletion",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "LIST on a tombstoned CRD group must keep returning 410 Gone — this is unrelated \
             to the deleteCollection fix above; a plain 404 here would make an informer's \
             re-list treat the type as merely transiently missing and retry indefinitely"
        );
        assert_eq!(json["reason"], "Gone");
    }

    // After a CRD is deleted, list_cr_namespaced must return 410 Gone (not 404).
    // This covers the HTTP handler path that informers actually call.
    #[tokio::test]
    async fn list_cr_namespaced_returns_410_after_crd_deleted() {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        // Delete the CRD.
        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("applications.argoproj.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        let err = expect_err_status(
            list_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    "default".to_string(),
                    "applications".to_string(),
                )),
                axum::http::HeaderMap::new(),
                no_watch_query(),
                "test-user".to_string(),
            )
            .await,
            "list_cr_namespaced must error after CRD deletion",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "list after CRD deletion must return 410 Gone, not 404 — \
             404 causes GC informer to retry indefinitely, blocking namespace deletion"
        );
    }

    // ---------------------------------------------------------------------------
    // Tombstone + watch guard tests (P1)
    //
    // These tests encode the contract that prevents the conformance-killing hot-loop:
    //
    //   watch=true + sendInitialEvents=true on a tombstoned group → 200 + BOOKMARK
    //   watch=true (no sendInitialEvents) on a tombstoned group   → 410 (client stops)
    //   non-watch LIST on a tombstoned group                      → 410 (preserved)
    //
    // The hot-loop scenario: after CRD deletion, client-go informers watch the group
    // with sendInitialEvents=true. A bare 410 here causes the informer to re-list; the
    // re-list also 410s (no resumable resourceVersion in body), so the informer retries
    // immediately — ~6000 req/s. This self-saturates the apiserver and kills conformance
    // runs. The fix intercepts the GONE error for watch+sendInitialEvents and returns an
    // empty watch stream (200 + BOOKMARK) so the informer parks at a valid RV instead.
    // ---------------------------------------------------------------------------

    // REGRESSION TEST (P1): a watch+sendInitialEvents=true on a tombstoned
    // CRD group must return HTTP 200 (chunked watch stream with BOOKMARK), NOT 410.
    // If reverted, this test returns Err(410) → confirm the hot-loop regression is back.
    #[tokio::test]
    async fn live_crd_watch_sendinitialevents_never_returns_410_cluster() {
        use crate::handlers::crd;

        let state = make_state();
        install_cluster_crd(&state).await;

        // Delete the CRD — writes the tombstone.
        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("widgets.example.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        // watch=true + sendInitialEvents=true on the now-tombstoned group.
        // Must NOT return 410 — a 410 here causes the informer to re-list; the re-list
        // also 410s (bare 410 with no resumable resourceVersion) → infinite hot-loop
        // (~6000 req/s) → apiserver self-saturation → conformance run killed.
        let query = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            send_initial_events: Some(true),
            allow_watch_bookmarks: Some(true),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            timeout_seconds: Some(1),
        };

        let resp = list_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            axum::http::HeaderMap::new(),
            query,
            "test-user".to_string(),
        )
        .await
        .expect(
            "watch+sendInitialEvents on tombstoned group must return 200, NOT 410 — \
             a 410 here causes the informer to hot-loop (~6000 req/s) and kill conformance runs",
        );

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "watch+sendInitialEvents on tombstoned CRD group must return 200 OK — \
             a 410 triggers client-go re-list which also 410s, creating an infinite hot-loop"
        );
        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("chunked"),
            "must be a chunked watch stream, not a buffered error response"
        );

        // Collect the stream and verify it contains a BOOKMARK (sendInitialEvents-end marker).
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");
        assert!(
            body_str.contains("BOOKMARK"),
            "watch+sendInitialEvents stream on tombstoned group must contain a BOOKMARK so the \
             informer can park at a valid resourceVersion — missing BOOKMARK means the informer \
             cannot make progress and will immediately reconnect, causing a hot-loop; \
             body={body_str:?}"
        );
        assert!(
            body_str.contains("initial-events-end"),
            "BOOKMARK must carry the k8s.io/initial-events-end annotation to signal the \
             informer that the initial snapshot is complete"
        );
    }

    // REGRESSION TEST (P1): same guard for the namespaced watch path.
    // Namespaced informers (e.g., argo CD watching per-namespace apps) hit list_cr_namespaced
    // — if this path still 410s on sendInitialEvents, they also hot-loop.
    #[tokio::test]
    async fn live_crd_watch_sendinitialevents_never_returns_410_namespaced() {
        use crate::handlers::crd;

        let state = make_state();
        install_namespaced_crd(&state).await;

        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("applications.argoproj.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        let query = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            send_initial_events: Some(true),
            allow_watch_bookmarks: Some(true),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            timeout_seconds: Some(1),
        };

        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            axum::http::HeaderMap::new(),
            query,
            "test-user".to_string(),
        )
        .await
        .expect(
            "namespaced watch+sendInitialEvents on tombstoned group must return 200, NOT 410 — \
             a 410 here triggers the same hot-loop as the cluster-scoped path",
        );

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");
        assert!(
            body_str.contains("BOOKMARK"),
            "namespaced watch+sendInitialEvents stream must contain BOOKMARK; body={body_str:?}"
        );
    }

    // Plain watch=true WITHOUT sendInitialEvents on a tombstoned group must still return
    // 410. A plain watch 410 (without sendInitialEvents) is safe: the informer's recovery
    // path does a re-LIST which also 410s, and client-go treats two consecutive 410s as
    // terminal — it backs off and eventually stops. The guard must be narrow (only
    // watch+sendInitialEvents) so we don't accidentally make a non-sendInitialEvents watch
    // on a tombstoned group succeed (which would give the informer a watch stream that
    // never receives events, keeping the informer alive on a dead type indefinitely).
    #[tokio::test]
    async fn deleted_crd_watch_no_sendinitialevents_returns_410() {
        use crate::handlers::crd;

        let state = make_state();
        install_cluster_crd(&state).await;

        crd::delete_crd(
            State(state.clone()),
            axum::extract::Path("widgets.example.io".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        // watch=true WITHOUT sendInitialEvents — should still 410.
        let query = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(0),
            send_initial_events: None, // NOT set
            allow_watch_bookmarks: Some(true),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            timeout_seconds: Some(1),
        };

        let err = expect_err_status(
            list_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                axum::http::HeaderMap::new(),
                query,
                "test-user".to_string(),
            )
            .await,
            "plain watch (no sendInitialEvents) on tombstoned group must error",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 410,
            "plain watch without sendInitialEvents on tombstoned group must still return 410 — \
             the guard must be narrow (only sendInitialEvents) to preserve informer stop semantics"
        );
    }

    fn json_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json-patch+json"),
        );
        h
    }

    fn merge_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        h
    }

    /// Controllers patching CRs with JSON Patch (RFC 6902) fail if the CR PATCH handler
    /// only accepts application/merge-patch+json — the handler must route json-patch
    /// requests to apply_json_patch so conformance tests can mutate CRs via JSON Patch.
    #[tokio::test]
    async fn cluster_cr_json_patch_applies_ops_and_returns_200() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/color", "value": "red"}
        ]);
        let patch_body = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let resp = patch_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            test_user(),
            json_patch_headers(),
            patch_body,
        )
        .await
        .expect("json-patch on cluster CR must return 200, not 415");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "red",
            "json-patch add op must update spec.color — without the fix the handler returns 415"
        );
    }

    /// Controllers patching namespaced CRs with JSON Patch fail if the CR PATCH handler
    /// only accepts application/merge-patch+json — namespace-scoped CRs need the same fix.
    #[tokio::test]
    async fn namespaced_cr_json_patch_applies_ops_and_returns_200() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let ns = "default".to_string();
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    ns.clone(),
                    "applications".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body("my-app", &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!([
            {"op": "add", "path": "/spec/newField", "value": "patched"}
        ]);
        let patch_body = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let resp = patch_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                ns.clone(),
                "applications".to_string(),
                "my-app".to_string(),
            )),
            test_user(),
            json_patch_headers(),
            patch_body,
        )
        .await
        .expect("json-patch on namespaced CR must return 200, not 415");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["newField"], "patched",
            "json-patch add op must set spec.newField — without the fix the handler returns 415"
        );
    }

    /// Merge-patch on a cluster-scoped CR must still work after the json-patch branch is added.
    #[tokio::test]
    async fn cluster_cr_merge_patch_still_works_after_json_patch_added() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("merge-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!({"spec": {"color": "green"}});
        let patch_body = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let resp = patch_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "merge-widget".to_string(),
            )),
            test_user(),
            merge_patch_headers(),
            patch_body,
        )
        .await
        .expect("merge-patch on cluster CR must still succeed");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["spec"]["color"], "green",
            "merge-patch must still update spec.color — regression check that the json-patch branch did not break merge-patch"
        );
    }

    /// A malformed JSON Patch (not an array) must return 422 Unprocessable Entity,
    /// matching core resource behaviour — controllers must get a clear error, not 500.
    #[tokio::test]
    async fn cluster_cr_malformed_json_patch_returns_422() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("bad-patch-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // A valid JSON object is not a valid JSON Patch (must be an array).
        let bad_patch = serde_json::json!({"op": "add", "path": "/spec/x", "value": 1});
        let patch_body = Bytes::from(serde_json::to_vec(&bad_patch).unwrap());

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "bad-patch-widget".to_string(),
                )),
                test_user(),
                json_patch_headers(),
                patch_body,
            )
            .await,
            "malformed json-patch must return an error",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(
            json["code"], 422,
            "malformed JSON Patch (non-array body) must return 422 — \
             returning 200/500 would hide client errors from controllers"
        );
    }

    // ---------------------------------------------------------------------------
    // Admission webhook invocation regression tests
    //
    // These tests verify that the CR create/update handlers call the admission
    // webhook pipeline. If the invocation logic is removed, a matching mutating
    // webhook must not apply its patch (mutation test) and a matching validating
    // webhook must not deny (denial test), causing these tests to fail.
    // ---------------------------------------------------------------------------

    /// A mutating webhook with failurePolicy=Ignore and an unreachable URL must not
    /// block CR creation — admission is attempted but the failure is absorbed.
    ///
    /// This test verifies that create_cr_namespaced calls the admission pipeline:
    /// if admission were skipped entirely, the Ignore-policy webhook would never be
    /// contacted, but the object would still be created. When invocation IS wired in
    /// but the webhook is unreachable with Ignore, the create must still succeed.
    #[tokio::test]
    async fn create_cr_namespaced_calls_admission_ignore_policy_passes_through() {
        use bytes::Bytes;
        use u7s_store::Store;

        let state = make_state();

        // Install CRD before seeding the webhook so CRD creation is not denied.
        install_namespaced_crd(&state).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "cr-test-mwc"},
            "webhooks": [{
                "name": "cr.mutate.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "failurePolicy": "Ignore"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/cr-test-mwc",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("wh-test-app", "argocd"),
        )
        .await;

        assert!(
            result.is_ok(),
            "mutating webhook with failurePolicy=Ignore must not block CR creation \
             — if admission is wired in and the webhook is unreachable with Ignore, \
             the create must still succeed"
        );
    }

    /// A validating webhook with failurePolicy=Fail and an unreachable URL must
    /// deny CR creation with an error.
    ///
    /// This regression test verifies that create_cr_namespaced invokes the validating
    /// webhook chain. If the chain were not called, the unreachable Fail-policy webhook
    /// would be silently skipped and the create would succeed — this test would then
    /// fail, proving the invocation was removed.
    #[tokio::test]
    async fn create_cr_namespaced_calls_validating_admission_fail_policy_denies() {
        use bytes::Bytes;
        use u7s_store::Store;

        let state = make_state();

        // Install CRD before seeding the webhook so CRD creation is not denied.
        install_namespaced_crd(&state).await;

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "cr-test-vwc"},
            "webhooks": [{
                "name": "cr.validate.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state.store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/cr-test-vwc",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("denied-app", "argocd"),
        )
        .await;

        assert!(
            result.is_err(),
            "validating webhook with failurePolicy=Fail must deny CR creation — \
             if the validating webhook chain is not called, the Fail-policy webhook \
             would be skipped and the create would incorrectly succeed"
        );
    }

    /// A `sideEffects: Some` mutating webhook has no contractual guarantee it honors
    /// `dryRun: true` in the AdmissionReview it receives — invoking it anyway on a
    /// dry-run CR create could trigger a real external side effect the client explicitly
    /// opted out of. Before this fix, create_cr_namespaced constructed AdmissionContext
    /// with `dry_run: false` hardcoded regardless of the real request (create_cr_namespaced
    /// has no Query extractor of its own — it's invoked directly by resource.rs's
    /// CRD-fallback path, not dispatched by axum), so the sideEffects gate never saw
    /// dry_run=true and always invoked the webhook. Reverting the fix makes this test
    /// fail: the webhook's HTTP endpoint gets called (call_count > 0) and the create
    /// succeeds instead of being rejected with 400 "does not support dry run".
    #[tokio::test]
    async fn create_cr_namespaced_dry_run_does_not_invoke_side_effects_some_webhook() {
        use bytes::Bytes;
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::net::TcpListener;
        use u7s_store::Store;

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();
        let router = axum::Router::new().route(
            "/mutate",
            axum::routing::post(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": { "uid": "uid-cr-dry-run", "allowed": true }
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock webhook server must not fail");
        });

        let state = make_state();
        install_namespaced_crd(&state).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "cr-dry-run-side-effects-mwc"},
            "webhooks": [{
                "name": "cr-side-effects-some.example.com",
                "clientConfig": { "url": format!("http://{addr}/mutate") },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "sideEffects": "Some"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/cr-dry-run-side-effects-mwc",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        // Mirrors what the router-wide inject_dry_run_header layer (lib.rs) stamps onto a
        // real ?dryRun=All request before it reaches create_cr_namespaced — this test calls
        // the handler directly, bypassing the router, so the header is set by hand.
        let mut dry_run_headers = axum::http::HeaderMap::new();
        dry_run_headers.insert(
            axum::http::HeaderName::from_static(crate::handlers::json_patch::DRY_RUN_HEADER),
            axum::http::HeaderValue::from_static("true"),
        );

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            dry_run_headers,
            app_body("dry-run-app", "argocd"),
        )
        .await;

        let err = expect_err_status(
            result,
            "dryRun=All against a sideEffects:Some webhook (default failurePolicy=Fail) must \
             be rejected with 400 \"does not support dry run\", not silently allowed through \
             — an Ok here means the CR create path never saw dry_run=true",
        );
        assert_eq!(
            err.0,
            axum::http::StatusCode::BAD_REQUEST,
            "dry-run rejection must come from the sideEffects gate (400), not some other \
             admission failure"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "AdmissionContext.dry_run must reflect the real dry-run flag on the CR path; if \
             this fails, create_cr_namespaced went back to hardcoding dry_run: false and the \
             sideEffects:Some webhook's HTTP endpoint was wrongly invoked on a dry-run request"
        );
    }

    /// A mutating webhook with failurePolicy=Fail and unreachable URL must
    /// deny cluster-scoped CR creation.
    ///
    /// Verifies that create_cr (cluster-scoped path) also invokes admission,
    /// not just the namespaced handler. If admission were skipped for cluster-scoped
    /// CRs, this create would succeed instead of being denied.
    #[tokio::test]
    async fn create_cr_calls_admission_fail_policy_denies_cluster_scoped() {
        use bytes::Bytes;
        use u7s_store::Store;

        let state = make_state();

        // Install CRD before seeding the webhook so CRD creation is not denied.
        install_cluster_crd(&state).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "cluster-cr-mwc"},
            "webhooks": [{
                "name": "cluster-cr.mutate.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state.store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/cluster-cr-mwc",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            widget_body("denied-widget"),
        )
        .await;

        assert!(
            result.is_err(),
            "mutating webhook with failurePolicy=Fail must deny cluster-scoped CR creation — \
             if admission is skipped for the cluster-scoped CR path, this create would \
             incorrectly succeed"
        );
    }

    /// A validating webhook with failurePolicy=Fail and an unreachable URL must
    /// deny CR deletion with an error, not silently allow it.
    ///
    /// Regression test: every DELETE handler in the apiserver skipped
    /// admission entirely, so a Fail-policy validating webhook registered on DELETE
    /// never received a request and the object was always removed regardless of the
    /// webhook's verdict. This is exactly the delete half of the conformance test
    /// "deny custom resource create/update/delete". If delete_cr_namespaced stops
    /// calling run_validating_webhooks (i.e. this fix is reverted), the delete below
    /// succeeds and the object disappears from the store — this test then fails,
    /// proving the admission invocation was removed.
    #[tokio::test]
    async fn delete_cr_namespaced_calls_validating_admission_fail_policy_denies() {
        use bytes::Bytes;
        use u7s_store::Store;

        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "wh-delete-app".to_string();

        // Seed the object to be deleted BEFORE registering the webhook, so creation
        // is not itself denied.
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "cr-delete-vwc"},
            "webhooks": [{
                "name": "cr.validate-delete.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["DELETE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/cr-delete-vwc",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = delete_cr_namespaced(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

        assert!(
            result.is_err(),
            "validating webhook with failurePolicy=Fail must deny CR deletion — \
             if delete_cr_namespaced does not call run_validating_webhooks, the \
             Fail-policy webhook is skipped and the delete incorrectly succeeds"
        );

        // The object must still exist — a webhook denial must not remove it.
        assert!(
            get_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns, plural, name)),
                axum::http::HeaderMap::new(),
            )
            .await
            .is_ok(),
            "object must survive a denied delete — otherwise the webhook denial is \
             cosmetic and the object is removed anyway"
        );
    }

    /// A validating webhook with failurePolicy=Fail and an unreachable URL must
    /// deny cluster-scoped CR deletion.
    ///
    /// Verifies that delete_cr (cluster-scoped path) also invokes admission on DELETE,
    /// not just the namespaced handler. Companion to
    /// delete_cr_namespaced_calls_validating_admission_fail_policy_denies above.
    #[tokio::test]
    async fn delete_cr_calls_admission_fail_policy_denies_cluster_scoped() {
        use bytes::Bytes;
        use u7s_store::Store;

        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "wh-delete-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "cluster-cr-delete-vwc"},
            "webhooks": [{
                "name": "cluster-cr.validate-delete.example.com",
                "clientConfig": { "url": "http://127.0.0.1:1" },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["DELETE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/cluster-cr-delete-vwc",
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = delete_cr(
            State(state.clone()),
            Path((group, version, plural, name)),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

        assert!(
            result.is_err(),
            "validating webhook with failurePolicy=Fail must deny cluster-scoped CR \
             deletion — if admission is skipped for the cluster-scoped delete path, \
             this delete would incorrectly succeed"
        );
    }

    /// The admission review sent by create_cr_namespaced must contain a non-null
    /// `userInfo` field with the authenticated user's username.
    ///
    /// Without this, validating admission policies (VAP) and webhook authorizers
    /// that inspect `request.userInfo` receive empty/null identity — allowing
    /// privilege-escalation attacks where an anonymous call is treated as the
    /// service-account identity the webhook expects.
    #[tokio::test]
    async fn create_cr_namespaced_admission_review_contains_user_info() {
        use axum::routing::post;
        use axum::Router;
        use bytes::Bytes;
        use std::sync::{Arc, Mutex};
        use tokio::net::TcpListener;
        use u7s_store::Store;

        // Capture the raw admission review body sent by the handler.
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);

        let router = Router::new().route(
            "/admit",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let captured_clone = Arc::clone(&captured_clone);
                async move {
                    *captured_clone.lock().unwrap() = Some(body.clone());
                    // Return an allow response so the create proceeds.
                    let uid = body["request"]["uid"].as_str().unwrap_or("").to_string();
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": { "uid": uid, "allowed": true }
                    }))
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock admission server must not fail");
        });
        let webhook_url = format!("http://{addr}/admit");

        let state = make_state();
        install_namespaced_crd(&state).await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "user-info-test-mwc"},
            "webhooks": [{
                "name": "user-info.test.example.com",
                "clientConfig": { "url": webhook_url },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/user-info-test-mwc",
                Bytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let result = create_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                "argocd".to_string(),
                "applications".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("user-info-test-app", "argocd"),
        )
        .await;

        assert!(
            result.is_ok(),
            "create_cr_namespaced must succeed when the mutating webhook allows the request"
        );

        let review =
            captured.lock().unwrap().take().expect(
                "webhook must have been called — if not, userInfo can never reach the webhook",
            );

        let user_info = &review["request"]["userInfo"];
        assert!(
            !user_info.is_null(),
            "admission review must contain non-null userInfo — \
             VAP expressions and webhook authorizers that inspect request.userInfo \
             receive empty identity if this field is absent"
        );
        assert_eq!(
            user_info["username"].as_str(),
            Some("admin"),
            "userInfo.username must match the authenticated caller — \
             a blank username means the webhook cannot distinguish users"
        );
    }

    fn strategic_merge_patch_headers() -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        h
    }

    /// A cluster-scoped CR PATCH with strategic-merge-patch Content-Type and a
    /// $patch:delete directive must remove the targeted field. Before the fix,
    /// $patch directives were silently ignored because merge_patch was called
    /// regardless of patch type.
    #[tokio::test]
    async fn cluster_cr_strategic_merge_patch_delete_removes_field() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let initial = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "smp-widget" },
                "spec": { "color": "blue", "size": "large" }
            })
            .to_string(),
        );

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                initial,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!({"spec": {"size": null}});
        let patch_body = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let resp = patch_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "smp-widget".to_string(),
            )),
            test_user(),
            strategic_merge_patch_headers(),
            patch_body,
        )
        .await
        .expect("strategic-merge-patch on cluster CR must return 200");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["spec"]["size"].is_null(),
            "strategic-merge-patch with null value must remove the field — \
             without the fix merge_patch is called and the field is silently left unchanged"
        );
        assert_eq!(
            obj["spec"]["color"], "blue",
            "strategic-merge-patch must preserve unpatched fields"
        );
    }

    /// A namespaced CR PATCH with strategic-merge-patch Content-Type and a null
    /// value must remove the targeted field. Before the fix, $patch directives
    /// were silently ignored because merge_patch was called for all non-JSON-Patch
    /// content types including strategic-merge-patch.
    #[tokio::test]
    async fn namespaced_cr_strategic_merge_patch_delete_removes_field() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let ns = "default".to_string();
        let initial = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": "smp-app", "namespace": ns },
                "spec": { "destination": { "namespace": "default" }, "project": "default" }
            })
            .to_string(),
        );

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((
                    "argoproj.io".to_string(),
                    "v1alpha1".to_string(),
                    ns.clone(),
                    "applications".to_string(),
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                initial,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let patch = serde_json::json!({"spec": {"project": null}});
        let patch_body = Bytes::from(serde_json::to_vec(&patch).unwrap());

        let resp = patch_cr_namespaced(
            State(state.clone()),
            Path((
                "argoproj.io".to_string(),
                "v1alpha1".to_string(),
                ns.clone(),
                "applications".to_string(),
                "smp-app".to_string(),
            )),
            test_user(),
            strategic_merge_patch_headers(),
            patch_body,
        )
        .await
        .expect("strategic-merge-patch on namespaced CR must return 200");

        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            obj["spec"]["project"].is_null(),
            "strategic-merge-patch with null value must remove the field — \
             without the fix merge_patch is called and the field is silently left unchanged"
        );
        assert_eq!(
            obj["spec"]["destination"]["namespace"], "default",
            "strategic-merge-patch must preserve unpatched fields"
        );
    }

    // GET for a namespaced CR must include kind and apiVersion in the response.
    // client-go typed clients assert these fields; missing them causes
    // "Object Kind is missing" errors in DRA and CRD conformance tests.
    #[tokio::test]
    async fn get_cr_namespaced_response_includes_type_meta() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect("get must succeed after create");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["kind"], "Application",
            "GET response must include kind — client-go returns 'Object Kind is missing' without it"
        );
        assert_eq!(
            obj["apiVersion"], "argoproj.io/v1alpha1",
            "GET response must include apiVersion — required by Kubernetes API contract"
        );
    }

    // GET for a cluster-scoped CR must include kind and apiVersion.
    // Removing the TypeMeta injection from get_cr must make this test fail.
    #[tokio::test]
    async fn get_cr_cluster_scoped_response_includes_type_meta() {
        let state = make_state();
        install_cluster_crd(&state).await;

        assert!(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string()
                )),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body("my-widget"),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = get_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "my-widget".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect("get must succeed after create");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            obj["kind"], "Widget",
            "cluster-scoped GET response must include kind — client-go returns 'Object Kind is missing' without it"
        );
        assert_eq!(
            obj["apiVersion"], "example.io/v1",
            "cluster-scoped GET response must include apiVersion"
        );
    }

    /// PUT /apis/{group}/{version}/{plural}/{name}/status must not overwrite finalizers or
    /// deletionTimestamp on a cluster-scoped CR. If a status PUT restores a finalizer that a peer
    /// controller just removed, the object is stuck Terminating forever (livelock).
    #[tokio::test]
    async fn put_cr_status_preserves_finalizers_and_deletion_timestamp() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        // Create a widget CR.
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "fin-widget" },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );
        assert!(
            create_cr(
                State(state.clone()),
                Path(("example.io".into(), "v1".into(), "widgets".into())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Directly stamp finalizers and deletionTimestamp into the stored object to simulate
        // a controller having added them.
        let key = "/registry/cr/example.io/widgets/fin-widget";
        let stored = state.store.get(key).await.unwrap().unwrap();
        let mut obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        obj["metadata"]["finalizers"] = serde_json::json!(["example.io/protection"]);
        obj["metadata"]["deletionTimestamp"] = serde_json::json!("2024-01-01T00:00:00Z");
        let rv: u64 = obj["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        state
            .store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&obj).unwrap()),
                Some(rv),
            )
            .await
            .unwrap();

        // PUT /status with a body that tries to clear finalizers and change deletionTimestamp.
        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": {
                    "name": "fin-widget",
                    "finalizers": [],
                    "deletionTimestamp": "2099-01-01T00:00:00Z"
                },
                "spec": { "color": "blue" },
                "status": { "ready": true }
            })
            .to_string(),
        );
        assert!(
            put_cr_status(
                State(state.clone()),
                Path((
                    "example.io".into(),
                    "v1".into(),
                    "widgets".into(),
                    "fin-widget".into()
                )),
                axum::http::HeaderMap::new(),
                put_body,
            )
            .await
            .is_ok(),
            "PUT /status must succeed"
        );

        let after = state.store.get(key).await.unwrap().unwrap();
        let after_obj: serde_json::Value = serde_json::from_slice(&after.value).unwrap();
        assert_eq!(
            after_obj["metadata"]["finalizers"][0], "example.io/protection",
            "finalizers must survive PUT /cr/status — a status write that clears finalizers can \
             restore a just-removed finalizer causing the object to be stuck Terminating forever (livelock)"
        );
        assert_eq!(
            after_obj["metadata"]["deletionTimestamp"], "2024-01-01T00:00:00Z",
            "deletionTimestamp must survive PUT /cr/status"
        );
        assert_eq!(after_obj["status"]["ready"], true, "status must be updated");
    }

    // ---------------------------------------------------------------------------
    // CR cascade-delete and apply_delete_policy tests (Rule 14: regressable)
    //
    // These tests encode GC conformance requirements:
    // - Deleting a CR owner (Background) must cascade to dependents so GC conformance
    //   spec 'should support cascading deletion of custom resources' does not leak CRs.
    // - Orphan delete must strip ownerRefs instead of deleting, so orphaned CRs survive.
    // - A CR with finalizers must be soft-deleted (deletionTimestamp set), not hard-deleted.
    // - Ownership chains (owner→dependent→grand-dependent) must all be reclaimed.
    // ---------------------------------------------------------------------------

    /// Deleting a cluster-scoped CR owner without specifying a policy (default = cascade)
    /// must delete its dependent CRs. Without this, GC conformance spec
    /// 'should support cascading deletion of custom resources' fails — the dependent
    /// CR is never removed and the test times out waiting for it to disappear.
    #[tokio::test]
    async fn delete_cr_owner_cascades_to_dependent_or_gc_conformance_fails() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Create owner widget.
        let owner_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "owner-widget" },
                "spec": {}
            })
            .to_string(),
        );
        create_cr(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            test_user(),
            axum::http::HeaderMap::new(),
            owner_body,
        )
        .await
        .expect("create owner CR");

        // Read back the owner to get its UID.
        let owner_stored = state
            .store
            .get(&cr_store_key(group, plural, None, "owner-widget"))
            .await
            .unwrap()
            .unwrap();
        let owner_obj: serde_json::Value = serde_json::from_slice(&owner_stored.value).unwrap();
        let owner_uid = owner_obj["metadata"]["uid"].as_str().unwrap().to_string();
        assert!(!owner_uid.is_empty(), "owner must have a UID");

        // Seed a dependent CR directly (with ownerReference → owner).
        let dependent_key = cr_store_key(group, plural, None, "dep-widget");
        let dependent_body = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "dep-widget",
                "uid": "dep-uid-1",
                "ownerReferences": [{
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "name": "owner-widget",
                    "uid": owner_uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &dependent_key,
                Bytes::from(serde_json::to_vec(&dependent_body).unwrap()),
                Some(0),
            )
            .await
            .expect("seed dependent CR");

        // Delete the owner with default (no) propagation policy.
        delete_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "owner-widget".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete owner CR");

        // Owner must be gone.
        let owner_after = state
            .store
            .get(&cr_store_key(group, plural, None, "owner-widget"))
            .await
            .unwrap();
        assert!(
            owner_after.is_none(),
            "owner CR must be deleted — if not, cascading delete is broken"
        );

        // Dependent must be gone (cascade).
        let dep_after = state.store.get(&dependent_key).await.unwrap();
        assert!(
            dep_after.is_none(),
            "deleting a CR owner must cascade to dependents or GC conformance fails / orphaned CRs leak"
        );
    }

    /// Deleting a namespaced CR owner must cascade to its namespaced dependents.
    /// Symmetric to the cluster-scoped test; without this, namespaced CRs owned
    /// by a deleted namespaced CR are never reclaimed.
    #[tokio::test]
    async fn delete_cr_namespaced_owner_cascades_to_dependent() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io";
        let version = "v1alpha1";
        let plural = "applications";
        let ns = "argocd";

        // Create owner app.
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("owner-app", ns),
        )
        .await
        .expect("create owner app");

        let owner_stored = state
            .store
            .get(&cr_store_key(group, plural, Some(ns), "owner-app"))
            .await
            .unwrap()
            .unwrap();
        let owner_obj: serde_json::Value = serde_json::from_slice(&owner_stored.value).unwrap();
        let owner_uid = owner_obj["metadata"]["uid"].as_str().unwrap().to_string();

        // Seed dependent app.
        let dep_key = cr_store_key(group, plural, Some(ns), "dep-app");
        let dep_body = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": "dep-app",
                "namespace": ns,
                "uid": "dep-app-uid",
                "ownerReferences": [{
                    "apiVersion": "argoproj.io/v1alpha1",
                    "kind": "Application",
                    "name": "owner-app",
                    "uid": owner_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &dep_key,
                Bytes::from(serde_json::to_vec(&dep_body).unwrap()),
                Some(0),
            )
            .await
            .expect("seed dependent app");

        // Delete the owner.
        delete_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                "owner-app".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete owner app");

        let dep_after = state.store.get(&dep_key).await.unwrap();
        assert!(
            dep_after.is_none(),
            "deleting a namespaced CR owner must cascade to dependents — orphaned CRs leak otherwise"
        );
    }

    /// Deleting a CR owner with Orphan propagationPolicy must soft-delete the owner (stamp
    /// deletionTimestamp, add the `orphan` finalizer) and must NOT synchronously hard-delete
    /// it or strip the dependent's ownerReference itself.
    ///
    /// The old implementation hard-deleted the owner CR immediately, then stripped the
    /// dependent's ownerReference afterward — worse than the equivalent bug already fixed for
    /// built-in RC/Deployment orphan-delete (mirrored by
    /// `orphan_delete_rc_soft_deletes_with_finalizer_and_does_not_strip_pods_synchronously`):
    /// here the owner was already gone from the store before any dependent's ownerRef was
    /// stripped, giving real KCM's GC controller a head start to cascade-delete a
    /// not-yet-stripped dependent. The `orphan` finalizer instead lets real, unmodified KCM
    /// strip dependents from its own consistent view before removing the finalizer, at which
    /// point `patch_cr`'s finalizer-drain-complete check does the real hard-delete.
    #[tokio::test]
    async fn delete_cr_with_orphan_policy_soft_deletes_and_does_not_strip_owner_ref_synchronously()
    {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Create owner.
        let owner_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "orphan-owner" },
                "spec": {}
            })
            .to_string(),
        );
        create_cr(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            test_user(),
            axum::http::HeaderMap::new(),
            owner_body,
        )
        .await
        .expect("create owner CR");

        let owner_stored = state
            .store
            .get(&cr_store_key(group, plural, None, "orphan-owner"))
            .await
            .unwrap()
            .unwrap();
        let owner_uid = serde_json::from_slice::<serde_json::Value>(&owner_stored.value).unwrap()
            ["metadata"]["uid"]
            .as_str()
            .unwrap()
            .to_string();

        // Seed dependent.
        let dep_key = cr_store_key(group, plural, None, "orphan-dep");
        let dep_body = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "orphan-dep",
                "uid": "orphan-dep-uid",
                "ownerReferences": [{
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "name": "orphan-owner",
                    "uid": owner_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &dep_key,
                Bytes::from(serde_json::to_vec(&dep_body).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Delete owner with Orphan policy.
        let orphan_opts = Bytes::from(
            serde_json::json!({
                "kind": "DeleteOptions",
                "apiVersion": "v1",
                "propagationPolicy": "Orphan"
            })
            .to_string(),
        );
        delete_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "orphan-owner".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            orphan_opts,
        )
        .await
        .expect("orphan delete must succeed");

        // Owner must be SOFT-deleted: still present, with deletionTimestamp and the `orphan`
        // finalizer — NOT hard-deleted synchronously in this request.
        let owner_key = cr_store_key(group, plural, None, "orphan-owner");
        let owner_after = state.store.get(&owner_key).await.unwrap().expect(
            "owner CR must remain in the store (soft-deleted) immediately after an Orphan \
             delete — hard-deleting it here, before KCM confirms dependents are stripped, is \
             the exact race that let real KCM's GC controller cascade-delete a dependent whose \
             ownerReference hasn't been stripped from its point of view yet",
        );
        let owner_val: serde_json::Value = serde_json::from_slice(&owner_after.value).unwrap();
        assert!(
            owner_val["metadata"]["deletionTimestamp"].is_string(),
            "Orphan delete must stamp deletionTimestamp on the owner CR"
        );
        assert_eq!(
            owner_val["metadata"]["finalizers"]
                .as_array()
                .map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["orphan"]),
            "Orphan delete must add the `orphan` finalizer so real KCM's GC controller knows \
             to strip dependents itself before the finalizer drains"
        );

        // Dependent must still exist (not cascade-deleted).
        let dep_after = state.store.get(&dep_key).await.unwrap().expect(
            "orphan delete of CR owner must leave dependent alive — cascade would be wrong",
        );

        // The ownerReference must be UNTOUCHED by u7s at this point: stripping is now
        // exclusively real KCM's job, once it observes the `orphan` finalizer above.
        let dep_obj: serde_json::Value = serde_json::from_slice(&dep_after.value).unwrap();
        let refs = dep_obj["metadata"]["ownerReferences"].as_array();
        let still_has_ref = refs.map(|r| {
            r.iter()
                .any(|entry| entry["uid"].as_str() == Some(&owner_uid))
        });
        assert_eq!(
            still_has_ref,
            Some(true),
            "u7s must NOT strip the dependent's ownerReference itself at delete time — doing \
             so synchronously, before the owner is confirmed gone, is exactly the race this \
             fix addresses"
        );
    }

    /// Once real KCM's GC controller has stripped a dependent's ownerReference and removes the
    /// owner CR's `orphan` finalizer via PATCH, patch_cr must complete the deferred hard-delete
    /// instead of storing the update — otherwise the owner sits stuck Terminating forever.
    #[tokio::test]
    async fn cr_orphan_finalizer_drain_completion_hard_deletes_owner() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Seed a Widget already in the post-orphan-delete state: soft-deleted with exactly the
        // `orphan` finalizer pending, as add_orphan_finalizer + apply_delete_policy leave it
        // for real KCM to act on.
        let owner_key = cr_store_key(group, plural, None, "draining-owner");
        let owner = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "draining-owner",
                "uid": "drain-uid-0002",
                "deletionTimestamp": "2026-07-22T00:00:00Z",
                "finalizers": ["orphan"]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &owner_key,
                Bytes::from(serde_json::to_vec(&owner).unwrap()),
                None,
            )
            .await
            .expect("seed draining owner CR");

        // Real KCM's GC controller has finished stripping dependents and now removes the
        // last finalizer via a merge-patch — the exact mechanism it uses to signal drain
        // completion.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/merge-patch+json"),
        );
        let patch = serde_json::json!({ "metadata": { "finalizers": [] } });
        patch_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "draining-owner".to_string(),
            )),
            test_user(),
            headers,
            Bytes::from(serde_json::to_vec(&patch).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("finalizer-drain patch must succeed: {e:?}"));

        assert!(
            state.store.get(&owner_key).await.unwrap().is_none(),
            "owner CR must be hard-deleted once its last finalizer (orphan) drains — this is \
             how the deferred hard-delete of an Orphan-marked owner actually completes"
        );
    }

    /// A PUT (replace_cr) whose body has deletionTimestamp set and finalizers now empty is
    /// how a controller that removes its own protection finalizer via Update rather than
    /// Patch signals drain completion — e.g. external-snapshotter's snapshot-controller
    /// updates VolumeSnapshotContent this way. Before this fix, replace_cr had no
    /// equivalent to patch_cr's finalizer-drain-complete check above, so the PUT just
    /// stored the finalizer-cleared object — leaving it stuck with deletionTimestamp set
    /// and no finalizers forever. This is exactly what caused the real e2e failure:
    /// "volumesnapshotcontents ... is not deleted within 5m0s".
    #[tokio::test]
    async fn replace_cr_finalizer_drain_completion_hard_deletes_object() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Seed a Widget already soft-deleted with one finalizer pending, as delete_cr
        // leaves it for the owning controller to drain.
        let key = cr_store_key(group, plural, None, "draining-widget");
        let widget = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "draining-widget",
                "uid": "drain-uid-put-1",
                "deletionTimestamp": "2026-07-22T00:00:00Z",
                "finalizers": ["snapshot.storage.k8s.io/vsc-protection"]
            },
            "spec": { "color": "blue" }
        });
        state
            .store
            .put(
                &key,
                Bytes::from(serde_json::to_vec(&widget).unwrap()),
                None,
            )
            .await
            .expect("seed draining widget CR");

        // The owning controller's Update() call: same deletionTimestamp, finalizers now
        // empty — mirrors snapshot-controller removing its own finalizer via PUT.
        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": {
                    "name": "draining-widget",
                    "deletionTimestamp": "2026-07-22T00:00:00Z",
                    "finalizers": []
                },
                "spec": { "color": "blue" }
            })
            .to_string(),
        );

        replace_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "draining-widget".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            put_body,
        )
        .await
        .unwrap_or_else(|e| panic!("finalizer-drain PUT must succeed: {e:?}"));

        assert!(
            state.store.get(&key).await.unwrap().is_none(),
            "object must be hard-deleted once its last finalizer drains via PUT — a \
             controller that uses Update rather than Patch to remove its own finalizer must \
             not leave the object stuck Terminating forever"
        );
    }

    /// Namespaced equivalent of `replace_cr_finalizer_drain_completion_hard_deletes_object`
    /// — mirrors external-snapshotter's snapshot-controller removing its protection
    /// finalizer from a namespaced VolumeSnapshot via PUT (Update), not PATCH.
    #[tokio::test]
    async fn replace_cr_namespaced_finalizer_drain_completion_hard_deletes_object() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io";
        let version = "v1alpha1";
        let ns = "argocd";
        let plural = "applications";

        let key = cr_store_key(group, plural, Some(ns), "draining-app");
        let app = serde_json::json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Application",
            "metadata": {
                "name": "draining-app",
                "namespace": ns,
                "uid": "drain-uid-put-2",
                "deletionTimestamp": "2026-07-22T00:00:00Z",
                "finalizers": ["snapshot.storage.k8s.io/vs-protection"]
            },
            "spec": {}
        });
        state
            .store
            .put(&key, Bytes::from(serde_json::to_vec(&app).unwrap()), None)
            .await
            .expect("seed draining Application CR");

        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": {
                    "name": "draining-app",
                    "namespace": ns,
                    "deletionTimestamp": "2026-07-22T00:00:00Z",
                    "finalizers": []
                },
                "spec": {}
            })
            .to_string(),
        );

        replace_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                "draining-app".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            put_body,
        )
        .await
        .unwrap_or_else(|e| panic!("finalizer-drain PUT must succeed: {e:?}"));

        assert!(
            state.store.get(&key).await.unwrap().is_none(),
            "namespaced object must be hard-deleted once its last finalizer drains via PUT \
             — the same VolumeSnapshot-deletion-timeout bug applies to the namespaced route"
        );
    }

    /// Deleting a CR with finalizers must soft-delete (stamp deletionTimestamp) rather than
    /// hard-delete. Without this, finalizer-based lifecycle hooks (e.g. cleanup controllers)
    /// never run and resources leak. The object must remain in the store.
    #[tokio::test]
    async fn delete_cr_with_finalizer_soft_deletes_not_hard_deletes() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Seed a CR with a finalizer directly (bypassing create handler which stamps UID).
        let key = cr_store_key(group, plural, None, "finalizer-widget");
        let cr_body = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "finalizer-widget",
                "uid": "fin-uid-1",
                "resourceVersion": "1",
                "finalizers": ["example.io/protect"]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &key,
                Bytes::from(serde_json::to_vec(&cr_body).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        delete_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "finalizer-widget".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete with finalizer must succeed (soft-delete)");

        // Object must still exist (soft-deleted, not hard-deleted).
        let after = state
            .store
            .get(&key)
            .await
            .unwrap()
            .expect("CR with finalizer must still exist after delete — hard delete ignores finalizers and breaks lifecycle hooks");

        let obj: serde_json::Value = serde_json::from_slice(&after.value).unwrap();
        assert!(
            !obj["metadata"]["deletionTimestamp"].is_null()
                && obj["metadata"]["deletionTimestamp"].as_str().is_some(),
            "soft-deleted CR must have deletionTimestamp set so finalizer controllers know to run cleanup"
        );
    }

    /// Deleting a CR owner must cascade transitively through ownership chains.
    /// owner → dependent → grand-dependent: all three must be deleted.
    /// Without transitive cascade, intermediate nodes survive and leak,
    /// violating GC semantics for CR ownership chains.
    #[tokio::test]
    async fn delete_cr_owner_cascades_transitively_through_ownership_chain() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Create owner.
        let owner_raw = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "chain-owner" },
                "spec": {}
            })
            .to_string(),
        );
        create_cr(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            test_user(),
            axum::http::HeaderMap::new(),
            owner_raw,
        )
        .await
        .unwrap();
        let owner_uid = {
            let s = state
                .store
                .get(&cr_store_key(group, plural, None, "chain-owner"))
                .await
                .unwrap()
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&s.value).unwrap()["metadata"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // Seed intermediate dependent owned by owner.
        let dep_key = cr_store_key(group, plural, None, "chain-dep");
        let dep_uid = "chain-dep-uid";
        let dep_body = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "chain-dep",
                "uid": dep_uid,
                "ownerReferences": [{
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "name": "chain-owner",
                    "uid": owner_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &dep_key,
                Bytes::from(serde_json::to_vec(&dep_body).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Seed grand-dependent owned by dep.
        let grand_key = cr_store_key(group, plural, None, "chain-grand");
        let grand_body = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": {
                "name": "chain-grand",
                "uid": "chain-grand-uid",
                "ownerReferences": [{
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "name": "chain-dep",
                    "uid": dep_uid,
                    "controller": true
                }]
            },
            "spec": {}
        });
        state
            .store
            .put(
                &grand_key,
                Bytes::from(serde_json::to_vec(&grand_body).unwrap()),
                Some(0),
            )
            .await
            .unwrap();

        // Delete chain owner.
        delete_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "chain-owner".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .unwrap();

        let dep_after = state.store.get(&dep_key).await.unwrap();
        assert!(
            dep_after.is_none(),
            "intermediate dependent must be cascade-deleted when owner is deleted"
        );

        let grand_after = state.store.get(&grand_key).await.unwrap();
        assert!(
            grand_after.is_none(),
            "grand-dependent must be transitively cascade-deleted — non-recursive cascade leaves intermediate nodes and leaks CRs"
        );
    }

    /// Creating a CR via the API with ownerReferences in metadata must preserve those
    /// references in storage. stamp_cr_fields rounds-trips metadata through ObjectMeta;
    /// if ObjectMeta ever stops modeling ownerReferences, this round-trip would silently
    /// drop them — cascade_delete_cr_dependents then can't find dependents and GC
    /// conformance 'should support cascading deletion of custom resources' fails.
    #[tokio::test]
    async fn create_cr_via_api_preserves_owner_references() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io";
        let version = "v1";
        let plural = "widgets";

        // Create owner first to get a UID.
        create_cr(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "metadata": { "name": "ownerref-owner" },
                    "spec": {}
                })
                .to_string(),
            ),
        )
        .await
        .expect("create owner");

        let owner_uid = {
            let s = state
                .store
                .get(&cr_store_key(group, plural, None, "ownerref-owner"))
                .await
                .unwrap()
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&s.value).unwrap()["metadata"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // Create dependent with ownerReference via the create_cr API handler.
        create_cr(
            State(state.clone()),
            Path((group.to_string(), version.to_string(), plural.to_string())),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "example.io/v1",
                    "kind": "Widget",
                    "metadata": {
                        "name": "ownerref-dep",
                        "ownerReferences": [{
                            "apiVersion": "example.io/v1",
                            "kind": "Widget",
                            "name": "ownerref-owner",
                            "uid": owner_uid,
                            "controller": true,
                            "blockOwnerDeletion": true
                        }]
                    },
                    "spec": {}
                })
                .to_string(),
            ),
        )
        .await
        .expect("create dependent");

        // Read back the dependent and verify ownerReferences survived the create round-trip.
        let dep_stored = state
            .store
            .get(&cr_store_key(group, plural, None, "ownerref-dep"))
            .await
            .unwrap()
            .unwrap();
        let dep_obj: serde_json::Value = serde_json::from_slice(&dep_stored.value).unwrap();
        let refs = dep_obj["metadata"]["ownerReferences"].as_array();
        assert!(
            refs.is_some() && !refs.unwrap().is_empty(),
            "ownerReferences must be preserved through create_cr — stamp_cr_fields \
             rounds-trips metadata through ObjectMeta; if ownerReferences were dropped, \
             cascade could not find dependents and GC conformance would fail"
        );
        assert_eq!(
            refs.unwrap()[0]["uid"].as_str(),
            Some(owner_uid.as_str()),
            "the ownerReference uid must match the owner's uid"
        );

        // Delete owner — cascade must find the API-created dependent and delete it.
        delete_cr(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                plural.to_string(),
                "ownerref-owner".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete owner");

        let dep_after = state
            .store
            .get(&cr_store_key(group, plural, None, "ownerref-dep"))
            .await
            .unwrap();
        assert!(
            dep_after.is_none(),
            "cascade must delete a dependent that was created via the API with ownerReferences — \
             if ownerRefs were dropped by create, cascade has nothing to match and the dependent leaks"
        );
    }

    /// Creating a NAMESPACED CR via the API with ownerReferences in metadata must preserve
    /// those references in storage. create_cr_namespaced round-trips metadata through
    /// ObjectMeta twice (once to stamp namespace, once in stamp_cr_fields); if either
    /// round-trip ever dropped ownerReferences, cascade_delete_cr_dependents could not find
    /// dependents and any namespaced CR-owns-CR relationship would silently lose its
    /// GC/cascade-delete link.
    #[tokio::test]
    async fn create_cr_namespaced_via_api_preserves_owner_references() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io";
        let version = "v1alpha1";
        let plural = "applications";
        let ns = "argocd";

        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            app_body("ownerref-owner", ns),
        )
        .await
        .expect("create owner");

        let owner_uid = {
            let s = state
                .store
                .get(&cr_store_key(group, plural, Some(ns), "ownerref-owner"))
                .await
                .unwrap()
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&s.value).unwrap()["metadata"]["uid"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // Create dependent with ownerReference via the create_cr_namespaced API handler.
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "argoproj.io/v1alpha1",
                    "kind": "Application",
                    "metadata": {
                        "name": "ownerref-dep",
                        "namespace": ns,
                        "ownerReferences": [{
                            "apiVersion": "argoproj.io/v1alpha1",
                            "kind": "Application",
                            "name": "ownerref-owner",
                            "uid": owner_uid,
                            "controller": true,
                            "blockOwnerDeletion": true
                        }]
                    },
                    "spec": { "destination": { "namespace": "default" } }
                })
                .to_string(),
            ),
        )
        .await
        .expect("create dependent");

        // Read back the dependent and verify ownerReferences survived the create round-trip.
        let dep_stored = state
            .store
            .get(&cr_store_key(group, plural, Some(ns), "ownerref-dep"))
            .await
            .unwrap()
            .unwrap();
        let dep_obj: serde_json::Value = serde_json::from_slice(&dep_stored.value).unwrap();
        let refs = dep_obj["metadata"]["ownerReferences"].as_array();
        assert!(
            refs.is_some() && !refs.unwrap().is_empty(),
            "ownerReferences must be preserved through create_cr_namespaced — the namespace-\
             setting ObjectMeta round-trip runs before stamp_cr_fields's own round-trip, so if \
             either one dropped ownerReferences, cascade_delete_cr_dependents could never find \
             this dependent by uid"
        );
        assert_eq!(
            refs.unwrap()[0]["uid"].as_str(),
            Some(owner_uid.as_str()),
            "the ownerReference uid must match the owner's uid"
        );

        // Delete owner — cascade must find the API-created dependent and delete it.
        delete_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                version.to_string(),
                ns.to_string(),
                plural.to_string(),
                "ownerref-owner".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete owner");

        let dep_after = state
            .store
            .get(&cr_store_key(group, plural, Some(ns), "ownerref-dep"))
            .await
            .unwrap();
        assert!(
            dep_after.is_none(),
            "cascade must delete a namespaced dependent that was created via the API with \
             ownerReferences — if ownerRefs were dropped by create, cascade has nothing to \
             match and the dependent leaks"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression tests: put_cr_status must CAS on the INCOMING
    // body's metadata.resourceVersion, not the stored object's RV.
    // ---------------------------------------------------------------------------

    /// put_cr_status with a stale resourceVersion in the body must return 409 Conflict.
    ///
    /// Without this fix put_cr_status used the stored object's RV as the CAS token,
    /// making every PUT unconditional — a controller with a stale snapshot of the CR
    /// would silently overwrite a peer's concurrent status write instead of receiving
    /// 409 and retrying from a fresh GET.
    #[tokio::test]
    async fn put_cr_status_stale_rv_returns_409_else_concurrent_writers_clobber() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        // Create the CR (rv=1 from the store).
        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "stale-widget" },
                "spec": { "color": "green" }
            })
            .to_string(),
        );
        assert!(
            create_cr(
                State(state.clone()),
                Path(("example.io".into(), "v1".into(), "widgets".into())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // Read rv1 from the store.
        let key = "/registry/cr/example.io/widgets/stale-widget";
        let stored = state.store.get(key).await.unwrap().unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&stored.value).unwrap();
        let rv1: u64 = obj["metadata"]["resourceVersion"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        // Advance to rv2 (peer writer succeeds).
        let mut obj2 = obj.clone();
        obj2["status"] = serde_json::json!({ "peer": true });
        let rv2 = state
            .store
            .put(
                key,
                Bytes::from(serde_json::to_vec(&obj2).unwrap()),
                Some(rv1),
            )
            .await
            .unwrap();
        assert!(rv2 > rv1, "rv must advance after peer write");

        // PUT /status body carries the now-stale rv1 — must be rejected with 409.
        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "stale-widget", "resourceVersion": rv1.to_string() },
                "status": { "ready": false }
            })
            .to_string(),
        );
        let result = put_cr_status(
            State(state.clone()),
            Path((
                "example.io".into(),
                "v1".into(),
                "widgets".into(),
                "stale-widget".into(),
            )),
            axum::http::HeaderMap::new(),
            put_body,
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!(
                "stale-rv PUT to put_cr_status must return 409 — \
                 without this check concurrent controllers silently clobber CR status writes"
            ),
        };
        assert_eq!(
            err.0,
            axum::http::StatusCode::CONFLICT,
            "stale resourceVersion in PUT /cr/status body must return 409 Conflict — \
             controllers must retry from a fresh GET when they lose the CAS race"
        );
    }

    /// put_cr_status with an absent resourceVersion in the body succeeds unconditionally.
    ///
    /// Upstream k8s allows omitting resourceVersion in a subresource PUT, treating it as
    /// an unconditional write.  The fix must not break this.
    #[tokio::test]
    async fn put_cr_status_absent_rv_is_unconditional_write() {
        let state = make_state();
        install_cluster_crd_with_status_subresource(&state).await;

        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "norev-widget" },
                "spec": { "color": "red" }
            })
            .to_string(),
        );
        assert!(
            create_cr(
                State(state.clone()),
                Path(("example.io".into(), "v1".into(), "widgets".into())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        // PUT body with no resourceVersion — must succeed as unconditional write.
        let put_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "norev-widget" },
                "status": { "ready": true }
            })
            .to_string(),
        );
        let result = put_cr_status(
            State(state.clone()),
            Path((
                "example.io".into(),
                "v1".into(),
                "widgets".into(),
                "norev-widget".into(),
            )),
            axum::http::HeaderMap::new(),
            put_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "absent resourceVersion in PUT /cr/status body must succeed (unconditional write) — \
             single-writer clients that omit rv must not be broken by the stale-RV CAS fix"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression test: non-storage-version CR writes must deliver
    // watch events on the storage-version prefix (FieldValidation conformance tests).
    //
    // Root cause: create_cr/delete_cr used the REQUEST version in the store key, but
    // list_cr/watch already remapped the key prefix to the STORAGE version. This caused
    // events emitted for non-storage-version operations to be silently filtered out by
    // the watch's prefix check — matching nothing because the key used v1beta1 while
    // the watch listened on v1.
    //
    // The conformance test helper `isWatchCachePrimed` (fixtures/resources.go) uses
    // exactly this pattern: creates + deletes a probe CR via the first SERVED version
    // (v1beta1, which is non-storage), then watches from the create RV and expects a
    // DELETED event. Without the fix, no event arrives and all 5 FieldValidation tests
    // fail with "cannot create crd gave up waiting for watch event".
    // ---------------------------------------------------------------------------

    /// A CR created then deleted via a non-storage version must deliver a DELETED watch
    /// event at that version's endpoint.
    ///
    /// WHY this matters: the k8s conformance helper `isWatchCachePrimed` uses the first
    /// served version (often non-storage) to probe watch readiness. A missing DELETED event
    /// causes all 5 FieldValidation [Conformance] tests to time out with "gave up waiting
    /// for watch event". Without this fix those tests fail and the suite regresses.
    #[tokio::test]
    async fn non_storage_version_cr_write_delivers_delete_watch_event() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use tokio::time::{timeout, Duration};

        let state = make_state();

        // Install a multi-version CRD: v1beta1 is served but NOT the storage version;
        // v1 is the storage version. This matches the CRD shape used by the FieldValidation
        // conformance test (NewRandomNameMultipleVersionCustomResourceDefinition).
        let multi_version_crd = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gadgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "gadgets",
                        "singular": "gadget",
                        "kind": "Gadget",
                        "listKind": "GadgetList"
                    },
                    "scope": "Cluster",
                    "versions": [
                        { "name": "v1beta1", "served": true, "storage": false },
                        { "name": "v1",      "served": true, "storage": true  }
                    ]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            multi_version_crd,
        )
        .await
        .expect("install multi-version CRD");

        // Step 1: create the probe CR via v1beta1 (non-storage version).
        let probe_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1beta1",
                "kind": "Gadget",
                "metadata": { "name": "probe" },
                "spec": {}
            })
            .to_string(),
        );
        let create_resp = create_cr(
            State(state.clone()),
            Path(("example.io".into(), "v1beta1".into(), "gadgets".into())),
            test_user(),
            axum::http::HeaderMap::new(),
            probe_body,
        )
        .await
        .expect("create probe CR via non-storage version");
        let create_body = to_bytes(create_resp.into_response().into_body(), usize::MAX)
            .await
            .expect("read create response body");
        let create_json: serde_json::Value =
            serde_json::from_slice(&create_body).expect("parse create response");
        let create_rv: u64 = create_json["metadata"]["resourceVersion"]
            .as_str()
            .expect("resourceVersion must be a string")
            .parse()
            .expect("resourceVersion must parse as u64");

        // Step 2: open a watch at the create RV on the v1beta1 endpoint.
        // This must observe the upcoming DELETE event even though v1 is the storage version.
        // timeout_seconds=2 closes the stream after 2s; the outer timeout is 15s so CI
        // (slower than a local dev machine) still has 13s of slack after the stream closes.
        let watch_q = super::super::generic::CollectionQuery {
            watch: Some(true),
            resource_version: Some(create_rv),
            label_selector: None,
            field_selector: None,
            limit: None,
            continue_token: None,
            send_initial_events: None,
            allow_watch_bookmarks: None,
            timeout_seconds: Some(2),
        };
        let watch_resp = list_cr(
            State(state.clone()),
            Path(("example.io".into(), "v1beta1".into(), "gadgets".into())),
            axum::http::HeaderMap::new(),
            watch_q,
            "test-user".into(),
        )
        .await
        .expect("open watch on v1beta1 endpoint");
        assert_eq!(watch_resp.status(), StatusCode::OK);

        // Step 3: delete the probe CR via v1beta1.
        delete_cr(
            State(state.clone()),
            Path((
                "example.io".into(),
                "v1beta1".into(),
                "gadgets".into(),
                "probe".into(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .expect("delete probe CR via non-storage version");

        // Step 4: collect the watch stream (15s outer timeout) and assert a DELETED event
        // arrives. The server closes the stream after timeout_seconds=2; we wait up to 15s
        // so CI latency does not cause the outer timer to fire before the server closes.
        //
        // If the fix is reverted, create_cr/delete_cr use `v1beta1` in the key while the
        // watch uses the `v1` prefix — the DELETE event key never starts with the v1 prefix
        // → the event is filtered → the stream ends without DELETED → assertion fails.
        let body = timeout(
            Duration::from_secs(15),
            to_bytes(watch_resp.into_body(), usize::MAX),
        )
        .await
        .expect("watch stream must complete within 15 seconds")
        .expect("collect watch stream body");
        let body_str = std::str::from_utf8(&body).expect("body must be valid UTF-8");

        assert!(
            body_str.contains("\"DELETED\""),
            "watch on non-storage-version (v1beta1) endpoint must receive DELETED event when \
             CR is deleted via that version — without this, the k8s conformance helper \
             isWatchCachePrimed times out and all 5 FieldValidation tests fail with \
             'cannot create crd gave up waiting for watch event'; body={body_str:?}"
        );
    }

    /// A CR created while v1 is the CRD's storage version must still be reachable — by
    /// GET and PATCH, through any served version — after the CRD is later patched to make
    /// a *different* served version (v2) the storage version. This is the exact
    /// "AdmissionWebhook ... mutate custom resource with different stored version"
    /// conformance flow: create via the storage version, flip storage to another served
    /// version, then patch through the new storage version.
    ///
    /// WHY this matters: a CR's stored bytes never move when a CRD's storage-version
    /// pointer changes — only which version is used to interpret/serve them. If the
    /// storage key instead embeds whatever find_crd resolves as the *current* storage
    /// version, then the instant that pointer moves, every already-written object
    /// becomes unreachable through every version (old and new alike), because the key
    /// computed at request time never matches the key the object was actually written
    /// under. Without this fix, every multi-version CRD 404s the moment its storage
    /// version changes.
    #[tokio::test]
    async fn cr_survives_storage_version_change_and_is_reachable_via_new_storage_version() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();
        let group = "multiver.example.com";
        let plural = "gizmos";
        let ns = "default";

        // v1 storage, v2 served-not-storage — the shape the conformance test starts from.
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gizmos.multiver.example.com" },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": plural,
                        "singular": "gizmo",
                        "kind": "Gizmo",
                        "listKind": "GizmoList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true },
                        { "name": "v2", "served": true, "storage": false }
                    ]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("install multi-version CRD");

        // Create the CR while v1 is the storage version.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "multiver.example.com/v1",
                "kind": "Gizmo",
                "metadata": { "name": "cr-instance-1", "namespace": ns },
                "data": { "mutation-start": "yes" }
            })
            .to_string(),
        );
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await
        .expect("create CR via v1 (storage version)");

        // Flip the CRD's storage version: v1 no longer storage, v2 becomes storage.
        // Mirrors the conformance test's StrategicMergePatchType on spec.versions.
        let storage_flip = Bytes::from(
            serde_json::json!({
                "spec": {
                    "versions": [
                        { "name": "v1", "served": true, "storage": false },
                        { "name": "v2", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        );
        let mut strategic_headers = axum::http::HeaderMap::new();
        strategic_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        crd::patch_crd(
            State(state.clone()),
            Path("gizmos.multiver.example.com".to_string()),
            test_user(),
            strategic_headers,
            storage_flip,
        )
        .await
        .expect("flip CRD storage version from v1 to v2");

        // The now-non-storage v1 endpoint must still find the object (GET does not 404).
        get_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
                "cr-instance-1".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect(
            "GET via v1 after the storage version moved to v2 must not 404 — the object's \
             bytes never moved, only which version is now considered storage",
        );

        // PATCH through the new storage version (v2) must find and update the same object —
        // this is the literal conformance assertion that was failing with 404.
        let dummy_patch = Bytes::from(
            serde_json::json!([{ "op": "add", "path": "/dummy", "value": "test" }]).to_string(),
        );
        let patch_resp = patch_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v2".to_string(),
                ns.to_string(),
                plural.to_string(),
                "cr-instance-1".to_string(),
            )),
            test_user(),
            json_patch_headers(),
            dummy_patch,
        )
        .await
        .expect(
            "PATCH via v2 must find the CR written under the v1 storage key — a 404 here \
             means the storage key still depends on the CRD's *current* storage-version \
             pointer instead of being version-independent",
        )
        .into_response();

        let body = to_bytes(patch_resp.into_body(), usize::MAX)
            .await
            .expect("read patch response body");
        let patched: serde_json::Value =
            serde_json::from_slice(&body).expect("parse patch response");
        assert_eq!(
            patched["data"]["mutation-start"], "yes",
            "the object patched via v2 must be the same object created via v1, not a fresh \
             empty one created at a new key"
        );
        assert_eq!(
            patched["dummy"], "test",
            "the JSON patch applied via the v2 endpoint must be persisted"
        );
        assert_eq!(
            patched["apiVersion"], "multiver.example.com/v2",
            "the response must reflect the version this request targeted, not whatever \
             stale version the object happened to be stamped with when first created"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression: conversion webhook must not be called for a version-to-itself
    // request after a CRD's storage version has moved on.
    //
    // Root cause: the "does this object need conversion" check compared the
    // REQUESTED version against the CRD's CURRENTLY CONFIGURED storage version,
    // not the object's OWN actually-stored apiVersion. A CR written while storage
    // was v1, then requested again at v1 after the CRD's storage version moved to
    // v2, needs no conversion (the request already matches the object's stored
    // version) — but the old check compared against the new storage version (v2),
    // saw "v1" != "v2", and wrongly invoked the webhook for a self-conversion. Real
    // conversion webhooks (and the conformance suite's sample webhook) explicitly
    // detect and reject that as a client bug, failing GET/LIST outright.
    // ---------------------------------------------------------------------------

    /// GET of a CR at its OWN already-stored version must not call the conversion
    /// webhook, even after the CRD's storage version has since moved to a different
    /// served version.
    ///
    /// WHY this matters: a real conversion webhook (including the k8s conformance
    /// suite's sample webhook) rejects a "convert a version to itself" request as a
    /// client bug. If the fix is reverted, this GET (at v1, now the non-storage
    /// version) would call the mock webhook below — which is set up to succeed, so
    /// the request would still return 200, but with the mock's canned body instead
    /// of the real stored object, and the call counter would be nonzero. Both
    /// assertions below catch that regression.
    #[tokio::test]
    async fn get_cr_at_its_own_stored_version_skips_conversion_webhook_after_storage_flip() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use axum::routing::post;
        use axum::Router;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let router = Router::new().route(
            "/convert",
            post(move || {
                let call_count_clone = Arc::clone(&call_count_clone);
                async move {
                    call_count_clone.fetch_add(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": [{
                                "apiVersion": "selfconv.example.com/v1",
                                "kind": "Widget",
                                "metadata": {"name": "cr-instance-1"}
                            }]
                        }
                    }))
                }
            }),
        );
        let (base_url, _handle) = start_mock_conversion_server(router).await;

        let state = make_state();
        let group = "selfconv.example.com";
        let plural = "widgets";
        let ns = "default";

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.selfconv.example.com" },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": plural,
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true },
                        { "name": "v2", "served": true, "storage": false }
                    ],
                    "conversion": {
                        "strategy": "Webhook",
                        "webhook": { "clientConfig": { "url": format!("{base_url}/convert") } }
                    }
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("install multi-version CRD with conversion webhook");

        // Create the CR while v1 is the storage version — its stored apiVersion is v1.
        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "selfconv.example.com/v1",
                "kind": "Widget",
                "metadata": { "name": "cr-instance-1", "namespace": ns },
                "data": { "marker": "original" }
            })
            .to_string(),
        );
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await
        .expect("create CR via v1 (storage version)");

        // Flip the CRD's storage version: v1 no longer storage, v2 becomes storage.
        // The object's bytes — and its own stored apiVersion — do not change.
        let storage_flip = Bytes::from(
            serde_json::json!({
                "spec": {
                    "versions": [
                        { "name": "v1", "served": true, "storage": false },
                        { "name": "v2", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        );
        let mut strategic_headers = axum::http::HeaderMap::new();
        strategic_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        crd::patch_crd(
            State(state.clone()),
            Path("widgets.selfconv.example.com".to_string()),
            test_user(),
            strategic_headers,
            storage_flip,
        )
        .await
        .expect("flip CRD storage version from v1 to v2");

        // GET at v1 — the object's OWN stored version — even though v2 is now the
        // CRD's configured storage version.
        let resp = get_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
                "cr-instance-1".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect("GET at the object's own stored version must succeed")
        .into_response();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "GET at v1 must NOT call the conversion webhook: the object's own stored \
             apiVersion already IS v1, so this is a version-to-itself request, which \
             real conversion webhooks (and the conformance suite's sample webhook) \
             reject as a client bug — comparing against the CRD's *current* storage \
             version (now v2) instead of the object's own version wrongly triggers it"
        );

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read GET response body");
        let obj: serde_json::Value = serde_json::from_slice(&body).expect("parse GET response");
        assert_eq!(
            obj["apiVersion"], "selfconv.example.com/v1",
            "the object must be returned exactly as stored, not replaced by whatever \
             the (incorrectly invoked) webhook would have returned"
        );
        assert_eq!(
            obj["data"]["marker"], "original",
            "the object's data must be untouched — a spurious webhook round-trip would \
             have replaced it with the mock webhook's canned response"
        );
    }

    /// LIST across a non-homogeneous set of CRs — one written before, one written
    /// after a CRD storage-version change — must send only the item whose OWN stored
    /// apiVersion differs from the requested one through the conversion webhook.
    ///
    /// WHY this matters: this is the exact upstream "should be able to convert a non
    /// homogeneous list of CRs" conformance scenario. Deciding once for the whole
    /// page (based on the CRD's current storage-version pointer) instead of per item
    /// sends an item that already matches the request through the webhook as a
    /// version-to-itself conversion — which real webhooks reject outright, failing
    /// the entire list response instead of just converting the one item that needed it.
    #[tokio::test]
    async fn list_cr_only_converts_items_whose_own_version_differs_from_requested() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use axum::routing::post;
        use axum::Router;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let call_count: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let objects_seen: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let objects_seen_clone = Arc::clone(&objects_seen);
        let router = Router::new().route(
            "/convert",
            post(move |axum::Json(review): axum::Json<serde_json::Value>| {
                let call_count_clone = Arc::clone(&call_count_clone);
                let objects_seen_clone = Arc::clone(&objects_seen_clone);
                async move {
                    call_count_clone.fetch_add(1, Ordering::SeqCst);
                    let objects = review["request"]["objects"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    objects_seen_clone.fetch_add(objects.len(), Ordering::SeqCst);
                    let desired = review["request"]["desiredAPIVersion"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    // Echo the objects back, relabeled, so converted items are
                    // distinguishable in the test's assertions below.
                    let converted: Vec<serde_json::Value> = objects
                        .into_iter()
                        .map(|mut o| {
                            o["apiVersion"] = serde_json::Value::String(desired.clone());
                            o["webhookTouched"] = serde_json::Value::Bool(true);
                            o
                        })
                        .collect();
                    axum::Json(serde_json::json!({
                        "apiVersion": "apiextensions.k8s.io/v1",
                        "kind": "ConversionReview",
                        "response": {
                            "uid": "test-uid",
                            "result": {"status": "Success"},
                            "convertedObjects": converted
                        }
                    }))
                }
            }),
        );
        let (base_url, _handle) = start_mock_conversion_server(router).await;

        let state = make_state();
        let group = "nonhomog.example.com";
        let plural = "widgets";
        let ns = "default";

        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.nonhomog.example.com" },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": plural,
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true },
                        { "name": "v2", "served": true, "storage": false }
                    ],
                    "conversion": {
                        "strategy": "Webhook",
                        "webhook": { "clientConfig": { "url": format!("{base_url}/convert") } }
                    }
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("install multi-version CRD with conversion webhook");

        // cr-a: written while v1 is the storage version — its own stored apiVersion is v1.
        let cr_a = Bytes::from(
            serde_json::json!({
                "apiVersion": "nonhomog.example.com/v1",
                "kind": "Widget",
                "metadata": { "name": "cr-a", "namespace": ns },
                "data": { "marker": "a" }
            })
            .to_string(),
        );
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_a,
        )
        .await
        .expect("create cr-a via v1");

        // Flip the CRD's storage version: v1 no longer storage, v2 becomes storage.
        let storage_flip = Bytes::from(
            serde_json::json!({
                "spec": {
                    "versions": [
                        { "name": "v1", "served": true, "storage": false },
                        { "name": "v2", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        );
        let mut strategic_headers = axum::http::HeaderMap::new();
        strategic_headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/strategic-merge-patch+json"),
        );
        crd::patch_crd(
            State(state.clone()),
            Path("widgets.nonhomog.example.com".to_string()),
            test_user(),
            strategic_headers,
            storage_flip,
        )
        .await
        .expect("flip CRD storage version from v1 to v2");

        // cr-b: written via v2 AFTER the flip — its own stored apiVersion is v2.
        let cr_b = Bytes::from(
            serde_json::json!({
                "apiVersion": "nonhomog.example.com/v2",
                "kind": "Widget",
                "metadata": { "name": "cr-b", "namespace": ns },
                "data": { "marker": "b" }
            })
            .to_string(),
        );
        create_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v2".to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_b,
        )
        .await
        .expect("create cr-b via v2");

        // LIST at v1: a non-homogeneous mix of one object already at v1 (cr-a) and
        // one still stored at v2 (cr-b).
        let resp = list_cr_namespaced(
            State(state.clone()),
            Path((
                group.to_string(),
                "v1".to_string(),
                ns.to_string(),
                plural.to_string(),
            )),
            axum::http::HeaderMap::new(),
            no_watch_query(),
            "test-user".into(),
        )
        .await
        .expect("LIST at v1 over a non-homogeneous set must succeed")
        .into_response();

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "the webhook must be called exactly once (one batched call carrying only \
             cr-b) — calling it again for cr-a (already at v1) would be a \
             version-to-itself conversion that real webhooks reject as a client bug"
        );
        assert_eq!(
            objects_seen.load(Ordering::SeqCst),
            1,
            "only cr-b (stored at v2) may ever be sent to the webhook; cr-a already \
             matches the requested v1 and must never appear in a conversion request"
        );

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read LIST response body");
        let list: serde_json::Value = serde_json::from_slice(&body).expect("parse LIST response");
        let items = list["items"].as_array().expect("items must be an array");
        assert_eq!(
            items.len(),
            2,
            "both cr-a and cr-b must be present in the list"
        );

        let a = items
            .iter()
            .find(|it| it["metadata"]["name"] == "cr-a")
            .expect("cr-a must be in the list");
        assert!(
            a.get("webhookTouched").is_none(),
            "cr-a already matched the requested version v1 and must be returned as-is, \
             never routed through the conversion webhook"
        );
        assert_eq!(
            a["data"]["marker"], "a",
            "cr-a's data must be unchanged since it required no conversion"
        );

        let b = items
            .iter()
            .find(|it| it["metadata"]["name"] == "cr-b")
            .expect("cr-b must be in the list");
        assert_eq!(
            b["webhookTouched"], true,
            "cr-b was stored at v2 and requested at v1, so it must have gone through \
             the conversion webhook"
        );
        assert_eq!(
            b["apiVersion"], "nonhomog.example.com/v1",
            "cr-b must be relabeled to the requested version by the conversion webhook"
        );
    }

    // ---------------------------------------------------------------------------
    // Regression test (SSA upsert): apply-patch+yaml on a missing
    // cluster-scoped CR must CREATE it (201), not return 404.
    //
    // Root cause: patch_cr returned 404 for objects not yet in the store even when
    // the Content-Type was application/apply-patch+yaml (SSA). The conformance test
    // at field_validation.go:278 sends a PATCH to create 'mytest' — without the
    // upsert path, 404 causes "the server could not find the requested resource".
    //
    // The client sends a JSON-encoded body even with the +yaml content-type (the
    // same as resource.rs's SSA upsert which also uses serde_json::from_slice).
    // ---------------------------------------------------------------------------

    /// An SSA apply-patch+yaml on a non-existent cluster-scoped CR must return 201.
    ///
    /// WHY this matters: the k8s conformance test "should create/apply a valid CR for CRD
    /// with validation schema" creates 'mytest' via apply-patch+yaml. Without the upsert
    /// path, patch_cr returns 404 and the test fails with "the server could not find the
    /// requested resource". The fix is required alongside the storage-version key fix.
    #[tokio::test]
    async fn ssa_apply_patch_creates_cluster_scoped_cr_when_absent() {
        use crate::handlers::crd;
        use axum::body::to_bytes;
        use axum::response::IntoResponse;

        let state = make_state();

        // Install a CRD with a single v1 version.
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "things.ssa.example.com" },
                "spec": {
                    "group": "ssa.example.com",
                    "names": {
                        "plural": "things",
                        "singular": "thing",
                        "kind": "Thing",
                        "listKind": "ThingList"
                    },
                    "scope": "Cluster",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true
                    }]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("install CRD");

        // Send an SSA PATCH with a JSON body (as the k8s client sends, despite the +yaml
        // content-type). The object does not exist — must be created with 201.
        let patch_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "ssa.example.com/v1",
                "kind": "Thing",
                "metadata": { "name": "mytest" },
                "spec": { "foo": "bar" }
            })
            .to_string(),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let resp = patch_cr(
            State(state.clone()),
            Path((
                "ssa.example.com".into(),
                "v1".into(),
                "things".into(),
                "mytest".into(),
            )),
            test_user(),
            headers,
            patch_body,
        )
        .await
        .expect("SSA upsert must not return Err")
        .into_response();

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::CREATED,
            "apply-patch+yaml on a missing cluster-scoped CR must return 201 CREATED — \
             without the SSA upsert path, patch_cr returns 404 and the conformance test \
             field_validation.go:278 fails with 'the server could not find the requested resource'"
        );

        let body_bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let resp_obj: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("response must be valid JSON");
        assert_eq!(
            resp_obj["spec"]["foo"].as_str(),
            Some("bar"),
            "the created CR must have spec.foo='bar' as sent in the patch body"
        );
    }

    // ---------------------------------------------------------------------------
    // CR fieldValidation regression tests
    //
    // Root cause: resource.rs routes any CR request to cr.rs BEFORE its own
    // apply_field_validation runs, and cr.rs never checked ?fieldValidation= at all — so
    // CRs silently accepted unknown/typo'd fields regardless of the CRD's schema. These
    // tests exercise the real handler entry points (create_cr / patch_cr's SSA-upsert
    // path) with the internal x-u7s-field-validation header that resource.rs sets from
    // the query string, so a regression that drops the wiring (not just the detection
    // algorithm) also fails these tests.
    // ---------------------------------------------------------------------------

    fn strict_field_validation_headers() -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_static(FIELD_VALIDATION_HEADER),
            axum::http::HeaderValue::from_static("Strict"),
        );
        headers
    }

    async fn install_cluster_crd_with_schema(state: &AppState, schema: serde_json::Value) {
        use crate::handlers::crd;
        let crd_bytes = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget",
                        "listKind": "WidgetList"
                    },
                    "scope": "Cluster",
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": { "openAPIV3Schema": schema }
                    }]
                }
            })
            .to_string(),
        );
        crd::create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            crd_bytes,
        )
        .await
        .expect("install CRD with schema");
    }

    /// create_cr with fieldValidation=Strict must reject a top-level property the CRD
    /// schema does not declare, naming the offending field.
    ///
    /// WHY: this is how kubectl create/apply --validate=strict catches a typo'd field
    /// name in a CR. Before this fix, cr.rs never checked fieldValidation at all — the
    /// CR was silently stored with the typo'd field, so schema drift went undetected
    /// (k8s conformance "should create/apply an invalid CR with extra properties").
    #[tokio::test]
    async fn create_cr_strict_field_validation_rejects_unknown_top_level_property() {
        let state = make_state();
        install_cluster_crd_with_schema(
            &state,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "spec": {
                        "type": "object",
                        "properties": { "foo": { "type": "string" } }
                    }
                }
            }),
        )
        .await;

        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "mytest" },
                "spec": { "foo": "foo1" },
                "unknownField": "unknown"
            })
            .to_string(),
        );

        let err = expect_err_status(
            create_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                )),
                test_user(),
                strict_field_validation_headers(),
                cr_body,
            )
            .await,
            "CR with an unknown top-level property must be rejected under fieldValidation=Strict",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "must return 422 Unprocessable Entity");
        let msg = err.1.message;
        assert!(
            msg.contains("unknown field \"unknownField\""),
            "error message must name the offending field, in upstream's exact \
             `unknown field \"<path>\"` wording (kubectl/conformance grep on that phrase, \
             not ours) so the client can fix its typo (got: {msg})"
        );
    }

    /// A schema-valid CR must be accepted under fieldValidation=Strict — the detector
    /// must not produce false positives on properties the schema actually declares.
    #[tokio::test]
    async fn create_cr_strict_field_validation_accepts_valid_body() {
        let state = make_state();
        install_cluster_crd_with_schema(
            &state,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "spec": {
                        "type": "object",
                        "properties": { "foo": { "type": "string" } }
                    }
                }
            }),
        )
        .await;

        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "mytest" },
                "spec": { "foo": "foo1" }
            })
            .to_string(),
        );

        let result = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            strict_field_validation_headers(),
            cr_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "a CR with only schema-declared fields must not be rejected by fieldValidation=Strict"
        );
    }

    /// Schema for the two tests below: mirrors the k8s conformance test "should detect
    /// unknown metadata fields in both the root and embedded object of a CR" — `spec` has
    /// x-kubernetes-preserve-unknown-fields, and `spec.template` is an
    /// x-kubernetes-embedded-resource whose own `metadata` only declares `name`.
    fn preserve_unknown_and_embedded_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-preserve-unknown-fields": true,
                    "properties": {
                        "template": {
                            "type": "object",
                            "x-kubernetes-embedded-resource": true,
                            "properties": {
                                "metadata": {
                                    "type": "object",
                                    "properties": { "name": { "type": "string" } }
                                },
                                "spec": { "type": "object" }
                            }
                        },
                        "foo": { "type": "string" }
                    }
                }
            }
        })
    }

    /// patch_cr's SSA-upsert path with fieldValidation=Strict must reject unknown metadata
    /// fields both at the CR root and inside an x-kubernetes-embedded-resource object, using
    /// the dotted structured-merge-diff wording SSA requests report (not the quoted
    /// strict-decoding wording Create/Update uses).
    ///
    /// WHY: ObjectMeta is a fixed structure; a CRD schema never enumerates its fields, so
    /// unknown-field detection cannot rely on `properties` alone here — it must fall back
    /// to the fixed ObjectMeta field list at the root AND inside embedded resources.
    /// Missing either one would let typo'd metadata (e.g. `unknownMeta`) slip through
    /// undetected (k8s conformance "should detect unknown metadata fields in both the
    /// root and embedded object of a CR").
    #[tokio::test]
    async fn patch_cr_ssa_strict_rejects_unknown_metadata_at_root_and_in_embedded_object() {
        let state = make_state();
        install_cluster_crd_with_schema(&state, preserve_unknown_and_embedded_schema()).await;

        let mut headers = strict_field_validation_headers();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        let patch_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "mytest", "unknownMeta": "unknown" },
                "spec": {
                    "template": {
                        "apiVersion": "foo/v1",
                        "kind": "Sub",
                        "metadata": { "name": "subobject", "unknownSubMeta": "unknown" }
                    },
                    "foo": "foo1"
                }
            })
            .to_string(),
        );

        let err = expect_err_status(
            patch_cr(
                State(state.clone()),
                Path((
                    "example.io".to_string(),
                    "v1".to_string(),
                    "widgets".to_string(),
                    "mytest".to_string(),
                )),
                test_user(),
                headers,
                patch_body,
            )
            .await,
            "unknown metadata fields at the root and in an embedded object must be rejected",
        );

        let json = serde_json::to_value(&err.1).unwrap();
        assert_eq!(json["code"], 422, "must return 422 Unprocessable Entity");
        let msg = err.1.message;
        assert!(
            msg.contains(".metadata.unknownMeta: field not declared in schema"),
            "must flag the unknown field on the CR's own (root) metadata, in the dotted \
             structured-merge-diff wording upstream's SSA path reports (got: {msg})"
        );
        assert!(
            msg.contains(".spec.template.metadata.unknownSubMeta: field not declared in schema"),
            "must also flag the unknown field on the embedded object's metadata, in the \
             dotted structured-merge-diff wording upstream's SSA path reports (got: {msg})"
        );
    }

    /// `apply_cr_field_validation` must pick the unknown-field wording by request type, not
    /// collapse to one wording for both: SSA Apply-patch is validated by
    /// structured-merge-diff, which reports the dotted `.<path>: field not declared in
    /// schema` form the FieldValidation conformance tests grep for; Create/Update goes
    /// through strict decoding, which reports `unknown field "<path>"` the
    /// CustomResourcePublishOpenAPI conformance test greps for instead.
    ///
    /// WHY: a prior fix made this wording SSA-vs-Create/Update-agnostic by always emitting
    /// one of the two forms — whichever direction that blanket choice goes, it passes one
    /// upstream conformance suite while silently breaking the other, because both wordings
    /// are genuinely upstream-correct, just for different request types. This test fails
    /// if the branch is ever collapsed back to a single wording in either direction.
    #[test]
    fn apply_cr_field_validation_wording_branches_on_ssa_vs_create_update() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": { "foo": { "type": "string" } }
                }
            }
        });

        let cr_with_unknown_field = || {
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "mytest" },
                "spec": { "foo": "foo1" },
                "unknownField": "unknown"
            })
        };

        let mut ssa_body = cr_with_unknown_field();
        let ssa_err = apply_cr_field_validation(&mut ssa_body, Some(&schema), Some("Strict"), true)
            .expect_err("SSA apply of a CR with an unknown field must be rejected");
        assert!(
            ssa_err
                .1
                .message
                .contains(".unknownField: field not declared in schema"),
            "SSA Apply-patch must use upstream's dotted structured-merge-diff wording \
             (got: {})",
            ssa_err.1.message
        );

        // A fresh, unpruned body: `apply_cr_field_validation` prunes in place, so the SSA
        // call above already stripped `unknownField` out of `ssa_body`.
        let mut create_body = cr_with_unknown_field();
        let create_err =
            apply_cr_field_validation(&mut create_body, Some(&schema), Some("Strict"), false)
                .expect_err("Create/Update of a CR with an unknown field must be rejected");
        assert!(
            create_err
                .1
                .message
                .contains("unknown field \"unknownField\""),
            "Create/Update must keep upstream's strict-decoding wording, which \
             CustomResourcePublishOpenAPI asserts verbatim (got: {})",
            create_err.1.message
        );
        assert!(
            !create_err
                .1
                .message
                .contains("field not declared in schema"),
            "Create/Update must not regress to the SSA dotted wording (got: {})",
            create_err.1.message
        );
    }

    /// A subtree marked x-kubernetes-preserve-unknown-fields must NOT be rejected for
    /// carrying fields the schema doesn't declare — that is the entire purpose of the
    /// annotation, and CRDs like cert-manager and Argo rely on it for free-form spec
    /// fields. Only the always-fixed ObjectMeta and embedded-resource TypeMeta rules stay
    /// unaffected.
    #[tokio::test]
    async fn patch_cr_ssa_strict_allows_unknown_fields_under_preserve_unknown_fields_subtree() {
        let state = make_state();
        install_cluster_crd_with_schema(&state, preserve_unknown_and_embedded_schema()).await;

        let mut headers = strict_field_validation_headers();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/apply-patch+yaml"),
        );

        // `spec` has x-kubernetes-preserve-unknown-fields: true, so `spec.freeform` (not
        // declared anywhere in the schema) must be preserved, not rejected.
        let patch_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "mytest" },
                "spec": { "foo": "foo1", "freeform": { "anything": "goes" } }
            })
            .to_string(),
        );

        let result = patch_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "mytest".to_string(),
            )),
            test_user(),
            headers,
            patch_body,
        )
        .await;
        assert!(
            result.is_ok(),
            "an unknown field under an x-kubernetes-preserve-unknown-fields subtree must \
             not be rejected by fieldValidation=Strict"
        );
    }

    // ---------------------------------------------------------------------------
    // CR structural-schema pruning
    //
    // Root cause: cr.rs never pruned CR data against the CRD's structural schema at all —
    // `apply_cr_field_validation` only DETECTED unknown fields for ?fieldValidation=
    // reporting, it never removed them, so a CRD's schema was purely advisory. Two
    // consequences, both conformance failures:
    //   1. A field a mutating admission webhook adds (which the schema doesn't declare)
    //      survived in the stored object forever, because pruning never re-ran after
    //      mutating webhooks — real k8s prunes both at decode time AND again right before
    //      storage (AdmissionWebhook "should mutate custom resource with pruning").
    //   2. The ?fieldValidation=Strict rejection message used invented wording
    //      (".foo: field not declared in schema") instead of upstream's exact
    //      `unknown field "foo"` phrasing that kubectl/conformance greps for
    //      (CustomResourcePublishOpenAPI "works for CRD with validation schema").
    // ---------------------------------------------------------------------------

    /// `prune_cr_unknown_fields` must remove a key the schema does not declare while
    /// leaving schema-declared siblings untouched — this is the core mechanism both
    /// conformance failures trace back to (nothing pruned CR data before this fix).
    #[test]
    fn prune_cr_unknown_fields_removes_undeclared_key_keeps_declared_siblings() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "mutation-start": { "type": "string" },
                        "mutation-stage-1": { "type": "string" }
                        // mutation-stage-2 is intentionally undeclared, mirroring the
                        // upstream AdmissionWebhook pruning conformance test's CRD.
                    }
                }
            }
        });
        let mut obj = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "cr-instance-1" },
            "data": {
                "mutation-start": "yes",
                "mutation-stage-1": "yes",
                "mutation-stage-2": "yes"
            }
        });

        let mut out = Vec::new();
        prune_cr_unknown_fields(&mut obj, &schema, "", true, true, &mut out);

        assert_eq!(
            obj["data"],
            serde_json::json!({ "mutation-start": "yes", "mutation-stage-1": "yes" }),
            "an undeclared field a mutating webhook injected must be pruned, while \
             schema-declared fields must survive untouched (got: {:?})",
            obj["data"]
        );
        assert_eq!(
            out,
            vec!["data.mutation-stage-2".to_string()],
            "the pruned path must be reported without a leading dot, matching upstream's \
             field.Path wording used in `unknown field \"<path>\"` messages"
        );
    }

    /// A subtree marked `x-kubernetes-preserve-unknown-fields` must survive pruning
    /// entirely — this is the escape hatch CRDs like cert-manager rely on for free-form
    /// spec data, and a pruning implementation that ignores it would break them.
    #[test]
    fn prune_cr_unknown_fields_preserves_marked_subtree() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "x-kubernetes-preserve-unknown-fields": true,
                    "properties": { "foo": { "type": "string" } }
                }
            }
        });
        let mut obj = serde_json::json!({
            "apiVersion": "example.io/v1",
            "kind": "Widget",
            "metadata": { "name": "cr-instance-1" },
            "spec": { "foo": "foo1", "freeform": { "anything": "goes" } }
        });

        let mut out = Vec::new();
        prune_cr_unknown_fields(&mut obj, &schema, "", true, true, &mut out);

        assert_eq!(
            obj["spec"]["freeform"],
            serde_json::json!({ "anything": "goes" }),
            "a field under x-kubernetes-preserve-unknown-fields must not be pruned"
        );
        assert!(
            out.is_empty(),
            "a preserved field must not be reported as an unknown-field violation either"
        );
    }

    /// End-to-end: a mutating webhook that adds a field the CRD schema does not declare
    /// must not leave that field in the stored/returned object. This is the exact upstream
    /// AdmissionWebhook "should mutate custom resource with pruning" scenario — before this
    /// fix, create_cr never re-pruned after `run_mutating_webhooks`, so `mutation-stage-2`
    /// (added by the webhook, absent from the schema) survived in the response.
    #[tokio::test]
    async fn create_cr_prunes_field_a_mutating_webhook_adds_but_schema_does_not_declare() {
        use axum::routing::post;
        use axum::Router;
        use bytes::Bytes as AxumBytes;
        use u7s_store::Store;

        let router = Router::new().route(
            "/mutate",
            post(|| async {
                let patch = serde_json::json!([
                    {"op": "add", "path": "/data/mutation-stage-1", "value": "yes"},
                    {"op": "add", "path": "/data/mutation-stage-2", "value": "yes"}
                ]);
                let patch_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    serde_json::to_string(&patch).unwrap(),
                );
                axum::Json(serde_json::json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "uid-mutate",
                        "allowed": true,
                        "patch": patch_b64,
                        "patchType": "JSONPatch"
                    }
                }))
            }),
        );
        let (base_url, _handle) = start_mock_conversion_server(router).await;

        let state = make_state();
        install_cluster_crd_with_schema(
            &state,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "data": {
                        "type": "object",
                        "properties": {
                            "mutation-start": { "type": "string" },
                            "mutation-stage-1": { "type": "string" }
                            // mutation-stage-2 intentionally undeclared.
                        }
                    }
                }
            }),
        )
        .await;

        let mwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "cr-prune-test-mwc"},
            "webhooks": [{
                "name": "cr.mutate.example.com",
                "clientConfig": { "url": format!("{base_url}/mutate") },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": ["CREATE"]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                "/registry/admissionregistration.k8s.io/mutatingwebhookconfigurations/cr-prune-test-mwc",
                AxumBytes::from(serde_json::to_vec(&mwc).unwrap()),
                None,
            )
            .await
            .unwrap();

        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "cr-instance-1" },
                "data": { "mutation-start": "yes" }
            })
            .to_string(),
        );

        let result = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await
        .expect("create must succeed: the mutating webhook only adds fields, it never denies");

        let body = axum::response::IntoResponse::into_response(result);
        let bytes = axum::body::to_bytes(body.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            obj["data"],
            serde_json::json!({ "mutation-start": "yes", "mutation-stage-1": "yes" }),
            "mutation-stage-2 was added by the webhook but never declared in the CRD's \
             schema, so it must be pruned before storage — same as it must be for the \
             upstream AdmissionWebhook pruning conformance test (got: {:?})",
            obj["data"]
        );
    }

    // ---------------------------------------------------------------------------
    // CRD structural-schema defaulting (apply_crd_schema_defaults)
    //
    // Conformance test "custom resource defaulting for requests and from storage works"
    // (test/e2e/apimachinery/custom_resource_definition.go) sets a `default:` on a CRD's
    // openAPIV3Schema property and expects every CR of that kind to have it filled in —
    // both in the CREATE response and on every subsequent GET, including for objects
    // created before the default existed. The walker must apply defaults at any schema
    // depth, including array items: a naive path-based implementation that treats an
    // array index like an object key (e.g. building the JSON pointer "/list/0/field" and
    // creating an intermediate object at "0") breaks with "cannot create intermediate
    // key '0' in non-object" the moment a default is nested under an array item.
    // ---------------------------------------------------------------------------

    /// A top-level property's `default` must be filled in when the CR omits the field.
    /// This is the exact scenario the conformance test exercises for field "a".
    #[test]
    fn schema_default_applied_to_missing_object_level_property() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a": { "type": "string", "default": "A" }
            }
        });
        let mut obj = serde_json::json!({ "metadata": { "name": "cr-1" } });

        apply_crd_schema_defaults(&schema, &mut obj);

        assert_eq!(
            obj["a"], "A",
            "a property's default must be applied when the CR body omits it — without this \
             a CR created before the schema default existed never picks it up on read"
        );
    }

    /// A client-supplied value must never be overwritten by the schema default.
    #[test]
    fn schema_default_does_not_overwrite_existing_value() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a": { "type": "string", "default": "A" }
            }
        });
        let mut obj = serde_json::json!({ "a": "client-value" });

        apply_crd_schema_defaults(&schema, &mut obj);

        assert_eq!(
            obj["a"], "client-value",
            "an explicit client value must never be clobbered by the schema default"
        );
    }

    /// A default nested two levels deep under object properties must be applied.
    #[test]
    fn schema_default_applied_to_nested_object_property() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "replicas": { "type": "integer", "default": 1 }
                    }
                }
            }
        });
        let mut obj = serde_json::json!({ "spec": {} });

        apply_crd_schema_defaults(&schema, &mut obj);

        assert_eq!(
            obj["spec"]["replicas"], 1,
            "defaults nested under an existing object property must be applied recursively"
        );
    }

    /// REGRESSION: a default nested under an array item must be applied to every element
    /// already present in the array, not treated as a single object path containing a
    /// literal "0" key. Before this fix there was no array-aware recursion at all, so a
    /// schema shaped like this would either silently skip the default or (in a path-based
    /// implementation) panic/error trying to create an object key named "0".
    #[test]
    fn schema_default_applied_under_array_item() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "color": { "type": "string", "default": "blue" }
                        }
                    }
                }
            }
        });
        let mut obj = serde_json::json!({
            "items": [
                { "name": "first" },
                { "name": "second", "color": "red" }
            ]
        });

        apply_crd_schema_defaults(&schema, &mut obj);

        assert_eq!(
            obj["items"][0]["color"], "blue",
            "an array element missing the field must get the item schema's default — this is \
             the array-index defaulting path that previously errored with \
             'cannot create intermediate key \"0\" in non-object'"
        );
        assert_eq!(
            obj["items"][1]["color"], "red",
            "an array element that already has the field must keep its own value, not the default"
        );
    }

    /// An empty array with a default nested under `items` must be a no-op — there is
    /// nothing to default into, and this must not panic or fabricate an element.
    #[test]
    fn schema_default_under_array_item_noop_on_empty_array() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": { "color": { "type": "string", "default": "blue" } }
                    }
                }
            }
        });
        let mut obj = serde_json::json!({ "items": [] });

        apply_crd_schema_defaults(&schema, &mut obj);

        assert_eq!(
            obj["items"],
            serde_json::json!([]),
            "an empty array must stay empty — defaulting must never insert a synthetic element"
        );
    }

    /// End-to-end: create_cr must apply the schema default to the CREATE response, and the
    /// defaulted value must be persisted (still present after the schema default is later
    /// removed) — matching the second phase of the conformance test where CR "cr-2" keeps
    /// its baked-in "a":"A" even after the CRD schema default for "a" is deleted.
    #[tokio::test]
    async fn create_cr_bakes_in_schema_default_at_write_time() {
        let state = make_state();
        install_cluster_crd_with_schema(
            &state,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "a": { "type": "string", "default": "A" }
                }
            }),
        )
        .await;

        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "cr-2" }
            })
            .to_string(),
        );

        let resp = create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await
        .expect("create with schema default must succeed")
        .into_response();

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["a"], "A",
            "the CREATE response must already reflect the schema default — the conformance \
             test reads this directly off the Create() call, not a subsequent Get()"
        );
    }

    /// End-to-end: GET must apply the *current* schema's defaults even to a CR that was
    /// created before the default existed — the default is never persisted for that
    /// object, so it must be computed fresh on every read. This is the "cr-1" phase of the
    /// conformance test: the CRD schema gains a default only after the CR is created, and
    /// the test polls GET until the field appears.
    #[tokio::test]
    async fn get_cr_applies_default_added_to_schema_after_creation() {
        let state = make_state();
        // Install with no default yet, matching the conformance test's initial CRD.
        install_cluster_crd_with_schema(
            &state,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "a": { "type": "string" }
                }
            }),
        )
        .await;

        let cr_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Widget",
                "metadata": { "name": "cr-1" }
            })
            .to_string(),
        );
        create_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
            )),
            test_user(),
            axum::http::HeaderMap::new(),
            cr_body,
        )
        .await
        .expect("create without default must succeed");

        // Patch the CRD (as the conformance test does via JSONPatch) to add a default for
        // "a" after the CR already exists — mirrors the real PATCH .../customresourcedefinitions.
        {
            use crate::handlers::crd;
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                "application/merge-patch+json".parse().unwrap(),
            );
            let patch = serde_json::json!({
                "spec": {
                    "versions": [{
                        "name": "v1",
                        "served": true,
                        "storage": true,
                        "schema": {
                            "openAPIV3Schema": {
                                "type": "object",
                                "properties": {
                                    "a": { "type": "string", "default": "A" }
                                }
                            }
                        }
                    }]
                }
            });
            crd::patch_crd(
                State(state.clone()),
                Path("widgets.example.io".to_string()),
                test_user(),
                headers,
                Bytes::from(patch.to_string()),
            )
            .await
            .expect("patching the CRD schema to add a default must succeed");
        }

        let resp = get_cr(
            State(state.clone()),
            Path((
                "example.io".to_string(),
                "v1".to_string(),
                "widgets".to_string(),
                "cr-1".to_string(),
            )),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect("get must succeed")
        .into_response();

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["a"], "A",
            "GET must apply the current schema's default even though the CR predates it — \
             without read-time defaulting, informers waiting on this field would hang forever"
        );
    }

    // Slow benchmark, not a regression gate — the real regression gates are the 3
    // admission-cap tests (crd.rs and cr.rs). This is opt-in via `cargo test -- --ignored`
    // and empirically confirms the audit's claim that boon's ECMA-compat rewrite (which
    // runs before Regex::new, so regex::RegexBuilder::size_limit can't help) is O(n^2):
    // each geometric doubling should roughly quadruple compile time, not double it. Each
    // size is individually wall-clock-capped at 60s so this never turns into a multi-minute
    // CI hang — a size that blows the cap is itself evidence of superlinear scaling.
    #[test]
    #[ignore]
    fn poc_timing_boon_ecma_compat_shim_is_quadratic() {
        use std::time::{Duration, Instant};

        const CAP: Duration = Duration::from_secs(60);

        // Baseline: a 1-byte pattern isolates boon::Compiler's fixed per-call setup cost
        // (meta-schema/vocabulary loading) from the marginal, pattern-length-driven cost
        // the geometric sweep below measures.
        {
            let start = Instant::now();
            let mut schemas = boon::Schemas::new();
            let mut compiler = boon::Compiler::new();
            compiler
                .add_resource(
                    "baseline.json",
                    serde_json::json!({ "type": "string", "pattern": "a" }),
                )
                .unwrap();
            let _ = compiler.compile("baseline.json", &mut schemas);
            eprintln!(
                "PoC: 1 B baseline pattern compiled in {:?}",
                start.elapsed()
            );
        }

        let mut prev: Option<(usize, Duration)> = None;

        for &size in &[1024usize, 4096, 16384, 65536, 262144, 1_048_576] {
            let pattern = "\\d".repeat(size / 2);
            let start = Instant::now();
            let mut schemas = boon::Schemas::new();
            let mut compiler = boon::Compiler::new();
            compiler
                .add_resource(
                    "poc.json",
                    serde_json::json!({ "type": "string", "pattern": pattern }),
                )
                .unwrap();
            let _ = compiler.compile("poc.json", &mut schemas);
            let elapsed = start.elapsed();
            eprintln!("PoC: {size} B \\d-repeated pattern compiled in {elapsed:?}");

            if elapsed > CAP {
                eprintln!("PoC: {size} B exceeded the {CAP:?} cap — stopping (superlinear scaling confirmed)");
                break;
            }
            if let Some((prev_size, prev_elapsed)) = prev {
                let size_ratio = size as f64 / prev_size as f64;
                let time_ratio = elapsed.as_secs_f64() / prev_elapsed.as_secs_f64().max(1e-9);
                eprintln!(
                    "PoC: {prev_size} B -> {size} B: size x{size_ratio:.1}, time x{time_ratio:.1} \
                     (linear would be x{size_ratio:.1}, quadratic would be x{:.1})",
                    size_ratio * size_ratio
                );
            }
            prev = Some((size, elapsed));
        }
    }

    // ---------------------------------------------------------------------------
    // CRD scale subresource
    // ---------------------------------------------------------------------------

    /// Builds a namespaced CRD body declaring `subresources.scale` with deliberately
    /// non-conventional JSON paths (not "spec.replicas"/"status.replicas"). A test built
    /// on the upstream-typical path names would still pass against a handler that hardcoded
    /// "spec.replicas" by mistake (copy-pasted from apps/v1's scale.rs); using different
    /// names here is what actually proves the handler reads the CRD-declared paths generically.
    fn namespaced_crd_with_scale_subresource_bytes() -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "gizmos.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "gizmos",
                        "singular": "gizmo",
                        "kind": "Gizmo",
                        "listKind": "GizmoList"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        {
                            "name": "v1",
                            "served": true,
                            "storage": true,
                            "subresources": {
                                "scale": {
                                    "specReplicasPath": ".spec.desiredReplicas",
                                    "statusReplicasPath": ".status.actualReplicas",
                                    "labelSelectorPath": ".status.podSelector"
                                }
                            }
                        }
                    ]
                }
            })
            .to_string(),
        )
    }

    async fn install_namespaced_crd_with_scale_subresource(state: &AppState) {
        use crate::handlers::crd;
        assert!(
            crd::create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                namespaced_crd_with_scale_subresource_bytes(),
            )
            .await
            .is_ok(),
            "install namespaced CRD with scale subresource"
        );
    }

    // GET /scale for a CRD-backed resource must succeed and resolve the CRD's own declared
    // specReplicasPath/statusReplicasPath/labelSelectorPath — not the apps/v1-hardcoded
    // spec.replicas/status.replicas. Before this fix, cr.rs had no scale route at all, so an
    // HPA targeting a CRD-backed resource got an immediate 404 reading replicas
    // ("Told to stop trying after 0.022s") instead of ever reaching this logic.
    #[tokio::test]
    async fn namespaced_cr_scale_get_resolves_crd_declared_paths() {
        let state = make_state();
        install_namespaced_crd_with_scale_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let ns = "default".to_string();
        let plural = "gizmos".to_string();
        let name = "my-gizmo".to_string();

        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Gizmo",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "desiredReplicas": 5 },
                "status": { "actualReplicas": 3, "podSelector": "app=gizmo" }
            })
            .to_string(),
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = get_cr_namespaced_scale(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
        )
        .await
        .expect(
            "GET /scale must succeed for a CRD declaring subresources.scale — a 404 here is \
             exactly the HPA-controller-facing bug this fix closes",
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let scale: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            scale["spec"]["replicas"], 5,
            "spec.replicas in the Scale object must come from the CRD-declared \
             specReplicasPath (.spec.desiredReplicas here), not a hardcoded 'spec.replicas' \
             — this is what makes the handler generic over arbitrary CRD field names"
        );
        assert_eq!(
            scale["status"]["replicas"], 3,
            "status.replicas must come from the CRD-declared statusReplicasPath"
        );
        assert_eq!(
            scale["status"]["selector"], "app=gizmo",
            "status.selector must come from the CRD-declared labelSelectorPath — the HPA \
             controller treats an empty selector as a hard, unrecoverable error"
        );
    }

    // PUT /scale is what the HPA controller actually calls to act on a scale-up/down
    // decision. The write must land at the CRD's own specReplicasPath, not spec.replicas —
    // a write anywhere else would silently never affect the workload the CR represents.
    #[tokio::test]
    async fn namespaced_cr_scale_put_writes_to_crd_declared_spec_path() {
        let state = make_state();
        install_namespaced_crd_with_scale_subresource(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let ns = "default".to_string();
        let plural = "gizmos".to_string();
        let name = "my-gizmo".to_string();

        let create_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "example.io/v1",
                "kind": "Gizmo",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "desiredReplicas": 2 }
            })
            .to_string(),
        );
        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                create_body,
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let scale_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "autoscaling/v1",
                "kind": "Scale",
                "spec": { "replicas": 7 }
            })
            .to_string(),
        );

        let put_result = put_cr_namespaced_scale(
            State(state.clone()),
            Path((
                group.clone(),
                version.clone(),
                ns.clone(),
                plural.clone(),
                name.clone(),
            )),
            axum::http::HeaderMap::new(),
            scale_body,
        )
        .await;
        assert!(
            put_result.is_ok(),
            "PUT /scale must succeed — this is the exact call the HPA controller makes to \
             act on its scale decision"
        );

        let resp = get_cr_namespaced(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
            axum::http::HeaderMap::new(),
        )
        .await
        .expect("get must succeed");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let obj: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            obj["spec"]["desiredReplicas"], 7,
            "PUT /scale must write the new replica count at the CRD-declared \
             specReplicasPath (.spec.desiredReplicas) — an HPA scale-up that landed anywhere \
             else would never actually resize the workload"
        );
    }

    // A CRD that never declares subresources.scale must not expose a working /scale route —
    // the same opt-in contract has_status_subresource already enforces for /status. Without
    // this gate, every CRD (even ones the author never wired for scale) would silently start
    // answering GET /scale with a bogus all-zero Scale object instead of 404.
    #[tokio::test]
    async fn namespaced_cr_scale_get_404s_when_crd_has_no_scale_subresource() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "my-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let result = get_cr_namespaced_scale(
            State(state.clone()),
            Path((group, version, ns, plural, name)),
        )
        .await;

        let err = expect_err_status(
            result,
            "scale must 404 when the CRD never declared subresources.scale",
        );
        assert_eq!(
            err.0,
            StatusCode::NOT_FOUND,
            "a CRD that never opted into subresources.scale must not expose a working \
             /scale route"
        );
    }

    // -- pre-update old_object threading tests --
    //
    // replace_cr, replace_cr_namespaced, patch_cr and patch_cr_namespaced all fetch the
    // pre-update object from the store but historically dropped it before calling
    // run_validating_webhooks, always passing None. A VAP/MAP webhook that enforces an
    // immutability rule (e.g. "spec.destination cannot change after creation") compares
    // request.oldObject against request.object — with oldObject always null it has nothing
    // to diff against and silently allows every mutation. These four tests spin up a real
    // mock webhook HTTP server and assert the captured AdmissionReview actually carries the
    // pre-update spec as oldObject, for each of the four fixed call sites plus the DELETE
    // path (which already had a correct, and must-stay-unchanged, old==stored shape).

    /// Start an axum router on a random local TCP port and return its base URL.
    async fn spawn_capturing_admission_server(
        captured: std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    ) -> String {
        use axum::routing::post;
        use axum::Router;
        use tokio::net::TcpListener;

        let router = Router::new().route(
            "/admit",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let captured = std::sync::Arc::clone(&captured);
                async move {
                    *captured.lock().unwrap() = Some(body.clone());
                    let uid = body["request"]["uid"].as_str().unwrap_or("").to_string();
                    axum::Json(serde_json::json!({
                        "apiVersion": "admission.k8s.io/v1",
                        "kind": "AdmissionReview",
                        "response": { "uid": uid, "allowed": true }
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock admission server must not fail");
        });
        format!("http://{addr}/admit")
    }

    async fn put_validating_webhook_config(state: &AppState, name: &str, url: &str, op: &str) {
        use u7s_store::Store;
        let vwc = serde_json::json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": { "name": name },
            "webhooks": [{
                "name": format!("{name}.test.example.com"),
                "clientConfig": { "url": url },
                "rules": [{"apiGroups": ["*"], "apiVersions": ["*"], "resources": ["*"], "operations": [op]}],
                "failurePolicy": "Fail"
            }]
        });
        state
            .store
            .put(
                &format!(
                    "/registry/admissionregistration.k8s.io/validatingwebhookconfigurations/{name}"
                ),
                Bytes::from(serde_json::to_vec(&vwc).unwrap()),
                None,
            )
            .await
            .unwrap();
    }

    /// replace_cr_namespaced (PUT) must give a VAP/MAP webhook the pre-update spec as
    /// oldObject, not None — otherwise an immutability rule on e.g. spec.destination can
    /// never detect that the field actually changed and silently allows the update.
    #[tokio::test]
    async fn replace_cr_namespaced_threads_pre_update_spec_as_old_object() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "replace-old-object-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let url = spawn_capturing_admission_server(std::sync::Arc::clone(&captured)).await;
        put_validating_webhook_config(&state, "replace-old-object-vwc", &url, "UPDATE").await;

        let update_body = Bytes::from(
            serde_json::json!({
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": { "name": &name, "namespace": &ns },
                "spec": { "destination": { "namespace": "other-ns" } }
            })
            .to_string(),
        );
        assert!(
            replace_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns, plural, name)),
                test_user(),
                axum::http::HeaderMap::new(),
                update_body,
            )
            .await
            .is_ok(),
            "namespaced replace must succeed when the validating webhook allows it"
        );

        let review = captured
            .lock()
            .unwrap()
            .take()
            .expect("webhook must have been called on UPDATE");
        assert!(
            !review["request"]["oldObject"].is_null(),
            "replace_cr_namespaced must pass the pre-update object as old_object — a null \
             oldObject means an immutability-enforcing webhook has nothing to compare the \
             new spec against and silently allows any change"
        );
        assert_ne!(
            review["request"]["oldObject"]["spec"], review["request"]["object"]["spec"],
            "old_object.spec must reflect the pre-update state, not the just-replaced spec — \
             otherwise a webhook diffing old vs new spec sees them as identical and can never \
             detect the change it exists to police"
        );
        assert_eq!(
            review["request"]["oldObject"]["spec"]["destination"]["namespace"], "default",
            "old_object must carry the value that was actually stored before this replace"
        );
    }

    /// patch_cr (JSON merge patch) must give a VAP/MAP webhook the pre-patch spec as
    /// oldObject. patch_cr deserializes the stored object straight into the mutable `obj`
    /// that the patch then mutates in place, so without a deliberate pre-patch snapshot
    /// there is nothing left to pass once the patch has applied.
    #[tokio::test]
    async fn patch_cr_merge_patch_threads_pre_patch_spec_as_old_object() {
        let state = make_state();
        install_cluster_crd(&state).await;

        let group = "example.io".to_string();
        let version = "v1".to_string();
        let plural = "widgets".to_string();
        let name = "patch-old-object-widget".to_string();

        assert!(
            create_cr(
                State(state.clone()),
                Path((group.clone(), version.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                widget_body(&name),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let url = spawn_capturing_admission_server(std::sync::Arc::clone(&captured)).await;
        put_validating_webhook_config(&state, "patch-old-object-vwc", &url, "UPDATE").await;

        let patch_body = Bytes::from(serde_json::json!({ "spec": { "color": "red" } }).to_string());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/merge-patch+json".parse().unwrap(),
        );
        assert!(
            patch_cr(
                State(state.clone()),
                Path((group, version, plural, name)),
                test_user(),
                headers,
                patch_body,
            )
            .await
            .is_ok(),
            "cluster-scoped patch must succeed when the validating webhook allows it"
        );

        let review = captured
            .lock()
            .unwrap()
            .take()
            .expect("webhook must have been called on UPDATE");
        assert!(
            !review["request"]["oldObject"].is_null(),
            "patch_cr must pass the pre-patch object as old_object, not None"
        );
        assert_ne!(
            review["request"]["oldObject"]["spec"], review["request"]["object"]["spec"],
            "old_object.spec must be the pre-patch spec — if patch_cr snapshots obj AFTER \
             the patch mutates it in place, old_object and object become identical and a \
             webhook can never see what changed"
        );
        assert_eq!(
            review["request"]["oldObject"]["spec"]["color"], "blue",
            "old_object must carry the color the widget was created with, before this patch"
        );
    }

    /// patch_cr_namespaced with a strategic-merge-patch body must give a VAP/MAP webhook
    /// the pre-patch spec as oldObject — same defect as the JSON-merge-patch case above,
    /// but exercised through the namespaced handler and a different patch content-type to
    /// cover the fourth (and last) fixed call site.
    #[tokio::test]
    async fn patch_cr_namespaced_strategic_merge_patch_threads_pre_patch_spec_as_old_object() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "patch-old-object-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let url = spawn_capturing_admission_server(std::sync::Arc::clone(&captured)).await;
        put_validating_webhook_config(&state, "patch-ns-old-object-vwc", &url, "UPDATE").await;

        let patch_body = Bytes::from(
            serde_json::json!({ "spec": { "destination": { "namespace": "prod" } } }).to_string(),
        );
        assert!(
            patch_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns, plural, name)),
                test_user(),
                strategic_merge_patch_headers(),
                patch_body,
            )
            .await
            .is_ok(),
            "namespaced strategic-merge patch must succeed when the validating webhook allows it"
        );

        let review = captured
            .lock()
            .unwrap()
            .take()
            .expect("webhook must have been called on UPDATE");
        assert!(
            !review["request"]["oldObject"].is_null(),
            "patch_cr_namespaced must pass the pre-patch object as old_object, not None"
        );
        assert_ne!(
            review["request"]["oldObject"]["spec"], review["request"]["object"]["spec"],
            "old_object.spec must be the pre-patch spec, not the already-patched spec"
        );
        assert_eq!(
            review["request"]["oldObject"]["spec"]["destination"]["namespace"], "default",
            "old_object must carry the namespace the Application was created with, before \
             this strategic-merge patch"
        );
    }

    /// The DELETE path (delete_cr_namespaced here) already passed the stored object as
    /// old_object correctly before this fix — old == the stored object, since there is no
    /// separate "new" on delete. This must stay unchanged: a DELETE-path VAP/MAP webhook
    /// (e.g. one that blocks deletion of resources with a protection label) depends on
    /// oldObject being populated exactly like this.
    #[tokio::test]
    async fn delete_cr_namespaced_still_passes_stored_object_as_old_object() {
        let state = make_state();
        install_namespaced_crd(&state).await;

        let group = "argoproj.io".to_string();
        let version = "v1alpha1".to_string();
        let ns = "argocd".to_string();
        let plural = "applications".to_string();
        let name = "delete-old-object-app".to_string();

        assert!(
            create_cr_namespaced(
                State(state.clone()),
                Path((group.clone(), version.clone(), ns.clone(), plural.clone())),
                test_user(),
                axum::http::HeaderMap::new(),
                app_body(&name, &ns),
            )
            .await
            .is_ok(),
            "seed create must succeed"
        );

        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let url = spawn_capturing_admission_server(std::sync::Arc::clone(&captured)).await;
        put_validating_webhook_config(&state, "delete-old-object-vwc", &url, "DELETE").await;

        assert!(
            delete_cr_namespaced(
                State(state.clone()),
                Path((group, version, ns.clone(), plural, name)),
                test_user(),
                axum::http::HeaderMap::new(),
                Bytes::new(),
            )
            .await
            .is_ok(),
            "delete must succeed when the validating webhook allows it"
        );

        let review = captured
            .lock()
            .unwrap()
            .take()
            .expect("webhook must have been called on DELETE");
        assert!(
            !review["request"]["oldObject"].is_null(),
            "delete_cr_namespaced must keep passing the stored object as old_object on \
             DELETE — this bead only changes the UPDATE call sites and must not regress \
             the DELETE contract"
        );
        assert_eq!(
            review["request"]["oldObject"]["spec"]["destination"]["namespace"], "default",
            "old_object on DELETE must be the object that was actually stored, not an \
             empty or unrelated placeholder"
        );
    }
}
