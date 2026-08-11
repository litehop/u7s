use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use u7s_store::{ListOptions, Store};

use crate::handlers::crd::CustomResourceDefinition;
use crate::state::{
    AppState, CachedDiscoveryGroup, CachedDiscoveryResource, CachedDiscoverySubresource,
    CachedDiscoveryVersion,
};
use crate::types::{
    APIGroup, APIGroupDiscovery, APIGroupDiscoveryList, APIGroupDiscoveryListMeta,
    APIGroupDiscoveryMeta, APIGroupList, APIResourceDiscovery, APISubresourceDiscovery,
    APIVersionDiscovery, APIVersions, ApiResourceList, DiscoveryResponseKind,
    GroupVersionForDiscovery,
};

pub async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "major": "1",
        "minor": "36",
        "gitVersion": "v1.36.0",
        "gitCommit": "0000000000000000000000000000000000000000",
        "gitTreeState": "clean",
        "buildDate": "1970-01-01T00:00:00Z",
        "goVersion": "go1.24.0",
        "compiler": "gc",
        "platform": "linux/amd64"
    }))
}

/// Parse the Accept header and return the aggregated discovery version if requested.
///
/// Returns `Some("v2")` or `Some("v2beta1")` if the header contains a media type with
/// `g=apidiscovery.k8s.io`, `as=APIGroupDiscoveryList`, and a supported `v=` parameter.
/// Returns `None` for plain `application/json` or any other Accept value.
///
/// client-go sends:
///   `application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList,
///    application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList,
///    application/json`
/// and validates the response Content-Type header, not the body's apiVersion field.
fn parse_aggregated_accept(accept: &str) -> Option<&'static str> {
    for media_type in accept.split(',') {
        let params: Vec<&str> = media_type.split(';').map(str::trim).collect();
        if params.first().copied() != Some("application/json") {
            continue;
        }
        if !params.contains(&"g=apidiscovery.k8s.io")
            || !params.contains(&"as=APIGroupDiscoveryList")
        {
            continue;
        }
        if params.contains(&"v=v2") {
            return Some("v2");
        }
        if params.contains(&"v=v2beta1") {
            return Some("v2beta1");
        }
    }
    None
}

fn aggregated_content_type(version: &str) -> String {
    format!("application/json;g=apidiscovery.k8s.io;v={version};as=APIGroupDiscoveryList")
}

pub async fn api_versions<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
) -> Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(version) = parse_aggregated_accept(accept) {
        // /api returns only the core group (name="") in the aggregated discovery list.
        // client-go's GroupsAndMaybeResources() handles /api and /apis separately;
        // include_core=true here, and /apis uses include_core=false to avoid duplicates.
        let authorization = headers.get(axum::http::header::AUTHORIZATION);
        let body = build_aggregated_discovery(&state, version, true, authorization, "/api").await;
        let core_only = body
            .items
            .into_iter()
            .filter(|i| i.metadata.name.is_empty())
            .collect();
        let core_body = APIGroupDiscoveryList {
            items: core_only,
            ..body
        };
        return (
            [(
                axum::http::header::CONTENT_TYPE,
                aggregated_content_type(version),
            )],
            Json(core_body),
        )
            .into_response();
    }

    Json(APIVersions::v1(state.server_address.clone())).into_response()
}

pub async fn api_v1_resources() -> Json<ApiResourceList> {
    Json(ApiResourceList::v1())
}

// ---------------------------------------------------------------------------
// /apis — group list
// ---------------------------------------------------------------------------

const STATIC_GROUPS: &[(&str, &str)] = &[
    ("admissionregistration.k8s.io", "v1"),
    ("apiextensions.k8s.io", "v1"),
    ("apiregistration.k8s.io", "v1"),
    ("apps", "v1"),
    ("authentication.k8s.io", "v1"),
    ("authorization.k8s.io", "v1"),
    ("autoscaling", "v2"),
    ("batch", "v1"),
    ("certificates.k8s.io", "v1"),
    ("coordination.k8s.io", "v1"),
    ("discovery.k8s.io", "v1"),
    ("events.k8s.io", "v1"),
    ("flowcontrol.apiserver.k8s.io", "v1"),
    ("gateway.networking.k8s.io", "v1"),
    ("networking.k8s.io", "v1"),
    ("node.k8s.io", "v1"),
    ("policy", "v1"),
    ("rbac.authorization.k8s.io", "v1"),
    ("resource.k8s.io", "v1"),
    ("scheduling.k8s.io", "v1"),
    ("storage.k8s.io", "v1"),
];

pub async fn api_group_list<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
) -> Response {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if let Some(version) = parse_aggregated_accept(accept) {
        // /apis returns only non-core groups (include_core=false).
        // The core group is returned by /api; client-go merges both separately.
        // Including core here would cause duplicate kind registrations (Namespace, Pod, etc.).
        let authorization = headers.get(axum::http::header::AUTHORIZATION);
        let body = build_aggregated_discovery(&state, version, false, authorization, "/apis").await;
        return (
            [(
                axum::http::header::CONTENT_TYPE,
                aggregated_content_type(version),
            )],
            Json(body),
        )
            .into_response();
    }

    Json(api_group_list_inner(&state).await).into_response()
}

/// Build the `STATIC_GROUPS` + CRD-backed group list only -- never an `APIService`-backed
/// group. This is exactly the portion `DiscoveryCache` (state.rs) covers, split out of
/// `api_group_list_inner` so both the cache's rebuild path and the plain `/apis` GroupList
/// path share one implementation instead of drifting apart.
async fn core_and_crd_groups<S: Store>(state: &AppState<S>) -> Vec<APIGroup> {
    let mut groups: Vec<APIGroup> = STATIC_GROUPS
        .iter()
        .map(|(name, version)| {
            // autoscaling advertises both v2 (preferred) and v1.
            if *name == "autoscaling" {
                make_group(name, version, &["v2", "v1"])
            // gateway.networking.k8s.io advertises v1 (preferred) and v1beta1.
            } else if *name == "gateway.networking.k8s.io" {
                make_group(name, version, &["v1", "v1beta1"])
            } else {
                make_group(name, version, &[version])
            }
        })
        .collect();

    if let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    {
        // Collect (group, versions) pairs from CRDs, deduplicating by group name.
        // A group already covered by STATIC_GROUPS is skipped.
        let mut seen: std::collections::HashSet<String> = STATIC_GROUPS
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();

        for obj in &resp.items {
            let Ok(crd) = serde_json::from_slice::<CustomResourceDefinition>(&obj.value) else {
                continue;
            };
            let group = &crd.spec.group;
            if seen.contains(group.as_str()) {
                continue;
            }
            seen.insert(group.clone());
            let preferred = preferred_version(&crd);
            let served: Vec<&str> = crd
                .spec
                .versions
                .iter()
                .filter(|v| v.served)
                .map(|v| v.name.as_str())
                .collect();
            groups.push(make_group(group, &preferred, &served));
        }
    }

    groups
}

pub(crate) async fn api_group_list_inner<S: Store>(state: &AppState<S>) -> APIGroupList {
    let mut groups = core_and_crd_groups(state).await;

    // Aggregated groups (APIService-backed): a group already covered by a built-in or CRD
    // group above is skipped -- u7s never creates an APIService for either, so in practice
    // this only ever adds genuinely external groups like wardle.example.com.
    let seen: std::collections::HashSet<String> = groups.iter().map(|g| g.name.clone()).collect();
    for (group, preferred, served) in super::aggregation::list_apiservice_groups(state).await {
        if seen.contains(group.as_str()) {
            continue;
        }
        let served_refs: Vec<&str> = served.iter().map(String::as_str).collect();
        groups.push(make_group(&group, &preferred, &served_refs));
    }

    APIGroupList {
        kind: "APIGroupList",
        api_version: "v1",
        groups,
    }
}

/// Return the preferred (storage=true, else first) version name for a CRD.
fn preferred_version(crd: &CustomResourceDefinition) -> String {
    crd.spec
        .versions
        .iter()
        .find(|v| v.storage)
        .or_else(|| crd.spec.versions.first())
        .map(|v| v.name.clone())
        .unwrap_or_default()
}

/// Build an APIGroup with all served versions listed and the storage version as preferred.
fn make_group(name: &str, preferred: &str, served: &[&str]) -> APIGroup {
    let versions: Vec<GroupVersionForDiscovery> = served
        .iter()
        .map(|v| GroupVersionForDiscovery {
            group_version: format!("{}/{}", name, v),
            version: v.to_string(),
        })
        .collect();
    let preferred_version = GroupVersionForDiscovery {
        group_version: format!("{}/{}", name, preferred),
        version: preferred.to_string(),
    };
    APIGroup {
        name: name.to_string(),
        versions,
        preferred_version,
    }
}

// ---------------------------------------------------------------------------
// AggregatedDiscovery — /apis + /discovery/v2 with Accept negotiation
// ---------------------------------------------------------------------------

/// Build an `APIGroupDiscoveryList` from all registered API groups and versions.
///
/// This is the GA AggregatedDiscovery format (k8s 1.27+). The conformance tests
/// send `Accept: application/json;g=apidiscovery.k8s.io;v=v2beta1` and expect
/// this response.
/// Build an `APIGroupDiscoveryList`.
///
/// When `include_core` is true, the core group (name="", v1 resources) is included as the
/// first item — this is used by `/discovery/v2` and `/api` with aggregated Accept.
///
/// When `include_core` is false, only non-core groups are included — this is used by `/apis`
/// with aggregated Accept. client-go's GroupsAndMaybeResources() merges /api (core) and /apis
/// (non-core) separately; including core in /apis causes duplicate Namespace/Pod registrations.
///
/// `authorization` is the caller's own bearer token (forwarded to APIService backends for
/// their live discovery fetch — see `discovery_resources_for_apiservice`'s doc for why an
/// aggregated group would otherwise silently show zero resources).
///
/// `route` identifies which caller fired this build (`/api`, `/apis`, or `/discovery/v2`) —
/// used only to label `u7s_discovery_build_total`, never to change behavior.
///
/// APIService cache-safety constraint: `authorization` above is forwarded, unmodified, from
/// `resolve_group_version_resources` into `aggregation::discovery_resources_for_apiservice`'s
/// outbound request to the backend, so a live `APIService` backend can enforce its own
/// per-caller authorization on the discovery document it returns. That means two different
/// callers can legitimately get two different discovery results for the exact same
/// `(discovery_version, include_core)` inputs whenever any `APIService` is registered — a cache
/// keyed only on those inputs would silently leak one caller's backend-authorized discovery
/// response to a different caller.
///
/// Resolution (option (a) of the four once listed here): only the `STATIC_GROUPS` + CRD-backed
/// portion is cached (`DiscoveryCache`, state.rs — never touches `authorization`); every
/// `APIService`-backed group is still resolved per-request, uncached, exactly as before this
/// cache existed.
pub(crate) async fn build_aggregated_discovery<S: Store>(
    state: &AppState<S>,
    discovery_version: &str,
    include_core: bool,
    authorization: Option<&axum::http::HeaderValue>,
    route: &str,
) -> APIGroupDiscoveryList {
    let apiservice_groups = super::aggregation::list_apiservice_groups(state).await;
    let has_apiservice = !apiservice_groups.is_empty();
    crate::metrics::DISCOVERY_BUILD_TOTAL
        .with_label_values(&[
            route,
            if include_core { "true" } else { "false" },
            if has_apiservice { "true" } else { "false" },
        ])
        .inc();

    let cached_groups = cached_core_and_crd_groups(state).await;

    let mut items: Vec<APIGroupDiscovery> = Vec::new();

    if include_core {
        // Build the core group item (group="", apiVersion="v1"). Never cached: it depends only
        // on the static `V1_RESOURCES` table, not on any store state, so rebuilding it is O(1)
        // and doesn't need write-through invalidation.
        let core_resources = api_resources_to_discovery_resources(&api_v1_resource_list_value());
        items.push(APIGroupDiscovery {
            metadata: APIGroupDiscoveryMeta {
                name: String::new(),
            },
            versions: vec![APIVersionDiscovery {
                freshness: "Current",
                resources: core_resources,
                version: "v1".to_string(),
            }],
        });
    }

    // STATIC_GROUPS + CRD-backed groups: reconstitute typed discovery entries from the cached,
    // plain-data snapshot (a data clone, not a store re-list + STATIC_GROUPS rebuild).
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(cached_groups.len());
    for group in cached_groups.iter() {
        seen.insert(group.name.clone());
        items.push(APIGroupDiscovery {
            metadata: APIGroupDiscoveryMeta {
                name: group.name.clone(),
            },
            versions: group
                .versions
                .iter()
                .map(|v| APIVersionDiscovery {
                    freshness: "Current",
                    resources: v.resources.iter().map(cached_resource_to_typed).collect(),
                    version: v.version.clone(),
                })
                .collect(),
        });
    }

    // APIService-backed groups only (a group already covered above is skipped, matching
    // api_group_list_inner's dedup rule). Every group+version is resolved as an independent
    // future and run concurrently (futures_util::future::join_all) rather than one `.await`
    // per loop iteration: an APIService-backed group's live discovery fetch carries its own
    // ~10s connect+request timeout (aggregation::build_backend_client), so awaiting them one
    // at a time means N slow/unresponsive backends add up to N * 10s to *every* /apis and
    // /discovery/v2 response -- even for callers who never asked about that backend's group.
    // Running them concurrently bounds the added latency to the single slowest backend.
    let group_futures = apiservice_groups
        .into_iter()
        .filter(|(group, _preferred, _served)| !seen.contains(group))
        .map(|(group, _preferred, served)| async move {
            let version_futures = served.iter().map(|version| async {
                let resources =
                    resolve_group_version_resources(state, &group, version, authorization).await;
                APIVersionDiscovery {
                    freshness: "Current",
                    resources,
                    version: version.clone(),
                }
            });
            APIGroupDiscovery {
                metadata: APIGroupDiscoveryMeta {
                    name: group.clone(),
                },
                versions: futures_util::future::join_all(version_futures).await,
            }
        });
    items.extend(futures_util::future::join_all(group_futures).await);

    // Compute a simple ETag from the number of items (sufficient for conformance).
    let resource_version = format!("{}", items.len());

    APIGroupDiscoveryList {
        api_version: format!("apidiscovery.k8s.io/{discovery_version}"),
        items,
        kind: "APIGroupDiscoveryList",
        metadata: APIGroupDiscoveryListMeta { resource_version },
    }
}

/// Read `DiscoveryCache`'s warm snapshot, rebuilding it first if cold. Mirrors
/// `fetch_mutating_configs`'s read pattern (admission.rs): clone the `Arc` under a short-lived
/// read lock so a concurrent rebuild can never hand out a torn/partial snapshot.
async fn cached_core_and_crd_groups<S: Store>(
    state: &AppState<S>,
) -> Arc<Vec<CachedDiscoveryGroup>> {
    let warm = state.discovery_cache.groups.read().unwrap().clone();
    if let Some(groups) = warm {
        return groups;
    }
    refresh_discovery_cache(state).await;
    state
        .discovery_cache
        .groups
        .read()
        .unwrap()
        .clone()
        .expect("refresh_discovery_cache always populates the cache before returning")
}

/// Rebuild `DiscoveryCache` from the store and swap it in atomically.
///
/// Called write-through by every CRD create/replace/patch/delete handler (`handlers/crd.rs`)
/// immediately after the store write succeeds, and lazily by `cached_core_and_crd_groups` on a
/// cold cache (first request since startup, or a test that seeds the store directly). Does
/// *not* need to run on `APIService` writes: `CachedDiscoveryGroup` never contains an
/// `APIService`-backed group (see `build_aggregated_discovery`'s doc), so an `APIService`
/// create/update/delete cannot change what this cache holds.
pub(crate) async fn refresh_discovery_cache<S: Store>(state: &AppState<S>) {
    let groups = core_and_crd_groups(state).await;
    let group_futures = groups.iter().map(|group| async move {
        let version_futures = group.versions.iter().map(|gv| async move {
            let resources = resolve_group_version_resources(
                state,
                group.name.as_str(),
                gv.version.as_str(),
                None,
            )
            .await;
            CachedDiscoveryVersion {
                version: gv.version.clone(),
                resources: resources.iter().map(typed_resource_to_cached).collect(),
            }
        });
        CachedDiscoveryGroup {
            name: group.name.clone(),
            versions: futures_util::future::join_all(version_futures).await,
        }
    });
    let cached = futures_util::future::join_all(group_futures).await;
    *state.discovery_cache.groups.write().unwrap() = Some(Arc::new(cached));
}

/// Convert a resolved `APIResourceDiscovery` into `DiscoveryCache`'s plain-data representation.
/// `APIResourceDiscovery` itself derives neither `Clone` nor `Deserialize` (types.rs keeps it
/// Serialize-only, since it's built once per request today) -- `CachedDiscoveryResource` exists
/// so the cache can hold an owned, `Clone`-able snapshot without adding either derive there.
fn typed_resource_to_cached(r: &APIResourceDiscovery) -> CachedDiscoveryResource {
    CachedDiscoveryResource {
        resource: r.resource.clone(),
        kind: r.response_kind.kind.clone(),
        namespaced: r.scope == "Namespaced",
        short_names: r.short_names.clone(),
        singular_resource: r.singular_resource.clone(),
        subresources: r
            .subresources
            .iter()
            .map(|s| CachedDiscoverySubresource {
                kind: s.response_kind.kind.clone(),
                subresource: s.subresource.clone(),
                verbs: s.verbs.clone(),
            })
            .collect(),
        verbs: r.verbs.clone(),
    }
}

/// The inverse of `typed_resource_to_cached`: reconstitute a fresh, owned `APIResourceDiscovery`
/// from a cached snapshot on every discovery request.
fn cached_resource_to_typed(r: &CachedDiscoveryResource) -> APIResourceDiscovery {
    APIResourceDiscovery {
        resource: r.resource.clone(),
        response_kind: DiscoveryResponseKind {
            kind: r.kind.clone(),
        },
        scope: if r.namespaced {
            "Namespaced"
        } else {
            "Cluster"
        },
        short_names: r.short_names.clone(),
        singular_resource: r.singular_resource.clone(),
        subresources: r
            .subresources
            .iter()
            .map(|s| APISubresourceDiscovery {
                response_kind: DiscoveryResponseKind {
                    kind: s.kind.clone(),
                },
                subresource: s.subresource.clone(),
                verbs: s.verbs.clone(),
            })
            .collect(),
        verbs: r.verbs.clone(),
    }
}

/// Resolve the resource list for one group+version in the aggregated-discovery response.
///
/// Tries, in order: a static built-in list, then CRD-backed resources from the store, then
/// (only if neither matched) an APIService-backed group's live discovery fetch -- the backend
/// is the only source of truth for what it actually serves, so this fetches its live discovery
/// document rather than guessing. Split out of `build_aggregated_discovery`'s loop so each
/// group+version is an independent future that can be driven concurrently with the others
/// instead of one at a time.
async fn resolve_group_version_resources<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
    authorization: Option<&axum::http::HeaderValue>,
) -> Vec<APIResourceDiscovery> {
    if let Some(rl) = static_group_resources(group, version) {
        return api_resources_to_discovery_resources(&rl);
    }
    // Dynamic group (CRD-backed): look up resources from the store.
    let crd_resources = crd_group_resources(state, group, version).await;
    if !crd_resources.is_empty() {
        return crd_resources;
    }
    // Not a CRD either: try an APIService-backed (aggregated) group.
    match super::aggregation::find_apiservice(state, group, version).await {
        Some(svc) => {
            match super::aggregation::discovery_resources_for_apiservice(state, &svc, authorization)
                .await
            {
                Some(rl) => api_resources_to_discovery_resources(&rl),
                None => crd_resources,
            }
        }
        None => crd_resources,
    }
}

/// Look up CRD-backed resources for a group/version from the store and return discovery entries.
async fn crd_group_resources<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
) -> Vec<APIResourceDiscovery> {
    let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    else {
        return vec![];
    };

    resp.items
        .iter()
        .filter_map(|obj| serde_json::from_slice::<CustomResourceDefinition>(&obj.value).ok())
        .filter(|crd| {
            crd.spec.group == group
                && crd
                    .spec
                    .versions
                    .iter()
                    .any(|v| v.name == version && v.served)
        })
        .map(|crd| {
            let scope = if crd.spec.scope == "Namespaced" {
                "Namespaced"
            } else {
                "Cluster"
            };
            APIResourceDiscovery {
                resource: crd.spec.names.plural.clone(),
                response_kind: DiscoveryResponseKind {
                    kind: crd.spec.names.kind.clone(),
                },
                scope,
                short_names: crd.spec.names.short_names.clone(),
                singular_resource: crd.spec.names.singular.clone(),
                subresources: vec![],
                verbs: [
                    "create",
                    "delete",
                    "deletecollection",
                    "get",
                    "list",
                    "patch",
                    "update",
                    "watch",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }
        })
        .collect()
}

/// Convert a `serde_json::Value` array of strings into a `Vec<String>`, defaulting to empty
/// on anything malformed. `resource_list` may come straight from an external `APIService`
/// backend's own discovery response (see `discovery_resources_for_apiservice`), so this stays
/// defensive rather than a strict typed deserialize of the whole document.
fn value_to_string_vec(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Convert an `APIResourceList` JSON value into the `APIGroupDiscovery` resource entry list.
///
/// `resource_list` stays `&serde_json::Value` rather than a typed `ApiResourceList` because
/// this is also fed an APIService backend's own live discovery document (arbitrary external
/// JSON, see `discovery_resources_for_apiservice`) — indexing defensively here means an
/// unexpected/missing field on that document degrades a single resource entry instead of
/// failing the whole aggregated-discovery response.
fn api_resources_to_discovery_resources(
    resource_list: &serde_json::Value,
) -> Vec<APIResourceDiscovery> {
    let empty = vec![];
    let resources = resource_list["resources"].as_array().unwrap_or(&empty);
    resources
        .iter()
        .filter_map(|r| {
            let name = r["name"].as_str().unwrap_or("");
            // Skip subresources (names with "/") — they appear as subresources in their parent.
            if name.contains('/') {
                return None;
            }
            let kind = r["kind"].as_str().unwrap_or("");
            let singular = r["singularName"].as_str().unwrap_or("");
            let namespaced = r["namespaced"].as_bool().unwrap_or(false);
            let scope = if namespaced { "Namespaced" } else { "Cluster" };
            let verbs = value_to_string_vec(&r["verbs"]);
            let short_names = r
                .get("shortNames")
                .map(value_to_string_vec)
                .unwrap_or_default();

            // Find subresources that belong to this resource.
            let prefix = format!("{name}/");
            let subresources: Vec<APISubresourceDiscovery> = resources
                .iter()
                .filter(|s| {
                    s["name"]
                        .as_str()
                        .map(|n| n.starts_with(&prefix))
                        .unwrap_or(false)
                })
                .map(|s| APISubresourceDiscovery {
                    response_kind: DiscoveryResponseKind {
                        kind: s["kind"].as_str().unwrap_or("").to_string(),
                    },
                    subresource: s["name"]
                        .as_str()
                        .unwrap_or("")
                        .trim_start_matches(&prefix)
                        .to_string(),
                    verbs: value_to_string_vec(&s["verbs"]),
                })
                .collect();

            Some(APIResourceDiscovery {
                resource: name.to_string(),
                response_kind: DiscoveryResponseKind {
                    kind: kind.to_string(),
                },
                scope,
                short_names,
                singular_resource: singular.to_string(),
                subresources,
                verbs,
            })
        })
        .collect()
}

/// Return the core v1 resource list as a JSON value (for aggregated discovery).
fn api_v1_resource_list_value() -> serde_json::Value {
    let list = crate::types::ApiResourceList::v1();
    serde_json::to_value(&list).unwrap_or(serde_json::Value::Null)
}

/// Handler for `GET /discovery/v2` — always returns the aggregated discovery list.
pub async fn aggregated_discovery_v2<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
) -> Response {
    let authorization = headers.get(axum::http::header::AUTHORIZATION);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json;g=apidiscovery.k8s.io;v=v2beta1",
        )],
        Json(
            build_aggregated_discovery(&state, "v2beta1", true, authorization, "/discovery/v2")
                .await,
        ),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /apis/:group/:version — per-group resource list
// ---------------------------------------------------------------------------

/// Return the static APIResourceList for a well-known group/version, or None if unknown.
fn static_group_resources(group: &str, version: &str) -> Option<serde_json::Value> {
    match (group, version) {
        ("admissionregistration.k8s.io", "v1") => Some(admissionregistration_v1_resources()),
        ("apiextensions.k8s.io", "v1") => Some(apiextensions_v1_resources()),
        ("apiregistration.k8s.io", "v1") => Some(apiregistration_v1_resources()),
        ("apps", "v1") => Some(apps_v1_resources()),
        ("authentication.k8s.io", "v1") => Some(authn_v1_resources()),
        ("authorization.k8s.io", "v1") => Some(authz_v1_resources()),
        ("autoscaling", "v1") => Some(autoscaling_v1_resources()),
        ("autoscaling", "v2") => Some(autoscaling_v2_resources()),
        ("batch", "v1") => Some(batch_v1_resources()),
        ("certificates.k8s.io", "v1") => Some(certificates_v1_resources()),
        ("coordination.k8s.io", "v1") => Some(coordination_v1_resources()),
        ("discovery.k8s.io", "v1") => Some(discovery_v1_resources()),
        ("events.k8s.io", "v1") => Some(events_v1_resources()),
        ("flowcontrol.apiserver.k8s.io", "v1") => Some(flowcontrol_v1_resources()),
        ("gateway.networking.k8s.io", "v1") => Some(gateway_networking_v1_resources()),
        ("gateway.networking.k8s.io", "v1beta1") => Some(gateway_networking_v1beta1_resources()),
        ("networking.k8s.io", "v1") => Some(networking_v1_resources()),
        ("node.k8s.io", "v1") => Some(node_v1_resources()),
        ("policy", "v1") => Some(policy_v1_resources()),
        ("rbac.authorization.k8s.io", "v1") => Some(rbac_v1_resources()),
        ("resource.k8s.io", "v1") => Some(resource_v1_resources()),
        ("scheduling.k8s.io", "v1") => Some(scheduling_v1_resources()),
        ("storage.k8s.io", "v1") => Some(storage_v1_resources()),
        _ => None,
    }
}

/// Handler for `GET /apis/{group}` — returns the APIGroup object for the named group.
///
/// Kubernetes clients use this to discover preferred versions for a specific group.
/// Without this endpoint, GET /apis/flowcontrol.apiserver.k8s.io returns 404 even
/// though the group appears in GET /apis (APIGroupList).
pub async fn api_group<S: Store>(
    State(state): State<AppState<S>>,
    Path(group): Path<String>,
) -> Response {
    let list = api_group_list_inner(&state).await;
    if let Some(g) = list.groups.into_iter().find(|g| g.name == group) {
        Json(serde_json::json!({
            "kind": "APIGroup",
            "apiVersion": "v1",
            "name": g.name,
            "versions": g.versions,
            "preferredVersion": g.preferred_version
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "message": format!("the server could not find the requested resource ({})", group),
                "reason": "NotFound",
                "code": 404
            })),
        )
            .into_response()
    }
}

pub async fn api_group_resources<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version)): Path<(String, String)>,
) -> Response {
    let static_list = static_group_resources(group.as_str(), version.as_str());

    if let Some(list) = static_list {
        return Json(list).into_response();
    }

    // Dynamic: query CRDs that belong to this group.
    if let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    {
        let resources: Vec<serde_json::Value> = resp
            .items
            .iter()
            .filter_map(|obj| serde_json::from_slice::<CustomResourceDefinition>(&obj.value).ok())
            .filter(|crd| {
                crd.spec.group == group && crd.spec.versions.iter().any(|v| v.name == version)
            })
            .map(|crd| {
                serde_json::json!({
                    "name": crd.spec.names.plural,
                    "singularName": crd.spec.names.singular,
                    "namespaced": crd.spec.scope == "Namespaced",
                    "kind": crd.spec.names.kind,
                    "shortNames": crd.spec.names.short_names,
                    "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
                })
            })
            .collect();

        if !resources.is_empty() {
            return Json(serde_json::json!({
                "kind": "APIResourceList",
                "apiVersion": "v1",
                "groupVersion": format!("{group}/{version}"),
                "resources": resources,
            }))
            .into_response();
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": format!("the server could not find the requested resource ({}/{})", group, version),
            "reason": "NotFound",
            "code": 404
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Static resource lists
// ---------------------------------------------------------------------------

fn apiregistration_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "apiregistration.k8s.io/v1",
        "resources": [
            {
                "name": "apiservices",
                "singularName": "apiservice",
                "namespaced": false,
                "kind": "APIService",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn apiextensions_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "apiextensions.k8s.io/v1",
        "resources": [
            {
                "name": "customresourcedefinitions",
                "singularName": "customresourcedefinition",
                "namespaced": false,
                "kind": "CustomResourceDefinition",
                "shortNames": ["crd", "crds"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn apps_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "apps/v1",
        "resources": [
            {
                "name": "daemonsets",
                "singularName": "daemonset",
                "namespaced": true,
                "kind": "DaemonSet",
                "shortNames": ["ds"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "deployments",
                "singularName": "deployment",
                "namespaced": true,
                "kind": "Deployment",
                "shortNames": ["deploy"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "deployments/scale",
                "singularName": "",
                "namespaced": true,
                "kind": "Scale",
                "group": "autoscaling",
                "version": "v1",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "replicasets",
                "singularName": "replicaset",
                "namespaced": true,
                "kind": "ReplicaSet",
                "shortNames": ["rs"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "replicasets/scale",
                "singularName": "",
                "namespaced": true,
                "kind": "Scale",
                "group": "autoscaling",
                "version": "v1",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "statefulsets",
                "singularName": "statefulset",
                "namespaced": true,
                "kind": "StatefulSet",
                "shortNames": ["sts"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "statefulsets/scale",
                "singularName": "",
                "namespaced": true,
                "kind": "Scale",
                "group": "autoscaling",
                "version": "v1",
                "verbs": ["get", "patch", "update"]
            }
        ]
    })
}

fn authn_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "authentication.k8s.io/v1",
        "resources": [
            {
                "name": "tokenreviews",
                "singularName": "tokenreview",
                "namespaced": false,
                "kind": "TokenReview",
                "verbs": ["create"]
            }
        ]
    })
}

fn authz_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "authorization.k8s.io/v1",
        "resources": [
            {
                "name": "localsubjectaccessreviews",
                "singularName": "localsubjectaccessreview",
                "namespaced": true,
                "kind": "LocalSubjectAccessReview",
                "verbs": ["create"]
            },
            {
                "name": "selfsubjectaccessreviews",
                "singularName": "selfsubjectaccessreview",
                "namespaced": false,
                "kind": "SelfSubjectAccessReview",
                "verbs": ["create"]
            },
            {
                "name": "selfsubjectrulesreviews",
                "singularName": "selfsubjectrulesreview",
                "namespaced": false,
                "kind": "SelfSubjectRulesReview",
                "verbs": ["create"]
            },
            {
                "name": "subjectaccessreviews",
                "singularName": "subjectaccessreview",
                "namespaced": false,
                "kind": "SubjectAccessReview",
                "verbs": ["create"]
            }
        ]
    })
}

fn rbac_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "rbac.authorization.k8s.io/v1",
        "resources": [
            {
                "name": "clusterroles",
                "singularName": "clusterrole",
                "namespaced": false,
                "kind": "ClusterRole",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "clusterrolebindings",
                "singularName": "clusterrolebinding",
                "namespaced": false,
                "kind": "ClusterRoleBinding",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "roles",
                "singularName": "role",
                "namespaced": true,
                "kind": "Role",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "rolebindings",
                "singularName": "rolebinding",
                "namespaced": true,
                "kind": "RoleBinding",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn resource_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "resource.k8s.io/v1",
        "resources": [
            {
                "name": "deviceclasses",
                "singularName": "deviceclass",
                "namespaced": false,
                "kind": "DeviceClass",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "resourceclaims",
                "singularName": "resourceclaim",
                "namespaced": true,
                "kind": "ResourceClaim",
                "shortNames": ["rc"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "resourceclaimtemplates",
                "singularName": "resourceclaimtemplate",
                "namespaced": true,
                "kind": "ResourceClaimTemplate",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "resourceslices",
                "singularName": "resourceslice",
                "namespaced": false,
                "kind": "ResourceSlice",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn admissionregistration_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "admissionregistration.k8s.io/v1",
        "resources": [
            {
                "name": "mutatingadmissionpolicies",
                "singularName": "mutatingadmissionpolicy",
                "namespaced": false,
                "kind": "MutatingAdmissionPolicy",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "mutatingadmissionpolicybindings",
                "singularName": "mutatingadmissionpolicybinding",
                "namespaced": false,
                "kind": "MutatingAdmissionPolicyBinding",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "mutatingwebhookconfigurations",
                "singularName": "mutatingwebhookconfiguration",
                "namespaced": false,
                "kind": "MutatingWebhookConfiguration",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "validatingadmissionpolicies",
                "singularName": "validatingadmissionpolicy",
                "namespaced": false,
                "kind": "ValidatingAdmissionPolicy",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "validatingadmissionpolicies/status",
                "singularName": "",
                "namespaced": false,
                "kind": "ValidatingAdmissionPolicy",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "validatingadmissionpolicybindings",
                "singularName": "validatingadmissionpolicybinding",
                "namespaced": false,
                "kind": "ValidatingAdmissionPolicyBinding",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "validatingadmissionpolicybindings/status",
                "singularName": "",
                "namespaced": false,
                "kind": "ValidatingAdmissionPolicyBinding",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "validatingwebhookconfigurations",
                "singularName": "validatingwebhookconfiguration",
                "namespaced": false,
                "kind": "ValidatingWebhookConfiguration",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn certificates_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "certificates.k8s.io/v1",
        "resources": [
            {
                "name": "certificatesigningrequests",
                "singularName": "certificatesigningrequest",
                "namespaced": false,
                "kind": "CertificateSigningRequest",
                "shortNames": ["csr"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "certificatesigningrequests/approval",
                "singularName": "",
                "namespaced": false,
                "kind": "CertificateSigningRequest",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "certificatesigningrequests/status",
                "singularName": "",
                "namespaced": false,
                "kind": "CertificateSigningRequest",
                "verbs": ["get", "patch", "update"]
            }
        ]
    })
}

fn coordination_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "coordination.k8s.io/v1",
        "resources": [
            {
                "name": "leases",
                "singularName": "lease",
                "namespaced": true,
                "kind": "Lease",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn discovery_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "discovery.k8s.io/v1",
        "resources": [
            {
                "name": "endpointslices",
                "singularName": "endpointslice",
                "namespaced": true,
                "kind": "EndpointSlice",
                "shortNames": ["eps"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn networking_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "networking.k8s.io/v1",
        "resources": [
            {
                "name": "ingressclasses",
                "singularName": "ingressclass",
                "namespaced": false,
                "kind": "IngressClass",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "ingresses",
                "singularName": "ingress",
                "namespaced": true,
                "kind": "Ingress",
                "shortNames": ["ing"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "ipaddresses",
                "singularName": "ipaddress",
                "namespaced": false,
                "kind": "IPAddress",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "networkpolicies",
                "singularName": "networkpolicy",
                "namespaced": true,
                "kind": "NetworkPolicy",
                "shortNames": ["netpol"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "servicecidrs",
                "singularName": "servicecidr",
                "namespaced": false,
                "kind": "ServiceCIDR",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn gateway_networking_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "gateway.networking.k8s.io/v1",
        "resources": [
            {
                "name": "gatewayclasses",
                "singularName": "gatewayclass",
                "namespaced": false,
                "kind": "GatewayClass",
                "shortNames": ["gc"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "gateways",
                "singularName": "gateway",
                "namespaced": true,
                "kind": "Gateway",
                "shortNames": ["gtw"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "httproutes",
                "singularName": "httproute",
                "namespaced": true,
                "kind": "HTTPRoute",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn gateway_networking_v1beta1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "gateway.networking.k8s.io/v1beta1",
        "resources": [
            {
                "name": "referencegrants",
                "singularName": "referencegrant",
                "namespaced": true,
                "kind": "ReferenceGrant",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn policy_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "policy/v1",
        "resources": [
            {
                "name": "poddisruptionbudgets",
                "singularName": "poddisruptionbudget",
                "namespaced": true,
                "kind": "PodDisruptionBudget",
                "shortNames": ["pdb"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn node_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "node.k8s.io/v1",
        "resources": [
            {
                "name": "runtimeclasses",
                "singularName": "runtimeclass",
                "namespaced": false,
                "kind": "RuntimeClass",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn batch_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "batch/v1",
        "resources": [
            {
                "name": "cronjobs",
                "singularName": "cronjob",
                "namespaced": true,
                "kind": "CronJob",
                "shortNames": ["cj"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "jobs",
                "singularName": "job",
                "namespaced": true,
                "kind": "Job",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn autoscaling_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "autoscaling/v1",
        "resources": [
            {
                "name": "horizontalpodautoscalers",
                "singularName": "horizontalpodautoscaler",
                "namespaced": true,
                "kind": "HorizontalPodAutoscaler",
                "shortNames": ["hpa"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn autoscaling_v2_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "autoscaling/v2",
        "resources": [
            {
                "name": "horizontalpodautoscalers",
                "singularName": "horizontalpodautoscaler",
                "namespaced": true,
                "kind": "HorizontalPodAutoscaler",
                "shortNames": ["hpa"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn storage_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "storage.k8s.io/v1",
        "resources": [
            {
                "name": "csidrivers",
                "singularName": "csidriver",
                "namespaced": false,
                "kind": "CSIDriver",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "csinodes",
                "singularName": "csinode",
                "namespaced": false,
                "kind": "CSINode",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "storageclasses",
                "singularName": "storageclass",
                "namespaced": false,
                "kind": "StorageClass",
                "shortNames": ["sc"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "volumeattachments",
                "singularName": "volumeattachment",
                "namespaced": false,
                "kind": "VolumeAttachment",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "volumeattributesclasses",
                "singularName": "volumeattributesclass",
                "namespaced": false,
                "kind": "VolumeAttributesClass",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "csistoragecapacities",
                "singularName": "csistoragecapacity",
                "namespaced": true,
                "kind": "CSIStorageCapacity",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn events_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "events.k8s.io/v1",
        "resources": [
            {
                "name": "events",
                "singularName": "event",
                "namespaced": true,
                "kind": "Event",
                "shortNames": ["ev"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

fn flowcontrol_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "flowcontrol.apiserver.k8s.io/v1",
        "resources": [
            {
                "name": "flowschemas",
                "singularName": "flowschema",
                "namespaced": false,
                "kind": "FlowSchema",
                "shortNames": ["fs"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "flowschemas/status",
                "singularName": "",
                "namespaced": false,
                "kind": "FlowSchema",
                "verbs": ["get", "patch", "update"]
            },
            {
                "name": "prioritylevelconfigurations",
                "singularName": "prioritylevelconfiguration",
                "namespaced": false,
                "kind": "PriorityLevelConfiguration",
                "shortNames": ["plc"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "prioritylevelconfigurations/status",
                "singularName": "",
                "namespaced": false,
                "kind": "PriorityLevelConfiguration",
                "verbs": ["get", "patch", "update"]
            }
        ]
    })
}

fn scheduling_v1_resources() -> serde_json::Value {
    serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "scheduling.k8s.io/v1",
        "resources": [
            {
                "name": "priorityclasses",
                "singularName": "priorityclass",
                "namespaced": false,
                "kind": "PriorityClass",
                "shortNames": ["pc"],
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// OpenAPI stub endpoints
// ---------------------------------------------------------------------------

/// Swagger 2.0 document with synthesized definitions for installed CRDs.
/// Polls the store at request time so that newly-created CRDs appear without
/// a restart — required by the CustomResourcePublishOpenAPI conformance test.
///
/// Content-type negotiation: kubectl 1.36's validation path sends a proto-only
/// Accept (`application/com.github.proto-openapi.spec.v2@v1.0+protobuf`) and
/// unconditionally gnostic-decodes the body, ignoring the response Content-Type.
/// Returning JSON to that request causes "proto: cannot parse invalid wire-format
/// data". When the Accept header is proto-only we return a minimal valid gnostic
/// openapi_v2.Document; otherwise (Accept includes application/json or */*) we
/// return JSON as before.
pub async fn openapi_v2<S: Store>(
    State(state): State<AppState<S>>,
    headers: HeaderMap,
) -> Response {
    let mut definitions = serde_json::Map::new();

    if let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    {
        for obj in &resp.items {
            let Ok(crd) = serde_json::from_slice::<CustomResourceDefinition>(&obj.value) else {
                continue;
            };
            let group = &crd.spec.group;
            let kind = &crd.spec.names.kind;
            let reversed: String = group.split('.').rev().collect::<Vec<_>>().join(".");
            for ver in &crd.spec.versions {
                if !ver.served {
                    continue;
                }
                let key = format!("{}.{}.{}", reversed, ver.name, kind);
                let mut def = serde_json::json!({
                    "type": "object",
                    "x-kubernetes-group-version-kind": [
                        {
                            "group": group,
                            "version": ver.name,
                            "kind": kind
                        }
                    ]
                });
                if let Some(schema) = ver
                    .schema
                    .as_ref()
                    .and_then(|s| s.get("openAPIV3Schema"))
                    .and_then(|s| s.as_object())
                {
                    for field in &[
                        "type",
                        "properties",
                        "items",
                        "description",
                        "format",
                        "required",
                    ] {
                        if let Some(v) = schema.get(*field) {
                            def[field] = v.clone();
                        }
                    }
                }
                definitions.insert(key, def);
            }
        }
    }

    // Proto-only content negotiation: if Accept contains the gnostic proto media type
    // and does NOT contain application/json, return a gnostic openapi_v2.Document.
    // kubectl 1.36's validation path sends proto-only Accept and gnostic-decodes the
    // body unconditionally — JSON bytes are invalid wire-format proto and cause
    // "proto: cannot parse invalid wire-format data".
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if accept.contains("proto-openapi") && !accept.contains("application/json") {
        const PROTO_CT: &str = "application/com.github.proto-openapi.spec.v2.v1.0+protobuf";
        let body = crate::proto::encode_gnostic_openapi_v2_document();
        return ([(axum::http::header::CONTENT_TYPE, PROTO_CT)], body).into_response();
    }

    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Json(serde_json::json!({
            "swagger": "2.0",
            "info": {"title": "u7s", "version": "v1"},
            "paths": {},
            "definitions": definitions
        })),
    )
        .into_response()
}

pub async fn openapi_v3<S: Store>(State(state): State<AppState<S>>) -> Response {
    let mut paths = serde_json::Map::new();

    // Core group ("" / v1) and every STATIC_GROUPS group+version get a real entry here
    // even with zero CRDs registered. kubectl 1.28+'s default (v3) `explain` renderer
    // looks up "api/v1" or "apis/<group>/<version>" in exactly this map and errors with
    // `couldn't find resource for ...` if the key is missing -- it does NOT fall back to
    // /openapi/v2 just because a key is absent (only if fetching /openapi/v3 itself errors
    // outright), so a missing entry here breaks `kubectl explain <builtin>` unconditionally.
    paths.insert(
        "api/v1".to_string(),
        serde_json::json!({ "serverRelativeURL": "/openapi/v3/api/v1" }),
    );
    for group in &api_group_list_inner(&state).await.groups {
        if !STATIC_GROUPS.iter().any(|(name, _)| *name == group.name) {
            continue; // CRD-backed groups are added below; aggregated groups aren't served yet.
        }
        for gv in &group.versions {
            let key = format!("apis/{}", gv.group_version);
            let url = format!("/openapi/v3/{key}");
            paths.insert(key, serde_json::json!({ "serverRelativeURL": url }));
        }
    }

    if let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    {
        for obj in &resp.items {
            let Ok(crd) = serde_json::from_slice::<CustomResourceDefinition>(&obj.value) else {
                continue;
            };
            let group = &crd.spec.group;
            for ver in &crd.spec.versions {
                if !ver.served {
                    continue;
                }
                let key = format!("apis/{}/{}", group, ver.name);
                let url = format!("/openapi/v3/apis/{}/{}", group, ver.name);
                paths.insert(key, serde_json::json!({ "serverRelativeURL": url }));
            }
        }
    }

    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Json(serde_json::json!({ "paths": paths })),
    )
        .into_response()
}

/// components.schemas key for the shared ObjectMeta definition referenced by
/// every CRD's `metadata` field (see `inject_standard_object_fields`).
const OBJECT_META_SCHEMA_NAME: &str = "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta";

/// Real kube-apiserver always injects TypeMeta (`apiVersion`, `kind`) and
/// ObjectMeta (`metadata`) into a CRD's published OpenAPI schema server-side —
/// CRD authors only ever describe `spec`/`status` in `openAPIV3Schema`.
/// `kubectl explain <crd>` and `kubectl explain <crd>.metadata` rely on these
/// standard fields being present; without them `apiVersion`/`kind` are
/// missing from the top-level FIELDS list and `.metadata` cannot be explained
/// at all (the field simply doesn't exist in the schema).
fn inject_standard_object_fields(schema_obj: &mut serde_json::Map<String, serde_json::Value>) {
    let properties = schema_obj
        .entry("properties")
        .or_insert_with(|| serde_json::json!({}));
    let Some(properties) = properties.as_object_mut() else {
        return;
    };
    properties.insert(
        "apiVersion".to_string(),
        serde_json::json!({
            "type": "string",
            "description": "APIVersion defines the versioned schema of this representation \
                of an object. Servers should convert recognized schemas to the latest internal \
                value, and may reject unrecognized values. More info: \
                https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources"
        }),
    );
    properties.insert(
        "kind".to_string(),
        serde_json::json!({
            "type": "string",
            "description": "Kind is a string value representing the REST resource this object \
                represents. Servers may infer this from the endpoint the client submits requests \
                to. Cannot be updated. In CamelCase. More info: \
                https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
        }),
    );
    // OpenAPI v3 ignores sibling keys next to `$ref` (unlike v2/Swagger), so a
    // flat `{"$ref": ..., "description": ...}` loses the field-level
    // description entirely once kubectl explain's template dereferences the
    // `$ref` — `kubectl explain <crd>.metadata` would then show only
    // ObjectMeta's own top-level description, never "Standard object's
    // metadata". Wrapping the `$ref` in `allOf` is the standard workaround:
    // kubectl's "description" template walks both the wrapper's own
    // description AND each `allOf` member's resolved description.
    properties.insert(
        "metadata".to_string(),
        serde_json::json!({
            "description": "Standard object's metadata. More info: \
                https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata",
            "allOf": [
                { "$ref": format!("#/components/schemas/{OBJECT_META_SCHEMA_NAME}") }
            ]
        }),
    );
}

/// The ObjectMeta shape every Kubernetes object carries under `metadata`,
/// referenced via `$ref` by `inject_standard_object_fields`. `kubectl explain
/// <crd>.metadata` resolves nested fields (e.g. `creationTimestamp`) against
/// this schema, so it needs real properties, not an opaque `type: object`.
fn object_meta_v3_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "description": "ObjectMeta is metadata that all persisted resources must have, which \
            includes all objects users must create.",
        "properties": {
            "name": {
                "type": "string",
                "description": "Name must be unique within a namespace. Is required when \
                    creating resources, although some resources may allow a client to request \
                    the generation of an appropriate name automatically. Cannot be updated. \
                    More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names#names"
            },
            "generateName": {
                "type": "string",
                "description": "GenerateName is an optional prefix, used by the server, to \
                    generate a unique name ONLY IF the Name field has not been provided. \
                    More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#idempotency"
            },
            "namespace": {
                "type": "string",
                "description": "Namespace defines the space within which each name must be \
                    unique. An empty namespace is equivalent to the \"default\" namespace. \
                    More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces"
            },
            "uid": {
                "type": "string",
                "description": "UID is the unique in time and space value for this object. It \
                    is typically generated by the server on successful creation of a resource \
                    and is not allowed to change on PUT operations. Populated by the system. \
                    Read-only. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names#uids"
            },
            "resourceVersion": {
                "type": "string",
                "description": "An opaque value that represents the internal version of this \
                    object that can be used by clients to determine when objects have changed. \
                    Populated by the system. Read-only. More info: \
                    https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency"
            },
            "generation": {
                "type": "integer",
                "format": "int64",
                "description": "A sequence number representing a specific generation of the \
                    desired state. Populated by the system. Read-only."
            },
            "creationTimestamp": {
                "type": "string",
                "format": "date-time",
                "description": "CreationTimestamp is a timestamp representing the server time \
                    when this object was created. It is not guaranteed to be set in \
                    happens-before order across separate operations. Clients may not set this \
                    value. It is represented in RFC3339 form and is in UTC. Populated by the \
                    system. Read-only. Null for lists. More info: \
                    https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata"
            },
            "deletionTimestamp": {
                "type": "string",
                "format": "date-time",
                "description": "DeletionTimestamp is RFC 3339 date and time at which this \
                    resource will be deleted. This field is set by the server when a graceful \
                    deletion is requested by the user, and is not directly settable by a \
                    client. Populated by the system when a graceful deletion is requested. \
                    Read-only. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata"
            },
            "deletionGracePeriodSeconds": {
                "type": "integer",
                "format": "int64",
                "description": "Number of seconds allowed for this object to gracefully \
                    terminate before it will be removed from the system. Only set when \
                    deletionTimestamp is also set. May only be shortened. Read-only."
            },
            "labels": {
                "type": "object",
                "additionalProperties": { "type": "string" },
                "description": "Map of string keys and values that can be used to organize and \
                    categorize (scope and select) objects. May match selectors of replication \
                    controllers and services. More info: \
                    https://kubernetes.io/docs/concepts/overview/working-with-objects/labels"
            },
            "annotations": {
                "type": "object",
                "additionalProperties": { "type": "string" },
                "description": "Annotations is an unstructured key value map stored with a \
                    resource that may be set by external tools to store and retrieve arbitrary \
                    metadata. They are not queryable and should be preserved when modifying \
                    objects. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations"
            },
            "finalizers": {
                "type": "array",
                "items": { "type": "string" },
                "description": "Must be empty before the object is deleted from the registry. \
                    Each entry is an identifier for the responsible component that will remove \
                    the entry from the list. If the deletionTimestamp of the object is non-nil, \
                    entries in this list can only be removed."
            },
            "ownerReferences": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "OwnerReference contains enough information to let you \
                        identify an owning object. An owning object must be in the same \
                        namespace as the dependent, or be cluster-scoped, so there is no \
                        namespace field.",
                    "properties": {
                        "apiVersion": { "type": "string", "description": "API version of the referent." },
                        "kind": {
                            "type": "string",
                            "description": "Kind of the referent. More info: \
                                https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds"
                        },
                        "name": {
                            "type": "string",
                            "description": "Name of the referent. More info: \
                                https://kubernetes.io/docs/concepts/overview/working-with-objects/names#names"
                        },
                        "uid": {
                            "type": "string",
                            "description": "UID of the referent. More info: \
                                https://kubernetes.io/docs/concepts/overview/working-with-objects/names#uids"
                        },
                        "controller": {
                            "type": "boolean",
                            "description": "If true, this reference points to the managing controller."
                        },
                        "blockOwnerDeletion": {
                            "type": "boolean",
                            "description": "If true, AND if the owner has the \
                                \"foregroundDeletion\" finalizer, then the owner cannot be \
                                deleted from the key-value store until this reference is removed."
                        }
                    },
                    "required": ["apiVersion", "kind", "name", "uid"]
                },
                "description": "List of objects depended by this object. If ALL objects in the \
                    list have been deleted, this object will be garbage collected. If this \
                    object is managed by a controller, then an entry in this list will point to \
                    this controller, with the controller field set to true."
            },
            "managedFields": {
                "type": "array",
                "items": { "type": "object" },
                "description": "ManagedFields maps workflow-id and version to the set of fields \
                    that are managed by that workflow. This is mostly for internal \
                    housekeeping, and users typically shouldn't need to set or understand this \
                    field."
            }
        }
    })
}

pub async fn openapi_v3_group<S: Store>(
    State(state): State<AppState<S>>,
    Path((group, version)): Path<(String, String)>,
) -> Response {
    let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let mut schemas = serde_json::Map::new();
    let mut paths = serde_json::Map::new();

    for obj in &resp.items {
        let Ok(crd) = serde_json::from_slice::<CustomResourceDefinition>(&obj.value) else {
            continue;
        };
        if crd.spec.group != group {
            continue;
        }
        for ver in &crd.spec.versions {
            if ver.name != version || !ver.served {
                continue;
            }
            let mut schema = ver
                .schema
                .as_ref()
                .and_then(|s| s.get("openAPIV3Schema"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({ "type": "object" }));
            let kind = &crd.spec.names.kind;
            let gvk = serde_json::json!({
                "group": group,
                "version": version,
                "kind": kind
            });
            // kubectl explain's OpenAPI v3 plaintext template filters
            // components.schemas by this extension to find the schema for a
            // resolved GVK; without it the schema is unreachable even though
            // it is present in the document.
            if let Some(schema_obj) = schema.as_object_mut() {
                schema_obj.insert(
                    "x-kubernetes-group-version-kind".to_string(),
                    serde_json::json!([gvk.clone()]),
                );
                inject_standard_object_fields(schema_obj);
            }
            schemas.insert(kind.clone(), schema);

            // kubectl explain resolves the GVK for a GVR by scanning `paths`
            // for the resource's REST path before ever looking at
            // components.schemas; an empty `paths` document makes explain
            // fail with "GVR (...) not found in OpenAPI schema" even when
            // the schema itself is fully populated.
            let plural = &crd.spec.names.plural;
            let path_key = if crd.spec.scope == "Namespaced" {
                format!("/apis/{group}/{version}/namespaces/{{namespace}}/{plural}")
            } else {
                format!("/apis/{group}/{version}/{plural}")
            };
            paths.insert(
                path_key,
                serde_json::json!({
                    "get": { "x-kubernetes-group-version-kind": gvk }
                }),
            );
        }
    }

    if schemas.is_empty() {
        // Not CRD-backed -- fall back to a static built-in group/version, if this is
        // one, so `kubectl explain <builtin>` gets a real document instead of a 404
        // (client-go's explain v2 renderer treats a fetch error here as a hard
        // failure, not a signal to retry against /openapi/v2).
        return match static_group_resources(group.as_str(), version.as_str()) {
            Some(resource_list) => Json(static_group_v3_document(
                group.as_str(),
                version.as_str(),
                &resource_list,
                &format!("/apis/{group}/{version}"),
            ))
            .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    schemas.insert(OBJECT_META_SCHEMA_NAME.to_string(), object_meta_v3_schema());

    Json(serde_json::json!({
        "openapi": "3.0.0",
        "info": { "title": format!("{}/{}", group, version), "version": "v1" },
        "paths": paths,
        "components": { "schemas": schemas }
    }))
    .into_response()
}

/// Handler for `GET /openapi/v3/api/v1` — the core group's OpenAPI v3 document.
/// `kubectl explain <core-kind>` (Pod, Service, ConfigMap, ...) needs this: the default
/// (v3) explain renderer resolves "api/v1" from `/openapi/v3`'s `paths` map (see
/// `openapi_v3`) and then fetches exactly this document.
pub async fn openapi_v3_core() -> Response {
    Json(static_group_v3_document(
        "",
        "v1",
        &api_v1_resource_list_value(),
        "/api/v1",
    ))
    .into_response()
}

/// Curated, real top-level description for the handful of built-in Kinds users most
/// commonly `kubectl explain`. Transcribed verbatim (trimmed to the essential sentence)
/// from k8s.io/api's `types.go` doc comments (release-1.36) — not invented, so it can't
/// drift from what `kubectl explain <kind>` shows against a real cluster.
fn curated_kind_description(kind: &str) -> Option<&'static str> {
    match kind {
        "Pod" => Some(
            "Pod is a collection of containers that can run on a host. This resource is \
             created by clients and scheduled onto hosts.",
        ),
        "Service" => Some(
            "Service is a named abstraction of software service (for example, mysql) \
             consisting of local port (for example 3306) that the proxy listens on, and the \
             selector that determines which pods will answer requests sent through the proxy.",
        ),
        "ConfigMap" => Some("ConfigMap holds configuration data for pods to consume."),
        "Secret" => Some(
            "Secret holds secret data of a certain type. The total bytes of the values in the \
             Data field must be less than MaxSecretSize bytes.",
        ),
        "Namespace" => {
            Some("Namespace provides a scope for Names. Use of multiple namespaces is optional.")
        }
        "Deployment" => Some("Deployment enables declarative updates for Pods and ReplicaSets."),
        "ReplicaSet" => Some(
            "ReplicaSet ensures that a specified number of pod replicas are running at any \
             given time.",
        ),
        "StatefulSet" => Some("StatefulSet represents a set of pods with consistent identities."),
        "DaemonSet" => Some("DaemonSet represents the configuration of a daemon set."),
        "Job" => Some("Job represents the configuration of a single job."),
        "CronJob" => Some("CronJob represents the configuration of a single cron job."),
        "PersistentVolume" => Some(
            "PersistentVolume (PV) is a storage resource provisioned by an administrator. It \
             is analogous to a node.",
        ),
        "PersistentVolumeClaim" => {
            Some("PersistentVolumeClaim is a user's request for and claim to a persistent volume")
        }
        "ServiceAccount" => Some(
            "ServiceAccount binds together:\n\
             * a name, understood by users, and perhaps by peripheral systems, for an identity\n\
             * a principal that can be authenticated and authorized\n\
             * a set of secrets",
        ),
        "Ingress" => Some(
            "Ingress is a collection of rules that allow inbound connections to reach the \
             endpoints defined by a backend. An Ingress can be configured to give services \
             externally-reachable urls, load balance traffic, terminate SSL, offer name based \
             virtual hosting etc.",
        ),
        "NetworkPolicy" => {
            Some("NetworkPolicy describes what network traffic is allowed for a set of Pods")
        }
        _ => None,
    }
}

/// Curated, real top-level properties (beyond the universal apiVersion/kind/metadata every
/// Kind gets from `inject_standard_object_fields`) for the same curated Kinds as
/// `curated_kind_description`, transcribed from `types.go` the same way.
///
/// Deliberately shallow: each property is `type: object` (or a primitive/map) with no
/// nested `properties` of its own. `kubectl explain <kind>` (no field path) only reads a
/// Kind's OWN top-level shape, so this is enough to make that succeed with real field
/// names; going deeper (e.g. every PodSpec field) is follow-up scope.
///
/// Kinds NOT listed here still get a valid, correct schema (apiVersion/kind/metadata only)
/// rather than a guessed `spec`/`status` -- many built-ins (ConfigMap, Secret, Endpoints...)
/// don't follow that convention, and a wrong field name is worse than an incomplete one.
fn curated_top_level_properties(kind: &str) -> Option<Vec<(&'static str, serde_json::Value)>> {
    match kind {
        "Pod" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Specification of the desired behavior of the pod. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Most recently observed status of the pod. This data may not be \
                        up to date. Populated by the system. Read-only. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "Service" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Spec defines the behavior of a service. \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Most recently observed status of the service. Populated by the \
                        system. Read-only. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "Namespace" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Spec defines the behavior of the Namespace. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Status describes the current status of a Namespace. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "ConfigMap" => Some(vec![
            (
                "immutable",
                serde_json::json!({
                    "type": "boolean",
                    "description": "Immutable, if set to true, ensures that data stored in the \
                        ConfigMap cannot be updated (only object metadata can be modified). If not \
                        set to true, the field can be modified at any time. Defaulted to nil."
                }),
            ),
            (
                "data",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Data contains the configuration data. Each key must consist of \
                        alphanumeric characters, '-', '_' or '.'. Values with non-UTF-8 byte \
                        sequences must use the BinaryData field. The keys stored in Data must not \
                        overlap with the keys in the BinaryData field, this is enforced during \
                        validation process."
                }),
            ),
            (
                "binaryData",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": { "type": "string", "format": "byte" },
                    "description": "BinaryData contains the binary data. Each key must consist of \
                        alphanumeric characters, '-', '_' or '.'. BinaryData can contain byte \
                        sequences that are not in the UTF-8 range. The keys stored in BinaryData \
                        must not overlap with the ones in the Data field, this is enforced during \
                        validation process. Using this field will require 1.10+ apiserver and kubelet."
                }),
            ),
        ]),
        "Secret" => Some(vec![
            (
                "immutable",
                serde_json::json!({
                    "type": "boolean",
                    "description": "Immutable, if set to true, ensures that data stored in the \
                        Secret cannot be updated (only object metadata can be modified). If not set \
                        to true, the field can be modified at any time. Defaulted to nil."
                }),
            ),
            (
                "data",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": { "type": "string", "format": "byte" },
                    "description": "Data contains the secret data. Each key must consist of \
                        alphanumeric characters, '-', '_' or '.'. The serialized form of the secret \
                        data is a base64 encoded string, representing the arbitrary (possibly \
                        non-string) data value here. Described in \
                        https://tools.ietf.org/html/rfc4648#section-4"
                }),
            ),
            (
                "stringData",
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "stringData allows specifying non-binary secret data in string \
                        form. It is provided as a write-only input field for convenience. All keys \
                        and values are merged into the data field on write, overwriting any existing \
                        values. The stringData field is never output when reading from the API."
                }),
            ),
            (
                "type",
                serde_json::json!({
                    "type": "string",
                    "description": "Used to facilitate programmatic handling of secret data. More \
                        info: https://kubernetes.io/docs/concepts/configuration/secret/#secret-types"
                }),
            ),
        ]),
        "Deployment" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Specification of the desired behavior of the Deployment."
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Most recently observed status of the Deployment."
                }),
            ),
        ]),
        "ReplicaSet" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Spec defines the specification of the desired behavior of \
                        the ReplicaSet. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Status is the most recently observed status of the \
                        ReplicaSet. This data may be out of date by some window of time. \
                        Populated by the system. Read-only. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "StatefulSet" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Spec defines the desired identities of pods in this set."
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Status is the current status of Pods in this StatefulSet. \
                        This data may be out of date by some window of time."
                }),
            ),
        ]),
        "DaemonSet" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "The desired behavior of this daemon set. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "The current status of this daemon set. This data may be \
                        out of date by some window of time. Populated by the system. Read-only. \
                        More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "Job" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Specification of the desired behavior of a job. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Current status of a job. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "CronJob" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "Specification of the desired behavior of a cron job, \
                        including the schedule. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "Current status of a cron job. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "PersistentVolume" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "spec defines a specification of a persistent volume owned \
                        by the cluster. Provisioned by an administrator. More info: \
                        https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistent-volumes"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "status represents the current information/status for the \
                        persistent volume. Populated by the system. Read-only. More info: \
                        https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistent-volumes"
                }),
            ),
        ]),
        "PersistentVolumeClaim" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "spec defines the desired characteristics of a volume \
                        requested by a pod author. More info: \
                        https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "status represents the current information/status of a \
                        persistent volume claim. Read-only. More info: \
                        https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims"
                }),
            ),
        ]),
        "ServiceAccount" => Some(vec![
            (
                "secrets",
                serde_json::json!({
                    "type": "array",
                    "items": { "type": "object" },
                    "description": "Secrets is a list of the secrets in the same namespace \
                        that pods running using this ServiceAccount are allowed to use. Pods \
                        are only limited to this list if this service account has a \
                        \"kubernetes.io/enforce-mountable-secrets\" annotation set to \"true\". \
                        The \"kubernetes.io/enforce-mountable-secrets\" annotation is deprecated \
                        since v1.32. Prefer separate namespaces to isolate access to mounted \
                        secrets. This field should not be used to find auto-generated service \
                        account token secrets for use outside of pods. Instead, tokens can be \
                        requested directly using the TokenRequest API, or service account token \
                        secrets can be manually created. More info: \
                        https://kubernetes.io/docs/concepts/configuration/secret"
                }),
            ),
            (
                "imagePullSecrets",
                serde_json::json!({
                    "type": "array",
                    "items": { "type": "object" },
                    "description": "ImagePullSecrets is a list of references to secrets in the \
                        same namespace to use for pulling any images in pods that reference \
                        this ServiceAccount. ImagePullSecrets are distinct from Secrets because \
                        Secrets can be mounted in the pod, but ImagePullSecrets are only \
                        accessed by the kubelet. More info: \
                        https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod"
                }),
            ),
            (
                "automountServiceAccountToken",
                serde_json::json!({
                    "type": "boolean",
                    "description": "AutomountServiceAccountToken indicates whether pods \
                        running as this service account should have an API token automatically \
                        mounted. Can be overridden at the pod level."
                }),
            ),
        ]),
        "Ingress" => Some(vec![
            (
                "spec",
                serde_json::json!({
                    "type": "object",
                    "description": "spec is the desired state of the Ingress. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
            (
                "status",
                serde_json::json!({
                    "type": "object",
                    "description": "status is the current state of the Ingress. More info: \
                        https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status"
                }),
            ),
        ]),
        "NetworkPolicy" => Some(vec![(
            "spec",
            serde_json::json!({
                "type": "object",
                "description": "spec represents the specification of the desired behavior \
                    for this NetworkPolicy."
            }),
        )]),
        _ => None,
    }
}

/// Build an OpenAPI v3 document (`paths` + `components.schemas`) for a static (built-in)
/// group/version from its `APIResourceList`-shaped resource data (the same JSON already
/// used to answer `GET /apis/<group>/<version>` and `GET /api/v1` — see
/// `static_group_resources` / `api_v1_resource_list_value`).
///
/// One function serves every static group uniformly: every Kind gets a real, correct
/// schema (apiVersion/kind/metadata, always accurate) enriched with
/// `curated_top_level_properties` for the handful of Kinds that table covers. This is
/// deliberately the ONLY place built-in v3 schemas are assembled — adding a group or Kind
/// never means copy-pasting this function, only adding data to the curated tables above.
fn static_group_v3_document(
    group: &str,
    version: &str,
    resource_list: &serde_json::Value,
    path_prefix: &str,
) -> serde_json::Value {
    let mut schemas = serde_json::Map::new();
    let mut paths = serde_json::Map::new();
    let empty = Vec::new();
    let resources = resource_list["resources"].as_array().unwrap_or(&empty);

    for r in resources {
        let name = r["name"].as_str().unwrap_or("");
        // Subresources (scale, status, binding, ...) share their parent's Kind schema and
        // aren't independently explainable Kinds.
        if name.is_empty() || name.contains('/') {
            continue;
        }
        let kind = r["kind"].as_str().unwrap_or("");
        if kind.is_empty() || schemas.contains_key(kind) {
            continue;
        }
        let namespaced = r["namespaced"].as_bool().unwrap_or(false);
        let gvk = serde_json::json!({ "group": group, "version": version, "kind": kind });

        let mut schema_obj = serde_json::Map::new();
        schema_obj.insert("type".to_string(), serde_json::json!("object"));
        if let Some(description) = curated_kind_description(kind) {
            schema_obj.insert("description".to_string(), serde_json::json!(description));
        }
        schema_obj.insert(
            "x-kubernetes-group-version-kind".to_string(),
            serde_json::json!([gvk.clone()]),
        );
        inject_standard_object_fields(&mut schema_obj);
        if let Some(extra) = curated_top_level_properties(kind) {
            if let Some(properties) = schema_obj
                .get_mut("properties")
                .and_then(|p| p.as_object_mut())
            {
                for (field, def) in extra {
                    properties.insert(field.to_string(), def);
                }
            }
        }
        schemas.insert(kind.to_string(), serde_json::Value::Object(schema_obj));

        let path_key = if namespaced {
            format!("{path_prefix}/namespaces/{{namespace}}/{name}")
        } else {
            format!("{path_prefix}/{name}")
        };
        paths.insert(
            path_key,
            serde_json::json!({ "get": { "x-kubernetes-group-version-kind": gvk } }),
        );
    }

    schemas.insert(OBJECT_META_SCHEMA_NAME.to_string(), object_meta_v3_schema());

    serde_json::json!({
        "openapi": "3.0.0",
        "info": {
            "title": if group.is_empty() { version.to_string() } else { format!("{group}/{version}") },
            "version": "v1"
        },
        "paths": paths,
        "components": { "schemas": schemas }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::{body::Body, http::Request, routing::get, Router};
    use bytes::Bytes;
    use std::sync::Arc;
    use tower::ServiceExt;
    use u7s_store::SqliteStore;

    use crate::handlers::crd::{create_crd, delete_crd};

    fn test_user() -> axum::Extension<crate::auth::UserInfo> {
        axum::Extension(crate::auth::UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        })
    }

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

    fn crd_bytes(
        group: &str,
        plural: &str,
        singular: &str,
        kind: &str,
        scope: &str,
        version: &str,
    ) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": format!("{plural}.{group}") },
                "spec": {
                    "group": group,
                    "names": {
                        "plural": plural,
                        "singular": singular,
                        "kind": kind
                    },
                    "scope": scope,
                    "versions": [
                        { "name": version, "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        )
    }

    // After inserting a CRD, api_group_list must include its group.
    // This verifies that discovery is live — not baked in at startup.
    #[tokio::test]
    async fn crd_group_appears_in_api_group_list() {
        let state = make_state();

        let body = crd_bytes(
            "example.io",
            "widgets",
            "widget",
            "Widget",
            "Namespaced",
            "v1beta1",
        );
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"example.io"),
            "example.io must appear in /apis after CRD install; got: {names:?}"
        );
    }

    // Static groups must always be present regardless of stored CRDs.
    #[tokio::test]
    async fn static_groups_always_present() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        for (group, _) in STATIC_GROUPS {
            assert!(
                names.contains(group),
                "static group {group} must always be in /apis; got: {names:?}"
            );
        }
    }

    // A group that matches a static group must not be duplicated even if a CRD
    // with that group name somehow exists in the store (e.g. inserted before
    // the create-time validation was added). This tests the discovery layer's
    // own deduplication logic, independent of API validation.
    #[tokio::test]
    async fn crd_group_does_not_duplicate_static_groups() {
        use crate::handlers::crd::{
            CrdMetadata, CustomResourceDefinitionNames, CustomResourceDefinitionSpec,
            CustomResourceDefinitionVersion,
        };
        let state = make_state();

        // Insert a CRD directly into the store, bypassing create_crd() validation,
        // to simulate a store that has a CRD with a built-in group (e.g. after a
        // schema migration or manual edit). The discovery layer must still deduplicate.
        let crd = CustomResourceDefinition {
            api_version: "apiextensions.k8s.io/v1".to_string(),
            kind: "CustomResourceDefinition".to_string(),
            metadata: CrdMetadata {
                name: "widgets.apps".to_string(),
                namespace: String::new(),
                labels: None,
                annotations: None,
                resource_version: String::new(),
                uid: "test-uid".to_string(),
                creation_timestamp: "2024-01-01T00:00:00Z".to_string(),
            },
            spec: CustomResourceDefinitionSpec {
                group: "apps".to_string(),
                names: CustomResourceDefinitionNames {
                    plural: "widgets".to_string(),
                    singular: "widget".to_string(),
                    kind: "Widget".to_string(),
                    short_names: vec![],
                    list_kind: String::new(),
                },
                scope: "Namespaced".to_string(),
                versions: vec![CustomResourceDefinitionVersion {
                    name: "v1".to_string(),
                    served: true,
                    storage: true,
                    schema: None,
                    subresources: None,
                    selectable_fields: vec![],
                }],
                conversion: None,
                preserve_unknown_fields: false,
            },
            status: None,
        };
        let key =
            "/registry/apiextensions.k8s.io/customresourcedefinitions/widgets.apps".to_string();
        let bytes = bytes::Bytes::from(serde_json::to_vec(&crd).unwrap());
        state
            .store
            .put(&key, bytes, Some(0))
            .await
            .expect("direct store insert must succeed");

        let list = api_group_list_inner(&state).await;
        let apps_count = list.groups.iter().filter(|g| g.name == "apps").count();
        assert_eq!(
            apps_count, 1,
            "apps group must appear exactly once even when a CRD declares group=apps"
        );
    }

    // After inserting a CRD, api_group_resources for that group/version must return its resource.
    #[tokio::test]
    async fn crd_resource_appears_in_api_group_resources() {
        let state = make_state();

        let body = crd_bytes(
            "example.io",
            "gadgets",
            "gadget",
            "Gadget",
            "Cluster",
            "v1alpha1",
        );
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = api_group_resources(
            State(state),
            Path(("example.io".to_string(), "v1alpha1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1, "one resource entry expected");
        assert_eq!(resources[0]["name"], "gadgets");
        assert_eq!(resources[0]["kind"], "Gadget");
        assert_eq!(resources[0]["namespaced"], false);
    }

    // api_group_resources for an unknown group/version must return 404.
    #[tokio::test]
    async fn unknown_group_returns_404() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("unknown.group.io".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // A CRD with multiple served versions must expose ALL of them in the APIGroup.versions
    // list, not just the storage version. This matters because kubectl discovery walks all
    // listed versions to find available resources.
    #[tokio::test]
    async fn multi_version_crd_lists_all_served_versions_with_correct_preferred() {
        let state = make_state();

        // v1alpha1: served but not storage; v1: served and storage (preferred).
        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": {
                        "plural": "widgets",
                        "singular": "widget",
                        "kind": "Widget"
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1alpha1", "served": true, "storage": false },
                        { "name": "v1",       "served": true, "storage": true  }
                    ]
                }
            })
            .to_string(),
        );
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let list = api_group_list_inner(&state).await;
        let group = list
            .groups
            .iter()
            .find(|g| g.name == "example.io")
            .expect("example.io must appear in /apis");

        let version_names: Vec<&str> = group.versions.iter().map(|v| v.version.as_str()).collect();
        assert!(
            version_names.contains(&"v1alpha1"),
            "v1alpha1 must be listed in versions; got: {version_names:?}"
        );
        assert!(
            version_names.contains(&"v1"),
            "v1 must be listed in versions; got: {version_names:?}"
        );
        assert_eq!(version_names.len(), 2, "exactly 2 served versions expected");
        assert_eq!(
            group.preferred_version.version, "v1",
            "v1 (storage=true) must be the preferredVersion"
        );
    }

    // discovery.k8s.io must appear in /apis — KCM's endpointslice-controller lists
    // discovery.k8s.io/v1/endpointslices at startup; 404 causes log-spam back-off.
    #[tokio::test]
    async fn discovery_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"discovery.k8s.io"),
            "discovery.k8s.io must appear in /apis; got: {names:?}"
        );
    }

    // discovery.k8s.io/v1 resource list must include endpointslices so KCM can watch them.
    #[tokio::test]
    async fn discovery_v1_resources_list() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("discovery.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"endpointslices"),
            "endpointslices must be in discovery.k8s.io/v1; got: {names:?}"
        );
    }

    // storage.k8s.io must appear unconditionally — kubelet probes it at startup.
    #[tokio::test]
    async fn storage_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"storage.k8s.io"),
            "storage.k8s.io must appear in /apis; got: {names:?}"
        );
    }

    // node.k8s.io must appear unconditionally — kubelet probes it at startup.
    #[tokio::test]
    async fn node_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"node.k8s.io"),
            "node.k8s.io must appear in /apis; got: {names:?}"
        );
    }

    // storage.k8s.io/v1 resource list must include csidrivers and csinodes so kubelet
    // can register itself without errors.
    #[tokio::test]
    async fn storage_v1_resources_list() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("storage.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"csidrivers"),
            "csidrivers must be in storage.k8s.io/v1; got: {names:?}"
        );
        assert!(
            names.contains(&"csinodes"),
            "csinodes must be in storage.k8s.io/v1; got: {names:?}"
        );
    }

    // static_group_resources must return Some for apps/v1 — this is one of the most
    // commonly probed groups and must always be present without a store lookup.
    #[test]
    fn static_group_resources_apps_v1_returns_some() {
        let result = static_group_resources("apps", "v1");
        assert!(result.is_some(), "apps/v1 must return Some");
        let val = result.unwrap();
        assert_eq!(val["groupVersion"], "apps/v1");
    }

    // static_group_resources must return Some for rbac.authorization.k8s.io/v1 —
    // RBAC resources are critical for cluster bootstrap and must be statically served.
    #[test]
    fn static_group_resources_rbac_v1_returns_some() {
        let result = static_group_resources("rbac.authorization.k8s.io", "v1");
        assert!(
            result.is_some(),
            "rbac.authorization.k8s.io/v1 must return Some"
        );
        let val = result.unwrap();
        assert_eq!(val["groupVersion"], "rbac.authorization.k8s.io/v1");
    }

    // static_group_resources must return None for unknown groups — callers fall through
    // to dynamic CRD lookup only when the static match returns None.
    #[test]
    fn static_group_resources_unknown_returns_none() {
        assert!(
            static_group_resources("unknown.group.io", "v1").is_none(),
            "unknown group must return None"
        );
        assert!(
            static_group_resources("apps", "v2").is_none(),
            "known group with unknown version must return None"
        );
    }

    // GET /version must return a JSON object containing "gitVersion" and "major".
    #[tokio::test]
    async fn version_returns_server_version() {
        let Json(val) = version().await;
        assert!(
            val.get("gitVersion").and_then(|v| v.as_str()).is_some(),
            "gitVersion must be present in /version response"
        );
        assert!(
            val.get("major").and_then(|v| v.as_str()).is_some(),
            "major must be present in /version response"
        );
    }

    // node.k8s.io/v1 resource list must include runtimeclasses so kubelet can
    // query the RuntimeClass API without errors.
    #[tokio::test]
    async fn node_v1_resources_list() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("node.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"runtimeclasses"),
            "runtimeclasses must be in node.k8s.io/v1; got: {names:?}"
        );
    }

    // apps/v1 resource list must include daemonsets — DaemonSet is a first-class workload
    // that the scheduler and node lifecycle controller depend on.
    #[tokio::test]
    async fn apps_v1_resources_includes_daemonsets() {
        let state = make_state();
        let resp =
            api_group_resources(State(state), Path(("apps".to_string(), "v1".to_string()))).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"daemonsets"),
            "daemonsets must be in apps/v1 — DaemonSet is required for system workloads like CNI and kube-proxy; got: {names:?}"
        );
    }

    // batch/v1 must appear in /apis so kubectl can discover Job and CronJob resources.
    // Without this, `kubectl get jobs` returns "the server doesn't have a resource type jobs".
    #[tokio::test]
    async fn batch_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"batch"),
            "batch must appear in /apis — Job and CronJob require it; got: {names:?}"
        );
    }

    // batch/v1 resource list must include jobs and cronjobs.
    #[tokio::test]
    async fn batch_v1_resources_list() {
        let state = make_state();
        let resp =
            api_group_resources(State(state), Path(("batch".to_string(), "v1".to_string()))).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"jobs"),
            "jobs must be in batch/v1; got: {names:?}"
        );
        assert!(
            names.contains(&"cronjobs"),
            "cronjobs must be in batch/v1; got: {names:?}"
        );
    }

    // autoscaling must appear in /apis with both v1 and v2 advertised.
    // HPA controllers probe the autoscaling group to determine which API version to use.
    #[tokio::test]
    async fn autoscaling_group_appears_in_api_group_list_with_both_versions() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let group = list
            .groups
            .iter()
            .find(|g| g.name == "autoscaling")
            .expect("autoscaling must appear in /apis — HPA requires it");

        let version_names: Vec<&str> = group.versions.iter().map(|v| v.version.as_str()).collect();
        assert!(
            version_names.contains(&"v1"),
            "autoscaling must list v1; got: {version_names:?}"
        );
        assert!(
            version_names.contains(&"v2"),
            "autoscaling must list v2 — HPA v2 is the preferred version since Kubernetes 1.23; got: {version_names:?}"
        );
        assert_eq!(
            group.preferred_version.version, "v2",
            "autoscaling preferredVersion must be v2"
        );
    }

    // autoscaling/v1 resource list must include HPA.
    #[tokio::test]
    async fn autoscaling_v1_resources_list() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("autoscaling".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"horizontalpodautoscalers"),
            "horizontalpodautoscalers must be in autoscaling/v1; got: {names:?}"
        );
    }

    // networking.k8s.io/v1 must include ingressclasses (cluster-scoped) alongside ingresses
    // and networkpolicies. Without IngressClass, ingress controllers cannot register themselves.
    #[tokio::test]
    async fn networking_v1_resources_includes_ingressclass() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("networking.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"ingressclasses"),
            "ingressclasses must be in networking.k8s.io/v1 — ingress controllers require it; got: {names:?}"
        );
        assert!(
            names.contains(&"ingresses"),
            "ingresses must be in networking.k8s.io/v1; got: {names:?}"
        );
        assert!(
            names.contains(&"networkpolicies"),
            "networkpolicies must be in networking.k8s.io/v1; got: {names:?}"
        );
    }

    // apps/v1 discovery must surface shortNames for replicasets and deployments so that
    // `kubectl get rs` and `kubectl get deploy` resolve without "server doesn't have a resource type".
    #[tokio::test]
    async fn apps_v1_resources_have_short_names() {
        let state = make_state();
        let resp =
            api_group_resources(State(state), Path(("apps".to_string(), "v1".to_string()))).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();

        let rs = resources
            .iter()
            .find(|r| r["name"] == "replicasets")
            .expect("replicasets must be in apps/v1");
        assert_eq!(
            rs["shortNames"][0], "rs",
            "replicasets must have shortName 'rs' so kubectl get rs works"
        );

        let deploy = resources
            .iter()
            .find(|r| r["name"] == "deployments")
            .expect("deployments must be in apps/v1");
        assert_eq!(
            deploy["shortNames"][0], "deploy",
            "deployments must have shortName 'deploy' so kubectl get deploy works"
        );
    }

    // /openapi/v2 must return a Swagger 2.0 document — Argo CD and other tools call this
    // on startup and hard-fail if the endpoint is missing or returns malformed JSON.
    #[tokio::test]
    async fn openapi_v2_returns_swagger_2_0() {
        let state = make_state();
        let resp = openapi_v2(State(state), axum::http::HeaderMap::new()).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            val.get("swagger").and_then(|v| v.as_str()),
            Some("2.0"),
            "/openapi/v2 must contain \"swagger\": \"2.0\""
        );
        assert!(
            val.get("paths").is_some(),
            "/openapi/v2 must contain a \"paths\" key"
        );
    }

    // /openapi/v3 must return an object with a "paths" key — kubectl 1.28+ calls this
    // first; an empty paths map causes it to fall back to /openapi/v2 gracefully.
    #[tokio::test]
    async fn openapi_v3_returns_paths_key() {
        let state = make_state();
        let resp = openapi_v3(State(state)).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            val.get("paths").is_some(),
            "/openapi/v3 must contain a \"paths\" key so kubectl can fall back to /openapi/v2"
        );
    }

    // HTTP-level: GET /openapi/v2 must return 200 with Swagger 2.0 JSON.
    // This verifies the route is wired — the unit test above does not catch
    // a route being removed from the router.
    #[tokio::test]
    async fn openapi_v2_route_returns_200_with_swagger_field() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v2", get(openapi_v2))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v2")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "GET /openapi/v2 must return 200 — kubectl fails with \
             'failed to download openapi: unknown' if the route is absent or returns an error"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("/openapi/v2 body must be valid JSON");
        assert_eq!(
            val.get("swagger").and_then(|v| v.as_str()),
            Some("2.0"),
            "/openapi/v2 JSON must contain \"swagger\": \"2.0\" — kubectl \
             rejects the schema if the swagger version field is absent"
        );
        assert!(
            val.get("paths").is_some(),
            "/openapi/v2 JSON must contain a \"paths\" key"
        );
    }

    // GET /openapi/v2 must return Content-Type: application/json.
    //
    // kubectl performs client-side validation by fetching /openapi/v2 and checking the
    // Content-Type header. If the server returns a different Content-Type (or none at all),
    // kubectl fails with:
    //   "error validating data: the server was unable to respond with a content type
    //    that the client supports"
    // This blocks `kubectl apply` and `kubectl create` in the [sig-cli] and [sig-api-machinery]
    // conformance tests.
    //
    // This test fails on revert: if openapi_v2 were changed to return a plain Response with
    // no Content-Type header, this assertion would fail.
    #[tokio::test]
    async fn openapi_v2_returns_content_type_application_json() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v2", get(openapi_v2))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v2")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("application/json"),
            "GET /openapi/v2 must return Content-Type: application/json — kubectl \
             client-side validation fails with 'unable to respond with a content type \
             that the client supports' if this header is absent or wrong; got: '{ct}'"
        );
    }

    // HTTP-level: GET /openapi/v3 must return 200 with a "paths" key.
    // This verifies the route is wired — kubectl 1.28+ calls /openapi/v3
    // first and falls back to /openapi/v2 only if it gets a valid response.
    #[tokio::test]
    async fn openapi_v3_route_returns_200_with_paths_key() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v3", get(openapi_v3))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v3")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "GET /openapi/v3 must return 200 — kubectl 1.28+ probes this \
             before falling back to /openapi/v2"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("/openapi/v3 body must be valid JSON");
        assert!(
            val.get("paths").is_some(),
            "/openapi/v3 JSON must contain a \"paths\" key so kubectl falls back to /openapi/v2 \
             rather than erroring out"
        );
    }

    // GET /openapi/v3 must return Content-Type: application/json.
    //
    // kubectl 1.28+ fetches /openapi/v3 before /openapi/v2 to get the schema index.
    // If the Content-Type is missing or wrong, kubectl reports "the server was unable
    // to respond with a content type that the client supports" and aborts validation,
    // causing `kubectl create` and `kubectl apply` to fail with a validation error.
    //
    // This test fails on revert: if openapi_v3 is changed back to returning
    // Json<serde_json::Value> without an explicit Content-Type header and the header
    // is somehow stripped, this assertion catches it.
    #[tokio::test]
    async fn openapi_v3_returns_content_type_application_json() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v3", get(openapi_v3))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v3")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("application/json"),
            "GET /openapi/v3 must return Content-Type: application/json — kubectl \
             client-side validation fails with 'unable to respond with a content type \
             that the client supports' if this header is absent or wrong; got: '{ct}'"
        );
    }

    // scheduling.k8s.io must appear in /apis — kube-scheduler reads PriorityClasses
    // at startup to assign pod scheduling priority. Without this group, scheduling
    // conformance tests fail with "resource not found".
    #[tokio::test]
    async fn scheduling_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"scheduling.k8s.io"),
            "scheduling.k8s.io must appear in /apis — kube-scheduler probes it for PriorityClasses; got: {names:?}"
        );
    }

    // scheduling.k8s.io/v1 must include priorityclasses — kube-scheduler reads these
    // to assign pod scheduling priority; missing this causes scheduling failures.
    #[tokio::test]
    async fn scheduling_v1_resources_includes_priorityclasses() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("scheduling.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"priorityclasses"),
            "priorityclasses must be in scheduling.k8s.io/v1 — kube-scheduler requires it; got: {names:?}"
        );
    }

    // events.k8s.io must appear in /apis — conformance tests use events.k8s.io/v1 Event
    // (the stable replacement for core/v1 Event). Without this group, conformance tests
    // fail with "resource not found".
    #[tokio::test]
    async fn events_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"events.k8s.io"),
            "events.k8s.io must appear in /apis — conformance tests use events.k8s.io/v1; got: {names:?}"
        );
    }

    // events.k8s.io/v1 must include events — this is the GA Event type since k8s 1.21;
    // conformance tests create and watch events via this API group.
    #[tokio::test]
    async fn events_v1_resources_includes_events() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("events.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"events"),
            "events must be in events.k8s.io/v1 — conformance tests require it; got: {names:?}"
        );
    }

    // storage.k8s.io/v1 must include volumeattributesclasses — GA since k8s 1.31;
    // sonobuoy conformance tests fail with "resource not found" without it.
    #[tokio::test]
    async fn storage_v1_resources_includes_volumeattributesclasses() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("storage.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"volumeattributesclasses"),
            "volumeattributesclasses must be in storage.k8s.io/v1 — GA since k8s 1.31; got: {names:?}"
        );
    }

    // storage.k8s.io/v1 must include csistoragecapacities — the conformance test
    // storage/csistoragecapacity.go:128 checks discovery before issuing API calls.
    #[tokio::test]
    async fn storage_v1_resources_includes_csistoragecapacities() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("storage.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"csistoragecapacities"),
            "csistoragecapacities must be in storage.k8s.io/v1 — \
             without it the conformance test cannot discover and test the resource; got: {names:?}"
        );
        let csc = resources
            .iter()
            .find(|r| r["name"] == "csistoragecapacities")
            .unwrap();
        assert_eq!(
            csc["namespaced"], true,
            "csistoragecapacities must be marked namespaced — it is a per-namespace resource"
        );
    }

    // networking.k8s.io/v1 must include servicecidrs and ipaddresses — GA since k8s 1.31;
    // sonobuoy conformance tests fail with "resource not found" without them.
    #[tokio::test]
    async fn networking_v1_resources_includes_servicecidrs_and_ipaddresses() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("networking.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"servicecidrs"),
            "servicecidrs must be in networking.k8s.io/v1 — GA since k8s 1.31; got: {names:?}"
        );
        assert!(
            names.contains(&"ipaddresses"),
            "ipaddresses must be in networking.k8s.io/v1 — GA since k8s 1.31; got: {names:?}"
        );
    }

    // admissionregistration.k8s.io/v1 must include validatingadmissionpolicies and
    // mutatingadmissionpolicies — GA since k8s 1.30/1.32 respectively; conformance
    // tests fail with "resource not found" without them.
    // The /status subresource must also be listed — the ValidatingAdmissionPolicy
    // conformance test explicitly checks for validatingadmissionpolicies/status in the
    // resource list and fails with "expected validatingadmissionpolicies/status, got [...]"
    // if it is absent.
    #[tokio::test]
    async fn admissionregistration_v1_resources_includes_admission_policies() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("admissionregistration.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"validatingadmissionpolicies"),
            "validatingadmissionpolicies must be in admissionregistration.k8s.io/v1 — \
             CEL-based admission GA since k8s 1.30; got: {names:?}"
        );
        assert!(
            names.contains(&"validatingadmissionpolicies/status"),
            "validatingadmissionpolicies/status must be in admissionregistration.k8s.io/v1 — \
             the ValidatingAdmissionPolicy conformance test checks for this subresource \
             in the resource list and fails with 'expected validatingadmissionpolicies/status' \
             if it is absent; got: {names:?}"
        );
        assert!(
            names.contains(&"mutatingadmissionpolicies"),
            "mutatingadmissionpolicies must be in admissionregistration.k8s.io/v1 — \
             GA since k8s 1.32; got: {names:?}"
        );
    }

    // A CRD whose spec.names.shortNames is non-empty must surface those short names in the
    // group-version discovery response so that `kubectl get <shortname>` resolves for CRDs.
    #[tokio::test]
    async fn crd_short_names_forwarded_in_group_version_discovery() {
        let state = make_state();

        let body = Bytes::from(
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
                        "shortNames": ["wdg"]
                    },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v1", "served": true, "storage": true }
                    ]
                }
            })
            .to_string(),
        );
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create must succeed"
        );

        let resp = api_group_resources(
            State(state),
            Path(("example.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let widget = resources
            .iter()
            .find(|r| r["name"] == "widgets")
            .expect("widgets resource must appear in example.io/v1 discovery");
        assert_eq!(
            widget["shortNames"][0], "wdg",
            "CRD shortNames must be forwarded into the APIResourceList entry"
        );
    }

    // authentication.k8s.io/v1 must include tokenreviews — KCM's namespace controller calls
    // ServerPreferredNamespacedResources on every sync; client-go treats a group with zero
    // resources as an error, which blocks ALL namespace deletion. The tokenreviews endpoint
    // already exists (POST .../tokenreviews) and must be reflected in discovery.
    #[tokio::test]
    async fn authn_v1_resources_includes_tokenreviews() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("authentication.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        assert!(
            !resources.is_empty(),
            "authentication.k8s.io/v1 must have at least one resource — an empty list causes \
             client-go discovery errors and blocks namespace deletion via KCM"
        );
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"tokenreviews"),
            "tokenreviews must be in authentication.k8s.io/v1 — \
             the endpoint already exists and must be discoverable; got: {names:?}"
        );
    }

    // resource.k8s.io must appear in /apis — Dynamic Resource Allocation (DRA) uses this
    // group for ResourceClaim, ResourceClaimTemplate, ResourceSlice, and DeviceClass (GA since k8s 1.32).
    // kubectl and admission webhooks depend on this group being discoverable; without it,
    // `kubectl get resourceclaims` returns "the server doesn't have a resource type".
    #[tokio::test]
    async fn resource_group_appears_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"resource.k8s.io"),
            "resource.k8s.io must appear in /apis — DRA requires ResourceClaim, \
             ResourceClaimTemplate, ResourceSlice, and DeviceClass to be discoverable; got: {names:?}"
        );
    }

    // resource.k8s.io/v1 must include all four DRA resource types — ResourceClaim,
    // ResourceClaimTemplate, ResourceSlice, and DeviceClass are the core DRA objects.
    // DRA is GA since k8s 1.32; missing any of them causes `kubectl get resourceclaims`
    // or scheduler DRA plugins to fail at startup with "resource not found".
    #[tokio::test]
    async fn resource_v1_resources_list() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("resource.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /apis/resource.k8s.io/v1 must return 200"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let resources = val["resources"].as_array().unwrap();
        let names: Vec<&str> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"resourceclaims"),
            "resourceclaims must be in resource.k8s.io/v1 — core DRA type (GA since k8s 1.32); got: {names:?}"
        );
        assert!(
            names.contains(&"resourceclaimtemplates"),
            "resourceclaimtemplates must be in resource.k8s.io/v1 — core DRA type (GA since k8s 1.32); got: {names:?}"
        );
        assert!(
            names.contains(&"resourceslices"),
            "resourceslices must be in resource.k8s.io/v1 — DRA node plugin reporting (GA since k8s 1.32); got: {names:?}"
        );
        assert!(
            names.contains(&"deviceclasses"),
            "deviceclasses must be in resource.k8s.io/v1 — DRA device class (GA since k8s 1.32); got: {names:?}"
        );
    }

    // GET /apis/flowcontrol.apiserver.k8s.io must return 200 with kind=APIGroup and the group
    // name. Without the /apis/{group} route, the API priority and fairness conformance test
    // fails: it GETs the group endpoint after discovering it in /apis, and 404 causes the test
    // to abort with "expected flowcontrol API group".
    #[tokio::test]
    async fn flowcontrol_api_group_endpoint_returns_200() {
        let state = make_state();
        let resp = api_group(
            State(state),
            Path("flowcontrol.apiserver.k8s.io".to_string()),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /apis/flowcontrol.apiserver.k8s.io must return 200 — \
             the conformance test GETs this endpoint after discovering the group in /apis; \
             404 causes the test to abort"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            val["kind"], "APIGroup",
            "response must have kind=APIGroup — clients use this to determine preferred version"
        );
        assert_eq!(
            val["name"], "flowcontrol.apiserver.k8s.io",
            "APIGroup name must match the requested group"
        );
        assert!(
            val["preferredVersion"]["version"].as_str().is_some(),
            "preferredVersion.version must be present"
        );
    }

    // GET /apis/<unknown-group> must return 404 — clients that request a non-existent group
    // must get a proper NotFound response, not a panic or 200 with empty body.
    #[tokio::test]
    async fn unknown_api_group_endpoint_returns_404() {
        let state = make_state();
        let resp = api_group(State(state), Path("no-such-group.example.io".to_string())).await;

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "GET /apis/<unknown-group> must return 404 — \
             the group does not exist and the client must get a clear error"
        );
    }

    // flowcontrol.apiserver.k8s.io must appear in /apis — the API priority and fairness
    // conformance test requires the group to be discoverable. Without this entry, kubectl
    // and client-go cannot find FlowSchema or PriorityLevelConfiguration resources.
    #[tokio::test]
    async fn flowcontrol_group_present_in_api_group_list() {
        let state = make_state();
        let list = api_group_list_inner(&state).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        assert!(
            names.contains(&"flowcontrol.apiserver.k8s.io"),
            "flowcontrol.apiserver.k8s.io must appear in /apis — the API priority and \
             fairness conformance test requires this group; got: {names:?}"
        );
    }

    // flowcontrol.apiserver.k8s.io/v1 must return 200 with flowschemas and
    // prioritylevelconfigurations — client-go lists these resources during discovery.
    // An empty or missing resource list causes namespace deletion to stall.
    #[tokio::test]
    async fn flowcontrol_v1_resources_returns_200_with_resources() {
        let state = make_state();
        let resp = api_group_resources(
            State(state),
            Path(("flowcontrol.apiserver.k8s.io".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /apis/flowcontrol.apiserver.k8s.io/v1 must return 200 — \
             the group is now served with flowschemas and prioritylevelconfigurations"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let empty = vec![];
        let resource_names: Vec<&str> = val["resources"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .filter_map(|r| r["name"].as_str())
            .collect();
        assert!(
            resource_names.contains(&"flowschemas"),
            "flowcontrol.apiserver.k8s.io/v1 must include flowschemas — \
             API priority and fairness conformance test creates FlowSchema objects; got: {resource_names:?}"
        );
        assert!(
            resource_names.contains(&"prioritylevelconfigurations"),
            "flowcontrol.apiserver.k8s.io/v1 must include prioritylevelconfigurations — \
             API priority and fairness conformance test creates PriorityLevelConfiguration objects; got: {resource_names:?}"
        );
    }

    // GET /apis must always return a plain APIGroupList — /apis is the legacy discovery
    // endpoint used by kubectl and all Kubernetes clients. Aggregated discovery is only
    // served from /discovery/v2, which clients probe separately. Returning an
    // APIGroupDiscoveryList from /apis breaks clients that expect APIGroupList.
    #[tokio::test]
    async fn apis_returns_api_group_list() {
        let state = make_state();
        let resp = api_group_list(State(state), axum::http::HeaderMap::new()).await;

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            val["kind"], "APIGroupList",
            "GET /apis without aggregated Accept must return kind=APIGroupList — all kubectl versions expect this format"
        );
        assert!(
            val["groups"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "APIGroupList must contain at least one group"
        );
    }

    // GET /apis with the k8s aggregated discovery Accept header must return APIGroupDiscoveryList.
    //
    // All 4 AggregatedDiscovery conformance tests hit /apis with this Accept header.
    // client-go sends both v=v2 and v=v2beta1; the server must respond with the first it supports.
    // The response Content-Type must match the requested version — client-go uses that header
    // (not the body's apiVersion field) to decide whether the server understood the request.
    // If /apis ignores the Accept header and returns APIGroupList, the conformance tests fail
    // with "Expected admissionregistration.k8s.io/v1 ... to be present".
    //
    // IMPORTANT: /api (core) must also negotiate — client-go's GroupsAndMaybeResources() clears
    // resources to nil if one endpoint returns aggregated and the other doesn't.
    #[tokio::test]
    async fn apis_with_aggregated_accept_returns_api_group_discovery_list_v2() {
        let state = make_state();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList, application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList, application/json",
            ),
        );
        let resp = api_group_list(State(state), headers).await;

        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            ct, "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList",
            "/apis must return Content-Type matching the requested v=v2 — \
             client-go checks this header to activate the aggregated discovery parser"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "APIGroupDiscoveryList");
        assert_eq!(val["apiVersion"], "apidiscovery.k8s.io/v2");

        let items = val["items"].as_array().expect("items must be array");
        assert!(!items.is_empty());
        assert!(
            items.iter().any(|i| i["metadata"]["name"] == "admissionregistration.k8s.io"),
            "admissionregistration.k8s.io must appear — conformance tests assert validatingwebhookconfigurations"
        );
    }

    // GET /api with the aggregated discovery Accept must return only the core group item.
    // client-go's GroupsAndMaybeResources() calls both /api and /apis; if one returns
    // aggregated and the other doesn't, resources is set to nil and all `kubectl apply`
    // commands fail with "no matches for kind".
    #[tokio::test]
    async fn api_with_aggregated_accept_returns_core_only_discovery_list() {
        let state = make_state();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            axum::http::HeaderValue::from_static(
                "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList, application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList, application/json",
            ),
        );
        let resp = api_versions(State(state), headers).await;

        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            ct, "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList",
            "/api must return Content-Type matching the requested v=v2"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(val["kind"], "APIGroupDiscoveryList");

        let items = val["items"].as_array().expect("items must be array");
        assert_eq!(
            items.len(),
            1,
            "only the core group must be returned from /api"
        );
        assert_eq!(
            items[0]["metadata"]["name"], "",
            "core group has empty name"
        );
        // Core group must include pods
        let resources = items[0]["versions"][0]["resources"].as_array().unwrap();
        assert!(
            resources.iter().any(|r| r["resource"] == "pods"),
            "core/v1 must include pods"
        );
    }

    // GET /discovery/v2 must return an APIGroupDiscoveryList with correct Content-Type,
    // core group resources, and apps/v1 resources. Conformance tests use this dedicated
    // endpoint rather than Accept-header negotiation on /apis.
    #[tokio::test]
    async fn discovery_v2_returns_aggregated_discovery_list_with_correct_content_type() {
        let app = Router::new()
            .route(
                "/discovery/v2",
                get(aggregated_discovery_v2::<u7s_store::SqliteStore>),
            )
            .with_state(make_state());

        let req = Request::builder()
            .method("GET")
            .uri("/discovery/v2")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            ct, "application/json;g=apidiscovery.k8s.io;v=v2beta1",
            "/discovery/v2 must carry Content-Type 'application/json;g=apidiscovery.k8s.io;v=v2beta1' \
             so conformance tests recognise it as aggregated discovery"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(val["kind"], "APIGroupDiscoveryList");
        assert_eq!(val["apiVersion"], "apidiscovery.k8s.io/v2beta1");
        assert!(val["metadata"]["resourceVersion"].as_str().is_some());

        let items = val["items"].as_array().expect("items must be an array");

        let core = items.iter().find(|i| i["metadata"]["name"] == "");
        assert!(core.is_some(), "core group must appear in /discovery/v2");
        let core_resources = core.unwrap()["versions"][0]["resources"]
            .as_array()
            .unwrap();
        let core_names: Vec<&str> = core_resources
            .iter()
            .filter_map(|r| r["resource"].as_str())
            .collect();
        assert!(
            core_names.contains(&"pods"),
            "core/v1 must include pods; got: {core_names:?}"
        );

        let apps = items.iter().find(|i| i["metadata"]["name"] == "apps");
        assert!(apps.is_some(), "apps group must appear in /discovery/v2");
        let apps_resources = apps.unwrap()["versions"][0]["resources"]
            .as_array()
            .unwrap();
        let apps_names: Vec<&str> = apps_resources
            .iter()
            .filter_map(|r| r["resource"].as_str())
            .collect();
        assert!(
            apps_names.contains(&"deployments"),
            "apps/v1 must include deployments; got: {apps_names:?}"
        );
    }

    // GET /discovery/v2 must always return an APIGroupDiscoveryList regardless of Accept header.
    // This is the dedicated aggregated discovery endpoint used by conformance tests.
    #[tokio::test]
    async fn discovery_v2_route_returns_api_group_discovery_list() {
        let app = Router::new()
            .route(
                "/discovery/v2",
                get(aggregated_discovery_v2::<u7s_store::SqliteStore>),
            )
            .with_state(make_state());

        let req = Request::builder()
            .method("GET")
            .uri("/discovery/v2")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "GET /discovery/v2 must return 200 — AggregatedDiscovery conformance tests hit this endpoint"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("/discovery/v2 body must be valid JSON");
        assert_eq!(
            val["kind"], "APIGroupDiscoveryList",
            "/discovery/v2 must return kind=APIGroupDiscoveryList"
        );
        assert!(
            val["items"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "/discovery/v2 must return a non-empty items array"
        );
    }

    // After creating a CRD, GET /openapi/v2 must include a definition entry with the
    // reversed-domain key for that CRD's kind. CustomResourcePublishOpenAPI conformance
    // test polls /openapi/v2 waiting for this entry to appear; if openapi_v2 is static
    // (no store lookup) the test times out after 60 s.
    #[tokio::test]
    async fn openapi_v2_contains_crd_definition_after_crd_create() {
        let state = make_state();

        let body = crd_bytes("example.io", "foos", "foo", "Foo", "Namespaced", "v1");
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create_crd must succeed"
        );

        let resp = openapi_v2(State(state), axum::http::HeaderMap::new()).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let defs = doc["definitions"]
            .as_object()
            .expect("definitions must be a JSON object");

        // Reversed-domain key: example.io/v1/Foo → io.example.v1.Foo
        let expected_key = "io.example.v1.Foo";
        assert!(
            defs.contains_key(expected_key),
            "definitions must contain '{expected_key}' after CRD create — \
             CustomResourcePublishOpenAPI conformance test polls /openapi/v2 for this key; \
             got keys: {:?}",
            defs.keys().collect::<Vec<_>>()
        );

        let gvk = &defs[expected_key]["x-kubernetes-group-version-kind"][0];
        assert_eq!(gvk["group"], "example.io");
        assert_eq!(gvk["version"], "v1");
        assert_eq!(gvk["kind"], "Foo");
    }

    // /openapi/v2 definitions must include the CRD's openAPIV3Schema properties so that
    // kubectl apply can validate CRD instances against their schema. Without property
    // translation, tools like Argo CD and the CustomResourcePublishOpenAPI conformance
    // test see only "type: object" with no fields and cannot validate or generate clients.
    #[tokio::test]
    async fn openapi_v2_crd_definition_includes_schema_properties() {
        let state = make_state();

        let body = crd_bytes_with_schema("stable.example.com", "crontabs", "CronTab", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create_crd must succeed");

        let resp = openapi_v2(State(state), axum::http::HeaderMap::new()).await;
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let defs = doc["definitions"]
            .as_object()
            .expect("definitions must be present");

        // com.example.stable.v1.CronTab — reversed group + version + kind
        let key = "com.example.stable.v1.CronTab";
        let def = defs.get(key).unwrap_or_else(|| {
            panic!(
                "definition '{key}' must exist; got: {:?}",
                defs.keys().collect::<Vec<_>>()
            )
        });

        assert_eq!(
            def["properties"]["spec"]["type"].as_str(),
            Some("object"),
            "spec property must be type=object — without schema translation, \
             kubectl apply cannot validate CRD instances because the definition has no fields"
        );
        assert_eq!(
            def["properties"]["spec"]["properties"]["replicas"]["type"].as_str(),
            Some("integer"),
            "spec.replicas must be type=integer — CRD schema properties must survive \
             the openAPIV3Schema→Swagger 2.0 translation for field-level validation to work"
        );
    }

    // /openapi/v2 must omit definitions for CRD versions that are not served.
    // The CustomResourcePublishOpenAPI conformance test flips a version's
    // `served` to false and polls /openapi/v2 waiting for that version's
    // definition to disappear; a handler that includes every version
    // unconditionally never satisfies that wait and the test times out.
    #[tokio::test]
    async fn openapi_v2_omits_definition_for_unserved_crd_version() {
        let state = make_state();

        let body = Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "multis.example.io" },
                "spec": {
                    "group": "example.io",
                    "names": { "plural": "multis", "singular": "multi", "kind": "Multi" },
                    "scope": "Namespaced",
                    "versions": [
                        { "name": "v5", "served": true, "storage": true },
                        { "name": "v6alpha1", "served": false, "storage": false }
                    ]
                }
            })
            .to_string(),
        );
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create_crd must succeed");

        let resp = openapi_v2(State(state), axum::http::HeaderMap::new()).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let defs = doc["definitions"].as_object().expect("definitions object");

        assert!(
            defs.contains_key("io.example.v5.Multi"),
            "served version v5 must still have a definition; got keys: {:?}",
            defs.keys().collect::<Vec<_>>()
        );
        assert!(
            !defs.contains_key("io.example.v6alpha1.Multi"),
            "unserved version v6alpha1 must NOT have a definition — conformance test \
             polls for its removal once served is set to false; got keys: {:?}",
            defs.keys().collect::<Vec<_>>()
        );
    }

    // create_crd must stamp status.conditions Established=True and NamesAccepted=True
    // so that controllers (e.g. kube-controller-manager CRD controller) do not wait
    // for a separate status update that never comes in u7s's single-process model.
    #[tokio::test]
    async fn create_crd_stamps_established_and_names_accepted_conditions() {
        use u7s_store::Store;

        let state = make_state();

        let body = crd_bytes("example.io", "bars", "bar", "Bar", "Cluster", "v1alpha1");
        assert!(
            create_crd(
                State(state.clone()),
                test_user(),
                axum::http::HeaderMap::new(),
                body
            )
            .await
            .is_ok(),
            "create_crd must succeed"
        );

        // Read back the stored CRD and verify status.conditions.
        let stored = state
            .store
            .get("/registry/apiextensions.k8s.io/customresourcedefinitions/bars.example.io")
            .await
            .expect("store get must not fail")
            .expect("stored CRD must exist");
        let val: serde_json::Value =
            serde_json::from_slice(&stored.value).expect("stored CRD must be valid JSON");

        let conditions = val["status"]["conditions"]
            .as_array()
            .expect("status.conditions must be present after create_crd");

        let established = conditions
            .iter()
            .find(|c| c["type"] == "Established")
            .expect("Established condition must be present — controllers wait for it");
        assert_eq!(
            established["status"], "True",
            "Established condition must be True so controllers see the CRD as ready"
        );

        let accepted = conditions
            .iter()
            .find(|c| c["type"] == "NamesAccepted")
            .expect("NamesAccepted condition must be present — controllers wait for it");
        assert_eq!(
            accepted["status"], "True",
            "NamesAccepted condition must be True so controllers see the CRD as ready"
        );
    }

    // GET /openapi/v2 with a proto-only Accept (client may send the deprecated @v1.0 form)
    // must return 200 with Content-Type using the non-deprecated dot form
    // (application/com.github.proto-openapi.spec.v2.v1.0+protobuf) — upstream kube-openapi
    // always responds with the dot form regardless of which Accept variant the client sent.
    // The @ form fails Go's mime.ParseMediaType (non-RFC-2045 token), causing kubectl
    // create/replace --validate to error with "mime: unexpected content after media subtype".
    //
    // This test fails on revert: reverting to the @ form makes the dot-form assertion fail
    // and kubectl validation breaks for all resources.
    #[tokio::test]
    async fn openapi_v2_proto_only_accept_returns_200_proto() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v2", get(openapi_v2))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v2")
            .header(
                "Accept",
                "application/com.github.proto-openapi.spec.v2@v1.0+protobuf",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "proto-only Accept on /openapi/v2 must return 200 — kubectl needs a valid \
             response to proceed with resource validation"
        );

        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("spec.v2.v1.0+protobuf"),
            "Content-Type must use the non-deprecated dot form \
             (spec.v2.v1.0+protobuf, not spec.v2@v1.0+protobuf); the @ form breaks \
             kubectl's mime.ParseMediaType with 'mime: unexpected content after media \
             subtype', causing kubectl create/replace --validate to fail; got: '{ct}'"
        );
        assert!(
            !ct.contains("@"),
            "Content-Type must NOT contain the deprecated @ form — Go's \
             mime.ParseMediaType rejects it with 'mime: unexpected content after media \
             subtype', breaking kubectl validation; got: '{ct}'"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // The body must NOT be JSON — if it were, gnostic would produce
        // "proto: cannot parse invalid wire-format data".
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body).is_err(),
            "proto-only Accept must not return JSON in the body; kubectl gnostic-decodes \
             it unconditionally and JSON bytes are invalid wire-format proto"
        );
        // The body must start with a valid gnostic Document proto field tag.
        // gnostic Document field 1 = swagger (string), wire type 2 (LEN) = 0x0a.
        assert_eq!(
            body.first().copied(),
            Some(0x0a),
            "gnostic Document must start with field-1 LEN tag (0x0a = field 1, wire type 2); \
             any other first byte means the proto is malformed and kubectl will reject it"
        );
    }

    // GET /openapi/v2 with proto + json in Accept must return 200 with JSON —
    // kubectl always sends both; the server must serve JSON so that schema
    // validation works and kubectl apply does not error.
    #[tokio::test]
    async fn openapi_v2_proto_and_json_accept_returns_200_json() {
        let state = make_state();
        let app = Router::new()
            .route("/openapi/v2", get(openapi_v2))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/openapi/v2")
            .header(
                "Accept",
                "application/com.github.proto-openapi.spec.v2@v1.0+protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "proto+json Accept on /openapi/v2 must return 200 — \
             kubectl sends both types and must receive a JSON schema to validate resources"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value =
            serde_json::from_slice(&body).expect("body must be valid JSON");
        assert_eq!(
            val.get("swagger").and_then(|v| v.as_str()),
            Some("2.0"),
            "response must be a Swagger 2.0 document"
        );
    }

    fn crd_bytes_with_schema(group: &str, plural: &str, kind: &str, version: &str) -> Bytes {
        Bytes::from(
            serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": format!("{plural}.{group}") },
                "spec": {
                    "group": group,
                    "names": { "plural": plural, "singular": plural, "kind": kind },
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
                                        "properties": {
                                            "replicas": { "type": "integer" }
                                        }
                                    }
                                }
                            }
                        }
                    }]
                }
            })
            .to_string(),
        )
    }

    // After a CRD is installed, /openapi/v3 must list its group/version in paths.
    // client-go's openapi3 package calls this index first; an absent entry means
    // the CRD type-checker never loads the schema and the conformance test hangs.
    #[tokio::test]
    async fn openapi_v3_paths_contains_crd_group() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3(State(state)).await;
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let paths = val["paths"].as_object().expect("paths must be an object");
        assert!(
            paths.contains_key("apis/probe.example.com/v1"),
            "apis/probe.example.com/v1 must appear in /openapi/v3 paths after CRD install — \
             client-go uses this index to discover per-group OpenAPI v3 schemas; got: {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }

    // /openapi/v3/apis/<group>/<version> must return an OpenAPI v3 document containing
    // the CRD's schema under components.schemas.<Kind>.  Without this the CEL type-checker
    // cannot validate CR fields and the conformance test "should type check a CRD" hangs.
    #[tokio::test]
    async fn openapi_v3_group_returns_crd_schema() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3_group(
            State(state),
            Path(("probe.example.com".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/openapi/v3/apis/probe.example.com/v1 must return 200 after CRD install"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            val["openapi"].as_str(),
            Some("3.0.0"),
            "response must identify as OpenAPI 3.0.0"
        );

        let replicas_type = val["components"]["schemas"]["Widget"]["properties"]["spec"]
            ["properties"]["replicas"]["type"]
            .as_str();
        assert_eq!(
            replicas_type,
            Some("integer"),
            "Widget.spec.properties.replicas must be type=integer — the CEL type-checker reads \
             this to validate CRD instances; got: {replicas_type:?}"
        );
    }

    // components.schemas.<Kind> in /openapi/v3/apis/<group>/<version> must carry
    // x-kubernetes-group-version-kind. kubectl explain's OpenAPI v3 plaintext
    // template locates a resource's schema by filtering components.schemas for
    // an entry whose x-kubernetes-group-version-kind matches the resolved GVK —
    // without this extension the schema is unreachable and `kubectl explain <cr>`
    // fails with "GVK ... not found in OpenAPI schema" even though the schema
    // content itself (properties, description, etc.) is present in the document.
    #[tokio::test]
    async fn openapi_v3_group_schema_carries_group_version_kind_extension() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3_group(
            State(state),
            Path(("probe.example.com".to_string(), "v1".to_string())),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let gvk = &val["components"]["schemas"]["Widget"]["x-kubernetes-group-version-kind"][0];
        assert_eq!(
            gvk["group"], "probe.example.com",
            "Widget schema must carry its group in x-kubernetes-group-version-kind — \
             kubectl explain cannot resolve the schema without it"
        );
        assert_eq!(gvk["version"], "v1");
        assert_eq!(gvk["kind"], "Widget");
    }

    // /openapi/v3/apis/<group>/<version> must include a `paths` entry for the CRD's
    // REST resource whose operation carries x-kubernetes-group-version-kind.
    // kubectl explain's plaintext template resolves the target GVK by scanning
    // `paths` for the requested GVR *before* it ever looks at components.schemas —
    // an empty `paths` object (the prior behavior) makes `kubectl explain <cr>`
    // fail with "GVR (...) not found in OpenAPI schema" even when the schema
    // itself is fully populated in components.schemas.
    #[tokio::test]
    async fn openapi_v3_group_paths_resolves_gvk_for_resource() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3_group(
            State(state),
            Path(("probe.example.com".to_string(), "v1".to_string())),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let paths = val["paths"].as_object().expect("paths must be an object");

        let expected_path = "/apis/probe.example.com/v1/namespaces/{namespace}/widgets";
        let op = paths.get(expected_path).unwrap_or_else(|| {
            panic!(
                "paths must contain '{expected_path}' (widgets CRD is Namespaced) — \
                 kubectl explain scans this map to resolve the GVK for the requested \
                 resource before it can look up the schema; got keys: {:?}",
                paths.keys().collect::<Vec<_>>()
            )
        });
        let gvk = &op["get"]["x-kubernetes-group-version-kind"];
        assert_eq!(gvk["group"], "probe.example.com");
        assert_eq!(gvk["version"], "v1");
        assert_eq!(gvk["kind"], "Widget");
    }

    // /openapi/v3/apis/<group>/<version> must return 404 when no CRD matches.
    // client-go must receive 404 to know the group has no schema, not hang on an error.
    #[tokio::test]
    async fn openapi_v3_group_returns_404_for_unknown_group() {
        let state = make_state();

        let resp = openapi_v3_group(
            State(state),
            Path(("unknown.example.com".to_string(), "v1".to_string())),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "/openapi/v3/apis/<unknown>/<version> must return 404 — \
             client-go uses the 404 to skip schema loading for absent groups"
        );
    }

    // Real kube-apiserver always injects TypeMeta (apiVersion, kind) and
    // ObjectMeta (metadata) into a CRD's published OpenAPI schema server-side —
    // CRD authors only ever declare spec/status. Without this injection,
    // `kubectl explain <crd>` never shows apiVersion/kind, and `kubectl explain
    // <crd>.metadata` fails outright with `field "metadata" does not exist`
    // because the schema has no such property at all.
    #[tokio::test]
    async fn openapi_v3_group_schema_includes_standard_object_fields() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3_group(
            State(state),
            Path(("probe.example.com".to_string(), "v1".to_string())),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let props = &val["components"]["schemas"]["Widget"]["properties"];

        assert_eq!(
            props["apiVersion"]["type"], "string",
            "apiVersion must be injected as a string field — kubectl explain's FIELDS \
             section needs it even though no CRD author ever declares it themselves"
        );
        assert!(
            props["apiVersion"]["description"]
                .as_str()
                .unwrap_or_default()
                .starts_with("APIVersion defines"),
            "apiVersion description must match upstream's TypeMeta doc — the \
             CustomResourcePublishOpenAPI conformance test regex requires this exact \
             prefix; got: {:?}",
            props["apiVersion"]["description"]
        );
        assert_eq!(props["kind"]["type"], "string");

        // OpenAPI v3 ignores sibling keys next to `$ref`, so `metadata` must wrap
        // its `$ref` in `allOf` to keep its own description — a bare
        // `{"$ref": ..., "description": ...}` silently loses "Standard object's
        // metadata" once kubectl explain's template dereferences the `$ref`,
        // even though the JSON itself looks perfectly reasonable.
        assert!(
            props["metadata"].get("$ref").is_none(),
            "metadata must not be a bare $ref sibling — OpenAPI v3 drops the sibling \
             description on dereference, breaking `kubectl explain <crd>.metadata`'s \
             DESCRIPTION section"
        );
        assert_eq!(
            props["metadata"]["allOf"][0]["$ref"],
            format!("#/components/schemas/{OBJECT_META_SCHEMA_NAME}"),
            "metadata must reference the shared ObjectMeta component schema via allOf"
        );
        assert_eq!(
            props["metadata"]["description"],
            "Standard object's metadata. More info: \
             https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata"
        );
    }

    // kubectl explain <crd>.metadata recursively dereferences the `metadata`
    // property's $ref and lists the target schema's own properties; if the
    // referenced ObjectMeta component schema is absent or empty, that command
    // fails with `field "metadata" does not exist` even though the top-level
    // `metadata` field itself is present and well-formed.
    #[tokio::test]
    async fn openapi_v3_group_object_meta_schema_has_creation_timestamp() {
        let state = make_state();

        let body = crd_bytes_with_schema("probe.example.com", "widgets", "Widget", "v1");
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create must succeed");

        let resp = openapi_v3_group(
            State(state),
            Path(("probe.example.com".to_string(), "v1".to_string())),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let creation_timestamp = &val["components"]["schemas"][OBJECT_META_SCHEMA_NAME]
            ["properties"]["creationTimestamp"];

        assert_eq!(creation_timestamp["type"], "string");
        assert!(
            creation_timestamp["description"]
                .as_str()
                .unwrap_or_default()
                .starts_with("CreationTimestamp is a timestamp"),
            "creationTimestamp's description must match upstream ObjectMeta — the \
             CustomResourcePublishOpenAPI conformance test regex requires this exact \
             prefix; got: {:?}",
            creation_timestamp["description"]
        );
    }

    // ---------------------------------------------------------------------------
    // openapi_v3 built-in (non-CRD) group coverage — kubectl explain <builtin>
    //
    // Before this fix, `openapi_v3()`'s `paths` map only ever contained CRD-backed
    // group/versions, so on a stack with zero CRDs registered `kubectl explain pods`
    // and `kubectl explain deployments` failed unconditionally with `couldn't find
    // resource for "..."` — kubectl 1.28+'s default explain renderer looks up
    // "api/v1"/"apis/<group>/<version>" in exactly this map and does not fall back to
    // /openapi/v2 just because the key is absent.
    // ---------------------------------------------------------------------------

    // /openapi/v3's root `paths` index must list "api/v1" and every STATIC_GROUPS
    // group/version even when zero CRDs are registered — this is the exact repro that
    // made `kubectl explain <any built-in>` fail 100% of the time on a fresh stack.
    #[tokio::test]
    async fn openapi_v3_root_paths_includes_core_and_static_groups_with_zero_crds() {
        let state = make_state();

        let resp = openapi_v3(State(state)).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let paths = val["paths"].as_object().expect("paths must be an object");

        assert!(
            paths.contains_key("api/v1"),
            "paths must contain \"api/v1\" with zero CRDs registered — kubectl explain's \
             v3 renderer looks up this exact key for every core-group resource (Pod, \
             Service, ConfigMap, ...) and errors with `couldn't find resource` if it's \
             absent; got keys: {:?}",
            paths.keys().collect::<Vec<_>>()
        );
        assert!(
            paths.contains_key("apis/apps/v1"),
            "paths must contain \"apis/apps/v1\" with zero CRDs registered — \
             `kubectl explain deployments` looks up this exact key; got keys: {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }

    // GET /openapi/v3/api/v1 (Pod, the type `kubectl explain pods` needs) must return a
    // document whose Pod schema has the real top-level fields (apiVersion, kind, metadata,
    // spec, status) and whose `paths` resolves the pods resource to the Pod GVK — the two
    // things kubectl's v3 explain renderer reads before it can print anything.
    #[tokio::test]
    async fn openapi_v3_core_pod_schema_has_real_top_level_fields() {
        let resp = openapi_v3_core().await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let pod = &val["components"]["schemas"]["Pod"];
        assert_eq!(
            pod["description"].as_str().unwrap_or_default(),
            "Pod is a collection of containers that can run on a host. This resource is \
             created by clients and scheduled onto hosts.",
            "kubectl explain pods must show Pod's real top-level DESCRIPTION"
        );
        for field in ["apiVersion", "kind", "metadata", "spec", "status"] {
            assert!(
                !pod["properties"][field].is_null(),
                "Pod schema must have a \"{field}\" property — this is exactly what \
                 `kubectl explain pods`'s FIELDS section lists; got properties: {:?}",
                pod["properties"]
            );
        }

        let paths = val["paths"].as_object().expect("paths must be an object");
        let op = paths
            .get("/api/v1/namespaces/{namespace}/pods")
            .expect("paths must resolve the pods resource to a GVK");
        assert_eq!(op["get"]["x-kubernetes-group-version-kind"]["kind"], "Pod");
    }

    // GET /openapi/v3/apis/apps/v1 (Deployment) on a stack with zero CRDs registered must
    // return 200 with a Deployment schema, not the CRD-only 404 — this is the second
    // explicitly-required repro from the bug report (`kubectl explain deployments`).
    #[tokio::test]
    async fn openapi_v3_group_apps_v1_returns_deployment_schema_with_zero_crds() {
        let state = make_state();

        let resp =
            openapi_v3_group(State(state), Path(("apps".to_string(), "v1".to_string()))).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/openapi/v3/apis/apps/v1 must return 200 even with zero CRDs registered — \
             apps/v1 is a built-in group, not CRD-backed"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let deployment = &val["components"]["schemas"]["Deployment"];
        assert_eq!(
            deployment["properties"]["spec"]["description"]
                .as_str()
                .unwrap_or_default(),
            "Specification of the desired behavior of the Deployment.",
            "kubectl explain deployments must show Deployment's real \"spec\" field"
        );
        assert!(
            !deployment["properties"]["status"].is_null(),
            "Deployment schema must have a \"status\" property"
        );
    }

    // A built-in Kind not in the curated top-level-fields table (ConfigMap does NOT follow
    // the spec/status convention: real ConfigMap fields are data/binaryData/immutable) must
    // show its OWN real fields, never a guessed "spec" — a wrong field name would be more
    // misleading to a `kubectl explain configmaps` user than an incomplete schema.
    #[tokio::test]
    async fn openapi_v3_core_configmap_schema_has_real_fields_not_invented_spec() {
        let resp = openapi_v3_core().await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let props = &val["components"]["schemas"]["ConfigMap"]["properties"];

        assert!(
            !props["data"].is_null(),
            "ConfigMap schema must have its real \"data\" field"
        );
        assert!(
            props["spec"].is_null(),
            "ConfigMap has no \"spec\" field in real Kubernetes — inventing one would be \
             actively wrong, not just incomplete; got properties: {props:?}"
        );
    }

    // GET /openapi/v3/apis/apps/v1 must show real spec/status descriptions for the other
    // apps/v1 workload Kinds too, not just Deployment — `kubectl explain replicasets`,
    // `daemonsets` and `statefulsets` were left at apiVersion/kind/metadata-only before this
    // curated data was added.
    #[tokio::test]
    async fn openapi_v3_group_apps_v1_replicaset_daemonset_statefulset_have_real_spec_status() {
        let state = make_state();
        let resp =
            openapi_v3_group(State(state), Path(("apps".to_string(), "v1".to_string()))).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for kind in ["ReplicaSet", "DaemonSet", "StatefulSet"] {
            let schema = &val["components"]["schemas"][kind];
            assert!(
                !schema["properties"]["spec"]["description"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "{kind} schema must have a real \"spec\" description — `kubectl explain \
                 {kind}` users need real field docs, not a bare type; got: {schema:?}"
            );
            assert!(
                !schema["properties"]["status"].is_null(),
                "{kind} schema must have a \"status\" property; got: {schema:?}"
            );
        }
    }

    // GET /openapi/v3/apis/batch/v1 must show real spec/status for Job and CronJob —
    // `kubectl explain jobs`/`cronjobs` were left at apiVersion/kind/metadata-only before
    // this curated data was added.
    #[tokio::test]
    async fn openapi_v3_group_batch_v1_job_and_cronjob_have_real_spec_status() {
        let state = make_state();
        let resp =
            openapi_v3_group(State(state), Path(("batch".to_string(), "v1".to_string()))).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for kind in ["Job", "CronJob"] {
            let schema = &val["components"]["schemas"][kind];
            assert!(
                !schema["properties"]["spec"]["description"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "{kind} schema must have a real \"spec\" description; got: {schema:?}"
            );
            assert!(
                !schema["properties"]["status"].is_null(),
                "{kind} schema must have a \"status\" property; got: {schema:?}"
            );
        }
    }

    // GET /openapi/v3/api/v1 must show real spec/status for PersistentVolume and
    // PersistentVolumeClaim, but NEVER invent a "spec"/"status" pair for ServiceAccount —
    // ServiceAccount's real top-level fields (secrets, imagePullSecrets,
    // automountServiceAccountToken) don't follow the spec/status convention, and a wrong
    // field name is worse than an incomplete schema for a `kubectl explain
    // serviceaccounts` user.
    #[tokio::test]
    async fn openapi_v3_core_pv_pvc_have_real_spec_status_serviceaccount_does_not() {
        let resp = openapi_v3_core().await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for kind in ["PersistentVolume", "PersistentVolumeClaim"] {
            let schema = &val["components"]["schemas"][kind];
            assert!(
                !schema["properties"]["spec"]["description"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "{kind} schema must have a real \"spec\" description; got: {schema:?}"
            );
            assert!(
                !schema["properties"]["status"].is_null(),
                "{kind} schema must have a \"status\" property; got: {schema:?}"
            );
        }

        let sa_props = &val["components"]["schemas"]["ServiceAccount"]["properties"];
        assert!(
            !sa_props["secrets"].is_null(),
            "ServiceAccount schema must have its real \"secrets\" field; got: {sa_props:?}"
        );
        assert!(
            sa_props["spec"].is_null() && sa_props["status"].is_null(),
            "ServiceAccount has no \"spec\"/\"status\" fields in real Kubernetes — inventing \
             them would be actively wrong, not just incomplete; got: {sa_props:?}"
        );
    }

    // GET /openapi/v3/apis/networking.k8s.io/v1 must show a real "spec" for Ingress AND
    // NetworkPolicy, but NEVER invent a "status" for NetworkPolicy — upstream tombstones
    // NetworkPolicy's status field (protobuf tag 3 reserved, field commented out) precisely
    // so it stays absent; guessing one back in would misrepresent the real API to a
    // `kubectl explain networkpolicies` user.
    #[tokio::test]
    async fn openapi_v3_group_networking_v1_ingress_has_status_networkpolicy_does_not() {
        let state = make_state();
        let resp = openapi_v3_group(
            State(state),
            Path(("networking.k8s.io".to_string(), "v1".to_string())),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let ingress = &val["components"]["schemas"]["Ingress"]["properties"];
        assert!(
            !ingress["spec"].is_null() && !ingress["status"].is_null(),
            "Ingress schema must have real \"spec\" and \"status\" fields; got: {ingress:?}"
        );

        let netpol = &val["components"]["schemas"]["NetworkPolicy"]["properties"];
        assert!(
            !netpol["spec"].is_null(),
            "NetworkPolicy schema must have a real \"spec\" field; got: {netpol:?}"
        );
        assert!(
            netpol["status"].is_null(),
            "NetworkPolicy has no \"status\" field in real Kubernetes (protobuf tag 3 is \
             reserved but the field itself was never added) — inventing one would be \
             actively wrong; got: {netpol:?}"
        );
    }

    // A built-in Kind in a group with NO curated top-level fields at all (storage.k8s.io/v1
    // isn't in the curated table) must still resolve to a valid document — `kubectl explain
    // storageclasses` should get a correct-but-minimal schema (apiVersion/kind/metadata),
    // never the 404 an unrecognized group gets, since storage.k8s.io IS a real built-in group.
    #[tokio::test]
    async fn openapi_v3_group_uncurated_static_group_still_returns_200_not_404() {
        let state = make_state();

        let resp = openapi_v3_group(
            State(state),
            Path(("storage.k8s.io".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "storage.k8s.io/v1 is a real built-in group (STATIC_GROUPS) — it must never 404 \
             just because it has no curated top-level fields yet"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let storage_class = &val["components"]["schemas"]["StorageClass"];
        assert_eq!(
            storage_class["properties"]["apiVersion"]["type"], "string",
            "even an uncurated Kind must get the real apiVersion/kind/metadata fields; \
             got: {storage_class:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // build_aggregated_discovery — u7s_discovery_build_total
    // ---------------------------------------------------------------------------

    /// `/api`, `/apis` and `/discovery/v2` are all on the auth exempt-list, so
    /// `apiserver_request_total` never gets a series for them (see `auth::is_exempt` /
    /// `AuthService::call`'s early return for exempt paths) -- `u7s_discovery_build_total` is
    /// the only per-request signal a future discovery cache's hit-rate work can measure against.
    /// If the increment in `build_aggregated_discovery` is ever dropped (e.g. during a refactor),
    /// that measurement silently goes back to zero series with no test failure elsewhere to
    /// catch it -- this test is that catch.
    ///
    /// Uses a route unused by any other call site so this test's before/after snapshot of the
    /// shared, process-global `DISCOVERY_BUILD_TOTAL` registry can't be perturbed by other tests'
    /// `build_aggregated_discovery` calls running concurrently on other `cargo test` threads.
    #[tokio::test]
    async fn build_aggregated_discovery_increments_discovery_build_total() {
        let state = make_state();
        let label_values = ["/test-only/discovery-build-total", "true", "false"];
        let before = crate::metrics::DISCOVERY_BUILD_TOTAL
            .with_label_values(&label_values)
            .get();

        build_aggregated_discovery(
            &state,
            "v2beta1",
            true,
            None,
            "/test-only/discovery-build-total",
        )
        .await;

        let after = crate::metrics::DISCOVERY_BUILD_TOTAL
            .with_label_values(&label_values)
            .get();
        assert_eq!(
            after,
            before + 1,
            "a single build_aggregated_discovery call with include_core=true and no \
             APIServices registered must increment exactly the \
             {{version=/discovery/v2, include_core=true, has_apiservice=false}} series by 1"
        );
    }

    // ---------------------------------------------------------------------------
    // build_aggregated_discovery — concurrent per-backend resolution
    // ---------------------------------------------------------------------------

    /// A store wrapper that sleeps before every `get()`, then delegates to the inner
    /// in-memory store unchanged. Stands in for a slow per-backend APIService lookup: the
    /// `.await` point this simulates (`find_apiservice`'s `store.get()`) sits inside the
    /// exact same per-group-version future that a live APIService's network discovery
    /// fetch (`discovery_resources_for_apiservice`) runs in, so proving this `.await` is
    /// driven concurrently proves the network fetch would be too.
    struct SlowGetStore {
        inner: Arc<SqliteStore>,
        delay: std::time::Duration,
    }

    impl u7s_store::Store for SlowGetStore {
        fn get(
            &self,
            key: &str,
        ) -> impl std::future::Future<Output = u7s_store::Result<Option<u7s_store::StoreObject>>> + Send
        {
            let inner = self.inner.clone();
            let key = key.to_string();
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                inner.get(&key).await
            }
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

    /// Regression test: before this fix, `build_aggregated_discovery` resolved every
    /// group+version with one `.await` per loop iteration, so N groups that each fall
    /// through to an APIService lookup added N * (per-lookup latency) to the response. In
    /// production that per-lookup step ends in a live network fetch to the backend with its
    /// own ~10s timeout (`aggregation::build_backend_client`), so a handful of unresponsive
    /// aggregated backends could add tens of seconds to *every* `/apis` and `/discovery/v2`
    /// call, even for callers who never asked about the slow backend's group.
    ///
    /// This test simulates that slow backend with a slow store `get()` rather than a slow
    /// live HTTP fetch: an APIService's backend is only reachable via a fixed
    /// `{name}.{namespace}.svc` DNS suffix (`aggregation::backend_base_url`), which cannot
    /// be pointed at a local test server without changing aggregation.rs's URL-resolution
    /// code — out of scope for this fix. Omitting `spec.service` makes
    /// `discovery_resources_for_apiservice` return instantly with no network call at all
    /// (see its doc), isolating the slow step to exactly the `.await` this fix parallelizes.
    ///
    /// If the `for` loop's `join_all` fan-out is reverted back to sequential `.await`s, this
    /// test's elapsed time goes from ~1 delay to ~BACKEND_COUNT delays and the assertion below
    /// fails.
    #[tokio::test]
    async fn build_aggregated_discovery_resolves_backends_concurrently_not_sequentially() {
        const DELAY: std::time::Duration = std::time::Duration::from_millis(200);
        const BACKEND_COUNT: usize = 5;

        let inner = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        for i in 0..BACKEND_COUNT {
            let group = format!("slowgroup{i}.example.com");
            let name = format!("v1.{group}");
            let key =
                crate::keys::group_object_key("apiregistration.k8s.io", "apiservices", None, &name);
            let body = serde_json::json!({
                "metadata": { "name": name },
                "spec": { "group": group, "version": "v1" }
            });
            inner
                .put(&key, Bytes::from(body.to_string()), Some(0))
                .await
                .expect("seed apiservice");
        }

        let state = AppState::new(
            Arc::new(SlowGetStore {
                inner,
                delay: DELAY,
            }),
            None,
            None,
            std::collections::HashMap::new(),
            "https://localhost:6443".into(),
        );

        let start = std::time::Instant::now();
        let body = build_aggregated_discovery(&state, "v2beta1", false, None, "/apis").await;
        let elapsed = start.elapsed();

        let names: Vec<String> = body.items.iter().map(|i| i.metadata.name.clone()).collect();
        for i in 0..BACKEND_COUNT {
            let expected = format!("slowgroup{i}.example.com");
            assert!(
                names.contains(&expected),
                "every registered APIService-backed group must still appear in aggregated \
                 discovery even though its resolution went through the slow store -- \
                 concurrency must not drop or fail a slow backend's own group; got: {names:?}"
            );
        }

        assert!(
            elapsed < DELAY * 3,
            "resolving {BACKEND_COUNT} backends one `.await` at a time would take at least \
             {BACKEND_COUNT} * {DELAY:?} = {:?}; concurrent resolution must stay close to a \
             single backend's own latency ({DELAY:?}) regardless of how many other backends \
             are also slow, got {elapsed:?}",
            DELAY * BACKEND_COUNT as u32
        );
    }

    // ---------------------------------------------------------------------------
    // build_aggregated_discovery — typed-struct migration (mayor-ohh8o)
    // ---------------------------------------------------------------------------

    /// Regression test for mayor-ohh8o: `build_aggregated_discovery` must serialize to the
    /// exact same bytes it did before migrating its `serde_json::json!`-built `Value` tree to
    /// the typed `APIGroupDiscoveryList`/`APIResourceDiscovery` family in `types.rs`. client-go's
    /// discovery cache stores this response verbatim and diffs it byte-for-byte on the next
    /// fetch, so a field-order or field-presence change here (even one that keeps the same JSON
    /// *meaning*) silently breaks discovery caching for every real client.
    ///
    /// The golden fixture was captured from the pre-migration `json!`-based implementation
    /// against an empty in-memory store (only the built-in `STATIC_GROUPS` and core v1
    /// resources appear — deterministic, no CRDs/APIServices/network calls involved).
    ///
    /// Note: because `serde_json::Value`'s `Map` is a `BTreeMap` (no `preserve_order` feature
    /// enabled anywhere in this workspace — see the doc comment on `types::APIGroupDiscoveryList`),
    /// the old `json!`-built output was *already* key-sorted, and this test's typed struct fields
    /// were deliberately declared in that same sorted order — so this assertion alone cannot
    /// distinguish the typed path from a reverted `json!` path (both produce identical bytes).
    /// See `build_aggregated_discovery_body_contains_no_untyped_json_value_construction` below
    /// for the test that actually fails on revert.
    #[tokio::test]
    async fn build_aggregated_discovery_output_is_byte_identical_to_pre_migration_golden() {
        let state = make_state();
        let body = build_aggregated_discovery(&state, "v2beta1", true, None, "/discovery/v2").await;
        let actual = serde_json::to_string(&body).unwrap();
        let golden = include_str!("testdata/aggregated_discovery_golden.json");
        assert_eq!(
            actual, golden,
            "build_aggregated_discovery's serialized output no longer matches the \
             pre-migration golden fixture byte-for-byte -- if this is an intentional wire \
             format change, regenerate testdata/aggregated_discovery_golden.json; otherwise \
             this breaks client-go's discovery response caching, which compares this body \
             verbatim"
        );
    }

    /// Regression test for mayor-ohh8o, and the actual fail-on-revert half of the pair above:
    /// `build_aggregated_discovery`'s own body must not construct its output via
    /// `serde_json::json!`/`serde_json::Value`. Mirrors the source-scan pattern used for the
    /// sibling perf fixes `content_type::reencode_proto_response` (mayor-g7g2m) and
    /// `auth::object_is_live` (mayor-e555b): a purely byte-equality test cannot catch a
    /// reintroduction of the untyped `Value`-tree-building path here, because
    /// `serde_json::Value`'s `Map` sorts keys the same way a hand-declared, alphabetically
    /// ordered struct does (see the test above) -- so the old and new code paths are
    /// byte-identical on the wire even though one path pays for building and dropping a full
    /// recursive `Value` tree per discovery request and the other does not.
    #[test]
    fn build_aggregated_discovery_body_contains_no_untyped_json_value_construction() {
        let source = include_str!("discovery.rs");
        let fn_start = source
            .find("pub(crate) async fn build_aggregated_discovery")
            .expect("build_aggregated_discovery must still exist in this file");
        let after_start = &source[fn_start..];
        let fn_end = after_start
            .find("\n}\n")
            .expect("build_aggregated_discovery's closing brace must be found");
        let fn_body = &after_start[..fn_end];

        assert!(
            !fn_body.contains("serde_json::json!") && !fn_body.contains("serde_json::Value"),
            "build_aggregated_discovery must build its response via the typed \
             APIGroupDiscoveryList/APIGroupDiscovery/APIVersionDiscovery structs, not \
             serde_json::json!/Value -- the byte-equality golden test above cannot catch this \
             regression on its own (see its doc comment), so this scans the function's own \
             source instead; fn body was:\n{fn_body}"
        );
    }

    // ---------------------------------------------------------------------------
    // DiscoveryCache — bytes-cache for the STATIC_GROUPS + CRD portion (mayor-a9kc1)
    // ---------------------------------------------------------------------------

    /// A cache-warm request and a cache-forced-cold request (the store's only source of
    /// truth, with `DiscoveryCache` cleared so `cached_core_and_crd_groups` must rebuild from
    /// scratch) must return byte-identical output for the same inputs -- the cache changes
    /// *when* the STATIC_GROUPS/CRD resolution work happens, never *what* it produces. Also
    /// pins down field-level correctness of the cache's own encode/decode round trip
    /// (`typed_resource_to_cached`/`cached_resource_to_typed`): a cold rebuild and a warm read
    /// both funnel through that round trip, so a self-consistent bug there (e.g. inverting the
    /// `namespaced` bool) would NOT show up as a diff between the two calls below -- only an
    /// explicit assertion on the actual field values can catch that class of bug, which is why
    /// this test checks `scope`/`shortNames`/`verbs` directly rather than relying solely on the
    /// two-calls comparison.
    ///
    /// Falsifiable: swap `namespaced: r.scope == "Namespaced"` for `!=` in
    /// `typed_resource_to_cached` and this test's `scope` assertion below fails (while the
    /// two-calls byte comparison alone would NOT, since both calls would agree on the same
    /// wrong answer -- demonstrating why the explicit field assertion is required here).
    #[tokio::test]
    async fn discovery_cache_hit_is_byte_identical_to_a_forced_cold_rebuild() {
        let state = make_state();
        let body = crd_bytes(
            "cache-check.example.com",
            "widgets",
            "widget",
            "Widget",
            "Namespaced",
            "v1",
        );
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create_crd must succeed");

        // First call: whatever cache state create_crd's write-through refresh left behind.
        let warm = build_aggregated_discovery(&state, "v2beta1", false, None, "/apis").await;
        let warm_bytes = serde_json::to_string(&warm).unwrap();

        // Force the cache cold, bypassing any invalidation path, so the next call must rebuild
        // straight from the store -- the "uncached" side of this comparison.
        *state.discovery_cache.groups.write().unwrap() = None;
        let cold = build_aggregated_discovery(&state, "v2beta1", false, None, "/apis").await;
        let cold_bytes = serde_json::to_string(&cold).unwrap();

        assert_eq!(
            warm_bytes, cold_bytes,
            "a cache-warm read and a forced cold rebuild must produce byte-identical output \
             for the same registered CRDs"
        );

        let group = cold
            .items
            .iter()
            .find(|g| g.metadata.name == "cache-check.example.com")
            .expect("the CRD's group must appear in aggregated discovery");
        let resource = &group.versions[0].resources[0];
        assert_eq!(resource.resource, "widgets");
        assert_eq!(resource.response_kind.kind, "Widget");
        assert_eq!(
            resource.scope, "Namespaced",
            "scope must round-trip through DiscoveryCache's plain-data encode/decode \
             unchanged -- this is the assertion that actually fails if the cache's \
             namespaced-bool mapping is ever inverted"
        );
        assert_eq!(resource.singular_resource, "widget");
    }

    /// Deleting a CRD must make its group disappear from the very next aggregated-discovery
    /// call. `DiscoveryCache` is keyed on nothing but "warm or cold" (see its doc in
    /// state.rs) -- a create/delete that doesn't call
    /// `handlers::discovery::refresh_discovery_cache` leaves the deleted CRD's group
    /// permanently visible in discovery, which would make kubectl and controllers keep
    /// believing a resource type still exists after `kubectl delete crd` succeeds.
    ///
    /// Falsifiable: comment out the `refresh_discovery_cache` call in `delete_crd` and this
    /// test fails, because the cache still holds the pre-delete snapshot.
    #[tokio::test]
    async fn deleting_a_crd_removes_its_group_from_discovery_on_the_next_call() {
        let state = make_state();
        let body = crd_bytes(
            "invalidation-check.example.com",
            "gadgets",
            "gadget",
            "Gadget",
            "Namespaced",
            "v1",
        );
        create_crd(
            State(state.clone()),
            test_user(),
            axum::http::HeaderMap::new(),
            body,
        )
        .await
        .expect("create_crd must succeed");

        let before = build_aggregated_discovery(&state, "v2beta1", false, None, "/apis").await;
        assert!(
            before
                .items
                .iter()
                .any(|g| g.metadata.name == "invalidation-check.example.com"),
            "the CRD's group must be visible in discovery right after creation"
        );

        delete_crd(
            State(state.clone()),
            Path("gadgets.invalidation-check.example.com".to_string()),
            test_user(),
        )
        .await
        .expect("delete_crd must succeed");

        let after = build_aggregated_discovery(&state, "v2beta1", false, None, "/apis").await;
        assert!(
            !after
                .items
                .iter()
                .any(|g| g.metadata.name == "invalidation-check.example.com"),
            "the CRD's group must be gone from discovery immediately after delete_crd -- a \
             stale DiscoveryCache entry would still show it here"
        );
    }

    /// Regression guard: `api_resources_to_discovery_resources` reads `resource_list` as a raw
    /// `serde_json::Value` (not a strict typed deserialize) precisely because it is also fed an
    /// external `APIService` backend's own live discovery document (see
    /// `aggregation::discovery_resources_for_apiservice`) -- arbitrary JSON this apiserver does
    /// not control. This test proves an unrecognized extra field on a resource entry is safely
    /// ignored rather than causing a panic or dropping the fields we *do* recognize, since a
    /// strict `#[derive(Deserialize)]` on that shape would instead reject or silently drop the
    /// whole entry the moment a real backend adds a field u7s doesn't yet know about (e.g. a
    /// newer Kubernetes minor version's `APIResourceList.categories`).
    #[test]
    fn api_resources_to_discovery_resources_ignores_unknown_extra_fields() {
        let resource_list = serde_json::json!({
            "resources": [{
                "name": "widgets",
                "singularName": "widget",
                "namespaced": true,
                "kind": "Widget",
                "verbs": ["get", "list"],
                "categories": ["all"],
                "storageVersionHash": "abc123=="
            }]
        });

        let resources = api_resources_to_discovery_resources(&resource_list);

        assert_eq!(
            resources.len(),
            1,
            "an unrecognized extra field (categories/storageVersionHash) must not cause the \
             resource entry to be dropped"
        );
        let widgets = &resources[0];
        assert_eq!(widgets.resource, "widgets");
        assert_eq!(widgets.response_kind.kind, "Widget");
        assert_eq!(widgets.scope, "Namespaced");
        assert_eq!(widgets.singular_resource, "widget");
        assert_eq!(
            widgets.verbs,
            vec!["get".to_string(), "list".to_string()],
            "recognized fields must still be extracted correctly alongside ignored ones"
        );
    }
}
