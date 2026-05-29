use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use u7s_store::{ListOptions, Store};

use crate::handlers::crd::CustomResourceDefinition;
use crate::state::AppState;
use crate::types::{
    APIGroup, APIGroupList, APIVersions, ApiResourceList, GroupVersionForDiscovery,
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
        let body = build_aggregated_discovery(&state, version, true).await;
        let items = body["items"].as_array().cloned().unwrap_or_default();
        let resource_version = body["metadata"]["resourceVersion"].clone();
        let core_only = items
            .into_iter()
            .filter(|i| i["metadata"]["name"] == "")
            .collect::<Vec<_>>();
        let core_body = serde_json::json!({
            "kind": "APIGroupDiscoveryList",
            "apiVersion": format!("apidiscovery.k8s.io/{version}"),
            "metadata": { "resourceVersion": resource_version },
            "items": core_only
        });
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
        let body = build_aggregated_discovery(&state, version, false).await;
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

pub(crate) async fn api_group_list_inner<S: Store>(state: &AppState<S>) -> APIGroupList {
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
pub(crate) async fn build_aggregated_discovery<S: Store>(
    state: &AppState<S>,
    discovery_version: &str,
    include_core: bool,
) -> serde_json::Value {
    // Collect all groups+versions (same logic as api_group_list_inner).
    let group_list = api_group_list_inner(state).await;

    let mut items: Vec<serde_json::Value> = Vec::new();

    if include_core {
        // Build the core group item (group="", apiVersion="v1").
        let core_resources = api_resources_to_discovery_resources(&api_v1_resource_list_value());
        let core_item = serde_json::json!({
            "metadata": { "name": "" },
            "versions": [{
                "version": "v1",
                "resources": core_resources,
                "freshness": "Current"
            }]
        });
        items.push(core_item);
    }

    // Build one item per non-core group.
    for group in &group_list.groups {
        let mut versions_arr: Vec<serde_json::Value> = Vec::new();
        for gv in &group.versions {
            let resources = if let Some(rl) =
                static_group_resources(group.name.as_str(), gv.version.as_str())
            {
                api_resources_to_discovery_resources(&rl)
            } else {
                // Dynamic group (CRD-backed): look up resources from the store.
                crd_group_resources(state, group.name.as_str(), gv.version.as_str()).await
            };
            versions_arr.push(serde_json::json!({
                "version": gv.version,
                "resources": resources,
                "freshness": "Current"
            }));
        }
        items.push(serde_json::json!({
            "metadata": { "name": group.name },
            "versions": versions_arr
        }));
    }

    // Compute a simple ETag from the number of items (sufficient for conformance).
    let resource_version = format!("{}", items.len());

    serde_json::json!({
        "kind": "APIGroupDiscoveryList",
        "apiVersion": format!("apidiscovery.k8s.io/{discovery_version}"),
        "metadata": { "resourceVersion": resource_version },
        "items": items
    })
}

/// Look up CRD-backed resources for a group/version from the store and return discovery entries.
async fn crd_group_resources<S: Store>(
    state: &AppState<S>,
    group: &str,
    version: &str,
) -> serde_json::Value {
    let Ok(resp) = state
        .store
        .list(
            "/registry/apiextensions.k8s.io/customresourcedefinitions/",
            ListOptions::default(),
        )
        .await
    else {
        return serde_json::Value::Array(vec![]);
    };

    let resources: Vec<serde_json::Value> = resp
        .items
        .iter()
        .filter_map(|obj| serde_json::from_slice::<CustomResourceDefinition>(&obj.value).ok())
        .filter(|crd| {
            crd.spec.group == group && crd.spec.versions.iter().any(|v| v.name == version && v.served)
        })
        .map(|crd| {
            let scope = if crd.spec.scope == "Namespaced" {
                "Namespaced"
            } else {
                "Cluster"
            };
            let mut entry = serde_json::json!({
                "resource": crd.spec.names.plural,
                "responseKind": { "kind": crd.spec.names.kind },
                "scope": scope,
                "singularResource": crd.spec.names.singular,
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            });
            if !crd.spec.names.short_names.is_empty() {
                entry["shortNames"] = serde_json::Value::Array(
                    crd.spec.names.short_names.iter().cloned().map(serde_json::Value::String).collect(),
                );
            }
            entry
        })
        .collect();

    serde_json::Value::Array(resources)
}

/// Convert an `APIResourceList` JSON value into the `APIGroupDiscovery` resource entry array.
fn api_resources_to_discovery_resources(resource_list: &serde_json::Value) -> serde_json::Value {
    let empty = vec![];
    let resources = resource_list["resources"].as_array().unwrap_or(&empty);
    let entries: Vec<serde_json::Value> = resources
        .iter()
        .map(|r| {
            let name = r["name"].as_str().unwrap_or("");
            // Skip subresources (names with "/") — they appear as subresources in their parent.
            let is_subresource = name.contains('/');
            let kind = r["kind"].as_str().unwrap_or("");
            let singular = r["singularName"].as_str().unwrap_or("");
            let namespaced = r["namespaced"].as_bool().unwrap_or(false);
            let scope = if namespaced { "Namespaced" } else { "Cluster" };
            let verbs = r["verbs"].clone();
            let short_names = r
                .get("shortNames")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            // Find subresources that belong to this resource.
            let sub_entries: Vec<serde_json::Value> = if !is_subresource {
                let prefix = format!("{name}/");
                resources
                    .iter()
                    .filter(|s| {
                        s["name"]
                            .as_str()
                            .map(|n| n.starts_with(&prefix))
                            .unwrap_or(false)
                    })
                    .map(|s| {
                        let sub_name = s["name"].as_str().unwrap_or("").trim_start_matches(&prefix);
                        let sub_kind = s["kind"].as_str().unwrap_or("");
                        serde_json::json!({
                            "subresource": sub_name,
                            "responseKind": { "kind": sub_kind },
                            "verbs": s["verbs"]
                        })
                    })
                    .collect()
            } else {
                vec![]
            };

            if is_subresource {
                return serde_json::Value::Null; // filtered out below
            }

            let mut entry = serde_json::json!({
                "resource": name,
                "responseKind": { "kind": kind },
                "scope": scope,
                "singularResource": singular,
                "verbs": verbs
            });
            if !short_names.is_null()
                && short_names
                    .as_array()
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            {
                entry["shortNames"] = short_names;
            }
            if !sub_entries.is_empty() {
                entry["subresources"] = serde_json::Value::Array(sub_entries);
            }
            entry
        })
        .filter(|v| !v.is_null())
        .collect();
    serde_json::Value::Array(entries)
}

/// Return the core v1 resource list as a JSON value (for aggregated discovery).
fn api_v1_resource_list_value() -> serde_json::Value {
    let list = crate::types::ApiResourceList::v1();
    serde_json::to_value(&list).unwrap_or(serde_json::Value::Null)
}

/// Handler for `GET /discovery/v2` — always returns the aggregated discovery list.
pub async fn aggregated_discovery_v2<S: Store>(State(state): State<AppState<S>>) -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json;g=apidiscovery.k8s.io;v=v2beta1",
        )],
        Json(build_aggregated_discovery(&state, "v2beta1", true).await),
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
                "name": "validatingadmissionpolicybindings",
                "singularName": "validatingadmissionpolicybinding",
                "namespaced": false,
                "kind": "ValidatingAdmissionPolicyBinding",
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
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
pub async fn openapi_v2<S: Store>(State(state): State<AppState<S>>) -> Json<serde_json::Value> {
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
            // Reverse the domain segments: "example.io" → "io.example"
            let reversed: String = group.split('.').rev().collect::<Vec<_>>().join(".");
            for ver in &crd.spec.versions {
                // Key format: io.example.v1.Foo
                let key = format!("{}.{}.{}", reversed, ver.name, kind);
                definitions.insert(
                    key,
                    serde_json::json!({
                        "type": "object",
                        "x-kubernetes-group-version-kind": [
                            {
                                "group": group,
                                "version": ver.name,
                                "kind": kind
                            }
                        ]
                    }),
                );
            }
        }
    }

    Json(serde_json::json!({
        "swagger": "2.0",
        "info": {"title": "u7s", "version": "v1"},
        "paths": {},
        "definitions": definitions
    }))
}

/// Minimal OpenAPI v3 discovery stub — kubectl 1.28+ calls /openapi/v3 first.
/// An empty "paths" map is valid and tells kubectl to fall back to /openapi/v2.
pub async fn openapi_v3() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "paths": {}
    }))
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

    use crate::handlers::crd::create_crd;

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
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
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
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
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
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
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
        let Json(val) = openapi_v2(State(state)).await;
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
        let Json(val) = openapi_v3().await;
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

    // HTTP-level: GET /openapi/v3 must return 200 with a "paths" key.
    // This verifies the route is wired — kubectl 1.28+ calls /openapi/v3
    // first and falls back to /openapi/v2 only if it gets a valid response.
    #[tokio::test]
    async fn openapi_v3_route_returns_200_with_paths_key() {
        let app = Router::new().route("/openapi/v3", get(openapi_v3));

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
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
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
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
                .await
                .is_ok(),
            "create_crd must succeed"
        );

        let Json(doc) = openapi_v2(State(state)).await;
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

    // create_crd must stamp status.conditions Established=True and NamesAccepted=True
    // so that controllers (e.g. kube-controller-manager CRD controller) do not wait
    // for a separate status update that never comes in u7s's single-process model.
    #[tokio::test]
    async fn create_crd_stamps_established_and_names_accepted_conditions() {
        use u7s_store::Store;

        let state = make_state();

        let body = crd_bytes("example.io", "bars", "bar", "Bar", "Cluster", "v1alpha1");
        assert!(
            create_crd(State(state.clone()), axum::http::HeaderMap::new(), body)
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
}
