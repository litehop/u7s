use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use u7s_store::{ListOptions, Store as _};

use crate::handlers::crd::CustomResourceDefinition;
use crate::state::AppState;
use crate::types::{APIGroup, APIGroupList, APIVersions, ApiResourceList, GroupVersionForDiscovery};

pub async fn api_versions(State(state): State<AppState>) -> Json<APIVersions> {
    Json(APIVersions::v1(state.server_address.clone()))
}

pub async fn api_v1_resources() -> Json<ApiResourceList> {
    Json(ApiResourceList::v1())
}

// ---------------------------------------------------------------------------
// /apis — group list
// ---------------------------------------------------------------------------

const STATIC_GROUPS: &[(&str, &str)] = &[
    ("apiextensions.k8s.io", "v1"),
    ("apps", "v1"),
    ("authentication.k8s.io", "v1"),
    ("authorization.k8s.io", "v1"),
    ("rbac.authorization.k8s.io", "v1"),
];

pub async fn api_group_list(State(state): State<AppState>) -> Json<APIGroupList> {
    let mut groups: Vec<APIGroup> = STATIC_GROUPS
        .iter()
        .map(|(name, version)| make_group(name, version, &[version]))
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

    Json(APIGroupList {
        kind: "APIGroupList",
        api_version: "v1",
        groups,
    })
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
// /apis/:group/:version — per-group resource list
// ---------------------------------------------------------------------------

pub async fn api_group_resources(
    State(state): State<AppState>,
    Path((group, version)): Path<(String, String)>,
) -> Response {
    let static_list = match (group.as_str(), version.as_str()) {
        ("apiextensions.k8s.io", "v1") => Some(apiextensions_v1_resources()),
        ("apps", "v1") => Some(apps_v1_resources()),
        ("authentication.k8s.io", "v1") => Some(authn_v1_resources()),
        ("authorization.k8s.io", "v1") => Some(authz_v1_resources()),
        ("rbac.authorization.k8s.io", "v1") => Some(rbac_v1_resources()),
        _ => None,
    };

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
                crd.spec.group == group
                    && crd.spec.versions.iter().any(|v| v.name == version)
            })
            .map(|crd| {
                serde_json::json!({
                    "name": crd.spec.names.plural,
                    "singularName": crd.spec.names.singular,
                    "namespaced": crd.spec.scope == "Namespaced",
                    "kind": crd.spec.names.kind,
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
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
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
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
                "name": "deployments",
                "singularName": "deployment",
                "namespaced": true,
                "kind": "Deployment",
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
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
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
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
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
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
        "resources": []
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
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "clusterrolebindings",
                "singularName": "clusterrolebinding",
                "namespaced": false,
                "kind": "ClusterRoleBinding",
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "roles",
                "singularName": "role",
                "namespaced": true,
                "kind": "Role",
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
            },
            {
                "name": "rolebindings",
                "singularName": "rolebinding",
                "namespaced": true,
                "kind": "RoleBinding",
                "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use bytes::Bytes;
    use std::sync::Arc;
    use u7s_store::SqliteStore;

    use crate::handlers::crd::create_crd;

    fn make_state() -> AppState {
        let store = Arc::new(SqliteStore::new(":memory:").expect("in-memory store"));
        AppState::new(store, None, None, std::collections::HashMap::new(), "https://localhost:6443".into())
    }

    fn crd_bytes(group: &str, plural: &str, singular: &str, kind: &str, scope: &str, version: &str) -> Bytes {
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

        let body = crd_bytes("example.io", "widgets", "widget", "Widget", "Namespaced", "v1beta1");
        assert!(create_crd(State(state.clone()), axum::http::HeaderMap::new(), body).await.is_ok(), "create must succeed");

        let Json(list) = api_group_list(State(state)).await;
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
        let Json(list) = api_group_list(State(state)).await;
        let names: Vec<&str> = list.groups.iter().map(|g| g.name.as_str()).collect();
        for (group, _) in STATIC_GROUPS {
            assert!(
                names.contains(group),
                "static group {group} must always be in /apis; got: {names:?}"
            );
        }
    }

    // A group that matches a static group must not be duplicated when a CRD
    // with that group name exists in the store.
    #[tokio::test]
    async fn crd_group_does_not_duplicate_static_groups() {
        let state = make_state();

        // Install a CRD whose group is already covered by static discovery.
        let body = crd_bytes("apps", "widgets", "widget", "Widget", "Namespaced", "v1");
        assert!(create_crd(State(state.clone()), axum::http::HeaderMap::new(), body).await.is_ok(), "create must succeed");

        let Json(list) = api_group_list(State(state)).await;
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

        let body = crd_bytes("example.io", "gadgets", "gadget", "Gadget", "Cluster", "v1alpha1");
        assert!(create_crd(State(state.clone()), axum::http::HeaderMap::new(), body).await.is_ok(), "create must succeed");

        let resp = api_group_resources(
            State(state),
            Path(("example.io".to_string(), "v1alpha1".to_string())),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
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
        assert!(create_crd(State(state.clone()), axum::http::HeaderMap::new(), body).await.is_ok(), "create must succeed");

        let Json(list) = api_group_list(State(state)).await;
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
}
