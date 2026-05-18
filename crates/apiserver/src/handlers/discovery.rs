use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::types::{APIGroup, APIGroupList, APIVersions, ApiResourceList, GroupVersionForDiscovery};

pub async fn api_versions() -> Json<APIVersions> {
    Json(APIVersions::v1())
}

pub async fn api_v1_resources() -> Json<ApiResourceList> {
    Json(ApiResourceList::v1())
}

// ---------------------------------------------------------------------------
// /apis — group list
// ---------------------------------------------------------------------------

pub async fn api_group_list() -> Json<APIGroupList> {
    let groups = vec![
        make_group("apps", "v1"),
        make_group("rbac.authorization.k8s.io", "v1"),
    ];
    Json(APIGroupList {
        kind: "APIGroupList",
        api_version: "v1",
        groups,
    })
}

fn make_group(name: &str, version: &str) -> APIGroup {
    let gv = GroupVersionForDiscovery {
        group_version: format!("{}/{}", name, version),
        version: version.to_string(),
    };
    let preferred = GroupVersionForDiscovery {
        group_version: format!("{}/{}", name, version),
        version: version.to_string(),
    };
    APIGroup {
        name: name.to_string(),
        versions: vec![gv],
        preferred_version: preferred,
    }
}

// ---------------------------------------------------------------------------
// /apis/:group/:version — per-group resource list
// ---------------------------------------------------------------------------

pub async fn api_group_resources(
    Path((group, version)): Path<(String, String)>,
) -> Response {
    let list = match (group.as_str(), version.as_str()) {
        ("apps", "v1") => apps_v1_resources(),
        ("rbac.authorization.k8s.io", "v1") => rbac_v1_resources(),
        _ => {
            return (
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
                .into_response();
        }
    };
    Json(list).into_response()
}

// ---------------------------------------------------------------------------
// Static resource lists
// ---------------------------------------------------------------------------

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
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            },
            {
                "name": "replicasets",
                "singularName": "replicaset",
                "namespaced": true,
                "kind": "ReplicaSet",
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            },
            {
                "name": "statefulsets",
                "singularName": "statefulset",
                "namespaced": true,
                "kind": "StatefulSet",
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
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
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            },
            {
                "name": "clusterrolebindings",
                "singularName": "clusterrolebinding",
                "namespaced": false,
                "kind": "ClusterRoleBinding",
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            },
            {
                "name": "roles",
                "singularName": "role",
                "namespaced": true,
                "kind": "Role",
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            },
            {
                "name": "rolebindings",
                "singularName": "rolebinding",
                "namespaced": true,
                "kind": "RoleBinding",
                "verbs": ["create", "delete", "get", "list", "patch", "update"]
            }
        ]
    })
}
