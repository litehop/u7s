pub async fn api_versions() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kind": "APIVersions",
        "apiVersion": "v1",
        "versions": ["v1"],
        "serverAddressByClientCIDRs": [
            { "clientCIDR": "0.0.0.0/0", "serverAddress": "https://127.0.0.1:6443" }
        ]
    }))
}

pub async fn api_v1_resources() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "kind": "APIResourceList",
        "apiVersion": "v1",
        "groupVersion": "v1",
        "resources": [
            {
                "name": "pods",
                "singularName": "pod",
                "namespaced": true,
                "kind": "Pod",
                "verbs": ["create", "delete", "get", "list", "patch", "update"],
                "shortNames": ["po"]
            }
        ]
    }))
}
