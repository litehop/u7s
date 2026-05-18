use crate::types::{APIVersions, ApiResourceList};

pub async fn api_versions() -> axum::Json<APIVersions> {
    axum::Json(APIVersions::v1())
}

pub async fn api_v1_resources() -> axum::Json<ApiResourceList> {
    axum::Json(ApiResourceList::v1())
}
