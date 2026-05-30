use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub kind: &'static str,
    pub api_version: &'static str,
    pub status: &'static str,
    pub message: String,
    pub reason: &'static str,
    pub code: u16,
    /// Optional metadata attached to the Status response.
    ///
    /// Used to carry `metadata.continue` in 410 Expired responses so clients
    /// can restart pagination from the beginning without a separate list call.
    /// Boxed to keep the `Status` struct small and avoid `clippy::result_large_err`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Box<serde_json::Value>>,
}

pub struct StatusError(pub StatusCode, pub Status);

impl std::fmt::Debug for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatusError({}: {})", self.0, self.1.message)
    }
}

impl IntoResponse for StatusError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(self.1)).into_response()
    }
}

impl Status {
    pub fn not_found(name: &str, kind: &str) -> StatusError {
        StatusError(
            StatusCode::NOT_FOUND,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message: format!("{kind} \"{name}\" not found"),
                reason: "NotFound",
                code: 404,
                metadata: None,
            },
        )
    }

    pub fn already_exists(name: &str, kind: &str) -> StatusError {
        StatusError(
            StatusCode::CONFLICT,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message: format!("{kind} \"{name}\" already exists"),
                reason: "AlreadyExists",
                code: 409,
                metadata: None,
            },
        )
    }

    pub fn conflict(message: String) -> StatusError {
        StatusError(
            StatusCode::CONFLICT,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Conflict",
                code: 409,
                metadata: None,
            },
        )
    }

    pub fn bad_request(message: String) -> StatusError {
        StatusError(
            StatusCode::BAD_REQUEST,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "BadRequest",
                code: 400,
                metadata: None,
            },
        )
    }

    pub fn unsupported_media_type(message: String) -> StatusError {
        StatusError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "UnsupportedMediaType",
                code: 415,
                metadata: None,
            },
        )
    }

    pub fn unprocessable_entity(message: String) -> StatusError {
        StatusError(
            StatusCode::UNPROCESSABLE_ENTITY,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Invalid",
                code: 422,
                metadata: None,
            },
        )
    }

    pub fn expired(message: String) -> StatusError {
        StatusError(
            StatusCode::GONE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Expired",
                code: 410,
                metadata: None,
            },
        )
    }

    /// Build a 410 Gone / Expired error that includes a new continue token in
    /// `metadata.continue`.  Clients (client-go) use this token to restart the
    /// paginated list from the beginning without issuing an additional request.
    pub fn expired_with_continue(message: String, continue_token: String) -> StatusError {
        StatusError(
            StatusCode::GONE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Expired",
                code: 410,
                metadata: Some(Box::new(serde_json::json!({ "continue": continue_token }))),
            },
        )
    }

    pub fn internal(message: String) -> StatusError {
        StatusError(
            StatusCode::INTERNAL_SERVER_ERROR,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "InternalError",
                code: 500,
                metadata: None,
            },
        )
    }

    pub fn too_many_requests(message: String) -> StatusError {
        StatusError(
            StatusCode::TOO_MANY_REQUESTS,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "TooManyRequests",
                code: 429,
                metadata: None,
            },
        )
    }

    pub fn forbidden(message: String) -> StatusError {
        StatusError(
            StatusCode::FORBIDDEN,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Forbidden",
                code: 403,
                metadata: None,
            },
        )
    }

    pub fn service_unavailable(message: String) -> StatusError {
        StatusError(
            StatusCode::SERVICE_UNAVAILABLE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "ServiceUnavailable",
                code: 503,
                metadata: None,
            },
        )
    }
}
