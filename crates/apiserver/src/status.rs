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
    /// Optional `status.details` (e.g. `causes`), used by callers that must set a
    /// machine-readable cause client-go can match on (e.g. `errors.HasStatusCause`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Box<serde_json::Value>>,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
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
                details: None,
            },
        )
    }

    /// 429 with a `status.details.causes[]` entry, so client-go's
    /// `apierrors.HasStatusCause(err, cause_reason)` can match on it. Used by pod eviction
    /// to signal `DisruptionBudget` as the cause (matches upstream's eviction REST handler) —
    /// `kubectl drain` and the conformance suite both check this cause, not just the HTTP code.
    pub fn too_many_requests_with_cause(
        message: String,
        cause_reason: &str,
        cause_message: String,
    ) -> StatusError {
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
                details: Some(Box::new(serde_json::json!({
                    "causes": [{"reason": cause_reason, "message": cause_message}]
                }))),
            },
        )
    }

    pub fn not_acceptable(message: String) -> StatusError {
        StatusError(
            StatusCode::NOT_ACCEPTABLE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "NotAcceptable",
                code: 406,
                metadata: None,
                details: None,
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
                details: None,
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
                details: None,
            },
        )
    }

    pub fn gateway_timeout(message: String) -> StatusError {
        StatusError(
            StatusCode::GATEWAY_TIMEOUT,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Timeout",
                code: 504,
                metadata: None,
                details: None,
            },
        )
    }

    /// 410 Gone — the resource existed but was permanently deleted.
    ///
    /// Informers (client-go reflector) distinguish 410 Gone from 404 Not Found:
    /// 410 means "stop retrying, this endpoint is gone"; 404 is treated as a
    /// transient error and retried with exponential backoff indefinitely.
    pub fn gone(message: String) -> StatusError {
        StatusError(
            StatusCode::GONE,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message,
                reason: "Gone",
                code: 410,
                metadata: None,
                details: None,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    // not_acceptable must produce HTTP 406 with reason "NotAcceptable" so client-go's
    // errors.IsNotAcceptable() returns true and the conformance test for Table 406 passes.
    #[test]
    fn not_acceptable_produces_406_with_correct_reason() {
        let StatusError(http_code, status) = Status::not_acceptable("test message".into());
        assert_eq!(
            http_code,
            StatusCode::NOT_ACCEPTABLE,
            "HTTP status must be 406 so client-go recognises Not Acceptable"
        );
        assert_eq!(
            status.code, 406,
            "Status.code must be 406 so Status().Code in conformance test equals int32(406)"
        );
        assert_eq!(
            status.reason, "NotAcceptable",
            "reason must be NotAcceptable so errors.IsNotAcceptable() returns true"
        );
    }
}
