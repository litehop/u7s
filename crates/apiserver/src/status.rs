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
}

pub struct StatusError(pub StatusCode, pub Status);

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
            },
        )
    }
}
