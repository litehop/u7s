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
        let retry_after = self
            .1
            .details
            .as_ref()
            .and_then(|d| d.get("retryAfterSeconds"))
            .and_then(|v| v.as_u64());
        let mut resp = (self.0, axum::Json(self.1)).into_response();
        if let Some(secs) = retry_after {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, secs.into());
        }
        resp
    }
}

impl Status {
    /// Mirrors upstream `NewNotFound(GroupResource{group, resource}, name)`: message is
    /// `<resource>[.<group>] "<name>" not found`; `details.kind` is the lowercase plural
    /// resource (not the object Kind) and `details.group` is omitted for the core group.
    pub fn not_found(group: &str, resource: &str, name: &str) -> StatusError {
        let qualified = if group.is_empty() {
            resource.to_string()
        } else {
            format!("{resource}.{group}")
        };
        let mut details = serde_json::json!({ "name": name, "kind": resource });
        if !group.is_empty() {
            details["group"] = group.into();
        }
        StatusError(
            StatusCode::NOT_FOUND,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message: format!("{qualified} \"{name}\" not found"),
                reason: "NotFound",
                code: 404,
                metadata: None,
                details: Some(Box::new(details)),
            },
        )
    }

    /// Upstream's response for a request path that names no served resource (no qualified
    /// resource), built by `NewGenericServerResponse(404, ...)`, whose non-nil empty
    /// `Details` serializes as `"details":{}`.
    pub fn route_not_found() -> StatusError {
        StatusError(
            StatusCode::NOT_FOUND,
            Status {
                kind: "Status",
                api_version: "v1",
                status: "Failure",
                message: "the server could not find the requested resource".into(),
                reason: "NotFound",
                code: 404,
                metadata: None,
                details: Some(Box::new(serde_json::json!({}))),
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

    /// A 409 whose `details.causes` carry machine-readable reasons, as server-side apply's
    /// field-manager conflicts do (`FieldManagerConflict`).
    pub fn conflict_with_causes(message: String, causes: Vec<serde_json::Value>) -> StatusError {
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
                details: Some(Box::new(serde_json::json!({ "causes": causes }))),
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

    /// A rejected strategic merge patch: 422 when the patch is well-formed but exceeds the
    /// work budget, 400 for a malformed patch.
    pub fn patch_error(e: crate::patch::PatchError) -> StatusError {
        match e {
            crate::patch::PatchError::TooComplex(_) => Status::unprocessable_entity(e.to_string()),
            _ => Status::bad_request(e.to_string()),
        }
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

    /// Upstream's 422 for failed `ValidatePatchOptions`: one `(field, reason, body)` per
    /// error, aggregated as `[a, b]` when there are several.
    pub fn invalid_patch_options(errs: &[(String, &'static str, String)]) -> StatusError {
        let lines: Vec<String> = errs.iter().map(|(f, _, b)| format!("{f}: {b}")).collect();
        let agg = if lines.len() == 1 {
            lines[0].clone()
        } else {
            format!("[{}]", lines.join(", "))
        };
        let mut e = Status::unprocessable_entity(format!(
            "PatchOptions.meta.k8s.io \"\" is invalid: {agg}"
        ));
        let causes: Vec<_> = errs
            .iter()
            .map(|(field, reason, body)| {
                serde_json::json!({"reason": reason, "message": body, "field": field})
            })
            .collect();
        e.1.details = Some(Box::new(serde_json::json!({
            "group": "meta.k8s.io",
            "kind": "PatchOptions",
            "causes": causes
        })));
        e
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

    /// 429 carrying `details.retryAfterSeconds` (also emitted as a `Retry-After` header),
    /// which client-go's rate-limit backoff honours instead of hammering a saturated server.
    pub fn too_many_requests_retry_after(message: String, retry_after_seconds: u64) -> StatusError {
        let mut err = Self::too_many_requests(message);
        err.1.details = Some(Box::new(
            serde_json::json!({ "retryAfterSeconds": retry_after_seconds }),
        ));
        err
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

    /// NamespaceLifecycle rejection of a create: 404 for a missing namespace, 403 with the
    /// `NamespaceTerminating` cause for one being deleted — the same responses upstream's
    /// admission plugin returns.
    pub fn namespace_create_rejected(
        ns: &str,
        err: &u7s_store::CreateNamespacedError,
    ) -> StatusError {
        if matches!(err, u7s_store::CreateNamespacedError::NamespaceNotFound) {
            return Status::not_found("", "namespaces", ns);
        }
        let mut e = Status::forbidden(format!(
            "unable to create new content in namespace {ns} because it is being terminated"
        ));
        e.1.details = Some(Box::new(serde_json::json!({
            "causes": [{
                "reason": "NamespaceTerminating",
                "message": format!("namespace {ns} is being terminated"),
                "field": "metadata.namespace"
            }]
        })));
        e
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

    // Upstream's NotFound carries details{name, group, kind=lowercase plural resource};
    // clients (kubectl, client-go retries keyed on the missing object) read them instead of
    // parsing the message, so a Kind there ("Widget") would mis-identify the resource.
    #[test]
    fn not_found_carries_name_group_and_plural_kind_details() {
        let StatusError(_, status) = Status::not_found("example.com", "widgets", "web");
        let details = status.details.expect("NotFound must carry details");
        assert_eq!(details["name"], "web");
        assert_eq!(details["kind"], "widgets");
        assert_eq!(details["group"], "example.com");
        assert_eq!(status.message, "widgets.example.com \"web\" not found");
    }

    // Upstream's StatusDetails.Group is `omitempty` and GroupResource.String() drops the dot
    // for the core group: `pods "x" not found`, not `pods. "x" not found`.
    #[test]
    fn not_found_core_group_omits_group_and_dot() {
        let StatusError(_, status) = Status::not_found("", "pods", "x");
        assert_eq!(status.message, "pods \"x\" not found");
        let details = status.details.expect("NotFound must carry details");
        assert!(details.get("group").is_none(), "core group must be omitted");
    }

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
