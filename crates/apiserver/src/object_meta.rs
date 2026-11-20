//! `metadata.labels` and `metadata.annotations` validation, matching apimachinery's
//! `ValidateLabels` / `ValidateAnnotations`.

use serde_json::Value;

use crate::admission::AdmissionContext;
use crate::cel_runtime::format::Format;
use crate::status::{Status, StatusError};

const TOTAL_ANNOTATION_SIZE_LIMIT_B: usize = 256 * (1 << 10);

fn invalid(path: &str, value: &str, msg: &str) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    format!("{path}: Invalid value: {quoted}: {msg}")
}

/// Violations in upstream's wording, labels before annotations; empty when the object conforms.
pub(crate) fn metadata_violations(object: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    if let Some(labels) = object["metadata"]["labels"].as_object() {
        for (k, v) in labels {
            for m in Format::QualifiedName.validate(k) {
                errs.push(invalid("metadata.labels", k, &m));
            }
            if let Some(v) = v.as_str() {
                for m in Format::LabelValue.validate(v) {
                    errs.push(invalid("metadata.labels", v, &m));
                }
            }
        }
    }
    if let Some(annotations) = object["metadata"]["annotations"].as_object() {
        let mut total = 0usize;
        for (k, v) in annotations {
            total += k.len() + v.as_str().map_or(0, str::len);
            for m in Format::QualifiedName.validate(&k.to_lowercase()) {
                errs.push(invalid("metadata.annotations", k, &m));
            }
        }
        if total > TOTAL_ANNOTATION_SIZE_LIMIT_B {
            errs.push(format!(
                "metadata.annotations: Too long: may not be more than {TOTAL_ANNOTATION_SIZE_LIMIT_B} bytes"
            ));
        }
    }
    errs
}

/// Rejects a CREATE/UPDATE body whose labels or annotations upstream's `ValidateObjectMeta`
/// would refuse. Every write path reaches this through the validating admission chain, so no
/// kind (built-in, CRD instance, Node) or verb (PUT, PATCH, apply, subresource) can store
/// a label the kubelet or a selector could never round-trip.
pub(crate) fn validate_write(
    ctx: &AdmissionContext<'_>,
    object: &Value,
) -> Result<(), StatusError> {
    if ctx.operation != "CREATE" && ctx.operation != "UPDATE" {
        return Ok(());
    }
    let errs = metadata_violations(object);
    if errs.is_empty() {
        return Ok(());
    }
    let kind = object["kind"].as_str().unwrap_or(ctx.resource);
    let kind = if ctx.group.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}.{}", ctx.group)
    };
    let name = object["metadata"]["name"].as_str().unwrap_or(ctx.name);
    let detail = match errs.as_slice() {
        [only] => only.clone(),
        _ => format!("[{}]", errs.join(", ")),
    };
    Err(Status::unprocessable_entity(format!(
        "{kind} \"{name}\" is invalid: {detail}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn label_value_over_63_chars_is_rejected_like_upstream() {
        let v = "a".repeat(64);
        let errs = metadata_violations(&json!({"metadata": {"labels": {"k": v}}}));
        assert_eq!(
            errs,
            vec![format!(
                "metadata.labels: Invalid value: \"{v}\": must be no more than 63 characters"
            )]
        );
    }

    #[test]
    fn label_key_must_be_a_qualified_name() {
        let errs = metadata_violations(&json!({"metadata": {"labels": {"bad key": "v"}}}));
        assert_eq!(errs.len(), 1);
        assert!(
            errs[0].starts_with("metadata.labels: Invalid value: \"bad key\": name part must"),
            "{errs:?}"
        );
    }

    #[test]
    fn conforming_labels_and_mixed_case_annotation_keys_pass() {
        let obj = json!({"metadata": {
            "labels": {"app.kubernetes.io/name": "x-1", "empty": ""},
            "annotations": {"Example.COM/Mixed": "anything at all"},
        }});
        assert!(metadata_violations(&obj).is_empty());
    }

    #[test]
    fn annotation_total_size_over_256kib_is_rejected() {
        let obj =
            json!({"metadata": {"annotations": {"a": "x".repeat(TOTAL_ANNOTATION_SIZE_LIMIT_B)}}});
        assert_eq!(
            metadata_violations(&obj),
            vec!["metadata.annotations: Too long: may not be more than 262144 bytes".to_string()]
        );
    }

    #[test]
    fn annotation_key_with_invalid_chars_is_rejected() {
        let errs = metadata_violations(&json!({"metadata": {"annotations": {"a b": "v"}}}));
        assert_eq!(errs.len(), 1, "{errs:?}");
    }
}
