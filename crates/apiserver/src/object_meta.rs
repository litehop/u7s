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

/// Violations of `meta`'s labels and annotations, reported under `prefix` + `labels` /
/// `annotations` (`metadata.` for an object, `spec.template.` for a pod template).
fn meta_violations(meta: &Value, prefix: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if let Some(labels) = meta["labels"].as_object() {
        let path = format!("{prefix}labels");
        for (k, v) in labels {
            for m in Format::QualifiedName.validate(k) {
                errs.push(invalid(&path, k, &m));
            }
            if let Some(v) = v.as_str() {
                for m in Format::LabelValue.validate(v) {
                    errs.push(invalid(&path, v, &m));
                }
            }
        }
    }
    if let Some(annotations) = meta["annotations"].as_object() {
        let path = format!("{prefix}annotations");
        let mut total = 0usize;
        for (k, v) in annotations {
            total += k.len() + v.as_str().map_or(0, str::len);
            for m in Format::QualifiedName.validate(&k.to_lowercase()) {
                errs.push(invalid(&path, k, &m));
            }
        }
        if total > TOTAL_ANNOTATION_SIZE_LIMIT_B {
            errs.push(format!(
                "{path}: Too long: may not be more than {TOTAL_ANNOTATION_SIZE_LIMIT_B} bytes"
            ));
        }
    }
    errs
}

/// Where a workload kind embeds its pod template, as the JSON path from the object root and
/// upstream's field-path prefix (`ValidatePodTemplateSpec` reports `<path>.labels`).
fn pod_template_location(
    group: &str,
    resource: &str,
) -> Option<(&'static [&'static str], &'static str)> {
    let resource = resource.split('/').next().unwrap_or(resource);
    match (group, resource) {
        ("apps", "deployments" | "replicasets" | "statefulsets" | "daemonsets")
        | ("batch", "jobs")
        | ("", "replicationcontrollers") => Some((&["spec", "template"], "spec.template.")),
        ("batch", "cronjobs") => Some((
            &["spec", "jobTemplate", "spec", "template"],
            "spec.jobTemplate.spec.template.",
        )),
        ("", "podtemplates") => Some((&["template"], "template.")),
        _ => None,
    }
}

/// Violations in upstream's wording, labels before annotations; empty when the object conforms.
/// Workload kinds also have their pod template's labels and annotations checked.
pub(crate) fn metadata_violations(object: &Value, group: &str, resource: &str) -> Vec<String> {
    let mut errs = meta_violations(&object["metadata"], "metadata.");
    if let Some((path, prefix)) = pod_template_location(group, resource) {
        let template = path.iter().fold(object, |v, key| &v[*key]);
        errs.extend(meta_violations(&template["metadata"], prefix));
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
    let errs = metadata_violations(object, ctx.group, ctx.resource);
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
        let errs =
            metadata_violations(&json!({"metadata": {"labels": {"k": v}}}), "", "configmaps");
        assert_eq!(
            errs,
            vec![format!(
                "metadata.labels: Invalid value: \"{v}\": must be no more than 63 characters"
            )]
        );
    }

    #[test]
    fn label_key_must_be_a_qualified_name() {
        let errs = metadata_violations(
            &json!({"metadata": {"labels": {"bad key": "v"}}}),
            "",
            "configmaps",
        );
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
        assert!(metadata_violations(&obj, "", "configmaps").is_empty());
    }

    #[test]
    fn annotation_total_size_over_256kib_is_rejected() {
        let obj =
            json!({"metadata": {"annotations": {"a": "x".repeat(TOTAL_ANNOTATION_SIZE_LIMIT_B)}}});
        assert_eq!(
            metadata_violations(&obj, "", "configmaps"),
            vec!["metadata.annotations: Too long: may not be more than 262144 bytes".to_string()]
        );
    }

    #[test]
    fn annotation_key_with_invalid_chars_is_rejected() {
        let errs = metadata_violations(
            &json!({"metadata": {"annotations": {"a b": "v"}}}),
            "",
            "configmaps",
        );
        assert_eq!(errs.len(), 1, "{errs:?}");
    }
}
