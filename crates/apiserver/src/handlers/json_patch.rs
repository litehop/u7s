use axum::http::HeaderMap;

use crate::{status::Status, util::content_type};

/// Patch Content-Type variants understood by all patch endpoints.
#[derive(Debug)]
pub(crate) enum PatchType {
    Merge,
    StrategicMerge,
    Json,
}

pub(crate) fn detect_patch_type(
    headers: &HeaderMap,
) -> Result<PatchType, crate::status::StatusError> {
    let ct = content_type(headers);
    if ct.contains("application/strategic-merge-patch+json") {
        return Ok(PatchType::StrategicMerge);
    }
    if ct.contains("application/merge-patch+json") {
        return Ok(PatchType::Merge);
    }
    if ct.contains("application/json-patch+json") {
        return Ok(PatchType::Json);
    }
    // Treat server-side apply as strategic-merge-patch: we don't implement full SSA
    // semantics (field ownership, managed fields), but the apply body is structurally
    // identical to a strategic-merge-patch body.  This is sufficient for kubelet's
    // Lease and CSINode use cases; without this kubelet gets 415 and logs
    // "invalid JSON: expected value at line 1 column 1".
    if ct.contains("application/apply-patch+yaml") {
        return Ok(PatchType::StrategicMerge);
    }
    Err(Status::unsupported_media_type(format!(
        "unsupported media type '{ct}'; use application/merge-patch+json, application/strategic-merge-patch+json, or application/json-patch+json"
    )))
}

/// Apply a JSON Patch (RFC 6902) to `obj`.
/// Supports `add`, `remove`, and `replace` operations.
/// Returns Err(422) for unsupported operations or invalid paths.
pub(crate) fn apply_json_patch(
    obj: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let ops = patch.as_array().ok_or_else(|| {
        Status::unprocessable_entity("JSON patch must be an array of operations".into())
    })?;

    for op in ops {
        let op_str = op["op"].as_str().ok_or_else(|| {
            Status::unprocessable_entity("each JSON patch operation must have an 'op' field".into())
        })?;
        let path = op["path"].as_str().ok_or_else(|| {
            Status::unprocessable_entity(
                "each JSON patch operation must have a 'path' field".into(),
            )
        })?;

        match op_str {
            "add" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'add' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // RFC 6902 §4.1: 'add' creates intermediate objects when missing.
                json_patch_add(obj, path, value)?;
            }
            "replace" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| {
                        Status::unprocessable_entity(
                            "'replace' operation requires a 'value' field".into(),
                        )
                    })?
                    .clone();
                // 'replace' is strict: 422 if path does not exist.
                json_patch_set(obj, path, value)?;
            }
            "remove" => {
                json_patch_remove(obj, path)?;
            }
            other => {
                return Err(Status::unprocessable_entity(format!(
                    "unsupported JSON patch operation '{other}'; supported: add, remove, replace"
                )));
            }
        }
    }
    Ok(())
}

/// Parse a JSON Pointer (RFC 6901) into path segments.
pub(crate) fn json_pointer_segments(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return vec![];
    }
    // Leading '/' is required for non-empty pointers; skip it.
    let stripped = pointer.strip_prefix('/').unwrap_or(pointer);
    stripped
        .split('/')
        .map(|seg| seg.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Navigate to the parent of the target, returning a mutable ref to the parent and the final key.
pub(crate) fn json_patch_navigate_mut<'a>(
    obj: &'a mut serde_json::Value,
    segments: &[String],
) -> Result<(&'a mut serde_json::Value, String), crate::status::StatusError> {
    if segments.is_empty() {
        return Err(Status::unprocessable_entity(
            "cannot operate on root document".into(),
        ));
    }
    let (parents, last) = segments.split_at(segments.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one(cur, seg)?;
    }
    Ok((cur, last[0].clone()))
}

pub(crate) fn json_navigate_one<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => map
            .get_mut(seg)
            .ok_or_else(|| Status::unprocessable_entity(format!("path segment '{seg}' not found"))),
        serde_json::Value::Array(arr) => {
            let idx: usize = seg.parse().map_err(|_| {
                Status::unprocessable_entity(format!(
                    "path segment '{seg}' is not a valid array index"
                ))
            })?;
            arr.get_mut(idx).ok_or_else(|| {
                Status::unprocessable_entity(format!("array index {idx} out of bounds"))
            })
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot traverse into non-object/array at segment '{seg}'"
        ))),
    }
}

/// Navigate to a child, creating an empty object if the key is absent.
/// Used by `json_patch_add` to satisfy RFC 6902 §4.1 intermediate-creation semantics.
pub(crate) fn json_navigate_one_or_create<'a>(
    node: &'a mut serde_json::Value,
    seg: &str,
) -> Result<&'a mut serde_json::Value, crate::status::StatusError> {
    match node {
        serde_json::Value::Object(map) => {
            map.entry(seg)
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            Ok(map.get_mut(seg).unwrap())
        }
        _ => Err(Status::unprocessable_entity(format!(
            "cannot create intermediate key '{seg}' in non-object"
        ))),
    }
}

/// Apply RFC 6902 'add': navigate parents creating missing objects, then insert.
pub(crate) fn json_patch_add(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parents, last) = segs.split_at(segs.len() - 1);
    let mut cur = obj;
    for seg in parents {
        cur = json_navigate_one_or_create(cur, seg)?;
    }
    let key = &last[0];
    match cur {
        serde_json::Value::Object(map) => {
            map.insert(key.clone(), value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot add value to non-object/array".into(),
            ))
        }
    }
    Ok(())
}

pub(crate) fn json_patch_set(
    obj: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    if segs.is_empty() {
        *obj = value;
        return Ok(());
    }
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(key, value);
        }
        serde_json::Value::Array(arr) => {
            if key == "-" {
                arr.push(value);
            } else {
                let idx: usize = key.parse().map_err(|_| {
                    Status::unprocessable_entity(format!("invalid array index '{key}'"))
                })?;
                if idx <= arr.len() {
                    arr.insert(idx, value);
                } else {
                    return Err(Status::unprocessable_entity(format!(
                        "array index {idx} out of bounds (len {})",
                        arr.len()
                    )));
                }
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot set value on non-object/array".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn json_patch_remove(
    obj: &mut serde_json::Value,
    pointer: &str,
) -> Result<(), crate::status::StatusError> {
    let segs = json_pointer_segments(pointer);
    let (parent, key) = json_patch_navigate_mut(obj, &segs)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.remove(&key).ok_or_else(|| {
                Status::unprocessable_entity(format!("path '{pointer}' not found"))
            })?;
        }
        serde_json::Value::Array(arr) => {
            let idx: usize = key.parse().map_err(|_| {
                Status::unprocessable_entity(format!("invalid array index '{key}'"))
            })?;
            if idx < arr.len() {
                arr.remove(idx);
            } else {
                return Err(Status::unprocessable_entity(format!(
                    "array index {idx} out of bounds"
                )));
            }
        }
        _ => {
            return Err(Status::unprocessable_entity(
                "cannot remove from non-object/array".into(),
            ));
        }
    }
    Ok(())
}
