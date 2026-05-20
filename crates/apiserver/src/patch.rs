use thiserror::Error;

/// Apply a JSON Merge Patch (RFC 7396) to `target`.
///
/// Rules:
/// - null value → remove key from object
/// - object value → recurse
/// - any other value → overwrite
/// - if patch or target is not an object → replace target with patch clone
pub fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                t.remove(k);
            } else if v.is_object() {
                let entry = t
                    .entry(k)
                    .or_insert(serde_json::Value::Object(Default::default()));
                merge_patch(entry, v);
            } else {
                t.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}

#[derive(Debug, Error)]
pub enum PatchError {
    #[error("patch is not an object")]
    NotAnObject,
    #[error("invalid $patch directive: {0}")]
    InvalidDirective(String),
}

/// Apply a strategic merge patch to `target`.
///
/// Rules (kubectl-compatible subset):
/// - null value → remove key
/// - known strategic-merge arrays → merge by merge key
/// - replace-only arrays (rules, subjects) and unknown arrays → last-write-wins
/// - objects → recurse
/// - scalars → overwrite
pub fn strategic_merge_patch(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), PatchError> {
    strategic_merge_patch_at(target, patch, "")
}

fn strategic_merge_patch_at(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    path: &str,
) -> Result<(), PatchError> {
    let patch_obj = patch.as_object().ok_or(PatchError::NotAnObject)?;

    // Ensure target is an object; if not, replace with empty object.
    if !target.is_object() {
        *target = serde_json::Value::Object(Default::default());
    }
    let target_obj = target.as_object_mut().unwrap();

    for (key, value) in patch_obj {
        if value.is_null() {
            target_obj.remove(key);
            continue;
        }

        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };

        if value.is_array() {
            match merge_key_for_path(&child_path) {
                MergeKeyKind::Key(merge_key) => {
                    let entry = target_obj
                        .entry(key)
                        .or_insert(serde_json::Value::Array(vec![]));
                    strategic_merge_array(entry, value, merge_key)?;
                }
                MergeKeyKind::Replace | MergeKeyKind::Unknown => {
                    // Last-write-wins: check for $patch:replace directive in elements.
                    if has_replace_directive(value) {
                        // Strip directive elements from patch before storing.
                        let cleaned = strip_directives(value);
                        target_obj.insert(key.clone(), cleaned);
                    } else {
                        target_obj.insert(key.clone(), value.clone());
                    }
                }
            }
        } else if value.is_object() {
            let entry = target_obj
                .entry(key)
                .or_insert(serde_json::Value::Object(Default::default()));
            strategic_merge_patch_at(entry, value, &child_path)?;
        } else {
            target_obj.insert(key.clone(), value.clone());
        }
    }

    Ok(())
}

/// Merge patch array into target array using `merge_key`.
///
/// For each element in patch:
/// - `"$patch": "delete"` → remove matching element from target
/// - `"$patch": "replace"` → replace entire target array with remaining patch elements
/// - otherwise → find matching element in target by merge key and deep-merge, or append
fn strategic_merge_array(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    merge_key: &str,
) -> Result<(), PatchError> {
    let patch_arr = match patch.as_array() {
        Some(a) => a,
        None => return Ok(()),
    };

    // Check for a $patch:replace directive first (any element triggers full replace).
    for elem in patch_arr {
        if let Some(directive) = elem.get("$patch").and_then(|v| v.as_str()) {
            if directive == "replace" {
                // Replace entire array, stripping the directive element(s).
                let cleaned: Vec<serde_json::Value> = patch_arr
                    .iter()
                    .filter(|e| e.get("$patch").is_none())
                    .cloned()
                    .collect();
                *target = serde_json::Value::Array(cleaned);
                return Ok(());
            }
        }
    }

    // Ensure target is an array.
    if !target.is_array() {
        *target = serde_json::Value::Array(vec![]);
    }
    let target_arr = target.as_array_mut().unwrap();

    for patch_elem in patch_arr {
        let directive = patch_elem.get("$patch").and_then(|v| v.as_str());

        match directive {
            Some("delete") => {
                // Remove element with matching merge key from target.
                let key_val = patch_elem.get(merge_key).ok_or_else(|| {
                    PatchError::InvalidDirective(format!(
                        "$patch:delete element missing merge key '{merge_key}'"
                    ))
                })?;
                target_arr.retain(|t| t.get(merge_key) != Some(key_val));
            }
            Some("replace") => {
                // Already handled above; unreachable here but be explicit.
                unreachable!("replace directive should have been handled above");
            }
            Some(other) => {
                return Err(PatchError::InvalidDirective(format!(
                    "unknown $patch directive '{other}'"
                )));
            }
            None => {
                // Normal merge: find by merge key and deep-merge, or append.
                let key_val = patch_elem.get(merge_key);
                let found = key_val.and_then(|kv| {
                    target_arr
                        .iter_mut()
                        .find(|t| t.get(merge_key) == Some(kv))
                });

                match found {
                    Some(target_elem) => {
                        // Deep-merge the patch element into the target element.
                        // We treat both as objects (they must be if they have a merge key).
                        strategic_merge_patch_at(target_elem, patch_elem, "")?;
                    }
                    None => {
                        target_arr.push(patch_elem.clone());
                    }
                }
            }
        }
    }

    Ok(())
}

enum MergeKeyKind {
    /// Array uses this field as the merge key.
    Key(&'static str),
    /// Array has no merge key — always replace.
    Replace,
    /// Not a known strategic-merge path — last-write-wins.
    Unknown,
}

fn merge_key_for_path(path: &str) -> MergeKeyKind {
    match path {
        "spec.containers"
        | "spec.initContainers"
        | "spec.ephemeralContainers"
        | "spec.volumes"
        | "spec.imagePullSecrets"
        | "spec.template.spec.containers"
        | "spec.template.spec.initContainers"
        | "spec.template.spec.volumes" => MergeKeyKind::Key("name"),

        "spec.hostAliases" => MergeKeyKind::Key("ip"),

        "rules" | "subjects" => MergeKeyKind::Replace,

        _ => MergeKeyKind::Unknown,
    }
}

fn has_replace_directive(arr: &serde_json::Value) -> bool {
    arr.as_array().is_some_and(|a| {
        a.iter()
            .any(|e| e.get("$patch").and_then(|v| v.as_str()) == Some("replace"))
    })
}

fn strip_directives(arr: &serde_json::Value) -> serde_json::Value {
    match arr.as_array() {
        Some(a) => serde_json::Value::Array(
            a.iter()
                .filter(|e| e.get("$patch").is_none())
                .cloned()
                .collect(),
        ),
        None => arr.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_smp_container_merge() {
        // Patching adds a new container; existing container must be preserved.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "existing", "image": "nginx:1.0"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "sidecar", "image": "sidecar:latest"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 2, "both containers must be present");
        let names: Vec<&str> = containers
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"existing"), "original container must survive");
        assert!(names.contains(&"sidecar"), "new container must be added");
    }

    #[test]
    fn test_smp_container_delete() {
        // $patch:delete removes a named container; others are untouched.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "keep", "image": "nginx"},
                    {"name": "remove-me", "image": "old"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "remove-me", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1, "only one container should remain");
        assert_eq!(
            containers[0]["name"].as_str().unwrap(),
            "keep",
            "the wrong container was removed"
        );
    }

    #[test]
    fn test_smp_null_removes_key() {
        // null in a patch object means "delete that key".
        let mut target = json!({
            "metadata": {
                "labels": {"app": "myapp", "env": "prod"},
                "name": "mypod"
            }
        });
        let patch = json!({
            "metadata": {
                "labels": {"env": null}
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        assert!(
            target["metadata"]["labels"].get("env").is_none(),
            "null patch must remove the key"
        );
        assert_eq!(
            target["metadata"]["labels"]["app"].as_str().unwrap(),
            "myapp",
            "sibling key must be untouched"
        );
    }

    #[test]
    fn test_smp_non_strategic_array_replaces() {
        // An array not in the merge key table is fully replaced (last-write-wins).
        let mut target = json!({
            "spec": {
                "tolerations": [
                    {"key": "old", "effect": "NoSchedule"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "tolerations": [
                    {"key": "new", "effect": "NoExecute"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let tolerations = target["spec"]["tolerations"].as_array().unwrap();
        assert_eq!(
            tolerations.len(),
            1,
            "non-strategic array must be fully replaced"
        );
        assert_eq!(
            tolerations[0]["key"].as_str().unwrap(),
            "new",
            "replacement element must be the patch value"
        );
    }

    #[test]
    fn test_smp_multiple_patch_delete() {
        // A patch with two $patch:delete elements must delete both matching elements.
        // This matters because each delete is processed independently in a loop; if the
        // loop short-circuits or skips after the first delete the second target survives.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "alpha", "image": "a:1"},
                    {"name": "beta",  "image": "b:1"},
                    {"name": "gamma", "image": "g:1"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "alpha", "$patch": "delete"},
                    {"name": "gamma", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1, "both deleted containers must be gone");
        assert_eq!(
            containers[0]["name"].as_str().unwrap(),
            "beta",
            "non-deleted container must survive"
        );
    }

    #[test]
    fn test_smp_patch_replace_directive() {
        // A patch containing $patch:replace replaces the entire array with the remaining
        // non-directive elements. Existing containers are discarded entirely; the directive
        // element itself must not appear in the result.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "old-a", "image": "a:1"},
                    {"name": "old-b", "image": "b:1"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"$patch": "replace"},
                    {"name": "new-only", "image": "n:1"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers.len(),
            1,
            "$patch:replace must discard old containers and yield exactly the non-directive elements"
        );
        assert_eq!(
            containers[0]["name"].as_str().unwrap(),
            "new-only",
            "only the non-directive patch element must remain"
        );
        assert!(
            containers.iter().all(|c| c.get("$patch").is_none()),
            "directive element must not appear in the result array"
        );
    }

    #[test]
    fn test_smp_element_without_merge_key_is_appended() {
        // A normal patch element (no $patch directive) that lacks the merge key cannot
        // match any existing element, so it must be appended.  If the code ever changes
        // to error-out instead, this test will catch it.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "existing", "image": "e:1"}
                ]
            }
        });
        // Patch element has no "name" field — the merge key for spec.containers.
        let patch = json!({
            "spec": {
                "containers": [
                    {"image": "no-name:1"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers.len(),
            2,
            "element without a merge key must be appended, not dropped or merged"
        );
        assert_eq!(
            containers[1]["image"].as_str().unwrap(),
            "no-name:1",
            "the appended element must be the patch element as-is"
        );
    }

    #[test]
    fn test_smp_patch_delete_with_empty_merge_key_value() {
        // $patch:delete where the merge key is present but set to "" (empty string).
        // The code matches by value equality, so it removes elements whose merge key
        // is exactly "".  Elements with a non-empty merge key must be untouched.
        let mut target = json!({
            "spec": {
                "containers": [
                    {"name": "",      "image": "unnamed:1"},
                    {"name": "real",  "image": "real:1"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {"name": "", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers.len(),
            1,
            "element with empty merge key value must be deleted"
        );
        assert_eq!(
            containers[0]["name"].as_str().unwrap(),
            "real",
            "element with non-empty merge key must be untouched"
        );
    }
}
