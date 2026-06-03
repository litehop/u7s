use thiserror::Error;

/// Apply a JSON Merge Patch (RFC 7396) to `target`.
///
/// Rules:
/// - null value → remove key from object (except creationTimestamp which is immutable)
/// - object value → recurse
/// - any other value → overwrite
/// - if patch or target is not an object → replace target with patch clone
pub fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(t), Some(p)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            if v.is_null() {
                if k != "creationTimestamp" {
                    t.remove(k);
                }
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
            if key != "creationTimestamp" {
                target_obj.remove(key);
            }
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
                    strategic_merge_array(entry, value, merge_key, &child_path)?;
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
    path: &str,
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
                let found = key_val
                    .and_then(|kv| target_arr.iter_mut().find(|t| t.get(merge_key) == Some(kv)));

                match found {
                    Some(target_elem) => {
                        // Deep-merge the patch element into the target element.
                        // Pass `path` (the array's own path) so nested lists like env,
                        // volumeMounts, ports resolve their merge keys correctly.
                        strategic_merge_patch_at(target_elem, patch_elem, path)?;
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
        | "spec.template.spec.volumes"
        | "spec.template.spec.imagePullSecrets" => MergeKeyKind::Key("name"),

        "spec.hostAliases" => MergeKeyKind::Key("ip"),

        // Nested list fields inside container objects.
        // These paths are relative to the container object (e.g. spec.containers.env).
        path if path.ends_with(".env")
            || path.ends_with(".initContainers.env")
            || path.ends_with(".ephemeralContainers.env") =>
        {
            MergeKeyKind::Key("name")
        }

        path if path.ends_with(".volumeMounts") => MergeKeyKind::Key("mountPath"),

        // Service spec.ports uses "port" (integer) as the merge key, not "containerPort".
        // This exact match must come before the suffix match below.
        "spec.ports" => MergeKeyKind::Key("port"),

        path if path.ends_with(".ports") => MergeKeyKind::Key("containerPort"),

        // conditions arrays use "type" as the merge key across all resource types
        // (Node, Pod, Deployment, PVC, Job, etc.).  Two paths are needed: "conditions"
        // when called from the /status subresource handler (path root is stripped to ""),
        // and "status.conditions" when patching the full object.
        path if path == "conditions" || path.ends_with(".conditions") => MergeKeyKind::Key("type"),

        // Pod status arrays — merge key used by kubelet strategic-merge-patch.
        // "podIPs" is used when the status patch is applied with path root "" (status
        // subresource handler strips the "status" wrapper before calling SMP).
        // "status.podIPs" covers the rare case of patching the full object.
        // Without these entries, $patch:delete directives on podIPs accumulate as literal
        // objects in the array, causing the kubelet to see phantom podIP changes on every
        // reconcile and continuously recreate the pod sandbox (sandbox loop).
        path if path == "podIPs" || path.ends_with(".podIPs") => MergeKeyKind::Key("ip"),

        path if path == "containerStatuses"
            || path.ends_with(".containerStatuses")
            || path == "initContainerStatuses"
            || path.ends_with(".initContainerStatuses")
            || path == "ephemeralContainerStatuses"
            || path.ends_with(".ephemeralContainerStatuses") =>
        {
            MergeKeyKind::Key("name")
        }

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
        assert!(
            names.contains(&"existing"),
            "original container must survive"
        );
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

    // --- Regression tests for nested list SMP merge (mayor-4c81) ---
    // These tests must FAIL if the path-threading fix is reverted (i.e. if
    // strategic_merge_array is called with "" instead of the array's path).

    #[test]
    fn test_smp_nested_env_survives_partial_patch() {
        // Two containers, each with two env vars.  Patching one env var in one
        // container must leave the untouched env var and the untouched container
        // intact.  Without the path fix, env falls through to last-write-wins
        // and the unpatched var is silently dropped.
        let mut target = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "env": [
                            {"name": "FOO", "value": "foo1"},
                            {"name": "BAR", "value": "bar1"}
                        ]
                    },
                    {
                        "name": "sidecar",
                        "env": [
                            {"name": "X", "value": "x1"},
                            {"name": "Y", "value": "y1"}
                        ]
                    }
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "env": [
                            {"name": "FOO", "value": "foo2"}
                        ]
                    }
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 2, "both containers must survive");

        // app container: FOO updated, BAR must still be present
        let app = containers.iter().find(|c| c["name"] == "app").unwrap();
        let env = app["env"].as_array().unwrap();
        assert_eq!(env.len(), 2, "app must still have two env vars");
        let foo = env.iter().find(|e| e["name"] == "FOO").unwrap();
        assert_eq!(foo["value"], "foo2", "FOO must be updated");
        let bar = env.iter().find(|e| e["name"] == "BAR");
        assert!(bar.is_some(), "BAR must survive the partial env patch");

        // sidecar container must be completely untouched
        let sidecar = containers.iter().find(|c| c["name"] == "sidecar").unwrap();
        let sidecar_env = sidecar["env"].as_array().unwrap();
        assert_eq!(sidecar_env.len(), 2, "sidecar env must be untouched");
    }

    #[test]
    fn test_smp_nested_volume_mounts_survives_partial_patch() {
        // One container with two volumeMounts.  Patching a field on one (matched
        // by mountPath, the volumeMounts merge key) must leave the other
        // volumeMount intact.  Without the path fix, volumeMounts falls through
        // to last-write-wins and the unpatched mount is silently dropped.
        let mut target = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "volumeMounts": [
                            {"mountPath": "/etc/config", "name": "config", "readOnly": false},
                            {"mountPath": "/var/data",   "name": "data",   "readOnly": false}
                        ]
                    }
                ]
            }
        });
        // Patch adds readOnly: true to /etc/config only; /var/data must survive.
        let patch = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "volumeMounts": [
                            {"mountPath": "/etc/config", "name": "config", "readOnly": true}
                        ]
                    }
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        let app = containers.iter().find(|c| c["name"] == "app").unwrap();
        let mounts = app["volumeMounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2, "both volumeMounts must survive");
        let config = mounts
            .iter()
            .find(|m| m["mountPath"] == "/etc/config")
            .unwrap();
        assert_eq!(
            config["readOnly"], true,
            "readOnly must be updated on the patched mount"
        );
        assert!(
            mounts.iter().any(|m| m["mountPath"] == "/var/data"),
            "data volumeMount must survive the partial patch"
        );
    }

    #[test]
    fn test_smp_nested_ports_survives_partial_patch() {
        // One container with two ports.  Patching one containerPort must leave
        // the other port intact.
        let mut target = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "ports": [
                            {"containerPort": 8080, "protocol": "TCP"},
                            {"containerPort": 9090, "protocol": "TCP"}
                        ]
                    }
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "ports": [
                            {"containerPort": 8080, "protocol": "UDP"}
                        ]
                    }
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["containers"].as_array().unwrap();
        let app = containers.iter().find(|c| c["name"] == "app").unwrap();
        let ports = app["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2, "both ports must survive");
        let port8080 = ports.iter().find(|p| p["containerPort"] == 8080).unwrap();
        assert_eq!(
            port8080["protocol"], "UDP",
            "port 8080 protocol must be updated"
        );
        assert!(
            ports.iter().any(|p| p["containerPort"] == 9090),
            "port 9090 must survive the partial patch"
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

    #[test]
    fn test_smp_service_ports_merge_key_is_port_not_container_port() {
        // Service spec.ports uses "port" as the merge key, not "containerPort".
        // Patching targetPort on port 80 must leave port 443 unchanged.
        // Without the explicit "spec.ports" → "port" entry the suffix-match arm
        // maps spec.ports to "containerPort", which finds no match (Service ports
        // have no containerPort field) and appends instead of merging — corrupting
        // the port list.
        let mut target = serde_json::json!({
            "spec": {
                "ports": [
                    {"port": 80,  "protocol": "TCP", "targetPort": 8080},
                    {"port": 443, "protocol": "TCP", "targetPort": 8443}
                ]
            }
        });
        let patch = serde_json::json!({
            "spec": {
                "ports": [
                    {"port": 80, "protocol": "TCP", "targetPort": 9090}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let ports = target["spec"]["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2, "port 443 must survive the partial patch");
        let port80 = ports.iter().find(|p| p["port"] == 80).unwrap();
        assert_eq!(
            port80["targetPort"], 9090,
            "targetPort for port 80 must be updated"
        );
        let port443 = ports.iter().find(|p| p["port"] == 443);
        assert!(port443.is_some(), "port 443 must not be dropped");
        assert_eq!(
            port443.unwrap()["targetPort"],
            8443,
            "port 443 targetPort must be unchanged"
        );
    }

    #[test]
    fn test_smp_conditions_merge_by_type_preserves_status_on_heartbeat() {
        // Kubelet sends a full condition on first write, then a heartbeat-only patch that
        // omits "status", "reason", and "message" for conditions that haven't transitioned.
        // Without "type" as the merge key for conditions, the heartbeat patch replaces the
        // whole array and the "status":"True" field on the Ready condition is lost.
        // The e2e BeforeSuite checks condition.Status == ConditionTrue — if it finds None,
        // all 444 conformance tests are skipped.
        let mut target = json!({
            "status": {
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "KubeletReady",
                        "message": "kubelet is posting ready status",
                        "lastHeartbeatTime": "2026-05-26T05:00:00Z",
                        "lastTransitionTime": "2026-05-26T05:00:00Z"
                    },
                    {
                        "type": "MemoryPressure",
                        "status": "False",
                        "reason": "KubeletHasSufficientMemory",
                        "message": "kubelet has sufficient memory available",
                        "lastHeartbeatTime": "2026-05-26T05:00:00Z",
                        "lastTransitionTime": "2026-05-26T05:00:00Z"
                    }
                ]
            }
        });

        // Heartbeat patch: only updates lastHeartbeatTime, omits status/reason/message.
        let heartbeat_patch = json!({
            "conditions": [
                {"type": "Ready",         "lastHeartbeatTime": "2026-05-26T05:00:10Z"},
                {"type": "MemoryPressure","lastHeartbeatTime": "2026-05-26T05:00:10Z"}
            ]
        });

        // This is called from the /status subresource handler: patch is applied to the
        // stored status object with path root "".
        let status = target["status"].as_object_mut().unwrap();
        let mut status_val = serde_json::Value::Object(status.clone());
        strategic_merge_patch(&mut status_val, &heartbeat_patch).unwrap();
        target["status"] = status_val;

        let conds = target["status"]["conditions"].as_array().unwrap();
        let ready = conds.iter().find(|c| c["type"] == "Ready").unwrap();
        assert_eq!(
            ready["status"], "True",
            "status:True must survive a heartbeat-only patch that omits the status field"
        );
        assert_eq!(
            ready["lastHeartbeatTime"], "2026-05-26T05:00:10Z",
            "lastHeartbeatTime must be updated by the heartbeat patch"
        );
        assert_eq!(
            ready["reason"], "KubeletReady",
            "reason must survive a heartbeat-only patch"
        );

        let mem = conds
            .iter()
            .find(|c| c["type"] == "MemoryPressure")
            .unwrap();
        assert_eq!(
            mem["status"], "False",
            "MemoryPressure status:False must survive a heartbeat-only patch"
        );
    }

    /// $patch:delete on podIPs must remove the matching entry, not store the directive literally.
    ///
    /// Without this fix, a kubelet status patch that includes $patch:delete to remove a
    /// stale podIP entry instead appends the directive object to the array.  On the next
    /// reconcile the kubelet sees a changed podIPs array and continuously recreates the
    /// pod sandbox, killing kube-proxy and any other hostNetwork pod (sandbox loop).
    #[test]
    fn smp_patch_delete_on_pod_ips_removes_entry_not_stores_directive() {
        let mut target = serde_json::json!({
            "status": {
                "podIPs": [
                    {"ip": "10.0.0.1"},
                    {"ip": "10.0.0.2"}
                ]
            }
        });
        // Kubelet sends $patch:delete to remove the stale 10.0.0.1 entry.
        let patch = serde_json::json!({
            "status": {
                "podIPs": [
                    {"ip": "10.0.0.1", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let pod_ips = target["status"]["podIPs"].as_array().unwrap();
        assert_eq!(
            pod_ips.len(),
            1,
            "$patch:delete must remove the matching podIP entry — if both entries survive \
             (or 3 entries are present including the directive object), the kubelet detects \
             phantom podIP changes on every reconcile and recreates the pod sandbox in a loop"
        );
        assert_eq!(
            pod_ips[0]["ip"], "10.0.0.2",
            "10.0.0.2 must survive — only the $patch:delete target (10.0.0.1) must be removed"
        );
        assert!(
            pod_ips.iter().all(|e| e.get("$patch").is_none()),
            "the $patch directive object must not appear as a literal entry in podIPs"
        );
    }

    /// merge_patch must not remove creationTimestamp when the patch includes it as null.
    /// Go client-go serializes v1.Time{} (zero time) as null in JSON; if merge_patch
    /// deleted creationTimestamp on every Event PATCH, the conformance test
    /// (core_events.go:144) would see CreationTimestamp=v1.Time{} instead of the
    /// original timestamp.
    #[test]
    fn merge_patch_preserves_creation_timestamp_when_patched_as_null() {
        let mut target = json!({
            "metadata": {
                "name": "my-event",
                "creationTimestamp": "2026-05-27T02:24:57Z"
            },
            "series": null
        });
        // Simulate what client-go sends: creationTimestamp null (zero time), series set.
        let patch = json!({
            "metadata": {
                "creationTimestamp": null
            },
            "series": {"count": 100, "lastObservedTime": "2017-09-19T13:49:16Z"}
        });

        merge_patch(&mut target, &patch);

        assert_eq!(
            target["metadata"]["creationTimestamp"], "2026-05-27T02:24:57Z",
            "creationTimestamp must not be removed by a null patch: \
             client-go serializes zero time as null but the server-stamped \
             creationTimestamp is immutable"
        );
        assert_eq!(
            target["series"]["count"], 100,
            "series.count must be set by the patch"
        );
        assert_eq!(
            target["series"]["lastObservedTime"], "2017-09-19T13:49:16Z",
            "series.lastObservedTime must be set by the patch"
        );
    }

    /// strategic_merge_patch must not remove creationTimestamp when the patch includes it as null.
    /// Same invariant as for merge_patch: creationTimestamp is immutable and client-go
    /// routinely includes it as null in strategic-merge patches.
    #[test]
    fn strategic_merge_patch_preserves_creation_timestamp_when_patched_as_null() {
        let mut target = json!({
            "metadata": {
                "name": "my-event",
                "creationTimestamp": "2026-05-27T02:24:57Z"
            }
        });
        let patch = json!({
            "metadata": {
                "creationTimestamp": null,
                "labels": {"patched": "yes"}
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        assert_eq!(
            target["metadata"]["creationTimestamp"], "2026-05-27T02:24:57Z",
            "creationTimestamp must not be removed by a null strategic-merge patch: \
             it is immutable and client-go serializes zero time as null"
        );
        assert_eq!(
            target["metadata"]["labels"]["patched"], "yes",
            "other patched fields must be applied"
        );
    }
}
