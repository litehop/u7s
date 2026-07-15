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
        // `$deleteFromPrimitiveList/<field>` removes listed elements from a primitive
        // (non-object) array such as metadata.finalizers, which has no merge key to match
        // elements by. KCM's Job controller removes the batch.kubernetes.io/job-tracking
        // finalizer this way (removeTrackingFinalizerPatch); without this directive the
        // key falls through to "unknown array" handling and is stored as a literal garbage
        // sibling field, so the finalizer is never actually removed and the evicted pod
        // stays Terminating forever — the Job's pod-failure-policy e2e test then times out
        // waiting for the pod to be deleted.
        if let Some(field) = key.strip_prefix("$deleteFromPrimitiveList/") {
            if let Some(to_remove) = value.as_array() {
                if let Some(target_arr) = target_obj.get_mut(field).and_then(|v| v.as_array_mut()) {
                    target_arr.retain(|elem| !to_remove.contains(elem));
                }
            }
            continue;
        }

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
                    // $patch:delete can only be honored by matching a merge key; an array
                    // with no registered merge key has no way to identify which element to
                    // remove. Fail loud instead of storing the directive object literally
                    // (which would corrupt the array with a garbage {$patch:delete,...} entry).
                    if has_delete_directive(value) {
                        return Err(PatchError::InvalidDirective(format!(
                            "$patch:delete on '{child_path}' but no merge key is registered \
                             for this path — cannot identify which element to delete"
                        )));
                    }
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
            if should_replace_object(&child_path) {
                target_obj.insert(key.clone(), value.clone());
            } else {
                let entry = target_obj
                    .entry(key)
                    .or_insert(serde_json::Value::Object(Default::default()));
                strategic_merge_patch_at(entry, value, &child_path)?;
            }
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
    // Snapshot the pre-patch order: needed after the merge loop below to replicate
    // upstream's element-ordering rule (see reorder_merged_array).
    let original: Vec<serde_json::Value> = target.as_array().unwrap().clone();
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

    reorder_merged_array(target, &original, patch_arr, merge_key);

    Ok(())
}

/// Reorder a just-merged strategic-merge-patch array to match upstream ordering semantics
/// (`mergeSortedSlice` in k8s.io/apimachinery/pkg/util/strategicpatch/patch.go).
///
/// A merge-key array is split into "server-only" elements (untouched — their merge key
/// isn't referenced anywhere in the patch) and "patch" elements (matched-and-merged, or
/// brand new). Upstream interleaves the two using each element's position in the
/// PRE-patch array as the comparison key. A brand-new patch element has no pre-patch
/// position, so the comparison can't place it relative to a not-yet-placed server-only
/// element — upstream resolves that ambiguity by emitting the patch element immediately,
/// i.e. brand-new elements land ahead of whatever untouched elements remain, not appended
/// at the end.
///
/// Without this, a StrategicMergePatch that adds a container whose name doesn't match any
/// existing container (e.g. the StatefulSet "list, patch and delete a collection" e2e test,
/// which patches in a container named after the StatefulSet rather than the fixture's
/// "webserver" container) lands the new container at index 1 instead of index 0, so
/// `Containers[0].Image` still reads the OLD image and the test's post-patch assertion
/// fails immediately — no controller or watch behavior involved, purely a patch-storage bug.
fn reorder_merged_array(
    target: &mut serde_json::Value,
    original: &[serde_json::Value],
    patch_arr: &[serde_json::Value],
    merge_key: &str,
) {
    let key_of = |v: &serde_json::Value| v.get(merge_key).cloned();

    // Only patch elements that carry the merge key participate in ordering; an element
    // missing the merge key can't be matched against anything, so it keeps the
    // append-at-the-end placement it got from the merge loop above.
    let patch_keys: Vec<serde_json::Value> = patch_arr
        .iter()
        .filter(|e| e.get("$patch").is_none())
        .filter_map(key_of)
        .collect();

    let merged = target.as_array().unwrap().clone();
    let (keyed, keyless): (Vec<_>, Vec<_>) = merged.into_iter().partition(|v| key_of(v).is_some());

    let (mut patch_items, mut server_only): (Vec<_>, Vec<_>) = keyed
        .into_iter()
        .partition(|v| patch_keys.contains(&key_of(v).unwrap()));

    // patch_items must appear in the order they were given in the raw patch.
    patch_items.sort_by_key(|v| {
        let k = key_of(v).unwrap();
        patch_keys
            .iter()
            .position(|pk| *pk == k)
            .unwrap_or(usize::MAX)
    });
    let original_index = |v: &serde_json::Value| {
        key_of(v).and_then(|k| original.iter().position(|o| key_of(o).as_ref() == Some(&k)))
    };
    // server_only elements always existed pre-patch, so this is always Some(_) in
    // practice; unwrap_or is defensive only.
    server_only.sort_by_key(|v| original_index(v).unwrap_or(usize::MAX));

    let mut result = Vec::with_capacity(server_only.len() + patch_items.len() + keyless.len());
    let (mut i, mut j) = (0, 0);
    while i < server_only.len() || j < patch_items.len() {
        if i >= server_only.len() {
            result.push(patch_items[j].clone());
            j += 1;
        } else if j >= patch_items.len() {
            result.push(server_only[i].clone());
            i += 1;
        } else {
            // Take the server-only element only if it demonstrably preceded the patch
            // element pre-patch; a brand-new patch element (no original position) always
            // loses this comparison, so it's emitted next instead.
            let take_left = matches!(
                (original_index(&server_only[i]), original_index(&patch_items[j])),
                (Some(l), Some(r)) if l < r
            );
            if take_left {
                result.push(server_only[i].clone());
                i += 1;
            } else {
                result.push(patch_items[j].clone());
                j += 1;
            }
        }
    }
    result.extend(keyless);
    *target = serde_json::Value::Array(result);
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
        | "spec.schedulingGates"
        | "spec.resourceClaims"
        | "spec.template.spec.containers"
        | "spec.template.spec.initContainers"
        | "spec.template.spec.volumes"
        | "spec.template.spec.imagePullSecrets"
        | "spec.template.spec.schedulingGates"
        | "spec.template.spec.resourceClaims" => MergeKeyKind::Key("name"),

        // topologySpreadConstraints — upstream patchMergeKey is "topologyKey" (singular;
        // the second +listMapKey=whenUnsatisfiable doc annotation is only a composite-key
        // hint for OpenAPI list-map validation, not a second real merge key: the Go struct
        // has exactly one `patchMergeKey:"topologyKey"` tag). Without this, a
        // strategic-merge-patch that adds one constraint (e.g. a GitOps tool layering a
        // zone-spread on top of an existing hostname-spread) falls through to
        // MergeKeyKind::Unknown, which silently replaces the whole array instead of
        // merging by topologyKey — losing every pre-existing constraint.
        "spec.topologySpreadConstraints" | "spec.template.spec.topologySpreadConstraints" => {
            MergeKeyKind::Key("topologyKey")
        }

        // hostAliases inside a Pod template (Deployment/StatefulSet/DaemonSet/Job) — same
        // silent-whole-array-replace bug as topologySpreadConstraints above: only the bare
        // "spec.hostAliases" path was registered, so patching a Deployment's
        // spec.template.spec.hostAliases to add one entry dropped every other hostAlias in
        // the template.
        "spec.hostAliases" | "spec.template.spec.hostAliases" => MergeKeyKind::Key("ip"),

        // Nested list fields inside container objects.
        // These paths are relative to the container object (e.g. spec.containers.env).
        path if path.ends_with(".env")
            || path.ends_with(".initContainers.env")
            || path.ends_with(".ephemeralContainers.env") =>
        {
            MergeKeyKind::Key("name")
        }

        path if path.ends_with(".volumeMounts") => MergeKeyKind::Key("mountPath"),

        // volumeDevices — same nested-inside-container shape as volumeMounts above
        // (Container.volumeDevices and EphemeralContainerCommon.volumeDevices both declare
        // patchMergeKey=devicePath/patchStrategy=merge upstream). Without this entry, a
        // strategic-merge-patch adding one block device to a container that already has
        // volumeDevices entries silently replaces the whole array instead of merging by
        // devicePath, dropping every other device mapping.
        path if path.ends_with(".volumeDevices") => MergeKeyKind::Key("devicePath"),

        // allocatedResourcesStatus is nested inside a containerStatuses element (same shape
        // as volumeMounts/env above, but for ContainerStatus rather than Container). Upstream
        // declares patchMergeKey=name/patchStrategy=merge; without this entry a kubelet status
        // patch reporting a new allocated-resource health entry silently replaces the whole
        // array instead of merging by name.
        path if path.ends_with(".allocatedResourcesStatus") => MergeKeyKind::Key("name"),

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

        // resourceClaimStatuses — same top-level-PodStatus shape as podIPs above (DRA claim
        // allocation results the kubelet reports back). Upstream declares
        // patchMergeKey=name/patchStrategy=merge,retainKeys; without this entry a
        // $patch:delete removing one claim's status returns 400 instead of removing just
        // that entry.
        path if path == "resourceClaimStatuses" || path.ends_with(".resourceClaimStatuses") => {
            MergeKeyKind::Key("name")
        }

        // NodeStatus.addresses — upstream declares patchMergeKey=type/patchStrategy=merge, but
        // unlike podIPs' "ip", "type" is not safely unique here (upstream's own comment on this
        // field warns the merge key "is not sufficiently unique, which can cause data
        // corruption when merged"). This also can't be a generic ".addresses" suffix arm: a
        // different array, core/v1 Endpoints' EndpointSubset.addresses, shares the field name
        // "addresses" but has NO merge-key annotation (must stay whole-array-replace) — a
        // suffix arm would silently start "merging" EndpointSubset.addresses by a "type" field
        // those elements don't even have, turning every subsequent patch into an
        // accumulate-only append that never removes stale endpoints. Two literal paths only:
        // "addresses" (the /status subresource handler, path root stripped to "") and
        // "status.addresses" (a full Node-object patch, computed transiently before the
        // main-endpoint handler restores the stored status — see handlers::resource's
        // has_status_subresource restore step).
        "addresses" | "status.addresses" => MergeKeyKind::Key("type"),

        // ownerReferences is keyed by uid.  KCM releases a pod from a ReplicaSet/RC by
        // sending $patch:delete with the RS uid; without this entry the directive is stored
        // literally, leaving a garbage ownerReference {$patch:delete, uid:…} that causes
        // controllers and GC to dereference a nil .Controller field and panic.
        path if path == "metadata.ownerReferences" || path.ends_with(".ownerReferences") => {
            MergeKeyKind::Key("uid")
        }

        path if path == "containerStatuses"
            || path.ends_with(".containerStatuses")
            || path == "initContainerStatuses"
            || path.ends_with(".initContainerStatuses")
            || path == "ephemeralContainerStatuses"
            || path.ends_with(".ephemeralContainerStatuses") =>
        {
            MergeKeyKind::Key("name")
        }

        // ServiceAccount.secrets is a top-level field directly on the object (ServiceAccount
        // has no spec/status wrapper), so PATCHing a ServiceAccount always produces the bare
        // "secrets" path (root path is "" for a main-resource PATCH). Upstream declares
        // patchMergeKey=name/patchStrategy=merge; without this entry a strategic-merge-patch
        // adding a second secret reference silently replaces the whole list.
        "secrets" => MergeKeyKind::Key("name"),

        // CSINodeSpec.drivers is the only "drivers" field across the vendored API surface
        // (verified: no other message declares a `drivers` field), so a suffix arm can't
        // collide with anything else. Upstream declares patchMergeKey=name/patchStrategy=merge;
        // without this entry, installing a second CSI driver on a Node silently replaces the
        // whole CSINode.spec.drivers array instead of merging by name, unregistering every
        // other already-installed CSI driver on that node.
        path if path.ends_with(".drivers") => MergeKeyKind::Key("name"),

        // matchConditions is declared patchMergeKey=name/patchStrategy=merge on all four
        // messages that carry it (MutatingWebhook, ValidatingWebhook, and both
        // {Mutating,Validating}AdmissionPolicySpec) — all four agree on the same key, so one
        // suffix arm covers every declaring message with no cross-message collision (unlike
        // variables below). It's reached as "webhooks.matchConditions" for the two Webhook
        // messages (one level inside the "webhooks" array — see that entry below) and as
        // "spec.matchConditions" for the two AdmissionPolicySpec messages (a direct child of
        // spec, no array wrapper). Without this entry, adding one match condition to an
        // existing webhook or admission policy silently replaces the whole array instead of
        // merging by name, dropping every other match condition that gates when it applies.
        path if path.ends_with(".matchConditions") => MergeKeyKind::Key("name"),

        // {Mutating,Validating}WebhookConfiguration.webhooks — the .proto token is spelled
        // capitalized "Webhooks", but admissionreg_gen_adapter.rs's
        // decode_{mutating,validating}webhookconfiguration_proto_gen constructs the real JSON
        // key lowercase ("webhooks": webhooks); an entry keyed on the proto spelling would
        // never match real traffic. Both configuration kinds have no spec/status wrapper (the
        // same top-level shape as ServiceAccount.secrets above), so "webhooks" is always the
        // bare path on a full-object patch. Without this entry, re-applying a webhook config
        // that only changes one entry's .rules silently drops clientConfig, failurePolicy,
        // admissionReviewVersions, and sideEffects from that entry — leaving the webhook
        // registered but unusable, since invoke_mutating_webhook/run_validating_webhooks can't
        // resolve a dispatch target without clientConfig.
        "webhooks" => MergeKeyKind::Key("name"),

        "rules" | "subjects" => MergeKeyKind::Replace,

        _ => MergeKeyKind::Unknown,
    }
}

/// Returns true for object-valued fields that must be replaced wholesale rather than
/// deep-merged. ContainerStatus.state is a discriminated union (exactly one of waiting,
/// running, or terminated is set); merging the patch into the existing object would leave
/// stale sibling keys (e.g. both "running" and "waiting" present simultaneously), which
/// breaks sonobuoy's aggregator readiness check and any other consumer that inspects state.
fn should_replace_object(path: &str) -> bool {
    // state under any containerStatuses element, e.g.:
    //   "containerStatuses.state", "initContainerStatuses.state", "ephemeralContainerStatuses.state"
    // The path uses "." as separator and each segment after the array merge is relative
    // to the element, so the path looks like "<prefix>.state" where prefix ends with
    // one of the status array names.
    path.ends_with(".state")
        && (path.contains("containerStatuses")
            || path.contains("initContainerStatuses")
            || path.contains("ephemeralContainerStatuses"))
}

fn has_delete_directive(arr: &serde_json::Value) -> bool {
    arr.as_array().is_some_and(|a| {
        a.iter()
            .any(|e| e.get("$patch").and_then(|v| v.as_str()) == Some("delete"))
    })
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

    /// StatefulSet "list, patch and delete a collection" conformance test patches in a
    /// container named after the StatefulSet (not the fixture's "webserver" container),
    /// then immediately asserts `Containers[0].Image` is the patched image. Upstream's
    /// strategic-merge-patch places an unmatched (brand-new) patch element ahead of
    /// untouched elements it wasn't compared against, so the new container must land at
    /// index 0 — not appended at the end, which would leave index 0 holding the stale
    /// image and fail the test immediately after the patch, before any controller runs.
    #[test]
    fn test_smp_unmatched_container_lands_before_untouched_container() {
        let mut target = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "webserver", "image": "agnhost:old"}
                        ]
                    }
                }
            }
        });
        let patch = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "test-ss", "image": "pause:new"}
                        ]
                    }
                }
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let containers = target["spec"]["template"]["spec"]["containers"]
            .as_array()
            .unwrap();
        assert_eq!(containers.len(), 2, "both containers must be present");
        assert_eq!(
            containers[0]["image"], "pause:new",
            "the unmatched patch container must be at index 0 so Containers[0].Image reads \
             the patched image, matching upstream strategic-merge-patch ordering"
        );
        assert_eq!(
            containers[1]["name"], "webserver",
            "the untouched original container must survive at index 1"
        );
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

    /// spec.schedulingGates must be registered with merge key "name" (matching upstream's
    /// `patchStrategy:"merge" patchMergeKey:"name"` tag on PodSpec.SchedulingGates).
    ///
    /// The real e2e test removes scheduling gates one at a time via exactly this kind of
    /// $patch:delete — predicates.go's "validates Pods with non-empty schedulingGates are
    /// blocked on scheduling" test patches `[{name: foo, $patch: delete}]` to drop "foo"
    /// while leaving "bar" in place. Without this entry, `merge_key_for_path` falls through
    /// to Unknown, and any $patch:delete on this field returns 400 ("no merge key is
    /// registered"), so the test can never even reach the "remove the remaining gate" step.
    #[test]
    fn test_smp_scheduling_gates_delete_by_name() {
        let mut target = json!({
            "spec": {
                "schedulingGates": [
                    {"name": "foo"},
                    {"name": "bar"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "schedulingGates": [
                    {"name": "foo", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch)
            .expect("$patch:delete on spec.schedulingGates must be accepted, not 400");

        let gates = target["spec"]["schedulingGates"].as_array().unwrap();
        assert_eq!(
            gates,
            &vec![json!({"name": "bar"})],
            "only the gate named \"foo\" should be removed — \"bar\" must remain untouched \
             since gates clear one at a time, not all-or-nothing"
        );
    }

    /// spec.topologySpreadConstraints must be registered with merge key "topologyKey"
    /// (matching upstream's `patchStrategy:"merge" patchMergeKey:"topologyKey"` tag on
    /// PodSpec.TopologySpreadConstraints).
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a patch
    /// that adds one constraint silently REPLACES the whole array instead of merging by
    /// key — e.g. a GitOps tool layering a zone-spread constraint on top of an
    /// already-configured hostname-spread constraint would silently delete the
    /// hostname-spread constraint instead of adding the zone-spread one alongside it.
    #[test]
    fn test_smp_topology_spread_constraints_merge_preserves_existing() {
        let mut target = json!({
            "spec": {
                "topologySpreadConstraints": [
                    {"maxSkew": 1, "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "DoNotSchedule"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "topologySpreadConstraints": [
                    {"maxSkew": 2, "topologyKey": "topology.kubernetes.io/zone", "whenUnsatisfiable": "ScheduleAnyway"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let constraints = target["spec"]["topologySpreadConstraints"]
            .as_array()
            .unwrap();
        let keys: Vec<&str> = constraints
            .iter()
            .map(|c| c["topologyKey"].as_str().unwrap())
            .collect();
        assert_eq!(
            constraints.len(),
            2,
            "adding a zone constraint must not silently drop the pre-existing hostname \
             constraint — both scheduling constraints must remain in effect; got: {constraints:?}"
        );
        assert!(
            keys.contains(&"kubernetes.io/hostname")
                && keys.contains(&"topology.kubernetes.io/zone"),
            "both the original and newly-patched topologyKey must survive; got: {keys:?}"
        );
    }

    /// spec.template.spec.hostAliases must be registered with merge key "ip", not just the
    /// bare spec.hostAliases (a Pod's own field) — hostAliases is commonly set inside a
    /// Deployment/StatefulSet/DaemonSet/Job pod template (e.g. a Helm chart adding a
    /// private-registry hostname override), and only the bare-Pod path was registered.
    ///
    /// Without the template-path entry, `merge_key_for_path` falls through to Unknown for
    /// `spec.template.spec.hostAliases`, and a patch that adds one hostAlias entry silently
    /// REPLACES the whole array instead of merging by ip — deleting every other host entry
    /// the template previously configured.
    #[test]
    fn test_smp_host_aliases_in_pod_template_merge_preserves_existing() {
        let mut target = json!({
            "spec": {
                "template": {
                    "spec": {
                        "hostAliases": [
                            {"ip": "10.0.0.1", "hostnames": ["registry.internal"]}
                        ]
                    }
                }
            }
        });
        let patch = json!({
            "spec": {
                "template": {
                    "spec": {
                        "hostAliases": [
                            {"ip": "10.0.0.2", "hostnames": ["cache.internal"]}
                        ]
                    }
                }
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let aliases = target["spec"]["template"]["spec"]["hostAliases"]
            .as_array()
            .unwrap();
        assert_eq!(
            aliases.len(),
            2,
            "adding a new hostAlias to a pod template must not silently drop the \
             pre-existing entry — the template's kubelet-injected /etc/hosts would lose an \
             entry other pods still depend on; got: {aliases:?}"
        );
        let ips: Vec<&str> = aliases.iter().map(|a| a["ip"].as_str().unwrap()).collect();
        assert!(
            ips.contains(&"10.0.0.1") && ips.contains(&"10.0.0.2"),
            "both the original and newly-patched ip must survive; got: {ips:?}"
        );
    }

    /// spec.resourceClaims must be registered with merge key "name" (matching upstream's
    /// `patchStrategy:"merge,retainKeys" patchMergeKey:"name"` tag on PodSpec.ResourceClaims).
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a
    /// $patch:delete removing one DRA claim reference from a Pod template — e.g. a
    /// Deployment rollout that drops a GPU claim from its template while keeping other
    /// claims — returns 400 ("no merge key is registered") instead of removing just the
    /// named claim.
    #[test]
    fn test_smp_resource_claims_delete_by_name() {
        let mut target = json!({
            "spec": {
                "resourceClaims": [
                    {"name": "gpu", "resourceClaimName": "gpu-claim"},
                    {"name": "nic", "resourceClaimName": "nic-claim"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "resourceClaims": [
                    {"name": "gpu", "$patch": "delete"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch)
            .expect("$patch:delete on spec.resourceClaims must be accepted, not 400");

        let claims = target["spec"]["resourceClaims"].as_array().unwrap();
        assert_eq!(
            claims,
            &vec![json!({"name": "nic", "resourceClaimName": "nic-claim"})],
            "only the claim named \"gpu\" should be removed — \"nic\" must remain untouched \
             since claims are removed one at a time, not all-or-nothing"
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
    fn test_smp_patch_delete_on_unregistered_array_errors_loudly() {
        // $patch:delete on an array with no registered merge key (tolerations) must be
        // rejected, not stored literally. Without this guard, the directive object
        // {"$patch":"delete",...} would be silently written into the array as a garbage
        // element (last-write-wins), corrupting the resource in a way that's invisible
        // until something downstream chokes on the malformed entry.
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
                    {"key": "old", "$patch": "delete"}
                ]
            }
        });

        let err = strategic_merge_patch(&mut target, &patch)
            .expect_err("$patch:delete on an unregistered array must be rejected");
        assert!(
            matches!(err, PatchError::InvalidDirective(_)),
            "error must be InvalidDirective so callers can distinguish it from other patch failures, got: {err:?}"
        );

        // The directive element must never have been written into the array.
        let tolerations = target["spec"]["tolerations"].as_array().unwrap();
        assert_eq!(
            tolerations.len(),
            1,
            "target must be untouched on error — the garbage directive element must not appear"
        );
        assert!(
            tolerations[0].get("$patch").is_none(),
            "the literal $patch directive object must never be stored in the array"
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

    #[test]
    fn container_state_is_replaced_not_merged_on_status_patch() {
        // ContainerStatus.state is a discriminated union — exactly one of waiting/running/terminated
        // must be set. If kubelet patches state from waiting to running via strategic-merge-patch,
        // the old "waiting" key must be gone; leaving both present causes sonobuoy's aggregator
        // readiness check to see "waiting: ContainerCreating" and hang forever even though the
        // pod phase is Running.
        let mut pod = json!({
            "status": {
                "containerStatuses": [{
                    "name": "kube-sonobuoy",
                    "state": {
                        "waiting": { "reason": "ContainerCreating" }
                    },
                    "ready": false,
                    "started": false
                }]
            }
        });
        let patch = json!({
            "status": {
                "containerStatuses": [{
                    "name": "kube-sonobuoy",
                    "state": {
                        "running": { "startedAt": "2026-06-04T00:00:00Z" }
                    },
                    "ready": true,
                    "started": true
                }]
            }
        });
        strategic_merge_patch(&mut pod, &patch).unwrap();

        let state = &pod["status"]["containerStatuses"][0]["state"];
        assert!(
            state.get("waiting").is_none(),
            "waiting key must be absent after transition to running — both present simultaneously \
             breaks sonobuoy aggregator readiness (it sees ContainerCreating and waits forever)"
        );
        assert!(
            state.get("running").is_some(),
            "running key must be present after kubelet patches state to running"
        );
    }

    /// $patch:delete on metadata.ownerReferences must remove the matching entry by uid,
    /// not store the directive object literally.
    ///
    /// KCM releases an adopted pod from a ReplicaSet/RC by sending a strategic-merge PATCH with
    /// {"metadata":{"ownerReferences":[{"$patch":"delete","uid":"<rs-uid>"}]}}.
    /// Without "uid" registered as the merge key for ownerReferences, the $patch:delete element
    /// falls through to last-write-wins and is stored as a garbage ownerReference
    /// {"$patch":"delete","uid":"..."} with no controller/blockOwnerDeletion fields.
    /// Controllers and GC that dereference .Controller on that entry nil-deref and panic
    /// (the ReplicaSet adopt-release conformance test panics at replica_set.go:392).
    #[test]
    fn smp_patch_delete_on_owner_references_removes_entry_not_stores_directive() {
        let mut target = serde_json::json!({
            "metadata": {
                "ownerReferences": [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": "my-rs",
                        "uid": "rs-uid-X",
                        "controller": true,
                        "blockOwnerDeletion": true
                    },
                    {
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": "other-rs",
                        "uid": "rs-uid-Y",
                        "controller": false,
                        "blockOwnerDeletion": false
                    }
                ]
            }
        });
        // KCM releases the pod from my-rs by sending $patch:delete for rs-uid-X.
        let patch = serde_json::json!({
            "metadata": {
                "ownerReferences": [
                    {"$patch": "delete", "uid": "rs-uid-X"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let refs = target["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(
            refs.len(),
            1,
            "$patch:delete must remove the matching ownerReference by uid — if the directive \
             is stored literally, controllers/GC dereference .Controller on the garbage entry \
             and nil-deref panic (RS adopt-release conformance test fails at replica_set.go:392)"
        );
        assert_eq!(
            refs[0]["uid"], "rs-uid-Y",
            "the surviving ownerReference must be the one whose uid was NOT deleted"
        );
        assert!(
            refs.iter().all(|r| r.get("$patch").is_none()),
            "the $patch directive object must not appear as a literal ownerReference entry"
        );
    }

    /// A normal (non-directive) ownerReferences strategic-merge patch merges by uid.
    ///
    /// Adding a new ownerReference must preserve existing ones; updating an existing one
    /// (same uid) must merge the fields rather than duplicate the entry.
    #[test]
    fn smp_owner_references_merge_by_uid_preserves_existing_entries() {
        let mut target = serde_json::json!({
            "metadata": {
                "ownerReferences": [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": "my-rs",
                        "uid": "rs-uid-X",
                        "controller": true
                    }
                ]
            }
        });
        // Patch adds a second ownerReference; the first must survive.
        let patch = serde_json::json!({
            "metadata": {
                "ownerReferences": [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": "other-rs",
                        "uid": "rs-uid-Y",
                        "controller": false
                    }
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let refs = target["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(
            refs.len(),
            2,
            "adding a new ownerReference must preserve the existing one — \
             without uid merge key, the entire array is replaced and the pod \
             loses its original owner, breaking GC and adoption tracking"
        );
        assert!(
            refs.iter().any(|r| r["uid"] == "rs-uid-X"),
            "original ownerReference (rs-uid-X) must survive the merge"
        );
        assert!(
            refs.iter().any(|r| r["uid"] == "rs-uid-Y"),
            "new ownerReference (rs-uid-Y) must be present after the merge"
        );
    }

    /// KCM's Job controller removes the `batch.kubernetes.io/job-tracking` finalizer with a
    /// `$deleteFromPrimitiveList/finalizers` strategic-merge patch (finalizers is a plain
    /// []string with no merge key, so `$patch:delete` on an object element can't be used).
    /// Without this directive, the evicted pod's finalizer is never removed, the pod is
    /// stuck Terminating forever, and the "ignore failure matching on DisruptionTarget"
    /// Job conformance test times out waiting for pod deletion.
    #[test]
    fn smp_delete_from_primitive_list_removes_finalizer_not_stores_directive() {
        let mut target = serde_json::json!({
            "metadata": {
                "finalizers": [
                    "batch.kubernetes.io/job-tracking",
                    "kubernetes.io/pv-protection"
                ]
            }
        });
        let patch = serde_json::json!({
            "metadata": {
                "$deleteFromPrimitiveList/finalizers": ["batch.kubernetes.io/job-tracking"]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let finalizers = target["metadata"]["finalizers"].as_array().unwrap();
        assert_eq!(
            finalizers.len(),
            1,
            "$deleteFromPrimitiveList must remove the named finalizer — if it doesn't, the \
             pod-tracking finalizer is never released and evicted Job pods never finish \
             deleting, timing out the DisruptionTarget pod-failure-policy conformance test"
        );
        assert_eq!(
            finalizers[0], "kubernetes.io/pv-protection",
            "the untouched finalizer must survive"
        );
        assert!(
            target["metadata"]
                .get("$deleteFromPrimitiveList/finalizers")
                .is_none(),
            "the directive key must never be stored literally as a sibling metadata field"
        );
    }

    #[test]
    fn init_container_state_is_replaced_not_merged_on_status_patch() {
        // Same invariant as container_state_is_replaced_not_merged_on_status_patch but for
        // initContainerStatuses, which uses the same discriminated-union state field.
        let mut pod = json!({
            "status": {
                "initContainerStatuses": [{
                    "name": "init",
                    "state": {
                        "waiting": { "reason": "PodInitializing" }
                    }
                }]
            }
        });
        let patch = json!({
            "status": {
                "initContainerStatuses": [{
                    "name": "init",
                    "state": {
                        "terminated": { "exitCode": 0 }
                    }
                }]
            }
        });
        strategic_merge_patch(&mut pod, &patch).unwrap();

        let state = &pod["status"]["initContainerStatuses"][0]["state"];
        assert!(
            state.get("waiting").is_none(),
            "waiting must be absent after init container terminates"
        );
        assert!(
            state.get("terminated").is_some(),
            "terminated must be present after init container exits"
        );
    }

    /// Container.volumeDevices must be registered with merge key "devicePath" (matching
    /// upstream's `patchStrategy:"merge" patchMergeKey:"devicePath"` tag — the same
    /// nested-inside-container shape as volumeMounts above; EphemeralContainerCommon.
    /// volumeDevices carries the identical tag and is covered by the same suffix arm).
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a patch that
    /// adds one block device to a container that already has one configured silently
    /// REPLACES the whole array instead of merging by devicePath — unmounting the
    /// pre-existing block device out from under the running container.
    #[test]
    fn test_smp_volume_devices_merge_preserves_existing() {
        let mut target = json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "volumeDevices": [
                        {"name": "data-disk", "devicePath": "/dev/xvda"}
                    ]
                }]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [{
                    "name": "app",
                    "volumeDevices": [
                        {"name": "log-disk", "devicePath": "/dev/xvdb"}
                    ]
                }]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let devices = target["spec"]["containers"][0]["volumeDevices"]
            .as_array()
            .unwrap();
        assert_eq!(
            devices.len(),
            2,
            "adding a new block device must not silently drop the pre-existing one — the \
             container would lose access to its already-mounted device; got: {devices:?}"
        );
        let paths: Vec<&str> = devices
            .iter()
            .map(|d| d["devicePath"].as_str().unwrap())
            .collect();
        assert!(
            paths.contains(&"/dev/xvda") && paths.contains(&"/dev/xvdb"),
            "both the original and newly-patched devicePath must survive; got: {paths:?}"
        );
    }

    /// ContainerStatus.allocatedResourcesStatus must be registered with merge key "name"
    /// (matching upstream's `patchStrategy:"merge" patchMergeKey:"name"` tag).
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a kubelet
    /// status patch reporting a newly-allocated resource's health silently REPLACES the
    /// whole array instead of merging by name — discarding the health status of every
    /// other already-allocated resource the moment a second one is allocated.
    #[test]
    fn test_smp_allocated_resources_status_merge_preserves_existing() {
        let mut target = json!({
            "status": {
                "containerStatuses": [{
                    "name": "app",
                    "allocatedResourcesStatus": [
                        {"name": "gpu", "resources": [{"resourceID": "gpu-0", "health": "Healthy"}]}
                    ]
                }]
            }
        });
        let patch = json!({
            "status": {
                "containerStatuses": [{
                    "name": "app",
                    "allocatedResourcesStatus": [
                        {"name": "nic", "resources": [{"resourceID": "nic-0", "health": "Healthy"}]}
                    ]
                }]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let statuses = target["status"]["containerStatuses"][0]["allocatedResourcesStatus"]
            .as_array()
            .unwrap();
        assert_eq!(
            statuses.len(),
            2,
            "reporting a newly-allocated resource must not silently drop the health status \
             of an already-allocated one; got: {statuses:?}"
        );
        let names: Vec<&str> = statuses
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"gpu") && names.contains(&"nic"),
            "both the original and newly-patched resource name must survive; got: {names:?}"
        );
    }

    /// NodeStatus.addresses must be registered with merge key "type" (matching upstream's
    /// `patchStrategy:"merge" patchMergeKey:"type"` tag), reached via the /status subresource
    /// handler which strips the "status" wrapper before calling SMP (path root "").
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a cloud
    /// controller manager patch that adds a newly-discovered address (e.g. an ExternalIP
    /// assigned after node registration) silently REPLACES the whole array instead of
    /// merging by type — dropping the node's InternalIP and disconnecting it from the
    /// cluster network view.
    #[test]
    fn test_smp_node_addresses_merge_preserves_existing() {
        let mut status = json!({
            "addresses": [
                {"type": "InternalIP", "address": "10.0.0.5"}
            ]
        });
        let patch = json!({
            "addresses": [
                {"type": "ExternalIP", "address": "203.0.113.5"}
            ]
        });

        strategic_merge_patch(&mut status, &patch).unwrap();

        let addresses = status["addresses"].as_array().unwrap();
        assert_eq!(
            addresses.len(),
            2,
            "adding an ExternalIP must not silently drop the node's InternalIP — the cluster \
             would lose its route to the node; got: {addresses:?}"
        );
        let types: Vec<&str> = addresses
            .iter()
            .map(|a| a["type"].as_str().unwrap())
            .collect();
        assert!(
            types.contains(&"InternalIP") && types.contains(&"ExternalIP"),
            "both the original and newly-patched address type must survive; got: {types:?}"
        );
    }

    /// PodStatus.resourceClaimStatuses must be registered with merge key "name" (matching
    /// upstream's `patchStrategy:"merge,retainKeys" patchMergeKey:"name"` tag), reached via
    /// the /status subresource handler which strips the "status" wrapper before calling SMP.
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a kubelet
    /// status patch reporting a newly-allocated DRA claim silently REPLACES the whole array
    /// instead of merging by name — dropping the allocation result of every other
    /// already-allocated claim.
    #[test]
    fn test_smp_resource_claim_statuses_merge_preserves_existing() {
        let mut status = json!({
            "resourceClaimStatuses": [
                {"name": "gpu", "resourceClaimName": "gpu-claim-abc123"}
            ]
        });
        let patch = json!({
            "resourceClaimStatuses": [
                {"name": "nic", "resourceClaimName": "nic-claim-def456"}
            ]
        });

        strategic_merge_patch(&mut status, &patch).unwrap();

        let statuses = status["resourceClaimStatuses"].as_array().unwrap();
        assert_eq!(
            statuses.len(),
            2,
            "reporting a newly-allocated claim must not silently drop an already-allocated \
             claim's status; got: {statuses:?}"
        );
        let names: Vec<&str> = statuses
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"gpu") && names.contains(&"nic"),
            "both the original and newly-patched claim name must survive; got: {names:?}"
        );
    }

    /// ServiceAccount.secrets must be registered with merge key "name" (matching upstream's
    /// `patchStrategy:"merge" patchMergeKey:"name"` tag). Unlike the other fixes above,
    /// ServiceAccount has no spec/status wrapper — secrets is a top-level field, so the path
    /// is always the bare field name (root path "" on a main-resource PATCH).
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and a patch adding
    /// a newly-created secret reference silently REPLACES the whole array instead of merging
    /// by name — revoking every other secret's mountable-secrets grant for pods using this
    /// ServiceAccount.
    #[test]
    fn test_smp_service_account_secrets_merge_preserves_existing() {
        let mut target = json!({
            "secrets": [
                {"name": "default-token-abc12"}
            ]
        });
        let patch = json!({
            "secrets": [
                {"name": "extra-token-xyz89"}
            ]
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let secrets = target["secrets"].as_array().unwrap();
        assert_eq!(
            secrets.len(),
            2,
            "adding a new secret reference must not silently drop the original — pods \
             already relying on it would lose access; got: {secrets:?}"
        );
        let names: Vec<&str> = secrets
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"default-token-abc12") && names.contains(&"extra-token-xyz89"),
            "both the original and newly-patched secret name must survive; got: {names:?}"
        );
    }

    /// CSINodeSpec.drivers must be registered with merge key "name" (matching upstream's
    /// `patchStrategy:"merge" patchMergeKey:"name"` tag) — this is the only field named
    /// "drivers" anywhere in the vendored API surface, so a plain suffix arm is safe.
    ///
    /// Without this entry, `merge_key_for_path` falls through to Unknown, and installing a
    /// second CSI driver on a node (e.g. adding a block-storage driver alongside an existing
    /// file-storage driver) silently REPLACES the whole array instead of merging by name,
    /// unregistering the driver that was already there — kubelet then refuses volume
    /// operations for the dropped driver even though its DaemonSet pod is still running.
    #[test]
    fn test_smp_csi_node_drivers_merge_preserves_existing() {
        let mut target = json!({
            "spec": {
                "drivers": [
                    {"name": "file.csi.example.com", "nodeID": "node-1", "topologyKeys": []}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "drivers": [
                    {"name": "block.csi.example.com", "nodeID": "node-1", "topologyKeys": []}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let drivers = target["spec"]["drivers"].as_array().unwrap();
        assert_eq!(
            drivers.len(),
            2,
            "registering a second CSI driver must not silently unregister the first one; got: {drivers:?}"
        );
        let names: Vec<&str> = drivers
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"file.csi.example.com") && names.contains(&"block.csi.example.com"),
            "both the original and newly-patched driver name must survive; got: {names:?}"
        );
    }

    /// {Mutating,Validating}AdmissionPolicySpec.matchConditions must be registered with merge
    /// key "name" (matching upstream's `patchStrategy:"merge" patchMergeKey:"name"` tag),
    /// reached as "spec.matchConditions" — a direct child of spec, no array wrapper needed.
    ///
    /// Without this entry, adding a second match condition to an existing admission policy
    /// (e.g. narrowing which namespaces a validating policy applies to, on top of an existing
    /// "skip dry-run requests" condition) silently REPLACES the whole array instead of merging
    /// by name, dropping the original gating condition — so the policy starts evaluating
    /// requests it was explicitly configured to skip.
    #[test]
    fn test_smp_admission_policy_spec_match_conditions_merge_preserves_existing() {
        let mut target = json!({
            "spec": {
                "matchConstraints": {"resourceRules": []},
                "matchConditions": [
                    {"name": "skip-dry-run", "expression": "!request.dryRun"}
                ]
            }
        });
        let patch = json!({
            "spec": {
                "matchConditions": [
                    {"name": "prod-namespace-only", "expression": "object.metadata.namespace == 'prod'"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let conditions = target["spec"]["matchConditions"].as_array().unwrap();
        assert_eq!(
            conditions.len(),
            2,
            "adding a match condition must not silently drop the pre-existing one; got: {conditions:?}"
        );
        let names: Vec<&str> = conditions
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"skip-dry-run") && names.contains(&"prod-namespace-only"),
            "both the original and newly-patched condition name must survive; got: {names:?}"
        );
    }

    /// MutatingAdmissionPolicySpec.variables declares `+listType=atomic` with NO
    /// patchMergeKey — upstream wants the whole array replaced on every patch, never merged.
    /// This must stay true even though ValidatingAdmissionPolicySpec.variables (a genuinely
    /// separate message) DOES declare `patchMergeKey=name` at the exact same JSON path
    /// ("spec.variables" — both kinds are patched via the same generic
    /// strategic_merge_patch(&mut current.body, ...) call starting at an empty root path, so
    /// there is no path-based way to tell the two messages apart). Registering "spec.variables"
    /// as a merge-by-name key to fix the Validating side would silently break this: a
    /// MutatingAdmissionPolicy patch intended to remove a variable would instead leave it in
    /// place forever (merge-by-name only adds/updates, never removes what's absent from the
    /// patch). This is why ValidatingAdmissionPolicySpec.variables stays deliberately
    /// unresolved in known_missing_tracked_separately below rather than "fixed" at the cost of
    /// this test.
    #[test]
    fn mutating_admission_policy_variables_stays_atomic_replace_not_merged_by_name() {
        assert!(
            matches!(merge_key_for_path("spec.variables"), MergeKeyKind::Unknown),
            "spec.variables must stay unregistered (Unknown -> whole-array replace) — if this \
             ever changes to MergeKeyKind::Key, it means someone registered a merge key at this \
             path to fix ValidatingAdmissionPolicySpec.variables, which would also incorrectly \
             start merging MutatingAdmissionPolicySpec.variables by name instead of replacing it"
        );

        let mut target = json!({
            "spec": {
                "variables": [
                    {"name": "isProdNamespace", "expression": "object.metadata.namespace == 'prod'"},
                    {"name": "stale", "expression": "true"}
                ]
            }
        });
        // A MutatingAdmissionPolicy update that drops the "stale" variable entirely.
        let patch = json!({
            "spec": {
                "variables": [
                    {"name": "isProdNamespace", "expression": "object.metadata.namespace == 'prod'"}
                ]
            }
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let variables = target["spec"]["variables"].as_array().unwrap();
        assert_eq!(
            variables.len(),
            1,
            "atomic (+listType=atomic, no patchMergeKey) semantics means the patch's array \
             wholly REPLACES the target — the dropped \"stale\" variable must be gone, not \
             retained as it would be under a (wrong, for this message) merge-by-name; got: {variables:?}"
        );
        assert_eq!(variables[0]["name"], "isProdNamespace");
    }

    /// ValidatingWebhookConfiguration.webhooks must be registered with merge key "name" at the
    /// real (lowercase) JSON path "webhooks" — the .proto token is capitalized "Webhooks", but
    /// admissionreg_gen_adapter.rs emits lowercase "webhooks", and this config kind has no
    /// spec/status wrapper (webhooks is a bare top-level field, same shape as
    /// ServiceAccount.secrets above).
    ///
    /// This is the exact repro from a real user-facing bug (mayor-t4opz): `kubectl create` a
    /// ValidatingWebhookConfiguration, then `kubectl apply` the same object again with only
    /// rules[].resources changed. Without this entry, "webhooks" falls through to Unknown
    /// (whole-array replace using whatever the second apply's computed patch happens to
    /// contain), which silently drops clientConfig, failurePolicy, admissionReviewVersions, and
    /// sideEffects from the stored webhook — leaving it registered but non-functional, since
    /// run_validating_webhooks can't resolve a dispatch target without clientConfig. This test
    /// also exercises the nested "webhooks.matchConditions" suffix-arm fix at the same time
    /// (adding a second match condition must not drop the first).
    #[test]
    fn test_smp_validating_webhook_configuration_apply_preserves_siblings_and_match_conditions() {
        let mut target = json!({
            "webhooks": [
                {
                    "name": "validate.example.com",
                    "clientConfig": {"url": "https://example.com/validate"},
                    "failurePolicy": "Fail",
                    "admissionReviewVersions": ["v1"],
                    "sideEffects": "None",
                    "matchConditions": [
                        {"name": "exclude-kube-system", "expression": "object.metadata.namespace != 'kube-system'"}
                    ],
                    "rules": [
                        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}
                    ]
                }
            ]
        });
        // Second apply: only rules and matchConditions change; every other field is omitted,
        // matching what a real strategic-merge-patch diff of "only rules changed" looks like.
        let patch = json!({
            "webhooks": [
                {
                    "name": "validate.example.com",
                    "rules": [
                        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}
                    ],
                    "matchConditions": [
                        {"name": "exclude-kube-system", "expression": "object.metadata.namespace != 'kube-system'"},
                        {"name": "exclude-kube-public", "expression": "object.metadata.namespace != 'kube-public'"}
                    ]
                }
            ]
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let webhooks = target["webhooks"].as_array().unwrap();
        assert_eq!(
            webhooks.len(),
            1,
            "the patch must merge into the existing webhook entry by name, not append a second one"
        );
        let wh = &webhooks[0];
        assert_eq!(
            wh["clientConfig"]["url"], "https://example.com/validate",
            "clientConfig must survive a patch that only changes rules — without it the \
             webhook is registered but dispatch can never resolve a target"
        );
        assert_eq!(wh["failurePolicy"], "Fail", "failurePolicy must survive");
        assert_eq!(
            wh["admissionReviewVersions"],
            json!(["v1"]),
            "admissionReviewVersions must survive"
        );
        assert_eq!(wh["sideEffects"], "None", "sideEffects must survive");
        assert_eq!(
            wh["rules"][0]["operations"],
            json!(["CREATE", "UPDATE"]),
            "the patched field (rules) must actually be updated"
        );

        let conditions = wh["matchConditions"].as_array().unwrap();
        assert_eq!(
            conditions.len(),
            2,
            "adding a second match condition must not drop the first; got: {conditions:?}"
        );
        let names: Vec<&str> = conditions
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"exclude-kube-system") && names.contains(&"exclude-kube-public"),
            "both match conditions must survive; got: {names:?}"
        );
    }

    /// Same fix as the ValidatingWebhookConfiguration test above, applied to
    /// MutatingWebhookConfiguration — the two kinds share the identical capitalization
    /// mismatch ("Webhooks" in the .proto vs "webhooks" in the real JSON) and the identical
    /// generic strategic-merge-patch code path, so both must be verified independently.
    #[test]
    fn test_smp_mutating_webhook_configuration_apply_preserves_siblings_and_match_conditions() {
        let mut target = json!({
            "webhooks": [
                {
                    "name": "mutate.example.com",
                    "clientConfig": {"url": "https://example.com/mutate"},
                    "failurePolicy": "Ignore",
                    "admissionReviewVersions": ["v1"],
                    "sideEffects": "None",
                    "reinvocationPolicy": "Never",
                    "matchConditions": [
                        {"name": "exclude-kube-system", "expression": "object.metadata.namespace != 'kube-system'"}
                    ],
                    "rules": [
                        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}
                    ]
                }
            ]
        });
        let patch = json!({
            "webhooks": [
                {
                    "name": "mutate.example.com",
                    "rules": [
                        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}
                    ]
                }
            ]
        });

        strategic_merge_patch(&mut target, &patch).unwrap();

        let webhooks = target["webhooks"].as_array().unwrap();
        assert_eq!(
            webhooks.len(),
            1,
            "must merge by name, not append a second entry"
        );
        let wh = &webhooks[0];
        assert_eq!(
            wh["clientConfig"]["url"], "https://example.com/mutate",
            "clientConfig must survive a patch that only changes rules"
        );
        assert_eq!(
            wh["reinvocationPolicy"], "Never",
            "reinvocationPolicy must survive"
        );
        assert_eq!(
            wh["matchConditions"][0]["name"], "exclude-kube-system",
            "matchConditions must survive untouched"
        );
        assert_eq!(
            wh["rules"][0]["operations"],
            json!(["CREATE", "UPDATE"]),
            "the patched field (rules) must actually be updated"
        );
    }

    // --- Completeness check: every schema-declared +patchMergeKey field must have SOME
    // matching entry in merge_key_for_path ---
    //
    // The vendored .proto files carry upstream's patchMergeKey/patchStrategy/listType
    // annotations verbatim as `//` comments (copied from the Go struct tags this repo has no
    // other access to). This parses those comments and cross-references every
    // (message, field, patchMergeKey) triple found against merge_key_for_path, so a field
    // that declares a merge key upstream can't silently regress to whole-array-replace the
    // way the 5 fields fixed above did — without this test ever having to hand-list every
    // field merge_key_for_path already knows about.

    /// One `+patchMergeKey=...` field extracted from a vendored .proto file's comments,
    /// together with any `+listType=...` annotation on the same field (needed to detect the
    /// legacy-strategic-merge-patch-vs-SSA annotation conflicts handled below).
    struct ProtoPatchMergeKeyField {
        message: String,
        field: String,
        patch_merge_key: String,
        list_type: Option<String>,
    }

    /// Extracts every `repeated` field whose immediately-preceding comment block declares
    /// `+patchMergeKey=<key>`, pairing it with the enclosing `message` and any co-located
    /// `+listType=<value>` annotation. Annotation comments only ever apply to the field
    /// declared directly below them, so any other line (a blank line, a non-repeated field, a
    /// closing brace, ...) resets whatever was pending.
    fn parse_patch_merge_key_fields(proto_source: &str) -> Vec<ProtoPatchMergeKeyField> {
        let mut fields = Vec::new();
        let mut current_message = String::new();
        let mut pending_key: Option<String> = None;
        let mut pending_list_type: Option<String> = None;

        for raw_line in proto_source.lines() {
            let line = raw_line.trim();

            if let Some(rest) = line.strip_prefix("message ") {
                current_message = rest.trim_end_matches('{').trim().to_string();
                pending_key = None;
                pending_list_type = None;
                continue;
            }

            if let Some(comment) = line.strip_prefix("//") {
                let comment = comment.trim();
                if let Some(v) = comment.strip_prefix("+patchMergeKey=") {
                    pending_key = Some(v.to_string());
                } else if let Some(v) = comment.strip_prefix("+listType=") {
                    pending_list_type = Some(v.to_string());
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("repeated ") {
                if let Some(key) = pending_key.take() {
                    let field = rest.split_whitespace().nth(1).unwrap_or("").to_string();
                    fields.push(ProtoPatchMergeKeyField {
                        message: current_message.clone(),
                        field,
                        patch_merge_key: key,
                        list_type: pending_list_type.take(),
                    });
                }
                pending_key = None;
                pending_list_type = None;
                continue;
            }

            // An `optional` field, a blank line, a closing brace, ... — annotations never
            // carry over past a line that isn't the field they were written for.
            pending_key = None;
            pending_list_type = None;
        }

        fields
    }

    fn collect_proto_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_proto_files(&path, out);
            } else if path.file_name().and_then(|n| n.to_str()) == Some("generated.proto") {
                out.push(path);
            }
        }
    }

    /// True if `merge_key_for_path` returns `Key(expected_key)` for at least one JSON path
    /// shape a field named `field` could realistically appear at: a top-level field (bare, or
    /// directly under spec/spec.template.spec — matching an exact-path table entry), or
    /// nested one level inside an already-merged array element (matching a generic
    /// `.ends_with(".field")` suffix arm — any non-empty prefix probes every suffix arm
    /// identically, so one stand-in nested prefix is enough to cover all of them).
    fn merge_key_for_path_covers(field: &str, expected_key: &str) -> bool {
        let candidates = [
            field.to_string(),
            format!("spec.{field}"),
            format!("spec.template.spec.{field}"),
            format!("spec.containers.{field}"),
        ];
        candidates
            .iter()
            .any(|p| matches!(merge_key_for_path(p), MergeKeyKind::Key(k) if k == expected_key))
    }

    #[test]
    fn merge_key_for_path_covers_every_schema_declared_patch_merge_key() {
        // Fields whose upstream annotations are self-contradictory: they declare BOTH
        // patchStrategy=merge/patchMergeKey=<key> (the legacy strategic-merge-patch this file
        // implements) AND +listType=atomic (an SSA-era annotation meaning "always replace the
        // whole list"). The two systems disagree on these specific fields and nothing here
        // can pick a winner without evidence of real client behavior — asserting an answer
        // would just be a guess, so these are deliberately excluded from the "must have a
        // merge key" check below rather than silently forced one way or the other.
        let known_ambiguous: &[(&str, &str)] =
            &[("JobStatus", "conditions"), ("PodStatus", "hostIPs")];

        // Two gaps from the same scan remain genuinely unresolved (the other 7 — CSINodeSpec.
        // drivers, the four *.matchConditions fields, and both {Mutating,Validating}
        // WebhookConfiguration.webhooks — are fixed above; see their regression tests below):
        //
        //  - ValidatingAdmissionPolicySpec.variables (patchMergeKey=name) collides with
        //    MutatingAdmissionPolicySpec.variables (same field name, +listType=atomic, NO
        //    patchMergeKey — must stay whole-array-replace). Unlike NodeStatus.addresses vs
        //    EndpointSubset.addresses (resolved with two literal paths because Node and
        //    Endpoints reach "addresses" at different structural depths), these two collide at
        //    the byte-identical path: both kinds are patched by the very same generic
        //    `strategic_merge_patch(&mut current.body, &patch)` call in handlers/resource.rs
        //    (confirmed: "mutatingadmissionpolicies" is registered and patched the same way as
        //    "validatingadmissionpolicies" in state.rs's build_registry), starting from an empty
        //    root path, and both nest `variables` exactly one level under `.spec` — so
        //    "spec.variables" is the identical string for both kinds. merge_key_for_path has no
        //    resource-kind context to tell them apart (its signature is just `&str -> ...`, and
        //    none of its call sites pass a kind/GVK), so neither an exact-path nor a suffix entry
        //    can fix Validating without also silently changing Mutating's variables from correct
        //    atomic-replace to incorrect merge-by-name. Resolving this needs a deliberate
        //    decision to thread resource-kind context into merge_key_for_path (a bigger,
        //    cross-cutting change) — flagged rather than guessed at here. See
        //    `mutating_admission_policy_variables_stays_atomic_replace_not_merged_by_name` below,
        //    which locks in the current (correct, for Mutating) behavior at this exact path.
        //  - JSONSchemaProps.xKubernetesValidations: the real JSON wire key is hyphenated
        //    "x-kubernetes-validations" (see apiextensions_gen_adapter.rs's
        //    `"x-kubernetes-validations".to_string()`), not the camelCase proto token, and it's
        //    nested inside a recursive JSONSchemaProps structure (properties/items/allOf/oneOf/
        //    anyOf/not) with no fixed parent path. It's also unreachable in practice today: the
        //    only way to reach it via strategic-merge-patch is by recursing through
        //    CustomResourceDefinitionSpec.versions first, and upstream's own .proto declares no
        //    patchMergeKey/patchStrategy on `versions` either — this codebase correctly leaves
        //    it whole-array-replace, matching upstream, which means the traversal never gets
        //    past `versions` to reach `schema.openAPIV3Schema.properties.*.x-kubernetes-
        //    validations` in the first place. Lowest priority of the original 9 given how rarely
        //    a CRD's OpenAPI schema is strategic-merge-patched at all.
        //
        // Two of the 7 fixed above (*WebhookConfiguration.webhooks) have a real JSON key that
        // differs in case from the literal .proto token, so this test's per-field candidate
        // probe (which always uses the verbatim proto token) can't see they're covered.
        // json_key_overrides redirects those two lookups to the real key so the completeness
        // check keeps verifying them instead of just deleting the safety net.
        let json_key_overrides: &[(&str, &str, &str)] = &[
            ("MutatingWebhookConfiguration", "Webhooks", "webhooks"),
            ("ValidatingWebhookConfiguration", "Webhooks", "webhooks"),
        ];

        let known_missing_tracked_separately: &[(&str, &str)] = &[
            ("ValidatingAdmissionPolicySpec", "variables"),
            ("JSONSchemaProps", "xKubernetesValidations"),
        ];

        let proto_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("proto-include");
        let mut proto_paths = Vec::new();
        collect_proto_files(&proto_dir, &mut proto_paths);
        assert!(
            proto_paths.len() > 10,
            "sanity check: expected many vendored generated.proto files under {}, found {} — \
             did the vendor layout move (this test would otherwise pass vacuously)?",
            proto_dir.display(),
            proto_paths.len()
        );

        let mut missing = Vec::new();
        let mut unexpected_ambiguous = Vec::new();

        for path in &proto_paths {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            for f in parse_patch_merge_key_fields(&source) {
                let is_annotation_conflict = f.list_type.as_deref() == Some("atomic");
                let is_known_ambiguous = known_ambiguous
                    .iter()
                    .any(|(m, field)| *m == f.message && *field == f.field);

                if is_annotation_conflict {
                    if !is_known_ambiguous {
                        unexpected_ambiguous.push(format!(
                            "{}.{} (patchMergeKey={}) in {}",
                            f.message,
                            f.field,
                            f.patch_merge_key,
                            path.display()
                        ));
                    }
                    continue;
                }

                let is_tracked_separately = known_missing_tracked_separately
                    .iter()
                    .any(|(m, field)| *m == f.message && *field == f.field);

                let effective_field = json_key_overrides
                    .iter()
                    .find(|(m, field, _)| *m == f.message && *field == f.field)
                    .map_or(f.field.as_str(), |(_, _, real_key)| *real_key);

                if !is_tracked_separately
                    && !merge_key_for_path_covers(effective_field, &f.patch_merge_key)
                {
                    missing.push(format!(
                        "{}.{} (patchMergeKey={}) in {}",
                        f.message,
                        f.field,
                        f.patch_merge_key,
                        path.display()
                    ));
                }
            }
        }

        assert!(
            unexpected_ambiguous.is_empty(),
            "field(s) newly declare BOTH patchMergeKey and +listType=atomic (a conflict \
             between the legacy strategic-merge-patch and SSA annotation systems) that aren't \
             in the known_ambiguous allowlist above — decide deliberately which annotation \
             patch.rs should trust for each rather than picking a side here: \
             {unexpected_ambiguous:#?}"
        );
        assert!(
            missing.is_empty(),
            "merge_key_for_path has no registered entry (exact-path or suffix arm) for these \
             schema-declared +patchMergeKey fields — a strategic-merge-patch against them will \
             silently replace the whole array instead of merging by key (or 400 on \
             $patch:delete): {missing:#?}"
        );
    }
}
