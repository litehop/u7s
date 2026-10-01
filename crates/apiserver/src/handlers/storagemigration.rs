//! Validation for storagemigration.k8s.io/v1 StorageVersionMigration, mirroring upstream's
//! `pkg/apis/storagemigration/validation`.
//!
//! The API object is served as plain CRUD: nothing here migrates stored data. Rewriting
//! objects is the kube-controller-manager storage-version-migrator controller's job, and it
//! only starts once something marks the object `Running`.

use serde_json::Value;

use super::certificates::is_dns1123_subdomain;

const CONDITION_SUCCEEDED: &str = "Succeeded";
const CONDITION_FAILED: &str = "Failed";

/// Upstream `IsDNS1035Label`: 1-63 chars of `[a-z0-9-]`, starting with a letter and ending
/// alphanumeric.
fn is_dns1035_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0].is_ascii_lowercase()
        && b[b.len() - 1] != b'-'
}

fn spec_resource(obj: &Value) -> (&str, &str) {
    let r = &obj["spec"]["resource"];
    (
        r["group"].as_str().unwrap_or(""),
        r["resource"].as_str().unwrap_or(""),
    )
}

/// Upstream `ValidateStorageVersionMigration` (spec part): the target resource names must be
/// well-formed, otherwise the migrator can never resolve them through discovery and the
/// migration would only fail later, far from the client that created it.
pub(crate) fn validate_spec(obj: &Value) -> Result<(), String> {
    let (group, resource) = spec_resource(obj);
    if resource.is_empty() {
        return Err(
            "spec.resource.resource: Required value: resource is required to be set".into(),
        );
    }
    if !is_dns1035_label(resource) {
        return Err(format!(
            "spec.resource.resource: Invalid value: {resource:?}: a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character"
        ));
    }
    if !group.is_empty() && !is_dns1123_subdomain(group) {
        return Err(format!(
            "spec.resource.group: Invalid value: {group:?}: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character"
        ));
    }
    Ok(())
}

/// Upstream `ValidateStorageVersionMigrationUpdate`: the spec names the resource being
/// migrated and is immutable; changing it under a running migration would orphan the
/// progress recorded in status.
pub(crate) fn validate_spec_immutable(old: &Value, new: &Value) -> Result<(), String> {
    if spec_resource(old) != spec_resource(new) {
        return Err("spec: Invalid value: field is immutable".into());
    }
    Ok(())
}

fn condition_true(obj: &Value, cond_type: &str) -> bool {
    obj["status"]["conditions"].as_array().is_some_and(|conds| {
        conds
            .iter()
            .any(|c| c["type"] == cond_type && c["status"] == "True")
    })
}

/// Upstream `ValidateStorageVersionMigrationStatusUpdate` (transition rules): the migrator
/// compares `status.resourceVersion` against its GC cache, so it must stay a valid, fixed
/// value once set, and a finished migration must never be reported unfinished or both
/// succeeded and failed.
pub(crate) fn validate_status_update(old: &Value, new: &Value) -> Result<(), String> {
    let new_rv = new["status"]["resourceVersion"].as_str().unwrap_or("");
    if !new_rv.is_empty() && new_rv.parse::<u64>().is_err() {
        return Err(format!(
            "status.resourceVersion: Invalid value: {new_rv:?}: resourceVersion must be a non-negative integer"
        ));
    }
    let old_rv = old["status"]["resourceVersion"].as_str().unwrap_or("");
    if !old_rv.is_empty() && old_rv != new_rv {
        return Err(format!(
            "status.resourceVersion: Invalid value: {new_rv:?}: field is immutable"
        ));
    }
    if condition_true(new, CONDITION_SUCCEEDED) && condition_true(new, CONDITION_FAILED) {
        return Err(
            "status.conditions: Invalid value: Both success and failed conditions cannot be true at the same time"
                .into(),
        );
    }
    if condition_true(old, CONDITION_SUCCEEDED) && !condition_true(new, CONDITION_SUCCEEDED) {
        return Err(
            "status.conditions: Invalid value: Success condition cannot be set to false once it is true"
                .into(),
        );
    }
    if condition_true(old, CONDITION_FAILED) && !condition_true(new, CONDITION_FAILED) {
        return Err(
            "status.conditions: Invalid value: Failed condition cannot be set to false once it is true"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query, State};
    use axum::http::{header::CONTENT_TYPE, HeaderMap, HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::Extension;
    use bytes::Bytes;
    use serde_json::json;

    use crate::auth::UserInfo;
    use crate::handlers::json_patch::{CreateQuery, PatchQuery, ReplaceQuery};
    use crate::handlers::test_support::make_state;
    use crate::state::AppState;

    const GROUP: &str = "storagemigration.k8s.io";
    const PLURAL: &str = "storageversionmigrations";

    fn admin() -> UserInfo {
        UserInfo {
            username: "admin".into(),
            uid: String::new(),
            groups: vec![],
            extra: Default::default(),
        }
    }

    fn headers(content_type: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        h
    }

    fn full(group: &str, resource: &str) -> Value {
        json!({
            "apiVersion": "storagemigration.k8s.io/v1",
            "kind": "StorageVersionMigration",
            "metadata": {"name": "m"},
            "spec": {"resource": {"group": group, "resource": resource}}
        })
    }

    async fn create(state: &AppState, body: &Value) -> Result<StatusCode, (StatusCode, String)> {
        super::super::resource::create_resource(
            State(state.clone()),
            Path((GROUP.into(), "v1".into(), PLURAL.into())),
            Query(CreateQuery::default()),
            Extension(admin()),
            headers("application/json"),
            Bytes::from(serde_json::to_vec(body).unwrap()),
        )
        .await
        .map(|r| r.into_response().status())
        .map_err(|e| (e.0, e.1.message))
    }

    fn name_path() -> Path<(String, String, String, String)> {
        Path((GROUP.into(), "v1".into(), PLURAL.into(), "m".into()))
    }

    async fn get(state: &AppState) -> Value {
        let key = crate::keys::group_object_key(GROUP, PLURAL, None, "m");
        use u7s_store::Store as _;
        let stored = state.store.get(&key).await.unwrap().expect("stored");
        serde_json::from_slice(&stored.value).unwrap()
    }

    /// One spec-changing write over `mode`; returns status and message.
    async fn retarget(state: &AppState, mode: &str) -> (StatusCode, String) {
        let target = full("", "bar");
        let partial =
            serde_json::to_vec(&json!({"spec": {"resource": {"resource": "bar"}}})).unwrap();
        let json_patch = serde_json::to_vec(&json!([
            {"op": "replace", "path": "/spec/resource/resource", "value": "bar"}
        ]))
        .unwrap();
        let content_type = match mode {
            "put" => "application/json",
            "merge" => "application/merge-patch+json",
            "smp" => "application/strategic-merge-patch+json",
            "json-patch" => "application/json-patch+json",
            "apply" => "application/apply-patch+yaml",
            _ => unreachable!(),
        };
        let result = if mode == "put" {
            super::super::resource::replace_resource(
                State(state.clone()),
                name_path(),
                Query(ReplaceQuery::default()),
                Extension(admin()),
                headers(content_type),
                Bytes::from(serde_json::to_vec(&target).unwrap()),
            )
            .await
            .map(IntoResponse::into_response)
        } else {
            super::super::resource::patch_resource(
                State(state.clone()),
                name_path(),
                Query(PatchQuery::default()),
                Extension(admin()),
                headers(content_type),
                Bytes::from(match mode {
                    "json-patch" => json_patch,
                    "apply" => serde_json::to_vec(&target).unwrap(),
                    _ => partial,
                }),
            )
            .await
            .map(IntoResponse::into_response)
        };
        match result {
            Ok(r) => (r.status(), String::new()),
            Err(e) => (e.0, e.1.message),
        }
    }

    /// Every write path that can reach the stored spec must refuse to retarget a migration;
    /// one unguarded path lets a client redirect a migration whose status tracks another
    /// resource.
    #[tokio::test]
    async fn every_spec_write_path_rejects_retargeting_because_spec_is_immutable() {
        let state = make_state();
        create(&state, &full("", "foo")).await.expect("seed create");
        let modes = ["put", "merge", "smp", "json-patch", "apply"];
        let mut guarded = 0;
        for mode in modes {
            let (status, message) = retarget(&state, mode).await;
            if status == StatusCode::UNPROCESSABLE_ENTITY && message.contains("immutable") {
                guarded += 1;
            } else {
                eprintln!("UNGUARDED {mode}: {status} {message:?}");
            }
        }
        eprintln!("sites: {guarded}/{} guarded", modes.len());
        assert_eq!(
            guarded,
            modes.len(),
            "every write path must enforce spec immutability"
        );
        assert_eq!(get(&state).await["spec"]["resource"]["resource"], "foo");
    }

    /// Create validates the target resource name (upstream rejects with 422) and drops any
    /// client-supplied status, which only the migrator may write.
    #[tokio::test]
    async fn create_rejects_invalid_resource_and_drops_client_status() {
        let state = make_state();
        let (status, _) = create(&state, &full("", "Foo")).await.unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = create(&state, &json!({"metadata": {"name": "m"}, "spec": {}}))
            .await
            .unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let mut with_status = full("", "foo");
        with_status["status"] = json!({"conditions": [{"type": "Succeeded", "status": "True"}]});
        create(&state, &with_status).await.expect("valid create");
        assert!(
            get(&state).await["status"]["conditions"].is_null(),
            "status must be cleared on create so a client cannot fake a finished migration"
        );
    }

    async fn status_write(state: &AppState, mode: &str, status: Value) -> (StatusCode, String) {
        let result = if mode == "put" {
            let mut body = full("", "foo");
            body["status"] = status;
            super::super::status::put_resource_status(
                State(state.clone()),
                name_path(),
                Extension(admin()),
                headers("application/json"),
                Bytes::from(serde_json::to_vec(&body).unwrap()),
            )
            .await
            .map(IntoResponse::into_response)
        } else {
            super::super::status::patch_resource_status(
                State(state.clone()),
                name_path(),
                Extension(admin()),
                headers("application/merge-patch+json"),
                Bytes::from(serde_json::to_vec(&json!({"status": status})).unwrap()),
            )
            .await
            .map(IntoResponse::into_response)
        };
        match result {
            Ok(r) => (r.status(), String::new()),
            Err(e) => (e.0, e.1.message),
        }
    }

    /// The /status write paths enforce the terminal-condition rules; without them a client
    /// could mark a finished migration unfinished and make the migrator re-run it.
    #[tokio::test]
    async fn status_paths_enforce_terminal_condition_rules_and_leave_spec_alone() {
        let state = make_state();
        create(&state, &full("", "foo")).await.expect("seed create");
        let done = json!({"conditions": [
            {"type": "Succeeded", "status": "True", "reason": "r", "lastTransitionTime": "2026-01-01T00:00:00Z"}
        ]});
        let undone = json!({"conditions": [
            {"type": "Succeeded", "status": "False", "reason": "r", "lastTransitionTime": "2026-01-01T00:00:00Z"}
        ]});
        for mode in ["put", "merge"] {
            let (status, message) = status_write(&state, mode, done.clone()).await;
            assert!(
                status.is_success(),
                "{mode}: marking done must work: {status} {message}"
            );
            let (status, message) = status_write(&state, mode, undone.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{mode}: {message}"
            );
            assert!(message.contains("Success condition"), "{mode}: {message}");
        }
        assert_eq!(get(&state).await["spec"]["resource"]["resource"], "foo");
    }

    fn svm(group: &str, resource: &str) -> Value {
        json!({"spec": {"resource": {"group": group, "resource": resource}}})
    }

    fn with_conditions(conds: &[(&str, &str)]) -> Value {
        let conds: Vec<Value> = conds
            .iter()
            .map(|(t, s)| json!({"type": t, "status": s}))
            .collect();
        json!({"status": {"conditions": conds}})
    }

    /// The conformance object targets the core group ("" group, resource "foo"): an empty
    /// group must be accepted or core-resource migrations could never be requested.
    #[test]
    fn spec_accepts_core_group_resource() {
        validate_spec(&svm("", "foo")).expect("core-group resource must be accepted");
        validate_spec(&svm("apps", "deployments")).expect("grouped resource must be accepted");
    }

    /// A missing resource name can never resolve through discovery, so it must be refused at
    /// create time instead of failing the migration later.
    #[test]
    fn spec_rejects_missing_resource() {
        assert!(validate_spec(&json!({})).is_err());
        assert!(validate_spec(&svm("apps", "")).is_err());
    }

    /// Resource must be a DNS-1035 label (letter first); a digit-leading or uppercase name is
    /// not a valid REST resource segment.
    #[test]
    fn spec_rejects_non_dns1035_resource_and_bad_group() {
        assert!(validate_spec(&svm("", "1foo")).is_err());
        assert!(validate_spec(&svm("", "Foo")).is_err());
        assert!(validate_spec(&svm("", "foo-")).is_err());
        assert!(validate_spec(&svm("Bad_Group", "foo")).is_err());
    }

    /// Spec is immutable: otherwise a client could retarget a migration whose status already
    /// describes progress on a different resource.
    #[test]
    fn spec_immutable_rejects_retargeting_but_ignores_empty_group_spelling() {
        assert!(
            validate_spec_immutable(&svm("apps", "deployments"), &svm("apps", "jobs")).is_err()
        );
        assert!(validate_spec_immutable(&svm("", "foo"), &svm("batch", "foo")).is_err());
        validate_spec_immutable(
            &svm("", "foo"),
            &json!({"spec": {"resource": {"resource": "foo"}}}),
        )
        .expect("absent group and empty group are the same core group");
    }

    /// Both terminal conditions True would tell consumers the migration simultaneously
    /// finished and failed.
    #[test]
    fn status_rejects_succeeded_and_failed_together() {
        let new = with_conditions(&[("Succeeded", "True"), ("Failed", "True")]);
        assert!(validate_status_update(&json!({}), &new).is_err());
    }

    /// A terminal condition is final: flipping Succeeded/Failed back would make the migrator
    /// re-run (or hide) a completed migration.
    #[test]
    fn status_rejects_unsetting_terminal_condition() {
        let done = with_conditions(&[("Succeeded", "True")]);
        let undone = with_conditions(&[("Succeeded", "False")]);
        assert!(validate_status_update(&done, &undone).is_err());
        let failed = with_conditions(&[("Failed", "True")]);
        assert!(validate_status_update(&failed, &json!({})).is_err());
        validate_status_update(&done, &done).expect("an unchanged terminal status is valid");
    }

    /// The conformance status update adds an arbitrary condition type; non-terminal
    /// conditions must pass freely.
    #[test]
    fn status_accepts_arbitrary_non_terminal_condition() {
        let new = with_conditions(&[("TestCondition", "True")]);
        validate_status_update(&json!({}), &new).expect("custom condition must be accepted");
    }

    /// status.resourceVersion is the GC-cache freshness anchor: once set it must not move, and
    /// it must be numeric.
    #[test]
    fn status_resource_version_is_numeric_and_frozen_once_set() {
        let set = |rv: &str| json!({"status": {"resourceVersion": rv}});
        validate_status_update(&json!({}), &set("42")).expect("first set is allowed");
        assert!(validate_status_update(&set("42"), &set("43")).is_err());
        assert!(validate_status_update(&set("42"), &json!({})).is_err());
        assert!(validate_status_update(&json!({}), &set("abc")).is_err());
    }
}
