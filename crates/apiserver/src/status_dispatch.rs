//! Typed-status GVK dispatch table.
//!
//! Root cause this closes: generic status handlers
//! manipulate `status` as raw `serde_json::Value`, so a scalar status silently
//! coerces (e.g. `NamespaceStatus::deserialize(v).unwrap_or_default()` turning
//! `"status": "oops"` into a stored `{}`) instead of being rejected. A typed decode
//! makes that a decode error by construction.
//!
//! Keyed on the composite `(apiVersion, kind)` pair, not `kind` alone — a kind can have
//! multiple wire shapes across versions (e.g. HorizontalPodAutoscaler v1 vs v2), so a
//! `kind`-only map would let a second entry for the same kind at a different apiVersion
//! silently overwrite the first via `HashMap::insert`. Composite-keying makes that a
//! distinct map entry instead of a collision, so differently-versioned same-named kinds
//! coexist by construction.
//!
//! Both wrappers are `Option`-returning: `None` means the (apiVersion, kind) pair
//! isn't registered yet, and the caller falls through to the existing dynamic
//! guard (`replace_status_field_dynamic` / `reject_non_object_status`) UNCHANGED.
//! This is what makes a non-migrated kind's behavior provably untouched, and lets
//! a future kind be added with one table entry, never touching a call site again.
//!
//! `null` is not handled here: RFC 7396 field-deletion (`{"status": null}`) is
//! legal for every kind regardless of typed shape, so callers check `is_null()`
//! before invoking either wrapper, same convention as
//! `handlers::status::apply_status_replacement`.

use crate::status::{Status, StatusError};
use crate::types::{
    ApiServiceStatus, CertificateSigningRequestStatus, CronJobStatus, DaemonSetStatus,
    DeploymentStatus, DeviceClassStatus, FlowSchemaStatus, HorizontalPodAutoscalerStatusV1,
    HorizontalPodAutoscalerStatusV2, IngressStatus, JobStatus, NamespaceStatus, NodeStatus,
    PersistentVolumeClaimStatus, PersistentVolumeStatus, PodCertificateRequestStatus, PodStatus,
    PriorityLevelConfigurationStatus, ReplicaSetStatus, ReplicationControllerStatus,
    ResourceClaimStatus, ResourceQuotaStatus, ServiceCidrStatus, StatefulSetStatus,
    ValidatingAdmissionPolicyBindingStatus, ValidatingAdmissionPolicyStatus,
    VolumeAttachmentStatus,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::OnceLock;

type StatusCodec = fn(&Value) -> Result<Value, serde_json::Error>;

/// Deserializes into `T` then re-serializes, so every registered kind's status is
/// canonicalized the same way regardless of its concrete struct — mirrors
/// `proto.rs`'s per-kind decoder table, generic instead of hand-written per kind
/// because every entry here does the identical decode-then-reencode.
fn codec<T: serde::Serialize + serde::de::DeserializeOwned>(
    v: &Value,
) -> Result<Value, serde_json::Error> {
    let typed: T = serde_json::from_value(v.clone())?;
    serde_json::to_value(typed)
}

/// Keyed on the full (apiVersion, kind) pair, not `kind` alone — a `HashMap` keyed on
/// `kind` would let a second entry for the same kind at a different apiVersion silently
/// overwrite the first via `insert`, and no lookup-time check catches it. Composite-keying
/// makes that collision a distinct map entry instead, so a future differently-versioned
/// same-named kind (e.g. HorizontalPodAutoscaler v1 vs v2) coexists by construction.
fn status_codecs() -> &'static HashMap<(&'static str, &'static str), StatusCodec> {
    static CODECS: OnceLock<HashMap<(&'static str, &'static str), StatusCodec>> = OnceLock::new();
    CODECS.get_or_init(|| {
        let mut m: HashMap<(&'static str, &'static str), StatusCodec> = HashMap::new();
        m.insert(("v1", "Namespace"), codec::<NamespaceStatus>);
        m.insert(
            ("certificates.k8s.io/v1", "CertificateSigningRequest"),
            codec::<CertificateSigningRequestStatus>,
        );
        m.insert(
            ("apiregistration.k8s.io/v1", "APIService"),
            codec::<ApiServiceStatus>,
        );
        m.insert(("v1", "ResourceQuota"), codec::<ResourceQuotaStatus>);
        m.insert(("v1", "Pod"), codec::<PodStatus>);
        // Phase 3 (m10di) — the remaining built-in status kinds, grouped by resource family.
        // apps/v1
        m.insert(("apps/v1", "Deployment"), codec::<DeploymentStatus>);
        m.insert(("apps/v1", "ReplicaSet"), codec::<ReplicaSetStatus>);
        m.insert(("apps/v1", "StatefulSet"), codec::<StatefulSetStatus>);
        m.insert(("apps/v1", "DaemonSet"), codec::<DaemonSetStatus>);
        // batch/v1
        m.insert(("batch/v1", "Job"), codec::<JobStatus>);
        m.insert(("batch/v1", "CronJob"), codec::<CronJobStatus>);
        // core/v1 (bare "v1")
        m.insert(("v1", "PersistentVolume"), codec::<PersistentVolumeStatus>);
        m.insert(
            ("v1", "PersistentVolumeClaim"),
            codec::<PersistentVolumeClaimStatus>,
        );
        m.insert(
            ("v1", "ReplicationController"),
            codec::<ReplicationControllerStatus>,
        );
        m.insert(("v1", "Node"), codec::<NodeStatus>);
        // autoscaling/v1 and autoscaling/v2 — the version-keying case: same kind, two
        // distinct wire shapes, resolved by the composite (apiVersion, kind) key.
        m.insert(
            ("autoscaling/v1", "HorizontalPodAutoscaler"),
            codec::<HorizontalPodAutoscalerStatusV1>,
        );
        m.insert(
            ("autoscaling/v2", "HorizontalPodAutoscaler"),
            codec::<HorizontalPodAutoscalerStatusV2>,
        );
        // networking.k8s.io/v1
        m.insert(("networking.k8s.io/v1", "Ingress"), codec::<IngressStatus>);
        m.insert(
            ("networking.k8s.io/v1", "ServiceCIDR"),
            codec::<ServiceCidrStatus>,
        );
        // storage.k8s.io/v1
        m.insert(
            ("storage.k8s.io/v1", "VolumeAttachment"),
            codec::<VolumeAttachmentStatus>,
        );
        // flowcontrol.apiserver.k8s.io/v1
        m.insert(
            ("flowcontrol.apiserver.k8s.io/v1", "FlowSchema"),
            codec::<FlowSchemaStatus>,
        );
        m.insert(
            (
                "flowcontrol.apiserver.k8s.io/v1",
                "PriorityLevelConfiguration",
            ),
            codec::<PriorityLevelConfigurationStatus>,
        );
        // admissionregistration.k8s.io/v1
        m.insert(
            (
                "admissionregistration.k8s.io/v1",
                "ValidatingAdmissionPolicy",
            ),
            codec::<ValidatingAdmissionPolicyStatus>,
        );
        m.insert(
            (
                "admissionregistration.k8s.io/v1",
                "ValidatingAdmissionPolicyBinding",
            ),
            codec::<ValidatingAdmissionPolicyBindingStatus>,
        );
        // resource.k8s.io/v1 (Dynamic Resource Allocation)
        m.insert(
            ("resource.k8s.io/v1", "ResourceClaim"),
            codec::<ResourceClaimStatus>,
        );
        m.insert(
            ("resource.k8s.io/v1", "DeviceClass"),
            codec::<DeviceClassStatus>,
        );
        // certificates.k8s.io/v1beta1
        m.insert(
            ("certificates.k8s.io/v1beta1", "PodCertificateRequest"),
            codec::<PodCertificateRequestStatus>,
        );
        // Test-only: none of the real Phase-1 kinds above collide on `kind` today, so this
        // synthetic pair is what makes `composite_key_keeps_both_api_versions_resolvable`
        // below an actual regression test instead of a no-op — see that test's doc comment.
        #[cfg(test)]
        {
            m.insert(
                ("test.example.com/v1", "SameKindDifferentVersion"),
                codec::<NamespaceStatus>,
            );
            m.insert(
                ("test.example.com/v2", "SameKindDifferentVersion"),
                codec::<ApiServiceStatus>,
            );
        }
        m
    })
}

fn lookup(api_version: &str, kind: &str) -> Option<StatusCodec> {
    status_codecs().get(&(api_version, kind)).copied()
}

/// PUT /status: a present-but-non-decodable status is upstream's whole-body typed-decode
/// failure (`transformDecodeError` -> `NewBadRequest`) -> 400.
pub(crate) fn decode_status_put(
    api_version: &str,
    kind: &str,
    incoming: &Value,
) -> Option<Result<Value, StatusError>> {
    lookup(api_version, kind)
        .map(|f| f(incoming).map_err(|e| Status::bad_request(format!("status: {e}"))))
}

/// PATCH (merge-PATCH / JSON-Patch / strategic-merge) post-merge convergence point: a
/// merged status that fails the same typed decode is upstream's post-merge validation
/// failure (`DecodeInto` -> `NewInvalid`) -> 422.
pub(crate) fn decode_status_patch(
    api_version: &str,
    kind: &str,
    merged: &Value,
) -> Option<Result<Value, StatusError>> {
    lookup(api_version, kind)
        .map(|f| f(merged).map_err(|e| Status::unprocessable_entity(format!("status: {e}"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A kind not in the table must fall through (`None`), not be silently accepted or
    /// rejected — this is the property that keeps every non-migrated kind's behavior
    /// untouched by Phase-1.
    #[test]
    fn unregistered_kind_returns_none() {
        assert!(decode_status_put("example.com/v1", "Widget", &json!({})).is_none());
        assert!(decode_status_patch("example.com/v1", "Widget", &json!({})).is_none());
    }

    /// A registered kind whose apiVersion doesn't match must also fall through — GVK
    /// keying, not kind-alone keying, is the whole point: a same-named kind at a
    /// different apiVersion must not be forced through the wrong codec.
    #[test]
    fn registered_kind_wrong_api_version_returns_none() {
        assert!(decode_status_put("v2", "Namespace", &json!({})).is_none());
    }

    /// Fail-on-revert test for the kind-only-keying bug: a `HashMap<&'static str,
    /// CodecEntry>` keyed on `kind` alone lets a second `insert` for the same kind
    /// silently overwrite the first, so one of two same-named, differently-versioned
    /// kinds becomes permanently unresolvable. `status_codecs()` registers exactly such a
    /// pair under `#[cfg(test)]` (`SameKindDifferentVersion` at two apiVersions) so this
    /// test exercises the real dispatch table, not a throwaway local map: reverting the
    /// composite `(apiVersion, kind)` key back to kind-only keying makes the first
    /// `lookup` call below return `None` (the entry was overwritten by the second
    /// `insert`), failing this test.
    #[test]
    fn composite_key_keeps_both_api_versions_resolvable() {
        assert!(
            lookup("test.example.com/v1", "SameKindDifferentVersion").is_some(),
            "the v1 entry must survive a same-kind v2 entry being registered afterward"
        );
        assert!(
            lookup("test.example.com/v2", "SameKindDifferentVersion").is_some(),
            "the v2 entry must also resolve — both apiVersions of one kind coexist"
        );
    }

    /// Fail-on-revert test for the silent-coercion bug: a scalar status
    /// must decode to `Err`, never to a defaulted value. Reverting the typed `codec::<T>`
    /// call back to `.unwrap_or_default()`-style handling makes this test fail because
    /// `Ok(Value::Object({}))` would compare unequal to nothing — the test only passes
    /// if the call site actually observes an `Err`.
    #[test]
    fn scalar_status_is_rejected_not_defaulted() {
        let put_result = decode_status_put("v1", "Namespace", &json!("oops"))
            .expect("Namespace is registered")
            .expect_err("a scalar status must not decode into a default NamespaceStatus");
        assert_eq!(put_result.0, axum::http::StatusCode::BAD_REQUEST);

        let patch_result = decode_status_patch("v1", "Namespace", &json!("oops"))
            .expect("Namespace is registered")
            .expect_err("a scalar status must not decode into a default NamespaceStatus");
        assert_eq!(patch_result.0, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// An array status must be rejected the same way a scalar is — both are "not an
    /// object", the same upstream typed-decode failure.
    #[test]
    fn array_status_is_rejected() {
        assert!(decode_status_put("v1", "Namespace", &json!([1, 2, 3]))
            .expect("Namespace is registered")
            .is_err());
    }

    /// Round-trip: every enumerated field set decodes and re-encodes losslessly for each
    /// of the three Phase-1 kinds — proves the dispatch table actually reaches the typed
    /// struct for all three entries, not just the one exercised by the scalar test above.
    #[test]
    fn round_trips_enumerated_fields_for_all_three_kinds() {
        let ns = json!({"phase": "Terminating"});
        let decoded = decode_status_put("v1", "Namespace", &ns)
            .expect("Namespace is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["phase"], "Terminating");

        let csr =
            json!({"certificate": "abc==", "conditions": [{"type": "Approved", "status": "True"}]});
        let decoded =
            decode_status_put("certificates.k8s.io/v1", "CertificateSigningRequest", &csr)
                .expect("CertificateSigningRequest is registered")
                .expect("valid status must decode");
        assert_eq!(decoded["certificate"], "abc==");
        assert_eq!(decoded["conditions"][0]["type"], "Approved");

        let apisvc = json!({"conditions": [{"type": "Available", "status": "True"}]});
        let decoded = decode_status_put("apiregistration.k8s.io/v1", "APIService", &apisvc)
            .expect("APIService is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["type"], "Available");
    }

    /// The flatten-rest lossless-passthrough property: a field no enumerated struct
    /// field names must survive verbatim, not be dropped. This is the safety property
    /// that makes hand-written minimal-field structs acceptable instead of a lossy
    /// codegen struct — under-enumerating a field must cost "not validated yet", never
    /// data loss.
    #[test]
    fn unrecognized_field_survives_via_rest() {
        let ns = json!({"phase": "Active", "someFutureField": {"nested": 1}});
        let decoded = decode_status_put("v1", "Namespace", &ns)
            .expect("Namespace is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["someFutureField"]["nested"], 1);

        let apisvc = json!({"conditions": [], "someFutureField": "x"});
        let decoded = decode_status_put("apiregistration.k8s.io/v1", "APIService", &apisvc)
            .expect("APIService is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["someFutureField"], "x");
    }

    // ---------------------------------------------------------------------------
    // Phase 3 (m10di) — the ~20 remaining built-in status kinds. Each test below
    // round-trips a real-shaped status payload for every kind in a resource family and
    // asserts (a) every enumerated field decodes and re-encodes losslessly, and (b) at
    // least one field NOT enumerated on the struct survives verbatim via `rest` — a
    // controller reading that field back after a write would starve without this.
    // ---------------------------------------------------------------------------

    /// apps/v1 workloads: Deployment, ReplicaSet, StatefulSet, DaemonSet. Each has its own
    /// condition shape (`WorkloadCondition`), so each gets its own `someFutureField`-style
    /// unknown-field check to prove `rest` catches it independently of the others.
    #[test]
    fn phase3_apps_v1_workload_statuses_round_trip_and_preserve_unknown_fields() {
        let deploy = json!({
            "observedGeneration": 2,
            "replicas": 3,
            "updatedReplicas": 3,
            "readyReplicas": 2,
            "availableReplicas": 2,
            "unavailableReplicas": 1,
            "terminatingReplicas": 0,
            "collisionCount": 1,
            "conditions": [{
                "type": "Available", "status": "True",
                "lastUpdateTime": "2026-01-01T00:00:00Z",
                "lastTransitionTime": "2026-01-01T00:00:00Z",
                "reason": "MinimumReplicasAvailable", "message": "ok"
            }],
            "someFutureField": "deploy-x"
        });
        let decoded = decode_status_put("apps/v1", "Deployment", &deploy)
            .expect("Deployment is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["replicas"], 3);
        assert_eq!(decoded["collisionCount"], 1);
        assert_eq!(
            decoded["conditions"][0]["lastUpdateTime"], "2026-01-01T00:00:00Z",
            "DeploymentCondition's lastUpdateTime is the one field WorkloadCondition has \
             that no other reused-condition kind does — it must not be dropped"
        );
        assert_eq!(decoded["someFutureField"], "deploy-x");

        let rs = json!({
            "replicas": 4, "fullyLabeledReplicas": 4, "readyReplicas": 3,
            "availableReplicas": 3, "terminatingReplicas": 0, "observedGeneration": 1,
            "conditions": [{"type": "ReplicaFailure", "status": "False"}],
            "someFutureField": "rs-x"
        });
        let decoded = decode_status_put("apps/v1", "ReplicaSet", &rs)
            .expect("ReplicaSet is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["fullyLabeledReplicas"], 4);
        assert_eq!(decoded["someFutureField"], "rs-x");

        let sts = json!({
            "observedGeneration": 5, "replicas": 3, "readyReplicas": 3, "currentReplicas": 3,
            "updatedReplicas": 3, "currentRevision": "web-abcd", "updateRevision": "web-abcd",
            "collisionCount": 0, "availableReplicas": 3,
            "conditions": [{"type": "Ready", "status": "True"}],
            "someFutureField": "sts-x"
        });
        let decoded = decode_status_put("apps/v1", "StatefulSet", &sts)
            .expect("StatefulSet is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["currentRevision"], "web-abcd");
        assert_eq!(decoded["someFutureField"], "sts-x");

        let ds = json!({
            "currentNumberScheduled": 3, "numberMisscheduled": 0, "desiredNumberScheduled": 3,
            "numberReady": 3, "observedGeneration": 1, "updatedNumberScheduled": 3,
            "numberAvailable": 3, "numberUnavailable": 0, "collisionCount": 0,
            "conditions": [{"type": "Available", "status": "True"}],
            "someFutureField": "ds-x"
        });
        let decoded = decode_status_put("apps/v1", "DaemonSet", &ds)
            .expect("DaemonSet is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["desiredNumberScheduled"], 3);
        assert_eq!(decoded["someFutureField"], "ds-x");
    }

    /// autoscaling/v1 and autoscaling/v2 HorizontalPodAutoscaler are the version-keying
    /// case: same kind, two different apiVersions, two different wire shapes — v1's scalar
    /// `currentCPUUtilizationPercentage` vs v2's `conditions`/`currentMetrics`. Both entries
    /// must resolve independently, proving the composite (apiVersion, kind) key does its
    /// job for a REAL kind, not just the synthetic `SameKindDifferentVersion` test pair.
    #[test]
    fn phase3_hpa_v1_and_v2_are_distinct_gvk_entries() {
        let v1 = json!({
            "observedGeneration": 1, "lastScaleTime": "2026-01-01T00:00:00Z",
            "currentReplicas": 2, "desiredReplicas": 3,
            "currentCPUUtilizationPercentage": 70,
            "someFutureField": "hpa-v1-x"
        });
        let decoded = decode_status_put("autoscaling/v1", "HorizontalPodAutoscaler", &v1)
            .expect("autoscaling/v1 HorizontalPodAutoscaler is registered")
            .expect("valid v1 status must decode");
        assert_eq!(
            decoded["currentCPUUtilizationPercentage"], 70,
            "the explicit rename must produce upstream's all-caps CPU spelling on the wire"
        );
        assert_eq!(decoded["someFutureField"], "hpa-v1-x");

        let v2 = json!({
            "observedGeneration": 1, "currentReplicas": 2, "desiredReplicas": 3,
            "conditions": [{"type": "AbleToScale", "status": "True"}],
            "currentMetrics": [{"type": "Resource"}],
            "someFutureField": "hpa-v2-x"
        });
        let decoded = decode_status_put("autoscaling/v2", "HorizontalPodAutoscaler", &v2)
            .expect("autoscaling/v2 HorizontalPodAutoscaler is registered")
            .expect("valid v2 status must decode");
        assert_eq!(decoded["conditions"][0]["type"], "AbleToScale");
        assert_eq!(
            decoded["currentMetrics"][0]["type"], "Resource",
            "currentMetrics is a nested list nothing in u7s reasons about — it must \
             survive via rest, not be dropped for being unenumerated"
        );
        assert_eq!(decoded["someFutureField"], "hpa-v2-x");

        // v1 and v2 must not cross-contaminate: a v1 payload has no `conditions`, so
        // decoding it through v1's codec must not spuriously invent one, and v2's codec
        // must still be independently reachable after v1's lookup above.
        assert!(decoded.get("currentCPUUtilizationPercentage").is_none());
    }

    /// batch/v1: Job, CronJob.
    #[test]
    fn phase3_batch_v1_statuses_round_trip_and_preserve_unknown_fields() {
        let job = json!({
            "conditions": [{"type": "Complete", "status": "True", "lastProbeTime": "2026-01-01T00:00:00Z"}],
            "startTime": "2026-01-01T00:00:00Z", "completionTime": "2026-01-01T00:05:00Z",
            "active": 0, "succeeded": 3, "failed": 0, "terminating": 0,
            "completedIndexes": "0-2", "ready": 0,
            "someFutureField": "job-x"
        });
        let decoded = decode_status_put("batch/v1", "Job", &job)
            .expect("Job is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["succeeded"], 3);
        assert_eq!(decoded["completedIndexes"], "0-2");
        assert_eq!(
            decoded["conditions"][0]["lastProbeTime"], "2026-01-01T00:00:00Z",
            "JobCondition's lastProbeTime must survive — PodCondition (reused here) carries it"
        );
        assert_eq!(decoded["someFutureField"], "job-x");

        let cronjob = json!({
            "active": [{"name": "job-1", "namespace": "default"}],
            "lastScheduleTime": "2026-01-01T00:00:00Z",
            "lastSuccessfulTime": "2026-01-01T00:00:00Z",
            "someFutureField": "cronjob-x"
        });
        let decoded = decode_status_put("batch/v1", "CronJob", &cronjob)
            .expect("CronJob is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["lastScheduleTime"], "2026-01-01T00:00:00Z");
        assert_eq!(
            decoded["active"][0]["name"], "job-1",
            "active (a list of ObjectReferences) is not enumerated — it must survive via rest"
        );
        assert_eq!(decoded["someFutureField"], "cronjob-x");
    }

    /// core/v1: PersistentVolume, PersistentVolumeClaim, ReplicationController, Node.
    #[test]
    fn phase3_core_v1_statuses_round_trip_and_preserve_unknown_fields() {
        let pv = json!({
            "phase": "Bound", "message": "bound ok", "reason": "",
            "lastPhaseTransitionTime": "2026-01-01T00:00:00Z",
            "someFutureField": "pv-x"
        });
        let decoded = decode_status_put("v1", "PersistentVolume", &pv)
            .expect("PersistentVolume is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["phase"], "Bound");
        assert_eq!(decoded["someFutureField"], "pv-x");

        // Real payload from the '[sig-storage] PersistentVolumes CSI Conformance should
        // apply changes to a pv/pvc status' conformance test (see status.rs's
        // pvc_status_conditions_persisted_via_patch) — a condition with no lastTransitionTime.
        let pvc = json!({
            "phase": "Bound", "accessModes": ["ReadWriteOnce"],
            "capacity": {"storage": "1Gi"},
            "conditions": [{"type": "StatusUpdated", "status": "True", "reason": "CSITest", "message": "applied by conformance test"}],
            "allocatedResources": {"storage": "1Gi"},
            "allocatedResourceStatuses": {"storage": "NodeResizeInProgress"},
            "currentVolumeAttributesClassName": "gold",
            "someFutureField": "pvc-x"
        });
        let decoded = decode_status_put("v1", "PersistentVolumeClaim", &pvc)
            .expect("PersistentVolumeClaim is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["capacity"]["storage"], "1Gi");
        assert_eq!(decoded["conditions"][0]["type"], "StatusUpdated");
        assert_eq!(
            decoded["allocatedResourceStatuses"]["storage"],
            "NodeResizeInProgress"
        );
        assert_eq!(decoded["someFutureField"], "pvc-x");

        let rc = json!({
            "replicas": 2, "fullyLabeledReplicas": 2, "readyReplicas": 2,
            "availableReplicas": 2, "observedGeneration": 1,
            "conditions": [{"type": "ReplicaFailure", "status": "False"}],
            "someFutureField": "rc-x"
        });
        let decoded = decode_status_put("v1", "ReplicationController", &rc)
            .expect("ReplicationController is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["replicas"], 2);
        assert_eq!(decoded["someFutureField"], "rc-x");

        // Node: capacity/allocatable are the scheduler's own fit-check inputs; conditions
        // carries lastHeartbeatTime, which neither `Condition` nor `WorkloadCondition` has a
        // slot for (that's why NodeCondition exists).
        let node = json!({
            "capacity": {"cpu": "4", "memory": "8Gi"},
            "allocatable": {"cpu": "3800m", "memory": "7Gi"},
            "conditions": [{
                "type": "Ready", "status": "True",
                "lastHeartbeatTime": "2026-01-01T00:00:10Z",
                "lastTransitionTime": "2026-01-01T00:00:00Z"
            }],
            "someFutureField": "node-x"
        });
        let decoded = decode_status_put("v1", "Node", &node)
            .expect("Node is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["allocatable"]["cpu"], "3800m");
        assert_eq!(
            decoded["conditions"][0]["lastHeartbeatTime"], "2026-01-01T00:00:10Z",
            "kubelet re-stamps lastHeartbeatTime on every periodic node status resync — \
             dropping it would desync every consumer of node freshness"
        );
        assert_eq!(decoded["someFutureField"], "node-x");
    }

    /// networking.k8s.io/v1 (Ingress, ServiceCIDR) and storage.k8s.io/v1 (VolumeAttachment).
    #[test]
    fn phase3_networking_and_storage_statuses_round_trip_and_preserve_unknown_fields() {
        let ingress = json!({
            "loadBalancer": {"ingress": [{"ip": "10.0.0.1"}]},
            "someFutureField": "ingress-x"
        });
        let decoded = decode_status_put("networking.k8s.io/v1", "Ingress", &ingress)
            .expect("Ingress is registered")
            .expect("valid status must decode");
        assert_eq!(
            decoded["loadBalancer"]["ingress"][0]["ip"], "10.0.0.1",
            "loadBalancer is IngressStatus's only field and is entirely unenumerated — it \
             must survive via rest wholesale, not just the fields alongside it"
        );
        assert_eq!(decoded["someFutureField"], "ingress-x");

        let svc_cidr = json!({
            "conditions": [{"type": "Ready", "status": "True", "reason": "Allocated", "message": "ok"}],
            "someFutureField": "cidr-x"
        });
        let decoded = decode_status_put("networking.k8s.io/v1", "ServiceCIDR", &svc_cidr)
            .expect("ServiceCIDR is registered")
            .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["reason"], "Allocated");
        assert_eq!(decoded["someFutureField"], "cidr-x");

        let volume_attachment = json!({
            "attached": true,
            "attachmentMetadata": {"devicePath": "/dev/xvdf"},
            "attachError": {"message": "transient", "time": "2026-01-01T00:00:00Z"},
            "someFutureField": "va-x"
        });
        let decoded =
            decode_status_put("storage.k8s.io/v1", "VolumeAttachment", &volume_attachment)
                .expect("VolumeAttachment is registered")
                .expect("valid status must decode");
        assert_eq!(decoded["attached"], true);
        assert_eq!(decoded["attachmentMetadata"]["devicePath"], "/dev/xvdf");
        assert_eq!(
            decoded["attachError"]["message"], "transient",
            "attachError is a nested VolumeError nothing in u7s reasons about — it must \
             survive via rest"
        );
        assert_eq!(decoded["someFutureField"], "va-x");
    }

    /// flowcontrol.apiserver.k8s.io/v1: FlowSchema, PriorityLevelConfiguration.
    #[test]
    fn phase3_flowcontrol_statuses_round_trip_and_preserve_unknown_fields() {
        let flow_schema = json!({
            "conditions": [{"type": "Dangling", "status": "False", "reason": "Bound", "message": "ok"}],
            "someFutureField": "fs-x"
        });
        let decoded = decode_status_put(
            "flowcontrol.apiserver.k8s.io/v1",
            "FlowSchema",
            &flow_schema,
        )
        .expect("FlowSchema is registered")
        .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["type"], "Dangling");
        assert_eq!(decoded["someFutureField"], "fs-x");

        let plc = json!({
            "conditions": [{"type": "Dangling", "status": "False"}],
            "someFutureField": "plc-x"
        });
        let decoded = decode_status_put(
            "flowcontrol.apiserver.k8s.io/v1",
            "PriorityLevelConfiguration",
            &plc,
        )
        .expect("PriorityLevelConfiguration is registered")
        .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["status"], "False");
        assert_eq!(decoded["someFutureField"], "plc-x");
    }

    /// admissionregistration.k8s.io/v1 (ValidatingAdmissionPolicy(+Binding)),
    /// resource.k8s.io/v1 (ResourceClaim, DeviceClass), certificates.k8s.io/v1beta1
    /// (PodCertificateRequest). Binding and DeviceClass have no status fields upstream at
    /// all — both structs are `rest`-only, so this proves an all-`rest` struct still
    /// round-trips an arbitrary object body rather than rejecting it.
    #[test]
    fn phase3_admissionregistration_dra_and_certificates_statuses_round_trip() {
        let vap = json!({
            "observedGeneration": 1,
            "conditions": [{"type": "Ready", "status": "True"}],
            "typeChecking": {"expressionWarnings": [{"fieldRef": "spec.validations[0]"}]},
            "someFutureField": "vap-x"
        });
        let decoded = decode_status_put(
            "admissionregistration.k8s.io/v1",
            "ValidatingAdmissionPolicy",
            &vap,
        )
        .expect("ValidatingAdmissionPolicy is registered")
        .expect("valid status must decode");
        assert_eq!(decoded["conditions"][0]["type"], "Ready");
        assert_eq!(
            decoded["typeChecking"]["expressionWarnings"][0]["fieldRef"], "spec.validations[0]",
            "typeChecking is a nested structure nothing in u7s reasons about — rest only"
        );
        assert_eq!(decoded["someFutureField"], "vap-x");

        // ValidatingAdmissionPolicyBinding has no upstream status type at all; the struct
        // exists only to reject scalar/array status on u7s's (wider-than-upstream) route.
        let vap_binding = json!({"someFutureField": "vapb-x"});
        let decoded = decode_status_put(
            "admissionregistration.k8s.io/v1",
            "ValidatingAdmissionPolicyBinding",
            &vap_binding,
        )
        .expect("ValidatingAdmissionPolicyBinding is registered")
        .expect("an object body must still round-trip through an all-rest struct");
        assert_eq!(decoded["someFutureField"], "vapb-x");

        let resource_claim = json!({
            "allocation": {"nodeSelector": {}},
            "reservedFor": [{"resource": "pods", "name": "consumer", "uid": "abc"}],
            "someFutureField": "rc-dra-x"
        });
        let decoded = decode_status_put("resource.k8s.io/v1", "ResourceClaim", &resource_claim)
            .expect("ResourceClaim is registered")
            .expect("valid status must decode");
        assert_eq!(
            decoded["reservedFor"][0]["name"], "consumer",
            "every ResourceClaimStatus field is a nested DRA structure — all must survive \
             via rest since none are enumerated"
        );
        assert_eq!(decoded["someFutureField"], "rc-dra-x");

        let device_class = json!({"someFutureField": "dc-x"});
        let decoded = decode_status_put("resource.k8s.io/v1", "DeviceClass", &device_class)
            .expect("DeviceClass is registered")
            .expect("an object body must still round-trip through an all-rest struct");
        assert_eq!(decoded["someFutureField"], "dc-x");

        let pod_cert_req = json!({
            "conditions": [{"type": "Issued", "status": "True"}],
            "certificateChain": "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----",
            "notBefore": "2026-01-01T00:00:00Z",
            "beginRefreshAt": "2026-01-02T00:00:00Z",
            "notAfter": "2026-01-03T00:00:00Z",
            "someFutureField": "pcr-x"
        });
        let decoded = decode_status_put(
            "certificates.k8s.io/v1beta1",
            "PodCertificateRequest",
            &pod_cert_req,
        )
        .expect("PodCertificateRequest is registered")
        .expect("valid status must decode");
        assert_eq!(
            decoded["certificateChain"],
            "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----"
        );
        assert_eq!(decoded["notAfter"], "2026-01-03T00:00:00Z");
        assert_eq!(decoded["someFutureField"], "pcr-x");
    }

    /// Representative 400 (PUT)/422 (PATCH) scalar-status-rejection sample across three
    /// different Phase-3 families (apps, core, DRA) — proves the SAME typed-decode
    /// mechanism `scalar_status_is_rejected_not_defaulted` proved for Namespace also fires
    /// for the new bulk-registered kinds, not just the table lookup succeeding.
    #[test]
    fn phase3_new_kinds_reject_scalar_status_400_put_422_patch() {
        for (api_version, kind) in [
            ("apps/v1", "Deployment"),
            ("v1", "Node"),
            ("resource.k8s.io/v1", "ResourceClaim"),
        ] {
            let put_err = decode_status_put(api_version, kind, &json!("oops"))
                .unwrap_or_else(|| panic!("{kind} must be registered"))
                .expect_err(&format!("a scalar status must not decode for {kind}"));
            assert_eq!(
                put_err.0,
                axum::http::StatusCode::BAD_REQUEST,
                "PUT scalar status on {kind} must be 400 (whole-body typed decode failure)"
            );

            let patch_err = decode_status_patch(api_version, kind, &json!("oops"))
                .unwrap_or_else(|| panic!("{kind} must be registered"))
                .expect_err(&format!("a scalar status must not decode for {kind}"));
            assert_eq!(
                patch_err.0,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "PATCH scalar status on {kind} must stay 422 (post-merge validation failure)"
            );
        }
    }
}
