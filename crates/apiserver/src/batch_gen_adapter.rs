use prost::Message;

use crate::apps_gen::k8s::io::api::batch::v1 as batch_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

fn gen_pod_template_spec_to_json(
    tmpl: crate::apps_gen::k8s::io::api::core::v1::PodTemplateSpec,
) -> serde_json::Value {
    crate::core_gen_adapter::gen_pod_template_spec_to_json(tmpl)
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    crate::core_gen_adapter::gen_label_selector_to_json(sel)
}

fn gen_pod_failure_policy_to_json(pfp: batch_v1::PodFailurePolicy) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = pfp
        .rules
        .into_iter()
        .map(|r| {
            let mut rule = serde_json::json!({});
            if let Some(v) = r.action.filter(|s| !s.is_empty()) {
                rule["action"] = v.into();
            }
            if let Some(ec) = r.on_exit_codes {
                let mut ec_json = serde_json::json!({});
                if let Some(v) = ec.container_name.filter(|s| !s.is_empty()) {
                    ec_json["containerName"] = v.into();
                }
                if let Some(v) = ec.operator.filter(|s| !s.is_empty()) {
                    ec_json["operator"] = v.into();
                }
                if !ec.values.is_empty() {
                    ec_json["values"] = ec
                        .values
                        .into_iter()
                        .map(serde_json::Value::from)
                        .collect::<Vec<_>>()
                        .into();
                }
                rule["onExitCodes"] = ec_json;
            }
            if !r.on_pod_conditions.is_empty() {
                rule["onPodConditions"] = r
                    .on_pod_conditions
                    .into_iter()
                    .map(|c| {
                        let mut cond = serde_json::json!({});
                        if let Some(v) = c.r#type.filter(|s| !s.is_empty()) {
                            cond["type"] = v.into();
                        }
                        if let Some(v) = c.status.filter(|s| !s.is_empty()) {
                            cond["status"] = v.into();
                        }
                        cond
                    })
                    .collect::<Vec<_>>()
                    .into();
            }
            rule
        })
        .collect();
    serde_json::json!({ "rules": rules })
}

fn gen_success_policy_to_json(sp: batch_v1::SuccessPolicy) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = sp
        .rules
        .into_iter()
        .map(|r| {
            let mut rule = serde_json::json!({});
            if let Some(v) = r.succeeded_indexes.filter(|s| !s.is_empty()) {
                rule["succeededIndexes"] = v.into();
            }
            if let Some(v) = r.succeeded_count {
                rule["succeededCount"] = v.into();
            }
            rule
        })
        .collect();
    serde_json::json!({ "rules": rules })
}

fn gen_job_spec_to_json(spec: batch_v1::JobSpec) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    // parallelism/completions/activeDeadlineSeconds/backoffLimit/ttlSecondsAfterFinished are
    // upstream *int32/*int64 (proto3 optional); Some(0) is a legitimate value (e.g. "run 0 pods
    // in parallel", "retry 0 times") distinct from absent, so these must always be emitted
    // when Some(_).
    if let Some(v) = spec.parallelism {
        m.insert("parallelism".to_string(), v.into());
    }
    if let Some(v) = spec.completions {
        m.insert("completions".to_string(), v.into());
    }
    if let Some(v) = spec.active_deadline_seconds {
        m.insert("activeDeadlineSeconds".to_string(), v.into());
    }
    if let Some(v) = spec.backoff_limit {
        m.insert("backoffLimit".to_string(), v.into());
    }
    if let Some(v) = spec.ttl_seconds_after_finished {
        m.insert("ttlSecondsAfterFinished".to_string(), v.into());
    }
    if let Some(v) = spec.completion_mode.filter(|s| !s.is_empty()) {
        m.insert("completionMode".to_string(), v.into());
    }
    if let Some(true) = spec.suspend {
        m.insert("suspend".to_string(), true.into());
    }
    if let Some(v) = spec.pod_replacement_policy.filter(|s| !s.is_empty()) {
        m.insert("podReplacementPolicy".to_string(), v.into());
    }
    if let Some(v) = spec.backoff_limit_per_index {
        m.insert("backoffLimitPerIndex".to_string(), v.into());
    }
    if let Some(v) = spec.max_failed_indexes {
        m.insert("maxFailedIndexes".to_string(), v.into());
    }
    if let Some(v) = spec.managed_by.filter(|s| !s.is_empty()) {
        m.insert("managedBy".to_string(), v.into());
    }
    if let Some(sel) = spec.selector {
        m.insert("selector".to_string(), gen_label_selector_to_json(sel));
    }
    if let Some(true) = spec.manual_selector {
        m.insert("manualSelector".to_string(), true.into());
    }
    if let Some(pfp) = spec.pod_failure_policy {
        m.insert(
            "podFailurePolicy".to_string(),
            gen_pod_failure_policy_to_json(pfp),
        );
    }
    if let Some(sp) = spec.success_policy {
        m.insert("successPolicy".to_string(), gen_success_policy_to_json(sp));
    }
    let tmpl_json = if let Some(tmpl) = spec.template {
        let t = gen_pod_template_spec_to_json(tmpl);
        if t.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            t
        }
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    m.insert("template".to_string(), tmpl_json);
    serde_json::Value::Object(m)
}

// ---- Decoder A: Job --------------------------------------------------------

pub fn decode_job_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let job = batch_v1::Job::decode(data).ok()?;
    let meta = gen_object_meta_to_json(job.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": meta
    });
    if let Some(spec) = job.spec {
        out["spec"] = gen_job_spec_to_json(spec);
    }
    if let Some(status) = job.status {
        let mut status_json = serde_json::json!({});
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| {
                    let mut cond = serde_json::json!({
                        "type": c.r#type.clone().unwrap_or_default(),
                        "status": c.status.clone().unwrap_or_default(),
                    });
                    if let Some(ref r) = c.reason {
                        if !r.is_empty() {
                            cond["reason"] = r.clone().into();
                        }
                    }
                    if let Some(ref msg) = c.message {
                        if !msg.is_empty() {
                            cond["message"] = msg.clone().into();
                        }
                    }
                    if let Some(t) = c.last_probe_time.as_ref() {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cond["lastProbeTime"] = crate::util::secs_to_rfc3339(secs).into();
                        }
                    }
                    if let Some(t) = c.last_transition_time.as_ref() {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cond["lastTransitionTime"] = crate::util::secs_to_rfc3339(secs).into();
                        }
                    }
                    cond
                })
                .collect();
        }
        if let Some(t) = status.start_time.as_ref() {
            if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                status_json["startTime"] = crate::util::secs_to_rfc3339(secs).into();
            }
        }
        if let Some(t) = status.completion_time.as_ref() {
            if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                status_json["completionTime"] = crate::util::secs_to_rfc3339(secs).into();
            }
        }
        // active/succeeded/failed/ready/terminating are upstream *int32 (proto3
        // optional); Some(0) is a legitimate value (e.g. 0 pods currently ready)
        // distinct from absent, so these must always be emitted when Some(_).
        if let Some(v) = status.active {
            status_json["active"] = v.into();
        }
        if let Some(v) = status.succeeded {
            status_json["succeeded"] = v.into();
        }
        if let Some(v) = status.failed {
            status_json["failed"] = v.into();
        }
        if let Some(v) = status.completed_indexes.filter(|s| !s.is_empty()) {
            status_json["completedIndexes"] = v.into();
        }
        if let Some(utp) = status.uncounted_terminated_pods {
            let mut utp_map = serde_json::Map::new();
            if !utp.succeeded.is_empty() {
                utp_map.insert(
                    "succeeded".to_string(),
                    utp.succeeded
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
            if !utp.failed.is_empty() {
                utp_map.insert(
                    "failed".to_string(),
                    utp.failed
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect::<Vec<_>>()
                        .into(),
                );
            }
            // Always emit the key when the proto field is Some, even if both lists are empty:
            // upstream's Job controller treats non-nil-ness of this pointer as load-bearing
            // state (JobTrackingWithFinalizers) and nil-derefs if a present-but-empty struct
            // round-trips as absent (job_controller.go:1568).
            status_json["uncountedTerminatedPods"] = serde_json::Value::Object(utp_map);
        }
        if let Some(v) = status.ready {
            status_json["ready"] = v.into();
        }
        if let Some(v) = status.failed_indexes.filter(|s| !s.is_empty()) {
            status_json["failedIndexes"] = v.into();
        }
        if let Some(v) = status.terminating {
            status_json["terminating"] = v.into();
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: CronJob ----------------------------------------------------

pub fn decode_cronjob_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let cj = batch_v1::CronJob::decode(data).ok()?;
    let meta = gen_object_meta_to_json(cj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": meta
    });
    if let Some(spec) = cj.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(v) = spec.schedule.filter(|s| !s.is_empty()) {
            spec_map.insert("schedule".to_string(), v.into());
        }
        // startingDeadlineSeconds/successfulJobsHistoryLimit/failedJobsHistoryLimit are
        // upstream *int64/*int32 (proto3 optional); Some(0) is a legitimate value (e.g. "keep
        // no history") distinct from absent, so these must always be emitted when Some(_).
        if let Some(v) = spec.starting_deadline_seconds {
            spec_map.insert("startingDeadlineSeconds".to_string(), v.into());
        }
        if let Some(v) = spec.concurrency_policy.filter(|s| !s.is_empty()) {
            spec_map.insert("concurrencyPolicy".to_string(), v.into());
        }
        if let Some(true) = spec.suspend {
            spec_map.insert("suspend".to_string(), true.into());
        }
        if let Some(v) = spec.successful_jobs_history_limit {
            spec_map.insert("successfulJobsHistoryLimit".to_string(), v.into());
        }
        if let Some(v) = spec.failed_jobs_history_limit {
            spec_map.insert("failedJobsHistoryLimit".to_string(), v.into());
        }
        if let Some(v) = spec.time_zone.filter(|s| !s.is_empty()) {
            spec_map.insert("timeZone".to_string(), v.into());
        }
        let jt_meta = spec
            .job_template
            .as_ref()
            .and_then(|jt| jt.metadata.clone())
            .map(gen_object_meta_to_json)
            .unwrap_or_else(|| serde_json::json!({"creationTimestamp": serde_json::Value::Null}));
        let jt_spec = spec
            .job_template
            .and_then(|jt| jt.spec)
            .map(gen_job_spec_to_json)
            .unwrap_or_else(|| serde_json::json!({"template": {}}));
        spec_map.insert(
            "jobTemplate".to_string(),
            serde_json::json!({
                "metadata": jt_meta,
                "spec": jt_spec
            }),
        );
        out["spec"] = serde_json::Value::Object(spec_map);
    }
    if let Some(status) = cj.status {
        let mut status_json = serde_json::json!({});
        if !status.active.is_empty() {
            status_json["active"] = status
                .active
                .iter()
                .filter_map(|r| {
                    let name = r.name.as_deref().unwrap_or("");
                    let ns = r.namespace.as_deref().unwrap_or("");
                    if name.is_empty() && ns.is_empty() {
                        return None;
                    }
                    let mut entry = serde_json::json!({});
                    if !name.is_empty() {
                        entry["name"] = name.to_string().into();
                    }
                    if !ns.is_empty() {
                        entry["namespace"] = ns.to_string().into();
                    }
                    if let Some(v) = r.kind.as_deref().filter(|s| !s.is_empty()) {
                        entry["kind"] = v.to_string().into();
                    }
                    if let Some(v) = r.api_version.as_deref().filter(|s| !s.is_empty()) {
                        entry["apiVersion"] = v.to_string().into();
                    }
                    if let Some(v) = r.uid.as_deref().filter(|s| !s.is_empty()) {
                        entry["uid"] = v.to_string().into();
                    }
                    if let Some(v) = r.resource_version.as_deref().filter(|s| !s.is_empty()) {
                        entry["resourceVersion"] = v.to_string().into();
                    }
                    if let Some(v) = r.field_path.as_deref().filter(|s| !s.is_empty()) {
                        entry["fieldPath"] = v.to_string().into();
                    }
                    Some(entry)
                })
                .collect::<Vec<_>>()
                .into();
        }
        if let Some(t) = status.last_schedule_time.as_ref() {
            if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                status_json["lastScheduleTime"] = crate::util::secs_to_rfc3339(secs).into();
            }
        }
        if let Some(t) = status.last_successful_time.as_ref() {
            if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                status_json["lastSuccessfulTime"] = crate::util::secs_to_rfc3339(secs).into();
            }
        }
        if status_json
            .as_object()
            .map(|m| !m.is_empty())
            .unwrap_or(false)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_job_success_policy_survives_decode_by_construction() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("sp-job".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completions: Some(3),
                completion_mode: Some("Indexed".to_string()),
                success_policy: Some(batch_v1::SuccessPolicy {
                    rules: vec![batch_v1::SuccessPolicyRule {
                        succeeded_indexes: Some("0-1".to_string()),
                        succeeded_count: Some(2),
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect(
            "Job with successPolicy must decode — generated struct has this field by construction",
        );

        assert_eq!(
            result["spec"]["successPolicy"]["rules"][0]["succeededIndexes"], "0-1",
            "successPolicy.succeededIndexes must survive: generated struct covers this field by \
             construction; hand struct could drop it silently, causing Job to never reach terminal condition"
        );
        assert_eq!(
            result["spec"]["successPolicy"]["rules"][0]["succeededCount"], 2,
            "successPolicy.succeededCount must survive: kcm uses this to declare Job as succeeded"
        );
    }

    #[test]
    fn generated_job_pod_failure_policy_survives_decode_by_construction() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("pfp-job".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                completion_mode: Some("Indexed".to_string()),
                pod_failure_policy: Some(batch_v1::PodFailurePolicy {
                    rules: vec![batch_v1::PodFailurePolicyRule {
                        action: Some("Ignore".to_string()),
                        on_exit_codes: Some(batch_v1::PodFailurePolicyOnExitCodesRequirement {
                            operator: Some("In".to_string()),
                            values: vec![42],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job with podFailurePolicy must decode");

        assert_eq!(
            result["spec"]["podFailurePolicy"]["rules"][0]["action"], "Ignore",
            "podFailurePolicy.action must survive: generated struct covers all fields by construction; \
             a dropped policy means the kcm job controller never sees failure rules"
        );
        assert_eq!(
            result["spec"]["podFailurePolicy"]["rules"][0]["onExitCodes"]["values"][0], 42,
            "onExitCodes.values must survive round-trip by construction"
        );
    }

    #[test]
    fn generated_cronjob_status_active_survives_decode_by_construction() {
        use crate::apps_gen::k8s::io::api::core::v1::ObjectReference;
        let cj = batch_v1::CronJob {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-cj".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::CronJobSpec {
                schedule: Some("*/5 * * * *".to_string()),
                concurrency_policy: Some("Forbid".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::CronJobStatus {
                active: vec![ObjectReference {
                    name: Some("my-cj-job".to_string()),
                    namespace: Some("default".to_string()),
                    kind: Some("Job".to_string()),
                    api_version: Some("batch/v1".to_string()),
                    uid: Some("uid-abc".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).unwrap();
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob with status must decode");

        assert_eq!(
            result["status"]["active"][0]["name"], "my-cj-job",
            "status.active[0].name must survive: generated struct covers CronJobStatus.active by \
             construction; dropped active list means concurrency control cannot see running jobs"
        );
        assert_eq!(
            result["status"]["active"][0]["kind"], "Job",
            "status.active[0].kind must survive"
        );
    }

    /// decode_cronjob_proto_gen must preserve status.lastScheduleTime and lastSuccessfulTime.
    ///
    /// The CronJob controller gates the next scheduled run on lastScheduleTime; if it is
    /// dropped, the controller cannot tell when the CronJob last fired and
    /// "should support CronJob API operations" conformance sees lastScheduleTime as nil
    /// after a status update.
    #[test]
    fn decode_cronjob_proto_gen_preserves_last_schedule_and_successful_time() {
        let cj = batch_v1::CronJob {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("timed-cj".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::CronJobSpec {
                schedule: Some("*/5 * * * *".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::CronJobStatus {
                last_schedule_time: Some(meta_v1::Time {
                    seconds: Some(1_704_067_200),
                    nanos: Some(0),
                }),
                last_successful_time: Some(meta_v1::Time {
                    seconds: Some(1_704_067_215),
                    nanos: Some(0),
                }),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).unwrap();
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob with status must decode");

        assert_eq!(
            result["status"]["lastScheduleTime"], "2024-01-01T00:00:00Z",
            "lastScheduleTime must survive decode; before the fix status only mapped .active, \
             so the controller would see lastScheduleTime as nil and could re-fire a job early"
        );
        assert_eq!(
            result["status"]["lastSuccessfulTime"], "2024-01-01T00:00:15Z",
            "lastSuccessfulTime must survive decode; before the fix this field was never mapped"
        );
    }

    /// Job conditions with None type/status must serialize as "" not null.
    ///
    /// k8s Job controller checks condition.type == "Complete" / "Failed" to determine
    /// terminal state. A null type causes JSON schema validation failures and breaks
    /// controllers that do exact string comparison on condition fields.
    /// This test fails if the unwrap_or_default() fix is reverted.
    #[test]
    fn batch_condition_none_type_status_emits_empty_string_not_null() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("job-null-cond".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::JobStatus {
                conditions: vec![batch_v1::JobCondition {
                    r#type: None,
                    status: None,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        let cond = &result["status"]["conditions"][0];
        assert_eq!(
            cond["type"],
            serde_json::Value::String(String::new()),
            "condition.type must be \"\" not null — Job controller checks type == \"Complete\" \
             and JSON schema validation rejects null in required condition fields"
        );
        assert_eq!(
            cond["status"],
            serde_json::Value::String(String::new()),
            "condition.status must be \"\" not null — controllers doing string comparison \
             (status == \"True\") panic or skip conditions with null status"
        );
    }

    /// decode_job_proto_gen must preserve JobCondition.lastTransitionTime and lastProbeTime.
    ///
    /// Controllers and `kubectl get job` order status changes by LastTransitionTime; if it is
    /// dropped, every Job condition looks un-transitioned (zero-valued), which breaks
    /// "should apply changes to a job status" conformance and any client waiting on the
    /// transition timestamp to detect a state change.
    #[test]
    fn decode_job_proto_gen_preserves_condition_last_transition_and_probe_time() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("timed-job".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::JobStatus {
                conditions: vec![batch_v1::JobCondition {
                    r#type: Some("Complete".to_string()),
                    status: Some("True".to_string()),
                    last_probe_time: Some(meta_v1::Time {
                        seconds: Some(1_704_067_200),
                        nanos: Some(0),
                    }),
                    last_transition_time: Some(meta_v1::Time {
                        seconds: Some(1_704_067_215),
                        nanos: Some(0),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        let cond = &result["status"]["conditions"][0];

        assert_eq!(
            cond["lastTransitionTime"], "2024-01-01T00:00:15Z",
            "lastTransitionTime must survive decode; before the fix this field was never mapped \
             and the condition would look un-transitioned (0001-01-01) to every client"
        );
        assert_eq!(
            cond["lastProbeTime"], "2024-01-01T00:00:00Z",
            "lastProbeTime must survive decode; before the fix this field was silently dropped"
        );
    }

    /// decode_job_proto_gen must preserve status.active/succeeded/failed/ready counts.
    ///
    /// The Job controller's own reconcile loop (and `kubectl get jobs`) reads these counters to
    /// decide whether to create more pods or declare the Job complete. Existing status coverage
    /// for this decoder only asserted on condition timestamps, never on the counts themselves,
    /// so a regression dropping them would make every Job look like it has never run a pod.
    #[test]
    fn decode_job_proto_gen_preserves_status_active_succeeded_failed_counts() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("counting-job".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::JobStatus {
                active: Some(2),
                succeeded: Some(3),
                failed: Some(1),
                ready: Some(2),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job with status counts must decode");

        assert_eq!(
            result["status"]["active"], 2,
            "status.active must survive decode — without it the Job controller cannot tell how \
             many pods are already running and creates duplicates past parallelism"
        );
        assert_eq!(
            result["status"]["succeeded"], 3,
            "status.succeeded must survive decode — without it a Job never reaches its \
             completions target and runs forever"
        );
        assert_eq!(
            result["status"]["failed"], 1,
            "status.failed must survive decode — without it backoffLimit accounting is blind \
             to prior failures"
        );
        assert_eq!(
            result["status"]["ready"], 2,
            "status.ready must survive decode — readiness-gated Job completion depends on it"
        );
    }

    /// decode_job_proto_gen must preserve spec.selector and spec.manualSelector.
    ///
    /// selector is re-sent on every subsequent Update once the Job controller (or a client using
    /// the legacy manual-selector workflow) has set it; before this fix it was never read at
    /// all, so it silently disappeared from the stored object on the very next write.
    #[test]
    fn decode_job_proto_gen_preserves_selector_and_manual_selector() {
        use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("manual-selector-job".to_string()),
                ..Default::default()
            }),
            spec: Some(batch_v1::JobSpec {
                selector: Some(LabelSelector {
                    match_labels: std::collections::HashMap::from([(
                        "controller-uid".to_string(),
                        "abc-123".to_string(),
                    )]),
                    ..Default::default()
                }),
                manual_selector: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job with selector must decode");

        assert_eq!(
            result["spec"]["selector"]["matchLabels"]["controller-uid"], "abc-123",
            "spec.selector must survive decode — without it the Job's pods lose their owning \
             selector on the next Update and orphan from their controller"
        );
        assert_eq!(
            result["spec"]["manualSelector"], true,
            "spec.manualSelector must survive decode — dropping it silently reverts a \
             user-managed selector Job to system-managed labeling"
        );
    }

    /// decode_job_proto_gen must preserve status.startTime and status.completionTime.
    ///
    /// `kubectl get job` computes AGE/duration from startTime, and the TTL-after-finished
    /// controller schedules cleanup from completionTime; before this fix neither field was read
    /// at all, so every Job looked like it had never started or finished.
    #[test]
    fn decode_job_proto_gen_preserves_start_and_completion_time() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("timed-job-status".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::JobStatus {
                start_time: Some(meta_v1::Time {
                    seconds: Some(1_704_067_200),
                    nanos: Some(0),
                }),
                completion_time: Some(meta_v1::Time {
                    seconds: Some(1_704_067_260),
                    nanos: Some(0),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job with timed status must decode");

        assert_eq!(
            result["status"]["startTime"], "2024-01-01T00:00:00Z",
            "startTime must survive decode; before the fix this field was never mapped and \
             `kubectl get job` would show an empty AGE for a running Job"
        );
        assert_eq!(
            result["status"]["completionTime"], "2024-01-01T00:01:00Z",
            "completionTime must survive decode; before the fix ttlSecondsAfterFinished cleanup \
             had no reference point to schedule from"
        );
    }

    /// decode_job_proto_gen must preserve status.uncountedTerminatedPods.
    ///
    /// The Job controller's pod-finalizer accounting (JobTrackingWithFinalizers) stages
    /// terminated pod UIDs here before folding them into succeeded/failed counters; dropping
    /// this field on decode would make the controller re-process (or lose track of) pods
    /// between reconciliations, risking double-counted or stuck finalizers.
    #[test]
    fn decode_job_proto_gen_preserves_uncounted_terminated_pods() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("uncounted-job".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::JobStatus {
                uncounted_terminated_pods: Some(batch_v1::UncountedTerminatedPods {
                    succeeded: vec!["uid-succeeded-1".to_string()],
                    failed: vec!["uid-failed-1".to_string()],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let result = decode_job_proto_gen(&buf).expect("Job with uncounted pods must decode");

        assert_eq!(
            result["status"]["uncountedTerminatedPods"]["succeeded"][0], "uid-succeeded-1",
            "uncountedTerminatedPods.succeeded must survive decode — without it the controller \
             cannot tell which succeeded pods it has already finalized and may double-count them"
        );
        assert_eq!(
            result["status"]["uncountedTerminatedPods"]["failed"][0], "uid-failed-1",
            "uncountedTerminatedPods.failed must survive decode"
        );
    }

    /// decode_job_proto_gen must preserve status.uncountedTerminatedPods when PRESENT BUT EMPTY.
    ///
    /// This is the normal steady state for a live Job with nothing currently pending finalizer
    /// removal: JobTrackingWithFinalizers sets a non-nil-but-empty pointer the moment it starts
    /// tracking a Job. Collapsing present-but-empty into absent on decode leaves upstream KCM's
    /// Job controller reading a nil pointer on its next reconcile, which panics
    /// (job_controller.go:1568, cleanUncountedPodsWithoutFinalizers) and crash-loops KCM to
    /// death — taking every other controller down with it.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_empty_uncounted_terminated_pods() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                uncounted_terminated_pods: Some(batch_v1::UncountedTerminatedPods::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");

        let result = decode_job_proto_gen(&buf).expect("Job must decode");

        assert!(
            result["status"]["uncountedTerminatedPods"].is_object(),
            "status.uncountedTerminatedPods must decode as PRESENT (empty object) when the proto \
             field is Some(default), NOT be dropped — upstream KCM Job controller nil-derefs on \
             absent field (job_controller.go:1568)"
        );
    }

    /// decode_job_proto_gen must preserve status.ready when PRESENT BUT ZERO.
    ///
    /// Upstream JobStatus.Ready is *int32 (proto3 optional); Some(0) is a legitimate value
    /// (0 pods currently ready) distinct from absent. Dropping it breaks successPolicy
    /// conformance tests that assert `Expected nil to equal 0` (job.go:597).
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_status_ready() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                ready: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["status"]["ready"], 0,
            "status.ready must decode as PRESENT with value 0 when the proto field is Some(0), \
             NOT be dropped — upstream KCM Job controller expects *int32 semantics; a nil (absent) \
             field breaks successPolicy tests that assert `Expected nil to equal 0` at \
             k8s.io/kubernetes/test/e2e/apps/job.go:597"
        );
    }

    /// decode_job_proto_gen must preserve status.active when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as status.ready: Some(0) (no pods currently active) must
    /// not be collapsed into absent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_status_active() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                active: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["status"]["active"], 0,
            "status.active must decode as PRESENT with value 0 when the proto field is Some(0), \
             NOT be dropped — upstream KCM Job controller expects *int32 semantics; a nil (absent) \
             field breaks successPolicy tests that assert `Expected nil to equal 0` at \
             k8s.io/kubernetes/test/e2e/apps/job.go:597"
        );
    }

    /// decode_job_proto_gen must preserve status.succeeded when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as status.ready: Some(0) (no pods succeeded yet) must not
    /// be collapsed into absent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_status_succeeded() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                succeeded: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["status"]["succeeded"], 0,
            "status.succeeded must decode as PRESENT with value 0 when the proto field is \
             Some(0), NOT be dropped — upstream KCM Job controller expects *int32 semantics; a \
             nil (absent) field breaks successPolicy tests that assert `Expected nil to equal 0` \
             at k8s.io/kubernetes/test/e2e/apps/job.go:597"
        );
    }

    /// decode_job_proto_gen must preserve status.failed when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as status.ready: Some(0) (no pods failed yet) must not be
    /// collapsed into absent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_status_failed() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                failed: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["status"]["failed"], 0,
            "status.failed must decode as PRESENT with value 0 when the proto field is Some(0), \
             NOT be dropped — upstream KCM Job controller expects *int32 semantics; a nil (absent) \
             field breaks successPolicy tests that assert `Expected nil to equal 0` at \
             k8s.io/kubernetes/test/e2e/apps/job.go:597"
        );
    }

    /// decode_job_proto_gen must preserve status.terminating when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as status.ready: Some(0) (0 pods currently terminating)
    /// must not be collapsed into absent. This is the exact field the failing successPolicy
    /// conformance tests assert on alongside status.ready.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_status_terminating() {
        let job = batch_v1::Job {
            status: Some(batch_v1::JobStatus {
                terminating: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["status"]["terminating"], 0,
            "status.terminating must decode as PRESENT with value 0 when the proto field is \
             Some(0), NOT be dropped — upstream KCM Job controller expects *int32 semantics; a \
             nil (absent) field breaks successPolicy tests that assert `Expected nil to equal 0` \
             at k8s.io/kubernetes/test/e2e/apps/job.go:597"
        );
    }

    /// decode_job_proto_gen must preserve spec.parallelism when PRESENT BUT ZERO.
    ///
    /// Upstream JobSpec.Parallelism is *int32 (proto3 optional); Some(0) means "explicitly
    /// don't run pods in parallel" (a valid Job spec). Dropping it to absent would make KCM's
    /// Job controller fall back to its hardcoded default of 1 instead of the user's intent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_spec_parallelism() {
        let job = batch_v1::Job {
            spec: Some(batch_v1::JobSpec {
                parallelism: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["spec"]["parallelism"], 0,
            "spec.parallelism must decode as PRESENT with value 0 when the proto field is \
             Some(0), NOT be dropped — user-visible intent, `parallelism: 0` means 'explicitly \
             don't run pods in parallel'. Silently dropping means KCM's controller falls back \
             to its hardcoded default of 1 instead."
        );
    }

    /// decode_job_proto_gen must preserve spec.completions when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as spec.parallelism: `completions: 0` is a rare but valid
    /// value for indexed jobs and must not be collapsed into absent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_spec_completions() {
        let job = batch_v1::Job {
            spec: Some(batch_v1::JobSpec {
                completions: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["spec"]["completions"], 0,
            "spec.completions must decode as PRESENT with value 0 when the proto field is \
             Some(0), NOT be dropped — user-visible intent, `completions: 0` means 'zero \
             completions required'. Silently dropping means KCM's controller treats the field \
             as unset instead."
        );
    }

    /// decode_job_proto_gen must preserve spec.activeDeadlineSeconds when PRESENT BUT ZERO.
    ///
    /// Upstream JobSpec.ActiveDeadlineSeconds is *int64 (proto3 optional); `activeDeadlineSeconds:
    /// 0` means "the Job's pods must be terminated immediately" and must not be collapsed into
    /// absent (which means "no deadline").
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_spec_active_deadline_seconds() {
        let job = batch_v1::Job {
            spec: Some(batch_v1::JobSpec {
                active_deadline_seconds: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["spec"]["activeDeadlineSeconds"], 0,
            "spec.activeDeadlineSeconds must decode as PRESENT with value 0 when the proto \
             field is Some(0), NOT be dropped — user-visible intent, `activeDeadlineSeconds: 0` \
             means 'terminate pods immediately'. Silently dropping means KCM's controller \
             treats the Job as having no deadline instead."
        );
    }

    /// decode_job_proto_gen must preserve spec.backoffLimit when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as spec.parallelism: `backoffLimit: 0` ("don't retry on
    /// failure") is a very common value and must not be collapsed into absent.
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_spec_backoff_limit() {
        let job = batch_v1::Job {
            spec: Some(batch_v1::JobSpec {
                backoff_limit: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["spec"]["backoffLimit"], 0,
            "spec.backoffLimit must decode as PRESENT with value 0 when the proto field is \
             Some(0), NOT be dropped — user-visible intent, `backoffLimit: 0` means 'don't \
             retry on failure'. Silently dropping means KCM's controller falls back to its \
             hardcoded default of 6 instead."
        );
    }

    /// decode_job_proto_gen must preserve spec.ttlSecondsAfterFinished when PRESENT BUT ZERO.
    ///
    /// Same *int32 tri-state issue as spec.parallelism: `ttlSecondsAfterFinished: 0` means
    /// "delete immediately after completion" and must not be collapsed into absent (which
    /// means "never automatically delete").
    #[test]
    fn decode_job_proto_gen_preserves_present_but_zero_spec_ttl_seconds_after_finished() {
        let job = batch_v1::Job {
            spec: Some(batch_v1::JobSpec {
                ttl_seconds_after_finished: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_job_proto_gen(&buf).expect("Job must decode");
        assert_eq!(
            result["spec"]["ttlSecondsAfterFinished"], 0,
            "spec.ttlSecondsAfterFinished must decode as PRESENT with value 0 when the proto \
             field is Some(0), NOT be dropped — user-visible intent, \
             `ttlSecondsAfterFinished: 0` means 'delete immediately after completion'. \
             Silently dropping means KCM's controller treats the Job as never eligible for \
             automatic deletion instead."
        );
    }

    /// decode_cronjob_proto_gen's status.active entries must preserve resourceVersion/fieldPath.
    ///
    /// ObjectReference has 7 fields; this hand-rolled mapping (not core_gen_adapter's shared
    /// gen_object_reference_to_json) only carried 5 of them before this fix.
    #[test]
    fn decode_cronjob_proto_gen_preserves_active_resource_version_and_field_path() {
        use crate::apps_gen::k8s::io::api::core::v1::ObjectReference;
        let cj = batch_v1::CronJob {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ref-fields-cj".to_string()),
                ..Default::default()
            }),
            status: Some(batch_v1::CronJobStatus {
                active: vec![ObjectReference {
                    name: Some("ref-fields-cj-job".to_string()),
                    namespace: Some("default".to_string()),
                    resource_version: Some("999".to_string()),
                    field_path: Some("spec.containers{main}".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).unwrap();
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob with status must decode");

        assert_eq!(
            result["status"]["active"][0]["resourceVersion"], "999",
            "status.active[0].resourceVersion must survive decode"
        );
        assert_eq!(
            result["status"]["active"][0]["fieldPath"], "spec.containers{main}",
            "status.active[0].fieldPath must survive decode"
        );
    }

    /// decode_cronjob_proto_gen must preserve spec.startingDeadlineSeconds when PRESENT BUT
    /// ZERO.
    ///
    /// Upstream CronJobSpec.StartingDeadlineSeconds is *int64 (proto3 optional);
    /// `startingDeadlineSeconds: 0` means "a missed schedule is never considered started" and
    /// must not be collapsed into absent (which means "no deadline").
    #[test]
    fn decode_cronjob_proto_gen_preserves_present_but_zero_spec_starting_deadline_seconds() {
        let cj = batch_v1::CronJob {
            spec: Some(batch_v1::CronJobSpec {
                starting_deadline_seconds: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob must decode");
        assert_eq!(
            result["spec"]["startingDeadlineSeconds"], 0,
            "spec.startingDeadlineSeconds must decode as PRESENT with value 0 when the proto \
             field is Some(0), NOT be dropped — user-visible intent, \
             `startingDeadlineSeconds: 0` means 'a missed schedule is never considered \
             started'. Silently dropping means KCM's CronJob controller treats the field as \
             unset instead."
        );
    }

    /// decode_cronjob_proto_gen must preserve spec.successfulJobsHistoryLimit when PRESENT BUT
    /// ZERO.
    ///
    /// Same *int32 tri-state issue as spec.startingDeadlineSeconds:
    /// `successfulJobsHistoryLimit: 0` ("keep no history of successful runs") is common in
    /// production and must not be collapsed into absent.
    #[test]
    fn decode_cronjob_proto_gen_preserves_present_but_zero_spec_successful_jobs_history_limit() {
        let cj = batch_v1::CronJob {
            spec: Some(batch_v1::CronJobSpec {
                successful_jobs_history_limit: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob must decode");
        assert_eq!(
            result["spec"]["successfulJobsHistoryLimit"], 0,
            "spec.successfulJobsHistoryLimit must decode as PRESENT with value 0 when the \
             proto field is Some(0), NOT be dropped — user-visible intent, \
             `successfulJobsHistoryLimit: 0` means 'keep no history of successful runs'. \
             Silently dropping means KCM's controller falls back to its hardcoded default of \
             3 instead."
        );
    }

    /// decode_cronjob_proto_gen must preserve spec.failedJobsHistoryLimit when PRESENT BUT
    /// ZERO.
    ///
    /// Same *int32 tri-state issue as spec.startingDeadlineSeconds:
    /// `failedJobsHistoryLimit: 0` ("keep no history of failed runs") must not be collapsed
    /// into absent.
    #[test]
    fn decode_cronjob_proto_gen_preserves_present_but_zero_spec_failed_jobs_history_limit() {
        let cj = batch_v1::CronJob {
            spec: Some(batch_v1::CronJobSpec {
                failed_jobs_history_limit: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).expect("prost encode must succeed");
        let result = decode_cronjob_proto_gen(&buf).expect("CronJob must decode");
        assert_eq!(
            result["spec"]["failedJobsHistoryLimit"], 0,
            "spec.failedJobsHistoryLimit must decode as PRESENT with value 0 when the proto \
             field is Some(0), NOT be dropped — user-visible intent, \
             `failedJobsHistoryLimit: 0` means 'keep no history of failed runs'. Silently \
             dropping means KCM's controller falls back to its hardcoded default of 1 instead."
        );
    }

    // ---- Sentinel completeness: decode_job_proto_gen / decode_cronjob_proto_gen ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in gen_object_meta_to_json, gen_job_spec_to_json, decode_job_proto_gen, or
    // decode_cronjob_proto_gen could mistake for "unset" (see u7s_sentinel::Sentinel), decodes
    // it through the real entry point, and asserts every field name shows up somewhere in the
    // resulting JSON. A name that never appears means one of those functions never reads that
    // field from the decoded protobuf struct at all — this is exactly how spec.selector,
    // spec.manualSelector, status.startTime, status.completionTime, and
    // status.uncountedTerminatedPods were found missing from this file while building this test.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    #[test]
    fn sentinel_completeness_decode_job_proto_gen() {
        let job = batch_v1::Job {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(batch_v1::JobSpec::sentinel()),
            status: Some(batch_v1::JobStatus::sentinel()),
        };
        let mut buf = Vec::new();
        job.encode(&mut buf).unwrap();
        let mut decoded =
            decode_job_proto_gen(&buf).expect("sentinel Job must decode via the generated path");

        // Blank (but keep the key of) the nested PodTemplateSpec: it shares field names with
        // JobSpec itself (e.g. activeDeadlineSeconds), so without this a dropped JobSpec-level
        // field could hide behind its PodSpec-level namesake still being present in the tree.
        // PodSpec/Container's own completeness is covered separately in core_gen_adapter.rs.
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            spec.insert("template".to_string(), serde_json::json!({}));
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        // selfLink is a legacy field the system no longer populates — permanently omitted.
        // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
        // pending a separate investigation into gen_object_meta_to_json's correct handling of
        // them; do not guess at the fix here.
        //
        // JobCondition.status is left off `expected` too: it lives under this object's own
        // "status" key, so the check would trivially pass off the ancestor key alone and could
        // never actually fail if condition.status handling regressed — existing hand-written
        // tests in this file cover it instead.
        let expected = [
            "name",
            "generateName",
            "namespace",
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "labels",
            "annotations",
            "ownerReferences",
            "finalizers",
            "parallelism",
            "completions",
            "activeDeadlineSeconds",
            "backoffLimit",
            "ttlSecondsAfterFinished",
            "completionMode",
            "suspend",
            "podReplacementPolicy",
            "backoffLimitPerIndex",
            "maxFailedIndexes",
            "managedBy",
            "selector",
            "manualSelector",
            "podFailurePolicy",
            "successPolicy",
            "template",
            "startTime",
            "completionTime",
            "active",
            "succeeded",
            "failed",
            "completedIndexes",
            "uncountedTerminatedPods",
            "ready",
            "failedIndexes",
            "terminating",
            "type",
            "reason",
            "message",
            "lastProbeTime",
            "lastTransitionTime",
        ];
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_cronjob_proto_gen() {
        let cj = batch_v1::CronJob {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(batch_v1::CronJobSpec::sentinel()),
            status: Some(batch_v1::CronJobStatus::sentinel()),
        };
        let mut buf = Vec::new();
        cj.encode(&mut buf).unwrap();
        let mut decoded = decode_cronjob_proto_gen(&buf)
            .expect("sentinel CronJob must decode via the generated path");

        // Blank the nested jobTemplate: JobTemplateSpec.spec is a full JobSpec, which shares
        // field names with CronJobSpec itself (e.g. suspend) — without this a dropped
        // CronJobSpec-level field could hide behind its JobSpec-level namesake. JobSpec's own
        // completeness is covered separately by sentinel_completeness_decode_job_proto_gen.
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            spec.insert("jobTemplate".to_string(), serde_json::json!({}));
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        // Same ObjectMeta omissions as sentinel_completeness_decode_job_proto_gen; see there.
        let expected = [
            "name",
            "generateName",
            "namespace",
            "uid",
            "resourceVersion",
            "generation",
            "creationTimestamp",
            "labels",
            "annotations",
            "ownerReferences",
            "finalizers",
            "schedule",
            "timeZone",
            "startingDeadlineSeconds",
            "concurrencyPolicy",
            "suspend",
            "jobTemplate",
            "successfulJobsHistoryLimit",
            "failedJobsHistoryLimit",
            "active",
            "lastScheduleTime",
            "lastSuccessfulTime",
        ];
        assert_fields_present(&paths, &expected);
    }
}
