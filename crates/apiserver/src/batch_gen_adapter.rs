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
    if let Some(v) = spec.parallelism.filter(|&n| n != 0) {
        m.insert("parallelism".to_string(), v.into());
    }
    if let Some(v) = spec.completions.filter(|&n| n != 0) {
        m.insert("completions".to_string(), v.into());
    }
    if let Some(v) = spec.active_deadline_seconds.filter(|&n| n != 0) {
        m.insert("activeDeadlineSeconds".to_string(), v.into());
    }
    if let Some(v) = spec.backoff_limit.filter(|&n| n != 0) {
        m.insert("backoffLimit".to_string(), v.into());
    }
    if let Some(v) = spec.ttl_seconds_after_finished.filter(|&n| n != 0) {
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
                    cond
                })
                .collect();
        }
        if let Some(v) = status.active.filter(|&n| n != 0) {
            status_json["active"] = v.into();
        }
        if let Some(v) = status.succeeded.filter(|&n| n != 0) {
            status_json["succeeded"] = v.into();
        }
        if let Some(v) = status.failed.filter(|&n| n != 0) {
            status_json["failed"] = v.into();
        }
        if let Some(v) = status.completed_indexes.filter(|s| !s.is_empty()) {
            status_json["completedIndexes"] = v.into();
        }
        if let Some(v) = status.ready.filter(|&n| n != 0) {
            status_json["ready"] = v.into();
        }
        if let Some(v) = status.failed_indexes.filter(|s| !s.is_empty()) {
            status_json["failedIndexes"] = v.into();
        }
        if let Some(v) = status.terminating.filter(|&n| n != 0) {
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
        if let Some(v) = spec.starting_deadline_seconds.filter(|&n| n != 0) {
            spec_map.insert("startingDeadlineSeconds".to_string(), v.into());
        }
        if let Some(v) = spec.concurrency_policy.filter(|s| !s.is_empty()) {
            spec_map.insert("concurrencyPolicy".to_string(), v.into());
        }
        if let Some(true) = spec.suspend {
            spec_map.insert("suspend".to_string(), true.into());
        }
        if let Some(v) = spec.successful_jobs_history_limit.filter(|&n| n != 0) {
            spec_map.insert("successfulJobsHistoryLimit".to_string(), v.into());
        }
        if let Some(v) = spec.failed_jobs_history_limit.filter(|&n| n != 0) {
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
                    Some(entry)
                })
                .collect::<Vec<_>>()
                .into();
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
}
