use prost::Message;

use crate::apps_gen::k8s::io::api::apps::v1 as apps_v1;
use crate::apps_gen::k8s::io::api::core::v1 as core_v1;
use crate::apps_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

fn gen_pod_template_spec_to_json(tmpl: core_v1::PodTemplateSpec) -> serde_json::Value {
    crate::core_gen_adapter::gen_pod_template_spec_to_json(tmpl)
}

fn gen_persistent_volume_claim_to_json(pvc: core_v1::PersistentVolumeClaim) -> serde_json::Value {
    crate::core_gen_adapter::gen_persistent_volume_claim_to_json(pvc)
}

fn gen_label_selector_requirement_to_json(
    req: meta_v1::LabelSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if let Some(k) = req.key.filter(|s| !s.is_empty()) {
        m["key"] = serde_json::Value::String(k);
    }
    if let Some(op) = req.operator.filter(|s| !s.is_empty()) {
        m["operator"] = serde_json::Value::String(op);
    }
    if !req.values.is_empty() {
        m["values"] = serde_json::Value::Array(
            req.values
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    m
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::json!({});
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["matchLabels"] = serde_json::Value::Object(labels);
    }
    if !sel.match_expressions.is_empty() {
        m["matchExpressions"] = serde_json::Value::Array(
            sel.match_expressions
                .into_iter()
                .map(gen_label_selector_requirement_to_json)
                .collect(),
        );
    }
    m
}

macro_rules! apps_condition_to_json {
    ($c:expr) => {{
        let mut cond = serde_json::json!({
            "type": $c.r#type.clone().unwrap_or_default(),
            "status": $c.status.clone().unwrap_or_default(),
        });
        if let Some(ref r) = $c.reason {
            if !r.is_empty() {
                cond["reason"] = r.clone().into();
            }
        }
        if let Some(ref msg) = $c.message {
            if !msg.is_empty() {
                cond["message"] = msg.clone().into();
            }
        }
        // lastTransitionTime is on all four *Condition types (only DeploymentCondition also has
        // lastUpdateTime, handled separately at its call site); dropping it made every
        // condition look like it had just transitioned, breaking anything that orders or ages
        // conditions by this timestamp (e.g. progressDeadlineSeconds tracking on Deployments).
        if let Some(t) = $c.last_transition_time.as_ref() {
            if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                cond["lastTransitionTime"] = crate::util::secs_to_rfc3339(secs).into();
            }
        }
        cond
    }};
}

fn gen_apps_spec_to_json(
    selector: Option<meta_v1::LabelSelector>,
    template: Option<core_v1::PodTemplateSpec>,
) -> Option<serde_json::Value> {
    let mut spec = serde_json::json!({});
    let mut non_empty = false;

    if let Some(sel) = selector {
        if !sel.match_labels.is_empty() || !sel.match_expressions.is_empty() {
            spec["selector"] = gen_label_selector_to_json(sel);
            non_empty = true;
        }
    }

    if let Some(tmpl) = template {
        let tmpl_json = gen_pod_template_spec_to_json(tmpl);
        if !tmpl_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            spec["template"] = tmpl_json;
            non_empty = true;
        }
    }

    if non_empty {
        Some(spec)
    } else {
        None
    }
}

// ---- Decoder A: StatefulSet ------------------------------------------------

pub fn decode_statefulset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::StatefulSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let update_strategy = spec.update_strategy;
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if let Some(us) = update_strategy {
            let mut us_json = serde_json::json!({});
            if let Some(t) = us.r#type.filter(|s| !s.is_empty()) {
                us_json["type"] = t.into();
            }
            if let Some(ru) = us.rolling_update {
                let mut ru_json = serde_json::json!({ "partition": ru.partition.unwrap_or(0) });
                if let Some(mu) = ru.max_unavailable {
                    ru_json["maxUnavailable"] = gen_apps_int_or_string_to_json(mu);
                }
                us_json["rollingUpdate"] = ru_json;
            }
            if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["updateStrategy"] = us_json;
            }
        }
        // volumeClaimTemplates is the field StatefulSet exists for: it's how each replica gets
        // its own stable PersistentVolumeClaim. serviceName drives the pod DNS/hostname pattern.
        // Both were entirely unread here, so every protobuf-encoded StatefulSet create/update
        // (client-go and kcm both default to protobuf) silently lost them on decode.
        if !spec.volume_claim_templates.is_empty() {
            spec_json["volumeClaimTemplates"] = spec
                .volume_claim_templates
                .into_iter()
                .map(gen_persistent_volume_claim_to_json)
                .collect::<Vec<_>>()
                .into();
        }
        if let Some(v) = spec.service_name.filter(|s| !s.is_empty()) {
            spec_json["serviceName"] = v.into();
        }
        if let Some(v) = spec.pod_management_policy.filter(|s| !s.is_empty()) {
            spec_json["podManagementPolicy"] = v.into();
        }
        if let Some(v) = spec.revision_history_limit {
            spec_json["revisionHistoryLimit"] = v.into();
        }
        if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {
            spec_json["minReadySeconds"] = v.into();
        }
        if let Some(rp) = spec.persistent_volume_claim_retention_policy {
            let mut rp_json = serde_json::json!({});
            if let Some(v) = rp.when_deleted.filter(|s| !s.is_empty()) {
                rp_json["whenDeleted"] = v.into();
            }
            if let Some(v) = rp.when_scaled.filter(|s| !s.is_empty()) {
                rp_json["whenScaled"] = v.into();
            }
            if !rp_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["persistentVolumeClaimRetentionPolicy"] = rp_json;
            }
        }
        if let Some(ord) = spec.ordinals {
            spec_json["ordinals"] = serde_json::json!({ "start": ord.start.unwrap_or(0) });
        }
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.current_replicas.filter(|&v| v != 0) {
            status_json["currentReplicas"] = v.into();
        }
        if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {
            status_json["updatedReplicas"] = v.into();
        }
        if let Some(v) = status.current_revision.filter(|s| !s.is_empty()) {
            status_json["currentRevision"] = v.into();
        }
        if let Some(v) = status.update_revision.filter(|s| !s.is_empty()) {
            status_json["updateRevision"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
        }
        if let Some(v) = status.available_replicas.filter(|&v| v != 0) {
            status_json["availableReplicas"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: Deployment -------------------------------------------------

fn gen_apps_int_or_string_to_json(
    ios: crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString,
) -> serde_json::Value {
    if ios.r#type.unwrap_or(0) == 0 {
        serde_json::Value::Number(ios.int_val.unwrap_or(0).into())
    } else {
        serde_json::Value::String(ios.str_val.unwrap_or_default())
    }
}

pub fn decode_deployment_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::Deployment::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if let Some(strategy) = spec.strategy {
            let mut strategy_json = serde_json::json!({});
            if let Some(t) = strategy.r#type.filter(|s| !s.is_empty()) {
                strategy_json["type"] = t.into();
            }
            if let Some(ru) = strategy.rolling_update {
                let mut ru_json = serde_json::json!({});
                if let Some(mu) = ru.max_unavailable {
                    ru_json["maxUnavailable"] = gen_apps_int_or_string_to_json(mu);
                }
                if let Some(ms) = ru.max_surge {
                    ru_json["maxSurge"] = gen_apps_int_or_string_to_json(ms);
                }
                if !ru_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                    strategy_json["rollingUpdate"] = ru_json;
                }
            }
            if !strategy_json
                .as_object()
                .map(|m| m.is_empty())
                .unwrap_or(true)
            {
                spec_json["strategy"] = strategy_json;
            }
        }
        if let Some(v) = spec.revision_history_limit {
            spec_json["revisionHistoryLimit"] = v.into();
        }
        if let Some(v) = spec.progress_deadline_seconds {
            spec_json["progressDeadlineSeconds"] = v.into();
        }
        if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {
            spec_json["minReadySeconds"] = v.into();
        }
        // paused is what `kubectl rollout pause` sets; dropping it here makes the pause appear
        // to succeed (200 OK) while the deployment controller keeps rolling out regardless.
        if let Some(true) = spec.paused {
            spec_json["paused"] = true.into();
        }
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {
            status_json["updatedReplicas"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.available_replicas.filter(|&v| v != 0) {
            status_json["availableReplicas"] = v.into();
        }
        if let Some(v) = status.unavailable_replicas.filter(|&v| v != 0) {
            status_json["unavailableReplicas"] = v.into();
        }
        if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {
            status_json["terminatingReplicas"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| {
                    let mut cond = apps_condition_to_json!(c);
                    // lastUpdateTime only exists on DeploymentCondition (not the other three
                    // *Condition types sharing the macro above); the deployment controller's
                    // progressDeadlineSeconds check depends on this timestamp to tell whether a
                    // rollout has actually stalled or is still making progress.
                    if let Some(t) = c.last_update_time.as_ref() {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cond["lastUpdateTime"] = crate::util::secs_to_rfc3339(secs).into();
                        }
                    }
                    cond
                })
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: DaemonSet --------------------------------------------------

pub fn decode_daemonset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::DaemonSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let update_strategy = spec.update_strategy;
        let min_ready_seconds = spec.min_ready_seconds;
        let revision_history_limit = spec.revision_history_limit;
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        // updateStrategy/minReadySeconds/revisionHistoryLimit were entirely unread here — a
        // protobuf-encoded DaemonSet create/update (client-go and kcm both default to protobuf)
        // silently lost its rolling-update config and history-retention settings on decode.
        if let Some(us) = update_strategy {
            let mut us_json = serde_json::json!({});
            if let Some(t) = us.r#type.filter(|s| !s.is_empty()) {
                us_json["type"] = t.into();
            }
            if let Some(ru) = us.rolling_update {
                let mut ru_json = serde_json::json!({});
                if let Some(mu) = ru.max_unavailable {
                    ru_json["maxUnavailable"] = gen_apps_int_or_string_to_json(mu);
                }
                if let Some(ms) = ru.max_surge {
                    ru_json["maxSurge"] = gen_apps_int_or_string_to_json(ms);
                }
                if !ru_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                    us_json["rollingUpdate"] = ru_json;
                }
            }
            if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["updateStrategy"] = us_json;
            }
        }
        if let Some(v) = min_ready_seconds.filter(|&v| v != 0) {
            spec_json["minReadySeconds"] = v.into();
        }
        if let Some(v) = revision_history_limit {
            spec_json["revisionHistoryLimit"] = v.into();
        }
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.current_number_scheduled.filter(|&v| v != 0) {
            status_json["currentNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_misscheduled.filter(|&v| v != 0) {
            status_json["numberMisscheduled"] = v.into();
        }
        if let Some(v) = status.desired_number_scheduled.filter(|&v| v != 0) {
            status_json["desiredNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_ready.filter(|&v| v != 0) {
            status_json["numberReady"] = v.into();
        }
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.updated_number_scheduled.filter(|&v| v != 0) {
            status_json["updatedNumberScheduled"] = v.into();
        }
        if let Some(v) = status.number_available.filter(|&v| v != 0) {
            status_json["numberAvailable"] = v.into();
        }
        if let Some(v) = status.number_unavailable.filter(|&v| v != 0) {
            status_json["numberUnavailable"] = v.into();
        }
        if let Some(v) = status.collision_count.filter(|&v| v != 0) {
            status_json["collisionCount"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: ReplicaSet -------------------------------------------------

pub fn decode_replicaset_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::ReplicaSet::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let replicas = spec.replicas.unwrap_or(0);
        let min_ready_seconds = spec.min_ready_seconds;
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
        if let Some(v) = min_ready_seconds.filter(|&v| v != 0) {
            spec_json["minReadySeconds"] = v.into();
        }
        if !spec_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
            out["spec"] = spec_json;
        }
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::json!({});
        if let Some(v) = status.replicas.filter(|&v| v != 0) {
            status_json["replicas"] = v.into();
        }
        if let Some(v) = status.fully_labeled_replicas.filter(|&v| v != 0) {
            status_json["fullyLabeledReplicas"] = v.into();
        }
        if let Some(v) = status.observed_generation.filter(|&v| v != 0) {
            status_json["observedGeneration"] = v.into();
        }
        if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {
            status_json["readyReplicas"] = v.into();
        }
        if let Some(v) = status.available_replicas.filter(|&v| v != 0) {
            status_json["availableReplicas"] = v.into();
        }
        if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {
            status_json["terminatingReplicas"] = v.into();
        }
        if !status.conditions.is_empty() {
            status_json["conditions"] = status
                .conditions
                .iter()
                .map(|c| apps_condition_to_json!(c))
                .collect();
        }
        if !status_json
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true)
        {
            out["status"] = status_json;
        }
    }
    Some(out)
}

// ---- Decoder A: ControllerRevision -----------------------------------------

pub fn decode_controllerrevision_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = apps_v1::ControllerRevision::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "ControllerRevision",
        "metadata": meta,
        "revision": obj.revision.unwrap_or(0)
    });
    if let Some(raw_ext) = obj.data {
        if let Some(raw) = raw_ext.raw {
            if !raw.is_empty() {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    out["data"] = parsed;
                }
            }
        }
    }
    Some(out)
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_lv(field: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = (field << 3) | 2;
        let mut t = tag as u64;
        loop {
            if t < 128 {
                buf.push(t as u8);
                break;
            }
            buf.push((t as u8) | 0x80);
            t >>= 7;
        }
        let mut l = data.len() as u64;
        loop {
            if l < 128 {
                buf.push(l as u8);
                break;
            }
            buf.push((l as u8) | 0x80);
            l >>= 7;
        }
        buf.extend_from_slice(data);
        buf
    }

    fn encode_varint_field(field: u32, value: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        let tag = field << 3; // varint wire type (wire type 0)
        let mut t = tag as u64;
        loop {
            if t < 128 {
                buf.push(t as u8);
                break;
            }
            buf.push((t as u8) | 0x80);
            t >>= 7;
        }
        let mut v = value as u64;
        loop {
            if v < 128 {
                buf.push(v as u8);
                break;
            }
            buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        buf
    }

    fn make_deployment_bytes_with_strategy() -> Vec<u8> {
        use prost::Message;
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("nginx-deploy".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DeploymentSpec {
                replicas: Some(3),
                strategy: Some(apps_v1::DeploymentStrategy {
                    r#type: Some("RollingUpdate".to_string()),
                    rolling_update: Some(apps_v1::RollingUpdateDeployment {
                        max_unavailable: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(1),
                                str_val: Some("25%".to_string()),
                                ..Default::default()
                            },
                        ),
                        max_surge: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(0),
                                int_val: Some(1),
                                ..Default::default()
                            },
                        ),
                    }),
                }),
                selector: Some(meta_v1::LabelSelector {
                    match_labels: [("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                template: Some(core_v1::PodTemplateSpec {
                    metadata: Some(meta_v1::ObjectMeta {
                        labels: [("app".to_string(), "nginx".to_string())]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    }),
                    spec: Some(core_v1::PodSpec {
                        containers: vec![core_v1::Container {
                            name: Some("nginx".to_string()),
                            image: Some("nginx:1.25".to_string()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();
        buf
    }

    #[test]
    fn generated_deployment_struct_emits_rolling_update_strategy_by_construction() {
        let bytes = make_deployment_bytes_with_strategy();
        let result = decode_deployment_proto_gen(&bytes)
            .expect("Deployment must decode — generated struct has all fields by construction");

        assert_eq!(
            result["spec"]["replicas"], 3,
            "spec.replicas must be present — dropped replicas corrupts scale operations"
        );

        assert_eq!(
            result["spec"]["strategy"]["type"], "RollingUpdate",
            "spec.strategy.type must decode from protobuf — dropping it lets defaults.rs \
             silently overwrite a user-chosen strategy"
        );
        assert_eq!(
            result["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], "25%",
            "rollingUpdate.maxUnavailable must survive decode — controls how many pods go \
             down during a rolling update"
        );
        assert_eq!(
            result["spec"]["strategy"]["rollingUpdate"]["maxSurge"], 1,
            "rollingUpdate.maxSurge must survive decode — controls how many extra pods \
             may be scheduled during a rolling update"
        );

        assert_eq!(
            result["metadata"]["name"], "nginx-deploy",
            "metadata.name must be present — missing name breaks object routing"
        );
        assert_eq!(
            result["spec"]["template"]["spec"]["containers"][0]["name"], "nginx",
            "container name must survive round-trip — EqualIgnoreHash in KCM compares containers"
        );
    }

    /// GATE: a Recreate deployment silently becoming RollingUpdate changes rollout
    /// semantics (all-pods-down vs surge). Before the fix, decode_deployment_proto_gen
    /// dropped spec.strategy/progressDeadlineSeconds/revisionHistoryLimit entirely, so
    /// defaults.rs filled in RollingUpdate/10, clobbering the user's Recreate/0 — making
    /// these fields uncontrollable via protobuf-encoded requests (typed clientsets and KCM
    /// both use protobuf by default).
    #[test]
    fn decode_deployment_proto_gen_preserves_recreate_strategy_and_history_limit() {
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("recreate-deploy".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DeploymentSpec {
                replicas: Some(1),
                strategy: Some(apps_v1::DeploymentStrategy {
                    r#type: Some("Recreate".to_string()),
                    rolling_update: None,
                }),
                revision_history_limit: Some(0),
                progress_deadline_seconds: Some(120),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();

        let result = decode_deployment_proto_gen(&buf).expect("Deployment must decode");

        assert_eq!(
            result["spec"]["strategy"]["type"], "Recreate",
            "Recreate must not be defaulted away to RollingUpdate — Recreate tears all \
             pods down before creating new ones, RollingUpdate surges; conflating the two \
             breaks RecreateDeployment conformance"
        );
        assert!(
            result["spec"]["strategy"]["rollingUpdate"].is_null(),
            "rollingUpdate must not be injected for a Recreate strategy"
        );
        assert_eq!(
            result["spec"]["revisionHistoryLimit"], 0,
            "explicit revisionHistoryLimit=0 must survive decode, not be defaulted to 10 — \
             it controls old ReplicaSet cleanup"
        );
        assert_eq!(
            result["spec"]["progressDeadlineSeconds"], 120,
            "progressDeadlineSeconds must round-trip through protobuf decode"
        );
    }

    #[test]
    fn generated_daemonset_conditions_type_field_survives_decode() {
        let ds = apps_v1::DaemonSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ds-test".to_string()),
                ..Default::default()
            }),
            status: Some(apps_v1::DaemonSetStatus {
                desired_number_scheduled: Some(3),
                number_ready: Some(3),
                conditions: vec![apps_v1::DaemonSetCondition {
                    r#type: Some("DaemonSetReady".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("AllPodsReady".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        ds.encode(&mut buf).unwrap();
        let result = decode_daemonset_proto_gen(&buf).expect("DaemonSet must decode");
        assert_eq!(
            result["status"]["desiredNumberScheduled"], 3,
            "desiredNumberScheduled must survive — node-readiness checks read this field"
        );
        let conditions = result["status"]["conditions"]
            .as_array()
            .expect("conditions must be an array");
        assert_eq!(
            conditions[0]["type"], "DaemonSetReady",
            "condition type must survive — node-readiness checks stall when conditions are absent"
        );
    }

    #[test]
    fn generated_replicaset_preserves_fully_labeled_replicas_by_construction() {
        let rs = apps_v1::ReplicaSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("rs-test".to_string()),
                ..Default::default()
            }),
            status: Some(apps_v1::ReplicaSetStatus {
                replicas: Some(5),
                fully_labeled_replicas: Some(5),
                ready_replicas: Some(5),
                available_replicas: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        rs.encode(&mut buf).unwrap();
        let result = decode_replicaset_proto_gen(&buf).expect("ReplicaSet must decode");
        assert_eq!(
            result["status"]["fullyLabeledReplicas"], 5,
            "fullyLabeledReplicas must survive — Deployment controller reads this to compute available replicas"
        );
    }

    #[test]
    fn volume_mount_read_only_true_survives_generated_decode() {
        let mut container = encode_lv(1, b"nginx");
        container.extend_from_slice(&encode_lv(2, b"nginx:latest"));
        let mut vm = encode_lv(1, b"data");
        vm.extend_from_slice(&encode_lv(3, b"/data"));
        vm.extend_from_slice(&encode_varint_field(2, 1)); // readOnly=true
        container.extend_from_slice(&encode_lv(9, &vm));

        let pod_spec_bytes = encode_lv(2, &container);

        let mut tmpl_meta = encode_lv(1, b"app");
        tmpl_meta.extend_from_slice(&encode_lv(2, b"nginx"));
        let tmpl_meta_bytes = encode_lv(11, &tmpl_meta);
        let mut template_bytes = encode_lv(1, &tmpl_meta_bytes);
        template_bytes.extend_from_slice(&encode_lv(2, &pod_spec_bytes));

        let mut label_entry = encode_lv(1, b"app");
        label_entry.extend_from_slice(&encode_lv(2, b"nginx"));
        let selector_bytes = encode_lv(1, &label_entry);

        let mut spec_bytes = encode_lv(2, &selector_bytes);
        spec_bytes.extend_from_slice(&encode_lv(3, &template_bytes));

        let name_bytes = encode_lv(1, b"nginx-deploy");
        let mut proto = encode_lv(1, &name_bytes);
        proto.extend_from_slice(&encode_lv(2, &spec_bytes));

        let result = decode_deployment_proto_gen(&proto)
            .expect("Deployment with VolumeMount readOnly=true must decode");
        let mounts = result["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts must be an array");
        assert_eq!(
            mounts[0]["readOnly"], true,
            "readOnly=true must survive — without it, volumes are mounted read-write, \
             causing data corruption in apps that rely on read-only enforcement"
        );
    }

    #[test]
    fn generated_statefulset_preserves_ordinals_start_field_absent_in_hand_struct() {
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("sts-ordinals".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::StatefulSetSpec {
                replicas: Some(3),
                ordinals: Some(apps_v1::StatefulSetOrdinals { start: Some(10) }),
                service_name: Some("headless".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        use prost::Message;
        sts.encode(&mut buf).unwrap();

        let obj = apps_v1::StatefulSet::decode(buf.as_slice()).expect("round-trip must succeed");
        assert_eq!(
            obj.spec
                .as_ref()
                .and_then(|s| s.ordinals.as_ref())
                .and_then(|o| o.start),
            Some(10),
            "spec.ordinals.start must survive round-trip — generated struct covers this field by \
             construction; hand struct omitted it, so pods started from index 0 instead of 10"
        );
    }

    /// Conditions with None type/status must serialize as "" not null.
    ///
    /// k8s controllers (e.g. deployment controller) read condition.type to determine
    /// rollout status. A null type causes JSON schema validation failures and breaks
    /// controllers that do exact string comparison (e.g. `c.Type == "Available"`).
    /// This test fails if the unwrap_or_default() fix is reverted.
    #[test]
    fn apps_condition_none_type_status_emits_empty_string_not_null() {
        use prost::Message;
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("sts-null-cond".to_string()),
                ..Default::default()
            }),
            status: Some(apps_v1::StatefulSetStatus {
                replicas: Some(1),
                conditions: vec![apps_v1::StatefulSetCondition {
                    r#type: None,
                    status: None,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sts.encode(&mut buf).unwrap();
        let result = decode_statefulset_proto_gen(&buf).expect("StatefulSet must decode");
        let cond = &result["status"]["conditions"][0];
        assert_eq!(
            cond["type"],
            serde_json::Value::String(String::new()),
            "condition.type must be \"\" not null — k8s controllers reject null type and \
             JSON schema validation fails for conditions with null required fields"
        );
        assert_eq!(
            cond["status"],
            serde_json::Value::String(String::new()),
            "condition.status must be \"\" not null — controllers doing string comparison \
             (e.g. status == \"True\") panic or skip conditions with null status"
        );
    }

    /// Deployment status.replicas/readyReplicas/unavailableReplicas/conditions must survive
    /// proto decode.
    ///
    /// `kubectl rollout status` and the deployment controller's own reconcile loop read these
    /// fields directly off a protobuf UpdateStatus PUT (client-go and KCM both default to
    /// protobuf); before this test, decode_deployment_proto_gen had zero status assertions at
    /// all, so a regression dropping `.status` would make every Deployment look permanently
    /// unavailable with nothing in the suite to catch it.
    #[test]
    fn decode_deployment_proto_gen_preserves_status_replicas_and_conditions() {
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-deploy".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(apps_v1::DeploymentStatus {
                observed_generation: Some(2),
                replicas: Some(3),
                updated_replicas: Some(3),
                ready_replicas: Some(2),
                available_replicas: Some(2),
                unavailable_replicas: Some(1),
                conditions: vec![apps_v1::DeploymentCondition {
                    r#type: Some("Available".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("MinimumReplicasAvailable".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();

        let result = decode_deployment_proto_gen(&buf).expect("Deployment with status must decode");

        assert_eq!(
            result["status"]["replicas"], 3,
            "status.replicas must survive decode — without it `kubectl rollout status` and the \
             deployment controller's own reconcile loop see zero replicas and loop forever"
        );
        assert_eq!(
            result["status"]["readyReplicas"], 2,
            "status.readyReplicas must survive decode — rollout readiness gating depends on it"
        );
        assert_eq!(
            result["status"]["unavailableReplicas"], 1,
            "status.unavailableReplicas must survive decode"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Available",
            "status.conditions must survive decode — without the Available condition, \
             `kubectl rollout status` never reports the deployment as ready"
        );
    }

    /// StatefulSet status.readyReplicas/currentRevision/updateRevision must survive proto
    /// decode.
    ///
    /// The StatefulSet controller compares currentRevision/updateRevision to decide which pods
    /// still need a rolling update, and readyReplicas gates ordered pod creation/scaling. The
    /// only existing status coverage for this decoder checked that a None condition
    /// type/status becomes "" (not null) — it never asserted that the numeric/revision status
    /// fields actually survive a populated decode.
    #[test]
    fn decode_statefulset_proto_gen_preserves_status_replicas_and_revisions() {
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-sts".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: None,
            status: Some(apps_v1::StatefulSetStatus {
                observed_generation: Some(4),
                replicas: Some(3),
                ready_replicas: Some(3),
                current_replicas: Some(2),
                updated_replicas: Some(1),
                current_revision: Some("my-sts-abc123".to_string()),
                update_revision: Some("my-sts-def456".to_string()),
                available_replicas: Some(3),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        sts.encode(&mut buf).unwrap();

        let result =
            decode_statefulset_proto_gen(&buf).expect("StatefulSet with status must decode");

        assert_eq!(
            result["status"]["readyReplicas"], 3,
            "status.readyReplicas must survive decode — ordered pod creation/scaling waits on it"
        );
        assert_eq!(
            result["status"]["currentRevision"], "my-sts-abc123",
            "status.currentRevision must survive decode — without it the StatefulSet controller \
             cannot tell which pods are already on the desired revision"
        );
        assert_eq!(
            result["status"]["updateRevision"], "my-sts-def456",
            "status.updateRevision must survive decode — without it a rolling update never \
             knows which revision to converge pods toward"
        );
    }

    /// decode_controllerrevision_proto_gen must preserve revision and the embedded raw data.
    ///
    /// The StatefulSet/DaemonSet history controllers roll back by matching on `revision` and
    /// replaying `data`; losing either makes a rollback silently replay the wrong (or no) state.
    #[test]
    fn decode_controllerrevision_proto_gen_preserves_revision_and_data() {
        let cr = apps_v1::ControllerRevision {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("my-sts-5d8f7c9b6".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            data: Some(
                crate::apps_gen::k8s::io::apimachinery::pkg::runtime::RawExtension {
                    raw: Some(br#"{"spec":{"replicas":3}}"#.to_vec()),
                },
            ),
            revision: Some(2),
        };
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();

        let result =
            decode_controllerrevision_proto_gen(&buf).expect("ControllerRevision must decode");

        assert_eq!(
            result["revision"], 2,
            "revision must survive decode — rollback controllers match on this to pick the \
             target revision"
        );
        assert_eq!(
            result["data"]["spec"]["replicas"], 3,
            "data must survive decode and parse as JSON — without it a rollback replays an \
             empty state instead of the recorded one"
        );
    }

    /// A Deployment selector expressed purely via matchExpressions (no matchLabels) must
    /// survive protobuf decode.
    ///
    /// Before the fix, gen_label_selector_to_json had no matchExpressions branch, and
    /// gen_apps_spec_to_json only emitted spec.selector when matchLabels was non-empty — so a
    /// matchExpressions-only selector decoded to a completely absent spec.selector. Live repro
    /// confirmed the fallout is worse than an empty `{}`: handlers/defaults.rs treats the missing
    /// selector as "absent" and silently substitutes one derived from spec.template.metadata.labels,
    /// discarding the user's actual selector without any error.
    #[test]
    fn decode_deployment_proto_gen_preserves_match_expressions_only_selector() {
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("matchexpr-deploy".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DeploymentSpec {
                replicas: Some(2),
                selector: Some(meta_v1::LabelSelector {
                    match_labels: Default::default(),
                    match_expressions: vec![meta_v1::LabelSelectorRequirement {
                        key: Some("tier".to_string()),
                        operator: Some("In".to_string()),
                        values: vec!["frontend".to_string()],
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();

        let result = decode_deployment_proto_gen(&buf).expect("Deployment must decode");

        assert_ne!(
            result["spec"]["selector"],
            serde_json::json!({}),
            "a matchExpressions-only selector must not decode to an absent/empty selector — \
             upstream treats that as \"select everything\", so the deployment controller would \
             adopt every pod in the namespace instead of only tier=frontend"
        );
        assert_eq!(
            result["spec"]["selector"]["matchExpressions"][0]["key"], "tier",
            "matchExpressions must survive decode when matchLabels is empty"
        );
        assert_eq!(
            result["spec"]["selector"]["matchExpressions"][0]["operator"], "In",
            "matchExpressions[].operator must survive decode"
        );
        assert_eq!(
            result["spec"]["selector"]["matchExpressions"][0]["values"][0], "frontend",
            "matchExpressions[].values must survive decode"
        );
    }

    /// A DaemonSet selector expressed purely via matchExpressions must survive protobuf decode.
    ///
    /// DaemonSet has no `replicas` field and (unlike Deployment/ReplicaSet/StatefulSet) no
    /// selector validation or defaulting in handlers/defaults.rs, so before the fix a
    /// matchExpressions-only selector decoded to spec.selector being completely absent, and
    /// nothing downstream caught or corrected it — live repro confirmed the DaemonSet was
    /// created successfully with no selector key at all in spec, which upstream semantics treat
    /// as matching every pod in the cluster.
    #[test]
    fn decode_daemonset_proto_gen_preserves_match_expressions_only_selector() {
        let ds = apps_v1::DaemonSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("matchexpr-ds".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DaemonSetSpec {
                selector: Some(meta_v1::LabelSelector {
                    match_labels: Default::default(),
                    match_expressions: vec![meta_v1::LabelSelectorRequirement {
                        key: Some("tier".to_string()),
                        operator: Some("In".to_string()),
                        values: vec!["frontend".to_string()],
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ds.encode(&mut buf).unwrap();

        let result = decode_daemonset_proto_gen(&buf).expect("DaemonSet must decode");

        assert!(
            !result["spec"]["selector"].is_null(),
            "a matchExpressions-only selector must not decode to a missing spec.selector — \
             DaemonSet has no fallback defaulting/validation, so a missing selector silently \
             becomes \"match every pod in the cluster\" with no error to the caller"
        );
        assert_eq!(
            result["spec"]["selector"]["matchExpressions"][0]["key"], "tier",
            "matchExpressions must survive decode when matchLabels is empty"
        );
    }

    /// decode_statefulset_proto_gen must preserve volumeClaimTemplates, serviceName,
    /// podManagementPolicy, persistentVolumeClaimRetentionPolicy, ordinals,
    /// revisionHistoryLimit, minReadySeconds, and updateStrategy.rollingUpdate.maxUnavailable.
    ///
    /// volumeClaimTemplates and serviceName are the fields StatefulSet exists for — stable
    /// per-replica storage and network identity, per the type's own doc comment. Before this
    /// fix, decode_statefulset_proto_gen only ever read replicas/selector/template/
    /// updateStrategy.partition, so every protobuf-encoded StatefulSet create/update (client-go
    /// and kcm both default to protobuf) silently lost the rest of its spec — a StatefulSet
    /// with volumeClaimTemplates would decode with no storage claims at all.
    #[test]
    fn decode_statefulset_proto_gen_preserves_previously_dropped_spec_fields() {
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("web".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::StatefulSetSpec {
                replicas: Some(3),
                service_name: Some("web-headless".to_string()),
                pod_management_policy: Some("Parallel".to_string()),
                revision_history_limit: Some(0),
                min_ready_seconds: Some(30),
                update_strategy: Some(apps_v1::StatefulSetUpdateStrategy {
                    r#type: Some("RollingUpdate".to_string()),
                    rolling_update: Some(apps_v1::RollingUpdateStatefulSetStrategy {
                        partition: Some(2),
                        max_unavailable: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(1),
                                str_val: Some("20%".to_string()),
                                ..Default::default()
                            },
                        ),
                    }),
                }),
                persistent_volume_claim_retention_policy: Some(
                    apps_v1::StatefulSetPersistentVolumeClaimRetentionPolicy {
                        when_deleted: Some("Delete".to_string()),
                        when_scaled: Some("Retain".to_string()),
                    },
                ),
                ordinals: Some(apps_v1::StatefulSetOrdinals { start: Some(10) }),
                volume_claim_templates: vec![core_v1::PersistentVolumeClaim {
                    metadata: Some(meta_v1::ObjectMeta {
                        name: Some("www".to_string()),
                        ..Default::default()
                    }),
                    spec: Some(core_v1::PersistentVolumeClaimSpec {
                        access_modes: vec!["ReadWriteOnce".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        sts.encode(&mut buf).unwrap();

        let result = decode_statefulset_proto_gen(&buf).expect("StatefulSet must decode");

        assert_eq!(
            result["spec"]["volumeClaimTemplates"][0]["metadata"]["name"], "www",
            "volumeClaimTemplates must survive decode — without it every replica loses its \
             stable per-pod storage claim"
        );
        assert_eq!(
            result["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"][0], "ReadWriteOnce",
            "volumeClaimTemplates[].spec must survive decode, not just metadata"
        );
        assert_eq!(
            result["spec"]["serviceName"], "web-headless",
            "serviceName must survive decode — without it pods lose their stable DNS identity"
        );
        assert_eq!(
            result["spec"]["podManagementPolicy"], "Parallel",
            "podManagementPolicy must survive decode"
        );
        assert_eq!(
            result["spec"]["revisionHistoryLimit"], 0,
            "explicit revisionHistoryLimit=0 must survive decode, not be silently absent"
        );
        assert_eq!(
            result["spec"]["minReadySeconds"], 30,
            "minReadySeconds must survive decode — it gates when a newly created pod counts as \
             available"
        );
        assert_eq!(
            result["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"], "20%",
            "updateStrategy.rollingUpdate.maxUnavailable must survive decode alongside partition"
        );
        assert_eq!(
            result["spec"]["persistentVolumeClaimRetentionPolicy"]["whenDeleted"], "Delete",
            "persistentVolumeClaimRetentionPolicy must survive decode — without it PVCs leak \
             (or vanish) on StatefulSet deletion/scale-down against the user's stated policy"
        );
        assert_eq!(
            result["spec"]["ordinals"]["start"], 10,
            "ordinals.start must survive decode — without it replicas start from index 0 \
             instead of the requested offset"
        );
    }

    /// decode_deployment_proto_gen must preserve spec.paused and spec.minReadySeconds.
    ///
    /// `kubectl rollout pause deployment/foo` sets spec.paused=true; before this fix it was
    /// never read, so the pause command would appear to succeed while the deployment
    /// controller kept rolling out regardless.
    #[test]
    fn decode_deployment_proto_gen_preserves_paused_and_min_ready_seconds() {
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("paused-deploy".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DeploymentSpec {
                replicas: Some(2),
                paused: Some(true),
                min_ready_seconds: Some(15),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();

        let result = decode_deployment_proto_gen(&buf).expect("Deployment must decode");

        assert_eq!(
            result["spec"]["paused"], true,
            "spec.paused must survive decode — `kubectl rollout pause` depends on this field \
             actually reaching storage"
        );
        assert_eq!(
            result["spec"]["minReadySeconds"], 15,
            "spec.minReadySeconds must survive decode — it gates when a newly created pod \
             counts as available during a rollout"
        );
    }

    /// decode_daemonset_proto_gen must preserve updateStrategy, minReadySeconds, and
    /// revisionHistoryLimit.
    ///
    /// Before this fix, decode_daemonset_proto_gen only ever read selector/template — a
    /// protobuf-encoded DaemonSet create/update with an explicit OnDelete or maxUnavailance
    /// rolling-update strategy would silently fall back to defaults.rs's RollingUpdate default
    /// instead, changing how node pods actually roll out.
    #[test]
    fn decode_daemonset_proto_gen_preserves_update_strategy_and_history_limit() {
        let ds = apps_v1::DaemonSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("ds-strategy".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::DaemonSetSpec {
                min_ready_seconds: Some(5),
                revision_history_limit: Some(0),
                update_strategy: Some(apps_v1::DaemonSetUpdateStrategy {
                    r#type: Some("RollingUpdate".to_string()),
                    rolling_update: Some(apps_v1::RollingUpdateDaemonSet {
                        max_unavailable: Some(
                            crate::apps_gen::k8s::io::apimachinery::pkg::util::intstr::IntOrString {
                                r#type: Some(0),
                                int_val: Some(2),
                                ..Default::default()
                            },
                        ),
                        max_surge: None,
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        ds.encode(&mut buf).unwrap();

        let result = decode_daemonset_proto_gen(&buf).expect("DaemonSet must decode");

        assert_eq!(
            result["spec"]["updateStrategy"]["type"], "RollingUpdate",
            "updateStrategy.type must survive decode — dropping it lets defaults.rs silently \
             overwrite a user-chosen OnDelete strategy with RollingUpdate"
        );
        assert_eq!(
            result["spec"]["updateStrategy"]["rollingUpdate"]["maxUnavailable"], 2,
            "updateStrategy.rollingUpdate.maxUnavailable must survive decode"
        );
        assert_eq!(
            result["spec"]["revisionHistoryLimit"], 0,
            "explicit revisionHistoryLimit=0 must survive decode, not be silently absent"
        );
        assert_eq!(
            result["spec"]["minReadySeconds"], 5,
            "minReadySeconds must survive decode"
        );
    }

    /// decode_replicaset_proto_gen must preserve spec.minReadySeconds.
    ///
    /// minReadySeconds gates when a newly created pod counts as available for the ReplicaSet's
    /// own availability accounting; before this fix it was never read at all.
    #[test]
    fn decode_replicaset_proto_gen_preserves_min_ready_seconds() {
        let rs = apps_v1::ReplicaSet {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("rs-min-ready".to_string()),
                ..Default::default()
            }),
            spec: Some(apps_v1::ReplicaSetSpec {
                replicas: Some(2),
                min_ready_seconds: Some(8),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();

        let result = decode_replicaset_proto_gen(&buf).expect("ReplicaSet must decode");

        assert_eq!(
            result["spec"]["minReadySeconds"], 8,
            "spec.minReadySeconds must survive decode"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how StatefulSet's volumeClaimTemplates/
    // serviceName/podManagementPolicy/persistentVolumeClaimRetentionPolicy/ordinals,
    // Deployment's paused, and DaemonSet's updateStrategy/revisionHistoryLimit (plus
    // minReadySeconds on all four resources) were found missing from this file.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them (this file delegates to core_gen_adapter's copy, which has the same omissions); do
    // not guess at the fix here.
    // labels/annotations are maps: their own field name is never a real leaf once populated,
    // only their sentinel-populated entry is (the deterministic "__sentinel__" map-key literal
    // u7s_sentinel's blanket `Sentinel for String` always produces). ownerReferences is an array
    // of a real struct (OwnerReference), so its own field name is likewise never a leaf; `uid`
    // pins the check to ownerReferences specifically rather than colliding with ObjectMeta's own
    // (separately checked) `uid`.
    const OBJECT_META_EXPECTED: &[&str] = &[
        "name",
        "generateName",
        "namespace",
        "uid",
        "resourceVersion",
        "generation",
        "creationTimestamp",
        "labels.__sentinel__",
        "annotations.__sentinel__",
        "ownerReferences.uid",
        "finalizers",
    ];

    /// PodSpec/Container's own completeness is covered separately in core_gen_adapter.rs; this
    /// blanks (but keeps the key of) the nested template so a dropped *SetSpec-level field
    /// (e.g. minReadySeconds shares no name with PodSpec, but this guards future additions too)
    /// can't hide behind a PodSpec-level namesake still being present in the tree.
    fn blank_template(spec_obj: &mut serde_json::Map<String, serde_json::Value>) {
        spec_obj.insert("template".to_string(), serde_json::json!({}));
    }

    #[test]
    fn sentinel_completeness_decode_statefulset_proto_gen() {
        let sts = apps_v1::StatefulSet {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apps_v1::StatefulSetSpec::sentinel()),
            status: Some(apps_v1::StatefulSetStatus::sentinel()),
        };
        let mut buf = Vec::new();
        sts.encode(&mut buf).unwrap();
        let mut decoded = decode_statefulset_proto_gen(&buf)
            .expect("sentinel StatefulSet must decode via the generated path");
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            blank_template(spec);
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "replicas",
            // "selector" is a LabelSelector: never a leaf itself once populated, only its
            // sentinel map entry is.
            "selector.matchLabels.__sentinel__",
            "template",
            // "volumeClaimTemplates" holds full PersistentVolumeClaim objects; that struct's own
            // completeness is covered by core_gen_adapter's PVC tests, so this only needs one
            // leaf proving the array survives decode at all.
            "volumeClaimTemplates.metadata.name",
            "serviceName",
            "podManagementPolicy",
            "revisionHistoryLimit",
            "minReadySeconds",
            // "updateStrategy"/"persistentVolumeClaimRetentionPolicy"/"ordinals" are containers
            // whose own field name is never itself a leaf; the leaf children below already
            // exercise each one (a decoder that dropped the whole container drops these too).
            "whenDeleted",
            "whenScaled",
            "start",
            "partition",
            "maxUnavailable",
            "observedGeneration",
            "readyReplicas",
            "currentReplicas",
            "updatedReplicas",
            "currentRevision",
            "updateRevision",
            "collisionCount",
            "availableReplicas",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_deployment_proto_gen() {
        let deploy = apps_v1::Deployment {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apps_v1::DeploymentSpec::sentinel()),
            status: Some(apps_v1::DeploymentStatus::sentinel()),
        };
        let mut buf = Vec::new();
        deploy.encode(&mut buf).unwrap();
        let mut decoded = decode_deployment_proto_gen(&buf)
            .expect("sentinel Deployment must decode via the generated path");
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            blank_template(spec);
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "replicas",
            "selector.matchLabels.__sentinel__",
            "template",
            // "strategy" is a container (DeploymentStrategy: type + rollingUpdate); its leaf
            // children below already exercise it.
            "maxUnavailable",
            "maxSurge",
            "revisionHistoryLimit",
            "progressDeadlineSeconds",
            "minReadySeconds",
            "paused",
            "observedGeneration",
            "updatedReplicas",
            "readyReplicas",
            "availableReplicas",
            "unavailableReplicas",
            "terminatingReplicas",
            "collisionCount",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
            "lastUpdateTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_daemonset_proto_gen() {
        let ds = apps_v1::DaemonSet {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apps_v1::DaemonSetSpec::sentinel()),
            status: Some(apps_v1::DaemonSetStatus::sentinel()),
        };
        let mut buf = Vec::new();
        ds.encode(&mut buf).unwrap();
        let mut decoded = decode_daemonset_proto_gen(&buf)
            .expect("sentinel DaemonSet must decode via the generated path");
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            blank_template(spec);
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "selector.matchLabels.__sentinel__",
            "template",
            // "updateStrategy" is a container (DaemonSetUpdateStrategy: type + rollingUpdate);
            // its leaf children below already exercise it.
            "maxUnavailable",
            "maxSurge",
            "minReadySeconds",
            "revisionHistoryLimit",
            "currentNumberScheduled",
            "numberMisscheduled",
            "desiredNumberScheduled",
            "numberReady",
            "observedGeneration",
            "updatedNumberScheduled",
            "numberAvailable",
            "numberUnavailable",
            "collisionCount",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_replicaset_proto_gen() {
        let rs = apps_v1::ReplicaSet {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apps_v1::ReplicaSetSpec::sentinel()),
            status: Some(apps_v1::ReplicaSetStatus::sentinel()),
        };
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();
        let mut decoded = decode_replicaset_proto_gen(&buf)
            .expect("sentinel ReplicaSet must decode via the generated path");
        if let Some(spec) = decoded.get_mut("spec").and_then(|s| s.as_object_mut()) {
            blank_template(spec);
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "replicas",
            "minReadySeconds",
            "selector.matchLabels.__sentinel__",
            "template",
            "fullyLabeledReplicas",
            "readyReplicas",
            "availableReplicas",
            "terminatingReplicas",
            "observedGeneration",
            "type",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_controllerrevision_proto_gen() {
        // Not ControllerRevision::sentinel() wholesale: RawExtension::sentinel() would fill
        // `raw` with an arbitrary non-empty byte sequence, which decode_controllerrevision_proto_gen
        // silently (and correctly) drops if it fails to parse as JSON — a sentinel value must be
        // valid JSON here to actually exercise the "data survives" path this test checks.
        let cr = apps_v1::ControllerRevision {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            data: Some(
                crate::apps_gen::k8s::io::apimachinery::pkg::runtime::RawExtension {
                    raw: Some(br#"{"a":1}"#.to_vec()),
                },
            ),
            revision: Some(2),
        };
        let mut buf = Vec::new();
        cr.encode(&mut buf).unwrap();
        let decoded = decode_controllerrevision_proto_gen(&buf)
            .expect("sentinel ControllerRevision must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        // "data" is a RawExtension, inlined as the parsed JSON document — {"a": 1} here — so
        // its own field name is never a leaf; "data.a" is the real decoded leaf.
        expected.extend(["revision", "data.a"]);
        assert_fields_present(&paths, &expected);
    }

    // ---- Field-omission: all-default proto must decode with no stray nulls ----
    //
    // Each test below builds a message with every optional field unset (`Default::default()`),
    // decodes it through the real entry point, and asserts no key survives as an explicit JSON
    // `null` (other than ObjectMeta's `creationTimestamp`) and that spec/status are genuinely
    // absent rather than present-with-nulls.

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_statefulset_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = apps_v1::StatefulSet::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_statefulset_proto_gen(&buf).expect("all-default StatefulSet must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — the StatefulSet controller checks \
             `status.currentRevision != null` to decide whether it has ever created a replica; \
             a stray null there is indistinguishable from a real (but empty) revision"
        );
    }

    #[test]
    fn decode_deployment_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = apps_v1::Deployment::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_deployment_proto_gen(&buf).expect("all-default Deployment must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — `kubectl rollout status` reads \
             status.conditions to report progress; a stray null there could crash a client that \
             expects either a real array or a missing key, but not `null`"
        );
    }

    #[test]
    fn decode_daemonset_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = apps_v1::DaemonSet::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded = decode_daemonset_proto_gen(&buf).expect("all-default DaemonSet must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null"
        );
    }

    #[test]
    fn decode_replicaset_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let obj = apps_v1::ReplicaSet::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded =
            decode_replicaset_proto_gen(&buf).expect("all-default ReplicaSet must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null"
        );
    }

    #[test]
    fn decode_controllerrevision_proto_gen_omits_unset_data_instead_of_emitting_null() {
        let obj = apps_v1::ControllerRevision::default();
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let decoded = decode_controllerrevision_proto_gen(&buf)
            .expect("all-default ControllerRevision must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("data").is_none(),
            "an unset data payload must be absent, not null — the StatefulSet/DaemonSet \
             controllers diff ControllerRevision.data to detect a rollback target; a stray null \
             would be indistinguishable from a revision that legitimately captured an empty patch"
        );
    }
}
