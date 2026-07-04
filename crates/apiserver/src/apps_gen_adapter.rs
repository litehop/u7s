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
    m
}

macro_rules! apps_condition_to_json {
    ($c:expr) => {{
        let mut cond = serde_json::json!({
            "type": $c.r#type,
            "status": $c.status,
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
        if !sel.match_labels.is_empty() {
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
                us_json["rollingUpdate"] =
                    serde_json::json!({ "partition": ru.partition.unwrap_or(0) });
            }
            if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                spec_json["updateStrategy"] = us_json;
            }
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
                .map(|c| {
                    let mut cond = serde_json::json!({
                        "type": c.r#type,
                        "status": c.status,
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
        if let Some(spec_json) = gen_apps_spec_to_json(spec.selector, spec.template) {
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
        let mut spec_json =
            gen_apps_spec_to_json(spec.selector, spec.template).unwrap_or(serde_json::json!({}));
        spec_json["replicas"] = serde_json::Value::Number(replicas.into());
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

        let strategy = &result["spec"];
        assert!(
            !strategy.is_null(),
            "spec must be present — generated struct includes strategy field by construction"
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
}
