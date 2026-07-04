use prost::Message;

use crate::storage_node_flow_gen::k8s::io::api::flowcontrol::v1 as flowcontrol_v1;
use crate::storage_node_flow_gen::k8s::io::api::node::v1 as node_v1;
use crate::storage_node_flow_gen::k8s::io::api::scheduling::v1 as scheduling_v1;
use crate::storage_node_flow_gen::k8s::io::api::storage::v1 as storage_v1;
use crate::storage_node_flow_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    let mut m = serde_json::json!({ "creationTimestamp": serde_json::Value::Null });
    if let Some(n) = meta.name.filter(|s| !s.is_empty()) {
        m["name"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.generate_name.filter(|s| !s.is_empty()) {
        m["generateName"] = serde_json::Value::String(n);
    }
    if let Some(n) = meta.namespace.filter(|s| !s.is_empty()) {
        m["namespace"] = serde_json::Value::String(n);
    }
    if let Some(u) = meta.uid.filter(|s| !s.is_empty()) {
        m["uid"] = serde_json::Value::String(u);
    }
    if let Some(rv) = meta.resource_version.filter(|s| !s.is_empty()) {
        m["resourceVersion"] = serde_json::Value::String(rv);
    }
    if let Some(g) = meta.generation.filter(|&v| v != 0) {
        m["generation"] = serde_json::Value::Number(g.into());
    }
    if let Some(ts) = meta.creation_timestamp {
        if let Some(secs) = ts.seconds {
            if secs > 0 {
                m["creationTimestamp"] =
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64));
            }
        }
    }
    if !meta.labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = meta
            .labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["labels"] = serde_json::Value::Object(labels);
    }
    if !meta.annotations.is_empty() {
        let annotations: serde_json::Map<String, serde_json::Value> = meta
            .annotations
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m["annotations"] = serde_json::Value::Object(annotations);
    }
    if !meta.owner_references.is_empty() {
        let refs: Vec<serde_json::Value> = meta
            .owner_references
            .into_iter()
            .map(|r| {
                let mut entry = serde_json::json!({});
                if let Some(v) = r.api_version.filter(|s| !s.is_empty()) {
                    entry["apiVersion"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.kind.filter(|s| !s.is_empty()) {
                    entry["kind"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.name.filter(|s| !s.is_empty()) {
                    entry["name"] = serde_json::Value::String(v);
                }
                if let Some(v) = r.uid.filter(|s| !s.is_empty()) {
                    entry["uid"] = serde_json::Value::String(v);
                }
                if let Some(ctrl) = r.controller {
                    entry["controller"] = serde_json::Value::Bool(ctrl);
                }
                if let Some(bod) = r.block_owner_deletion {
                    entry["blockOwnerDeletion"] = serde_json::Value::Bool(bod);
                }
                entry
            })
            .collect();
        if !refs.is_empty() {
            m["ownerReferences"] = serde_json::Value::Array(refs);
        }
    }
    if !meta.finalizers.is_empty() {
        let fins: Vec<serde_json::Value> = meta
            .finalizers
            .into_iter()
            .map(serde_json::Value::String)
            .collect();
        m["finalizers"] = serde_json::Value::Array(fins);
    }
    m
}

fn gen_label_selector_to_json(sel: meta_v1::LabelSelector) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !sel.match_labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = sel
            .match_labels
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        m.insert("matchLabels".to_string(), serde_json::Value::Object(labels));
    }
    if !sel.match_expressions.is_empty() {
        let exprs: Vec<serde_json::Value> = sel
            .match_expressions
            .into_iter()
            .map(|e| {
                let mut em = serde_json::Map::new();
                if let Some(k) = e.key.filter(|s| !s.is_empty()) {
                    em.insert("key".to_string(), serde_json::Value::String(k));
                }
                if let Some(op) = e.operator.filter(|s| !s.is_empty()) {
                    em.insert("operator".to_string(), serde_json::Value::String(op));
                }
                if !e.values.is_empty() {
                    em.insert(
                        "values".to_string(),
                        serde_json::Value::Array(
                            e.values
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                serde_json::Value::Object(em)
            })
            .collect();
        m.insert(
            "matchExpressions".to_string(),
            serde_json::Value::Array(exprs),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_quantity_opt_to_json(
    q: Option<crate::storage_node_flow_gen::k8s::io::apimachinery::pkg::api::resource::Quantity>,
) -> Option<serde_json::Value> {
    q.and_then(|q| q.string)
        .filter(|s| !s.is_empty())
        .map(serde_json::Value::String)
}

// ---- Decoder A: CSINode ---------------------------------------------------

pub fn decode_csinode_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::CsiNode::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let drivers: Vec<serde_json::Value> = obj
        .spec
        .map(|s| s.drivers)
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            let mut dm = serde_json::Map::new();
            if let Some(n) = d.name.filter(|s| !s.is_empty()) {
                dm.insert("name".to_string(), serde_json::Value::String(n));
            }
            if let Some(nid) = d.node_id.filter(|s| !s.is_empty()) {
                dm.insert("nodeID".to_string(), serde_json::Value::String(nid));
            }
            if !d.topology_keys.is_empty() {
                dm.insert(
                    "topologyKeys".to_string(),
                    serde_json::Value::Array(
                        d.topology_keys
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            if let Some(alloc) = d.allocatable {
                if let Some(count) = alloc.count {
                    dm.insert(
                        "allocatable".to_string(),
                        serde_json::json!({ "count": count }),
                    );
                }
            }
            serde_json::Value::Object(dm)
        })
        .collect();

    Some(serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "CSINode",
        "metadata": meta,
        "spec": { "drivers": drivers }
    }))
}

// ---- Decoder A: CSIDriver ------------------------------------------------

pub fn decode_csidriver_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::CsiDriver::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut spec = serde_json::Map::new();
    if let Some(s) = obj.spec {
        if let Some(v) = s.attach_required {
            spec.insert("attachRequired".to_string(), serde_json::Value::Bool(v));
        }
        if let Some(v) = s.pod_info_on_mount {
            spec.insert("podInfoOnMount".to_string(), serde_json::Value::Bool(v));
        }
        if !s.volume_lifecycle_modes.is_empty() {
            spec.insert(
                "volumeLifecycleModes".to_string(),
                serde_json::Value::Array(
                    s.volume_lifecycle_modes
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        if let Some(v) = s.storage_capacity {
            spec.insert("storageCapacity".to_string(), serde_json::Value::Bool(v));
        }
        if let Some(v) = s.fs_group_policy.filter(|s| !s.is_empty()) {
            spec.insert("fsGroupPolicy".to_string(), serde_json::Value::String(v));
        }
        if !s.token_requests.is_empty() {
            let trs: Vec<serde_json::Value> = s
                .token_requests
                .into_iter()
                .map(|tr| {
                    let mut trm = serde_json::Map::new();
                    if let Some(aud) = tr.audience.filter(|s| !s.is_empty()) {
                        trm.insert("audience".to_string(), serde_json::Value::String(aud));
                    }
                    if let Some(exp) = tr.expiration_seconds.filter(|&v| v != 0) {
                        trm.insert(
                            "expirationSeconds".to_string(),
                            serde_json::Value::Number(exp.into()),
                        );
                    }
                    serde_json::Value::Object(trm)
                })
                .collect();
            spec.insert("tokenRequests".to_string(), serde_json::Value::Array(trs));
        }
        if let Some(v) = s.requires_republish {
            spec.insert("requiresRepublish".to_string(), serde_json::Value::Bool(v));
        }
        if let Some(v) = s.se_linux_mount {
            spec.insert("seLinuxMount".to_string(), serde_json::Value::Bool(v));
        }
    }

    Some(serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "CSIDriver",
        "metadata": meta,
        "spec": serde_json::Value::Object(spec)
    }))
}

// ---- Decoder A: CSIStorageCapacity ----------------------------------------

pub fn decode_csistoragecapacity_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::CsiStorageCapacity::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "CSIStorageCapacity",
        "metadata": meta
    });

    if let Some(scn) = obj.storage_class_name.filter(|s| !s.is_empty()) {
        result["storageClassName"] = serde_json::Value::String(scn);
    }
    if let Some(sel) = obj.node_topology {
        result["nodeTopology"] = gen_label_selector_to_json(sel);
    }
    if let Some(v) = gen_quantity_opt_to_json(obj.capacity) {
        result["capacity"] = v;
    }
    if let Some(v) = gen_quantity_opt_to_json(obj.maximum_volume_size) {
        result["maximumVolumeSize"] = v;
    }

    Some(result)
}

// ---- Decoder A: VolumeAttachment ------------------------------------------

pub fn decode_volumeattachment_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::VolumeAttachment::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "VolumeAttachment",
        "metadata": meta
    });

    if let Some(spec) = obj.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(v) = spec.attacher.filter(|s| !s.is_empty()) {
            spec_map.insert("attacher".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = spec.node_name.filter(|s| !s.is_empty()) {
            spec_map.insert("nodeName".to_string(), serde_json::Value::String(v));
        }
        let mut source_map = serde_json::Map::new();
        if let Some(src) = spec.source {
            if let Some(v) = src.persistent_volume_name.filter(|s| !s.is_empty()) {
                source_map.insert(
                    "persistentVolumeName".to_string(),
                    serde_json::Value::String(v),
                );
            }
        }
        spec_map.insert("source".to_string(), serde_json::Value::Object(source_map));
        result["spec"] = serde_json::Value::Object(spec_map);
    }

    if let Some(status) = obj.status {
        let mut status_map = serde_json::Map::new();
        if let Some(v) = status.attached {
            status_map.insert("attached".to_string(), serde_json::Value::Bool(v));
        }
        if !status.attachment_metadata.is_empty() {
            let am: serde_json::Map<String, serde_json::Value> = status
                .attachment_metadata
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            status_map.insert(
                "attachmentMetadata".to_string(),
                serde_json::Value::Object(am),
            );
        }
        if let Some(err) = status.attach_error {
            let mut em = serde_json::Map::new();
            if let Some(v) = err.message.filter(|s| !s.is_empty()) {
                em.insert("message".to_string(), serde_json::Value::String(v));
            }
            if let Some(t) = err.time {
                if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                    em.insert(
                        "time".to_string(),
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64)),
                    );
                }
            }
            status_map.insert("attachError".to_string(), serde_json::Value::Object(em));
        }
        if let Some(err) = status.detach_error {
            let mut em = serde_json::Map::new();
            if let Some(v) = err.message.filter(|s| !s.is_empty()) {
                em.insert("message".to_string(), serde_json::Value::String(v));
            }
            if let Some(t) = err.time {
                if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                    em.insert(
                        "time".to_string(),
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64)),
                    );
                }
            }
            status_map.insert("detachError".to_string(), serde_json::Value::Object(em));
        }
        if !status_map.is_empty() {
            result["status"] = serde_json::Value::Object(status_map);
        }
    }

    Some(result)
}

// ---- Decoder A: StorageClass -----------------------------------------------

pub fn decode_storageclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::StorageClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": meta
    });

    if let Some(v) = obj.provisioner.filter(|s| !s.is_empty()) {
        result["provisioner"] = serde_json::Value::String(v);
    }
    if !obj.parameters.is_empty() {
        let params: serde_json::Map<String, serde_json::Value> = obj
            .parameters
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        result["parameters"] = serde_json::Value::Object(params);
    }
    if let Some(v) = obj.reclaim_policy.filter(|s| !s.is_empty()) {
        result["reclaimPolicy"] = serde_json::Value::String(v);
    }
    if !obj.mount_options.is_empty() {
        result["mountOptions"] = serde_json::Value::Array(
            obj.mount_options
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    if let Some(v) = obj.allow_volume_expansion {
        result["allowVolumeExpansion"] = serde_json::Value::Bool(v);
    }
    if let Some(v) = obj.volume_binding_mode.filter(|s| !s.is_empty()) {
        result["volumeBindingMode"] = serde_json::Value::String(v);
    }

    Some(result)
}

// ---- Decoder A: VolumeAttributesClass --------------------------------------

pub fn decode_volumeattributesclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = storage_v1::VolumeAttributesClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "storage.k8s.io/v1",
        "kind": "VolumeAttributesClass",
        "metadata": meta
    });

    if let Some(v) = obj.driver_name.filter(|s| !s.is_empty()) {
        result["driverName"] = serde_json::Value::String(v);
    }
    if !obj.parameters.is_empty() {
        let params: serde_json::Map<String, serde_json::Value> = obj
            .parameters
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        result["parameters"] = serde_json::Value::Object(params);
    }

    Some(result)
}

// ---- Decoder A: RuntimeClass -----------------------------------------------

pub fn decode_runtimeclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = node_v1::RuntimeClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "node.k8s.io/v1",
        "kind": "RuntimeClass",
        "metadata": meta,
        "handler": obj.handler.unwrap_or_default()
    });

    if let Some(overhead) = obj.overhead {
        if !overhead.pod_fixed.is_empty() {
            let pod_fixed: serde_json::Map<String, serde_json::Value> = overhead
                .pod_fixed
                .into_iter()
                .filter_map(|(k, q)| {
                    q.string
                        .filter(|s| !s.is_empty())
                        .map(|s| (k, serde_json::Value::String(s)))
                })
                .collect();
            if !pod_fixed.is_empty() {
                result["overhead"] =
                    serde_json::json!({ "podFixed": serde_json::Value::Object(pod_fixed) });
            }
        }
    }

    if let Some(sched) = obj.scheduling {
        let mut sched_map = serde_json::Map::new();
        if !sched.node_selector.is_empty() {
            let ns: serde_json::Map<String, serde_json::Value> = sched
                .node_selector
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            sched_map.insert("nodeSelector".to_string(), serde_json::Value::Object(ns));
        }
        if !sched.tolerations.is_empty() {
            let tols: Vec<serde_json::Value> = sched
                .tolerations
                .into_iter()
                .map(|t| {
                    let mut tm = serde_json::Map::new();
                    if let Some(k) = t.key.filter(|s| !s.is_empty()) {
                        tm.insert("key".to_string(), serde_json::Value::String(k));
                    }
                    if let Some(op) = t.operator.filter(|s| !s.is_empty()) {
                        tm.insert("operator".to_string(), serde_json::Value::String(op));
                    }
                    if let Some(v) = t.value.filter(|s| !s.is_empty()) {
                        tm.insert("value".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(eff) = t.effect.filter(|s| !s.is_empty()) {
                        tm.insert("effect".to_string(), serde_json::Value::String(eff));
                    }
                    if let Some(ts) = t.toleration_seconds {
                        tm.insert(
                            "tolerationSeconds".to_string(),
                            serde_json::Value::Number(ts.into()),
                        );
                    }
                    serde_json::Value::Object(tm)
                })
                .collect();
            sched_map.insert("tolerations".to_string(), serde_json::Value::Array(tols));
        }
        if !sched_map.is_empty() {
            result["scheduling"] = serde_json::Value::Object(sched_map);
        }
    }

    Some(result)
}

// ---- Decoder A: PriorityClass (scheduling.k8s.io/v1) ----------------------

pub fn decode_priorityclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = scheduling_v1::PriorityClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "scheduling.k8s.io/v1",
        "kind": "PriorityClass",
        "metadata": meta,
        "value": obj.value.unwrap_or(0)
    });

    if let Some(true) = obj.global_default {
        result["globalDefault"] = serde_json::Value::Bool(true);
    }
    if let Some(v) = obj.description.filter(|s| !s.is_empty()) {
        result["description"] = serde_json::Value::String(v);
    }
    if let Some(v) = obj.preemption_policy.filter(|s| !s.is_empty()) {
        result["preemptionPolicy"] = serde_json::Value::String(v);
    }

    Some(result)
}

// ---- Decoder A: FlowSchema -------------------------------------------------

pub fn decode_flowschema_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = flowcontrol_v1::FlowSchema::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": meta
    });

    if let Some(spec) = obj.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(mp) = spec.matching_precedence.filter(|&v| v != 0) {
            spec_map.insert(
                "matchingPrecedence".to_string(),
                serde_json::Value::Number(mp.into()),
            );
        }
        if let Some(plc) = spec.priority_level_configuration {
            if let Some(n) = plc.name.filter(|s| !s.is_empty()) {
                spec_map.insert(
                    "priorityLevelConfiguration".to_string(),
                    serde_json::json!({ "name": n }),
                );
            }
        }
        if let Some(dm) = spec.distinguisher_method {
            if let Some(t) = dm.r#type.filter(|s| !s.is_empty()) {
                spec_map.insert(
                    "distinguisherMethod".to_string(),
                    serde_json::json!({ "type": t }),
                );
            }
        }
        if !spec.rules.is_empty() {
            let rules: Vec<serde_json::Value> = spec
                .rules
                .into_iter()
                .map(gen_policy_rules_with_subjects_to_json)
                .collect();
            spec_map.insert("rules".to_string(), serde_json::Value::Array(rules));
        }
        if !spec_map.is_empty() {
            result["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    if let Some(status) = obj.status {
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(gen_flowschema_condition_to_json)
                .collect();
            result["status"] = serde_json::json!({ "conditions": conds });
        }
    }

    Some(result)
}

fn gen_policy_rules_with_subjects_to_json(
    rule: flowcontrol_v1::PolicyRulesWithSubjects,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !rule.subjects.is_empty() {
        let subjects: Vec<serde_json::Value> = rule
            .subjects
            .into_iter()
            .map(|s| {
                let mut sm = serde_json::Map::new();
                if let Some(k) = s.kind.filter(|s| !s.is_empty()) {
                    sm.insert("kind".to_string(), serde_json::Value::String(k));
                }
                if let Some(u) = s.user {
                    if let Some(n) = u.name.filter(|s| !s.is_empty()) {
                        sm.insert("user".to_string(), serde_json::json!({ "name": n }));
                    }
                }
                if let Some(g) = s.group {
                    if let Some(n) = g.name.filter(|s| !s.is_empty()) {
                        sm.insert("group".to_string(), serde_json::json!({ "name": n }));
                    }
                }
                if let Some(sa) = s.service_account {
                    let mut sam = serde_json::Map::new();
                    if let Some(ns) = sa.namespace.filter(|s| !s.is_empty()) {
                        sam.insert("namespace".to_string(), serde_json::Value::String(ns));
                    }
                    if let Some(n) = sa.name.filter(|s| !s.is_empty()) {
                        sam.insert("name".to_string(), serde_json::Value::String(n));
                    }
                    sm.insert("serviceAccount".to_string(), serde_json::Value::Object(sam));
                }
                serde_json::Value::Object(sm)
            })
            .collect();
        m.insert("subjects".to_string(), serde_json::Value::Array(subjects));
    }
    if !rule.resource_rules.is_empty() {
        let rr: Vec<serde_json::Value> = rule
            .resource_rules
            .into_iter()
            .map(|r| {
                let mut rm = serde_json::Map::new();
                if !r.verbs.is_empty() {
                    rm.insert(
                        "verbs".to_string(),
                        serde_json::Value::Array(
                            r.verbs.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }
                if !r.api_groups.is_empty() {
                    rm.insert(
                        "apiGroups".to_string(),
                        serde_json::Value::Array(
                            r.api_groups
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                if !r.resources.is_empty() {
                    rm.insert(
                        "resources".to_string(),
                        serde_json::Value::Array(
                            r.resources
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                if let Some(true) = r.cluster_scope {
                    rm.insert("clusterScope".to_string(), serde_json::Value::Bool(true));
                }
                if !r.namespaces.is_empty() {
                    rm.insert(
                        "namespaces".to_string(),
                        serde_json::Value::Array(
                            r.namespaces
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                serde_json::Value::Object(rm)
            })
            .collect();
        m.insert("resourceRules".to_string(), serde_json::Value::Array(rr));
    }
    if !rule.non_resource_rules.is_empty() {
        let nrr: Vec<serde_json::Value> = rule
            .non_resource_rules
            .into_iter()
            .map(|r| {
                let mut rm = serde_json::Map::new();
                if !r.verbs.is_empty() {
                    rm.insert(
                        "verbs".to_string(),
                        serde_json::Value::Array(
                            r.verbs.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }
                if !r.non_resource_ur_ls.is_empty() {
                    rm.insert(
                        "nonResourceURLs".to_string(),
                        serde_json::Value::Array(
                            r.non_resource_ur_ls
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                serde_json::Value::Object(rm)
            })
            .collect();
        m.insert(
            "nonResourceRules".to_string(),
            serde_json::Value::Array(nrr),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_flowschema_condition_to_json(c: flowcontrol_v1::FlowSchemaCondition) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = c.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.status.filter(|s| !s.is_empty()) {
        m.insert("status".to_string(), serde_json::Value::String(v));
    }
    if let Some(t) = c.last_transition_time {
        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
            m.insert(
                "lastTransitionTime".to_string(),
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs as u64)),
            );
        }
    }
    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
        m.insert("reason".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
        m.insert("message".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

// ---- Decoder A: PriorityLevelConfiguration ---------------------------------

pub fn decode_prioritylevelconfiguration_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = flowcontrol_v1::PriorityLevelConfiguration::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());

    let mut result = serde_json::json!({
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": meta
    });

    if let Some(spec) = obj.spec {
        let mut spec_map = serde_json::Map::new();
        if let Some(t) = spec.r#type.filter(|s| !s.is_empty()) {
            spec_map.insert("type".to_string(), serde_json::Value::String(t));
        }
        if let Some(limited) = spec.limited {
            let mut lm = serde_json::Map::new();
            if let Some(ncs) = limited.nominal_concurrency_shares.filter(|&v| v != 0) {
                lm.insert(
                    "nominalConcurrencyShares".to_string(),
                    serde_json::Value::Number(ncs.into()),
                );
            }
            if let Some(lp) = limited.lendable_percent.filter(|&v| v != 0) {
                lm.insert(
                    "lendablePercent".to_string(),
                    serde_json::Value::Number(lp.into()),
                );
            }
            if let Some(blp) = limited.borrowing_limit_percent {
                lm.insert(
                    "borrowingLimitPercent".to_string(),
                    serde_json::Value::Number(blp.into()),
                );
            }
            if let Some(lr) = limited.limit_response {
                let mut lrm = serde_json::Map::new();
                if let Some(t) = lr.r#type.filter(|s| !s.is_empty()) {
                    lrm.insert("type".to_string(), serde_json::Value::String(t));
                }
                if let Some(q) = lr.queuing {
                    let mut qm = serde_json::Map::new();
                    if let Some(v) = q.queues.filter(|&v| v != 0) {
                        qm.insert("queues".to_string(), serde_json::Value::Number(v.into()));
                    }
                    if let Some(v) = q.hand_size.filter(|&v| v != 0) {
                        qm.insert("handSize".to_string(), serde_json::Value::Number(v.into()));
                    }
                    if let Some(v) = q.queue_length_limit.filter(|&v| v != 0) {
                        qm.insert(
                            "queueLengthLimit".to_string(),
                            serde_json::Value::Number(v.into()),
                        );
                    }
                    if !qm.is_empty() {
                        lrm.insert("queuing".to_string(), serde_json::Value::Object(qm));
                    }
                }
                if !lrm.is_empty() {
                    lm.insert("limitResponse".to_string(), serde_json::Value::Object(lrm));
                }
            }
            if !lm.is_empty() {
                spec_map.insert("limited".to_string(), serde_json::Value::Object(lm));
            }
        }
        if let Some(exempt) = spec.exempt {
            let mut em = serde_json::Map::new();
            if let Some(ncs) = exempt.nominal_concurrency_shares.filter(|&v| v != 0) {
                em.insert(
                    "nominalConcurrencyShares".to_string(),
                    serde_json::Value::Number(ncs.into()),
                );
            }
            if let Some(lp) = exempt.lendable_percent.filter(|&v| v != 0) {
                em.insert(
                    "lendablePercent".to_string(),
                    serde_json::Value::Number(lp.into()),
                );
            }
            if !em.is_empty() {
                spec_map.insert("exempt".to_string(), serde_json::Value::Object(em));
            }
        }
        if !spec_map.is_empty() {
            result["spec"] = serde_json::Value::Object(spec_map);
        }
    }

    if let Some(status) = obj.status {
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut m = serde_json::Map::new();
                    if let Some(v) = c.r#type.filter(|s| !s.is_empty()) {
                        m.insert("type".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = c.status.filter(|s| !s.is_empty()) {
                        m.insert("status".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            m.insert(
                                "lastTransitionTime".to_string(),
                                serde_json::Value::String(crate::util::secs_to_rfc3339(
                                    secs as u64,
                                )),
                            );
                        }
                    }
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        m.insert("reason".to_string(), serde_json::Value::String(v));
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        m.insert("message".to_string(), serde_json::Value::String(v));
                    }
                    serde_json::Value::Object(m)
                })
                .collect();
            result["status"] = serde_json::json!({ "conditions": conds });
        }
    }

    Some(result)
}
