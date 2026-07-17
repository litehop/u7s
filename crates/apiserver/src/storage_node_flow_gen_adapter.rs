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
                    serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
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
        // nodeAllocatableUpdatePeriodSeconds/serviceAccountTokenInSecrets/
        // preventPodSchedulingIfMissing were silently dropped: without the first, periodic
        // CSINode allocatable-count updates never resume after a capacity-related failure;
        // without the second, service account tokens meant for the Secrets field are still
        // sent via VolumeContext where they risk being logged; without the third, the
        // scheduler stops refusing to place pods on nodes missing this driver.
        if let Some(v) = s.node_allocatable_update_period_seconds.filter(|&v| v != 0) {
            spec.insert(
                "nodeAllocatableUpdatePeriodSeconds".to_string(),
                serde_json::Value::Number(v.into()),
            );
        }
        if let Some(v) = s.service_account_token_in_secrets {
            spec.insert(
                "serviceAccountTokenInSecrets".to_string(),
                serde_json::Value::Bool(v),
            );
        }
        if let Some(v) = s.prevent_pod_scheduling_if_missing {
            spec.insert(
                "preventPodSchedulingIfMissing".to_string(),
                serde_json::Value::Bool(v),
            );
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
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
                    );
                }
            }
            // errorCode is the gRPC status code the CSI driver returned; dropping it hid the
            // machine-readable failure reason behind the free-text message.
            if let Some(v) = err.error_code {
                em.insert("errorCode".to_string(), serde_json::Value::Number(v.into()));
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
                        serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
                    );
                }
            }
            if let Some(v) = err.error_code {
                em.insert("errorCode".to_string(), serde_json::Value::Number(v.into()));
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
    // allowedTopologies restricts which node topologies a volume of this class can be
    // dynamically provisioned to; dropping it silently let the provisioner place volumes
    // anywhere, defeating a topology restriction the user configured.
    if !obj.allowed_topologies.is_empty() {
        let topologies: Vec<serde_json::Value> = obj
            .allowed_topologies
            .into_iter()
            .map(|t| {
                let exprs: Vec<serde_json::Value> = t
                    .match_label_expressions
                    .into_iter()
                    .map(|e| {
                        let mut em = serde_json::Map::new();
                        if let Some(k) = e.key.filter(|s| !s.is_empty()) {
                            em.insert("key".to_string(), serde_json::Value::String(k));
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
                serde_json::json!({ "matchLabelExpressions": exprs })
            })
            .collect();
        result["allowedTopologies"] = serde_json::Value::Array(topologies);
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
                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
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
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs)),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn quantity(
        s: &str,
    ) -> crate::storage_node_flow_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
        crate::storage_node_flow_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {
            string: Some(s.to_string()),
        }
    }

    #[test]
    fn generated_csinode_preserves_driver_topology_and_allocatable_by_construction() {
        let obj = storage_v1::CsiNode {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("node-1".to_string()),
                ..Default::default()
            }),
            spec: Some(storage_v1::CsiNodeSpec {
                drivers: vec![storage_v1::CsiNodeDriver {
                    name: Some("csi.example.com".to_string()),
                    node_id: Some("node-1-id".to_string()),
                    topology_keys: vec!["topology.example.com/zone".to_string()],
                    allocatable: Some(storage_v1::VolumeNodeResources { count: Some(8) }),
                }],
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_csinode_proto_gen(&buf).expect("CSINode must decode");
        assert_eq!(
            result["metadata"]["name"], "node-1",
            "metadata.name must survive — CSINode name must match the node it describes"
        );
        let driver = &result["spec"]["drivers"][0];
        assert_eq!(
            driver["nodeID"], "node-1-id",
            "nodeID must survive — attach/detach controller uses it to address the node in the \
             storage backend's own naming scheme"
        );
        assert_eq!(
            driver["topologyKeys"][0], "topology.example.com/zone",
            "topologyKeys must survive — topology-aware provisioning reads them to place PVs \
             near the pods that will use them"
        );
        assert_eq!(
            driver["allocatable"]["count"], 8,
            "allocatable.count must survive — the scheduler uses it to cap volumes per node"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — CSINode is cluster-scoped; a leaked namespace \
             key would make namespace-scoped watchers believe it belongs to a namespace"
        );
    }

    #[test]
    fn generated_csidriver_preserves_all_spec_fields_by_construction() {
        let obj = storage_v1::CsiDriver {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("csi.example.com".to_string()),
                ..Default::default()
            }),
            spec: Some(storage_v1::CsiDriverSpec {
                attach_required: Some(true),
                pod_info_on_mount: Some(true),
                volume_lifecycle_modes: vec!["Persistent".to_string(), "Ephemeral".to_string()],
                storage_capacity: Some(true),
                fs_group_policy: Some("File".to_string()),
                token_requests: vec![storage_v1::TokenRequest {
                    audience: Some("gcp".to_string()),
                    expiration_seconds: Some(3600),
                }],
                requires_republish: Some(true),
                se_linux_mount: Some(true),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_csidriver_proto_gen(&buf).expect("CSIDriver must decode");
        assert_eq!(
            result["spec"]["attachRequired"], true,
            "attachRequired must survive — a dropped false-to-true flip silently skips the attach \
             step the driver actually requires"
        );
        assert_eq!(
            result["spec"]["podInfoOnMount"], true,
            "podInfoOnMount must survive — kubelet decides whether to pass pod identity into \
             NodePublishVolume based on this"
        );
        assert_eq!(
            result["spec"]["volumeLifecycleModes"][1], "Ephemeral",
            "volumeLifecycleModes must survive — it gates whether inline ephemeral volumes are \
             accepted for this driver"
        );
        assert_eq!(
            result["spec"]["storageCapacity"], true,
            "storageCapacity must survive — the scheduler only consults CSIStorageCapacity when \
             this is true"
        );
        assert_eq!(
            result["spec"]["fsGroupPolicy"], "File",
            "fsGroupPolicy must survive — it controls whether kubelet chowns/chmods the volume"
        );
        assert_eq!(
            result["spec"]["tokenRequests"][0]["audience"], "gcp",
            "tokenRequests must survive — a dropped audience breaks driver-requested service \
             account token exchange"
        );
        assert_eq!(
            result["spec"]["tokenRequests"][0]["expirationSeconds"], 3600,
            "tokenRequests[].expirationSeconds must survive — it bounds token lifetime"
        );
        assert_eq!(
            result["spec"]["requiresRepublish"], true,
            "requiresRepublish must survive — dropping it stops kubelet from periodically \
             refreshing the mount for drivers that need it"
        );
        assert_eq!(
            result["spec"]["seLinuxMount"], true,
            "seLinuxMount must survive — it decides whether kubelet passes -o context to the driver"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — CSIDriver is cluster-scoped, so a leaked \
             namespace key would misrepresent its scope to clients"
        );
    }

    #[test]
    fn generated_csistoragecapacity_preserves_topology_and_quantities_by_construction() {
        let obj = storage_v1::CsiStorageCapacity {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("cap-1".to_string()),
                namespace: Some("kube-system".to_string()),
                ..Default::default()
            }),
            node_topology: Some(meta_v1::LabelSelector {
                match_labels: [(
                    "topology.example.com/zone".to_string(),
                    "us-east1".to_string(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            }),
            storage_class_name: Some("standard".to_string()),
            capacity: Some(quantity("100Gi")),
            maximum_volume_size: Some(quantity("50Gi")),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result =
            decode_csistoragecapacity_proto_gen(&buf).expect("CSIStorageCapacity must decode");
        assert_eq!(
            result["storageClassName"], "standard",
            "storageClassName must survive — it ties this capacity report to a specific \
             StorageClass the scheduler compares against"
        );
        assert_eq!(
            result["nodeTopology"]["matchLabels"]["topology.example.com/zone"], "us-east1",
            "nodeTopology must survive — dropping it makes the scheduler treat the capacity as \
             available on the wrong nodes"
        );
        assert_eq!(
            result["capacity"], "100Gi",
            "capacity must survive — the scheduler falls back to it when maximumVolumeSize is unset"
        );
        assert_eq!(
            result["maximumVolumeSize"], "50Gi",
            "maximumVolumeSize must survive — it is the primary value the scheduler filters \
             candidate nodes against"
        );
        assert!(
            result["nodeTopology"]["matchExpressions"].is_null(),
            "nodeTopology.matchExpressions must stay absent when unset — a spuriously emitted \
             empty array would look like an always-false selector instead of no selector at all"
        );
    }

    #[test]
    fn generated_volumeattachment_preserves_spec_and_status_by_construction() {
        let obj = storage_v1::VolumeAttachment {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("va-1".to_string()),
                ..Default::default()
            }),
            spec: Some(storage_v1::VolumeAttachmentSpec {
                attacher: Some("csi.example.com".to_string()),
                node_name: Some("node-1".to_string()),
                source: Some(storage_v1::VolumeAttachmentSource {
                    persistent_volume_name: Some("pv-1".to_string()),
                    ..Default::default()
                }),
            }),
            status: Some(storage_v1::VolumeAttachmentStatus {
                attached: Some(true),
                attachment_metadata: [("device".to_string(), "/dev/sdb".to_string())]
                    .into_iter()
                    .collect(),
                attach_error: Some(storage_v1::VolumeError {
                    message: Some("timed out".to_string()),
                    time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_000),
                        nanos: Some(0),
                    }),
                    ..Default::default()
                }),
                detach_error: Some(storage_v1::VolumeError {
                    message: Some("device busy".to_string()),
                    time: Some(meta_v1::Time {
                        seconds: Some(1_700_000_100),
                        nanos: Some(0),
                    }),
                    ..Default::default()
                }),
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_volumeattachment_proto_gen(&buf).expect("VolumeAttachment must decode");
        assert_eq!(
            result["spec"]["attacher"], "csi.example.com",
            "spec.attacher must survive — it names which driver MUST handle this attach/detach"
        );
        assert_eq!(
            result["spec"]["source"]["persistentVolumeName"], "pv-1",
            "spec.source.persistentVolumeName must survive — dropping it leaves the \
             external-attacher with nothing to attach"
        );
        assert_eq!(
            result["status"]["attached"], true,
            "status.attached must survive — the attach/detach controller and kubelet's mount \
             wait on this flag"
        );
        assert_eq!(
            result["status"]["attachmentMetadata"]["device"], "/dev/sdb",
            "attachmentMetadata must survive — kubelet needs it for the subsequent mount call"
        );
        assert_eq!(
            result["status"]["attachError"]["message"], "timed out",
            "attachError must survive — losing it hides a failed attach from the controller \
             and from kubectl describe"
        );
        assert_eq!(
            result["status"]["detachError"]["message"], "device busy",
            "detachError must survive — losing it hides a failed detach that blocks pod deletion"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — VolumeAttachment is cluster-scoped"
        );
    }

    #[test]
    fn generated_storageclass_preserves_provisioner_and_binding_fields_by_construction() {
        let obj = storage_v1::StorageClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("standard".to_string()),
                ..Default::default()
            }),
            provisioner: Some("csi.example.com".to_string()),
            parameters: [("type".to_string(), "gp3".to_string())]
                .into_iter()
                .collect(),
            reclaim_policy: Some("Retain".to_string()),
            mount_options: vec!["noatime".to_string()],
            allow_volume_expansion: Some(true),
            volume_binding_mode: Some("WaitForFirstConsumer".to_string()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_storageclass_proto_gen(&buf).expect("StorageClass must decode");
        assert_eq!(
            result["provisioner"], "csi.example.com",
            "provisioner must survive — it selects which CSI driver services PVCs of this class"
        );
        assert_eq!(
            result["parameters"]["type"], "gp3",
            "parameters must survive — they are opaque driver config passed straight through \
             to CreateVolume"
        );
        assert_eq!(
            result["reclaimPolicy"], "Retain",
            "reclaimPolicy must survive — Retain vs Delete decides whether data is destroyed \
             when a PVC is removed"
        );
        assert_eq!(
            result["mountOptions"][0], "noatime",
            "mountOptions must survive — they are passed to the actual mount(8) call"
        );
        assert_eq!(
            result["allowVolumeExpansion"], true,
            "allowVolumeExpansion must survive — dropping it silently blocks online PVC resize"
        );
        assert_eq!(
            result["volumeBindingMode"], "WaitForFirstConsumer",
            "volumeBindingMode must survive — Immediate vs WaitForFirstConsumer changes when \
             the scheduler and provisioner interact"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — StorageClass is cluster-scoped"
        );
    }

    #[test]
    fn generated_volumeattributesclass_preserves_driver_and_parameters_by_construction() {
        let obj = storage_v1::VolumeAttributesClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("silver".to_string()),
                ..Default::default()
            }),
            driver_name: Some("csi.example.com".to_string()),
            parameters: [("iops".to_string(), "3000".to_string())]
                .into_iter()
                .collect(),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_volumeattributesclass_proto_gen(&buf)
            .expect("VolumeAttributesClass must decode");
        assert_eq!(
            result["driverName"], "csi.example.com",
            "driverName must survive — it is immutable and identifies which CSI driver applies \
             these attributes"
        );
        assert_eq!(
            result["parameters"]["iops"], "3000",
            "parameters must survive — this is the only content of a mutable-attributes request; \
             dropping it makes ModifyVolume a no-op"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — VolumeAttributesClass is cluster-scoped"
        );
    }

    #[test]
    fn generated_runtimeclass_preserves_overhead_and_scheduling_by_construction() {
        let obj = node_v1::RuntimeClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gvisor".to_string()),
                ..Default::default()
            }),
            handler: Some("runsc".to_string()),
            overhead: Some(node_v1::Overhead {
                pod_fixed: [("memory".to_string(), quantity("128Mi"))]
                    .into_iter()
                    .collect(),
            }),
            scheduling: Some(node_v1::Scheduling {
                node_selector: [("runtime".to_string(), "gvisor".to_string())]
                    .into_iter()
                    .collect(),
                tolerations: vec![
                    crate::storage_node_flow_gen::k8s::io::api::core::v1::Toleration {
                        key: Some("sandbox".to_string()),
                        operator: Some("Exists".to_string()),
                        effect: Some("NoSchedule".to_string()),
                        ..Default::default()
                    },
                ],
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_runtimeclass_proto_gen(&buf).expect("RuntimeClass must decode");
        assert_eq!(
            result["handler"], "runsc",
            "handler must survive — it is required and selects the CRI shim the kubelet invokes"
        );
        assert_eq!(
            result["overhead"]["podFixed"]["memory"], "128Mi",
            "overhead.podFixed must survive — dropping it under-reports node capacity used by \
             pods of this RuntimeClass, over-committing the node"
        );
        assert_eq!(
            result["scheduling"]["nodeSelector"]["runtime"], "gvisor",
            "scheduling.nodeSelector must survive — it is merged into the pod's nodeSelector \
             to keep pods off nodes lacking this runtime"
        );
        assert_eq!(
            result["scheduling"]["tolerations"][0]["key"], "sandbox",
            "scheduling.tolerations must survive — they are unioned into the pod's tolerations \
             at admission"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — RuntimeClass is cluster-scoped"
        );
    }

    #[test]
    fn generated_priorityclass_preserves_value_and_preemption_policy_by_construction() {
        let obj = scheduling_v1::PriorityClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("high".to_string()),
                ..Default::default()
            }),
            value: Some(1_000_000),
            global_default: Some(true),
            description: Some("critical workloads".to_string()),
            preemption_policy: Some("Never".to_string()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_priorityclass_proto_gen(&buf).expect("PriorityClass must decode");
        assert_eq!(
            result["value"], 1_000_000,
            "value must survive — the scheduler compares this integer directly to rank \
             preemption candidates"
        );
        assert_eq!(
            result["globalDefault"], true,
            "globalDefault must survive — losing it silently strips priority from every pod \
             that doesn't name a class explicitly"
        );
        assert_eq!(
            result["preemptionPolicy"], "Never",
            "preemptionPolicy must survive — Never vs PreemptLowerPriority changes whether this \
             class can evict other pods to schedule"
        );
        assert!(
            result["metadata"]["namespace"].is_null(),
            "metadata.namespace must stay absent — PriorityClass is cluster-scoped"
        );
    }

    #[test]
    fn generated_flowschema_preserves_rules_subjects_and_status_by_construction() {
        let obj = flowcontrol_v1::FlowSchema {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("workload-low".to_string()),
                ..Default::default()
            }),
            spec: Some(flowcontrol_v1::FlowSchemaSpec {
                matching_precedence: Some(500),
                priority_level_configuration: Some(
                    flowcontrol_v1::PriorityLevelConfigurationReference {
                        name: Some("workload-low".to_string()),
                    },
                ),
                distinguisher_method: Some(flowcontrol_v1::FlowDistinguisherMethod {
                    r#type: Some("ByUser".to_string()),
                }),
                rules: vec![flowcontrol_v1::PolicyRulesWithSubjects {
                    subjects: vec![
                        flowcontrol_v1::Subject {
                            kind: Some("ServiceAccount".to_string()),
                            service_account: Some(flowcontrol_v1::ServiceAccountSubject {
                                namespace: Some("kube-system".to_string()),
                                name: Some("controller".to_string()),
                            }),
                            ..Default::default()
                        },
                        flowcontrol_v1::Subject {
                            kind: Some("Group".to_string()),
                            group: Some(flowcontrol_v1::GroupSubject {
                                name: Some("system:authenticated".to_string()),
                            }),
                            ..Default::default()
                        },
                    ],
                    resource_rules: vec![flowcontrol_v1::ResourcePolicyRule {
                        verbs: vec!["get".to_string(), "list".to_string()],
                        api_groups: vec!["".to_string()],
                        resources: vec!["pods".to_string()],
                        cluster_scope: Some(true),
                        namespaces: vec!["*".to_string()],
                    }],
                    non_resource_rules: vec![flowcontrol_v1::NonResourcePolicyRule {
                        verbs: vec!["get".to_string()],
                        non_resource_ur_ls: vec!["/healthz".to_string()],
                    }],
                }],
            }),
            status: Some(flowcontrol_v1::FlowSchemaStatus {
                conditions: vec![flowcontrol_v1::FlowSchemaCondition {
                    r#type: Some("Dangling".to_string()),
                    status: Some("False".to_string()),
                    reason: Some("Found".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_flowschema_proto_gen(&buf).expect("FlowSchema must decode");
        assert_eq!(
            result["spec"]["matchingPrecedence"], 500,
            "matchingPrecedence must survive — it decides which FlowSchema wins when several match"
        );
        assert_eq!(
            result["spec"]["priorityLevelConfiguration"]["name"], "workload-low",
            "priorityLevelConfiguration reference must survive — a dropped reference makes the \
             FlowSchema invalid and it gets ignored"
        );
        assert_eq!(
            result["spec"]["distinguisherMethod"]["type"], "ByUser",
            "distinguisherMethod must survive — dropping it silently disables per-user \
             shuffle-sharding for this schema"
        );
        let rule = &result["spec"]["rules"][0];
        assert_eq!(
            rule["subjects"][0]["serviceAccount"]["name"], "controller",
            "subjects[].serviceAccount must survive — it is who this rule actually matches"
        );
        assert_eq!(
            rule["subjects"][1]["group"]["name"], "system:authenticated",
            "subjects[].group must survive — dropping it would match zero or the wrong requesters"
        );
        assert!(
            rule["subjects"][0]["group"].is_null(),
            "subjects[0].group must stay absent — this subject is a ServiceAccount kind; \
             emitting an empty group would make it match by group as well as by identity"
        );
        assert!(
            rule["subjects"][1]["serviceAccount"].is_null(),
            "subjects[1].serviceAccount must stay absent — this subject is a Group kind; \
             a spuriously emitted serviceAccount would widen who the rule matches"
        );
        assert_eq!(
            rule["resourceRules"][0]["resources"][0], "pods",
            "resourceRules must survive — this is the actual request-matching predicate"
        );
        assert_eq!(
            rule["resourceRules"][0]["clusterScope"], true,
            "clusterScope must survive — flips which requests without a namespace match"
        );
        assert_eq!(
            rule["nonResourceRules"][0]["nonResourceURLs"][0], "/healthz",
            "nonResourceRules must survive — health/metrics endpoint matching depends on it"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Dangling",
            "status.conditions must survive — it is how APF reports a FlowSchema referencing a \
             missing PriorityLevelConfiguration"
        );
    }

    #[test]
    fn generated_prioritylevelconfiguration_preserves_limited_and_exempt_by_construction() {
        let obj = flowcontrol_v1::PriorityLevelConfiguration {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("workload-low".to_string()),
                ..Default::default()
            }),
            spec: Some(flowcontrol_v1::PriorityLevelConfigurationSpec {
                r#type: Some("Limited".to_string()),
                limited: Some(flowcontrol_v1::LimitedPriorityLevelConfiguration {
                    nominal_concurrency_shares: Some(30),
                    lendable_percent: Some(50),
                    borrowing_limit_percent: Some(10),
                    limit_response: Some(flowcontrol_v1::LimitResponse {
                        r#type: Some("Queue".to_string()),
                        queuing: Some(flowcontrol_v1::QueuingConfiguration {
                            queues: Some(64),
                            hand_size: Some(6),
                            queue_length_limit: Some(50),
                        }),
                    }),
                }),
                exempt: None,
            }),
            status: Some(flowcontrol_v1::PriorityLevelConfigurationStatus {
                conditions: vec![flowcontrol_v1::PriorityLevelConfigurationCondition {
                    r#type: Some("Concurrency".to_string()),
                    status: Some("True".to_string()),
                    ..Default::default()
                }],
            }),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();

        let result = decode_prioritylevelconfiguration_proto_gen(&buf)
            .expect("PriorityLevelConfiguration must decode");
        assert_eq!(
            result["spec"]["type"], "Limited",
            "spec.type must survive — it is the union discriminator; losing it makes the \
             concurrency-limiting fields ambiguous"
        );
        assert_eq!(
            result["spec"]["limited"]["nominalConcurrencyShares"], 30,
            "nominalConcurrencyShares must survive — it directly sets this level's slice of \
             server concurrency"
        );
        assert_eq!(
            result["spec"]["limited"]["borrowingLimitPercent"], 10,
            "borrowingLimitPercent must survive — dropping it silently makes borrowing unbounded"
        );
        assert_eq!(
            result["spec"]["limited"]["limitResponse"]["queuing"]["handSize"], 6,
            "limitResponse.queuing.handSize must survive — it controls shuffle-sharding fairness \
             across requests queued at this level"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Concurrency",
            "status.conditions must survive — this is how APF reports concurrency-limit health \
             for the level"
        );
        assert!(
            result["spec"]["exempt"].is_null(),
            "spec.exempt must stay absent when type is Limited — spuriously emitting it would \
             suggest this level ignores concurrency limits when it does not"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how CsiDriverSpec's
    // nodeAllocatableUpdatePeriodSeconds/serviceAccountTokenInSecrets/
    // preventPodSchedulingIfMissing, StorageClass.allowedTopologies, and VolumeError.errorCode
    // (used by both attachError and detachError) were found missing from this file.
    //
    // VolumeAttachmentSource.inlineVolumeSpec (a full core/v1 PersistentVolumeSpec, used only by
    // the legacy CSIMigration in-tree-plugin-translation path) is deliberately left unhandled
    // and excluded from `expected` below: implementing it would mean duplicating a large
    // fraction of PersistentVolumeSpec's own JSON translation for a feature u7s has no in-tree
    // volume plugins to migrate from. Flagged here rather than guessed at.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them (this file's copy has the same omissions as every other gen_adapter's); do not
    // guess at the fix here.
    const OBJECT_META_EXPECTED: &[&str] = &[
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
    ];

    const LABEL_SELECTOR_EXPECTED: &[&str] = &[
        "matchLabels",
        "matchExpressions",
        "key",
        "operator",
        "values",
    ];

    #[test]
    fn sentinel_completeness_decode_csinode_proto_gen() {
        let obj = storage_v1::CsiNode {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(storage_v1::CsiNodeSpec::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_csinode_proto_gen(&buf)
            .expect("sentinel CSINode must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "spec",
            "drivers",
            "nodeID",
            "topologyKeys",
            "allocatable",
            "count",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_csidriver_proto_gen() {
        let obj = storage_v1::CsiDriver {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(storage_v1::CsiDriverSpec::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_csidriver_proto_gen(&buf)
            .expect("sentinel CSIDriver must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "spec",
            "attachRequired",
            "podInfoOnMount",
            "volumeLifecycleModes",
            "storageCapacity",
            "fsGroupPolicy",
            "tokenRequests",
            "audience",
            "expirationSeconds",
            "requiresRepublish",
            "seLinuxMount",
            "nodeAllocatableUpdatePeriodSeconds",
            "serviceAccountTokenInSecrets",
            "preventPodSchedulingIfMissing",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_csistoragecapacity_proto_gen() {
        let obj = storage_v1::CsiStorageCapacity {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            node_topology: Some(meta_v1::LabelSelector::sentinel()),
            storage_class_name: Some("standard".to_string()),
            capacity: Some(quantity("100Gi")),
            maximum_volume_size: Some(quantity("50Gi")),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_csistoragecapacity_proto_gen(&buf)
            .expect("sentinel CSIStorageCapacity must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(LABEL_SELECTOR_EXPECTED);
        expected.extend([
            "storageClassName",
            "nodeTopology",
            "capacity",
            "maximumVolumeSize",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_volumeattachment_proto_gen() {
        let obj = storage_v1::VolumeAttachment {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(storage_v1::VolumeAttachmentSpec {
                source: Some(storage_v1::VolumeAttachmentSource {
                    persistent_volume_name: Some("pv-1".to_string()),
                    inline_volume_spec: None,
                }),
                ..storage_v1::VolumeAttachmentSpec::sentinel()
            }),
            status: Some(storage_v1::VolumeAttachmentStatus::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_volumeattachment_proto_gen(&buf)
            .expect("sentinel VolumeAttachment must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "spec",
            "attacher",
            "nodeName",
            "source",
            "persistentVolumeName",
            // inlineVolumeSpec deliberately excluded — see the module-level note above.
            "status",
            "attached",
            "attachmentMetadata",
            "attachError",
            "message",
            "time",
            "errorCode",
            "detachError",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_storageclass_proto_gen() {
        let obj = storage_v1::StorageClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            provisioner: Some("csi.example.com".to_string()),
            parameters: [("type".to_string(), "gp3".to_string())].into_iter().collect(),
            reclaim_policy: Some("Retain".to_string()),
            mount_options: vec!["noatime".to_string()],
            allow_volume_expansion: Some(true),
            volume_binding_mode: Some("WaitForFirstConsumer".to_string()),
            allowed_topologies: vec![
                crate::storage_node_flow_gen::k8s::io::api::core::v1::TopologySelectorTerm::sentinel(
                ),
            ],
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_storageclass_proto_gen(&buf)
            .expect("sentinel StorageClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "provisioner",
            "parameters",
            "reclaimPolicy",
            "mountOptions",
            "allowVolumeExpansion",
            "volumeBindingMode",
            "allowedTopologies",
            "matchLabelExpressions",
            "key",
            "values",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_volumeattributesclass_proto_gen() {
        let obj = storage_v1::VolumeAttributesClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            driver_name: Some("csi.example.com".to_string()),
            parameters: [("iops".to_string(), "3000".to_string())]
                .into_iter()
                .collect(),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_volumeattributesclass_proto_gen(&buf)
            .expect("sentinel VolumeAttributesClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(["driverName", "parameters"]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_runtimeclass_proto_gen() {
        let obj = node_v1::RuntimeClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            handler: Some("runsc".to_string()),
            overhead: Some(node_v1::Overhead::sentinel()),
            scheduling: Some(node_v1::Scheduling::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_runtimeclass_proto_gen(&buf)
            .expect("sentinel RuntimeClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "handler",
            "overhead",
            "podFixed",
            "scheduling",
            "nodeSelector",
            "tolerations",
            "key",
            "operator",
            "value",
            "effect",
            "tolerationSeconds",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_priorityclass_proto_gen() {
        let obj = scheduling_v1::PriorityClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            value: Some(1_000_000),
            global_default: Some(true),
            description: Some("critical workloads".to_string()),
            preemption_policy: Some("Never".to_string()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_priorityclass_proto_gen(&buf)
            .expect("sentinel PriorityClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend(["value", "globalDefault", "description", "preemptionPolicy"]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_flowschema_proto_gen() {
        let obj = flowcontrol_v1::FlowSchema {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(flowcontrol_v1::FlowSchemaSpec::sentinel()),
            status: Some(flowcontrol_v1::FlowSchemaStatus::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_flowschema_proto_gen(&buf)
            .expect("sentinel FlowSchema must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "spec",
            "matchingPrecedence",
            "priorityLevelConfiguration",
            "distinguisherMethod",
            "type",
            "rules",
            "subjects",
            // Subject.kind deliberately excluded — masked by the envelope's own top-level
            // "kind": "FlowSchema" literal.
            "user",
            "group",
            "serviceAccount",
            "resourceRules",
            "verbs",
            "apiGroups",
            "resources",
            "clusterScope",
            "namespaces",
            "nonResourceRules",
            "nonResourceURLs",
            "status",
            "conditions",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_prioritylevelconfiguration_proto_gen() {
        let obj = flowcontrol_v1::PriorityLevelConfiguration {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(flowcontrol_v1::PriorityLevelConfigurationSpec::sentinel()),
            status: Some(flowcontrol_v1::PriorityLevelConfigurationStatus::sentinel()),
        };
        let mut buf = Vec::new();
        obj.encode(&mut buf).unwrap();
        let result = decode_prioritylevelconfiguration_proto_gen(&buf)
            .expect("sentinel PriorityLevelConfiguration must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&result, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "spec",
            "type",
            "limited",
            "nominalConcurrencyShares",
            "lendablePercent",
            "borrowingLimitPercent",
            "limitResponse",
            "queuing",
            "queues",
            "handSize",
            "queueLengthLimit",
            "exempt",
            "status",
            "conditions",
            "reason",
            "message",
            "lastTransitionTime",
        ]);
        assert_fields_present(&paths, &expected);
    }
}
