use prost::Message;

use u7s_proto_generated::k8s::io::api::core::v1 as core_v1;
use u7s_proto_generated::k8s::io::api::resource::v1 as resource_v1;
use u7s_proto_generated::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

fn gen_object_meta_to_json(meta: meta_v1::ObjectMeta) -> serde_json::Value {
    crate::core_gen_adapter::gen_object_meta_to_json(meta)
}

fn gen_quantity_to_json(
    q: Option<u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity>,
) -> Option<serde_json::Value> {
    q.and_then(|q| q.string)
        .filter(|s| !s.is_empty())
        .map(serde_json::Value::String)
}

fn gen_quantity_map_to_json(
    map: std::collections::HashMap<
        String,
        u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity,
    >,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        if let Some(s) = v.string.filter(|s| !s.is_empty()) {
            out.insert(k, serde_json::Value::String(s));
        }
    }
    serde_json::Value::Object(out)
}

fn gen_raw_extension_to_json(
    ext: Option<u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension>,
) -> Option<serde_json::Value> {
    let raw = ext?.raw?;
    if raw.is_empty() {
        return None;
    }
    serde_json::from_slice::<serde_json::Value>(&raw).ok()
}

fn gen_meta_condition_to_json(c: meta_v1::Condition) -> serde_json::Value {
    let mut m = serde_json::json!({
        "type": c.r#type.unwrap_or_default(),
        "status": c.status.unwrap_or_default(),
    });
    if let Some(v) = c.observed_generation {
        m["observedGeneration"] = v.into();
    }
    if let Some(t) = c.last_transition_time {
        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
            m["lastTransitionTime"] = crate::util::secs_to_rfc3339(secs).into();
        }
    }
    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
        m["reason"] = v.into();
    }
    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
        m["message"] = v.into();
    }
    m
}

fn gen_node_selector_requirement_to_json(
    req: core_v1::NodeSelectorRequirement,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = req.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), v.into());
    }
    if let Some(v) = req.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), v.into());
    }
    if !req.values.is_empty() {
        m.insert(
            "values".to_string(),
            req.values
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_node_selector_term_to_json(term: core_v1::NodeSelectorTerm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !term.match_expressions.is_empty() {
        m.insert(
            "matchExpressions".to_string(),
            term.match_expressions
                .into_iter()
                .map(gen_node_selector_requirement_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !term.match_fields.is_empty() {
        m.insert(
            "matchFields".to_string(),
            term.match_fields
                .into_iter()
                .map(gen_node_selector_requirement_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_node_selector_to_json(ns: core_v1::NodeSelector) -> serde_json::Value {
    serde_json::json!({
        "nodeSelectorTerms": ns
            .node_selector_terms
            .into_iter()
            .map(gen_node_selector_term_to_json)
            .collect::<Vec<_>>(),
    })
}

// ---- Device building blocks -------------------------------------------------

fn gen_device_taint_to_json(t: resource_v1::DeviceTaint) -> serde_json::Value {
    let mut m = serde_json::json!({
        "key": t.key.unwrap_or_default(),
        "effect": t.effect.unwrap_or_default(),
    });
    if let Some(v) = t.value.filter(|s| !s.is_empty()) {
        m["value"] = v.into();
    }
    if let Some(ta) = t.time_added {
        if let Some(secs) = ta.seconds.filter(|&s| s > 0) {
            m["timeAdded"] = crate::util::secs_to_rfc3339(secs).into();
        }
    }
    m
}

fn gen_device_toleration_to_json(t: resource_v1::DeviceToleration) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = t.key.filter(|s| !s.is_empty()) {
        m.insert("key".to_string(), v.into());
    }
    if let Some(v) = t.operator.filter(|s| !s.is_empty()) {
        m.insert("operator".to_string(), v.into());
    }
    if let Some(v) = t.value.filter(|s| !s.is_empty()) {
        m.insert("value".to_string(), v.into());
    }
    if let Some(v) = t.effect.filter(|s| !s.is_empty()) {
        m.insert("effect".to_string(), v.into());
    }
    if let Some(v) = t.toleration_seconds {
        m.insert("tolerationSeconds".to_string(), v.into());
    }
    serde_json::Value::Object(m)
}

fn gen_capacity_request_policy_range_to_json(
    r: resource_v1::CapacityRequestPolicyRange,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = gen_quantity_to_json(r.min) {
        m.insert("min".to_string(), v);
    }
    if let Some(v) = gen_quantity_to_json(r.max) {
        m.insert("max".to_string(), v);
    }
    if let Some(v) = gen_quantity_to_json(r.step) {
        m.insert("step".to_string(), v);
    }
    serde_json::Value::Object(m)
}

fn gen_capacity_request_policy_to_json(p: resource_v1::CapacityRequestPolicy) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = gen_quantity_to_json(p.default) {
        m.insert("default".to_string(), v);
    }
    if !p.valid_values.is_empty() {
        m.insert(
            "validValues".to_string(),
            p.valid_values
                .into_iter()
                .filter_map(|q| gen_quantity_to_json(Some(q)))
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(vr) = p.valid_range {
        m.insert(
            "validRange".to_string(),
            gen_capacity_request_policy_range_to_json(vr),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_capacity_to_json(c: resource_v1::DeviceCapacity) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = gen_quantity_to_json(c.value) {
        m.insert("value".to_string(), v);
    }
    if let Some(rp) = c.request_policy {
        m.insert(
            "requestPolicy".to_string(),
            gen_capacity_request_policy_to_json(rp),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_attribute_to_json(attr: resource_v1::DeviceAttribute) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = attr.int {
        m.insert("int".to_string(), v.into());
    }
    if let Some(v) = attr.bool {
        m.insert("bool".to_string(), v.into());
    }
    if let Some(v) = attr.string.filter(|s| !s.is_empty()) {
        m.insert("string".to_string(), v.into());
    }
    if let Some(v) = attr.version.filter(|s| !s.is_empty()) {
        m.insert("version".to_string(), v.into());
    }
    if !attr.ints.is_empty() {
        m.insert(
            "ints".to_string(),
            attr.ints
                .into_iter()
                .map(serde_json::Value::from)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !attr.bools.is_empty() {
        m.insert(
            "bools".to_string(),
            attr.bools
                .into_iter()
                .map(serde_json::Value::from)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !attr.strings.is_empty() {
        m.insert(
            "strings".to_string(),
            attr.strings
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !attr.versions.is_empty() {
        m.insert(
            "versions".to_string(),
            attr.versions
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_counter_to_json(c: resource_v1::Counter) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = gen_quantity_to_json(c.value) {
        m.insert("value".to_string(), v);
    }
    serde_json::Value::Object(m)
}

fn gen_counter_map_to_json(
    map: std::collections::HashMap<String, resource_v1::Counter>,
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (k, v) in map {
        out.insert(k, gen_counter_to_json(v));
    }
    serde_json::Value::Object(out)
}

fn gen_counter_set_to_json(cs: resource_v1::CounterSet) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = cs.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), v.into());
    }
    if !cs.counters.is_empty() {
        m.insert("counters".to_string(), gen_counter_map_to_json(cs.counters));
    }
    serde_json::Value::Object(m)
}

fn gen_device_counter_consumption_to_json(
    d: resource_v1::DeviceCounterConsumption,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = d.counter_set.filter(|s| !s.is_empty()) {
        m.insert("counterSet".to_string(), v.into());
    }
    if !d.counters.is_empty() {
        m.insert("counters".to_string(), gen_counter_map_to_json(d.counters));
    }
    serde_json::Value::Object(m)
}

fn gen_node_allocatable_resource_mapping_to_json(
    n: resource_v1::NodeAllocatableResourceMapping,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = n.capacity_key.filter(|s| !s.is_empty()) {
        m.insert("capacityKey".to_string(), v.into());
    }
    if let Some(v) = gen_quantity_to_json(n.allocation_multiplier) {
        m.insert("allocationMultiplier".to_string(), v);
    }
    serde_json::Value::Object(m)
}

fn gen_device_to_json(d: resource_v1::Device) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = d.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), v.into());
    }
    if !d.attributes.is_empty() {
        let attrs: serde_json::Map<String, serde_json::Value> = d
            .attributes
            .into_iter()
            .map(|(k, v)| (k, gen_device_attribute_to_json(v)))
            .collect();
        m.insert("attributes".to_string(), serde_json::Value::Object(attrs));
    }
    if !d.capacity.is_empty() {
        let cap: serde_json::Map<String, serde_json::Value> = d
            .capacity
            .into_iter()
            .map(|(k, v)| (k, gen_device_capacity_to_json(v)))
            .collect();
        m.insert("capacity".to_string(), serde_json::Value::Object(cap));
    }
    if !d.consumes_counters.is_empty() {
        m.insert(
            "consumesCounters".to_string(),
            d.consumes_counters
                .into_iter()
                .map(gen_device_counter_consumption_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(v) = d.node_name.filter(|s| !s.is_empty()) {
        m.insert("nodeName".to_string(), v.into());
    }
    if let Some(ns) = d.node_selector {
        m.insert("nodeSelector".to_string(), gen_node_selector_to_json(ns));
    }
    if let Some(true) = d.all_nodes {
        m.insert("allNodes".to_string(), true.into());
    }
    if !d.taints.is_empty() {
        m.insert(
            "taints".to_string(),
            d.taints
                .into_iter()
                .map(gen_device_taint_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(true) = d.binds_to_node {
        m.insert("bindsToNode".to_string(), true.into());
    }
    if !d.binding_conditions.is_empty() {
        m.insert(
            "bindingConditions".to_string(),
            d.binding_conditions
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !d.binding_failure_conditions.is_empty() {
        m.insert(
            "bindingFailureConditions".to_string(),
            d.binding_failure_conditions
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(true) = d.allow_multiple_allocations {
        m.insert("allowMultipleAllocations".to_string(), true.into());
    }
    if !d.node_allocatable_resource_mappings.is_empty() {
        let nam: serde_json::Map<String, serde_json::Value> = d
            .node_allocatable_resource_mappings
            .into_iter()
            .map(|(k, v)| (k, gen_node_allocatable_resource_mapping_to_json(v)))
            .collect();
        m.insert(
            "nodeAllocatableResourceMappings".to_string(),
            serde_json::Value::Object(nam),
        );
    }
    serde_json::Value::Object(m)
}

// ---- Claim building blocks ---------------------------------------------------

fn gen_device_selector_to_json(sel: resource_v1::DeviceSelector) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(cel) = sel.cel {
        if let Some(v) = cel.expression.filter(|s| !s.is_empty()) {
            m.insert("cel".to_string(), serde_json::json!({ "expression": v }));
        }
    }
    serde_json::Value::Object(m)
}

fn gen_device_configuration_to_json(c: resource_v1::DeviceConfiguration) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(o) = c.opaque {
        let mut om = serde_json::Map::new();
        if let Some(v) = o.driver.filter(|s| !s.is_empty()) {
            om.insert("driver".to_string(), v.into());
        }
        if let Some(v) = gen_raw_extension_to_json(o.parameters) {
            om.insert("parameters".to_string(), v);
        }
        m.insert("opaque".to_string(), serde_json::Value::Object(om));
    }
    serde_json::Value::Object(m)
}

fn gen_capacity_requirements_to_json(c: resource_v1::CapacityRequirements) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !c.requests.is_empty() {
        m.insert("requests".to_string(), gen_quantity_map_to_json(c.requests));
    }
    serde_json::Value::Object(m)
}

fn gen_exact_device_request_to_json(r: resource_v1::ExactDeviceRequest) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.device_class_name.filter(|s| !s.is_empty()) {
        m.insert("deviceClassName".to_string(), v.into());
    }
    if !r.selectors.is_empty() {
        m.insert(
            "selectors".to_string(),
            r.selectors
                .into_iter()
                .map(gen_device_selector_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(v) = r.allocation_mode.filter(|s| !s.is_empty()) {
        m.insert("allocationMode".to_string(), v.into());
    }
    if let Some(v) = r.count {
        m.insert("count".to_string(), v.into());
    }
    if let Some(true) = r.admin_access {
        m.insert("adminAccess".to_string(), true.into());
    }
    if !r.tolerations.is_empty() {
        m.insert(
            "tolerations".to_string(),
            r.tolerations
                .into_iter()
                .map(gen_device_toleration_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(cap) = r.capacity {
        m.insert(
            "capacity".to_string(),
            gen_capacity_requirements_to_json(cap),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_sub_request_to_json(r: resource_v1::DeviceSubRequest) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), v.into());
    }
    if let Some(v) = r.device_class_name.filter(|s| !s.is_empty()) {
        m.insert("deviceClassName".to_string(), v.into());
    }
    if !r.selectors.is_empty() {
        m.insert(
            "selectors".to_string(),
            r.selectors
                .into_iter()
                .map(gen_device_selector_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(v) = r.allocation_mode.filter(|s| !s.is_empty()) {
        m.insert("allocationMode".to_string(), v.into());
    }
    if let Some(v) = r.count {
        m.insert("count".to_string(), v.into());
    }
    if !r.tolerations.is_empty() {
        m.insert(
            "tolerations".to_string(),
            r.tolerations
                .into_iter()
                .map(gen_device_toleration_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(cap) = r.capacity {
        m.insert(
            "capacity".to_string(),
            gen_capacity_requirements_to_json(cap),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_request_to_json(r: resource_v1::DeviceRequest) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = r.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), v.into());
    }
    if let Some(e) = r.exactly {
        m.insert("exactly".to_string(), gen_exact_device_request_to_json(e));
    }
    if !r.first_available.is_empty() {
        m.insert(
            "firstAvailable".to_string(),
            r.first_available
                .into_iter()
                .map(gen_device_sub_request_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_constraint_to_json(c: resource_v1::DeviceConstraint) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !c.requests.is_empty() {
        m.insert(
            "requests".to_string(),
            c.requests
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(v) = c.match_attribute.filter(|s| !s.is_empty()) {
        m.insert("matchAttribute".to_string(), v.into());
    }
    if let Some(v) = c.distinct_attribute.filter(|s| !s.is_empty()) {
        m.insert("distinctAttribute".to_string(), v.into());
    }
    serde_json::Value::Object(m)
}

fn gen_device_claim_configuration_to_json(
    c: resource_v1::DeviceClaimConfiguration,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !c.requests.is_empty() {
        m.insert(
            "requests".to_string(),
            c.requests
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(dc) = c.device_configuration {
        m.insert(
            "deviceConfiguration".to_string(),
            gen_device_configuration_to_json(dc),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_device_claim_to_json(dc: resource_v1::DeviceClaim) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !dc.requests.is_empty() {
        m.insert(
            "requests".to_string(),
            dc.requests
                .into_iter()
                .map(gen_device_request_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !dc.constraints.is_empty() {
        m.insert(
            "constraints".to_string(),
            dc.constraints
                .into_iter()
                .map(gen_device_constraint_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !dc.config.is_empty() {
        m.insert(
            "config".to_string(),
            dc.config
                .into_iter()
                .map(gen_device_claim_configuration_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

// ---- Allocation building blocks ---------------------------------------------

fn gen_device_request_allocation_result_to_json(
    r: resource_v1::DeviceRequestAllocationResult,
) -> serde_json::Value {
    let mut m = serde_json::json!({
        "request": r.request.unwrap_or_default(),
        "driver": r.driver.unwrap_or_default(),
        "pool": r.pool.unwrap_or_default(),
        "device": r.device.unwrap_or_default(),
    });
    if let Some(true) = r.admin_access {
        m["adminAccess"] = true.into();
    }
    if !r.tolerations.is_empty() {
        m["tolerations"] = r
            .tolerations
            .into_iter()
            .map(gen_device_toleration_to_json)
            .collect::<Vec<_>>()
            .into();
    }
    if !r.binding_conditions.is_empty() {
        m["bindingConditions"] = r
            .binding_conditions
            .into_iter()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
            .into();
    }
    if !r.binding_failure_conditions.is_empty() {
        m["bindingFailureConditions"] = r
            .binding_failure_conditions
            .into_iter()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(v) = r.share_id.filter(|s| !s.is_empty()) {
        m["shareID"] = v.into();
    }
    if !r.consumed_capacity.is_empty() {
        m["consumedCapacity"] = gen_quantity_map_to_json(r.consumed_capacity);
    }
    m
}

fn gen_device_allocation_configuration_to_json(
    c: resource_v1::DeviceAllocationConfiguration,
) -> serde_json::Value {
    let mut m = serde_json::json!({ "source": c.source.unwrap_or_default() });
    if !c.requests.is_empty() {
        m["requests"] = c
            .requests
            .into_iter()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(dc) = c.device_configuration {
        m["deviceConfiguration"] = gen_device_configuration_to_json(dc);
    }
    m
}

fn gen_device_allocation_result_to_json(
    r: resource_v1::DeviceAllocationResult,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !r.results.is_empty() {
        m.insert(
            "results".to_string(),
            r.results
                .into_iter()
                .map(gen_device_request_allocation_result_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if !r.config.is_empty() {
        m.insert(
            "config".to_string(),
            r.config
                .into_iter()
                .map(gen_device_allocation_configuration_to_json)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_allocation_result_to_json(a: resource_v1::AllocationResult) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(d) = a.devices {
        m.insert(
            "devices".to_string(),
            gen_device_allocation_result_to_json(d),
        );
    }
    if let Some(ns) = a.node_selector {
        m.insert("nodeSelector".to_string(), gen_node_selector_to_json(ns));
    }
    if let Some(t) = a.allocation_timestamp {
        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
            m.insert(
                "allocationTimestamp".to_string(),
                crate::util::secs_to_rfc3339(secs).into(),
            );
        }
    }
    serde_json::Value::Object(m)
}

// ---- Status building blocks --------------------------------------------------

fn gen_resource_claim_consumer_reference_to_json(
    r: resource_v1::ResourceClaimConsumerReference,
) -> serde_json::Value {
    let mut m = serde_json::json!({
        "resource": r.resource.unwrap_or_default(),
        "name": r.name.unwrap_or_default(),
        "uid": r.uid.unwrap_or_default(),
    });
    if let Some(v) = r.api_group.filter(|s| !s.is_empty()) {
        m["apiGroup"] = v.into();
    }
    m
}

fn gen_network_device_data_to_json(n: resource_v1::NetworkDeviceData) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = n.interface_name.filter(|s| !s.is_empty()) {
        m.insert("interfaceName".to_string(), v.into());
    }
    if !n.ips.is_empty() {
        m.insert(
            "ips".to_string(),
            n.ips
                .into_iter()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>()
                .into(),
        );
    }
    if let Some(v) = n.hardware_address.filter(|s| !s.is_empty()) {
        m.insert("hardwareAddress".to_string(), v.into());
    }
    serde_json::Value::Object(m)
}

fn gen_allocated_device_status_to_json(s: resource_v1::AllocatedDeviceStatus) -> serde_json::Value {
    let mut m = serde_json::json!({
        "driver": s.driver.unwrap_or_default(),
        "pool": s.pool.unwrap_or_default(),
        "device": s.device.unwrap_or_default(),
    });
    if let Some(v) = s.share_id.filter(|s| !s.is_empty()) {
        m["shareID"] = v.into();
    }
    if !s.conditions.is_empty() {
        m["conditions"] = s
            .conditions
            .into_iter()
            .map(gen_meta_condition_to_json)
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(v) = gen_raw_extension_to_json(s.data) {
        m["data"] = v;
    }
    if let Some(nd) = s.network_data {
        m["networkData"] = gen_network_device_data_to_json(nd);
    }
    m
}

// ---- Decoder A: DeviceClass -------------------------------------------------

pub fn decode_deviceclass_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = resource_v1::DeviceClass::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "resource.k8s.io/v1",
        "kind": "DeviceClass",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if !spec.selectors.is_empty() {
            spec_json.insert(
                "selectors".to_string(),
                spec.selectors
                    .into_iter()
                    .map(gen_device_selector_to_json)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if !spec.config.is_empty() {
            spec_json.insert(
                "config".to_string(),
                spec.config
                    .into_iter()
                    .filter_map(|c| c.device_configuration)
                    .map(|dc| {
                        serde_json::json!({ "deviceConfiguration": gen_device_configuration_to_json(dc) })
                    })
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if let Some(v) = spec.extended_resource_name.filter(|s| !s.is_empty()) {
            spec_json.insert("extendedResourceName".to_string(), v.into());
        }
        out["spec"] = serde_json::Value::Object(spec_json);
    }
    Some(out)
}

// ---- Decoder A: ResourceClaim ------------------------------------------------

pub fn decode_resourceclaim_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = resource_v1::ResourceClaim::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "resource.k8s.io/v1",
        "kind": "ResourceClaim",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::Map::new();
        if let Some(devices) = spec.devices {
            spec_json.insert("devices".to_string(), gen_device_claim_to_json(devices));
        }
        out["spec"] = serde_json::Value::Object(spec_json);
    }
    if let Some(status) = obj.status {
        let mut status_json = serde_json::Map::new();
        if let Some(a) = status.allocation {
            status_json.insert("allocation".to_string(), gen_allocation_result_to_json(a));
        }
        if !status.reserved_for.is_empty() {
            status_json.insert(
                "reservedFor".to_string(),
                status
                    .reserved_for
                    .into_iter()
                    .map(gen_resource_claim_consumer_reference_to_json)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if !status.devices.is_empty() {
            status_json.insert(
                "devices".to_string(),
                status
                    .devices
                    .into_iter()
                    .map(gen_allocated_device_status_to_json)
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if !status_json.is_empty() {
            out["status"] = serde_json::Value::Object(status_json);
        }
    }
    Some(out)
}

// ---- Decoder A: ResourceClaimTemplate -----------------------------------------

pub fn decode_resourceclaimtemplate_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = resource_v1::ResourceClaimTemplate::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "resource.k8s.io/v1",
        "kind": "ResourceClaimTemplate",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let tmpl_meta = spec
            .metadata
            .map(gen_object_meta_to_json)
            .unwrap_or_else(|| serde_json::json!({"creationTimestamp": serde_json::Value::Null}));
        let mut tmpl_spec = serde_json::Map::new();
        if let Some(rc_spec) = spec.spec {
            if let Some(devices) = rc_spec.devices {
                tmpl_spec.insert("devices".to_string(), gen_device_claim_to_json(devices));
            }
        }
        out["spec"] = serde_json::json!({
            "metadata": tmpl_meta,
            "spec": serde_json::Value::Object(tmpl_spec),
        });
    }
    Some(out)
}

// ---- Decoder A: ResourceSlice -------------------------------------------------

pub fn decode_resourceslice_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let obj = resource_v1::ResourceSlice::decode(data).ok()?;
    let meta = gen_object_meta_to_json(obj.metadata.unwrap_or_default());
    let mut out = serde_json::json!({
        "apiVersion": "resource.k8s.io/v1",
        "kind": "ResourceSlice",
        "metadata": meta
    });
    if let Some(spec) = obj.spec {
        let mut spec_json = serde_json::json!({ "driver": spec.driver.unwrap_or_default() });
        if let Some(pool) = spec.pool {
            spec_json["pool"] = serde_json::json!({
                "name": pool.name.unwrap_or_default(),
                "generation": pool.generation.unwrap_or(0),
                "resourceSliceCount": pool.resource_slice_count.unwrap_or(0),
            });
        }
        if let Some(v) = spec.node_name.filter(|s| !s.is_empty()) {
            spec_json["nodeName"] = v.into();
        }
        if let Some(ns) = spec.node_selector {
            spec_json["nodeSelector"] = gen_node_selector_to_json(ns);
        }
        if let Some(true) = spec.all_nodes {
            spec_json["allNodes"] = true.into();
        }
        if !spec.devices.is_empty() {
            spec_json["devices"] = spec
                .devices
                .into_iter()
                .map(gen_device_to_json)
                .collect::<Vec<_>>()
                .into();
        }
        if let Some(true) = spec.per_device_node_selection {
            spec_json["perDeviceNodeSelection"] = true.into();
        }
        if !spec.shared_counters.is_empty() {
            spec_json["sharedCounters"] = spec
                .shared_counters
                .into_iter()
                .map(gen_counter_set_to_json)
                .collect::<Vec<_>>()
                .into();
        }
        out["spec"] = spec_json;
    }
    Some(out)
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// DeviceClass is the simplest DRA top-level kind; before this decoder existed there was
    /// no protobuf path for it at all, so a protobuf-encoded create (the default for typed
    /// clients) would silently drop selectors/extendedResourceName instead of storing them.
    #[test]
    fn decode_deviceclass_proto_gen_round_trips_selectors_and_extended_resource_name() {
        let dc = resource_v1::DeviceClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu.example.com".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::DeviceClassSpec {
                selectors: vec![resource_v1::DeviceSelector {
                    cel: Some(resource_v1::CelDeviceSelector {
                        expression: Some("device.driver == \"gpu.example.com\"".to_string()),
                    }),
                }],
                extended_resource_name: Some("example.com/gpu".to_string()),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        dc.encode(&mut buf).unwrap();

        let result = decode_deviceclass_proto_gen(&buf)
            .expect("DeviceClass must decode — generated struct covers all fields by construction");

        assert!(
            result["metadata"]["namespace"].is_null(),
            "DeviceClass is cluster-scoped — a decoded namespace would mean cluster-scoped \
             objects are being mis-routed as namespaced"
        );
        assert_eq!(
            result["spec"]["selectors"][0]["cel"]["expression"],
            "device.driver == \"gpu.example.com\"",
            "selectors[].cel.expression must survive decode — it is the only way a DeviceClass \
             restricts which devices it matches"
        );
        assert_eq!(
            result["spec"]["extendedResourceName"], "example.com/gpu",
            "extendedResourceName must survive decode — without it pods cannot request this \
             class via a plain resource request"
        );
    }

    /// ResourceClaim is the DRA type pods actually reference; its status.allocation is what the
    /// scheduler and kubelet read to know which concrete devices were bound to the claim.
    /// Before this decoder existed, a protobuf status update (client-go default) would silently
    /// wipe status.allocation.devices instead of storing it, which is exactly the
    /// protobuf-status-decode bug class this project has hit repeatedly for other types.
    #[test]
    fn decode_resourceclaim_proto_gen_round_trips_spec_devices_and_status_allocation() {
        let rc = resource_v1::ResourceClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu-claim".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceClaimSpec {
                devices: Some(resource_v1::DeviceClaim {
                    requests: vec![resource_v1::DeviceRequest {
                        name: Some("gpu".to_string()),
                        exactly: Some(resource_v1::ExactDeviceRequest {
                            device_class_name: Some("gpu.example.com".to_string()),
                            count: Some(1),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }),
            status: Some(resource_v1::ResourceClaimStatus {
                allocation: Some(resource_v1::AllocationResult {
                    devices: Some(resource_v1::DeviceAllocationResult {
                        results: vec![resource_v1::DeviceRequestAllocationResult {
                            request: Some("gpu".to_string()),
                            driver: Some("gpu.example.com".to_string()),
                            pool: Some("node-1".to_string()),
                            device: Some("gpu-0".to_string()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                reserved_for: vec![resource_v1::ResourceClaimConsumerReference {
                    resource: Some("pods".to_string()),
                    name: Some("consumer-pod".to_string()),
                    uid: Some("uid-123".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).unwrap();

        let result = decode_resourceclaim_proto_gen(&buf).expect("ResourceClaim must decode");

        assert_eq!(
            result["spec"]["devices"]["requests"][0]["exactly"]["deviceClassName"],
            "gpu.example.com",
            "spec.devices.requests[].exactly.deviceClassName must survive decode — without it \
             the claim requests nothing and the scheduler has no allocation to perform"
        );
        assert_eq!(
            result["status"]["allocation"]["devices"]["results"][0]["device"], "gpu-0",
            "status.allocation.devices.results[].device must survive decode — the kubelet reads \
             this to know which physical device to prepare for the pod"
        );
        assert_eq!(
            result["status"]["reservedFor"][0]["name"], "consumer-pod",
            "status.reservedFor must survive decode — losing it would let a claim in active use \
             be deallocated out from under a running pod"
        );
    }

    /// ResourceClaimTemplateSpec nests both an ObjectMeta and a full ResourceClaimSpec; before
    /// this decoder existed, the fields a Pod's ephemeral claim actually needs (the device
    /// requests) had no protobuf decode path.
    #[test]
    fn decode_resourceclaimtemplate_proto_gen_round_trips_nested_device_requests() {
        let rct = resource_v1::ResourceClaimTemplate {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu-template".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceClaimTemplateSpec {
                metadata: Some(meta_v1::ObjectMeta {
                    labels: [("app".to_string(), "ml".to_string())]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                }),
                spec: Some(resource_v1::ResourceClaimSpec {
                    devices: Some(resource_v1::DeviceClaim {
                        requests: vec![resource_v1::DeviceRequest {
                            name: Some("gpu".to_string()),
                            exactly: Some(resource_v1::ExactDeviceRequest {
                                device_class_name: Some("gpu.example.com".to_string()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                }),
            }),
        };
        let mut buf = Vec::new();
        rct.encode(&mut buf).unwrap();

        let result = decode_resourceclaimtemplate_proto_gen(&buf)
            .expect("ResourceClaimTemplate must decode");

        assert_eq!(
            result["spec"]["metadata"]["labels"]["app"], "ml",
            "spec.metadata labels must survive decode — they get copied onto every generated \
             ResourceClaim"
        );
        assert_eq!(
            result["spec"]["spec"]["devices"]["requests"][0]["exactly"]["deviceClassName"],
            "gpu.example.com",
            "the embedded ResourceClaimSpec must survive decode — it is copied verbatim into \
             every ResourceClaim the control plane creates from this template"
        );
    }

    /// ResourceSlice is how a DRA driver publishes which devices exist; the scheduler cannot
    /// allocate a device it never decoded. This also covers nodeSelector, which is how a
    /// non-node-local pool tells the scheduler where its devices are reachable from.
    #[test]
    fn decode_resourceslice_proto_gen_round_trips_pool_and_devices() {
        let rs = resource_v1::ResourceSlice {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("node-1-slice".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceSliceSpec {
                driver: Some("gpu.example.com".to_string()),
                pool: Some(resource_v1::ResourcePool {
                    name: Some("node-1".to_string()),
                    generation: Some(1),
                    resource_slice_count: Some(1),
                }),
                node_name: Some("node-1".to_string()),
                devices: vec![resource_v1::Device {
                    name: Some("gpu-0".to_string()),
                    attributes: [(
                        "model".to_string(),
                        resource_v1::DeviceAttribute {
                            string: Some("A100".to_string()),
                            ..Default::default()
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();

        let result = decode_resourceslice_proto_gen(&buf).expect("ResourceSlice must decode");

        assert!(
            result["metadata"]["namespace"].is_null(),
            "ResourceSlice is cluster-scoped — a decoded namespace would mean cluster-scoped \
             objects are being mis-routed as namespaced"
        );
        assert_eq!(
            result["spec"]["pool"]["name"], "node-1",
            "spec.pool.name must survive decode — consumers key on it to group ResourceSlices \
             belonging to the same pool"
        );
        assert_eq!(
            result["spec"]["devices"][0]["attributes"]["model"]["string"], "A100",
            "spec.devices[].attributes must survive decode — CEL selectors in DeviceClass/claims \
             match against exactly these attributes"
        );
    }

    /// A DeviceCapacity requestPolicy's validRange must survive decode — without it a consumer
    /// requesting a capacity amount outside [min,max] would be silently allowed when it should
    /// have been rejected by the driver's stated policy.
    #[test]
    fn decode_resourceslice_proto_gen_preserves_capacity_request_policy_valid_range() {
        let rs = resource_v1::ResourceSlice {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("shared-gpu-slice".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceSliceSpec {
                driver: Some("gpu.example.com".to_string()),
                pool: Some(resource_v1::ResourcePool {
                    name: Some("node-1".to_string()),
                    generation: Some(1),
                    resource_slice_count: Some(1),
                }),
                devices: vec![resource_v1::Device {
                    name: Some("gpu-0".to_string()),
                    capacity: [(
                        "memory".to_string(),
                        resource_v1::DeviceCapacity {
                            value: Some(
                                u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                    string: Some("80Gi".to_string()),
                                },
                            ),
                            request_policy: Some(resource_v1::CapacityRequestPolicy {
                                valid_range: Some(resource_v1::CapacityRequestPolicyRange {
                                    min: Some(
                                        u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                            string: Some("1Gi".to_string()),
                                        },
                                    ),
                                    max: Some(
                                        u7s_proto_generated::k8s::io::apimachinery::pkg::api::resource::Quantity {
                                            string: Some("80Gi".to_string()),
                                        },
                                    ),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();

        let result = decode_resourceslice_proto_gen(&buf).expect("ResourceSlice must decode");
        let policy = &result["spec"]["devices"][0]["capacity"]["memory"]["requestPolicy"];
        assert_eq!(
            policy["validRange"]["min"], "1Gi",
            "requestPolicy.validRange.min must survive decode — it bounds how little capacity \
             a consumer may request from a shared device"
        );
        assert_eq!(
            policy["validRange"]["max"], "80Gi",
            "requestPolicy.validRange.max must survive decode — without it over-subscription \
             requests against a shared device would go unbounded"
        );
    }

    /// OpaqueDeviceConfiguration.parameters is a RawExtension: the only way a DeviceClass
    /// conveys driver-specific configuration, and opaque-by-design so the control plane can
    /// never validate its shape itself. Losing it silently makes the driver configure every
    /// device in the class with no parameters at all instead of failing loud.
    #[test]
    fn decode_deviceclass_proto_gen_round_trips_opaque_config_parameters() {
        let dc = resource_v1::DeviceClass {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu.example.com".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::DeviceClassSpec {
                config: vec![resource_v1::DeviceClassConfiguration {
                    device_configuration: Some(resource_v1::DeviceConfiguration {
                        opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                            driver: Some("gpu.example.com".to_string()),
                            parameters: Some(
                                u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                    raw: Some(br#"{"clockSpeed":"3.5GHz"}"#.to_vec()),
                                },
                            ),
                        }),
                    }),
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        dc.encode(&mut buf).unwrap();

        let result = decode_deviceclass_proto_gen(&buf).expect("DeviceClass must decode");

        assert_eq!(
            result["spec"]["config"][0]["deviceConfiguration"]["opaque"]["parameters"]
                ["clockSpeed"],
            "3.5GHz",
            "OpaqueDeviceConfiguration.parameters must survive decode as its actual JSON value \
             — a silently dropped or null blob makes the driver configure the device class with \
             no parameters at all, with no error to surface the loss"
        );
    }

    /// ResourceClaim carries two independent RawExtension driver-config blobs:
    /// spec.devices.config[].deviceConfiguration.opaque.parameters (input the claim gives the
    /// driver) and status.devices[].data (state the driver reports back). The kubelet reads
    /// `data` to prepare an allocated device for the pod, so losing either silently breaks
    /// driver configuration on one end or device preparation on the other.
    #[test]
    fn decode_resourceclaim_proto_gen_round_trips_opaque_parameters_and_status_data() {
        let rc = resource_v1::ResourceClaim {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu-claim".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceClaimSpec {
                devices: Some(resource_v1::DeviceClaim {
                    config: vec![resource_v1::DeviceClaimConfiguration {
                        device_configuration: Some(resource_v1::DeviceConfiguration {
                            opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                                driver: Some("gpu.example.com".to_string()),
                                parameters: Some(
                                    u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                        raw: Some(br#"{"mig":"1g.10gb"}"#.to_vec()),
                                    },
                                ),
                            }),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }),
            status: Some(resource_v1::ResourceClaimStatus {
                devices: vec![resource_v1::AllocatedDeviceStatus {
                    driver: Some("gpu.example.com".to_string()),
                    pool: Some("node-1".to_string()),
                    device: Some("gpu-0".to_string()),
                    data: Some(
                        u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                            raw: Some(br#"{"uuid":"GPU-1234"}"#.to_vec()),
                        },
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).unwrap();

        let result = decode_resourceclaim_proto_gen(&buf).expect("ResourceClaim must decode");

        assert_eq!(
            result["spec"]["devices"]["config"][0]["deviceConfiguration"]["opaque"]["parameters"]
                ["mig"],
            "1g.10gb",
            "spec.devices.config[].deviceConfiguration.opaque.parameters must survive decode — \
             it is how a claim tells the driver how to configure the device it allocates"
        );
        assert_eq!(
            result["status"]["devices"][0]["data"]["uuid"], "GPU-1234",
            "status.devices[].data must survive decode — the kubelet reads driver-reported \
             per-device state from here to prepare the device for the pod"
        );
    }

    /// ResourceClaimTemplate.spec.spec is copied verbatim into every ResourceClaim the control
    /// plane generates from the template, so its embedded
    /// OpaqueDeviceConfiguration.parameters must survive decode or every claim created from
    /// this template inherits driver configuration with no parameters.
    #[test]
    fn decode_resourceclaimtemplate_proto_gen_round_trips_embedded_opaque_config_parameters() {
        let rct = resource_v1::ResourceClaimTemplate {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("gpu-template".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            spec: Some(resource_v1::ResourceClaimTemplateSpec {
                spec: Some(resource_v1::ResourceClaimSpec {
                    devices: Some(resource_v1::DeviceClaim {
                        config: vec![resource_v1::DeviceClaimConfiguration {
                            device_configuration: Some(resource_v1::DeviceConfiguration {
                                opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                                    driver: Some("gpu.example.com".to_string()),
                                    parameters: Some(
                                        u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                            raw: Some(br#"{"mig":"2g.20gb"}"#.to_vec()),
                                        },
                                    ),
                                }),
                            }),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        rct.encode(&mut buf).unwrap();

        let result = decode_resourceclaimtemplate_proto_gen(&buf)
            .expect("ResourceClaimTemplate must decode");

        assert_eq!(
            result["spec"]["spec"]["devices"]["config"][0]["deviceConfiguration"]["opaque"]
                ["parameters"]["mig"],
            "2g.20gb",
            "the embedded ResourceClaimSpec's OpaqueDeviceConfiguration.parameters must survive \
             decode — it is copied verbatim into every ResourceClaim the control plane creates \
             from this template"
        );
    }

    // ---- Field-omission: all-default proto must decode with no stray nulls ----
    //
    // The round-trip tests above check `result["metadata"]["namespace"].is_null()`, which is
    // also true when the key is simply absent — it cannot tell "correctly omitted" apart from
    // "present as null" (the exact bug class this bead is about). The tests below use
    // `assert_no_stray_nulls`/`.get()` on the actual JSON object map instead, so they would fail
    // if a future change started emitting `null` for an unset optional field.

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_deviceclass_proto_gen_omits_unset_spec_instead_of_emitting_null() {
        let dc = resource_v1::DeviceClass::default();
        let mut buf = Vec::new();
        dc.encode(&mut buf).unwrap();
        let decoded =
            decode_deviceclass_proto_gen(&buf).expect("all-default DeviceClass must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none(),
            "an unset DeviceClassSpec must be absent, not null"
        );
    }

    #[test]
    fn decode_resourceclaim_proto_gen_omits_unset_spec_and_status_instead_of_emitting_null() {
        let rc = resource_v1::ResourceClaim::default();
        let mut buf = Vec::new();
        rc.encode(&mut buf).unwrap();
        let decoded =
            decode_resourceclaim_proto_gen(&buf).expect("all-default ResourceClaim must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none() && decoded.get("status").is_none(),
            "unset spec/status must be absent, not null — the scheduler checks \
             `status.allocation != null` to know whether devices have already been bound to \
             this claim; a stray null would be indistinguishable from a real (but empty) \
             allocation result"
        );
    }

    #[test]
    fn decode_resourceclaimtemplate_proto_gen_omits_unset_nested_fields_instead_of_emitting_null() {
        // Unlike the other three Kinds in this file, ResourceClaimTemplate.spec is realistically
        // always Some() (it's the only reason the template exists) — so the meaningful
        // all-default case is a *present* spec whose nested metadata/devices are themselves
        // unset, not an absent top-level spec.
        let rct = resource_v1::ResourceClaimTemplate {
            spec: Some(resource_v1::ResourceClaimTemplateSpec::default()),
            ..Default::default()
        };
        let mut buf = Vec::new();
        rct.encode(&mut buf).unwrap();
        let decoded = decode_resourceclaimtemplate_proto_gen(&buf)
            .expect("ResourceClaimTemplate with an all-default spec must decode");

        // creationTimestamp appears twice here: once on the object's own metadata, once on the
        // nested template metadata this file's decode_resourceclaimtemplate_proto_gen
        // synthesizes for an unset spec.metadata — both are the same deliberate convention.
        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded["spec"]["spec"]
                .as_object()
                .is_some_and(|m| !m.contains_key("devices")),
            "an unset embedded ResourceClaimSpec.devices must be absent, not null — every \
             ResourceClaim the control plane generates from this template copies spec.spec \
             verbatim, so a stray null here would propagate to every generated claim"
        );
    }

    #[test]
    fn decode_resourceslice_proto_gen_omits_unset_spec_instead_of_emitting_null() {
        let rs = resource_v1::ResourceSlice::default();
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();
        let decoded =
            decode_resourceslice_proto_gen(&buf).expect("all-default ResourceSlice must decode");

        assert_no_stray_nulls(&decoded, &["creationTimestamp"]);
        assert!(
            decoded.get("spec").is_none(),
            "an unset ResourceSliceSpec must be absent, not null"
        );
    }

    // ---- Sentinel completeness: every schema field must reach the decoded JSON ----
    //
    // Derived from the compiled `FileDescriptorSet` (see `proto_descriptor::expected_json_keys_for`)
    // rather than hand-listed, so a field added upstream is demanded here automatically instead of
    // relying on a human to notice. Before this section existed this file had zero tests of this
    // shape at all — the ObjectMeta/PodStatus history in core_gen_adapter.rs is exactly the bug
    // class it exists to catch: a field can be forgotten in both the decoder and a hand-typed
    // `expected` list at once, and the hand-typed list can't tell you it's wrong.
    //
    // `DeviceClassSpec`/`ResourceClaimSpec`/`ResourceClaimTemplateSpec` each reach an
    // `OpaqueDeviceConfiguration.parameters` (or `AllocatedDeviceStatus.data`) RawExtension leaf
    // somewhere in their tree. A blind `::sentinel()` on those types would fill that RawExtension's
    // `raw` bytes with an arbitrary non-JSON byte (see `u7s_sentinel::Sentinel`'s impl for
    // `Vec<u8>`), which `gen_raw_extension_to_json` silently (and correctly) drops when it fails to
    // parse as JSON — so the three tests below override just that leaf with valid JSON, matching
    // `apps_gen_adapter`'s `ControllerRevision` precedent, to actually exercise the "survives
    // decode" path instead of one that would pass green even if the pass-through were deleted.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    #[test]
    fn sentinel_completeness_decode_deviceclass_proto_gen() {
        // parameters.raw must be a JSON *scalar*, not an object: RawExtension is opaque to the
        // oracle (its own field name IS the leaf, since the schema can't know what shape
        // arbitrary driver config takes), so an object payload would recurse one level deeper
        // (".parameters.a") and never satisfy the oracle's exact ".parameters" leaf — while still
        // needing to be valid JSON to exercise gen_json_raw_to_value's real parsing path (a
        // blind `RawExtension::sentinel()` fills `raw` with non-JSON bytes, which is silently —
        // and correctly — dropped, so completeness here would be untestable without this).
        let dc = resource_v1::DeviceClass {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(resource_v1::DeviceClassSpec {
                config: vec![resource_v1::DeviceClassConfiguration {
                    device_configuration: Some(resource_v1::DeviceConfiguration {
                        opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                            driver: Some("__sentinel__".to_string()),
                            parameters: Some(
                                u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                    raw: Some(br#"1"#.to_vec()),
                                },
                            ),
                        }),
                    }),
                }],
                ..resource_v1::DeviceClassSpec::sentinel()
            }),
        };
        let mut buf = Vec::new();
        dc.encode(&mut buf).unwrap();
        let decoded = decode_deviceclass_proto_gen(&buf)
            .expect("sentinel DeviceClass must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.resource.v1.DeviceClass",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_resourceclaim_proto_gen() {
        // Every RawExtension.raw below is a JSON *scalar*, not an object — see the comment on
        // sentinel_completeness_decode_deviceclass_proto_gen for why. `status.allocation` also
        // needs its own explicit override (rather than relying on `ResourceClaimStatus::sentinel()`
        // blindly filling it): the same DeviceConfiguration/OpaqueDeviceConfiguration/
        // RawExtension chain is reachable there too, and a blind sentinel's non-JSON raw bytes
        // would otherwise leave `status.allocation.devices.config.deviceConfiguration.opaque.
        // parameters` untestable for the same reason.
        let rc = resource_v1::ResourceClaim {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(resource_v1::ResourceClaimSpec {
                devices: Some(resource_v1::DeviceClaim {
                    config: vec![resource_v1::DeviceClaimConfiguration {
                        device_configuration: Some(resource_v1::DeviceConfiguration {
                            opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                                driver: Some("__sentinel__".to_string()),
                                parameters: Some(
                                    u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                        raw: Some(br#"1"#.to_vec()),
                                    },
                                ),
                            }),
                        }),
                        ..resource_v1::DeviceClaimConfiguration::sentinel()
                    }],
                    ..resource_v1::DeviceClaim::sentinel()
                }),
            }),
            status: Some(resource_v1::ResourceClaimStatus {
                devices: vec![resource_v1::AllocatedDeviceStatus {
                    data: Some(
                        u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                            raw: Some(br#"2"#.to_vec()),
                        },
                    ),
                    ..resource_v1::AllocatedDeviceStatus::sentinel()
                }],
                allocation: Some(resource_v1::AllocationResult {
                    devices: Some(resource_v1::DeviceAllocationResult {
                        config: vec![resource_v1::DeviceAllocationConfiguration {
                            device_configuration: Some(resource_v1::DeviceConfiguration {
                                opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                                    driver: Some("__sentinel__".to_string()),
                                    parameters: Some(
                                        u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                            raw: Some(br#"3"#.to_vec()),
                                        },
                                    ),
                                }),
                            }),
                            ..resource_v1::DeviceAllocationConfiguration::sentinel()
                        }],
                        ..resource_v1::DeviceAllocationResult::sentinel()
                    }),
                    ..resource_v1::AllocationResult::sentinel()
                }),
                ..resource_v1::ResourceClaimStatus::sentinel()
            }),
        };
        let mut buf = Vec::new();
        rc.encode(&mut buf).unwrap();
        let decoded = decode_resourceclaim_proto_gen(&buf)
            .expect("sentinel ResourceClaim must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.resource.v1.ResourceClaim",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_decode_resourceclaimtemplate_proto_gen() {
        // parameters.raw is a JSON scalar, not an object — see the comment on
        // sentinel_completeness_decode_deviceclass_proto_gen for why.
        let rct = resource_v1::ResourceClaimTemplate {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(resource_v1::ResourceClaimTemplateSpec {
                spec: Some(resource_v1::ResourceClaimSpec {
                    devices: Some(resource_v1::DeviceClaim {
                        config: vec![resource_v1::DeviceClaimConfiguration {
                            device_configuration: Some(resource_v1::DeviceConfiguration {
                                opaque: Some(resource_v1::OpaqueDeviceConfiguration {
                                    driver: Some("__sentinel__".to_string()),
                                    parameters: Some(
                                        u7s_proto_generated::k8s::io::apimachinery::pkg::runtime::RawExtension {
                                            raw: Some(br#"1"#.to_vec()),
                                        },
                                    ),
                                }),
                            }),
                            ..resource_v1::DeviceClaimConfiguration::sentinel()
                        }],
                        ..resource_v1::DeviceClaim::sentinel()
                    }),
                }),
                ..resource_v1::ResourceClaimTemplateSpec::sentinel()
            }),
        };
        let mut buf = Vec::new();
        rct.encode(&mut buf).unwrap();
        let decoded = decode_resourceclaimtemplate_proto_gen(&buf)
            .expect("sentinel ResourceClaimTemplate must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.resource.v1.ResourceClaimTemplate",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }

    /// ResourceSlice has no RawExtension-typed field anywhere in its tree, so unlike the three
    /// tests above a blind `::sentinel()` is sufficient here — this is the one decoder in the
    /// file the survey already found nothing missing in; this test is what locks that in.
    #[test]
    fn sentinel_completeness_decode_resourceslice_proto_gen() {
        let rs = resource_v1::ResourceSlice {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(resource_v1::ResourceSliceSpec::sentinel()),
        };
        let mut buf = Vec::new();
        rs.encode(&mut buf).unwrap();
        let decoded = decode_resourceslice_proto_gen(&buf)
            .expect("sentinel ResourceSlice must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let expected = crate::proto_descriptor::expected_json_keys_for(&[
            ".k8s.io.api.resource.v1.ResourceSlice",
        ]);
        let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
        assert_fields_present(&paths, &expected);
    }
}
