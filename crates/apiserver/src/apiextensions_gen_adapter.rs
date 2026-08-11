use prost::Message;

use crate::apiextensions_gen::k8s::io::apiextensions_apiserver::pkg::apis::apiextensions::v1 as apiext_v1;
use crate::apiextensions_gen::k8s::io::apimachinery::pkg::apis::meta::v1 as meta_v1;

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

fn gen_json_raw_to_value(j: apiext_v1::Json) -> serde_json::Value {
    j.raw
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn gen_json_schema_props_to_json(schema: apiext_v1::JsonSchemaProps) -> serde_json::Value {
    let mut m = serde_json::Map::with_capacity(32);

    if let Some(v) = schema.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.description.filter(|s| !s.is_empty()) {
        m.insert("description".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.format.filter(|s| !s.is_empty()) {
        m.insert("format".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.title.filter(|s| !s.is_empty()) {
        m.insert("title".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.r#ref.filter(|s| !s.is_empty()) {
        m.insert("$ref".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.id.filter(|s| !s.is_empty()) {
        m.insert("id".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.schema.filter(|s| !s.is_empty()) {
        m.insert("$schema".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.pattern.filter(|s| !s.is_empty()) {
        m.insert("pattern".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = schema.default {
        let raw = gen_json_raw_to_value(v);
        if !raw.is_null() {
            m.insert("default".to_string(), raw);
        }
    }
    if let Some(v) = schema.maximum {
        m.insert(
            "maximum".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
    }
    if let Some(v) = schema.exclusive_maximum.filter(|&b| b) {
        m.insert("exclusiveMaximum".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = schema.minimum {
        m.insert(
            "minimum".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
    }
    if let Some(v) = schema.exclusive_minimum.filter(|&b| b) {
        m.insert("exclusiveMinimum".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = schema.max_length {
        m.insert("maxLength".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = schema.min_length {
        m.insert("minLength".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = schema.max_items {
        m.insert("maxItems".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = schema.min_items {
        m.insert("minItems".to_string(), serde_json::Value::Number(v.into()));
    }
    if let Some(v) = schema.unique_items.filter(|&b| b) {
        m.insert("uniqueItems".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = schema.multiple_of {
        m.insert(
            "multipleOf".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
    }
    if let Some(v) = schema.max_properties {
        m.insert(
            "maxProperties".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = schema.min_properties {
        m.insert(
            "minProperties".to_string(),
            serde_json::Value::Number(v.into()),
        );
    }
    if let Some(v) = schema.nullable.filter(|&b| b) {
        m.insert("nullable".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = schema.x_kubernetes_preserve_unknown_fields.filter(|&b| b) {
        m.insert(
            "x-kubernetes-preserve-unknown-fields".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(v) = schema.x_kubernetes_embedded_resource.filter(|&b| b) {
        m.insert(
            "x-kubernetes-embedded-resource".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(v) = schema.x_kubernetes_int_or_string.filter(|&b| b) {
        m.insert(
            "x-kubernetes-int-or-string".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(v) = schema.x_kubernetes_list_type.filter(|s| !s.is_empty()) {
        m.insert(
            "x-kubernetes-list-type".to_string(),
            serde_json::Value::String(v),
        );
    }
    if let Some(v) = schema.x_kubernetes_map_type.filter(|s| !s.is_empty()) {
        m.insert(
            "x-kubernetes-map-type".to_string(),
            serde_json::Value::String(v),
        );
    }
    if !schema.x_kubernetes_list_map_keys.is_empty() {
        m.insert(
            "x-kubernetes-list-map-keys".to_string(),
            serde_json::Value::Array(
                schema
                    .x_kubernetes_list_map_keys
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !schema.required.is_empty() {
        m.insert(
            "required".to_string(),
            serde_json::Value::Array(
                schema
                    .required
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !schema.r#enum.is_empty() {
        let enum_vals: Vec<serde_json::Value> = schema
            .r#enum
            .into_iter()
            .map(gen_json_raw_to_value)
            .collect();
        m.insert("enum".to_string(), serde_json::Value::Array(enum_vals));
    }
    if !schema.properties.is_empty() {
        let props: serde_json::Map<String, serde_json::Value> = schema
            .properties
            .into_iter()
            .map(|(k, v)| (k, gen_json_schema_props_to_json(v)))
            .collect();
        m.insert("properties".to_string(), serde_json::Value::Object(props));
    }
    if !schema.pattern_properties.is_empty() {
        let pp: serde_json::Map<String, serde_json::Value> = schema
            .pattern_properties
            .into_iter()
            .map(|(k, v)| (k, gen_json_schema_props_to_json(v)))
            .collect();
        m.insert(
            "patternProperties".to_string(),
            serde_json::Value::Object(pp),
        );
    }
    if !schema.definitions.is_empty() {
        let defs: serde_json::Map<String, serde_json::Value> = schema
            .definitions
            .into_iter()
            .map(|(k, v)| (k, gen_json_schema_props_to_json(v)))
            .collect();
        m.insert("definitions".to_string(), serde_json::Value::Object(defs));
    }
    if !schema.dependencies.is_empty() {
        let deps: serde_json::Map<String, serde_json::Value> = schema
            .dependencies
            .into_iter()
            .map(|(k, v)| {
                let mut dep_m = serde_json::Map::new();
                if let Some(s) = v.schema {
                    dep_m.insert("schema".to_string(), gen_json_schema_props_to_json(s));
                }
                if !v.property.is_empty() {
                    dep_m.insert(
                        "property".to_string(),
                        serde_json::Value::Array(
                            v.property
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                (k, serde_json::Value::Object(dep_m))
            })
            .collect();
        m.insert("dependencies".to_string(), serde_json::Value::Object(deps));
    }
    if let Some(boxed) = schema.items {
        let items_val = if let Some(s) = boxed.schema {
            gen_json_schema_props_to_json(*s)
        } else if !boxed.j_son_schemas.is_empty() {
            serde_json::Value::Array(
                boxed
                    .j_son_schemas
                    .into_iter()
                    .map(gen_json_schema_props_to_json)
                    .collect(),
            )
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };
        m.insert("items".to_string(), items_val);
    }
    if let Some(boxed) = schema.additional_properties {
        let ap_val = match (boxed.allows, boxed.schema) {
            (_, Some(s)) => gen_json_schema_props_to_json(*s),
            (Some(b), None) => serde_json::Value::Bool(b),
            (None, None) => serde_json::Value::Object(serde_json::Map::new()),
        };
        m.insert("additionalProperties".to_string(), ap_val);
    }
    if let Some(boxed) = schema.additional_items {
        let ai_val = match (boxed.allows, boxed.schema) {
            (_, Some(s)) => gen_json_schema_props_to_json(*s),
            (Some(b), None) => serde_json::Value::Bool(b),
            (None, None) => serde_json::Value::Object(serde_json::Map::new()),
        };
        m.insert("additionalItems".to_string(), ai_val);
    }
    if !schema.all_of.is_empty() {
        m.insert(
            "allOf".to_string(),
            serde_json::Value::Array(
                schema
                    .all_of
                    .into_iter()
                    .map(gen_json_schema_props_to_json)
                    .collect(),
            ),
        );
    }
    if !schema.one_of.is_empty() {
        m.insert(
            "oneOf".to_string(),
            serde_json::Value::Array(
                schema
                    .one_of
                    .into_iter()
                    .map(gen_json_schema_props_to_json)
                    .collect(),
            ),
        );
    }
    if !schema.any_of.is_empty() {
        m.insert(
            "anyOf".to_string(),
            serde_json::Value::Array(
                schema
                    .any_of
                    .into_iter()
                    .map(gen_json_schema_props_to_json)
                    .collect(),
            ),
        );
    }
    if let Some(boxed) = schema.not {
        m.insert("not".to_string(), gen_json_schema_props_to_json(*boxed));
    }
    if let Some(ed) = schema.external_docs {
        let mut ed_m = serde_json::Map::new();
        if let Some(d) = ed.description.filter(|s| !s.is_empty()) {
            ed_m.insert("description".to_string(), serde_json::Value::String(d));
        }
        if let Some(u) = ed.url.filter(|s| !s.is_empty()) {
            ed_m.insert("url".to_string(), serde_json::Value::String(u));
        }
        if !ed_m.is_empty() {
            m.insert("externalDocs".to_string(), serde_json::Value::Object(ed_m));
        }
    }
    if let Some(ex) = schema.example {
        let raw = gen_json_raw_to_value(ex);
        if !raw.is_null() {
            m.insert("example".to_string(), raw);
        }
    }
    if !schema.x_kubernetes_validations.is_empty() {
        let rules: Vec<serde_json::Value> = schema
            .x_kubernetes_validations
            .into_iter()
            .map(|r| {
                let mut rm = serde_json::Map::new();
                if let Some(v) = r.rule.filter(|s| !s.is_empty()) {
                    rm.insert("rule".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = r.message.filter(|s| !s.is_empty()) {
                    rm.insert("message".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = r.message_expression.filter(|s| !s.is_empty()) {
                    rm.insert(
                        "messageExpression".to_string(),
                        serde_json::Value::String(v),
                    );
                }
                if let Some(v) = r.reason.filter(|s| !s.is_empty()) {
                    rm.insert("reason".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = r.field_path.filter(|s| !s.is_empty()) {
                    rm.insert("fieldPath".to_string(), serde_json::Value::String(v));
                }
                if let Some(v) = r.optional_old_self.filter(|&b| b) {
                    rm.insert("optionalOldSelf".to_string(), serde_json::Value::Bool(v));
                }
                serde_json::Value::Object(rm)
            })
            .collect();
        m.insert(
            "x-kubernetes-validations".to_string(),
            serde_json::Value::Array(rules),
        );
    }

    serde_json::Value::Object(m)
}

fn gen_crd_names_to_json(names: apiext_v1::CustomResourceDefinitionNames) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = names.plural.filter(|s| !s.is_empty()) {
        m.insert("plural".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = names.singular.filter(|s| !s.is_empty()) {
        m.insert("singular".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = names.kind.filter(|s| !s.is_empty()) {
        m.insert("kind".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = names.list_kind.filter(|s| !s.is_empty()) {
        m.insert("listKind".to_string(), serde_json::Value::String(v));
    }
    if !names.short_names.is_empty() {
        m.insert(
            "shortNames".to_string(),
            serde_json::Value::Array(
                names
                    .short_names
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !names.categories.is_empty() {
        m.insert(
            "categories".to_string(),
            serde_json::Value::Array(
                names
                    .categories
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

fn gen_printer_column_to_json(col: apiext_v1::CustomResourceColumnDefinition) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = col.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = col.r#type.filter(|s| !s.is_empty()) {
        m.insert("type".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = col.json_path.filter(|s| !s.is_empty()) {
        m.insert("jsonPath".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = col.format.filter(|s| !s.is_empty()) {
        m.insert("format".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = col.description.filter(|s| !s.is_empty()) {
        m.insert("description".to_string(), serde_json::Value::String(v));
    }
    if let Some(v) = col.priority.filter(|&p| p != 0) {
        m.insert("priority".to_string(), serde_json::Value::Number(v.into()));
    }
    serde_json::Value::Object(m)
}

fn gen_selectable_field_to_json(f: apiext_v1::SelectableField) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(v) = f.json_path.filter(|s| !s.is_empty()) {
        m.insert("jsonPath".to_string(), serde_json::Value::String(v));
    }
    serde_json::Value::Object(m)
}

fn gen_subresources_to_json(sr: apiext_v1::CustomResourceSubresources) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if sr.status.is_some() {
        m.insert("status".to_string(), serde_json::json!({}));
    }
    if let Some(scale) = sr.scale {
        let mut sm = serde_json::Map::new();
        if let Some(v) = scale.spec_replicas_path.filter(|s| !s.is_empty()) {
            sm.insert("specReplicasPath".to_string(), serde_json::Value::String(v));
        }
        if let Some(v) = scale.status_replicas_path.filter(|s| !s.is_empty()) {
            sm.insert(
                "statusReplicasPath".to_string(),
                serde_json::Value::String(v),
            );
        }
        if let Some(v) = scale.label_selector_path.filter(|s| !s.is_empty()) {
            sm.insert(
                "labelSelectorPath".to_string(),
                serde_json::Value::String(v),
            );
        }
        m.insert("scale".to_string(), serde_json::Value::Object(sm));
    }
    serde_json::Value::Object(m)
}

fn gen_version_to_json(v: apiext_v1::CustomResourceDefinitionVersion) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if let Some(name) = v.name.filter(|s| !s.is_empty()) {
        m.insert("name".to_string(), serde_json::Value::String(name));
    }
    m.insert(
        "served".to_string(),
        serde_json::Value::Bool(v.served.unwrap_or(false)),
    );
    m.insert(
        "storage".to_string(),
        serde_json::Value::Bool(v.storage.unwrap_or(false)),
    );
    if let Some(dep) = v.deprecated.filter(|&b| b) {
        m.insert("deprecated".to_string(), serde_json::Value::Bool(dep));
    }
    if let Some(dw) = v.deprecation_warning.filter(|s| !s.is_empty()) {
        m.insert(
            "deprecationWarning".to_string(),
            serde_json::Value::String(dw),
        );
    }
    if let Some(schema_wrapper) = v.schema {
        if let Some(schema) = schema_wrapper.open_apiv3_schema {
            m.insert(
                "schema".to_string(),
                serde_json::json!({
                    "openAPIV3Schema": gen_json_schema_props_to_json(schema)
                }),
            );
        }
    }
    if let Some(sr) = v.subresources {
        let sr_json = gen_subresources_to_json(sr);
        if !sr_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {
            m.insert("subresources".to_string(), sr_json);
        }
    }
    if !v.additional_printer_columns.is_empty() {
        m.insert(
            "additionalPrinterColumns".to_string(),
            serde_json::Value::Array(
                v.additional_printer_columns
                    .into_iter()
                    .map(gen_printer_column_to_json)
                    .collect(),
            ),
        );
    }
    // selectableFields backs the CustomResourceFieldSelectors feature (`kubectl get widgets
    // --field-selector ...`); dropping it silently strips a client's field-selector
    // configuration on every protobuf-encoded CRD create/update.
    if !v.selectable_fields.is_empty() {
        m.insert(
            "selectableFields".to_string(),
            serde_json::Value::Array(
                v.selectable_fields
                    .into_iter()
                    .map(gen_selectable_field_to_json)
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(m)
}

pub fn decode_crd_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let crd = apiext_v1::CustomResourceDefinition::decode(data).ok()?;
    let mut meta = gen_object_meta_to_json(crd.metadata.unwrap_or_default());
    if meta["creationTimestamp"].is_null() {
        meta["creationTimestamp"] = serde_json::Value::String(String::new());
    }

    let spec = crd.spec.unwrap_or_default();
    let mut spec_m = serde_json::Map::with_capacity(7);

    if let Some(g) = spec.group.filter(|s| !s.is_empty()) {
        spec_m.insert("group".to_string(), serde_json::Value::String(g));
    }
    if let Some(s) = spec.scope.filter(|s| !s.is_empty()) {
        spec_m.insert("scope".to_string(), serde_json::Value::String(s));
    }
    if let Some(names) = spec.names {
        spec_m.insert("names".to_string(), gen_crd_names_to_json(names));
    }
    if !spec.versions.is_empty() {
        spec_m.insert(
            "versions".to_string(),
            serde_json::Value::Array(spec.versions.into_iter().map(gen_version_to_json).collect()),
        );
    }
    if let Some(b) = spec.preserve_unknown_fields.filter(|&b| b) {
        spec_m.insert(
            "preserveUnknownFields".to_string(),
            serde_json::Value::Bool(b),
        );
    }
    if let Some(conv) = spec.conversion {
        let mut cm = serde_json::Map::new();
        if let Some(strategy) = conv.strategy.filter(|s| !s.is_empty()) {
            cm.insert("strategy".to_string(), serde_json::Value::String(strategy));
        }
        if let Some(wh) = conv.webhook {
            let mut wm = serde_json::Map::new();
            if !wh.conversion_review_versions.is_empty() {
                wm.insert(
                    "conversionReviewVersions".to_string(),
                    serde_json::Value::Array(
                        wh.conversion_review_versions
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
            if let Some(cc) = wh.client_config {
                let mut ccm = serde_json::Map::new();
                if let Some(ca) = cc.ca_bundle.filter(|b| !b.is_empty()) {
                    ccm.insert(
                        "caBundle".to_string(),
                        serde_json::Value::String(base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &ca,
                        )),
                    );
                }
                if let Some(url) = cc.url.filter(|s| !s.is_empty()) {
                    ccm.insert("url".to_string(), serde_json::Value::String(url));
                }
                if let Some(svc) = cc.service {
                    let mut svm = serde_json::Map::new();
                    if let Some(ns) = svc.namespace.filter(|s| !s.is_empty()) {
                        svm.insert("namespace".to_string(), serde_json::Value::String(ns));
                    }
                    if let Some(name) = svc.name.filter(|s| !s.is_empty()) {
                        svm.insert("name".to_string(), serde_json::Value::String(name));
                    }
                    if let Some(path) = svc.path.filter(|s| !s.is_empty()) {
                        svm.insert("path".to_string(), serde_json::Value::String(path));
                    }
                    if let Some(port) = svc.port {
                        svm.insert("port".to_string(), serde_json::Value::Number(port.into()));
                    }
                    ccm.insert("service".to_string(), serde_json::Value::Object(svm));
                }
                if !ccm.is_empty() {
                    wm.insert("clientConfig".to_string(), serde_json::Value::Object(ccm));
                }
            }
            if !wm.is_empty() {
                cm.insert("webhook".to_string(), serde_json::Value::Object(wm));
            }
        }
        spec_m.insert("conversion".to_string(), serde_json::Value::Object(cm));
    }

    let mut obj = serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": meta,
        "spec": serde_json::Value::Object(spec_m)
    });

    // status carries Established/NamesAccepted conditions (and acceptedNames,
    // storedVersions). Without decoding it, a protobuf status subresource PUT/PATCH
    // (the typed clientset's default content type for this built-in-shaped resource)
    // silently drops the client's status entirely — the status subresource conformance
    // test then reads back an empty conditions list.
    if let Some(status) = crd.status {
        let mut status_m = serde_json::Map::new();
        if !status.conditions.is_empty() {
            let conds: Vec<serde_json::Value> = status
                .conditions
                .into_iter()
                .map(|c| {
                    let mut cm = serde_json::json!({
                        "type": c.r#type.unwrap_or_default(),
                        "status": c.status.unwrap_or_default(),
                    });
                    if let Some(v) = c.reason.filter(|s| !s.is_empty()) {
                        cm["reason"] = v.into();
                    }
                    if let Some(v) = c.message.filter(|s| !s.is_empty()) {
                        cm["message"] = v.into();
                    }
                    if let Some(t) = c.last_transition_time {
                        if let Some(secs) = t.seconds.filter(|&s| s > 0) {
                            cm["lastTransitionTime"] =
                                serde_json::Value::String(crate::util::secs_to_rfc3339(secs));
                        }
                    }
                    if let Some(og) = c.observed_generation.filter(|&g| g != 0) {
                        cm["observedGeneration"] = og.into();
                    }
                    cm
                })
                .collect();
            status_m.insert("conditions".to_string(), serde_json::Value::Array(conds));
        }
        if let Some(names) = status.accepted_names {
            status_m.insert("acceptedNames".to_string(), gen_crd_names_to_json(names));
        }
        if !status.stored_versions.is_empty() {
            status_m.insert(
                "storedVersions".to_string(),
                serde_json::Value::Array(
                    status
                        .stored_versions
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
        // observedGeneration lets the CRDEstablishedController-style reconciler (and clients
        // polling for spec.versions[].schema changes to take effect) detect a status update is
        // stale; dropping it made every protobuf-written CRD status look permanently
        // up-to-date.
        if let Some(og) = status.observed_generation.filter(|&g| g != 0) {
            status_m.insert("observedGeneration".to_string(), og.into());
        }
        if !status_m.is_empty() {
            obj["status"] = serde_json::Value::Object(status_m);
        }
    }

    Some(obj)
}

pub fn decode_delete_options_proto_gen(data: &[u8]) -> Option<serde_json::Value> {
    let opts = meta_v1::DeleteOptions::decode(data).ok()?;
    let mut obj = serde_json::json!({
        "apiVersion": "meta.k8s.io/v1",
        "kind": "DeleteOptions"
    });
    if let Some(policy) = opts.propagation_policy.filter(|s| !s.is_empty()) {
        obj["propagationPolicy"] = serde_json::Value::String(policy);
    }
    if let Some(orphan) = opts.orphan_dependents {
        obj["orphanDependents"] = serde_json::Value::Bool(orphan);
    }
    if let Some(grace) = opts.grace_period_seconds {
        obj["gracePeriodSeconds"] = serde_json::Value::Number(grace.into());
    }
    if !opts.dry_run.is_empty() {
        obj["dryRun"] = serde_json::Value::Array(
            opts.dry_run
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    // preconditions carries the UID/resourceVersion a client expects the target to still have;
    // dropping it silently turned every protobuf-encoded conditional delete (client-go's
    // DeleteOptions{Preconditions: ...}, used by the GC controller to avoid racing a recreate)
    // into an unconditional one.
    if let Some(pre) = opts.preconditions {
        let mut pm = serde_json::Map::new();
        if let Some(uid) = pre.uid.filter(|s| !s.is_empty()) {
            pm.insert("uid".to_string(), serde_json::Value::String(uid));
        }
        if let Some(rv) = pre.resource_version.filter(|s| !s.is_empty()) {
            pm.insert("resourceVersion".to_string(), serde_json::Value::String(rv));
        }
        if !pm.is_empty() {
            obj["preconditions"] = serde_json::Value::Object(pm);
        }
    }
    Some(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_crd_preserves_spec_schema_and_status_by_construction() {
        let crd = apiext_v1::CustomResourceDefinition {
            metadata: Some(meta_v1::ObjectMeta {
                name: Some("widgets.example.com".to_string()),
                ..Default::default()
            }),
            spec: Some(apiext_v1::CustomResourceDefinitionSpec {
                group: Some("example.com".to_string()),
                scope: Some("Namespaced".to_string()),
                names: Some(apiext_v1::CustomResourceDefinitionNames {
                    plural: Some("widgets".to_string()),
                    singular: Some("widget".to_string()),
                    kind: Some("Widget".to_string()),
                    list_kind: Some("WidgetList".to_string()),
                    short_names: vec!["wg".to_string()],
                    categories: vec!["all".to_string()],
                }),
                versions: vec![apiext_v1::CustomResourceDefinitionVersion {
                    name: Some("v1".to_string()),
                    served: Some(true),
                    storage: Some(true),
                    deprecated: Some(true),
                    deprecation_warning: Some("use v2".to_string()),
                    schema: Some(apiext_v1::CustomResourceValidation {
                        open_apiv3_schema: Some(apiext_v1::JsonSchemaProps {
                            r#type: Some("object".to_string()),
                            description: Some("a widget".to_string()),
                            required: vec!["size".to_string()],
                            properties: [(
                                "size".to_string(),
                                apiext_v1::JsonSchemaProps {
                                    r#type: Some("string".to_string()),
                                    ..Default::default()
                                },
                            )]
                            .into_iter()
                            .collect(),
                            x_kubernetes_preserve_unknown_fields: Some(true),
                            x_kubernetes_validations: vec![apiext_v1::ValidationRule {
                                rule: Some("self.size != ''".to_string()),
                                message: Some("size must not be empty".to_string()),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                    }),
                    subresources: Some(apiext_v1::CustomResourceSubresources {
                        status: Some(apiext_v1::CustomResourceSubresourceStatus {}),
                        scale: Some(apiext_v1::CustomResourceSubresourceScale {
                            spec_replicas_path: Some(".spec.replicas".to_string()),
                            status_replicas_path: Some(".status.replicas".to_string()),
                            label_selector_path: Some(".status.selector".to_string()),
                        }),
                    }),
                    additional_printer_columns: vec![apiext_v1::CustomResourceColumnDefinition {
                        name: Some("Size".to_string()),
                        r#type: Some("string".to_string()),
                        json_path: Some(".spec.size".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                preserve_unknown_fields: Some(true),
                conversion: Some(apiext_v1::CustomResourceConversion {
                    strategy: Some("Webhook".to_string()),
                    webhook: Some(apiext_v1::WebhookConversion {
                        conversion_review_versions: vec!["v1".to_string()],
                        client_config: Some(apiext_v1::WebhookClientConfig {
                            url: Some("https://example.com/convert".to_string()),
                            ca_bundle: Some(b"test-ca-cert-bytes".to_vec()),
                            service: Some(apiext_v1::ServiceReference {
                                namespace: Some("default".to_string()),
                                name: Some("convert-svc".to_string()),
                                path: Some("/convert".to_string()),
                                port: Some(443),
                            }),
                        }),
                    }),
                }),
            }),
            status: Some(apiext_v1::CustomResourceDefinitionStatus {
                conditions: vec![apiext_v1::CustomResourceDefinitionCondition {
                    r#type: Some("Established".to_string()),
                    status: Some("True".to_string()),
                    reason: Some("InitialNamesAccepted".to_string()),
                    ..Default::default()
                }],
                accepted_names: Some(apiext_v1::CustomResourceDefinitionNames {
                    plural: Some("widgets".to_string()),
                    kind: Some("Widget".to_string()),
                    ..Default::default()
                }),
                stored_versions: vec!["v1".to_string()],
                ..Default::default()
            }),
        };
        let mut buf = Vec::new();
        crd.encode(&mut buf).unwrap();

        let result = decode_crd_proto_gen(&buf).expect("CRD must decode");

        assert_eq!(
            result["spec"]["group"], "example.com",
            "spec.group must survive — it is half of the CRD's identity (name = <plural>.<group>)"
        );
        assert_eq!(
            result["spec"]["names"]["plural"], "widgets",
            "spec.names.plural must survive — it determines the REST path clients hit"
        );
        assert_eq!(
            result["spec"]["versions"][0]["name"], "v1",
            "version name must survive — kubectl/clients pin to a specific served version"
        );
        assert_eq!(
            result["spec"]["versions"][0]["deprecated"], true,
            "deprecated must survive — dropping it silently removes the client warning header"
        );
        assert_eq!(
            result["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["size"]
                ["type"],
            "string",
            "nested schema properties must survive — this is the validation contract for custom resources"
        );
        assert_eq!(
            result["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["required"][0], "size",
            "required must survive — dropping it silently makes a mandatory field optional"
        );
        assert_eq!(
            result["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
                ["x-kubernetes-validations"][0]["rule"],
            "self.size != ''",
            "CEL validation rules must survive — dropping them silently disables admission validation"
        );
        assert_eq!(
            result["spec"]["versions"][0]["subresources"]["scale"]["specReplicasPath"],
            ".spec.replicas",
            "scale subresource paths must survive — HPA reads/writes through them"
        );
        assert_eq!(
            result["spec"]["versions"][0]["additionalPrinterColumns"][0]["name"], "Size",
            "printer columns must survive — kubectl get output depends on them"
        );
        assert_eq!(
            result["spec"]["conversion"]["webhook"]["clientConfig"]["service"]["name"],
            "convert-svc",
            "webhook service reference must survive — a dropped conversion webhook breaks multi-version CRDs"
        );
        assert_eq!(
            result["spec"]["conversion"]["webhook"]["clientConfig"]["caBundle"],
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"test-ca-cert-bytes"
            ),
            "caBundle must survive a protobuf-encoded CRD create/update (client-go's typed \
             apiextensions clientset sends protobuf by default) — otherwise every conversion \
             webhook registered via a real Kubernetes client loses its trust anchor and every \
             call fails TLS verification against the apiserver's cluster-CA-only fallback"
        );
        assert_eq!(
            result["status"]["conditions"][0]["type"], "Established",
            "status.conditions must survive a protobuf PUT — otherwise the Established/NamesAccepted \
             controller reads back an empty list and never converges"
        );
        assert_eq!(
            result["status"]["acceptedNames"]["plural"], "widgets",
            "status.acceptedNames must survive — clients discover CRD names from here"
        );
        assert_eq!(
            result["status"]["storedVersions"][0], "v1",
            "status.storedVersions must survive — it drives the etcd storage-migration path"
        );
        assert!(
            result["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["nullable"].is_null(),
            "nullable must stay absent when unset — a spurious false would make clients treat a \
             field as explicitly non-nullable when the schema author never said so"
        );
        assert!(
            result["spec"]["versions"][0]["additionalPrinterColumns"][0]["priority"].is_null(),
            "printer column priority must stay absent when unset — emitting a spurious 0 is \
             indistinguishable from an explicit priority=0 column"
        );
    }

    #[test]
    fn decode_delete_options_proto_gen_preserves_propagation_and_dry_run_by_construction() {
        let opts = meta_v1::DeleteOptions {
            propagation_policy: Some("Foreground".to_string()),
            orphan_dependents: None,
            grace_period_seconds: Some(30),
            dry_run: vec!["All".to_string()],
            preconditions: Some(meta_v1::Preconditions {
                uid: Some("target-uid".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        opts.encode(&mut buf).unwrap();

        let result = decode_delete_options_proto_gen(&buf).expect("DeleteOptions must decode");

        assert_eq!(
            result["propagationPolicy"], "Foreground",
            "propagationPolicy must survive — Foreground vs Background changes deletion ordering \
             semantics for dependents"
        );
        assert_eq!(
            result["gracePeriodSeconds"], 30,
            "gracePeriodSeconds must survive — a dropped grace period forces immediate deletion \
             instead of the client-requested delay"
        );
        assert_eq!(
            result["dryRun"][0], "All",
            "dryRun must survive — dropping it would let a dry-run delete actually persist"
        );
        assert!(
            result["orphanDependents"].is_null(),
            "orphanDependents must stay absent when the caller never set it — a spurious false \
             is indistinguishable from an explicit opt-out of orphaning, corrupting garbage \
             collection intent"
        );
        assert_eq!(
            result["preconditions"]["uid"], "target-uid",
            "preconditions.uid must survive — dropping it turns a client's conditional delete \
             (used by the GC controller to avoid racing a recreate) into an unconditional one"
        );
    }

    // ---- Sentinel completeness ----
    //
    // Each test below builds a message with every field set to a value no zero/empty-elision
    // check in this file's gen_*_to_json functions could mistake for "unset" (see
    // u7s_sentinel::Sentinel), decodes it through the real decode_*_proto_gen entry point, and
    // asserts every field name shows up somewhere in the resulting JSON. A name that never
    // appears means some gen_*_to_json function never reads that field from the decoded
    // protobuf struct at all — this is exactly how CustomResourceDefinitionVersion's
    // selectableFields, CustomResourceDefinitionStatus's/CustomResourceDefinitionCondition's
    // observedGeneration, and DeleteOptions's preconditions were found missing from this file.
    //
    // JsonSchemaProps nests itself (properties/allOf/items/etc. all eventually contain another
    // JsonSchemaProps), which without u7s_sentinel::sentinel_guard would make `.sentinel()`
    // recurse forever; see crates/sentinel/tests/recursion.rs for the regression test covering
    // that guard directly.

    use std::collections::BTreeSet;
    use u7s_sentinel::Sentinel;

    use crate::util::sentinel_test_util::{assert_fields_present, collect_leaf_paths};

    // selfLink is a legacy field the system no longer populates — permanently omitted.
    // deletionTimestamp/deletionGracePeriodSeconds/managedFields are left off `expected`
    // pending a separate investigation into gen_object_meta_to_json's correct handling of
    // them (this file's copy has the same omissions as every other gen_adapter's); do not
    // guess at the fix here.
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

    #[test]
    fn sentinel_completeness_decode_crd_proto_gen() {
        let crd = apiext_v1::CustomResourceDefinition {
            metadata: Some(meta_v1::ObjectMeta::sentinel()),
            spec: Some(apiext_v1::CustomResourceDefinitionSpec::sentinel()),
            status: Some(apiext_v1::CustomResourceDefinitionStatus::sentinel()),
        };
        let mut buf = Vec::new();
        crd.encode(&mut buf).unwrap();
        let mut decoded = decode_crd_proto_gen(&buf)
            .expect("sentinel CustomResourceDefinition must decode via the generated path");

        // JsonSchemaProps' own completeness is covered in isolation by the test below; blank
        // it here so a dropped CRD-structural field that happens to share a name with a
        // JsonSchemaProps field (type/format/description also appear on
        // additionalPrinterColumns entries and status conditions) can't hide behind the
        // schema's own copy still being present somewhere in the tree.
        if let Some(schema_obj) = decoded
            .get_mut("spec")
            .and_then(|s| s.get_mut("versions"))
            .and_then(|v| v.get_mut(0))
            .and_then(|v0| v0.get_mut("schema"))
            .and_then(|s| s.as_object_mut())
        {
            schema_obj.insert("openAPIV3Schema".to_string(), serde_json::json!({}));
        }

        let mut paths = BTreeSet::new();
        collect_leaf_paths(&decoded, "", &mut paths);

        let mut expected = OBJECT_META_EXPECTED.to_vec();
        expected.extend([
            "group",
            "scope",
            // "names"/"versions"/"schema"/"subresources"/"scale"/"additionalPrinterColumns"/
            // "selectableFields"/"conversion"/"webhook"/"clientConfig"/"service"/"conditions"/
            // "acceptedNames" are containers whose own field name is never itself a real leaf
            // once populated — each is dropped here in favor of the genuine leaf children below,
            // which already fully exercise it (a decoder that dropped the whole container would
            // drop its children too, and this list would still catch that).
            "plural",
            "singular",
            // "kind" deliberately excluded: names.kind/acceptedNames.kind would be masked by
            // the envelope's own top-level "kind": "CustomResourceDefinition" literal, so a
            // dropped names.kind could never fail this check.
            "listKind",
            "shortNames",
            "categories",
            "name",
            "served",
            "storage",
            "deprecated",
            "deprecationWarning",
            "openAPIV3Schema",
            "status",
            "specReplicasPath",
            "statusReplicasPath",
            "labelSelectorPath",
            "type",
            "jsonPath",
            "format",
            "description",
            "priority",
            "preserveUnknownFields",
            "strategy",
            "conversionReviewVersions",
            "caBundle",
            "url",
            "namespace",
            "path",
            "port",
            "reason",
            "message",
            "lastTransitionTime",
            "observedGeneration",
            "storedVersions",
        ]);
        assert_fields_present(&paths, &expected);
    }

    #[test]
    fn sentinel_completeness_gen_json_schema_props_to_json() {
        let mut schema = apiext_v1::JsonSchemaProps::sentinel();
        // Json.raw is arbitrary sentinel bytes, which gen_json_raw_to_value silently (and
        // correctly) drops if they don't parse as JSON — give default/example/enum real JSON
        // so decode_crd_proto_gen's handling of them is actually exercised (mirrors
        // apps_gen_adapter.rs's ControllerRevision.data handling for the same
        // RawExtension/Json-shaped gotcha).
        schema.default = Some(apiext_v1::Json {
            raw: Some(br#"{"d":1}"#.to_vec()),
        });
        schema.example = Some(apiext_v1::Json {
            raw: Some(br#"{"e":2}"#.to_vec()),
        });
        schema.r#enum = vec![apiext_v1::Json {
            raw: Some(br#"{"v":3}"#.to_vec()),
        }];

        let crd = apiext_v1::CustomResourceDefinition {
            spec: Some(apiext_v1::CustomResourceDefinitionSpec {
                versions: vec![apiext_v1::CustomResourceDefinitionVersion {
                    schema: Some(apiext_v1::CustomResourceValidation {
                        open_apiv3_schema: Some(schema),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut buf = Vec::new();
        crd.encode(&mut buf).unwrap();
        let decoded = decode_crd_proto_gen(&buf)
            .expect("sentinel JsonSchemaProps must decode via the generated path");

        let mut paths = BTreeSet::new();
        collect_leaf_paths(
            &decoded["spec"]["versions"][0]["schema"]["openAPIV3Schema"],
            "",
            &mut paths,
        );

        let expected = [
            "type",
            "description",
            "format",
            "title",
            "$ref",
            "id",
            "$schema",
            "pattern",
            "maximum",
            "exclusiveMaximum",
            "minimum",
            "exclusiveMinimum",
            "maxLength",
            "minLength",
            "maxItems",
            "minItems",
            "uniqueItems",
            "multipleOf",
            "maxProperties",
            "minProperties",
            "nullable",
            "x-kubernetes-preserve-unknown-fields",
            "x-kubernetes-embedded-resource",
            "x-kubernetes-int-or-string",
            "x-kubernetes-list-type",
            "x-kubernetes-map-type",
            "x-kubernetes-list-map-keys",
            "required",
            // Containers below (properties/patternProperties/definitions/dependencies/allOf/
            // items/etc.) are never real JSON *leaves* once populated — a nested JsonSchemaProps
            // is a non-empty struct, so only a dotted descendant leaf can survive strict
            // leaf-path matching. "properties"/"patternProperties"/"definitions" bottom out to
            // `{}` here because they self-reference JsonSchemaProps and `sentinel_guard` short-
            // circuits the re-entrant construction, so their sentinel-populated map key
            // ("__sentinel__", from u7s_sentinel's blanket `Sentinel for String`) is itself the
            // deepest real leaf.
            "default.d",
            "enum.v",
            "example.e",
            "properties.__sentinel__",
            "patternProperties.__sentinel__",
            "definitions.__sentinel__",
            // "schema"/"property" are JSONSchemaPropsOrStringArray's own two fields, reached
            // through "dependencies" — both are already-passing bare suffix matches, kept as-is.
            "schema",
            "property",
            "additionalProperties",
            "additionalItems",
            "allOf",
            "oneOf",
            "anyOf",
            "not",
            "externalDocs.description",
            "url",
            "x-kubernetes-validations.rule",
            "message",
            "messageExpression",
            "reason",
            "fieldPath",
            "optionalOldSelf",
        ];
        assert_fields_present(&paths, &expected);
    }

    // ---- Field-omission: all-default proto must decode with no stray nulls ----

    use crate::util::sentinel_test_util::assert_no_stray_nulls;

    #[test]
    fn decode_crd_proto_gen_omits_unset_status_instead_of_emitting_null() {
        let crd = apiext_v1::CustomResourceDefinition::default();
        let mut buf = Vec::new();
        crd.encode(&mut buf).unwrap();
        let decoded =
            decode_crd_proto_gen(&buf).expect("all-default CustomResourceDefinition must decode");

        // This adapter deliberately special-cases creationTimestamp to `""` instead of the
        // `null` every other adapter emits (see decode_crd_proto_gen's fixup) — no allow-list
        // entry needed here, so any null this test does find is a genuine bug.
        assert_no_stray_nulls(&decoded, &[]);
        assert_eq!(
            decoded["metadata"]["creationTimestamp"], "",
            "CRD creationTimestamp must be an empty string, never null, when unset — this \
             adapter's own established convention, verified so a future refactor toward the \
             other adapters' null convention doesn't slip in unnoticed"
        );
        assert!(
            decoded.get("status").is_none(),
            "an unset CustomResourceDefinitionStatus must be absent, not null — a controller \
             that treats `status != null` as \"has been reconciled at least once\" would \
             otherwise treat a brand-new CRD as already established"
        );
    }

    #[test]
    fn decode_delete_options_proto_gen_omits_all_unset_fields_instead_of_emitting_null() {
        let opts = meta_v1::DeleteOptions::default();
        let mut buf = Vec::new();
        opts.encode(&mut buf).unwrap();
        let decoded =
            decode_delete_options_proto_gen(&buf).expect("all-default DeleteOptions must decode");

        assert_no_stray_nulls(&decoded, &[]);
        let keys: Vec<&String> = decoded.as_object().unwrap().keys().collect();
        assert_eq!(
            keys.len(),
            2,
            "an all-default DeleteOptions must only carry apiVersion/kind ({keys:?}) — a \
             spurious `orphanDependents: false` or `gracePeriodSeconds: 0` key would be \
             indistinguishable from a client's explicit request to disable orphaning or force \
             immediate deletion"
        );
    }
}
