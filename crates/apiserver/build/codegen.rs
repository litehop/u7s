//! Walks the `FileDescriptorSet` `build.rs` already emits (see `config.file_descriptor_set_path`
//! in `build.rs`) and emits a JSON<->proto codec for a single message as a `.rs` file under
//! `OUT_DIR`, spliced into the crate via `include!` — see `src/core_gen_adapter.rs`.
//!
//! `generate_object_reference` (Phase 0) is scoped to `.k8s.io.api.core.v1.ObjectReference`
//! only: its 7 fields are all `optional string` with no renames/inline-embeds/omissions.
//! `generate_volume_source` (Phase 1) extends this to `.k8s.io.api.core.v1.VolumeSource`, whose
//! ~30 fields are each themselves `optional <SomeVolumeType>Source` messages — the first type in
//! this migration needing `Option<Message>` field handling, not just scalars.
//!
//! `RENAMES`/`INLINE_EMBEDS`/`OPAQUE_MESSAGES`/`DELIBERATE_OMISSIONS`/`KNOWN_GAPS` and the
//! `json_key`/`is_excluded`/`is_inline_embed` helpers built on them live in
//! `src/proto_exceptions.rs`, shared verbatim (via `include!`, not `mod`) with
//! `src/proto_descriptor.rs`'s `#[cfg(test)]` sentinel-completeness oracle — a build script
//! cannot `use` anything from the crate it is building, so textual inclusion is the only way
//! both consumers share the same exception data without one duplicating the other.

use heck::{ToSnakeCase, ToUpperCamelCase};
use prost::Message;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorSet};
use std::fmt::Write as _;

include!("../src/proto_exceptions.rs");

/// Depth-first search for `fq_name` (e.g. `.k8s.io.api.core.v1.ObjectReference`) among a
/// `FileDescriptorSet`'s top-level and nested message types. Mirrors the recursion shape of
/// `src/proto_descriptor.rs::message_index`/`insert_message`, minus the index — this module only
/// ever looks up a handful of messages per generated file.
fn find_message<'a>(set: &'a FileDescriptorSet, fq_name: &str) -> &'a DescriptorProto {
    for file in &set.file {
        let package = format!(".{}", file.package());
        for message in &file.message_type {
            if let Some(found) = search_nested(message, &package, fq_name) {
                return found;
            }
        }
    }
    panic!("message {fq_name} not found in descriptor set");
}

fn search_nested<'a>(
    message: &'a DescriptorProto,
    prefix: &str,
    fq_name: &str,
) -> Option<&'a DescriptorProto> {
    let full_name = format!("{prefix}.{}", message.name());
    if full_name == fq_name {
        return Some(message);
    }
    message
        .nested_type
        .iter()
        .find_map(|nested| search_nested(nested, &full_name, fq_name))
}

/// prost renames every generated struct field to Rust's snake_case regardless of how the proto
/// declares it (`k8s.io/api`'s own style is camelCase, e.g. `apiVersion`), using `heck` — see
/// `prost-build`'s own `ident::to_snake` (`s.to_snake_case()`, from the same `heck` crate).
/// Calling the identical `heck` function is what makes this correct for names like `scaleIO`
/// (-> `scale_io`) that a naive "insert `_` before each uppercase" rule mishandles.
///
/// A snake_cased field name that collides with a Rust keyword (`HostPathVolumeSource.type` is
/// the one VolumeSource has today) additionally needs `prost-build`'s `r#` raw-identifier escape
/// (`ident::sanitize_identifier`) — without it the generated code would reference a field named
/// `type` as a bare keyword, which doesn't parse.
fn rust_field_name(proto_field_name: &str) -> String {
    let snake = proto_field_name.to_snake_case();
    if is_rust_keyword(&snake) {
        format!("r#{snake}")
    } else {
        snake
    }
}

/// Strict + reserved keywords per the Rust reference, minus `_`/`self`/`Self`/`super`/`extern`/
/// `crate` (which prost-build suffixes with `_` instead of using `r#` — not reachable by any
/// current or plausible future VolumeSource field name, so left unhandled rather than copied
/// speculatively).
fn is_rust_keyword(s: &str) -> bool {
    matches!(
        s,
        "as" | "break"
            | "const"
            | "continue"
            | "else"
            | "enum"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "static"
            | "struct"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "dyn"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "async"
            | "await"
            | "try"
            | "gen"
    )
}

/// prost's generated struct/enum name for a proto message, e.g. `ISCSIVolumeSource` ->
/// `IscsiVolumeSource`, `ScaleIOVolumeSource` -> `ScaleIoVolumeSource` — see `prost-build`'s own
/// `ident::to_upper_camel` (`s.to_upper_camel_case()`, same `heck` crate). `fq_type_name` is a
/// fully-qualified descriptor name (e.g. `.k8s.io.api.core.v1.ISCSIVolumeSource`); only the last
/// segment matters since none of the messages this module reaches are nested types.
fn rust_message_type_name(fq_type_name: &str) -> String {
    fq_type_name
        .rsplit('.')
        .next()
        .expect("fully-qualified type name always has at least one segment")
        .to_upper_camel_case()
}

/// The fully-qualified Rust path a generated decoder must use to build a message-typed field's
/// struct literal, e.g. `.k8s.io.api.core.v1.ContainerPort` -> `core_v1::ContainerPort`,
/// `.k8s.io.apimachinery.pkg.apis.meta.v1.LabelSelector` -> `meta_v1::LabelSelector`. Every
/// message Phase 0/1's VolumeSource walker ever reached lived in `core/v1`, so hardcoding
/// `core_v1::` at the one call site that builds a struct-literal header was invisible until
/// Phase 2's `TopologySpreadConstraint.labelSelector` reached `meta/v1` for the first time.
fn rust_message_path(fq_type_name: &str) -> String {
    let name = rust_message_type_name(fq_type_name);
    if fq_type_name.starts_with(".k8s.io.api.core.v1.") {
        format!("core_v1::{name}")
    } else if fq_type_name.starts_with(".k8s.io.apimachinery.pkg.apis.meta.v1.") {
        format!("meta_v1::{name}")
    } else {
        panic!(
            "{fq_type_name} is outside the k8s.io.api.core.v1/k8s.io.apimachinery.pkg.apis.meta.v1 \
             packages this codegen module's mechanical decode walker knows the Rust module alias \
             for — add the new package's alias here"
        )
    }
}

/// Generates the `gen_object_reference_to_json`/`json_to_object_reference_proto` pair, matching
/// field-for-field the hand-rolled functions they replace. Panics rather than silently
/// mis-generating if a future proto vendor-bump gives `ObjectReference` a non-string field — this
/// spike's codegen only knows the `Option<String>` shape, by design (see module doc).
pub fn generate_object_reference(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let owner = ".k8s.io.api.core.v1.ObjectReference";
    let message = find_message(&set, owner);

    let fields: Vec<(String, String)> = message
        .field
        .iter()
        .map(|field| {
            assert_eq!(
                field.r#type(),
                Type::String,
                "ObjectReference.{} is not a string field — this codegen only handles the \
                 all-scalar-string shape ObjectReference had when this spike was written",
                field.name()
            );
            (
                rust_field_name(field.name()),
                json_key(owner, field.name(), field.json_name()),
            )
        })
        .collect();

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str(
        "fn gen_object_reference_to_json(r: core_v1::ObjectReference) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    for (rust_name, key) in &fields {
        writeln!(
            out,
            "    if let Some(v) = r.{rust_name}.filter(|s| !s.is_empty()) {{"
        )
        .unwrap();
        writeln!(
            out,
            "        m.insert(\"{key}\".to_string(), serde_json::Value::String(v));"
        )
        .unwrap();
        out.push_str("    }\n");
    }
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n\n");

    out.push_str(
        "fn json_to_object_reference_proto(v: &serde_json::Value) -> core_v1::ObjectReference {\n",
    );
    out.push_str("    core_v1::ObjectReference {\n");
    for (rust_name, key) in &fields {
        writeln!(out, "        {rust_name}: jstr(v, \"{key}\"),").unwrap();
    }
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

const VOLUME_SOURCE: &str = ".k8s.io.api.core.v1.VolumeSource";
const VOLUME: &str = ".k8s.io.api.core.v1.Volume";
const QUANTITY: &str = ".k8s.io.apimachinery.pkg.api.resource.Quantity";

/// VolumeSource fields with zero implementation today, matched against the hand-rolled
/// `json_to_volume_proto`/`gen_pod_spec_to_json` this codegen replaces before it was deleted.
/// `generate_volume_source`'s per-field loop below asserts this list and
/// `proto_exceptions.rs`'s DELIBERATE_OMISSIONS name exactly the same VolumeSource fields — the
/// other ~15 in-tree volume plugins DELIBERATE_OMISSIONS used to also list (iscsi/glusterfs/rbd/
/// gitRepo/cinder/cephfs/flexVolume/flocker/azureFile/vsphereVolume/quobyte/azureDisk/
/// portworxVolume/scaleIO/storageos) are pinned as supported by
/// `encode_pod_proto_gen_round_trips_rare_deprecated_volume_sources` /
/// `decode_pod_proto_gen_round_trips_rare_deprecated_volume_sources` (core_gen_adapter.rs),
/// round-tripping through real protobuf bytes, so they were pruned from DELIBERATE_OMISSIONS
/// rather than kept as a table/code divergence.
const EXCLUDED_FIELDS: &[&str] = &[
    "awsElasticBlockStore",
    "gcePersistentDisk",
    "photonPersistentDisk",
    "fc",
];

/// VolumeSource fields whose current JSON<->proto mapping is not the uniform "one message field,
/// walk its own scalar/list/map sub-fields, always emit once the Option is Some" shape the
/// mechanical walker below assumes:
///   - `secret`/`configMap`/`persistentVolumeClaim`/`csi` only emit their JSON key when a
///     specific identifying sub-field survives (secretName / the embedded LocalObjectReference's
///     name / claimName / driver) rather than whenever the outer Option is Some — a per-field
///     business rule with no proto-schema signal to derive it from.
///   - `ephemeral` reconstructs an embedded `PersistentVolumeClaim` object rather than mirroring
///     its own proto fields directly.
///   - `downwardAPI`/`projected` are themselves union-shaped repeated-message lists (their own
///     encoders are reused by `projected.sources[]`'s own downwardAPI/configMap projections),
///     already-existing standalone functions this codegen just needs to call correctly.
///
/// Each maps to a `gen_*_to_json`/`json_to_*_proto` pair in `core_gen_adapter.rs` — pre-existing
/// for downwardAPI/projected, extracted verbatim (zero logic change) from the inline closures
/// this codegen deletes for the rest. Returns `(encode_statement, decode_expression)` source
/// text to splice directly into the generated functions.
fn delegated_field_templates(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "secret" => Some((
            "if let Some(x0) = src.secret { \
                if let Some(j) = gen_secret_volume_source_to_json(x0) { \
                    vm.insert(\"secret\".to_string(), j); \
                } \
             }",
            "v.get(\"secret\").map(json_to_secret_volume_source_proto)",
        )),
        "configMap" => Some((
            "if let Some(x0) = src.config_map { \
                if let Some(j) = gen_config_map_volume_source_to_json(x0) { \
                    vm.insert(\"configMap\".to_string(), j); \
                } \
             }",
            "v.get(\"configMap\").map(json_to_config_map_volume_source_proto)",
        )),
        "persistentVolumeClaim" => Some((
            "if let Some(x0) = src.persistent_volume_claim { \
                if let Some(j) = gen_persistent_volume_claim_volume_source_to_json(x0) { \
                    vm.insert(\"persistentVolumeClaim\".to_string(), j); \
                } \
             }",
            "v.get(\"persistentVolumeClaim\").map(json_to_persistent_volume_claim_volume_source_proto)",
        )),
        "downwardAPI" => Some((
            "if let Some(x0) = src.downward_api { \
                vm.insert(\"downwardAPI\".to_string(), \
                    gen_downward_api_volume_source_to_json(x0.items, x0.default_mode)); \
             }",
            "v.get(\"downwardAPI\").map(json_to_downward_api_volume_source_proto)",
        )),
        "projected" => Some((
            "if let Some(x0) = src.projected { \
                vm.insert(\"projected\".to_string(), gen_projected_volume_source_to_json(x0)); \
             }",
            "v.get(\"projected\").map(json_to_projected_volume_source_proto)",
        )),
        "ephemeral" => Some((
            "if let Some(x0) = src.ephemeral { \
                if let Some(j) = gen_ephemeral_volume_source_to_json(x0) { \
                    vm.insert(\"ephemeral\".to_string(), j); \
                } \
             }",
            "v.get(\"ephemeral\").and_then(json_to_ephemeral_volume_source_proto)",
        )),
        "csi" => Some((
            "if let Some(x0) = src.csi { \
                if let Some(j) = gen_csi_volume_source_to_json(x0) { \
                    vm.insert(\"csi\".to_string(), j); \
                } \
             }",
            "v.get(\"csi\").map(json_to_csi_volume_source_proto)",
        )),
        _ => None,
    }
}

/// Is `field` a protoc-synthesized `map<string, string>` entry? Maps are wire-encoded as
/// `repeated <Entry> field = N` with a nested `Entry { key, value }` message carrying
/// `options.map_entry = true` — mirrors `src/proto_descriptor.rs::map_value_type`'s detection,
/// narrowed to the one map shape (`map<string, string>`) VolumeSource's mechanical fields use
/// (`FlexVolumeSource.options`).
fn is_string_map_field(set: &FileDescriptorSet, field: &FieldDescriptorProto) -> bool {
    field.r#type() == Type::Message && {
        let entry = find_message(set, field.type_name());
        entry.options.as_ref().is_some_and(|o| o.map_entry())
    }
}

/// Is `field` a protoc-synthesized `map<string, Quantity>` entry (`ResourceRequirements.limits`,
/// `ContainerStatus.allocatedResources`, `PodSpec.overhead`, ...)? Checked ahead of
/// `is_string_map_field` in the dispatch below: both detect a `map_entry` submessage, but only
/// this one additionally confirms the map's `value` field is `Quantity` rather than assuming
/// `String` — `is_string_map_field`'s existing callers only ever reach a `map<string, string>`
/// field, so it never needed the distinction; Phase 2's owners have both shapes.
fn is_quantity_map_field(set: &FileDescriptorSet, field: &FieldDescriptorProto) -> bool {
    field.r#type() == Type::Message && {
        let entry = find_message(set, field.type_name());
        entry.options.as_ref().is_some_and(|o| o.map_entry())
            && entry
                .field
                .iter()
                .any(|f| f.name() == "value" && f.type_name() == QUANTITY)
    }
}

/// Emits the encode-direction (proto -> JSON) statements for `message`'s own fields, reading
/// from `value_var` (an already-unwrapped `Option::Some` binding) and writing into `map_var`. A
/// nested message-typed field (VolumeSource's `secretRef: Option<LocalObjectReference>` fields)
/// recurses one level deeper with fresh `x{depth}`/`m{depth}` names — required because, unlike
/// VolumeSource's own top-level fields (always inserted once `Option` is `Some`, matching
/// `generate_volume_source`'s own unconditional insert below), a nested field is only inserted
/// if the object it recurses into ends up non-empty (e.g. a `secretRef` with no `name` is
/// dropped entirely, not emitted as `{}` — matches every hand-rolled `secretRef` branch this
/// replaces). Thin loop over `emit_field_encode`, which does the actual per-field dispatch — kept
/// separate so Phase 2's generators (`generate_container`/`generate_pod_spec`/...) can call it for
/// one field at a time, skipping the fields their own delegation tables already cover.
fn emit_mechanical_encode(
    set: &FileDescriptorSet,
    owner: &str,
    message: &DescriptorProto,
    value_var: &str,
    map_var: &str,
    depth: u32,
    out: &mut String,
) {
    for field in &message.field {
        emit_field_encode(set, owner, field, value_var, map_var, depth, out);
    }
}

/// Emits one field's encode-direction statement. See `emit_mechanical_encode` for the recursion
/// shape this dispatches into; see `field_decode_rhs` for the decode-direction mirror.
///
/// `repeated Message` (not a map) is Phase 2's addition over Phase 1's VolumeSource walker
/// (which never needed it — VolumeSource's own fields are all singular): iterates the vec,
/// recursing into each element as its own fresh `x{depth}`/`m{depth}` object, always pushing the
/// element (even a `{}` one) rather than filtering it — matching every hand-rolled repeated-struct
/// field this walker replaces (`hostAliases`, `tolerations`, `resourceClaims`, ...), none of which
/// skip degenerate elements. The outer key is still only inserted if the resulting array is
/// non-empty, matching the vec's own emptiness rather than each element's.
fn emit_field_encode(
    set: &FileDescriptorSet,
    owner: &str,
    field: &FieldDescriptorProto,
    value_var: &str,
    map_var: &str,
    depth: u32,
    out: &mut String,
) {
    let key = json_key(owner, field.name(), field.json_name());
    let rust_field = rust_field_name(field.name());
    let repeated = field.label() == Label::Repeated;
    match field.r#type() {
        Type::String if repeated => {
            writeln!(out, "    if !{value_var}.{rust_field}.is_empty() {{").unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Array({value_var}.{rust_field}.into_iter().map(serde_json::Value::String).collect()));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::String => {
            writeln!(
                out,
                "    if let Some(v) = {value_var}.{rust_field}.filter(|s| !s.is_empty()) {{"
            )
            .unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::String(v));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Bool => {
            writeln!(out, "    if let Some(v) = {value_var}.{rust_field} {{").unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Bool(v));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Int32 | Type::Int64 if repeated => {
            writeln!(out, "    if !{value_var}.{rust_field}.is_empty() {{").unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Array({value_var}.{rust_field}.into_iter().map(|n| serde_json::Value::Number(n.into())).collect()));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Int32 | Type::Int64 => {
            writeln!(out, "    if let Some(v) = {value_var}.{rust_field} {{").unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Number(v.into()));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Message if repeated && is_quantity_map_field(set, field) => {
            writeln!(out, "    if !{value_var}.{rust_field}.is_empty() {{").unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), gen_quantity_map_to_json({value_var}.{rust_field}));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Message if repeated && is_string_map_field(set, field) => {
            writeln!(out, "    if !{value_var}.{rust_field}.is_empty() {{").unwrap();
            writeln!(
                out,
                "        let attrs: serde_json::Map<String, serde_json::Value> = {value_var}.{rust_field}.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect();"
            )
            .unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Object(attrs));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Message if field.type_name() == QUANTITY => {
            writeln!(
                out,
                "    if let Some(v) = {value_var}.{rust_field}.and_then(|q| q.string).filter(|s| !s.is_empty()) {{"
            )
            .unwrap();
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::String(v));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Message if repeated => {
            let nested = find_message(set, field.type_name());
            let item_var = format!("x{}", depth + 1);
            let item_map = format!("m{}", depth + 1);
            writeln!(out, "    if !{value_var}.{rust_field}.is_empty() {{").unwrap();
            writeln!(out, "        let mut arr = Vec::new();").unwrap();
            writeln!(out, "        for {item_var} in {value_var}.{rust_field} {{").unwrap();
            writeln!(
                out,
                "            let mut {item_map} = serde_json::Map::new();"
            )
            .unwrap();
            emit_mechanical_encode(
                set,
                field.type_name(),
                nested,
                &item_var,
                &item_map,
                depth + 1,
                out,
            );
            writeln!(
                out,
                "            arr.push(serde_json::Value::Object({item_map}));"
            )
            .unwrap();
            out.push_str("        }\n");
            writeln!(
                out,
                "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Array(arr));"
            )
            .unwrap();
            out.push_str("    }\n");
        }
        Type::Message => {
            let nested = find_message(set, field.type_name());
            let nested_value = format!("x{}", depth + 1);
            let nested_map = format!("m{}", depth + 1);
            writeln!(
                out,
                "    if let Some({nested_value}) = {value_var}.{rust_field} {{"
            )
            .unwrap();
            writeln!(
                out,
                "        let mut {nested_map} = serde_json::Map::new();"
            )
            .unwrap();
            emit_mechanical_encode(
                set,
                field.type_name(),
                nested,
                &nested_value,
                &nested_map,
                depth + 1,
                out,
            );
            writeln!(out, "        if !{nested_map}.is_empty() {{").unwrap();
            writeln!(
                out,
                "            {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Object({nested_map}));"
            )
            .unwrap();
            out.push_str("        }\n");
            out.push_str("    }\n");
        }
        other => panic!(
            "{owner}.{} has a shape ({other:?}, repeated={repeated}) the mechanical codegen \
             walker doesn't know how to handle — add the owning top-level field to this type's \
             delegated-field table in build/codegen.rs, or extend the walker",
            field.name(),
        ),
    }
}

/// Emits the decode-direction (JSON -> proto) struct-literal expression for `message`, reading
/// keys off `value_var` (an already-in-scope `&serde_json::Value`). Thin loop over
/// `field_decode_rhs`, which computes the per-field right-hand side — see that function's doc for
/// the shape dispatch, and `emit_mechanical_encode`'s doc for why depth-suffixed variable names
/// are threaded through.
fn emit_mechanical_decode(
    set: &FileDescriptorSet,
    owner: &str,
    message: &DescriptorProto,
    rust_type_path: &str,
    value_var: &str,
    depth: u32,
    out: &mut String,
) {
    writeln!(out, "{rust_type_path} {{").unwrap();
    for field in &message.field {
        let rust_field = rust_field_name(field.name());
        let rhs = field_decode_rhs(set, owner, field, value_var, depth);
        writeln!(out, "    {rust_field}: {rhs},").unwrap();
    }
    out.push('}');
}

/// Computes one field's decode-direction right-hand-side expression (the value assigned to that
/// field in the enclosing struct literal). See `emit_field_encode` for the encode-direction
/// mirror and the doc on why `repeated Message` (not a map) recurses via a closure over a fresh
/// `v{depth}` per element instead of the singular-nested-message `.map(...)` shape.
fn field_decode_rhs(
    set: &FileDescriptorSet,
    owner: &str,
    field: &FieldDescriptorProto,
    value_var: &str,
    depth: u32,
) -> String {
    let key = json_key(owner, field.name(), field.json_name());
    let repeated = field.label() == Label::Repeated;
    match field.r#type() {
        Type::String if repeated => format!("jstrs({value_var}, \"{key}\")"),
        Type::String => format!("jstr({value_var}, \"{key}\")"),
        Type::Bool => format!("jbool({value_var}, \"{key}\")"),
        Type::Int32 if repeated => format!(
            "{value_var}.get(\"{key}\").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|n| n.as_i64()).map(|n| n as i32).collect()).unwrap_or_default()"
        ),
        Type::Int32 => format!("ji32({value_var}, \"{key}\")"),
        Type::Int64 if repeated => format!(
            "{value_var}.get(\"{key}\").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|n| n.as_i64()).collect()).unwrap_or_default()"
        ),
        Type::Int64 => format!("ji64({value_var}, \"{key}\")"),
        Type::Message if repeated && is_quantity_map_field(set, field) => {
            format!("json_quantity_map_to_proto({value_var}, \"{key}\")")
        }
        Type::Message if repeated && is_string_map_field(set, field) => {
            format!("jstrmap({value_var}, \"{key}\")")
        }
        Type::Message if field.type_name() == QUANTITY => format!(
            "jstr({value_var}, \"{key}\").map(|s| super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {{ string: Some(s) }})"
        ),
        Type::Message if repeated => {
            let nested = find_message(set, field.type_name());
            let nested_rust_type = rust_message_path(field.type_name());
            let item_var = format!("v{}", depth + 1);
            let mut item_expr = String::new();
            emit_mechanical_decode(
                set,
                field.type_name(),
                nested,
                &nested_rust_type,
                &item_var,
                depth + 1,
                &mut item_expr,
            );
            format!(
                "{value_var}.get(\"{key}\").and_then(|a| a.as_array()).map(|a| a.iter().map(|{item_var}| {item_expr}).collect()).unwrap_or_default()"
            )
        }
        Type::Message => {
            let nested = find_message(set, field.type_name());
            let nested_rust_type = rust_message_path(field.type_name());
            let nested_var = format!("v{}", depth + 1);
            let mut nested_expr = String::new();
            emit_mechanical_decode(
                set,
                field.type_name(),
                nested,
                &nested_rust_type,
                &nested_var,
                depth + 1,
                &mut nested_expr,
            );
            format!("{value_var}.get(\"{key}\").map(|{nested_var}| {nested_expr})")
        }
        other => panic!(
            "{owner}.{} has a shape ({other:?}, repeated={repeated}) the mechanical codegen \
             walker doesn't know how to handle — add the owning top-level field to this type's \
             delegated-field table in build/codegen.rs, or extend the walker",
            field.name(),
        ),
    }
}

/// Generates the `gen_volume_to_json`/`json_to_volume_proto` pair that fully replaces the
/// hand-rolled `json_to_volume_proto` and the volume branch of `gen_pod_spec_to_json`.
///
/// Walks every declared field of `VolumeSource` (~30, zero proto `oneof` — upstream models "one
/// of N volume types" as N ordinary optional message fields) and classifies each one:
///   - `EXCLUDED_FIELDS`: no branch emitted at all (`awsElasticBlockStore` is the canonical
///     example: DELIBERATE_OMISSIONS-listed, genuinely unimplemented, asserted below).
///   - `delegated_field_templates`: a fixed call into a hand-written `core_gen_adapter.rs`
///     helper (secret/configMap/persistentVolumeClaim/downwardAPI/projected/ephemeral/csi).
///   - everything else: walked mechanically by `emit_mechanical_encode`/`emit_mechanical_decode`
///     — this is the common case, and the one a future proto vendor-bump's new field lands in by
///     default (see PROOF-OF-SCALE below).
///
/// `Volume.volumeSource` is an `INLINE_EMBEDS` entry (asserted below): `VolumeSource`'s fields
/// land directly on the `Volume` JSON object (`{"name": ..., "hostPath": {...}}`), never nested
/// under a `"volumeSource"` key — `gen_volume_to_json` writes straight into the same `vm` map
/// `name` was inserted into, and `json_to_volume_proto` reads keys straight off the `Volume`'s
/// own JSON object (`v`), never a `v.get("volumeSource")` sub-object.
///
/// PROOF-OF-SCALE — what happens when `.k8s.io.api.core.v1.VolumeSource` gets a new field in a
/// future proto vendor-bump, e.g. a hypothetical `optional NewVolumeSource newVolumeType = 31`
/// where `NewVolumeSource` has a couple of `optional string`/`optional bool` fields (the shape
/// every real upstream addition to this message has had so far — see the 15 "rare/deprecated"
/// fields this bead's mechanical walker already covers with zero hand code beyond their initial
/// classification): the field loop below finds `newVolumeType` in neither `EXCLUDED_FIELDS` nor
/// `delegated_field_templates`, so it falls through to the mechanical branch — the
/// `assert_eq!(field.r#type(), Type::Message, ...)` a few lines down passes (every VolumeSource
/// field is message-typed), `find_message` resolves `NewVolumeSource`'s descriptor, and
/// `emit_mechanical_encode`/`emit_mechanical_decode` walk its `string`/`bool` fields the same way
/// they already walk `HostPathVolumeSource`/`IscsiVolumeSource`/etc — zero lines changed in this
/// file, zero hand-written code anywhere. Only if the new field's own shape needs something
/// outside `{string, bool, int32, repeated string, map<string,string>, one level of nested
/// message}` (a repeated message, an enum, a second level of nesting) does the walker's `panic!`
/// fire at build time, forcing an explicit `DELEGATED_FIELDS`/`EXCLUDED_FIELDS` decision instead
/// of silently mis-generating — this IS the fail-loud property the ObjectReference spike (Phase
/// 0) established for its own single assumption (all-scalar-string), extended here to the wider
/// but still-enumerable mechanical shape VolumeSource needs.
pub fn generate_volume_source(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VOLUME_SOURCE);

    assert!(
        is_inline_embed(VOLUME, "volumeSource"),
        "generate_volume_source assumes Volume.volumeSource is an INLINE_EMBEDS entry — if that \
         table entry is ever removed, gen_volume_to_json/json_to_volume_proto's calling \
         convention (writing into / reading off the Volume's own JSON object, not a nested \
         \"volumeSource\" key) needs to change to match"
    );

    let mut encode_stmts = String::new();
    let mut decode_fields = String::new();

    for field in &message.field {
        let name = field.name();

        let in_excluded_fields = EXCLUDED_FIELDS.contains(&name);
        let in_deliberate_omissions = is_excluded(VOLUME_SOURCE, name);
        assert_eq!(
            in_excluded_fields, in_deliberate_omissions,
            "{name}: codegen's local EXCLUDED_FIELDS ({in_excluded_fields}) and \
             proto_exceptions.rs's DELIBERATE_OMISSIONS ({in_deliberate_omissions}) disagree \
             for VolumeSource — the two lists must name exactly the same fields now that \
             DELIBERATE_OMISSIONS has no stale entries left, so any future drift in either \
             direction is caught at build time instead of silently misdescribing what's \
             implemented"
        );
        if in_excluded_fields {
            continue;
        }

        let rust_field = rust_field_name(name);
        let key = json_key(VOLUME_SOURCE, name, field.json_name());

        if let Some((encode, decode)) = delegated_field_templates(name) {
            encode_stmts.push_str("    ");
            encode_stmts.push_str(encode);
            encode_stmts.push('\n');
            writeln!(decode_fields, "        {rust_field}: {decode},").unwrap();
            continue;
        }

        assert_eq!(
            field.r#type(),
            Type::Message,
            "VolumeSource.{name} is not message-typed — the mechanical walker only knows how \
             to handle VolumeSource's own \"one message field per volume plugin\" shape"
        );
        let nested = find_message(&set, field.type_name());
        let rust_type = rust_message_path(field.type_name());

        writeln!(encode_stmts, "    if let Some(x0) = src.{rust_field} {{").unwrap();
        encode_stmts.push_str("        let mut m0 = serde_json::Map::new();\n");
        emit_mechanical_encode(
            &set,
            field.type_name(),
            nested,
            "x0",
            "m0",
            0,
            &mut encode_stmts,
        );
        writeln!(
            encode_stmts,
            "        vm.insert(\"{key}\".to_string(), serde_json::Value::Object(m0));"
        )
        .unwrap();
        encode_stmts.push_str("    }\n");

        let mut decode_expr = String::new();
        emit_mechanical_decode(
            &set,
            field.type_name(),
            nested,
            &rust_type,
            "v0",
            0,
            &mut decode_expr,
        );
        writeln!(
            decode_fields,
            "        {rust_field}: v.get(\"{key}\").map(|v0| {decode_expr}),"
        )
        .unwrap();
    }

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str("fn gen_volume_to_json(v: core_v1::Volume) -> serde_json::Value {\n");
    out.push_str("    let mut vm = serde_json::Map::new();\n");
    out.push_str("    if let Some(n) = v.name.filter(|s| !s.is_empty()) {\n");
    out.push_str("        vm.insert(\"name\".to_string(), serde_json::Value::String(n));\n");
    out.push_str("    }\n");
    out.push_str("    if let Some(src) = v.volume_source {\n");
    out.push_str(&encode_stmts);
    out.push_str("    }\n");
    out.push_str("    serde_json::Value::Object(vm)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_volume_proto(v: &serde_json::Value) -> core_v1::Volume {\n");
    out.push_str("    core_v1::Volume {\n");
    out.push_str("        name: jstr(v, \"name\"),\n");
    out.push_str("        volume_source: Some(core_v1::VolumeSource {\n");
    out.push_str(&decode_fields);
    // EXCLUDED_FIELDS have no entry above, so the literal needs a base value for them —
    // `Default::default()` gives every genuinely-omitted field `None`, matching a decoder that
    // never populates it.
    out.push_str("            ..Default::default()\n");
    out.push_str("        }),\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

const CONTAINER: &str = ".k8s.io.api.core.v1.Container";
const CONTAINER_STATUS: &str = ".k8s.io.api.core.v1.ContainerStatus";
const POD_SPEC: &str = ".k8s.io.api.core.v1.PodSpec";
const POD_STATUS: &str = ".k8s.io.api.core.v1.PodStatus";

/// Shared field-walking loop for Phase 2's four top-level types (`Container`/`ContainerStatus`/
/// `PodSpec`/`PodStatus`). Unlike `generate_volume_source`'s walk above (which only ever
/// delegates one specific field's own body before recursing into it), every field of these four
/// types that needs anything beyond the mechanical "if Some/non-empty, insert" default already
/// has an established, tested hand-written counterpart to call by name (`Probe`,
/// `SecurityContext`, `ResourceRequirements`, ...) or its own well-documented business rule
/// (`hostNetwork`'s true-only guard, `PodCondition`'s unconditional `type`/`status`) — so
/// delegation here is always whole-field, never a nested per-field override reached mid-walk.
/// Each of the four `generate_*` functions below supplies its own delegation table; a field with
/// no entry falls through to `emit_field_encode`/`field_decode_rhs`, which walk it (and, for a
/// nested or repeated message, everything reachable from it) the same way
/// `generate_volume_source` already does for `VolumeSource`'s own mechanical fields.
///
/// No `EXCLUDED_FIELDS` table is needed for any of the four owners here (unlike
/// `generate_volume_source`'s VolumeSource, whose ~15 legacy volume plugins are a deliberate u7s
/// policy decision): every field of `Container`/`ContainerStatus`/`PodSpec`/`PodStatus` is either
/// mechanically walkable or has a real, wanted JSON representation, confirmed against every
/// declared field in the vendored `.proto` before this function's delegation tables were written.
fn generate_message_codec(
    set: &FileDescriptorSet,
    owner: &str,
    message: &DescriptorProto,
    delegate: impl Fn(&str) -> Option<(&'static str, &'static str)>,
    value_var: &str,
    map_var: &str,
) -> (String, String) {
    let mut encode_stmts = String::new();
    let mut decode_fields = String::new();
    for field in &message.field {
        let name = field.name();
        let rust_field = rust_field_name(name);
        if let Some((encode, decode)) = delegate(name) {
            encode_stmts.push_str(encode);
            writeln!(decode_fields, "        {rust_field}: {decode},").unwrap();
            continue;
        }
        emit_field_encode(set, owner, field, value_var, map_var, 0, &mut encode_stmts);
        let rhs = field_decode_rhs(set, owner, field, "v", 0);
        writeln!(decode_fields, "        {rust_field}: {rhs},").unwrap();
    }
    (encode_stmts, decode_fields)
}

/// Generates the `gen_container_to_json`/`json_to_container_proto` pair that fully replaces the
/// hand-rolled functions of the same name — the first of the four "incident cluster" types
/// (mayor-13y4a) this codegen closes.
pub fn generate_container(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CONTAINER);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        CONTAINER,
        message,
        container_delegated_field,
        "c",
        "cm",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str("fn gen_container_to_json(c: core_v1::Container) -> serde_json::Value {\n");
    out.push_str("    let mut cm = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(cm)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_container_proto(v: &serde_json::Value) -> core_v1::Container {\n");
    out.push_str("    core_v1::Container {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// `Container` fields whose JSON shape needs more than `emit_field_encode`/`field_decode_rhs` can
/// derive on their own — each maps to an existing (or, for `ports`/`env`/`envFrom`/
/// `volumeMounts`, newly extracted) hand-written pair in `core_gen_adapter.rs`, with one
/// exception: `stdin`/`stdinOnce`/`tty` are plain (non-pointer), gogoproto-`nullable=false` bool
/// fields — the same class as `PodSpec.hostNetwork`/`hostPID`/`hostIPC` (see `hostNetwork`'s
/// generated-code call site in `pod_spec_delegated_field` for the full explanation) — so they
/// need the same true-only guard rather than the mechanical `Some`-gated default. Every other
/// `Container` field with no entry here is genuinely just "if Some/non-empty, insert", confirmed
/// against `generated.proto`'s `message Container` field-by-field.
fn container_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "stdin" => Some((
            "    if let Some(true) = c.stdin {\n        cm.insert(\"stdin\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"stdin\")",
        )),
        "stdinOnce" => Some((
            "    if let Some(true) = c.stdin_once {\n        cm.insert(\"stdinOnce\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"stdinOnce\")",
        )),
        "tty" => Some((
            "    if let Some(true) = c.tty {\n        cm.insert(\"tty\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"tty\")",
        )),
        "ports" => Some((
            "    if !c.ports.is_empty() {\n        cm.insert(\"ports\".to_string(), serde_json::Value::Array(c.ports.into_iter().map(gen_container_port_to_json).collect()));\n    }\n",
            "v.get(\"ports\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_port_proto).collect()).unwrap_or_default()",
        )),
        "env" => Some((
            "    if !c.env.is_empty() {\n        cm.insert(\"env\".to_string(), serde_json::Value::Array(c.env.into_iter().map(gen_env_var_to_json).collect()));\n    }\n",
            "v.get(\"env\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_env_var_proto).collect()).unwrap_or_default()",
        )),
        "envFrom" => Some((
            "    if !c.env_from.is_empty() {\n        cm.insert(\"envFrom\".to_string(), serde_json::Value::Array(c.env_from.into_iter().map(gen_env_from_source_to_json).collect()));\n    }\n",
            "v.get(\"envFrom\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_env_from_source_proto).collect()).unwrap_or_default()",
        )),
        "resources" => Some((
            "    if let Some(res) = c.resources {\n        let res_json = gen_resource_requirements_to_json(res);\n        if res_json.as_object().is_some_and(|m| !m.is_empty()) {\n            cm.insert(\"resources\".to_string(), res_json);\n        }\n    }\n",
            "v.get(\"resources\").map(json_to_resource_requirements_proto)",
        )),
        "livenessProbe" => Some((
            "    if let Some(p) = c.liveness_probe {\n        cm.insert(\"livenessProbe\".to_string(), gen_probe_to_json(p));\n    }\n",
            "v.get(\"livenessProbe\").map(json_to_probe_proto)",
        )),
        "readinessProbe" => Some((
            "    if let Some(p) = c.readiness_probe {\n        cm.insert(\"readinessProbe\".to_string(), gen_probe_to_json(p));\n    }\n",
            "v.get(\"readinessProbe\").map(json_to_probe_proto)",
        )),
        "startupProbe" => Some((
            "    if let Some(p) = c.startup_probe {\n        cm.insert(\"startupProbe\".to_string(), gen_probe_to_json(p));\n    }\n",
            "v.get(\"startupProbe\").map(json_to_probe_proto)",
        )),
        "lifecycle" => Some((
            "    if let Some(lc) = c.lifecycle {\n        cm.insert(\"lifecycle\".to_string(), gen_lifecycle_to_json(lc));\n    }\n",
            "v.get(\"lifecycle\").map(json_to_lifecycle_proto)",
        )),
        "securityContext" => Some((
            "    if let Some(sc) = c.security_context {\n        cm.insert(\"securityContext\".to_string(), gen_security_context_to_json(sc));\n    }\n",
            "v.get(\"securityContext\").map(json_to_security_context_proto)",
        )),
        "volumeMounts" => Some((
            "    if !c.volume_mounts.is_empty() {\n        cm.insert(\"volumeMounts\".to_string(), serde_json::Value::Array(c.volume_mounts.into_iter().map(gen_volume_mount_to_json).collect()));\n    }\n",
            "v.get(\"volumeMounts\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_volume_mount_proto).collect()).unwrap_or_default()",
        )),
        _ => None,
    }
}

const EPHEMERAL_CONTAINER_COMMON: &str = ".k8s.io.api.core.v1.EphemeralContainerCommon";

/// Generates the `gen_ephemeral_container_to_json`/`json_to_ephemeral_container_proto` pair,
/// replacing the hand-written functions of the same name (mayor-nxr7j) — the previous hand-rolled
/// `gen_ephemeral_container_to_json` had drifted to cover only 9 of `EphemeralContainerCommon`'s 24
/// fields, silently dropping `stdin`/`stdinOnce`/`tty` (and 14 others) from every protobuf-encoded
/// `kubectl debug -it` ephemeral-container update.
///
/// `EphemeralContainerCommon` declares the exact same field set as `Container` — its own .proto
/// comment says so verbatim ("EphemeralContainerCommon is a copy of all fields in Container...
/// When a new field is added to Container it must be added here as well"), confirmed field-by-field
/// against the compiled descriptor above — so this reuses `container_delegated_field` as-is rather
/// than duplicating its ports/env/envFrom/resources/probes/lifecycle/securityContext/volumeMounts/
/// stdin/stdinOnce/tty delegation table; any future field this bead's fix doesn't already cover
/// lands in that one shared table instead of needing a second hand-kept copy here.
///
/// Unlike `Container`, `EphemeralContainer` itself is a thin wrapper (`ephemeralContainerCommon` +
/// `targetContainerName`) whose `ephemeralContainerCommon` field is a Go inline embed
/// (`INLINE_EMBEDS`-listed in `proto_exceptions.rs`, asserted by `proto_descriptor.rs`'s
/// `inlines_ephemeralcontainercommon_fields_onto_ephemeralcontainer`): its fields land directly on
/// the same JSON object as `targetContainerName`, never nested under an `"ephemeralContainerCommon"`
/// key. So the generated functions below walk `EphemeralContainerCommon`'s fields into/out of the
/// very same map/value `targetContainerName` uses, the same way `generate_volume_source` inlines
/// `VolumeSource` straight onto `Volume` rather than nesting it.
pub fn generate_ephemeral_container(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, EPHEMERAL_CONTAINER_COMMON);
    // `value_var`/`map_var` must be "c"/"cm" — `container_delegated_field`'s delegated-field
    // templates hardcode those exact identifiers (see e.g. its "stdin" arm), so any other choice
    // here would leave the emitted code referencing an out-of-scope `c`/`cm`.
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        EPHEMERAL_CONTAINER_COMMON,
        message,
        container_delegated_field,
        "c",
        "cm",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str(
        "fn gen_ephemeral_container_to_json(ec: core_v1::EphemeralContainer) -> serde_json::Value {\n",
    );
    out.push_str("    let mut cm = serde_json::Map::new();\n");
    out.push_str("    if let Some(v) = ec.target_container_name.filter(|s| !s.is_empty()) {\n");
    out.push_str(
        "        cm.insert(\"targetContainerName\".to_string(), serde_json::Value::String(v));\n",
    );
    out.push_str("    }\n");
    out.push_str("    if let Some(c) = ec.ephemeral_container_common {\n");
    out.push_str(&encode_stmts);
    out.push_str("    }\n");
    out.push_str("    serde_json::Value::Object(cm)\n");
    out.push_str("}\n\n");

    out.push_str(
        "fn json_to_ephemeral_container_proto(v: &serde_json::Value) -> core_v1::EphemeralContainer {\n",
    );
    out.push_str("    core_v1::EphemeralContainer {\n");
    out.push_str("        target_container_name: jstr(v, \"targetContainerName\"),\n");
    out.push_str("        ephemeral_container_common: Some(core_v1::EphemeralContainerCommon {\n");
    out.push_str(&decode_fields);
    out.push_str("        }),\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// Generates the `gen_container_status_to_json`/`json_to_container_status_proto` pair.
pub fn generate_container_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CONTAINER_STATUS);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        CONTAINER_STATUS,
        message,
        container_status_delegated_field,
        "cs",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str(
        "fn gen_container_status_to_json(cs: core_v1::ContainerStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n\n");

    out.push_str(
        "fn json_to_container_status_proto(v: &serde_json::Value) -> core_v1::ContainerStatus {\n",
    );
    out.push_str("    core_v1::ContainerStatus {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// `ContainerStatus` fields needing more than the mechanical default: `state`/`lastState` (a
/// `ContainerState` union with its own RFC3339 time handling), `ready`/`restartCount` (plain,
/// non-pointer upstream fields Kubernetes always serializes including zero values, unlike every
/// optional field the mechanical walker assumes), `resources` (delegates to the same
/// `ResourceRequirements` encoder `Container`/`PodSpec`/`PodStatus` use), and `user` (only ever
/// emitted when the nested `linux` sub-message is present).
fn container_status_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "state" => Some((
            "    if let Some(state) = cs.state {\n        m.insert(\"state\".to_string(), gen_container_state_to_json(state));\n    }\n",
            "v.get(\"state\").map(json_to_container_state_proto)",
        )),
        "lastState" => Some((
            "    if let Some(state) = cs.last_state {\n        m.insert(\"lastState\".to_string(), gen_container_state_to_json(state));\n    }\n",
            "v.get(\"lastState\").map(json_to_container_state_proto)",
        )),
        "ready" => Some((
            "    m.insert(\"ready\".to_string(), serde_json::Value::Bool(cs.ready.unwrap_or(false)));\n",
            "jbool(v, \"ready\")",
        )),
        "restartCount" => Some((
            "    m.insert(\"restartCount\".to_string(), serde_json::Value::Number(cs.restart_count.unwrap_or(0).into()));\n",
            "ji32(v, \"restartCount\")",
        )),
        "resources" => Some((
            "    if let Some(res) = cs.resources {\n        m.insert(\"resources\".to_string(), gen_resource_requirements_to_json(res));\n    }\n",
            "v.get(\"resources\").map(json_to_resource_requirements_proto)",
        )),
        "user" => Some((
            "    if let Some(j) = cs.user.and_then(gen_container_user_to_json) {\n        m.insert(\"user\".to_string(), j);\n    }\n",
            "v.get(\"user\").map(json_to_container_user_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_pod_spec_to_json`/`json_to_pod_spec_proto` pair.
pub fn generate_pod_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POD_SPEC);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        POD_SPEC,
        message,
        pod_spec_delegated_field,
        "spec",
        "spec_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str(
        "pub(crate) fn gen_pod_spec_to_json(spec: core_v1::PodSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_pod_spec_proto(v: &serde_json::Value) -> core_v1::PodSpec {\n");
    out.push_str("    core_v1::PodSpec {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// `PodSpec` fields needing more than the mechanical default: `volumes`/`containers`/
/// `initContainers`/`ephemeralContainers` delegate to their own (generated or hand-written)
/// per-element encoders; `containers` alone is unconditionally emitted (upstream has no
/// `omitempty` on it — a Pod always has at least one container). `activeDeadlineSeconds`/
/// `hostNetwork`/`hostPID`/`hostIPC` preserve business-rule guards (a positive-only filter and
/// a true-only filter, the latter documented at length on `hostNetwork`'s own generated-code
/// call site) no schema annotation encodes. `imagePullSecrets`/`readinessGates`/`schedulingGates` project one field
/// out of their element type and skip elements missing it. `affinity`/`securityContext`/
/// `resources`/`os`/`schedulingGroup` delegate to existing (or, for the two single-field structs,
/// inline) converters.
fn pod_spec_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "volumes" => Some((
            "    if !spec.volumes.is_empty() {\n        spec_map.insert(\"volumes\".to_string(), serde_json::Value::Array(spec.volumes.into_iter().map(gen_volume_to_json).collect()));\n    }\n",
            "v.get(\"volumes\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_volume_proto).collect()).unwrap_or_default()",
        )),
        "containers" => Some((
            "    {\n        let containers: Vec<serde_json::Value> = spec.containers.into_iter().map(gen_container_to_json).collect();\n        spec_map.insert(\"containers\".to_string(), serde_json::Value::Array(containers));\n    }\n",
            "v.get(\"containers\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_proto).collect()).unwrap_or_default()",
        )),
        "initContainers" => Some((
            "    if !spec.init_containers.is_empty() {\n        spec_map.insert(\"initContainers\".to_string(), serde_json::Value::Array(spec.init_containers.into_iter().map(gen_container_to_json).collect()));\n    }\n",
            "v.get(\"initContainers\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_proto).collect()).unwrap_or_default()",
        )),
        "ephemeralContainers" => Some((
            "    if !spec.ephemeral_containers.is_empty() {\n        spec_map.insert(\"ephemeralContainers\".to_string(), serde_json::Value::Array(spec.ephemeral_containers.into_iter().map(gen_ephemeral_container_to_json).collect()));\n    }\n",
            "v.get(\"ephemeralContainers\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_ephemeral_container_proto).collect()).unwrap_or_default()",
        )),
        "activeDeadlineSeconds" => Some((
            "    if let Some(ads) = spec.active_deadline_seconds {\n        if ads > 0 {\n            spec_map.insert(\"activeDeadlineSeconds\".to_string(), serde_json::Value::Number(serde_json::Number::from(ads)));\n        }\n    }\n",
            "ji64(v, \"activeDeadlineSeconds\")",
        )),
        "imagePullSecrets" => Some((
            "    if !spec.image_pull_secrets.is_empty() {\n        let refs: Vec<serde_json::Value> = spec.image_pull_secrets.into_iter().filter_map(|r| r.name.filter(|s| !s.is_empty())).map(|name| serde_json::json!({ \"name\": name })).collect();\n        spec_map.insert(\"imagePullSecrets\".to_string(), serde_json::Value::Array(refs));\n    }\n",
            "v.get(\"imagePullSecrets\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_local_object_reference_proto).collect()).unwrap_or_default()",
        )),
        "affinity" => Some((
            "    if let Some(affinity) = spec.affinity {\n        let mut am = serde_json::Map::new();\n        if let Some(na) = affinity.node_affinity {\n            am.insert(\"nodeAffinity\".to_string(), gen_node_affinity_to_json(na));\n        }\n        if let Some(pa) = affinity.pod_affinity {\n            am.insert(\"podAffinity\".to_string(), gen_pod_affinity_to_json(pa));\n        }\n        if let Some(paa) = affinity.pod_anti_affinity {\n            am.insert(\"podAntiAffinity\".to_string(), gen_pod_anti_affinity_to_json(paa));\n        }\n        spec_map.insert(\"affinity\".to_string(), serde_json::Value::Object(am));\n    }\n",
            "v.get(\"affinity\").map(json_to_affinity_proto)",
        )),
        "readinessGates" => Some((
            "    if !spec.readiness_gates.is_empty() {\n        let gates: Vec<serde_json::Value> = spec.readiness_gates.into_iter().filter_map(|g| g.condition_type.filter(|s| !s.is_empty())).map(|ct| serde_json::json!({ \"conditionType\": ct })).collect();\n        spec_map.insert(\"readinessGates\".to_string(), serde_json::Value::Array(gates));\n    }\n",
            "v.get(\"readinessGates\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_pod_readiness_gate_proto).collect()).unwrap_or_default()",
        )),
        "os" => Some((
            "    if let Some(name) = spec.os.and_then(|os| os.name).filter(|s| !s.is_empty()) {\n        spec_map.insert(\"os\".to_string(), serde_json::json!({ \"name\": name }));\n    }\n",
            "jstr(v.get(\"os\").unwrap_or(&serde_json::Value::Null), \"name\").map(|name| core_v1::PodOs { name: Some(name) })",
        )),
        "resources" => Some((
            "    if let Some(res) = spec.resources {\n        spec_map.insert(\"resources\".to_string(), gen_resource_requirements_to_json(res));\n    }\n",
            "v.get(\"resources\").map(json_to_resource_requirements_proto)",
        )),
        "schedulingGroup" => Some((
            "    if let Some(pgn) = spec.scheduling_group.and_then(|sg| sg.pod_group_name).filter(|s| !s.is_empty()) {\n        spec_map.insert(\"schedulingGroup\".to_string(), serde_json::json!({ \"podGroupName\": pgn }));\n    }\n",
            "v.get(\"schedulingGroup\").and_then(|sg| jstr(sg, \"podGroupName\")).map(|pgn| core_v1::PodSchedulingGroup { pod_group_name: Some(pgn) })",
        )),
        "securityContext" => Some((
            "    if let Some(sc) = spec.security_context {\n        spec_map.insert(\"securityContext\".to_string(), gen_pod_security_context_to_json(sc));\n    }\n",
            "v.get(\"securityContext\").map(json_to_pod_security_context_proto)",
        )),
        "hostNetwork" => Some((
            "    if let Some(true) = spec.host_network {\n        spec_map.insert(\"hostNetwork\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"hostNetwork\")",
        )),
        // hostPID/hostIPC are the same plain (non-pointer), gogoproto-`nullable=false` bool
        // class as hostNetwork just above — see that field's guard for the full explanation.
        // A real client-go protobuf write always puts an explicit `false` for either on the
        // wire even when the caller never touched them, so without this true-only guard a
        // metadata-only PUT resubmitted through a protobuf client fabricates "hostPID: false"/
        // "hostIPC: false" on a pod that never had the key, which validate_pod_spec_immutable's
        // whole-spec deep-equal then rejects as a spec change that never happened (mayor-swxjj,
        // 3rd recurrence of the RC/Job label-only-PUT immutability regression, mayor-y6gtg).
        "hostPID" => Some((
            "    if let Some(true) = spec.host_pid {\n        spec_map.insert(\"hostPID\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"hostPID\")",
        )),
        "hostIPC" => Some((
            "    if let Some(true) = spec.host_ipc {\n        spec_map.insert(\"hostIPC\".to_string(), serde_json::Value::Bool(true));\n    }\n",
            "jbool(v, \"hostIPC\")",
        )),
        "schedulingGates" => Some((
            "    if !spec.scheduling_gates.is_empty() {\n        let gates: Vec<serde_json::Value> = spec.scheduling_gates.into_iter().filter_map(|g| g.name.filter(|s| !s.is_empty())).map(|name| serde_json::json!({ \"name\": name })).collect();\n        spec_map.insert(\"schedulingGates\".to_string(), serde_json::Value::Array(gates));\n    }\n",
            "v.get(\"schedulingGates\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_scheduling_gate_proto).collect()).unwrap_or_default()",
        )),
        _ => None,
    }
}

/// Generates the `gen_pod_status_to_json`/`json_to_pod_status_proto` pair.
pub fn generate_pod_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POD_STATUS);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        POD_STATUS,
        message,
        pod_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");

    out.push_str("fn gen_pod_status_to_json(status: core_v1::PodStatus) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_pod_status_proto(v: &serde_json::Value) -> core_v1::PodStatus {\n");
    out.push_str("    core_v1::PodStatus {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");

    out
}

/// `PodStatus` fields needing more than the mechanical default: `observedGeneration` (a
/// positive-only filter, the same class of guard as `PodSpec.activeDeadlineSeconds`),
/// `conditions` (unconditional `type`/`status` plus RFC3339 time conversion, see
/// `gen_pod_condition_to_json`), `hostIPs`/`podIPs` (project the element's `ip` field and skip
/// elements missing it), `startTime` (a bare `metav1.Time`, the same opaque-scalar handling
/// `Quantity` gets), the three container-status arrays (delegate to `ContainerStatus`'s own
/// generated codec), and `resources` (delegates to the shared `ResourceRequirements` encoder).
fn pod_status_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "observedGeneration" => Some((
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
            "ji64(v, \"observedGeneration\")",
        )),
        "conditions" => Some((
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_pod_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
            "v.get(\"conditions\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_pod_condition_proto).collect()).unwrap_or_default()",
        )),
        "hostIPs" => Some((
            "    if !status.host_i_ps.is_empty() {\n        let ips: Vec<serde_json::Value> = status.host_i_ps.into_iter().filter_map(|h| h.ip.filter(|s| !s.is_empty())).map(|ip| serde_json::json!({ \"ip\": ip })).collect();\n        if !ips.is_empty() {\n            m.insert(\"hostIPs\".to_string(), serde_json::Value::Array(ips));\n        }\n    }\n",
            "v.get(\"hostIPs\").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|ip| jstr(ip, \"ip\")).map(|ip| core_v1::HostIp { ip: Some(ip) }).collect()).unwrap_or_default()",
        )),
        "podIPs" => Some((
            "    if !status.pod_i_ps.is_empty() {\n        let ips: Vec<serde_json::Value> = status.pod_i_ps.into_iter().filter_map(|p| p.ip.filter(|s| !s.is_empty())).map(|ip| serde_json::json!({ \"ip\": ip })).collect();\n        if !ips.is_empty() {\n            m.insert(\"podIPs\".to_string(), serde_json::Value::Array(ips));\n        }\n    }\n",
            "v.get(\"podIPs\").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|ip| jstr(ip, \"ip\")).map(|ip| core_v1::PodIp { ip: Some(ip) }).collect()).unwrap_or_default()",
        )),
        "startTime" => Some((
            "    if let Some(secs) = status.start_time.and_then(|t| t.seconds) {\n        m.insert(\"startTime\".to_string(), serde_json::Value::String(crate::util::secs_to_rfc3339(secs)));\n    }\n",
            "jtime(v, \"startTime\")",
        )),
        "initContainerStatuses" => Some((
            "    if !status.init_container_statuses.is_empty() {\n        m.insert(\"initContainerStatuses\".to_string(), serde_json::Value::Array(status.init_container_statuses.into_iter().map(gen_container_status_to_json).collect()));\n    }\n",
            "v.get(\"initContainerStatuses\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_status_proto).collect()).unwrap_or_default()",
        )),
        "containerStatuses" => Some((
            "    if !status.container_statuses.is_empty() {\n        m.insert(\"containerStatuses\".to_string(), serde_json::Value::Array(status.container_statuses.into_iter().map(gen_container_status_to_json).collect()));\n    }\n",
            "v.get(\"containerStatuses\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_status_proto).collect()).unwrap_or_default()",
        )),
        "ephemeralContainerStatuses" => Some((
            "    if !status.ephemeral_container_statuses.is_empty() {\n        m.insert(\"ephemeralContainerStatuses\".to_string(), serde_json::Value::Array(status.ephemeral_container_statuses.into_iter().map(gen_container_status_to_json).collect()));\n    }\n",
            "v.get(\"ephemeralContainerStatuses\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_status_proto).collect()).unwrap_or_default()",
        )),
        "resources" => Some((
            "    if let Some(res) = status.resources {\n        m.insert(\"resources\".to_string(), gen_resource_requirements_to_json(res));\n    }\n",
            "v.get(\"resources\").map(json_to_resource_requirements_proto)",
        )),
        _ => None,
    }
}

const NAMESPACE: &str = ".k8s.io.api.core.v1.Namespace";
const NAMESPACE_STATUS: &str = ".k8s.io.api.core.v1.NamespaceStatus";
const CONFIG_MAP: &str = ".k8s.io.api.core.v1.ConfigMap";
const SECRET: &str = ".k8s.io.api.core.v1.Secret";

/// Field-walking loop for a message type with no matching `encode_*_proto_gen` entry point in
/// `core_gen_adapter.rs` — `Namespace`/`ConfigMap`/`Secret` (Phase 3.1) are decode-only kinds
/// today (compare `core_gen_adapter.rs`'s `pub fn decode_*_proto_gen` list against its
/// `pub fn encode_*_proto_gen` list: none of these three appear in the latter), so generating a
/// `json_to_*_proto` decode-direction pair alongside them the way `generate_message_codec` does
/// for `Container`/`PodSpec`/etc. would be genuinely dead code — never called, and
/// `cargo clippy --tests -D warnings` would fail the build on it. Mirrors
/// `generate_message_codec`'s delegate-or-mechanical dispatch but only ever calls
/// `emit_field_encode`, never `field_decode_rhs`.
fn generate_message_encode_only(
    set: &FileDescriptorSet,
    owner: &str,
    message: &DescriptorProto,
    delegate: impl Fn(&str) -> Option<&'static str>,
    value_var: &str,
    map_var: &str,
) -> String {
    let mut encode_stmts = String::new();
    for field in &message.field {
        if let Some(encode) = delegate(field.name()) {
            encode_stmts.push_str(encode);
            continue;
        }
        emit_field_encode(set, owner, field, value_var, map_var, 0, &mut encode_stmts);
    }
    encode_stmts
}

/// Generates `gen_namespace_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_namespace_proto_gen` this Phase 3.1 migration retires. The entry point itself stays
/// hand-written in `core_gen_adapter.rs`: it decodes the proto bytes and stamps
/// `apiVersion`/`kind`, neither of which exist on the wire for this message.
pub fn generate_namespace(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, NAMESPACE);
    let encode_stmts = generate_message_encode_only(
        &set,
        NAMESPACE,
        message,
        namespace_delegated_field,
        "ns",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_namespace_to_json(ns: core_v1::Namespace) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` is `.k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta` on every top-level Kind this
/// codegen module reaches — the first time Phase 3 has walked a *whole* Kind (Namespace/
/// ConfigMap/Secret) rather than a spec/status sub-message, since Phase 0-2's VolumeSource/
/// Container/ContainerStatus/PodSpec/PodStatus are all themselves nested under a Kind's own
/// `spec`/`status`, never `metadata` itself. `ObjectMeta.creationTimestamp` is a `Time`-typed
/// field needing RFC3339 conversion plus an always-emit-defaulting-to-null rule the mechanical
/// walker's generic `Type::Message` branch doesn't know, and 4 of `ObjectMeta`'s fields are
/// `DELIBERATE_OMISSIONS`'d for compensating-control reasons (see `proto_exceptions.rs`) — so
/// `metadata` routes to the existing hand-written `gen_object_meta_to_json` instead, the same
/// call the hand-rolled decoder this replaces already made. `spec` needs no delegate entry:
/// `NamespaceSpec` has a single `repeated string finalizers` field, which the mechanical walker
/// already handles correctly (only emits the `spec` key once `finalizers` is non-empty, matching
/// the hand-rolled `if !spec.finalizers.is_empty()` guard exactly). `status` delegates to the
/// separately generated `gen_namespace_status_to_json` (`generate_namespace_status` below)
/// because `NamespaceStatus.conditions` needs its own delegate one level down — this mechanical
/// walker has no per-field override hook at a recursion depth below the type it was invoked for.
fn namespace_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(ns.metadata.unwrap_or_default()));\n",
        ),
        "status" => Some(
            "    if let Some(status) = ns.status {\n        let status_json = gen_namespace_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_namespace_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_namespace_proto_gen` this migration retires — including the PANIC-1 fix
/// (see `core_gen_adapter.rs`'s `gen_namespace_condition_to_json` doc and the
/// `namespace_status_proto_decode_preserves_phase_and_conditions` regression test): this
/// function's existence is what makes `status` reachable at all from
/// `decode_namespace_proto_gen` post-migration.
pub fn generate_namespace_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, NAMESPACE_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        NAMESPACE_STATUS,
        message,
        namespace_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_namespace_status_to_json(status: core_v1::NamespaceStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `conditions`' `type`/`status` are unconditionally emitted (even empty) — matching upstream's
/// non-`omitempty` JSON tags — and `lastTransitionTime` is a bare `Time` needing RFC3339
/// conversion, neither of which the mechanical walker's generic `Type::Message`
/// (`NamespaceCondition` itself) or `Type::String` (`type`/`status`) branches know how to do, so
/// `conditions` delegates wholesale to the hand-written `gen_namespace_condition_to_json` — the
/// same shape `pod_status_delegated_field`'s own `conditions` entry already established for
/// `PodCondition`. `phase` needs no entry: a plain `optional string` the mechanical walker
/// already handles.
fn namespace_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_namespace_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_configmap_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_configmap_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why).
pub fn generate_configmap(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CONFIG_MAP);
    let encode_stmts = generate_message_encode_only(
        &set,
        CONFIG_MAP,
        message,
        configmap_delegated_field,
        "cm",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_configmap_to_json(cm: core_v1::ConfigMap) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry.
/// `binaryData` is a `map<string, bytes>` field — the mechanical walker's existing map-entry
/// detector (`is_string_map_field`) only checks for a `map_entry` submessage, not its value
/// type, so it would mis-generate `binaryData` as a `map<string, string>` (a build-time type
/// error against `Vec<u8>`, not a silent bug — but a delegate is still needed to emit the base64
/// encoding this field's JSON form actually requires). `immutable`/`data` need no entry: a plain
/// `optional bool` and a genuine `map<string, string>` the mechanical walker already handles
/// correctly.
fn configmap_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(cm.metadata.unwrap_or_default()));\n",
        ),
        "binaryData" => Some(
            "    if !cm.binary_data.is_empty() {\n        use base64::Engine;\n        let binary_data_map: serde_json::Map<String, serde_json::Value> = cm.binary_data.into_iter().map(|(k, v)| (k, serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)))).collect();\n        obj.insert(\"binaryData\".to_string(), serde_json::Value::Object(binary_data_map));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_secret_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_secret_proto_gen` this migration retires (the entry point itself stays hand-written —
/// see `generate_namespace`'s doc for why).
pub fn generate_secret(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SECRET);
    let encode_stmts = generate_message_encode_only(
        &set,
        SECRET,
        message,
        secret_delegated_field,
        "secret",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_secret_to_json(secret: core_v1::Secret) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `data`
/// is a `map<string, bytes>` field (same shape/reason as `ConfigMap.binaryData` above).
/// `immutable`/`stringData`/`type` need no entry: a plain `optional bool`, a genuine
/// `map<string, string>`, and a plain `optional string` (on the Rust-keyword-escaped `r#type`
/// field — `rust_field_name` already handles this) the mechanical walker handles correctly.
fn secret_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(secret.metadata.unwrap_or_default()));\n",
        ),
        "data" => Some(
            "    if !secret.data.is_empty() {\n        use base64::Engine;\n        let data_map: serde_json::Map<String, serde_json::Value> = secret.data.into_iter().map(|(k, v)| (k, serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&v)))).collect();\n        obj.insert(\"data\".to_string(), serde_json::Value::Object(data_map));\n    }\n",
        ),
        _ => None,
    }
}

const RESOURCE_QUOTA: &str = ".k8s.io.api.core.v1.ResourceQuota";
const RESOURCE_QUOTA_SPEC: &str = ".k8s.io.api.core.v1.ResourceQuotaSpec";

/// `ScopedResourceSelectorRequirement`'s per-item `scopeName`/`operator` fields are
/// unconditionally emitted (see `core_gen_adapter.rs::gen_scope_selector_to_json`'s doc) — a
/// per-field override one level below `ResourceQuotaSpec` itself, which the repeated-message
/// branch `emit_field_encode` uses for `ScopeSelector.matchExpressions` has no delegate hook for
/// (the same limitation `namespace_status_delegated_field`'s own `conditions` entry documents),
/// so `scopeSelector` delegates wholesale to the hand-written function instead. `hard`/`scopes`
/// need no entry: a `map<string, Quantity>` and a `repeated string` the mechanical walker already
/// handles correctly.
fn resourcequota_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "scopeSelector" => Some(
            "    if let Some(ss) = spec.scope_selector {\n        let ss_json = gen_scope_selector_to_json(ss);\n        if ss_json.as_object().is_some_and(|m| !m.is_empty()) {\n            m.insert(\"scopeSelector\".to_string(), ss_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_resourcequota_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_resourcequota_proto_gen` this migration retires.
pub fn generate_resourcequota_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, RESOURCE_QUOTA_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        RESOURCE_QUOTA_SPEC,
        message,
        resourcequota_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_resourcequota_spec_to_json(spec: core_v1::ResourceQuotaSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`
/// delegates to the separately generated `gen_resourcequota_spec_to_json` above because
/// `ResourceQuotaSpec.scopeSelector` needs its own delegate one level down (see
/// `resourcequota_spec_delegated_field`'s doc). `status` needs no entry: upstream's quota
/// controller (`pkg/controller/resourcequota`) calls `ResourceQuotas(ns).UpdateStatus(...)` every
/// reconcile using protobuf content-type by default, so `status.hard`/`status.used` must survive
/// this decode path — but both are plain `map<string, Quantity>` fields, which the mechanical
/// walker's generic nested-`Type::Message` recursion already handles correctly at any depth (no
/// per-field override needed one level down, unlike `spec`).
fn resourcequota_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(rq.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = rq.spec {\n        let spec_json = gen_resourcequota_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_resourcequota_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_resourcequota_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why).
pub fn generate_resourcequota(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, RESOURCE_QUOTA);
    let encode_stmts = generate_message_encode_only(
        &set,
        RESOURCE_QUOTA,
        message,
        resourcequota_delegated_field,
        "rq",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_resourcequota_to_json(rq: core_v1::ResourceQuota) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const LIMIT_RANGE: &str = ".k8s.io.api.core.v1.LimitRange";
const LIMIT_RANGE_SPEC: &str = ".k8s.io.api.core.v1.LimitRangeSpec";

/// `LimitRangeItem.type` is unconditionally emitted (see
/// `core_gen_adapter.rs::gen_limit_range_item_to_json`'s doc) — the same per-item-override
/// limitation `resourcequota_spec_delegated_field` documents for `scopeSelector` — so `limits`
/// delegates wholesale to the hand-written per-item function.
fn limitrange_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "limits" => Some(
            "    if !spec.limits.is_empty() {\n        let limits: Vec<serde_json::Value> = spec.limits.into_iter().map(gen_limit_range_item_to_json).collect();\n        m.insert(\"limits\".to_string(), serde_json::Value::Array(limits));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_limitrange_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_limitrange_proto_gen` this migration retires.
pub fn generate_limitrange_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LIMIT_RANGE_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        LIMIT_RANGE_SPEC,
        message,
        limitrange_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_limitrange_spec_to_json(spec: core_v1::LimitRangeSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`
/// delegates to the separately generated `gen_limitrange_spec_to_json` above because
/// `LimitRangeSpec.limits` needs its own delegate one level down (see
/// `limitrange_spec_delegated_field`'s doc).
fn limitrange_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(lr.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = lr.spec {\n        let spec_json = gen_limitrange_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_limitrange_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_limitrange_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why).
pub fn generate_limitrange(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LIMIT_RANGE);
    let encode_stmts = generate_message_encode_only(
        &set,
        LIMIT_RANGE,
        message,
        limitrange_delegated_field,
        "lr",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_limitrange_to_json(lr: core_v1::LimitRange) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const REPLICATION_CONTROLLER: &str = ".k8s.io.api.core.v1.ReplicationController";
const REPLICATION_CONTROLLER_SPEC: &str = ".k8s.io.api.core.v1.ReplicationControllerSpec";
const REPLICATION_CONTROLLER_STATUS: &str = ".k8s.io.api.core.v1.ReplicationControllerStatus";

/// `replicas` is unconditionally emitted, defaulting to 0 (matching the hand-rolled body this
/// migration replaces exactly — upstream's own `+default=1` doc notwithstanding, since this
/// decoder has never treated an absent `replicas` as anything other than 0 on the wire).
/// `minReadySeconds` is a zero-filtered `optional int32`, the same class of guard as
/// `PodStatus.observedGeneration`. `template` delegates to the existing hand-written
/// `gen_pod_template_spec_to_json`. `selector` needs no entry: a genuine `map<string, string>`
/// the mechanical walker already handles correctly.
fn replicationcontroller_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    spec_map.insert(\"replicas\".to_string(), serde_json::Value::Number(spec.replicas.unwrap_or(0).into()));\n",
        ),
        "minReadySeconds" => Some(
            "    if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {\n        spec_map.insert(\"minReadySeconds\".to_string(), serde_json::Value::Number(v.into()));\n    }\n",
        ),
        "template" => Some(
            "    if let Some(tmpl) = spec.template {\n        spec_map.insert(\"template\".to_string(), gen_pod_template_spec_to_json(tmpl));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_replicationcontroller_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_replicationcontroller_proto_gen` this migration retires.
pub fn generate_replicationcontroller_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICATION_CONTROLLER_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICATION_CONTROLLER_SPEC,
        message,
        replicationcontroller_spec_delegated_field,
        "spec",
        "spec_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_replicationcontroller_spec_to_json(spec: core_v1::ReplicationControllerSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n");
    out
}

/// The five int fields (`replicas`/`fullyLabeledReplicas`/`observedGeneration`/`readyReplicas`/
/// `availableReplicas`) are all zero-filtered, the same class of guard as
/// `PodStatus.observedGeneration`. `conditions` needs its own per-item delegate (see
/// `core_gen_adapter.rs::gen_replicationcontroller_condition_to_json`'s doc) for the same reason
/// `namespace_status_delegated_field`'s own `conditions` entry does.
fn replicationcontroller_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    if let Some(v) = status.replicas.filter(|&v| v != 0) {\n        m.insert(\"replicas\".to_string(), v.into());\n    }\n",
        ),
        "fullyLabeledReplicas" => Some(
            "    if let Some(v) = status.fully_labeled_replicas.filter(|&v| v != 0) {\n        m.insert(\"fullyLabeledReplicas\".to_string(), v.into());\n    }\n",
        ),
        "observedGeneration" => Some(
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
        ),
        "readyReplicas" => Some(
            "    if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {\n        m.insert(\"readyReplicas\".to_string(), v.into());\n    }\n",
        ),
        "availableReplicas" => Some(
            "    if let Some(v) = status.available_replicas.filter(|&v| v != 0) {\n        m.insert(\"availableReplicas\".to_string(), v.into());\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_replicationcontroller_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_replicationcontroller_status_to_json`, replacing the `status` assembly block of
/// the hand-rolled `decode_replicationcontroller_proto_gen` this migration retires.
pub fn generate_replicationcontroller_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICATION_CONTROLLER_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICATION_CONTROLLER_STATUS,
        message,
        replicationcontroller_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_replicationcontroller_status_to_json(status: core_v1::ReplicationControllerStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`/
/// `status` delegate to the separately generated `gen_replicationcontroller_spec_to_json`/
/// `gen_replicationcontroller_status_to_json` above because each needs its own per-field delegate
/// one level down (see those functions' docs).
fn replicationcontroller_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(rc.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = rc.spec {\n        obj.insert(\"spec\".to_string(), gen_replicationcontroller_spec_to_json(spec));\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = rc.status {\n        let status_json = gen_replicationcontroller_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_replicationcontroller_to_json`, replacing the message-walking body of the
/// hand-rolled `decode_replicationcontroller_proto_gen` this migration retires (the entry point
/// itself stays hand-written — see `generate_namespace`'s doc for why).
pub fn generate_replicationcontroller(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICATION_CONTROLLER);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICATION_CONTROLLER,
        message,
        replicationcontroller_delegated_field,
        "rc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_replicationcontroller_to_json(rc: core_v1::ReplicationController) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const EVENT: &str = ".k8s.io.api.core.v1.Event";

/// `metadata`/`involvedObject`/`count`/`firstTimestamp`/`lastTimestamp`/`eventTime`/`series` are
/// the only `Event` fields needing more than `emit_field_encode`/`field_decode_rhs` can derive on
/// their own:
///   - `metadata` delegates to the existing hand-written `gen_object_meta_to_json`/
///     `json_to_object_meta_proto` pair, the same reason every other top-level Kind's `metadata`
///     does (see `namespace_delegated_field`'s doc).
///   - `involvedObject` is unconditionally emitted (even `{}`) — unlike `related` below (also an
///     `ObjectReference`), which the mechanical walker's generic nested-`Type::Message` branch
///     already handles correctly (build `ObjectReference`'s own map inline, insert only if
///     non-empty — exactly what the Phase-0-generated `gen_object_reference_to_json`/
///     `json_to_object_reference_proto` themselves do, since `ObjectReference` is all
///     scalar-string fields needing no further overrides at any depth). `involvedObject` needs
///     the unconditional-insert override the mechanical default doesn't have.
///   - `count` is zero-filtered on encode, the same class of guard as
///     `PodStatus.observedGeneration`.
///   - `firstTimestamp`/`lastTimestamp` are bare `Time`s and `eventTime` a bare `MicroTime`, all
///     needing RFC3339 conversion, the same opaque-scalar handling `Quantity`/
///     `PodStatus.startTime` get (`firstTimestamp`/`lastTimestamp` additionally zero-filter their
///     `seconds`, matching the hand-rolled body this migration replaces exactly; `eventTime` does
///     not, since an explicit `seconds: Some(0)` there is upstream's own "not set" sentinel for a
///     `MicroTime`-typed field, not a value to drop).
///   - `series` needs its own per-field overrides one level down (`EventSeries.count`'s own
///     zero-filter, `lastObservedTime`'s own opaque-scalar handling) that this mechanical walker
///     has no per-field override hook for below the type it was invoked for (the same limitation
///     `namespace_status_delegated_field`'s own `conditions` entry documents), so it delegates
///     wholesale to the hand-written `gen_event_series_to_json`/`json_to_event_series_proto` pair.
///
/// `reason`/`message`/`type`/`action`/`reportingComponent`/`reportingInstance` (plain optional
/// strings) and `related` (a nested `ObjectReference`, see above) need no entry: the mechanical
/// walker's generic branches already produce byte-identical output to what this migration's
/// hand-rolled predecessor did for all seven. `source` (a nested `EventSource` with two plain
/// optional-string fields, `component`/`host`) likewise needs no entry — the now-dead
/// `json_to_event_source_proto` this migration deletes was doing exactly the same walk as the
/// mechanical default, just as a named function instead of inlined.
fn event_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "metadata" => Some((
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(event.metadata.unwrap_or_default()));\n",
            "Some(json_to_object_meta_proto(v))",
        )),
        "involvedObject" => Some((
            "    obj.insert(\"involvedObject\".to_string(), event.involved_object.map(gen_object_reference_to_json).unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())));\n",
            "v.get(\"involvedObject\").map(json_to_object_reference_proto)",
        )),
        "count" => Some((
            "    if let Some(v) = event.count.filter(|&n| n != 0) {\n        obj.insert(\"count\".to_string(), serde_json::Value::Number(serde_json::Number::from(v)));\n    }\n",
            "ji32(v, \"count\")",
        )),
        "firstTimestamp" => Some((
            "    if let Some(t) = event.first_timestamp {\n        if let Some(secs) = t.seconds.filter(|&s| s > 0) {\n            obj.insert(\"firstTimestamp\".to_string(), serde_json::Value::String(crate::util::secs_to_rfc3339(secs)));\n        }\n    }\n",
            "jtime(v, \"firstTimestamp\")",
        )),
        "lastTimestamp" => Some((
            "    if let Some(t) = event.last_timestamp {\n        if let Some(secs) = t.seconds.filter(|&s| s > 0) {\n            obj.insert(\"lastTimestamp\".to_string(), serde_json::Value::String(crate::util::secs_to_rfc3339(secs)));\n        }\n    }\n",
            "jtime(v, \"lastTimestamp\")",
        )),
        "eventTime" => Some((
            "    if let Some(t) = event.event_time {\n        if let Some(secs) = t.seconds {\n            obj.insert(\"eventTime\".to_string(), serde_json::Value::String(gen_microtime_fields_to_rfc3339(secs, t.nanos.unwrap_or(0))));\n        }\n    }\n",
            "json_to_microtime_proto(v, \"eventTime\")",
        )),
        "series" => Some((
            "    if let Some(s) = event.series {\n        let series_json = gen_event_series_to_json(s);\n        if series_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"series\".to_string(), series_json);\n        }\n    }\n",
            "v.get(\"series\").map(json_to_event_series_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_event_to_json`/`json_to_event_proto` pair, replacing the message-walking
/// bodies of the hand-rolled `decode_event_proto_gen`/`json_to_event_proto` this migration
/// retires — the first top-level Kind in this codegen module needing both directions at once
/// (Namespace/ConfigMap/Secret were decode-only; Container/PodSpec/PodStatus are two-way but
/// aren't themselves top-level Kinds — they're a Kind's own `spec`/`status` sub-message). The
/// `decode_event_proto_gen`/`encode_event_proto_gen`/`encode_eventlist_proto_gen` entry points
/// stay hand-written in `core_gen_adapter.rs`: the decode one stamps `apiVersion`/`kind`, neither
/// of which exist on the wire, and the encode ones just call `.encode_to_vec()`.
pub fn generate_event(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, EVENT);
    let (encode_stmts, decode_fields) =
        generate_message_codec(&set, EVENT, message, event_delegated_field, "event", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_event_to_json(event: core_v1::Event) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_event_proto(v: &serde_json::Value) -> core_v1::Event {\n");
    out.push_str("    core_v1::Event {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

const NODE: &str = ".k8s.io.api.core.v1.Node";
const NODE_SPEC: &str = ".k8s.io.api.core.v1.NodeSpec";
const NODE_STATUS: &str = ".k8s.io.api.core.v1.NodeStatus";

/// `taints` needs its own per-item overrides (`Taint.key` is unconditionally emitted, matching
/// upstream's non-`omitempty` JSON tag, and `timeAdded` is a bare `Time` needing RFC3339
/// conversion) that this mechanical walker has no per-field override hook for one level below
/// `NodeSpec` itself — the same limitation `namespace_status_delegated_field`'s own `conditions`
/// entry documents — so it delegates wholesale to the hand-written `gen_taints_to_json`/
/// `json_to_taint_proto` pair. `configSource` is the same class of delegate: `NodeConfigSource`'s
/// own `configMap` sub-field is unconditionally inserted once present (matching every other
/// `NodeConfigSource`/`NodeConfigStatus` call site in this file), which the mechanical walker's
/// generic nested-message branch (insert only if the built submessage ends up non-empty) can't
/// express, so it delegates to the existing hand-written `gen_node_config_source_to_json` pair.
/// `podCIDR`/`podCIDRs`/`providerID`/`unschedulable`/`externalID` need no entry: plain optional
/// scalars the mechanical walker already handles correctly.
fn node_spec_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "taints" => Some((
            "    if !spec.taints.is_empty() {\n        spec_map.insert(\"taints\".to_string(), gen_taints_to_json(spec.taints));\n    }\n",
            "v.get(\"taints\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_taint_proto).collect()).unwrap_or_default()",
        )),
        "configSource" => Some((
            "    if let Some(cs) = spec.config_source {\n        let cs_json = gen_node_config_source_to_json(cs);\n        if cs_json.as_object().is_some_and(|m| !m.is_empty()) {\n            spec_map.insert(\"configSource\".to_string(), cs_json);\n        }\n    }\n",
            "v.get(\"configSource\").map(json_to_node_config_source_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_node_spec_to_json`/`json_to_node_spec_proto` pair, replacing the `spec`
/// assembly block of the hand-rolled `decode_node_proto_gen`/`json_to_node_proto` this migration
/// retires.
pub fn generate_node_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, NODE_SPEC);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        NODE_SPEC,
        message,
        node_spec_delegated_field,
        "spec",
        "spec_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_node_spec_to_json(spec: core_v1::NodeSpec) -> serde_json::Value {\n");
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_node_spec_proto(v: &serde_json::Value) -> core_v1::NodeSpec {\n");
    out.push_str("    core_v1::NodeSpec {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// `conditions`/`addresses` need their own per-item overrides (unconditional `type`/`status` or
/// `type`/`address`, plus RFC3339 time conversion for `conditions`), the same class of delegate as
/// `node_spec_delegated_field`'s own `taints` entry, so both delegate wholesale to hand-written
/// `gen_node_condition_to_json`/`gen_node_address_to_json`. `nodeInfo`'s own `swap.capacity` is
/// zero-filtered (unlike this walker's plain-int64 default) and `images`' own `sizeBytes`
/// likewise, so both delegate to hand-written `gen_node_system_info_to_json`/
/// `gen_container_image_to_json`. `volumesAttached`'s `name`/`devicePath` are unconditionally
/// emitted (matching upstream's non-`omitempty` JSON tags on both `AttachedVolume` fields), so it
/// delegates to `gen_attached_volume_to_json`. `config` needs the same `NodeConfigStatus`/
/// `NodeConfigSource` delegate `node_spec_delegated_field`'s own `configSource` entry documents.
/// `daemonEndpoints` needs no entry despite nesting through `DaemonEndpoint.Port` (a Go-style
/// capitalised field name) — `json_key`'s own lowercasing rule (`proto_exceptions.rs`) already
/// normalises it to `port` at whatever recursion depth the mechanical walker reaches it, and the
/// walker's insert-only-if-non-empty rule at every level already matches this field's own "only
/// present once kubeletEndpoint.port is set" semantics (the mayor-j3p0n fix surface — see
/// `core_gen_adapter.rs`'s old `gen_node_status_to_json` doc, retired by this migration).
/// `capacity`/`allocatable`/`phase`/`volumesInUse`/`runtimeHandlers`/`features`/`declaredFeatures`
/// need no entry either: two `map<string, Quantity>`s, a plain optional string, two `repeated
/// string`s, and two message types (`NodeRuntimeHandler`/`NodeFeatures`) whose own fields are all
/// plain optional bool/string the mechanical walker already handles correctly at any depth.
fn node_status_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "conditions" => Some((
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_node_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
            "v.get(\"conditions\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_node_condition_proto).collect()).unwrap_or_default()",
        )),
        "addresses" => Some((
            "    if !status.addresses.is_empty() {\n        let addrs: Vec<serde_json::Value> = status.addresses.into_iter().map(gen_node_address_to_json).collect();\n        m.insert(\"addresses\".to_string(), serde_json::Value::Array(addrs));\n    }\n",
            "v.get(\"addresses\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_node_address_proto).collect()).unwrap_or_default()",
        )),
        "nodeInfo" => Some((
            "    if let Some(info) = status.node_info {\n        let ni_json = gen_node_system_info_to_json(info);\n        if ni_json.as_object().is_some_and(|m| !m.is_empty()) {\n            m.insert(\"nodeInfo\".to_string(), ni_json);\n        }\n    }\n",
            "v.get(\"nodeInfo\").map(json_to_node_system_info_proto)",
        )),
        "images" => Some((
            "    if !status.images.is_empty() {\n        let images: Vec<serde_json::Value> = status.images.into_iter().map(gen_container_image_to_json).collect();\n        m.insert(\"images\".to_string(), serde_json::Value::Array(images));\n    }\n",
            "v.get(\"images\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_container_image_proto).collect()).unwrap_or_default()",
        )),
        "volumesAttached" => Some((
            "    if !status.volumes_attached.is_empty() {\n        let vols: Vec<serde_json::Value> = status.volumes_attached.into_iter().map(gen_attached_volume_to_json).collect();\n        m.insert(\"volumesAttached\".to_string(), serde_json::Value::Array(vols));\n    }\n",
            "v.get(\"volumesAttached\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_attached_volume_proto).collect()).unwrap_or_default()",
        )),
        "config" => Some((
            "    if let Some(cs) = status.config {\n        let cs_json = gen_node_config_status_to_json(cs);\n        if cs_json.as_object().is_some_and(|m| !m.is_empty()) {\n            m.insert(\"config\".to_string(), cs_json);\n        }\n    }\n",
            "v.get(\"config\").map(json_to_node_config_status_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_node_status_to_json`/`json_to_node_status_proto` pair, replacing the
/// `status` assembly block of the hand-rolled `decode_node_proto_gen`/`json_to_node_proto` this
/// migration retires — including the mayor-j3p0n `daemonEndpoints` fix (see
/// `node_status_delegated_field`'s doc) and, as a natural consequence of `generate_message_codec`
/// requiring every field to have a decode expression, completing `json_to_node_status_proto`'s own
/// previously-partial coverage (`images`/`volumesInUse`/`volumesAttached`/`config`/
/// `runtimeHandlers`/`features`/`declaredFeatures` were silently dropped on the JSON->proto
/// direction via a trailing `..Default::default()`) — the same class of fix mayor-36gtx's `Event`
/// migration made for several previously-dropped fields.
pub fn generate_node_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, NODE_STATUS);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        NODE_STATUS,
        message,
        node_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_node_status_to_json(status: core_v1::NodeStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_node_status_proto(v: &serde_json::Value) -> core_v1::NodeStatus {\n");
    out.push_str("    core_v1::NodeStatus {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec` is
/// unconditionally inserted only when the generated `gen_node_spec_to_json` result is non-empty
/// (matching the hand-rolled body this migration replaces exactly); `status` is unconditionally
/// inserted whenever `node.status` is `Some`, regardless of emptiness (also matching that body
/// exactly). Both delegate to the separately generated `gen_node_spec_to_json`/
/// `gen_node_status_to_json` above because each needs its own per-field delegate one level down
/// (see those functions' docs).
fn node_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "metadata" => Some((
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(node.metadata.unwrap_or_default()));\n",
            "Some(json_to_object_meta_proto(v))",
        )),
        "spec" => Some((
            "    if let Some(spec) = node.spec {\n        let spec_json = gen_node_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
            "v.get(\"spec\").map(json_to_node_spec_proto)",
        )),
        "status" => Some((
            "    if let Some(status) = node.status {\n        obj.insert(\"status\".to_string(), gen_node_status_to_json(status));\n    }\n",
            "v.get(\"status\").map(json_to_node_status_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_node_to_json`/`json_to_node_proto` pair, replacing the message-walking
/// bodies of the hand-rolled `decode_node_proto_gen`/`json_to_node_proto` this migration retires —
/// the second top-level Kind (after `Event`) needing both directions at once, since `Node` has an
/// encoder (`encode_node_proto_gen`) alongside its decoder. The `decode_node_proto_gen`/
/// `encode_node_proto_gen`/`encode_nodelist_proto_gen` entry points stay hand-written in
/// `core_gen_adapter.rs`, matching `generate_event`'s own doc for why.
pub fn generate_node(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, NODE);
    let (encode_stmts, decode_fields) =
        generate_message_codec(&set, NODE, message, node_delegated_field, "node", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_node_to_json(node: core_v1::Node) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_node_proto(v: &serde_json::Value) -> core_v1::Node {\n");
    out.push_str("    core_v1::Node {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

const PERSISTENT_VOLUME: &str = ".k8s.io.api.core.v1.PersistentVolume";
const PERSISTENT_VOLUME_SPEC: &str = ".k8s.io.api.core.v1.PersistentVolumeSpec";
const PERSISTENT_VOLUME_SOURCE: &str = ".k8s.io.api.core.v1.PersistentVolumeSource";
const PERSISTENT_VOLUME_STATUS: &str = ".k8s.io.api.core.v1.PersistentVolumeStatus";

/// `PersistentVolumeSource` fields this codebase does not implement — legacy in-tree cloud/
/// protocol-specific volume plugins with no live conformance coverage, matching
/// `generate_volume_source`'s own `EXCLUDED_FIELDS`/`DELIBERATE_OMISSIONS` precedent (the same
/// policy: decode what has a live consumer — local/hostPath/nfs/csi — rather than the full
/// upstream field set). Asserted below against `proto_exceptions.rs`'s `DELIBERATE_OMISSIONS` so
/// the two lists can't silently drift apart.
const PERSISTENT_VOLUME_SOURCE_EXCLUDED_FIELDS: &[&str] = &[
    "gcePersistentDisk",
    "awsElasticBlockStore",
    "glusterfs",
    "rbd",
    "iscsi",
    "cinder",
    "cephfs",
    "fc",
    "flocker",
    "flexVolume",
    "azureFile",
    "vsphereVolume",
    "quobyte",
    "azureDisk",
    "photonPersistentDisk",
    "portworxVolume",
    "scaleIO",
    "storageos",
];

/// `claimRef` and `nodeAffinity` are unconditionally inserted once their outer `Option` is `Some`
/// (matching every other top-level `PersistentVolumeSpec` field's own "if Some, always emit"
/// semantics, the same class of override `resourcequota_spec_delegated_field`'s own `scopeSelector`
/// entry documents) rather than the mechanical walker's default "insert only if the built
/// submessage is non-empty" rule one level down — `claimRef` delegates to the existing
/// hand-written `gen_object_reference_to_json`, and `nodeAffinity` needs its own bespoke assembly
/// (only `required.nodeSelectorTerms` is implemented; `preferred` has no live consumer). `capacity`/
/// `accessModes`/`persistentVolumeReclaimPolicy`/`storageClassName`/`mountOptions`/`volumeMode`/
/// `volumeAttributesClassName` need no entry: a `map<string, Quantity>`, two `repeated string`s,
/// and four plain optional strings the mechanical walker already handles correctly.
/// `persistentVolumeSource` is handled separately by `generate_persistentvolume_spec` itself (an
/// `INLINE_EMBEDS` field, the same shape `generate_volume_source` handles for `Volume.volumeSource`
/// — see that function's doc), so it never reaches this table.
fn persistentvolume_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "claimRef" => Some(
            "    if let Some(v) = spec.claim_ref {\n        spec_map.insert(\"claimRef\".to_string(), gen_object_reference_to_json(v));\n    }\n",
        ),
        "nodeAffinity" => Some(
            "    if let Some(na) = spec.node_affinity {\n        if let Some(req) = na.required {\n            spec_map.insert(\"nodeAffinity\".to_string(), serde_json::json!({ \"required\": { \"nodeSelectorTerms\": req.node_selector_terms.into_iter().map(gen_node_selector_term_to_json).collect::<Vec<_>>() } }));\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_persistentvolume_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_persistentvolume_proto_gen` this migration retires. Decode-only: like
/// Namespace/ConfigMap/Secret/ResourceQuota/LimitRange/ReplicationController, `PersistentVolume`
/// has no `encode_persistentvolume_proto_gen` entry point today, so generating a `json_to_*_proto`
/// decode-direction pair alongside this would be dead code (see `generate_message_encode_only`'s
/// own doc).
///
/// Unlike every other `generate_*_spec` function in this module, this one cannot delegate its
/// whole per-field loop to `generate_message_encode_only`: `persistentVolumeSource` is an
/// `INLINE_EMBEDS` field whose own per-field walk (local/hostPath/nfs/csi, each unconditionally
/// inserted into `PersistentVolumeSpec`'s own JSON object once present) needs the same bespoke
/// "one message field per volume plugin" loop `generate_volume_source` hand-rolls for
/// `Volume.volumeSource` — a shape `generate_message_encode_only`'s delegate-returns-a-fixed-string
/// signature can't express, since the loop body itself must be built from
/// `PersistentVolumeSource`'s own descriptor at codegen time. So this function reimplements
/// `generate_message_encode_only`'s per-field dispatch loop directly, special-casing
/// `persistentVolumeSource` inline rather than routing it through a delegate table.
pub fn generate_persistentvolume_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PERSISTENT_VOLUME_SPEC);
    assert!(
        is_inline_embed(PERSISTENT_VOLUME_SPEC, "persistentVolumeSource"),
        "generate_persistentvolume_spec assumes PersistentVolumeSpec.persistentVolumeSource is an \
         INLINE_EMBEDS entry — if that table entry is ever removed, this function's calling \
         convention (writing local/hostPath/nfs/csi straight into PersistentVolumeSpec's own JSON \
         object, not a nested \"persistentVolumeSource\" key) needs to change to match"
    );

    let source_message = find_message(&set, PERSISTENT_VOLUME_SOURCE);
    let mut source_stmts = String::new();
    for field in &source_message.field {
        let name = field.name();
        let in_excluded_fields = PERSISTENT_VOLUME_SOURCE_EXCLUDED_FIELDS.contains(&name);
        let in_deliberate_omissions = is_excluded(PERSISTENT_VOLUME_SOURCE, name);
        assert_eq!(
            in_excluded_fields, in_deliberate_omissions,
            "{name}: codegen's local PERSISTENT_VOLUME_SOURCE_EXCLUDED_FIELDS \
             ({in_excluded_fields}) and proto_exceptions.rs's DELIBERATE_OMISSIONS \
             ({in_deliberate_omissions}) disagree for PersistentVolumeSource — the two lists must \
             name exactly the same fields so any future drift in either direction is caught at \
             build time instead of silently misdescribing what's implemented"
        );
        if in_excluded_fields {
            continue;
        }
        assert_eq!(
            field.r#type(),
            Type::Message,
            "PersistentVolumeSource.{name} is not message-typed — the mechanical walker only \
             knows how to handle PersistentVolumeSource's own \"one message field per volume \
             plugin\" shape"
        );
        let rust_field = rust_field_name(name);
        let key = json_key(PERSISTENT_VOLUME_SOURCE, name, field.json_name());
        let nested = find_message(&set, field.type_name());
        writeln!(source_stmts, "    if let Some(x0) = src.{rust_field} {{").unwrap();
        source_stmts.push_str("        let mut m0 = serde_json::Map::new();\n");
        emit_mechanical_encode(
            &set,
            field.type_name(),
            nested,
            "x0",
            "m0",
            0,
            &mut source_stmts,
        );
        writeln!(
            source_stmts,
            "        spec_map.insert(\"{key}\".to_string(), serde_json::Value::Object(m0));"
        )
        .unwrap();
        source_stmts.push_str("    }\n");
    }

    let mut encode_stmts = String::new();
    for field in &message.field {
        let name = field.name();
        if name == "persistentVolumeSource" {
            encode_stmts.push_str("    if let Some(src) = spec.persistent_volume_source {\n");
            encode_stmts.push_str(&source_stmts);
            encode_stmts.push_str("    }\n");
            continue;
        }
        if let Some(stmt) = persistentvolume_spec_delegated_field(name) {
            encode_stmts.push_str(stmt);
            continue;
        }
        emit_field_encode(
            &set,
            PERSISTENT_VOLUME_SPEC,
            field,
            "spec",
            "spec_map",
            0,
            &mut encode_stmts,
        );
    }

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_persistentvolume_spec_to_json(spec: core_v1::PersistentVolumeSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n");
    out
}

/// `lastPhaseTransitionTime` is a bare `Time` needing RFC3339 conversion, the same opaque-scalar
/// handling `Quantity`/`PodStatus.startTime` get. `phase`/`message`/`reason` need no entry: plain
/// optional strings the mechanical walker already handles correctly.
fn persistentvolume_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "lastPhaseTransitionTime" => Some(
            "    if let Some(secs) = status.last_phase_transition_time.and_then(|t| t.seconds) {\n        status_map.insert(\"lastPhaseTransitionTime\".to_string(), serde_json::Value::String(crate::util::secs_to_rfc3339(secs)));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_persistentvolume_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_persistentvolume_proto_gen` this migration retires.
pub fn generate_persistentvolume_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PERSISTENT_VOLUME_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        PERSISTENT_VOLUME_STATUS,
        message,
        persistentvolume_status_delegated_field,
        "status",
        "status_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_persistentvolume_status_to_json(status: core_v1::PersistentVolumeStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut status_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(status_map)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`/
/// `status` delegate to the separately generated `gen_persistentvolume_spec_to_json`/
/// `gen_persistentvolume_status_to_json` above because each needs its own per-field delegate one
/// level down (see those functions' docs).
fn persistentvolume_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(pv.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = pv.spec {\n        let spec_json = gen_persistentvolume_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = pv.status {\n        let status_json = gen_persistentvolume_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_persistentvolume_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_persistentvolume_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why).
pub fn generate_persistentvolume(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PERSISTENT_VOLUME);
    let encode_stmts = generate_message_encode_only(
        &set,
        PERSISTENT_VOLUME,
        message,
        persistentvolume_delegated_field,
        "pv",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_persistentvolume_to_json(pv: core_v1::PersistentVolume) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const PERSISTENT_VOLUME_CLAIM_SPEC: &str = ".k8s.io.api.core.v1.PersistentVolumeClaimSpec";
const PERSISTENT_VOLUME_CLAIM_STATUS: &str = ".k8s.io.api.core.v1.PersistentVolumeClaimStatus";

/// `selector`/`dataSource`/`dataSourceRef` are unconditionally inserted once their outer `Option`
/// is `Some` (the same class of override `persistentvolume_spec_delegated_field`'s own `claimRef`
/// entry documents), delegating to the existing hand-written `gen_label_selector_to_json`/
/// `gen_typed_local_object_reference_to_json`/`gen_typed_object_reference_to_json`.
/// `storageClassName`/`volumeAttributesClassName` are present-but-empty-preserving (upstream has
/// no `omitempty` on either JSON tag, confirmed by
/// `gen_persistent_volume_claim_to_json_preserves_present_but_empty_*` in
/// `core_gen_adapter.rs`), unlike the mechanical walker's default non-empty filter for optional
/// strings, so both need their own unconditional-insert override. `accessModes`/`resources`/
/// `volumeName`/`volumeMode` need no entry: a `repeated string`, a message whose own two
/// `map<string, Quantity>` fields the mechanical walker already handles correctly at any depth, and
/// two plain (filtered) optional strings.
fn persistentvolumeclaim_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "selector" => Some(
            "    if let Some(sel) = spec.selector {\n        spec_map.insert(\"selector\".to_string(), gen_label_selector_to_json(sel));\n    }\n",
        ),
        "storageClassName" => Some(
            "    if let Some(v) = spec.storage_class_name {\n        spec_map.insert(\"storageClassName\".to_string(), serde_json::Value::String(v));\n    }\n",
        ),
        "dataSource" => Some(
            "    if let Some(ds) = spec.data_source {\n        spec_map.insert(\"dataSource\".to_string(), gen_typed_local_object_reference_to_json(ds));\n    }\n",
        ),
        "dataSourceRef" => Some(
            "    if let Some(dsr) = spec.data_source_ref {\n        spec_map.insert(\"dataSourceRef\".to_string(), gen_typed_object_reference_to_json(dsr));\n    }\n",
        ),
        "volumeAttributesClassName" => Some(
            "    if let Some(v) = spec.volume_attributes_class_name {\n        spec_map.insert(\"volumeAttributesClassName\".to_string(), serde_json::Value::String(v));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_persistentvolumeclaim_spec_to_json`, replacing the `spec` assembly block of
/// `gen_persistent_volume_claim_to_json` this migration retires.
pub fn generate_persistentvolumeclaim_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PERSISTENT_VOLUME_CLAIM_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        PERSISTENT_VOLUME_CLAIM_SPEC,
        message,
        persistentvolumeclaim_spec_delegated_field,
        "spec",
        "spec_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_persistentvolumeclaim_spec_to_json(spec: core_v1::PersistentVolumeClaimSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n");
    out
}

/// `conditions` needs its own per-item overrides (unconditional `type`/`status`, plus RFC3339 time
/// conversion for `lastProbeTime`/`lastTransitionTime`), the same class of delegate
/// `node_status_delegated_field`'s own `conditions` entry documents, so it delegates wholesale to
/// the hand-written `gen_persistentvolumeclaim_condition_to_json`. `modifyVolumeStatus` is
/// unconditionally inserted once present, delegating to the existing hand-written
/// `gen_modify_volume_status_to_json`. `phase`/`accessModes`/`capacity`/`allocatedResources`/
/// `allocatedResourceStatuses`/`currentVolumeAttributesClassName` need no entry: a plain optional
/// string, a `repeated string`, two `map<string, Quantity>`s, a `map<string, string>`, and another
/// plain (filtered) optional string the mechanical walker already handles correctly.
fn persistentvolumeclaim_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_persistentvolumeclaim_condition_to_json).collect();\n        status_map.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
        ),
        "modifyVolumeStatus" => Some(
            "    if let Some(mvs) = status.modify_volume_status {\n        status_map.insert(\"modifyVolumeStatus\".to_string(), gen_modify_volume_status_to_json(mvs));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_persistentvolumeclaim_status_to_json`, replacing the `status` assembly block of
/// `gen_persistent_volume_claim_to_json` this migration retires.
pub fn generate_persistentvolumeclaim_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PERSISTENT_VOLUME_CLAIM_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        PERSISTENT_VOLUME_CLAIM_STATUS,
        message,
        persistentvolumeclaim_status_delegated_field,
        "status",
        "status_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_persistentvolumeclaim_status_to_json(status: core_v1::PersistentVolumeClaimStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut status_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(status_map)\n");
    out.push_str("}\n");
    out
}

const SERVICE: &str = ".k8s.io.api.core.v1.Service";
const SERVICE_SPEC: &str = ".k8s.io.api.core.v1.ServiceSpec";
const SERVICE_STATUS: &str = ".k8s.io.api.core.v1.ServiceStatus";

/// `ports` needs its own per-item overrides (`ServicePort.port`/`.nodePort` zero-filtered — a
/// genuinely-0 port is invalid per the Kubernetes API and indistinguishable from unset on the
/// wire, the same reasoning `node_status_delegated_field`'s own `images` entry documents for
/// `ContainerImage.sizeBytes` — plus `targetPort`'s opaque `IntOrString` encoding) that this
/// mechanical walker has no per-field override hook for one level below `ServiceSpec` itself —
/// the same limitation `node_spec_delegated_field`'s own `taints` entry documents — so it
/// delegates wholesale to the hand-written `gen_service_port_to_json`/
/// `json_to_service_port_proto` pair. `healthCheckNodePort` is a positive-only filter, the same
/// class of guard as `PodStatus.observedGeneration`. `sessionAffinityConfig` needs the same
/// "insert only if the built submessage is non-empty after an inner zero-filter" shape
/// `node_spec_delegated_field`'s own `configSource` entry documents, so it delegates to the
/// hand-written `gen_session_affinity_config_to_json`/`json_to_session_affinity_config_proto`
/// pair. Every other `ServiceSpec` field needs no entry: plain optional scalars, `repeated
/// string`s, and a `map<string, string>` (`selector`) the mechanical walker already handles
/// correctly.
fn service_spec_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "ports" => Some((
            "    if !spec.ports.is_empty() {\n        let ports: Vec<serde_json::Value> = spec.ports.into_iter().map(gen_service_port_to_json).collect();\n        spec_map.insert(\"ports\".to_string(), serde_json::Value::Array(ports));\n    }\n",
            "v.get(\"ports\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_service_port_proto).collect()).unwrap_or_default()",
        )),
        "healthCheckNodePort" => Some((
            "    if let Some(v) = spec.health_check_node_port.filter(|&v| v != 0) {\n        spec_map.insert(\"healthCheckNodePort\".to_string(), v.into());\n    }\n",
            "ji32(v, \"healthCheckNodePort\")",
        )),
        "sessionAffinityConfig" => Some((
            "    if let Some(sac) = spec.session_affinity_config {\n        let sac_json = gen_session_affinity_config_to_json(sac);\n        if sac_json.as_object().is_some_and(|m| !m.is_empty()) {\n            spec_map.insert(\"sessionAffinityConfig\".to_string(), sac_json);\n        }\n    }\n",
            "v.get(\"sessionAffinityConfig\").map(json_to_session_affinity_config_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_service_spec_to_json`/`json_to_service_spec_proto` pair, replacing the
/// `spec` assembly block of the hand-rolled `decode_service_proto_gen`/`json_to_service_proto`
/// this migration retires.
pub fn generate_service_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SERVICE_SPEC);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        SERVICE_SPEC,
        message,
        service_spec_delegated_field,
        "spec",
        "spec_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_service_spec_to_json(spec: core_v1::ServiceSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut spec_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(spec_map)\n");
    out.push_str("}\n\n");

    out.push_str(
        "fn json_to_service_spec_proto(v: &serde_json::Value) -> core_v1::ServiceSpec {\n",
    );
    out.push_str("    core_v1::ServiceSpec {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// `loadBalancer`'s own `ingress[].ports[].port` is zero-filtered two levels below
/// `ServiceStatus` itself — past this mechanical walker's one-level override hook — so it
/// delegates wholesale to the hand-written `gen_load_balancer_status_to_json`/
/// `json_to_load_balancer_status_proto` pair. `conditions` needs the same unconditional
/// `type`/`status` override every other resource's own condition encoder in this file
/// documents, plus a zero-filtered `observedGeneration`, so it delegates to the hand-written
/// `gen_meta_condition_to_json`/`json_to_meta_condition_proto` pair (the generic
/// `k8s.io.apimachinery.pkg.apis.meta.v1.Condition`, not a resource-specific condition type).
fn service_status_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "loadBalancer" => Some((
            "    if let Some(lb) = status.load_balancer {\n        let lb_json = gen_load_balancer_status_to_json(lb);\n        if lb_json.as_object().is_some_and(|m| !m.is_empty()) {\n            status_map.insert(\"loadBalancer\".to_string(), lb_json);\n        }\n    }\n",
            "v.get(\"loadBalancer\").map(json_to_load_balancer_status_proto)",
        )),
        "conditions" => Some((
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_meta_condition_to_json).collect();\n        status_map.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
            "v.get(\"conditions\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_meta_condition_proto).collect()).unwrap_or_default()",
        )),
        _ => None,
    }
}

/// Generates the `gen_service_status_to_json`/`json_to_service_status_proto` pair, replacing
/// the `status` assembly block of the hand-rolled `decode_service_proto_gen`/
/// `json_to_service_proto` this migration retires.
pub fn generate_service_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SERVICE_STATUS);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        SERVICE_STATUS,
        message,
        service_status_delegated_field,
        "status",
        "status_map",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_service_status_to_json(status: core_v1::ServiceStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut status_map = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(status_map)\n");
    out.push_str("}\n\n");

    out.push_str(
        "fn json_to_service_status_proto(v: &serde_json::Value) -> core_v1::ServiceStatus {\n",
    );
    out.push_str("    core_v1::ServiceStatus {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`
/// is unconditionally inserted only when the generated `gen_service_spec_to_json` result is
/// non-empty; `status` uses the identical non-empty guard — unlike `node_delegated_field`'s own
/// `status` entry, which inserts unconditionally regardless of emptiness — matching the
/// hand-rolled body this migration replaces exactly (a Service whose status has neither
/// loadBalancer nor conditions omits the `status` key entirely). Both delegate to the
/// separately generated `gen_service_spec_to_json`/`gen_service_status_to_json` above because
/// each needs its own per-field delegate one level down (see those functions' docs).
fn service_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "metadata" => Some((
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(svc.metadata.unwrap_or_default()));\n",
            "Some(json_to_object_meta_proto(v))",
        )),
        "spec" => Some((
            "    if let Some(spec) = svc.spec {\n        let spec_json = gen_service_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
            "v.get(\"spec\").map(json_to_service_spec_proto)",
        )),
        "status" => Some((
            "    if let Some(status) = svc.status {\n        let status_json = gen_service_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
            "v.get(\"status\").map(json_to_service_status_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_service_to_json`/`json_to_service_proto` pair, replacing the
/// message-walking bodies of the hand-rolled `decode_service_proto_gen`/`json_to_service_proto`
/// this migration retires. `Service` has both a decoder and an encoder — kube-proxy's iptables/
/// IPVS sync re-reads exactly the bytes `encode_service_proto_gen` produces, making this the
/// highest-risk pair in this migration — so the `decode_service_proto_gen` entry point stays
/// hand-written in `core_gen_adapter.rs`, matching `generate_node`'s own doc for why.
pub fn generate_service(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SERVICE);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        SERVICE,
        message,
        service_delegated_field,
        "svc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_service_to_json(svc: core_v1::Service) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_service_proto(v: &serde_json::Value) -> core_v1::Service {\n");
    out.push_str("    core_v1::Service {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

const ENDPOINTS: &str = ".k8s.io.api.core.v1.Endpoints";

/// `subsets` needs its own per-item overrides two levels below `Endpoints` itself
/// (`EndpointAddress.ip`/`EndpointPort.port` are both unconditionally emitted, matching
/// upstream's non-`omitempty` JSON tags — the same class of override `gen_node_address_to_json`
/// documents for `NodeAddress.type`/`.address`) that this mechanical walker has no per-field
/// override hook for, so it delegates wholesale to the hand-written
/// `gen_endpoint_subset_to_json`/`json_to_endpoint_subset_proto` pair. `metadata` delegates for
/// the same reason as `namespace_delegated_field`'s own entry.
fn endpoints_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "metadata" => Some((
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(eps.metadata.unwrap_or_default()));\n",
            "Some(json_to_object_meta_proto(v))",
        )),
        "subsets" => Some((
            "    if !eps.subsets.is_empty() {\n        let subsets: Vec<serde_json::Value> = eps.subsets.into_iter().map(gen_endpoint_subset_to_json).collect();\n        obj.insert(\"subsets\".to_string(), serde_json::Value::Array(subsets));\n    }\n",
            "v.get(\"subsets\").and_then(|a| a.as_array()).map(|a| a.iter().map(json_to_endpoint_subset_proto).collect()).unwrap_or_default()",
        )),
        _ => None,
    }
}

/// Generates the `gen_endpoints_to_json`/`json_to_endpoints_proto` pair, replacing the
/// message-walking bodies of the hand-rolled `decode_endpoints_proto_gen`/
/// `json_to_endpoints_proto` this migration retires. Like `Service`, `Endpoints` has both a
/// decoder and an encoder — kube-proxy's legacy (non-EndpointSlice) code path re-reads exactly
/// these bytes — so the `decode_endpoints_proto_gen` entry point stays hand-written; see
/// `generate_service`'s own doc for why.
pub fn generate_endpoints(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, ENDPOINTS);
    let (encode_stmts, decode_fields) = generate_message_codec(
        &set,
        ENDPOINTS,
        message,
        endpoints_delegated_field,
        "eps",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_endpoints_to_json(eps: core_v1::Endpoints) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_endpoints_proto(v: &serde_json::Value) -> core_v1::Endpoints {\n");
    out.push_str("    core_v1::Endpoints {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

const POD: &str = ".k8s.io.api.core.v1.Pod";

/// `metadata`/`spec` are unconditionally inserted once decoded (a Pod always carries both on the
/// wire, even an all-defaults `PodSpec`), matching the hand-rolled `decode_pod_proto_gen`/
/// `json_to_pod_proto` this migration retires exactly — unlike every other top-level Kind's own
/// `spec` entry in this module (e.g. `node_delegated_field`'s), which only inserts once the
/// generated sub-message is non-empty. `status` is inserted whenever the outer `Option` is `Some`
/// regardless of emptiness, the same rule `node_delegated_field`'s own `status` entry documents.
fn pod_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
        "metadata" => Some((
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(pod.metadata.unwrap_or_default()));\n",
            "Some(json_to_object_meta_proto(v))",
        )),
        "spec" => Some((
            "    obj.insert(\"spec\".to_string(), gen_pod_spec_to_json(pod.spec.unwrap_or_default()));\n",
            "Some(json_to_pod_spec_proto(v.get(\"spec\").unwrap_or(&serde_json::Value::Null)))",
        )),
        "status" => Some((
            "    if let Some(status) = pod.status {\n        obj.insert(\"status\".to_string(), gen_pod_status_to_json(status));\n    }\n",
            "v.get(\"status\").map(json_to_pod_status_proto)",
        )),
        _ => None,
    }
}

/// Generates the `gen_pod_to_json`/`json_to_pod_proto` pair, replacing the message-walking
/// bodies of the hand-rolled `decode_pod_proto_gen`/`json_to_pod_proto` this migration retires —
/// the highest-risk pair in the whole codegen rollout, since kubelet re-reads exactly the bytes
/// `encode_pod_proto_gen` produces to actuate containers. `PodSpec`/`PodStatus` are themselves
/// already generated by `generate_pod_spec`/`generate_pod_status` (an earlier phase); this
/// function only closes the remaining gap at the `Pod` Kind's own top level. The
/// `decode_pod_proto_gen`/`encode_pod_proto_gen`/`encode_podlist_proto_gen` entry points stay
/// hand-written in `core_gen_adapter.rs`, matching `generate_node`'s own doc for why.
pub fn generate_pod(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POD);
    let (encode_stmts, decode_fields) =
        generate_message_codec(&set, POD, message, pod_delegated_field, "pod", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_pod_to_json(pod: core_v1::Pod) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n\n");

    out.push_str("fn json_to_pod_proto(v: &serde_json::Value) -> core_v1::Pod {\n");
    out.push_str("    core_v1::Pod {\n");
    out.push_str(&decode_fields);
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

const POD_TEMPLATE_SPEC: &str = ".k8s.io.api.core.v1.PodTemplateSpec";

/// `metadata`/`spec` are each inserted only when their outer `Option` is `Some`, with no
/// emptiness check on the resulting sub-object — matching the hand-rolled
/// `gen_pod_template_spec_to_json` this migration retires exactly (`t["metadata"] = ...`/
/// `t["spec"] = ...` unconditionally once present, never gated on the built object being
/// non-empty the way e.g. `node_delegated_field`'s own `spec` entry is). Both delegate wholesale
/// because `PodTemplateSpec.spec` must call the already-generated `gen_pod_spec_to_json` rather
/// than have the mechanical walker re-derive `PodSpec`'s own field set a second time.
fn pod_template_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    if let Some(meta) = tmpl.metadata {\n        t.insert(\"metadata\".to_string(), gen_object_meta_to_json(meta));\n    }\n",
        ),
        "spec" => Some(
            "    if let Some(pod_spec) = tmpl.spec {\n        t.insert(\"spec\".to_string(), gen_pod_spec_to_json(pod_spec));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_pod_template_spec_to_json`, replacing the hand-rolled function of the same
/// name this migration retires. Decode-only in the sense `generate_message_encode_only`'s own
/// doc describes: `PodTemplateSpec` never appears as its own top-level Kind with a JSON->proto
/// entry point in this file — every consumer (`PodTemplate`'s own `template` field below,
/// Deployment/ReplicaSet/DaemonSet/Job/CronJob's own `spec.template` in `apps_gen_adapter.rs`/
/// `batch_gen_adapter.rs`) only ever reads a `PodTemplateSpec` out of a stored proto message, so
/// a `json_to_pod_template_spec_proto` decode direction would be genuinely dead code today.
/// `pub(crate)`, not `fn`, because those other two adapter files call it by name across the
/// crate boundary — matching the hand-rolled function's own visibility exactly.
pub fn generate_pod_template_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POD_TEMPLATE_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        POD_TEMPLATE_SPEC,
        message,
        pod_template_spec_delegated_field,
        "tmpl",
        "t",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "pub(crate) fn gen_pod_template_spec_to_json(tmpl: core_v1::PodTemplateSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut t = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(t)\n");
    out.push_str("}\n");
    out
}

const POD_TEMPLATE: &str = ".k8s.io.api.core.v1.PodTemplate";

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry.
/// `template` is unconditionally inserted (defaulting to `{}` when the Pod never set one),
/// matching the hand-rolled `decode_podtemplate_proto_gen` this migration retires exactly — a
/// `PodTemplate` with no `template` field still round-trips an (empty-object) `"template"` key
/// rather than omitting it.
fn podtemplate_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(pt.metadata.unwrap_or_default()));\n",
        ),
        "template" => Some(
            "    obj.insert(\"template\".to_string(), pt.template.map(gen_pod_template_spec_to_json).unwrap_or_else(|| serde_json::json!({})));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_podtemplate_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_podtemplate_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `PodTemplate` has no
/// `encode_podtemplate_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_podtemplate(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POD_TEMPLATE);
    let encode_stmts = generate_message_encode_only(
        &set,
        POD_TEMPLATE,
        message,
        podtemplate_delegated_field,
        "pt",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_podtemplate_to_json(pt: core_v1::PodTemplate) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const SERVICE_ACCOUNT: &str = ".k8s.io.api.core.v1.ServiceAccount";

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `secrets`
/// needs its own per-item override the mechanical walker can't express: an entry is only emitted
/// once its `name` sub-field is non-empty (the hand-rolled decoder this replaces uses
/// `filter_map` on `name`, unlike the mechanical repeated-message branch, which pushes every
/// element unconditionally), so it delegates wholesale to the hand-written
/// `gen_serviceaccount_secret_to_json` (a thin `name`-presence guard around the already-generated
/// `gen_object_reference_to_json`). `imagePullSecrets` needs the identical `LocalObjectReference`
/// name-projection `pod_spec_delegated_field`'s own `imagePullSecrets` entry documents, so it is
/// delegated the same way here. `automountServiceAccountToken` needs no entry: a plain optional
/// bool the mechanical walker already handles correctly.
fn serviceaccount_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(sa.metadata.unwrap_or_default()));\n",
        ),
        "secrets" => Some(
            "    if !sa.secrets.is_empty() {\n        let secrets: Vec<serde_json::Value> = sa.secrets.into_iter().filter_map(gen_serviceaccount_secret_to_json).collect();\n        obj.insert(\"secrets\".to_string(), serde_json::Value::Array(secrets));\n    }\n",
        ),
        "imagePullSecrets" => Some(
            "    if !sa.image_pull_secrets.is_empty() {\n        let refs: Vec<serde_json::Value> = sa.image_pull_secrets.into_iter().filter_map(|r| r.name.filter(|s| !s.is_empty())).map(|name| serde_json::json!({ \"name\": name })).collect();\n        obj.insert(\"imagePullSecrets\".to_string(), serde_json::Value::Array(refs));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_serviceaccount_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_serviceaccount_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `ServiceAccount` has no
/// `encode_serviceaccount_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_serviceaccount(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SERVICE_ACCOUNT);
    let encode_stmts = generate_message_encode_only(
        &set,
        SERVICE_ACCOUNT,
        message,
        serviceaccount_delegated_field,
        "sa",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_serviceaccount_to_json(sa: core_v1::ServiceAccount) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const APISERVICE: &str = ".k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIService";
const APISERVICE_SPEC: &str = ".k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIServiceSpec";
const APISERVICE_STATUS: &str =
    ".k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.APIServiceStatus";

/// `caBundle` is the only `APIServiceSpec` field the mechanical walker can't derive on its own:
/// it's a `bytes` field (`Type::Bytes`), a shape `emit_field_encode` has no match arm for (every
/// opaque-scalar field this codegen module has met so far — `Quantity` — gets its own dedicated
/// arm instead), so it delegates to an inline base64 encode, the same shape
/// `configmap_delegated_field`/`secret_delegated_field` already use for their own `bytes`-valued
/// fields. `service` needs no entry: `ServiceReference`'s three fields (namespace/name/port) are
/// all plain scalars, so the mechanical nested-message branch already reproduces the hand-rolled
/// `if !svc_map.is_empty() { ... }` guard exactly.
fn apiservice_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "caBundle" => Some(
            "    if let Some(v) = spec.ca_bundle.filter(|b| !b.is_empty()) {\n        use base64::Engine as _;\n        m.insert(\"caBundle\".to_string(), serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(v)));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_apiservice_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_apiservice_proto_gen` this migration retires.
pub fn generate_apiservice_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, APISERVICE_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        APISERVICE_SPEC,
        message,
        apiservice_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_apiservice_spec_to_json(spec: apiregistration_v1::ApiServiceSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `conditions` needs its own per-element override (`lastTransitionTime`'s RFC3339 conversion,
/// plus `type`/`status`/`reason`/`message` empty-string filtering) that the mechanical walker's
/// generic repeated-message branch can't express — mirrors `namespace_status_delegated_field`'s
/// own `conditions` entry. Delegates wholesale to the hand-written
/// `gen_apiservice_condition_to_json`.
fn apiservice_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conditions: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_apiservice_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conditions));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_apiservice_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_apiservice_proto_gen` this migration retires.
pub fn generate_apiservice_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, APISERVICE_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        APISERVICE_STATUS,
        message,
        apiservice_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_apiservice_status_to_json(status: apiregistration_v1::ApiServiceStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`/
/// `status` each delegate wholesale to the separately generated `gen_apiservice_spec_to_json`/
/// `gen_apiservice_status_to_json`, only inserting the resulting key when non-empty — matching
/// the hand-rolled `decode_apiservice_proto_gen` this migration retires exactly (it never emits
/// an empty `"spec": {}` / `"status": {}`).
fn apiservice_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(svc.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = svc.spec {\n        let spec_json = gen_apiservice_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = svc.status {\n        let status_json = gen_apiservice_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_apiservice_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_apiservice_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `APIService` has no
/// `encode_apiservice_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_apiservice(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, APISERVICE);
    let encode_stmts = generate_message_encode_only(
        &set,
        APISERVICE,
        message,
        apiservice_delegated_field,
        "svc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_apiservice_to_json(svc: apiregistration_v1::ApiService) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}
const LEASE: &str = ".k8s.io.api.coordination.v1.Lease";
const LEASE_SPEC: &str = ".k8s.io.api.coordination.v1.LeaseSpec";

/// `leaseDurationSeconds`/`leaseTransitions` are gogoproto `nullable=false` int32 fields — the
/// same class `container_delegated_field`'s `stdin`/`stdinOnce`/`tty` doc explains for bools — so
/// an explicit `0` is indistinguishable on the wire from "never set" and the pre-migration
/// `decode_lease_proto_gen_a` this replaces only emits them once non-zero; the mechanical walker's
/// generic `Type::Int32` branch has no such filter, so both need a delegate entry. `acquireTime`/
/// `renewTime` are bare `MicroTime`s needing RFC3339 conversion, the same opaque-scalar handling
/// `Quantity`/`event_delegated_field`'s own Time/MicroTime entries get — the mechanical walker's
/// `Type::Message` branch only special-cases `Quantity` by FQN, so a `MicroTime`-typed field
/// reached mechanically would wrongly walk into its own `seconds`/`nanos` fields instead of
/// producing a string. `holderIdentity`/`strategy`/`preferredHolder` need no entry: plain optional
/// strings the mechanical walker already handles correctly.
fn lease_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "leaseDurationSeconds" => Some(
            "    if let Some(v) = spec.lease_duration_seconds.filter(|&n| n != 0) {\n        m.insert(\"leaseDurationSeconds\".to_string(), serde_json::Value::Number(v.into()));\n    }\n",
        ),
        "acquireTime" => Some(
            "    if let Some(t) = spec.acquire_time.as_ref() {\n        if let Some(ts) = gen_microtime_to_rfc3339(t) {\n            m.insert(\"acquireTime\".to_string(), serde_json::Value::String(ts));\n        }\n    }\n",
        ),
        "renewTime" => Some(
            "    if let Some(t) = spec.renew_time.as_ref() {\n        if let Some(ts) = gen_microtime_to_rfc3339(t) {\n            m.insert(\"renewTime\".to_string(), serde_json::Value::String(ts));\n        }\n    }\n",
        ),
        "leaseTransitions" => Some(
            "    if let Some(v) = spec.lease_transitions.filter(|&n| n != 0) {\n        m.insert(\"leaseTransitions\".to_string(), serde_json::Value::Number(v.into()));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_lease_spec_to_json`, replacing the `spec` assembly block of the hand-rolled
/// `decode_lease_proto_gen_a` this migration retires — this function's existence is what makes
/// `spec` reachable at all from `decode_lease_proto_gen_a` post-migration, the same split
/// `generate_namespace_status` established for `Namespace.status`.
pub fn generate_lease_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LEASE_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        LEASE_SPEC,
        message,
        lease_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_lease_spec_to_json(spec: coord_v1::LeaseSpec) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`
/// delegates to the separately generated `gen_lease_spec_to_json`, only inserted once the result
/// is non-empty — matching the pre-migration `decode_lease_proto_gen_a`'s own
/// `if !spec_map.is_empty() { obj["spec"] = ... }` guard exactly, the same shape
/// `namespace_delegated_field`'s own `status` entry uses.
fn lease_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(lease.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = lease.spec {\n        let spec_json = gen_lease_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_lease_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_lease_proto_gen_a` this migration retires (the entry point itself stays hand-written —
/// see `generate_namespace`'s doc for why; `Lease` has no `encode_lease_proto_gen` today, so this
/// is decode-only in the same sense).
pub fn generate_lease(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LEASE);
    let encode_stmts =
        generate_message_encode_only(&set, LEASE, message, lease_delegated_field, "lease", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_lease_to_json(lease: coord_v1::Lease) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const LEASE_CANDIDATE: &str = ".k8s.io.api.coordination.v1alpha2.LeaseCandidate";
const LEASE_CANDIDATE_SPEC: &str = ".k8s.io.api.coordination.v1alpha2.LeaseCandidateSpec";

/// `pingTime`/`renewTime` are bare `MicroTime`s needing the same RFC3339 delegate
/// `lease_spec_delegated_field`'s own `acquireTime`/`renewTime` entries document. `leaseName`/
/// `binaryVersion`/`emulationVersion`/`strategy` need no entry: plain optional strings the
/// mechanical walker already handles correctly.
fn leasecandidate_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "pingTime" => Some(
            "    if let Some(t) = spec.ping_time.as_ref() {\n        if let Some(ts) = gen_microtime_to_rfc3339(t) {\n            m.insert(\"pingTime\".to_string(), serde_json::Value::String(ts));\n        }\n    }\n",
        ),
        "renewTime" => Some(
            "    if let Some(t) = spec.renew_time.as_ref() {\n        if let Some(ts) = gen_microtime_to_rfc3339(t) {\n            m.insert(\"renewTime\".to_string(), serde_json::Value::String(ts));\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_leasecandidate_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_leasecandidate_proto_gen` this migration retires, the same split
/// `generate_lease_spec` establishes for `Lease.spec`.
pub fn generate_leasecandidate_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LEASE_CANDIDATE_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        LEASE_CANDIDATE_SPEC,
        message,
        leasecandidate_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_leasecandidate_spec_to_json(spec: coord_v1alpha2::LeaseCandidateSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`
/// delegates to the separately generated `gen_leasecandidate_spec_to_json`, only inserted once
/// non-empty — matching the pre-migration `decode_leasecandidate_proto_gen`'s own
/// `if !spec_map.is_empty() { obj["spec"] = ... }` guard exactly.
fn leasecandidate_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(candidate.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = candidate.spec {\n        let spec_json = gen_leasecandidate_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_leasecandidate_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_leasecandidate_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `LeaseCandidate` has no
/// `encode_leasecandidate_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_leasecandidate(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, LEASE_CANDIDATE);
    let encode_stmts = generate_message_encode_only(
        &set,
        LEASE_CANDIDATE,
        message,
        leasecandidate_delegated_field,
        "candidate",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_leasecandidate_to_json(candidate: coord_v1alpha2::LeaseCandidate) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const POLICY_RULE: &str = ".k8s.io.api.rbac.v1.PolicyRule";
const SUBJECT: &str = ".k8s.io.api.rbac.v1.Subject";
const ROLE_REF: &str = ".k8s.io.api.rbac.v1.RoleRef";
const CLUSTER_ROLE: &str = ".k8s.io.api.rbac.v1.ClusterRole";
const CLUSTER_ROLE_BINDING: &str = ".k8s.io.api.rbac.v1.ClusterRoleBinding";
const ROLE: &str = ".k8s.io.api.rbac.v1.Role";
const ROLE_BINDING: &str = ".k8s.io.api.rbac.v1.RoleBinding";

/// Generates `gen_policy_rule_to_json`, replacing the hand-rolled function of the same name.
/// Every `PolicyRule` field (`verbs`/`apiGroups`/`resources`/`resourceNames`/`nonResourceURLs`) is
/// a plain `repeated string`, which the mechanical walker's `Type::String if repeated` branch
/// already reproduces exactly (insert as a JSON array only once non-empty) — no delegate table
/// needed.
pub fn generate_policy_rule(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, POLICY_RULE);
    let encode_stmts =
        generate_message_encode_only(&set, POLICY_RULE, message, |_| None, "rule", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_policy_rule_to_json(rule: rbac_v1::PolicyRule) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `apiGroup` is the one `Subject` field whose emission the mechanical walker's generic
/// `Type::String` branch gets wrong: that branch always applies `.filter(|s| !s.is_empty())`
/// before inserting, but the hand-rolled `gen_subject_to_json` this migration replaces inserts
/// `apiGroup` whenever the `Option` is `Some`, even `Some("")` — upstream's own doc comment
/// ("Defaults to \"\" for ServiceAccount subjects") makes an explicitly-set empty string a
/// meaningful, distinct-from-absent value here, unlike every other string field on this message.
/// `kind`/`name`/`namespace` need no entry: the mechanical empty-string-filtering default already
/// matches the hand-rolled behaviour for those three.
fn subject_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "apiGroup" => Some(
            "    if let Some(v) = s.api_group {\n        m.insert(\"apiGroup\".to_string(), serde_json::Value::String(v));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_subject_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_subject(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SUBJECT);
    let encode_stmts =
        generate_message_encode_only(&set, SUBJECT, message, subject_delegated_field, "s", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_subject_to_json(s: rbac_v1::Subject) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_role_ref_to_json`, replacing the hand-rolled function of the same name. All
/// three `RoleRef` fields (`apiGroup`/`kind`/`name`) are plain `optional string` fields that
/// filter out an explicit empty string — unlike `Subject.apiGroup` above, `RoleRef.apiGroup`'s
/// hand-rolled counterpart already applied `.filter(|s| !s.is_empty())`, so the mechanical
/// walker's default reproduces it exactly with no delegate table needed.
pub fn generate_role_ref(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, ROLE_REF);
    let encode_stmts = generate_message_encode_only(&set, ROLE_REF, message, |_| None, "rr", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_role_ref_to_json(rr: rbac_v1::RoleRef) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `rules`
/// must be emitted unconditionally (even as `[]`) — upstream's `Rules []PolicyRule json:"rules"`
/// has no `omitempty` — which the mechanical `Type::Message if repeated` branch's own
/// only-insert-if-non-empty default gets wrong, so it delegates wholesale to the separately
/// generated `gen_policy_rule_to_json`. `aggregationRule` needs its own per-field override the
/// mechanical walker can't express: the hand-rolled `decode_clusterrole_proto_gen` this migration
/// retires only emits the key once `clusterRoleSelectors` is non-empty (an `AggregationRule` that
/// is `Some` but carries no selectors is dropped entirely, not emitted as `{}`), reusing the
/// existing hand-written `gen_label_selector_to_json` for each selector.
fn clusterrole_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(cr.metadata.unwrap_or_default()));\n",
        ),
        "rules" => Some(
            "    obj.insert(\"rules\".to_string(), serde_json::Value::Array(cr.rules.into_iter().map(gen_policy_rule_to_json).collect()));\n",
        ),
        "aggregationRule" => Some(
            "    if let Some(ar) = cr.aggregation_rule {\n        if !ar.cluster_role_selectors.is_empty() {\n            let selectors: Vec<serde_json::Value> = ar.cluster_role_selectors.into_iter().map(gen_label_selector_to_json).collect();\n            obj.insert(\"aggregationRule\".to_string(), serde_json::json!({ \"clusterRoleSelectors\": selectors }));\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_clusterrole_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_clusterrole_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `ClusterRole` has no
/// `encode_clusterrole_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_clusterrole(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CLUSTER_ROLE);
    let encode_stmts = generate_message_encode_only(
        &set,
        CLUSTER_ROLE,
        message,
        clusterrole_delegated_field,
        "cr",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_clusterrole_to_json(cr: rbac_v1::ClusterRole) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry.
/// `subjects` must be emitted unconditionally (even as `[]`) for the same
/// no-`omitempty`-upstream reason `clusterrole_delegated_field`'s own `rules` entry documents, so
/// it delegates wholesale to the separately generated `gen_subject_to_json`. `roleRef` must also
/// be emitted unconditionally — even an unset `RoleRef` decodes to `{}`, not an absent key, per
/// the pre-migration `.unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()))` this
/// entry reproduces exactly — unlike every other nested-message field this codegen module has met
/// so far, which omits the key entirely once the nested object is empty.
fn clusterrolebinding_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(crb.metadata.unwrap_or_default()));\n",
        ),
        "subjects" => Some(
            "    obj.insert(\"subjects\".to_string(), serde_json::Value::Array(crb.subjects.into_iter().map(gen_subject_to_json).collect()));\n",
        ),
        "roleRef" => Some(
            "    obj.insert(\"roleRef\".to_string(), crb.role_ref.map(gen_role_ref_to_json).unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_clusterrolebinding_to_json`, replacing the message-walking body of the
/// hand-rolled `decode_clusterrolebinding_proto_gen` this migration retires (the entry point
/// itself stays hand-written — see `generate_namespace`'s doc for why; `ClusterRoleBinding` has
/// no `encode_clusterrolebinding_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_clusterrolebinding(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CLUSTER_ROLE_BINDING);
    let encode_stmts = generate_message_encode_only(
        &set,
        CLUSTER_ROLE_BINDING,
        message,
        clusterrolebinding_delegated_field,
        "crb",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_clusterrolebinding_to_json(crb: rbac_v1::ClusterRoleBinding) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `rules`
/// delegates wholesale to `gen_policy_rule_to_json` for the same unconditional-emission reason
/// `clusterrole_delegated_field`'s own `rules` entry documents — `Role` and `ClusterRole` share
/// the identical upstream `Rules []PolicyRule json:"rules"` shape.
fn role_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(role.metadata.unwrap_or_default()));\n",
        ),
        "rules" => Some(
            "    obj.insert(\"rules\".to_string(), serde_json::Value::Array(role.rules.into_iter().map(gen_policy_rule_to_json).collect()));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_role_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_role_proto_gen` this migration retires (the entry point itself stays hand-written —
/// see `generate_namespace`'s doc for why; `Role` has no `encode_role_proto_gen` today, so this is
/// decode-only in the same sense).
pub fn generate_role(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, ROLE);
    let encode_stmts =
        generate_message_encode_only(&set, ROLE, message, role_delegated_field, "role", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_role_to_json(role: rbac_v1::Role) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata`/`subjects`/`roleRef` delegate for the same reasons
/// `clusterrolebinding_delegated_field`'s own entries document — `RoleBinding` and
/// `ClusterRoleBinding` share the identical upstream `Subjects`/`RoleRef` shape and JSON
/// semantics, just at a different scope (namespaced vs. cluster-wide).
fn rolebinding_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(rb.metadata.unwrap_or_default()));\n",
        ),
        "subjects" => Some(
            "    obj.insert(\"subjects\".to_string(), serde_json::Value::Array(rb.subjects.into_iter().map(gen_subject_to_json).collect()));\n",
        ),
        "roleRef" => Some(
            "    obj.insert(\"roleRef\".to_string(), rb.role_ref.map(gen_role_ref_to_json).unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new())));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_rolebinding_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_rolebinding_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `RoleBinding` has no
/// `encode_rolebinding_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_rolebinding(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, ROLE_BINDING);
    let encode_stmts = generate_message_encode_only(
        &set,
        ROLE_BINDING,
        message,
        rolebinding_delegated_field,
        "rb",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_rolebinding_to_json(rb: rbac_v1::RoleBinding) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const DEPLOYMENT: &str = ".k8s.io.api.apps.v1.Deployment";
const DEPLOYMENT_SPEC: &str = ".k8s.io.api.apps.v1.DeploymentSpec";
const DEPLOYMENT_STATUS: &str = ".k8s.io.api.apps.v1.DeploymentStatus";
const STATEFULSET: &str = ".k8s.io.api.apps.v1.StatefulSet";
const STATEFULSET_SPEC: &str = ".k8s.io.api.apps.v1.StatefulSetSpec";
const STATEFULSET_STATUS: &str = ".k8s.io.api.apps.v1.StatefulSetStatus";
const DAEMONSET: &str = ".k8s.io.api.apps.v1.DaemonSet";
const DAEMONSET_SPEC: &str = ".k8s.io.api.apps.v1.DaemonSetSpec";
const DAEMONSET_STATUS: &str = ".k8s.io.api.apps.v1.DaemonSetStatus";
const REPLICASET: &str = ".k8s.io.api.apps.v1.ReplicaSet";
const REPLICASET_SPEC: &str = ".k8s.io.api.apps.v1.ReplicaSetSpec";
const REPLICASET_STATUS: &str = ".k8s.io.api.apps.v1.ReplicaSetStatus";
const CONTROLLER_REVISION: &str = ".k8s.io.api.apps.v1.ControllerRevision";

/// `replicas` is unconditionally emitted, defaulting an unset field to `0` rather than omitting
/// the key — matching every apps/v1 workload spec's own "the API always reports a concrete
/// replica count" convention, the same shape `lease_spec_delegated_field`'s own zero-default
/// fields document but inverted (always-emit instead of only-emit-if-nonzero). `selector`
/// delegates wholesale to the hand-written `gen_apps_spec_to_json` (shared verbatim across all
/// four apps/v1 workload kinds this migration touches) and, in the same statement, consumes
/// `template` too — the mechanical walker has no per-field hook that lets two sibling proto
/// fields merge into one JSON object, so `template`'s own entry below is a deliberate no-op.
/// `strategy`'s own `rollingUpdate.maxUnavailable`/`.maxSurge` are `IntOrString`, opaque to the
/// mechanical walker (it only special-cases `Quantity` by FQN), so the whole field delegates to
/// the hand-written `gen_apps_int_or_string_to_json`. `minReadySeconds` is zero-filtered, unlike
/// the mechanical walker's default no-filter int32 handling. `paused` is only ever emitted when
/// `true`, never `false` — matching `kubectl rollout pause`/`resume`'s own asymmetric JSON patch,
/// which only ever sets `paused: true` and unsets the field entirely to resume, never sends
/// `paused: false`. `revisionHistoryLimit`/`progressDeadlineSeconds` need no entry: the
/// mechanical walker's default "emit whenever `Some`, no zero filter" int32 handling already
/// matches the pre-migration decoder exactly.
fn deployment_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    m.insert(\"replicas\".to_string(), serde_json::Value::Number(spec.replicas.unwrap_or(0).into()));\n",
        ),
        "selector" => Some(
            "    if let Some(serde_json::Value::Object(sm)) = gen_apps_spec_to_json(spec.selector, spec.template) {\n        m.extend(sm);\n    }\n",
        ),
        "template" => Some(""),
        "strategy" => Some(
            "    if let Some(strategy) = spec.strategy {\n        let mut strategy_json = serde_json::json!({});\n        if let Some(t) = strategy.r#type.filter(|s| !s.is_empty()) {\n            strategy_json[\"type\"] = t.into();\n        }\n        if let Some(ru) = strategy.rolling_update {\n            let mut ru_json = serde_json::json!({});\n            if let Some(mu) = ru.max_unavailable {\n                ru_json[\"maxUnavailable\"] = gen_apps_int_or_string_to_json(mu);\n            }\n            if let Some(ms) = ru.max_surge {\n                ru_json[\"maxSurge\"] = gen_apps_int_or_string_to_json(ms);\n            }\n            if !ru_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n                strategy_json[\"rollingUpdate\"] = ru_json;\n            }\n        }\n        if !strategy_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n            m.insert(\"strategy\".to_string(), strategy_json);\n        }\n    }\n",
        ),
        "minReadySeconds" => Some(
            "    if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {\n        m.insert(\"minReadySeconds\".to_string(), v.into());\n    }\n",
        ),
        "paused" => Some(
            "    if let Some(true) = spec.paused {\n        m.insert(\"paused\".to_string(), true.into());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_deployment_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_deployment_proto_gen` this migration retires.
pub fn generate_deployment_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DEPLOYMENT_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        DEPLOYMENT_SPEC,
        message,
        deployment_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_deployment_spec_to_json(spec: apps_v1::DeploymentSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Every numeric field here is zero-filtered (unlike the mechanical walker's default no-filter
/// int32/int64 handling) — an explicit `0` is indistinguishable on the wire from "never set" for
/// every one of these gauges, the same reasoning `pod_status_delegated_field`'s own
/// `observedGeneration` entry documents. `conditions` needs the shared `apps_condition_to_json!`
/// macro (defined in `src/apps_gen_adapter.rs`, in scope for this `include!`d code) plus
/// `DeploymentCondition`'s own extra `lastUpdateTime` field, which the other three apps/v1
/// condition types don't have — the deployment controller's `progressDeadlineSeconds` check
/// depends on this timestamp to tell whether a rollout has actually stalled.
fn deployment_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "observedGeneration" => Some(
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
        ),
        "replicas" => Some(
            "    if let Some(v) = status.replicas.filter(|&v| v != 0) {\n        m.insert(\"replicas\".to_string(), v.into());\n    }\n",
        ),
        "updatedReplicas" => Some(
            "    if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {\n        m.insert(\"updatedReplicas\".to_string(), v.into());\n    }\n",
        ),
        "readyReplicas" => Some(
            "    if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {\n        m.insert(\"readyReplicas\".to_string(), v.into());\n    }\n",
        ),
        "availableReplicas" => Some(
            "    if let Some(v) = status.available_replicas.filter(|&v| v != 0) {\n        m.insert(\"availableReplicas\".to_string(), v.into());\n    }\n",
        ),
        "unavailableReplicas" => Some(
            "    if let Some(v) = status.unavailable_replicas.filter(|&v| v != 0) {\n        m.insert(\"unavailableReplicas\".to_string(), v.into());\n    }\n",
        ),
        "terminatingReplicas" => Some(
            "    if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {\n        m.insert(\"terminatingReplicas\".to_string(), v.into());\n    }\n",
        ),
        "collisionCount" => Some(
            "    if let Some(v) = status.collision_count.filter(|&v| v != 0) {\n        m.insert(\"collisionCount\".to_string(), v.into());\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        m.insert(\"conditions\".to_string(), status.conditions.iter().map(|c| {\n            let mut cond = apps_condition_to_json!(c);\n            if let Some(t) = c.last_update_time.as_ref() {\n                if let Some(secs) = t.seconds.filter(|&s| s > 0) {\n                    cond[\"lastUpdateTime\"] = crate::util::secs_to_rfc3339(secs).into();\n                }\n            }\n            cond\n        }).collect());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_deployment_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_deployment_proto_gen` this migration retires.
pub fn generate_deployment_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DEPLOYMENT_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        DEPLOYMENT_STATUS,
        message,
        deployment_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_deployment_status_to_json(status: apps_v1::DeploymentStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as `namespace_delegated_field`'s own entry. `spec`/
/// `status` delegate to the separately generated `gen_deployment_spec_to_json`/
/// `gen_deployment_status_to_json`, only inserted once non-empty — matching the pre-migration
/// `decode_deployment_proto_gen`'s own `if !spec_json.is_empty() { ... }`/`if !status_json.is_empty()
/// { ... }` guards exactly.
fn deployment_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(deploy.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = deploy.spec {\n        let spec_json = gen_deployment_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = deploy.status {\n        let status_json = gen_deployment_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_deployment_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_deployment_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `Deployment` has no
/// `encode_deployment_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_deployment(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DEPLOYMENT);
    let encode_stmts = generate_message_encode_only(
        &set,
        DEPLOYMENT,
        message,
        deployment_delegated_field,
        "deploy",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_deployment_to_json(deploy: apps_v1::Deployment) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `replicas`/`selector`+`template` mirror `deployment_spec_delegated_field`'s own entries
/// exactly (StatefulSet shares the same "always report a concrete replica count" and
/// selector/template merge trick). `volumeClaimTemplates` delegates wholesale to the hand-written
/// `gen_persistent_volume_claim_to_json` (already covers `PersistentVolumeClaim`'s own
/// completeness, tested separately in `core_gen_adapter.rs`) — this is the field StatefulSet
/// exists for, per the type's own doc comment. `updateStrategy`'s own
/// `rollingUpdate.maxUnavailable` is `IntOrString` (same reasoning as Deployment's `strategy`)
/// and `rollingUpdate.partition` is unconditionally emitted (defaulting to `0`), so the whole
/// field delegates. `minReadySeconds` is zero-filtered. `persistentVolumeClaimRetentionPolicy`
/// only inserts once its own `whenDeleted`/`whenScaled` sub-fields produce a non-empty object —
/// past this mechanical walker's one-level override hook, the same limitation
/// `service_spec_delegated_field`'s own `sessionAffinityConfig` entry documents. `ordinals` is
/// unconditionally `{"start": ord.start.unwrap_or(0)}` whenever the outer `Option` is `Some`,
/// regardless of whether `start` itself was ever set — unlike every other nested-message field in
/// this file, which only inserts once genuinely non-empty. `serviceName`/`podManagementPolicy`/
/// `revisionHistoryLimit` need no entry: the mechanical walker's defaults already match the
/// pre-migration decoder exactly.
fn statefulset_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    m.insert(\"replicas\".to_string(), serde_json::Value::Number(spec.replicas.unwrap_or(0).into()));\n",
        ),
        "selector" => Some(
            "    if let Some(serde_json::Value::Object(sm)) = gen_apps_spec_to_json(spec.selector, spec.template) {\n        m.extend(sm);\n    }\n",
        ),
        "template" => Some(""),
        "volumeClaimTemplates" => Some(
            "    if !spec.volume_claim_templates.is_empty() {\n        m.insert(\"volumeClaimTemplates\".to_string(), spec.volume_claim_templates.into_iter().map(gen_persistent_volume_claim_to_json).collect::<Vec<_>>().into());\n    }\n",
        ),
        "updateStrategy" => Some(
            "    if let Some(us) = spec.update_strategy {\n        let mut us_json = serde_json::json!({});\n        if let Some(t) = us.r#type.filter(|s| !s.is_empty()) {\n            us_json[\"type\"] = t.into();\n        }\n        if let Some(ru) = us.rolling_update {\n            let mut ru_json = serde_json::json!({ \"partition\": ru.partition.unwrap_or(0) });\n            if let Some(mu) = ru.max_unavailable {\n                ru_json[\"maxUnavailable\"] = gen_apps_int_or_string_to_json(mu);\n            }\n            us_json[\"rollingUpdate\"] = ru_json;\n        }\n        if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n            m.insert(\"updateStrategy\".to_string(), us_json);\n        }\n    }\n",
        ),
        "minReadySeconds" => Some(
            "    if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {\n        m.insert(\"minReadySeconds\".to_string(), v.into());\n    }\n",
        ),
        "persistentVolumeClaimRetentionPolicy" => Some(
            "    if let Some(rp) = spec.persistent_volume_claim_retention_policy {\n        let mut rp_json = serde_json::json!({});\n        if let Some(v) = rp.when_deleted.filter(|s| !s.is_empty()) {\n            rp_json[\"whenDeleted\"] = v.into();\n        }\n        if let Some(v) = rp.when_scaled.filter(|s| !s.is_empty()) {\n            rp_json[\"whenScaled\"] = v.into();\n        }\n        if !rp_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n            m.insert(\"persistentVolumeClaimRetentionPolicy\".to_string(), rp_json);\n        }\n    }\n",
        ),
        "ordinals" => Some(
            "    if let Some(ord) = spec.ordinals {\n        m.insert(\"ordinals\".to_string(), serde_json::json!({ \"start\": ord.start.unwrap_or(0) }));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_statefulset_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_statefulset_proto_gen` this migration retires.
pub fn generate_statefulset_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, STATEFULSET_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        STATEFULSET_SPEC,
        message,
        statefulset_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_statefulset_spec_to_json(spec: apps_v1::StatefulSetSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Every numeric field here is zero-filtered, the same reasoning
/// `deployment_status_delegated_field` documents. `conditions` uses the shared
/// `apps_condition_to_json!` macro with no extra field (only `DeploymentCondition` has
/// `lastUpdateTime`). `currentRevision`/`updateRevision` need no entry: plain optional strings
/// the mechanical walker already handles correctly.
fn statefulset_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "observedGeneration" => Some(
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
        ),
        "replicas" => Some(
            "    if let Some(v) = status.replicas.filter(|&v| v != 0) {\n        m.insert(\"replicas\".to_string(), v.into());\n    }\n",
        ),
        "readyReplicas" => Some(
            "    if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {\n        m.insert(\"readyReplicas\".to_string(), v.into());\n    }\n",
        ),
        "currentReplicas" => Some(
            "    if let Some(v) = status.current_replicas.filter(|&v| v != 0) {\n        m.insert(\"currentReplicas\".to_string(), v.into());\n    }\n",
        ),
        "updatedReplicas" => Some(
            "    if let Some(v) = status.updated_replicas.filter(|&v| v != 0) {\n        m.insert(\"updatedReplicas\".to_string(), v.into());\n    }\n",
        ),
        "collisionCount" => Some(
            "    if let Some(v) = status.collision_count.filter(|&v| v != 0) {\n        m.insert(\"collisionCount\".to_string(), v.into());\n    }\n",
        ),
        "availableReplicas" => Some(
            "    if let Some(v) = status.available_replicas.filter(|&v| v != 0) {\n        m.insert(\"availableReplicas\".to_string(), v.into());\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        m.insert(\"conditions\".to_string(), status.conditions.iter().map(|c| apps_condition_to_json!(c)).collect());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_statefulset_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_statefulset_proto_gen` this migration retires.
pub fn generate_statefulset_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, STATEFULSET_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        STATEFULSET_STATUS,
        message,
        statefulset_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_statefulset_status_to_json(status: apps_v1::StatefulSetStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Mirrors `deployment_delegated_field` exactly, delegating `spec`/`status` to the separately
/// generated `gen_statefulset_spec_to_json`/`gen_statefulset_status_to_json`.
fn statefulset_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(sts.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = sts.spec {\n        let spec_json = gen_statefulset_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = sts.status {\n        let status_json = gen_statefulset_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_statefulset_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_statefulset_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `StatefulSet` has no
/// `encode_statefulset_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_statefulset(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, STATEFULSET);
    let encode_stmts = generate_message_encode_only(
        &set,
        STATEFULSET,
        message,
        statefulset_delegated_field,
        "sts",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_statefulset_to_json(sts: apps_v1::StatefulSet) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `selector`+`template` merge the same way `deployment_spec_delegated_field`'s own entries do.
/// `updateStrategy`'s own `rollingUpdate.maxUnavailable`/`.maxSurge` are `IntOrString`, so the
/// whole field delegates (DaemonSet's `RollingUpdateDaemonSet` has no `partition`, unlike
/// StatefulSet's own rolling-update strategy). `minReadySeconds` is zero-filtered.
/// `revisionHistoryLimit` needs no entry: the mechanical walker's default already matches.
/// DaemonSet has no `replicas` field (node-count is implicit in the node selector/taints match),
/// unlike the other three apps/v1 workload kinds.
fn daemonset_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "selector" => Some(
            "    if let Some(serde_json::Value::Object(sm)) = gen_apps_spec_to_json(spec.selector, spec.template) {\n        m.extend(sm);\n    }\n",
        ),
        "template" => Some(""),
        "updateStrategy" => Some(
            "    if let Some(us) = spec.update_strategy {\n        let mut us_json = serde_json::json!({});\n        if let Some(t) = us.r#type.filter(|s| !s.is_empty()) {\n            us_json[\"type\"] = t.into();\n        }\n        if let Some(ru) = us.rolling_update {\n            let mut ru_json = serde_json::json!({});\n            if let Some(mu) = ru.max_unavailable {\n                ru_json[\"maxUnavailable\"] = gen_apps_int_or_string_to_json(mu);\n            }\n            if let Some(ms) = ru.max_surge {\n                ru_json[\"maxSurge\"] = gen_apps_int_or_string_to_json(ms);\n            }\n            if !ru_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n                us_json[\"rollingUpdate\"] = ru_json;\n            }\n        }\n        if !us_json.as_object().map(|m| m.is_empty()).unwrap_or(true) {\n            m.insert(\"updateStrategy\".to_string(), us_json);\n        }\n    }\n",
        ),
        "minReadySeconds" => Some(
            "    if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {\n        m.insert(\"minReadySeconds\".to_string(), v.into());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_daemonset_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_daemonset_proto_gen` this migration retires.
pub fn generate_daemonset_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DAEMONSET_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        DAEMONSET_SPEC,
        message,
        daemonset_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_daemonset_spec_to_json(spec: apps_v1::DaemonSetSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Every numeric field here is zero-filtered, the same reasoning
/// `deployment_status_delegated_field` documents. `conditions` uses the shared
/// `apps_condition_to_json!` macro with no extra field.
fn daemonset_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "currentNumberScheduled" => Some(
            "    if let Some(v) = status.current_number_scheduled.filter(|&v| v != 0) {\n        m.insert(\"currentNumberScheduled\".to_string(), v.into());\n    }\n",
        ),
        "numberMisscheduled" => Some(
            "    if let Some(v) = status.number_misscheduled.filter(|&v| v != 0) {\n        m.insert(\"numberMisscheduled\".to_string(), v.into());\n    }\n",
        ),
        "desiredNumberScheduled" => Some(
            "    if let Some(v) = status.desired_number_scheduled.filter(|&v| v != 0) {\n        m.insert(\"desiredNumberScheduled\".to_string(), v.into());\n    }\n",
        ),
        "numberReady" => Some(
            "    if let Some(v) = status.number_ready.filter(|&v| v != 0) {\n        m.insert(\"numberReady\".to_string(), v.into());\n    }\n",
        ),
        "observedGeneration" => Some(
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
        ),
        "updatedNumberScheduled" => Some(
            "    if let Some(v) = status.updated_number_scheduled.filter(|&v| v != 0) {\n        m.insert(\"updatedNumberScheduled\".to_string(), v.into());\n    }\n",
        ),
        "numberAvailable" => Some(
            "    if let Some(v) = status.number_available.filter(|&v| v != 0) {\n        m.insert(\"numberAvailable\".to_string(), v.into());\n    }\n",
        ),
        "numberUnavailable" => Some(
            "    if let Some(v) = status.number_unavailable.filter(|&v| v != 0) {\n        m.insert(\"numberUnavailable\".to_string(), v.into());\n    }\n",
        ),
        "collisionCount" => Some(
            "    if let Some(v) = status.collision_count.filter(|&v| v != 0) {\n        m.insert(\"collisionCount\".to_string(), v.into());\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        m.insert(\"conditions\".to_string(), status.conditions.iter().map(|c| apps_condition_to_json!(c)).collect());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_daemonset_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_daemonset_proto_gen` this migration retires.
pub fn generate_daemonset_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DAEMONSET_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        DAEMONSET_STATUS,
        message,
        daemonset_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_daemonset_status_to_json(status: apps_v1::DaemonSetStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Mirrors `deployment_delegated_field` exactly, delegating `spec`/`status` to the separately
/// generated `gen_daemonset_spec_to_json`/`gen_daemonset_status_to_json`.
fn daemonset_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(ds.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = ds.spec {\n        let spec_json = gen_daemonset_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = ds.status {\n        let status_json = gen_daemonset_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_daemonset_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_daemonset_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `DaemonSet` has no
/// `encode_daemonset_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_daemonset(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DAEMONSET);
    let encode_stmts = generate_message_encode_only(
        &set,
        DAEMONSET,
        message,
        daemonset_delegated_field,
        "ds",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_daemonset_to_json(ds: apps_v1::DaemonSet) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `replicas`/`selector`+`template` mirror `deployment_spec_delegated_field`'s own entries.
/// `minReadySeconds` is zero-filtered.
fn replicaset_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    m.insert(\"replicas\".to_string(), serde_json::Value::Number(spec.replicas.unwrap_or(0).into()));\n",
        ),
        "minReadySeconds" => Some(
            "    if let Some(v) = spec.min_ready_seconds.filter(|&v| v != 0) {\n        m.insert(\"minReadySeconds\".to_string(), v.into());\n    }\n",
        ),
        "selector" => Some(
            "    if let Some(serde_json::Value::Object(sm)) = gen_apps_spec_to_json(spec.selector, spec.template) {\n        m.extend(sm);\n    }\n",
        ),
        "template" => Some(""),
        _ => None,
    }
}

/// Generates `gen_replicaset_spec_to_json`, replacing the `spec` assembly block of the
/// hand-rolled `decode_replicaset_proto_gen` this migration retires.
pub fn generate_replicaset_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICASET_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICASET_SPEC,
        message,
        replicaset_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_replicaset_spec_to_json(spec: apps_v1::ReplicaSetSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Every numeric field here is zero-filtered, the same reasoning
/// `deployment_status_delegated_field` documents. `conditions` uses the shared
/// `apps_condition_to_json!` macro with no extra field.
fn replicaset_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "replicas" => Some(
            "    if let Some(v) = status.replicas.filter(|&v| v != 0) {\n        m.insert(\"replicas\".to_string(), v.into());\n    }\n",
        ),
        "fullyLabeledReplicas" => Some(
            "    if let Some(v) = status.fully_labeled_replicas.filter(|&v| v != 0) {\n        m.insert(\"fullyLabeledReplicas\".to_string(), v.into());\n    }\n",
        ),
        "observedGeneration" => Some(
            "    if let Some(v) = status.observed_generation.filter(|&v| v != 0) {\n        m.insert(\"observedGeneration\".to_string(), v.into());\n    }\n",
        ),
        "readyReplicas" => Some(
            "    if let Some(v) = status.ready_replicas.filter(|&v| v != 0) {\n        m.insert(\"readyReplicas\".to_string(), v.into());\n    }\n",
        ),
        "availableReplicas" => Some(
            "    if let Some(v) = status.available_replicas.filter(|&v| v != 0) {\n        m.insert(\"availableReplicas\".to_string(), v.into());\n    }\n",
        ),
        "terminatingReplicas" => Some(
            "    if let Some(v) = status.terminating_replicas.filter(|&v| v != 0) {\n        m.insert(\"terminatingReplicas\".to_string(), v.into());\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        m.insert(\"conditions\".to_string(), status.conditions.iter().map(|c| apps_condition_to_json!(c)).collect());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_replicaset_status_to_json`, replacing the `status` assembly block of the
/// hand-rolled `decode_replicaset_proto_gen` this migration retires.
pub fn generate_replicaset_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICASET_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICASET_STATUS,
        message,
        replicaset_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_replicaset_status_to_json(status: apps_v1::ReplicaSetStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Mirrors `deployment_delegated_field` exactly, delegating `spec`/`status` to the separately
/// generated `gen_replicaset_spec_to_json`/`gen_replicaset_status_to_json`.
fn replicaset_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(rs.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = rs.spec {\n        let spec_json = gen_replicaset_spec_to_json(spec);\n        if spec_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"spec\".to_string(), spec_json);\n        }\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = rs.status {\n        let status_json = gen_replicaset_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_replicaset_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_replicaset_proto_gen` this migration retires (the entry point itself stays
/// hand-written — see `generate_namespace`'s doc for why; `ReplicaSet` has no
/// `encode_replicaset_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_replicaset(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, REPLICASET);
    let encode_stmts = generate_message_encode_only(
        &set,
        REPLICASET,
        message,
        replicaset_delegated_field,
        "rs",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_replicaset_to_json(rs: apps_v1::ReplicaSet) -> serde_json::Value {\n");
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `revision` is
/// unconditionally emitted, defaulting an unset field to `0` — matching every other apps/v1
/// workload's own "always report a concrete value" convention for this class of int field.
/// `data` is a `RawExtension`: the same opaque-scalar handling every other `RawExtension` field in
/// this codebase gets (inline the embedded document as JSON), except this one is silently dropped
/// entirely if the raw bytes fail to parse as JSON, matching the pre-migration decoder's own
/// `if let Ok(parsed) = ... { out["data"] = parsed; }` (no fallback, no error surfaced) exactly —
/// the StatefulSet/DaemonSet history controllers roll back by matching on `revision` and
/// replaying `data`; losing either makes a rollback silently replay the wrong (or no) state.
fn controllerrevision_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(cr.metadata.unwrap_or_default()));\n",
        ),
        "data" => Some(
            "    if let Some(raw_ext) = cr.data {\n        if let Some(raw) = raw_ext.raw {\n            if !raw.is_empty() {\n                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&raw) {\n                    obj.insert(\"data\".to_string(), parsed);\n                }\n            }\n        }\n    }\n",
        ),
        "revision" => Some(
            "    obj.insert(\"revision\".to_string(), serde_json::Value::Number(cr.revision.unwrap_or(0).into()));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_controllerrevision_to_json`, replacing the message-walking body of the
/// hand-rolled `decode_controllerrevision_proto_gen` this migration retires (the entry point
/// itself stays hand-written — see `generate_namespace`'s doc for why; `ControllerRevision` has
/// no `encode_controllerrevision_proto_gen` today, so this is decode-only in the same sense).
pub fn generate_controllerrevision(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CONTROLLER_REVISION);
    let encode_stmts = generate_message_encode_only(
        &set,
        CONTROLLER_REVISION,
        message,
        controllerrevision_delegated_field,
        "cr",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_controllerrevision_to_json(cr: apps_v1::ControllerRevision) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const JSON_SCHEMA_PROPS: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps";
const VALIDATION_RULE: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.ValidationRule";
const CRD_SERVICE_REFERENCE: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.ServiceReference";
const CRD_WEBHOOK_CLIENT_CONFIG: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.WebhookClientConfig";
const WEBHOOK_CONVERSION: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.WebhookConversion";
const CRD_CONVERSION: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceConversion";
const CRD_NAMES: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinitionNames";
const PRINTER_COLUMN: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceColumnDefinition";
const SELECTABLE_FIELD: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.SelectableField";
const SUBRESOURCE_SCALE: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceSubresourceScale";
const SUBRESOURCES: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceSubresources";
const CRD_VERSION: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinitionVersion";
const CRD_STATUS: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinitionStatus";
const CRD_SPEC: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinitionSpec";
const CRD: &str =
    ".k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.CustomResourceDefinition";
const DELETE_OPTIONS: &str = ".k8s.io.apimachinery.pkg.apis.meta.v1.DeleteOptions";

/// `optionalOldSelf` is the only `ValidationRule` field needing more than the mechanical default:
/// the hand-rolled `x-kubernetes-validations` closure this migration replaces only ever emits it
/// when `true` (`r.optional_old_self.filter(|&b| b)`), the same true-only-guard class as
/// `Container`'s `stdin`/`stdinOnce`/`tty`. `rule`/`message`/`messageExpression`/`reason`/
/// `fieldPath` are all plain `optional string` fields the mechanical walker's
/// empty-string-filtering default already reproduces exactly.
fn validation_rule_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "optionalOldSelf" => Some(
            "    if let Some(v) = r.optional_old_self.filter(|&b| b) {\n        m.insert(\"optionalOldSelf\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validation_rule_to_json`, replacing the inline `x-kubernetes-validations`
/// closure of the hand-rolled `gen_json_schema_props_to_json` this migration retires.
pub fn generate_validation_rule(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATION_RULE);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATION_RULE,
        message,
        validation_rule_delegated_field,
        "r",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validation_rule_to_json(r: apiext_v1::ValidationRule) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `JSONSchemaProps` is the only self-referential message this codegen module generates a codec
/// for: `properties`/`patternProperties`/`definitions` (`map<string, JSONSchemaProps>`),
/// `allOf`/`oneOf`/`anyOf` (`repeated JSONSchemaProps`), and `not`/`items.schema`/
/// `additionalProperties.schema`/`additionalItems.schema`/`dependencies[].schema` (each a
/// `JSONSchemaProps`, some `Box`ed by prost to break the otherwise-infinite struct size) all
/// eventually contain another `JSONSchemaProps`. The mechanical walker's own recursion
/// (`emit_mechanical_encode`/`emit_field_encode`'s `Type::Message` branches) has no cycle guard —
/// unlike `proto_descriptor.rs::walk()`'s `stack` check — because every other message this module
/// has generated a codec for is finitely nested (a fixed, schema-visible depth); letting any of
/// these fields fall through to that generic recursive-inlining branch would make
/// `find_message`/`emit_mechanical_encode` recurse forever at build time (an infinite string, not
/// a compile error). Every self-referential field is therefore delegated to a hand-templated
/// snippet that calls `gen_json_schema_props_to_json` **by name** — the same shape the hand-rolled
/// function this migration replaces already uses for its own recursive calls — so the *generated*
/// function recurses at Rust run time, not at codegen build time.
///
/// Every field below that is not self-referential is delegated here too if it needs anything
/// beyond the mechanical default: the two `double`-typed fields (`maximum`/`minimum`/
/// `multipleOf` — `Type::Double` has no arm in `emit_field_encode`, the same gap `Type::Bytes` had
/// before `apiservice_spec_delegated_field`'s `caBundle` entry), the true-only-guarded bool fields
/// (`exclusiveMaximum`/`exclusiveMinimum`/`uniqueItems`/`nullable`/the three `xKubernetes*`
/// booleans — the same class as `Container.stdin`), `default`/`example`/`enum` (each wraps or
/// contains the opaque `JSON` scalar type, handled by the hand-written `gen_json_raw_to_value`),
/// and `xKubernetesValidations` (delegates to the separately generated
/// `gen_validation_rule_to_json`). Only `id`/`schema`($schema)/`ref`($ref)/`description`/`type`/
/// `format`/`title`/`pattern`/`maxLength`/`minLength`/`maxItems`/`minItems`/`maxProperties`/
/// `minProperties`/`required`/`xKubernetesListMapKeys`/`xKubernetesListType`/
/// `xKubernetesMapType`/`externalDocs` are left mechanical — `externalDocs`
/// (`ExternalDocumentation { description, url }`) is a genuinely finite, non-recursive nested
/// message, so the generic `Type::Message` branch already reproduces the hand-rolled
/// `if !ed_m.is_empty() { ... }` guard exactly.
fn json_schema_props_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "default" => Some(
            "    if let Some(v) = schema.default {\n        let raw = gen_json_raw_to_value(v);\n        if !raw.is_null() {\n            m.insert(\"default\".to_string(), raw);\n        }\n    }\n",
        ),
        "maximum" => Some(
            "    if let Some(v) = schema.maximum {\n        m.insert(\"maximum\".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0))));\n    }\n",
        ),
        "exclusiveMaximum" => Some(
            "    if let Some(v) = schema.exclusive_maximum.filter(|&b| b) {\n        m.insert(\"exclusiveMaximum\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "minimum" => Some(
            "    if let Some(v) = schema.minimum {\n        m.insert(\"minimum\".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0))));\n    }\n",
        ),
        "exclusiveMinimum" => Some(
            "    if let Some(v) = schema.exclusive_minimum.filter(|&b| b) {\n        m.insert(\"exclusiveMinimum\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "uniqueItems" => Some(
            "    if let Some(v) = schema.unique_items.filter(|&b| b) {\n        m.insert(\"uniqueItems\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "multipleOf" => Some(
            "    if let Some(v) = schema.multiple_of {\n        m.insert(\"multipleOf\".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(v).unwrap_or_else(|| serde_json::Number::from(0))));\n    }\n",
        ),
        "enum" => Some(
            "    if !schema.r#enum.is_empty() {\n        let enum_vals: Vec<serde_json::Value> = schema.r#enum.into_iter().map(gen_json_raw_to_value).collect();\n        m.insert(\"enum\".to_string(), serde_json::Value::Array(enum_vals));\n    }\n",
        ),
        "items" => Some(
            "    if let Some(boxed) = schema.items {\n        let items_val = if let Some(s) = boxed.schema {\n            gen_json_schema_props_to_json(*s)\n        } else if !boxed.j_son_schemas.is_empty() {\n            serde_json::Value::Array(boxed.j_son_schemas.into_iter().map(gen_json_schema_props_to_json).collect())\n        } else {\n            serde_json::Value::Object(serde_json::Map::new())\n        };\n        m.insert(\"items\".to_string(), items_val);\n    }\n",
        ),
        "allOf" => Some(
            "    if !schema.all_of.is_empty() {\n        m.insert(\"allOf\".to_string(), serde_json::Value::Array(schema.all_of.into_iter().map(gen_json_schema_props_to_json).collect()));\n    }\n",
        ),
        "oneOf" => Some(
            "    if !schema.one_of.is_empty() {\n        m.insert(\"oneOf\".to_string(), serde_json::Value::Array(schema.one_of.into_iter().map(gen_json_schema_props_to_json).collect()));\n    }\n",
        ),
        "anyOf" => Some(
            "    if !schema.any_of.is_empty() {\n        m.insert(\"anyOf\".to_string(), serde_json::Value::Array(schema.any_of.into_iter().map(gen_json_schema_props_to_json).collect()));\n    }\n",
        ),
        "not" => Some(
            "    if let Some(boxed) = schema.not {\n        m.insert(\"not\".to_string(), gen_json_schema_props_to_json(*boxed));\n    }\n",
        ),
        "properties" => Some(
            "    if !schema.properties.is_empty() {\n        let props: serde_json::Map<String, serde_json::Value> = schema.properties.into_iter().map(|(k, v)| (k, gen_json_schema_props_to_json(v))).collect();\n        m.insert(\"properties\".to_string(), serde_json::Value::Object(props));\n    }\n",
        ),
        "additionalProperties" => Some(
            "    if let Some(boxed) = schema.additional_properties {\n        let ap_val = match (boxed.allows, boxed.schema) {\n            (_, Some(s)) => gen_json_schema_props_to_json(*s),\n            (Some(b), None) => serde_json::Value::Bool(b),\n            (None, None) => serde_json::Value::Object(serde_json::Map::new()),\n        };\n        m.insert(\"additionalProperties\".to_string(), ap_val);\n    }\n",
        ),
        "patternProperties" => Some(
            "    if !schema.pattern_properties.is_empty() {\n        let pp: serde_json::Map<String, serde_json::Value> = schema.pattern_properties.into_iter().map(|(k, v)| (k, gen_json_schema_props_to_json(v))).collect();\n        m.insert(\"patternProperties\".to_string(), serde_json::Value::Object(pp));\n    }\n",
        ),
        "dependencies" => Some(
            "    if !schema.dependencies.is_empty() {\n        let deps: serde_json::Map<String, serde_json::Value> = schema.dependencies.into_iter().map(|(k, v)| {\n            let mut dep_m = serde_json::Map::new();\n            if let Some(s) = v.schema {\n                dep_m.insert(\"schema\".to_string(), gen_json_schema_props_to_json(s));\n            }\n            if !v.property.is_empty() {\n                dep_m.insert(\"property\".to_string(), serde_json::Value::Array(v.property.into_iter().map(serde_json::Value::String).collect()));\n            }\n            (k, serde_json::Value::Object(dep_m))\n        }).collect();\n        m.insert(\"dependencies\".to_string(), serde_json::Value::Object(deps));\n    }\n",
        ),
        "additionalItems" => Some(
            "    if let Some(boxed) = schema.additional_items {\n        let ai_val = match (boxed.allows, boxed.schema) {\n            (_, Some(s)) => gen_json_schema_props_to_json(*s),\n            (Some(b), None) => serde_json::Value::Bool(b),\n            (None, None) => serde_json::Value::Object(serde_json::Map::new()),\n        };\n        m.insert(\"additionalItems\".to_string(), ai_val);\n    }\n",
        ),
        "definitions" => Some(
            "    if !schema.definitions.is_empty() {\n        let defs: serde_json::Map<String, serde_json::Value> = schema.definitions.into_iter().map(|(k, v)| (k, gen_json_schema_props_to_json(v))).collect();\n        m.insert(\"definitions\".to_string(), serde_json::Value::Object(defs));\n    }\n",
        ),
        "example" => Some(
            "    if let Some(ex) = schema.example {\n        let raw = gen_json_raw_to_value(ex);\n        if !raw.is_null() {\n            m.insert(\"example\".to_string(), raw);\n        }\n    }\n",
        ),
        "nullable" => Some(
            "    if let Some(v) = schema.nullable.filter(|&b| b) {\n        m.insert(\"nullable\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "xKubernetesPreserveUnknownFields" => Some(
            "    if let Some(v) = schema.x_kubernetes_preserve_unknown_fields.filter(|&b| b) {\n        m.insert(\"x-kubernetes-preserve-unknown-fields\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "xKubernetesEmbeddedResource" => Some(
            "    if let Some(v) = schema.x_kubernetes_embedded_resource.filter(|&b| b) {\n        m.insert(\"x-kubernetes-embedded-resource\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "xKubernetesIntOrString" => Some(
            "    if let Some(v) = schema.x_kubernetes_int_or_string.filter(|&b| b) {\n        m.insert(\"x-kubernetes-int-or-string\".to_string(), serde_json::Value::Bool(v));\n    }\n",
        ),
        "xKubernetesValidations" => Some(
            "    if !schema.x_kubernetes_validations.is_empty() {\n        let rules: Vec<serde_json::Value> = schema.x_kubernetes_validations.into_iter().map(gen_validation_rule_to_json).collect();\n        m.insert(\"x-kubernetes-validations\".to_string(), serde_json::Value::Array(rules));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates the recursive `gen_json_schema_props_to_json`, replacing the hand-rolled function of
/// the same name — see `json_schema_props_delegated_field`'s doc for why this type needs its own
/// delegate table rather than reusing another generator's.
pub fn generate_json_schema_props(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, JSON_SCHEMA_PROPS);
    let encode_stmts = generate_message_encode_only(
        &set,
        JSON_SCHEMA_PROPS,
        message,
        json_schema_props_delegated_field,
        "schema",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_json_schema_props_to_json(schema: apiext_v1::JsonSchemaProps) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_crd_names_to_json`, replacing the hand-rolled function of the same name. Every
/// field (`plural`/`singular`/`kind`/`listKind` — plain strings — and `shortNames`/`categories` —
/// plain repeated strings) is already exactly what the mechanical walker's defaults produce, so no
/// delegate table is needed.
pub fn generate_crd_names(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_NAMES);
    let encode_stmts =
        generate_message_encode_only(&set, CRD_NAMES, message, |_| None, "names", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_crd_names_to_json(names: apiext_v1::CustomResourceDefinitionNames) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `priority` is the only `CustomResourceColumnDefinition` field the mechanical walker gets
/// wrong: the hand-rolled function this migration replaces only emits it when non-zero
/// (`col.priority.filter(|&p| p != 0)`) — a zero priority is indistinguishable from "unset" per
/// upstream's own doc comment ("Columns ... should be given a priority greater than 0"), the same
/// class of guard as `PodStatus.observedGeneration`.
fn printer_column_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "priority" => Some(
            "    if let Some(v) = col.priority.filter(|&p| p != 0) {\n        m.insert(\"priority\".to_string(), serde_json::Value::Number(v.into()));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_printer_column_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_printer_column(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PRINTER_COLUMN);
    let encode_stmts = generate_message_encode_only(
        &set,
        PRINTER_COLUMN,
        message,
        printer_column_delegated_field,
        "col",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_printer_column_to_json(col: apiext_v1::CustomResourceColumnDefinition) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_selectable_field_to_json`, replacing the hand-rolled function of the same name.
/// `SelectableField`'s single field (`jsonPath`, a plain string) is already exactly what the
/// mechanical walker's default produces.
pub fn generate_selectable_field(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SELECTABLE_FIELD);
    let encode_stmts =
        generate_message_encode_only(&set, SELECTABLE_FIELD, message, |_| None, "f", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_selectable_field_to_json(f: apiext_v1::SelectableField) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_service_reference_to_json`. Every field (`namespace`/`name`/`path` — plain
/// strings — and `port` — a plain int32, inserted whenever set with no zero-filter, matching the
/// hand-rolled `if let Some(port) = svc.port { ... }` this migration replaces) is already exactly
/// what the mechanical walker's defaults produce.
pub fn generate_crd_service_reference(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_SERVICE_REFERENCE);
    let encode_stmts =
        generate_message_encode_only(&set, CRD_SERVICE_REFERENCE, message, |_| None, "svc", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_service_reference_to_json(svc: apiext_v1::ServiceReference) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `caBundle` is a `bytes` field (`Type::Bytes`, the same shape `apiservice_spec_delegated_field`
/// handles for `APIServiceSpec.caBundle`) — delegates to the identical base64-encode template.
/// `service` must be inserted unconditionally once `Some`, even if the nested `ServiceReference`
/// ends up empty (the hand-rolled function this migration replaces never checks
/// `svm.is_empty()`), unlike every other nested-message field this codegen module has met so far —
/// so it delegates to a direct call into the separately generated `gen_service_reference_to_json`
/// rather than the mechanical nested-message branch's only-if-non-empty default.
fn crd_webhook_client_config_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "caBundle" => Some(
            "    if let Some(v) = cc.ca_bundle.filter(|b| !b.is_empty()) {\n        use base64::Engine as _;\n        m.insert(\"caBundle\".to_string(), serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(v)));\n    }\n",
        ),
        "service" => Some(
            "    if let Some(svc) = cc.service {\n        m.insert(\"service\".to_string(), gen_service_reference_to_json(svc));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_webhook_client_config_to_json`, replacing the `clientConfig` assembly block of
/// the hand-rolled `decode_crd_proto_gen` this migration retires.
pub fn generate_crd_webhook_client_config(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_WEBHOOK_CLIENT_CONFIG);
    let encode_stmts = generate_message_encode_only(
        &set,
        CRD_WEBHOOK_CLIENT_CONFIG,
        message,
        crd_webhook_client_config_delegated_field,
        "cc",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_webhook_client_config_to_json(cc: apiext_v1::WebhookClientConfig) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `clientConfig` must only be inserted once the separately generated
/// `gen_webhook_client_config_to_json` produces a non-empty object — the hand-rolled function this
/// migration replaces builds `ccm` itself and only inserts it into `wm` if `!ccm.is_empty()`;
/// since that check now has to run on an already-generated JSON value rather than the map being
/// built in place, it can't be expressed by the mechanical nested-message branch (which recurses
/// inline, not through a named function call) and must be delegated.
fn webhook_conversion_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "clientConfig" => Some(
            "    if let Some(cc) = wh.client_config {\n        let ccj = gen_webhook_client_config_to_json(cc);\n        if ccj.as_object().is_some_and(|m| !m.is_empty()) {\n            m.insert(\"clientConfig\".to_string(), ccj);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_webhook_conversion_to_json`, replacing the `webhook` assembly block of the
/// hand-rolled `decode_crd_proto_gen` this migration retires. `conversionReviewVersions` needs no
/// delegate: it is a plain `repeated string`, and the mechanical walker's only-if-non-empty
/// default already matches the hand-rolled `if !wh.conversion_review_versions.is_empty()` guard.
pub fn generate_webhook_conversion(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, WEBHOOK_CONVERSION);
    let encode_stmts = generate_message_encode_only(
        &set,
        WEBHOOK_CONVERSION,
        message,
        webhook_conversion_delegated_field,
        "wh",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_webhook_conversion_to_json(wh: apiext_v1::WebhookConversion) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `webhook` mirrors `webhook_conversion_delegated_field`'s own `clientConfig` entry one level up:
/// only inserted once the separately generated `gen_webhook_conversion_to_json` produces a
/// non-empty object, matching the hand-rolled `if !wm.is_empty() { cm.insert("webhook", ...) }`
/// guard this migration retires.
fn crd_conversion_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "webhook" => Some(
            "    if let Some(wh) = conv.webhook {\n        let whj = gen_webhook_conversion_to_json(wh);\n        if whj.as_object().is_some_and(|m| !m.is_empty()) {\n            m.insert(\"webhook\".to_string(), whj);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_crd_conversion_to_json`, replacing the `conversion` assembly block of the
/// hand-rolled `decode_crd_proto_gen` this migration retires. `strategy` needs no delegate: it is
/// a plain string, and the mechanical walker's empty-string-filtering default already matches.
pub fn generate_crd_conversion(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_CONVERSION);
    let encode_stmts = generate_message_encode_only(
        &set,
        CRD_CONVERSION,
        message,
        crd_conversion_delegated_field,
        "conv",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_crd_conversion_to_json(conv: apiext_v1::CustomResourceConversion) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_subresource_scale_to_json`. All three fields (`specReplicasPath`/
/// `statusReplicasPath`/`labelSelectorPath`) are plain strings the mechanical walker's default
/// already handles.
pub fn generate_subresource_scale(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SUBRESOURCE_SCALE);
    let encode_stmts =
        generate_message_encode_only(&set, SUBRESOURCE_SCALE, message, |_| None, "scale", "m");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_subresource_scale_to_json(scale: apiext_v1::CustomResourceSubresourceScale) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Both `CustomResourceSubresources` fields need a delegate: `status` is a zero-field marker
/// message (`CustomResourceSubresourceStatus {}`), so the mechanical nested-message branch's
/// only-if-non-empty default would never insert it (an empty message always produces an empty
/// map) — the hand-rolled function this migration replaces inserts a literal `{}` whenever the
/// field is `Some` regardless. `scale` must be inserted unconditionally once `Some`, even if the
/// separately generated `gen_subresource_scale_to_json` produces an empty object — the hand-rolled
/// `m.insert("scale", Object(sm))` this migration replaces has no `is_empty()` guard.
fn subresources_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "status" => Some(
            "    if sr.status.is_some() {\n        m.insert(\"status\".to_string(), serde_json::json!({}));\n    }\n",
        ),
        "scale" => Some(
            "    if let Some(scale) = sr.scale {\n        m.insert(\"scale\".to_string(), gen_subresource_scale_to_json(scale));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_subresources_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_subresources(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SUBRESOURCES);
    let encode_stmts = generate_message_encode_only(
        &set,
        SUBRESOURCES,
        message,
        subresources_delegated_field,
        "sr",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_subresources_to_json(sr: apiext_v1::CustomResourceSubresources) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `CustomResourceDefinitionVersion` fields needing more than the mechanical default:
///   - `served`/`storage` must always be present, defaulting to `false` — the hand-rolled function
///     this migration replaces inserts them unconditionally
///     (`serde_json::Value::Bool(v.served.unwrap_or(false))`), unlike every optional-bool field
///     this codegen module has otherwise met.
///   - `deprecated` is true-only-guarded, the same class as `Container.stdin`.
///   - `schema` unwraps the `CustomResourceValidation` wrapper and re-nests the recursively
///     generated `gen_json_schema_props_to_json` output under a literal `"openAPIV3Schema"` key —
///     a two-level `Option` unwrap (`CustomResourceValidation.open_apiv3_schema`) no mechanical
///     branch derives.
///   - `subresources` only inserts once the separately generated `gen_subresources_to_json`
///     produces a non-empty object, the same named-function-call-then-check-emptiness shape
///     `webhook_conversion_delegated_field`'s own `clientConfig` entry documents.
///   - `additionalPrinterColumns`/`selectableFields` delegate wholesale to their own separately
///     generated per-element codecs (`gen_printer_column_to_json`/`gen_selectable_field_to_json`)
///     rather than the mechanical repeated-message branch's inline unrolling.
///
/// `name`/`deprecationWarning` need no entry: both are plain strings the mechanical walker's
/// empty-string-filtering default already reproduces exactly.
fn crd_version_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "served" => Some(
            "    m.insert(\"served\".to_string(), serde_json::Value::Bool(v.served.unwrap_or(false)));\n",
        ),
        "storage" => Some(
            "    m.insert(\"storage\".to_string(), serde_json::Value::Bool(v.storage.unwrap_or(false)));\n",
        ),
        "deprecated" => Some(
            "    if let Some(dep) = v.deprecated.filter(|&b| b) {\n        m.insert(\"deprecated\".to_string(), serde_json::Value::Bool(dep));\n    }\n",
        ),
        "schema" => Some(
            "    if let Some(schema_wrapper) = v.schema {\n        if let Some(schema) = schema_wrapper.open_apiv3_schema {\n            m.insert(\"schema\".to_string(), serde_json::json!({ \"openAPIV3Schema\": gen_json_schema_props_to_json(schema) }));\n        }\n    }\n",
        ),
        "subresources" => Some(
            "    if let Some(sr) = v.subresources {\n        let sr_json = gen_subresources_to_json(sr);\n        if !sr_json.as_object().map(|o| o.is_empty()).unwrap_or(true) {\n            m.insert(\"subresources\".to_string(), sr_json);\n        }\n    }\n",
        ),
        "additionalPrinterColumns" => Some(
            "    if !v.additional_printer_columns.is_empty() {\n        m.insert(\"additionalPrinterColumns\".to_string(), serde_json::Value::Array(v.additional_printer_columns.into_iter().map(gen_printer_column_to_json).collect()));\n    }\n",
        ),
        "selectableFields" => Some(
            "    if !v.selectable_fields.is_empty() {\n        m.insert(\"selectableFields\".to_string(), serde_json::Value::Array(v.selectable_fields.into_iter().map(gen_selectable_field_to_json).collect()));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_version_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_crd_version(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_VERSION);
    let encode_stmts = generate_message_encode_only(
        &set,
        CRD_VERSION,
        message,
        crd_version_delegated_field,
        "v",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_version_to_json(v: apiext_v1::CustomResourceDefinitionVersion) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `conditions` delegates wholesale to the hand-written `gen_crd_condition_to_json` (kept
/// hand-written for the same `lastTransitionTime`/`Time`-opaque-scalar reason
/// `gen_apiservice_condition_to_json` stays hand-written in `apiregistration_gen_adapter.rs`),
/// only inserting the array once non-empty. `acceptedNames` must be inserted unconditionally once
/// `Some`, mirroring `crd_spec_delegated_field`'s own `names` entry. `observedGeneration` is
/// zero-filtered, the same class of guard as `PodStatus.observedGeneration`.
fn crd_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conds: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_crd_condition_to_json).collect();\n        m.insert(\"conditions\".to_string(), serde_json::Value::Array(conds));\n    }\n",
        ),
        "acceptedNames" => Some(
            "    if let Some(names) = status.accepted_names {\n        m.insert(\"acceptedNames\".to_string(), gen_crd_names_to_json(names));\n    }\n",
        ),
        "observedGeneration" => Some(
            "    if let Some(og) = status.observed_generation.filter(|&g| g != 0) {\n        m.insert(\"observedGeneration\".to_string(), og.into());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_crd_status_to_json`, replacing the `status` assembly block of the hand-rolled
/// `decode_crd_proto_gen` this migration retires. `storedVersions` needs no delegate: it is a
/// plain `repeated string`, and the mechanical walker's only-if-non-empty default already matches.
pub fn generate_crd_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        CRD_STATUS,
        message,
        crd_status_delegated_field,
        "status",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_crd_status_to_json(status: apiext_v1::CustomResourceDefinitionStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `CustomResourceDefinitionSpec` fields needing more than the mechanical default:
///   - `names` must be inserted unconditionally once `Some`, calling the separately generated
///     `gen_crd_names_to_json`.
///   - `versions` delegates wholesale to `gen_version_to_json`, only inserting the array once
///     non-empty (mirrors every other repeated-message-of-a-separately-generated-type field this
///     codegen module has met).
///   - `conversion` must be inserted unconditionally once `Some`, calling the separately generated
///     `gen_crd_conversion_to_json` — the hand-rolled function this migration replaces has no
///     `is_empty()` guard around this particular key, unlike its own nested `webhook`/
///     `clientConfig` keys one level down.
///   - `preserveUnknownFields` is true-only-guarded, the same class as `Container.stdin`.
///
/// `group`/`scope` need no entry: both are plain strings the mechanical walker's
/// empty-string-filtering default already reproduces exactly.
fn crd_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "names" => Some(
            "    if let Some(names) = spec.names {\n        m.insert(\"names\".to_string(), gen_crd_names_to_json(names));\n    }\n",
        ),
        "versions" => Some(
            "    if !spec.versions.is_empty() {\n        m.insert(\"versions\".to_string(), serde_json::Value::Array(spec.versions.into_iter().map(gen_version_to_json).collect()));\n    }\n",
        ),
        "conversion" => Some(
            "    if let Some(conv) = spec.conversion {\n        m.insert(\"conversion\".to_string(), gen_crd_conversion_to_json(conv));\n    }\n",
        ),
        "preserveUnknownFields" => Some(
            "    if let Some(b) = spec.preserve_unknown_fields.filter(|&b| b) {\n        m.insert(\"preserveUnknownFields\".to_string(), serde_json::Value::Bool(b));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_crd_spec_to_json`, replacing the `spec` assembly block of the hand-rolled
/// `decode_crd_proto_gen` this migration retires.
pub fn generate_crd_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        CRD_SPEC,
        message,
        crd_spec_delegated_field,
        "spec",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_crd_spec_to_json(spec: apiext_v1::CustomResourceDefinitionSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `CustomResourceDefinition`'s three fields all delegate: `metadata` for the same reason
/// `namespace_delegated_field`'s own entry documents; `spec` must always be present (built from
/// `crd.spec.unwrap_or_default()` even when the CRD itself carries no spec at all — the hand-rolled
/// function this migration replaces never gates the `"spec"` key on `Option::is_some()`); `status`
/// is gated on both `Some` and the separately generated `gen_crd_status_to_json` producing a
/// non-empty object, the only field in this migration needing both checks together.
fn crd_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(crd.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    obj.insert(\"spec\".to_string(), gen_crd_spec_to_json(crd.spec.unwrap_or_default()));\n",
        ),
        "status" => Some(
            "    if let Some(status) = crd.status {\n        let status_json = gen_crd_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_crd_to_json`, replacing the message-walking body of the hand-rolled
/// `decode_crd_proto_gen` this migration retires (the entry point itself stays hand-written — see
/// `generate_namespace`'s doc for why; `CustomResourceDefinition` has no `encode_crd_proto_gen`
/// today, so this is decode-only in the same sense).
pub fn generate_crd(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, CRD);
    let encode_stmts =
        generate_message_encode_only(&set, CRD, message, crd_delegated_field, "crd", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_crd_to_json(crd: apiext_v1::CustomResourceDefinition) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_delete_options_to_json`, replacing the hand-rolled body of
/// `decode_delete_options_proto_gen` this migration retires. Every field (`gracePeriodSeconds`/
/// `orphanDependents` — inserted whenever set, no zero/false filtering, matching the hand-rolled
/// unconditional-on-`Some` inserts exactly — `propagationPolicy` — a plain string —
/// `dryRun` — a plain repeated string — and `preconditions` — a two-string-field nested message,
/// only inserted once non-empty) is already exactly what the mechanical walker's defaults
/// produce, so no delegate table is needed.
pub fn generate_delete_options(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, DELETE_OPTIONS);
    let encode_stmts =
        generate_message_encode_only(&set, DELETE_OPTIONS, message, |_| None, "opts", "obj");

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_delete_options_to_json(opts: meta_v1::DeleteOptions) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

const APPLY_CONFIGURATION: &str = ".k8s.io.api.admissionregistration.v1.ApplyConfiguration";
const JSON_PATCH: &str = ".k8s.io.api.admissionregistration.v1.JSONPatch";
const AUDIT_ANNOTATION: &str = ".k8s.io.api.admissionregistration.v1.AuditAnnotation";
const EXPRESSION_WARNING: &str = ".k8s.io.api.admissionregistration.v1.ExpressionWarning";
const VARIABLE: &str = ".k8s.io.api.admissionregistration.v1.Variable";
const MATCH_CONDITION: &str = ".k8s.io.api.admissionregistration.v1.MatchCondition";
const PARAM_KIND: &str = ".k8s.io.api.admissionregistration.v1.ParamKind";
const SERVICE_REFERENCE: &str = ".k8s.io.api.admissionregistration.v1.ServiceReference";
const WEBHOOK_CLIENT_CONFIG: &str = ".k8s.io.api.admissionregistration.v1.WebhookClientConfig";
const RULE: &str = ".k8s.io.api.admissionregistration.v1.Rule";
const RULE_WITH_OPERATIONS: &str = ".k8s.io.api.admissionregistration.v1.RuleWithOperations";
const NAMED_RULE_WITH_OPERATIONS: &str =
    ".k8s.io.api.admissionregistration.v1.NamedRuleWithOperations";
const MATCH_RESOURCES: &str = ".k8s.io.api.admissionregistration.v1.MatchResources";
const PARAM_REF: &str = ".k8s.io.api.admissionregistration.v1.ParamRef";
const VALIDATING_WEBHOOK: &str = ".k8s.io.api.admissionregistration.v1.ValidatingWebhook";
const MUTATING_WEBHOOK: &str = ".k8s.io.api.admissionregistration.v1.MutatingWebhook";
const VALIDATING_WEBHOOK_CONFIGURATION: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingWebhookConfiguration";
const MUTATING_WEBHOOK_CONFIGURATION: &str =
    ".k8s.io.api.admissionregistration.v1.MutatingWebhookConfiguration";
const VALIDATION: &str = ".k8s.io.api.admissionregistration.v1.Validation";
const TYPE_CHECKING: &str = ".k8s.io.api.admissionregistration.v1.TypeChecking";
const META_CONDITION: &str = ".k8s.io.apimachinery.pkg.apis.meta.v1.Condition";
const VALIDATING_ADMISSION_POLICY_SPEC: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicySpec";
const VALIDATING_ADMISSION_POLICY_STATUS: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicyStatus";
const VALIDATING_ADMISSION_POLICY: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicy";
const VALIDATING_ADMISSION_POLICY_BINDING_SPEC: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicyBindingSpec";
const VALIDATING_ADMISSION_POLICY_BINDING: &str =
    ".k8s.io.api.admissionregistration.v1.ValidatingAdmissionPolicyBinding";
const MUTATION: &str = ".k8s.io.api.admissionregistration.v1.Mutation";
const MUTATING_ADMISSION_POLICY_SPEC: &str =
    ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicySpec";
const MUTATING_ADMISSION_POLICY: &str =
    ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicy";
const MUTATING_ADMISSION_POLICY_BINDING_SPEC: &str =
    ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicyBindingSpec";
const MUTATING_ADMISSION_POLICY_BINDING: &str =
    ".k8s.io.api.admissionregistration.v1.MutatingAdmissionPolicyBinding";

/// Emits a `gen_<fn_name>_to_json` for a message whose JSON form is exactly its own declared
/// fields, in field order, each an `optional string` inserted unconditionally — matching every
/// hand-rolled admissionregistration/v1 leaf message this migration replaces
/// (`ApplyConfiguration`/`JSONPatch`/`AuditAnnotation`/`ExpressionWarning`/`Variable`/
/// `MatchCondition`/`ParamKind`), which build their JSON via a `serde_json::json!({...})` literal
/// assigning `.unwrap_or_default()` directly rather than the mechanical walker's own
/// omit-if-empty/unset default. Several of these are exactly the CEL expression strings
/// `admission.rs`'s evaluator reads (`Validation.Expression` inside
/// `ValidatingAdmissionPolicySpec.validations`, `Variable.Expression`, `MatchCondition.expression`
/// on both webhooks and policies) — preserving unconditional emission (not the mechanical
/// omit-if-empty default) matters here specifically so an explicitly-set-but-empty expression
/// stays distinguishable from "field absent", not just for the common non-empty case.
fn generate_always_string_fields(
    set: &FileDescriptorSet,
    owner: &str,
    fn_name: &str,
    rust_type: &str,
    arg_name: &str,
) -> String {
    let message = find_message(set, owner);
    let fields: Vec<(String, String)> = message
        .field
        .iter()
        .map(|field| {
            assert_eq!(
                field.r#type(),
                Type::String,
                "{owner}.{} is not a string field — generate_always_string_fields only handles \
                 the all-scalar-string shape this message had when this codegen was written",
                field.name()
            );
            (
                rust_field_name(field.name()),
                json_key(owner, field.name(), field.json_name()),
            )
        })
        .collect();

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    writeln!(
        out,
        "fn gen_{fn_name}_to_json({arg_name}: {rust_type}) -> serde_json::Value {{"
    )
    .unwrap();
    out.push_str("    serde_json::json!({\n");
    for (rust_field, key) in &fields {
        writeln!(
            out,
            "        \"{key}\": {arg_name}.{rust_field}.unwrap_or_default(),"
        )
        .unwrap();
    }
    out.push_str("    })\n");
    out.push_str("}\n");
    out
}

pub fn generate_apply_configuration(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(
        &set,
        APPLY_CONFIGURATION,
        "apply_configuration",
        "ar_v1::ApplyConfiguration",
        "ac",
    )
}

pub fn generate_json_patch(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(&set, JSON_PATCH, "json_patch", "ar_v1::JsonPatch", "jp")
}

pub fn generate_audit_annotation(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(
        &set,
        AUDIT_ANNOTATION,
        "audit_annotation",
        "ar_v1::AuditAnnotation",
        "a",
    )
}

pub fn generate_expression_warning(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(
        &set,
        EXPRESSION_WARNING,
        "expression_warning",
        "ar_v1::ExpressionWarning",
        "w",
    )
}

pub fn generate_variable(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(&set, VARIABLE, "variable", "ar_v1::Variable", "v")
}

pub fn generate_match_condition(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(
        &set,
        MATCH_CONDITION,
        "match_condition",
        "ar_v1::MatchCondition",
        "c",
    )
}

pub fn generate_param_kind(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    generate_always_string_fields(&set, PARAM_KIND, "param_kind", "ar_v1::ParamKind", "pk")
}

/// `namespace`/`name` are unconditionally emitted (even `Some("")`), matching the hand-rolled
/// `gen_webhook_client_config_to_json`'s inline `ServiceReference` mapping this replaces; `port`
/// needs its zero-filter spelled out because the mechanical `Type::Int32` branch has no such
/// filter by default. `path` needs no entry: a plain optional string the mechanical walker already
/// handles correctly.
fn service_reference_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "namespace" => Some(
            "    m.insert(\"namespace\".to_string(), serde_json::Value::String(svc.namespace.unwrap_or_default()));\n",
        ),
        "name" => Some(
            "    m.insert(\"name\".to_string(), serde_json::Value::String(svc.name.unwrap_or_default()));\n",
        ),
        "port" => Some(
            "    if let Some(port) = svc.port.filter(|&v| v != 0) {\n        m.insert(\"port\".to_string(), serde_json::Value::Number(serde_json::Number::from(port)));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_service_reference_to_json`, replacing the inline `ServiceReference` mapping the
/// hand-rolled `gen_webhook_client_config_to_json` built directly.
pub fn generate_service_reference(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, SERVICE_REFERENCE);
    let encode_stmts = generate_message_encode_only(
        &set,
        SERVICE_REFERENCE,
        message,
        service_reference_delegated_field,
        "svc",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_service_reference_to_json(svc: ar_v1::ServiceReference) -> serde_json::Value {\n",
    );
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// `caBundle` is a `bytes` field, a shape `emit_field_encode` has no match arm for (the same
/// reason `apiservice_spec_delegated_field`'s own `caBundle` entry needs one); `service` delegates
/// to the separately generated `gen_service_reference_to_json`, inserted unconditionally whenever
/// the `Option` is `Some` — matching the hand-rolled `gen_webhook_client_config_to_json`'s
/// `cfg["service"] = s;` exactly. `url` needs no entry: a plain optional string the mechanical
/// walker already handles correctly.
fn webhook_client_config_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "caBundle" => Some(
            "    if let Some(ca) = cc.ca_bundle.filter(|b| !b.is_empty()) {\n        cfg.insert(\"caBundle\".to_string(), serde_json::Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ca)));\n    }\n",
        ),
        "service" => Some(
            "    if let Some(svc) = cc.service {\n        cfg.insert(\"service\".to_string(), gen_service_reference_to_json(svc));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_webhook_client_config_to_json`, replacing the hand-rolled function of the same
/// name.
pub fn generate_webhook_client_config(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, WEBHOOK_CLIENT_CONFIG);
    let encode_stmts = generate_message_encode_only(
        &set,
        WEBHOOK_CLIENT_CONFIG,
        message,
        webhook_client_config_delegated_field,
        "cc",
        "cfg",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_webhook_client_config_to_json(cc: ar_v1::WebhookClientConfig) -> serde_json::Value {\n",
    );
    out.push_str("    let mut cfg = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(cfg)\n");
    out.push_str("}\n");
    out
}

/// `RuleWithOperations.rule` is a Go inline embed (`INLINE_EMBEDS`-listed in
/// `proto_exceptions.rs`, asserted below): `Rule`'s `apiGroups`/`apiVersions`/`resources`/`scope`
/// land directly on the same JSON object as `operations`, never nested under a `"rule"` key.
/// Unlike every mechanically-walked message field, `operations`/`apiGroups`/`apiVersions`/
/// `resources` are unconditionally emitted (even as `[]`) and `scope` defaults to `"*"` rather than
/// being omitted when unset — matching upstream's own documented default ("Default is `\"*\"`.")
/// and the hand-rolled `gen_rule_with_operations_to_json` this replaces exactly. Because this
/// shape (always-emit + a non-absent default) has no mechanical walker branch, this generator is
/// bespoke rather than built on `generate_message_encode_only`, asserting the exact field lists it
/// assumes so a future proto vendor-bump that changes either message's shape fails the build
/// instead of silently mis-generating.
pub fn generate_rule_with_operations(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    assert!(
        is_inline_embed(RULE_WITH_OPERATIONS, "rule"),
        "generate_rule_with_operations assumes RuleWithOperations.rule is an INLINE_EMBEDS entry"
    );
    let rwo = find_message(&set, RULE_WITH_OPERATIONS);
    let rwo_fields: Vec<&str> = rwo.field.iter().map(|f| f.name()).collect();
    assert_eq!(
        rwo_fields,
        vec!["operations", "rule"],
        "RuleWithOperations field shape changed — update generate_rule_with_operations"
    );
    let rule = find_message(&set, RULE);
    let rule_fields: Vec<&str> = rule.field.iter().map(|f| f.name()).collect();
    assert_eq!(
        rule_fields,
        vec!["apiGroups", "apiVersions", "resources", "scope"],
        "Rule field shape changed — update generate_rule_with_operations"
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_rule_with_operations_to_json(r: ar_v1::RuleWithOperations) -> serde_json::Value {\n",
    );
    out.push_str("    let rule = r.rule.unwrap_or_default();\n");
    out.push_str("    serde_json::json!({\n");
    out.push_str("        \"operations\": r.operations,\n");
    out.push_str("        \"apiGroups\": rule.api_groups,\n");
    out.push_str("        \"apiVersions\": rule.api_versions,\n");
    out.push_str("        \"resources\": rule.resources,\n");
    out.push_str(
        "        \"scope\": rule.scope.filter(|s| !s.is_empty()).unwrap_or_else(|| \"*\".to_string()),\n",
    );
    out.push_str("    })\n");
    out.push_str("}\n");
    out
}

/// `NamedRuleWithOperations.ruleWithOperations` is a Go inline embed (`INLINE_EMBEDS`-listed,
/// asserted below), one level deeper than `generate_rule_with_operations`'s own embed: its fields
/// land directly on the `NamedRuleWithOperations` JSON object alongside `resourceNames`. Unlike
/// `RuleWithOperations`'s own JSON form, `scope` here is omitted (not defaulted to `"*"`) when
/// unset — matching the hand-rolled `gen_named_rule_with_operations_to_json` this replaces exactly
/// (an intentional asymmetry in the pre-migration code, preserved rather than "fixed" here).
pub fn generate_named_rule_with_operations(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    assert!(
        is_inline_embed(NAMED_RULE_WITH_OPERATIONS, "ruleWithOperations"),
        "generate_named_rule_with_operations assumes NamedRuleWithOperations.ruleWithOperations \
         is an INLINE_EMBEDS entry"
    );
    let nrwo = find_message(&set, NAMED_RULE_WITH_OPERATIONS);
    let nrwo_fields: Vec<&str> = nrwo.field.iter().map(|f| f.name()).collect();
    assert_eq!(
        nrwo_fields,
        vec!["resourceNames", "ruleWithOperations"],
        "NamedRuleWithOperations field shape changed — update generate_named_rule_with_operations"
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_named_rule_with_operations_to_json(r: ar_v1::NamedRuleWithOperations) -> serde_json::Value {\n",
    );
    out.push_str("    let rwo = r.rule_with_operations.unwrap_or_default();\n");
    out.push_str("    let inner = rwo.rule.unwrap_or_default();\n");
    out.push_str("    let mut rule = serde_json::json!({\n");
    out.push_str("        \"apiGroups\": inner.api_groups,\n");
    out.push_str("        \"apiVersions\": inner.api_versions,\n");
    out.push_str("        \"resources\": inner.resources,\n");
    out.push_str("        \"operations\": rwo.operations,\n");
    out.push_str("    });\n");
    out.push_str("    if let Some(scope) = inner.scope.filter(|s| !s.is_empty()) {\n");
    out.push_str("        rule[\"scope\"] = serde_json::Value::String(scope);\n");
    out.push_str("    }\n");
    out.push_str("    if !r.resource_names.is_empty() {\n");
    out.push_str(
        "        rule[\"resourceNames\"] = serde_json::Value::Array(r.resource_names.into_iter().map(serde_json::Value::String).collect());\n",
    );
    out.push_str("    }\n");
    out.push_str("    rule\n");
    out.push_str("}\n");
    out
}

/// `resourceRules`/`excludeResourceRules` delegate wholesale to the separately generated
/// `gen_named_rule_with_operations_to_json` (the mechanical walker cannot express its embedded
/// shape); `namespaceSelector`/`objectSelector` delegate to the hand-written
/// `gen_label_selector_to_json`, inserted unconditionally whenever the `Option` is `Some` —
/// matching the hand-rolled `gen_match_resources_to_json` this replaces exactly. `matchPolicy`
/// needs no entry: a plain optional string the mechanical walker already handles correctly.
fn match_resources_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "namespaceSelector" => Some(
            "    if let Some(ns) = mc.namespace_selector {\n        obj.insert(\"namespaceSelector\".to_string(), gen_label_selector_to_json(ns));\n    }\n",
        ),
        "objectSelector" => Some(
            "    if let Some(os) = mc.object_selector {\n        obj.insert(\"objectSelector\".to_string(), gen_label_selector_to_json(os));\n    }\n",
        ),
        "resourceRules" => Some(
            "    if !mc.resource_rules.is_empty() {\n        let resource_rules: Vec<serde_json::Value> = mc.resource_rules.into_iter().map(gen_named_rule_with_operations_to_json).collect();\n        obj.insert(\"resourceRules\".to_string(), serde_json::Value::Array(resource_rules));\n    }\n",
        ),
        "excludeResourceRules" => Some(
            "    if !mc.exclude_resource_rules.is_empty() {\n        let exclude_rules: Vec<serde_json::Value> = mc.exclude_resource_rules.into_iter().map(gen_named_rule_with_operations_to_json).collect();\n        obj.insert(\"excludeResourceRules\".to_string(), serde_json::Value::Array(exclude_rules));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_match_resources_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_match_resources(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MATCH_RESOURCES);
    let encode_stmts = generate_message_encode_only(
        &set,
        MATCH_RESOURCES,
        message,
        match_resources_delegated_field,
        "mc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_match_resources_to_json(mc: ar_v1::MatchResources) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `selector` delegates to the hand-written `gen_label_selector_to_json`, inserted unconditionally
/// whenever the `Option` is `Some` — matching the hand-rolled `gen_param_ref_to_json` this
/// replaces exactly. `name`/`namespace`/`parameterNotFoundAction` need no entry: plain optional
/// strings the mechanical walker already handles correctly.
fn param_ref_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "selector" => Some(
            "    if let Some(sel) = pr.selector {\n        m.insert(\"selector\".to_string(), gen_label_selector_to_json(sel));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_param_ref_to_json`, replacing the hand-rolled function of the same name.
pub fn generate_param_ref(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, PARAM_REF);
    let encode_stmts = generate_message_encode_only(
        &set,
        PARAM_REF,
        message,
        param_ref_delegated_field,
        "pr",
        "m",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_param_ref_to_json(pr: ar_v1::ParamRef) -> serde_json::Value {\n");
    out.push_str("    let mut m = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(m)\n");
    out.push_str("}\n");
    out
}

/// Shared delegate table for `ValidatingWebhook`/`MutatingWebhook`, which declare the identical
/// field set for everything this table overrides (`MutatingWebhook`'s one extra field,
/// `reinvocationPolicy`, is a plain optional string the mechanical walker's own omit-if-empty
/// default already reproduces correctly, so it needs no entry here). `name` is unconditionally
/// emitted; `clientConfig` always inserts (defaulting to `{}` when unset); `rules`/
/// `admissionReviewVersions` are unconditionally emitted arrays (upstream has no `omitempty` on
/// either); `timeoutSeconds` needs its zero-filter spelled out; `namespaceSelector`/
/// `objectSelector` delegate to the hand-written `gen_label_selector_to_json`; `matchConditions`
/// delegates to the separately generated `gen_match_condition_to_json` — matching the hand-rolled
/// `gen_validating_webhook_to_json`/`gen_mutating_webhook_to_json` this replaces exactly.
fn admission_webhook_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "name" => Some(
            "    entry.insert(\"name\".to_string(), serde_json::Value::String(w.name.unwrap_or_default()));\n",
        ),
        "clientConfig" => Some(
            "    entry.insert(\"clientConfig\".to_string(), w.client_config.map(gen_webhook_client_config_to_json).unwrap_or(serde_json::json!({})));\n",
        ),
        "rules" => Some(
            "    {\n        let rules: Vec<serde_json::Value> = w.rules.into_iter().map(gen_rule_with_operations_to_json).collect();\n        entry.insert(\"rules\".to_string(), serde_json::Value::Array(rules));\n    }\n",
        ),
        "timeoutSeconds" => Some(
            "    if let Some(v) = w.timeout_seconds.filter(|&v| v != 0) {\n        entry.insert(\"timeoutSeconds\".to_string(), serde_json::Value::Number(serde_json::Number::from(v)));\n    }\n",
        ),
        "admissionReviewVersions" => Some(
            "    entry.insert(\"admissionReviewVersions\".to_string(), serde_json::Value::Array(w.admission_review_versions.into_iter().map(serde_json::Value::String).collect()));\n",
        ),
        "namespaceSelector" => Some(
            "    if let Some(ns) = w.namespace_selector {\n        entry.insert(\"namespaceSelector\".to_string(), gen_label_selector_to_json(ns));\n    }\n",
        ),
        "objectSelector" => Some(
            "    if let Some(os) = w.object_selector {\n        entry.insert(\"objectSelector\".to_string(), gen_label_selector_to_json(os));\n    }\n",
        ),
        "matchConditions" => Some(
            "    if !w.match_conditions.is_empty() {\n        let conds: Vec<serde_json::Value> = w.match_conditions.into_iter().map(gen_match_condition_to_json).collect();\n        entry.insert(\"matchConditions\".to_string(), serde_json::Value::Array(conds));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_webhook_to_json`, replacing the hand-rolled function of the same
/// name.
pub fn generate_validating_webhook(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_WEBHOOK);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_WEBHOOK,
        message,
        admission_webhook_delegated_field,
        "w",
        "entry",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_webhook_to_json(w: ar_v1::ValidatingWebhook) -> serde_json::Value {\n",
    );
    out.push_str("    let mut entry = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(entry)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_mutating_webhook_to_json`, replacing the hand-rolled function of the same name —
/// shares `admission_webhook_delegated_field` with `generate_validating_webhook` (see that
/// function's doc for why `reinvocationPolicy` needs no entry of its own here).
pub fn generate_mutating_webhook(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_WEBHOOK);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_WEBHOOK,
        message,
        admission_webhook_delegated_field,
        "w",
        "entry",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_webhook_to_json(w: ar_v1::MutatingWebhook) -> serde_json::Value {\n",
    );
    out.push_str("    let mut entry = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(entry)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `Webhooks` (declared
/// capitalised in the vendored proto — see `json_key`'s leading-capital-lowering rule) is
/// unconditionally emitted (upstream has no `omitempty` on it — matches the existing
/// `..._omits_no_nulls_on_all_default_input` test's expectation of `"webhooks": []`, never an
/// absent key), delegating to the separately generated `gen_validating_webhook_to_json`.
fn validating_webhook_configuration_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(vwc.metadata.unwrap_or_default()));\n",
        ),
        "Webhooks" => Some(
            "    {\n        let webhooks: Vec<serde_json::Value> = vwc.webhooks.into_iter().map(gen_validating_webhook_to_json).collect();\n        obj.insert(\"webhooks\".to_string(), serde_json::Value::Array(webhooks));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_webhook_configuration_to_json`, replacing the message-walking body of
/// the hand-rolled `decode_validatingwebhookconfiguration_proto_gen` this migration retires (the
/// entry point itself stays hand-written — see `generate_namespace`'s doc for why;
/// `ValidatingWebhookConfiguration` has no `encode_validatingwebhookconfiguration_proto_gen` today,
/// so this is decode-only in the same sense).
pub fn generate_validating_webhook_configuration(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_WEBHOOK_CONFIGURATION);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_WEBHOOK_CONFIGURATION,
        message,
        validating_webhook_configuration_delegated_field,
        "vwc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_webhook_configuration_to_json(vwc: ar_v1::ValidatingWebhookConfiguration) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata`/`Webhooks` delegate for the same reasons `validating_webhook_configuration_delegated_field`'s
/// own entries document — `MutatingWebhookConfiguration` shares the identical shape one level down
/// (`MutatingWebhook` instead of `ValidatingWebhook`).
fn mutating_webhook_configuration_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(mwc.metadata.unwrap_or_default()));\n",
        ),
        "Webhooks" => Some(
            "    {\n        let webhooks: Vec<serde_json::Value> = mwc.webhooks.into_iter().map(gen_mutating_webhook_to_json).collect();\n        obj.insert(\"webhooks\".to_string(), serde_json::Value::Array(webhooks));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutating_webhook_configuration_to_json`, replacing the message-walking body of
/// the hand-rolled `decode_mutatingwebhookconfiguration_proto_gen` this migration retires (the
/// entry point itself stays hand-written — see `generate_namespace`'s doc for why;
/// `MutatingWebhookConfiguration` has no `encode_mutatingwebhookconfiguration_proto_gen` today, so
/// this is decode-only in the same sense).
pub fn generate_mutating_webhook_configuration(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_WEBHOOK_CONFIGURATION);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_WEBHOOK_CONFIGURATION,
        message,
        mutating_webhook_configuration_delegated_field,
        "mwc",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_webhook_configuration_to_json(mwc: ar_v1::MutatingWebhookConfiguration) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `Expression` (declared capitalised in the vendored proto — see `json_key`'s leading-capital
/// -lowering rule) is unconditionally emitted, matching the hand-rolled `gen_vap_spec_to_json`'s
/// inline `validations` mapping this replaces — this is one of the two CEL expression fields
/// `admission.rs`'s evaluator reads directly (`spec.validations[].expression`). `message`/`reason`/
/// `messageExpression` need no entry: plain optional strings the mechanical walker already handles
/// correctly.
fn validation_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "Expression" => Some(
            "    entry.insert(\"expression\".to_string(), serde_json::Value::String(v.expression.unwrap_or_default()));\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validation_to_json`, replacing the inline `validations` mapping the hand-rolled
/// `gen_vap_spec_to_json` built directly.
pub fn generate_validation(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATION);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATION,
        message,
        validation_delegated_field,
        "v",
        "entry",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_validation_to_json(v: ar_v1::Validation) -> serde_json::Value {\n");
    out.push_str("    let mut entry = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(entry)\n");
    out.push_str("}\n");
    out
}

/// Generates `gen_type_checking_to_json`, replacing the inline `typeChecking` handling the
/// hand-rolled `gen_vap_status_to_json` built directly. Returns `Option` (not a bare `Value`) —
/// the same "drop entirely rather than emit an empty wrapper" shape `delegated_field_templates`'s
/// VolumeSource entries use — because the hand-rolled status builder only ever inserts the
/// `typeChecking` key when `expressionWarnings` is non-empty, even though `TypeChecking` itself is
/// present as soon as the *outer* `Option<TypeChecking>` is `Some`; the mechanical walker has no
/// way to express "conditionally drop based on an inner field", so `type_checking`'s own delegate
/// entry in `vap_status_delegated_field` calls this and only inserts on `Some`.
pub fn generate_type_checking(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, TYPE_CHECKING);
    let fields: Vec<&str> = message.field.iter().map(|f| f.name()).collect();
    assert_eq!(
        fields,
        vec!["expressionWarnings"],
        "TypeChecking field shape changed — update generate_type_checking"
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_type_checking_to_json(tc: ar_v1::TypeChecking) -> Option<serde_json::Value> {\n",
    );
    out.push_str("    if tc.expression_warnings.is_empty() {\n");
    out.push_str("        return None;\n");
    out.push_str("    }\n");
    out.push_str(
        "    let warns: Vec<serde_json::Value> = tc.expression_warnings.into_iter().map(gen_expression_warning_to_json).collect();\n",
    );
    out.push_str("    Some(serde_json::json!({ \"expressionWarnings\": warns }))\n");
    out.push_str("}\n");
    out
}

/// `type`/`status` are unconditionally emitted; `lastTransitionTime` only when its seconds are
/// positive; `observedGeneration` only when non-zero — matching the hand-rolled
/// `gen_vap_status_to_json`'s inline `conditions` mapping this replaces exactly (a different
/// convention than `apiservice_status_delegated_field`'s own `meta_v1::Condition` mapping, which
/// omits `type`/`status` when empty — the two Kinds' pre-migration hand-written code genuinely
/// disagreed here, and this migration preserves each one's own behaviour rather than unifying
/// them). `reason`/`message` need no entry: plain optional strings the mechanical walker already
/// handles correctly.
fn vap_condition_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "type" => Some(
            "    cm.insert(\"type\".to_string(), serde_json::Value::String(c.r#type.unwrap_or_default()));\n",
        ),
        "status" => Some(
            "    cm.insert(\"status\".to_string(), serde_json::Value::String(c.status.unwrap_or_default()));\n",
        ),
        "lastTransitionTime" => Some(
            "    if let Some(secs) = c.last_transition_time.and_then(|t| t.seconds).filter(|&s| s > 0) {\n        cm.insert(\"lastTransitionTime\".to_string(), serde_json::Value::String(crate::util::secs_to_rfc3339(secs)));\n    }\n",
        ),
        "observedGeneration" => Some(
            "    if let Some(og) = c.observed_generation.filter(|&g| g != 0) {\n        cm.insert(\"observedGeneration\".to_string(), og.into());\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_vap_condition_to_json`, replacing the inline `conditions` mapping the hand-rolled
/// `gen_vap_status_to_json` built directly.
pub fn generate_vap_condition(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, META_CONDITION);
    let encode_stmts = generate_message_encode_only(
        &set,
        META_CONDITION,
        message,
        vap_condition_delegated_field,
        "c",
        "cm",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_vap_condition_to_json(c: meta_v1::Condition) -> serde_json::Value {\n");
    out.push_str("    let mut cm = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(cm)\n");
    out.push_str("}\n");
    out
}

/// `matchConstraints`/`paramKind` delegate to their own separately generated converters, inserted
/// unconditionally whenever the `Option` is `Some`; `validations`/`auditAnnotations`/
/// `matchConditions`/`variables` are arrays only emitted when non-empty, each delegating to its
/// own per-element generated converter — matching the hand-rolled `gen_vap_spec_to_json` this
/// replaces exactly. `failurePolicy` needs no entry: a plain optional string the mechanical walker
/// already handles correctly.
fn vap_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "matchConstraints" => Some(
            "    if let Some(mc) = spec.match_constraints {\n        obj.insert(\"matchConstraints\".to_string(), gen_match_resources_to_json(mc));\n    }\n",
        ),
        "paramKind" => Some(
            "    if let Some(pk) = spec.param_kind {\n        obj.insert(\"paramKind\".to_string(), gen_param_kind_to_json(pk));\n    }\n",
        ),
        "validations" => Some(
            "    if !spec.validations.is_empty() {\n        let vals: Vec<serde_json::Value> = spec.validations.into_iter().map(gen_validation_to_json).collect();\n        obj.insert(\"validations\".to_string(), serde_json::Value::Array(vals));\n    }\n",
        ),
        "auditAnnotations" => Some(
            "    if !spec.audit_annotations.is_empty() {\n        let anns: Vec<serde_json::Value> = spec.audit_annotations.into_iter().map(gen_audit_annotation_to_json).collect();\n        obj.insert(\"auditAnnotations\".to_string(), serde_json::Value::Array(anns));\n    }\n",
        ),
        "matchConditions" => Some(
            "    if !spec.match_conditions.is_empty() {\n        let conds: Vec<serde_json::Value> = spec.match_conditions.into_iter().map(gen_match_condition_to_json).collect();\n        obj.insert(\"matchConditions\".to_string(), serde_json::Value::Array(conds));\n    }\n",
        ),
        "variables" => Some(
            "    if !spec.variables.is_empty() {\n        let vars: Vec<serde_json::Value> = spec.variables.into_iter().map(gen_variable_to_json).collect();\n        obj.insert(\"variables\".to_string(), serde_json::Value::Array(vars));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_admission_policy_spec_to_json`, replacing the hand-rolled
/// `gen_vap_spec_to_json`.
pub fn generate_validating_admission_policy_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_ADMISSION_POLICY_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_ADMISSION_POLICY_SPEC,
        message,
        vap_spec_delegated_field,
        "spec",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_admission_policy_spec_to_json(spec: ar_v1::ValidatingAdmissionPolicySpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `observedGeneration` needs its zero-filter spelled out; `typeChecking` delegates to the
/// separately generated (`Option`-returning) `gen_type_checking_to_json`, only inserting on
/// `Some`; `conditions` is an array only emitted when non-empty, delegating to the separately
/// generated `gen_vap_condition_to_json` — matching the hand-rolled `gen_vap_status_to_json` this
/// replaces exactly.
fn vap_status_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "observedGeneration" => Some(
            "    if let Some(og) = status.observed_generation.filter(|&v| v != 0) {\n        obj.insert(\"observedGeneration\".to_string(), serde_json::Value::Number(og.into()));\n    }\n",
        ),
        "typeChecking" => Some(
            "    if let Some(tc) = status.type_checking {\n        if let Some(j) = gen_type_checking_to_json(tc) {\n            obj.insert(\"typeChecking\".to_string(), j);\n        }\n    }\n",
        ),
        "conditions" => Some(
            "    if !status.conditions.is_empty() {\n        let conds: Vec<serde_json::Value> = status.conditions.into_iter().map(gen_vap_condition_to_json).collect();\n        obj.insert(\"conditions\".to_string(), serde_json::Value::Array(conds));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_admission_policy_status_to_json`, replacing the hand-rolled
/// `gen_vap_status_to_json`.
pub fn generate_validating_admission_policy_status(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_ADMISSION_POLICY_STATUS);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_ADMISSION_POLICY_STATUS,
        message,
        vap_status_delegated_field,
        "status",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_admission_policy_status_to_json(status: ar_v1::ValidatingAdmissionPolicyStatus) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `spec` delegates to
/// the separately generated `gen_validating_admission_policy_spec_to_json`, inserted
/// unconditionally whenever the `Option` is `Some` (never gated on the resulting object's
/// emptiness). `status` delegates to `gen_validating_admission_policy_status_to_json`, but —
/// unlike `spec` — only inserts the key when the resulting object is also non-empty: matching the
/// hand-rolled `decode_validatingadmissionpolicy_proto_gen` this migration retires exactly, which
/// treats `spec`/`status` differently from each other on purpose (an empty `status: {}` on a
/// brand-new policy would otherwise look like "already reconciled" to a controller checking
/// `status != null`).
fn validating_admission_policy_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(vap.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = vap.spec {\n        obj.insert(\"spec\".to_string(), gen_validating_admission_policy_spec_to_json(spec));\n    }\n",
        ),
        "status" => Some(
            "    if let Some(status) = vap.status {\n        let status_json = gen_validating_admission_policy_status_to_json(status);\n        if status_json.as_object().is_some_and(|m| !m.is_empty()) {\n            obj.insert(\"status\".to_string(), status_json);\n        }\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_admission_policy_to_json`, replacing the message-walking body of the
/// hand-rolled `decode_validatingadmissionpolicy_proto_gen` this migration retires (the entry
/// point itself stays hand-written — see `generate_namespace`'s doc for why;
/// `ValidatingAdmissionPolicy` has no `encode_validatingadmissionpolicy_proto_gen` today, so this
/// is decode-only in the same sense).
pub fn generate_validating_admission_policy(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_ADMISSION_POLICY);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_ADMISSION_POLICY,
        message,
        validating_admission_policy_delegated_field,
        "vap",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_admission_policy_to_json(vap: ar_v1::ValidatingAdmissionPolicy) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `paramRef`/`matchResources` delegate to their own separately generated converters, inserted
/// unconditionally whenever the `Option` is `Some` — matching the hand-rolled
/// `decode_validatingadmissionpolicybinding_proto_gen` this migration retires exactly.
/// `policyName` needs no entry (a plain optional string); `validationActions` needs no entry
/// either — a `repeated string` with no per-element structure, so the mechanical walker's own
/// omit-if-empty default already reproduces the hand-rolled `if !empty { ... }` guard exactly.
fn vap_binding_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "paramRef" => Some(
            "    if let Some(pr) = spec.param_ref {\n        obj.insert(\"paramRef\".to_string(), gen_param_ref_to_json(pr));\n    }\n",
        ),
        "matchResources" => Some(
            "    if let Some(mr) = spec.match_resources {\n        obj.insert(\"matchResources\".to_string(), gen_match_resources_to_json(mr));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_admission_policy_binding_spec_to_json`, replacing the inline `spec`
/// assembly block the hand-rolled `decode_validatingadmissionpolicybinding_proto_gen` built
/// directly.
pub fn generate_validating_admission_policy_binding_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_ADMISSION_POLICY_BINDING_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_ADMISSION_POLICY_BINDING_SPEC,
        message,
        vap_binding_spec_delegated_field,
        "spec",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_admission_policy_binding_spec_to_json(spec: ar_v1::ValidatingAdmissionPolicyBindingSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `spec` delegates to
/// the separately generated `gen_validating_admission_policy_binding_spec_to_json`, inserted
/// unconditionally whenever the `Option` is `Some` — matching the hand-rolled
/// `decode_validatingadmissionpolicybinding_proto_gen` this migration retires exactly.
fn validating_admission_policy_binding_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(binding.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = binding.spec {\n        obj.insert(\"spec\".to_string(), gen_validating_admission_policy_binding_spec_to_json(spec));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_validating_admission_policy_binding_to_json`, replacing the message-walking body
/// of the hand-rolled `decode_validatingadmissionpolicybinding_proto_gen` this migration retires
/// (the entry point itself stays hand-written — see `generate_namespace`'s doc for why;
/// `ValidatingAdmissionPolicyBinding` has no `encode_validatingadmissionpolicybinding_proto_gen`
/// today, so this is decode-only in the same sense).
pub fn generate_validating_admission_policy_binding(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, VALIDATING_ADMISSION_POLICY_BINDING);
    let encode_stmts = generate_message_encode_only(
        &set,
        VALIDATING_ADMISSION_POLICY_BINDING,
        message,
        validating_admission_policy_binding_delegated_field,
        "binding",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_validating_admission_policy_binding_to_json(binding: ar_v1::ValidatingAdmissionPolicyBinding) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `patchType` is unconditionally emitted; `applyConfiguration`/`jsonPatch` delegate to their own
/// separately generated converters, inserted unconditionally whenever the `Option` is `Some` —
/// matching the hand-rolled `gen_map_spec_to_json`'s inline `mutations` mapping this replaces
/// exactly. `applyConfiguration.expression`/`jsonPatch.expression` are the other two CEL
/// expression fields `admission.rs`'s mutation-evaluation path reads.
fn mutation_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "patchType" => Some(
            "    entry.insert(\"patchType\".to_string(), serde_json::Value::String(m.patch_type.unwrap_or_default()));\n",
        ),
        "applyConfiguration" => Some(
            "    if let Some(ac) = m.apply_configuration {\n        entry.insert(\"applyConfiguration\".to_string(), gen_apply_configuration_to_json(ac));\n    }\n",
        ),
        "jsonPatch" => Some(
            "    if let Some(jp) = m.json_patch {\n        entry.insert(\"jsonPatch\".to_string(), gen_json_patch_to_json(jp));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutation_to_json`, replacing the inline `mutations` mapping the hand-rolled
/// `gen_map_spec_to_json` built directly.
pub fn generate_mutation(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATION);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATION,
        message,
        mutation_delegated_field,
        "m",
        "entry",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str("fn gen_mutation_to_json(m: ar_v1::Mutation) -> serde_json::Value {\n");
    out.push_str("    let mut entry = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(entry)\n");
    out.push_str("}\n");
    out
}

/// `matchConstraints`/`paramKind` delegate to their own separately generated converters, inserted
/// unconditionally whenever the `Option` is `Some`; `variables`/`mutations`/`matchConditions` are
/// arrays only emitted when non-empty, each delegating to its own per-element generated converter
/// — matching the hand-rolled `gen_map_spec_to_json` this replaces exactly. `failurePolicy`/
/// `reinvocationPolicy` need no entry: plain optional strings the mechanical walker already
/// handles correctly.
fn map_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "matchConstraints" => Some(
            "    if let Some(mc) = spec.match_constraints {\n        obj.insert(\"matchConstraints\".to_string(), gen_match_resources_to_json(mc));\n    }\n",
        ),
        "paramKind" => Some(
            "    if let Some(pk) = spec.param_kind {\n        obj.insert(\"paramKind\".to_string(), gen_param_kind_to_json(pk));\n    }\n",
        ),
        "variables" => Some(
            "    if !spec.variables.is_empty() {\n        let vars: Vec<serde_json::Value> = spec.variables.into_iter().map(gen_variable_to_json).collect();\n        obj.insert(\"variables\".to_string(), serde_json::Value::Array(vars));\n    }\n",
        ),
        "mutations" => Some(
            "    if !spec.mutations.is_empty() {\n        let muts: Vec<serde_json::Value> = spec.mutations.into_iter().map(gen_mutation_to_json).collect();\n        obj.insert(\"mutations\".to_string(), serde_json::Value::Array(muts));\n    }\n",
        ),
        "matchConditions" => Some(
            "    if !spec.match_conditions.is_empty() {\n        let conds: Vec<serde_json::Value> = spec.match_conditions.into_iter().map(gen_match_condition_to_json).collect();\n        obj.insert(\"matchConditions\".to_string(), serde_json::Value::Array(conds));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutating_admission_policy_spec_to_json`, replacing the hand-rolled
/// `gen_map_spec_to_json`.
pub fn generate_mutating_admission_policy_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_ADMISSION_POLICY_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_ADMISSION_POLICY_SPEC,
        message,
        map_spec_delegated_field,
        "spec",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_admission_policy_spec_to_json(spec: ar_v1::MutatingAdmissionPolicySpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `spec` delegates to
/// the separately generated `gen_mutating_admission_policy_spec_to_json`, inserted unconditionally
/// whenever the `Option` is `Some` — matching the hand-rolled `decode_mutatingadmissionpolicy_proto_gen`
/// this migration retires exactly.
fn mutating_admission_policy_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(map_obj.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = map_obj.spec {\n        obj.insert(\"spec\".to_string(), gen_mutating_admission_policy_spec_to_json(spec));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutating_admission_policy_to_json`, replacing the message-walking body of the
/// hand-rolled `decode_mutatingadmissionpolicy_proto_gen` this migration retires (the entry point
/// itself stays hand-written — see `generate_namespace`'s doc for why; `MutatingAdmissionPolicy`
/// has no `encode_mutatingadmissionpolicy_proto_gen` today, so this is decode-only in the same
/// sense).
pub fn generate_mutating_admission_policy(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_ADMISSION_POLICY);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_ADMISSION_POLICY,
        message,
        mutating_admission_policy_delegated_field,
        "map_obj",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_admission_policy_to_json(map_obj: ar_v1::MutatingAdmissionPolicy) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `paramRef`/`matchResources` delegate to their own separately generated converters, inserted
/// unconditionally whenever the `Option` is `Some` — matching the hand-rolled
/// `decode_mutatingadmissionpolicybinding_proto_gen` this migration retires exactly. `policyName`
/// needs no entry: a plain optional string the mechanical walker already handles correctly. Unlike
/// `ValidatingAdmissionPolicyBindingSpec`, this message has no `validationActions` field.
fn map_binding_spec_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "paramRef" => Some(
            "    if let Some(pr) = spec.param_ref {\n        obj.insert(\"paramRef\".to_string(), gen_param_ref_to_json(pr));\n    }\n",
        ),
        "matchResources" => Some(
            "    if let Some(mr) = spec.match_resources {\n        obj.insert(\"matchResources\".to_string(), gen_match_resources_to_json(mr));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutating_admission_policy_binding_spec_to_json`, replacing the inline `spec`
/// assembly block the hand-rolled `decode_mutatingadmissionpolicybinding_proto_gen` built directly.
pub fn generate_mutating_admission_policy_binding_spec(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_ADMISSION_POLICY_BINDING_SPEC);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_ADMISSION_POLICY_BINDING_SPEC,
        message,
        map_binding_spec_delegated_field,
        "spec",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_admission_policy_binding_spec_to_json(spec: ar_v1::MutatingAdmissionPolicyBindingSpec) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}

/// `metadata` delegates for the same reason as every other Kind in this file. `spec` delegates to
/// the separately generated `gen_mutating_admission_policy_binding_spec_to_json`, inserted
/// unconditionally whenever the `Option` is `Some` — matching the hand-rolled
/// `decode_mutatingadmissionpolicybinding_proto_gen` this migration retires exactly.
fn mutating_admission_policy_binding_delegated_field(field_name: &str) -> Option<&'static str> {
    match field_name {
        "metadata" => Some(
            "    obj.insert(\"metadata\".to_string(), gen_object_meta_to_json(binding.metadata.unwrap_or_default()));\n",
        ),
        "spec" => Some(
            "    if let Some(spec) = binding.spec {\n        obj.insert(\"spec\".to_string(), gen_mutating_admission_policy_binding_spec_to_json(spec));\n    }\n",
        ),
        _ => None,
    }
}

/// Generates `gen_mutating_admission_policy_binding_to_json`, replacing the message-walking body
/// of the hand-rolled `decode_mutatingadmissionpolicybinding_proto_gen` this migration retires
/// (the entry point itself stays hand-written — see `generate_namespace`'s doc for why;
/// `MutatingAdmissionPolicyBinding` has no `encode_mutatingadmissionpolicybinding_proto_gen` today,
/// so this is decode-only in the same sense).
pub fn generate_mutating_admission_policy_binding(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, MUTATING_ADMISSION_POLICY_BINDING);
    let encode_stmts = generate_message_encode_only(
        &set,
        MUTATING_ADMISSION_POLICY_BINDING,
        message,
        mutating_admission_policy_binding_delegated_field,
        "binding",
        "obj",
    );

    let mut out = String::new();
    out.push_str("// @generated by crates/apiserver/build/codegen.rs — do not hand-edit.\n");
    out.push_str("// Regenerated on every `cargo build -p u7s-apiserver`.\n\n");
    out.push_str(
        "fn gen_mutating_admission_policy_binding_to_json(binding: ar_v1::MutatingAdmissionPolicyBinding) -> serde_json::Value {\n",
    );
    out.push_str("    let mut obj = serde_json::Map::new();\n");
    out.push_str(&encode_stmts);
    out.push_str("    serde_json::Value::Object(obj)\n");
    out.push_str("}\n");
    out
}
