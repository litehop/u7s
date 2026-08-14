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
/// `json_to_volume_proto`/`gen_pod_spec_to_json` this codegen replaces before it was deleted —
/// not merely "listed in DELIBERATE_OMISSIONS", which is checked as a *necessary* precondition
/// below (an assert, not the source of this list) rather than a sufficient one.
///
/// Fifteen other `VolumeSource` entries in that table (iscsi/glusterfs/rbd/gitRepo/cinder/
/// cephfs/flexVolume/flocker/azureFile/vsphereVolume/quobyte/azureDisk/portworxVolume/scaleIO/
/// storageos) describe a "no plan to implement" policy the hand-rolled code had already reversed
/// by the time this bead started: `encode_pod_proto_gen_round_trips_rare_deprecated_volume_sources`
/// / `decode_pod_proto_gen_round_trips_rare_deprecated_volume_sources` (core_gen_adapter.rs)
/// pin exactly those 15 as supported, round-tripping through real protobuf bytes. Treating
/// DELIBERATE_OMISSIONS as the sole source of what to skip here would silently delete 15
/// already-shipped, already-tested volume types and fail both regression tests — this table is
/// the actual, current omission set; the stale 15 entries are a pre-existing table/code
/// divergence this codegen preserves as-is (content changes to the table are out of scope for
/// this bead) rather than "fixes" by matching code to a table nobody has re-confirmed lately.
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

        if EXCLUDED_FIELDS.contains(&name) {
            assert!(
                is_excluded(VOLUME_SOURCE, name),
                "{name} is in codegen's local EXCLUDED_FIELDS but not in \
                 proto_exceptions.rs's DELIBERATE_OMISSIONS — every field this codegen skips \
                 must be a sanctioned omission, not an arbitrary one"
            );
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
/// `volumeMounts`, newly extracted) hand-written pair in `core_gen_adapter.rs`. Every `Container`
/// field with no entry here is genuinely just "if Some/non-empty, insert", confirmed against
/// `generated.proto`'s `message Container` field-by-field.
fn container_delegated_field(field_name: &str) -> Option<(&'static str, &'static str)> {
    match field_name {
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
/// `hostNetwork` preserve business-rule guards (a positive-only filter and a true-only filter,
/// the latter documented at length on `hostNetwork`'s own generated-code call site) no schema
/// annotation encodes. `imagePullSecrets`/`readinessGates`/`schedulingGates` project one field
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
