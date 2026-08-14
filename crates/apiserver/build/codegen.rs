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

/// Emits the encode-direction (proto -> JSON) statements for `message`'s own fields, reading
/// from `value_var` (an already-unwrapped `Option::Some` binding) and writing into `map_var`. A
/// nested message-typed field (VolumeSource's `secretRef: Option<LocalObjectReference>` fields)
/// recurses one level deeper with fresh `x{depth}`/`m{depth}` names — required because, unlike
/// VolumeSource's own top-level fields (always inserted once `Option` is `Some`, matching
/// `generate_volume_source`'s own unconditional insert below), a nested field is only inserted
/// if the object it recurses into ends up non-empty (e.g. a `secretRef` with no `name` is
/// dropped entirely, not emitted as `{}` — matches every hand-rolled `secretRef` branch this
/// replaces).
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
            Type::Int32 if !repeated => {
                writeln!(out, "    if let Some(v) = {value_var}.{rust_field} {{").unwrap();
                writeln!(
                    out,
                    "        {map_var}.insert(\"{key}\".to_string(), serde_json::Value::Number(v.into()));"
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
            Type::Message if !repeated => {
                let nested = find_message(set, field.type_name());
                let nested_value = format!("x{}", depth + 1);
                let nested_map = format!("m{}", depth + 1);
                writeln!(out, "    if let Some({nested_value}) = {value_var}.{rust_field} {{").unwrap();
                writeln!(out, "        let mut {nested_map} = serde_json::Map::new();").unwrap();
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
                "{owner}.{} has a shape ({other:?}, repeated={repeated}) the mechanical VolumeSource \
                 codegen walker doesn't know how to handle — add the owning top-level VolumeSource \
                 field to DELEGATED_FIELDS/EXCLUDED_FIELDS in build/codegen.rs, or extend the walker",
                field.name(),
            ),
        }
    }
}

/// Emits the decode-direction (JSON -> proto) struct-literal expression for `message`, reading
/// keys off `value_var` (an already-in-scope `&serde_json::Value`). Mirrors
/// `emit_mechanical_encode`'s field-shape dispatch field-for-field, including the same nested
/// recursion for message-typed fields — see that function's doc for why depth-suffixed variable
/// names are threaded through.
fn emit_mechanical_decode(
    set: &FileDescriptorSet,
    owner: &str,
    message: &DescriptorProto,
    rust_type: &str,
    value_var: &str,
    depth: u32,
    out: &mut String,
) {
    writeln!(out, "core_v1::{rust_type} {{").unwrap();
    for field in &message.field {
        let key = json_key(owner, field.name(), field.json_name());
        let rust_field = rust_field_name(field.name());
        let repeated = field.label() == Label::Repeated;
        let rhs = match field.r#type() {
            Type::String if repeated => format!("jstrs({value_var}, \"{key}\")"),
            Type::String => format!("jstr({value_var}, \"{key}\")"),
            Type::Bool => format!("jbool({value_var}, \"{key}\")"),
            Type::Int32 if !repeated => format!("ji32({value_var}, \"{key}\")"),
            Type::Message if repeated && is_string_map_field(set, field) => {
                format!("jstrmap({value_var}, \"{key}\")")
            }
            Type::Message if field.type_name() == QUANTITY => format!(
                "jstr({value_var}, \"{key}\").map(|s| super::apps_gen::k8s::io::apimachinery::pkg::api::resource::Quantity {{ string: Some(s) }})"
            ),
            Type::Message if !repeated => {
                let nested = find_message(set, field.type_name());
                let nested_rust_type = rust_message_type_name(field.type_name());
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
                "{owner}.{} has a shape ({other:?}, repeated={repeated}) the mechanical VolumeSource \
                 codegen walker doesn't know how to handle — add the owning top-level VolumeSource \
                 field to DELEGATED_FIELDS/EXCLUDED_FIELDS in build/codegen.rs, or extend the walker",
                field.name(),
            ),
        };
        writeln!(out, "    {rust_field}: {rhs},").unwrap();
    }
    out.push('}');
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
        let rust_type = rust_message_type_name(field.type_name());

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
