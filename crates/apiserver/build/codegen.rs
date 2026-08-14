//! Walks the `FileDescriptorSet` `build.rs` already emits (see `config.file_descriptor_set_path`
//! in `build.rs`) and emits a JSON<->proto codec for a single message as a `.rs` file under
//! `OUT_DIR`, spliced into the crate via `include!` — see `src/core_gen_adapter.rs`.
//!
//! Scoped to `.k8s.io.api.core.v1.ObjectReference` only: its 7 fields are all `optional string`
//! with no renames/inline-embeds/omissions, which is what makes it the right type to prove the
//! walk-the-descriptor/emit-a-file shape on before paying for the exception-table machinery
//! (`RENAMES`/`INLINE_EMBEDS`/`OPAQUE_MESSAGES`/`DELIBERATE_OMISSIONS` in `src/proto_descriptor.rs`)
//! VolumeSource will need. That module's tables stay test-only (`#[cfg(test)] mod
//! proto_descriptor;` in `src/lib.rs`) rather than being made build-script-accessible here,
//! since nothing in this spike would exercise them — deferred to VolumeSource's codegen instead.

use prost::Message;
use prost_types::{field_descriptor_proto::Type, DescriptorProto, FileDescriptorSet};
use std::fmt::Write as _;

/// Depth-first search for `fq_name` (e.g. `.k8s.io.api.core.v1.ObjectReference`) among a
/// `FileDescriptorSet`'s top-level and nested message types. Mirrors the recursion shape of
/// `src/proto_descriptor.rs::message_index`/`insert_message`, minus the index — this module only
/// ever looks up one message per generated file.
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

/// protoc's `json_name` only strips underscores; it leaves a leading capital alone (see
/// `src/proto_descriptor.rs::json_key`, which additionally consults a `RENAMES` table this spike
/// doesn't need — none of `ObjectReference`'s 7 fields are renamed). None of them are declared
/// with a Go-style capitalised name either, so this never actually fires today; kept so the
/// codegen's rule matches the oracle it is checked against field-for-field.
fn json_key(json_name: &str) -> String {
    let mut chars = json_name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {
            first.to_ascii_lowercase().to_string() + chars.as_str()
        }
        _ => json_name.to_string(),
    }
}

/// prost renames every generated struct field to Rust's snake_case regardless of how the proto
/// declares it (`k8s.io/api`'s own style is camelCase, e.g. `apiVersion`). This is a deliberately
/// narrow re-implementation covering plain camelCase with no consecutive-capital runs, which is
/// all `ObjectReference` has. VolumeSource has runs like `scaleIO` that need the real
/// `heck::ToSnakeCase` algorithm prost-build itself uses internally (not part of prost-build's
/// public API) — that generalization is Phase 1's problem (mayor-8tcd3), not this spike's.
fn rust_field_name(proto_field_name: &str) -> String {
    let mut out = String::new();
    for c in proto_field_name.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Generates the `gen_object_reference_to_json`/`json_to_object_reference_proto` pair, matching
/// field-for-field the hand-rolled functions they replace. Panics rather than silently
/// mis-generating if a future proto vendor-bump gives `ObjectReference` a non-string field — this
/// spike's codegen only knows the `Option<String>` shape, by design (see module doc).
pub fn generate_object_reference(descriptor_bytes: &[u8]) -> String {
    let set = FileDescriptorSet::decode(descriptor_bytes)
        .expect("descriptor set emitted by build.rs must decode");
    let message = find_message(&set, ".k8s.io.api.core.v1.ObjectReference");

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
            (rust_field_name(field.name()), json_key(field.json_name()))
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
