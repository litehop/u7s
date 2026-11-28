//! Representative CRD structural-schema shapes validated through `build_schema_validator`.
//! `upstream_valid` is the verdict of upstream apiextensions (go-openapi validation over
//! kube-openapi); a row where ours differs must be listed in `KNOWN_GAPS`, so a gap can
//! neither appear nor silently close.

use serde_json::{json, Value};

#[derive(Debug, PartialEq, Clone, Copy)]
enum Ours {
    Valid,
    Invalid,
    BuildError,
}

struct Row {
    name: &'static str,
    schema: Value,
    instance: Value,
    upstream_valid: bool,
    ours: Ours,
}

fn row(
    name: &'static str,
    schema: Value,
    instance: Value,
    upstream_valid: bool,
    ours: Ours,
) -> Row {
    Row {
        name,
        schema,
        instance,
        upstream_valid,
        ours,
    }
}

fn rows() -> Vec<Row> {
    use Ours::{BuildError, Invalid, Valid};
    vec![
        row(
            "nullable_null",
            json!({"type":"string","nullable":true}),
            json!(null),
            true,
            Invalid,
        ),
        row(
            "non_nullable_null",
            json!({"type":"string"}),
            json!(null),
            false,
            Invalid,
        ),
        row(
            "int_or_string_int",
            json!({"x-kubernetes-int-or-string":true,"anyOf":[{"type":"integer"},{"type":"string"}]}),
            json!(5),
            true,
            Valid,
        ),
        row(
            "int_or_string_object",
            json!({"x-kubernetes-int-or-string":true,"anyOf":[{"type":"integer"},{"type":"string"}]}),
            json!({"a":1}),
            false,
            Invalid,
        ),
        row(
            "preserve_unknown_fields",
            json!({"type":"object","x-kubernetes-preserve-unknown-fields":true,"properties":{"a":{"type":"string"}}}),
            json!({"a":"x","b":1}),
            true,
            Valid,
        ),
        row(
            "embedded_resource",
            json!({"type":"object","x-kubernetes-embedded-resource":true,"x-kubernetes-preserve-unknown-fields":true}),
            json!({"kind":"X"}),
            true,
            Valid,
        ),
        row(
            "list_type_map_type_ignored",
            json!({"type":"array","x-kubernetes-list-type":"set","items":{"type":"string"}}),
            json!(["a", "a"]),
            true,
            Valid,
        ),
        row(
            "default_not_validated",
            json!({"type":"object","properties":{"a":{"type":"string","default":5}}}),
            json!({}),
            true,
            Valid,
        ),
        row(
            "required_empty_array",
            json!({"type":"object","required":[]}),
            json!({}),
            true,
            Valid,
        ),
        row(
            "integer_written_as_float",
            json!({"type":"integer"}),
            json!(5.0),
            true,
            Valid,
        ),
        row(
            "additional_properties_false",
            json!({"type":"object","additionalProperties":false,"properties":{"a":{"type":"string"}}}),
            json!({"b":1}),
            false,
            Invalid,
        ),
        row(
            "unique_items",
            json!({"type":"array","uniqueItems":true}),
            json!([1, 1]),
            false,
            Invalid,
        ),
        row(
            "min_length_counts_runes",
            json!({"type":"string","minLength":2}),
            json!("\u{1F600}"),
            false,
            Invalid,
        ),
        row(
            "unknown_format_ignored",
            json!({"type":"string","format":"quantity-ish"}),
            json!("anything"),
            true,
            Valid,
        ),
        row(
            "format_date_time_bad",
            json!({"type":"string","format":"date-time"}),
            json!("yesterday"),
            false,
            Valid,
        ),
        row(
            "format_byte_bad",
            json!({"type":"string","format":"byte"}),
            json!("!!notbase64"),
            false,
            Valid,
        ),
        row(
            "format_int32_out_of_range",
            json!({"type":"integer","format":"int32"}),
            json!(4294967296i64),
            false,
            Valid,
        ),
        row(
            "exclusive_minimum_boolean_form",
            json!({"type":"integer","minimum":1,"exclusiveMinimum":true}),
            json!(1),
            false,
            BuildError,
        ),
    ]
}

/// Gaps shared with the previous validator (boon gave identical verdicts on every row).
const KNOWN_GAPS: &[&str] = &[
    "nullable_null",
    "format_date_time_bad",
    "format_byte_bad",
    "format_int32_out_of_range",
    "exclusive_minimum_boolean_form",
];

#[test]
fn crd_schema_shapes_validate_as_upstream_except_the_documented_gaps() {
    let mut gaps = Vec::new();
    for r in rows() {
        let actual = match super::crd::build_schema_validator(&r.schema) {
            Err(_) => Ours::BuildError,
            Ok(v) if v.iter_errors(&r.instance).next().is_none() => Ours::Valid,
            Ok(_) => Ours::Invalid,
        };
        assert_eq!(
            actual, r.ours,
            "{}: verdict changed; a CR that was rejected may now be admitted, or the reverse",
            r.name
        );
        if actual == Ours::BuildError || (actual == Ours::Valid) != r.upstream_valid {
            gaps.push(r.name);
        }
    }
    assert_eq!(gaps, KNOWN_GAPS, "set of differences from upstream changed");
}
