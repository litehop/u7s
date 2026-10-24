//! Compile-time checks for `x-kubernetes-validations` rules, run when a CRD is created or
//! updated so a broken rule is rejected up front instead of failing every CR write.
//!
//! The `cel` crate has no checker, so this walks the parsed AST against the CRD schema and
//! reports the two classes of error upstream's checker surfaces most often: a field
//! selection that the schema does not declare (`undefined field 'z'`) and a reference to an
//! identifier that is not in scope. Anything it cannot type statically is treated as
//! dynamic and accepted, so it never rejects a rule upstream would accept.

use cel::common::ast::{operators, EntryExpr, Expr, IdedExpr};
use serde_json::Value as J;

use crate::handlers::cel_cost;
use crate::handlers::cr::cel_escape_ident;

/// Static type of a CEL expression, as far as the schema determines it.
#[derive(Clone, Copy)]
enum Ty<'a> {
    Dyn,
    /// Object with declared `properties`; `open_root` also admits the
    /// `apiVersion`/`kind`/`metadata` fields every root or embedded resource carries.
    Obj {
        schema: &'a J,
        open_root: bool,
    },
    List(&'a J),
    Map(&'a J),
}

pub(crate) const CEL_TYPE_IDENTS: &[&str] = &[
    "bool",
    "int",
    "uint",
    "double",
    "string",
    "bytes",
    "list",
    "map",
    "null_type",
    "type",
    "dyn",
    "timestamp",
    "duration",
];

fn ty_of(schema: &J, is_root: bool) -> Ty<'_> {
    if schema.get("x-kubernetes-int-or-string") == Some(&J::Bool(true)) {
        return Ty::Dyn;
    }
    match schema.get("type").and_then(|t| t.as_str()) {
        Some("object") => {
            if schema.get("additionalProperties").is_some_and(J::is_object) {
                Ty::Map(schema)
            } else if schema.get("properties").is_some_and(J::is_object) {
                Ty::Obj {
                    schema,
                    open_root: is_root
                        || schema.get("x-kubernetes-embedded-resource") == Some(&J::Bool(true)),
                }
            } else {
                Ty::Dyn
            }
        }
        Some("array") => Ty::List(schema),
        _ => Ty::Dyn,
    }
}

impl<'a> Ty<'a> {
    fn elem(self) -> Ty<'a> {
        match self {
            Ty::List(s) => s.get("items").map_or(Ty::Dyn, |i| ty_of(i, false)),
            Ty::Map(s) => s
                .get("additionalProperties")
                .map_or(Ty::Dyn, |i| ty_of(i, false)),
            _ => Ty::Dyn,
        }
    }

    fn field(self, name: &str) -> Option<Ty<'a>> {
        let Ty::Obj { schema, open_root } = self else {
            return Some(Ty::Dyn);
        };
        if open_root && matches!(name, "apiVersion" | "kind" | "metadata") {
            return Some(Ty::Dyn);
        }
        schema
            .get("properties")
            .and_then(J::as_object)?
            .iter()
            .find(|(key, _)| cel_escape_ident(key).as_deref() == Some(name))
            .map(|(_, prop)| ty_of(prop, false))
    }
}

struct Checker<'a, 'p> {
    program: &'p cel::Program,
    scope: Vec<(String, Ty<'a>)>,
    errors: Vec<String>,
}

impl<'a> Checker<'a, '_> {
    fn error(&mut self, id: u64, msg: String) {
        let source = &self.program.source_info().source;
        let (line, col) = self
            .program
            .source_info()
            .offset_for(id)
            .map_or((1, 1), |(start, _)| {
                let before = &source[..(start as usize).min(source.len())];
                let line = before.matches('\n').count() + 1;
                let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                (line, col)
            });
        self.errors
            .push(format!("ERROR: <input>:{line}:{col}: {msg}"));
    }

    fn check(&mut self, e: &IdedExpr) -> Ty<'a> {
        match &e.expr {
            Expr::Ident(name) => {
                if let Some((_, ty)) = self.scope.iter().rev().find(|(n, _)| n == name) {
                    return *ty;
                }
                if !name.starts_with('@') && !CEL_TYPE_IDENTS.contains(&name.as_str()) {
                    self.error(
                        e.id,
                        format!("undeclared reference to '{name}' (in container '')"),
                    );
                }
                Ty::Dyn
            }
            Expr::Select(sel) => {
                let operand = self.check(&sel.operand);
                match operand.field(&sel.field) {
                    Some(ty) if !sel.test => ty,
                    Some(_) => Ty::Dyn,
                    None => {
                        self.error(e.id, format!("undefined field '{}'", sel.field));
                        Ty::Dyn
                    }
                }
            }
            Expr::Call(call) => {
                if let Some(target) = &call.target {
                    // `math.greatest(..)`-style namespaces are idents with no binding.
                    let is_namespace = matches!(&target.expr, Expr::Ident(n)
                        if !self.scope.iter().any(|(s, _)| s == n));
                    if !is_namespace {
                        self.check(target);
                    }
                }
                let arg_tys: Vec<_> = call.args.iter().map(|a| self.check(a)).collect();
                if call.func_name == operators::INDEX {
                    return arg_tys.first().map_or(Ty::Dyn, |t| t.elem());
                }
                Ty::Dyn
            }
            Expr::Comprehension(c) => {
                let range = self.check(&c.iter_range);
                self.check(&c.accu_init);
                let depth = self.scope.len();
                self.scope.push((c.accu_var.clone(), Ty::Dyn));
                match &c.iter_var2 {
                    Some(v2) => {
                        self.scope.push((c.iter_var.clone(), Ty::Dyn));
                        self.scope.push((v2.clone(), range.elem()));
                    }
                    None => self.scope.push((c.iter_var.clone(), range.elem())),
                }
                self.check(&c.loop_cond);
                self.check(&c.loop_step);
                self.check(&c.result);
                self.scope.truncate(depth);
                Ty::Dyn
            }
            Expr::List(l) => {
                for el in &l.elements {
                    self.check(el);
                }
                Ty::Dyn
            }
            Expr::Map(m) => {
                for entry in &m.entries {
                    if let EntryExpr::MapEntry(me) = &entry.expr {
                        self.check(&me.key);
                        self.check(&me.value);
                    }
                }
                Ty::Dyn
            }
            Expr::Struct(s) => {
                for entry in &s.entries {
                    if let EntryExpr::StructField(f) = &entry.expr {
                        self.check(&f.value);
                    }
                }
                Ty::Dyn
            }
            Expr::Literal(_) | Expr::Unspecified => Ty::Dyn,
        }
    }
}

/// Parses `source` and checks it against the schema node it is declared on. `is_root` is
/// true for the CRD's top-level `openAPIV3Schema`.
pub(crate) fn compile_rule(
    source: &str,
    schema: &J,
    is_root: bool,
) -> Result<cel::Program, String> {
    let program = crate::cel_runtime::compile_program(source)?;
    let self_ty = ty_of(schema, is_root);
    let mut checker = Checker {
        program: &program,
        scope: vec![("self".into(), self_ty), ("oldSelf".into(), self_ty)],
        errors: Vec::new(),
    };
    checker.check(program.expression());
    if checker.errors.is_empty() {
        Ok(program)
    } else {
        Err(checker.errors.join("\n"))
    }
}

/// How many instances of a schema node one object can hold, from the `maxItems` /
/// `maxProperties` of its ancestors; `None` when some ancestor collection is unbounded.
type Cardinality = Option<u64>;

fn child_cardinality(card: Cardinality, schema: &J) -> Cardinality {
    let factor = match schema.get("type").and_then(|t| t.as_str()) {
        Some("array") => schema.get("maxItems").and_then(J::as_u64),
        Some("object") if schema.get("additionalProperties").is_some_and(J::is_object) => {
            schema.get("maxProperties").and_then(J::as_u64)
        }
        _ => Some(1),
    };
    Some(card?.saturating_mul(factor?))
}

/// Every `rule` and `messageExpression` under the `x-kubernetes-validations` of a stored
/// schema value; an update must not start failing on text the CRD already carried.
pub(crate) fn collect_expressions(value: &J, out: &mut std::collections::HashSet<String>) {
    match value {
        J::Object(map) => {
            if let Some(rules) = map.get("x-kubernetes-validations").and_then(J::as_array) {
                for rule in rules {
                    for key in ["rule", "messageExpression"] {
                        if let Some(s) = rule.get(key).and_then(J::as_str) {
                            out.insert(s.to_string());
                        }
                    }
                }
            }
            map.values().for_each(|v| collect_expressions(v, out));
        }
        J::Array(items) => items.iter().for_each(|v| collect_expressions(v, out)),
        _ => {}
    }
}

/// What an update inherits from the stored CRD: expressions already present are not
/// re-failed on compile errors or the per-rule cost limit. The CRD-wide total still applies.
#[derive(Default)]
pub(crate) struct Ratchet<'a> {
    pub preexisting: Option<&'a std::collections::HashSet<String>>,
}

/// Rejects a CRD `openAPIV3Schema` whose `x-kubernetes-validations` rules or
/// `messageExpression`s do not compile, or whose estimated cost exceeds the budgets,
/// formatted like upstream's field errors.
pub(crate) fn check_schema_rules(
    schema: &J,
    path: &str,
    is_root: bool,
    ratchet: &Ratchet,
) -> Result<(), crate::status::StatusError> {
    let mut total_cost = 0u64;
    check_node(schema, path, is_root, Some(1), ratchet, &mut total_cost)?;
    if total_cost > cel_cost::STATIC_CRD_COST_LIMIT {
        return Err(crate::status::Status::unprocessable_entity(format!(
            "{path}: Forbidden: {}",
            cel_cost::budget_message(
                "x-kubernetes-validations estimated rule cost total for entire OpenAPIv3 schema",
                total_cost,
                cel_cost::STATIC_CRD_COST_LIMIT
            )
        )));
    }
    Ok(())
}

fn check_node(
    schema: &J,
    path: &str,
    is_root: bool,
    card: Cardinality,
    ratchet: &Ratchet,
    total_cost: &mut u64,
) -> Result<(), crate::status::StatusError> {
    if let Some(rules) = schema
        .get("x-kubernetes-validations")
        .and_then(|v| v.as_array())
    {
        let instances = card.unwrap_or_else(|| cel_cost::unbounded_cardinality(schema));
        for (i, rule) in rules.iter().enumerate() {
            for key in ["rule", "messageExpression"] {
                let Some(src) = rule
                    .get(key)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                else {
                    continue;
                };
                let program = match compile_rule(src, schema, is_root) {
                    Ok(p) => p,
                    Err(_) if ratchet.preexisting.is_some_and(|p| p.contains(src)) => continue,
                    Err(e) => {
                        return Err(crate::status::Status::unprocessable_entity(format!(
                            "{path}.x-kubernetes-validations[{i}].{key}: Invalid value: \
                             \"{src}\": compilation failed: {e}"
                        )))
                    }
                };
                let node = cel_cost::Node::Schema(schema);
                let cost =
                    cel_cost::estimate(&program, node, Some(node), None).saturating_mul(instances);
                *total_cost = total_cost.saturating_add(cost);
                if cost > cel_cost::STATIC_COST_LIMIT
                    && !ratchet.preexisting.is_some_and(|p| p.contains(src))
                {
                    let name = if key == "rule" {
                        "estimated rule cost"
                    } else {
                        "estimated messageExpression cost"
                    };
                    return Err(crate::status::Status::unprocessable_entity(format!(
                        "{path}.x-kubernetes-validations[{i}].{key}: Forbidden: {}",
                        cel_cost::budget_message(name, cost, cel_cost::STATIC_COST_LIMIT)
                    )));
                }
            }
        }
    }
    let child_card = child_cardinality(card, schema);
    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        for (name, sub) in props {
            let sub_path = format!("{path}.properties[{name}]");
            check_node(sub, &sub_path, false, child_card, ratchet, total_cost)?;
        }
    }
    if let Some(items) = schema.get("items").filter(|v| v.is_object()) {
        check_node(
            items,
            &format!("{path}.items"),
            false,
            child_card,
            ratchet,
            total_cost,
        )?;
    }
    if let Some(ap) = schema.get("additionalProperties").filter(|v| v.is_object()) {
        let sub_path = format!("{path}.additionalProperties");
        check_node(ap, &sub_path, false, child_card, ratchet, total_cost)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> J {
        serde_json::json!({
            "type": "object",
            "properties": {
                "spec": {
                    "type": "object",
                    "properties": {
                        "x": { "type": "integer" },
                        "namespace": { "type": "string" },
                        "list": { "type": "array", "items": {
                            "type": "object",
                            "properties": { "name": { "type": "string" } }
                        } },
                        "labels": { "type": "object",
                            "additionalProperties": { "type": "string" } }
                    }
                }
            }
        })
    }

    fn check_at_spec(rule: &str) -> Result<(), String> {
        let root = schema();
        compile_rule(rule, &root["properties"]["spec"], false).map(|_| ())
    }

    #[test]
    fn rule_selecting_undeclared_property_is_rejected_so_typos_fail_at_crd_create() {
        let err = check_at_spec("self.z == 100").unwrap_err();
        assert!(err.contains("undefined field 'z'"), "{err}");
        assert!(err.contains("<input>:1:"), "{err}");
    }

    #[test]
    fn rule_with_syntax_error_is_rejected_at_crd_create() {
        let err = check_at_spec("self = 42").unwrap_err();
        assert!(err.contains("Syntax error"), "{err}");
    }

    #[test]
    fn declared_properties_escaped_names_and_macro_variables_are_accepted() {
        for rule in [
            "self.x > 0",
            "has(self.x) && self.__namespace__ == 'a'",
            "self.list.all(i, i.name != '')",
            "self.list.exists(i, has(i.name))",
            "self.labels.all(k, self.labels[k] != '')",
            "self.list[0].name == 'a'",
            "self.list.map(i, i.name).size() > 0",
        ] {
            assert!(
                check_at_spec(rule).is_ok(),
                "{rule}: {:?}",
                check_at_spec(rule)
            );
        }
    }

    #[test]
    fn undefined_field_inside_a_comprehension_over_typed_items_is_rejected() {
        let err = check_at_spec("self.list.all(i, i.nope == 'a')").unwrap_err();
        assert!(err.contains("undefined field 'nope'"), "{err}");
    }

    #[test]
    fn undeclared_identifier_is_rejected_but_comprehension_and_namespace_idents_are_not() {
        let err = check_at_spec("foo > 1").unwrap_err();
        assert!(err.contains("undeclared reference to 'foo'"), "{err}");
        assert!(
            check_at_spec("self.list.all(i, i.name == 'a') && math.greatest(1, 2) > 0").is_ok()
        );
    }

    #[test]
    fn root_rule_may_reference_metadata_without_it_being_declared() {
        let root = schema();
        assert!(compile_rule("self.metadata.name == 'a'", &root, true).is_ok());
        assert!(compile_rule(
            "self.metadata.name == 'a'",
            &root["properties"]["spec"],
            false
        )
        .is_err());
    }

    #[test]
    fn untyped_free_form_objects_accept_any_field_like_upstream_preserve_unknown() {
        let free =
            serde_json::json!({ "type": "object", "x-kubernetes-preserve-unknown-fields": true });
        assert!(compile_rule("self.anything == 1", &free, false).is_ok());
    }

    #[test]
    fn rule_over_unbounded_nested_lists_exceeds_the_estimated_cost_budget() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "properties": { "x": {
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": { "type": "string" },
                        "x-kubernetes-validations": [
                            { "rule": "self.all(s, s == 'string constant')" }
                        ]
                    }
                } }
            } }
        });
        let err =
            check_schema_rules(&schema, "openAPIV3Schema", true, &Ratchet::default()).unwrap_err();
        assert!(
            err.1.message.contains("exceeds budget"),
            "a rule that can cost billions per CR must be refused at CRD create, not at every \
             write: {}",
            err.1.message
        );
    }

    #[test]
    fn same_nested_rule_with_max_items_declared_is_within_budget() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "properties": { "x": {
                    "type": "array",
                    "maxItems": 10,
                    "items": {
                        "type": "array",
                        "maxItems": 10,
                        "items": { "type": "string", "maxLength": 10 },
                        "x-kubernetes-validations": [
                            { "rule": "self.all(s, s == 'string constant')" }
                        ]
                    }
                } }
            } }
        });
        assert!(
            check_schema_rules(&schema, "openAPIV3Schema", true, &Ratchet::default()).is_ok(),
            "bounding the collections is the documented remedy; it must make the rule acceptable"
        );
    }

    #[test]
    fn quadratic_rule_over_725_items_is_accepted_at_crd_create() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "x-kubernetes-validations": [
                    { "rule": "self.largeArray.all(x, self.largeArray.all(y, y == x))" }
                ],
                "properties": { "largeArray": {
                    "type": "array", "maxItems": 725, "items": { "type": "integer" }
                } }
            } }
        });
        assert!(
            check_schema_rules(&schema, "openAPIV3Schema", true, &Ratchet::default()).is_ok(),
            "the O(n^2) rule is within the static budget; only its runtime cost must trip"
        );
    }

    #[test]
    fn check_schema_rules_reports_the_field_path_of_the_bad_rule() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "spec": {
                "type": "object",
                "x-kubernetes-validations": [{ "rule": "self.z == 100" }],
                "properties": { "x": { "type": "integer" } }
            } }
        });
        let err =
            check_schema_rules(&schema, "openAPIV3Schema", true, &Ratchet::default()).unwrap_err();
        assert!(
            err.1.message.contains(
                "openAPIV3Schema.properties[spec].x-kubernetes-validations[0].rule: \
                 Invalid value: \"self.z == 100\": compilation failed"
            ),
            "{}",
            err.1.message
        );
    }
}
