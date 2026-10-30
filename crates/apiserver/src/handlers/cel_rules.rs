//! Compile-time checks for `x-kubernetes-validations` rules, run when a CRD is created or
//! updated so a broken rule is rejected up front instead of failing every CR write.
//!
//! The `cel` crate has no checker, so this walks the parsed AST against the CRD schema and
//! reports the two classes of error upstream's checker surfaces most often: a field
//! selection that the schema does not declare (`undefined field 'z'`) and a reference to an
//! identifier that is not in scope. Anything it cannot type statically is treated as
//! dynamic and accepted, so it never rejects a rule upstream would accept.

use cel::common::ast::{operators, EntryExpr, Expr, IdedExpr, LiteralValue};
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
    Bool,
    Int,
    Str,
}

/// Schema of a collection whose element type the checker does not track.
static OPAQUE: J = J::Null;

/// Two-variable comprehension macros (cel-go `ext.TwoVarComprehensions`) and the argument
/// counts they accept, counting the two loop variables; any other count is an ordinary call
/// to an undeclared function.
pub(crate) fn two_var_arity(name: &str) -> Option<std::ops::RangeInclusive<usize>> {
    match name {
        "all" | "exists" | "exists_one" | "existsOne" => Some(3..=3),
        "transformList" | "transformMap" | "transformMapEntry" => Some(3..=4),
        _ => None,
    }
}

/// The comprehension a well-formed two-variable macro call expands to, built like cel-go's
/// `ext/comprehensions.go`, so the cost model sees exactly the loop upstream costs.
///
/// With `lowered` the loop is one the `cel` interpreter can run, which has no second loop
/// variable: it iterates `@pairs(range)` and each body binds `k`/`v` to the pair's halves.
pub(crate) fn two_var_comprehension(
    e: &IdedExpr,
    lowered: bool,
) -> Option<cel::common::ast::ComprehensionExpr> {
    use cel::common::ast::{CallExpr, ComprehensionExpr, ListExpr, MapExpr};
    let Expr::Call(call) = &e.expr else {
        return None;
    };
    let target = call.target.as_deref()?;
    if !two_var_arity(&call.func_name)?.contains(&call.args.len()) {
        return None;
    }
    let (Expr::Ident(k), Expr::Ident(v)) = (&call.args[0].expr, &call.args[1].expr) else {
        return None;
    };
    let id = e.id;
    let mk = |expr| IdedExpr { id, expr };
    let accu = || mk(Expr::Ident("@result".into()));
    let op = |f: &str, args: Vec<IdedExpr>| {
        mk(Expr::Call(CallExpr {
            func_name: f.into(),
            target: None,
            args,
        }))
    };
    let boolean = |b: bool| mk(Expr::Literal(LiteralValue::Boolean(b.into())));
    let int = |n: i64| mk(Expr::Literal(LiteralValue::Int(n.into())));
    let pair_half = |n: i64| {
        op(
            operators::INDEX,
            vec![mk(Expr::Ident("@it".into())), int(n)],
        )
    };
    let bind = |var: &String, init: IdedExpr, body: IdedExpr| {
        mk(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: mk(Expr::List(ListExpr::default())),
            iter_var: "@unused".into(),
            iter_var2: None,
            accu_var: var.clone(),
            accu_init: init,
            loop_cond: boolean(false),
            loop_step: mk(Expr::Ident(var.clone())),
            result: body,
        })))
    };
    let rest: Vec<IdedExpr> = call.args[2..]
        .iter()
        .map(|a| {
            if lowered {
                bind(k, pair_half(0), bind(v, pair_half(1), a.clone()))
            } else {
                a.clone()
            }
        })
        .collect();
    let (map_insert, key) = if lowered {
        ("@mapInsert", pair_half(0))
    } else {
        ("cel.@mapInsert", mk(Expr::Ident(k.clone())))
    };
    let name = call.func_name.as_str();
    let (init, cond, step, result) = match name {
        "all" => (
            boolean(true),
            op(operators::NOT_STRICTLY_FALSE, vec![accu()]),
            op(operators::LOGICAL_AND, vec![accu(), rest[0].clone()]),
            accu(),
        ),
        "exists" => (
            boolean(false),
            op(
                operators::NOT_STRICTLY_FALSE,
                vec![op(operators::LOGICAL_NOT, vec![accu()])],
            ),
            op(operators::LOGICAL_OR, vec![accu(), rest[0].clone()]),
            accu(),
        ),
        "exists_one" | "existsOne" => (
            int(0),
            boolean(true),
            op(
                operators::CONDITIONAL,
                vec![
                    rest[0].clone(),
                    op(operators::ADD, vec![accu(), int(1)]),
                    accu(),
                ],
            ),
            op(operators::EQUALS, vec![accu(), int(1)]),
        ),
        _ => {
            let transform = rest[rest.len() - 1].clone();
            let mut step = match name {
                "transformList" => op(
                    operators::ADD,
                    vec![
                        accu(),
                        mk(Expr::List(ListExpr {
                            elements: vec![transform],
                            optional_indices: vec![],
                        })),
                    ],
                ),
                "transformMap" => op(map_insert, vec![accu(), key, transform]),
                _ => op(map_insert, vec![accu(), transform]),
            };
            if rest.len() == 2 {
                step = op(operators::CONDITIONAL, vec![rest[0].clone(), step, accu()]);
            }
            let init = if name == "transformList" {
                mk(Expr::List(ListExpr::default()))
            } else {
                mk(Expr::Map(MapExpr::default()))
            };
            (init, boolean(true), step, accu())
        }
    };
    let (iter_range, iter_var, iter_var2) = if lowered {
        (op("@pairs", vec![target.clone()]), "@it".to_string(), None)
    } else {
        (target.clone(), k.clone(), Some(v.clone()))
    };
    Some(ComprehensionExpr {
        iter_range,
        iter_var,
        iter_var2,
        accu_var: "@result".into(),
        accu_init: init,
        loop_cond: cond,
        loop_step: step,
        result,
    })
}

/// `expr` with every two-variable macro call replaced by a loop the `cel` interpreter can
/// run; `None` when it has none.
pub(crate) fn lower_two_var_macros(expr: &IdedExpr) -> Option<IdedExpr> {
    fn lower(e: &mut IdedExpr) -> bool {
        let mut changed = false;
        match &mut e.expr {
            Expr::Select(s) => changed |= lower(&mut s.operand),
            Expr::Call(c) => {
                if let Some(t) = c.target.as_deref_mut() {
                    changed |= lower(t);
                }
                for a in &mut c.args {
                    changed |= lower(a);
                }
            }
            Expr::List(l) => {
                for el in &mut l.elements {
                    changed |= lower(el);
                }
            }
            Expr::Map(m) => {
                for entry in &mut m.entries {
                    if let EntryExpr::MapEntry(me) = &mut entry.expr {
                        changed |= lower(&mut me.key);
                        changed |= lower(&mut me.value);
                    }
                }
            }
            Expr::Struct(s) => {
                for entry in &mut s.entries {
                    if let EntryExpr::StructField(f) = &mut entry.expr {
                        changed |= lower(&mut f.value);
                    }
                }
            }
            Expr::Comprehension(c) => {
                for part in [
                    &mut c.iter_range,
                    &mut c.accu_init,
                    &mut c.loop_cond,
                    &mut c.loop_step,
                    &mut c.result,
                ] {
                    changed |= lower(part);
                }
            }
            Expr::Ident(_) | Expr::Literal(_) | Expr::Unspecified => {}
        }
        if let Some(comprehension) = two_var_comprehension(e, true) {
            e.expr = Expr::Comprehension(Box::new(comprehension));
            changed = true;
        }
        changed
    }
    let mut lowered = expr.clone();
    lower(&mut lowered).then_some(lowered)
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
        Some("boolean") => Ty::Bool,
        Some("integer") => Ty::Int,
        Some("string") if schema.get("format").is_none() => Ty::Str,
        _ => Ty::Dyn,
    }
}

impl<'a> Ty<'a> {
    fn name(self) -> Option<&'static str> {
        match self {
            Ty::Bool => Some("bool"),
            Ty::Int => Some("int"),
            Ty::Str => Some("string"),
            Ty::List(_) => Some("list(dyn)"),
            Ty::Map(_) => Some("map(string, dyn)"),
            Ty::Dyn | Ty::Obj { .. } => None,
        }
    }

    fn is_scalar(self) -> bool {
        matches!(self, Ty::Bool | Ty::Int | Ty::Str)
    }

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

    /// A two-variable macro with an accepted argument count: the loop variables are typed as
    /// cel-go's checker types them (map key / list index, then the element) and the result
    /// by macro.
    fn check_two_var(
        &mut self,
        e: &IdedExpr,
        call: &cel::common::ast::CallExpr,
        range: Ty<'a>,
    ) -> Ty<'a> {
        let mut names = Vec::new();
        for arg in &call.args[..2] {
            match &arg.expr {
                Expr::Ident(n) => names.push(n.clone()),
                _ => {
                    self.error(arg.id, "argument must be a simple name".into());
                    return Ty::Dyn;
                }
            }
        }
        if names[0] == names[1] {
            self.error(
                call.args[1].id,
                format!("duplicate variable name: {}", names[0]),
            );
            return Ty::Dyn;
        }
        if let Some((i, _)) = names
            .iter()
            .enumerate()
            .find(|(_, n)| n.as_str() == "__result__")
        {
            self.error(
                call.args[i].id,
                "iteration variable overwrites accumulator variable".into(),
            );
            return Ty::Dyn;
        }
        let (key, value) = match range {
            Ty::List(_) => (Ty::Int, range.elem()),
            Ty::Map(_) => (Ty::Str, range.elem()),
            Ty::Dyn | Ty::Obj { .. } => (Ty::Dyn, Ty::Dyn),
            other => {
                if let Some(name) = other.name() {
                    self.error(
                        call.target.as_ref().map_or(e.id, |t| t.id),
                        format!(
                            "expression of type '{name}' cannot be range of a comprehension \
                             (must be list, map, or dynamic)"
                        ),
                    );
                }
                (Ty::Dyn, Ty::Dyn)
            }
        };
        let depth = self.scope.len();
        self.scope.push((names[0].clone(), key));
        self.scope.push((names[1].clone(), value));
        for a in &call.args[2..] {
            self.check(a);
        }
        self.scope.truncate(depth);
        match call.func_name.as_str() {
            "transformList" => Ty::List(&OPAQUE),
            "transformMap" | "transformMapEntry" => Ty::Map(&OPAQUE),
            _ => Ty::Bool,
        }
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
                if let Some(name) = operand.name().filter(|_| operand.is_scalar()) {
                    self.error(
                        e.id,
                        format!("type '{name}' does not support field selection"),
                    );
                    return Ty::Dyn;
                }
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
                let mut target_ty = Ty::Dyn;
                if let Some(target) = &call.target {
                    // `math.greatest(..)`-style namespaces are idents with no binding.
                    let is_namespace = matches!(&target.expr, Expr::Ident(n)
                        if !self.scope.iter().any(|(s, _)| s == n));
                    if !is_namespace {
                        target_ty = self.check(target);
                    }
                }
                let macro_arity = two_var_arity(&call.func_name).filter(|_| call.target.is_some());
                if let (Some(arity), Some(_)) = (&macro_arity, &call.target) {
                    if arity.contains(&call.args.len()) {
                        return self.check_two_var(e, call, target_ty);
                    }
                }
                let arg_tys: Vec<_> = call.args.iter().map(|a| self.check(a)).collect();
                if macro_arity.is_some() {
                    self.error(
                        e.id,
                        format!(
                            "undeclared reference to '{}' (in container '')",
                            call.func_name
                        ),
                    );
                    return Ty::Dyn;
                }
                if call.func_name == operators::INDEX {
                    return arg_tys.first().map_or(Ty::Dyn, |t| t.elem());
                }
                if let ([a, b], true) = (arg_tys.as_slice(), call.func_name == operators::ADD) {
                    let same_kind = |a: Ty, b: Ty| {
                        matches!(
                            (a, b),
                            (Ty::Int, Ty::Int) | (Ty::Str, Ty::Str) | (Ty::List(_), Ty::List(_))
                        )
                    };
                    if let (Some(an), Some(bn)) = (a.name(), b.name()) {
                        if !same_kind(*a, *b) {
                            self.error(
                                e.id,
                                format!(
                                    "found no matching overload for '_+_' applied to '({an}, {bn})'"
                                ),
                            );
                        }
                    }
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
            Expr::Literal(LiteralValue::Int(_)) => Ty::Int,
            Expr::Literal(LiteralValue::String(_)) => Ty::Str,
            Expr::Literal(LiteralValue::Boolean(_)) => Ty::Bool,
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
    let errors = crate::cel_runtime::walk_deep(source, "checker", || {
        checker.check(program.expression());
        std::mem::take(&mut checker.errors)
    })?;
    if errors.is_empty() {
        Ok(program)
    } else {
        Err(errors.join("\n"))
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
                let cost = crate::cel_runtime::walk_deep(src, "cost estimator", || {
                    cel_cost::estimate(&program, node, Some(node), None)
                })
                .map_err(crate::status::Status::unprocessable_entity)?
                .saturating_mul(instances);
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

    /// The type checker and cost estimator recurse once per AST level. A rule at the depth
    /// limit used to run them on the 512 KiB request thread, which aborts the whole process
    /// in a debug build, so a CRD create could kill the apiserver.
    #[test]
    fn rule_at_depth_limit_is_checked_without_overflowing_a_request_thread() {
        let handle = std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let calls = crate::cel_runtime::MAX_RECURSION_DEPTH - 5;
                let schema = serde_json::json!({
                    "type": "string",
                    "x-kubernetes-validations": [
                        {"rule": format!("self{} == 'a'", ".lowerAscii()".repeat(calls))}
                    ]
                });
                check_schema_rules(&schema, "spec", true, &Ratchet { preexisting: None })
            })
            .unwrap();
        handle
            .join()
            .expect("deep rule must not crash the request thread")
            .expect("rule at the depth limit is valid");
    }

    fn crd_with_spec(spec: J) -> J {
        serde_json::json!({ "type": "object", "properties": { "spec": spec } })
    }

    fn check_crd(schema: &J) -> Result<(), String> {
        check_schema_rules(schema, "S", true, &Ratchet::default()).map_err(|e| e.1.message)
    }

    fn int_obj() -> J {
        serde_json::json!({ "type": "object", "properties": { "n": { "type": "integer" } } })
    }

    fn with_rules(mut node: J, rules: &[&str]) -> J {
        let rules: Vec<J> = rules
            .iter()
            .map(|r| serde_json::json!({ "rule": r }))
            .collect();
        node["x-kubernetes-validations"] = J::Array(rules);
        node
    }

    fn map_of(value: J) -> J {
        serde_json::json!({ "type": "object", "maxProperties": 10, "additionalProperties": value })
    }

    /// A rule on a map's object values must see the value's declared fields, otherwise
    /// no rule on map values with sub-fields can ever be created.
    #[test]
    fn rule_on_additional_properties_object_value_sees_its_fields() {
        let spec = map_of(with_rules(int_obj(), &["self.n > 0"]));
        check_crd(&crd_with_spec(spec)).expect("self.n is declared on the map value");
        let bad = map_of(with_rules(int_obj(), &["self.z > 0"]));
        let err = check_crd(&crd_with_spec(bad)).unwrap_err();
        assert!(err.contains("undefined field 'z'"), "{err}");
    }

    #[test]
    fn rule_on_additional_properties_value_of_a_spec_property() {
        let spec = serde_json::json!({ "type": "object", "properties": {
            "m": map_of(with_rules(int_obj(), &["self.n > 0"])) } });
        check_crd(&crd_with_spec(spec)).expect("self.n is declared on the map value");
    }

    #[test]
    fn rule_on_nested_additional_properties_sees_inner_value_fields() {
        let inner = map_of(with_rules(int_obj(), &["self.n > 0"]));
        let spec = map_of(with_rules(inner, &["self.all(k, self[k].n > 0)"]));
        check_crd(&crd_with_spec(spec)).expect("map of maps of objects");
        let bad = map_of(map_of(with_rules(int_obj(), &["self.z > 0"])));
        assert!(check_crd(&crd_with_spec(bad)).is_err());
    }

    #[test]
    fn rule_on_additional_properties_under_array_items_sees_value_fields() {
        let items = map_of(with_rules(int_obj(), &["self.n > 0"]));
        let spec = serde_json::json!({ "type": "array", "maxItems": 10, "items": items });
        check_crd(&crd_with_spec(spec)).expect("array of maps of objects");
        let spec = serde_json::json!({ "type": "array", "maxItems": 10,
            "items": with_rules(map_of(int_obj()), &["self.all(k, self[k].n > 0)"]) });
        check_crd(&crd_with_spec(spec)).expect("rule on the map inside array items");
    }

    #[test]
    fn additional_properties_true_has_no_value_fields_to_check() {
        let spec = with_rules(
            serde_json::json!({ "type": "object", "additionalProperties": true }),
            &["self.anything == 1"],
        );
        check_crd(&crd_with_spec(spec)).expect("untyped map is dynamic");
    }

    #[test]
    fn preserve_unknown_fields_under_additional_properties_is_dynamic() {
        let value = with_rules(
            serde_json::json!({ "type": "object", "x-kubernetes-preserve-unknown-fields": true }),
            &["self.anything == 1"],
        );
        check_crd(&crd_with_spec(map_of(value))).expect("preserve-unknown value is dynamic");
    }

    #[test]
    fn rule_on_the_map_itself_indexes_values_and_selects_their_fields() {
        let spec = with_rules(
            map_of(int_obj()),
            &[
                "self['a'].n > 0",
                "self.all(k, self[k].n > 0)",
                "self.all(k, v, v.n > 0)",
            ],
        );
        check_crd(&crd_with_spec(spec)).expect("map value fields are typed");
        let bad = with_rules(map_of(int_obj()), &["self['a'].z > 0"]);
        let err = check_crd(&crd_with_spec(bad)).unwrap_err();
        assert!(err.contains("undefined field 'z'"), "{err}");
    }

    #[test]
    fn transition_rule_on_additional_properties_value_types_old_self() {
        let spec = map_of(with_rules(int_obj(), &["self.n >= oldSelf.n"]));
        check_crd(&crd_with_spec(spec)).expect("oldSelf is the value object");
    }

    fn two_var_schema() -> J {
        serde_json::json!({ "type": "object", "properties": {
            "m": { "type": "object", "maxProperties": 10,
                   "additionalProperties": { "type": "string" } },
            "l": { "type": "array", "maxItems": 10, "items": { "type": "integer" } },
        } })
    }

    fn check_two_var(rule: &str) -> Result<(), String> {
        compile_rule(rule, &two_var_schema(), false).map(|_| ())
    }

    #[test]
    fn two_var_macros_accept_exactly_the_upstream_argument_counts() {
        for rule in [
            "self.l.all(i, v, v > 0)",
            "self.l.exists(i, v, v > 0)",
            "self.l.existsOne(i, v, v > 0)",
            "self.l.exists_one(i, v, v > 0)",
            "self.l.transformList(i, v, v)",
            "self.l.transformList(i, v, v > 0, v)",
            "self.l.transformMap(i, v, v)",
            "self.l.transformMap(i, v, v > 0, v)",
            "self.l.transformMapEntry(i, v, {v: i})",
            "self.l.transformMapEntry(i, v, v > 0, {v: i})",
            "self.m.all(k, v, v != '')",
        ] {
            check_two_var(rule).unwrap_or_else(|e| panic!("{rule}: {e}"));
        }
    }

    #[test]
    fn two_var_macros_with_any_other_argument_count_are_rejected_like_an_undeclared_function() {
        for (rule, name) in [
            ("self.l.all(i, v, true, true)", "all"),
            ("self.l.exists(i, v, true, true)", "exists"),
            ("self.l.existsOne(i, v, true, true)", "existsOne"),
            ("self.l.exists_one(i, v, true, true)", "exists_one"),
            ("self.l.all()", "all"),
            ("self.l.transformList(i, v)", "transformList"),
            ("self.l.transformList(i, v, true, v, v)", "transformList"),
            ("self.l.transformMap(i, v)", "transformMap"),
            ("self.l.transformMap(i, v, true, v, v)", "transformMap"),
            ("self.l.transformMapEntry(i, v)", "transformMapEntry"),
            (
                "self.l.transformMapEntry(i, v, true, {v: i}, 1)",
                "transformMapEntry",
            ),
        ] {
            let err = check_two_var(rule)
                .expect_err(&format!("{rule}: the runtime cannot evaluate this arity"));
            assert!(
                err.contains(&format!(
                    "undeclared reference to '{name}' (in container '')"
                )),
                "{rule}: {err}"
            );
        }
    }

    #[test]
    fn two_var_loop_variables_must_be_distinct_simple_names() {
        let err = check_two_var("self.l.all(i, i, true)").unwrap_err();
        assert!(err.contains("duplicate variable name: i"), "{err}");
        let err = check_two_var("self.l.all(i, 1, true)").unwrap_err();
        assert!(err.contains("argument must be a simple name"), "{err}");
    }

    #[test]
    fn two_var_loop_variables_are_typed_like_upstream() {
        let err = check_two_var("self.m.all(k, v, k.foo == 1)").unwrap_err();
        assert!(
            err.contains("type 'string' does not support field selection"),
            "map keys are strings: {err}"
        );
        let err = check_two_var("self.l.all(i, v, i.foo == 1)").unwrap_err();
        assert!(
            err.contains("type 'int' does not support field selection"),
            "list indexes are ints: {err}"
        );
        let err = check_two_var("self.l.all(i, v, v.foo == 1)").unwrap_err();
        assert!(
            err.contains("type 'int' does not support field selection"),
            "the second variable is the element type: {err}"
        );
        check_two_var("self.l.all(i, v, i < v) && self.m.all(k, v, k + v != '')")
            .expect("int index and string key/value are usable as such");
    }

    #[test]
    fn two_var_results_are_typed_per_macro() {
        for rule in [
            "self.l.all(i, v, true) + 1",
            "self.l.exists(i, v, true) + 1",
            "self.l.existsOne(i, v, true) + 1",
            "self.l.transformList(i, v, v) + 1",
            "self.l.transformMap(i, v, v) + 1",
            "self.l.transformMapEntry(i, v, {v: i}) + 1",
        ] {
            let err = check_two_var(rule).unwrap_err();
            assert!(
                err.contains("found no matching overload for '_+_'"),
                "{rule}: {err}"
            );
        }
        check_two_var("self.l.transformList(i, v, v) + [1]").expect("list + list");
        check_two_var("self.l.transformMap(i, v, v).size() == 1").expect("map result");
    }

    fn nested_list_rule(max: Option<u64>, rule: &str) -> J {
        let mut outer = serde_json::json!({ "type": "array" });
        let mut inner = serde_json::json!({
            "type": "array", "items": { "type": "string" },
            "x-kubernetes-validations": [{ "rule": rule }]
        });
        if let Some(n) = max {
            outer["maxItems"] = n.into();
            inner["maxItems"] = n.into();
            inner["items"]["maxLength"] = 10.into();
        }
        outer["items"] = inner;
        serde_json::json!({ "type": "object", "properties": { "spec": outer } })
    }

    #[test]
    fn over_budget_two_var_rule_is_rejected_at_create_like_the_one_var_form() {
        for rule in [
            "self.all(i, s, s == 'string constant')",
            "self.exists(i, s, s == 'string constant')",
            "self.transformList(i, s, s == 'x').size() > 0",
        ] {
            let err = check_crd(&nested_list_rule(None, rule)).unwrap_err();
            assert!(
                err.contains("estimated rule cost exceeds budget by factor of"),
                "{rule}: an unbounded two-variable loop must be refused at create, not left \
                 to blow the runtime budget: {err}"
            );
        }
    }

    #[test]
    fn bounded_two_var_rule_is_accepted_at_create() {
        check_crd(&nested_list_rule(
            Some(10),
            "self.all(i, s, s == 'string constant')",
        ))
        .expect("maxItems-bounded two-variable loop is within budget");
    }

    #[test]
    fn two_var_macro_costs_the_same_as_the_equivalent_one_var_comprehension() {
        let schema = two_var_schema();
        let cost = |rule: &str| {
            let program = compile_rule(rule, &schema, false).unwrap();
            let node = cel_cost::Node::Schema(&schema);
            cel_cost::estimate(&program, node, Some(node), None)
        };
        assert_eq!(
            cost("self.l.all(i, v, v > 0)"),
            cost("self.l.all(v, v > 0)"),
            "upstream expands both to the same loop shape"
        );
        assert_eq!(
            cost("self.l.exists(i, v, v > 0)"),
            cost("self.l.exists(v, v > 0)")
        );
        assert!(
            cost("self.l.transformList(i, v, v > 0, v)") > cost("self.l.transformList(i, v, v)"),
            "the filter is evaluated per element"
        );
    }
}
