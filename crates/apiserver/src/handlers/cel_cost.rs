//! Cost estimation for `x-kubernetes-validations` rules, in the spirit of cel-go's
//! `EstimateCost`: every identifier, selection and call costs one unit, and a comprehension
//! (`all`, `exists`, `map`, `filter`, ...) costs its per-element work times the number of
//! elements in the collection it ranges over.
//!
//! The same walk serves two callers. With a schema it yields the worst-case cost of a rule
//! (collection sizes from `maxItems`/`maxProperties`, or the most elements that fit in a
//! request when unbounded); with the object being validated it yields the cost for that
//! object's real collection sizes. It assumes no short-circuiting, so it never undercounts
//! work the evaluator does, and it counts a value whose size it cannot trace as empty so a
//! rule is never rejected for a collection the walk cannot see.

use cel::common::ast::{operators, EntryExpr, Expr, IdedExpr};
use serde_json::Value as J;

use crate::handlers::cr::cel_escape_ident;

/// Largest request body the apiserver accepts (`k8s.io/apiserver/pkg/apis/cel` `MaxRequestSizeBytes`).
const MAX_REQUEST_BYTES: u64 = 3 * 1024 * 1024;

/// Largest estimated cost of one rule, after multiplying by how often its schema node can occur.
pub(crate) const STATIC_COST_LIMIT: u64 = 10_000_000;

/// Largest summed estimated cost of every rule in one CRD schema.
pub(crate) const STATIC_CRD_COST_LIMIT: u64 = 100_000_000;

/// Largest cost one rule may incur evaluating against one object.
pub(crate) const CALL_COST_LIMIT: u64 = 1_000_000;

/// Where the size of a value comes from.
#[derive(Clone, Copy)]
pub(crate) enum Node<'a> {
    Unknown,
    /// A list of unknown elements with this many entries.
    Sized(u64),
    Schema(&'a J),
    Data {
        value: &'a J,
        schema: Option<&'a J>,
    },
}

/// Fewest bytes a JSON value of this schema occupies.
pub(crate) fn min_serialized_size(schema: &J) -> u64 {
    if schema.get("x-kubernetes-int-or-string") == Some(&J::Bool(true)) {
        return 1;
    }
    match schema.get("type").and_then(|t| t.as_str()) {
        Some("string" | "array" | "object") => 2,
        Some("boolean") => 4,
        _ => 1,
    }
}

/// How many times a value of this schema can appear in one request.
pub(crate) fn unbounded_cardinality(schema: &J) -> u64 {
    MAX_REQUEST_BYTES / (min_serialized_size(schema) + 1)
}

fn max_elements(schema: &J) -> u64 {
    let (limit_key, elem) = match schema.get("type").and_then(|t| t.as_str()) {
        Some("array") => ("maxItems", schema.get("items")),
        Some("object") => ("maxProperties", schema.get("additionalProperties")),
        _ => return 0,
    };
    if let Some(n) = schema.get(limit_key).and_then(J::as_u64) {
        return n;
    }
    elem.filter(|e| e.is_object())
        .map_or(0, |e| MAX_REQUEST_BYTES / (min_serialized_size(e) + 4))
}

fn weight(v: &J) -> usize {
    match v {
        J::Array(a) => a.len(),
        J::Object(o) => o.len(),
        _ => 0,
    }
}

impl<'a> Node<'a> {
    fn len(self) -> u64 {
        match self {
            Node::Unknown => 0,
            Node::Sized(n) => n,
            Node::Schema(s) => max_elements(s),
            Node::Data { value, .. } => weight(value) as u64,
        }
    }

    fn elem(self) -> Node<'a> {
        match self {
            Node::Schema(s) => match s.get("type").and_then(|t| t.as_str()) {
                Some("array") => s.get("items").map_or(Node::Unknown, Node::Schema),
                Some("object") => s
                    .get("additionalProperties")
                    .filter(|v| v.is_object())
                    .map_or(Node::Unknown, Node::Schema),
                _ => Node::Unknown,
            },
            Node::Data { value, schema } => {
                let elem_schema = schema.and_then(|s| match value {
                    J::Array(_) => s.get("items"),
                    _ => s.get("additionalProperties").filter(|v| v.is_object()),
                });
                let largest = match value {
                    J::Array(a) => a.iter().max_by_key(|v| weight(v)),
                    J::Object(o) => o.values().max_by_key(|v| weight(v)),
                    _ => None,
                };
                largest.map_or(Node::Unknown, |value| Node::Data {
                    value,
                    schema: elem_schema,
                })
            }
            Node::Unknown | Node::Sized(_) => Node::Unknown,
        }
    }

    fn field(self, name: &str) -> Node<'a> {
        let prop = |schema: &'a J| {
            schema
                .get("properties")
                .and_then(J::as_object)?
                .iter()
                .find(|(key, _)| cel_escape_ident(key).as_deref() == Some(name))
        };
        match self {
            Node::Schema(s) => prop(s).map_or(Node::Unknown, |(_, p)| Node::Schema(p)),
            Node::Data { value, schema } => match schema.and_then(prop) {
                Some((key, p)) => value.get(key).map_or(Node::Unknown, |value| Node::Data {
                    value,
                    schema: Some(p),
                }),
                None => value.get(name).map_or(Node::Unknown, |value| Node::Data {
                    value,
                    schema: None,
                }),
            },
            _ => Node::Unknown,
        }
    }
}

struct Coster<'a> {
    scope: Vec<(String, Node<'a>)>,
}

impl<'a> Coster<'a> {
    fn cost(&mut self, e: &IdedExpr) -> (u64, Node<'a>) {
        match &e.expr {
            Expr::Ident(name) => {
                let node = self
                    .scope
                    .iter()
                    .rev()
                    .find(|(n, _)| n == name)
                    .map_or(Node::Unknown, |(_, n)| *n);
                (1, node)
            }
            Expr::Literal(_) | Expr::Unspecified => (0, Node::Unknown),
            Expr::Select(sel) => {
                let (c, operand) = self.cost(&sel.operand);
                let node = if sel.test {
                    Node::Unknown
                } else {
                    operand.field(&sel.field)
                };
                (c.saturating_add(1), node)
            }
            Expr::Call(call) => {
                let mut total = 1u64;
                let mut target_node = Node::Unknown;
                if let Some(target) = &call.target {
                    let namespace = matches!(&target.expr, Expr::Ident(n)
                        if !self.scope.iter().any(|(s, _)| s == n));
                    if !namespace {
                        let (c, n) = self.cost(target);
                        total = total.saturating_add(c);
                        target_node = n;
                    }
                }
                let mut arg_nodes = Vec::with_capacity(call.args.len());
                for arg in &call.args {
                    let (c, n) = self.cost(arg);
                    total = total.saturating_add(c);
                    arg_nodes.push(n);
                }
                let result = match call.func_name.as_str() {
                    operators::INDEX => arg_nodes.first().map_or(Node::Unknown, |n| n.elem()),
                    "isSorted" | "sum" | "min" | "max" => {
                        total = total.saturating_add(target_node.len());
                        Node::Unknown
                    }
                    operators::IN => {
                        total = total.saturating_add(arg_nodes.get(1).map_or(0, |n| n.len()));
                        Node::Unknown
                    }
                    _ => Node::Unknown,
                };
                (total, result)
            }
            Expr::Comprehension(c) => {
                let (range_cost, range) = self.cost(&c.iter_range);
                let (init_cost, _) = self.cost(&c.accu_init);
                let depth = self.scope.len();
                self.scope.push((c.accu_var.clone(), Node::Unknown));
                match &c.iter_var2 {
                    Some(v2) => {
                        self.scope.push((c.iter_var.clone(), Node::Unknown));
                        self.scope.push((v2.clone(), range.elem()));
                    }
                    None => self.scope.push((c.iter_var.clone(), range.elem())),
                }
                let (cond, _) = self.cost(&c.loop_cond);
                let (step, _) = self.cost(&c.loop_step);
                let (result, _) = self.cost(&c.result);
                self.scope.truncate(depth);
                let n = range.len();
                let per_iteration = cond.saturating_add(step).saturating_add(1);
                let total = range_cost
                    .saturating_add(init_cost)
                    .saturating_add(n.saturating_mul(per_iteration))
                    .saturating_add(result);
                let node = if matches!(c.accu_init.expr, Expr::List(_)) {
                    Node::Sized(n)
                } else {
                    Node::Unknown
                };
                (total, node)
            }
            Expr::List(l) => (self.sum(l.elements.iter()), Node::Unknown),
            Expr::Map(m) => {
                let mut total = 0u64;
                for entry in &m.entries {
                    if let EntryExpr::MapEntry(me) = &entry.expr {
                        total = total
                            .saturating_add(self.cost(&me.key).0)
                            .saturating_add(self.cost(&me.value).0);
                    }
                }
                (total, Node::Unknown)
            }
            Expr::Struct(s) => {
                let mut total = 0u64;
                for entry in &s.entries {
                    if let EntryExpr::StructField(f) = &entry.expr {
                        total = total.saturating_add(self.cost(&f.value).0);
                    }
                }
                (total, Node::Unknown)
            }
        }
    }

    fn sum<'e>(&mut self, exprs: impl Iterator<Item = &'e IdedExpr>) -> u64 {
        exprs.fold(0u64, |acc, e| acc.saturating_add(self.cost(e).0))
    }
}

/// Cost of evaluating `program` with `self` (and, when given, `oldSelf`) sized by the nodes.
pub(crate) fn estimate(
    program: &cel::Program,
    self_node: Node<'_>,
    old_self_node: Option<Node<'_>>,
) -> u64 {
    let mut scope = vec![("self".to_string(), self_node)];
    if let Some(old) = old_self_node {
        scope.push(("oldSelf".to_string(), old));
    }
    Coster { scope }.cost(program.expression()).0
}

/// The `exceeds budget` detail upstream reports for an over-limit estimate.
pub(crate) fn budget_message(cost_name: &str, cost: u64, limit: u64) -> String {
    let factor = cost as f64 / limit as f64;
    let factor = if factor > 100.0 {
        "more than 100x".to_string()
    } else if factor < 1.5 {
        format!("{factor:.6}x")
    } else {
        format!("{factor:.1}x")
    };
    format!(
        "{cost_name} exceeds budget by factor of {factor} (try simplifying the rule, or adding \
         maxItems, maxProperties, and maxLength where arrays, maps, and strings are declared)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cost_of(rule: &str, self_schema: &J) -> u64 {
        let program = cel::Program::compile(rule).unwrap();
        estimate(&program, Node::Schema(self_schema), None)
    }

    fn int_list(max_items: Option<u64>) -> J {
        let mut s = serde_json::json!({ "type": "array", "items": { "type": "integer" } });
        if let Some(n) = max_items {
            s["maxItems"] = n.into();
        }
        s
    }

    #[test]
    fn comprehension_cost_scales_with_declared_max_items() {
        let small = cost_of("self.all(x, x > 0)", &int_list(Some(10)));
        let large = cost_of("self.all(x, x > 0)", &int_list(Some(1000)));
        assert!(
            large > small * 50,
            "doubling maxItems must scale the estimate, or a rule over a big list is never \
             flagged: {small} vs {large}"
        );
    }

    #[test]
    fn nested_comprehension_over_same_bounded_list_is_quadratic_but_under_the_static_limit() {
        let c = cost_of("self.all(x, self.all(y, y == x))", &int_list(Some(725)));
        assert!(
            c > CALL_COST_LIMIT && c < STATIC_COST_LIMIT,
            "725-element O(n^2) rule must be accepted statically yet exceed the per-call \
             runtime limit, as upstream's CRD validation spec requires: {c}"
        );
    }

    #[test]
    fn unbounded_list_makes_the_same_rule_cost_millions_per_instance() {
        let c = cost_of("self.all(x, x > 0)", &int_list(None));
        assert!(
            c > 1_000_000,
            "without maxItems the estimate must assume the request-size worst case: {c}"
        );
    }

    #[test]
    fn runtime_cost_uses_actual_list_length_not_schema_bound() {
        let schema = int_list(Some(5000));
        let data = serde_json::json!([1, 2, 3]);
        let program = cel::Program::compile("self.all(x, x > 0)").unwrap();
        let actual = estimate(
            &program,
            Node::Data {
                value: &data,
                schema: Some(&schema),
            },
            None,
        );
        assert!(actual < 100, "3 elements must cost little, got {actual}");
    }

    #[test]
    fn untraceable_collection_is_counted_empty_so_rule_is_not_rejected_blindly() {
        let free =
            serde_json::json!({ "type": "object", "x-kubernetes-preserve-unknown-fields": true });
        assert!(cost_of("self.anything.all(x, x > 0)", &free) < 10);
    }

    #[test]
    fn budget_message_names_the_factor_like_upstream() {
        assert!(
            budget_message("estimated rule cost", 2_000_000_000, 10_000_000)
                .starts_with("estimated rule cost exceeds budget by factor of more than 100x")
        );
        assert!(
            budget_message("estimated rule cost", 20_000_000, 10_000_000)
                .contains("by factor of 2.0x")
        );
    }
}
