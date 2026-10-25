//! Cost estimation for `x-kubernetes-validations` rules, in the spirit of cel-go's
//! `EstimateCost`: every identifier, selection and call costs one unit, and a comprehension
//! (`all`, `exists`, `map`, `filter`, ...) costs its per-element work times the number of
//! elements in the collection it ranges over.
//!
//! The same walk serves two callers. With a schema it yields the worst-case cost of a rule
//! (collection sizes from `maxItems`/`maxProperties`, or the most elements that fit in a
//! request when unbounded); with the object being validated it yields the cost for that
//! object's real collection sizes. Both assume no short-circuiting, so they never undercount
//! work the evaluator does, and count a value whose size they cannot trace as empty so a
//! rule is never rejected for a collection the walk cannot see. Given a context holding the
//! real values, the walk instead replays the rule and follows its short-circuits.

use std::sync::atomic::{AtomicBool, Ordering};

use cel::common::ast::{operators, EntryExpr, Expr, IdedExpr, LiteralValue};
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
        Some("string" | "array") => 2,
        Some("object") => {
            let is_map = schema.get("additionalProperties").is_some_and(J::is_object);
            let (Some(props), false) = (schema.get("properties").and_then(J::as_object), is_map)
            else {
                return 2;
            };
            let required = schema.get("required").and_then(J::as_array);
            let is_required = |name: &str| required.is_some_and(|r| r.iter().any(|n| n == name));
            props
                .iter()
                .filter(|(name, p)| is_required(name) && p.get("default").is_none() && is_typed(p))
                .fold(2u64, |acc, (name, p)| {
                    acc.saturating_add(name.len() as u64 + min_serialized_size(p) + 4)
                })
        }
        Some("boolean") => 4,
        _ => 1,
    }
}

/// Whether upstream gives the schema a CEL type; untyped nodes are opaque to its estimator.
fn is_typed(schema: &J) -> bool {
    schema.get("x-kubernetes-int-or-string") == Some(&J::Bool(true))
        || match schema.get("type").and_then(|t| t.as_str()) {
            Some("array") => schema.get("items").is_some_and(is_typed),
            Some("object" | "string" | "boolean" | "number" | "integer") => true,
            _ => false,
        }
}

/// How many times a value of this schema can appear in one request.
pub(crate) fn unbounded_cardinality(schema: &J) -> u64 {
    MAX_REQUEST_BYTES / (min_serialized_size(schema) + 1)
}

fn max_elements(schema: &J) -> u64 {
    let (limit_key, elem, per_element_overhead) = match schema.get("type").and_then(|t| t.as_str())
    {
        Some("array") => ("maxItems", schema.get("items"), 1),
        Some("object") => ("maxProperties", schema.get("additionalProperties"), 6),
        _ => return 0,
    };
    if let Some(n) = schema.get(limit_key).and_then(J::as_u64) {
        return n;
    }
    elem.filter(|e| e.is_object() && is_typed(e))
        .map_or(0, |e| {
            (MAX_REQUEST_BYTES - 2) / (min_serialized_size(e) + per_element_overhead)
        })
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

    /// Bytes of the string this node holds, when the data says.
    /// Characters of the string this node holds, when the data says.
    fn text_chars(self) -> Option<u64> {
        match self {
            Node::Data {
                value: J::String(s),
                ..
            } => Some(s.chars().count() as u64),
            _ => None,
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

type Ctx<'c, 'p> = Option<&'c cel::Context<'p, 'static>>;

static NULL: J = J::Null;

/// One pass of a comprehension: the key (or index) and element it visits, as sizes and,
/// when they come from an evaluated value rather than the data, as values.
struct Pass<'a> {
    key: (Node<'a>, Option<cel::Value>),
    elem: (Node<'a>, Option<cel::Value>),
}

impl Pass<'_> {
    /// The element's value; built from the data on demand, so a loop that exits early
    /// never converts the elements it does not reach.
    fn elem_value(&self) -> Option<cel::Value> {
        self.elem.1.clone().or_else(|| match self.elem.0 {
            Node::Data { value, schema } => {
                crate::handlers::cr::json_to_cel_value(schema.unwrap_or(&NULL), value).ok()
            }
            _ => None,
        })
    }
}

/// The passes a comprehension makes over `range`, and whether it ranges over a map. The
/// data says how many; failing that, when replaying, the value the range evaluates to.
fn passes<'a>(
    range: Node<'a>,
    live: Ctx<'_, '_>,
    expr: &IdedExpr,
) -> Option<(Vec<Pass<'a>>, bool)> {
    let elem_of = |value: &'a J, schema: Option<&'a J>| Node::Data { value, schema };
    match range {
        Node::Data { value, schema } => match value {
            J::Array(a) => {
                let items = schema.and_then(|s| s.get("items"));
                Some((
                    a.iter()
                        .enumerate()
                        .map(|(i, v)| Pass {
                            key: (Node::Unknown, Some(cel::Value::Int(i as i64))),
                            elem: (elem_of(v, items), None),
                        })
                        .collect(),
                    false,
                ))
            }
            J::Object(o) => {
                let values =
                    schema.and_then(|s| s.get("additionalProperties").filter(|v| v.is_object()));
                Some((
                    o.iter()
                        .map(|(k, v)| Pass {
                            key: (Node::Unknown, Some(cel::Value::from(k.as_str()))),
                            elem: (elem_of(v, values), None),
                        })
                        .collect(),
                    true,
                ))
            }
            _ => None,
        },
        _ => match live?.resolve(expr).ok()? {
            cel::Value::List(l) => Some((
                l.iter()
                    .enumerate()
                    .map(|(i, v)| Pass {
                        key: (Node::Unknown, Some(cel::Value::Int(i as i64))),
                        elem: (Node::Unknown, Some(v.clone())),
                    })
                    .collect(),
                false,
            )),
            cel::Value::Map(m) => Some((
                m.map
                    .iter()
                    .map(|(k, v)| Pass {
                        key: (Node::Unknown, Some(k.into())),
                        elem: (Node::Unknown, Some(v.clone())),
                    })
                    .collect(),
                true,
            )),
            _ => None,
        },
    }
}

struct Coster<'a> {
    scope: Vec<(String, Node<'a>)>,
    /// A comprehension stops iterating once its cost passes this: the caller only needs to
    /// know the limit was crossed.
    limit: u64,
    /// Element count billed for a comprehension range whose size cannot be traced.
    untraced_range_len: u64,
    /// Set by the caller when it gives up waiting; the walk then stops iterating so a
    /// replay does not outlive its caller.
    cancelled: Option<&'a AtomicBool>,
}

/// cel-go v0.29.2 `common/cost.go` `StringTraversalCostFactor`: cost of traversing a string
/// once, per character.
const STRING_TRAVERSAL_COST_FACTOR: f64 = 0.1;

/// cel-go v0.29.2 `common/cost.go` `RegexStringLengthCostFactor`: cost of applying a regex,
/// per pattern character.
const REGEX_STRING_LENGTH_COST_FACTOR: f64 = 0.25;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Str,
    Bytes,
    List,
    Other,
}

/// One operand of a call as cel-go's `actualSize` sees it: its size and kind. `traversal`
/// and `text_chars` are only filled for the functions that bill by them (`DEEP_FUNCS`).
#[derive(Clone, Copy)]
struct Operand {
    size: u64,
    kind: Kind,
    /// k8s `traversalCost`: 0.1 per byte of every string or bytes value nested in it.
    traversal: u64,
    /// Characters of the string elements of a list.
    text_chars: u64,
}

impl Operand {
    const fn new(size: u64, kind: Kind) -> Self {
        Operand {
            size,
            kind,
            traversal: 0,
            text_chars: 0,
        }
    }

    /// An operand whose size the walk cannot see: one unit, like any non-sizer.
    const UNKNOWN: Operand = Operand::new(1, Kind::Other);
}

fn scaled_ceil(n: u64, factor: f64) -> u64 {
    (n as f64 * factor).ceil() as u64
}

/// k8s `library/cost.go` `traversalCost`.
fn traversal_cost(v: &cel::Value) -> u64 {
    match v {
        cel::Value::String(s) => (s.len() as f64 * STRING_TRAVERSAL_COST_FACTOR) as u64,
        cel::Value::Bytes(b) => (b.len() as f64 * STRING_TRAVERSAL_COST_FACTOR) as u64,
        cel::Value::List(l) => l.iter().map(traversal_cost).sum(),
        cel::Value::Map(m) => m
            .map
            .iter()
            .map(|(k, v)| traversal_cost(&k.into()) + traversal_cost(v))
            .sum(),
        _ => 1,
    }
}

/// cel-go `actualSize`: an optional holding a value is as big as the value.
fn operand_of_value(v: &cel::Value, deep: bool) -> Operand {
    if let Ok(opt) = <&cel::objects::OptionalValue>::try_from(v) {
        if let Some(inner) = opt.value() {
            return operand_of_value(inner, deep);
        }
    }
    let (size, kind) = match v {
        cel::Value::String(s) => (s.chars().count() as u64, Kind::Str),
        cel::Value::Bytes(b) => (b.len() as u64, Kind::Bytes),
        cel::Value::List(l) => (l.len() as u64, Kind::List),
        cel::Value::Map(m) => (m.map.len() as u64, Kind::Other),
        _ => (1, Kind::Other),
    };
    let mut operand = Operand::new(size, kind);
    if deep {
        operand.traversal = traversal_cost(v);
        if let cel::Value::List(l) = v {
            operand.text_chars = l
                .iter()
                .map(|e| match e {
                    cel::Value::String(s) => s.chars().count() as u64,
                    _ => 0,
                })
                .sum();
        }
    }
    operand
}

/// Functions `call_cost_from_table` bills by size; every other call is one unit, so its
/// operands need not be evaluated.
const TABLE_FUNCS: &[&str] = &[
    "startsWith",
    "endsWith",
    "contains",
    "matches",
    "bytes",
    "string",
    "format",
    "quote",
    "size",
    "trim",
    "lowerAscii",
    "upperAscii",
    "substring",
    "url",
    "replace",
    "split",
    "find",
    "findAll",
    "join",
    "isSorted",
    "sum",
    "min",
    "max",
    "indexOf",
    "lastIndexOf",
    "includes",
    operators::LESS,
    operators::LESS_EQUALS,
    operators::GREATER,
    operators::GREATER_EQUALS,
    operators::EQUALS,
    operators::NOT_EQUALS,
    operators::ADD,
    operators::IN,
];

/// Functions whose bill needs `Operand::traversal` or `Operand::text_chars`.
const DEEP_FUNCS: &[&str] = &[
    "join",
    "isSorted",
    "sum",
    "min",
    "max",
    "indexOf",
    "lastIndexOf",
    "includes",
];

/// What cel-go's runtime cost tracker bills one call with these operands, receiver first
/// (`interpreter/runtimecost.go` `costCall`, v0.29.2), or the Kubernetes extension library
/// does (`k8s.io/apiserver/pkg/cel/library/cost.go` `CallCost`, which takes precedence).
/// `None` is the default of one unit.
fn call_cost_from_table(func: &str, operands: &[Operand], is_member: bool) -> Option<u64> {
    let traversal = |n: u64| scaled_ceil(n, STRING_TRAVERSAL_COST_FACTOR);
    match (func, operands) {
        ("startsWith" | "endsWith", [_, arg]) if is_member => Some(traversal(arg.size)),
        ("contains", [recv, arg]) if is_member => Some(traversal(recv.size) * traversal(arg.size)),
        ("matches", [subject, regex]) => Some(
            traversal(1 + subject.size) * scaled_ceil(regex.size, REGEX_STRING_LENGTH_COST_FACTOR),
        ),
        ("bytes", [arg]) if !is_member && arg.kind == Kind::Str => Some(traversal(arg.size)),
        ("string", [arg]) if !is_member && arg.kind == Kind::Bytes => Some(traversal(arg.size)),
        ("format", [recv, _]) if is_member => Some(traversal(recv.size)),
        ("quote", [arg]) if !is_member => Some(traversal(arg.size)),
        // cel-go bills `size` as one unit, but the `cel` crate counts a string's
        // characters on every call, so a loop calling it on a large payload string is
        // real work. Billing the traversal keeps that loop inside the limit.
        ("size", [arg]) if arg.kind == Kind::Str => Some(traversal(arg.size).max(1)),
        ("trim" | "lowerAscii" | "upperAscii" | "substring" | "url", [recv, ..]) => {
            Some(traversal(recv.size))
        }
        ("replace" | "split", [recv, ..]) => Some(traversal(recv.size * 2)),
        ("join", [recv, rest @ ..]) => {
            let separators = recv.size.saturating_sub(1) * rest.first().map_or(0, |s| s.size);
            Some(traversal((recv.text_chars + separators) * 2))
        }
        ("find" | "findAll", [subject, regex, ..]) => Some(
            traversal(1 + subject.size) * scaled_ceil(regex.size, REGEX_STRING_LENGTH_COST_FACTOR),
        ),
        (
            "isSorted" | "sum" | "min" | "max" | "indexOf" | "lastIndexOf" | "includes",
            [recv, ..],
        ) => Some(recv.traversal),
        (
            operators::LESS
            | operators::LESS_EQUALS
            | operators::GREATER
            | operators::GREATER_EQUALS
            | operators::EQUALS
            | operators::NOT_EQUALS,
            [l, r],
        ) => Some(traversal(l.size.min(r.size))),
        (operators::ADD, [l, r])
            if l.kind == r.kind && matches!(l.kind, Kind::Str | Kind::Bytes) =>
        {
            Some(traversal(l.size + r.size))
        }
        (operators::IN, [_, coll]) if coll.kind == Kind::List => Some(coll.size),
        _ => None,
    }
}

impl<'a> Coster<'a> {
    /// The operand of `e` for billing before anything is evaluated: a string literal, or
    /// the data string the node holds. `None` when the walk cannot tell.
    fn static_operand(e: &IdedExpr, node: Node<'a>) -> Option<Operand> {
        if let Expr::Literal(LiteralValue::String(s)) = &e.expr {
            return Some(Operand::new(s.inner().chars().count() as u64, Kind::Str));
        }
        node.text_chars().map(|size| Operand::new(size, Kind::Str))
    }

    /// What one call costs per cel-go's table, replacing the unit a bare call is billed
    /// (`None`: keep the unit). With a context the operands are the real values, so the
    /// bill is upstream's exactly; without one a call is billed only when its receiver's
    /// size is known from the data or a literal, and an argument of unknown size counts as
    /// one character. Checks the cancel flag before each operand it evaluates.
    fn table_cost(
        &self,
        call: &cel::common::ast::CallExpr,
        target_node: Node<'a>,
        arg_nodes: &[Node<'a>],
        ctx: Ctx<'_, '_>,
    ) -> Option<u64> {
        if !TABLE_FUNCS.contains(&call.func_name.as_str()) {
            return None;
        }
        let is_member = call.target.is_some();
        let deep = DEEP_FUNCS.contains(&call.func_name.as_str());
        let mut operands = Vec::with_capacity(call.args.len() + 1);
        if let Some(ctx) = ctx {
            for expr in call.target.iter().map(|t| &**t).chain(&call.args) {
                if self.is_cancelled() {
                    return Some(self.limit.saturating_add(1));
                }
                operands.push(operand_of_value(&ctx.resolve(expr).ok()?, deep));
            }
        } else {
            if let Some(target) = &call.target {
                operands.push(Self::static_operand(target, target_node)?);
            }
            for (arg, node) in call.args.iter().zip(arg_nodes) {
                operands.push(Self::static_operand(arg, *node).unwrap_or(Operand::UNKNOWN));
            }
        }
        call_cost_from_table(&call.func_name, &operands, is_member)
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.is_some_and(|c| c.load(Ordering::Relaxed))
    }

    fn cost(&mut self, e: &IdedExpr, ctx: Ctx<'_, '_>) -> (u64, Node<'a>) {
        // Every loop in the walk recurses through here, so a cancelled walk unwinds without
        // visiting or evaluating anything further.
        if self.is_cancelled() {
            return (self.limit.saturating_add(1), Node::Unknown);
        }
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
                let (c, operand) = self.cost(&sel.operand, ctx);
                let node = if sel.test {
                    Node::Unknown
                } else {
                    operand.field(&sel.field)
                };
                // Kubernetes' environment sets PresenceTestHasCost(false): has() adds nothing
                // beyond its operand.
                (c.saturating_add(u64::from(!sel.test)), node)
            }
            Expr::Call(call) => {
                let func = call.func_name.as_str();
                if let (Some(ctx), true) = (
                    ctx,
                    call.target.is_none()
                        && matches!(
                            func,
                            operators::CONDITIONAL | operators::LOGICAL_AND | operators::LOGICAL_OR
                        ),
                ) {
                    let (head, _) = self.cost(&call.args[0], Some(ctx));
                    // Resolving the head runs it for real: only do so once its counted
                    // cost has shown it cheap.
                    if head > self.limit {
                        return (head, Node::Unknown);
                    }
                    let head_value = ctx.resolve(&call.args[0]).ok();
                    let branch = match (func, head_value) {
                        (operators::LOGICAL_AND, Some(cel::Value::Bool(false)))
                        | (operators::LOGICAL_OR, Some(cel::Value::Bool(true))) => {
                            return (head, Node::Unknown)
                        }
                        (operators::CONDITIONAL, Some(cel::Value::Bool(b))) => {
                            Some(&call.args[if b { 1 } else { 2 }])
                        }
                        _ => None,
                    };
                    let rest = match branch {
                        Some(arm) => self.cost(arm, Some(ctx)).0,
                        None if func == operators::CONDITIONAL => call.args[1..]
                            .iter()
                            .map(|a| self.cost(a, Some(ctx)).0)
                            .max()
                            .unwrap_or(0),
                        None => self.cost(&call.args[1], Some(ctx)).0,
                    };
                    return (head.saturating_add(rest), Node::Unknown);
                }
                let is_conditional = func == operators::CONDITIONAL;
                let mut total = match func {
                    operators::CONDITIONAL | operators::LOGICAL_AND | operators::LOGICAL_OR => 0,
                    _ => 1u64,
                };
                let mut branch_max = 0u64;
                let mut target_node = Node::Unknown;
                if let Some(target) = &call.target {
                    let namespace = matches!(&target.expr, Expr::Ident(n)
                        if !self.scope.iter().any(|(s, _)| s == n));
                    if !namespace {
                        let (c, n) = self.cost(target, ctx);
                        total = total.saturating_add(c);
                        target_node = n;
                    }
                }
                let mut arg_nodes = Vec::with_capacity(call.args.len());
                for (i, arg) in call.args.iter().enumerate() {
                    let (c, n) = self.cost(arg, ctx);
                    if is_conditional && i > 0 {
                        branch_max = branch_max.max(c);
                    } else {
                        total = total.saturating_add(c);
                    }
                    arg_nodes.push(n);
                }
                total = total.saturating_add(branch_max);
                if total <= self.limit {
                    if let Some(cost) = self.table_cost(call, target_node, &arg_nodes, ctx) {
                        total = total.saturating_sub(1).saturating_add(cost);
                    }
                }
                let result = match call.func_name.as_str() {
                    operators::INDEX => arg_nodes.first().map_or(Node::Unknown, |n| n.elem()),
                    "isSorted" | "sum" | "min" | "max" if ctx.is_none() => {
                        total = total.saturating_add(target_node.len());
                        Node::Unknown
                    }
                    operators::IN if ctx.is_none() => {
                        total = total.saturating_add(arg_nodes.get(1).map_or(0, |n| n.len()));
                        Node::Unknown
                    }
                    _ => Node::Unknown,
                };
                (total, result)
            }
            Expr::Comprehension(c) => {
                let (range_cost, range) = self.cost(&c.iter_range, ctx);
                let (init_cost, _) = self.cost(&c.accu_init, ctx);
                let mut total = range_cost.saturating_add(init_cost);
                // Iterating resolves the range, which runs it for real: not once its
                // counted cost alone has crossed the limit.
                if ctx.is_some() && total > self.limit {
                    return (total, Node::Unknown);
                }
                let depth = self.scope.len();
                self.scope.push((c.accu_var.clone(), Node::Unknown));
                let mut accu = ctx.and_then(|ctx| ctx.resolve(&c.accu_init).ok());
                // `map` and `filter` loop unconditionally and nothing in them reads the
                // accumulator, so only a conditional loop (`all`, `exists`) needs it tracked.
                let track_accu = !matches!(c.loop_cond.expr, Expr::Literal(_));
                let n = match passes(range, ctx, &c.iter_range) {
                    Some((passes, is_map)) => {
                        let mut ran = 0u64;
                        let mut child = ctx.map(|ctx| ctx.new_inner_scope());
                        for pass in passes {
                            if self.is_cancelled() {
                                total = self.limit.saturating_add(1);
                                break;
                            }
                            let first_is_elem = c.iter_var2.is_none() && !is_map;
                            self.scope.truncate(depth + 1);
                            self.scope.push((
                                c.iter_var.clone(),
                                if first_is_elem {
                                    pass.elem.0
                                } else {
                                    pass.key.0
                                },
                            ));
                            if let Some(name) = &c.iter_var2 {
                                self.scope.push((name.clone(), pass.elem.0));
                            }
                            if let Some(child) = child.as_mut() {
                                if let Some(accu) = &accu {
                                    child.add_variable_from_value(c.accu_var.clone(), accu.clone());
                                }
                                let first_value = if first_is_elem {
                                    pass.elem_value()
                                } else {
                                    pass.key.1.clone()
                                };
                                if let Some(value) = first_value {
                                    child.add_variable_from_value(c.iter_var.clone(), value);
                                }
                                if let (Some(name), Some(value)) = (&c.iter_var2, pass.elem_value())
                                {
                                    child.add_variable_from_value(name.clone(), value);
                                }
                            }
                            let pass_ctx = child.as_ref();
                            let (cond, _) = self.cost(&c.loop_cond, pass_ctx);
                            total = total.saturating_add(cond);
                            if total > self.limit {
                                break;
                            }
                            if track_accu
                                && pass_ctx.is_some_and(|ctx| {
                                    !matches!(ctx.resolve(&c.loop_cond), Ok(cel::Value::Bool(true)))
                                })
                            {
                                break;
                            }
                            let (step, _) = self.cost(&c.loop_step, pass_ctx);
                            total = total.saturating_add(step);
                            ran += 1;
                            if total > self.limit {
                                break;
                            }
                            if track_accu {
                                if let Some(next) =
                                    pass_ctx.and_then(|ctx| ctx.resolve(&c.loop_step).ok())
                                {
                                    accu = Some(next);
                                }
                            }
                        }
                        ran
                    }
                    None => {
                        let n = match range {
                            Node::Unknown => self.untraced_range_len,
                            _ => range.len(),
                        };
                        let elem = range.elem();
                        match &c.iter_var2 {
                            Some(v2) => {
                                self.scope.push((c.iter_var.clone(), Node::Unknown));
                                self.scope.push((v2.clone(), elem));
                            }
                            None => self.scope.push((c.iter_var.clone(), elem)),
                        }
                        let (cond, _) = self.cost(&c.loop_cond, ctx);
                        let (step, _) = self.cost(&c.loop_step, ctx);
                        total = total.saturating_add(n.saturating_mul(cond.saturating_add(step)));
                        n
                    }
                };
                self.scope.truncate(depth + 1);
                let mut result_ctx = ctx.map(|ctx| ctx.new_inner_scope());
                if let (Some(child), Some(accu)) = (result_ctx.as_mut(), &accu) {
                    child.add_variable_from_value(c.accu_var.clone(), accu.clone());
                }
                let (result, _) = self.cost(&c.result, result_ctx.as_ref());
                self.scope.truncate(depth);
                total = total.saturating_add(result);
                let node = if !matches!(c.accu_init.expr, Expr::List(_)) {
                    Node::Unknown
                } else if let Some(cel::Value::List(l)) = &accu {
                    Node::Sized(l.len() as u64)
                } else {
                    Node::Sized(n)
                };
                (total, node)
            }
            Expr::List(l) => (
                self.sum(l.elements.iter(), ctx).saturating_add(10),
                Node::Sized(l.elements.len() as u64),
            ),
            Expr::Map(m) => {
                let mut total = 0u64;
                for entry in &m.entries {
                    if let EntryExpr::MapEntry(me) = &entry.expr {
                        total = total
                            .saturating_add(self.cost(&me.key, ctx).0)
                            .saturating_add(self.cost(&me.value, ctx).0);
                    }
                }
                (total.saturating_add(30), Node::Unknown)
            }
            Expr::Struct(s) => {
                let mut total = 0u64;
                for entry in &s.entries {
                    if let EntryExpr::StructField(f) = &entry.expr {
                        total = total.saturating_add(self.cost(&f.value, ctx).0);
                    }
                }
                (total.saturating_add(40), Node::Unknown)
            }
        }
    }

    fn sum<'e>(&mut self, exprs: impl Iterator<Item = &'e IdedExpr>, ctx: Ctx<'_, '_>) -> u64 {
        exprs.fold(0u64, |acc, e| acc.saturating_add(self.cost(e, ctx).0))
    }
}

/// Cost of evaluating `program` with `self` (and, when given, `oldSelf`) sized by the nodes.
///
/// Without `ctx` every branch and loop iteration is billed, an upper bound on the work
/// done. With a context holding the real `self`/`oldSelf` values, the rule is replayed:
/// the branch taken, the `&&`/`||`/ternary short-circuits and the early exit of `all` and
/// `exists` follow the data, as in the evaluator's own cost accounting. Iterating stops
/// once [`CALL_COST_LIMIT`] is crossed.
pub(crate) fn estimate(
    program: &cel::Program,
    self_node: Node<'_>,
    old_self_node: Option<Node<'_>>,
    ctx: Ctx<'_, '_>,
) -> u64 {
    estimate_with(program, self_node, old_self_node, ctx, (0, None))
}

/// [`estimate`] for a rule about to run against a request: a comprehension over a range
/// the walk cannot trace (`split()`, `a + b`, a ternary) is billed as if it held as many
/// elements as fit in a request body, not zero. The result is only used to decide whether
/// to replay the rule against the real values, so over-billing costs a replay but never
/// rejects a rule; billing zero let a quadratic rule skip the replay and run unmetered.
pub(crate) fn estimate_for_write(
    program: &cel::Program,
    self_node: Node<'_>,
    old_self_node: Option<Node<'_>>,
    ctx: Ctx<'_, '_>,
    cancelled: Option<&AtomicBool>,
) -> u64 {
    estimate_with(
        program,
        self_node,
        old_self_node,
        ctx,
        (MAX_REQUEST_BYTES / 2, cancelled),
    )
}

fn estimate_with(
    program: &cel::Program,
    self_node: Node<'_>,
    old_self_node: Option<Node<'_>>,
    ctx: Ctx<'_, '_>,
    (untraced_range_len, cancelled): (u64, Option<&AtomicBool>),
) -> u64 {
    let mut scope = vec![("self".to_string(), self_node)];
    if let Some(old) = old_self_node {
        scope.push(("oldSelf".to_string(), old));
    }
    Coster {
        scope,
        limit: CALL_COST_LIMIT,
        untraced_range_len,
        cancelled,
    }
    .cost(program.expression(), ctx)
    .0
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
        estimate(&program, Node::Schema(self_schema), None, None)
    }

    fn int_list(max_items: Option<u64>) -> J {
        let mut s = serde_json::json!({ "type": "array", "items": { "type": "integer" } });
        if let Some(n) = max_items {
            s["maxItems"] = n.into();
        }
        s
    }

    #[test]
    fn has_presence_test_costs_only_its_operand_like_kubernetes() {
        let obj = serde_json::json!({ "type": "object" });
        assert_eq!(
            cost_of("has(self.a) || has(self.b)", &obj),
            2,
            "Kubernetes sets PresenceTestHasCost(false), so each has() costs just `self`; \
             billing the select too doubles the estimate and rejects CRDs (Envoy Gateway \
             SecurityPolicy) that upstream accepts"
        );
        assert_eq!(cost_of("self.a", &obj), 2, "a plain select still costs one");
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
    fn ternary_costs_condition_plus_the_costlier_branch_not_both_branches() {
        let schema = int_list(Some(1000));
        let one = cost_of("self.all(x, x > 0)", &schema);
        let ternary = cost_of(
            "self.size() > 0 ? self.all(x, x > 0) : self.all(x, x > 1)",
            &schema,
        );
        assert!(
            ternary < one + one / 10,
            "summing both branches would roughly double the estimate and falsely reject a rule \
             upstream accepts near the 10M budget: {ternary} vs single branch {one}"
        );
    }

    #[test]
    fn comprehension_cost_is_step_plus_loop_condition_per_element_without_extra_overhead() {
        let c = cost_of("self.all(x, x > 0)", &int_list(Some(1000)));
        assert!(
            (5_000..5_100).contains(&c),
            "cel-go bills 5 units per element for all(): loop condition 2 + step 3; an extra \
             per-element unit would falsely reject borderline rules: {c}"
        );
    }

    #[test]
    fn logical_operators_add_no_call_overhead_of_their_own() {
        let schema = int_list(None);
        let one = cost_of("self.size() > 0", &schema);
        let and = cost_of("self.size() > 0 && self.size() > 0", &schema);
        assert_eq!(and, one * 2, "cel-go costs && as lhs + rhs only");
    }

    #[test]
    fn list_of_objects_with_required_fields_fits_fewer_elements_per_request() {
        let items = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "properties": { "name": { "type": "string" }, "opt": { "type": "string" } }
        });
        assert_eq!(min_serialized_size(&items), 2 + 4 + 2 + 4);
        let list = serde_json::json!({ "type": "array", "items": items });
        assert_eq!(max_elements(&list), (3 * 1024 * 1024 - 2) / (12 + 1));
    }

    #[test]
    fn unbounded_map_entries_account_for_quotes_colon_and_comma() {
        let map = serde_json::json!({
            "type": "object", "additionalProperties": { "type": "integer" }
        });
        assert_eq!(max_elements(&map), (3 * 1024 * 1024 - 2) / (1 + 6));
    }

    #[test]
    fn untyped_items_are_opaque_to_the_estimator_like_upstream() {
        let list = serde_json::json!({ "type": "array", "items": {} });
        assert_eq!(max_elements(&list), 0);
    }

    #[test]
    fn replay_stops_where_exists_finds_its_match_while_the_upper_bound_bills_every_cell() {
        let schema = serde_json::json!({
            "type": "array", "maxItems": 1000,
            "items": { "type": "array", "maxItems": 1000, "items": { "type": "string" } }
        });
        let row: Vec<&str> = std::iter::once("x")
            .chain(std::iter::repeat_n("y", 999))
            .collect();
        let data = serde_json::json!(vec![row; 1000]);
        let program = cel::Program::compile("self.exists(r, r.exists(c, c == 'x'))").unwrap();
        let node = Node::Data {
            value: &data,
            schema: Some(&schema),
        };
        let upper = estimate(&program, node, None, None);
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value(
            "self",
            crate::handlers::cr::json_to_cel_value(&schema, &data).unwrap(),
        );
        let replayed = estimate(&program, node, None, Some(&ctx));
        assert!(
            upper > CALL_COST_LIMIT,
            "the no-short-circuit bound must see a million cells: {upper}"
        );
        assert!(
            replayed < 100,
            "upstream stops at the first cell, so replaying must too: {replayed}"
        );
    }

    fn big_text_schema() -> J {
        serde_json::json!({
            "type": "object",
            "properties": {
                "csv": { "type": "string" },
                "items": { "type": "array", "items": { "type": "string" } }
            }
        })
    }

    /// A loop whose every step scans a 200KB string does 600M byte-reads over 3000 items yet
    /// counts as ~5 units per item unless the scan itself is billed; the rule then runs
    /// unmetered on a thread that outlives the request's timeout.
    #[test]
    fn string_scan_inside_a_loop_is_billed_by_the_receiver_size() {
        let schema = big_text_schema();
        let data = serde_json::json!({
            "csv": "a".repeat(200_000),
            "items": vec!["a"; 3000],
        });
        let program = cel::Program::compile("self.items.all(x, self.csv.contains(x))").unwrap();
        let node = Node::Data {
            value: &data,
            schema: Some(&schema),
        };
        let cost = estimate_for_write(&program, node, None, None, None);
        assert!(
            cost > CALL_COST_LIMIT,
            "3000 scans of a 200KB string must exceed the per-call limit: {cost}"
        );
    }

    #[test]
    fn short_string_scans_stay_cheap_so_ordinary_rules_are_not_rejected() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "abc", "items": vec!["a"; 3000] });
        let program = cel::Program::compile("self.items.all(x, self.csv.contains(x))").unwrap();
        let node = Node::Data {
            value: &data,
            schema: Some(&schema),
        };
        let cost = estimate_for_write(&program, node, None, None, None);
        assert!(cost < CALL_COST_LIMIT, "{cost}");
    }

    /// A replay whose caller has given up must stop iterating instead of finishing the
    /// work on a thread nobody waits for.
    #[test]
    fn cancelled_replay_stops_iterating_and_reports_over_limit() {
        let schema = int_list(Some(10));
        let data = serde_json::json!([1, 2, 3, 4, 5]);
        let program = cel::Program::compile("self.all(x, x > 0)").unwrap();
        let mut ctx = cel::Context::default();
        ctx.add_variable_from_value(
            "self",
            crate::handlers::cr::json_to_cel_value(&schema, &data).unwrap(),
        );
        let node = Node::Data {
            value: &data,
            schema: Some(&schema),
        };
        let live = AtomicBool::new(false);
        assert!(
            estimate_for_write(&program, node, None, Some(&ctx), Some(&live)) < CALL_COST_LIMIT
        );
        let cancelled = AtomicBool::new(true);
        assert!(
            estimate_for_write(&program, node, None, Some(&ctx), Some(&cancelled))
                > CALL_COST_LIMIT,
            "a cancelled walk must not keep evaluating elements"
        );
    }

    fn op(size: u64, kind: Kind) -> Operand {
        Operand::new(size, kind)
    }

    /// Expected costs are hand-computed from cel-go v0.29.2 `interpreter/runtimecost.go`
    /// `costCall` with `StringTraversalCostFactor` 0.1 and `RegexStringLengthCostFactor`
    /// 0.25. A drifting factor or product term mis-bills a rule differently from upstream,
    /// so a CRD upstream accepts is rejected, or a payload scan upstream rejects is let in.
    #[test]
    fn call_costs_follow_the_upstream_runtime_cost_table() {
        use Kind::{Bytes, List, Other, Str};
        let cases: &[(&str, &[Operand], bool, Option<u64>)] = &[
            ("startsWith", &[op(1000, Str), op(25, Str)], true, Some(3)),
            ("endsWith", &[op(1000, Str), op(10, Str)], true, Some(1)),
            ("startsWith", &[op(1000, Str), op(0, Str)], true, Some(0)),
            ("contains", &[op(1000, Str), op(25, Str)], true, Some(300)),
            (
                "contains",
                &[op(110_000, Str), op(5, Str)],
                true,
                Some(11_000),
            ),
            ("matches", &[op(99, Str), op(40, Str)], false, Some(100)),
            ("matches", &[op(99, Str), op(40, Str)], true, Some(100)),
            ("matches", &[op(0, Str), op(4, Str)], false, Some(1)),
            ("bytes", &[op(100, Str)], false, Some(10)),
            ("string", &[op(100, Bytes)], false, Some(10)),
            ("string", &[op(100, Str)], false, None),
            ("string", &[op(1, Other)], false, None),
            ("format", &[op(50, Str), op(3, List)], true, Some(5)),
            ("quote", &[op(100, Str)], false, Some(10)),
            (
                operators::EQUALS,
                &[op(35, Str), op(1000, Str)],
                false,
                Some(4),
            ),
            (
                operators::NOT_EQUALS,
                &[op(1, Other), op(1, Other)],
                false,
                Some(1),
            ),
            (operators::LESS, &[op(5, Str), op(0, Str)], false, Some(0)),
            (operators::ADD, &[op(40, Str), op(60, Str)], false, Some(10)),
            (
                operators::ADD,
                &[op(4, Bytes), op(4, Bytes)],
                false,
                Some(1),
            ),
            (
                operators::ADD,
                &[op(1000, List), op(1000, List)],
                false,
                None,
            ),
            (operators::ADD, &[op(1, Other), op(1, Other)], false, None),
            (operators::IN, &[op(1, Other), op(7, List)], false, Some(7)),
            (operators::IN, &[op(1, Other), op(7, Other)], false, None),
            ("size", &[op(1000, Str)], true, Some(100)),
            ("size", &[op(1000, Str)], false, Some(100)),
            ("size", &[op(3, Str)], true, Some(1)),
            ("size", &[op(1000, List)], true, None),
            ("size", &[op(1000, Bytes)], true, None),
            // Kubernetes library `CallCost`: 0.1 per receiver char, 0.2 where a result is built.
            ("trim", &[op(1000, Str)], true, Some(100)),
            ("lowerAscii", &[op(1000, Str)], true, Some(100)),
            ("upperAscii", &[op(1001, Str)], true, Some(101)),
            ("substring", &[op(1000, Str), op(1, Other)], true, Some(100)),
            ("url", &[op(1000, Str)], false, Some(100)),
            ("split", &[op(1000, Str), op(1, Str)], true, Some(200)),
            (
                "replace",
                &[op(1000, Str), op(1, Str), op(1, Str)],
                true,
                Some(200),
            ),
            ("find", &[op(99, Str), op(40, Str)], true, Some(100)),
            ("findAll", &[op(99, Str), op(40, Str)], true, Some(100)),
            // 3 strings of 10 chars joined by a 2-char separator: 34 chars, doubled.
            (
                "join",
                &[
                    Operand {
                        text_chars: 30,
                        ..op(3, List)
                    },
                    op(2, Str),
                ],
                true,
                Some(7),
            ),
            (
                "sum",
                &[Operand {
                    traversal: 7,
                    ..op(3, List)
                }],
                true,
                Some(7),
            ),
        ];
        for (func, operands, is_member, expected) in cases {
            assert_eq!(
                call_cost_from_table(func, operands, *is_member),
                *expected,
                "{func} over {} operand(s)",
                operands.len()
            );
        }
    }

    fn live_cost(rule: &str, schema: &J, data: &J, cancelled: Option<&AtomicBool>) -> u64 {
        let program = cel::Program::compile(rule).unwrap();
        let mut ctx = cel::Context::default();
        crate::handlers::cr::register_cel_extensions(&mut ctx);
        ctx.add_variable_from_value(
            "self",
            crate::handlers::cr::json_to_cel_value(schema, data).unwrap(),
        );
        let node = Node::Data {
            value: data,
            schema: Some(schema),
        };
        estimate_for_write(&program, node, None, Some(&ctx), cancelled)
    }

    #[test]
    fn replayed_contains_is_billed_receiver_times_needle_like_upstream() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "a".repeat(1000), "items": [] });
        let short = live_cost("self.csv.contains('abc')", &schema, &data, None);
        let long = live_cost(
            "self.csv.contains('abcdefghijklmnopqrst')",
            &schema,
            &data,
            None,
        );
        // ident + select = 2; the call itself: ceil(1000*0.1) * ceil(len*0.1).
        assert_eq!(short, 2 + 100, "3-char needle");
        assert_eq!(
            long,
            2 + 100 * 2,
            "20-char needle costs 2x: product, not receiver-only"
        );
    }

    /// 20k split items each scanning a 110KB payload is billed ~11000 per step, so the
    /// replay refuses it without doing the scans.
    #[test]
    fn replayed_payload_scan_per_item_exceeds_the_limit() {
        let schema = big_text_schema();
        let csv = "a1234567,".repeat(12_000);
        let data = serde_json::json!({ "csv": csv, "items": vec!["a"; 20_000] });
        let cost = live_cost(
            "self.items.all(a, self.csv.contains(a))",
            &schema,
            &data,
            None,
        );
        assert!(cost > CALL_COST_LIMIT, "{cost}");
    }

    /// `size(string)` counts characters on every call, so one per list item over a payload
    /// string is items x payload bytes of work. Billed as a unit it stayed far under the
    /// limit; it must be refused by its counted cost.
    #[test]
    fn size_of_a_large_string_per_item_exceeds_the_limit() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "a".repeat(110_000), "items": vec!["a"; 20_000] });
        let cost = live_cost(
            "self.items.all(a, self.csv.size() > 0)",
            &schema,
            &data,
            None,
        );
        assert!(cost > CALL_COST_LIMIT, "{cost}");
        let cheap = serde_json::json!({ "csv": "abc", "items": vec!["a"; 20_000] });
        let cost = live_cost(
            "self.items.all(a, self.csv.size() > 0)",
            &schema,
            &cheap,
            None,
        );
        assert!(cost < CALL_COST_LIMIT, "short strings stay cheap: {cost}");
    }

    /// `trim`, `split`, `join` and friends allocate or traverse their receiver, so a loop
    /// calling one on a payload string per item is real work that billing a unit hides.
    #[test]
    fn extension_string_functions_in_a_loop_are_billed_by_the_receiver_size() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "a,".repeat(55_000), "items": vec!["a"; 20_000] });
        for rule in [
            "self.items.all(a, self.csv.trim() != '')",
            "self.items.all(a, self.csv.split(',').size() > 0)",
            "self.items.all(a, self.csv.replace('a', 'b') != '')",
            "self.items.all(a, self.csv.lowerAscii() != '')",
            "self.items.all(a, self.items.join(',') != '')",
        ] {
            let cost = live_cost(rule, &schema, &data, None);
            assert!(cost > CALL_COST_LIMIT, "{rule}: {cost}");
        }
        let small = serde_json::json!({ "csv": "a,b", "items": vec!["a"; 20] });
        let cost = live_cost(
            "self.items.all(a, self.csv.split(',').size() > 0)",
            &schema,
            &small,
            None,
        );
        assert!(cost < CALL_COST_LIMIT, "ordinary rules stay cheap: {cost}");
    }

    /// cel-go `actualSize` looks through an optional, so billing `optional.of(big)` as one
    /// unit would let a payload string hide inside an optional.
    #[test]
    fn optional_operands_are_sized_by_their_content() {
        let big = cel::Value::String(std::sync::Arc::new("a".repeat(1000)));
        let some = cel::Value::Opaque(std::sync::Arc::new(cel::objects::OptionalValue::of(big)));
        assert_eq!(operand_of_value(&some, false).size, 1000);
        let none = cel::Value::Opaque(std::sync::Arc::new(cel::objects::OptionalValue::none()));
        assert_eq!(operand_of_value(&none, false).size, 1);
    }

    /// Cancellation must reach every kind of work in the walk, not only comprehension passes:
    /// a flat expression of many calls (no loop at all) used to be walked to the end, so an
    /// abandoned replay held its gate slot for as long as the walk takes.
    #[test]
    fn cancelled_walk_stops_in_expressions_without_a_comprehension() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "abc", "items": [] });
        let rule = format!("[{}][0]", vec!["self.csv"; 40].join(", "));
        let cost = live_cost(&rule, &schema, &data, Some(&AtomicBool::new(false)));
        assert!(cost < CALL_COST_LIMIT, "uncancelled walk is cheap: {cost}");
        let cost = live_cost(&rule, &schema, &data, Some(&AtomicBool::new(true)));
        assert!(
            cost > CALL_COST_LIMIT,
            "a cancelled walk must stop at the next node, not finish the expression: {cost}"
        );
    }

    /// A deep method chain is re-evaluated by the call that bills its receiver; once the
    /// caller has given up that must not run, or a cancelled replay keeps burning CPU.
    #[test]
    fn cancelled_replay_does_not_reevaluate_a_deep_chain_to_bill_it() {
        let schema = big_text_schema();
        let data = serde_json::json!({ "csv": "a".repeat(100_000), "items": [] });
        let rule = format!("self.csv{}.startsWith('a')", ".trim()".repeat(25));
        let live = AtomicBool::new(false);
        let cost = live_cost(&rule, &schema, &data, Some(&live));
        assert!(cost < CALL_COST_LIMIT, "uncancelled chain is cheap: {cost}");
        let cancelled = AtomicBool::new(true);
        let cost = live_cost(&rule, &schema, &data, Some(&cancelled));
        assert!(
            cost > CALL_COST_LIMIT,
            "a cancelled walk must stop before re-resolving the receiver: {cost}"
        );
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
