//! Tree-walking evaluator over the `cel` crate's parsed AST with cel-go semantics: error
//! absorption in `&&`/`||`/`?:`, optional values, macros the parser leaves as calls, and a
//! cost meter charged per node, per iteration and per byte/element produced.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use cel::common::ast::{
    operators, CallExpr, ComprehensionExpr, EntryExpr, Expr, IdedExpr, LiteralValue, SelectExpr,
};

use super::authzlib::{
    root as authorizer_root, Attributes, AuthorizeFn, Decision, Principal, RequestResource,
};
use super::parse::{parse_cached, qualified_segments};
use super::stdlib;
use super::value::{CelError, MapKey, Value, R};

/// Per-expression cost budget, as upstream's `PerCallLimit`.
pub(crate) const COST_LIMIT: u64 = 1_000_000;

/// Deepest evaluator recursion; the parser's own cap keeps real expressions far below it.
const MAX_DEPTH: u32 = 512;

/// Most stack an evaluation may use below its `Evaluator`. Evaluation runs on request and
/// blocking threads of 512 KiB, and a 250-level expression that compilation accepts
/// overflows 160 KiB in a release build and 512 KiB in a debug one; the frames already
/// on the stack take part of the rest. Counting levels cannot bound this, as frame sizes
/// differ per node kind and build profile, and a stack overflow aborts the whole process.
const MAX_STACK_BYTES: usize = 192 * 1024;

fn stack_position() -> usize {
    let marker = 0u8;
    std::hint::black_box(&marker) as *const u8 as usize
}

/// Roots and lazily evaluated policy variables an expression is evaluated against.
pub(crate) struct Env<'a> {
    pub(crate) roots: Vec<(&'static str, Value<'a>)>,
    /// `spec.variables` in declaration order: `(name, expression)`. Each is evaluated on
    /// first use and may only see the variables declared before it.
    pub(crate) variables: Vec<(String, String)>,
    memo: RefCell<Vec<Option<R<Value<'a>>>>>,
    /// Backs the `authorizer` root; absent when the environment does not declare one.
    authorize: Option<AuthorizeFn<'a>>,
}

impl<'a> Env<'a> {
    pub(crate) fn new(roots: Vec<(&'static str, Value<'a>)>) -> Self {
        Env {
            roots,
            variables: Vec::new(),
            memo: RefCell::new(Vec::new()),
            authorize: None,
        }
    }

    pub(crate) fn with_authorizer(mut self, request: RequestResource, f: AuthorizeFn<'a>) -> Self {
        self.roots.push(("authorizer", authorizer_root(request)));
        self.authorize = Some(f);
        self
    }

    pub(crate) fn with_variables(mut self, variables: Vec<(String, String)>) -> Self {
        self.memo = RefCell::new(vec![None; variables.len()]);
        self.variables = variables;
        self
    }

    pub(crate) fn root_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = self.roots.iter().map(|(n, _)| *n).collect();
        if !self.variables.is_empty() {
            names.push("variables");
        }
        names
    }
}

pub(crate) struct Evaluator<'a, 'p> {
    env: &'p Env<'a>,
    cost: Cell<u64>,
    depth: Cell<u32>,
    stack_base: usize,
    locals: RefCell<Vec<(String, R<Value<'a>>)>>,
    var_limit: Cell<usize>,
}

struct DepthGuard<'x>(&'x Cell<u32>);

impl Drop for DepthGuard<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

const TYPE_IDENTS: &[&str] = &[
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
    "timestamp",
    "duration",
];

/// Qualified type names that are values (`net.IP`).
const QUALIFIED_TYPES: &[&str] = &[
    "net.IP",
    "net.CIDR",
    "kubernetes.Quantity",
    "kubernetes.URL",
    "kubernetes.Semver",
    "kubernetes.format.Format",
    "optional_type",
];

impl<'a, 'p> Evaluator<'a, 'p> {
    pub(crate) fn new(env: &'p Env<'a>) -> Self {
        Evaluator {
            env,
            cost: Cell::new(COST_LIMIT),
            depth: Cell::new(0),
            stack_base: stack_position(),
            locals: RefCell::new(Vec::new()),
            var_limit: Cell::new(env.variables.len()),
        }
    }

    pub(crate) fn authorize(&self, principal: &Principal, attrs: &Attributes) -> Decision {
        match &self.env.authorize {
            Some(f) => f(principal, attrs),
            None => Decision {
                allowed: false,
                reason: String::new(),
                error: Some("no authorizer is available".into()),
            },
        }
    }

    /// Parses (through the shared cache), checks references against the env's roots, and
    /// evaluates `expr`.
    pub(crate) fn eval_str(&self, expr: &str) -> R<Value<'a>> {
        let parsed = parse_cached(expr, &self.env.root_names()).map_err(CelError::new)?;
        self.eval(&parsed.ast)
    }

    pub(crate) fn charge(&self, units: u64) -> R<()> {
        let left = self.cost.get();
        if units > left {
            self.cost.set(0);
            Err(CelError::cost())
        } else {
            self.cost.set(left - units);
            Ok(())
        }
    }

    /// Cost of producing `n` bytes: one unit per 32.
    pub(crate) fn charge_size(&self, n: usize) -> R<()> {
        self.charge(1 + (n as u64) / 32)
    }

    /// Cost of walking or copying `v`: one unit per 16 nodes, measured within the budget
    /// that remains so an oversized value is refused without being walked to the end.
    pub(crate) fn charge_nodes(&self, v: &Value<'_>) -> R<()> {
        const NODES_PER_UNIT: u64 = 16;
        let cap = self.cost.get().saturating_mul(NODES_PER_UNIT);
        self.charge(1 + v.weight(cap) / NODES_PER_UNIT)
    }

    /// Cost of producing `n` list or map elements: one unit each, since an element is far
    /// larger than a byte and the budget bounds memory as much as time.
    pub(crate) fn charge_elems(&self, n: usize) -> R<()> {
        self.charge(1 + n as u64)
    }

    fn enter(&self) -> R<DepthGuard<'_>> {
        let d = self.depth.get();
        if d >= MAX_DEPTH || stack_position().abs_diff(self.stack_base) > MAX_STACK_BYTES {
            return Err(CelError::new("expression nests too deeply"));
        }
        self.depth.set(d + 1);
        self.charge(1)?;
        Ok(DepthGuard(&self.depth))
    }

    pub(crate) fn eval(&self, e: &IdedExpr) -> R<Value<'a>> {
        let _g = self.enter()?;
        match &e.expr {
            Expr::Literal(l) => Ok(match l {
                LiteralValue::Boolean(b) => Value::Bool(*b.inner()),
                LiteralValue::Int(i) => Value::Int(*i.inner()),
                LiteralValue::UInt(u) => Value::UInt(*u.inner()),
                LiteralValue::Double(d) => Value::Double(*d.inner()),
                LiteralValue::String(s) => Value::str(s.inner()),
                LiteralValue::Bytes(b) => Value::Bytes(Arc::from(b.inner())),
                LiteralValue::Null => Value::Null,
            }),
            Expr::Ident(name) => self.resolve_ident(name),
            Expr::Select(sel) => self.eval_select(e, sel),
            Expr::Call(c) => self.eval_call(c),
            Expr::List(l) => {
                let mut out = Vec::with_capacity(l.elements.len());
                for (i, el) in l.elements.iter().enumerate() {
                    let v = self.eval(el)?;
                    if l.optional_indices.contains(&i) {
                        match v {
                            Value::Optional(Some(inner)) => out.push((*inner).clone()),
                            Value::Optional(None) => {}
                            other => out.push(other),
                        }
                    } else {
                        out.push(v);
                    }
                }
                self.charge_elems(out.len())?;
                Ok(Value::list(out))
            }
            Expr::Map(m) => {
                let mut out = BTreeMap::new();
                for entry in &m.entries {
                    let EntryExpr::MapEntry(me) = &entry.expr else {
                        return Err(CelError::new("invalid map entry"));
                    };
                    let k = self.eval(&me.key)?;
                    let key = MapKey::from_value(&k).ok_or_else(|| {
                        CelError::new(format!("unsupported key type: {}", k.type_name()))
                    })?;
                    let v = self.eval(&me.value)?;
                    let v = if me.optional {
                        match v {
                            Value::Optional(Some(inner)) => (*inner).clone(),
                            Value::Optional(None) => continue,
                            other => other,
                        }
                    } else {
                        v
                    };
                    if out.insert(key.clone(), v).is_some() {
                        return Err(CelError::new(format!(
                            "Failed with repeated key: {}",
                            key.display()
                        )));
                    }
                }
                self.charge_elems(out.len())?;
                Ok(Value::map(out))
            }
            Expr::Struct(s) => {
                let mut out = BTreeMap::new();
                for entry in &s.entries {
                    let EntryExpr::StructField(f) = &entry.expr else {
                        return Err(CelError::new("invalid struct field"));
                    };
                    let v = self.eval(&f.value)?;
                    let v = if f.optional {
                        match v {
                            Value::Optional(Some(inner)) => (*inner).clone(),
                            Value::Optional(None) => continue,
                            other => other,
                        }
                    } else {
                        v
                    };
                    out.insert(MapKey::Str(Arc::from(f.field.as_str())), v);
                }
                self.charge_elems(out.len())?;
                Ok(Value::map(out))
            }
            Expr::Comprehension(c) => self.eval_comprehension(c),
            Expr::Unspecified => Err(CelError::new("invalid expression")),
        }
    }

    fn resolve_ident(&self, name: &str) -> R<Value<'a>> {
        let name = name.strip_prefix('.').unwrap_or(name);
        if let Some((_, v)) = self.locals.borrow().iter().rev().find(|(n, _)| n == name) {
            return v.clone();
        }
        if let Some((_, v)) = self.env.roots.iter().find(|(n, _)| *n == name) {
            return Ok(v.clone());
        }
        if name == "variables" && !self.env.variables.is_empty() {
            return Ok(Value::Variables(self.var_limit.get()));
        }
        if TYPE_IDENTS.contains(&name) {
            return Ok(Value::Type(Arc::from(match name {
                "timestamp" => "google.protobuf.Timestamp",
                "duration" => "google.protobuf.Duration",
                n => n,
            })));
        }
        Err(CelError::new(format!(
            "undeclared reference to '{name}' (in container '')"
        )))
    }

    fn is_bound(&self, name: &str) -> bool {
        self.locals.borrow().iter().any(|(n, _)| n == name)
            || self.env.roots.iter().any(|(n, _)| *n == name)
            || (name == "variables" && !self.env.variables.is_empty())
    }

    fn variable(&self, idx: usize) -> R<Value<'a>> {
        if let Some(v) = &self.env.memo.borrow()[idx] {
            return v.clone();
        }
        let expr = self.env.variables[idx].1.clone();
        let saved_limit = self.var_limit.replace(idx);
        let saved_locals = std::mem::take(&mut *self.locals.borrow_mut());
        let result = self.eval_str(&expr);
        *self.locals.borrow_mut() = saved_locals;
        self.var_limit.set(saved_limit);
        if matches!(&result, Err(e) if e.fatal) {
            return result;
        }
        self.env.memo.borrow_mut()[idx] = Some(result.clone());
        result
    }

    fn eval_select(&self, e: &IdedExpr, sel: &SelectExpr) -> R<Value<'a>> {
        if sel.test {
            return self.eval_has(sel);
        }
        if let Some(segs) = qualified_segments(&e.expr) {
            if segs.len() > 1 && !self.is_bound(segs[0]) {
                let q = segs.join(".");
                if QUALIFIED_TYPES.contains(&q.as_str()) {
                    return Ok(Value::Type(Arc::from(q)));
                }
            }
        }
        let operand = self.eval(&sel.operand)?;
        self.select(operand, &sel.field)
    }

    fn select(&self, operand: Value<'a>, field: &str) -> R<Value<'a>> {
        match &operand {
            Value::Variables(limit) => {
                let idx = self.env.variables[..*limit]
                    .iter()
                    .position(|(n, _)| n == field)
                    .ok_or_else(|| CelError::new(format!("no such key: {field}")))?;
                self.variable(idx)
            }
            Value::Optional(None) => Ok(operand),
            Value::Optional(Some(inner)) => {
                let inner = (**inner).clone();
                Ok(self.select_optional(inner, field))
            }
            Value::Authz(a) => a
                .select(field)
                .ok_or_else(|| CelError::new(format!("no such key: {field}"))),
            v if v.is_map() => v
                .map_get(&MapKey::Str(Arc::from(field)))
                .ok_or_else(|| CelError::new(format!("no such key: {field}"))),
            _ => Err(CelError::new(format!("no such key: {field}"))),
        }
    }

    fn select_optional(&self, operand: Value<'a>, field: &str) -> Value<'a> {
        let found = match &operand {
            Value::Variables(limit) => self.env.variables[..*limit]
                .iter()
                .position(|(n, _)| n == field)
                .and_then(|idx| self.variable(idx).ok()),
            v => v.map_get(&MapKey::Str(Arc::from(field))),
        };
        Value::Optional(found.map(Arc::new))
    }

    fn eval_has(&self, sel: &SelectExpr) -> R<Value<'a>> {
        let operand = self.eval(&sel.operand)?;
        Ok(Value::Bool(match &operand {
            Value::Variables(limit) => self.env.variables[..*limit]
                .iter()
                .any(|(n, _)| *n == sel.field),
            // An explicit null is unset, as for unstructured objects.
            v if v.is_map() => v
                .map_get(&MapKey::Str(Arc::from(sel.field.as_str())))
                .is_some_and(|f| !matches!(f, Value::Null)),
            // Upstream type-checks `has()` operands as maps or messages at compile time, so
            // a presence test on anything else must not read as "absent".
            _ => return Err(CelError::overload()),
        }))
    }

    fn index(&self, operand: Value<'a>, idx: Value<'a>) -> R<Value<'a>> {
        match &operand {
            Value::Variables(_) => {
                let Value::Str(name) = &idx else {
                    return Err(CelError::overload());
                };
                self.select(operand.clone(), name)
            }
            Value::Optional(None) => Ok(operand),
            Value::Optional(Some(inner)) => {
                let inner = (**inner).clone();
                Ok(self.index_optional(inner, idx)?)
            }
            v if v.is_list() => {
                let i = index_arg(&idx)?;
                usize::try_from(i)
                    .ok()
                    .and_then(|i| v.list_get(i))
                    .ok_or_else(|| CelError::new(format!("index out of bounds: {i}")))
            }
            v if v.is_map() => {
                let key = MapKey::from_value(&idx).ok_or_else(CelError::overload)?;
                v.map_get(&key)
                    .ok_or_else(|| CelError::new(format!("no such key: {}", key.display())))
            }
            _ => Err(CelError::overload()),
        }
    }

    fn index_optional(&self, operand: Value<'a>, idx: Value<'a>) -> R<Value<'a>> {
        match &operand {
            Value::Optional(None) => Ok(operand),
            Value::Optional(Some(inner)) => {
                let inner = (**inner).clone();
                self.index_optional(inner, idx)
            }
            Value::Variables(limit) => {
                let Value::Str(name) = &idx else {
                    return Err(CelError::overload());
                };
                Ok(self.select_optional(Value::Variables(*limit), name))
            }
            v if v.is_list() => {
                let i = index_arg(&idx)?;
                Ok(Value::Optional(
                    usize::try_from(i)
                        .ok()
                        .and_then(|i| v.list_get(i))
                        .map(Arc::new),
                ))
            }
            v if v.is_map() => {
                let key = MapKey::from_value(&idx).ok_or_else(CelError::overload)?;
                Ok(Value::Optional(v.map_get(&key).map(Arc::new)))
            }
            _ => Ok(Value::Optional(None)),
        }
    }

    fn eval_call(&self, c: &CallExpr) -> R<Value<'a>> {
        let name = c.func_name.as_str();
        match c.target.as_deref() {
            None => self.eval_global(name, &c.args),
            Some(target) => self.eval_member(name, target, &c.args),
        }
    }

    fn eval_global(&self, name: &str, args: &[IdedExpr]) -> R<Value<'a>> {
        match (name, args) {
            (operators::LOGICAL_AND, [a, b]) => self.eval_logic(a, b, false),
            (operators::LOGICAL_OR, [a, b]) => self.eval_logic(a, b, true),
            (operators::CONDITIONAL, [c, t, f]) => match self.eval(c)? {
                Value::Bool(true) => self.eval(t),
                Value::Bool(false) => self.eval(f),
                _ => Err(CelError::overload()),
            },
            (operators::NOT_STRICTLY_FALSE, [a]) => match self.eval(a) {
                Ok(Value::Bool(false)) => Ok(Value::Bool(false)),
                Err(e) if e.fatal => Err(e),
                _ => Ok(Value::Bool(true)),
            },
            (operators::OPT_SELECT, [a, f]) => {
                let operand = self.eval(a)?;
                let Expr::Literal(LiteralValue::String(field)) = &f.expr else {
                    return Err(CelError::new("invalid optional select"));
                };
                Ok(match operand {
                    Value::Optional(None) => operand,
                    Value::Optional(Some(inner)) => {
                        let inner = (*inner).clone();
                        self.select_optional(inner, field.inner())
                    }
                    v => self.select_optional(v, field.inner()),
                })
            }
            (operators::OPT_INDEX, [a, i]) => {
                let operand = self.eval(a)?;
                let idx = self.eval(i)?;
                self.index_optional(operand, idx)
            }
            (operators::INDEX, [a, i]) => {
                let operand = self.eval(a)?;
                let idx = self.eval(i)?;
                self.index(operand, idx)
            }
            _ => {
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval(a)?);
                }
                stdlib::call(self, name, None, vals)
            }
        }
    }

    fn eval_logic(&self, a: &IdedExpr, b: &IdedExpr, is_or: bool) -> R<Value<'a>> {
        let mut err: Option<CelError> = None;
        for term in [a, b] {
            match self.eval(term) {
                Ok(Value::Bool(v)) if v == is_or => return Ok(Value::Bool(is_or)),
                Ok(Value::Bool(_)) => {}
                Ok(_) => {
                    err.get_or_insert_with(CelError::overload);
                }
                Err(e) if e.fatal => return Err(e),
                Err(e) => {
                    err.get_or_insert(e);
                }
            }
        }
        match err {
            Some(e) => Err(e),
            None => Ok(Value::Bool(!is_or)),
        }
    }

    fn eval_member(&self, name: &str, target: &IdedExpr, args: &[IdedExpr]) -> R<Value<'a>> {
        if let Expr::Ident(ns) = &target.expr {
            if !self.is_bound(ns) {
                return self.eval_namespaced(ns, name, args);
            }
        }
        if let Expr::Select(_) = &target.expr {
            if let Some(segs) = qualified_segments(&target.expr) {
                if !self.is_bound(segs[0]) {
                    return self.eval_namespaced(&segs.join("."), name, args);
                }
            }
        }
        let id = |e: &'_ IdedExpr| match &e.expr {
            Expr::Ident(n) => Some(n.clone()),
            _ => None,
        };
        match (name, args) {
            ("all" | "exists" | "exists_one" | "existsOne", [i, v, body])
                if id(i).is_some() && id(v).is_some() =>
            {
                let range = self.eval(target)?;
                self.two_var_quantifier(
                    name,
                    &range,
                    &id(i).unwrap_or_default(),
                    &id(v).unwrap_or_default(),
                    body,
                )
            }
            ("transformList", [i, v, rest @ ..])
                if id(i).is_some() && id(v).is_some() && (1..=2).contains(&rest.len()) =>
            {
                let range = self.eval(target)?;
                self.transform_list(
                    &range,
                    &id(i).unwrap_or_default(),
                    &id(v).unwrap_or_default(),
                    rest,
                )
            }
            ("transformMap" | "transformMapEntry", [k, v, rest @ ..])
                if id(k).is_some() && id(v).is_some() && (1..=2).contains(&rest.len()) =>
            {
                let range = self.eval(target)?;
                self.transform_map(
                    name == "transformMapEntry",
                    &range,
                    &id(k).unwrap_or_default(),
                    &id(v).unwrap_or_default(),
                    rest,
                )
            }
            ("sortBy", [var, key]) if id(var).is_some() => {
                let range = self.eval(target)?;
                self.sort_by(&range, &id(var).unwrap_or_default(), key)
            }
            ("optMap" | "optFlatMap", [var, body]) if id(var).is_some() => {
                let opt = self.eval(target)?;
                let Value::Optional(o) = opt else {
                    return Err(CelError::overload());
                };
                let Some(inner) = o else {
                    return Ok(Value::Optional(None));
                };
                let var = id(var).unwrap_or_default();
                let out = self.with_local(&var, Ok((*inner).clone()), || self.eval(body))?;
                if name == "optFlatMap" {
                    Ok(out)
                } else {
                    Ok(Value::Optional(Some(Arc::new(out))))
                }
            }
            ("or", [other]) => match self.eval(target)? {
                Value::Optional(None) => self.eval(other),
                v @ Value::Optional(Some(_)) => Ok(v),
                _ => Err(CelError::overload()),
            },
            ("orValue", [other]) => match self.eval(target)? {
                Value::Optional(None) => self.eval(other),
                Value::Optional(Some(v)) => Ok((*v).clone()),
                _ => Err(CelError::overload()),
            },
            _ => {
                let recv = self.eval(target)?;
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval(a)?);
                }
                stdlib::call(self, name, Some(recv), vals)
            }
        }
    }

    fn eval_namespaced(&self, ns: &str, name: &str, args: &[IdedExpr]) -> R<Value<'a>> {
        if ns == "cel" && name == "bind" {
            if let [IdedExpr {
                expr: Expr::Ident(var),
                ..
            }, init, body] = args
            {
                let v = match self.eval(init) {
                    Err(e) if e.fatal => return Err(e),
                    other => other,
                };
                return self.with_local(var, v, || self.eval(body));
            }
        }
        let mut vals = Vec::with_capacity(args.len());
        for a in args {
            vals.push(self.eval(a)?);
        }
        stdlib::call(self, &format!("{ns}.{name}"), None, vals)
    }

    pub(crate) fn with_local<T>(
        &self,
        name: &str,
        value: R<Value<'a>>,
        f: impl FnOnce() -> R<T>,
    ) -> R<T> {
        self.locals.borrow_mut().push((name.to_string(), value));
        let r = f();
        self.locals.borrow_mut().pop();
        r
    }

    fn set_local(&self, slot: usize, value: R<Value<'a>>) {
        self.locals.borrow_mut()[slot].1 = value;
    }

    fn eval_comprehension(&self, c: &ComprehensionExpr) -> R<Value<'a>> {
        let range = self.eval(&c.iter_range)?;
        let init = self.eval(&c.accu_init)?;
        let Some(items) = range.range_iter() else {
            return Err(CelError::new(format!(
                "expression of type '{}' cannot be range of a comprehension (must be list, map, or dynamic)",
                range.type_name()
            )));
        };
        let base = self.locals.borrow().len();
        {
            let mut l = self.locals.borrow_mut();
            l.push((c.accu_var.clone(), Ok(init)));
            l.push((c.iter_var.clone(), Ok(Value::Null)));
        }
        let result = (|| {
            if let Some(append) = AppendStep::of(c) {
                let mut out = Vec::new();
                for item in items {
                    self.charge(1)?;
                    self.set_local(base + 1, Ok(item));
                    if let Some(cond) = append.cond {
                        match self.eval(cond)? {
                            Value::Bool(true) => {}
                            Value::Bool(false) => continue,
                            _ => return Err(CelError::overload()),
                        }
                    }
                    out.push(self.eval(append.elem)?);
                }
                self.charge_elems(out.len())?;
                self.set_local(base, Ok(Value::list(out)));
            } else {
                for item in items {
                    self.charge(1)?;
                    self.set_local(base + 1, Ok(item));
                    match self.eval(&c.loop_cond)? {
                        Value::Bool(false) => break,
                        Value::Bool(true) => {}
                        _ => return Err(CelError::overload()),
                    }
                    let step = self.eval(&c.loop_step);
                    if matches!(&step, Err(e) if e.fatal) {
                        return step;
                    }
                    self.set_local(base, step);
                }
            }
            self.eval(&c.result)
        })();
        self.locals.borrow_mut().truncate(base);
        result
    }

    /// `(key-or-index, value)` pairs of a list or map.
    fn pairs(&self, range: &Value<'a>) -> R<Vec<(Value<'a>, Value<'a>)>> {
        if let Some(it) = range.list_iter() {
            return Ok(it
                .enumerate()
                .map(|(i, v)| (Value::Int(i as i64), v))
                .collect());
        }
        if let Some(it) = range.map_iter() {
            return Ok(it.map(|(k, v)| (k.to_value(), v)).collect());
        }
        Err(CelError::new(format!(
            "expression of type '{}' cannot be range of a comprehension (must be list, map, or dynamic)",
            range.type_name()
        )))
    }

    fn with_two<T>(&self, a: &str, b: &str, f: impl FnOnce(usize) -> R<T>) -> R<T> {
        let base = self.locals.borrow().len();
        {
            let mut l = self.locals.borrow_mut();
            l.push((a.to_string(), Ok(Value::Null)));
            l.push((b.to_string(), Ok(Value::Null)));
        }
        let r = f(base);
        self.locals.borrow_mut().truncate(base);
        r
    }

    fn two_var_quantifier(
        &self,
        kind: &str,
        range: &Value<'a>,
        a: &str,
        b: &str,
        body: &IdedExpr,
    ) -> R<Value<'a>> {
        let pairs = self.pairs(range)?;
        self.with_two(a, b, |base| {
            let (mut matches, mut err) = (0usize, None::<CelError>);
            for (k, v) in pairs {
                self.charge(1)?;
                self.set_local(base, Ok(k));
                self.set_local(base + 1, Ok(v));
                match self.eval(body) {
                    Ok(Value::Bool(b)) => {
                        let hit = if kind == "all" { !b } else { b };
                        if hit {
                            match kind {
                                "all" => return Ok(Value::Bool(false)),
                                "exists" => return Ok(Value::Bool(true)),
                                _ => matches += 1,
                            }
                        }
                    }
                    Ok(_) => {
                        err.get_or_insert_with(CelError::overload);
                    }
                    Err(e) if e.fatal => return Err(e),
                    Err(e) => {
                        err.get_or_insert(e);
                    }
                }
            }
            match kind {
                "all" => err.map_or(Ok(Value::Bool(true)), Err),
                "exists" => err.map_or(Ok(Value::Bool(false)), Err),
                _ => err.map_or(Ok(Value::Bool(matches == 1)), Err),
            }
        })
    }

    fn transform_list(
        &self,
        range: &Value<'a>,
        a: &str,
        b: &str,
        rest: &[IdedExpr],
    ) -> R<Value<'a>> {
        let pairs = self.pairs(range)?;
        self.with_two(a, b, |base| {
            let mut out = Vec::new();
            for (k, v) in pairs {
                self.charge(1)?;
                self.set_local(base, Ok(k));
                self.set_local(base + 1, Ok(v));
                if let [filter, _] = rest {
                    match self.eval(filter)? {
                        Value::Bool(true) => {}
                        Value::Bool(false) => continue,
                        _ => return Err(CelError::overload()),
                    }
                }
                out.push(self.eval(&rest[rest.len() - 1])?);
            }
            self.charge_elems(out.len())?;
            Ok(Value::list(out))
        })
    }

    fn transform_map(
        &self,
        entry_form: bool,
        range: &Value<'a>,
        a: &str,
        b: &str,
        rest: &[IdedExpr],
    ) -> R<Value<'a>> {
        let pairs = self.pairs(range)?;
        self.with_two(a, b, |base| {
            let mut out: BTreeMap<MapKey, Value<'a>> = BTreeMap::new();
            for (k, v) in pairs {
                self.charge(1)?;
                self.set_local(base, Ok(k.clone()));
                self.set_local(base + 1, Ok(v));
                if let [filter, _] = rest {
                    match self.eval(filter)? {
                        Value::Bool(true) => {}
                        Value::Bool(false) => continue,
                        _ => return Err(CelError::overload()),
                    }
                }
                let produced = self.eval(&rest[rest.len() - 1])?;
                if entry_form {
                    let Some(entries) = produced.map_iter() else {
                        return Err(CelError::overload());
                    };
                    for (ek, ev) in entries {
                        if out.insert(ek.clone(), ev).is_some() {
                            return Err(CelError::new(format!(
                                "insert failed: key {} already exists",
                                ek.display()
                            )));
                        }
                    }
                } else {
                    let key = MapKey::from_value(&k).ok_or_else(CelError::overload)?;
                    out.insert(key, produced);
                }
            }
            self.charge_elems(out.len())?;
            Ok(Value::map(out))
        })
    }

    fn sort_by(&self, range: &Value<'a>, var: &str, key: &IdedExpr) -> R<Value<'a>> {
        let Some(items) = range.list_iter() else {
            return Err(CelError::overload());
        };
        let items: Vec<Value<'a>> = items.collect();
        let mut keyed = Vec::with_capacity(items.len());
        for item in items {
            self.charge(1)?;
            let k = self.with_local(var, Ok(item.clone()), || self.eval(key))?;
            keyed.push((k, item));
        }
        stdlib::sort_by_keys(self, keyed)
    }
}

/// `x[i]` index argument: an integral number.
fn index_arg(idx: &Value<'_>) -> R<i64> {
    match idx {
        Value::Int(i) => Ok(*i),
        Value::UInt(u) => {
            i64::try_from(*u).map_err(|_| CelError::new(format!("index out of bounds: {u}")))
        }
        Value::Double(d) if d.fract() == 0.0 && d.is_finite() => Ok(*d as i64),
        _ => Err(CelError::new(format!(
            "unsupported index type '{}' in list",
            idx.type_name()
        ))),
    }
}

/// The `map`/`filter` loop shapes: `@result + [elem]`, optionally behind a condition.
struct AppendStep<'e> {
    cond: Option<&'e IdedExpr>,
    elem: &'e IdedExpr,
}

impl<'e> AppendStep<'e> {
    fn of(c: &'e ComprehensionExpr) -> Option<Self> {
        let Expr::List(init) = &c.accu_init.expr else {
            return None;
        };
        if !init.elements.is_empty() || !matches!(&c.loop_cond.expr, Expr::Literal(_)) {
            return None;
        }
        let is_accu = |e: &IdedExpr| matches!(&e.expr, Expr::Ident(n) if *n == c.accu_var);
        let append = |e: &'e IdedExpr| -> Option<&'e IdedExpr> {
            let Expr::Call(call) = &e.expr else {
                return None;
            };
            let [lhs, rhs] = call.args.as_slice() else {
                return None;
            };
            let Expr::List(l) = &rhs.expr else {
                return None;
            };
            (call.func_name == operators::ADD
                && call.target.is_none()
                && is_accu(lhs)
                && l.elements.len() == 1
                && l.optional_indices.is_empty())
            .then(|| &l.elements[0])
        };
        if let Some(elem) = append(&c.loop_step) {
            return Some(AppendStep { cond: None, elem });
        }
        let Expr::Call(call) = &c.loop_step.expr else {
            return None;
        };
        let [cond, then, otherwise] = call.args.as_slice() else {
            return None;
        };
        (call.func_name == operators::CONDITIONAL && call.target.is_none() && is_accu(otherwise))
            .then(|| append(then))
            .flatten()
            .map(|elem| AppendStep {
                cond: Some(cond),
                elem,
            })
    }
}
