//! Parsing and the compile-step checks: the vendored `cel` crate (a cel-go port) supplies
//! the grammar, and this adds what cel-go's checker rejects that the parser does not.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use cel::common::ast::{EntryExpr, Expr, IdedExpr};

use super::stdlib;

/// Expressions parsed (and so cached) at most this long, in bytes.
const CACHE_MAX_EXPR_LEN: usize = 4096;
const CACHE_MAX_ENTRIES: usize = 1024;
const CACHE_MAX_TOTAL_BYTES: usize = 256 * 1024;

/// The check verdict for one set of declared roots.
type Verdict = (Vec<&'static str>, Result<(), String>);

pub(crate) struct Parsed {
    pub(crate) ast: IdedExpr,
    verdicts: Mutex<Vec<Verdict>>,
}

#[cfg(test)]
thread_local! {
    pub(crate) static PARSE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn parse_with_stack(expr: &str, stack_size: usize) -> Result<IdedExpr, String> {
    #[cfg(test)]
    PARSE_COUNT.with(|c| c.set(c.get() + 1));
    let parse = || {
        cel::parser::Parser::new()
            .enable_optional_syntax(true)
            .enable_ident_escape_syntax(true)
            .parse(expr)
    };
    // The generated parser recurses up to its 96-level cap on a request thread's small
    // stack; an expression too short to nest deeply than ~50 levels parses in place.
    if expr.len() <= 100 {
        parse()
    } else {
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(stack_size)
                .spawn_scoped(s, parse)
                .map_err(|e| format!("compilation failed: {e}"))?
                .join()
                .map_err(|_| "compilation failed: parser panicked".to_string())
        })?
    }
    .map_err(|e| format!("compilation failed: {e}"))
}

pub(crate) fn parse(expr: &str) -> Result<IdedExpr, String> {
    parse_with_stack(expr, 32 << 20)
}

/// The reference and function checks cel-go's checker performs, against `roots`.
fn check(ast: &IdedExpr, roots: &[&str]) -> Result<(), String> {
    match first_undeclared_ref(ast, &mut Vec::new(), roots) {
        Some(name) => Err(format!(
            "compilation failed: undeclared reference to '{name}' (in container '')"
        )),
        None => Ok(()),
    }
}

/// Compile-step analogue: parse errors must stay distinct from eval errors, since the
/// evaluator absorbs eval errors in `a || true`, which a syntax error must never be.
pub(crate) fn check_syntax(expr: &str, roots: &[&str]) -> Result<(), String> {
    check(&parse(expr)?, roots)
}

#[cfg(test)]
pub(crate) fn check_syntax_with_stack(
    expr: &str,
    roots: &[&str],
    stack_size: usize,
) -> Result<(), String> {
    check(&parse_with_stack(expr, stack_size)?, roots)
}

type Cache = HashMap<Box<str>, Arc<Parsed>>;

/// Memoised parse + check for the evaluation hot path: each distinct expression is parsed
/// (and, when long, on a big-stack thread) once per cache lifetime. A failure, including a
/// failed thread spawn, is returned as `Err` so the caller denies under Fail.
pub(crate) fn parse_cached(expr: &str, roots: &[&'static str]) -> Result<Arc<Parsed>, String> {
    static CACHE: Mutex<Option<(Cache, usize)>> = Mutex::new(None);
    let hit = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|(m, _)| m.get(expr).cloned());
    let parsed = match hit {
        Some(p) => p,
        None => {
            let p = Arc::new(Parsed {
                ast: parse(expr)?,
                verdicts: Mutex::new(Vec::new()),
            });
            if expr.len() <= CACHE_MAX_EXPR_LEN {
                let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
                let (m, total) = guard.get_or_insert_with(|| (HashMap::new(), 0));
                if m.len() >= CACHE_MAX_ENTRIES || *total + expr.len() > CACHE_MAX_TOTAL_BYTES {
                    m.clear();
                    *total = 0;
                }
                *total += expr.len();
                m.insert(expr.into(), p.clone());
            }
            p
        }
    };
    let mut verdicts = parsed.verdicts.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, v)) = verdicts.iter().find(|(r, _)| r == roots) {
        return v.clone().map(|()| parsed.clone());
    }
    let verdict = check(&parsed.ast, roots);
    verdicts.push((roots.to_vec(), verdict.clone()));
    drop(verdicts);
    verdict.map(|()| parsed)
}

/// First identifier in `e` that is neither a declared root, a macro/`cel.bind` variable in
/// scope, a type name, nor a macro accumulator (`@result`); or an unknown function. The
/// target of a call is skipped when it is a bare undeclared identifier: that is a function
/// namespace (`sets.contains`).
fn first_undeclared_ref(e: &IdedExpr, scope: &mut Vec<String>, roots: &[&str]) -> Option<String> {
    match &e.expr {
        Expr::Ident(name) => {
            let declared = name.starts_with('@')
                || scope.contains(name)
                || roots.contains(&name.as_str())
                || ["net", "kubernetes"].contains(&name.as_str())
                || crate::handlers::cel_rules::CEL_TYPE_IDENTS.contains(&name.as_str());
            (!declared).then(|| name.clone())
        }
        Expr::Select(sel) => first_undeclared_ref(&sel.operand, scope, roots),
        Expr::Call(call) => {
            let is_cel_ns = matches!(call.target.as_deref(),
                Some(t) if matches!(&t.expr, Expr::Ident(n) if n == "cel"));
            if let (true, "bind", [var, init, body]) =
                (is_cel_ns, call.func_name.as_str(), call.args.as_slice())
            {
                if let Expr::Ident(var) = &var.expr {
                    if let Some(bad) = first_undeclared_ref(init, scope, roots) {
                        return Some(bad);
                    }
                    scope.push(var.clone());
                    let r = first_undeclared_ref(body, scope, roots);
                    scope.pop();
                    return r;
                }
            }
            // Macros the parser leaves as calls bind their first identifier arguments:
            // `all(i, v, body)`, `transformList(i, v, f?, e)`, `sortBy(x, key)`, `optMap(x, e)`.
            if let Some(target) = &call.target {
                let bound = match (call.func_name.as_str(), call.args.as_slice()) {
                    (
                        "all" | "exists" | "exists_one" | "existsOne" | "transformList"
                        | "transformMap" | "transformMapEntry",
                        [i, v, ..],
                    ) => match (&i.expr, &v.expr) {
                        (Expr::Ident(i), Expr::Ident(v)) => Some((vec![i.clone(), v.clone()], 2)),
                        _ => None,
                    },
                    ("sortBy" | "optMap" | "optFlatMap", [x, ..]) => match &x.expr {
                        Expr::Ident(x) => Some((vec![x.clone()], 1)),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some((vars, skip)) = bound {
                    if let Some(bad) = first_undeclared_ref(target, scope, roots) {
                        return Some(bad);
                    }
                    let depth = scope.len();
                    scope.extend(vars);
                    let r = call
                        .args
                        .iter()
                        .skip(skip)
                        .find_map(|a| first_undeclared_ref(a, scope, roots));
                    scope.truncate(depth);
                    return r;
                }
            }
            let mut namespace = None;
            if let Some(target) = &call.target {
                let ns = qualified_segments(&target.expr).filter(|segs| {
                    !scope.iter().any(|s| s == segs[0]) && !roots.contains(&segs[0])
                });
                match ns {
                    Some(segs) => namespace = Some(segs.join(".")),
                    None => {
                        if let Some(bad) = first_undeclared_ref(target, scope, roots) {
                            return Some(bad);
                        }
                    }
                }
            }
            if !stdlib::is_known_function(
                namespace.as_deref(),
                call.func_name.as_str(),
                call.target.is_some(),
            ) {
                return Some(match &namespace {
                    Some(ns) => ns.split('.').next().unwrap_or(ns).to_string(),
                    None => call.func_name.clone(),
                });
            }
            call.args
                .iter()
                .find_map(|a| first_undeclared_ref(a, scope, roots))
        }
        Expr::Comprehension(c) => {
            if let Some(bad) = first_undeclared_ref(&c.iter_range, scope, roots)
                .or_else(|| first_undeclared_ref(&c.accu_init, scope, roots))
            {
                return Some(bad);
            }
            let depth = scope.len();
            scope.push(c.accu_var.clone());
            scope.push(c.iter_var.clone());
            scope.extend(c.iter_var2.clone());
            let r = [&c.loop_cond, &c.loop_step, &c.result]
                .into_iter()
                .find_map(|x| first_undeclared_ref(x, scope, roots));
            scope.truncate(depth);
            r
        }
        Expr::List(l) => l
            .elements
            .iter()
            .find_map(|a| first_undeclared_ref(a, scope, roots)),
        Expr::Map(m) => m.entries.iter().find_map(|entry| match &entry.expr {
            EntryExpr::MapEntry(me) => first_undeclared_ref(&me.key, scope, roots)
                .or_else(|| first_undeclared_ref(&me.value, scope, roots)),
            EntryExpr::StructField(f) => first_undeclared_ref(&f.value, scope, roots),
        }),
        Expr::Struct(s) => s.entries.iter().find_map(|entry| match &entry.expr {
            EntryExpr::StructField(f) => first_undeclared_ref(&f.value, scope, roots),
            EntryExpr::MapEntry(me) => first_undeclared_ref(&me.value, scope, roots),
        }),
        Expr::Literal(_) | Expr::Unspecified => None,
    }
}

/// The segments of the dotted name `e` spells, root first (`a.b.c` is `["a", "b", "c"]`);
/// `None` for anything but an identifier with plain field selections on it.
pub(crate) fn qualified_segments(e: &Expr) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut expr = e;
    loop {
        match expr {
            Expr::Ident(name) => {
                segments.push(name.as_str());
                segments.reverse();
                return Some(segments);
            }
            Expr::Select(sel) if !sel.test => {
                segments.push(sel.field.as_str());
                expr = &sel.operand.expr;
            }
            _ => return None,
        }
    }
}
