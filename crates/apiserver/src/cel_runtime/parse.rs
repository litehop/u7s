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

/// cel-go's default `MaxRecursionDepth`; Kubernetes does not override it.
pub(crate) const MAX_RECURSION_DEPTH: usize = 250;

/// cel-go's default `ExpressionSizeCodePointLimit`; Kubernetes does not override it.
const MAX_EXPRESSION_CODE_POINTS: usize = 100_000;

/// Stack for the thread that parses and walks an untrusted expression. Sized for the
/// worst accepted input (100k code points, parsed before the depth check can reject it),
/// not for a request thread's 512 KiB; untouched pages cost no memory.
pub(crate) const PARSE_STACK_SIZE: usize = 256 << 20;

/// Longest expression that is parsed on the calling thread: it cannot nest deeply
/// enough to threaten a request thread's small stack.
const IN_PLACE_PARSE_MAX_LEN: usize = 100;

/// Parses `expr` with `parse` under cel-go's size and depth limits, on a thread with
/// `stack_size` of stack so no accepted or rejected input can overflow a request thread.
/// `ast` exposes the tree whose depth is bounded; a too-deep result is dropped on the
/// parse thread, where a deep drop has the stack to run.
pub(crate) fn parse_bounded<T: Send>(
    expr: &str,
    stack_size: usize,
    parse: impl FnOnce() -> Result<T, String> + Send,
    ast: impl FnOnce(&T) -> &IdedExpr + Send,
) -> Result<T, String> {
    let code_points = expr.chars().count();
    if code_points > MAX_EXPRESSION_CODE_POINTS {
        return Err(format!(
            "compilation failed: ERROR: <input>:-1:0: expression code point size exceeds \
             limit: size: {code_points}, limit {MAX_EXPRESSION_CODE_POINTS}"
        ));
    }
    let run = move || {
        let parsed = parse()?;
        if depth_exceeds(ast(&parsed), MAX_RECURSION_DEPTH) {
            return Err(
                "compilation failed: ERROR: <input>:-1:0: max recursion depth exceeded".into(),
            );
        }
        Ok(parsed)
    };
    if expr.len() <= IN_PLACE_PARSE_MAX_LEN {
        return run();
    }
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(stack_size)
            .spawn_scoped(s, run)
            .map_err(|e| format!("compilation failed: {e}"))?
            .join()
            .map_err(|_| "compilation failed: parser panicked".to_string())
    })?
}

/// Whether `root` nests deeper than `max` levels, walked with an explicit stack so the
/// check itself cannot overflow on the tree it is rejecting.
fn depth_exceeds(root: &IdedExpr, max: usize) -> bool {
    let mut pending = vec![(root, 1usize)];
    while let Some((e, depth)) = pending.pop() {
        if depth > max {
            return true;
        }
        let d = depth + 1;
        match &e.expr {
            Expr::Call(c) => {
                pending.extend(c.target.iter().map(|t| (&**t, d)));
                pending.extend(c.args.iter().map(|a| (a, d)));
            }
            Expr::Select(s) => pending.push((&s.operand, d)),
            Expr::List(l) => pending.extend(l.elements.iter().map(|a| (a, d))),
            Expr::Map(m) => pending.extend(m.entries.iter().flat_map(|e| entry_children(e, d))),
            Expr::Struct(s) => pending.extend(s.entries.iter().flat_map(|e| entry_children(e, d))),
            Expr::Comprehension(c) => pending.extend(
                [
                    &c.iter_range,
                    &c.accu_init,
                    &c.loop_cond,
                    &c.loop_step,
                    &c.result,
                ]
                .into_iter()
                .map(|x| (x, d)),
            ),
            Expr::Ident(_) | Expr::Literal(_) | Expr::Unspecified => {}
        }
    }
    false
}

fn entry_children(e: &cel::common::ast::IdedEntryExpr, depth: usize) -> Vec<(&IdedExpr, usize)> {
    match &e.expr {
        EntryExpr::StructField(f) => vec![(&f.value, depth)],
        EntryExpr::MapEntry(m) => vec![(&m.key, depth), (&m.value, depth)],
    }
}

fn parse_with_stack(expr: &str, stack_size: usize) -> Result<IdedExpr, String> {
    #[cfg(test)]
    PARSE_COUNT.with(|c| c.set(c.get() + 1));
    parse_bounded(
        expr,
        stack_size,
        || {
            cel::parser::Parser::new()
                .max_recursion_depth(MAX_RECURSION_DEPTH as u16)
                .enable_optional_syntax(true)
                .enable_ident_escape_syntax(true)
                .parse(expr)
                .map_err(|e| format!("compilation failed: {e}"))
        },
        |e| e,
    )
}

pub(crate) fn parse(expr: &str) -> Result<IdedExpr, String> {
    parse_with_stack(expr, PARSE_STACK_SIZE)
}

/// Compiles a CRD rule under cel-go's size and depth limits. `Program::compile` has no
/// depth option beyond the parser's own 96-level cap, which does not bound member chains.
pub(crate) fn compile_program(source: &str) -> Result<cel::Program, String> {
    parse_bounded(
        source,
        PARSE_STACK_SIZE,
        || cel::Program::compile(source).map_err(|e| e.to_string()),
        |p| p.expression(),
    )
}

/// The reference and function checks cel-go's checker performs, against `roots`.
/// The walk recurses once per AST level, so a long `expr` is checked on the parse stack.
fn check(expr: &str, ast: &IdedExpr, roots: &[&str]) -> Result<(), String> {
    let walk = || match first_undeclared_ref(ast, &mut Vec::new(), roots) {
        Some(name) => Err(format!(
            "compilation failed: undeclared reference to '{name}' (in container '')"
        )),
        None => Ok(()),
    };
    if expr.len() <= IN_PLACE_PARSE_MAX_LEN {
        return walk();
    }
    std::thread::scope(|s| {
        std::thread::Builder::new()
            .stack_size(PARSE_STACK_SIZE)
            .spawn_scoped(s, walk)
            .map_err(|e| format!("compilation failed: {e}"))?
            .join()
            .map_err(|_| "compilation failed: checker panicked".to_string())
    })?
}

/// Compile-step analogue: parse errors must stay distinct from eval errors, since the
/// evaluator absorbs eval errors in `a || true`, which a syntax error must never be.
pub(crate) fn check_syntax(expr: &str, roots: &[&str]) -> Result<(), String> {
    check(expr, &parse(expr)?, roots)
}

#[cfg(test)]
pub(crate) fn check_syntax_with_stack(
    expr: &str,
    roots: &[&str],
    stack_size: usize,
) -> Result<(), String> {
    check(expr, &parse_with_stack(expr, stack_size)?, roots)
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
    let verdict = check(expr, &parsed.ast, roots);
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
