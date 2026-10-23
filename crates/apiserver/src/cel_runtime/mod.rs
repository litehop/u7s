//! A CEL evaluator with cel-go semantics over the `cel` crate's parser: the engine behind
//! ValidatingAdmissionPolicy, MutatingAdmissionPolicy and webhook match conditions.
//!
//! The vendored `cel` interpreter has no cooperative cost hook, so evaluation is done here,
//! where every node, iteration and produced byte is charged against a per-expression
//! budget and exhaustion aborts the expression (never absorbed by `&&`/`||`).

mod format;
mod interp;
mod k8slib;
mod listlib;
mod net;
mod parse;
mod quantity;
mod semver;
mod stdlib;
mod strlib;
mod timelib;
mod url;
mod value;

pub(crate) use interp::{Env, Evaluator};
pub(crate) use parse::check_syntax;
#[cfg(test)]
pub(crate) use parse::{check_syntax_with_stack, PARSE_COUNT};
pub(crate) use value::Value;

/// Evaluates `expr` to a boolean with a fresh cost budget.
pub(crate) fn eval_bool(env: &Env<'_>, expr: &str) -> Result<bool, String> {
    match Evaluator::new(env).eval_str(expr).map_err(|e| e.msg)? {
        Value::Bool(b) => Ok(b),
        other => Err(format!(
            "expression must evaluate to a bool, got {}",
            other.type_name()
        )),
    }
}

/// Evaluates `expr` with a fresh cost budget and converts the result to JSON.
pub(crate) fn eval_json(env: &Env<'_>, expr: &str) -> Result<serde_json::Value, String> {
    Evaluator::new(env)
        .eval_str(expr)
        .and_then(|v| v.to_json())
        .map_err(|e| e.msg)
}

#[cfg(test)]
mod tests;
