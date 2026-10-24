//! Function and operator dispatch: the CEL standard library plus the extension libraries
//! Kubernetes enables (strings v2, sets, lists, two-variable comprehensions, optionals,
//! and the `kubernetes.*` libraries).

use std::cmp::Ordering;
use std::sync::Arc;

use cel::common::ast::operators;

use super::interp::Evaluator;
use super::value::{go_format_float, CelError, MapKey, Value, R};
use super::{k8slib, listlib, strlib, timelib};

type V<'a> = Value<'a>;

pub(crate) fn call<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    recv: Option<V<'a>>,
    args: Vec<V<'a>>,
) -> R<V<'a>> {
    match recv {
        None => call_global(ev, name, args),
        Some(r) => call_method(ev, name, r, args),
    }
}

/// Whether `ns.name` (or `name`) is a function the environment declares; the compile-step
/// rejects calls to anything else.
pub(crate) fn is_known_function(ns: Option<&str>, name: &str, has_target: bool) -> bool {
    match (ns, has_target) {
        (Some(ns), _) => {
            matches!(
                (ns, name),
                ("optional", "of" | "none" | "ofNonZeroValue")
                    | ("sets", "contains" | "equivalent" | "intersects")
                    | ("strings", "quote")
                    | ("lists", "range")
                    | ("ip", "isCanonical")
                    | ("cel", "bind")
                    | ("jsonpatch", "escapeKey")
                    | ("format", _)
            ) && (ns != "format" || name == "named" || super::format::Format::named(name).is_some())
        }
        (None, false) => {
            is_operator(name)
                || matches!(
                    name,
                    "size"
                        | "int"
                        | "uint"
                        | "double"
                        | "string"
                        | "bytes"
                        | "bool"
                        | "dyn"
                        | "type"
                        | "timestamp"
                        | "duration"
                        | "matches"
                        | "has"
                        | "quantity"
                        | "isQuantity"
                        | "sign"
                        | "ip"
                        | "isIP"
                        | "cidr"
                        | "isCIDR"
                        | "semver"
                        | "isSemver"
                        | "url"
                        | "isURL"
                )
        }
        (None, true) => matches!(
            name,
            "size"
                | "contains"
                | "startsWith"
                | "endsWith"
                | "matches"
                | "charAt"
                | "indexOf"
                | "lastIndexOf"
                | "lowerAscii"
                | "upperAscii"
                | "replace"
                | "split"
                | "substring"
                | "trim"
                | "join"
                | "format"
                | "isSorted"
                | "sum"
                | "min"
                | "max"
                | "includes"
                | "slice"
                | "flatten"
                | "distinct"
                | "reverse"
                | "sort"
                | "sortBy"
                | "getFullYear"
                | "getMonth"
                | "getDayOfYear"
                | "getDayOfMonth"
                | "getDate"
                | "getDayOfWeek"
                | "getHours"
                | "getMinutes"
                | "getSeconds"
                | "getMilliseconds"
                | "hasValue"
                | "value"
                | "or"
                | "orValue"
                | "optMap"
                | "optFlatMap"
                | "all"
                | "exists"
                | "exists_one"
                | "existsOne"
                | "map"
                | "filter"
                | "transformList"
                | "transformMap"
                | "transformMapEntry"
                | "isInteger"
                | "asInteger"
                | "asApproximateFloat"
                | "add"
                | "sub"
                | "isGreaterThan"
                | "isLessThan"
                | "compareTo"
                | "sign"
                | "family"
                | "isUnspecified"
                | "isLoopback"
                | "isLinkLocalMulticast"
                | "isLinkLocalUnicast"
                | "isGlobalUnicast"
                | "containsIP"
                | "containsCIDR"
                | "masked"
                | "prefixLength"
                | "major"
                | "minor"
                | "patch"
                | "validate"
                | "getScheme"
                | "getHost"
                | "getHostname"
                | "getPort"
                | "getEscapedPath"
                | "getQuery"
                | "ip"
                | "find"
                | "findAll"
                | "path"
                | "group"
                | "serviceAccount"
                | "resource"
                | "subresource"
                | "namespace"
                | "name"
                | "check"
                | "allowed"
                | "reason"
                | "errored"
                | "error"
                | "fieldSelector"
                | "labelSelector"
        ),
    }
}

fn is_operator(name: &str) -> bool {
    matches!(
        name,
        operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO
            | operators::EQUALS
            | operators::NOT_EQUALS
            | operators::LESS
            | operators::LESS_EQUALS
            | operators::GREATER
            | operators::GREATER_EQUALS
            | operators::NEGATE
            | operators::LOGICAL_NOT
            | operators::LOGICAL_AND
            | operators::LOGICAL_OR
            | operators::CONDITIONAL
            | operators::INDEX
            | operators::OPT_INDEX
            | operators::OPT_SELECT
            | operators::IN
            | operators::NOT_STRICTLY_FALSE
    )
}

fn call_global<'a>(ev: &Evaluator<'a, '_>, name: &str, args: Vec<V<'a>>) -> R<V<'a>> {
    use operators as op;
    match (name, args.as_slice()) {
        (op::ADD, [a, b]) => add(ev, a, b),
        (op::SUBSTRACT, [a, b]) => sub(a, b),
        (op::MULTIPLY, [a, b]) => mul(a, b),
        (op::DIVIDE, [a, b]) => div(a, b),
        (op::MODULO, [a, b]) => rem(a, b),
        (op::EQUALS, [a, b]) => ev
            .charge_nodes(a)
            .and_then(|()| ev.charge_nodes(b))
            .map(|()| V::Bool(a.equals(b))),
        (op::NOT_EQUALS, [a, b]) => ev
            .charge_nodes(a)
            .and_then(|()| ev.charge_nodes(b))
            .map(|()| V::Bool(!a.equals(b))),
        (op::LESS, [a, b]) => Ok(V::Bool(a.compare(b)? == Ordering::Less)),
        (op::LESS_EQUALS, [a, b]) => Ok(V::Bool(a.compare(b)? != Ordering::Greater)),
        (op::GREATER, [a, b]) => Ok(V::Bool(a.compare(b)? == Ordering::Greater)),
        (op::GREATER_EQUALS, [a, b]) => Ok(V::Bool(a.compare(b)? != Ordering::Less)),
        (op::LOGICAL_NOT, [V::Bool(b)]) => Ok(V::Bool(!b)),
        (op::NEGATE, [a]) => negate(a),
        (op::IN, [needle, haystack]) => contains_in(ev, needle, haystack),
        ("size", [a]) => size(a),
        ("matches", [V::Str(s), V::Str(re)]) => strlib::matches(ev, s, re),
        ("dyn", [a]) => Ok(a.clone()),
        ("type", [a]) => Ok(type_of(a)),
        ("int", [a]) => to_int(a),
        ("uint", [a]) => to_uint(a),
        ("double", [a]) => to_double(a),
        ("string", [a]) => to_string(a),
        ("bytes", [a]) => to_bytes(a),
        ("bool", [a]) => to_bool(a),
        ("timestamp", [a]) => timelib::to_timestamp(a),
        ("duration", [a]) => timelib::to_duration(a),
        _ => k8slib::call_global(ev, name, &args)
            .or_else(|| listlib::call_global(ev, name, &args))
            .or_else(|| strlib::call_global(name, &args))
            .unwrap_or_else(|| Err(unknown_or_overload(name))),
    }
}

/// A call that matched no overload: the standard `no such overload`, except for names the
/// environment does not declare at all.
fn unknown_or_overload(name: &str) -> CelError {
    if is_known_function(
        name.split_once('.').map(|(n, _)| n),
        name.rsplit('.').next().unwrap_or(name),
        false,
    ) {
        CelError::overload()
    } else {
        CelError::new(format!(
            "undeclared reference to '{name}' (in container '')"
        ))
    }
}

fn call_method<'a>(ev: &Evaluator<'a, '_>, name: &str, recv: V<'a>, args: Vec<V<'a>>) -> R<V<'a>> {
    match (name, &recv, args.as_slice()) {
        ("size", r, []) => size(r),
        ("matches", V::Str(s), [V::Str(re)]) => strlib::matches(ev, s, re),
        _ => super::authzlib::call_method(ev, name, &recv, &args)
            .or_else(|| k8slib::call_method(ev, name, &recv, &args))
            .or_else(|| strlib::call_method(ev, name, &recv, &args))
            .or_else(|| listlib::call_method(ev, name, &recv, &args))
            .or_else(|| timelib::call_method(name, &recv, &args))
            .unwrap_or_else(|| {
                if is_known_function(None, name, true) {
                    Err(CelError::overload())
                } else {
                    Err(CelError::new(format!(
                        "undeclared reference to '{name}' (in container '')"
                    )))
                }
            }),
    }
}

pub(crate) fn size<'a>(v: &V<'a>) -> R<V<'a>> {
    Ok(V::Int(match v {
        V::Str(s) => s.chars().count() as i64,
        V::Bytes(b) => b.len() as i64,
        v if v.is_list() => v.list_len().unwrap_or(0) as i64,
        v if v.is_map() => v.map_len().unwrap_or(0) as i64,
        _ => return Err(CelError::overload()),
    }))
}

fn contains_in<'a>(ev: &Evaluator<'a, '_>, needle: &V<'a>, haystack: &V<'a>) -> R<V<'a>> {
    if let Some(items) = haystack.list_iter() {
        ev.charge_nodes(haystack)?;
        ev.charge_nodes(needle)?;
        return Ok(V::Bool(items.into_iter().any(|item| item.equals(needle))));
    }
    if haystack.is_map() {
        return Ok(V::Bool(
            MapKey::from_value(needle).is_some_and(|k| haystack.map_get(&k).is_some()),
        ));
    }
    Err(CelError::overload())
}

pub(crate) fn type_of<'a>(v: &V<'a>) -> V<'a> {
    V::Type(Arc::from(match v {
        V::Type(_) => "type",
        v => v.type_name(),
    }))
}

fn int_overflow() -> CelError {
    CelError::new("integer overflow")
}

fn uint_overflow() -> CelError {
    CelError::new("unsigned integer overflow")
}

fn add<'a>(ev: &Evaluator<'a, '_>, a: &V<'a>, b: &V<'a>) -> R<V<'a>> {
    Ok(match (a, b) {
        (V::Int(x), V::Int(y)) => V::Int(x.checked_add(*y).ok_or_else(int_overflow)?),
        (V::UInt(x), V::UInt(y)) => V::UInt(x.checked_add(*y).ok_or_else(uint_overflow)?),
        (V::Double(x), V::Double(y)) => V::Double(x + y),
        (V::Str(x), V::Str(y)) => {
            ev.charge_size(x.len() + y.len())?;
            V::str(format!("{x}{y}"))
        }
        (V::Bytes(x), V::Bytes(y)) => {
            ev.charge_size(x.len() + y.len())?;
            V::Bytes([&x[..], &y[..]].concat().into())
        }
        (x, y) if x.is_list() && y.is_list() => {
            let (nx, ny) = (x.list_len().unwrap_or(0), y.list_len().unwrap_or(0));
            ev.charge_elems(nx + ny)?;
            let mut out = Vec::with_capacity(nx + ny);
            out.extend(x.list_iter().into_iter().flatten());
            out.extend(y.list_iter().into_iter().flatten());
            V::list(out)
        }
        (V::Timestamp(t), V::Duration(d)) | (V::Duration(d), V::Timestamp(t)) => {
            timelib::add_duration(t, *d)?
        }
        (V::Duration(x), V::Duration(y)) => V::Duration(
            x.checked_add(*y)
                .ok_or_else(|| CelError::new("duration overflow"))?,
        ),
        _ => return Err(CelError::overload()),
    })
}

fn sub<'a>(a: &V<'a>, b: &V<'a>) -> R<V<'a>> {
    Ok(match (a, b) {
        (V::Int(x), V::Int(y)) => V::Int(x.checked_sub(*y).ok_or_else(int_overflow)?),
        (V::UInt(x), V::UInt(y)) => V::UInt(x.checked_sub(*y).ok_or_else(uint_overflow)?),
        (V::Double(x), V::Double(y)) => V::Double(x - y),
        (V::Timestamp(t), V::Duration(d)) => timelib::add_duration(
            t,
            d.checked_neg()
                .ok_or_else(|| CelError::new("duration overflow"))?,
        )?,
        (V::Timestamp(x), V::Timestamp(y)) => timelib::diff(x, y)?,
        (V::Duration(x), V::Duration(y)) => V::Duration(
            x.checked_sub(*y)
                .ok_or_else(|| CelError::new("duration overflow"))?,
        ),
        _ => return Err(CelError::overload()),
    })
}

fn mul<'a>(a: &V<'a>, b: &V<'a>) -> R<V<'a>> {
    Ok(match (a, b) {
        (V::Int(x), V::Int(y)) => V::Int(x.checked_mul(*y).ok_or_else(int_overflow)?),
        (V::UInt(x), V::UInt(y)) => V::UInt(x.checked_mul(*y).ok_or_else(uint_overflow)?),
        (V::Double(x), V::Double(y)) => V::Double(x * y),
        _ => return Err(CelError::overload()),
    })
}

fn div<'a>(a: &V<'a>, b: &V<'a>) -> R<V<'a>> {
    Ok(match (a, b) {
        (V::Int(_), V::Int(0)) | (V::UInt(_), V::UInt(0)) => {
            return Err(CelError::new("division by zero"))
        }
        (V::Int(x), V::Int(y)) => V::Int(x.checked_div(*y).ok_or_else(int_overflow)?),
        (V::UInt(x), V::UInt(y)) => V::UInt(x / y),
        (V::Double(x), V::Double(y)) => V::Double(x / y),
        _ => return Err(CelError::overload()),
    })
}

fn rem<'a>(a: &V<'a>, b: &V<'a>) -> R<V<'a>> {
    Ok(match (a, b) {
        (V::Int(_), V::Int(0)) | (V::UInt(_), V::UInt(0)) => {
            return Err(CelError::new("modulus by zero"))
        }
        (V::Int(x), V::Int(y)) => V::Int(x.checked_rem(*y).ok_or_else(int_overflow)?),
        (V::UInt(x), V::UInt(y)) => V::UInt(x % y),
        _ => return Err(CelError::overload()),
    })
}

fn negate<'a>(a: &V<'a>) -> R<V<'a>> {
    Ok(match a {
        V::Int(x) => V::Int(x.checked_neg().ok_or_else(int_overflow)?),
        V::Double(x) => V::Double(-x),
        V::Duration(d) => V::Duration(
            d.checked_neg()
                .ok_or_else(|| CelError::new("duration overflow"))?,
        ),
        _ => return Err(CelError::overload()),
    })
}

fn conversion_error(from: &V<'_>, to: &str) -> CelError {
    CelError::new(format!(
        "type conversion error from '{}' to '{to}'",
        from.type_name()
    ))
}

fn to_int<'a>(v: &V<'a>) -> R<V<'a>> {
    Ok(V::Int(match v {
        V::Int(i) => *i,
        V::UInt(u) => i64::try_from(*u).map_err(|_| int_overflow())?,
        V::Double(d) => {
            if d.is_nan()
                || d.is_infinite()
                || *d <= -9_223_372_036_854_775_808.0
                || *d >= 9_223_372_036_854_775_808.0
            {
                return Err(int_overflow());
            }
            *d as i64
        }
        V::Str(s) => s.parse::<i64>().map_err(|_| conversion_error(v, "int"))?,
        V::Timestamp(t) => t.timestamp(),
        _ => return Err(CelError::overload()),
    }))
}

fn to_uint<'a>(v: &V<'a>) -> R<V<'a>> {
    Ok(V::UInt(match v {
        V::UInt(u) => *u,
        V::Int(i) => u64::try_from(*i).map_err(|_| uint_overflow())?,
        V::Double(d) => {
            if d.is_nan() || d.is_infinite() || *d < 0.0 || *d >= 18_446_744_073_709_551_616.0 {
                return Err(uint_overflow());
            }
            *d as u64
        }
        V::Str(s) => s.parse::<u64>().map_err(|_| conversion_error(v, "uint"))?,
        _ => return Err(CelError::overload()),
    }))
}

fn to_double<'a>(v: &V<'a>) -> R<V<'a>> {
    Ok(V::Double(match v {
        V::Double(d) => *d,
        V::Int(i) => *i as f64,
        V::UInt(u) => *u as f64,
        V::Str(s) => parse_go_float(s).ok_or_else(|| conversion_error(v, "double"))?,
        _ => return Err(CelError::overload()),
    }))
}

/// `strconv.ParseFloat(s, 64)`: decimal and hex-free forms plus `inf`/`nan` spellings.
fn parse_go_float(s: &str) -> Option<f64> {
    let lower = s.to_ascii_lowercase();
    let t = lower.trim_start_matches(['+', '-']);
    if matches!(t, "inf" | "infinity" | "nan") && lower.len() - t.len() <= 1 {
        return Some(match (t, lower.starts_with('-')) {
            ("nan", _) => f64::NAN,
            (_, true) => f64::NEG_INFINITY,
            _ => f64::INFINITY,
        });
    }
    if s.is_empty() || s.contains(['_', ' ']) || t.starts_with("inf") || t.starts_with("nan") {
        return None;
    }
    s.parse::<f64>().ok()
}

fn to_string<'a>(v: &V<'a>) -> R<V<'a>> {
    Ok(V::str(match v {
        V::Str(s) => s.to_string(),
        V::Int(i) => i.to_string(),
        V::UInt(u) => u.to_string(),
        V::Double(d) => go_format_g(*d),
        V::Bool(b) => b.to_string(),
        V::Bytes(b) => std::str::from_utf8(b)
            .map_err(|_| CelError::new("invalid UTF-8 in bytes, cannot convert to string"))?
            .to_string(),
        V::Timestamp(t) => t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        V::Duration(d) => super::value::format_duration(*d),
        V::Type(t) => t.to_string(),
        V::Ip(ip) => ip.to_string(),
        V::Cidr(c) => c.render(),
        V::Quantity(q) => q.to_canonical_string(),
        _ => return Err(conversion_error(v, "string")),
    }))
}

fn to_bytes<'a>(v: &V<'a>) -> R<V<'a>> {
    match v {
        V::Bytes(_) => Ok(v.clone()),
        V::Str(s) => Ok(V::Bytes(Arc::from(s.as_bytes()))),
        _ => Err(CelError::overload()),
    }
}

fn to_bool<'a>(v: &V<'a>) -> R<V<'a>> {
    match v {
        V::Bool(_) => Ok(v.clone()),
        V::Str(s) => match &**s {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(V::Bool(true)),
            "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(V::Bool(false)),
            _ => Err(conversion_error(v, "bool")),
        },
        _ => Err(CelError::overload()),
    }
}

/// Go's `%g` with the shortest representation that round-trips.
pub(crate) fn go_format_g(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        };
    }
    if f == 0.0 {
        return if f.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (neg, mant) = match mant.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mant),
    };
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let sign = if neg { "-" } else { "" };
    if !(-4..6).contains(&exp) {
        let frac = &digits[1..];
        let dot = if frac.is_empty() { "" } else { "." };
        format!(
            "{sign}{}{dot}{frac}e{}{:02}",
            &digits[..1],
            if exp < 0 { '-' } else { '+' },
            exp.abs()
        )
    } else {
        go_format_float(f)
    }
}

/// Sorts `(key, element)` pairs by key, as `sortBy` and `sort` do.
pub(crate) fn sort_by_keys<'a>(ev: &Evaluator<'a, '_>, mut keyed: Vec<(V<'a>, V<'a>)>) -> R<V<'a>> {
    ev.charge_elems(keyed.len().saturating_mul(2))?;
    if let Some((first, _)) = keyed.first() {
        if !matches!(
            first,
            V::Int(_)
                | V::UInt(_)
                | V::Double(_)
                | V::Bool(_)
                | V::Str(_)
                | V::Bytes(_)
                | V::Timestamp(_)
                | V::Duration(_)
        ) {
            return Err(CelError::new("list elements must be comparable"));
        }
        let t = first.type_name();
        if keyed.iter().any(|(k, _)| k.type_name() != t) {
            return Err(CelError::new("list elements must have the same type"));
        }
    }
    let mut err = None;
    keyed.sort_by(|(a, _), (b, _)| match a.compare(b) {
        Ok(o) => o,
        Err(e) => {
            err.get_or_insert(e);
            Ordering::Equal
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(V::list(keyed.into_iter().map(|(_, v)| v).collect())),
    }
}

/// `string(v)` as plain text, for `%s` formatting.
pub(crate) fn call_to_string(v: &V<'_>) -> R<String> {
    match to_string(v)? {
        V::Str(s) => Ok(s.to_string()),
        _ => Err(CelError::overload()),
    }
}
