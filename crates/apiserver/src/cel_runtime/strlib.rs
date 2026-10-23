//! String functions: CEL standard, `ext.Strings(v2)` and the Kubernetes `regex` library.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use regex::{Regex, RegexBuilder};

use super::interp::Evaluator;
use super::value::{CelError, MapKey, Value, R};
use crate::field_manager::go_quote;

type V<'a> = Value<'a>;

const REGEX_CACHE_MAX: usize = 256;

/// Compiles `pattern` with a bounded program size, through a small shared cache.
fn compile(pattern: &str) -> Result<Arc<Regex>, CelError> {
    static CACHE: Mutex<Option<HashMap<String, Arc<Regex>>>> = Mutex::new(None);
    if let Some(re) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(pattern))
    {
        return Ok(re.clone());
    }
    let re = Arc::new(
        RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| CelError::new(format!("Illegal regex: error parsing regexp: {e}")))?,
    );
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let m = guard.get_or_insert_with(HashMap::new);
    if m.len() >= REGEX_CACHE_MAX {
        m.clear();
    }
    m.insert(pattern.to_string(), re.clone());
    Ok(re)
}

pub(crate) fn matches<'a>(ev: &Evaluator<'a, '_>, s: &str, pattern: &str) -> R<V<'a>> {
    ev.charge_size(s.len() + pattern.len())?;
    let re = compile(pattern).map_err(|e| {
        CelError::new(
            e.msg
                .strip_prefix("Illegal regex: ")
                .unwrap_or(&e.msg)
                .to_string(),
        )
    })?;
    Ok(V::Bool(re.is_match(s)))
}

pub(crate) fn call_global<'a>(name: &str, args: &[V<'a>]) -> Option<R<V<'a>>> {
    match (name, args) {
        ("strings.quote", [V::Str(s)]) => Some(Ok(V::str(quote(s)))),
        ("strings.quote", _) => Some(Err(CelError::overload())),
        _ => None,
    }
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn oor(i: i64) -> CelError {
    CelError::new(format!("index out of range: {i}"))
}

pub(crate) fn call_method<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    recv: &V<'a>,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    if name == "join" {
        return recv.is_list().then(|| join(ev, recv, args));
    }
    let V::Str(s) = recv else {
        return None;
    };
    if let Err(e) = ev.charge_size(s.len()) {
        return Some(Err(e));
    }
    Some(match (name, args) {
        ("contains", [V::Str(x)]) => Ok(V::Bool(s.contains(&**x))),
        ("startsWith", [V::Str(x)]) => Ok(V::Bool(s.starts_with(&**x))),
        ("endsWith", [V::Str(x)]) => Ok(V::Bool(s.ends_with(&**x))),
        ("charAt", [V::Int(i)]) => char_at(s, *i),
        ("indexOf", [V::Str(x)]) => index_of(s, x, 0),
        ("indexOf", [V::Str(x), V::Int(off)]) => index_of(s, x, *off),
        ("lastIndexOf", [V::Str(x)]) => last_index_of(s, x, None),
        ("lastIndexOf", [V::Str(x), V::Int(off)]) => last_index_of(s, x, Some(*off)),
        ("lowerAscii", []) => Ok(V::str(s.to_ascii_lowercase())),
        ("upperAscii", []) => Ok(V::str(s.to_ascii_uppercase())),
        ("replace", [V::Str(old), V::Str(new)]) => replace(ev, s, old, new, -1),
        ("replace", [V::Str(old), V::Str(new), V::Int(n)]) => replace(ev, s, old, new, *n),
        ("split", [V::Str(sep)]) => split(ev, s, sep, -1),
        ("split", [V::Str(sep), V::Int(n)]) => split(ev, s, sep, *n),
        ("substring", [V::Int(start)]) => substring(s, *start, None),
        ("substring", [V::Int(start), V::Int(end)]) => substring(s, *start, Some(*end)),
        ("trim", []) => Ok(V::str(s.trim())),
        ("format", [list]) if list.is_list() => format(ev, s, list),
        ("find", [V::Str(re)]) => {
            compile(re).map(|re| V::str(re.find(s).map_or("", |m| m.as_str())))
        }
        ("findAll", [V::Str(re)]) => find_all(ev, s, re, -1),
        ("findAll", [V::Str(re), V::Int(n)]) => find_all(ev, s, re, *n),
        (
            "contains" | "startsWith" | "endsWith" | "charAt" | "indexOf" | "lastIndexOf"
            | "lowerAscii" | "upperAscii" | "replace" | "split" | "substring" | "trim" | "format"
            | "find" | "findAll",
            _,
        ) => Err(CelError::overload()),
        _ => return None,
    })
}

fn char_at<'a>(s: &str, i: i64) -> R<V<'a>> {
    let n = s.chars().count() as i64;
    if i < 0 || i > n {
        return Err(oor(i));
    }
    Ok(V::str(
        s.chars()
            .nth(i as usize)
            .map(String::from)
            .unwrap_or_default(),
    ))
}

fn index_of<'a>(s: &str, sub: &str, off: i64) -> R<V<'a>> {
    if off < 0 {
        return Err(oor(off));
    }
    let runes: Vec<char> = s.chars().collect();
    if sub.is_empty() {
        return Ok(V::Int(off.min(runes.len() as i64)));
    }
    let sub: Vec<char> = sub.chars().collect();
    let off = off as usize;
    if off >= runes.len() || sub.len() > runes.len() {
        return Ok(V::Int(-1));
    }
    for i in off..=runes.len() - sub.len() {
        if runes[i..i + sub.len()] == sub[..] {
            return Ok(V::Int(i as i64));
        }
    }
    Ok(V::Int(-1))
}

fn last_index_of<'a>(s: &str, sub: &str, off: Option<i64>) -> R<V<'a>> {
    let runes: Vec<char> = s.chars().collect();
    let off = match off {
        Some(o) => {
            if o < 0 {
                return Err(oor(o));
            }
            o
        }
        None => {
            if sub.is_empty() {
                return Ok(V::Int(runes.len() as i64));
            }
            if s.len() < sub.len() {
                return Ok(V::Int(-1));
            }
            runes.len() as i64 - 1
        }
    };
    if sub.is_empty() {
        return Ok(V::Int(off.min(runes.len() as i64)));
    }
    let sub: Vec<char> = sub.chars().collect();
    if off >= runes.len() as i64 || sub.len() > runes.len() {
        return Ok(V::Int(-1));
    }
    let start = (off as usize).min(runes.len() - sub.len());
    for i in (0..=start).rev() {
        if runes[i..i + sub.len()] == sub[..] {
            return Ok(V::Int(i as i64));
        }
    }
    Ok(V::Int(-1))
}

fn substring<'a>(s: &str, start: i64, end: Option<i64>) -> R<V<'a>> {
    let runes: Vec<char> = s.chars().collect();
    let l = runes.len() as i64;
    if let Some(end) = end {
        if start > end {
            return Err(CelError::new(format!(
                "invalid substring range. start: {start}, end: {end}"
            )));
        }
    }
    if start < 0 || start > l {
        return Err(oor(start));
    }
    let end = match end {
        Some(e) => {
            if e < 0 || e > l {
                return Err(oor(e));
            }
            e
        }
        None => l,
    };
    Ok(V::str(
        runes[start as usize..end as usize]
            .iter()
            .collect::<String>(),
    ))
}

fn replace<'a>(ev: &Evaluator<'a, '_>, s: &str, old: &str, new: &str, n: i64) -> R<V<'a>> {
    if old == new || n == 0 {
        return Ok(V::str(s));
    }
    let limit = if n < 0 { usize::MAX } else { n as usize };
    // Bound the result before building it: a short input and a long replacement multiply.
    let hits = if old.is_empty() {
        (s.chars().count() + 1).min(limit)
    } else {
        s.matches(old).count().min(limit)
    };
    ev.charge_size(
        s.len()
            .saturating_add(hits.saturating_mul(new.len()))
            .saturating_sub(hits.saturating_mul(old.len())),
    )?;
    let out = if old.is_empty() {
        let mut out = String::new();
        let mut count = 0;
        for c in s.chars() {
            if count < limit {
                out.push_str(new);
                count += 1;
            }
            out.push(c);
        }
        if count < limit {
            out.push_str(new);
        }
        out
    } else {
        s.replacen(old, new, limit)
    };
    Ok(V::str(out))
}

fn split<'a>(ev: &Evaluator<'a, '_>, s: &str, sep: &str, n: i64) -> R<V<'a>> {
    if n == 0 {
        return Ok(V::list(vec![]));
    }
    let pieces = if sep.is_empty() {
        s.chars().count()
    } else {
        s.matches(sep).count() + 1
    };
    ev.charge_elems(if n > 0 {
        pieces.min(n as usize)
    } else {
        pieces
    })?;
    let parts: Vec<String> = if sep.is_empty() {
        let chars: Vec<char> = s.chars().collect();
        if n > 0 && (n as usize) < chars.len() {
            let n = n as usize;
            let mut parts: Vec<String> = chars[..n - 1].iter().map(|c| c.to_string()).collect();
            parts.push(chars[n - 1..].iter().collect());
            parts
        } else {
            chars.iter().map(|c| c.to_string()).collect()
        }
    } else if n < 0 {
        s.split(sep).map(String::from).collect()
    } else {
        s.splitn(n as usize, sep).map(String::from).collect()
    };
    Ok(V::list(parts.into_iter().map(V::str).collect()))
}

fn find_all<'a>(ev: &Evaluator<'a, '_>, s: &str, re: &str, n: i64) -> R<V<'a>> {
    ev.charge_size(s.len())?;
    if n == 0 {
        return Ok(V::list(vec![]));
    }
    let re = compile(re)?;
    let it = re.find_iter(s).map(|m| V::str(m.as_str()));
    let out: Vec<V<'a>> = if n < 0 {
        it.collect()
    } else {
        it.take(n as usize).collect()
    };
    ev.charge_elems(out.len())?;
    Ok(V::list(out))
}

fn join<'a>(ev: &Evaluator<'a, '_>, list: &V<'a>, args: &[V<'a>]) -> R<V<'a>> {
    let sep = match args {
        [] => "",
        [V::Str(sep)] => sep,
        _ => return Err(CelError::overload()),
    };
    let mut out = String::new();
    for (i, el) in list.list_iter().into_iter().flatten().enumerate() {
        if i != 0 {
            out.push_str(sep);
        }
        match el {
            V::Str(s) => out.push_str(&s),
            other => {
                return Err(CelError::new(format!(
                    "join: invalid input: {}",
                    display(&other)
                )))
            }
        }
    }
    ev.charge_size(out.len())?;
    Ok(V::str(out))
}

/// Go's `%v` of a CEL value, as the library's error messages embed it.
fn display(v: &V<'_>) -> String {
    match v {
        V::Null => "null".into(),
        V::Bool(b) => b.to_string(),
        V::Int(i) => i.to_string(),
        V::UInt(u) => u.to_string(),
        V::Double(d) => super::stdlib::go_format_g(*d),
        V::Str(s) => s.to_string(),
        other => format!("{other:?}"),
    }
}

// ---- string.format ----

const DEFAULT_PRECISION: usize = 6;

fn format<'a>(ev: &Evaluator<'a, '_>, fmt: &str, list: &V<'a>) -> R<V<'a>> {
    let args: Vec<V<'a>> = list.list_iter().into_iter().flatten().collect();
    let b = fmt.as_bytes();
    let (mut i, mut arg_idx) = (0usize, 0usize);
    let mut out = String::new();
    while i < b.len() {
        if b[i] != b'%' {
            let ch_len = fmt[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&fmt[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        if i + 1 < b.len() && b[i + 1] == b'%' {
            out.push('%');
            i += 2;
            continue;
        }
        let Some(arg) = args.get(arg_idx) else {
            return Err(CelError::new(format!("index {arg_idx} out of range")));
        };
        if i + 1 >= b.len() {
            return Err(CelError::new("unexpected end of string"));
        }
        let (read, text) = format_clause(&fmt[i + 1..], arg).map_err(CelError::new)?;
        out.push_str(&text);
        i += 1 + read;
        arg_idx += 1;
        ev.charge_size(out.len())?;
    }
    Ok(V::str(out))
}

fn format_clause(rest: &str, arg: &V<'_>) -> Result<(usize, String), String> {
    let wrap_parse = |e: String| format!("could not parse formatting clause: {e}");
    let wrap_fmt = |e: String| format!("error during formatting: {e}");
    let b = rest.as_bytes();
    let mut i = 0;
    let mut precision: Option<usize> = None;
    if b.first() == Some(&b'.') {
        i += 1;
        let start = i;
        loop {
            if i >= b.len() {
                return Err(wrap_parse(
                    "error while parsing precision: could not find end of precision specifier"
                        .into(),
                ));
            }
            if !b[i].is_ascii_digit() {
                break;
            }
            i += 1;
        }
        precision = Some(rest[start..i].parse().map_err(|e| {
            wrap_parse(format!(
                "error while parsing precision: error while converting precision to integer: {e}"
            ))
        })?);
    }
    let Some(&verb) = b.get(i) else {
        return Err(wrap_parse(
            "error while parsing precision: index out of range".into(),
        ));
    };
    i += 1;
    let text = match verb {
        b's' => format_string(arg),
        b'd' => format_decimal(arg),
        b'f' => format_fixed(arg, precision.unwrap_or(DEFAULT_PRECISION)),
        b'e' => format_scientific(arg, precision.unwrap_or(DEFAULT_PRECISION)),
        b'b' => format_binary(arg),
        b'x' => format_hex(arg, false),
        b'X' => format_hex(arg, true),
        b'o' => format_octal(arg),
        other => {
            return Err(wrap_parse(format!(
                "unrecognized formatting clause \"{}\"",
                other as char
            )))
        }
    }
    .map_err(wrap_fmt)?;
    Ok((i, text))
}

fn format_string(arg: &V<'_>) -> Result<String, String> {
    match arg {
        v if v.is_list() => format_list(v),
        v if v.is_map() => format_map(v),
        V::Int(_) | V::UInt(_) | V::Double(_) | V::Bool(_) | V::Str(_) | V::Timestamp(_)
        | V::Bytes(_) | V::Duration(_) | V::Type(_) => {
            match super::stdlib::call_to_string(arg) {
                Ok(s) => Ok(s),
                Err(e) => Err(e.msg),
            }
        }
        V::Null => Ok("null".into()),
        other => Err(format!(
            "string clause can only be used on strings, bools, bytes, ints, doubles, maps, lists, types, durations, and timestamps, was given {}",
            other.type_name()
        )),
    }
}

fn format_decimal(arg: &V<'_>) -> Result<String, String> {
    match arg {
        V::Int(i) => Ok(i.to_string()),
        V::UInt(u) => Ok(u.to_string()),
        other => Err(format!(
            "decimal clause can only be used on integers, was given {}",
            other.type_name()
        )),
    }
}

fn double_arg(arg: &V<'_>, clause: &str) -> Result<f64, String> {
    match arg {
        V::Double(d) => Ok(*d),
        V::Str(s) if matches!(&**s, "NaN" | "Infinity" | "-Infinity") => Ok(match &**s {
            "NaN" => f64::NAN,
            "Infinity" => f64::INFINITY,
            _ => f64::NEG_INFINITY,
        }),
        other => Err(format!(
            "{clause} clause can only be used on doubles, was given {}",
            other.type_name()
        )),
    }
}

fn format_fixed(arg: &V<'_>, precision: usize) -> Result<String, String> {
    let d = double_arg(arg, "fixed-point")?;
    Ok(if d.is_nan() {
        "NaN".into()
    } else if d.is_infinite() {
        if d > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        }
    } else {
        format!("{d:.precision$}")
    })
}

fn format_scientific(arg: &V<'_>, width: usize) -> Result<String, String> {
    let d = double_arg(arg, "scientific")?;
    if d.is_nan() {
        return Ok("NaN".into());
    }
    if d.is_infinite() {
        return Ok(if d > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        });
    }
    let sci = format!("{d:.6e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let s = format!("{mant}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    Ok(format!("{s:>width$}"))
}

fn format_binary(arg: &V<'_>) -> Result<String, String> {
    match arg {
        V::Int(i) => Ok(format!(
            "{}{:b}",
            if *i < 0 { "-" } else { "" },
            i.unsigned_abs()
        )),
        V::UInt(u) => Ok(format!("{u:b}")),
        V::Bool(b) => Ok(if *b { "1".into() } else { "0".into() }),
        other => Err(format!(
            "only integers and bools can be formatted as binary, was given {}",
            other.type_name()
        )),
    }
}

fn format_hex(arg: &V<'_>, upper: bool) -> Result<String, String> {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|b| {
                if upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
            })
            .collect::<String>()
    };
    match arg {
        V::Str(s) => Ok(hex(s.as_bytes())),
        V::Bytes(b) => Ok(hex(b)),
        V::Int(i) => {
            let sign = if *i < 0 { "-" } else { "" };
            Ok(if upper {
                format!("{sign}{:X}", i.unsigned_abs())
            } else {
                format!("{sign}{:x}", i.unsigned_abs())
            })
        }
        V::UInt(u) => Ok(if upper {
            format!("{u:X}")
        } else {
            format!("{u:x}")
        }),
        other => Err(format!(
            "only integers, byte buffers, and strings can be formatted as hex, was given {}",
            other.type_name()
        )),
    }
}

fn format_octal(arg: &V<'_>) -> Result<String, String> {
    match arg {
        V::Int(i) => Ok(format!(
            "{}{:o}",
            if *i < 0 { "-" } else { "" },
            i.unsigned_abs()
        )),
        V::UInt(u) => Ok(format!("{u:o}")),
        other => Err(format!(
            "octal clause can only be used on integers, was given {}",
            other.type_name()
        )),
    }
}

/// The clause a list/map member is rendered with, plus CEL-literal quoting.
fn format_member(v: &V<'_>) -> Result<String, String> {
    let raw = match v {
        V::Int(_) | V::UInt(_) => format_decimal(v)?,
        V::Str(_) | V::Bytes(_) | V::Bool(_) | V::Null | V::Type(_) => format_string(v)?,
        V::Timestamp(_) => format!("timestamp({})", go_quote(&format_string(v)?)),
        V::Duration(_) => format!("duration({})", go_quote(&format_string(v)?)),
        v if v.is_list() => format_list(v)?,
        v if v.is_map() => format_map(v)?,
        V::Double(d) => format!("{d:.DEFAULT_PRECISION$}"),
        other => return Err(format!("no formatting function for {}", other.type_name())),
    };
    Ok(match v {
        V::Str(_) => go_quote(&raw),
        V::Bytes(_) => format!("b{}", go_quote(&raw)),
        V::Double(d) if !d.is_finite() => go_quote(&raw),
        _ => raw,
    })
}

fn format_list(v: &V<'_>) -> Result<String, String> {
    let parts: Result<Vec<String>, String> = v
        .list_iter()
        .into_iter()
        .flatten()
        .map(|m| format_member(&m))
        .collect();
    Ok(format!("[{}]", parts?.join(", ")))
}

fn format_map(v: &V<'_>) -> Result<String, String> {
    let mut pairs = Vec::new();
    for (k, val) in v.map_iter().into_iter().flatten() {
        let key = match &k {
            MapKey::Str(_) | MapKey::Bool(_) => {
                let raw = format_string(&k.to_value())?;
                if matches!(k, MapKey::Str(_)) {
                    go_quote(&raw)
                } else {
                    raw
                }
            }
            MapKey::Int(_) | MapKey::UInt(_) => format_decimal(&k.to_value())?,
        };
        pairs.push((key, format_member(&val)?));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(format!(
        "{{{}}}",
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}
