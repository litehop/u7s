//! List functions: Kubernetes' `lists` library (isSorted, sum, min, max, indexOf,
//! lastIndexOf, includes), `ext.Lists` (slice, flatten, distinct, reverse, sort,
//! `lists.range`) and `ext.Sets`.

use std::cmp::Ordering;

use super::interp::Evaluator;
use super::stdlib::sort_by_keys;
use super::value::{CelError, Value, R};

type V<'a> = Value<'a>;

pub(crate) fn call_global<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    Some(match (name, args) {
        ("lists.range", [V::Int(n)]) => {
            if *n < 0 {
                return Some(Err(CelError::new(format!(
                    "lists.range: size must be non-negative, got {n}"
                ))));
            }
            if let Err(e) = ev.charge_elems(*n as usize) {
                return Some(Err(e));
            }
            Ok(V::list((0..*n).map(V::Int).collect()))
        }
        ("sets.contains", [a, b]) if a.is_list() && b.is_list() => {
            charge_pairs(ev, a, b).map(|()| V::Bool(contains_all(a, b)))
        }
        ("sets.intersects", [a, b]) if a.is_list() && b.is_list() => {
            charge_pairs(ev, a, b).map(|()| V::Bool(intersects(a, b)))
        }
        ("sets.equivalent", [a, b]) if a.is_list() && b.is_list() => {
            charge_pairs(ev, a, b).map(|()| V::Bool(contains_all(a, b) && contains_all(b, a)))
        }
        ("lists.range" | "sets.contains" | "sets.intersects" | "sets.equivalent", _) => {
            Err(CelError::overload())
        }
        _ => return None,
    })
}

fn charge_pairs(ev: &Evaluator<'_, '_>, a: &V<'_>, b: &V<'_>) -> R<()> {
    let n = a.list_len().unwrap_or(0) * b.list_len().unwrap_or(0);
    ev.charge_size(n)
}

fn contains_all(list: &V<'_>, sub: &V<'_>) -> bool {
    sub.list_iter()
        .into_iter()
        .flatten()
        .all(|x| list.list_iter().into_iter().flatten().any(|y| x.equals(&y)))
}

fn intersects(a: &V<'_>, b: &V<'_>) -> bool {
    a.list_iter()
        .into_iter()
        .flatten()
        .any(|x| b.list_iter().into_iter().flatten().any(|y| x.equals(&y)))
}

pub(crate) fn call_method<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    recv: &V<'a>,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    if !recv.is_list() {
        return None;
    }
    let n = recv.list_len().unwrap_or(0);
    let elems = || recv.list_iter().into_iter().flatten();
    Some(match (name, args) {
        ("isSorted", []) => ev.charge_size(n).and_then(|()| is_sorted(elems())),
        ("sum", []) => ev.charge_size(n).and_then(|()| sum(elems())),
        ("min", []) => ev
            .charge_size(n)
            .and_then(|()| extremum(elems(), "min", Ordering::Greater)),
        ("max", []) => ev
            .charge_size(n)
            .and_then(|()| extremum(elems(), "max", Ordering::Less)),
        ("indexOf", [item]) => ev.charge_size(n).map(|()| {
            V::Int(
                elems()
                    .position(|e| e.equals(item))
                    .map_or(-1, |i| i as i64),
            )
        }),
        ("lastIndexOf", [item]) => ev.charge_size(n).map(|()| {
            let items: Vec<V<'a>> = elems().collect();
            V::Int(
                items
                    .iter()
                    .rposition(|e| e.equals(item))
                    .map_or(-1, |i| i as i64),
            )
        }),
        ("includes", [item]) => ev
            .charge_size(n)
            .map(|()| V::Bool(elems().any(|e| e.equals(item)))),
        ("slice", [V::Int(start), V::Int(end)]) => slice(ev, recv, *start, *end),
        ("flatten", []) => flatten_to(ev, recv, 1),
        ("flatten", [V::Int(d)]) => flatten_to(ev, recv, *d),
        ("distinct", []) => distinct(ev, recv),
        ("reverse", []) => ev
            .charge_elems(n)
            .map(|()| V::list(elems().collect::<Vec<_>>().into_iter().rev().collect())),
        ("sort", []) => ev
            .charge_elems(n)
            .and_then(|()| sort_by_keys(ev, elems().map(|e| (e.clone(), e)).collect())),
        (
            "isSorted" | "sum" | "min" | "max" | "indexOf" | "lastIndexOf" | "includes" | "slice"
            | "flatten" | "distinct" | "reverse" | "sort",
            _,
        ) => Err(CelError::overload()),
        _ => return None,
    })
}

fn is_comparable(v: &V<'_>) -> bool {
    matches!(
        v,
        V::Int(_)
            | V::UInt(_)
            | V::Double(_)
            | V::Bool(_)
            | V::Str(_)
            | V::Bytes(_)
            | V::Timestamp(_)
            | V::Duration(_)
    )
}

fn is_sorted<'a>(items: impl Iterator<Item = V<'a>>) -> R<V<'a>> {
    let mut prev: Option<V<'a>> = None;
    for next in items {
        if !is_comparable(&next) {
            return Err(CelError::overload());
        }
        if let Some(p) = &prev {
            if p.compare(&next).ok() == Some(Ordering::Greater) {
                return Ok(V::Bool(false));
            }
        }
        prev = Some(next);
    }
    Ok(V::Bool(true))
}

fn sum<'a>(items: impl Iterator<Item = V<'a>>) -> R<V<'a>> {
    let mut acc: Option<V<'a>> = None;
    for next in items {
        acc = Some(match (acc, next) {
            (None, n @ (V::Int(_) | V::UInt(_) | V::Double(_) | V::Duration(_))) => n,
            (Some(V::Int(a)), V::Int(b)) => V::Int(
                a.checked_add(b)
                    .ok_or_else(|| CelError::new("integer overflow"))?,
            ),
            (Some(V::UInt(a)), V::UInt(b)) => V::UInt(
                a.checked_add(b)
                    .ok_or_else(|| CelError::new("unsigned integer overflow"))?,
            ),
            (Some(V::Double(a)), V::Double(b)) => V::Double(a + b),
            (Some(V::Duration(a)), V::Duration(b)) => V::Duration(
                a.checked_add(b)
                    .ok_or_else(|| CelError::new("duration overflow"))?,
            ),
            _ => return Err(CelError::overload()),
        });
    }
    Ok(acc.unwrap_or(V::Int(0)))
}

/// `min`/`max`: keeps the candidate whose comparison against the next element is `replace`.
fn extremum<'a>(items: impl Iterator<Item = V<'a>>, name: &str, replace: Ordering) -> R<V<'a>> {
    let mut best: Option<V<'a>> = None;
    for next in items {
        if !is_comparable(&next) {
            return Err(CelError::overload());
        }
        best = match best {
            None => Some(next),
            Some(b) => {
                if b.compare(&next).ok() == Some(replace) {
                    Some(next)
                } else {
                    Some(b)
                }
            }
        };
    }
    best.ok_or_else(|| CelError::new(format!("{name} called on empty list")))
}

fn slice<'a>(ev: &Evaluator<'a, '_>, list: &V<'a>, start: i64, end: i64) -> R<V<'a>> {
    let len = list.list_len().unwrap_or(0) as i64;
    if start < 0 || end < 0 {
        return Err(CelError::new(format!(
            "cannot slice({start}, {end}), negative indexes not supported"
        )));
    }
    if start > end {
        return Err(CelError::new(format!(
            "cannot slice({start}, {end}), start index must be less than or equal to end index"
        )));
    }
    if len < end {
        return Err(CelError::new(format!(
            "cannot slice({start}, {end}), list is length {len}"
        )));
    }
    ev.charge_elems((end - start) as usize)?;
    Ok(V::list(
        (start..end)
            .filter_map(|i| list.list_get(i as usize))
            .collect(),
    ))
}

fn flatten_to<'a>(ev: &Evaluator<'a, '_>, list: &V<'a>, depth: i64) -> R<V<'a>> {
    if depth < 0 {
        return Err(CelError::new("level must be non-negative"));
    }
    fn go<'a>(ev: &Evaluator<'a, '_>, list: &V<'a>, depth: i64, out: &mut Vec<V<'a>>) -> R<()> {
        for el in list.list_iter().into_iter().flatten() {
            ev.charge(1)?;
            if depth > 0 && el.is_list() {
                go(ev, &el, depth - 1, out)?;
            } else {
                out.push(el);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    go(ev, list, depth, &mut out)?;
    Ok(V::list(out))
}

fn distinct<'a>(ev: &Evaluator<'a, '_>, list: &V<'a>) -> R<V<'a>> {
    let n = list.list_len().unwrap_or(0);
    ev.charge_size(n.saturating_mul(n) / 2)?;
    let mut out: Vec<V<'a>> = Vec::new();
    for v in list.list_iter().into_iter().flatten() {
        if !out.iter().any(|o| v.equals(o)) {
            out.push(v);
        }
    }
    Ok(V::list(out))
}
