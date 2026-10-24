//! The Kubernetes CEL libraries not built on lists/strings: quantity, ip, cidr, semver,
//! url, format, optional values and jsonpatch.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::format::Format;
use super::interp::Evaluator;
use super::net::{
    ip_is_global_unicast, ip_is_link_local_multicast, ip_is_link_local_unicast, parse_cidr,
    parse_ip,
};
use super::quantity::Quantity;
use super::semver::Semver;
use super::url::Url;
use super::value::{CelError, MapKey, Value, R};

type V<'a> = Value<'a>;

fn new_err<'a>(msg: impl Into<String>) -> R<V<'a>> {
    Err(CelError::new(msg))
}

pub(crate) fn call_global<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    let _ = ev;
    Some(match (name, args) {
        ("quantity", [V::Str(s)]) => match Quantity::parse(s) {
            Ok(q) => Ok(V::Quantity(Arc::new(q))),
            Err(e) => new_err(e),
        },
        ("isQuantity", [V::Str(s)]) => Ok(V::Bool(Quantity::parse(s).is_ok())),
        ("sign", [V::Quantity(q)]) => Ok(V::Int(q.sign())),
        ("ip", [V::Str(s)]) => parse_ip(s).map(V::Ip).map_err(CelError::new),
        ("isIP", [V::Str(s)]) => Ok(V::Bool(parse_ip(s).is_ok())),
        ("ip.isCanonical", [V::Str(s)]) => match parse_ip(s) {
            Ok(ip) => Ok(V::Bool(ip.to_string() == **s)),
            Err(e) => new_err(e),
        },
        ("cidr", [V::Str(s)]) => parse_cidr(s).map(V::Cidr).map_err(CelError::new),
        ("isCIDR", [V::Str(s)]) => Ok(V::Bool(parse_cidr(s).is_ok())),
        ("semver", [V::Str(s)]) => semver(s, false),
        ("semver", [V::Str(s), V::Bool(n)]) => semver(s, *n),
        ("isSemver", [V::Str(s)]) => Ok(V::Bool(semver(s, false).is_ok())),
        ("isSemver", [V::Str(s), V::Bool(n)]) => Ok(V::Bool(semver(s, *n).is_ok())),
        ("url", [V::Str(s)]) => Url::parse_for_cel(s)
            .map(|u| V::Url(Arc::new(u)))
            .map_err(CelError::new),
        ("isURL", [V::Str(s)]) => Ok(V::Bool(Url::is_request_uri(s))),
        ("format.named", [V::Str(s)]) => Ok(V::Optional(
            Format::named(s).map(|f| Arc::new(V::Format(f))),
        )),
        ("optional.of", [v]) => Ok(V::Optional(Some(Arc::new(v.clone())))),
        ("optional.none", []) => Ok(V::Optional(None)),
        ("optional.ofNonZeroValue", [v]) => {
            Ok(V::Optional((!is_zero(v)).then(|| Arc::new(v.clone()))))
        }
        ("jsonpatch.escapeKey", [V::Str(s)]) => Ok(V::str(s.replace('~', "~0").replace('/', "~1"))),
        (n, []) if n.starts_with("format.") => Ok(V::Format(Format::named(&n["format.".len()..])?)),
        (
            "quantity"
            | "isQuantity"
            | "sign"
            | "ip"
            | "isIP"
            | "ip.isCanonical"
            | "cidr"
            | "isCIDR"
            | "semver"
            | "isSemver"
            | "url"
            | "isURL"
            | "format.named"
            | "optional.of"
            | "optional.none"
            | "optional.ofNonZeroValue"
            | "jsonpatch.escapeKey",
            _,
        ) => Err(CelError::overload()),
        _ => return None,
    })
}

fn semver<'a>(s: &str, normalize: bool) -> R<V<'a>> {
    let parsed = if normalize {
        Semver::parse_normalized(s)
    } else {
        Semver::parse(s)
    };
    parsed
        .map(|v| V::Semver(Arc::new(v)))
        .map_err(CelError::new)
}

fn is_zero(v: &V<'_>) -> bool {
    match v {
        V::Null => true,
        V::Bool(b) => !b,
        V::Int(i) => *i == 0,
        V::UInt(u) => *u == 0,
        V::Double(d) => *d == 0.0,
        V::Str(s) => s.is_empty(),
        V::Bytes(b) => b.is_empty(),
        V::Duration(d) => *d == 0,
        v if v.is_list() => v.list_len() == Some(0),
        v if v.is_map() => v.map_len() == Some(0),
        _ => false,
    }
}

fn cmp_int(o: Ordering) -> i64 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub(crate) fn call_method<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    recv: &V<'a>,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    let _ = ev;
    Some(match (recv, name, args) {
        (V::Quantity(q), "isInteger", []) => Ok(V::Bool(q.as_i64().is_some())),
        (V::Quantity(q), "asInteger", []) => match q.as_i64() {
            Some(i) => Ok(V::Int(i)),
            None => new_err("cannot convert value to integer"),
        },
        (V::Quantity(q), "asApproximateFloat", []) => Ok(V::Double(q.as_approximate_float())),
        (V::Quantity(q), "sign", []) => Ok(V::Int(q.sign())),
        (V::Quantity(q), "add", [V::Quantity(o)]) => Ok(V::Quantity(Arc::new(q.add(o)))),
        (V::Quantity(q), "add", [V::Int(i)]) => {
            Ok(V::Quantity(Arc::new(q.add(&Quantity::from_i64(*i)))))
        }
        (V::Quantity(q), "sub", [V::Quantity(o)]) => Ok(V::Quantity(Arc::new(q.sub(o)))),
        (V::Quantity(q), "sub", [V::Int(i)]) => {
            Ok(V::Quantity(Arc::new(q.sub(&Quantity::from_i64(*i)))))
        }
        (
            V::Quantity(_) | V::Str(_),
            "compareTo" | "isLessThan" | "isGreaterThan",
            [V::Quantity(o)],
        ) => {
            let q = match recv {
                V::Quantity(q) => Ok((**q).clone()),
                V::Str(s) => Quantity::parse(s).map_err(CelError::new),
                _ => unreachable!(),
            };
            q.map(|q| {
                let ord = q.cmp(o);
                match name {
                    "compareTo" => V::Int(cmp_int(ord)),
                    "isLessThan" => V::Bool(ord == Ordering::Less),
                    _ => V::Bool(ord == Ordering::Greater),
                }
            })
        }
        (V::Ip(ip), "family", []) => Ok(V::Int(if ip.is_ipv4() { 4 } else { 6 })),
        (V::Ip(ip), "isUnspecified", []) => Ok(V::Bool(ip.is_unspecified())),
        (V::Ip(ip), "isLoopback", []) => Ok(V::Bool(ip.is_loopback())),
        (V::Ip(ip), "isLinkLocalMulticast", []) => Ok(V::Bool(ip_is_link_local_multicast(ip))),
        (V::Ip(ip), "isLinkLocalUnicast", []) => Ok(V::Bool(ip_is_link_local_unicast(ip))),
        (V::Ip(ip), "isGlobalUnicast", []) => Ok(V::Bool(ip_is_global_unicast(ip))),
        (V::Cidr(c), "containsIP", [V::Ip(ip)]) => Ok(V::Bool(c.contains_ip(ip))),
        (V::Cidr(c), "containsIP", [V::Str(s)]) => parse_ip(s)
            .map(|ip| V::Bool(c.contains_ip(&ip)))
            .map_err(CelError::new),
        (V::Cidr(c), "containsCIDR", [V::Cidr(o)]) => Ok(V::Bool(c.contains_cidr(o))),
        (V::Cidr(c), "containsCIDR", [V::Str(s)]) => parse_cidr(s)
            .map(|o| V::Bool(c.contains_cidr(&o)))
            .map_err(CelError::new),
        (V::Cidr(c), "ip", []) => Ok(V::Ip(c.addr)),
        (V::Cidr(c), "masked", []) => Ok(V::Cidr(c.masked())),
        (V::Cidr(c), "prefixLength", []) => Ok(V::Int(c.bits as i64)),
        (V::Semver(v), "major", []) => Ok(V::Int(v.major as i64)),
        (V::Semver(v), "minor", []) => Ok(V::Int(v.minor as i64)),
        (V::Semver(v), "patch", []) => Ok(V::Int(v.patch as i64)),
        (V::Semver(v), "compareTo", [V::Semver(o)]) => Ok(V::Int(v.compare(o))),
        (V::Semver(v), "isLessThan", [V::Semver(o)]) => Ok(V::Bool(v.compare(o) < 0)),
        (V::Semver(v), "isGreaterThan", [V::Semver(o)]) => Ok(V::Bool(v.compare(o) > 0)),
        (V::Url(u), "getScheme", []) => Ok(V::str(u.scheme())),
        (V::Url(u), "getHost", []) => Ok(V::str(u.host())),
        (V::Url(u), "getHostname", []) => Ok(V::str(u.hostname())),
        (V::Url(u), "getPort", []) => Ok(V::str(u.port())),
        (V::Url(u), "getEscapedPath", []) => Ok(V::str(u.escaped_path())),
        (V::Url(u), "getQuery", []) => {
            let mut m = BTreeMap::new();
            for (k, vals) in u.query() {
                m.insert(
                    MapKey::Str(Arc::from(k.as_str())),
                    V::list(vals.into_iter().map(V::str).collect()),
                );
            }
            Ok(V::map(m))
        }
        (V::Format(f), "validate", [V::Str(s)]) => {
            let errs = f.validate(s);
            Ok(V::Optional((!errs.is_empty()).then(|| {
                Arc::new(V::list(errs.into_iter().map(V::str).collect()))
            })))
        }
        (V::Optional(o), "hasValue", []) => Ok(V::Bool(o.is_some())),
        (V::Optional(o), "value", []) => match o {
            Some(v) => Ok((**v).clone()),
            None => new_err("optional.none() dereference"),
        },
        (
            V::Quantity(_)
            | V::Ip(_)
            | V::Cidr(_)
            | V::Semver(_)
            | V::Url(_)
            | V::Format(_)
            | V::Optional(_),
            _,
            _,
        ) if is_lib_method(name) => Err(CelError::overload()),
        _ => return None,
    })
}

fn is_lib_method(name: &str) -> bool {
    matches!(
        name,
        "isInteger"
            | "asInteger"
            | "asApproximateFloat"
            | "sign"
            | "add"
            | "sub"
            | "compareTo"
            | "isLessThan"
            | "isGreaterThan"
            | "family"
            | "isUnspecified"
            | "isLoopback"
            | "isLinkLocalMulticast"
            | "isLinkLocalUnicast"
            | "isGlobalUnicast"
            | "containsIP"
            | "containsCIDR"
            | "ip"
            | "masked"
            | "prefixLength"
            | "major"
            | "minor"
            | "patch"
            | "getScheme"
            | "getHost"
            | "getHostname"
            | "getPort"
            | "getEscapedPath"
            | "getQuery"
            | "validate"
            | "hasValue"
            | "value"
    )
}
