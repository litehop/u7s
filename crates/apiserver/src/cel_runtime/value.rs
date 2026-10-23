//! CEL values, their JSON bridge, equality and ordering (cel-go semantics).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::Value as J;

use super::format::Format;
use super::net::Cidr;
use super::quantity::Quantity;
use super::semver::Semver;
use super::url::Url;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CelError {
    pub msg: String,
    /// Cost exhaustion: never absorbed by `&&`, `||`, `?:` or a macro.
    pub fatal: bool,
}

impl CelError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        CelError {
            msg: msg.into(),
            fatal: false,
        }
    }

    pub(crate) fn overload() -> Self {
        CelError::new("no such overload")
    }

    pub(crate) fn cost() -> Self {
        CelError {
            msg: "operation cancelled: actual cost limit exceeded".into(),
            fatal: true,
        }
    }
}

impl fmt::Display for CelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

pub(crate) type R<T> = Result<T, CelError>;

/// A string that is either owned or borrowed from request data, so reading a large field
/// never copies it.
#[derive(Clone, Debug)]
pub(crate) enum Text<'a> {
    Owned(Arc<str>),
    Borrowed(&'a str),
}

impl std::ops::Deref for Text<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Text::Owned(s) => s,
            Text::Borrowed(s) => s,
        }
    }
}

impl PartialEq for Text<'_> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

/// A map key; `UInt` keys that fit an `int` are folded into `Int` so lookups are
/// numerically heterogeneous like cel-go's.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MapKey {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Str(Arc<str>),
}

impl MapKey {
    pub(crate) fn from_value(v: &Value<'_>) -> Option<MapKey> {
        Some(match v {
            Value::Bool(b) => MapKey::Bool(*b),
            Value::Int(i) => MapKey::Int(*i),
            Value::UInt(u) => i64::try_from(*u).map_or(MapKey::UInt(*u), MapKey::Int),
            Value::Str(s) => MapKey::Str(Arc::from(&**s)),
            _ => return None,
        })
    }

    pub(crate) fn to_value<'a>(&self) -> Value<'a> {
        match self {
            MapKey::Bool(b) => Value::Bool(*b),
            MapKey::Int(i) => Value::Int(*i),
            MapKey::UInt(u) => Value::UInt(*u),
            MapKey::Str(s) => Value::Str(Text::Owned(s.clone())),
        }
    }

    pub(crate) fn display(&self) -> String {
        match self {
            MapKey::Bool(b) => b.to_string(),
            MapKey::Int(i) => i.to_string(),
            MapKey::UInt(u) => u.to_string(),
            MapKey::Str(s) => s.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Value<'a> {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Double(f64),
    Str(Text<'a>),
    Bytes(Arc<[u8]>),
    List(Arc<Vec<Value<'a>>>),
    Map(Arc<BTreeMap<MapKey, Value<'a>>>),
    /// Borrowed request data, converted per element only as it is touched.
    JList(&'a [J]),
    JMap(&'a serde_json::Map<String, J>),
    Timestamp(DateTime<Utc>),
    /// Nanoseconds, as Go's `time.Duration`.
    Duration(i64),
    Type(Arc<str>),
    Optional(Option<Arc<Value<'a>>>),
    Quantity(Arc<Quantity>),
    Ip(IpAddr),
    Cidr(Cidr),
    Semver(Arc<Semver>),
    Url(Arc<Url>),
    Format(Format),
    /// The `variables` root: the policy variables declared before this index.
    Variables(usize),
}

impl<'a> Value<'a> {
    pub(crate) fn str(s: impl AsRef<str>) -> Self {
        Value::Str(Text::Owned(Arc::from(s.as_ref())))
    }

    pub(crate) fn list(v: Vec<Value<'a>>) -> Self {
        Value::List(Arc::new(v))
    }

    pub(crate) fn map(m: BTreeMap<MapKey, Value<'a>>) -> Self {
        Value::Map(Arc::new(m))
    }

    pub(crate) fn from_json(j: &'a J) -> Value<'a> {
        match j {
            J::Null => Value::Null,
            J::Bool(b) => Value::Bool(*b),
            J::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(u) = n.as_u64() {
                    Value::UInt(u)
                } else {
                    Value::Double(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            J::String(s) => Value::Str(Text::Borrowed(s)),
            J::Array(a) => Value::JList(a),
            J::Object(m) => Value::JMap(m),
        }
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null_type",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::UInt(_) => "uint",
            Value::Double(_) => "double",
            Value::Str(_) => "string",
            Value::Bytes(_) => "bytes",
            Value::List(_) | Value::JList(_) => "list",
            Value::Map(_) | Value::JMap(_) | Value::Variables(_) => "map",
            Value::Timestamp(_) => "google.protobuf.Timestamp",
            Value::Duration(_) => "google.protobuf.Duration",
            Value::Type(_) => "type",
            Value::Optional(_) => "optional_type",
            Value::Quantity(_) => "kubernetes.Quantity",
            Value::Ip(_) => "net.IP",
            Value::Cidr(_) => "net.CIDR",
            Value::Semver(_) => "kubernetes.Semver",
            Value::Url(_) => "kubernetes.URL",
            Value::Format(_) => "kubernetes.format.Format",
        }
    }

    pub(crate) fn is_list(&self) -> bool {
        matches!(self, Value::List(_) | Value::JList(_))
    }

    pub(crate) fn is_map(&self) -> bool {
        matches!(self, Value::Map(_) | Value::JMap(_))
    }

    pub(crate) fn list_len(&self) -> Option<usize> {
        match self {
            Value::List(l) => Some(l.len()),
            Value::JList(l) => Some(l.len()),
            _ => None,
        }
    }

    pub(crate) fn list_get(&self, i: usize) -> Option<Value<'a>> {
        match self {
            Value::List(l) => l.get(i).cloned(),
            Value::JList(l) => l.get(i).map(Value::from_json),
            _ => None,
        }
    }

    pub(crate) fn list_iter<'s>(&'s self) -> Option<Box<dyn Iterator<Item = Value<'a>> + 's>> {
        match self {
            Value::List(l) => Some(Box::new(l.iter().cloned())),
            Value::JList(l) => Some(Box::new(l.iter().map(Value::from_json))),
            _ => None,
        }
    }

    pub(crate) fn map_len(&self) -> Option<usize> {
        match self {
            Value::Map(m) => Some(m.len()),
            Value::JMap(m) => Some(m.len()),
            _ => None,
        }
    }

    pub(crate) fn map_get(&self, key: &MapKey) -> Option<Value<'a>> {
        match self {
            Value::Map(m) => m.get(key).cloned(),
            Value::JMap(m) => match key {
                MapKey::Str(s) => m.get(&**s).map(Value::from_json),
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn map_iter<'s>(
        &'s self,
    ) -> Option<Box<dyn Iterator<Item = (MapKey, Value<'a>)> + 's>> {
        match self {
            Value::Map(m) => Some(Box::new(m.iter().map(|(k, v)| (k.clone(), v.clone())))),
            Value::JMap(m) => {
                Some(Box::new(m.iter().map(|(k, v)| {
                    (MapKey::Str(Arc::from(k.as_str())), Value::from_json(v))
                })))
            }
            _ => None,
        }
    }

    /// The elements of a list or the keys of a map, as a comprehension ranges over them.
    pub(crate) fn range_iter<'s>(&'s self) -> Option<Box<dyn Iterator<Item = Value<'a>> + 's>> {
        if let Some(it) = self.list_iter() {
            return Some(it);
        }
        self.map_iter()
            .map(|it| Box::new(it.map(|(k, _)| k.to_value())) as Box<dyn Iterator<Item = _>>)
    }

    /// Converts to JSON for apply configurations and message expressions.
    pub(crate) fn to_json(&self) -> R<J> {
        Ok(match self {
            Value::Null => J::Null,
            Value::Bool(b) => J::Bool(*b),
            Value::Int(i) => J::from(*i),
            Value::UInt(u) => J::from(*u),
            Value::Double(d) => serde_json::Number::from_f64(*d)
                .map(J::Number)
                .ok_or_else(|| CelError::new("cannot convert a non-finite double to JSON"))?,
            Value::Str(s) => J::String(s.to_string()),
            Value::Bytes(b) => {
                use base64::Engine;
                J::String(base64::engine::general_purpose::STANDARD.encode(b))
            }
            Value::List(l) => J::Array(l.iter().map(Value::to_json).collect::<R<_>>()?),
            Value::JList(l) => J::Array(l.to_vec()),
            Value::Map(m) => J::Object(
                m.iter()
                    .map(|(k, v)| Ok((k.display(), v.to_json()?)))
                    .collect::<R<_>>()?,
            ),
            Value::JMap(m) => J::Object((*m).clone()),
            Value::Timestamp(t) => {
                J::String(t.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true))
            }
            Value::Duration(d) => J::String(format_duration(*d)),
            Value::Quantity(q) => J::String(q.to_canonical_string()),
            Value::Ip(ip) => J::String(ip.to_string()),
            Value::Cidr(c) => J::String(c.render()),
            Value::Optional(Some(v)) => v.to_json()?,
            Value::Optional(None) => J::Null,
            Value::Type(_)
            | Value::Semver(_)
            | Value::Url(_)
            | Value::Format(_)
            | Value::Variables(_) => {
                return Err(CelError::new(format!(
                    "unsupported type conversion to JSON from '{}'",
                    self.type_name()
                )))
            }
        })
    }

    pub(crate) fn equals(&self, other: &Value<'_>) -> bool {
        use Value as V;
        match (self, other) {
            (V::Null, V::Null) => true,
            (V::Bool(a), V::Bool(b)) => a == b,
            (V::Str(a), V::Str(b)) => a == b,
            (V::Bytes(a), V::Bytes(b)) => a == b,
            (V::Int(_) | V::UInt(_) | V::Double(_), V::Int(_) | V::UInt(_) | V::Double(_)) => {
                matches!(compare_numbers(self, other), Some(Ordering::Equal))
            }
            (V::Timestamp(a), V::Timestamp(b)) => a == b,
            (V::Duration(a), V::Duration(b)) => a == b,
            (V::Type(a), V::Type(b)) => a == b,
            (V::Quantity(a), V::Quantity(b)) => a.cmp(b) == Ordering::Equal,
            (V::Ip(a), V::Ip(b)) => a == b,
            (V::Cidr(a), V::Cidr(b)) => a == b,
            (V::Semver(a), V::Semver(b)) => a.compare(b) == 0,
            (V::Url(a), V::Url(b)) => a == b,
            (V::Format(a), V::Format(b)) => a == b,
            (V::Optional(a), V::Optional(b)) => match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => a.equals(b),
                _ => false,
            },
            (a, b) if a.is_list() && b.is_list() => {
                a.list_len() == b.list_len()
                    && a.list_iter()
                        .into_iter()
                        .flatten()
                        .zip(b.list_iter().into_iter().flatten())
                        .all(|(x, y)| x.equals(&y))
            }
            (a, b) if a.is_map() && b.is_map() => {
                a.map_len() == b.map_len()
                    && a.map_iter().is_some_and(|mut it| {
                        it.all(|(k, v)| b.map_get(&k).is_some_and(|w| v.equals(&w)))
                    })
            }
            _ => false,
        }
    }

    /// Ordering for `<` and friends; errors as cel-go does for NaN and unordered types.
    pub(crate) fn compare(&self, other: &Value<'_>) -> R<Ordering> {
        use Value as V;
        match (self, other) {
            (V::Int(_) | V::UInt(_) | V::Double(_), V::Int(_) | V::UInt(_) | V::Double(_)) => {
                compare_numbers(self, other)
                    .ok_or_else(|| CelError::new("NaN values cannot be ordered"))
            }
            (V::Bool(a), V::Bool(b)) => Ok(a.cmp(b)),
            (V::Str(a), V::Str(b)) => Ok(a.cmp(b)),
            (V::Bytes(a), V::Bytes(b)) => Ok(a.cmp(b)),
            (V::Timestamp(a), V::Timestamp(b)) => Ok(a.cmp(b)),
            (V::Duration(a), V::Duration(b)) => Ok(a.cmp(b)),
            _ => Err(CelError::overload()),
        }
    }
}

const TWO_63: f64 = 9_223_372_036_854_775_808.0;
const TWO_64: f64 = 18_446_744_073_709_551_616.0;

fn cmp_i64_f64(i: i64, d: f64) -> Option<Ordering> {
    if d.is_nan() {
        return None;
    }
    if d >= TWO_63 {
        return Some(Ordering::Less);
    }
    if d < -TWO_63 {
        return Some(Ordering::Greater);
    }
    let t = d.trunc();
    Some(i.cmp(&(t as i64)).then_with(|| {
        let frac = d - t;
        if frac > 0.0 {
            Ordering::Less
        } else if frac < 0.0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }))
}

fn cmp_u64_f64(u: u64, d: f64) -> Option<Ordering> {
    if d.is_nan() {
        return None;
    }
    if d >= TWO_64 {
        return Some(Ordering::Less);
    }
    if d < 0.0 {
        return Some(Ordering::Greater);
    }
    let t = d.trunc();
    Some(u.cmp(&(t as u64)).then_with(|| {
        if d - t > 0.0 {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }))
}

/// Exact cross-type numeric comparison; `None` when a NaN is involved.
pub(crate) fn compare_numbers(a: &Value<'_>, b: &Value<'_>) -> Option<Ordering> {
    use Value as V;
    match (a, b) {
        (V::Int(x), V::Int(y)) => Some(x.cmp(y)),
        (V::UInt(x), V::UInt(y)) => Some(x.cmp(y)),
        (V::Double(x), V::Double(y)) => x.partial_cmp(y),
        (V::Int(x), V::UInt(y)) => Some(if *x < 0 {
            Ordering::Less
        } else {
            (*x as u64).cmp(y)
        }),
        (V::UInt(x), V::Int(y)) => Some(if *y < 0 {
            Ordering::Greater
        } else {
            x.cmp(&(*y as u64))
        }),
        (V::Int(x), V::Double(y)) => cmp_i64_f64(*x, *y),
        (V::Double(x), V::Int(y)) => cmp_i64_f64(*y, *x).map(Ordering::reverse),
        (V::UInt(x), V::Double(y)) => cmp_u64_f64(*x, *y),
        (V::Double(x), V::UInt(y)) => cmp_u64_f64(*y, *x).map(Ordering::reverse),
        _ => None,
    }
}

/// Go's `time.Duration.String`-free rendering used by `string(duration)`: seconds with
/// the shortest fractional part, then `s`.
pub(crate) fn format_duration(ns: i64) -> String {
    let secs = ns as f64 / 1e9;
    format!("{}s", go_format_float(secs))
}

/// `strconv.FormatFloat(f, 'f', -1, 64)`.
pub(crate) fn go_format_float(f: f64) -> String {
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
    let s = format!("{f}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_equality_is_heterogeneous_and_exact() {
        assert!(Value::Int(1).equals(&Value::UInt(1)));
        assert!(Value::Int(1).equals(&Value::Double(1.0)));
        assert!(!Value::Int(-1).equals(&Value::UInt(u64::MAX)));
        assert!(!Value::Double(f64::NAN).equals(&Value::Double(f64::NAN)));
        assert!(
            !Value::Int(i64::MAX).equals(&Value::Double(9_223_372_036_854_775_808.0)),
            "2^63 is not representable as an int"
        );
    }

    #[test]
    fn nan_ordering_is_an_error_not_false() {
        let err = Value::Double(f64::NAN).compare(&Value::Int(1)).unwrap_err();
        assert_eq!(err.msg, "NaN values cannot be ordered");
    }

    #[test]
    fn json_maps_compare_equal_to_built_maps() {
        let j: J = serde_json::json!({"a": 1, "b": [true]});
        let from_json = Value::from_json(&j);
        let mut m = BTreeMap::new();
        m.insert(MapKey::Str("a".into()), Value::Int(1));
        m.insert(
            MapKey::Str("b".into()),
            Value::list(vec![Value::Bool(true)]),
        );
        assert!(from_json.equals(&Value::map(m)));
    }

    #[test]
    fn uint_keys_fold_into_int_keys() {
        assert_eq!(
            MapKey::from_value(&Value::UInt(1)),
            MapKey::from_value(&Value::Int(1))
        );
    }
}
