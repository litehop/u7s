//! `timestamp` and `duration`: construction, arithmetic and component accessors.

use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Timelike, Utc};

use super::value::{CelError, Value, R};

type V<'a> = Value<'a>;

const MIN_UNIX: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
const MAX_UNIX: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z

fn ts_overflow() -> CelError {
    CelError::new("timestamp overflow")
}

fn in_range(t: &DateTime<Utc>) -> bool {
    (MIN_UNIX..=MAX_UNIX).contains(&t.timestamp())
}

pub(crate) fn to_timestamp<'a>(v: &V<'a>) -> R<V<'a>> {
    match v {
        V::Timestamp(_) => Ok(v.clone()),
        V::Int(i) => {
            if !(MIN_UNIX..=MAX_UNIX).contains(i) {
                return Err(ts_overflow());
            }
            Ok(V::Timestamp(
                DateTime::from_timestamp(*i, 0).ok_or_else(ts_overflow)?,
            ))
        }
        V::Str(s) => {
            let t = DateTime::parse_from_rfc3339(s).map_err(|_| {
                CelError::new("type conversion error from 'string' to 'google.protobuf.Timestamp'")
            })?;
            let t = t.with_timezone(&Utc);
            if !in_range(&t) {
                return Err(ts_overflow());
            }
            Ok(V::Timestamp(t))
        }
        _ => Err(CelError::overload()),
    }
}

pub(crate) fn to_duration<'a>(v: &V<'a>) -> R<V<'a>> {
    match v {
        V::Duration(_) => Ok(v.clone()),
        V::Str(s) => parse_go_duration(s).map(V::Duration).map_err(|_| {
            CelError::new("type conversion error from 'string' to 'google.protobuf.Duration'")
        }),
        _ => Err(CelError::overload()),
    }
}

/// `time.ParseDuration`.
fn parse_go_duration(orig: &str) -> Result<i64, String> {
    let mut s = orig;
    let mut neg = false;
    if let Some(rest) = s.strip_prefix(['-', '+']) {
        neg = s.starts_with('-');
        s = rest;
    }
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(format!("time: invalid duration {orig:?}"));
    }
    let mut total: f64 = 0.0;
    let mut int_total: i128 = 0;
    let mut exact = true;
    while !s.is_empty() {
        let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let int_part = &s[..digits_end];
        s = &s[digits_end..];
        let mut frac_part = "";
        if let Some(rest) = s.strip_prefix('.') {
            let fe = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            frac_part = &rest[..fe];
            s = &rest[fe..];
        }
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(format!("time: invalid duration {orig:?}"));
        }
        let unit_end = s
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        let unit = &s[..unit_end];
        s = &s[unit_end..];
        if unit.is_empty() {
            return Err(format!("time: missing unit in duration {orig:?}"));
        }
        let scale: i128 = match unit {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(format!("time: unknown unit {unit:?} in duration {orig:?}")),
        };
        let int_val: i128 = if int_part.is_empty() {
            0
        } else {
            int_part
                .parse()
                .map_err(|_| format!("time: invalid duration {orig:?}"))?
        };
        int_total += int_val * scale;
        if !frac_part.is_empty() {
            let frac: f64 = format!("0.{frac_part}").parse().unwrap_or(0.0);
            total += frac * scale as f64;
            exact = false;
        }
        if int_total > i64::MAX as i128 + 1 {
            return Err(format!("time: invalid duration {orig:?}"));
        }
    }
    let ns = int_total as f64 + total;
    let ns = if exact { int_total } else { ns as i128 };
    if ns > i64::MAX as i128 + i128::from(neg) {
        return Err(format!("time: invalid duration {orig:?}"));
    }
    Ok(if neg { (-ns) as i64 } else { ns as i64 })
}

pub(crate) fn add_duration<'a>(t: &DateTime<Utc>, d: i64) -> R<V<'a>> {
    let out = t
        .checked_add_signed(chrono::Duration::nanoseconds(d))
        .filter(in_range)
        .ok_or_else(ts_overflow)?;
    Ok(V::Timestamp(out))
}

pub(crate) fn diff<'a>(a: &DateTime<Utc>, b: &DateTime<Utc>) -> R<V<'a>> {
    a.signed_duration_since(*b)
        .num_nanoseconds()
        .map(V::Duration)
        .ok_or_else(|| CelError::new("duration overflow"))
}

enum Zone {
    Utc,
    Named(chrono_tz::Tz),
    Fixed(FixedOffset),
}

fn parse_zone(tz: &str) -> R<Zone> {
    if let Some(ind) = tz.find(':') {
        let hr: i32 = tz[..ind].parse().map_err(|_| {
            CelError::new(format!(
                "strconv.Atoi: parsing {}: invalid syntax",
                crate::field_manager::go_quote(&tz[..ind])
            ))
        })?;
        let min: i32 = tz[ind + 1..].parse().map_err(|_| {
            CelError::new(format!(
                "strconv.Atoi: parsing {}: invalid syntax",
                crate::field_manager::go_quote(&tz[ind + 1..])
            ))
        })?;
        if !(0..=59).contains(&min) {
            return Err(CelError::new(format!(
                "timezone offset minutes out of range [0, 59]: {tz}"
            )));
        }
        let offset = if tz.starts_with('-') {
            hr * 60 - min
        } else {
            hr * 60 + min
        };
        return FixedOffset::east_opt(offset * 60)
            .map(Zone::Fixed)
            .ok_or_else(|| CelError::new(format!("invalid timezone offset: {tz}")));
    }
    if tz.is_empty() || tz == "UTC" {
        return Ok(Zone::Utc);
    }
    tz.parse::<chrono_tz::Tz>()
        .map(Zone::Named)
        .map_err(|_| CelError::new(format!("unknown time zone {tz}")))
}

fn component<'a>(name: &str, t: &DateTime<Utc>, zone: &Zone) -> Option<V<'a>> {
    fn pick<'a, Tz: TimeZone>(name: &str, t: DateTime<Tz>) -> Option<V<'a>> {
        Some(V::Int(match name {
            "getFullYear" => t.year() as i64,
            "getMonth" => t.month0() as i64,
            "getDayOfYear" => t.ordinal0() as i64,
            "getDayOfMonth" => t.day0() as i64,
            "getDate" => t.day() as i64,
            "getDayOfWeek" => t.weekday().num_days_from_sunday() as i64,
            "getHours" => t.hour() as i64,
            "getMinutes" => t.minute() as i64,
            "getSeconds" => t.second() as i64,
            "getMilliseconds" => (t.nanosecond() / 1_000_000) as i64,
            _ => return None,
        }))
    }
    match zone {
        Zone::Utc => pick(name, *t),
        Zone::Named(tz) => pick(name, t.with_timezone(tz)),
        Zone::Fixed(off) => pick(name, t.with_timezone(off)),
    }
}

pub(crate) fn call_method<'a>(name: &str, recv: &V<'a>, args: &[V<'a>]) -> Option<R<V<'a>>> {
    match (recv, name, args) {
        (V::Timestamp(t), _, [] | [V::Str(_)]) => {
            let zone = match args {
                [V::Str(tz)] => match parse_zone(tz) {
                    Ok(z) => z,
                    Err(e) => return Some(Err(e)),
                },
                _ => Zone::Utc,
            };
            component(name, t, &zone).map(Ok)
        }
        (V::Duration(d), "getHours", []) => Some(Ok(V::Int(d / 3_600_000_000_000))),
        (V::Duration(d), "getMinutes", []) => Some(Ok(V::Int(d / 60_000_000_000))),
        (V::Duration(d), "getSeconds", []) => Some(Ok(V::Int(d / 1_000_000_000))),
        (V::Duration(d), "getMilliseconds", []) => Some(Ok(V::Int(d / 1_000_000))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_duration_forms() {
        assert_eq!(parse_go_duration("1h30m").unwrap(), 5_400_000_000_000);
        assert_eq!(parse_go_duration("-1.5s").unwrap(), -1_500_000_000);
        assert_eq!(parse_go_duration("0").unwrap(), 0);
        assert!(parse_go_duration("5").is_err());
        assert!(parse_go_duration("1x").is_err());
    }

    #[test]
    fn timestamp_components_respect_the_zone() {
        let t = to_timestamp(&V::str("2023-06-15T23:30:00Z")).unwrap();
        let V::Timestamp(t) = t else { unreachable!() };
        let hours = |tz: &[V<'_>]| match call_method("getHours", &V::Timestamp(t), tz) {
            Some(Ok(V::Int(h))) => h,
            other => panic!("{other:?}"),
        };
        assert_eq!(hours(&[]), 23);
        assert_eq!(hours(&[V::str("+02:00")]), 1);
        assert_eq!(hours(&[V::str("Asia/Tokyo")]), 8);
    }
}
