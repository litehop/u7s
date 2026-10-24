//! The Kubernetes CEL `semver` library over `blang/semver/v4` parsing rules and errors.

use std::cmp::Ordering;

use crate::field_manager::go_quote;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pre {
    Num(u64),
    Alpha(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Semver {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pre: Vec<Pre>,
}

fn only(s: &str, ok: impl Fn(u8) -> bool) -> bool {
    s.bytes().all(ok)
}

fn is_num(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

fn leading_zeroes(s: &str) -> bool {
    s.len() > 1 && s.starts_with('0')
}

fn number(label: &str, s: &str) -> Result<u64, String> {
    if !only(s, is_num) {
        return Err(format!(
            "Invalid character(s) found in {label} number {}",
            go_quote(s)
        ));
    }
    if leading_zeroes(s) {
        return Err(format!(
            "{} number must not contain leading zeroes {}",
            capitalize(label),
            go_quote(s)
        ));
    }
    s.parse().map_err(|_| {
        format!(
            "strconv.ParseUint: parsing {}: value out of range",
            go_quote(s)
        )
    })
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

impl Semver {
    pub(crate) fn parse(s: &str) -> Result<Semver, String> {
        if s.is_empty() {
            return Err("Version string empty".into());
        }
        let parts: Vec<&str> = s.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("No Major.Minor.Patch elements found".into());
        }
        let major = number("major", parts[0])?;
        let minor = number("minor", parts[1])?;
        let mut patch_str = parts[2];
        let mut build: Vec<&str> = Vec::new();
        let mut prerelease: Vec<&str> = Vec::new();
        if let Some(i) = patch_str.find('+') {
            build = patch_str[i + 1..].split('.').collect();
            patch_str = &patch_str[..i];
        }
        if let Some(i) = patch_str.find('-') {
            prerelease = patch_str[i + 1..].split('.').collect();
            patch_str = &patch_str[..i];
        }
        let patch = number("patch", patch_str)?;
        let mut pre = Vec::new();
        for p in prerelease {
            if p.is_empty() {
                return Err("Prerelease is empty".into());
            }
            if only(p, is_num) {
                if leading_zeroes(p) {
                    return Err(format!(
                        "Numeric PreRelease version must not contain leading zeroes {}",
                        go_quote(p)
                    ));
                }
                let n = p.parse().map_err(|_| {
                    format!(
                        "strconv.ParseUint: parsing {}: value out of range",
                        go_quote(p)
                    )
                })?;
                pre.push(Pre::Num(n));
            } else if only(p, is_alnum) {
                pre.push(Pre::Alpha(p.to_string()));
            } else {
                return Err(format!(
                    "Invalid character(s) found in prerelease {}",
                    go_quote(p)
                ));
            }
        }
        for b in build {
            if b.is_empty() {
                return Err("Build meta data is empty".into());
            }
            if !only(b, is_alnum) {
                return Err(format!(
                    "Invalid character(s) found in build meta data {}",
                    go_quote(b)
                ));
            }
        }
        Ok(Semver {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// The library's `normalize` flag: drop a leading `v`, strip leading zeroes, pad to
    /// three fields.
    pub(crate) fn parse_normalized(s: &str) -> Result<Semver, String> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let mut parts: Vec<String> = s.splitn(3, '.').map(String::from).collect();
        for p in parts.iter_mut() {
            if p.len() > 1 {
                let mut t = p.trim_start_matches('0').to_string();
                if t.is_empty() || !t.as_bytes()[0].is_ascii_digit() {
                    t.insert(0, '0');
                }
                *p = t;
            }
        }
        if parts.len() < 3 {
            if parts[parts.len() - 1].contains(['+', '-']) {
                return Err("short version cannot contain PreRelease/Build meta data".into());
            }
            while parts.len() < 3 {
                parts.push("0".into());
            }
        }
        Semver::parse(&parts.join("."))
    }

    pub(crate) fn compare(&self, other: &Semver) -> i64 {
        let ord = self
            .major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    let mut o = Ordering::Equal;
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        o = match (a, b) {
                            (Pre::Num(x), Pre::Num(y)) => x.cmp(y),
                            (Pre::Num(_), Pre::Alpha(_)) => Ordering::Less,
                            (Pre::Alpha(_), Pre::Num(_)) => Ordering::Greater,
                            (Pre::Alpha(x), Pre::Alpha(y)) => x.cmp(y),
                        };
                        if o != Ordering::Equal {
                            break;
                        }
                    }
                    o.then(self.pre.len().cmp(&other.pre.len()))
                }
            });
        match ord {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parse_rejects_what_blang_rejects() {
        assert_eq!(Semver::parse("").unwrap_err(), "Version string empty");
        assert_eq!(
            Semver::parse("1.1").unwrap_err(),
            "No Major.Minor.Patch elements found"
        );
        assert!(Semver::parse("v1.0.0").is_err());
        assert!(Semver::parse("01.01.01")
            .unwrap_err()
            .contains("leading zeroes"));
        assert!(Semver::parse("1.2.3-beta.1+build.1").is_ok());
        assert!(Semver::parse(" 1.0.0").is_err());
    }

    #[test]
    fn normalize_accepts_loose_forms() {
        assert_eq!(
            Semver::parse_normalized("v01.01")
                .unwrap()
                .compare(&Semver::parse("1.1.0").unwrap()),
            0
        );
        assert!(Semver::parse_normalized("1.0-pre").is_err());
    }

    #[test]
    fn prerelease_orders_below_release() {
        let a = Semver::parse("1.0.0-alpha").unwrap();
        let b = Semver::parse("1.0.0").unwrap();
        assert_eq!(a.compare(&b), -1);
    }
}
