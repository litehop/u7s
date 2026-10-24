//! The Kubernetes CEL `url` library over a port of Go's `net/url` parser.

use std::collections::BTreeMap;

use crate::field_manager::go_quote;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Url {
    scheme: String,
    host: String,
    path: String,
    raw_path: String,
    raw_query: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Path,
    Host,
    Query,
    Userinfo,
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if mode == Mode::Host
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::Path => c == b'?',
            Mode::Userinfo => matches!(c, b'@' | b'/' | b'?' | b':'),
            Mode::Query => true,
            Mode::Host => false,
        },
        _ => true,
    }
}

fn escape(s: &str, mode: Mode) -> String {
    let mut out = String::new();
    for &c in s.as_bytes() {
        if should_escape(c, mode) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(c as char);
        }
    }
    out
}

fn unescape(s: &str, mode: Mode) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = (
                    b.get(i + 1).copied().and_then(hex),
                    b.get(i + 2).copied().and_then(hex),
                );
                let (Some(h1), Some(h2)) = h else {
                    let bad: String = s[i..].chars().take(3).collect();
                    return Err(format!("invalid URL escape {}", go_quote(&bad)));
                };
                if mode == Mode::Host && h1 < 8 && should_escape(h1 << 4 | h2, Mode::Host) {
                    let bad: String = s[i..].chars().take(3).collect();
                    return Err(format!("invalid URL escape {}", go_quote(&bad)));
                }
                out.push(h1 << 4 | h2);
                i += 3;
            }
            b'+' if mode == Mode::Query => {
                out.push(b' ');
                i += 1;
            }
            c => {
                if mode == Mode::Host && c < 0x80 && should_escape(c, Mode::Host) {
                    return Err(format!(
                        "invalid character {} in host name",
                        go_quote(&(c as char).to_string())
                    ));
                }
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "invalid UTF-8".to_string())
}

fn get_scheme(raw: &str) -> Result<(&str, &str), String> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".into());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

fn valid_optional_port(port: &str) -> bool {
    match port.strip_prefix(':') {
        None => port.is_empty(),
        Some(p) => p.bytes().all(|c| c.is_ascii_digit()),
    }
}

fn parse_host(host: &str) -> Result<String, String> {
    if host.starts_with('[') {
        let Some(close) = host.rfind(']') else {
            return Err("missing ']' in host".into());
        };
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", go_quote(colon_port)));
        }
        let zone = host[..close].find("%25");
        return Ok(match zone {
            Some(z) => {
                let h1 = unescape(&host[..z], Mode::Host)?;
                let h2 = unescape(&host[z..close], Mode::Host)?;
                let h3 = unescape(&host[close..], Mode::Host)?;
                format!("{h1}{h2}{h3}")
            }
            None => unescape(host, Mode::Host)?,
        });
    }
    if let Some(i) = host.rfind(':') {
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {} after host", go_quote(colon_port)));
        }
    }
    unescape(host, Mode::Host)
}

fn valid_userinfo(s: &str) -> bool {
    s.bytes().all(|r| {
        r.is_ascii_alphanumeric()
            || matches!(
                r,
                b'-' | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
                    | b'@'
            )
    })
}

fn parse_authority(authority: &str) -> Result<String, String> {
    let host = match authority.rfind('@') {
        None => authority,
        Some(i) => {
            let user = &authority[..i];
            if !valid_userinfo(user) {
                return Err("net/url: invalid userinfo".into());
            }
            if !user.contains(':') {
                unescape(user, Mode::Userinfo)?;
            } else {
                let (u, p) = user.split_once(':').unwrap_or((user, ""));
                unescape(u, Mode::Userinfo)?;
                unescape(p, Mode::Userinfo)?;
            }
            &authority[i + 1..]
        }
    };
    parse_host(host)
}

fn parse(raw: &str, via_request: bool) -> Result<Url, String> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("net/url: invalid control character in URL".into());
    }
    if raw.is_empty() && via_request {
        return Err("empty url".into());
    }
    let mut url = Url {
        scheme: String::new(),
        host: String::new(),
        path: String::new(),
        raw_path: String::new(),
        raw_query: String::new(),
    };
    if raw == "*" {
        url.path = "*".into();
        return Ok(url);
    }
    let (scheme, mut rest) = get_scheme(raw)?;
    url.scheme = scheme.to_ascii_lowercase();
    let mut rest_owned;
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else if let Some((r, q)) = rest.split_once('?') {
        url.raw_query = q.to_string();
        rest = r;
    }
    if !rest.starts_with('/') {
        if !url.scheme.is_empty() {
            // Rootless paths are opaque.
            return Ok(url);
        }
        if via_request {
            return Err("invalid URI for request".into());
        }
        if rest.split('/').next().unwrap_or("").contains(':') {
            return Err("first path segment in URL cannot contain colon".into());
        }
    }
    if (!url.scheme.is_empty() || !via_request && !rest.starts_with("///"))
        && rest.starts_with("//")
    {
        let after = &rest[2..];
        let (authority, tail) = match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        };
        url.host = parse_authority(authority)?;
        rest_owned = tail.to_string();
    } else {
        rest_owned = rest.to_string();
    }
    let path = unescape(&rest_owned, Mode::Path)?;
    if escape(&path, Mode::Path) != rest_owned {
        url.raw_path = std::mem::take(&mut rest_owned);
    }
    url.path = path;
    Ok(url)
}

fn go_error(op: &str, raw: &str, e: &str) -> String {
    format!("{op} {}: {e}", go_quote(raw))
}

impl Url {
    /// `url.ParseRequestURI` then `url.Parse`, as the library constructor does.
    pub(crate) fn parse_for_cel(raw: &str) -> Result<Url, String> {
        parse(raw, true).map_err(|e| {
            format!(
                "URL parse error during conversion from string: {}",
                go_error("parse", raw, &e)
            )
        })?;
        let (u, _frag) = raw.split_once('#').unwrap_or((raw, ""));
        parse(u, false).map_err(|e| {
            format!(
                "URL parse error during conversion from string: {}",
                go_error("parse", u, &e)
            )
        })
    }

    pub(crate) fn is_request_uri(raw: &str) -> bool {
        parse(raw, true).is_ok()
    }

    /// `url.ParseRequestURI`'s error, as Go prints it.
    pub(crate) fn request_uri_error(raw: &str) -> Option<String> {
        parse(raw, true).err().map(|e| go_error("parse", raw, &e))
    }

    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    fn split_host_port(&self) -> (&str, &str) {
        let h = self.host.as_str();
        let Some(colon) = h.rfind(':') else {
            return (h, "");
        };
        if let Some(end) = h.rfind(']') {
            if colon < end {
                return (h, "");
            }
        }
        if !valid_optional_port(&h[colon..]) {
            return (h, "");
        }
        (&h[..colon], &h[colon + 1..])
    }

    pub(crate) fn hostname(&self) -> &str {
        let (host, _) = self.split_host_port();
        host.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
    }

    pub(crate) fn port(&self) -> &str {
        self.split_host_port().1
    }

    pub(crate) fn escaped_path(&self) -> String {
        if !self.raw_path.is_empty() {
            if let Ok(p) = unescape(&self.raw_path, Mode::Path) {
                if p == self.path {
                    return self.raw_path.clone();
                }
            }
        }
        if self.path == "*" {
            return "*".into();
        }
        escape(&self.path, Mode::Path)
    }

    /// `url.Query()`: pairs that fail to decode or contain `;` are dropped.
    pub(crate) fn query(&self) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for pair in self.raw_query.split('&') {
            if pair.is_empty() || pair.contains(';') {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let (Ok(k), Ok(v)) = (unescape(k, Mode::Query), unescape(v, Mode::Query)) else {
                continue;
            };
            out.entry(k).or_default().push(v);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_of_a_full_url() {
        let u =
            Url::parse_for_cel("https://user@example.com:8080/a%20b/c?x=1&x=2&y=z#frag").unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host(), "example.com:8080");
        assert_eq!(u.hostname(), "example.com");
        assert_eq!(u.port(), "8080");
        assert_eq!(u.escaped_path(), "/a%20b/c");
        assert_eq!(u.query()["x"], vec!["1", "2"]);
    }

    #[test]
    fn request_uri_rules() {
        assert!(Url::is_request_uri("http://example.com"));
        assert!(Url::is_request_uri("/path"));
        assert!(!Url::is_request_uri("example.com/path"));
        assert!(!Url::is_request_uri(""));
        assert!(Url::parse_for_cel("example.com")
            .unwrap_err()
            .contains("invalid URI for request"));
    }

    #[test]
    fn bad_port_text() {
        assert_eq!(
            Url::parse_for_cel("http://host:abc/").unwrap_err(),
            "URL parse error during conversion from string: parse \"http://host:abc/\": invalid port \":abc\" after host"
        );
    }

    #[test]
    fn ipv6_hostname_strips_brackets() {
        let u = Url::parse_for_cel("http://[::1]:80/").unwrap();
        assert_eq!(u.hostname(), "::1");
        assert_eq!(u.port(), "80");
    }
}
