//! The Kubernetes CEL `ip` and `cidr` libraries: Go `net/netip` parsing (with its error
//! text) over `std::net`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::field_manager::go_quote;

fn addr_err(input: &str, msg: &str, at: &str) -> String {
    if at.is_empty() {
        format!("ParseAddr({}): {msg}", go_quote(input))
    } else {
        format!(
            "ParseAddr({}): {msg} (at {})",
            go_quote(input),
            go_quote(at)
        )
    }
}

fn parse_ipv4_fields(input: &str, s: &str) -> Result<[u8; 4], String> {
    let b = s.as_bytes();
    let (mut val, mut pos, mut dig_len) = (0u32, 0usize, 0u32);
    let mut fields = [0u8; 4];
    for i in 0..b.len() {
        if b[i].is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(addr_err(
                    input,
                    "IPv4 field has octet with leading zero",
                    "",
                ));
            }
            val = val * 10 + (b[i] - b'0') as u32;
            dig_len += 1;
            if val > 255 {
                return Err(addr_err(input, "IPv4 field has value >255", ""));
            }
        } else if b[i] == b'.' {
            if i == 0 || i == b.len() - 1 || b[i - 1] == b'.' {
                return Err(addr_err(
                    input,
                    "IPv4 field must have at least one digit",
                    &s[i..],
                ));
            }
            if pos == 3 {
                return Err(addr_err(input, "IPv4 address too long", ""));
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(addr_err(input, "unexpected character", &s[i..]));
        }
    }
    if pos < 3 {
        return Err(addr_err(input, "IPv4 address too short", ""));
    }
    fields[3] = val as u8;
    Ok(fields)
}

/// `netip.ParseAddr`; the second element is whether a zone was present.
fn parse_addr(input: &str) -> Result<(IpAddr, bool), String> {
    for c in input.bytes() {
        match c {
            b'.' => {
                return Ok((
                    IpAddr::V4(Ipv4Addr::from(parse_ipv4_fields(input, input)?)),
                    false,
                ))
            }
            b':' => return parse_ipv6(input),
            b'%' => return Err(addr_err(input, "missing IPv6 address", "")),
            _ => {}
        }
    }
    Err(addr_err(input, "unable to parse IP", ""))
}

fn parse_ipv6(input: &str) -> Result<(IpAddr, bool), String> {
    let (mut s, zone) = match input.find('%') {
        Some(i) => {
            let zone = &input[i + 1..];
            if zone.is_empty() {
                return Err(addr_err(input, "zone must be a non-empty string", ""));
            }
            (&input[..i], zone)
        }
        None => (input, ""),
    };
    let mut ip = [0u8; 16];
    let mut ellipsis: Option<usize> = None;
    if s.len() >= 2 && s.starts_with("::") {
        ellipsis = Some(0);
        s = &s[2..];
        if s.is_empty() {
            return Ok((IpAddr::V6(Ipv6Addr::UNSPECIFIED), !zone.is_empty()));
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let sb = s.as_bytes();
        let mut off = 0usize;
        let mut acc = 0u32;
        while off < sb.len() {
            let c = sb[off];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => break,
            };
            acc = (acc << 4) + d as u32;
            if off > 3 {
                return Err(addr_err(
                    input,
                    "each colon-separated field must have at most 4 hex digits",
                    s,
                ));
            }
            if acc > 0xffff {
                return Err(addr_err(input, "IPv6 field has value >=2^16", s));
            }
            off += 1;
        }
        if off == 0 {
            return Err(addr_err(
                input,
                "each colon-separated field must have at least one digit",
                s,
            ));
        }
        if off < sb.len() && sb[off] == b'.' {
            if ellipsis.is_none() && i != 12 {
                return Err(addr_err(
                    input,
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    s,
                ));
            }
            if i + 4 > 16 {
                return Err(addr_err(
                    input,
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    s,
                ));
            }
            ip[i..i + 4].copy_from_slice(&parse_ipv4_fields(input, s)?);
            s = "";
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if !s.starts_with(':') {
            return Err(addr_err(input, "unexpected character, want colon", s));
        } else if s.len() == 1 {
            return Err(addr_err(
                input,
                "colon must be followed by more characters",
                s,
            ));
        }
        s = &s[1..];
        if s.starts_with(':') {
            if ellipsis.is_some() {
                return Err(addr_err(input, "multiple :: in address", s));
            }
            ellipsis = Some(i);
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(addr_err(input, "trailing garbage after address", s));
    }
    if i < 16 {
        let Some(e) = ellipsis else {
            return Err(addr_err(input, "address string too short", ""));
        };
        let n = 16 - i;
        for j in (e..i).rev() {
            ip[j + n] = ip[j];
        }
        ip[e..e + n].fill(0);
    } else if ellipsis.is_some() {
        return Err(addr_err(
            input,
            "the :: must expand to at least one field of zeros",
            "",
        ));
    }
    Ok((IpAddr::V6(Ipv6Addr::from(ip)), !zone.is_empty()))
}

fn is_4in6(a: &IpAddr) -> bool {
    matches!(a, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
}

/// The `ip()` library constructor: `netip.ParseAddr` minus zones and 4-in-6 forms.
pub(crate) fn parse_ip(raw: &str) -> Result<IpAddr, String> {
    let (addr, zoned) = parse_addr(raw).map_err(|e| {
        format!(
            "IP Address {} parse error during conversion from string: {e}",
            go_quote(raw)
        )
    })?;
    if zoned {
        return Err(format!(
            "IP address {} with zone value is not allowed",
            go_quote(raw)
        ));
    }
    if is_4in6(&addr) {
        return Err(format!(
            "IPv4-mapped IPv6 address {} is not allowed",
            go_quote(raw)
        ));
    }
    Ok(addr)
}

pub(crate) fn ip_is_link_local_multicast(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v4) => v4.octets()[..3] == [224, 0, 0],
        IpAddr::V6(v6) => v6.segments()[0] == 0xff02,
    }
}

pub(crate) fn ip_is_link_local_unicast(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v4) => v4.octets()[..2] == [169, 254],
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

fn ip_is_multicast(a: &IpAddr) -> bool {
    match a {
        IpAddr::V4(v4) => v4.octets()[0] & 0xf0 == 0xe0,
        IpAddr::V6(v6) => v6.octets()[0] == 0xff,
    }
}

pub(crate) fn ip_is_global_unicast(a: &IpAddr) -> bool {
    if let IpAddr::V4(v4) = a {
        if v4.is_unspecified() || v4.octets() == [255; 4] {
            return false;
        }
    }
    !a.is_unspecified() && !a.is_loopback() && !ip_is_multicast(a) && !ip_is_link_local_unicast(a)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cidr {
    pub addr: IpAddr,
    pub bits: u8,
}

fn prefix_err(input: &str, msg: &str) -> String {
    format!("netip.ParsePrefix({}): {msg}", go_quote(input))
}

/// The `cidr()` library constructor. The message nests the same prefix twice, as upstream's
/// wrapper formats an error that already carries it.
pub(crate) fn parse_cidr(raw: &str) -> Result<Cidr, String> {
    let wrap = |e: String| {
        format!(
            "network address parse error during conversion from string: \
             network address parse error during conversion from string: {e}"
        )
    };
    let Some(slash) = raw.rfind('/') else {
        return Err(wrap(prefix_err(raw, "no '/'")));
    };
    let (addr, zoned) = parse_addr(&raw[..slash]).map_err(|e| wrap(prefix_err(raw, &e)))?;
    if zoned && addr.is_ipv6() {
        return Err(wrap(prefix_err(
            raw,
            "IPv6 zones cannot be present in a prefix",
        )));
    }
    let bits_str = &raw[slash + 1..];
    let bad_bits = || {
        wrap(prefix_err(
            raw,
            &format!("bad bits after slash: {}", go_quote(bits_str)),
        ))
    };
    if bits_str.len() > 1 && !matches!(bits_str.as_bytes()[0], b'1'..=b'9') {
        return Err(bad_bits());
    }
    let bits: i64 = bits_str.parse().map_err(|_| bad_bits())?;
    let max = if addr.is_ipv6() { 128 } else { 32 };
    if !(0..=max).contains(&bits) {
        return Err(wrap(prefix_err(raw, "prefix length out of range")));
    }
    if is_4in6(&addr) {
        return Err(format!(
            "network address parse error during conversion from string: \
             IPv4-mapped IPv6 address {} is not allowed",
            go_quote(raw)
        ));
    }
    Ok(Cidr {
        addr,
        bits: bits as u8,
    })
}

fn to_u128(a: &IpAddr) -> u128 {
    match a {
        IpAddr::V4(v4) => u32::from(*v4) as u128,
        IpAddr::V6(v6) => u128::from(*v6),
    }
}

fn width(a: &IpAddr) -> u32 {
    if a.is_ipv4() {
        32
    } else {
        128
    }
}

impl Cidr {
    fn mask(&self) -> u128 {
        let w = width(&self.addr);
        if self.bits == 0 {
            0
        } else {
            (u128::MAX << (128 - self.bits as u32)) >> (128 - w)
        }
    }

    pub(crate) fn masked_addr(&self) -> IpAddr {
        let v = to_u128(&self.addr) & self.mask();
        match self.addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(v as u32)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(v)),
        }
    }

    pub(crate) fn masked(&self) -> Cidr {
        Cidr {
            addr: self.masked_addr(),
            bits: self.bits,
        }
    }

    pub(crate) fn contains_ip(&self, ip: &IpAddr) -> bool {
        width(&self.addr) == width(ip)
            && to_u128(ip) & self.mask() == to_u128(&self.addr) & self.mask()
    }

    /// `cidr.containsCIDR`: the prefixes overlap and `self` is no longer than `other`.
    pub(crate) fn contains_cidr(&self, other: &Cidr) -> bool {
        width(&self.addr) == width(&other.addr)
            && self.bits <= other.bits
            && to_u128(&other.addr) & self.mask() == to_u128(&self.addr) & self.mask()
    }

    pub(crate) fn render(&self) -> String {
        format!("{}/{}", self.addr, self.bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_errors_carry_go_netip_text() {
        assert_eq!(
            parse_ip("192.168.0.1.0").unwrap_err(),
            "IP Address \"192.168.0.1.0\" parse error during conversion from string: \
             ParseAddr(\"192.168.0.1.0\"): IPv4 address too long"
        );
        assert!(parse_ip("2001:db8:::68")
            .unwrap_err()
            .contains("each colon-separated field must have at least one digit (at \":68\")"));
    }

    #[test]
    fn ip_rejects_mapped_and_zoned() {
        assert!(parse_ip("::ffff:1.2.3.4")
            .unwrap_err()
            .contains("IPv4-mapped"));
        assert!(parse_ip("fe80::1%eth0").unwrap_err().contains("zone"));
    }

    #[test]
    fn cidr_containment_follows_upstream_rules() {
        let c = parse_cidr("192.168.0.0/24").unwrap();
        assert!(c.contains_ip(&parse_ip("192.168.0.1").unwrap()));
        assert!(!c.contains_ip(&parse_ip("192.168.1.1").unwrap()));
        assert!(c.contains_cidr(&parse_cidr("192.168.0.0/25").unwrap()));
        assert!(!c.contains_cidr(&parse_cidr("192.168.0.0/23").unwrap()));
        assert_eq!(
            parse_cidr("192.168.0.1/24").unwrap().masked().render(),
            "192.168.0.0/24"
        );
        assert!(parse_cidr("2001:db8::/32")
            .unwrap()
            .contains_ip(&parse_ip("2001:db8::1").unwrap()));
    }

    #[test]
    fn cidr_error_text() {
        assert_eq!(
            parse_cidr("192.168.0.0/").unwrap_err(),
            "network address parse error during conversion from string: network address parse \
             error during conversion from string: netip.ParsePrefix(\"192.168.0.0/\"): bad bits \
             after slash: \"\""
        );
    }

    #[test]
    fn global_unicast_matches_go() {
        assert!(ip_is_global_unicast(&parse_ip("192.168.0.1").unwrap()));
        assert!(!ip_is_global_unicast(&parse_ip("255.255.255.255").unwrap()));
        assert!(!ip_is_global_unicast(&parse_ip("ff00::1").unwrap()));
    }
}
