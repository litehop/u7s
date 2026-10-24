//! `resource.Quantity` as the Kubernetes CEL `quantity` library sees it: arbitrary
//! precision decimals with apimachinery's parse, round-up-to-nano and `AsInt64` rules.

use std::cmp::Ordering;

const ERR_FORMAT: &str = "quantities must match the regular expression \
     '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'";
const ERR_SUFFIX: &str = "unable to parse quantity's suffix";
const ERR_NUMERIC: &str = "unable to parse numeric part of quantity";

/// `±digits × 10^exp`; `digits` is most-significant first with no leading zeros, empty for 0.
#[derive(Clone, Debug)]
struct Dec {
    neg: bool,
    digits: Vec<u8>,
    exp: i32,
}

impl Dec {
    fn zero() -> Self {
        Dec {
            neg: false,
            digits: Vec::new(),
            exp: 0,
        }
    }

    fn from_i64(value: i64, scale: i32) -> Self {
        let mut d = Dec::from_digits(value.unsigned_abs().to_string().bytes().map(|b| b - b'0'));
        d.neg = value < 0 && !d.digits.is_empty();
        d.exp = scale;
        d
    }

    fn from_digits(digits: impl Iterator<Item = u8>) -> Self {
        let digits: Vec<u8> = digits.skip_while(|d| *d == 0).collect();
        Dec {
            neg: false,
            digits,
            exp: 0,
        }
    }

    fn is_zero(&self) -> bool {
        self.digits.is_empty()
    }

    /// Both values over the smaller exponent.
    fn aligned(a: &Dec, b: &Dec) -> (Vec<u8>, Vec<u8>, i32) {
        let exp = a.exp.min(b.exp);
        let widen = |d: &Dec| {
            let mut v = d.digits.clone();
            if !v.is_empty() {
                v.extend(std::iter::repeat_n(0, (d.exp - exp) as usize));
            }
            v
        };
        (widen(a), widen(b), exp)
    }

    fn cmp_mag(a: &[u8], b: &[u8]) -> Ordering {
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }

    fn cmp(&self, other: &Dec) -> Ordering {
        match (self.is_zero(), other.is_zero()) {
            (true, true) => return Ordering::Equal,
            (true, false) => {
                return if other.neg {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, true) => {
                return if self.neg {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            _ => {}
        }
        if self.neg != other.neg {
            return if self.neg {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let (a, b, _) = Dec::aligned(self, other);
        let m = Dec::cmp_mag(&a, &b);
        if self.neg {
            m.reverse()
        } else {
            m
        }
    }

    fn add_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
        let (mut i, mut j, mut carry) = (a.len(), b.len(), 0u8);
        while i > 0 || j > 0 || carry > 0 {
            let x = if i > 0 {
                i -= 1;
                a[i]
            } else {
                0
            };
            let y = if j > 0 {
                j -= 1;
                b[j]
            } else {
                0
            };
            let s = x + y + carry;
            out.push(s % 10);
            carry = s / 10;
        }
        out.reverse();
        out
    }

    /// `a - b` for `a >= b`.
    fn sub_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(a.len());
        let (mut i, mut j, mut borrow) = (a.len(), b.len(), 0i8);
        while i > 0 {
            i -= 1;
            let y = if j > 0 {
                j -= 1;
                b[j] as i8
            } else {
                0
            };
            let mut d = a[i] as i8 - y - borrow;
            if d < 0 {
                d += 10;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(d as u8);
        }
        out.reverse();
        out.into_iter().skip_while(|d| *d == 0).collect()
    }

    fn add(&self, other: &Dec) -> Dec {
        let (a, b, exp) = Dec::aligned(self, other);
        let (neg, digits) = if self.neg == other.neg {
            (self.neg, Dec::add_mag(&a, &b))
        } else {
            match Dec::cmp_mag(&a, &b) {
                Ordering::Equal => (false, Vec::new()),
                Ordering::Greater => (self.neg, Dec::sub_mag(&a, &b)),
                Ordering::Less => (other.neg, Dec::sub_mag(&b, &a)),
            }
        };
        let digits: Vec<u8> = digits.into_iter().skip_while(|d| *d == 0).collect();
        Dec {
            neg: neg && !digits.is_empty(),
            digits,
            exp,
        }
    }

    fn negated(&self) -> Dec {
        Dec {
            neg: !self.neg && !self.is_zero(),
            ..self.clone()
        }
    }

    /// Multiplies the magnitude by `2^bits`.
    fn shl(&mut self, bits: u32) {
        for _ in 0..bits {
            let mut carry = 0u8;
            for d in self.digits.iter_mut().rev() {
                let v = *d * 2 + carry;
                *d = v % 10;
                carry = v / 10;
            }
            if carry > 0 {
                self.digits.insert(0, carry);
            }
        }
    }

    /// Rounds the magnitude up so the exponent is at least `min_exp`.
    fn round_up_to(&mut self, min_exp: i32) {
        if self.exp >= min_exp || self.is_zero() {
            return;
        }
        let drop = (min_exp - self.exp) as usize;
        if drop >= self.digits.len() {
            self.digits = vec![1];
        } else {
            let cut = self.digits.len() - drop;
            let dropped_nonzero = self.digits[cut..].iter().any(|d| *d != 0);
            self.digits.truncate(cut);
            if dropped_nonzero {
                self.digits = Dec::add_mag(&self.digits, &[1]);
            }
            if self.digits.iter().all(|d| *d == 0) {
                self.digits.clear();
            }
        }
        self.exp = min_exp;
    }

    fn to_f64(&self) -> f64 {
        if self.is_zero() {
            return 0.0;
        }
        let digits: String = self.digits.iter().map(|d| (b'0' + d) as char).collect();
        let s = format!("{}{digits}e{}", if self.neg { "-" } else { "" }, self.exp);
        s.parse().unwrap_or(f64::NAN)
    }

    fn to_plain_string(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let digits: String = self.digits.iter().map(|d| (b'0' + d) as char).collect();
        let sign = if self.neg { "-" } else { "" };
        if self.exp >= 0 {
            format!("{sign}{digits}{}", "0".repeat(self.exp as usize))
        } else {
            let frac = (-self.exp) as usize;
            if digits.len() > frac {
                let (i, f) = digits.split_at(digits.len() - frac);
                format!("{sign}{i}.{f}")
            } else {
                format!("{sign}0.{}{digits}", "0".repeat(frac - digits.len()))
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Amount {
    /// `value × 10^scale`, apimachinery's `int64Amount`.
    Small {
        value: i64,
        scale: i32,
    },
    Big(Dec),
}

#[derive(Clone, Debug)]
pub(crate) struct Quantity {
    amount: Amount,
}

const NANO: i32 = -9;

fn pow10(n: u32) -> Option<i64> {
    10i64.checked_pow(n)
}

fn positive_scale(value: i64, scale: i32) -> Option<i64> {
    value.checked_mul(pow10(scale as u32)?)
}

impl Quantity {
    pub(crate) fn from_i64(v: i64) -> Self {
        Quantity {
            amount: Amount::Small { value: v, scale: 0 },
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Quantity, &'static str> {
        if s.is_empty() {
            return Err(ERR_FORMAT);
        }
        if s == "0" {
            return Ok(Quantity::from_i64(0));
        }
        let b = s.as_bytes();
        let mut pos = 0;
        let positive = match b[0] {
            b'-' => {
                pos = 1;
                false
            }
            b'+' => {
                pos = 1;
                true
            }
            _ => true,
        };
        let num_start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        let num = &s[num_start..pos];
        let mut denom = "";
        if pos < b.len() && b[pos] == b'.' {
            pos += 1;
            let d0 = pos;
            while pos < b.len() && b[pos].is_ascii_digit() {
                pos += 1;
            }
            denom = &s[d0..pos];
        }
        if num.is_empty() && denom.is_empty() {
            return Err(ERR_FORMAT);
        }
        let suffix_start = pos;
        while pos < b.len() && b"eEinumkKMGTP".contains(&b[pos]) {
            pos += 1;
        }
        if pos < b.len() && (b[pos] == b'-' || b[pos] == b'+') {
            pos += 1;
        }
        if b[pos.min(b.len())..].iter().any(|c| !c.is_ascii_digit()) {
            return Err(ERR_FORMAT);
        }
        let suffix = &s[suffix_start..];
        let (base, exponent, binary) = interpret_suffix(suffix).ok_or(ERR_SUFFIX)?;

        let digits = format!("{num}{denom}");
        if !binary || exponent >= 0 && denom.is_empty() {
            let (scale, precision) = if binary {
                (
                    0,
                    15 - num.len() as i32 - (exponent as f32 * 3.0 / 10.0) as i32 - 1,
                )
            } else {
                (exponent, 18 - (num.len() + denom.len()) as i32)
            };
            if precision >= 0 {
                let scale = scale - denom.len() as i32;
                if scale >= NANO {
                    let value: i64 = digits.parse().map_err(|_| ERR_NUMERIC)?;
                    let mantissa = if binary {
                        1i64.checked_shl(exponent as u32)
                    } else {
                        Some(1)
                    };
                    if let Some(result) = mantissa.and_then(|m| value.checked_mul(m)) {
                        return Ok(Quantity {
                            amount: Amount::Small {
                                value: if positive { result } else { -result },
                                scale,
                            },
                        });
                    }
                }
            }
        }
        let mut dec = Dec::from_digits(digits.bytes().map(|c| c - b'0'));
        dec.exp = -(denom.len() as i32);
        if base == 10 {
            dec.exp += exponent;
        } else {
            dec.shl(exponent as u32);
        }
        dec.round_up_to(NANO);
        dec.neg = !positive && !dec.is_zero();
        Ok(Quantity {
            amount: Amount::Big(dec),
        })
    }

    fn dec(&self) -> Dec {
        match &self.amount {
            Amount::Small { value, scale } => Dec::from_i64(*value, *scale),
            Amount::Big(d) => d.clone(),
        }
    }

    pub(crate) fn cmp(&self, other: &Quantity) -> Ordering {
        self.dec().cmp(&other.dec())
    }

    pub(crate) fn sign(&self) -> i64 {
        match self.dec().cmp(&Dec::zero()) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// `AsInt64`: only the fast representation converts, and only at non-negative scale.
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match &self.amount {
            Amount::Small { value, scale: 0 } => Some(*value),
            Amount::Small { value, scale } if *scale > 0 => positive_scale(*value, *scale),
            _ => None,
        }
    }

    pub(crate) fn as_approximate_float(&self) -> f64 {
        self.dec().to_f64()
    }

    pub(crate) fn add(&self, other: &Quantity) -> Quantity {
        if let (
            Amount::Small {
                value: av,
                scale: asc,
            },
            Amount::Small {
                value: bv,
                scale: bsc,
            },
        ) = (&self.amount, &other.amount)
        {
            let sum = if *bv == 0 {
                Some((*av, *asc))
            } else if *av == 0 {
                Some((*bv, *bsc))
            } else if asc == bsc {
                av.checked_add(*bv).map(|v| (v, *asc))
            } else if asc > bsc {
                positive_scale(*av, asc - bsc)
                    .and_then(|c| c.checked_add(*bv))
                    .map(|v| (v, *bsc))
            } else {
                positive_scale(*bv, bsc - asc)
                    .and_then(|c| av.checked_add(c))
                    .map(|v| (v, *asc))
            };
            if let Some((value, scale)) = sum {
                return Quantity {
                    amount: Amount::Small { value, scale },
                };
            }
        }
        Quantity {
            amount: Amount::Big(self.dec().add(&other.dec())),
        }
    }

    pub(crate) fn sub(&self, other: &Quantity) -> Quantity {
        let negated = match &other.amount {
            Amount::Small { value, scale } => match value.checked_neg() {
                Some(v) => Amount::Small {
                    value: v,
                    scale: *scale,
                },
                None => Amount::Big(other.dec().negated()),
            },
            Amount::Big(d) => Amount::Big(d.negated()),
        };
        self.add(&Quantity { amount: negated })
    }

    pub(crate) fn to_canonical_string(&self) -> String {
        self.dec().to_plain_string()
    }
}

/// `(base, exponent, is_binary)` of a quantity suffix.
fn interpret_suffix(s: &str) -> Option<(u32, i32, bool)> {
    Some(match s {
        "" => (10, 0, false),
        "n" => (10, -9, false),
        "u" => (10, -6, false),
        "m" => (10, -3, false),
        "k" => (10, 3, false),
        "M" => (10, 6, false),
        "G" => (10, 9, false),
        "T" => (10, 12, false),
        "P" => (10, 15, false),
        "E" => (10, 18, false),
        "Ki" => (2, 10, true),
        "Mi" => (2, 20, true),
        "Gi" => (2, 30, true),
        "Ti" => (2, 40, true),
        "Pi" => (2, 50, true),
        "Ei" => (2, 60, true),
        _ => {
            let rest = s.strip_prefix(['e', 'E'])?;
            let n: i32 = rest.parse().ok()?;
            if rest.is_empty() || n.abs() > 10_000 {
                return None;
            }
            (10, n, false)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(s: &str) -> Quantity {
        Quantity::parse(s).unwrap()
    }

    #[test]
    fn equal_quantities_in_different_suffixes_compare_equal() {
        assert_eq!(q("200M").cmp(&q("0.2G")), Ordering::Equal);
        assert_eq!(q("2000k").cmp(&q("0.002G")), Ordering::Equal);
        assert_eq!(q("50Mi").cmp(&q("50M")), Ordering::Greater);
    }

    #[test]
    fn as_i64_follows_the_fast_path_rules() {
        assert_eq!(q("50k").as_i64(), Some(50_000));
        assert_eq!(q("1500m").as_i64(), None, "negative scale never converts");
        assert_eq!(
            q("9999999999999999999999999999999999999G").as_i64(),
            None,
            "a value beyond int64 must not wrap"
        );
        assert_eq!(q("50k").add(&Quantity::from_i64(20)).as_i64(), Some(50_020));
    }

    #[test]
    fn add_sub_are_exact_beyond_i64() {
        let big = q("9999999999999999999999999999999999999");
        assert_eq!(
            big.add(&q("1")).cmp(&big.add(&q("2"))),
            Ordering::Less,
            "adjacent huge quantities must stay distinguishable"
        );
        assert_eq!(q("50k").sub(&q("20")).cmp(&q("49.98k")), Ordering::Equal);
    }

    #[test]
    fn parse_rejects_what_apimachinery_rejects() {
        assert_eq!(Quantity::parse("10Mo").unwrap_err(), ERR_FORMAT);
        assert_eq!(Quantity::parse("10Mm").unwrap_err(), ERR_SUFFIX);
        assert_eq!(Quantity::parse("").unwrap_err(), ERR_FORMAT);
        assert!(Quantity::parse("1e3").is_ok());
        assert!(Quantity::parse("-1.5Gi").is_ok());
    }

    #[test]
    fn sub_nano_fractions_round_up() {
        assert_eq!(q("0.0000000001").cmp(&q("1n")), Ordering::Equal);
    }

    #[test]
    fn approximate_float() {
        assert!((q("50.703k").as_approximate_float() - 50_703.0).abs() < 1e-9);
    }
}
