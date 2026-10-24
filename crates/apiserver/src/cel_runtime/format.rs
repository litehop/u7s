//! The Kubernetes CEL `format` library: named validators returning apimachinery's messages.

use std::sync::OnceLock;

use regex::Regex;

use super::url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Dns1123Label,
    Dns1123Subdomain,
    Dns1035Label,
    QualifiedName,
    Dns1123LabelPrefix,
    Dns1123SubdomainPrefix,
    Dns1035LabelPrefix,
    LabelValue,
    Uri,
    Uuid,
    Byte,
    Date,
    DateTime,
}

impl Format {
    pub(crate) fn named(name: &str) -> Option<Format> {
        Some(match name {
            "dns1123Label" => Format::Dns1123Label,
            "dns1123Subdomain" => Format::Dns1123Subdomain,
            "dns1035Label" => Format::Dns1035Label,
            "qualifiedName" => Format::QualifiedName,
            "dns1123LabelPrefix" => Format::Dns1123LabelPrefix,
            "dns1123SubdomainPrefix" => Format::Dns1123SubdomainPrefix,
            "dns1035LabelPrefix" => Format::Dns1035LabelPrefix,
            "labelValue" => Format::LabelValue,
            "uri" => Format::Uri,
            "uuid" => Format::Uuid,
            "byte" => Format::Byte,
            "date" => Format::Date,
            "datetime" => Format::DateTime,
            _ => return None,
        })
    }

    /// Validation failures; empty when `s` conforms.
    pub(crate) fn validate(self, s: &str) -> Vec<String> {
        match self {
            Format::Dns1123Label => is_dns1123_label(s),
            Format::Dns1123Subdomain => is_dns1123_subdomain(s),
            Format::Dns1035Label => is_dns1035_label(s),
            Format::QualifiedName => is_qualified_name(s),
            Format::Dns1123LabelPrefix => is_dns1123_label(&mask_trailing_dash(s)),
            Format::Dns1123SubdomainPrefix => is_dns1123_subdomain(&mask_trailing_dash(s)),
            Format::Dns1035LabelPrefix => is_dns1035_label(&mask_trailing_dash(s)),
            Format::LabelValue => is_valid_label_value(s),
            Format::Uri => Url::request_uri_error(s).into_iter().collect(),
            Format::Uuid => {
                if uuid_re().is_match(s) {
                    vec![]
                } else {
                    vec!["does not match the UUID format".into()]
                }
            }
            Format::Byte => {
                if base64_std_valid(s) {
                    vec![]
                } else {
                    vec!["invalid base64".into()]
                }
            }
            Format::Date => {
                if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok() && s.len() == 10 {
                    vec![]
                } else {
                    vec!["invalid date".into()]
                }
            }
            Format::DateTime => {
                if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                    vec![]
                } else {
                    vec!["invalid datetime".into()]
                }
            }
        }
    }
}

fn mask_trailing_dash(s: &str) -> String {
    match s.strip_suffix('-') {
        Some(rest) if !s.is_empty() => format!("{rest}a"),
        _ => s.to_string(),
    }
}

fn regex_error(msg: &str, fmt: &str, examples: &[&str]) -> String {
    let mut out = format!("{msg} (e.g. ");
    for (i, e) in examples.iter().enumerate() {
        if i > 0 {
            out.push_str(" or ");
        }
        out.push_str(&format!("'{e}', "));
    }
    out.push_str(&format!("regex used for validation is '{fmt}')"));
    out
}

fn max_len_error(n: usize) -> String {
    format!("must be no more than {n} characters")
}

const DNS1123_LABEL_FMT: &str = "[a-z0-9]([-a-z0-9]*[a-z0-9])?";
const DNS1123_LABEL_MSG: &str = "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character";
const DNS1123_SUBDOMAIN_FMT: &str =
    "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*";
const DNS1123_SUBDOMAIN_MSG: &str = "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character";
const DNS1035_LABEL_FMT: &str = "[a-z]([-a-z0-9]*[a-z0-9])?";
const DNS1035_LABEL_MSG: &str = "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character";
const QUALIFIED_NAME_FMT: &str = "([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]";
const QUALIFIED_NAME_MSG: &str = "must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character";
const LABEL_VALUE_FMT: &str = "(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?";
const LABEL_VALUE_MSG: &str = "a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character";

fn anchored(fmt: &str) -> Regex {
    Regex::new(&format!("^(?:{fmt})$")).expect("static pattern")
}

fn dns1123_label_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(DNS1123_LABEL_FMT))
}

fn dns1123_subdomain_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(DNS1123_SUBDOMAIN_FMT))
}

fn dns1035_label_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(DNS1035_LABEL_FMT))
}

fn qualified_name_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(QUALIFIED_NAME_FMT))
}

fn label_value_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| anchored(LABEL_VALUE_FMT))
}

fn uuid_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            "(?i)(^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)|(^[0-9a-f]{32}$)",
        )
        .expect("static pattern")
    })
}

pub(super) fn is_dns1123_label(v: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if v.len() > 63 {
        errs.push(max_len_error(63));
    }
    if !dns1123_label_re().is_match(v) {
        if dns1123_subdomain_re().is_match(v) {
            errs.push("must not contain dots".into());
        } else {
            errs.push(regex_error(
                DNS1123_LABEL_MSG,
                DNS1123_LABEL_FMT,
                &["my-name", "123-abc"],
            ));
        }
    }
    errs
}

pub(super) fn is_dns1123_subdomain(v: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if v.len() > 253 {
        errs.push(max_len_error(253));
    }
    if !dns1123_subdomain_re().is_match(v) {
        errs.push(regex_error(
            DNS1123_SUBDOMAIN_MSG,
            DNS1123_SUBDOMAIN_FMT,
            &["example.com"],
        ));
    }
    errs
}

fn is_dns1035_label(v: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if v.len() > 63 {
        errs.push(max_len_error(63));
    }
    if !dns1035_label_re().is_match(v) {
        errs.push(regex_error(
            DNS1035_LABEL_MSG,
            DNS1035_LABEL_FMT,
            &["my-name", "abc-123"],
        ));
    }
    errs
}

fn is_qualified_name(v: &str) -> Vec<String> {
    let mut errs = Vec::new();
    let parts: Vec<&str> = v.split('/').collect();
    let name = match parts.as_slice() {
        [name] => *name,
        [prefix, name] => {
            if prefix.is_empty() {
                errs.push("prefix part must be non-empty".into());
            } else {
                for m in is_dns1123_subdomain(prefix) {
                    errs.push(format!("prefix part {m}"));
                }
            }
            *name
        }
        _ => {
            errs.push(format!(
                "a qualified name {} with an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyName')",
                regex_error(
                    QUALIFIED_NAME_MSG,
                    QUALIFIED_NAME_FMT,
                    &["MyName", "my.name", "123-abc"]
                )
            ));
            return errs;
        }
    };
    if name.is_empty() {
        errs.push("name part must be non-empty".into());
    } else if name.len() > 63 {
        errs.push(format!("name part {}", max_len_error(63)));
    }
    if !qualified_name_re().is_match(name) {
        errs.push(format!(
            "name part {}",
            regex_error(
                QUALIFIED_NAME_MSG,
                QUALIFIED_NAME_FMT,
                &["MyName", "my.name", "123-abc"]
            )
        ));
    }
    errs
}

fn is_valid_label_value(v: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if v.len() > 63 {
        errs.push(max_len_error(63));
    }
    if !label_value_re().is_match(v) {
        errs.push(regex_error(
            LABEL_VALUE_MSG,
            LABEL_VALUE_FMT,
            &["MyValue", "my_value", "12345"],
        ));
    }
    errs
}

/// Whether `s` is standard, padded base64.
fn base64_std_valid(s: &str) -> bool {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conforming_names_have_no_errors() {
        assert!(Format::Dns1123Label.validate("my-label-name").is_empty());
        assert!(Format::Dns1123Subdomain
            .validate("apiextensions.k8s.io")
            .is_empty());
        assert!(Format::QualifiedName
            .validate("apiextensions.k8s.io/v1beta1")
            .is_empty());
        assert!(Format::Dns1123LabelPrefix
            .validate("my-label-prefix-")
            .is_empty());
        assert!(Format::Uuid
            .validate("123e4567-e89b-12d3-a456-426614174000")
            .is_empty());
        assert!(Format::Byte.validate("aGVsbG8=").is_empty());
        assert!(Format::Date.validate("2021-01-01").is_empty());
        assert!(Format::DateTime.validate("2021-01-01T00:00:00Z").is_empty());
        assert!(Format::Uri.validate("http://example.com").is_empty());
    }

    #[test]
    fn nonconforming_values_report_apimachinery_text() {
        let errs = Format::Dns1123Label.validate("contains a space");
        assert_eq!(errs.len(), 1);
        assert!(errs[0].starts_with("a lowercase RFC 1123 label must consist of"));
        assert!(errs[0].contains("(e.g. 'my-name',  or '123-abc', regex used for validation is"));
        assert_eq!(Format::Byte.validate("aGVsbG8"), vec!["invalid base64"]);
        assert_eq!(Format::Date.validate("2020-01-32"), vec!["invalid date"]);
        assert_eq!(
            Format::DateTime.validate("2020-01-32T00:00:00Z"),
            vec!["invalid datetime"]
        );
    }

    #[test]
    fn dotted_label_is_called_out() {
        assert_eq!(
            Format::Dns1123Label.validate("a.b"),
            vec!["must not contain dots"]
        );
    }
}
