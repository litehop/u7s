//! `pattern` parity with upstream. Upstream kube-openapi compiles `pattern` with Go's
//! `regexp` (RE2); `testdata/crd_pattern_parity.json` holds, per pattern, whether Go 1.26.3
//! `regexp.Compile` accepted it and what `MatchString` returned for each input. A divergence
//! means u7s admits a CR upstream rejects (or the reverse), or accepts a CRD upstream
//! rejects (or the reverse).

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    pattern: String,
    inputs: Vec<String>,
    go_compiles: bool,
    go_matches: Vec<bool>,
}

fn corpus() -> Vec<Case> {
    serde_json::from_str(include_str!("testdata/crd_pattern_parity.json")).unwrap()
}

fn production(pattern: &str) -> Result<jsonschema::Validator, String> {
    super::crd::build_schema_validator(&serde_json::json!({"type": "string", "pattern": pattern}))
}

/// Why the case differs from Go. The test asserts exactly this set, so an entry that stops
/// diverging (or a new divergence) fails it.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[
    (
        "shorthand_s",
        "`\\s` is Unicode White_Space; Go's is [\\t\\n\\f\\r ]",
    ),
    ("word_boundary", "`\\b` is Unicode; Go's is ASCII"),
    ("flag_s_dot", "ECMA has no `(?s)`; `.` stays non-newline"),
    ("posix_class", "ECMA has no `[[:alpha:]]`"),
    ("posix_class_neg", "ECMA has no `[[:^digit:]]`"),
    ("escape_bell_a", "ECMA has no `\\a`"),
    ("quote_Q_E", "no `\\Q..\\E` in ECMA or regex"),
    ("escape_ctrl_cA", "ECMA `\\cA` accepted; Go rejects"),
    ("escape_u_ecma", "ECMA `\\u0041` accepted; Go rejects"),
    (
        "escape_lt_gt",
        "regex `\\<` `\\>` are word boundaries; Go treats them as literals",
    ),
    ("possessive", "`a++` accepted; Go rejects"),
    ("repeat_1001", "Go caps a repeat count at 1000"),
    (
        "repeat_nested_big",
        "Go caps the nested repeat product at 1000",
    ),
    (
        "repeat_lower_missing",
        "Go treats `{,3}` as literal text; regex rejects it",
    ),
    (
        "repeat_unicode_class_244",
        "compiles past the 1 MiB per-pattern limit on purpose",
    ),
];

fn diverges(c: &Case) -> bool {
    match (production(&c.pattern), c.go_compiles) {
        (Ok(_), false) | (Err(_), true) => true,
        (Err(_), false) => false,
        (Ok(v), true) => {
            let got: Vec<bool> = c
                .inputs
                .iter()
                .map(|i| v.is_valid(&serde_json::Value::String(i.clone())))
                .collect();
            got != c.go_matches
        }
    }
}

#[test]
fn crd_pattern_verdicts_match_go_regexp_except_the_documented_divergences() {
    let mut actual: Vec<String> = corpus()
        .iter()
        .filter(|c| diverges(c))
        .map(|c| c.name.clone())
        .collect();
    let mut expected: Vec<String> = KNOWN_DIVERGENCES
        .iter()
        .map(|(n, _)| n.to_string())
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "a pattern CRs are validated with must behave as under upstream's Go regexp: a new \
         divergence admits or rejects objects upstream would not; a vanished one means the \
         documented list is stale"
    );
}

/// Real CRDs ship this 1199-byte pattern (Cilium `ciliumbgpclusterconfigs`); it must build
/// under the per-pattern limit and classify addresses exactly as Go does.
#[test]
fn real_cilium_1199_byte_pattern_builds_and_matches_like_go() {
    let c = corpus()
        .into_iter()
        .find(|c| c.name == "cilium_bgp_ip_1199B")
        .unwrap();
    assert_eq!(c.pattern.len(), 1199);
    assert!(
        !diverges(&c),
        "Cilium's IP pattern must agree with Go on every sample input"
    );
}

/// Go's `\w`/`\d` are ASCII. With the engine's own (Unicode) syntax `^\w{1,253}$` needs
/// ~16 MiB, so a common DNS-name pattern would be rejected as too large.
#[test]
fn ascii_shorthand_patterns_common_in_crds_stay_under_the_size_limit() {
    for p in [
        "^\\w{1,253}$",
        "^[\\w-]{1,253}$",
        "^\\d{1,64}$",
        "^(\\d{1,3}\\.){3}\\d{1,3}$",
    ] {
        production(p).unwrap_or_else(|e| panic!("{p} must build: {e}"));
    }
}
