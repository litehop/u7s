//! Measurement-only: compile cost of CRD `pattern` regexes through boon.
//! Run with `cargo test -p apiserver --release crd_pattern_cost -- --ignored --nocapture`.

use std::time::{Duration, Instant};

use super::crd::MAX_CRD_PATTERN_BYTES;

const WALL_CAP: Duration = Duration::from_secs(120);
const STOP_AFTER: Duration = Duration::from_secs(15);

fn max_rss_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let raw = ru.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        raw / (1024.0 * 1024.0)
    } else {
        raw / 1024.0
    }
}

fn compile(patterns: &[String]) -> (Duration, Result<(), String>) {
    let mut props = serde_json::Map::new();
    for (i, p) in patterns.iter().enumerate() {
        props.insert(
            format!("f{i}"),
            serde_json::json!({ "type": "string", "pattern": p }),
        );
    }
    let schema = serde_json::json!({ "type": "object", "properties": props });
    let start = Instant::now();
    let res = crate::cel_runtime::format::on_compile_stack(|| {
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler
            .add_resource("schema.json", schema)
            .map_err(|e| e.to_string())?;
        compiler
            .compile("schema.json", &mut schemas)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    (start.elapsed(), res)
}

fn short(e: &str) -> String {
    e.chars().take(70).collect()
}

fn sweep(name: &str, sizes: &[usize], build: impl Fn(usize) -> String) {
    let global = Instant::now();
    for &n in sizes {
        let p = build(n);
        assert!(
            p.len() <= MAX_CRD_PATTERN_BYTES,
            "{name} n={n} len={}",
            p.len()
        );
        let (t, res) = compile(std::slice::from_ref(&p));
        let outcome = match &res {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("err: {}", short(e)),
        };
        eprintln!(
            "POC {name} n={n} len={} time={:.1}ms peak_rss={:.0}MiB {outcome}",
            p.len(),
            t.as_secs_f64() * 1e3,
            max_rss_mib()
        );
        if t > STOP_AFTER || global.elapsed() > WALL_CAP {
            eprintln!("POC {name} stopping: cost exceeded cap");
            break;
        }
    }
}

fn schema_with(patterns: &[&str]) -> serde_json::Value {
    let props: serde_json::Map<_, _> = patterns
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                format!("f{i}"),
                serde_json::json!({"type": "string", "pattern": p}),
            )
        })
        .collect();
    serde_json::json!({ "type": "object", "properties": props })
}

/// An 8-byte `\pL{244}` is under boon's 10 MiB default yet costs ~15 MiB resident per
/// property; a CRD repeating it must be refused at admission instead of letting the
/// first CR write pay seconds and GiB.
#[test]
fn pattern_over_nfa_budget_is_rejected_even_when_short() {
    let schema = schema_with(&["\\pL{244}"]);
    let err = super::crd::check_pattern_compile_budget(&schema, "s", &mut 0)
        .expect_err("a pattern that compiles past the NFA budget must be rejected");
    let json = serde_json::to_value(&err.1).unwrap();
    assert_eq!(json["code"], 422);
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("s.properties.f0.pattern"));
}

/// Real CRDs use these shapes; the budget must not become a kubectl-compat regression.
#[test]
fn realistic_patterns_stay_within_nfa_budget() {
    let schema = schema_with(&[
        "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
        "^\\d{1,64}$",
        "^\\w{1,253}$",
        "^[a-z]{1,63}$",
        "^(\\d{1,3}\\.){3}\\d{1,3}(/\\d{1,2})?$",
        "(unclosed",
    ]);
    super::crd::check_pattern_compile_budget(&schema, "s", &mut 0)
        .expect("ordinary patterns, and invalid ones (left to boon), must pass");
}

/// Each `\pL{20}` compiles to ~0.8 MiB, under the 1 MiB per-pattern cap.
const SUBCAP_PATTERN: &str = "\\pL{20}";

/// Every property a CRD declares keeps its own compiled regex resident, so ten patterns
/// that each pass the per-pattern cap can still pin ~8.6 MiB; without the aggregate
/// bound one CRD could retain GiBs, and the same pattern repeated counts every time
/// because boon compiles each occurrence separately.
#[test]
fn sum_of_subcap_patterns_over_total_budget_is_rejected_with_path_and_totals() {
    let schema = schema_with(&[SUBCAP_PATTERN; 10]);
    let err = super::crd::check_pattern_compile_budget(&schema, "s", &mut 0)
        .expect_err("ten sub-cap patterns summing past 8 MiB must be rejected");
    let json = serde_json::to_value(&err.1).unwrap();
    assert_eq!(json["code"], 422);
    let msg = json["message"].as_str().unwrap();
    assert!(msg.contains("s.properties.f9.pattern"), "{msg}");
    assert!(
        msg.contains("CRD pattern compile budget exceeded (8.2 MiB > 8.0 MiB)"),
        "{msg}"
    );
}

#[test]
fn sum_under_total_budget_is_accepted() {
    let schema = schema_with(&[SUBCAP_PATTERN; 9]);
    let mut total = 0;
    super::crd::check_pattern_compile_budget(&schema, "s", &mut total)
        .expect("nine sub-cap patterns stay under 8 MiB");
    assert!(
        total > 7 << 20,
        "total must actually be accumulated: {total}"
    );
}

/// Representative of Cilium CiliumNetworkPolicy, the largest real CRD measured: many
/// copies of CIDR / FQDN / port patterns. Must stay far below the budget so real
/// installs keep working.
#[test]
fn cilium_style_pattern_set_is_accepted_with_headroom() {
    let distinct = [
        "^([-a-zA-Z0-9_]+[.]?)+$",
        "^[-a-zA-Z0-9_*]+([.][-a-zA-Z0-9_*]+)*[.]?$",
        "^(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/(?:3[0-2]|[12]?[0-9]))$",
        "^([0-9]{1,5}|[a-z][a-z0-9-]{0,14}[a-z0-9])$",
        "^[a-zA-Z0-9]([-a-zA-Z0-9_.]*[a-zA-Z0-9])?$",
        "^(\\d{1,3}\\.){3}\\d{1,3}$",
        "^[0-9a-fA-F:]+(/\\d{1,3})?$",
    ];
    let patterns: Vec<&str> = (0..140).map(|i| distinct[i % distinct.len()]).collect();
    let schema = schema_with(&patterns);
    let mut total = 0;
    super::crd::check_pattern_compile_budget(&schema, "s", &mut total)
        .expect("a Cilium-style pattern set must be accepted");
    assert!(
        total * 4 < super::crd::MAX_CRD_PATTERN_TOTAL_NFA_BYTES,
        "expected generous headroom, got {total}"
    );
}

#[test]
#[ignore = "measurement only; run with --ignored --nocapture"]
fn measure_single_pattern_compile_cost() {
    sweep("pL{n}", &[10, 100, 130, 160, 200, 250, 1000], |n| {
        format!("\\pL{{{n}}}")
    });
    sweep("(pL{n}){2}", &[10, 100, 500, 1000], |n| {
        format!("(\\pL{{{n}}}){{2}}")
    });
    sweep("w{n}", &[10, 100, 500, 1000], |n| format!("\\w{{{n}}}"));
    sweep(".{n}", &[10, 100, 500, 1000], |n| format!(".{{{n}}}"));
    sweep("(pL{10}){n}", &[10, 100, 500, 1000], |n| {
        format!("(\\pL{{10}}){{{n}}}")
    });
    sweep("nested-3x1000", &[1], |_| {
        "((\\pL{1000}){1000}){1000}".to_string()
    });
    sweep("pL{1000}xn", &[5, 20, 50, 113], |n| "\\pL{1000}".repeat(n));
    sweep("alt-classes", &[10, 50, 100], |n| {
        vec!["[\\pL\\pN]"; n].join("|")
    });
    sweep("a?^n a^n", &[10, 100, 340], |n| {
        format!("{}{}", "a?".repeat(n), "a".repeat(n))
    });
    sweep("(((pL)))nest", &[10, 100, 240], |n| {
        format!("{}\\pL{}", "(".repeat(n), ")".repeat(n))
    });
}

#[test]
#[ignore = "measurement only; run with --ignored --nocapture"]
fn measure_many_pattern_crd_compile_cost() {
    let realistic =
        "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$".to_string();
    let (mut lo, mut hi) = (1usize, 1000usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if compile(&[format!("\\pL{{{mid}}}")]).1.is_ok() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    eprintln!("POC largest compiling \\pL{{n}}: n={lo}");
    let global = Instant::now();
    for (label, p) in [
        ("realistic", realistic),
        ("pL{max}", format!("\\pL{{{lo}}}")),
        ("pL{max/2}", format!("\\pL{{{}}}", lo / 2)),
    ] {
        for count in [10usize, 50, 200] {
            let pats = vec![p.clone(); count];
            let (t, res) = compile(&pats);
            eprintln!(
                "POC many {label} len={} count={count} time={:.1}ms peak_rss={:.0}MiB {:?}",
                p.len(),
                t.as_secs_f64() * 1e3,
                max_rss_mib(),
                res.as_ref().map_err(|e| short(e))
            );
            if t > STOP_AFTER || global.elapsed() > WALL_CAP {
                break;
            }
        }
    }
}
