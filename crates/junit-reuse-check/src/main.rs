/// CLI wrapper around u7s_junit_reuse_check: decides whether a prior
/// sonobuoy junit result can stand in for a fresh conformance run for the
/// given focus and sensitive file(s).
///
/// Usage:
///   u7s-junit-reuse-check --repo-root <path> --focus <string> \
///       --ref <sha> --file <path> [--file <path> ...]
///
/// `--ref` must be the actual ref/SHA being pushed (git pre-push hook
/// protocol's `<local sha1>`), never a caller-side stand-in for "whatever is
/// checked out" -- see GitFreshnessCheck::pushed_ref in the lib for why.
///
/// On success (a reusable result was found): prints its path to stdout on
/// its own line, everything else to stderr, exits 0.
/// On failure (no reusable result, or a usage error): exits non-zero. The
/// caller (scripts/sensitive-conformance-gate.sh) must treat ANY non-zero
/// exit as "require a fresh run" -- this binary never distinguishes
/// "genuinely no match" from "couldn't tell" in its exit code, because both
/// need the same fail-safe response.
use std::path::PathBuf;
use std::process::ExitCode;

use u7s_junit_reuse_check::{
    find_junit_candidates, parse_junit, select_reusable, Candidate, GitFreshnessCheck,
};

fn usage() -> &'static str {
    "usage: u7s-junit-reuse-check --repo-root <path> --focus <string> --ref <sha> --file <path> [--file <path> ...]"
}

fn main() -> ExitCode {
    let mut repo_root: Option<PathBuf> = None;
    let mut focus: Option<String> = None;
    let mut pushed_ref: Option<String> = None;
    let mut files: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo-root" => match args.next() {
                Some(v) => repo_root = Some(PathBuf::from(v)),
                None => {
                    eprintln!("error: --repo-root requires a value\n{}", usage());
                    return ExitCode::FAILURE;
                }
            },
            "--focus" => match args.next() {
                Some(v) => focus = Some(v),
                None => {
                    eprintln!("error: --focus requires a value\n{}", usage());
                    return ExitCode::FAILURE;
                }
            },
            "--ref" => match args.next() {
                Some(v) => pushed_ref = Some(v),
                None => {
                    eprintln!("error: --ref requires a value\n{}", usage());
                    return ExitCode::FAILURE;
                }
            },
            "--file" => match args.next() {
                Some(v) => files.push(v),
                None => {
                    eprintln!("error: --file requires a value\n{}", usage());
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("error: unknown argument {other:?}\n{}", usage());
                return ExitCode::FAILURE;
            }
        }
    }

    let (Some(repo_root), Some(focus), Some(pushed_ref)) = (repo_root, focus, pushed_ref) else {
        eprintln!(
            "error: --repo-root, --focus, and --ref are required\n{}",
            usage()
        );
        return ExitCode::FAILURE;
    };
    if files.is_empty() {
        eprintln!("error: at least one --file is required\n{}", usage());
        return ExitCode::FAILURE;
    }

    let candidate_paths = find_junit_candidates(&repo_root);
    if candidate_paths.is_empty() {
        eprintln!(
            "[junit-reuse-check] no junit_01.xml found under {}/temp/e2e/*/plugins/e2e/results/global/ -- fresh run required",
            repo_root.display()
        );
        return ExitCode::FAILURE;
    }

    let mut candidates = Vec::new();
    for path in candidate_paths {
        let xml = match std::fs::read_to_string(&path) {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "[junit-reuse-check] skipping {} (unreadable: {e})",
                    path.display()
                );
                continue;
            }
        };
        match parse_junit(&xml) {
            Ok(summary) => {
                eprintln!(
                    "[junit-reuse-check] candidate {}: focus={:?} failures={} errors={} timestamp={}",
                    path.display(),
                    summary.focus_strings,
                    summary.failures,
                    summary.errors,
                    summary.timestamp
                );
                candidates.push(Candidate { path, summary });
            }
            Err(e) => {
                eprintln!(
                    "[junit-reuse-check] skipping {} (unparseable: {e})",
                    path.display()
                );
            }
        }
    }

    if candidates.is_empty() {
        eprintln!("[junit-reuse-check] no parseable candidates -- fresh run required");
        return ExitCode::FAILURE;
    }

    let checker = GitFreshnessCheck {
        repo_root: repo_root.clone(),
        pushed_ref,
    };
    match select_reusable(&candidates, &focus, &files, &checker) {
        Some(chosen) => {
            eprintln!(
                "[junit-reuse-check] REUSE: {} (focus matches required {:?}, failures=0 errors=0, no uncommitted/newer changes to: {})",
                chosen.path.display(),
                focus,
                files.join(", ")
            );
            println!("{}", chosen.path.display());
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("[junit-reuse-check] no reusable prior result -- fresh run required");
            ExitCode::FAILURE
        }
    }
}
