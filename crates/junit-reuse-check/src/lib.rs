/// u7s-junit-reuse-check — decides whether a prior sonobuoy junit_01.xml
/// result can stand in for a fresh conformance run.
///
/// Used by scripts/sensitive-conformance-gate.sh (invoked from
/// .githooks/pre-push) to avoid re-running an expensive live-VM sonobuoy
/// focus for a push whose sensitive file(s) were already verified by a
/// still-valid, still-passing result on disk. See that script's own header
/// comment for the full mechanism.
///
/// This is a SAFETY-relevant gate: every function here must fail toward
/// "not reusable" (forcing the caller back onto a fresh, expensive run)
/// whenever the evidence is missing, malformed, or ambiguous. Never fail
/// toward silently reusing a result that might not actually cover the
/// pushed change.
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The fields of a ginkgo/sonobuoy junit_01.xml this tool cares about,
/// pulled from the report's single inner `<testsuite>` element (the
/// `<testsuites>` root repeats totals but not the run's own `timestamp` or
/// `<properties>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JunitSummary {
    /// Exact value of the run's `<property name="FocusStrings" value="...">`
    /// -- the ginkgo focus regex the run was invoked with.
    pub focus_strings: String,
    pub failures: u64,
    pub errors: u64,
    /// The `<testsuite timestamp="...">` attribute, e.g.
    /// `"2026-08-26T04:32:14"` -- ginkgo/sonobuoy emit this with NO UTC
    /// offset. It is forwarded to `git log --since=<timestamp>` by
    /// `GitFreshnessCheck`, which appends an explicit `+00:00` before doing
    /// so (see `git_log_since_is_empty`): the sonobuoy e2e pod runs with no
    /// TZ override on a stock Ubuntu-cloud-image Lima VM (both default to
    /// UTC -- see lima/kubelet.yaml and scripts/conformance/04-start-kcm.sh's
    /// own explicit `TZ=UTC`), so this value denotes UTC wall-clock time.
    /// Treating it as bare/local would make `git --since` resolve it in
    /// whatever timezone the machine RUNNING THE HOOK happens to be
    /// configured for -- which is the HOST, not the VM that generated the
    /// timestamp -- silently shifting the freshness cutoff by the host/VM
    /// offset on any host not itself set to UTC.
    pub timestamp: String,
}

#[derive(Debug)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parses `failures`, `errors`, `timestamp`, and the `FocusStrings` property
/// out of a ginkgo-generated junit_01.xml document.
///
/// Deliberately NOT a general XML parser -- pulling in an XML crate for one
/// narrowly-shaped, machine-generated file (see u7s-kubeconfig's own
/// hand-rolled YAML field extraction for the same rationale) is more
/// dependency surface than this needs. This depends on ginkgo's junit
/// reporter producing exactly one inner `<testsuite ...>` element (the outer
/// `<testsuites ...>` is skipped by matching "<testsuite " with a trailing
/// space -- "<testsuites " never matches that pattern because "testsuite" is
/// followed by 's', not a space) with a `timestamp` attribute and a
/// `<property name="FocusStrings" value="...">` child. Any deviation is a
/// parse error, not a best-effort guess: a caller that can't parse the file
/// must treat it as non-reusable, never as an ambiguous pass.
pub fn parse_junit(xml: &str) -> Result<JunitSummary, ParseError> {
    let testsuite_start = xml
        .find("<testsuite ")
        .ok_or_else(|| ParseError("no <testsuite> element found".to_string()))?;
    let tag_end = xml[testsuite_start..]
        .find('>')
        .map(|i| testsuite_start + i)
        .ok_or_else(|| ParseError("<testsuite> element has no closing '>'".to_string()))?;
    let tag = &xml[testsuite_start..tag_end];

    let failures = extract_attr(tag, "failures")
        .ok_or_else(|| ParseError("<testsuite> missing failures attribute".to_string()))?;
    let failures: u64 = failures
        .parse()
        .map_err(|_| ParseError(format!("failures attribute not a number: {failures:?}")))?;

    let errors = extract_attr(tag, "errors")
        .ok_or_else(|| ParseError("<testsuite> missing errors attribute".to_string()))?;
    let errors: u64 = errors
        .parse()
        .map_err(|_| ParseError(format!("errors attribute not a number: {errors:?}")))?;

    let timestamp = extract_attr(tag, "timestamp")
        .ok_or_else(|| ParseError("<testsuite> missing timestamp attribute".to_string()))?;

    // Bound the FocusStrings search to this testsuite's own body (up to its
    // closing tag, or end of document if truncated) so a document with more
    // than one <testsuite> -- never produced by ginkgo today, but not worth
    // trusting blindly -- can't pick up a property from the wrong one.
    let body_start = tag_end;
    let body_end = xml[body_start..]
        .find("</testsuite>")
        .map(|i| body_start + i)
        .unwrap_or(xml.len());
    let body = &xml[body_start..body_end];

    let focus_strings = extract_property(body, "FocusStrings")
        .ok_or_else(|| ParseError("no FocusStrings property found".to_string()))?;

    Ok(JunitSummary {
        focus_strings,
        failures,
        errors,
        timestamp,
    })
}

/// Finds `name="<value>"` inside `tag` and returns the unescaped value.
fn extract_attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = start + tag[start..].find('"')?;
    Some(unescape_xml(&tag[start..end]))
}

/// Finds `<property name="<name>" value="<value>">` inside `body` and
/// returns the unescaped value.
fn extract_property(body: &str, name: &str) -> Option<String> {
    let needle = format!("<property name=\"{name}\" value=\"");
    let start = body.find(&needle)? + needle.len();
    let end = start + body[start..].find('"')?;
    Some(unescape_xml(&body[start..end]))
}

/// Decodes the 5 predefined XML entities. Safe to apply in any order here:
/// none of `&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;` is a substring of
/// another (they differ at the 2nd character), so replacing one can't create
/// or destroy an occurrence of another.
fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

/// True if `summary` records a clean run: `failures="0" errors="0"`. A
/// nonzero count means the focus regex matched specs that failed -- reusing
/// that result would let a push through on the strength of a run that did
/// NOT actually pass.
pub fn is_clean_pass(summary: &JunitSummary) -> bool {
    summary.failures == 0 && summary.errors == 0
}

/// A candidate prior junit result: where it came from, and what it says.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub summary: JunitSummary,
}

/// Locates every `<repo_root>/temp/e2e/*/plugins/e2e/results/global/
/// junit_01.xml` -- the layout scripts/conformance/06-run-sonobuoy.sh writes
/// each unpacked run to. Missing/unreadable `temp/e2e/` is not an error --
/// it just means there are no candidates, so the caller falls back to a
/// fresh run.
pub fn find_junit_candidates(repo_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let e2e_dir = repo_root.join("temp/e2e");
    let Ok(entries) = std::fs::read_dir(&e2e_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let candidate = entry.path().join("plugins/e2e/results/global/junit_01.xml");
        if candidate.is_file() {
            out.push(candidate);
        }
    }
    out
}

/// Determines whether `file`, as of right now, is still accurately
/// represented by a junit result recorded at `since_timestamp`.
///
/// `Ok(false)` means a genuinely newer edit exists (uncommitted, or a commit
/// landed after the run started) -- the result is stale for this file.
/// `Err` means the check itself couldn't be completed (e.g. git failed to
/// run) -- callers MUST treat this the same as `Ok(false)`, never as
/// "assume fresh".
pub trait FreshnessCheck {
    fn is_fresh(&self, file: &str, since_timestamp: &str) -> Result<bool, String>;
}

/// Real `FreshnessCheck` backed by the actual git repository at `repo_root`.
pub struct GitFreshnessCheck {
    pub repo_root: PathBuf,
    /// The actual ref/SHA being pushed (git pre-push hook protocol's
    /// `<local sha1>`), e.g. as read by `.githooks/pre-push`'s `while read
    /// local_ref local_oid remote_ref remote_oid` loop. Deliberately NOT
    /// derived from implicit `HEAD`: `HEAD` is whatever the checkout
    /// happens to have out right now, which is NOT necessarily what's being
    /// pushed -- e.g. `git push origin feature-b:main` while `main` is
    /// checked out locally. Using implicit HEAD here would walk the WRONG
    /// branch's history, making a real regression on the pushed branch
    /// invisible to this freshness check.
    pub pushed_ref: String,
}

impl FreshnessCheck for GitFreshnessCheck {
    fn is_fresh(&self, file: &str, since_timestamp: &str) -> Result<bool, String> {
        if !git_diff_quiet(&self.repo_root, &self.pushed_ref, file)? {
            return Ok(false);
        }
        git_log_since_is_empty(&self.repo_root, &self.pushed_ref, file, since_timestamp)
    }
}

/// `GIT_*` environment variables that, if inherited from an enclosing git
/// process, silently override `-C <dir>` and redirect git's chosen
/// repository/working-tree elsewhere -- most notably `GIT_DIR`, which per
/// git's own docs takes precedence over the `-C`-selected directory's
/// discovered `.git`. This binary runs from INSIDE a git hook
/// (`.githooks/pre-push` -> scripts/sensitive-conformance-gate.sh ->
/// u7s-junit-reuse-check), which git itself may export these into, so every
/// `git` subprocess spawned below clears them first -- otherwise `repo_root`
/// (the explicit argument this whole safety story depends on) could be
/// silently ignored in favor of whatever the enclosing hook invocation's
/// environment happens to point at.
fn git_command() -> Command {
    let mut cmd = Command::new("git");
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Runs `git diff --quiet <pushed_ref> -- <file>`. Ok(true) = the working
/// tree's current copy of `file` is identical to what's in `pushed_ref`'s
/// tree for that path -- i.e. nothing about `file` has diverged from the
/// commit actually being pushed. Any exit code other than 0/1 (git itself
/// failing, e.g. not a repo or an unresolvable ref) is an error, not a
/// guess.
fn git_diff_quiet(repo_root: &Path, pushed_ref: &str, file: &str) -> Result<bool, String> {
    let status = git_command()
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--quiet", pushed_ref, "--", file])
        .status()
        .map_err(|e| format!("failed to run git diff: {e}"))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => Err(format!(
            "git diff --quiet {pushed_ref} -- {file} exited with unexpected code {other:?}"
        )),
    }
}

/// Runs `git log --since=<since_timestamp UTC> --oneline <pushed_ref> --
/// <file>`. Ok(true) = no commit reachable from `pushed_ref` touched `file`
/// on/after `since_timestamp`.
///
/// `since_timestamp` (the literal junit `timestamp` attribute -- see this
/// module's doc comment on `JunitSummary::timestamp`) has no UTC offset, so
/// an explicit `+00:00` is appended before handing it to git: `--since`
/// resolves an offset-less string in the CALLING PROCESS's own local
/// timezone, which is the host running this hook, not the VM that generated
/// the timestamp. Without the explicit offset, a host not itself configured
/// for UTC would silently shift the effective cutoff by the host/VM
/// timezone difference -- in the worst case shifting it LATER, which can
/// make a genuinely-stale result (a regression committed after the real
/// cutoff) look fresh.
///
/// The revision is `pushed_ref`, not implicit `HEAD` -- see
/// `GitFreshnessCheck::pushed_ref` doc comment for why that distinction is
/// safety-critical here.
fn git_log_since_is_empty(
    repo_root: &Path,
    pushed_ref: &str,
    file: &str,
    since_timestamp: &str,
) -> Result<bool, String> {
    let since_utc = format!("{since_timestamp}+00:00");
    let output = git_command()
        .arg("-C")
        .arg(repo_root)
        .args([
            "log",
            &format!("--since={since_utc}"),
            "--oneline",
            pushed_ref,
            "--",
            file,
        ])
        .output()
        .map_err(|e| format!("failed to run git log: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git log --since={since_utc} {pushed_ref} -- {file} exited with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout.iter().all(u8::is_ascii_whitespace))
}

/// Picks the best reusable candidate for `required_focus` across `files`, or
/// `None` if none qualifies (caller must then require a fresh run).
///
/// A candidate qualifies only if ALL of:
///   - it is a clean pass (`is_clean_pass`)
///   - its FocusStrings is an EXACT match for `required_focus` (byte-for-byte
///     -- not a superset/subset/regex-equivalence check, since anything
///     looser risks reusing a result that covered a different, possibly
///     narrower, set of specs than the push actually needs)
///   - `freshness.is_fresh(..)` returns `Ok(true)` for every file in `files`
///
/// Candidates are tried newest-timestamp-first (lexicographic compare is
/// correct here: junit timestamps are ISO-8601-ish and monotonically
/// sortable as strings) so the freshest available evidence wins when more
/// than one candidate qualifies.
pub fn select_reusable<'a>(
    candidates: &'a [Candidate],
    required_focus: &str,
    files: &[String],
    freshness: &dyn FreshnessCheck,
) -> Option<&'a Candidate> {
    let mut sorted: Vec<&Candidate> = candidates.iter().collect();
    sorted.sort_by(|a, b| b.summary.timestamp.cmp(&a.summary.timestamp));

    for candidate in sorted {
        if !is_clean_pass(&candidate.summary) {
            continue;
        }
        if candidate.summary.focus_strings != required_focus {
            continue;
        }
        let all_fresh = files.iter().all(|f| {
            matches!(
                freshness.is_fresh(f, &candidate.summary.timestamp),
                Ok(true)
            )
        });
        if all_fresh {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn sample_junit(focus: &str, failures: u64, errors: u64, timestamp: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
  <testsuites tests="10" disabled="0" errors="{errors}" failures="{failures}" time="1.0">
      <testsuite name="Kubernetes e2e suite" package="/usr/local/bin" tests="10" disabled="0" skipped="0" errors="{errors}" failures="{failures}" time="1.0" timestamp="{timestamp}">
          <properties>
              <property name="SuiteSucceeded" value="true"></property>
              <property name="FocusStrings" value="{focus}"></property>
              <property name="SkipStrings" value=""></property>
          </properties>
          <testcase name="[It] some spec" classname="Kubernetes e2e suite" status="passed" time="0.1"></testcase>
      </testsuite>
  </testsuites>
"#
        )
    }

    // --- parse_junit ---------------------------------------------------

    #[test]
    fn parse_junit_extracts_focus_failures_errors_timestamp() {
        // The whole reuse decision hinges on reading these four fields
        // correctly -- a bug here silently breaks both "reuse a good result"
        // and "reject a bad one".
        let xml = sample_junit(
            r"ReplicationController should release no longer matching pods",
            0,
            0,
            "2026-08-26T04:32:14",
        );
        let summary = parse_junit(&xml).expect("valid junit must parse");
        assert_eq!(
            summary.focus_strings,
            "ReplicationController should release no longer matching pods"
        );
        assert_eq!(summary.failures, 0);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.timestamp, "2026-08-26T04:32:14");
    }

    #[test]
    fn parse_junit_skips_outer_testsuites_element() {
        // The outer <testsuites> tag also has failures/errors attributes but
        // NO timestamp -- if the parser ever matched that tag instead of the
        // inner <testsuite>, this would fail to find a timestamp at all
        // (or worse, silently succeed with the wrong element in a future
        // ginkgo version). Regression guard for that specific tag-name
        // collision ("<testsuite" is a prefix of "<testsuites").
        let xml = sample_junit("X", 0, 0, "2026-01-01T00:00:00");
        let summary = parse_junit(&xml).unwrap();
        assert_eq!(summary.timestamp, "2026-01-01T00:00:00");
    }

    #[test]
    fn parse_junit_rejects_missing_testsuite() {
        // Malformed/foreign input must be a hard parse error, not a panic or
        // a default-valued summary that could be mistaken for a real (and
        // reusable) result.
        assert!(parse_junit("<not-junit-at-all/>").is_err());
    }

    #[test]
    fn parse_junit_rejects_non_numeric_failures() {
        // A corrupted or truncated file with a garbled failures value must
        // fail loudly rather than reuse a result whose pass/fail state is
        // unknown.
        let xml = r#"<testsuites><testsuite name="x" failures="oops" errors="0" timestamp="2026-01-01T00:00:00"><properties><property name="FocusStrings" value="X"></property></properties></testsuite></testsuites>"#;
        assert!(parse_junit(xml).is_err());
    }

    #[test]
    fn parse_junit_unescapes_xml_entities_in_focus_string() {
        // Focus regexes commonly contain literal brackets (e.g.
        // "\[Conformance\]"); a real ginkgo report also XML-escapes any '&'
        // in a value. If unescaping is wrong, an exact-match focus
        // comparison silently and permanently fails to reuse a result that
        // should qualify.
        let xml = sample_junit("A &amp; B", 0, 0, "2026-01-01T00:00:00");
        let summary = parse_junit(&xml).unwrap();
        assert_eq!(summary.focus_strings, "A & B");
    }

    // --- is_clean_pass ---------------------------------------------------

    #[test]
    fn is_clean_pass_true_only_when_both_zero() {
        let clean = JunitSummary {
            focus_strings: "X".into(),
            failures: 0,
            errors: 0,
            timestamp: "t".into(),
        };
        assert!(is_clean_pass(&clean));

        let failed = JunitSummary {
            failures: 1,
            ..clean.clone()
        };
        assert!(
            !is_clean_pass(&failed),
            "a single failing spec must never be treated as a clean pass"
        );

        let errored = JunitSummary { errors: 1, ..clean };
        assert!(
            !is_clean_pass(&errored),
            "a single erroring spec must never be treated as a clean pass"
        );
    }

    // --- select_reusable --------------------------------------------------

    /// Fake FreshnessCheck driven by a fixed table, so select_reusable's
    /// matching logic can be tested without shelling out to real git.
    struct FakeFreshness {
        answers: RefCell<HashMap<(String, String), Result<bool, String>>>,
    }

    impl FakeFreshness {
        fn new() -> Self {
            Self {
                answers: RefCell::new(HashMap::new()),
            }
        }
        fn set(&self, file: &str, since: &str, answer: Result<bool, String>) {
            self.answers
                .borrow_mut()
                .insert((file.to_string(), since.to_string()), answer);
        }
    }

    impl FreshnessCheck for FakeFreshness {
        fn is_fresh(&self, file: &str, since_timestamp: &str) -> Result<bool, String> {
            self.answers
                .borrow()
                .get(&(file.to_string(), since_timestamp.to_string()))
                .cloned()
                .unwrap_or(Ok(false))
        }
    }

    fn candidate(focus: &str, failures: u64, errors: u64, timestamp: &str) -> Candidate {
        Candidate {
            path: PathBuf::from(format!("/tmp/{timestamp}.xml")),
            summary: JunitSummary {
                focus_strings: focus.to_string(),
                failures,
                errors,
                timestamp: timestamp.to_string(),
            },
        }
    }

    #[test]
    fn select_reusable_accepts_clean_matching_fresh_candidate() {
        // The core "happy path" this whole tool exists for: a real prior
        // PASS, same focus, no newer edits -- must be reused so a push
        // doesn't pay for a redundant sonobuoy run.
        let c = candidate("FOCUS", 0, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set(
            "crates/apiserver/src/handlers/pods.rs",
            "2026-08-26T04:32:14",
            Ok(true),
        );
        let files = vec!["crates/apiserver/src/handlers/pods.rs".to_string()];
        let picked = select_reusable(std::slice::from_ref(&c), "FOCUS", &files, &fresh);
        assert_eq!(
            picked.map(|c| &c.summary.timestamp),
            Some(&c.summary.timestamp)
        );
    }

    #[test]
    fn select_reusable_rejects_candidate_with_failures() {
        // A failing run is not evidence the code is safe -- reusing it would
        // let a real regression through the gate silently.
        let c = candidate("FOCUS", 1, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set("f.rs", "2026-08-26T04:32:14", Ok(true));
        let files = vec!["f.rs".to_string()];
        assert!(select_reusable(&[c], "FOCUS", &files, &fresh).is_none());
    }

    #[test]
    fn select_reusable_rejects_mismatched_focus() {
        // A result for a DIFFERENT focus regex says nothing about whether
        // the currently-required specs pass -- exact match only.
        let c = candidate("OTHER FOCUS", 0, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set("f.rs", "2026-08-26T04:32:14", Ok(true));
        let files = vec!["f.rs".to_string()];
        assert!(select_reusable(&[c], "FOCUS", &files, &fresh).is_none());
    }

    #[test]
    fn select_reusable_rejects_stale_result_with_newer_commit() {
        // This is the specific commit-then-push workflow bug this tool must
        // not have: if a file was edited again AFTER the recorded run
        // started, that run no longer says anything about the file's
        // current content.
        let c = candidate("FOCUS", 0, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set("f.rs", "2026-08-26T04:32:14", Ok(false));
        let files = vec!["f.rs".to_string()];
        assert!(select_reusable(&[c], "FOCUS", &files, &fresh).is_none());
    }

    #[test]
    fn select_reusable_rejects_when_freshness_check_errors() {
        // If git itself couldn't answer (e.g. spawn failure), the ONLY safe
        // outcome is "not reusable" -- an Err must never be treated as
        // "assume fresh".
        let c = candidate("FOCUS", 0, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set("f.rs", "2026-08-26T04:32:14", Err("git not found".into()));
        let files = vec!["f.rs".to_string()];
        assert!(select_reusable(&[c], "FOCUS", &files, &fresh).is_none());
    }

    #[test]
    fn select_reusable_requires_freshness_for_every_touched_file() {
        // A push can touch multiple sensitive files sharing one combined
        // focus; a stale edit to ANY of them must sink reuse, not just the
        // first one checked.
        let c = candidate("FOCUS", 0, 0, "2026-08-26T04:32:14");
        let fresh = FakeFreshness::new();
        fresh.set("a.rs", "2026-08-26T04:32:14", Ok(true));
        fresh.set("b.rs", "2026-08-26T04:32:14", Ok(false));
        let files = vec!["a.rs".to_string(), "b.rs".to_string()];
        assert!(select_reusable(&[c], "FOCUS", &files, &fresh).is_none());
    }

    #[test]
    fn select_reusable_prefers_newest_qualifying_candidate() {
        // Two clean, matching, fresh candidates exist -- pick the one with
        // the later timestamp, since it's the more recent evidence.
        let older = candidate("FOCUS", 0, 0, "2026-08-01T00:00:00");
        let newer = candidate("FOCUS", 0, 0, "2026-08-20T00:00:00");
        let fresh = FakeFreshness::new();
        fresh.set("f.rs", "2026-08-01T00:00:00", Ok(true));
        fresh.set("f.rs", "2026-08-20T00:00:00", Ok(true));
        let files = vec!["f.rs".to_string()];
        let both = [older, newer.clone()];
        let picked = select_reusable(&both, "FOCUS", &files, &fresh).unwrap();
        assert_eq!(picked.summary.timestamp, newer.summary.timestamp);
    }

    #[test]
    fn select_reusable_returns_none_for_empty_candidates() {
        let fresh = FakeFreshness::new();
        let files = vec!["f.rs".to_string()];
        assert!(select_reusable(&[], "FOCUS", &files, &fresh).is_none());
    }

    // --- find_junit_candidates -------------------------------------------

    #[test]
    fn find_junit_candidates_returns_empty_for_missing_temp_e2e() {
        // No temp/e2e/ directory at all (e.g. a fresh checkout that never
        // ran conformance locally) must be treated as "no candidates", not
        // an error that could be mishandled into a false reuse.
        let dir =
            std::env::temp_dir().join(format!("u7s-junit-reuse-check-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(find_junit_candidates(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- GitFreshnessCheck: real git subprocess -----------------------------
    //
    // Everything above drives select_reusable/is_clean_pass through the
    // FakeFreshness stub. The tests below instead exercise the REAL
    // GitFreshnessCheck against disposable sandbox git repos, because both
    // bugs fixed here (wrong ref, wrong timezone) live entirely in exactly
    // how git_diff_quiet/git_log_since_is_empty invoke `git` -- a fake would
    // trivially "pass" either bug.

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "u7s-junit-reuse-check-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Every git subprocess below goes through `git_command()` (see its doc
    // comment), never a bare `Command::new("git")` -- learned the hard way:
    // an earlier version of these tests used `Command::new("git")` directly
    // and, when this crate's own `cargo test` ran as part of `.githooks/
    // pre-push`'s pre-push verification (i.e. testing a push that touches
    // THIS file), inherited that hook's `GIT_DIR` and committed these tests'
    // throwaway fixtures into the real u7s repository instead of the
    // intended sandbox.

    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        git_command()
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run git {args:?}: {e}"))
    }

    fn init_repo(dir: &Path) {
        // `git init <dir>` alone is not enough: per git's own docs, an
        // inherited GIT_DIR takes precedence over the positional target
        // directory too, not just over `-C`.
        assert!(git_command()
            .args(["init", "-q", "-b", "main"])
            .arg(dir)
            .status()
            .unwrap()
            .success());
        assert!(git(dir, &["config", "user.email", "test@example.com"])
            .status
            .success());
        assert!(git(dir, &["config", "user.name", "Test"]).status.success());
    }

    /// Writes `file` with `contents` and commits it with the given
    /// ISO-8601-with-offset author/committer date -- an explicit offset so
    /// these fixture commit times are themselves immune to the ambient host
    /// timezone, keeping every test below deterministic regardless of which
    /// machine (or CI runner) it executes on.
    fn commit_file(dir: &Path, file: &str, contents: &str, date_with_offset: &str, msg: &str) {
        let path = dir.join(file);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        assert!(git(dir, &["add", file]).status.success());
        let status = git_command()
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", msg])
            .env("GIT_AUTHOR_DATE", date_with_offset)
            .env("GIT_COMMITTER_DATE", date_with_offset)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn create_branch(dir: &Path, name: &str) {
        assert!(git(dir, &["checkout", "-q", "-b", name]).status.success());
    }

    fn checkout(dir: &Path, ref_name: &str) {
        assert!(git(dir, &["checkout", "-q", ref_name]).status.success());
    }

    fn rev_parse(dir: &Path, ref_name: &str) -> String {
        let out = git(dir, &["rev-parse", ref_name]);
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn git_freshness_check_walks_pushed_ref_not_whatever_is_checked_out() {
        // Reproduces the review's exact finding (PR #1408 review):
        // `git push origin feature-b:some-remote-ref` while `main` is
        // checked out locally must still see a regression committed to
        // feature-b after the recorded junit run. A caller that (as this
        // code used to) checks implicit HEAD instead of the actually-pushed
        // ref would walk `main` -- which never got the regression commit --
        // and wrongly report a stale result as reusable.
        let dir = scratch_dir("wrong-ref");
        init_repo(&dir);
        let file = "sensitive.rs";
        commit_file(&dir, file, "v1", "2026-08-26T04:00:00+00:00", "base");
        create_branch(&dir, "feature-b");
        // Regression: lands on feature-b only, after the recorded run.
        commit_file(
            &dir,
            file,
            "v2 -- regression",
            "2026-08-26T05:00:00+00:00",
            "regression",
        );
        let pushed_sha = rev_parse(&dir, "feature-b");
        // The checked-out branch is NOT the one being pushed -- the exact
        // divergence the review reproduced.
        checkout(&dir, "main");

        let recorded_at = "2026-08-26T04:30:00"; // between base and regression

        let real = GitFreshnessCheck {
            repo_root: dir.clone(),
            pushed_ref: pushed_sha,
        };
        assert_eq!(
            real.is_fresh(file, recorded_at),
            Ok(false),
            "a regression committed to the ref actually being pushed, after \
             the recorded run, must never be reported fresh just because a \
             different branch happens to be checked out"
        );

        // Sanity check proving this is genuinely the wrong-ref bug and not
        // some other cause: implicit HEAD (main) truly has no such commit,
        // which is exactly what made the bug invisible before this fix.
        let buggy_via_head = GitFreshnessCheck {
            repo_root: dir.clone(),
            pushed_ref: "HEAD".to_string(),
        };
        assert_eq!(
            buggy_via_head.is_fresh(file, recorded_at),
            Ok(true),
            "sanity check: HEAD (main) has no commit after the timestamp -- \
             confirms checking HEAD instead of the pushed ref is what hid \
             the regression"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_log_since_is_empty_walks_pushed_ref_history_even_when_working_tree_matches_head() {
        // Isolates the git-log half of the wrong-ref bug from the git-diff
        // half: feature-b's file content nets back to the SAME bytes as
        // main's (so a plain content comparison can't tell the branches
        // apart), but feature-b's own history still has a commit to `file`
        // landing after the recorded timestamp. Only walking the PUSHED
        // ref's log (not HEAD's) can catch this.
        let dir = scratch_dir("log-ref");
        init_repo(&dir);
        let file = "sensitive.rs";
        commit_file(&dir, file, "v1", "2026-08-26T04:00:00+00:00", "base");
        create_branch(&dir, "feature-b");
        commit_file(&dir, file, "v2", "2026-08-26T05:00:00+00:00", "touch-1");
        commit_file(
            &dir,
            file,
            "v1",
            "2026-08-26T05:30:00+00:00",
            "touch-2-reverts-to-v1",
        );
        let pushed_sha = rev_parse(&dir, "feature-b");
        checkout(&dir, "main"); // main's tree for `file` is also "v1"

        let recorded_at = "2026-08-26T04:30:00";

        assert_eq!(
            git_log_since_is_empty(&dir, &pushed_sha, file, recorded_at),
            Ok(false),
            "two commits on the pushed ref touched `file` after the \
             recorded run -- the pushed ref's own history is not covered \
             by that run even though its net file content happens to match \
             HEAD's"
        );
        assert_eq!(
            git_log_since_is_empty(&dir, "HEAD", file, recorded_at),
            Ok(true),
            "sanity check: HEAD (main) has no such commits in its own \
             history -- confirms walking the wrong ref is what would have \
             hidden this"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restores a possibly-unset `TZ` env var on drop, so the process-wide
    /// mutation the timezone test below needs can never leak into later
    /// tests even on assertion panic. Safe to mutate process-wide `TZ` here
    /// specifically because every OTHER test in this file that spawns real
    /// git either never calls `--since` at all, or (after this fix) always
    /// passes an explicit `+00:00`-suffixed timestamp and explicit-offset
    /// commit dates -- none of them depend on the ambient timezone, so a
    /// concurrently-running test can't be perturbed by this one flipping it.
    struct TzGuard(Option<String>);
    impl TzGuard {
        fn set(value: &str) -> Self {
            let prev = std::env::var("TZ").ok();
            std::env::set_var("TZ", value);
            Self(prev)
        }
    }
    impl Drop for TzGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("TZ", v),
                None => std::env::remove_var("TZ"),
            }
        }
    }

    #[test]
    fn git_log_since_is_empty_treats_bare_timestamp_as_utc_not_host_local() {
        // Reproduces the review's second finding: a bare junit timestamp
        // (no UTC offset) handed straight to `git --since` is resolved in
        // the CALLING PROCESS's local timezone. Ginkgo/sonobuoy generate it
        // inside the Lima VM (UTC, see JunitSummary::timestamp doc), but
        // this check runs on the host -- a host set 8 hours west of UTC
        // shifts the effective cutoff 8 hours LATER, which can hide a
        // regression that landed strictly after the real cutoff but before
        // the miscalculated one: exactly the dangerous "stale looks fresh"
        // direction the review called out.
        //
        // TZ="XXX8" is a POSIX (not IANA) zone spec -- no zoneinfo database
        // lookup needed, so this is deterministic on any machine running
        // this test, matching the review's own "reproduced under a
        // JST-vs-UTC mismatch" methodology without depending on the actual
        // host's real configured zone.
        let _tz_guard = TzGuard::set("XXX8");

        let dir = scratch_dir("tz");
        init_repo(&dir);
        let file = "sensitive.rs";
        commit_file(&dir, file, "v1", "2026-08-26T04:00:00+00:00", "base");
        // Regression lands 4 real-world hours after the recorded run below --
        // a fresh-run-required case under ANY correct timezone handling.
        commit_file(
            &dir,
            file,
            "v2 -- regression",
            "2026-08-26T08:00:00+00:00",
            "regression",
        );

        // The literal, offset-less string ginkgo would have written.
        let recorded_at = "2026-08-26T04:00:00";

        assert_eq!(
            git_log_since_is_empty(&dir, "HEAD", file, recorded_at),
            Ok(false),
            "the fix (appending +00:00 before calling git) must find the \
             regression regardless of the host's local timezone -- if this \
             fails, the UTC offset is no longer being applied"
        );

        // Empirically prove the bug this guards against, the same way the
        // review did: the SAME bare timestamp, under the SAME host
        // timezone, run through the pre-fix invocation shape (no appended
        // offset) directly against real git.
        let buggy = git(
            &dir,
            &[
                "log",
                &format!("--since={recorded_at}"),
                "--oneline",
                "--",
                file,
            ],
        );
        assert!(buggy.status.success());
        assert!(
            buggy.stdout.iter().all(u8::is_ascii_whitespace),
            "sanity check: the pre-fix bare-timestamp invocation finds \
             NEITHER commit under TZ=XXX8 (the bug: --since is pushed 8h \
             later than intended, hiding a regression that landed only 4h \
             after the real cutoff) -- confirms this is genuinely the \
             timezone bug, not something else"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
