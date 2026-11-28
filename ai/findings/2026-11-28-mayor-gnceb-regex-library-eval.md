# CRD pattern regex library evaluation (boon replacement)

Bead: mayor-gnceb
Date: 2026-11-28 (audit, read-only; no workspace dependency added)

**Answer:** boon's ECMA rewrite is hard-wired (no hook to skip or bound it), but
boon is not hard-wired into u7s beyond ~4 files, and one viable replacement
exists (`jsonschema` 0.63 with `PatternSyntax::Engine`); however the cheapest
fix that closes the quadratic is not a library swap but a linear pre-rewrite of
`\d \D \w \W \s \S \cX` in our own code before boon sees the pattern (bead
option (a)), and a full swap should be deferred as a separate, larger decision.

**Recommendation:** do (a) now (it also unblocks raising the 1024 cap); do not
adopt regress or fancy-regex; track `jsonschema` migration as an optional
follow-up whose payoff is deleting the double compile and the bisection budget.

## Is boon hard-wired?

- Regex handling: `boon-0.6.1/src/compiler.rs:379-392` (patternProperties) and
  `:471-472` (pattern) call `ecma::convert` then `Regex::new` unconditionally.
  `ecma` is `pub(crate)`; no option for size limit, syntax or engine. So we
  cannot configure our way out; only (i) feed boon an already-rewritten pattern,
  (ii) fork/`[patch]` boon, or (iii) replace it.
- Scope of boon in u7s: it validates the **whole** CRD `openAPIV3Schema`, not
  only `pattern`: `crates/apiserver/src/state.rs:694-695` (`CompiledCrSchema`
  holds `boon::Schemas` + `SchemaIndex`), `handlers/cr.rs:1061-1066` (compile on
  cache miss) and `:1086` (`schemas.validate`), error-tree mappers
  `cr.rs:2586-2660` (`ErrorKind::Enum/Required`, `InstanceLocation`,
  `InstanceToken`) that produce the k8s `Unsupported value` / `Required value`
  wording kubectl and conformance match on, plus `crd_pattern_cost.rs:34-35`
  (test PoC). Roughly 3 source files + the tests asserting boon wording
  (`cr.rs` ~13348, 13429, 13486, 16981).
- Upstream dialect: kube-openapi calls Go `regexp.Compile(pattern)` (RE2) on
  the raw pattern (`temp/research/kube-openapi-rexp.go`, kube-openapi pinned by
  kubernetes release-1.37 go.mod `v0.0.0-20260721132016-d427ff9ee9ad`).
  apiextensions validation (`temp/research/apiext-validation-1.37.go:1495`)
  forbids `patternProperties` and does NOT compile `pattern` at CRD admission.
  RE2 has no lookaround/backrefs, `\d \w` ASCII, `\s` = `[\t\n\f\r ]`, `\a` valid.
  So the closest Rust dialect is the `regex` crate itself, not ECMA.

## Past regex problems (checklist)

| # | Problem | Source |
|---|---------|--------|
| P1 | boon ECMA rewrite O(n^2), runs before any size check | mayor-cmtwm, PR #924; 1 KiB cap |
| P2 | Compiled-size blowup (200 x `\pL{244}`: 6 s, 2.9 GiB) | mayor-2ye50, #2289: 1 MiB/pattern, 8 MiB/CRD |
| P3 | Budget bisection CPU with many tiny patterns (9.3 s) | 4 KiB floor, implies <=2048 patterns |
| P4 | Async-runtime stall during compile | `spawn_blocking`, `on_compile_stack` |
| P5 | Recompile per CR write | `CrSchemaCache` per CRD generation |
| P6 | Source cap rejects real CRD (Cilium, 1199 B) | mayor-nq194, #2317 blocked |
| P7 | ECMA-vs-Go semantic gaps (`\a` rejected by boon but valid in Go; `\s` set; `\cX`) | boon `ecma.rs`, upstream RE2 |
| P8 | `patternProperties` DoS | forbidden outright, matches upstream |
| P9 | Runtime (match-time) ReDoS | `regex` crate linear; any backtracker would regress this |
| P10 | boon `Regex::new` default 10 MiB size limit, no hook, so we compile each pattern a second time to measure it | `crd.rs:293-372` |

## Candidates

| Candidate | Dialect vs Go RE2 | Linear match | Compile on gnceb shape | P1 | P2/P3/P10 | P7 | P9 | Health | Blast radius |
|---|---|---|---|---|---|---|---|---|---|
| boon 0.6.1 (current) | ECMA to Rust; stricter than RE2 | yes (regex) | quadratic: `\s` 8 KiB 18 s | fail | fail (no limit hook) | partial | pass | last release 2025-01-07, last push 2026-11-01, open regex issues | n.a. |
| jsonschema 0.63.2, default (fancy-regex) | ECMA + lookaround/backref (superset of RE2) | NO when lookaround/backref used (backtrack_limit only) | measured linear (below) | pass | pass if `size_limit` set | partial | fail unless forced to `regex` | release 2026-11-23, push 2026-11-27, very active | large |
| jsonschema, `PatternOptions::regex()` + `PatternSyntax::Engine` (0.62+) | Rust regex syntax, no translation: nearest to RE2 | yes | no translation step | pass | pass: `size_limit`/`dfa_size_limit` honoured; `PatternCache` dedups | best | pass | as above | large |
| regress 0.12.0 | ECMAScript, backtracking | NO (catastrophic backtracking at CR-write time) | measured linear | pass | no size-limit API found | wrong dialect | fail | release 2026-08-23 | needs a validator wrapper anyway |
| fancy-regex 0.20.2 alone | Rust syntax + lookaround | NO beyond delegate | n.a. (not a validator) | n.a. | has limits | needs translation | fail | active | needs validator |
| `regex` direct + our linear rewrite, boon kept (option a) | RE2-ish after rewrite | yes | linear, boon loop iterates once | pass | P10 stays | same as boon | pass | n.a. | 1 function in `crd.rs` + call before boon |
| valico / jsonschema-valid | old drafts, unmaintained (valico last push 2024-03-07) | n.a. | n.a. | not evaluated | not evaluated | not evaluated | not evaluated | stale | rejected on health |

## Bounded measurement (scratch crate `temp/gnceb-poc`, gitignored, release, cap 100 s, not in workspace)

Pattern = N copies of the shorthand, `jsonschema_regex::to_rust_regex` (the
translation step) and `regress::Regex::new`:

| unit | 1 KiB | 8 KiB | 64 KiB |
|---|---|---|---|
| `\s` jsonschema-regex translate | 0.26 ms | 2.0 ms | 17 ms |
| `\s` regress compile | 0.10 ms | 0.6 ms | 7 ms |
| `\d` jsonschema-regex translate | 0.13 ms | 0.24 ms | 1.8 ms |
| `\w` jsonschema-regex translate | 0.05 ms | 0.25 ms | 2.3 ms |

8x size gives ~8x time (linear), vs boon `\s` 8 KiB = 18 s (bead). Source:
`jsonschema-regex` `to_rust_regex` does one parse and one AST visit
(`temp/research/jsonschema-regex-lib.rs:31-76`). regress being linear to
compile is irrelevant: it is a backtracking matcher, so match-time ReDoS (P9)
is unbounded for e.g. `(a+)+$`. Not measured: end-to-end u7s CR-write latency
with a swapped validator; jsonschema's behaviour on real CRD schemas
(draft selection for schemas without `$schema`, `nullable`, `format`
differences); regex-crate vs Go acceptance gaps (e.g. escapes of punctuation,
Go's 1000 repeat cap).

## Findings on option (a), the cheap fix

- boon's loop does nothing quadratic when the pattern holds no `\d \D \w \W \s
  \S` outside what it has already rewritten: `visit` returns `None` and the
  loop breaks after one parse + visit (`ecma.rs:19-30`). The first loop also
  re-parses once per `\cX` (`ecma.rs:12-23`, `fix_error`), so `\cA` x N is a
  second quadratic path; the pre-rewrite must cover it too.
- `crd.rs:293` `ascii_shorthands` exists but is budget-only: it ignores `\s`
  and emits `[0-9]` inside classes the same way boon does (`[[0-9]]` is valid
  Rust). A production rewrite must be a single linear scan that also tracks `\\`
  escapes and emits boon's exact `\s` set (`ecma.rs:77-84`) so semantics do not
  change, and must be applied to the pattern fed to boon, with a test that
  equals `ecma::convert` output on a corpus.
- Residual after (a): P10 double compile remains (boon `Regex::new` 10 MiB
  default is unbounded for us, so the budget check must stay).

## Why not swap now

`jsonschema` + `Engine` syntax is the only candidate that removes P1, P2, P10
and aligns with RE2 (and `PatternCache` helps P5). Costs: new dependency tree
(`referencing`, `fancy-regex`, `ahash`, `hashbrown`; must disable default
features `resolve-http`/`tls`), fast breaking-release cadence (0.62 to 0.63
within about 2 weeks), rewrite of error mappers `cr.rs:2586-2660` onto
`ValidationErrorKind`, and re-verification of conformance wording. Engine
syntax also changes which patterns are accepted (ECMA-only escapes would
break). That is a feature-sized change, not a security patch.

## Residual risk if nothing is done

Needs CRD-write privilege; CPU on a blocking thread (bead estimate ~7 min per
worst-case CRD write, not measured end-to-end). Accepting is defensible, but
(a) is small and lets #2317 proceed.

## URLs

- https://github.com/santhosh-tekuri/boon
- https://github.com/Stranger6667/jsonschema (CHANGELOG 0.62.0)
- https://github.com/kubernetes/kube-openapi/blob/master/pkg/validation/validate/rexp.go
