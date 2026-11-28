# boon to jsonschema swap spike

Bead: mayor-gnceb
Date: 2026-11-28 (prototype on branch, draft PR; upstream target 1.37.3)

**GO**: `jsonschema` 0.63 replaces boon entirely with no hand-rolled regex
rewriting, but only with `PatternSyntax::Ecma262` on `PatternOptions::regex()`
(the library's own single-pass translation), NOT the `Engine` syntax the bead
proposed: Engine makes `\w`/`\d` Unicode, so Go-valid `^\w{1,253}$` needs ~16 MiB
and is rejected at the 1 MiB limit. The prototype also makes PR #2317 (raise the
1 KiB source cap) moot: the cap is deleted.

## Prototype

boon removed; `build_schema_validator` (crd.rs) is the one build path: ECMA-262
syntax translated linearly to `regex`, `size_limit` 1 MiB per pattern. Kept from
#2289: the per-CRD 8 MiB aggregate budget with the 4 KiB floor (it defends
against N distinct sub-limit patterns pinning GiBs, which a per-pattern limit
cannot see) and `patternProperties` rejection. Deleted: the 1024-byte source
cap, `ascii_shorthands`, the boon quadratic PoC and the 3 cap tests. Draft: the
library default (2020-12), same as boon.

## 10-problem checklist

| # | Problem | Result |
|---|---|---|
| P1 | quadratic rewrite | PASS: `\s` 8 KiB 17 ms vs boon 20.5 s |
| P2 | compiled-size blowup | PASS: 200 x `\pL{244}` rejected in 3.3 ms, RSS 38 MiB (boon 8.2 s) |
| P3 | bisection CPU, many tiny patterns | PASS by existing tests; 2048-tiny admission cost NOT re-measured |
| P4 | async stall | PASS: `on_compile_stack` + blocking pool unchanged |
| P5 | recompile per CR write | PASS: cache kept; live first write 334 ms, next 0 ms |
| P6 | Cilium 1199 B rejected | PASS: cap deleted; builds, matches Go on 8 inputs; live CRD created |
| P7 | ECMA vs Go gaps | PARTIAL: 15 divergent corpus rows vs boon's 13 (below) |
| P8 | patternProperties | PASS: unchanged |
| P9 | match-time ReDoS | PASS: regex engine; `^(a+)+$` agrees with Go |
| P10 | double compile | PARTIAL: budget build + validator build remain, now one engine and one limit |

## The four unknowns

1. **Real CRD schemas.** No `$schema`: default 2020-12 works. Draft4 (the
   k8s-flavoured choice) breaks 3 existing tests: it rejects `required: []`
   (metaschema minItems 1) and integral floats `5.0` as integer; upstream
   accepts both. x-kubernetes-int-or-string/preserve-unknown-fields/
   embedded-resource/list-type, `default`, `description`: ignored, as upstream's
   structural pruning expects. Unknown formats are ignored. Gaps, identical to
   boon on all 18 rows (`crd_schema_parity.rs`): `nullable: true` rejects null
   (upstream accepts); formats are annotation-only (with
   `should_validate_formats(true)` date-time/email/uuid/ipv4/hostname assert and
   unknown ones are still ignored, but `int32`/`int64`/`byte` are never
   checked); boolean `exclusiveMinimum` fails the metaschema (500 on first CR
   write).
2. **Pattern acceptance vs Go RE2** (oracle: Go 1.26.3 `regexp`, 66 patterns,
   `testdata/crd_pattern_parity.json`). All real-world patterns (quantity,
   Prometheus durations, DNS-1123, semver, UUID, Cilium 1199 B) agree with Go.
   Ecma262 diverges on 15 rows: Go accepts but we reject: `\Q..\E`, `{,n}`,
   `\a`, `(?s)` semantics, POSIX classes, and `\pL{244}` (size limit, on
   purpose); we accept but Go rejects: `\u`, `\cA`, `a++`, repeat counts above
   1000; `\s`/`\b` are Unicode. boon diverged on 13 (same families, but it handles
   `(?s)` and POSIX classes). Engine syntax diverges on 17: it adds Unicode `\d \w`
   (5 more rows) and the size problem above. Neither syntax is Go; a CRD using an unsupported form
   is now rejected at admission (422) instead of failing every CR write (500).
3. **Wording.** `ValidationError` carries kind, instance and path, so every kind
   maps exactly. Implemented: enum ("Unsupported value"), required ("Required
   value"), pattern (`in body should match`), type (`must be of type`); other
   kinds fall back to `Invalid value: <library text>` (limits are on the kind,
   not yet mapped). Errors are now aggregated (boon reported the first) and have
   paths. Gap, pre-existing: upstream wraps `Kind.group "name" is invalid: [a, b]`;
   we emit `CR schema validation failed: a, b`.
4. **Latency** (release, this machine, same session):

| shape | boon 0.6.1 | jsonschema |
|---|---|---|
| `\s` 1 KiB / 2 / 4 / 8 | 267 ms / 1.04 s / 4.4 s / 20.5 s | 4.4 / 5.5 / 11 / 17 ms (4, 8 KiB then rejected: over 1 MiB compiled) |
| 200 x `\pL{244}` | 8.2 s compiles | rejected in 3.3 ms |
| representative schema build | 0.85 ms | 0.35 ms |
| representative CR validate | 0.31 us | 0.10 us |

   Live (lima-node-smoke): CRD with 6 x 1 KiB `\s` created in 321 ms, first CR
   write 334 ms, repeat 0 ms; 24 such properties rejected by the aggregate budget
   in 1.2 s; 32 x 8 KiB `\s` (400 KB body) rejected in 34 ms server side. The
   bounded bench is the `#[ignore]`d `measure_jsonschema_compile_and_validate_cost`.

## Test failure classification

Final tree: `cargo test --workspace` 5345 passed, 0 failed, clippy clean.
Intermediate Draft4 attempt: 3 failures, all semantic divergence from upstream
(`required: []`, `5.0`), fixed by dropping Draft4. Tests removed or changed that
asserted boon quirks: 5 (3 source-cap tests, the quadratic PoC, the "invalid
pattern is left to boon" clause). Wording-only failures: 0 (existing assertions
use `contains`; new test `schema_violations_are_all_reported_in_upstream_field_error_wording`).

## Migration blast radius

4 production files (`Cargo.toml`, `state.rs`, `cr.rs`, `crd.rs`), net production
code is smaller (crd.rs -104 lines). Diff outside Cargo.lock: 6 files +309/-409;
3 new test/data files (+1183 incl. the 862-line Go-oracle JSON). Dependencies:
+23 crates, -2 (`boon`, `appendlist`), including `fancy-regex`, `email_address`,
`fraction`, `num*`; `resolve-http`/`tls` are off.

## Live conformance gate

`--focus` on CustomResourceValidationRules, CustomResourcePublishOpenAPI,
CustomResourceDefinition resources, and the FieldValidation CR specs (`create/apply`,
`detect unknown metadata fields in both`, `detect duplicates in a CR`), from `e2e.txt`:
`Ran 26 of 3206 Specs in 6.899 seconds`, `SUCCESS! -- 26 Passed | 0 Failed | 0
Pending | 3180 Skipped`; run-all summary `[parallel] Ran: 26 Passed: 26 Failed: 0`.
Live kubectl on a stack-only run: the Cilium CRD is created, and a CR violating
a pattern, an enum and a required field returns
`spec.name: Required value, spec.code: Invalid value: "x1": spec.code in body
should match '^[0-9]+$', spec.mode: Unsupported value: "z": supported values: "a", "b", ...`.

## Residual risks

- Dependency growth (+23 crates) against the minimal-dependency stance; 0.62 to
  0.63 broke API within two weeks, so pin and expect churn.
- Unicode `\s`/`\b` accept inputs Go rejects (e.g. NBSP for `\s`); no fix
  without our own rewrite.
- Invalid or Go-only patterns now fail CRD creation, upstream accepts them.
- `nullable`, format asserts, int32/int64/byte, boolean exclusive bounds: open
  parity gaps (same as boon); 2 are cheap (`should_validate_formats`,
  `with_format("byte")`) but untested against go-openapi quirks.
- pattern errors are indistinguishable (too large vs invalid), so one message
  covers both.
- Aggregate budget still needs our bisection (~1 build per 21 bits per
  pattern above the floor); 2048-tiny case not re-measured.
