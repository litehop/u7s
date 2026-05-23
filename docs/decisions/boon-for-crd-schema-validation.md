# boon for CRD openAPIV3Schema validation

**Status:** Accepted  
**Date:** 2026-05-23

## Context

u7s validates Custom Resource instances against the `openAPIV3Schema` stored in each CRD version. The hand-rolled validator (`validate_against_schema`, ~125 lines) supported only `type`, `properties`, `required`, and `additionalProperties`. It silently accepted CRs that violated `enum`, `pattern`, `minimum`, `maximum`, `format`, `items`, `oneOf`, `allOf`, and any other keyword — giving users false confidence.

The validator was already wired into all 6 CR write paths (create + replace + patch, cluster-scoped and namespaced). The question was whether to extend the hand-rolled approach or replace it with a standards-compliant library.

Two candidates were evaluated: `boon` and `jsonschema`.

## Decision

Replace the hand-rolled validator with `boon`.

## Evidence

### Runtime benchmark (2026-05-23)

A local benchmark (`crates/schema-bench`) compiled a realistic CRD schema (Certificate-like: nested objects, `required`, `additionalProperties`, `enum`, `pattern`, `minimum`) once per validator and ran 100,000 mixed validations (valid + enum violation + pattern violation + missing required + extra field). Measured with `memory-stats` (current RSS via `task_info` on macOS, `/proc/self/status` on Linux):

| Validator | Schema compile RSS delta | 100k validations | Behavioral coverage |
|-----------|--------------------------|------------------|---------------------|
| hand-rolled baseline | +0 KB (no compile step) | 50 ms | type, properties, required, additionalProperties only |
| boon | +3,584 KB | 35 ms | full openAPIV3Schema |
| jsonschema | +27,088 KB | 4 ms | full openAPIV3Schema |

Schema compile cost is one-time per CRD version, incurred at CR write time (not at startup). Per-request steady-state RSS delta was negligible for all three (~50 KB across the entire 100k loop).

### Academic reference

Viotti et al., "An Analysis of JSON Schema Validators" (VLDB 2026, p279): evaluated `boon` and `jsonschema` among others for correctness and performance. Both Rust crates were included in the study's benchmark suite. The paper's central finding is that validator correctness varies significantly across implementations, and that widely-used validators can still carry defects — reinforcing that benchmark-and-verify is the right selection process rather than trusting reputation alone.

## Rationale

`boon` was chosen over `jsonschema` on two grounds:

**Dependency footprint.** `jsonschema` pulls in `fancy-regex` (backtracking regex engine), ICU locale tables, URL parsing, and format validators — approximately 15 additional crates and +27 MB RSS per compiled schema. `boon` uses the `regex` crate (already a transitive dependency of u7s) — zero net new transitive deps and +3.6 MB per schema.

**Adequate performance.** CR writes are low-frequency (human or controller-driven, not in the hot read path). The 35 ms / 100k figure translates to ~0.35 µs per validation — well within any latency budget. `jsonschema`'s 9× speed advantage is irrelevant at this workload frequency.

The hand-rolled baseline was rejected because it silently passes invalid CRs (enum and pattern violations accepted as valid). This is the wrong behavior for a kubectl-compatible API server — `kubectl --validate` trusts the server to enforce the schema it stores.

## Consequences

- `boon = "0.6"` added to `crates/apiserver/Cargo.toml`.
- `validate_against_schema`, `json_type_name`, and the old `validate_cr_schema` deleted (~125 lines). Replaced with a single ~20-line `validate_cr_schema` backed by boon.
- 10 existing tests ported to go through `validate_cr_schema`; 2 new tests added for `enum` and `pattern` enforcement.
- Schema compilation happens per CR write (not cached across requests). Acceptable: `CrContext` is already built per-request from the store, and the +3.6 MB cost is absorbed at CRD registration time.
- If schema compilation ever shows up in profiling (unlikely), cache the compiled `boon::Schemas` keyed by CRD resource version in `AppState`.
