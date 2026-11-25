# CEL expression depth: 96 for policies and CRD rules

**Status:** Accepted
**Date:** 2026-11-25
**Supersedes:** [cel-policy-recursion-depth-128.md](cel-policy-recursion-depth-128.md)

## Context

cel-go v0.29.2 (the version in Kubernetes release-1.37 and v1.37.1 `go.mod`;
`parser` defaults `maxRecursionDepth` to 250, which Kubernetes does not
override) rejects expressions nested deeper than 250 levels at compile time.
The Rust `cel` crate's `Program::compile` always parses with a fixed cap of 96
(`Parser::default()`, no public knob); since 0.16.1 it also counts operator and
member chains, so it rejects CRD rules cel-go accepts.

## Decision

- CRD `x-kubernetes-validations` and policy (ValidatingAdmissionPolicy,
  MutatingAdmissionPolicy, authorization) expressions nested deeper than 96
  levels are rejected at create, with upstream's
  `max recursion depth exceeded` text. cel-go accepts up to 250. No upstream
  e2e asserts depth.
- One limit (`MAX_RECURSION_DEPTH`) serves both paths. Our AST walk counts every
  level, a superset of what the library counts, and the library's own
  `Recursion limit of 96 exceeded` error is mapped to the upstream text.
- The crate is not pinned or patched: a pin would freeze the dependency, and
  raising the cap is not possible through `Program::compile`.

## Rationale

Policies evaluate on a 512 KiB request thread under a 192 KiB stack budget. An
expression the compiler accepts but the evaluator refuses ("expression nests too
deeply") is stored, then denies every matching request under
`failurePolicy: Fail`. Measured on a release build, no shape evaluates fewer than
187 levels, so 96 leaves ample headroom.

## Consequences

- Debug builds have larger frames and may refuse expressions below 96;
  the guarantee holds for release builds, covered by
  `every_depth_the_compiler_accepts_evaluates_in_release`, which the
  `release-invariants` CI job runs with `cargo test --release`.
- CRD rules are covered per shape and entry path (root, list item, map value,
  `oldSelf` transition) by
  `every_crd_shape_at_the_deepest_accepted_depth_evaluates_on_every_entry_path`.
