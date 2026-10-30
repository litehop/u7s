# CEL expression depth: 128 for policies, 250 for CRD rules

**Status:** Accepted
**Date:** 2026-10-30

## Context

cel-go (Kubernetes 1.37.1) rejects expressions nested deeper than 250 levels at
compile time. u7s evaluates two ways: CRD `x-kubernetes-validations` run on a
dedicated 32 MiB thread, while ValidatingAdmissionPolicy, MutatingAdmissionPolicy
and authorization expressions run on a 512 KiB request thread under a 192 KiB
stack budget. An expression the compiler accepts but the evaluator refuses
("expression nests too deeply") is stored successfully, then denies every matching
request under `failurePolicy: Fail`.

## Decision

- Policy expressions are rejected at create (and again at parse on evaluation)
  deeper than `MAX_POLICY_RECURSION_DEPTH` = 128, with the
  `max recursion depth exceeded` text.
- CRD rules keep cel-go's 250 (`MAX_RECURSION_DEPTH`).
- The vendored `cel` crate's 96-level cap on the parser `expr` rule (ternaries,
  parentheses, list literals) is not patched. CRD rules nested past 96 that
  cel-go accepts are rejected.

## Rationale

Measured on a release build, the deepest evaluable `n` before the budget refuses:
call chain 204, left-associated sum 188, index chain 187, `in` chain 188;
ternary, list, map and nested comprehension reach 249. No shape evaluates fewer
than 187 levels, so 128 leaves about 45% headroom for frame sizes not measured.
A count cannot be exact because frame size differs per node kind.

This is a deliberate safe default: pathologically nested expressions cel-go
accepts are refused here, because the alternative is a stored policy that fails
closed. No real policy nests near 128.

## Consequences

- Debug builds have larger frames and may refuse expressions below 128;
  the guarantee holds for release builds, covered by
  `every_depth_the_compiler_accepts_evaluates_in_release` (`cargo test --release`).
- A new evaluable shape with larger frames than the measured ones needs the
  limit re-measured.
