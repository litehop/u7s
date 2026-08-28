Bead: mayor-h3zsf

# DRA CEL reuse scout: VAP evaluator subset vs real DeviceClass selector shapes

## Verdict: B — small, enumerable extensions

The VAP CEL subset in `crates/apiserver/src/admission.rs` covers the majority
of real DRA `DeviceClass.Spec.Selectors` shapes (driver equality, nested
attribute field/bracket access, optional-chaining `.?field.orValue(...)`,
boolean-attribute-as-predicate, `&&`/`||` composition) once a `device`-rooted
variable is bound — confirming mayor-8qcaw's 2026-08-04 correction for those
shapes. But the single most frequent real shape in the upstream allocator
test corpus, `device.capacity[...].X.compareTo(quantity("6Gi")) >= 0`
(Quantity comparison), is not covered today and needs two specific,
bounded extensions: (1) general `.method(args)` call syntax in the field
chain (today only `orValue` is hardcoded), and (2) a `quantity()`/
`.compareTo()` builtin reusing u7s's existing (already duplicated 2x)
`parse_quantity_milli` logic. Estimated ~150-250 LoC total including tests.
Not verdict A (a real gap exists, not just rebinding) and not verdict C (no
new subsystem or external crate needed — the recursive-descent parser
architecture generalizes cleanly to both extensions).

## 1. What the VAP evaluator actually supports

Read directly from `crates/apiserver/src/admission.rs` (functions
`eval_cel_bool_expr`/`eval_cel_vap_value` at L1517-1561, and the
`parse_vap_*` family at L1573-2359; `tokenize_cel` at L2396-2599).

- **Roots**: `object`, `variables`, `request`, `namespaceObject`, `oldObject`
  — five hardcoded identifier names in `parse_vap_primary`'s `Ident` arm
  (L2054-2064). No general variable-binding mechanism; a 6th root is a
  one-line `else if name == "device"` addition (or, more cheaply, extending
  the existing `object` check to `name == "object" || name == "device"` and
  calling `eval_cel_bool_expr` with the device value in the `object` slot —
  DRA selectors never reference `object`/`variables`/`request` and so never
  collide).
- **Precedence chain**: ternary `?:` → `||` → `&&` → comparison (`==` `!=`
  `<` `<=` `>` `>=`) → additive (`+` `-`, checked-overflow) → multiplicative
  (`*` `/` `%`, checked) → unary (`!` `-`) → primary. Full precedence
  climbing, not a flat/one-pass evaluator.
- **Field/index chain** (`parse_vap_field_chain`, L2175-2305): `.field`,
  `.?field` (optional), `[idx]`/`[?idx]` (map-key or list-index, `.?`
  variants propagate a `present` flag), and **one** hardcoded method call —
  `.orValue(default)` — used to resolve an absent optional chain to a
  default. This is the *only* function-call syntax the parser recognizes
  anywhere; there is no generic `.method(args)` or bare `func(args)` node.
- **Literals/collections**: int, float, bool, string (single/double quoted,
  with escapes), `null`, array literals `[...]`, map/struct literals
  `{...}` (including bogus `TypeName{...}` constructors, used by VAP's
  `oldObject`-ternary pattern — type name discarded).
- **Not present at all**: any macro form (`.exists()`, `.all()`,
  `.exists_one()`, `.map()`, `.filter()`), `.matches()`/`.contains()`/
  `.startsWith()`/`.endsWith()`/`.size()`, the infix `in` operator, `has()`,
  `cel.bind()`, `type()`, or any notion of a typed value beyond raw JSON
  (no Quantity/Duration/Timestamp/Semver types or their comparison methods).
- **Latent robustness gap (not a DRA blocker, but relevant to any
  extension work here)**: neither `eval_cel_bool_expr` nor
  `eval_cel_vap_value` checks that the parser consumed the entire token
  stream — trailing unrecognized tokens (e.g. an unsupported `.exists(...)`
  suffix) are silently dropped rather than producing a parse error. A real
  DRA selector using an unsupported macro would silently evaluate to
  whatever the *supported* prefix produces instead of failing loud. Worth a
  one-line fix (`if *pos != tokens.len() { return None; }`) whenever this
  evaluator is next touched, but out of scope for this read-only scout.

A parallel, narrower `parse_cel_value`/`parse_cel_primary` family (L2609+)
backs `eval_cel_apply_config` for MutatingAdmissionPolicy JSON-patch value
expressions — object root only, `+` for concat/add, no boolean logic. Not
relevant to DRA (selectors are boolean expressions over `device`).

## 2. Real DRA selector shapes (upstream release-1.36)

Sources fetched into `temp/research/` (not previously cached):
`dra-utils-builder.go`, `dra.go`, `allocator_testing.go` (the shared fixture
builder backing `k8s.io/dynamic-resource-allocation/structured`'s own
allocator tests — the closest available proxy for "real" selector usage,
since it is exercised by the allocation algorithm itself, not just the CEL
package's feature-coverage tests), `cel-compile.go`, `cel-compile_test.go`,
`wrappers.go`, `dynamicresources_test.go`, `devicetaints_test.go`,
`partitionabledevices_test.go`, `dra-integration-helpers.go`.

`k8s.io/dynamic-resource-allocation/cel/compile.go` (the reference
evaluator DRA actually runs — read for registered features, not ported)
shows the `device` variable is `{driver: string, attributes: map[domain]
map[id]any, capacity: map[domain]map[id]Quantity, allowMultipleAllocations:
bool}`, built on the full Kubernetes CEL base environment (`environment.
MustBaseEnvSet`) plus one DRA-specific function (`includes`, gated behind
the alpha `DRAListTypeAttributes` feature as of 1.36).

Shape census (frequency counted in `allocator_testing.go`, the real-usage
proxy; compile_test.go referenced separately as "language capability, not
observed real usage"):

| Shape | Example | Verdict |
|---|---|---|
| Driver equality | `device.driver == "foo.example.com"` | ✅ covered |
| Bool field on device root | `device.driver == "x" && device.allowMultipleAllocations == true` | ✅ covered |
| Attribute dot access, compared | `device.attributes["dra.example.com"].kind == "shared"` | ✅ covered |
| Attribute bracket access | `device.attributes["dra.example.com"]["name"]` | ✅ covered |
| Attribute as bare bool predicate | `device.attributes["dra.example.com"].boolAttribute` | ✅ covered |
| Optional chain + orValue | `device.attributes["example.com"].?type.orValue("") == "devicetaints"` | ✅ covered (verbatim — `.?field`/`.orValue()` already implemented) |
| `&&`/`||` composition of the above | `device.attributes["x"].kind == "shared" \|\| device.attributes["x"].kind == "fallback"` | ✅ covered |
| **Quantity comparison** | `device.capacity["dra.example.com"].memory.compareTo(quantity("6Gi")) >= 0` | ❌ not covered — **~20+ occurrences, the single most common shape in the corpus** |
| Map-key presence check | `"dra.example.com" in device.attributes` | ❌ not covered — 0 occurrences in allocator_testing.go, present only in cel-compile_test.go as the documented safe-access idiom before a Quantity/attribute lookup |
| Semver comparison | `device.attributes[...].version.isGreaterThan(semver("0.0.1"))` | ❌ not covered — 0 occurrences in allocator_testing.go, only in cel-compile_test.go |
| Quantifier macros (`exists`/`all`/`map`/`filter`/`exists_one`), `.matches()`, `includes()` | `device.attributes[...].names.exists(x, x > 0)` | ❌ not covered — 0 occurrences in allocator_testing.go; gated behind alpha `DRAListTypeAttributes` upstream |
| `cel.bind()` | `cel.bind(dra, device.attributes["x"], dra.name)` | ❌ not covered — 0 occurrences in allocator_testing.go |
| Deliberately-invalid selector (negative test) | `device.attributes["driver"].exists` (bare, no macro args — tests CEL *runtime error* handling) | N/A — not a real selector, a negative-path fixture in dra.go:1332 |

## 3. Scope for mayor-8qcaw's CEL portion (verdict B extensions)

**Mandatory** (block the narrow "must deallocate after use" / basic
allocation conformance target mayor-8qcaw cites, since Quantity-gated
capacity selectors are the dominant real shape):

1. **`device` root binding** — extend `parse_vap_primary`'s root-identifier
   check. ~10-20 LoC.
2. **Generic function-call postfix** — generalize
   `parse_vap_field_chain`'s hardcoded `orValue` special case into an
   arg-list parser (reuse the existing `[...]`-literal comma-parsing
   pattern already in `parse_vap_primary`) dispatched by `(value-tag,
   method-name)`, plus a bare-`Ident(args)` global-function call path in
   `parse_vap_primary` (today `Ident` followed by `(` is unhandled/silently
   truncated per the robustness gap above). ~50-70 LoC.
3. **Quantity type + `quantity()`/`.compareTo()`** — represent a Quantity
   as a tagged JSON value produced by `quantity("6Gi")`, reusing the
   Kubernetes-suffix parsing logic that **already exists twice** in this
   codebase (`crates/scheduler/src/lib.rs:1120` and
   `crates/apiserver/src/quota.rs:67`, both named `parse_quantity_milli`);
   `.compareTo()` compares two milli-scaled i64s and returns -1/0/1. A
   third copy in `admission.rs` matches this codebase's existing
   duplication convention rather than motivating a shared-crate
   extraction. ~40-60 LoC.

Total mandatory: **~150-250 LoC** including unit tests mirroring the
existing VAP test style.

**Deferred / not required for the narrow conformance target** (zero
occurrences in the real allocator fixture corpus; upstream itself gates
several of these behind alpha feature flags): `in` membership operator,
`semver()`/`.isGreaterThan()`, quantifier macros (`exists`/`all`/`map`/
`filter`/`exists_one`), `.matches()`/`includes()`, `cel.bind()`. Each would
be its own small, independent extension (~20-80 LoC) if a future DeviceClass
selector needs it — file follow-on beads only when that need materializes,
per Rule 2 (no speculative features).

## What this scout did not verify

Did not exhaustively search third-party/production DeviceClass CRD samples
via `gh api /search/code` (the task's optional dimension) — the upstream
allocator test corpus alone already gave a clear, high-confidence signal
(dominant Quantity-comparison shape, zero real use of the deferred
features), so the additional search was judged low-marginal-value against
the budget and skipped. If a future implementer hits selector shapes not in
this census, re-run that search then.
