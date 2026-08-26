# Proto typing initiative — decision record (2026-07-03)

Durable context for a future mayor. Why we're moving proto decode to prost-build
codegen, and why we rejected the alternatives. EPIC: **mayor-xmu4** (phases
mayor-dqwf/tkyb/0vl5/2bfd).

## The problem this solves
The single most recurring bug class in the project: `crates/apiserver/src/proto.rs`
is (as of this decision) ~17.6k lines of **hand-written PARTIAL prost structs** —
224 of 643 upstream message types; e.g. `PodSpec` decoded 11 of 41 fields. A field
present in the upstream `.proto` but absent from the hand struct is **silently
dropped on decode**, invisible until it causes a conformance failure. The week of
2026-06-26 → 2026-07-03 fixed ~10 instances (enableServiceLinks, PDB spec,
Deployment/RS status, Job spec/successPolicy/podFailurePolicy, Lease MicroTime
nanos + renewTime, Volume defaultMode, generic PATCH TypeMeta, PodSpec
activeDeadlineSeconds, ResourceQuota scopeSelector). Every `// skipped` in proto.rs
is a latent bug.

## The decision: DIRECTION A — prost-build codegen
Generate COMPLETE Rust structs FROM upstream `generated.proto` via prost-build.
Completeness becomes **structural** — you cannot silently omit a field (all fields
generate, or the build fails). This permanently eliminates the bug class.

## Why NOT the two alternatives

### Status quo (keep hand-maintaining proto.rs) — rejected
A worsening treadmill. Upstream adds ~28 fields/release; each field u7s needs is a
manual PR to proto.rs, and its absence is invisible until it bugs. We were paying
multiple silent-drop-bug PRs per week.

### Direction B (our Rust types = source of truth; derive proto + compat-check) — rejected
This was the operator's initial architectural lean, and it is **correct reasoning
for Go**: upstream k8s treats the Go structs as source of truth; `generated.proto`
AND the OpenAPI/JSON schema are *derived* from them (via `go-to-protobuf` and
openapi-gen). So treating upstream's *derived proto* as *our* source of truth is
deriving-from-a-derivation — backwards.

**Why it doesn't translate to Rust (spike a65027ab, 2026-07-03):**
1. **No Rust `types → .proto` tool exists.** Surveyed prost-build, prost-reflect,
   protobuf-codegen, protoc-gen-prost, tonic-reflection, protofish (7 crates) —
   every one goes proto→Rust, never the reverse. Go has `go-to-protobuf`; Rust has
   no equivalent. So Direction B in Rust is NOT "author types, derive proto." It is
   "hand-author complete structs with `#[prost(tag=N)]` + build a custom
   compat-checker" — i.e. **proto.rs but complete and documented**.
2. **Its compat-checker catches wrong tag NUMBERS but NOT omissions** — a field you
   never authored has no tag to diff against upstream. So Direction B does **not
   structurally kill the bug class it is meant to fix**; a missed field is a latent
   bug identical to today.
3. **~2× the cost** (5–10 days hand-authoring ~51k LoC + 1.5–2 days for the
   checker) vs Direction A (3–5 days).
4. Field numbers are **upstream-pinned either way** — wire-compat is defined by the
   numbers, so even "our types" don't get to choose them.

Direction B's ONE genuine win is **documentation** — authored types can carry rich
per-field k8s semantic doc comments (the spike PoC was 2× the LoC, all semantic).
That win is **separable**: it can be layered onto Direction A later (a doc-comment
pass parsing upstream proto `//` comments into the generated types) without
hand-authoring everything. If deep in-code k8s documentation becomes a priority,
revisit that as an add-on to A — not as a reason to choose B.

## Key facts (from prior research)
- `k8s-proto-schema-churn-1.34-1.36-2026-07-03.md`: upstream GA proto is
  addition-dominated — 55 field additions, 0 breaking changes across 1.34→1.36.
  The one "removal" was an alpha field (`WorkloadReference` #42) that lasted one
  release. Our `.proto` FILES are already complete/current at v1.36 (the problem is
  the partial structs, not the schema files). Full-codegen binary bloat ~225KB
  (negligible vs a 10–30MB tokio/hyper binary). Per-release upkeep ~2–4h.
- `proto-source-of-truth-spike-2026-07-03.md` + `proto-spike-poc/lease-direction-b/`:
  the A-vs-B toolchain eval + a byte-level-verified Lease PoC.

## The hard part of the migration (for whoever does it)
proto.rs's decode functions (~200) COMBINE proto-decode + `serde_json` emission in
one pass. prost-build only generates the decode structs. So the migration must
**split** each into generated-decode + a JSON-emission adapter layer. That adapter
design is exactly what Phase 1 (mayor-dqwf, the GATE) must prove on one group
before fan-out. Don't fan out until the pattern is proven.

## Downstream: OpenAPI v2 (mayor-52wo, deferred)
Complete typing is a **necessary-not-sufficient** prereq for generated OpenAPI.
NOTE mayor-52wo currently plans to embed a STATIC upstream OpenAPI blob — a
different approach. Once typing lands, generated OpenAPI (from the typed schema +
a metadata pass for descriptions/validation markers) becomes an option that could
supersede the static blob. Decide that when Phase 4 completes; linked relates-to.
