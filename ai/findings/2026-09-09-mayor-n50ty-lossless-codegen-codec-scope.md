# Lossless codegen JSON codec: scope + estimate

Bead: mayor-n50ty
Date: 2026-09-09
Author: worker agent-a99fda01e8702889a (read-only investigation, Shape-3 audit)
Status: DESIGN INPUT — no product code changed, no PR merge. Decides mayor-m10di Q3.

## Answer first

**Do not invest in the codec. Hand-write the ~23 `types.rs` status structs now**,
exactly as mayor-m10di already recommended, and do not revisit the codec unless
priorities change materially. The codec is not a shortcut that saves the
hand-written work — it is a **strictly larger, higher-risk project** that would
still need to solve the same "which fields does the apiserver reason about"
problem, plus several problems the hand-written path never has to face at all.
Effort to build a genuinely lossless codec: **large** (multi-week, multiple
PRs, comparable to or bigger than the existing multi-PR "codegen Phase 4.x"
wire-format EPIC already in-tree — see §4), **high risk**
(the failure mode is silent field drops, the exact bug class this whole effort
exists to prevent), for a payoff that turns out to be **small**: the things it
would supposedly "unblock beyond status" (defaults, discovery, protobuf content
type) already have their own working solution today. Hand-written is **~250
LOC scaled to ~23 structs (≈300 LOC), medium effort, proven twice** (mayor-ds8hb,
mayor-ohh8o) and already 2-for-3 done for the currently-typed status paths.

## 1. What "lossless / serde-faithful" means here, precisely

A codec is lossless/serde-faithful over real k8s JSON iff, for every value `x`
a real k8s client can legally send or a real k8s controller can legally store:

1. **Exact round-trip**: `from_json(to_json(x)) == x` bit-for-bit at the JSON
   level (key order aside), not just "the fields the codec's author thought of."
2. **No dropped fields** — including fields the codec's schema doesn't know
   about yet (a field added in a newer k8s minor version than the vendored
   `.proto`, or a legitimate but unusual extra key). This is **forward
   compatibility**, not just correctness against today's schema.
3. **Correct proto3-optional / Go-`omitempty` semantics** — "absent" and
   "explicitly zero/empty" must stay distinguishable exactly where upstream
   itself distinguishes them (pointer Go fields), and may collapse exactly
   where upstream itself collapses them (plain Go fields with `omitempty` —
   upstream *cannot* round-trip explicit-zero there either, so matching that
   collapse is correct, not lossy).
4. **camelCase JSON keys**, matching upstream's exact `json_name` per field
   (not just a generic snake→camel string transform, which misses edge cases
   protoc's own `json_name` resolution already handles).
5. **Merge-safe**, not just snapshot-safe: the JSON serving boundary needs
   partial-body PATCH/PUT semantics (RFC 7396 `null` = delete a key) layered
   on top of the schema, not just "serialize a complete struct."

The bar in (2) is the one that turns out to matter most below.

## 2. Where today's codegen is lossy (and where it correctly is NOT)

The codegen machinery here (`crates/apiserver/build/codegen.rs`, 10,968 lines;
`crates/apiserver/src/proto_exceptions.rs`, 440 lines) is a real,
already-substantial, descriptor-driven system — the multi-PR "codegen Phase
4.x" EPIC (`git log`: Phase 4.5 `92529c9f`, 4.7 `b66fc94f`, 4.8 `37f2385d`, 4.9
`1ac6e7a6`, all 2026-08-20) that mechanically walks compiled `FileDescriptorProto`
bytes to generate proto↔JSON conversions, with a fail-loud `panic!` for any
field shape the walker doesn't recognize
(`crates/apiserver/build/codegen.rs:566-571`, `:666-671`). It is much more
sophisticated than "hand-mapped" — but it was built for one purpose, stated
explicitly in its own doc comment:

> "Encoders — JSON (u7s's own already-validated stored representation) →
> Kubernetes protobuf wire format, **for hot-path GET/LIST responses** ...
> Field coverage is scoped to what matters for kube-proxy/kubelet/scheduler
> consumers ... **rather than full 1:1 parity**."
> — `crates/apiserver/src/core_gen_adapter.rs:2780-2785`

That is the protobuf-content-negotiation path (`content_type.rs`), not the
general JSON-serving boundary. Concretely:

- **No unknown-field passthrough anywhere.** `emit_field_encode` builds a
  fresh `serde_json::Map::new()` and only ever inserts fields the descriptor
  declares (`crates/apiserver/build/codegen.rs:862-877`, `896-904`) — no
  `flatten`/`passthrough`/catch-all mechanism exists anywhere in the 10,968-line
  file. A field present in a stored JSON object but absent from the vendored
  `.proto` (a newer k8s field, or anything genuinely unknown) is unrecoverable.
  This is the single blocker for definition-point (2) above, and it is
  architectural, not a bug to patch: see §3.
- **~90% of the generated adapters are one-directional.** 201 `generate_*`
  functions exist; only **~18 are bidirectional** (16 call
  `generate_message_codec` directly, plus 1 that calls both directions and 1
  bespoke bidirectional body) — the other **~183 are encode-only** (172 call
  `generate_message_encode_only` directly, e.g. `generate_deployment_status`
  at `codegen.rs:3815-3839` calling `generate_message_encode_only` at
  `:3819`, plus 11 bespoke encode-only bodies). Most status types have no
  generated decode direction at all today.
- **26 permanently, deliberately dropped fields**, `proto_exceptions.rs:177-400`
  (`DELIBERATE_OMISSIONS`), e.g. `ObjectMeta.managedFields`,
  `VolumeSource.awsElasticBlockStore` (~15 legacy in-tree volume plugins) —
  scope decisions, not oversights, but real, permanent data loss vs point (2).
  `KNOWN_GAPS` (`codegen.rs:406`) is empty, meaning the EPIC considers itself
  complete **against its own reduced scope**, not against full JSON parity.
- **Zero-value/empty-string filters are a mix of correct and previously-buggy.**
  `.filter(|&v| v != 0)` on `observedGeneration` (`codegen.rs:1293-1294`,
  `pod_status_delegated_field`) and 30+ sibling sites (`:1765`, `:1810-1822`,
  `:3783-3804`, `:4126-4135`, ...). Most of these correctly mirror upstream's own Go
  `omitempty`-on-plain-`int64`-field collapse (upstream *also* can't
  distinguish `observedGeneration: 0` from absent — matching that is
  faithful, not lossy). But this exact pattern already produced one confirmed,
  shipped, live bug: commit `6877c906` (2026-09-04) — `spec.replicas` was
  unconditionally defaulted to `0` on protobuf decode, because `replicas` *is*
  a genuinely pointer/optional field upstream where explicit-zero is
  meaningful, and the codegen's zero-collapse heuristic didn't distinguish
  it from the omitempty-plain-field case. **Telling the two apart requires a
  per-field check against upstream's Go type**, which the current templates
  do by hand-reasoned code comment (e.g. `codegen.rs:1284-1290`), not by a
  mechanical rule — i.e. exactly the same manual, per-field audit burden a
  lossless rewrite would still have to redo.
- **Generic string encode also filters empty**, unconditionally, with no
  escape hatch: `codegen.rs:424-436` (`.filter(|s| !s.is_empty())`), inside
  the *mechanical* (non-delegated) walker every message falls into by
  default.

## 3. Mechanism options

**(a) Generate a parallel struct from the proto descriptors, in the
`types.rs` minimal-field-plus-`rest` shape.** Layering serde directly onto
the existing prost structs is structurally impossible: they are
`#[derive(Message)]` for protobuf wire encoding, and every field on them is
walked by that derive via its own `#[prost(...)]` attribute, so there is no
way to add a `#[serde(flatten)] rest: serde_json::Value` catch-all — it isn't
a wire field, and prost's derive has no concept of "extra, non-wire" fields.
The only mechanically sound path is to generate a **second, JSON-only struct
per message type**, reusing the already-vendored `.proto` descriptors and the
existing `json_name`-aware field-naming logic (`proto_exceptions.rs:409`, the
`json_key` helper) as the schema source — structurally identical to what
ds8hb/ohh8o hand-wrote, just machine-generated. This still has to add the
missing decode direction for the ~183 encode-only types, design the
merge/passthrough logic the current snapshot-only walker has never needed
(§4), and re-derive every zero/omitempty judgment call against upstream Go
pointer-ness (the same audit the replicas bug proves is easy to get wrong) —
and even then it only covers fields known to the *vendored* `.proto` at
generation time, landing anything else in `rest` for exactly the reason a
hand-written struct's `rest` field already does. Generation buys nothing on
the one part of the work that matters: choosing *which* fields the apiserver
reasons about is a judgment call a schema walker cannot make. A generated
struct either types everything (defeating "minimal field," multiplying the
omitempty-audit burden across every field instead of ~5-10 per type) or
types nothing (back to hand-picking, per type, exactly what ds8hb/ohh8o
already did).

**(b) A serde attribute layer on the prost structs** (rename_all + per-field
rename + skip_serializing_if, no flatten). `crates/proto-generated/build.rs:10-23`
configures `prost_build::Config` with one `type_attribute` (a `Sentinel`
derive, unrelated) and zero serde derives or renames today. Building this
needs the same per-field `json_name` walk as (a) to get k8s's exact
camelCase, so it is no cheaper, and it inherits (a)'s structural blocker with
no escape hatch: there is nowhere to put an unknown-field catch-all on a
`Message`-deriving struct, and (b)'s whole premise is reusing that same
struct rather than generating a second one.

**(c) An OpenAPI/JSON-schema-driven generator**, sourcing field/type
information from k8s's OpenAPI v3 schema instead of the vendored `.proto`.
No OpenAPI/swagger schema is vendored anywhere in this repo, unlike the 28
`.proto` files already vendored and already feeding the Phase-4.x EPIC, so
this option needs a brand-new vendoring pipeline (fetch, pin, and re-vendor a
multi-MB schema document per k8s version bump) before any codegen work
starts — on top of sharing (a)'s two hard problems: field selection still
needs human judgment, and unknown-field passthrough still needs a
hand-designed `rest` mechanism, since OpenAPI's `additionalProperties`
doesn't map onto Rust structs automatically either.

**(d) Adopt an existing crate** (e.g. `pbjson`/`pbjson-build`, which
generates serde impls for the canonical protobuf-JSON mapping). The canonical
protobuf JSON mapping has the same no-unknown-field-passthrough property
protobuf JSON has always had, so it fails definition-point (2) regardless,
and it adds a new external dependency against the project's
minimal-dependency stance, on top of the bead's explicit "no k8s-openapi."

**Only (a) is mechanically sound, and it saves nothing on the field-selection
judgment that is the actual work, while adding real new cost: decode-direction
backfill, a not-yet-designed merge/passthrough capability, and a fresh
per-field omitempty-vs-pointer audit across a much larger field surface than
the ~5-10 fields per type the apiserver actually reasons about.**

## 4. Effort estimate to build the codec (mechanism (a)) anyway

- **Decode-direction backfill**: ~183 encode-only adapters need a matching
  decode function. Each of the existing ~18 bidirectional pairs runs
  roughly 20-40 generated lines per direction for a small message
  (`generate_pod_status`/`generate_container_status` are representative);
  scaled up, **order of 2,000-4,000 generated LOC** of new decode logic (not
  hand-typed, but hand-verified — see next point).
- **Merge/passthrough semantics**: does not exist in the walker at all today
  (it only does full-snapshot proto↔JSON conversion, never a "here's the
  existing stored object, only touch the keys you recognize, respect RFC 7396
  null-delete" merge). This is a **new capability**, not a template tweak —
  every recursive nested-message case (`emit_mechanical_encode`/`_decode`,
  `codegen.rs:512-565`, `632-665`) would need a redesign to thread "existing
  value at this path" through instead of building fresh maps. Rough
  complexity: comparable to rewriting the walker's core, not extending it.
- **Per-field omitempty-vs-pointer audit**: ~30+ existing zero-filter call
  sites need re-verifying against upstream Go source (one wrong call already
  shipped and broke ReplicaSet scheduling in production — `6877c906`), *plus*
  every field a decode-backfill or minimal-field selection newly touches.
- **Risk**: high. The failure mode (silently dropping/mis-defaulting a field)
  is exactly the incident class (`mayor-xv1pk` imagePullPolicy bug, the
  `6877c906` replicas bug) the whole typed-status effort exists to prevent —
  building a bigger, more mechanical system to solve it is fighting the
  problem with more surface area for the same class of bug, verified only by
  re-deriving the same per-field judgment calls by hand anyway.
- **Coverage if it worked**: all ~24 built-in status kinds plus, in
  principle, spec/full-object/defaults/discovery — genuinely broader than the
  hand-written path's status-only scope. See §5 for why that breadth doesn't
  actually save work.
- **Rough total**: **large** — multi-week, multiple PRs, on the order of the
  already-4-PR (4.5/4.7/4.8/4.9) Phase-4.x EPIC's scale *or bigger*, since that
  EPIC never had to solve merge-safety or unknown-field passthrough at all.

## 5. Head-to-head vs the m10di hand-written path

| | Hand-written `types.rs` (m10di) | Codec (a) |
|---|---|---|
| Precedent | Shipped twice: mayor-ds8hb (19 structs, ~250 LOC, `defaults.rs`), mayor-ohh8o (`discovery.rs`); 2 of the 3 currently-typed statuses (`NamespaceStatus` `types.rs:636-644`, `CertificateSigningRequestStatus` `types.rs:750-764`) already use exactly this pattern | None — would be new |
| Scope of field-selection judgment | Same either way — a human decides which ~5-10 fields per type the apiserver reasons about | Same, cannot be automated (see §3) |
| Unknown-field passthrough | Free — `#[serde(flatten)] rest: serde_json::Value` is one line per struct, already proven | Has to design + build the same mechanism from scratch inside a walker that has never needed it |
| Decode direction | Comes free with `#[derive(Deserialize)]` | ~183 of 201 existing adapters need it built |
| Merge/PATCH-null semantics | Comes free — serde `Option<T>` + the existing `reject_non_object_status`/RFC 7396 handling at the handler boundary already does this | Not designed at all in the walker today |
| LOC (extrapolated) | ~300 (23/19 × 250) | Multi-thousand (see §4) |
| Risk | Low — narrow, reviewable, per-field | High — broad mechanical surface, same silent-drop failure mode, already caught once live |
| Does it unblock more than status? | No — but nothing else needs unblocking: `defaults.rs`/`discovery.rs` already got the *same* hand-written treatment (ds8hb/ohh8o) successfully; the protobuf content-type path already has its own working (if intentionally lossy) Phase-4.x solution serving its own purpose | In theory yes (spec, full objects), but everything it would unblock already has a solution, so the marginal benefit is small |

**Less total work: hand-written, decisively.**

## 6. Recommendation

**Hand-write the ~23 status structs now** (mayor-m10di's own plan), and do
**not** make the codec a prerequisite. The codec is not "the same work,
automated" — it is a materially larger, higher-risk project that still
requires the one judgment call (which fields matter) that can't be automated,
while adding a merge-safety and passthrough design the existing codegen
machinery has never needed and doesn't have. Compose with codegen later only
if the *protobuf wire-format* Phase-4.x EPIC's own scope grows toward
something the JSON boundary could reuse cheaply — not before, and not as a
blocker on m10di.

## 7. Confidence

- Codegen structure, one-directional/bidirectional counts (~183 vs ~18), the
  `DELIBERATE_OMISSIONS`/`KNOWN_GAPS` tables, and the absence of any
  passthrough mechanism: **high** — grepped and read directly in source.
- The `Message`-derive-incompatible-with-flatten claim underlying (a) and
  (b): **high** — structural property of prost's derive macro, not an
  assumption.
- The replicas-bug-class evidence for the omitempty/pointer audit burden:
  **high** — verified against the actual commit (`6877c906`, 2026-09-04) and
  its own commit message.
- Effort estimate for building (a): **medium-high confidence it is large and
  risky**, extrapolated from the existing Phase-4.x EPIC's own multi-PR scale
  for a strictly easier (lossy-by-design, encode-mostly) problem; the exact
  LOC number is a rough order-of-magnitude, not a measured quantity.
