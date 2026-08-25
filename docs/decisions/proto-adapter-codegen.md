# Schema-driven codegen for k8s proto adapters via build.rs

**Status:** Accepted
**Date:** 2026-08-14

## Context

Each vendored k8s API package has a hand-rolled `_gen_adapter.rs` file that mediates between protobuf and JSON: pairs of `json_to_<type>_proto` (JSON → proto for admission/PUT paths) and `gen_<type>_to_json` (proto → JSON for storage/GET paths). The total across `core_gen_adapter.rs` and its 11 siblings was ~27,694 lines of hand transcription against roughly the same number of proto fields.

The failure mode this shape produced was silent field-drop: adding a proto field required also editing the two hand-rolled paths, and a missed edit stayed silent until a client actually used the field. This class of bug shipped three times in two days in August 2026 — VolumeSource encode (PR #1171), VolumeSource decode (PR #1173), Node `.status.daemonEndpoints` (PR #1177). Each was a single missing branch buried in the corresponding hand-rolled function.

Sentinel-completeness tests (PR #1157) catch the class of bug at CI time, but they are themselves a second hand-maintained transcription of the schema.

## Decision

Generate `json_to_<type>_proto` / `gen_<type>_to_json` at build time by walking the compiled `FileDescriptorSet` (`k8s_descriptors.bin`) emitted by `prost-build`. Splice the generated files into the adapter modules via `include!(concat!(env!("OUT_DIR"), "/<type>_gen.rs"))`. Delete the hand-rolled versions once codegen fully replaces them.

## Rationale

Options weighed:

- **Runtime reflection** — one generic walker at each call site. Rejected: regresses per-call CPU and destroys profileability on a hot path.
- **Macro-derive** — `#[derive(JsonProto)]` on prost types. Rejected: prost erases `json_name` and other JSON-specific info before a derive macro could see it, and prost's generated types are downstream — attaching a derive without vendoring prost is awkward.
- **build.rs codegen** — chosen. Runtime shape is identical to the hand-rolled code being replaced (same `if let Some(x) = ...`, same field ordering), but generated instead of typed. Modeled on `pbjson-build`'s proven approach.

Two properties of the vendored k8s schema make this materially simpler than a general-purpose tool: zero `oneof` and zero proto `enum` anywhere (verified via grep). Neither of the hard cases (oneof-as-Rust-enum, int-enum-as-JSON-string) needs to be solved.

Existing JSON quirk handling in `proto_descriptor.rs` — one mechanical rule (`json_key()`) plus four small const tables (`RENAMES`, `INLINE_EMBEDS`, `OPAQUE_MESSAGES`, `DELIBERATE_OMISSIONS`) — is reused verbatim. The tables are extracted into `proto_exceptions.rs` and `include!`'d by both the test oracle (`proto_descriptor.rs`, `#[cfg(test)]`) and the build script (`build/codegen.rs`). A build script cannot `use` symbols from the crate it is building, so textual splicing is the surgical alternative to widening visibility.

## Consequences

- Small build-time cost (walker + string emission per type). No runtime cost.
- Types migrate one at a time; hand-rolled and generated code coexist during the transition.
- A new field added to a migrated type in a future vendor bump auto-round-trips with zero hand code — verified live in Phase 2 (PR #1184) by adding a throwaway proto field, rebuilding, and confirming full-suite green with no manual edits.
- Phase order: Phase 0 spike (`ObjectReference`, PR #1176) → Phase 1 MVP (`VolumeSource`, PR #1181) → Phase 2 (`PodSpec` / `PodStatus` / `Container` / `ContainerStatus`, PR #1184) → Phase 3 (rest of `core_gen_adapter.rs`) → Phase 4 (11 sibling `_gen_adapter.rs` files). Each phase is a solo PR whose acceptance is the pre-existing sentinel tests staying green plus a Rule-14 regression test proving codegen matches hand-rolled byte-for-byte on revert. Design-time scope estimate: ~20-30 hours for the Phase 0-1 MVP that retires the specific recurring bug class (#1171/#1173); ~185-310 hours for full migration across all 12 adapter files.
- The `DELIBERATE_OMISSIONS` table has grown stale during the migration; it does not affect correctness (codegen consults the smaller `EXCLUDED_FIELDS` list authoritatively) but wants a cleanup pass.
