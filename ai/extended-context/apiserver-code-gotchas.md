# Apiserver code gotchas

Scope: non-obvious correctness constraints in the u7s apiserver that a fresh mayor (or worker) would not infer from the code alone — each has bitten conformance before. These are "why the code is shaped this way," not operational process (those live in `bd memories`). Recategorized from bead memories 2026-06-26 because they are code-findings, not operational rules.

## KCM panic propagation kills root-ca-cert-publisher
KCM controller goroutines run inside `sync.WaitGroup.Go`, which **re-panics after recovery** — so a panic in ANY single controller (e.g. the endpoints controller) kills the **entire** kube-controller-manager process. Symptom: all KCM controllers go silent at once, including `root-ca-cert-publisher`, so `kube-root-ca.crt` is never created in new namespaces → pods with projected ServiceAccount-token volumes stick in `ContainerCreating`. If you see broad "pods stuck ContainerCreating + no kube-root-ca.crt" symptoms, look for a panicking controller upstream, not a missing feature.

## fetch_initial_events / sendInitialEvents must apply read-time defaults
`fetch_initial_events` in `watch.rs` MUST call `apply_defaults` on each item before returning. Raw store bytes lack read-time defaults (e.g. `ipFamilies` on Services). Seeded objects (default/kubernetes, kube-system/kube-dns) are stored WITHOUT `ipFamilies` — defaults are applied at read time only. Bypassing this makes the KCM endpoints controller panic on `IPFamilies[0]` at startup (the `sendInitialEvents=true` watch path), which (per the panic-propagation gotcha above) kills the whole KCM. Fixed in c777cd7; regression test `fetch_initial_events_applies_defaults_to_snapshot_items` in watch.rs. General rule: any path that returns stored objects to a client/controller must apply the same read-time defaults the normal GET/LIST path does.

## exec/attach: kubelet uses different query-param names than kubectl
On the apiserver→kubelet exec/attach proxy path, the kubelet expects DIFFERENT param names than kubectl sends, and integer booleans:
- kubectl sends `stdin`/`stdout`/`stderr`; kubelet expects `input`/`output`/`error` (k8s api/core/types.go: ExecStdinParam=`input`, ExecStdoutParam=`output`, ExecStderrParam=`error`).
- kubelet expects integer booleans (`1`/`0`), not `true`/`false`.
- `command` passes through unchanged.
So the proxy must map e.g. inbound `stdin=true&stdout=true&command=echo` → outbound `input=1&output=1&command=echo`. (Original fix PR #366 handled the boolean encoding but the param-name translation is the load-bearing part.)

## CSINode has no status subresource / admission logic (known conformance gap)
In a real cluster, CSINode (storage.k8s.io/v1) has a custom status subresource and admission logic. The u7s generic handler serves CSINode without these. The kubelet does NOT depend on it for basic node registration, so it's not a startup blocker, but it IS a conformance gap — revisit when working on storage conformance or related sonobuoy failures.

## ⚠️ PATTERN — proto-decode field drops (the single most recurring bug class)
When kubectl/client-go/KCM send an object as `application/vnd.kubernetes.protobuf`, u7s
decodes it via `prost-build`-**generated** types compiled by `crates/apiserver/build.rs`
straight from the real vendored upstream `*.proto` files under `proto-include/` (protoc,
not hand-authored structs — see `bd memory proto-rs-hand-rolled-structs-are-dead-code`).
The hand-rolled structs that used to live in `proto.rs` (`PodSpec`, `Container`, etc.) are
gone entirely; `decode_proto_by_kind_and_version` (`proto.rs`) dispatches by Kind/apiVersion
to a `decode_<kind>_proto_gen` function in the matching per-group adapter module —
`core_gen_adapter.rs`, `apps_gen_adapter.rs`, `batch_gen_adapter.rs`, `rbac_gen_adapter.rs`,
and siblings for the other API groups.

Because the generated types are structurally complete and protoc-assigned (no possibility
of a hand-authored tag mismatch), **the field is never actually missing from the decoded
struct** — the drop happens one layer up: `decode_<kind>_proto_gen` calls the generated
type's `::decode()`, getting a fully-populated struct, then hands it to a `gen_<kind>_to_json`
(or a nested `gen_<field>_to_json`) helper that manually copies fields into the served JSON
`Value` — and that helper simply doesn't read every field. This has bitten conformance
repeatedly, each time as a separate "mysterious missing field" investigation (kept here as
historical instances of the pattern, from back when the cause genuinely was a missing prost
tag in the old hand-rolled `proto.rs` structs, through the post-codegen-migration instances
where the cause is a `gen_*_to_json` field the adapter forgot to copy):
- PodSpec.enableServiceLinks (tag 26) — #605
- PodSpec.runtimeClassName (tag 29) — #600
- Service.status (was opaque bytes, now typed ServiceStatus) — #597
- EndpointSlice tag-swap (metadata/endpoints/ports/addressType) — #609
- PersistentVolumeClaim.status (no status field in the struct) — #622
- PodDisruptionBudget.status.disruptedPods (field 3 status not decoded) — #627
- ObjectMeta.ownerReferences not decoded by object_meta_to_json — #626
- Container.resizePolicy (field 23) — #631 (mayor-op18)
- ReplicationController.status, DaemonSet.status, Job.status, CronJob.status (decoded but never emitted to JSON) — #636 (mayor-cokf)

**Rule when touching ANY proto decode / fixing a "field is missing after a write" bug:**
first check whether the field is present on the **generated** type (`cargo doc --open -p
u7s-apiserver` or grep the vendored `proto-include/.../generated.proto` for the field) —
if it is, the fix is in the corresponding `gen_<kind>_to_json`/`gen_<field>_to_json`
function in the matching `*_gen_adapter.rs`: read the field off the already-decoded struct
and add it to the JSON `Value`. Add a proto-round-trip regression test
(`decode_<kind>_proto_gen_preserves_<field>`). Only if the field is missing from the
**generated** type too does the vendored `.proto` under `proto-include/` need updating from
upstream — that is rare and a different (bigger) fix than the usual adapter oversight.
**Higher-leverage move:** when fixing one, AUDIT the rest of that `gen_<kind>_to_json`
function's fields against the generated struct in the same pass — there are likely
siblings also missing.

## ⚠️ PATTERN — ObjectMeta serde round-trip drops ownerReferences (HISTORICAL, fixed)
This class of bug is fixed at the type level: `ObjectMeta` now declares an `owner_references`
field (PR #1079, mayor-0bd14.2), so the `serde_json::from_value::<ObjectMeta>` /
`to_value(...)` round-trip is lossless. The 3 manual save/restore workarounds this section
used to document (`create_namespaced_resource`, `object_meta_to_json`, `stamp_cr_fields`) were
all removed once the type-level fix landed (PR #1081). Kept as a pointer to why `ObjectMeta`
looks the way it does — do not reintroduce a save/restore workaround for this field.
