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
When kubectl/client-go/KCM send an object as `application/vnd.kubernetes.protobuf`, u7s decodes it with a hand-written `prost` struct in `crates/apiserver/src/proto.rs`. **If a field exists in the upstream k8s `*.proto` but is NOT declared (with the correct field number) in the u7s prost struct, that field is SILENTLY DROPPED on decode** — the JSON u7s stores is missing it, with no error and no compile-time signal. This has bitten conformance repeatedly, each time as a separate "mysterious missing field" investigation:
- PodSpec.enableServiceLinks (tag 26) — #605
- PodSpec.runtimeClassName (tag 29) — #600
- Service.status (was opaque bytes, now typed ServiceStatus) — #597
- EndpointSlice tag-swap (metadata/endpoints/ports/addressType) — #609
- PersistentVolumeClaim.status (no status field in the struct) — #622
- PodDisruptionBudget.status.disruptedPods (field 3 status not decoded) — #627
- ObjectMeta.ownerReferences not decoded by object_meta_to_json — #626
- Container.resizePolicy (field 23) — mayor-op18 (open)

**Rule when touching ANY proto struct / fixing a "field is missing after a write" bug:** the cause is almost always a missing field in the prost struct. Add the field with the correct upstream field NUMBER (check k8s `staging/src/k8s.io/api/<group>/<v>/generated.proto`), decode it, and add a proto-round-trip regression test (`decode_<kind>_proto_preserves_<field>`). **Higher-leverage move:** when fixing one, AUDIT the rest of that struct's fields against the upstream .proto in the same pass — there are likely siblings also missing. A systematic proto-struct-vs-upstream audit (its own bead) would surface the remaining drops in one sweep instead of one-conformance-spec-at-a-time.

## ⚠️ PATTERN — ObjectMeta serde round-trip drops ownerReferences (and any field ObjectMeta doesn't declare)
Several handlers round-trip an object's metadata through the typed `ObjectMeta` struct: `serde_json::from_value::<ObjectMeta>(obj["metadata"])` then `to_value(...)` back. **`ObjectMeta` does NOT declare every metadata field — notably `ownerReferences` — so the round-trip SILENTLY DROPS undeclared fields.** This dropped ownerReferences on EVERY create / decode until found, breaking GC/ownership cluster-wide. Bitten 3×, each a different code path:
- `create_namespaced_resource` ObjectMeta round-trip — #626
- `object_meta_to_json` (proto path) — #626
- `stamp_cr_fields` (cr.rs, for custom resources) — #629

**Current workaround pattern (used in all 3 fixes):** save the field before the round-trip and restore it after — `let saved = obj["metadata"]["ownerReferences"].clone(); /* round-trip */; if !saved.is_null() { obj["metadata"]["ownerReferences"] = saved; }`. **Better long-term fix (worth a bead):** either add the missing fields (ownerReferences at minimum) to the `ObjectMeta` struct so the round-trip is lossless, OR stop round-tripping metadata through ObjectMeta where only a couple of fields are being set (mutate the JSON in place). When you add a NEW handler that touches metadata, do NOT round-trip through ObjectMeta without preserving ownerReferences (and audit whether other fields like finalizers/managedFields are at risk too).
