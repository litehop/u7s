# Typed-status migration: Phase-1 implementation plan

Bead: mayor-m10di
Date: 2026-09-10
Author: worker agent-a5a4b3081e277b0af (read-only investigation + plan, no code changed)
Status: PLAN FOR OPERATOR GREENLIGHT — draft PR, no product code touched.

## Answer first

Phase-1 is one small PR: add a `status_dispatch.rs` per-kind dispatch table
(mirroring `proto.rs`'s decode-map) and wire exactly **three** kinds through
it — retrofit the two already-typed statuses (**Namespace**, **CertificateSigningRequest**)
as a behavior-preserving refactor, plus **one** new struct
(**APIService** — reuses the existing `Condition` type, ~15 LOC). This closes
two real, live gaps discovered during this investigation (not hypothetical):
`put_namespace_status` currently **silently coerces** a scalar status to `{}`
via `unwrap_or_default()` instead of rejecting it, and CSR's real
`/status` route (`cr::put_cr_status`) returns the wrong code (422, not
upstream's 400) for a PUT scalar because it has no typed decode to fail. Only
**one** existing test needs to flip 422→400 (`cr.rs:19643`) — the bulk of Q1's
400/422 split already landed on main on 2026-09-09 (commits `dd4d4e72`,
`9a4cddcd`), before this plan; the dispatch-brief's cited `pods.rs:17719` is
already 400 and does not need to change.

## 0. Correction to the 2026-09-06 scoping doc's status quo

Re-reading source as of 2026-09-10 (post the 2026-09-09 Q1 commits) changes
two facts the earlier findings doc and the bead's Q1 note stated:

1. **The PUT-vs-PATCH 400/422 split is already implemented for the generic
   built-in paths.** `status.rs::reject_non_object_status_put` (400) vs
   `reject_non_object_status` (422), and `replace_status_field` (400,
   built-ins) vs `replace_status_field_dynamic` (422, CR/CRD) already exist
   and are wired into `put_resource_status`, `put_namespaced_resource_status`,
   and `replace_pod_status`. The pods.rs test the dispatch brief named
   (`replace_pod_status_rejects_non_object_status`, `pods.rs:17685`) already
   asserts `StatusCode::BAD_REQUEST` — it was fixed by commit `dd4d4e72`
   (2026-09-09), a day before this plan. **Phase-1 must not re-flip it.**
2. **CSR and APIService (and 7 other cluster-scoped, non-core-group built-ins)
   do not reach `status.rs`'s generic handlers at all.** Route registration
   (`lib.rs:1227-1232`) sends every `/apis/{group}/{version}/{resource}/{name}/status`
   request — cluster-scoped, any group except the empty core group — to
   `handlers::cr::{get,put,patch}_cr_status`, not `handlers::status`. `put_cr_status`
   does look up the static registry to resolve `kind` and the store key
   (`cr.rs:4479-4491`), but always guards with `replace_status_field_dynamic`
   (422) regardless of whether the lookup hit a real built-in — this is the
   "KNOWN EDGE from #1634" the bead notes already flagged, confirmed here at
   `cr.rs:4507`. The 9 kinds funneled through this exact code path are:
   **CertificateSigningRequest, APIService, ServiceCIDR,
   ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
   VolumeAttachment, FlowSchema, PriorityLevelConfiguration, DeviceClass.**
   (Node and PersistentVolume are also cluster-scoped but core-group, so they
   route through `core_put_resource_status` → `status.rs::put_resource_status`
   and already get 400 — unaffected.)

These corrections narrow Phase-1's real Q1 work from "flip pods.rs" to "fix
`put_cr_status`/`patch_cr_status`'s registry-hit branch for the kinds we type",
and surface a second bug — Namespace's silent scalar-to-`{}` coercion — that
was previously described only as "lenient" in the 2026-09-06 doc's open
question #4, not confirmed as a concrete no-test-covers-this gap.

## 1. Phase-1 scope

### Lands in PR-1 (this bead's first apply)

- New module `crates/apiserver/src/status_dispatch.rs`: the per-kind dispatch
  table plus two thin call wrappers (400-on-failure for PUT, 422-on-failure
  for PATCH). See §2.
- Three dispatch-table entries: `Namespace` (existing `NamespaceStatus`),
  `CertificateSigningRequest` (existing `CertificateSigningRequestStatus`),
  `APIService` (new `ApiServiceStatus`, §3).
- `namespaces.rs::put_namespace_status`/`patch_namespace_status` retrofitted
  to call the dispatch table instead of the local ad hoc
  `NamespaceStatus::deserialize(v).unwrap_or_default()` — this is the fix for
  the silent-coercion bug in §0.
- `cr.rs::put_cr_status`/`patch_cr_status` retrofitted: after resolving
  `kind` from the registry-hit/CR-fallback branch, check the dispatch table;
  a hit uses the typed codec (400 for PUT, 422 for PATCH), a miss falls
  through to the existing `replace_status_field_dynamic`/
  `reject_non_object_status` guards, completely unchanged. This is the fix
  for the KNOWN EDGE in §0, and the only site among the 9 affected kinds
  Phase-1 fixes (CSR + APIService); the other 7 stay on the dynamic guard
  until Phase 3 types them.
- Test updates per §4/§5.

### Explicitly NOT in PR-1 (deferred)

- **Phase 2** (next PR after Phase-1 lands): wire the same dispatch-table
  check into `status.rs`'s four generic functions
  (`put_resource_status`/`patch_resource_status`/
  `put_namespaced_resource_status`/`patch_namespaced_resource_status`) —
  deferred out of Phase-1 deliberately (see §8, Rule-2 simplicity: wiring an
  unused check into four functions with zero live dispatch entries is
  speculative). Phase 2 adds this wiring in the same PR as its first
  namespaced/core-cluster-scoped kind: **ResourceQuota** (usage; retires the
  `lib.rs:3494` reconciler coercion) and **Pod** (resize + readiness
  conditions, retrofitting the existing partial typing in `pods.rs`).
- **Phase 3**: the passthrough bulk — Deployment, ReplicaSet, StatefulSet,
  DaemonSet, Job, CronJob, PersistentVolume, PersistentVolumeClaim,
  ReplicationController, HorizontalPodAutoscaler (v1 **and** v2 — see §2 on
  version-keying), Ingress, VolumeAttachment, FlowSchema,
  PriorityLevelConfiguration, ServiceCIDR, ValidatingAdmissionPolicy(+Binding),
  ResourceClaim, DeviceClass, PodCertificateRequest, Node.
- **Phase 4**: retire the Class-A/B guards for kinds now fully typed; retire
  the Class-C read-path coercions for built-ins (gated per Q2 on every
  built-in write entry point converging on the dispatch table); flip the
  three completeness meta-tests' `SAFE`/`TYPED_SAFE` lists to cover only the
  dynamic cr.rs/crd.rs paths.
- **Phase 5** (optional, not scheduled): compose with a future lossless
  codegen codec, per the n50ty audit — not blocking.

### Why this slice

Three kinds, one new struct, two call sites (`namespaces.rs`, `cr.rs`) is the
smallest change that (a) proves the dispatch-table pattern end-to-end for
both a dedicated handler and a shared generic handler, (b) fixes two real
bugs found during this investigation rather than typing something
speculative, and (c) stays entirely inside two non-giant files plus one new
file — `namespaces.rs` and the new module are not on the r871h hot-giant
list, and the `cr.rs` diff is confined to two functions' status-guard
selection, not a structural rewrite of the file.

## 2. Dispatch-table design

**Location**: `crates/apiserver/src/status_dispatch.rs` (crate root, sibling
to `types.rs` and `proto.rs` — it is shared infrastructure called from
multiple `handlers/*.rs` files, the same reason `proto.rs`'s decode map isn't
under `handlers/`).

**Keying**: primarily `kind: &str` (e.g. `"Namespace"`, `"CertificateSigningRequest"`,
`"APIService"`), matching `proto.rs::decoders()`'s convention and rationale
(one wire/JSON layout per kind, the common case). **HorizontalPodAutoscaler
is the one kind needing version-awareness** (v1 `status.currentReplicas`/
`desiredReplicas` vs v2's richer `conditions`/`currentMetrics` — same
apiVersion-dependent-shape exception `proto.rs`'s own doc comment calls out
for `Event`/`HorizontalPodAutoscaler`). Phase-3 must special-case HPA the
same way `proto.rs::decode_proto_by_kind_and_version` does — dispatch on
`(kind, version)` before falling back to the plain `kind` map — not force a
single struct to cover both shapes. No other currently-enumerated kind has
this problem (single `apiVersion` per kind in the registry today).

**Shape** (mirrors `proto.rs:541-556`):

```rust
type StatusCodec = fn(&serde_json::Value) -> Result<serde_json::Value, serde_json::Error>;

fn status_codecs() -> &'static HashMap<&'static str, StatusCodec> {
    static CODECS: OnceLock<HashMap<&'static str, StatusCodec>> = OnceLock::new();
    CODECS.get_or_init(|| {
        let mut m: HashMap<&'static str, StatusCodec> = HashMap::new();
        m.insert("Namespace", codec::<crate::types::NamespaceStatus>);
        m.insert("CertificateSigningRequest", codec::<crate::types::CertificateSigningRequestStatus>);
        m.insert("APIService", codec::<crate::types::ApiServiceStatus>);
        m
    })
}

fn codec<T: serde::Serialize + serde::de::DeserializeOwned>(
    v: &serde_json::Value,
) -> Result<serde_json::Value, serde_json::Error> {
    let typed: T = serde_json::from_value(v.clone())?;
    serde_json::to_value(typed)
}
```

(`codec::<T>` monomorphizes to a distinct, zero-capture fn item per `T`,
which coerces to the `StatusCodec` fn-pointer type — the same mechanism
`proto.rs` relies on for its per-kind `fn(&[u8]) -> Option<Value>` entries,
just generic instead of hand-written per kind, since every entry here does
the identical deserialize-then-reserialize.)

**The two call wrappers** (public API other handler files use):

```rust
/// PUT /status: a present-but-non-decodable status is upstream's whole-body
/// typed-decode failure -> 400. `null` stays legal (RFC 7396 field deletion),
/// checked by the caller before this is invoked, same convention as
/// reject_non_object_status_put.
pub(crate) fn decode_status_put(kind: &str, incoming: &Value) -> Option<Result<Value, StatusError>> {
    status_codecs().get(kind).map(|f| f(incoming).map_err(|e| Status::bad_request(format!("status: {e}"))))
}

/// PATCH (any content-type) post-merge convergence point: a merged status
/// that fails the same typed decode is upstream's post-merge validation
/// failure -> 422, per Q1.
pub(crate) fn decode_status_patch(kind: &str, merged: &Value) -> Option<Result<Value, StatusError>> {
    status_codecs().get(kind).map(|f| f(merged).map_err(|e| Status::unprocessable_entity(format!("status: {e}"))))
}
```

Returning `Option<Result<...>>` (not `Result<...>`) is the load-bearing part
of the design: `None` means "this kind isn't in the dispatch table yet" and
the caller falls through to the **existing, unchanged** guard
(`replace_status_field`/`replace_status_field_dynamic`/
`reject_non_object_status`) — this is what makes every non-migrated kind's
behavior provably untouched by Phase-1, and what lets Phase 2/3 add a kind by
adding one `m.insert(...)` line plus its struct, never touching the call
sites again.

**How a built-in kind routes to typed vs. CR/CRD raw fallback**: unchanged —
still the existing `lookup()`/registry-hit boundary
(`cr.rs:4479` `state.resource_registry.get(&registry_key)`, and the
equivalent in `status.rs`/`namespaces.rs`). The dispatch table is consulted
**only after** that boundary already resolved `kind` to a genuine built-in;
a CR/CRD (registry miss) never reaches `status_codecs()` at all, preserving
the structural-only invariant on the dynamic path unconditionally — the
dispatch table has no CR/CRD entries and never will.

## 3. First structs

**Namespace, CertificateSigningRequest**: no new struct — Phase-1 reuses
`types.rs`'s existing `NamespaceStatus` (`types.rs:638`) and
`CertificateSigningRequestStatus` (`types.rs:753`) unchanged. The work here
is wiring, not authoring.

**APIService** (new, representative example): mirrors upstream
`k8s.io/kube-aggregator/pkg/apis/apiregistration/v1.APIServiceStatus`, whose
only field is `Conditions []APIServiceCondition` (`type`, `status`, `reason`,
`message`, `lastTransitionTime` — no `observedGeneration` upstream, but that
is exactly the shape `types.rs`'s existing `Condition` (`types.rs:1249`,
already used by `aggregation.rs::upsert_available_condition`'s reconcile-side
read/write) already models 1:1. Minimal-field + flatten-rest shape:

```rust
/// Upstream apiregistration/v1.APIServiceStatus — the only reasoned-about
/// field is `conditions` (the aggregator's own Available-condition sweep,
/// `handlers/aggregation.rs::upsert_available_condition`, already reads and
/// writes this shape via the shared `Condition` struct on the reconcile
/// side; this is the write-boundary counterpart for the /status subresource
/// itself).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiServiceStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,
    #[serde(flatten)]
    pub rest: serde_json::Value,
}
```

No other field of `APIServiceStatus` exists upstream, so there is nothing
else to enumerate; `rest` is present anyway per the binding invariant (§7),
in case a future k8s minor adds one.

## 4. Strict 400/422 wiring (Q1)

Per §0, most of Q1 already landed (2026-09-09, `dd4d4e72`/`9a4cddcd`).
Phase-1's remaining Q1 work is narrow:

- **`put_namespace_status`** (`namespaces.rs:759`): replace
  `NamespaceStatus::deserialize(v).unwrap_or_default()` (silently produces
  `NamespaceStatus::default()` = `{}` on any decode failure, currently a
  **200 success storing an empty status**, not even a rejection) with
  `status_dispatch::decode_status_put("Namespace", v)`'s `Result`,
  propagated as 400. This is a strict tightening, not a code-flip — there is
  no existing test asserting the old lenient behavior (confirmed: no
  `put_namespace_status_rejects_scalar` test exists in `namespaces.rs`), so
  nothing needs to be deleted, only a new regression test added (§5).
- **`put_cr_status`** (`cr.rs:4507`): when `kind` (already resolved by the
  registry-hit/CR-fallback branch) has a dispatch-table entry, use
  `decode_status_put` (400) instead of unconditionally calling
  `replace_status_field_dynamic` (422). This is the code-path change that
  flips the one test below.
- **`patch_namespace_status`**/**`patch_cr_status`**: same dispatch-table
  check, but via `decode_status_patch` (422) — **no code changes to their
  external behavior for the 3 Phase-1 kinds**, since PATCH already returns
  422 for both typed and untyped kinds; the only change is that the check
  becomes genuine schema validation (deserializes into
  `NamespaceStatus`/`CertificateSigningRequestStatus`/`ApiServiceStatus`)
  instead of the current mere "is this a JSON object" shape check
  (`reject_non_object_status`/`is_object_or_null_status`) — strictly
  stronger, same HTTP code, so no existing PATCH test changes.

### The exact list of existing tests that must flip 422→400

**Exactly one.** `cr.rs:19643`,
`put_cr_status_rejects_scalar_status_on_csr_closing_the_approval_panic_chain`
— asserts `UNPROCESSABLE_ENTITY` (`cr.rs:19692`) for a PUT scalar status on a
CSR routed through `put_cr_status`'s registry-hit branch; must become
`BAD_REQUEST` once CSR is in the dispatch table, with its doc comment and
assertion message updated to state upstream's 400-for-decode-failure
reasoning (matching the sibling test in `pods.rs:17676-17725`, already
correct). No other existing test in the tree asserts 422 for a PUT to a
registry-hit built-in's `/status` — grepped every
`"scalar status must be rejected with 422"` site (`pods.rs:4516,15502` are
PATCH; `crd.rs:3275,3329` and `cr.rs:12716,12788` are genuine-CRD PUT/PATCH,
correctly staying 422; `status.rs:2124,2201,2321,2394` are the generic
handlers' own PUT/PATCH pairs, and their PUT-side assertions were already
updated to 400 by `dd4d4e72`).

## 5. Test strategy

- **Dispatch-table unit tests** (in `status_dispatch.rs`): one round-trip
  test per registered kind — a representative status object with every
  reasoned-about field set decodes and re-encodes losslessly; a status
  object with an extra, unrecognized field (simulating a newer k8s minor or
  a controller writing an extension) round-trips through `rest` unchanged
  (the flatten-rest lossless-passthrough property, the safety invariant
  behind Q3's decision — this is the test that would fail if a future
  contributor ever "cleans up" `rest` away). A scalar/array input returns
  `Err`, not a defaulted value (**this is the fail-on-revert test for the
  silent-coercion bug**: reverting the `codec::<T>` change back to
  `.unwrap_or_default()`-style handling makes this test fail).
- **Per-call-site 400/422 tests**: extend
  `put_and_merge_patch_diverge_on_scalar_status_code` (or add its CSR/APIService
  siblings) so the three-way contract (built-in PUT → 400, CR/CRD PUT → 422,
  merge-PATCH → 422) is pinned for CSR and APIService specifically, alongside
  the existing Namespace/generic-built-in cases — this is what proves the
  KNOWN EDGE is closed for these two kinds without re-deriving the whole
  matrix by hand.
- **The one flipped test** (§4): update assertion + doc comment, keep the
  regression intent (a corrupted CSR status must never reach
  `merge_approval_conditions`'s in-place stamp) — the persisted-status
  assertion at the end of that test is unaffected by the code-flip and stays
  as-is.
- **New regression test for the silent-coercion bug**: a PUT to
  `/api/v1/namespaces/{name}/status` with `"status": "x"` must return 400 and
  must **not** persist `status: {}` — asserting both the code and that the
  store was never written proves this is a real fix, not just a
  differently-worded success path. Revert-fails: without the fix,
  `unwrap_or_default()` returns `Ok(200)` with an empty stored status,
  the exact silent-corruption behavior in §0.
- **Completeness meta-tests**: no changes required in Phase-1 (§2's `Option`
  return means the existing guard calls remain physically present in every
  touched function body as the fallback branch, so
  `every_status_put_handler_guards_against_non_object_status`,
  `every_status_patch_handler_guards_non_object_status_outside_any_branch`,
  and `every_main_resource_write_handler_preserves_stored_status` keep
  passing unchanged against the same grep). Confirm this holds after
  implementing by running the three meta-tests explicitly, not just trusting
  the design — grep-based tests are exactly the kind that can pass
  vacuously if a refactor moves a call site the test's naming heuristic
  doesn't recognize.

## 6. File-by-file change list + sequencing

1. `crates/apiserver/src/status_dispatch.rs` (**new**) — dispatch table +
   `decode_status_put`/`decode_status_patch` (§2). No dependencies on other
   Phase-1 changes; land first.
2. `crates/apiserver/src/types.rs` — add `ApiServiceStatus` (§3), near the
   existing `Condition` struct (`types.rs:1249`) so the reuse relationship is
   visually obvious in a diff.
3. `crates/apiserver/src/lib.rs` — one line, `mod status_dispatch;`.
4. `crates/apiserver/src/handlers/namespaces.rs` — retrofit
   `put_namespace_status`/`patch_namespace_status` (§4). Small diff, two
   functions, not on the r871h giant list.
5. `crates/apiserver/src/handlers/cr.rs` — retrofit `put_cr_status`/
   `patch_cr_status`'s status-guard selection (§4). **This is the one file
   in Phase-1's diff that is also an r871h hot giant (22.4k lines).** Keep
   the diff confined to the guard-selection lines inside these two
   functions — do not touch anything else in the file, and land this PR
   promptly once approved rather than let it sit alongside other in-flight
   `cr.rs` work.
6. Test updates: the one flip (§4), new dispatch-table tests, new
   APIService/CSR 400-vs-422 tests, the namespace silent-coercion regression
   test (§5) — spread across `status_dispatch.rs`'s own test module,
   `cr.rs`, and `namespaces.rs`.

**Collision-avoidance vs r871h (file split)**: `cr.rs` is on r871h's target
list. Q4 already settled type-first-then-split, so r871h must not begin
splitting `cr.rs` until this PR (and Phase 2/3's later `cr.rs` touches) land
— this plan doesn't change that ordering, just narrows Phase-1's `cr.rs`
footprint to two functions' guard-selection logic, minimizing exactly the
kind of overlapping-line-range conflict r871h is trying to avoid.

**Collision-avoidance vs in-flight PRs**: as of this plan, PR #1646
(`fix(apiserver): populate mutating-webhook oldObject on built-in UPDATE
path`, branch `worker/agent-ab6752c291bb8a245`) is open against
`crd.rs`/`pods.rs`/`resource.rs`. It does not touch `cr.rs` or
`namespaces.rs`, so there is no line-level overlap with Phase-1's diff —
worth a `git fetch`+rebase check before finishing this PR regardless, since
`resource.rs`/`pods.rs` share the same handlers-module namespace and recent
history (`dd4d4e72`, `9a4cddcd`, the mayor-17nj7 perf series) shows this
directory churns weekly.

## 7. Hard constraints (binding on the implementer)

- **Which fields carry server-side semantics is fixed by upstream
  Kubernetes, never invented.** Every new status struct's field list is read
  off upstream's actual Go type (defaulting, validation, immutability,
  status-stamping, subresource-routing behavior) — never hand-picked by
  local judgment about what "looks important."
- **Every status struct carries `#[serde(flatten)] rest: serde_json::Value`.**
  This is not optional per-struct; it is the lossless-passthrough safety
  property that makes hand-written minimal-field structs safe (Q3's
  conclusion). Under-enumerating a field costs only "not actively validated
  yet" — it must never cost data loss.
- **No new dependency.** No k8s-openapi, no pbjson, no codegen-generated
  serde structs (Q3) — hand-written `types.rs`-pattern structs only.
- **The dispatch table is the single convergence point** for a migrated
  kind's status write path. Do not add a second, parallel typed-check
  mechanism at a different layer for the same kind — every call site
  (`put_namespace_status`, `put_cr_status`, and Phase 2/3's `status.rs`/
  `pods.rs` sites) must go through `status_dispatch`, not a local
  `serde_json::from_value::<KindStatus>` copy.
- **CR/CRD dynamic paths keep the structural object-or-null invariant
  permanently.** `status_codecs()` must never gain a CR/CRD entry; the
  registry-hit boundary (§2) is the only gate, and it is not the dispatch
  table's job to be schema-aware for unstructured objects.
- **Class-C read-path coercions stay in place** for built-ins until Phase
  4's gate (every built-in write entry point — create/PUT/PATCH/status-sub/
  internal stampers — converges on the dispatch table) is met. Do not remove
  `generic.rs:720-721`, the `lib.rs:3494` ResourceQuota coercion, or
  `aggregation.rs`'s status-shape defense per-kind as each kind gets typed;
  that is explicitly a Phase-4 batch decision (Q2), not a Phase-1/2/3
  side-effect.

## 8. Risks + open questions

**Risks:**

1. **`cr.rs` is a hot giant with weekly churn** (§6) — the highest
   mechanical risk to this PR is a merge conflict or a rebase surprise, not
   a design flaw. Mitigate by keeping the diff to the two functions' guard
   lines and merging promptly.
2. **Scope creep temptation**: since `put_cr_status`'s registry-hit branch
   is being touched anyway, it's tempting to also fix the remaining 7
   KNOWN-EDGE kinds' HTTP code mechanically (decouple "which code" from
   "does a typed struct exist yet" — e.g. always use `replace_status_field`
   (400) for any registry hit, dispatch-table membership aside). This IS
   smaller than typing all 7. Recommend **against** doing this in Phase-1:
   it would create exactly the "second, parallel mechanism" the hard
   constraints above forbid (a code-selection rule independent of the
   dispatch table), and Q1's own note already resolved this "by construction"
   via typing, not via a decoupled mechanical fix. Flagging for the
   operator in case the tradeoff (7 kinds' correct HTTP code sooner, vs. one
   clean convergence point) is worth revisiting explicitly.

**Open questions for the operator:**

1. **Confirm APIService as Phase-1's one new struct** (vs. ResourceQuota or
   another Phase-2 candidate). Rationale for APIService: smallest (reuses
   `Condition` verbatim, ~15 LOC), and it's one of the 9 KNOWN-EDGE kinds, so
   it doubles as a second confirmation (beyond CSR) that the dispatch-table
   fix generalizes to a kind with no pre-existing typed-status code at all
   (CSR already had 90% of the work done via `CertificateSigningRequestStatus`;
   APIService proves the "author a struct from scratch, then wire it" motion).
2. **Confirm deferring the `status.rs` four-function wiring to Phase 2**
   (§1) rather than adding it now as unused-but-ready infrastructure. Recommend
   deferring per Rule 2 (simplicity — don't wire a check with zero live
   entries); flag in case the operator prefers front-loading the wiring to
   avoid a second review pass on `status.rs` later.

**Phase-1 effort estimate**: **small**, roughly 350–500 LOC including tests —
one new ~80–100 LOC module, two structs (one existing reused, one new
~15 LOC), two files (`namespaces.rs`, `cr.rs`) with a two-function diff each,
and 150–250 LOC of new/updated tests (dispatch round-trips, the one 422→400
flip, the new silent-coercion regression, the APIService/CSR 400-vs-422
pins). Comparable in scale to a single ds8hb/ohh8o-style PR (~250 LOC
datapoint), slightly larger because Phase-1 also carries the one-time
dispatch-table scaffolding Phase 2/3 will then reuse for free.
