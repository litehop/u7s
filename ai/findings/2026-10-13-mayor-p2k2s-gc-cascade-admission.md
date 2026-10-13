# GC / owner-cascade deletes and admission (mayor-p2k2s)

Bead: mayor-p2k2s

Answer: upstream kube-apiserver never cascades dependents in-process (the garbage collector and namespace controller do it with REST DELETE / DeleteCollection, which run validating admission), so u7s's in-process dependent cascades are a GAP, not an intentional skip; the finalizer-drain hard-deletes and the REST-driven collection deletes MATCH upstream.

Stance applied: match upstream. All upstream citations are release-1.37, cached in `temp/research/p2k2s_*`.

## Upstream facts

- GC deletes dependents over REST: `pkg/controller/garbagecollector/garbagecollector.go:627,654` (`gc.deleteObject(... &policy)`), so every cascade DELETE goes through admission, finalizers, graceful deletion, and the "all owners gone" check (`:551` onward).
- Namespace content is drained by the namespace controller over REST: `pkg/controller/namespace/deletion/namespaced_resources_deleter.go:324` (`DeleteCollection`) and `:391` (`Delete`). The apiserver's own namespace DELETE (`pkg/registry/core/namespace/storage/storage.go:138-262`) only stamps deletionTimestamp / phase Terminating (running `deleteValidation` = admission) and finalizers; it deletes nothing else.
- `Store.DeleteCollection` (`staging/.../registry/generic/registry/store.go:1309,1353`) calls `Store.Delete` per item with `deleteValidation`, so admission runs per item.
- Finalizer-drain delete (last finalizer removed by UPDATE/PATCH on a terminating object) is `deleteWithoutFinalizers` (`store.go:658,870`): no `deleteValidation`, so DELETE webhooks do NOT run (the UPDATE webhooks already did).
- CRD instance cleanup is in-process and skips admission: `apiextensions-apiserver/pkg/controller/finalizer/crd_finalizer.go:220` (`DeleteCollection(..., rest.ValidateAllObjectFunc, ...)`).

## Table

| Path (u7s file:line) | Internal / REST | Upstream equivalent | Admission upstream | Admission u7s | Verdict |
|---|---|---|---|---|---|
| `handlers/cr.rs:2807` `cascade_delete_cr_dependents` (called `cr.rs:3008,3995` after Background CR owner delete) | Internal (store scan of `/registry/cr/`, `store.delete`) | GC controller REST DELETE (`garbagecollector.go:654`) | Yes (validating) | No; also ignores dependent finalizers and other live owners | GAP, MED |
| `handlers/resource.rs:4292-4332` -> `delete_pods_owned_by:5268`, `delete_replicasets_owned_by:5326`, `delete_jobs_owned_by:5393`, `strip_or_delete_dependent:5178` (DaemonSet, Deployment->RS, RC explicit Background, StatefulSet, CronJob->Job->Pod) | Internal (`store.delete`) | GC controller REST DELETE | Yes | No; pods hard-deleted with no graceful termination, dependent finalizers ignored | GAP, MED |
| `resource.rs:5466` `remove_job_tracking_finalizer_from_pods` (run on Job delete) | Internal; u7s acts as the Job controller | Job controller PATCH (REST) | Yes (UPDATE) | No | GAP, LOW (folded into the built-in cascade follow-on) |
| `namespaces.rs:953` `cascade_delete_namespace_resources`, reached only from `delete_namespace` `:1540` when the namespace has no `spec.finalizers` | Internal | Namespace controller DeleteCollection (`nsdeleter.go:324`) | Yes per object | No (namespace's own DELETE webhook does run, `:1466`) | GAP, LOW (API-created namespaces always get the `kubernetes` finalizer, test `create_namespace_stamps_kubernetes_finalizer`, so the path is for seeded/test namespaces; the normal path at `:1500-1525` correctly defers to KCM) |
| `namespaces.rs:1151` `maybe_finalize_terminating_namespace` + `purge_namespace_object:1216` (purges finalizer-free leftovers once spec.finalizers empty) | Internal | None; upstream just deletes the namespace on finalize (`ShouldDeleteNamespaceDuringUpdate`, `storage.go:~252`) and leaves content | n/a | No | DIVERGENCE, LOW (cleanup of leaked content, not a cascade a webhook should see; bundled with the row above) |
| `namespaces.rs:1263` `delete_namespace_scoped_crds` | Internal | None (u7s-specific workaround for test-framework CRDs whose group embeds the namespace) | n/a | No | u7s-only, not an upstream path; LOW, bundled with the namespace follow-on |
| `resource.rs:4570,4757`, `cr.rs:3031,4030`, `pods.rs` collection delete (namespace controller target) | REST handler | `Store.DeleteCollection` (`store.go:1353`) | Yes per item | Yes per item (`run_validating_webhooks`, verified in `resource.rs:4680-4690,4860-4875`) | MATCHES |
| Finalizer-drain hard-delete: `resource.rs:1325` `complete_finalizer_drain`, `cr.rs:2860` `complete_cr_finalizer_drain` | Internal, but triggered by the client's own PATCH/PUT | `deleteWithoutFinalizers` (`store.go:658`) | No DELETE admission | No DELETE admission (UPDATE admission already ran) | MATCHES |
| Foreground / orphan: `add_foreground_deletion_finalizer`, `add_orphan_finalizer` (`resource.rs`, used `:4200-4210`, `cr.rs:~2960`) | Soft-delete only; KCM GC does the cascade over REST | Namespace/generic delete sets finalizers; GC drains | n/a | n/a (the owner DELETE runs webhooks first) | MATCHES |
| Owner side of Background DELETE (hard-delete owner, validating webhooks run first) | REST handler | `Store.Delete` | Yes | Yes (`resource.rs:4183-4196`, `cr.rs` `run_validating_webhooks`) | MATCHES |
| CRD delete does not remove its CR instances at all | Internal (absent) | `crd_finalizer.go:220`, no admission | No | n/a | Not an admission gap; separate behavior difference, not investigated further, no bead |

TTL/expiry: grep of `crates/apiserver/src` for `ttl|expire` function names found no apiserver-side delete path (only status/SA-token cache helpers); not exhaustively verified beyond that grep.

## Why the internal cascades matter (beyond webhooks)

- They race the real KCM GC, which deletes the same dependents anyway; the in-process copy only adds divergence: `cascade_delete_cr_dependents` hard-deletes a CR dependent even when it has finalizers or another live owner (the built-in helper `strip_or_delete_dependent` does check other live owners; the CR one does not).
- A Fail-policy validating webhook on the dependent (the conformance "deny" webhooks) cannot veto them.
- Existing comments in `cr.rs`/`resource.rs` already record that the orphan and foreground paths were moved to KCM for exactly this race; Background was left behind.

## Follow-ons

One bead per GAP (ids appended to mayor-p2k2s): CR cascade (MED), built-in cascade incl. job-tracking finalizer (MED), namespace no-finalizer cascade/purge (LOW). Each requires VM verification (GC conformance `should delete ... when the rc/dependents are background deleted`, plus a deny-webhook test on a dependent).
