# csi-hostpath conformance triage: 3 failures root-caused (mayor-6dj51)

Bead: mayor-6dj51

Run: `temp/e2e/0903-1111-csi-hostpath/` (mayor checkout, gitignored). Pinned to k8s 1.36.4 test semantics (`release-1.36` branch of kubernetes/kubernetes).

## Verdict

All 3 failures are genuine u7s gaps, not flakes. Only one (#1) has a watchdog-reap namespace mixed into its symptom; the underlying bug is independent of the reap and would have timed out on its own budget anyway. #2 and #3 are clean scheduler predicate gaps with zero watchdog interference.

| # | Test | Root cause | Genuine / reap | Severity | Fix-bead |
|---|------|------------|-----------------|----------|----------|
| 1 | AnyVolumeDataSource provisioning | `hello-populator` Deployment's ReplicaSet never gets a Pod created | Genuine (reap only shaped the error message) | HIGH | mayor-6dj51.1 |
| 2 | RWOP preemption | scheduler has zero ReadWriteOncePod volume-exclusivity awareness | Genuine | HIGH | mayor-6dj51.2 |
| 3 | volumeLimits | scheduler has zero CSI per-node attach-count-limit awareness | Genuine | HIGH | mayor-6dj51.3 |
| — | (infra) watchdog namespace-reap threshold | 600s reap threshold < some Serial CSI tests' own 900s budget | Infra, not product code | LOW | mayor-6dj51.4 |

## Failure 1 — AnyVolumeDataSource provisioning

`[sig-storage] CSI Volumes [Driver: csi-hostpath] [Testpattern: Dynamic PV (default fs)] provisioning should provision storage with any volume data source [Serial]`

Assertion (`junit_01.xml:4909`): `Failed to create client pod: Timed out after 900.000s` waiting for `hostpath-client` to reach `Running`; last observed phase `Pending`/`ContainerCreating`. `In [It] at: k8s.io/kubernetes/test/e2e/framework/volume/fixtures.go:592`.

The test provisions `pvc-bc2ec` via `dataSourceRef` to a custom `Hello` CR (`hello.example.com`), which requires the `hello-populator` Deployment (namespace `provisioning-4898-pop-4464`) to run a populator Pod that creates a "prime" PVC, copies data, then hands off the real volume. `apiserver.log:139599` shows the Deployment's ReplicaSet `hello-populator-79474c6f64` created successfully (`POST .../replicasets status=201`) and its status written once (`PUT .../status status=200`) — then **total silence for the next 10.5 minutes**: `grep -c "79474c6f64" host-logs/apiserver.log` = 5 hits total, all status/GET/DELETE on the RS object itself, **zero** `POST .../pods` for any pod named `hello-populator-79474c6f64-*`. No pod was ever created for that ReplicaSet.

Consequently `pvc-bc2ec` never got provisioned (`kubelet.log:27849` onward: `error processing PVC provisioning-4898/pvc-bc2ec: PVC is not bound`, repeating every ~13s until the namespace died), and `hostpath-client` stayed stuck in `ContainerCreating` for its entire lifetime. The in-tree PV controller's `persistent-volume-binder` behavior (`kcm.log:5521` then the recurring `PATCH .../events/pvc-bc2ec...` every 15s from `10:55:45` to `10:59:45`) is textbook "waiting for external provisioner" — expected once ownership is handed to the CSI sidecar, not itself a bug.

Separately: the operator's watchdog force-deleted `provisioning-4898` and its 3 sibling namespaces at `2026-09-03T11:06:01Z` — `terminal.log:212-223`: `[watchdog] force-deleting namespace 'provisioning-4898' (Active for 628s (>= 10m threshold))`. That is *why* the failure message reads "Namespace ... not found" instead of a plain timeout — the reap fired mid-poll, 272s before the test's own 900s budget would have expired. **The reap is cosmetic here**: with the populator pod never created, the test was already doomed to fail on its own clock; the watchdog only changed the error text, not the outcome. Filed the reap-threshold mismatch as its own LOW-severity infra bead (mayor-6dj51.4) rather than conflating it with the genuine bug.

Root cause of the missing Pod is not pinned to an exact line — reproducing live (VM) is needed to confirm whether it's a stale informer read in the pod-count reconcile, a lost watch event, or something u7s-side in `crates/apiserver/src/handlers/defaults.rs`'s `default_deployment`/`default_replicaset` (`crates/apiserver/src/handlers/defaults.rs:1244-1284`, `:1071-1084`) failing to persist `replicas: 1` under this specific request shape. Filed as mayor-6dj51.1 with the full evidence trail above.

## Failure 2 — RWOP preemption

`read-write-once-pod should preempt lower priority pods using ReadWriteOncePod volumes [Serial]`

Assertion (`junit_01.xml:4926`): `failed to wait for pod1 to be preempted: expected pod to not be found: Timed out after 300.004s` — `pod1` still `Running` on `lima-node-4`. `In [It] at: readwriteoncepod.go:171`.

Test mechanics (`test/e2e/storage/testsuites/readwriteoncepod.go:133-179`, fetched at `release-1.36`): `pod1` (default priority) claims a `ReadWriteOncePod` PVC and runs; `pod2` is created with a `PriorityClass` of value 1000 using the *same* PVC. Upstream, the scheduler's `VolumeRestrictions` filter must report `pod2` unschedulable due to the RWOP exclusivity conflict, which makes `pod2` a preemption candidate, and `DefaultPreemption` evicts `pod1` to free the volume.

`scheduler.log:2688-2691`:
```
10:49:31.142  unscheduled pod detected: read-write-once-pod-554/pod-d907a316... (pod1)
10:49:31.154  bound pod ... → node lima-node-4
10:50:11.266  unscheduled pod detected: read-write-once-pod-554/pod-ad4d6b6a... (pod2)
10:50:11.284  bound pod ... → node lima-node-4
```
`pod2` was bound to the **same node** 40s after `pod1`, with no filter rejection and no preemption event of any kind — the scheduler treated the RWOP conflict as nonexistent. `crates/scheduler/src/lib.rs` (9878 lines, exhaustively grepped) has **zero** matches for `ReadWriteOncePod`, `access_mode`/`AccessMode`, or `volume_in_use` — there is no RWOP-exclusivity predicate implemented at all, so the precondition for preemption (pod2 unschedulable) never fires and two pods concurrently bind the same exclusive-access volume on one node. No watchdog reap touched this namespace (`terminal.log` has zero `read-write-once-pod` reap lines).

## Failure 3 — volumeLimits

`[Testpattern: Dynamic PV (filesystem volmode)] volumeLimits should support volume limits [Serial]`

Assertion (`junit_01.xml:5058`): `Eventually` expected the pod exceeding the node's CSI attach limit to stay `Pending` with a `PodScheduled=False`/`Unschedulable` condition matching `max.+volume.+count` (`test/e2e/storage/testsuites/volumelimits.go:274-293`); instead it observed `phase: Running`.

Upstream mechanics: the test fills a node to its CSI driver's advertised attach limit (from `CSINode.spec.drivers[].allocatable.count`), then adds one more pod requiring one more volume and expects the `CSILimits`/`NodeVolumeLimits`-equivalent scheduler filter to reject it. `crates/scheduler/src/lib.rs` has extensive `allocatable`-based fitting logic for cpu/memory/ephemeral-storage/pod-count/extended-resources (lines 1760-2100, 3076-3236) but **zero** matches for `CSINode`, `allocatable.count`, or any volume-count concept — the scheduler has no notion of per-node CSI attach limits, so an over-limit pod is never rejected and schedules normally. Same root-cause category as Failure 2 (missing CSI-aware scheduler plugin), but a distinct predicate/data source (CSINode allocatable vs. PV access-mode), hence a separate fix-bead. No watchdog reap in this namespace (`terminal.log` has zero `volumelimits-1449` reap lines).

## Fix-beads filed

- mayor-6dj51.1 (HIGH): AnyVolumeDataSource populator Deployment/ReplicaSet never gets a Pod created — needs live-cluster repro to pin exact code path.
- mayor-6dj51.2 (HIGH): scheduler missing ReadWriteOncePod volume-exclusivity filter + preemption support.
- mayor-6dj51.3 (HIGH): scheduler missing CSI per-node attach-count-limit filter (CSINode.allocatable).
- mayor-6dj51.4 (LOW): watchdog namespace-reap threshold (600s) shorter than some Serial CSI tests' own budget (900s) — causes misleading "Namespace not found" failure text on tests that are already going to time out on their own, and could false-positive-reap tests that are still making genuine progress.
