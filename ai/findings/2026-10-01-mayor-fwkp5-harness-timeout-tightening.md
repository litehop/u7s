# Harness timeout tightening audit

Bead: mayor-fwkp5

**Answer: tightening the namespace watchdog would save no wall-clock, because
a reap does not abort the spec. The stuck csi-hostpath spec always runs out
the upstream 900 s pod-start timer (about 14 extra minutes per occurrence).
The watchdog's 600 s Active threshold is already only 1.3-1.7x the slowest
healthy spec, so it should stay. The real savings are a root-cause fix for the
stuck spec (HIGH), suite-level caps for total hangs (MED), and a few
inert-but-loose knobs (LOW).**

Measured 2026-09-30/10-01 from the archives in the mayor checkout's
`temp/e2e/` (read-only). Per-spec data is from ginkgo `report.json`
(`SpecReports[].RunTime`, `State`). Namespace lifetimes are from
`host-logs/apiserver.log`. Watchdog lines are from `terminal.log`. Local
terminal time is UTC+9 (`19:58:07` local is `10:58:07Z`). Everything below is
UTC unless marked.

## 1. Suite wall-clock

| Run | Result | `RunTime` |
|---|---|---|
| conformance, 10 runs 0827-0926 (446 specs each) | all pass except 0926 (1 real CR-conversion failure) | min 1442 s, p50 about 1560 s (26 min), max 1699 s (28.3 min) |
| conformance 0910-1621 / 0926-1051 (current rig) | pass / 445 of 446 | 1557 s / 1466 s |
| csi-hostpath 0907-0026 / 0910-2329 (green) | 96 of 96 | 2414 s / 2592 s (40-43 min) |
| csi-hostpath with the stuck spec: 0905, 0906, 0926 | 95 or 94 of 96 | 3279 s, 3250 s, 3291 s |
| csi-hostpath 0903-1111 (3 failures) | 93 of 96 | 3933 s |

A single stuck `any volume data source` spec accounts for the whole csi
slowdown: +700 s over the 2592 s green run. Four early csi runs (0830-0901)
have a `report.json` with `SpecReports: null` and no junit, so they cannot be
measured. They are cited only for their watchdog logs.

## 2. Per-spec durations (passing specs only)

| Suite | n | p50 | p95 | p99 | max | >120 s | >300 s | >600 s |
|---|---|---|---|---|---|---|---|---|
| conformance, 10 runs | 4459 | 4.0 s | 70.2 s | 242.6 s | 356.3 s | 109 | 20 | 0 |
| csi-hostpath, 6 runs | 569 | 49.3 s | 216.0 s | 415.4 s | 440.3 s | 59 | 18 | 0 |

Only 10 and 6 samples per spec exist, so a per-spec p99 is just the max.

Specs over 300 s in passing runs:

- **conformance**
  - `SchedulerPredicates [Serial] ... same hostPort ... 0.0.0.0 hostIP`: median 304 s, max 356 s.
  - `CronJob should not schedule jobs when suspended [Slow]`: 300 s (the 5-minute `Consistently`).
- **csi-hostpath**
  - `volume-lifecycle-performance ... [Slow] [Serial]`: max 440 s.
  - Two `snapshottable-stress ... [Slow]` specs: max 415 s and 408 s.

Slow-but-passing outliers (worst run is at least 5x the median):

- `ResourceQuota should apply changes to a resourcequota status`: 5 s in 5 of
  10 runs but 150-275 s in the others. Kcm logs `ResourceQuota ... cannot be
  updated: resource version mismatch`, so this is a retry race. Passes
  eventually.
- `Namespaces [Serial] should ensure that all pods are removed when a namespace is deleted`: max 81 s.
- `EmptyDir wrapper volumes ... configmaps [Serial]`: max 73 s.

Full tables: `conf_perspec.tsv` and `csi_perspec.tsv` are not committed. They
can be regenerated with the `jq` extraction in section 7.

### Healthy namespace termination

Measured as the e2e `DELETE /api/v1/namespaces/X` to the first namespace-controller
`PUT .../X/finalize 200`, from `apiserver.log`. Ginkgo's own AfterEach only
issues the DELETE (about 2 ms) and does not wait, so spec `RunTime` excludes
termination. Namespace age is therefore about spec time plus this.

| Run | n | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| conformance 0926-1051 | 482 | 5.0 s | 10.1 s | 10.1 s | 10.1 s |
| conformance 0910-1621 | 482 | 5.1 s | 10.1 s | 10.2 s | 25.1 s |
| csi 0910-2329 | 230 | 15.0 s | 25.2 s | 30.1 s | 30.2 s |
| csi 0926-1153 | 229 | 5.1 s | 10.1 s | 10.2 s | 20.4 s |

The 5 s quantisation matches namespace-controller requeue steps. No healthy
namespace took more than 30 s to terminate. No archived `terminal.log` has a
`>= 15m threshold` (Terminating/any-phase) reap line. Only Active-at-10m
reaps ever fired.

## 3. Timeout-knob inventory

The git history of these lines is squashed at `29d13cdc` (2026-08-17, PR
#1201), so `git log -S` cannot attribute the original thresholds. The rationale
below is from the in-file comments and `test-watchdog-logic.sh`.

### Harness-imposed (ours, tunable)

| Knob | File:line | Current | Why it exists | Proposed | Rule | Tag |
|---|---|---|---|---|---|---|
| Watchdog poll interval | `06-run-sonobuoy.sh:114` | `sleep 30` | Reap granularity (observed 602-630 s Active at reap) | keep | n/a | DEFER |
| Watchdog Active reap | `06-run-sonobuoy.sh:148` | 600 s | Must clear the 300 s CronJob `Consistently`; in-file comment explains a 300 s value raced it | **keep 600** | max healthy spec + teardown = 356 + 10 s (conformance) and 440 + 30 s (csi); 600 s is 1.28-1.7x that. 2x p99 = 485 s would sit 15 s above csi's 470 s | LOW |
| Watchdog any-phase reap (in practice Terminating only, since Active always hits 600 first) | `06-run-sonobuoy.sh:151` | 900 s | "keeps the any-phase net above the Active threshold" | **split a Terminating threshold: 180 s** | 6x healthy max termination (30 s), floor 120 s | LOW |
| Driver-ns exemption regex | `06-run-sonobuoy.sh:135` | `^(.+-[0-9]+)-[0-9]+$` | Keeps the CSI driver ns alive while the parent exists | keep; note the gap below | n/a | LOW |
| Sonobuoy `--timeout` (focus and certified modes) | not passed; aggregator default | 21600 s (6 h) | Upstream sonobuoy default (see the note on `test-all-e2e-timeout-logic.sh`) | **`--timeout 5400` (conformance 3600, csi 5400)** | 2x slowest passing suite: 2 x 1699 = 3400, round to 3600; 2 x 2592 = 5184, round to 5400 | MED |
| Sonobuoy `--timeout` (`--all-e2e`) | `06-run-sonobuoy.sh:22, 338` | 43200 s (12 h) | The default 6 h killed an overnight run at exactly 6h00m00s | keep | documented 6-12 h budget | DEFER |
| Ginkgo suite `--timeout` | not passed | 24 h | The report's `SuiteConfig.Timeout` is 86399999977625 ns. Who sets it was not determined; neither our script nor the plugin YAML passes it | **add `--timeout=3600s` / `5400s` via `E2E_EXTRA_GINKGO_ARGS`** (the same channel as `--procs`, line 258) | same as sonobuoy `--timeout`; ginkgo then aborts cleanly and still emits `report.json` | MED |
| Ginkgo grace period | not passed | 30 s (`GracePeriod` in the report) | ginkgo default | keep | n/a | DEFER |
| Per-call retrieval | `06-run-sonobuoy.sh:384` | `CALL_TIMEOUT=30` | Hung `kubectl logs` / `limactl` calls blocked the script silently | keep | n/a | DEFER |
| `--procs` | `06-run-sonobuoy.sh:34` | 16 | Parallelism, not a timeout; parallel-total 16 in every report | n/a | n/a | n/a |
| `batch-focus.sh` per-batch | `batch-focus.sh:67, 390` | `--ginkgo.timeout=5m` | Separate debug harness | keep | n/a | DEFER |
| Node NotReady toleration | `sonobuoy-plugin-e2e.yaml:34` | `tolerationSeconds: 120` | Survive a kubelet heartbeat gap (87 s observed) without evicting the e2e-job pod | keep | n/a | DEFER |
| Startup waits | `lima-start.sh:280` (`--timeout 30m`), `run-all.sh:504` (60 s netpol DS), `run-all.sh:621` (300 s dhat flush) | as stated | VM boot / dhat flush | keep | out of scope | DEFER |
| Suite budget comment | `run-all.sh:317` | "~25 min un-profiled budget" | Advisory only (dhat warning), not enforced | n/a | n/a | n/a |

`test-watchdog-logic.sh` re-implements `watchdog_decide` (line 58) instead of
sourcing the script. Any threshold change has to be made in both places or the
test passes while production drifts.

Driver-ns regex gap: csi child namespaces named `provisioning-293-val-9754`
and `provisioning-293-pop-2971` (from the kubelet log) do not match
`^(.+-[0-9]+)-[0-9]+$`, so they are not exempt from the age reap. No reap of
such a namespace appears in the archived logs, so this is a latent risk only.

### Upstream per-spec timeouts (inside `e2e.test`, not harness-tunable as shipped)

Observed, not configured by us:

- "Timed out after 900.00Xs" in the stuck spec. This matches the e2e
  framework's slow pod-start timeout of 15 min. It was the failure in
  `provisioning.go:285` / `fixtures.go:592`, in every run (see section 4).
- "Timed out after 300.000s" in the 0903-1111 failures
  (`volumeLimits`, `read-write-once-pod` preempt). This matches the
  5 min pod-start / claim timeout.

Whether `e2e.test` exposes flags for these is **unverified**:
`temp/k8s-src` has no `test/` tree and no other source was available. My
recollection is that the e2e framework has only a few timeout flags
(`--system-pods-startup-timeout`, `--node-schedulable-timeout`) and that the
per-spec pod-start/claim timeouts are compiled-in defaults, so there is
probably no CLI knob. Confirm with `e2e.test --help | grep -i timeout` inside
`registry.k8s.io/conformance:v1.37.1` before relying on this. Until then,
treat per-spec upstream timeouts as untunable.

## 4. Failed and reaped specs

### 0926-1153-csi-hostpath (the requested verdict)

**A watchdog reap was involved in one of the two failures, and it did not
shorten that failure.**

`terminal.log` has exactly one reap line for the whole run:

```
[watchdog] 2026-09-26T11:47:46Z force-deleting namespace 'provisioning-293' (Active for 611s (>= 10m threshold))
```

Timeline for `provisioning should provision storage with any volume data
source [Serial]` (default fs), from `report.json` and the logs:

- 11:37:34 spec starts (report `StartTime` 11:37:34.29Z). Client pod
  `provisioning-293/hostpath-client` is created at 11:37:35.
- 11:37:35 kcm logs `Operation for "provision-provisioning-293/pvc-8054b" failed
  ... durationBeforeRetry 500ms ... PersistentVolumeClaim "pvc-80..." cannot be
  updated: resource version mismatch (expected 57429, current 57430)`.
- 11:37:35 to 11:47:42 kubelet logs, repeatedly, `error processing PVC
  provisioning-293/pvc-8054b: PVC is not bound` (192 kubelet lines mention the pod).
  kcm has 11 lines mentioning `pvc-8054b` in total. After the 11:37:35 failure,
  the next is 11:52:40, so the claim was never re-queued in between.
- 11:47:46 watchdog force-deletes the namespace (apiserver log: `DELETE
  .../namespaces/provisioning-293 ... user_agent=kubectl/v1.36.1`).
- 11:52:40 kcm now logs `storageclass ... "provisioning-293bjldq" not found` for
  the claim (the test's storage class has been torn down).
- 11:53:09 spec fails (`EndTime` 11:53:09.52Z, 935 s). Message: `Failed to
  create client pod: Timed out after 900.004s ... Pod "hostpath-client" not
  found ... Expected Pod to be in Running`. Last observed pod state:
  `Pending`, `ContainerCreating`. The test's own `DELETE` of the namespace at
  11:53:09 got 200.

The reap fired 324 s before the spec's own 900 s timer. Eventually-polling in the
framework treats `NotFound` as transient (`framework.transientError`), so the
spec kept polling to the end. **Classification: genuine hang** (PVC never bound
because of a lost retry after an update conflict in the PV controller). The
reap was correct but inert.

The other failure, `provisioning should provision storage with pvc data source
in parallel [Slow]` (block), ran 10:59:02-11:00:42 (100 s; passing max 96 s).
Message: `invalid JSON: expected value at line 1 column 1`
(`provisioning.go:779`). This is the HTTP 400 from mayor-l0wkh. **No watchdog
involvement** (no reap line near it; the namespace was about 100 s old) and no
timeout. Classification: **other (real apiserver/body defect, fast failure)**.

### Every failed or reaped spec in measurable runs

| Run | Spec | Duration | Reap? | Class |
|---|---|---|---|---|
| 0903-1111 csi | `any volume data source [Serial]` | 908 s | `provisioning-4898` at 11:06:01Z, 628 s | genuine hang; spec then logged `Namespace "provisioning-4898" not found` as transient until 900 s |
| 0903-1111 csi | `volumeLimits should support volume limits [Serial]` | 344 s | none | hang: `Timed out after 300.000s ... expected pod to be in phase Pending, but got Running` (passes in 14-101 s in other runs) |
| 0903-1111 csi | `read-write-once-pod should preempt ... [Serial]` | 372 s | none | hang: `Timed out after 300.004s` (passes in 41-85 s elsewhere) |
| 0905-1501 csi | `any volume data source [Serial]` | 908 s | `provisioning-6452` at 14:54:54Z, 630 s | genuine hang |
| 0906-0500 csi | `any volume data source [Serial]` | 936 s | `provisioning-6547` at 04:54:21Z, 627 s | genuine hang |
| 0906-0542 (focus) | `any volume data source [Serial]` | 936 s | `provisioning-9808` at 05:36:36Z, 614 s | genuine hang |
| 0926-1153 csi | `any volume data source [Serial]` | 935 s | `provisioning-293` at 11:47:46Z, 611 s | genuine hang (above) |
| 0926-1153 csi | `pvc data source in parallel [Slow]` | 100 s | none | other (HTTP 400) |
| 0926-1051 conformance | `CustomResourceConversionWebhook ... non homogeneous list` | 3 s | none | other (real bug, fixed separately) |
| 0907-0100 (focus) | `pod overhead is accounted for` | 184 s | none | other: `context deadline exceeded`; no terminal log or further evidence, not classified beyond that |

The same spec passed in 76-89 s in 0906-0713, 0907-0026 and 0910-2329. So it is
a race, failing in 5 of 8 archived runs, not a slow spec. It would never have
passed late: the PVC was not bound and kubelet logged it for the full 15 min.

Older csi runs 0830-1358 (26 reaps), 0831-0338 (18) and 0901-0350 (2) reaped
many `ephemeral-*` / `provisioning-*` namespaces at 602-630 s, including
driver child namespaces (pre-exemption, and pre-fix rig). The healthy maximum
for those specs is 142 s (ephemeral expansion), so these were 4x or more over
healthy. No `SpecReports` exist for them, so specs are not attributable.
Likely genuine hangs, unverified.

No reap in any archive hit a spec that would later have passed. Every reap in
a run with data coincides with a spec that failed at the upstream timer.

## 5. Recommendations

Wall-clock arithmetic. A stuck `any volume data source` costs about 935 s
versus about 80 s healthy, so about 14 extra minutes per occurrence (it runs
last because it is `[Serial]`, nothing overlaps it). A stuck-forever e2e run
currently costs up to the 6 h sonobuoy default. Terminating-namespace stalls
have not occurred in any archive.

1. **HIGH: fix the PV controller lost-retry instead of tuning timers.** After
   the 11:37:35 `resource version mismatch` on claim provisioning, the claim is
   never re-synced for 15 min. Saves about 14 min per failing csi run (5 of the
   last 8 csi runs). This is product work, not harness. Stop-gap, operator's
   call: `--e2e-skip` of this one spec trades that coverage for the same 14 min
   (DEFER, because it hides a real defect).
2. **MED: cap the whole suite.** Ginkgo `--timeout` via
   `E2E_EXTRA_GINKGO_ARGS` (3600 s conformance, 5400 s csi), plus sonobuoy
   `--timeout` at the same or 600 s more. Saves hours on a total hang and
   nothing on the normal stuck-spec case (3933 s worst observed is under 5400 s).
   False-reap risk: 2-2.5x headroom over every measured pass
   (1699 s / 2592 s); `--focus` batches are shorter so the cap only
   gets looser relative to them. `test-all-e2e-timeout-logic.sh` currently
   asserts that the non-`--all-e2e` branches do NOT pass `--timeout`; that
   test and its rationale would need updating.
3. **LOW: split the Terminating threshold to 180 s.** Saves up to 720 s per
   stuck-Terminating namespace, but none has been observed, so this is
   prevention only. Must change `watchdog_decide` in
   `test-watchdog-logic.sh` in lockstep.
4. **LOW: keep the Active threshold at 600 s.** Any value under about 500 s
   starts reaping the csi `[Slow] [Serial]` specs (namespace age about 470 s at
   the top) and sits within 15-25% of `hostPort` (366 s with teardown).
   If the operator still wants it lower, the rule `max(2 x p99, floor)` gives
   485 s for conformance and 830 s for csi, both worse than 600 s.
5. **DEFER: upstream per-spec timeout flags.** Only worth pursuing if
   `e2e.test --help` shows them; the target would be the 900 s pod-start timer.
   If it existed and were set to 300 s, stuck specs would cost about 5 min
   instead of about 15 min, but `volume-lifecycle-performance` and the
   snapshot stress specs are `[Slow]` and already spend 400+ s in total
   (not necessarily in one pod start), so a blanket cap needs checking per
   timer. Cannot be evaluated without the flag list.

## 6. Risks and unknowns

- Early csi runs (0830-0901) have no per-spec data; their reap attribution is
  indirect.
- Only 10 conformance and 6 csi passing samples per spec. A p99 is the max. A
  rare slow outlier (like `ResourceQuota status` at 275 s vs 5 s) can land
  anywhere, so 2x max is the honest margin.
- The 0930-1359 1.37.1 full run was lost, so nothing here is measured on the
  1.37.1 binary (archives run `e2e.test/v1.36.4`). Re-measure after the next
  1.37.1 csi run.
- Namespace termination uses the apiserver's finalize `PUT` as the end marker.
  It is a proxy for "gone". The two measured csi runs disagree on p50
  (15 s vs 5 s), which suggests load-dependence.
- Where ginkgo's 24 h suite timeout comes from is not determined.

## 7. Method (reproducible)

```
# per-spec rows: run, state, seconds, start, end, full name
jq -r --arg d "$RUN" '.[0].SpecReports[]
  | select(.LeafNodeType=="It" and .State!="skipped")
  | [$d,.State,(.RunTime/1e9),.StartTime,.EndTime,
     ((.ContainerHierarchyTexts+[.LeafNodeText])|join(" "))] | @tsv' \
  "$RUN/plugins/e2e/results/global/report.json"
# sort -n + awk index at NR*p for percentiles
```

Namespace termination: `awk` over `apiserver.log` pairing the first
`method=DELETE .../api/v1/namespaces/X status=200 user_agent=e2e.test` with the
first `method=PUT .../namespaces/X/finalize status=200`.
