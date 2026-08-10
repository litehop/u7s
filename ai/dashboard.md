# Dashboard
2026-08-10 (session) — Mayor at HEAD `e894b873` (main).
Resume: `bd prime` → this file.

## Stance
Resource-optimized k8s. Correctness → observability → perf. Pre-alpha, no back-compat.
**This session:** drain P1s + chase disjoint P2s; merge on green (never `--admin`); no per-PR approval.

## ▶ IN PROGRESS
- **mayor-ajogf** (P2, script) — worker running. Flip KCM to `--kube-api-content-type=application/vnd.kubernetes.protobuf` (one-line change to `scripts/conformance/04-start-kcm.sh:~140`). Gate: **full conformance suite** run (the one documented exception to the no-bare-run-all.sh rule). Compares against 0810-0107 baseline pass count. VM `lima-node-4` :6446 kubelet :10253 (reusing rcujn's stack).

## Open PRs
_none._

## ✅ merged this session (7)
- **#1080** — `refactor(watch): type-migrate watch stamping + PartialObjectMetadata (mayor-4yct9)` — 249/45/1-file. Structurally impossible to leak spec/status into PartialObjectMetadata now.
- **#1079** — `refactor(apiserver): OwnerReference struct + GC + LIST envelope (mayor-0bd14.2)` — 328/41/3-file. Closes the cross-cutting ownerReferences workaround gap.
- **#1078** — `docs(extended-context): synthesize memory-management-state.md (mayor-0owbg)` — 49/0/2-file committed synthesis; refresh via Sun :37 UTC cron `c6250b1c`.
- **#1077** — `fix(apiserver): decode PVCStatus.{6 fields} (mayor-ovni7)`.
- **#1076** — `fix(scheduler): enforce PV spec.nodeAffinity in Filter (mayor-k8m7p)` — 622s → 80s.
- **#1075** — `perf(auth): move is_exempt/parse_path before async move (mayor-dv6we)` — ~1% apiserver alloc bytes.
- **#1074** — `fix(apiserver): decode PVCSpec.{4 fields} (mayor-ifrs4)`.

## Recently returned + closed
- **c6s2o** — proto-encoding audit. HEADLINE: response-side re-encoding was reverted the same day it shipped (2026-05-21 commit `51d54dec`); `reencode_proto_response` is a pass-through today. Filed **mayor-7txak** (P3, delete vestigial guards). Verified `mayor-xuzqu`'s premise as FALSE — doc-comment is accurate on current main → **closed xuzqu** as verified-false. Part B: KCM flip SAFE on 6 tested Pod fields → dispatched **mayor-ajogf**.
- rcujn, 0bd14.1, ddcyx, 0owbg, rr177 — earlier returns/closures still on record.

## Unblocked-by-#1079 cluster (next dispatch after ajogf)
Three P3 typed-migration cleanup beads all touching the same "post-ownerReferences tightening" theme → natural single cluster PR:
- **mayor-m2db9** — 2nd ownerReferences workaround site in `handlers/resource.rs::create_namespaced_resource`
- **mayor-0bd14.6** — CR envelope stamping (removes `handlers/cr.rs::stamp_cr_fields` workaround)
- **mayor-7p767** — tighten `handlers/watch.rs::{to_partial_object_metadata, finish_deleted_event}` to full ObjectMeta round-trip

## Queued
- **mayor-0bd14 children (.3/.4/.5/.7/.8/.9)** — P3, dispatch after cleanup cluster lands.
- **mayor-drs2a** (P1, store) — Stage-2 SqliteStore sharding. Needs Phase-1 scoping bead.
- **mayor-bfq6l** (P2, scout) — rcujn follow-on: `--procs=4+` mount-race retest.
- **mayor-7txak** (P3, cleanup) — 4 vestigial re-encode guards in `content_type.rs`.
- **mayor-5uuqt** (P4, process) — 0bd14-tracking audit-trail gap.

## Loops registered
:07 reread · :17 worktree hygiene · :13/:43 cluster review · :23/:53 merge sweep · :08/:23/:38/:53 dispatch · :04/:14/:24/:34/:44/:54 dashboard · Sun :37 UTC extended-context freshness (cron `c6250b1c`)

## VM inventory
- `lima-node` :6443 kubelet :10250 — mayor
- `lima-node-2` :6444 kubelet :10251 — free (k8m7p returned)
- `lima-node-3` :6445 kubelet :10261 — operator's companion; do NOT reassign
- `lima-node-4` :6446 kubelet :10253 — **mayor-ajogf KCM-flip worker** (reusing rcujn stack)
- `lima-node-5` :6447 kubelet :10254 — free (c6s2o returned; stack running)
- Slot 5 (`lima-node-smoke`) unprovisioned
