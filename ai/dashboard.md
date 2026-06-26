# Dashboard
2026-06-26T09:19Z — Mayor active. **0 workers in-flight, 0 open PRs, all 3 VMs free.** On main `98b8e69a`. Branch protection ON.

Resume: `bd prime`

## What needs the operator now
**Decision: kick off a fresh FULL conformance run?** The actionable bead queue is drained (19 PRs merged this session). The last full data is the PARTIAL 0625-2158 sample (184/444 specs, killed at the 6h cap) — now stale after 19 fixes. A fresh full run would re-baseline the real remaining surface and inform the 2 non-trivial open beads (wjon, gobh).
- Open question if you run it: bump the 6h sonobuoy cap? This session fixed many hang sources (pod-start/defaulting, proxy, status), so it may now finish in 6h. (NOTE: `--plugin-timeout` is NOT a valid flag — that was reverted. The cap is the aggregator `timeoutseconds` in the sonobuoy config; needs `sonobuoy gen --timeout` or a config file — verify the flag against the binary before editing.)

## Open beads (3) — none a clean fix-dispatch
- **mayor-wjon** (P2) in-place pod resize (`/pods/{name}/resize` subresource) — SPIKE-FIRST, a real feature. Scope before dispatch.
- **mayor-gobh** (P3) OIDC discovery residual failures after the #606 TLS fix — INVESTIGATE-FIRST: needs a fresh `--focus` to capture the real failures (RBAC escalation? kube-root-ca CA mismatch?). Original log was lost.
- **mayor-9xb5** (P3) remove dead `default_pod` from defaults.rs (trivial cargo-only chore; filed from #612). The one cleanly-dispatchable item, but tiny.

## Deferred (3)
- mayor-52wo (P2) embed upstream OpenAPI v2 for built-in types — also makes `kubectl create/apply --validate` work (currently fails default validation on built-in types; needs `--validate=false`).
- mayor-j7to (P2) Argo CD minimal RBAC seed.
- mayor-rvkq (P3) CRD CEL validation rules.

## Stance
Pre-alpha Kubernetes apiserver in Rust. Correctness > conformance breadth. Workers in isolated worktrees (`ai/worktrees/`); mayor orchestrates, does not code (except trivial 4-condition, externally-verified edits). Merge-on-green WITH verification. No back-compat shims. Never `--admin`.

## Standing rules / lessons
Persisted as bd memories (survive compaction) — `bd memories` to read. This session banked: verify-bead-framing-before-dispatch · typing-guideline-no-raw-json-for-reasoned-fields · continue-running-agent-with-sendmessage · extract-e2e-logs-before-worktree-remove. (Time discipline + push policy + worker-dispatch mechanics already in memory.)

## VM slots
| Slot | VM | Port | Kubelet | Status |
|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | operator stack (kubeconfig at temp/u7s/kubeconfig, node Ready) |
| worker-1 | lima-node-smoke | 6444 | 10251 | free |
| worker-2 | lima-node-2 | 6445 | 10252 | free |
Konnectivity ports now per-slot (#613): server = 8135 + N×100; default 8135 = mayor.

## Recent merges (this session) — 19 PRs + 1 direct commit
Drain/endpointslice wave (latest first): #613 konnectivity per-slot ports (3w29) · #612 consolidate pod defaulting + found #610 default_pod dead-code (kma3) · #611 QOS compare-by-value (w3b5) · #610 containerPort/Service-port protocol=TCP (8ykk) · #609 EndpointSlice proto tag-swap (6ipr) · #608 clear stale condition reason on kubelet null (wblp).
DEFER re-triage wave: #607 enable disruption controller (khgv) · #606 serving-cert kubernetes.default.svc SANs (s8ur) · #605 enableServiceLinks proto field 26 (kgtw) · #604 cfg(test) prepare_live_event (18h4) · `1a437ce9` KCM `--controllers='*,-cloud'` direct-commit (4xjk).
Triage wave: #603 pod-proxy http→https (52fb) · #602 secs_to_rfc3339 leap-year fix (9ai4) · #601 Table 406 for non-Table auth handlers (ugt8) · #600 pod QOS+RuntimeClass overhead (jgwx/7r0q) · #599 lastTransitionTime decode (o67l) · #597 Service UpdateStatus conditions (ujet) · #596 CSI + ephemeral containers (emm1/xt41/trm9). #598 closed (wrong-path, superseded by #601).

## Session loops
:07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard
