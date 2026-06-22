# Dashboard
2026-06-22T03:23Z — No in-flight workers. No open PRs. Queue empty. 0 P1s.

Resume: `bd prime`

## Operator attention needed

**Queue is empty** — run a fresh broad conformance run to replenish beads.

Suggested: `scripts/conformance/06-run-sonobuoy.sh` (no `--focus`, lima-node-smoke or lima-node-2 slot, full non-disruptive-conformance mode).

**Stance** — pre-alpha Kubernetes apiserver in Rust. Correctness > breadth. Merge-on-green. No back-compat shims.

## In-flight workers
None.

## Open PRs
None.

## Recent merges (this session)
- #558 feat(apiserver): ResourceQuota status.used background reconciler (mayor-lym4)
- #557 fix(apiserver): SSRR non_resource_rules always empty (mayor-29lw)
- #556 fix(apiserver): strategic-merge-patch routed to correct handler (mayor-33m1)
- #555 fix(apiserver): merge_conditions handles $patch:delete (mayor-s4lo)
- #554 fix(apiserver): validate_cr_name rejects uppercase and leading/trailing punctuation (mayor-f26s/3vgq)
- #553 fix(apiserver): CEL tokenizer single & and | return parse failure (mayor-ksix)
- #552 fix(apiserver): admission hardening — response cap, SSRF, oldObject, userInfo (mayor-uabj/p5kq/0604/8qqp/gx4t)
- #551 fix(apiserver): EndpointSlice reconciler — skip redundant writes, shutdown signal, backoff (mayor-m7sy/05kd)
- #550 fix(apiserver): sync Endpoints to match EndpointSlice (mayor-r5u3)
- #549 fix(apiserver): pod phase=Pending on create, self-consistent PodScheduled condition (mayor-5asj)
- #548 fix(conformance): remove unreliable stall watchdog from sonobuoy run script (mayor-xhhg)
- #547 fix(apiserver): RuntimeClass overhead injection + Event timestamp round-trip (mayor-y4ll/7jli)
- #546 fix(apiserver): check admission webhooks before websocket upgrade on pod attach (mayor-iv82)
- #545 fix(apiserver): CSR admission wiring + webhook timeout HTTP 504 (mayor-shi8/scgr)
- #544 fix(apiserver): ADDED watch event regression test for label-selector path (mayor-0ck0)
- #543 feat(apiserver): invoke admission webhooks during CR admission (mayor-91p3)
- #542 fix(apiserver): matchConditions CEL validation enforced on webhook create (mayor-zbqc)
- #541 fix(conformance): re-enable watchdog loops (mayor-sz6b)
- #540 fix(apiserver): ConfigMap empty-key 422, OpenAPI content-type, NodePort→ExternalName
- #539 fix(scripts): always propagate --workdir to child scripts (mayor-apfa)

## VM port assignment
| Slot | VM | Port | Kubelet | Who |
|---|---|---|---|---|
| mayor | lima-node | 6443 | 10250 | operator |
| worker-1 | lima-node-smoke | 6444 | 10251 | free |
| worker-2 | lima-node-2 | 6445 | 10252 | free |
| worker-3 | — | 6446 | 10253 | free |

## Queued beads
None — queue empty.

## Session loops
- :07 posture · :11 worktree hygiene · :17/2h cluster · :23/2h merge · :43 dispatch · :53 dashboard
