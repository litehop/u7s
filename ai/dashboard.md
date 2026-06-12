# Dashboard
2026-06-12T10:05Z — 1 worker in-flight (P1 stall-watchdog fix). No open PRs.

Resume: `bd prime`

## Operator attention needed

**GitHub branch protection is off.** Workers can push directly to main. Recommend enabling (PR + status checks required, 0 approvals). One `gh api` call — operator decision needed.

**Decision pending: admission webhook enforcement (mayor-91p3, P1).** Large structural feature (webhook invocation path, mTLS via konnectivity, matching engine). NOT yet dispatched — needs scoping/approach decision before a worker. Recommend audit → operator decides → apply.

**Confirmed root cause: stall-watchdog (b1dc438) was killing healthy runs.** It keyed on result-counts, which sonobuoy returns as `null` for the entire e2e run until the very end. Fix dispatched (mayor-f73c) — now keys on progress.completed/msg. Verified against sonobuoy docs + your midway-dump.log. This was NOT an apiserver bug.

## In-flight workers

| Worker | Bead | Surface | VM |
|---|---|---|---|
| acc440329b9ec0b4f | mayor-f73c (P1) | scripts/conformance/06-run-sonobuoy.sh | lima-node-smoke:6444 |

## Open PRs

None.

## Recent merges
- #531 fix(apiserver): seed CoreDNS Corefile with kubernetes cluster.local plugin (mayor-mm5q)
- #529 fix(apiserver): store and validate matchConditions in webhook configurations (mayor-ahqr)
- acda944 docs(ai): lead vm-operations.md with run-all.sh as primary conformance path
- b1dc438 fix(scripts): sonobuoy stall detector (mayor-l5hs, direct push)

## VM port assignment
| Slot | VM | Port | Who |
|---|---|---|---|
| mayor | lima-node | 6443 | Mayor |
| worker-1 | lima-node-smoke | 6444 | free |
| worker-2 | lima-node-2 | 6445 | free |
| worker-3 | — | 6446 | free |
| worker-4 | — | 6447 | free |
| worker-5 | — | 6448 | free |

## Queued beads
- mayor-91p3 (P1) — admission webhook enforcement (webhooks never invoked during admission)
- mayor-b69i (P2) — CEL validation on MutatingWebhookConfiguration matchConditions
- mayor-1mp5 (P2) — json-patch on custom resources (application/json-patch+json)

## Loops running (session-only, expire 7 days)
- :07 hourly — posture reread (bb24b47f)
- :11 hourly — worktree hygiene (08b00076)
- :17 every 2h — cluster review (21c96a0e)
- :23 every 2h — merge pass (a9211fb9)
- :43 hourly — bead dispatch pass (6c5b835f)
- :53 hourly — dashboard refresh (a0fe9f4a)
