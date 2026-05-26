# Dashboard
2026-05-26 17:30 UTC
Session: current — resume with `claude --continue` in /Users/balint.erdos/u7s
Open beads: 1

## What I need to do next

**Operator action needed: wait for PR #260 to go green, then `--reset` run.**

PR #260 fixes the second BeforeSuite blocker: `spec.unschedulable=false` returned 0 nodes because absent fields weren't treated as the zero value. Two-bug chain:
1. `!=` parsing bug (PR #259 ✓) — nodes query was malformed
2. `=false` absent-field bug (PR #260 pending CI) — nodes returned but filtered out

Once #260 merges, run:
```bash
scripts/conformance/run-all.sh --reset
```

No operator decisions pending.

## Forward-looking

**Next: sonobuoy triage wave.** Once we have real failures, expected surface from prior analysis:
- `generateName` (mayor-l8f — check status)
- JSON Patch / `application/json-patch+json` (mayor-jf3)
- `spec.nodeName` fieldSelector on pods (probably works — SQL fast-path)
- Other fieldSelectors (mayor-yx5 — partial; `!=` now works, `=false` on absent now works too)
- Namespace Terminating lifecycle (mayor-c3v)
- Pod status subresource (mayor-b4g)
- `kubectl logs` / log proxy returning 500 (known surface, was mayor-f44c)

After sonobuoy: file beads → cluster by surface → dispatch 4-6 workers.

## Recent progress (this session)

**PR #260 in CI:** fix fieldSelector `=false` on absent field. Root cause of SECOND BeforeSuite failure. The e2e framework queries `spec.unschedulable=false` (not `!=true`!). Our node has `spec.unschedulable` absent. Old code: absent field returns `*negated` = `false` (excluded). Fix: absent fields match `""` or `"false"` (Kubernetes zero-value semantics).

**Investigation method:** extracted e2e.log from sonobuoy tarball inside kubelet emptyDir volume. Confirmed: DNAT works from container network (tested via `nsenter -n -t <coredns-pid>`). Bug was pure store logic, not network.

| PR | What | Beads |
|----|------|-------|
| #260 🟡 CI | fieldSelector `=false` on absent field | mayor-mc5q (P1) |
| #259 ✓ merged | fieldSelector `!=` + bool comparison | mayor-gtue (P1, closed) |
| #258 ✓ merged | kubelet client cert on log/exec proxy | — |
| #257 ✓ merged | sonobuoy retrieve before aggregator exits | — |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal deps. Mayor merges on green CI automatically; flags security/API/architecture decisions first.
