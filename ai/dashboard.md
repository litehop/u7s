# Dashboard
2026-05-26 17:05 UTC
Session: current — resume with `claude --continue` in /Users/balint.erdos/u7s
Open beads: 0

## What I need to do next

**Operator action needed: one more `--reset` run.**

The last sonobuoy run (07:18 UTC) started before PR #259 merged (07:25 UTC) so it used the old binary. The fix IS verified working end-to-end: SA token from inside the VM against `10.96.0.1:443` now returns lima-node correctly. Run:
```bash
scripts/conformance/run-all.sh --reset
```
This time BeforeSuite should pass and real test failures will appear.

No operator decisions pending.

## Forward-looking

**Next: sonobuoy triage wave.** Once we have real failures, expected surface from prior analysis:
- `generateName` (mayor-l8f was filed — check if still open after bd sync)
- JSON Patch / `application/json-patch+json` (mayor-jf3)
- `spec.nodeName` fieldSelector on pods (probably works — we have the SQL fast-path)
- Other fieldSelectors (mayor-yx5 — partial; `!=` now works, but other spec fields may not)
- Namespace Terminating lifecycle (mayor-c3v)
- Pod status subresource (mayor-b4g)
- `kubectl logs` / log proxy returning 500 (known surface, was mayor-f44c)

After sonobuoy: file beads → cluster by surface → dispatch 4-6 workers.

## Recent progress (this session)

**PR #259 in CI:** fix fieldSelector `!=` operator and bool comparison — root cause of 0 tests running. Worker diagnosed: `parse_field_selector` split on first `=`, so `spec.unschedulable!=true` became field=`spec.unschedulable!`, value=`true`. Store returned 0 nodes. BeforeSuite aborted.

**Root cause investigation method:** read e2e log directly from kubelet emptyDir volume (`/var/lib/kubelet/pods/.../output-volume/`) via Lima MCP — no need for full sonobuoy run to diagnose. Also confirmed via `kubectl get nodes --field-selector=spec.unschedulable!=true` returning empty live.

| PR | What | Beads |
|----|------|-------|
| #259 ✓ merged | fieldSelector `!=` + bool comparison | mayor-gtue (P1, closed) |
| #258 | kubelet client cert on log/exec proxy | — |
| #257 | sonobuoy retrieve before aggregator exits | — |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first, performance-critical (RSS/latency hard targets), kubectl-compatible API surface, minimal deps. Mayor merges on green CI automatically; flags security/API/architecture decisions first.
