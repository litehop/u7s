# Dashboard
2026-05-24 05:00 UTC
Session: f317c180-6e09-4912-b648-3b889a2d42d0 (CLOSED)
Open beads: 2 (1×P2 stale in-progress, 1×P3 deferred)

## What needs the operator now

**sonobuoy-run.sh has an uncommitted fix** — `--skip-preflight=dnscheck` added to
`scripts/sonobuoy-run.sh`. Include in next commit before running sonobuoy.

**Decision on mayor-4na6 (P2, IN_PROGRESS since 2026-05-22):**
Generify AppState over `S: Store`. The OCC tests it was meant to unlock were delivered
without it (PRs #221–#222). Close as superseded, or dispatch for future testability?

**Run sonobuoy** (Phase 3 exit criterion 2):
```
scripts/conformance/run-all.sh --reset
```

## Forward-looking

After sonobuoy: triage HIGH failures → file beads → conformance sprint (Phase 3 → Phase 4).
`mayor-6w76` (P3) — proto decoder, activate only on observed decode failure.

## Recent progress

**Session f317c180: 9 PRs merged (#217–#225), ~21 beads closed, 912 workspace tests (+56 from ~856).**

| Area | What landed |
|------|-------------|
| Conformance stack | reset.sh, --reset flag, 04-start-kcm.sh bash fix, sonobuoy dns preflight fix |
| Security | CT token constant-time comparison, JWT sub guard, cert identity rename + 3 tests |
| Store | Lagged emits compaction_horizon correctly (not message count) |
| Scheduler | Double-bind dedup, bind_pod Err on non-2xx, drain_watch_buffer → client-util, +14 tests |
| Handler coverage | cr, status, resource, namespaces, pods, approval, csr (+42 tests, PRs #221–#222) |
| Final coverage | stream.rs splice/BiStream, tls.rs edge cases, proxy.rs node-not-found (+13 tests, PRs #223–#225) |

## Stance
Pre-alpha/greenfield — break freely, no backward compat, correctness first,
performance-critical, kubectl-compatible surface, minimal deps. Mayor merges on
green CI automatically; flags security/API/architecture for operator first.
