---
updated: 2026-10-17T05:00Z
---
# Dashboard — session 2026-10-16 → 17 WRAPPED (main `49b75c06`)
**Stance:** pre-alpha; correctness (Conformance first) > security > perf > features; queue merge on green, never `--admin`. Never put the GCP account/project in git/GitHub.
**Resume:** `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register 4 crons (tick 15m, posture 60m, hygiene 60m, beep-release watch 60m). No workers, worktrees, VMs or stashes left running.

## 🎯 Waiting on you
- **Security call:** #1866 kubelet-serving approver IP-SAN rule (mayor default: unique across Nodes, not loopback/link-local/multicast/service-CIDR/apiserver). Stronger pinning = `xdw6u.6.2`.
- **Your OK:** `60d7s` — loosen #1885's aggregation traversal guard to upstream parity (%2F as separator); classifier blocks it as a security weakening.
- **Release dry run:** #1874's split release workflow is untested until a real run; a `workflow_dispatch` `-SNAPSHOT` publishes a prerelease. Want one before `v0.4.0-snapshot.1`?
- **Decide:** `5b58c` skills repo · CI toolchain pinning · gate confirmation timing (3× at 50 pods, else 40; ~1 h quiet host).
- **Permission:** classifier blocks guard-disabling revert runs and direct guard-script invocation; workers use read-based revert evidence. Settings call.
- **beep:** v0.6.0 not green (ETP=Local LB with zero local pods: beep operator's call); beep sends an RC.
- **#1871:** Renovate bump of taiki-e/install-action, not mayor-reviewed.

## Next up (no operator input needed)
- P2: `4xypz` SMP directive keys stored in appended list elements · `zkchq` /healthz ?verbose checks (conformance) · `1xpj7` remaining SSA ownership items.
- P3: `ynfzk` tick cursor + skipped-bead list · `7r4et` stale discovery diagnostics · `d8c5z` query gracePeriodSeconds · audit beads.
- Release: beep v0.6.0 RC → re-eval → `jlm8z` → `v0.4.0-snapshot.1` (confirm with you).

## Decided this session
- Beads close on PR **merge** (2026-10-17). Workers note `PR #N opened` (or `(partial: …)`); mayor-tick closes only beads with a matching non-partial note (#1887 + #1889). First run wrongly closed 5 beads; reopened.
- C2 join: Secret-backed single-use tokens, 24h TTL, stdin, tokenless upgrades; installer upgrade compatibility once installs exist in the wild.
- Version format `v1.37.1+u7s-<release>`.

## ✅ Merged this session (#1812–#1889)
**All 7 HIGH OWASP fixes** · **C2 join series** (#1854 #1864 #1866 #1873) · ServerSideApply 2/7 → 7/7 (#1862, 21 e2e specs in CI) + per-kind ownership (#1868) · RBAC: reconcile, key parsing, escalation + nonexistent roleRef, rules_cover parity · authz: no exemptions for discovery/health (#1888), verb from decoded query, non-resource HEAD · DoS: watch caps, idle h2 + per-IP cap, body-read deadline, inflight reserved seats + pre-auth guard, linear SMP + budget, aggregation body cap · API parity: PUT-on-missing 404, options validation (Create/Update/Patch/Delete), creationTimestamp, storageVersionHash, CSR timestamps + table, $retainKeys · CA roll-forward + fsync · version stamping · P1 port-kill · git guard ×3 · release workflow least-privilege + --locked · politeia v0.2.1 (#12–#16).
