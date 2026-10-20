---
updated: 2026-10-20T11:11Z
---
# Dashboard — session 2026-10-20 WRAPPED (main `bfe00c53`)
**Stance:** pre-alpha; correctness (Conformance first) > security > perf > features; match upstream unless incompatible; queue merge on green, never `--admin`. No GCP account/project in git.
**Resume:** `ai/prompts/mayor-bootstrap.md`; `bd prime`; read `ai/extended-context/cert-rotation-and-release-gate-state.md`; re-register crons (tick 15m, posture 60m, hygiene 60m). No workers, worktrees, VMs or stashes left.

## 🎯 Waiting on you
- 🚫 **Release gated** on the cert-rotation story: only `zboqh` (control-plane kubelet's own identity) left. `.8`/`.9` non-gating.
- **Quiet window** when convenient (~1–2 h): `scripts/release-gate/burst-gate.sh --confirm` (last FAIL was the rv=0 watch bug, fixed #1924; `--runs 3` since passed 3/3 at 50) + `w898x` KCM/kubelet memory (scrape via `kubectl create token monitoring -n kube-system`).
- `pki-rotation-e2e` → required check after 10 green runs (`bjuu2`).
- Optional: GitHub Release page for politeia `v0.3.0` (tag exists).

## Next up (no operator input needed)
- Gating: `zboqh`. Then `oebl7` (control-plane Node label, kubeadm parity), `g7cts` (VAP CEL macros + failurePolicy, P2), `2zd47` (ephemeralcontainers mutating tests + post-mutation validation, P2), `d07ct` (narrow KCM role; keep delegation rules).
- P3 follow-ons from this session's reviews: `lrrru` `7uopb` `ynn8q` (pod subresource admission) · `rrwub` `mj8xq` `c4arr` `am6oj` `yzoq1` `s62j7` `7wrra` `l2imr` `wgo1c` `8h0e0` `2o37f` `lafbn` `u9ymo` `itfmm` `7ahpf` `3cuym` `oua2n` `tcewr` `q59ly` `d7uta` (k8s apt key pin, before 2026-12-15).
- Renovate #1846 (politeia bump) is superseded by #1926 — close or let Renovate drop it.

## Decided this session
- Release gated on cert rotation done properly (`.5`, `.11` client scenarios, `.2`, `zboqh`); `.8`/`.9` P3. `xdw6u.6.2` deferred; `b8kun` pod-CIDR SAN exclusion shipped.
- Gate spec = option A (50 else 40, quiet host). PodSecurity: full upstream port. KCM delegated auth with its own identity (kubeadm parity).

## ✅ Merged this session (#1901–#1926)
Conformance: 460/460 + 2/2 restored (#1919 DefaultTolerationSeconds on update + managedFields in protobuf) · rv=0 watch serves current state (#1924) · PodSecurity admission (#1916) · health ?verbose checks (#1905) · SMP directive parity (#1902) · **cert rotation**: finite lifetimes #1909, hot-swap + 2/3 rotation #1913, file-path kubeconfigs #1917, rotation e2e #1918, scheduler reload #1926 (politeia v0.3.0), expiry visibility #1925 · security: admin role bind/escalate #1903, node-authz scoping #1904, authz path decode #1908/#1914, pod-CIDR SANs #1911, ephemeralcontainers admission #1922, KCM `/metrics` RBAC #1923, supply chain #1907 · encode-direction proto check #1921 · migrate export dry-run #1915 · gate harness #1912 · mayor tooling #1920.
