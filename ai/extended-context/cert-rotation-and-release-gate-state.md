---
as_of: 2026-10-21
kind: initiative-state
---

# Cert rotation and the release gate: state as of 2026-10-21

Main (`4d3641a2`) is release-ready: cert rotation is complete, the 1 GiB
burst gate passed at 50 pods 3/3, and `cargo audit` is clean. Cutting the
snapshot is the operator's call.

## Release checks

| Check | Result |
|---|---|
| Cert rotation (`xdw6u.2-.5`, `.11`, `zboqh`) | merged; control-plane kubelet runs as `system:node:<name>` with rotating certs (#1932) |
| Burst gate (`f2gfd` option A) | 50 pods, 3/3, quiet host, main `360b9750`; MemAvailable ≥ 202 MiB, bursts 24–32 s |
| Install on uppercase hostnames (`zl285`) | fixed (#1935); hosts that already failed recover on re-run |
| Advisories (`09au3`) | `cmov`, `rustls-webpki`, `webpki-root-certs` bumped (#1938) |

Non-gating: `xdw6u.8` (two-tier CA), `.9` (root succession; carries a note
about worker `ca.pem` going stale after succession). `pki-rotation-e2e`
becomes a required check after 10 green runs (`bjuu2`, operator action).
`d7uta`: the pinned pkgs.k8s.io apt key expires 2026-12-29 and upstream had
not extended it on 2026-10-21; re-check by 2026-12-08.

## Re-running the burst gate

`scripts/release-gate/burst-gate.sh --confirm` (~1–2 h). "Quiet" means no
other Lima VM, host CPU ≥ 70% idle, no cargo builds. Pattern that worked:
put the dashboard on a dispatch hold, skip the hygiene loop (a remote branch
delete triggers the pre-push hook's full cargo run), then ONE worker runs the
gate and any measurement back to back. A noisy run counts as FAIL (no
INVALID verdict yet, `6uez9`). The harness names VMs with an uppercase UTC
stamp, which is also the only live test of uppercase-hostname installs.

## Memory measurement (`w898x`, feeds the Rust-rewrite go/no-go `vc844`)

On the loaded 1 GiB node a rewrite would save at most ~22–34 MB (KCM) and
~27–32 MB (kubelet); flags recover ~12 / ~8 MB today (trimmed `--controllers`
+ `GOMEMLIMIT`; `GOMEMLIMIT=40MiB` on the full controller set costs ~22% vCPU
in GC). Findings: tag `archive/mayor-w898x-findings`.

## Working rules learned 2026-10-20/21

- Match upstream unless incompatible with a deliberate u7s choice; check
  bead notes and upstream source before surfacing a "decide" bead.
- Any PR that narrows a component's identity (e.g. kubelet off admin), or
  changes admission/watch/RBAC semantics, stays draft until a full two-node
  Conformance run is green; focus specs missed 8 failures on #1932.
- Live `install.sh` checks need an uppercase hostname.
- `cargo audit` is non-blocking for PRs (operator decision); the hygiene
  loop's STEP H flags a red main audit as exit bit 4.
- The tick queues a PR the moment it has an LGTM(-with-suggestions) and
  removes its worktree on merge: convert to draft before sending follow-ups,
  and never leave commits unpushed in a queued worker's worktree.
- The tick discards the regenerated `.beads/issues.jsonl` before each pull;
  run `bd export -o .beads/issues.jsonl` and land it in the wrap PR, or bead
  state stays only in the local DB.
