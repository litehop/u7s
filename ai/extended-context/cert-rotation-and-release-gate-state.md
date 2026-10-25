---
as_of: 2026-10-25
kind: initiative-state
---

# Cert rotation and the release gate: state as of 2026-10-25

Main is NOT release-ready: `v0.4.2-snapshot.1` (main `89de86f6`, prerelease
2026-10-25) FAILS criterion (d) of the release-authoritative GCP e2-micro
gate, reproducing the `v0.4.1-snapshot.1` failure (`mayor-vw7jc`). Cert
rotation, install on uppercase hostnames and the advisory bumps are done; the
Lima burst gate (50 pods, 3/3, 1 GiB) passed on 2026-10-21.

## The GCP gate failure (`vw7jc`)

On a fresh e2-micro, io PSI reaches 72% and cpu PSI ~61% for the first ~20
min, and mariadb's 375m CPU limit is throttled. The official mariadb
entrypoint's 30 s temporary-server wait then expires: it logs `Unable to
start server.` and exits 1 after the datadir is initialised but before the
root password is set. The container restarts on the same emptyDir, skips
init, and root auth is broken forever, while `mariadb-admin ping` still
succeeds so the pod stays Ready. WordPress returns 000 and the marker write
fails. A `startupProbe` does not help (the exit is self-inflicted). Aged nodes
start the same pod in 12-100 s.

Ruled out: OOM, steal, MTU, DNS, memory pressure. Not isolated: cold
pd-standard disk versus e2 shared-core burst-credit exhaustion.

Options awaiting operator decision (none chosen):

- Robust mariadb workload (init tolerant of slow start); the mayor's recommendation (`vw7jc` note), still pending the
  operator's decision.
- Gate waits for mariadb-0 Ready before applying WordPress, and pre-pulls images.
- pd-balanced boot disk (`scripts/gcp/lib.sh`); pd-standard is deliberate,
  see `docs/dev-setup.md`.

Harness notes: gate VPSes are named `u7s-rg-<MMDDHHMMSS>-<n>` with no
per-worker prefix (`mayor-ddhlo`), so check for strays by that pattern. A
Google preemption mid-run yields no verdict.

## Other release checks

| Check | Result |
|---|---|
| Cert rotation (`xdw6u.2-.5`, `.11`, `zboqh`) | merged; control-plane kubelet runs as `system:node:<name>` with rotating certs (#1932) |
| Install on uppercase hostnames (`zl285`) | fixed (#1935); hosts that already failed recover on re-run |
| Advisories (`09au3`) | `cmov`, `rustls-webpki`, `webpki-root-certs` bumped (#1938) |

Non-gating: `xdw6u.8` (two-tier CA), `.9` (root succession; carries a note
about worker `ca.pem` going stale after succession).
`pki-rotation-e2e` is ADVISORY, removed from required checks 2026-10-24
(`fhdqw`, #2013) after hitting the merge queue's 20-min check timeout. Observe
its wall-clock; do not re-require it without asking the operator.
`d7uta`: the pinned pkgs.k8s.io apt key expires 2026-12-29 and upstream had
not extended it on 2026-10-21; re-check by 2026-12-08.

## Re-running the burst gate

`scripts/release-gate/burst-gate.sh --confirm` (~1-2 h). For the Lima
backend "quiet" means no other Lima VM, host CPU >= 70% idle, no cargo
builds. Put the dashboard on a dispatch hold, skip the hygiene loop (a remote
branch delete triggers the pre-push hook's full cargo run), then ONE worker
runs the gate and any measurement back to back. A noisy run counts as FAIL (no
INVALID verdict yet, `6uez9`). The harness names Lima VMs with an uppercase
UTC stamp, the only live test of uppercase-hostname installs.

## Memory measurement (`w898x`, feeds the Rust-rewrite go/no-go `vc844`)

On the loaded 1 GiB node a rewrite would save at most ~22-34 MB (KCM) and
~27-32 MB (kubelet); flags recover ~12 / ~8 MB today (trimmed `--controllers`
+ `GOMEMLIMIT`; `GOMEMLIMIT=40MiB` on the full controller set costs ~22% vCPU
in GC). Findings: tag `archive/mayor-w898x-findings`.

## Working rules

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
