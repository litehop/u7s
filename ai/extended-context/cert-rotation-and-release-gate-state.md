---
as_of: 2026-11-04
kind: initiative-state
---

# Release gate and cert rotation: state as of 2026-11-04

Main is NOT release-ready: on the real gate shape the node wedges under a
40-50 pod burst (page-cache thrash of the control plane's own file pages), and
mitigation awaits an operator decision (`mayor-hjwdo`).

## Gate shape and first real verdict

- Release-authoritative GCP gate VM: `n1-custom-1-1024` (1 dedicated vCPU, 1
  GiB; `mayor-kwu4h`, #2105, operator 2026-11-04), Spot ~$0.019/h. Rejected:
  e2-micro (0.25 sustained vCPU, 30 s burst; E2 caps do not show as steal,
  `mayor-w5xs5`) and e2-custom-medium-1024 (2 x 50%; one thread drops to 0.5
  core after a 120 s burst). A dedicated core is slightly optimistic against a
  shared VPS.
- `mayor-ltido` (v0.4.3-snapshot.4, `--confirm`): FAIL, 0/3 at 50 pods and 0/3
  at 40. 20 pods take 14-54 s. The node wedges with ~95% iowait; no OOM, steal
  0. The earlier e2-micro verdict (`mayor-mk9lv`) was CPU-starved and is not
  representative. The MariaDB first-init failures on e2-micro (`mayor-vw7jc`,
  `mayor-yfca9`) came from that shape's CPU cap plus the 375m limit, not a u7s
  bug.

## Cause of the burst cliff (`mayor-kutwm`)

Once burst pods take ~100 MiB of ~210 MiB idle headroom (WordPress+MariaDB
resident), the control plane's file pages thrash (~1.4M refaults/s across KCM,
kubelet, CRI-O, apiserver). Kubelet stalls, the node goes NotReady and taint
eviction removes every pod; there is no recovery at rest. Not CPU, I/O or
apiserver. Knee: <=20 pods with WordPress+MariaDB, 50-60 without. Findings:
`git show archive/mayor-kutwm-findings`.

Open:
- `mayor-hjwdo`: product mitigation, operator decision pending.
- `mayor-9ygmh`: A/B of #2039 (control-plane memory protection: MemoryLow,
  kubelet reserved, `enforceNodeAllocatable=pods`) on the Lima ramp. No
  verdict yet.
- `mayor-adwea`: the ~100 MiB idle-headroom loss since October. Interim
  result: no u7s release lost it (GCP MemAvailable flat v0.3.0 to
  v0.4.3-snapshot.4); 10 ssh observers cost 79 MiB, a Lima direct test is
  pending under `mayor-9ygmh`.

## Harness

- Lima backend installs its unsigned local tarball with `--tarball` (#2108);
  script-tests flake fixed (#2104); hygiene (#2101).
- GCP experiment mode (`mayor-086v6`, #2041): `burst-gate.sh --backend gcp
  --tarball` installs a tarball built by
  `scripts/release-gate/build-experiment-tarball.sh <ref>`; verdicts are tagged
  EXPERIMENT.
- Open gap `mayor-hxuqo`: a run that wedges mid-burst loses its verdict
  evidence, and a never-Ready mariadb-0 leaves no describe/logs (also
  `mayor-jvcxv`).
- Publish needs operator approval on the Release environment; snapshot cuts are
  operator-only.
- Operator rules (2026-10-30): no pre-pull or sequencing in the gate (users
  just `kubectl apply`); pd-standard stays; do not publish unmerged code.
- Gate VPSes are `u7s-rg-<MMDDHHMMSS>-<n>` (`mayor-ddhlo`); check for strays by
  that pattern; node name <= 52 chars. A preemption mid-run yields no verdict.
- Burst gate: `scripts/release-gate/burst-gate.sh --confirm` (~1-2 h). On Lima,
  "quiet" means no other Lima VM, host CPU >= 70% idle, no cargo builds; a noisy
  run counts as FAIL (`6uez9`).

## Cert rotation and other checks

Control-plane kubelet runs as `system:node:<name>` with rotating certs (#1932);
uppercase-hostname install (#1935, `zl285`; live checks need an uppercase
hostname); advisories bumped (#1938). Non-gating: `xdw6u.8` (two-tier CA),
`.9` (root succession; worker `ca.pem` goes stale after succession).
`pki-rotation-e2e` is ADVISORY (removed from required checks 2026-10-24,
`fhdqw`, #2013); do not re-require it without asking the operator.

## Memory measurement (`w898x`)

A Rust rewrite would save at most ~22-34 MB (KCM) and ~27-32 MB (kubelet) on the
loaded 1 GiB node (feeds `vc844`). Findings: `git show
archive/mayor-w898x-findings`.

## Working rules

- Match upstream unless incompatible with a deliberate u7s choice.
- A PR that narrows a component's identity or changes admission/watch/RBAC
  semantics stays draft until a full two-node Conformance run is green.
- `cargo audit` is non-blocking for PRs (operator decision).
- The tick queues a PR on LGTM and removes its worktree on merge: convert to
  draft before follow-ups; never leave commits unpushed in a queued worktree.
- The tick discards the regenerated `.beads/issues.jsonl` before each pull; run
  `bd export -o .beads/issues.jsonl` and land it in the wrap PR.
