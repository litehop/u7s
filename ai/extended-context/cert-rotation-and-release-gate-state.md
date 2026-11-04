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
  at 40. 20-pod bursts take 14-54 s across the six runs (50-pod runs 14-46 s,
  40-pod runs 46-54 s). The node wedges with ~95% iowait; no OOM, steal 0. The
  earlier e2-micro verdict (`mayor-mk9lv`) was CPU-starved and is not
  representative. `mayor-w5xs5` reproduced the slow MariaDB first init with
  plain podman on a drained e2-micro (25% sustained CPU plus 11.8.6
  temp-server RSA keygen); the 375m CPU limit adds throttling under u7s. The
  fix choice is open (`mayor-yfca9` in progress, `mayor-vw7jc` open).

## Cause of the burst cliff (`mayor-kutwm`)

Once burst pods take ~100 MiB of ~210 MiB idle headroom (WordPress+MariaDB
resident), the control plane's file pages thrash (~1.4M refaults/s across KCM,
kubelet, CRI-O, apiserver). Kubelet stalls, the node goes NotReady and taint
eviction removes every pod; there is no recovery at rest. Not CPU, I/O or
apiserver. Knee: <=20 pods with WordPress+MariaDB, 50-60 without. Findings:
`git show archive/mayor-kutwm-findings`.

Open: `mayor-hjwdo`, product mitigation, operator decision pending.

Verdicts (2026-11-04):
- `mayor-9ygmh` (closed): #2039's control-plane memory protection measured
  WORSE than main on the Lima ramp (knee 20 vs 20-50; MemAvailable min 153-161
  vs 195-256 MiB; mem PSI 79-84% vs 41-64%; one OOM of CoreDNS+MariaDB),
  consistent with the 1 GiB node being capacity-bound. #2039 is left as a
  draft (`mayor-i4bvb`: operator to decide whether to close it). The
  observer-light knee is unknown.
- `mayor-adwea` (closed): no release regression; idle headroom is flat
  v0.3.0 to v0.4.3-snapshot.4 on GCP N1. The "~100 MiB" was observer load (~79
  MiB from streaming ssh sessions), so the kutwm knee is pessimistic; GCP's
  unstreamed gate still fails at 40/50. Findings: `git show
  archive/mayor-adwea-findings`.

## Harness

- Lima backend installs its unsigned local tarball with `--tarball` (#2108);
  script-tests flake fixed (#2104); hygiene (#2101).
- GCP experiment mode (`mayor-086v6`, #2041): `burst-gate.sh --backend gcp
  --tarball` installs a tarball built by
  `scripts/release-gate/build-experiment-tarball.sh <ref>`; verdicts are tagged
  EXPERIMENT.
- Open gap `mayor-hxuqo`: a run that wedges mid-burst loses its verdict
  evidence, and a never-Ready mariadb-0 leaves no describe/logs.
- Publish needs operator approval on the Release environment; snapshot cuts are
  operator-only.
- Gate VPSes are `u7s-rg-<MMDDHHMMSS>-<n>` (`mayor-ddhlo`); check for strays by
  that pattern; node name <= 52 chars. A preemption mid-run yields no verdict.
- Burst gate: `scripts/release-gate/burst-gate.sh --confirm` (~1-2 h). On Lima,
  "quiet" means no other Lima VM and host CPU >= 70% idle over 30 s (re-checked
  every ~60 s, plus an in-guest CPU calibration); a non-pass on a noisy host is
  INVALID (exit 3), repeated up to `MAX_INVALID_RUNS` and never counted; a PASS
  under contention stays a PASS. Shipped in #1955 (`mayor-6uez9`, still open:
  collector tests, in-VM watchdog kill, forced-failure path, unifying the
  aarch64/x86_64 tarball staging).

## Cert rotation and other checks

Control-plane kubelet runs as `system:node:<name>` with rotating certs (#1932);
uppercase-hostname install (#1935, `zl285`; live checks need an uppercase
hostname); advisories bumped (#1938); two-tier CA shipped (`xdw6u.8`, #1995).
Non-gating and open: `xdw6u.9` (root succession; worker `ca.pem` goes stale
after succession).
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
