---
as_of: 2026-10-30
kind: initiative-state
---

# Release gate and cert rotation: state as of 2026-10-30

Main is NOT release-ready: the release-authoritative GCP e2-micro gate fails
criterion (d) because MariaDB's first init does not survive a cold pd-standard
disk (`mayor-vw7jc`). Fix choice is waiting on an operator decision
(`mayor-yfca9`). Cert rotation, uppercase-hostname install and advisory bumps
are done; the Lima burst gate (50 pods, 3/3, 1 GiB) passed on 2026-10-21.

## Root-cause chain (`vw7jc`)

1. Saturation is ours, not the platform's (`mayor-uaasp`, #2032): install,
   image pull/unpack and MariaDB/WordPress start-up drive the 10 GB pd-standard
   to 85-93% busy (3.8 GiB read, 2.7 GiB written). The same saturation shows at
   VM age 55 min, so it is not a fresh-VM or burst-credit effect; the earlier
   "~20 min saturated fresh VM" premise was wrong. Disk-IO attribution is well
   supported; "CPU dominant" is not established.
2. Install now exits only once node and kube-system are Ready (`mayor-csud5`,
   #2034), so the example no longer overlaps install pulls. (d) still fails
   (`mayor-kbpw7`, `v0.4.2-snapshot.2`, 2/2 runs; install PASS ~12 min).
3. Not memory on GCP: refault_file <= ~800 pages/s (A/B pre-burst <= ~1.7k/s)
   versus ~100k/s idle and ~1.2M/s under an 80-pod burst on Lima
   (`mayor-rdy7h`, `mayor-i4bvb`). Memory PSI full ~1%, MemAvailable min 278
   MiB, 0 OOM. Lima thrash numbers do not transfer to GCP.
4. MariaDB: the old liveness (initialDelay 120 s, timeout 1 s) killed init
   mid-run, and readiness `mariadb-admin ping` hid broken root auth. Probes are
   fixed in #2046 (`mayor-vnmcw`: startupProbe, `healthcheck.sh`). (d) still
   fails: the first container exits ~3 min in with `[Entrypoint]: Unable to
   start server.` (the entrypoint's own 30 s temp-server wait on the cold disk,
   CPU-throttled at the 375m limit); the restart skips init and root auth stays
   broken, now correctly never Ready.

Pending operator decision (`mayor-yfca9`): A (recommended) drop the CPU limit
(keep the request) plus small-node InnoDB init settings; B marker-gated init
recovery (initContainer wipes a datadir that never finished init; excluded
earlier); C both. Verify on GCP through the gate (example manifests come from
the checkout even with `--release`, no snapshot needed).

## Memory protection (`mayor-i4bvb`, PR #2039 DRAFT)

Option A was approved (`mayor-8bhlt`): systemd MemoryLow on u7s-apiserver,
scheduler, kcm, kubelet and crio plus kubelet systemReserved/kubeReserved with
`enforceNodeAllocatable=pods`; zram by default was not chosen (u7s configures
no swap). Lima: refaults 64.4M -> 25.7M, reads 269.6 -> 110.2 GB, MemAvailable
min 187 -> 288 MiB, but only 21/80 pods Ready in ~250 s. The GCP A/B
(both arms experiment tarballs) is INCONCLUSIVE: neither arm reached a burst
because MariaDB failed first; B showed no pre-burst memory regression. Sizing
evidence, page-cache-inflated: systemReserved ~160Mi (non-control-plane
system.slice idle 150-187 MiB), kubeReserved ~136Mi (kubelet+crio idle
115-233 MiB). Re-run A/B with bursts once (d) passes.

## Harness and rules

- GCP experiment mode (`mayor-086v6`, #2041): `burst-gate.sh --backend gcp
  --tarball` installs an unpublished x86_64 tarball built by
  `scripts/release-gate/build-experiment-tarball.sh <ref>`; verdicts are tagged
  EXPERIMENT. Use it for both A/B arms so they share a base.
- The sampler records refault/majfault/pgscan and per-cgroup memory from before
  install (#2043).
- The publish job needs operator approval on the Release environment; snapshot
  cuts are operator-only.
- Operator rules (2026-10-30): no pre-pull or sequencing in the gate (users just
  `kubectl apply`); pd-standard stays (it models the cheapest VPS); do not
  publish unmerged code.
- Gate VPSes are `u7s-rg-<MMDDHHMMSS>-<n>` (`mayor-ddhlo`); check for strays by
  that pattern; node name must stay <= 52 chars. A Google preemption mid-run
  yields no verdict.
- Burst gate: `scripts/release-gate/burst-gate.sh --confirm` (~1-2 h). On Lima,
  "quiet" means no other Lima VM, host CPU >= 70% idle, no cargo builds; a noisy
  run counts as FAIL (`6uez9`).

## Cert rotation and other checks

Control-plane kubelet runs as `system:node:<name>` with rotating certs (#1932);
uppercase-hostname install fixed (#1935, `zl285`; live checks need an uppercase
hostname); advisories bumped (#1938). Non-gating: `xdw6u.8` (two-tier CA),
`.9` (root succession; worker `ca.pem` goes stale after succession).
`pki-rotation-e2e` is ADVISORY (removed from required checks 2026-10-24,
`fhdqw`, #2013); do not re-require it without asking the operator. `d7uta`: the
pinned pkgs.k8s.io apt key expires 2026-12-29; re-check by 2026-12-08.

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
