---
as_of: 2026-10-20
kind: initiative-state
---

# Cert rotation and the release gate: state as of 2026-10-20

No release until the cert-rotation story is done properly: `mayor-zboqh` is
the one gating item left. The 1 GiB burst gate has not yet produced a
confirmed ceiling; re-run `--confirm` in a quiet window.

## Release-gating scope (operator 2026-10-20)

Certs have finite lifetimes on main since #1909, so the next snapshot or
release waits for renewal to be complete end to end. Gating set:

| Bead | What | State |
|---|---|---|
| `mayor-xdw6u.3` | apiserver hot-swaps serving TLS + client-CA store; leaves rotate at 2/3 lifetime | merged #1913 |
| `mayor-xdw6u.4` | file-path kubeconfigs; KCM/kubelet live-reload via client-go | merged #1917 |
| `mayor-xdw6u.5` | scheduler on politeia v0.3.0, one shared reloading client | merged #1926 |
| `mayor-xdw6u.11` | rotation e2e on real binaries (`pki-rotation-e2e` CI job + `leaf-rotation.sh --vm`) | merged #1918; bead open for .8/.9 scenarios |
| `mayor-xdw6u.2` | expiry visibility: Warning headers (admins/kubectl only), Node Events, `apiserver_client_certificate_expiration_seconds` + `u7s_certificate_*` | merged #1925 |
| `mayor-zboqh` | control-plane kubelet gets its own `system:node` identity instead of admin | **open** |

`mayor-xdw6u.8` (two-tier CA) and `.9` (root succession) are P3,
non-gating nice-to-haves. `pki-rotation-e2e` becomes a required check
after 10 consecutive green runs (`mayor-bjuu2`, operator action).

## Release gate (1 GiB / 1 vCPU, no swap)

- Spec is option A (`mayor-f2gfd`): gate on the largest no-swap burst that
  passes 3/3 on a quiet host, 50 else 40. Run
  `scripts/release-gate/burst-gate.sh --confirm` (~1–2 h).
- The 2026-10-20 `--confirm` FAILED on criterion (b) only, and the cause
  was not the node: `kubectl get node -w` sends `watch?resourceVersion=0`,
  and u7s replayed write history instead of current state, so the sampler
  saw stale Unknown/False. Fixed in #1924 (`mayor-03hfx`). With the fix,
  `--runs 3` passed (b) 3/3 at 50 pods on a busy host. Capacity itself
  held: bursts 15–32 s, MemAvailable ≥ 120 MiB, peak PSS apiserver 29–31,
  KCM 76–95, kubelet 78–83, CRI-O 72–78 MiB.
- No INVALID verdict yet (`mayor-6uez9`): a noisy run counts as FAIL.

## Quiet-window protocol

"Quiet" means no other Lima VM running and host CPU ≥ 70% idle, which
includes no cargo builds from other workers (every `cargo test`/clippy and
the pre-push hook peg the host). Pattern that worked: put the dashboard on
a dispatch hold, let VM workers drain, then ONE worker runs the gate and
any measurement back to back. Defer the hygiene script during the window:
deleting a remote branch triggers the pre-push hook's full cargo run.

`mayor-w898x` (KCM/kubelet Go memory, feeds the Rust-rewrite go/no-go
`mayor-vc844`) is unblocked: KCM `/metrics` honours RBAC since #1923;
scrape with `kubectl create token monitoring -n kube-system`. It needs the
next quiet window.

## Working rules learned this session

- Match upstream behaviour unless incompatible with a deliberate u7s
  choice; don't ask the operator to pick on taste (bd memory
  `upstream-parity-default-unless-incompatible`).
- Core-semantics PRs (watch, admission, PodSecurity) stay draft until a
  full two-node Conformance run on the branch is green; the tick merges
  any LGTM'd PR.
- Command shape: a chained or redirected Bash command can be denied even
  when each part is allowed; retry as bare single commands first (bd
  memory `worker-classifier-denial-stop-not-reshape`).
- A session that ends without its bookkeeping PR strands bead state in
  the local DB; check `git log -1 origin/main -- .beads/issues.jsonl` at
  bootstrap (bd memory
  `verify-carried-over-dashboard-decisions-and-bead-export-lag`).
