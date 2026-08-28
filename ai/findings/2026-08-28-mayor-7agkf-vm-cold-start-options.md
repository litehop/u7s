Bead: mayor-7agkf

# VM cold-start options for `--reset` provisioning

## Recommendation

Provision one stopped "golden" Lima instance per node role once, and on
`--reset` do `limactl delete <target>` + `limactl clone <golden> <target>
--start` (APFS copy-on-write, confirmed in Lima's own source and its
original design issue) instead of `limactl start <template.yaml>`. This is
the only enumerated option that (a) works with our current `vmType: vz`
with no hypervisor swap, (b) needs no new image-hosting pipeline — the
golden instance IS the template, provisioned once via the existing
`lima/kubelet.yaml` path — and (c) leaves `--extra-node` untouched, since
`add-node.sh`/`lima-start.sh` only require the named VM to exist and be
Running, indifferent to how it got there.

## Measured baseline (Phase 1)

Two-node `--reset --stack-only` cycle, `lima-node-5` (primary) +
`lima-node-smoke` (extra node), timestamps from `run-all.sh`'s own log and
Lima's hostagent log (JST, UTC+9):

| Step | Span | Wall-clock |
|---|---|---|
| Reset (teardown, nothing existed) | 19:02:00–19:02:06 | ~6s |
| Step 1: Build (`cargo build --release`, cold `target/`) | 19:02:06–19:06:28 | 4m22s |
| Step 2: Start apiserver + metrics-server | 19:06:28–19:06:35 | ~7s |
| **Step 3: Start lima VM (primary)** | 19:06:35–~19:11:12 | **~4m37s** |
| — of which `limactl start`→READY (boot+cloud-init+apt+25 image pulls+sonobuoy) | 19:06:35–19:10:49 | 4m14s |
| — of which lima-start.sh's own tail (CNI/certs/kubeconfig/kube-proxy/node-wait) | ~19:10:49–~19:11:12 | ~23s |
| Step 4: Start KCM (cached binary) | instant | ~0s |
| Step 5: Start scheduler (separate incremental build + start) | ~19:11:12–19:11:46 | 32s |
| **Extra node: join lima-node-smoke** | 19:11:46–~19:16:19 | **~4m33s** |
| — of which `limactl start`→READY | 19:11:46–19:15:33 | 3m47s |
| — of which lima-start.sh's tail + inter-node route programming | ~19:15:33–19:16:19 | ~46s |
| Final (DaemonSet-ready wait, sampler, done) | ~19:16:19 | few s |
| **Total** | 19:02:06–19:16:19 | **14m13s** |

VM provisioning (Step 3 + extra-node join) = **9m10s of 14m13s (~64%)**, vs.
build ~4m54s (~34%). This is a *single clean-build* measurement — on any
subsequent `--reset` with a warm `target/`, Step 1 drops to seconds while
provisioning stays fixed at ~9min, making it dominate even harder.
Corrections to the bead's stated premises: `lima/kubelet.yaml`'s base image
is already Ubuntu **26.04** (systemd 259, confirmed live via `systemctl
--version` inside `lima-node-5`), not 24.04 — the vsock-fallback fix (bd
memory `all-lima-vms-share-vsock-fallback-limitation`) has already shipped;
this run's hostagent log shows a real vsock SSH forwarder for both nodes,
not the usernet fallback.

## Options enumerated

1. **`limactl snapshot` (QEMU-only).** Source-verified at the installed
   version (`limactl 2.1.1`): `LimaVzDriver.CreateSnapshot/ApplySnapshot/
   DeleteSnapshot/ListSnapshots` all `return errUnimplemented`; only the
   QEMU driver implements it. Empirically reproduced live: `limactl
   snapshot create lima-node-5 --tag t1` → `level=fatal msg=unimplemented`.
   Would require switching `vmType: vz` → `qemu` fleet-wide to unlock —
   not evaluated further here (see "does NOT work").
2. **Pre-baked custom cloud image** (cri-o/kubelet/crictl/sonobuoy +
   pre-pulled images baked into the OS image referenced by `images:`).
   Works with vz. Cost: needs a build+hosting pipeline (packer or similar)
   external to this repo, plus a staleness/refresh story whenever
   `lima/kubelet.yaml`'s provision script changes.
3. **`limactl clone` of a golden instance (recommended).** `pkg/instance/
   clone.go` copies the instance directory via `continuity/fs.CopyFile`,
   which "attempts copy-on-write when supported by the filesystem" — the
   maintainer's own design issue (#3658) names APFS `clonefile(2)`
   explicitly. Not marked experimental (unlike `snapshot`). Measured disk
   cost of one fully-provisioned instance: 5.8GB (`du -sh
   ~/.lima/lima-node-2/disk`); a CoW clone costs ~0 extra until blocks
   diverge. Requires the source stopped (fine — golden sits idle, 0
   CPU/RAM between clones). Real cost: cloning copies the golden's
   `networks:`/pod-subnet too, so per-target-slot `--set` yq patches are
   needed at clone time (small, well-scoped implementation work); golden
   needs a freshness gate against `lima/kubelet.yaml` changes.
4. **Warm VM pool** (N spare already-Running, already-joined VMs swapped
   in). Fastest in theory (~0s), but conflicts with `--reset`'s actual
   job — a known-clean state — unless paired with a separate app-level-only
   reset, and adds pool allocation/lifecycle complexity. Not worth it once
   option 3 already gets provisioning to seconds.

## What does NOT work, and why

- **`limactl snapshot` on our current stack**: hard-disqualified by shipped
  code, not a maybe — `errUnimplemented` for vz, confirmed both by reading
  `v2.1.1` source and by reproducing the exact failure live against
  `lima-node-5`.
- **Waiting for vz snapshot/auto-save-restore to land upstream**:
  `lima-vm/lima` PR #2900 ("vz: implement auto save/restore") has been
  open and unmerged since Nov 2024 (last activity Jul 2025) — do not plan
  around it shipping.
- **Switching `vmType: vz` → `qemu` to unlock snapshot**: architecturally
  plausible, but this is exactly the failure pattern in bd memory
  `architectural-reasoning-is-not-verification` (two prior network-driver
  recommendations were disqualified only once measured). Any such
  recommendation needs its own gated boot+provision+conformance A/B before
  it can be shipped — out of scope for this audit, not bundled into the
  recommendation above.
- **Base-image download caching as "the fix"**: already solved and not the
  bottleneck. Lima already caches the Ubuntu image by URL hash
  (`~/Library/Caches/lima/download/by-url-sha256/`, confirmed live); the
  measured ~4m/node is 100% the `provision:` script (apt-get + 25 `crictl
  pull`s + sonobuoy download), which reruns unconditionally on every
  `--reset` regardless of image-download caching.

## Follow-on beads to propose (mayor to file)

1. Spike: golden `lima-node-*` template + wire `--reset` to `limactl
   clone --start`; measure real clone-vs-fresh wall-clock and verify a
   cloned instance boots/joins/routes correctly before shipping.
2. Add a staleness gate for the golden template (hash the provision script
   into the golden instance; mismatch → fresh-provision + re-bake).
3. Re-check mayor-hm02b's P4 priority once a real `--reset` wall-clock
   number ships from #1.
4. (Lower priority, only if #1 proves insufficient) A dedicated, gated
   vz-vs-qemu boot+provision+conformance A/B for snapshot support.
