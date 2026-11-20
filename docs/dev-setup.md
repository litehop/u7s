# Dev Setup

## Rust toolchain

The Rust toolchain is pinned by `rust-toolchain.toml` at the repo root; rustup installs it on the first `cargo` run and CI uses the same file.

## kubectl

kubectl is pinned per-project via [aqua](https://aquaproj.github.io/) to avoid touching your system install.

Install aqua following the [official instructions](https://aquaproj.github.io/docs/install), then from the repo root:

```sh
aqua install
aqua exec -- kubectl version --client
```

To use `kubectl` directly without `aqua exec --`, add the aqua shim dir to your PATH in your shell profile:

```sh
export PATH="$(aqua root-dir)/bin:$PATH"
```

The pinned version is in `aqua.yaml` at the repo root. Update it there to change the project-wide kubectl version.

## Local kubelet testing (Mac)

To test a real kubelet join against u7s on your Mac, use [lima](https://lima-vm.io/):

```sh
brew install lima
```

Start u7s manually (note the kubeconfig path it prints), then:

```sh
export KUBECONFIG=/path/u7s/printed/kubeconfig
scripts/conformance/lima-start.sh
```

The script starts an Ubuntu 24.04 VM with cri-o + crun + kubelet, copies the kubeconfig into the VM (rewriting the address to `host.lima.internal`), starts kubelet, and polls until `lima-node` appears in `kubectl get nodes`.

The VM definition is at [lima/kubelet.yaml](../lima/kubelet.yaml). The kubelet will show `NotReady` (no CNI) but it will register — that is the acceptance bar for this smoke test.

## Local sonobuoy conformance testing

To run the Kubernetes conformance suite against u7s locally:

1. Start u7s and export the kubeconfig it prints:
   ```sh
   export KUBECONFIG=/path/u7s/printed/kubeconfig
   ```

2. Start the lima VM with kubelet registered (if not already running):
   ```sh
   scripts/conformance/lima-start.sh
   ```

3. Run sonobuoy (installed inside the VM):
   ```sh
   scripts/conformance/06-run-sonobuoy.sh
   ```
   This runs `--mode=non-disruptive-conformance` — the single-node conformance subset, approximately 5–15 minutes.
   Exit code: `0` clean, `10` specs failed (results were retrieved), anything else is an infrastructure failure.
   `U7S_SUITE_TIMEOUT_S` overrides the ginkgo suite cap (default 5400s for a full or storage-focused run, 3600s otherwise); sonobuoy's `--timeout` is the cap + 600s. Must be a positive integer; anything else exits 1 before any VM work starts.

4. To iterate on a specific failure area, use `--focus` to run only matching tests:
   ```sh
   scripts/conformance/06-run-sonobuoy.sh --focus "ConfigMap"
   ```

### Rig-only add-ons and host setup

The conformance rig applies host setup that u7s does not ship, in both the host rig and `run-all.sh --install`
(after `install.sh` runs). It is recorded in the run archive's `run-meta` as `rig_only_host_setup=apparmor-dig-nslookup`.

On hosts whose kernel stacks AppArmor profiles (Ubuntu 26.04, kernel 7.0.0-43 and later) the host `dig` and
`nslookup` profiles deny BIND's self-signal inside containers, so `dig` aborts and `nslookup` exits 139.
The rig adds `signal (send,receive) peer=@{profile_name}//&u7s-default,` to `/etc/apparmor.d/local/dig` and
`/etc/apparmor.d/local/nslookup` and reloads both profiles. On your own host, apply the same host-side change if
you need `dig` or `nslookup` in pods. The specs that depend on it are `should provide DNS for the cluster`, `should
provide DNS for services`, `should provide DNS for pods for Subdomain`, `should resolve DNS of partial qualified
names for the cluster`, and the three ExternalName specs (`should provide DNS for ExternalName services`,
`should be able to change the type from ClusterIP to ExternalName`, `... from NodePort to ExternalName`).

The rig also applies three upstream add-ons that u7s does not ship:

- `kube-network-policies`
- `metrics-server`
- `external-snapshotter`

The rig labels each add-on with this label:

```text
u7s.io/conformance-rig-only=true
```

Specs that depend on the add-ons pass only when the add-ons are present.

`install.sh` installs no add-on. `manifests/` doesn't carry them. If you need NetworkPolicy enforcement, resource metrics (`metrics.k8s.io`, HPA) or volume snapshots, install the upstream components yourself.

The `ClusterTrustBundle`, `ClusterTrustBundleProjection` and `PodCertificateRequest` kubelet gates are GA and on by default in Kubernetes 1.37, so u7s installs have them too.

Dependent spec groups, from the upstream `release-1.37` e2e sources:

| Dependency | Spec group | Basis |
| --- | --- | --- |
| kube-network-policies | `[sig-network] Netpol` | `test/e2e/network/netpol/network_policy.go` tests traffic reachability; `Netpol API` is not verified |
| metrics-server | `[sig-autoscaling]` `[Feature:HPA]` "Horizontal pod autoscaling (scale resource: CPU)" and "(scale resource: Memory)" | Spec names from `test/e2e/autoscaling/horizontal_pod_autoscaling.go`; the metrics-server link comes from the `run-all.sh:571-580` comments, not the spec source |
| external-snapshotter | `[sig-storage]` `[Feature:VolumeSnapshotDataSource]` snapshottable suite | Spec names from `test/e2e/storage/testsuites/snapshottable.go`; the external-snapshotter link comes from the `run-all.sh:582-592` comments, not the spec source |

**Architecture:** u7s runs on the Mac host for a fast `cargo build` → restart loop. kubelet and sonobuoy run inside the lima VM (Linux, cri-o+crun) for reproducibility. sonobuoy reaches u7s via `host.lima.internal:6443`.

## Release gate: 1 GiB burst survival

### Release-gate exit codes

`burst-gate.sh` and `scripts/e2e-install/cloud-two-node.sh` share one table:

| Code | Meaning |
|------|---------|
| 0 | PASS |
| 1 | FAIL: a valid run failed (u7s is broken) |
| 2 | usage error |
| 3 | INVALID or PREEMPTED: infrastructure or contention, not a verdict |
| 4 | PASS, but a VPS could not be deleted (`leaked-vps.txt`) and may still be billing; a FAIL or INVALID keeps its own code |

With `burst-gate.sh --confirm`, leaks from every size's sub-gate are aggregated into the top-level `leaked-vps.txt`.

Every release must pass `scripts/release-gate/burst-gate.sh` (operator decision 2026-10-15). It boots fresh 1 vCPU / 1 GiB arm64 Lima VMs from `scripts/release-gate/u7s-vps-1g.yaml`, installs a tarball built from the current checkout with the zero-argument `install.sh`, deploys WordPress+MariaDB, then runs a 20-pod warm-up burst and an N-pod burst (`--burst-pods`, default 20) and `scripts/e2e-workload/webhook-smoke.sh`. The gated size is ~20-pod bursts on a 1 GiB / 1 vCPU node (operator decision 2026-11-05): 3/3 runs at 20 pods on a quiet host, confirmed with `--confirm` before cutting a minor release (patch releases skip it). Denser workloads need swap/zram (see [docs/install.md](install.md#running-on-a-1-gib-host)).

```sh
scripts/release-gate/burst-gate.sh                  # 3 runs, VMs deleted afterwards
scripts/release-gate/burst-gate.sh --confirm        # release confirmation: 3x at 20 pods (~1 h, quiet host)
scripts/release-gate/burst-gate.sh --runs 1 --keep   # debug one run, keep the VM
scripts/release-gate/burst-gate.sh --overload-pods 40 --overload-mib 20  # killable BestEffort memory overload; reports recovery time, exits 0 only if the node recovered
```

Exit status: 0 PASS, 1 FAIL, 3 INVALID. A run during which the host is not quiet (another Lima VM running, host CPU idle under 70% over 30 s, minus the gate VM's own vCPU share, judged only before the gate's own bursts start because the thrashing guest's hypervisor disk reads cost host cores, or the in-guest CPU calibration at the pre-burst idle boundary over 1.5x the pre-install baseline of the same VM; fewer than 3 samples = unmeasured, judged on the host checks alone; a marker write failing before the bursts is a harness error, also INVALID) is INVALID: it is repeated (up to 3 times) and never counted, and `--confirm` reports INVALID rather than FAIL when noise leaves too few valid runs. Contention judgment is outcome-independent: a contended PASS is INVALID too (reasons in `contention.txt`). A/B runs use the in-VM sampler only; off-VM `limactl shell` observers cost ~79 MiB on 1 GiB. Criterion (d) also requires a marker row written to MariaDB before the bursts to survive (MariaDB is on emptyDir; a recreated pod would otherwise pass via WordPress's installer redirect).

Needs `limactl` (vz), `cargo-zigbuild` + `zig`, and a quiet host (no other VM workloads: timings are part of the verdict). A run takes about 25 minutes. PASS requires all of, in every run: (a) no OOM kill of a control-plane host process or kube-system pod, (b) node Ready throughout, (c) each burst finished within 5 minutes, (d) WordPress still answers after the burst, (e) webhook-smoke passes. Exit status is non-zero on any FAIL; per-run verdicts, samples (`MemAvailable`, per-process PSS/RSS) and kernel logs land in `temp/release-gate/<timestamp>/` (gitignored, so copy numbers you need into the PR). `scripts/release-gate/test-burst-gate-logic.sh` covers the verdict logic without a VM.

### Upgrade check

`scripts/release-gate/upgrade-gate.sh` checks that re-running the
candidate's `install.sh` with no flags ([upgrading.md](upgrading.md)) over
the previous release keeps the cluster intact. The supported path is the
immediately previous release only. Per run it boots a fresh gate-shaped VM
(1 vCPU, 1 GiB), installs the previous release, deploys a ConfigMap marker,
a 2-replica Deployment and a DaemonSet, polls `/readyz` every 2 s, upgrades,
and upgrades once more for idempotence. It prints a verdict table: install
exit 0, server version changed to the candidate's, CA and `sa.pub`
preserved, marker readable, Deployment and DaemonSet pods keep UIDs with no
new restarts, API outage at most 60 s (the measured gap is always
reported), and the re-run exit 0 with nothing recreated or restarted.
Flannel's DaemonSet pod is recreated on upgrade and not asserted. It is not
a performance measurement: the burst gate's quiet-host INVALID logic does
not apply.

```sh
scripts/release-gate/upgrade-gate.sh                       # lima: v<latest release> built from its tag -> this checkout
scripts/release-gate/upgrade-gate.sh --from v0.4.6         # lima, explicit previous release
scripts/release-gate/upgrade-gate.sh --backend gcp --from v0.4.6 --release v0.4.7-snapshot.1
```

Lima VMs are arm64 and releases are x86_64, so the previous release is built
from a scratch worktree of its tag at `./temp/prev-src` and the candidate
from this checkout, both with `build-arm64-tarball.sh` (needs `cosign`; see
the burst gate's requirements) and stamped so their versions differ; add
`--prev-dir`/`--cand-dir` to reuse finished builds. The unsigned local
tarballs are installed with `--tarball`, the one deviation from a flagless
re-run. On GCP both releases are
installed from the mirror on the `n1-custom-1-1024` / `pd-balanced` gate
shape. VMs are named `u7s-upg-*`. Exit codes are the release-gate table
above; INVALID also covers a previous release that fails to install on its
own. Results land in `temp/upgrade-gate/<timestamp>/` (`verdict.txt`,
`out/` with `readyz.log` and the pod snapshots). The check logic is tested
by `scripts/release-gate/test-upgrade-gate-logic.sh`.

## GCP test VPSes

Real-VPC, x86_64 test hosts on GCP: Spot hosts installed from the mirror (`https://u7s.dekiru.tech/<tag>/install.sh`), never from a local build. `vps.sh up` defaults to `e2-micro` (0.25 sustained vCPU) and `--machine-type` picks another. The release gate uses the custom `n1-custom-1-1024` (1 dedicated vCPU, 1 GiB; kubelet allocatable cpu=1; a dedicated core is more generous than a typical shared 1-vCPU VPS, so a gate PASS is slightly optimistic for shared hosts), set once as `GCP_GATE_MACHINE_TYPE` in `scripts/gcp/lib.sh` and forced over an ambient `U7S_GCP_MACHINE_TYPE`. Helpers live in `scripts/gcp/`; the account, project and zone live only in a local gcloud named configuration, never in git.

**One-time config** (per machine):

```sh
gcloud config configurations create u7s-gcp --no-activate
gcloud config set account <you@example.com> --configuration u7s-gcp
gcloud config set project <project>          --configuration u7s-gcp
gcloud config set compute/zone us-west1-b    --configuration u7s-gcp
```

The scripts select it with `CLOUDSDK_ACTIVE_CONFIG_NAME` (`U7S_GCP_CONFIG` overrides the name) and exit non-zero if it is missing or has no project; they never fall back to the default configuration.

**One-time project setup**: `scripts/gcp/setup.sh --dry-run` runs only read-only gcloud calls and prints every mutating command it would run (enable the IAP API, VPC `u7s-test` in custom mode, dual-stack subnets `u7s-test` (`10.80.0.0/24`) and `u7s-test-b` (`10.82.0.0/24`) in `us-west1` with VPC flow logs (5-min aggregation, 0.5 sampling), firewall: tcp:22 from the IAP range `35.235.240.0/20` plus all traffic between the two subnets over IPv4 and, via their external /64s, IPv6; no internet ingress; the separate `u7s-probe` VPC with its own dual-stack subnet and IAP-only SSH, for the outside-VPC probe VM). The subnets use external IPv6, an access type that can never change afterwards. Review it, then run `scripts/gcp/setup.sh`; re-running is a no-op. If the org policy ever forbids external IPs, VPSes need Cloud Router + Cloud NAT and `--no-address` (not scripted).

**VPS lifecycle** (`scripts/gcp/vps.sh up [--stack-type IPV4_ONLY|IPV4_IPV6] [--network u7s-test|u7s-probe] [--subnet u7s-test|u7s-test-b] NAME | ssh NAME [-- cmd] | scp SRC NAME:DST | down NAME | list | gc`). SSH/scp tunnel through IAP. VPSes are Spot, label `u7s-test=1`, termination action STOP and `--max-run-duration=16h`. The 10 GB boot disk is `pd-balanced` (SSD-class) by default; `U7S_GCP_BOOT_DISK_TYPE` overrides it in the harnesses that honour it (`pd-standard` is HDD-class and reproduces the disk-IO wedge); the release gate ignores the env var and takes `--boot-disk-type`. Google reclaims Spot capacity on its own demand (30 s notice); preemption and the 16h cap STOP the VPS rather than delete it, so the disk and logs survive for post-mortem. A stopped VPS still bills its 10 GB disk (about $1/month for pd-balanced, unverified); only `down`/`gc` removes it (`down` of a missing name exits non-zero), so check `vps.sh list` (state and creation time) after a session. The default stack is `IPV4_ONLY`; `IPV4_IPV6` adds an external IPv6 address. `gc` deletes every `u7s-test=1` instance, stopped and probes included, plus leftover `u7s-e2e-*-lb-v4/v6` firewall rules, so it is mayor/operator-only and never run during a live harness run; workers `down` only the VPSes (name prefix) they were assigned.

**Cutting a snapshot release** (mayor/operator only; publishes a GitHub prerelease, so confirm with the operator first): `gh workflow run release-tarball.yaml -f version=v0.3.0-snapshot.N`. Full procedure: [releasing.md](releasing.md).

**Timings are not Lima timings.** The VPS is x86_64 on a shared core (2 vCPU burst, about 25% sustained) with a network-backed `pd-balanced` disk; the Lima release gate is arm64 on a dedicated vCPU. Compare a result only to other results from the same backend.

**Run a workload on a VPS** (WordPress as the example):

```sh
scripts/gcp/vps.sh up t1
scripts/gcp/vps.sh ssh t1 -- 'curl -fsSL https://u7s.dekiru.tech/<tag>/install.sh | sudo bash'
scripts/gcp/vps.sh scp --recurse <manifest-dir> t1:/tmp/wp
scripts/gcp/vps.sh ssh t1 -- sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig apply -f /tmp/wp
scripts/gcp/vps.sh down t1
```

The apiserver listens on the node's own interface addresses, and the firewall admits no internet ingress to 6443, so run kubectl on the VPS. MariaDB's PVC stays Pending without csi-hostpath; use `emptyDir` instead, as the gate's rewrite does (`scripts/release-gate/burst-gate.sh`, "emptyDir").

**Two-node install + join check.** `scripts/e2e-install/cloud-two-node.sh --release <tag> [--keep] [--dual-stack] [--machine-type <type>] [--w1-subnet <subnet>] [--external-traffic-policy <policies>] [--beep-evidence <collector>] [--skip-sonobuoy]` creates VPSes `cp` and `w1` under a run-unique `u7s-e2e-` prefix, installs from the mirror, joins `w1` with a token passed on stdin, and asserts both nodes Ready, a pod pinned to `w1`, `kubectl logs/exec`, cross-node pod traffic and `webhook-smoke.sh`. If the release bundles beep it also creates a client VPS and checks that a `type=LoadBalancer` Service answers from it with the client's internal IP preserved (otherwise `SKIPPED`). `--dual-stack` uses `IPV4_IPV6` VPSes and dual cluster/service CIDRs, asserts both families end to end (needs a release bundling beep), curls the LB over v4 and v6 from a probe VM in `u7s-probe` (refused before the narrow per-family LB firewall rules, admitted after), and finishes with the upstream IPv6DualStack sonobuoy focus. `--machine-type` sets the VPS type: `e2-micro` by default, `e2-standard-2` with `--dual-stack` (sonobuoy saturates e2-micro). `--w1-subnet u7s-test-b` puts `w1` on the second subnet; `--external-traffic-policy Cluster,Local` repeats the LB checks under each policy; `--beep-evidence` takes beep's `scripts/real-cloud-evidence.sh` and adds beep's real-cloud (B) evidence, the MTU transfer and the `--pod-cidr` negative control (flags in the script header). A preempted VPS reports `PREEMPTED` (exit 3), not `FAIL`; a failure whose preemption lookup keeps erroring is `INVALID` (exit 3); a PASS whose VPS could not be deleted exits 4 (see "Release-gate exit codes"). Without `--keep` it deletes only the VPSes it created. Results land in `temp/e2e-install/<timestamp>/`.

**Release-authoritative gate run.** `scripts/release-gate/burst-gate.sh --backend gcp --release <tag> [--runs N | --confirm]` runs the 1 GiB burst gate on a fresh Spot `n1-custom-1-1024` per run (name `u7s-rg-<timestamp>-<n>`), installing `<tag>` from the mirror; nothing is built locally. Signature verification applies only to releases whose `install.sh` includes it; older prereleases do not verify. It uses the same phases, collectors and verdict logic as the Lima gate (`scripts/release-gate/lib.sh`), and its x86_64 result is the one that gates a release; the Lima arm64 run is an advisory pre-check. `--memory` and `--tarball-dir` are rejected (the VPS is fixed at 1 GiB and installs from the mirror). The gate VM boot disk is `pd-balanced` (SSD-class; on v0.4.5-snapshot.1 at 20 pods it passed 3/3, while `pd-standard` failed 0/3 with disk-IO wedges); `--boot-disk-type TYPE` overrides it (gcp only) and the type is recorded in `backend.txt` and the GATE line. Each run's VPS is deleted at the end, also on interrupt.

**Experiment mode (unpublished code, never a release verdict).** To A/B an unmerged branch on the same shape without publishing anything, build a tarball locally and pass it with `--tarball`: `scripts/release-gate/build-experiment-tarball.sh <ref>` cross-builds `u7s-apiserver`/`u7s-scheduler` with `cargo zigbuild` (x86_64, glibc 2.35), bundles the same upstream binaries, licenses and `manifests/*.yaml` as `scripts/build-release-tarball.sh` (upstream binaries are sha256-checked only, no cosign), and writes the tarball, that ref's `install.sh` and a `.source` file (ref + full sha) side by side. Then `burst-gate.sh --backend gcp --tarball <tarball> [--install-only] [--runs N]` uploads them and runs `install.sh --tarball <path>`. `--tarball` is exclusive with `--release` and refused with `--confirm`; the output dir, run dirs, verdict files, summaries, `backend.txt` and the final GATE line all say `EXPERIMENT` plus the ref/sha, and `release-authoritative=no`. `--install-only` stops after install + node Ready.

Noise and preemption mapping. On Lima the host is the Mac, so the gate checks host idle CPU and other running VMs. On GCP the guest is the host, so those checks are replaced by in-guest measurements: steal time from `/proc/stat` over the idle window before the first burst (above 10% is contention; throttling during the bursts is the shared core's behaviour under the load being gated and is not judged), plus the unchanged in-guest CPU calibration. Either is `INVALID` (repeated up to 3 times, never counted), whatever the verdict. If Google reclaimed the VPS (a `compute.instances.preempted` operation exists for it), a non-pass is `PREEMPTED`: not a verdict, not FAIL, counted apart in the summary line. A VPS that is never created or never reachable over IAP ssh, or a failed run whose preemption lookup keeps erroring, is `INVALID` (infrastructure, not u7s). A VPS whose delete fails is reported as `LEAKED` (stderr and `leaked-vps.txt`). Exit status 3 covers both `INVALID` and `PREEMPTED`; 1 is a valid FAIL; 4 is a PASS verdict with a leaked VPS (a FAIL or INVALID keeps its own code). Results land in `temp/release-gate/<timestamp>/` (`backend.txt` records `release-authoritative=yes`).
