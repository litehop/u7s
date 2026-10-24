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

**Architecture:** u7s runs on the Mac host for a fast `cargo build` → restart loop. kubelet and sonobuoy run inside the lima VM (Linux, cri-o+crun) for reproducibility. sonobuoy reaches u7s via `host.lima.internal:6443`.

## Release gate: 1 GiB burst survival

Every release must pass `scripts/release-gate/burst-gate.sh` (operator decision 2026-10-15). It boots fresh 1 vCPU / 1 GiB arm64 Lima VMs from `scripts/release-gate/u7s-vps-1g.yaml`, installs a tarball built from the current checkout with the zero-argument `install.sh`, deploys WordPress+MariaDB, then runs a 20-pod and an N-pod burst (`--burst-pods`, default 50) and `scripts/e2e-workload/webhook-smoke.sh`. The gated size is the no-swap ceiling: the largest of 50, 40 that passes 3/3 on a quiet host, found with `--confirm` before cutting a minor release (patch releases skip it). Denser workloads need swap/zram (see the README).

```sh
scripts/release-gate/burst-gate.sh                  # 3 runs, VMs deleted afterwards
scripts/release-gate/burst-gate.sh --confirm        # release confirmation: 3x at 50, else 3x at 40; prints the gated ceiling (~1-2 h, quiet host)
scripts/release-gate/burst-gate.sh --runs 1 --keep   # debug one run, keep the VM
scripts/release-gate/burst-gate.sh --mem-hog-mib 400  # forced-failure check: pins memory after install; exits 0 only if the burst is what failed
```

Exit status: 0 PASS, 1 FAIL, 3 INVALID. A run that does not pass while the host is not quiet (another Lima VM running, host CPU idle under 70% over 30 s, minus the gate VM's own vCPU share, or the in-guest CPU calibration at the pre-burst idle boundary over 1.5x the pre-install baseline of the same VM; fewer than 3 samples = unmeasured, judged on the host checks alone, so a missing probe never turns a FAIL into INVALID; a marker write failing before the bursts is a harness error, also INVALID) is INVALID: it is repeated (up to 3 times) and never counted, and `--confirm` does not drop to 40 pods on INVALID runs. A PASS under contention stays PASS. Criterion (d) also requires a marker row written to MariaDB before the bursts to survive (MariaDB is on emptyDir; a recreated pod would otherwise pass via WordPress's installer redirect).

Needs `limactl` (vz), `cargo-zigbuild` + `zig`, and a quiet host (no other VM workloads: timings are part of the verdict). A run takes about 25 minutes. PASS requires all of, in every run: (a) no OOM kill of a control-plane host process or kube-system pod, (b) node Ready throughout, (c) each burst finished within 5 minutes, (d) WordPress still answers after the burst, (e) webhook-smoke passes. Exit status is non-zero on any FAIL; per-run verdicts, samples (`MemAvailable`, per-process PSS/RSS) and kernel logs land in `temp/release-gate/<timestamp>/` (gitignored, so copy numbers you need into the PR). `scripts/release-gate/test-burst-gate-logic.sh` covers the verdict logic without a VM.

## GCP test VPSes

Real-VPC, x86_64 test hosts on GCP: Spot `e2-micro` (shared core, 1 GB) installed from the mirror (`https://u7s.dekiru.tech/<tag>/install.sh`), never from a local build. Helpers live in `scripts/gcp/`; the account, project and zone live only in a local gcloud named configuration, never in git.

**One-time config** (per machine):

```sh
gcloud config configurations create u7s-gcp --no-activate
gcloud config set account <you@example.com> --configuration u7s-gcp
gcloud config set project <project>          --configuration u7s-gcp
gcloud config set compute/zone us-west1-b    --configuration u7s-gcp
```

The scripts select it with `CLOUDSDK_ACTIVE_CONFIG_NAME` (`U7S_GCP_CONFIG` overrides the name) and exit non-zero if it is missing or has no project; they never fall back to the default configuration.

**One-time project setup**: `scripts/gcp/setup.sh --dry-run` runs only read-only gcloud calls and prints every mutating command it would run (enable the IAP API, VPC `u7s-test` in custom mode, subnet `10.80.0.0/24` in `us-west1`, firewall: tcp:22 from the IAP range `35.235.240.0/20` plus all traffic inside the subnet; no internet ingress). Review it, then run `scripts/gcp/setup.sh`; it skips what exists, so re-running is a no-op. If the org policy ever forbids external IPs, VPSes need Cloud Router + Cloud NAT and `--no-address` (not scripted).

**VPS lifecycle** (`scripts/gcp/vps.sh up NAME | ssh NAME [-- cmd] | scp SRC NAME:DST | down NAME | list | gc`). SSH/scp tunnel through IAP. VPSes are Spot, label `u7s-test=1`, termination action STOP and `--max-run-duration=16h`. Google reclaims Spot capacity on its own demand (30 s notice), not on idleness; preemption and the 16h cap STOP the VPS rather than delete it, so the disk and logs survive for post-mortem. A stopped VPS still bills its 10 GB disk (about $0.40/month); only `down`/`gc` removes it (`down` of a name that does not exist exits non-zero), so check `vps.sh list` (shows state and creation time) after a session. `gc` deletes every `u7s-test=1` instance, stopped included, so it is mayor/operator-only; workers `down` only the VPSes (name prefix) they were assigned.

**Cutting a snapshot release** (mayor/operator only; publishes a GitHub prerelease, so confirm with the operator first): `gh workflow run release-tarball.yaml -f version=v0.3.0-snapshot.N`.

**Timings are not Lima timings.** The VPS is x86_64 on a shared core (2 vCPU burst, about 25% sustained) with a network-backed `pd-standard` disk; the Lima release gate is arm64 on a dedicated vCPU. Compare a result only to other results from the same backend.

**Run a workload on a VPS** (WordPress as the example):

```sh
scripts/gcp/vps.sh up t1
scripts/gcp/vps.sh ssh t1 -- 'curl -fsSL https://u7s.dekiru.tech/<tag>/install.sh | sudo bash'
scripts/gcp/vps.sh scp --recurse <manifest-dir> t1:/tmp/wp
scripts/gcp/vps.sh ssh t1 -- sudo kubectl --kubeconfig /var/lib/u7s/kubeconfig apply -f /tmp/wp
scripts/gcp/vps.sh down t1
```

The apiserver listens on the internal IP only, so run kubectl on the VPS. MariaDB's PVC stays Pending without csi-hostpath; use `emptyDir` instead, as the gate's rewrite does (`scripts/release-gate/burst-gate.sh`, "emptyDir").

**Two-node install + join check.** `scripts/e2e-install/cloud-two-node.sh --release <tag> [--keep]` creates VPSes `cp` and `w1` under a run-unique `u7s-e2e-` prefix, installs from the mirror, joins `w1` with a token passed on stdin, and asserts both nodes Ready, a pod pinned to `w1`, `kubectl logs/exec`, cross-node pod traffic and `webhook-smoke.sh`. If the release bundles beep it also creates a client VPS and checks that a `type=LoadBalancer` Service answers from it with the client's internal IP preserved (otherwise `SKIPPED`). A preempted VPS reports `PREEMPTED` (exit 3), not `FAIL`; a failure whose preemption lookup keeps erroring is `INVALID` (exit 4). Without `--keep` it deletes only the VPSes it created. Results land in `temp/e2e-install/<timestamp>/`.

**Release-authoritative gate run.** `scripts/release-gate/burst-gate.sh --backend gcp --release <tag> [--runs N | --confirm]` runs the 1 GiB burst gate on a fresh Spot `e2-micro` per run (name `u7s-rg-<timestamp>-<n>`), installing `<tag>` from the mirror; nothing is built locally. It uses the same phases, collectors and verdict logic as the Lima gate (`scripts/release-gate/lib.sh`), and its x86_64 result is the one that gates a release; the Lima arm64 run is an advisory pre-check. Install-time signature verification only applies to releases whose `install.sh` was built after it was added; older prereleases carry the old `install.sh`. `--memory` and `--tarball-dir` are rejected (the VPS is fixed at 1 GiB and installs from the mirror). Each run's VPS is deleted at the end, also on interrupt.

Noise and preemption mapping. On Lima the host is the Mac, so the gate checks host idle CPU and other running VMs. On GCP the guest is the host, so those checks are replaced by in-guest measurements: steal time from `/proc/stat` over the idle window before the first burst (above 10% is contention; throttling during the bursts is the shared core's behaviour under the load being gated and is not judged), plus the unchanged in-guest CPU calibration. A non-pass with either is `INVALID` (repeated up to 3 times, never counted); a PASS stays a PASS. If Google reclaimed the VPS (a `compute.instances.preempted` operation exists for it), a non-pass is `PREEMPTED`: not a verdict, not FAIL, counted apart in the summary line. A VPS that is never created or never reachable over IAP ssh, or a failed run whose preemption lookup keeps erroring, is `INVALID` (infrastructure, not u7s). A VPS whose delete fails is reported as `LEAKED` (stderr and `leaked-vps.txt`). Exit status 3 covers both `INVALID` and `PREEMPTED`; 1 is a valid FAIL; 4 is a PASS verdict with a leaked VPS (a FAIL or INVALID keeps its own code). Results land in `temp/release-gate/<timestamp>/` (`backend.txt` records `release-authoritative=yes`).
