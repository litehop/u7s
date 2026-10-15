# Dev Setup

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

Every release must pass `scripts/release-gate/burst-gate.sh` (operator decision 2026-10-15). It boots fresh 1 vCPU / 1 GiB arm64 Lima VMs from `scripts/release-gate/u7s-vps-1g.yaml`, installs a tarball built from the current checkout with the zero-argument `install.sh`, deploys WordPress+MariaDB, then runs a 20-pod and an 80-pod burst and `scripts/e2e-workload/webhook-smoke.sh`.

```sh
scripts/release-gate/burst-gate.sh                  # 3 runs, VMs deleted afterwards
scripts/release-gate/burst-gate.sh --runs 1 --keep   # debug one run, keep the VM
scripts/release-gate/burst-gate.sh --memory 0.625    # forced-failure check
```

Needs `limactl` (vz), `cargo-zigbuild` + `zig`, and a quiet host (no other VM workloads: timings are part of the verdict). A run takes about 25 minutes. PASS requires all of, in every run: (a) no OOM kill of a control-plane host process or kube-system pod, (b) node Ready throughout, (c) each burst finished within 5 minutes, (d) WordPress still answers after the burst, (e) webhook-smoke passes. Exit status is non-zero on any FAIL; per-run verdicts, samples (`MemAvailable`, per-process PSS/RSS) and kernel logs land in `temp/release-gate/<timestamp>/` (gitignored, so copy numbers you need into the PR). `scripts/release-gate/test-burst-gate-logic.sh` covers the verdict logic without a VM.
