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

4. To iterate on a specific failure area, use `--focus` to run only matching tests:
   ```sh
   scripts/conformance/06-run-sonobuoy.sh --focus "ConfigMap"
   ```

**Architecture:** u7s runs on the Mac host for a fast `cargo build` → restart loop. kubelet and sonobuoy run inside the lima VM (Linux, cri-o+crun) for reproducibility. sonobuoy reaches u7s via `host.lima.internal:6443`.

## Comment-only-diff fast path (difftastic)

`.githooks/pre-push`'s sensitive-conformance gate uses [difftastic](https://difftastic.wilfred.me.uk/) (`difft`) to skip the sonobuoy requirement when a push to a sensitive file is a pure comment/whitespace edit. It's a dev-environment tool only — not an install.sh/production dependency:

```sh
brew install difftastic
```

Without it, the gate falls back to the full check (never silently skips) — see `scripts/sensitive-conformance-gate.sh`.
