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
scripts/lima-start.sh
```

The script starts an Ubuntu 24.04 VM with containerd + kubelet 1.31, copies the kubeconfig into the VM (rewriting the address to `host.lima.internal`), starts kubelet, and polls until `lima-node` appears in `kubectl get nodes`.

The VM definition is at [lima/kubelet.yaml](../lima/kubelet.yaml). The kubelet will show `NotReady` (no CNI) but it will register — that is the acceptance bar for this smoke test.
