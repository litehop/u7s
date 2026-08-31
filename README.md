# u7s

u7s is a Kubernetes-compatible control plane, implemented from scratch in
Rust, for resource-constrained environments where a 1 vCPU / 1 GiB RAM VPS
is normal. It exposes a kubectl-compatible API surface: `kubectl` and other
standard Kubernetes clients talk to u7s the same way they talk to upstream
Kubernetes.

u7s is pre-alpha. There is no stable release, the API surface is bounded to
what the project's current milestones need, and behavior changes without
notice. Do not run production workloads against it yet.

## Quick start

The install script bootstraps a single-node cluster on a fresh Ubuntu LTS
host: it installs CRI-O, stages the u7s binaries and the vendored kubelet
and kube-controller-manager, and writes a systemd unit for each.

1. Run the install script as root on the target host:

   ```bash
   curl -sfL https://u7s.dekiru.tech/install.sh | sudo bash
   ```

2. With no flags, the node name defaults to the host's hostname and the
   cluster network binds to the first non-loopback interface. Override
   either with `--node-name` or `--iface` (see `scripts/install.sh --help`
   for the full flag list, including `--manifest-output-dir` for GitOps
   setups).
3. Connect with `kubectl` using the kubeconfig the script writes, at
   `/var/lib/u7s/kubeconfig` by default:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig get nodes
   ```

u7s does not ship metrics-server. The `scale` subresource is implemented, so
`HorizontalPodAutoscaler` works once you install metrics-server yourself —
apply upstream's release manifest:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

## Architecture

u7s implements the Kubernetes REST API surface natively rather than
wrapping or proxying `kube-apiserver`, and reuses unmodified upstream
components (kubelet, kube-controller-manager) for now. Measurements show
these two are the largest memory consumers in the stack; an upstream
config-tuning audit is next, and a native rewrite of either remains an open
question. See `docs/decisions/` for the reasoning behind these and other
component choices, one Architecture Decision Record per decision.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how work is tracked and how to
open a pull request.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## License

u7s is licensed under the [Apache License 2.0](LICENSE).
