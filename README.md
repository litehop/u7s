# u7s

u7s is a Kubernetes-compatible control plane, implemented from scratch in
Rust, for resource-constrained environments where a 1 vCPU / 1 GiB RAM VPS
is normal. It exposes a kubectl-compatible API surface: `kubectl` and other
standard Kubernetes clients talk to u7s the same way they talk to upstream
Kubernetes.

u7s is alpha. There is no compatibility promise: the API surface is bounded
to what the project's current milestones need, and behavior can change
between releases. Do not run production workloads against it yet.

## Prerequisites

1. Ubuntu 24.04 or newer (kernel 6.6+).
2. x86_64 (release assets are published for linux/amd64 only).
3. systemd as PID 1 and root access. OpenSSL 3+ is needed only to verify a
   downloaded tarball.
4. Outbound HTTPS to `u7s.dekiru.tech` (installer and release), the container
   registries `registry.k8s.io`
   and Docker Hub, and the CDN and auth hosts they redirect to; the CRI-O apt
   mirror `slc-mirror.opensuse.org`; and your distribution's package mirrors.
5. At least 1 dedicated vCPU, 1 GiB RAM and about 10 GB of disk. First boot to
   Ready takes 4-10 minutes on a 10 GB e2-micro; the install waits up to 20
   minutes.

## Quick start

`install.sh` bootstraps a single-node cluster on a fresh Ubuntu host: it
installs CRI-O, stages the u7s binaries and the vendored kubelet and
kube-controller-manager, and writes a systemd unit for each. Every step
below uses the downloaded script; the join step needs it, because the token
is read from stdin. For flags, signature verification and reinstalling, see
[docs/install.md](docs/install.md). For upgrades, see
[docs/upgrading.md](docs/upgrading.md).

1. Install the control plane as root. The script verifies the release
   tarball against the signing key embedded in it and refuses to install if
   that fails:

   ```bash
   curl --proto '=https' --tlsv1.2 -fsSLO https://u7s.dekiru.tech/install.sh
   sudo bash install.sh
   ```

2. Check the node. The kubeconfig is written to `/var/lib/u7s/kubeconfig`
   and is readable by root only, so the examples in this README run
   `kubectl` with `sudo`:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig get nodes
   ```

3. To add a worker, mint a single-use token on the control plane. The
   output holds the token (valid 24 hours), the API server URL and the CA
   certificate hash (`sha256:...`):

   ```bash
   sudo bash install.sh --mint-join-token
   ```

   Install the control plane's release (the default), because a worker must
   never be newer than the control plane. An older worker is fine during a
   rolling upgrade, within upstream's kubelet skew policy (up to 3 minor
   versions older); see [Upgrading](docs/upgrading.md). Print the
   installed release tag:

   ```bash
   /opt/u7s/bin/u7s-apiserver --version | grep -oE '\+u7s-[^ ]+' | sed 's/^+u7s-/v/'
   ```

4. On the worker, set `TAG` to that tag, download `install.sh`, then join
   with a `--node-name` other than the control plane's:

   ```bash
   TAG=<tag from step 3>
   curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
   echo '<token>' | sudo bash install.sh --join https://<control-plane-ip>:6443 \
     --ca-cert-hash sha256:<hash> --node-name <worker-name> --token -
   ```

5. On the control plane, check that the worker is Ready with the command
   from step 2.

More in [docs/install.md](docs/install.md):

- [Verifying the release](docs/install.md#verifying-the-release): signed
  `install.sh`, `release.pub`, `openssl` check.
- [Flags and defaults](docs/install.md#flags-and-defaults): `--iface`,
  `--node-name`, `--node-ip`, kubeconfig on another machine.
- [Dual-stack install](docs/install.md#dual-stack-install)
- [Add a worker](docs/install.md#add-a-worker): token details and failures.
- [Files, logs and reinstalling](docs/install.md#files-logs-and-reinstalling)
- [Running on a 1 GiB host](docs/install.md#running-on-a-1-gib-host): zram,
  swapfile, services to disable.

u7s does not ship metrics-server. The `scale` subresource is implemented, so
`HorizontalPodAutoscaler` works once you install metrics-server yourself —
apply upstream's release manifest:

```bash
sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

## Expose a Service with a LoadBalancer

u7s applies beep as its LoadBalancer provider by default, so a Service of
`type: LoadBalancer` gets an external address with no extra install. beep
needs kernel >= 6.6 (see Prerequisites).

1. Create the Service. Add `ipFamilyPolicy: PreferDualStack` on a dual-stack
   cluster to get an address of each family:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig apply -f - <<'EOF'
   apiVersion: v1
   kind: Service
   metadata:
     name: web
   spec:
     type: LoadBalancer
     selector:
       app: web
     ports:
     - port: 80
       targetPort: 8080
   EOF
   ```

2. Read the address from the Service status:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig get svc web -o jsonpath='{.status.loadBalancer.ingress[*].ip}'
   ```

   The addresses are node addresses: every node under the default
   `externalTrafficPolicy: Cluster`, and only nodes with a local ready
   endpoint under `Local`.

Differences from upstream Kubernetes:

- `externalTrafficPolicy: Local`: a node with no local ready endpoint forwards
  to ready endpoints on other nodes, with the client IP preserved, instead of
  dropping the traffic.
- `sessionAffinity: ClientIP` is honoured. `timeoutSeconds` is not.

## Logs and exec

`kubectl logs` and `kubectl exec` work on the control plane and on joined
workers:

```bash
sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig logs <pod>
sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig exec -it <pod> -- sh
```

They fail when the API server reaches a node's kubelet through a `127.0.0.1`
port forward, for example a Mac host in front of Lima VMs: the kubelet
serving certificate cannot be verified against that address. Real installs
reach the node's InternalIP.

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
