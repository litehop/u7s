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

1. Run the install script as root on the target host. Every release is
   still a prerelease (snapshot), so the unpinned `/install.sh` URL
   returns 404 by design; pin a snapshot tag instead:

   ```bash
   TAG=$(curl -sf "https://api.github.com/repos/litehop/u7s/releases?per_page=1" | grep -m1 '"tag_name"' | cut -d'"' -f4)
   curl -fsSL "https://u7s.dekiru.tech/${TAG:?could not resolve the latest release tag - set TAG manually}/install.sh" | sudo bash
   ```

   The lookup uses `curl`, `grep` and `cut` (unauthenticated GitHub API
   calls are rate-limited; if it fails, set `TAG` by hand from
   <https://github.com/litehop/u7s/releases>).

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

## Upgrading

Upgrade in place by re-running the install script of the newer release on each
node. It needs no token and mints nothing. Upgrade the control plane first,
then the workers.

- **Control plane**: re-run with no flags. The binaries and unit files are
  replaced and the services restarted; the CA and service-account keys
  (`/var/lib/u7s/ca.key`, `ca.crt`, `sa.key`, `sa.pub`) and the cluster
  state are kept, and the script fails if those keys changed.
- **Joined worker**: re-run with no flags (no `--join`, no token). The script
  recognises the node's identity (`/var/lib/u7s/kubeconfig`, `ca.pem`,
  `kubelet-client.crt` and `.key`, plus the kubelet's rotated client cert in
  `/var/lib/u7s/kubelet/pki/`), swaps the kubelet binary and config,
  restarts kubelet, and waits for the Node to report Ready again. The
  kubelet keeps its own rotating client and serving certificates. The
  upgrade needs a reachable API server: it reads the Node's Ready heartbeat
  first and aborts before touching kubelet if it cannot.
- **Expired or missing worker identity**: a worker offline past its client
  certificate lifetime fails with an error naming the state to clear
  (`systemctl stop kubelet; rm -rf /var/lib/u7s`); re-join it with a fresh
  `install.sh --mint-join-token` token. A worker whose identity files are
  missing needs a join too.

## Running on a 1 GiB host

On a 1 vCPU / 1 GiB Ubuntu host the stack boots to Ready in about a minute
and leaves roughly 450 MiB of `MemAvailable` idle, and about 320 MiB with a
small app (WordPress + MariaDB) running. Large pod bursts on top of that
push the host into page-cache thrash. `install.sh` deliberately does not
touch the host OS, so these node-level mitigations are yours to apply:

- Recommended for bursty or dense workloads: enable zram swap. `install.sh`
  does not configure swap. On 1 GiB / 1 vCPU with no swap, an 80-pod burst
  never reached all-Ready within 600 s and the node went NotReady; with
  512 MiB zram, 80 pods were Ready in 15-17 s and the node stayed Ready.
  With `systemd-zram-generator` installed:

  ```bash
  printf '[zram0]\nzram-size = 512\ncompression-algorithm = zstd\n' |
    sudo tee /etc/systemd/zram-generator.conf
  sudo systemctl daemon-reload && sudo systemctl start /dev/zram0
  ```

  Kubelet runs with `failSwapOn: false` and its default `NoSwap` behaviour,
  so pods do not swap; system processes and the kernel do.

- Or add a swapfile instead:

  ```bash
  sudo fallocate -l 1G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```

- Disable cloud-image services that u7s does not need. On Ubuntu cloud
  images, `udisksd`, `multipathd`, `ModemManager`, `unattended-upgrades`,
  `networkd-dispatcher`, `polkitd` and `rsyslog` together hold roughly
  100 MB:

  ```bash
  sudo systemctl disable --now udisks2 multipathd ModemManager \
    unattended-upgrades networkd-dispatcher polkit rsyslog
  ```

  Only disable what you do not rely on (for example, keep
  `unattended-upgrades` if you want automatic security updates).

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
