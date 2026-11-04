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
   still a prerelease, so the unpinned `/install.sh` URL returns 404 by
   design; pin a release tag instead:

   ```bash
   TAG=$(curl --proto '=https' --tlsv1.2 -sf "https://api.github.com/repos/litehop/u7s/releases?per_page=1" | grep -m1 '"tag_name"' | cut -d'"' -f4)
   curl --proto '=https' --tlsv1.2 -fsSL "https://u7s.dekiru.tech/${TAG:?could not resolve the latest release tag - set TAG manually}/install.sh" | sudo bash
   ```

   The lookup uses `curl`, `grep` and `cut` (unauthenticated GitHub API
   calls are rate-limited; if it fails, set `TAG` by hand from
   <https://github.com/litehop/u7s/releases>).

   `install.sh` verifies the release tarball and its `.sha256` against Ed25519
   signatures (`.sig` assets) using the public key below, which is also
   embedded in the script; it refuses to install if verification fails or
   OpenSSL >= 3.0 is missing. To verify an artifact by hand:
   `openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in <file> -sigfile <file>.sig`.

   Release signing public key (releases are signed with the matching private
   key):

   ```
   -----BEGIN PUBLIC KEY-----
   MCowBQYDK2VwAyEAQyJWAOZX5w4sMHM+w/dKPlR3rIHYzOPalQ2UXVJIK+8=
   -----END PUBLIC KEY-----
   ```

   **The one-liner above trusts the download channel.** The key embedded in
   `install.sh` arrives with the script, so it only protects against a
   compromised release publisher, not against whoever controls the proxy or
   your network path to it.

   **Verify before running.** `install.sh` is itself signed with the same
   key. Save the public key above (copied from GitHub, a different channel
   from the proxy) as `release.pub`, then:

   ```bash
   curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
   curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh.sig"
   openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in install.sh -sigfile install.sh.sig
   sudo bash install.sh
   ```

   Run it only if openssl prints `Signature Verified Successfully`
   (OpenSSL >= 3.0; macOS's LibreSSL cannot verify Ed25519).

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

   The kubeconfig is readable by root only, so run `kubectl` as root
   (`sudo kubectl ...`) in this README's examples. It refers to
   `ca-bundle.pem` and `admin.pem` beside it by path, so a rotated certificate is picked up without rewriting it. To use it on
   another machine, embed them first:
   `kubectl --kubeconfig=/var/lib/u7s/kubeconfig config view --raw --flatten`.

u7s does not ship metrics-server. The `scale` subresource is implemented, so
`HorizontalPodAutoscaler` works once you install metrics-server yourself —
apply upstream's release manifest:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

## Dual-stack install

A dual-stack cluster gives Services and pods an IPv4 and an IPv6 address.
IPv6-only clusters and clusters with mixed single/dual ranges are not
supported.

Prerequisites:

- The node has a global-scope address of each family on the cluster
  interface, or you pass one of each with `--node-ip`. The install fails with
  an error naming the missing family otherwise.
- The Service range and the pod range each have two entries, one per
  family. The first entry is the primary family.

1. Download `install.sh` for your release tag (see Quick start for `TAG`):

   ```bash
   curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
   ```

2. Run it with a range of each family. Add `--node-ip <ipv4>,<ipv6>` if the
   interface does not carry both addresses or you want other ones:

   ```bash
   sudo bash install.sh \
     --service-cidr 10.96.0.0/12,fd00:96::/108 \
     --cluster-cidr 10.244.0.0/16,fd00:244::/56
   ```

3. Check the Service ranges:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig get servicecidr kubernetes -o jsonpath='{.spec.cidrs}'
   ```

   The output lists both ranges.

The ranges are fixed at first install: a re-run that passes a different
value is refused. The only supported change is the single-stack to
dual-stack upgrade below. The script enables IPv6 forwarding for a
dual-stack install by writing `/etc/sysctl.d/u7s-ipv6-forwarding.conf`.
A joining worker reads the ranges from the cluster, so it needs no CIDR
flags, only an address of each family.

## Add a worker

A worker runs only kubelet and joins an existing control plane with a
single-use token. Use the saved `install.sh`, not `curl | sudo bash`: the
script reads the token from stdin, which is the script itself in the one-liner.

1. On the control plane, mint a token. The script is the one you installed
   with (see Quick start, "Verify before running"):

   ```bash
   sudo bash install.sh --mint-join-token
   ```

   The output holds a token that expires after 24 hours and works once, the
   API server URL, and the CA certificate hash (`sha256:...`).

2. On the worker, download `install.sh` of the same release tag:

   ```bash
   curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
   ```

3. On the worker, join. Choose a `--node-name` other than the control
   plane's, and pipe the token in with `--token -` (it lands in your shell
   history, but it expires and works once):

   ```bash
   echo '<token>' | sudo bash install.sh --join https://<control-plane-ip>:6443 \
     --ca-cert-hash sha256:<hash> --node-name <worker-name> --token -
   ```

4. On the control plane, check that the worker is Ready:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig get nodes
   ```

The worker learns the Service and pod ranges from the cluster, so it takes no
CIDR flags. A token whose join failed after the certificate was issued is
consumed; mint a new one.

## Expose a Service with a LoadBalancer

u7s applies beep as its LoadBalancer provider by default, so a Service of
`type: LoadBalancer` gets an external address with no extra install. beep
needs kernel >= 6.6, and `install.sh` refuses to run on an older kernel.

1. Create the Service. Add `ipFamilyPolicy: PreferDualStack` on a dual-stack
   cluster to get an address of each family:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig apply -f - <<'EOF'
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
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig get svc web -o jsonpath='{.status.loadBalancer.ingress[*].ip}'
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
kubectl --kubeconfig=/var/lib/u7s/kubeconfig logs <pod>
kubectl --kubeconfig=/var/lib/u7s/kubeconfig exec -it <pod> -- sh
```

They fail when the API server reaches a node's kubelet through a `127.0.0.1`
port forward, for example a Mac host in front of Lima VMs: the kubelet
serving certificate cannot be verified against that address. Real installs
reach the node's InternalIP.

## Files, logs and reinstalling

| What | Where |
|---|---|
| State: CA, keys, state store, kubeconfig | `/var/lib/u7s/` |
| Install settings read by re-runs | `/var/lib/u7s/config` |
| Binaries | `/opt/u7s/bin/` |
| Vendored manifests applied at every apiserver boot | `/etc/u7s/manifests/` (`--manifest-output-dir`) |
| Static pods | `/etc/u7s/static-pods/` |
| CRI-O memory settings | `/etc/crio/crio.conf.d/10-memory.conf` |
| Kernel settings | `/etc/sysctl.d/u7s-*.conf`, `/etc/modules-load.d/u7s-br-netfilter.conf` |
| Systemd units | `u7s-apiserver`, `u7s-kcm`, `u7s-kcm-restart.path` and `.service`, `kubelet` (a worker has `kubelet` only) |

Read a service's log with `journalctl`:

```bash
sudo journalctl -u u7s-apiserver
sudo journalctl -u kubelet
```

There is no uninstaller. To start a node over, stop its services, delete the
state directory, and re-run `install.sh`:

1. Stop the services (on a worker, `kubelet` only):

   ```bash
   sudo systemctl stop kubelet u7s-kcm u7s-apiserver
   ```

2. Delete the state directory. This deletes the cluster's CA and state
   store on a control plane:

   ```bash
   sudo rm -rf /var/lib/u7s
   ```

3. Run `install.sh` again. A worker must be joined again with a new token;
   see "Add a worker". The worker may re-join under its old name; the Node
   object need not be deleted first. A control plane re-installed this way
   comes back with the default ranges unless you pass the dual-stack flags
   again.

This leaves CRI-O, its apt sources, the systemd unit files, the binaries in
`/opt/u7s/bin`, and the sysctl and module files in place. Remove them by hand
if you need a clean host.

## Upgrading

Upgrade in place by re-running the install script of the newer release on each
node. It needs no token and mints nothing. Upgrade the control plane first,
then the workers.

- **Control plane**: re-run with no flags. A re-run with no flags keeps a
  single-stack cluster single-stack; see "Upgrading to dual-stack" below
  to add IPv6. The binaries and unit files are
  replaced and the services restarted; the CA (`/var/lib/u7s/ca.key`,
  `ca.crt`), the service-account keyring (`sa.key`, `sa.pub`) and the cluster
  state are kept, and the script fails if the CA changed. The keyring rotates
  on its own, so `sa.key` changing between runs is expected.
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
- **Node name on join**: a joiner cannot claim the control-plane node's name
  (the apiserver answers 403 "it is the control-plane node"); pick a
  different `--node-name`. Other names, including an existing worker's, are
  accepted so a worker can re-join.

### Upgrading to dual-stack

Releases up to and including `v0.4.3-snapshot.4` refuse this and require
a reinstall; use a later release. To add an IPv6 range to a single-stack
cluster, re-run the install
script on the control plane with your existing range followed by one range
of the other family. Any other change to the ranges is refused. The node
needs an address of each family (see "Dual-stack install").

Existing Nodes keep their single-stack `spec.podCIDRs`, because upstream
does not allow a Node to gain a pod range in place. Each Node must be
re-created before its pods get an IPv6 address. Existing Services keep their
single ClusterIP; new Services can request `ipFamilyPolicy:
PreferDualStack` or `RequireDualStack`.

1. Read the existing ranges:

   ```bash
   sudo grep -E '^(SERVICE_CIDR|POD_CLUSTER_CIDR)=' /var/lib/u7s/config
   ```

2. Re-run `install.sh` of the same release with each existing range followed
   by a range of the other family. This example upgrades a default install:

   ```bash
   sudo bash install.sh \
     --service-cidr 10.96.0.0/12,fd00:96::/108 \
     --cluster-cidr 10.244.0.0/16,fd00:244::/56
   ```

   The script prints `upgraded to dual-stack` and the commands in steps 3-6.

3. For each Node, drain it and delete the Node object. Pass `--force` to
   `drain` if bare pods (not managed by a controller) run on the Node:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig drain <node> --ignore-daemonsets --delete-emptydir-data
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig delete node <node>
   ```

4. On that node, restart kubelet so the Node re-registers with both
   podCIDRs:

   ```bash
   sudo systemctl restart kubelet
   ```

5. Restart flannel so it reads the new podCIDRs. Pods created before this
   step get an IPv4 address only:

   ```bash
   kubectl --kubeconfig=/var/lib/u7s/kubeconfig -n kube-flannel delete pod -l app=flannel
   ```

6. Deleting the control-plane Node removed its
   `node-role.kubernetes.io/control-plane` label. After it re-registers,
   re-run the command from step 2 to restore the label.

7. Re-join each worker: its address families are learned at join. On the
   worker, stop kubelet and clear its state, then follow "Add a worker"
   with a new token:

   ```bash
   sudo systemctl stop kubelet
   sudo rm -rf /var/lib/u7s
   ```

## Running on a 1 GiB host

On a 1 vCPU / 1 GiB Ubuntu host the stack boots to Ready in about a minute
and leaves roughly 450 MiB of `MemAvailable` idle, and about 320 MiB with a
small app (WordPress + MariaDB) running. Large pod bursts on top of that
push the host into page-cache thrash. `install.sh` deliberately does not
touch the host OS, so these node-level mitigations are yours to apply:

- Recommended for bursty or dense workloads: enable zram swap. `install.sh`
  does not configure swap, and the release gate runs without it: the gated
  burst size is measured at release time (see `docs/dev-setup.md`). On
  1 GiB / 1 vCPU with no swap, an 80-pod burst
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
