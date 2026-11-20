# Upgrading

You upgrade u7s by re-running the `install.sh` of the next release on each
node, from the immediately previous release only. Control plane first, then
workers.

## Supported paths

u7s is pre-production. The only supported upgrade is from release N-1 to
release N (operator decision 2026-11-18).

- To skip releases, step through each one in order.
- Downgrades are unsupported. The API server refuses to start on a store
  whose format is newer than it supports and names both formats. The store
  format is SQLite's `PRAGMA user_version` (today 1), independent of the
  release version.
- u7s sends no update notification. Watch
  [GitHub Releases](https://github.com/litehop/u7s/releases) and read
  `CHANGELOG.md` before each step.

## Before you upgrade

1. Print the installed release (see
   [Pinning a release tag](install.md#pinning-a-release-tag)). It must be
   the release just before your target.
2. Back up the control plane (see [Back up and restore](#back-up-and-restore)).
3. Expect a short API outage on the control plane.

## Upgrade a control plane

Download the target release's `install.sh` and re-run it with no flags. Set
`TAG` to the target release tag:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
sudo bash install.sh
```

The script prints `existing u7s install detected -- upgrading in place`
when `ca.key` or `kubeconfig` exists under `/var/lib/u7s`. It replaces the
binaries and unit files, then restarts the API server, controller manager,
and kubelet. The CA, the cluster state, and the pods keep their identity. The
script fails if the CA changed; recover as in
[Back up and restore](#back-up-and-restore). A changed `sa.key` is expected.

The script reads `/var/lib/u7s/config`, so `--iface` and `--node-name` need
no repeat, and a different value is refused. A re-run keeps a single-stack
cluster single-stack.

## Upgrade a worker

After the control plane is done, re-run `install.sh` on each worker with no
flags: no `--join` and no token. The script swaps the kubelet binary and
config, restarts kubelet, and waits for the Node to report Ready. It aborts
before touching kubelet if it cannot reach the API server.

A worker must never be newer than the control plane. An older worker is fine
within upstream's kubelet skew policy (up to 3 minor versions older).

A worker offline past its client certificate lifetime fails with an error that
tells you what to clear (`systemctl stop kubelet; rm -rf /var/lib/u7s`). Re-join
it with a token from `install.sh --mint-join-token`; see
[Add a worker](install.md#add-a-worker). A joiner cannot claim the
control-plane node's name (the API server answers 403).

## Expected outage

The API is down while the API server restarts. One probe upgraded a
single-node GCP VM from v0.4.5 to v0.4.6: the script ran 99 s, and one of 132
`/readyz` polls at 2 s failed. CoreDNS, kube-proxy, and the `servicelb` pods
kept their UIDs with 0 restarts, and the flannel pod was recreated by design.
The release gate asserts at most 60 s
([dev-setup.md](dev-setup.md#upgrade-check)). Multi-node is not probed.

## Back up and restore

This is disaster recovery, not a supported downgrade. It discards every
change made since the backup. On a single-node control plane it restored
v0.4.6 after an upgrade to v0.4.7.

1. Before upgrading, stop the services and copy the whole state directory
   (the API is down meanwhile). Committed writes can stay in
   `state.db-wal`, so a copy of `state.db` alone may lose data. The archive
   contains the CA private key and service-account keys, so `umask` makes it
   mode 0600:

   ```bash
   sudo systemctl stop kubelet u7s-kcm u7s-apiserver
   sudo sh -c 'umask 077; tar -C /var/lib -czpf u7s-state-backup.tar.gz u7s'
   sudo systemctl start u7s-apiserver u7s-kcm kubelet
   ```

   Never copy a running store: 8 of 12 live copies changed mid-copy.

2. Upgrade.

3. To restore, replace the state directory, then re-run the previous
   release's `install.sh` with no flags, as in
   [Upgrade a control plane](#upgrade-a-control-plane). It restores the
   binaries and prints `Control-plane identity preserved` (tested with a
   local `--tarball` install, not the mirror URL):

   ```bash
   sudo systemctl stop kubelet u7s-kcm u7s-apiserver
   sudo rm -rf /var/lib/u7s
   sudo tar -C /var/lib -xzpf u7s-state-backup.tar.gz
   ```

4. Check that `sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig get --raw /readyz`
   prints `ok` and the Node is Ready.

If the CA files were lost or replaced, extract them from the archive:

```bash
sudo systemctl stop kubelet u7s-kcm u7s-apiserver
sudo tar -C /var/lib -xzpf u7s-state-backup.tar.gz u7s/ca.key u7s/ca.crt
sudo systemctl start u7s-apiserver u7s-kcm kubelet
```

## Upgrading to dual-stack

This changes the pod and service ranges, so it is separate from a release
upgrade. Releases before v0.4.4-snapshot.1 refuse it and need a reinstall.
Existing Nodes keep their single-stack `spec.podCIDRs`, because upstream does
not let a Node gain a pod range in place; re-create each Node. Existing
Services keep their single ClusterIP; new ones can request
`ipFamilyPolicy: PreferDualStack` or `RequireDualStack`. Any range change
other than adding one range of the other family is refused.

1. Give each node an address of each family (see
   [Dual-stack install](install.md#dual-stack-install)).

2. Read the existing ranges:

   ```bash
   sudo grep -E '^(SERVICE_CIDR|POD_CLUSTER_CIDR)=' /var/lib/u7s/config
   ```

3. On the control plane, re-run `install.sh` of the same release with each
   existing range followed by a range of the other family. This example
   upgrades a default install:

   ```bash
   sudo bash install.sh \
     --service-cidr 10.96.0.0/12,fd00:96::/108 \
     --cluster-cidr 10.244.0.0/16,fd00:244::/56
   ```

   The script prints `upgraded to dual-stack` and the commands in steps 4-6.

4. For each Node, drain it, delete the Node object, and restart kubelet on
   that node so it re-registers. Pass `--force` to `drain` if bare pods run
   on the Node:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig drain <node> --ignore-daemonsets --delete-emptydir-data
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig delete node <node>
   sudo systemctl restart kubelet
   ```

5. Restart flannel so it reads the new podCIDRs. Pods created before this
   step get an IPv4 address only:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig -n kube-flannel delete pod -l app=flannel
   ```

6. Deleting the control-plane Node removed its
   `node-role.kubernetes.io/control-plane` label. After it re-registers,
   re-run the command from step 3 to restore the label.

7. Re-join each worker: its address families are learned at join. On the
   worker, stop kubelet and clear its state, then follow
   [Add a worker](install.md#add-a-worker) with a new token:

   ```bash
   sudo systemctl stop kubelet
   sudo rm -rf /var/lib/u7s
   ```
