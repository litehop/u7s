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
  format is SQLite's `PRAGMA user_version`, independent of the release
  version. Today it is 1, so most release steps change no format.
- u7s sends no update notification and has no `--check-update`. Watch
  [GitHub Releases](https://github.com/litehop/u7s/releases) and read
  `CHANGELOG.md` before each step.

## Before you upgrade

1. Read the `CHANGELOG.md` entries of the target release.
2. Print the installed release (see
   [Pinning a release tag](install.md#pinning-a-release-tag)). It must be
   the release just before your target.
3. Back up the control plane (see [Backup and rollback](#backup-and-rollback)).
4. Expect a short API outage on the control plane.

## Upgrade a control plane

Download the target release's `install.sh` and re-run it with no flags. Set
`TAG` to the target release tag:

```bash
curl --proto '=https' --tlsv1.2 -fsSLO "https://u7s.dekiru.tech/${TAG}/install.sh"
sudo bash install.sh
```

The script prints `existing u7s install detected -- upgrading in place`
when `ca.key` or `kubeconfig` exists under `/var/lib/u7s`. It replaces the
binaries and unit files, then enables and restarts the API server,
controller manager, and kubelet. The CA, the cluster state, and the pods keep
their identity. The script fails if the CA changed. The service-account
keyring rotates on its own, so `sa.key` changing is expected.

The script reads `/var/lib/u7s/config`, so `--iface` and `--node-name` need
no repeat. A different value is refused. A re-run with no flags keeps a
single-stack cluster single-stack.

## Upgrade a worker

After the control plane is done, re-run `install.sh` on each worker with no
flags: no `--join` and no token. The script refuses `--join` on a joined
worker. It swaps the kubelet binary and config, restarts kubelet, and waits
for the Node to report Ready. It needs a reachable API server, and aborts
before touching kubelet if it cannot read the Node.

A worker must never be newer than the control plane. An older worker is fine
during the rollout, within upstream's kubelet skew policy (up to 3 minor
versions older).

A worker offline past its client certificate lifetime fails with an error that
tells you what to clear (`systemctl stop kubelet; rm -rf /var/lib/u7s`).
Re-join it with a token from `install.sh --mint-join-token`; see
[Add a worker](install.md#add-a-worker). A joiner cannot claim the
control-plane node's name (the API server answers 403); other names,
including an existing worker's, are accepted.

## Expected outage

The API is down while the API server restarts. One probe upgraded a
single-node GCP VM from v0.4.5 to v0.4.6: the script ran 99 s, and one of 132
`/readyz` polls at 2 s failed (about 2 to 4 s down). CoreDNS, kube-proxy, and
the `servicelb` pods kept their UIDs with 0 restarts, a `hostPath` marker
kept its content, and the flannel DaemonSet pod was recreated by design. The
release gate asserts an outage of at most 60 s
([dev-setup.md](dev-setup.md#upgrade-check)). A multi-node control plane is
not probed.

## Backup and rollback

There is no rollback command. To make one possible, copy the state before
you upgrade:

```bash
sudo systemctl stop kubelet u7s-kcm u7s-apiserver
sudo tar -C /var/lib -czpf u7s-state-backup.tar.gz u7s
sudo systemctl start u7s-apiserver u7s-kcm kubelet
```

The archive contains the CA, keys, and the store. Keep it private.

To roll back, stop the services, restore the archive, and re-run the
previous release's `install.sh`. This undoes the upgrade only at the cost of
all changes made since the backup. It is a downgrade, so it is unsupported
and no test covers it. If the store format changed, the old binary refuses
the new store and you must restore the archive first.

If the script reports that the CA changed, restore `ca.key` and `ca.crt`
from the backup; every node's client identity is invalid until then.

## Upgrading to dual-stack

This changes the pod and service ranges, so it is a separate step from a
release upgrade. Releases before v0.4.4-snapshot.1 refuse it and need a
reinstall. Existing Nodes keep their single-stack `spec.podCIDRs`, because
upstream does not allow a Node to gain a pod range in place. Re-create each
Node before its pods get an IPv6 address. Existing Services keep their single
ClusterIP; new Services can request `ipFamilyPolicy: PreferDualStack` or
`RequireDualStack`. A change to the ranges other than adding one range of the
other family is refused.

1. Make sure each node has an address of each family (see
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

   The script prints `upgraded to dual-stack` and the commands in steps 4-7.

4. For each Node, drain it and delete the Node object. Pass `--force` to
   `drain` if bare pods run on the Node:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig drain <node> --ignore-daemonsets --delete-emptydir-data
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig delete node <node>
   ```

5. On that node, restart kubelet so the Node re-registers with both
   podCIDRs:

   ```bash
   sudo systemctl restart kubelet
   ```

6. Restart flannel so it reads the new podCIDRs. Pods created before this
   step get an IPv4 address only:

   ```bash
   sudo kubectl --kubeconfig=/var/lib/u7s/kubeconfig -n kube-flannel delete pod -l app=flannel
   ```

7. Deleting the control-plane Node removed its
   `node-role.kubernetes.io/control-plane` label. After it re-registers,
   re-run the command from step 3 to restore the label.

8. Re-join each worker: its address families are learned at join. On the
   worker, stop kubelet and clear its state, then follow
   [Add a worker](install.md#add-a-worker) with a new token:

   ```bash
   sudo systemctl stop kubelet
   sudo rm -rf /var/lib/u7s
   ```
