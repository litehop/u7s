# Cutting a single-node k3s host over to u7s

```
u7s migrate cutover --install-script ./install.sh [--confirm-retain] -- --tarball u7s.tar.gz
u7s migrate rollback
```

Run as root on the k3s host. Without `--confirm-retain` the command exports
the cluster, lists the PVs it would protect, and stops; the source is
unchanged. Re-run the same command with the flag to continue. A failed run
resumes where it stopped when re-run; `rollback` undoes it.

## What cutover does, in order

1. Export (objects file holds Secrets in clear text; mode 0600, in
   `--work-dir`).
2. Set reclaim policy `Retain` on every migrated PV, recording the original
   policy in the annotation `migrate.u7s.dev/original-reclaim-policy`.
3. Scale migrated Deployments and StatefulSets to zero.
4. Wait until no pod mounts a migrated volume and no VolumeAttachment
   references one. If this times out k3s is still running.
5. Stop and disable k3s. Its data directory (including local-path volumes)
   stays in place. k3s's uninstall script is never run: it deletes that
   directory.
6. Install u7s with the source's service CIDR, pod CIDR and kube-dns IP.
7. Import, wait for imported CSI drivers to register, wait for workloads
   and volumes to be ready.
8. Put the original reclaim policies back on the u7s PVs.

## Rollback window

`u7s migrate rollback` stops u7s, starts k3s, and restores the source PVs'
original reclaim policies and the workloads' replica counts. It works from
any point until you delete a migrated PVC on u7s: once a migrated PV is
missing, `Released` or being deleted on u7s, rollback is refused, because
k3s would start against volumes u7s already deleted. Until step 8 the u7s
PVs are `Retain`, so deleting a claim cannot delete data.

Rollback leaves `/var/lib/u7s` in place; stop the u7s units and remove it
before running a new cutover.

## Not covered

Multi-node and dual-stack sources, k3s datastores other than SQLite, and
copying volume data between hosts or regions.
