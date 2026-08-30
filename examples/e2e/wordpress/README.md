# WordPress + nginx + php-fpm + MariaDB E2E workload

Committed, apply-able manifests reproducing the nginx -> php-fpm -> MariaDB -> HTTP
write path validated in an earlier hand-hacked VM session, now built from files
in this repo, with no dependency on ephemeral VM state.

## Prerequisites

1. A running u7s cluster (`scripts/install.sh` on a fresh VM).
2. csi-hostpath v1.17.1, installed from the pinned upstream tag (do not float a
   branch clone -- see `csi-hostpath-storageclass.yaml` for why):

   ```
   git clone --depth 1 --branch v1.17.1 https://github.com/kubernetes-csi/csi-driver-host-path.git
   cd csi-driver-host-path/deploy/kubernetes-latest && ./deploy.sh
   ```

   `deploy.sh` also applies a VolumeSnapshot snapshotclass that hard-fails without
   VolumeSnapshot CRDs installed -- harmless, ignore it.

## Apply

```
kubectl apply -f examples/e2e/wordpress/
```

Creates the `csi-hostpath-sc` StorageClass, a MariaDB StatefulSet+Secret+ConfigMap+
Service, and a WordPress+nginx+php-fpm Deployment+Secret+ConfigMaps+Service, all in
the `default` namespace.

## Smoke test

```
scripts/e2e-workload/wordpress-smoke.sh
```

Applies the manifests, waits for MariaDB and WordPress to become Ready, then
asserts the full HTTP write path: `GET /` -> 302 -> `GET /wp-admin/install.php` ->
200 -> `POST install.php?step=2` -> body contains `Success!` -> final `GET /`
renders the just-submitted site title (proves the write reached MariaDB and
round-tripped back out through nginx+php-fpm). Exits non-zero on any failed
assertion. Requires a WordPress database with no prior install -- re-running
against an already-installed WordPress will not see the 302 in step 1 (see the
script's own comments for how to reset).

## Provenance

Recovered from the `lima-workload` Lima VM's live cluster objects (`kubectl get
<kind> -o yaml`), sanitized of cluster-assigned fields (`status`,
`metadata.uid`/`resourceVersion`/`generation`/`creationTimestamp`/`managedFields`,
`spec.clusterIP(s)`).
