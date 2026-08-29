# Phase 3: WordPress+nginx deploy on fixed u7s (v0.2.1-snapshot.1)

Bead: mayor-f3h0p
Date: 2026-08-29
Shape: 3 (audit) — one fresh VM, findings only, no u7s code changes

## Verdict

WordPress reached `Running` with both containers Ready (`pehelypress` php-fpm, `pehelypress-nginx`); 5 of 5 tested Phase 2 workarounds are now no-ops, but the fix wave shipped **one regression**: mayor-vamg1's kubelet reset-cert-cache fix (PR #1462) is itself a no-op — `certDir` is not a real `KubeletConfiguration` field — so Phase 1's manual `rm -rf /var/lib/kubelet/pki` workaround is still required on every reset. Filed as mayor-nly97 (P1).

## Fix validation matrix

| Phase 2 workaround | Result | Fix PR |
|---|---|---|
| `system:node` PVC/PV/VolumeAttachment RBAC patch | **No-op** — kubelet mounted the PVC unpatched | mayor-u1g6k / #1464 |
| Secret `--from-literal` (avoid `stringData`) | **No-op** — plain `stringData:` manifest round-tripped into base64 `data`, `stringData` cleared | mayor-l9oo0 / #1467 |
| CoreDNS `bootstrapping` label removal | **No-op** — pre-seeded binding still carries the label; DNS resolved instantly; a *new* SSA-applied ClusterRoleBinding was also honored immediately (positive+negative SAR both correct) | mayor-e78se / #1466 |
| `modprobe br_netfilter` + sysctl | **No-op** — ClusterIP DNS and MariaDB Service DNS both worked with zero manual networking steps (install.sh already carried this fix pre-dating Phase 2's stale-tarball repro) | mayor-ilu9b / #1465 |
| `system:node` pod-delete RBAC / manual pod cleanup | **No-op** — `kubectl delete pod` completed cleanly, no Terminating wedge | mayor-m7fxk / #1469 |
| MariaDB temp-server bootstrap SQL patch | **Not needed this run** — mariadb-0 reached Ready unassisted, ~30s past the first probe attempt, no crash loop. Consistent with mayor-22ygq's closed verdict (environmental/QEMU-TCG timing, no code bug) — not proof of a fix, just non-recurrence | mayor-22ygq (closed, no fix) |
| kubelet reset-cert-cache (`rm -rf /var/lib/kubelet/pki`) | **Still needed** — regression: fix is a no-op | mayor-vamg1 / #1462 (ineffective) |

## Timeline

1. Reset + install v0.2.1-snapshot.1: **~12 min** (VM stop/start ~1 min, tarball+install.sh download ~15s, install.sh run <1 min, then ~9 min diagnosing+working around the certDir regression before the node registered).
2. CoreDNS verify: **<1 min** once the node was Ready — `nslookup kubernetes.default.svc.cluster.local` resolved on the first attempt.
3. csi-hostpath + MariaDB (4 workaround-avoidance tests): **~7 min** — csi-hostpathplugin-0 8/8 Running in 7s; MariaDB PVC bound and pod Ready without any RBAC patch; `SELECT 1` over the Service DNS name succeeded.
4. WordPress + nginx: **~7 min**, including diagnosing an upstream chart assumption (below) — final pod `2/2 Running`.

## New gaps

| Symptom | Category | Proposed fix |
|---|---|---|
| kubelet never registers after `install.sh`'s documented reset when a prior install's `/var/lib/kubelet/pki` still has a rotated cert signed by the deleted CA; apiserver logs continuous `TLS accept error: invalid peer certificate: UnknownIssuer`. Root cause: `certDir:` in the generated `kubelet-config.yaml` is not a valid `KubeletConfiguration` key — the real setting, `CertDirectory`, lives only in `KubeletFlags`, bound to the `--cert-dir` CLI flag (kubelet's own `--help` marks neighboring config-file-backed flags deprecated, not this one). Kubelet silently ignores the unknown key and keeps using the hardcoded default. | u7s-should-own (P1, regression in a fix shipped this snapshot) | mayor-nly97: pass `--cert-dir=$STATE_DIR/kubelet/pki` on kubelet's `ExecStart`; delete the dead `certDir:` line |

One environment-only finding, not filed as a bead: the `pehelypress` chart's nginx readinessProbe sets `X-Forwarded-Proto: https`, which makes WordPress's `is_ssl()` redirect `/wp-login.php` to an `https://` URL; with no TLS-terminating ingress in front of this bare pod, nginx can't serve that scheme and the probe fails regardless of DB state. Dropping that one header (documented deviation) lets the same redirect resolve on the real `http` scheme and return 200 once php-fpm reaches MariaDB — proving the done-when criterion. Chart/ingress-assumption mismatch, not a u7s defect.

## Reproducible recipe

```
# Reset (still needs the pre-vamg1 workaround -- see mayor-nly97)
limactl stop lima-workload && limactl start lima-workload
limactl shell lima-workload -- sudo systemctl stop u7s-apiserver u7s-kcm u7s-scheduler kubelet
limactl shell lima-workload -- sudo rm -rf /var/lib/u7s /opt/u7s /var/lib/kubelet/pki

# Install v0.2.1-snapshot.1
limactl shell lima-workload -- curl -fL -o /tmp/u7s.tar.gz \
  https://github.com/litehop/u7s/releases/download/v0.2.1-snapshot.1/u7s-v0.2.1-snapshot.1-x86_64-unknown-linux-gnu.tar.gz
limactl shell lima-workload -- curl -fL -o /tmp/install.sh \
  https://github.com/litehop/u7s/releases/download/v0.2.1-snapshot.1/install.sh
limactl shell lima-workload -- sudo bash /tmp/install.sh --tarball /tmp/u7s.tar.gz

# csi-hostpath v1.17.1 + StorageClass (unchanged from Phase 2)
git clone --depth 1 --branch v1.17.1 https://github.com/kubernetes-csi/csi-driver-host-path.git
cd csi-driver-host-path/deploy/kubernetes-latest && sudo env KUBECONFIG=/var/lib/u7s/kubeconfig ./deploy.sh
kubectl apply -f ../../examples/csi-storageclass.yaml

# MariaDB: plain `kubectl apply -f secret.yaml` (stringData, no --from-literal);
# storageClassName: csi-hostpath-sc; no RBAC patch, no br_netfilter, no SQL patch.

# WordPress+nginx: hand-rendered valerauko/pehelypress v1.2.1, database.hostname=mariadb.default.svc.cluster.local,
# credentials matching the MariaDB Secret, persistence.enabled=false (emptyDir, simpler than a static PV),
# readinessProbe's X-Forwarded-Proto header dropped (see New gaps).
```

## Follow-on beads

- mayor-nly97 — install.sh's kubelet `certDir` YAML field is not a real `KubeletConfiguration` key; mayor-vamg1's fix is a no-op (P1 bug, `discovered-from: mayor-f3h0p`)

`lima-workload` left running (WordPress `2/2 Running`) for Phase 4 (mayor-22c3m).
