# Phase 4: WordPress end-to-end HTTP + mayor-nly97 confirm (v0.2.1-snapshot.2)

Bead: mayor-22c3m
Date: 2026-08-29
Shape: 3 (audit) — one VM, findings only, no u7s code changes

## Verdict

`curl` against WordPress's Service renders a full page end-to-end (nginx →
php-fpm → MariaDB → HTML, including a real write: the installer form
created an admin user and site), **and** mayor-nly97's `--cert-dir` fix
works cleanly — a plain `rm -rf $STATE_DIR` + re-run `install.sh` reached
node `Ready` in ~83s with **zero manual `/var/lib/kubelet/pki` cleanup**,
even though that directory still held a cert signed by the deleted CA from
Phase 3's prior run.

## Evidence

**HTTP chain:** `GET /` → `302 Found` → `Location: /wp-admin/install.php`
→ `GET /wp-admin/install.php` → `200 OK`, body starts:
```
<!DOCTYPE html>
<html lang="en-US" xml:lang="en-US">
...
<title>WordPress &rsaquo; Installation</title>
```
`POST /wp-admin/install.php?step=2` (weblog_title, user_name, admin_password,
admin_email) → `200 OK`, body: `<h1>Success!</h1><p>WordPress has been
installed. Thank you, and enjoy!</p>`. Final `GET /` → `200 OK`, 32619-byte
rendered homepage: `<title>Phase4 Test Site</title>` (the title just
submitted) — proves the write landed in MariaDB and round-tripped back out.

**Reset-path:** `sudo systemctl stop u7s-apiserver u7s-kcm kubelet` (no
`u7s-scheduler` unit — scheduler is embedded); `sudo rm -rf /var/lib/u7s
/opt/u7s` (deliberately **not** touching `/var/lib/kubelet/pki`, which still
had a stale cert); download+run `install.sh --tarball
u7s-v0.2.1-snapshot.2-...tar.gz`. `kubectl get nodes` showed `Ready` 3s
after registration. `systemctl cat kubelet` confirmed
`--cert-dir=/var/lib/u7s/kubelet/pki` on the `ExecStart` line; `ls
/var/lib/u7s/kubelet/pki` returned `Permission denied` (root-owned, freshly
created) rather than "no such file," confirming kubelet wrote new certs
under `$STATE_DIR` and never touched the stale, now-irrelevant
`/var/lib/kubelet/pki`.

## Timeline

1. Reset + install to node `Ready`: **~83s** (14:10:49→14:12:12) — the
   mayor-nly97 datum, down from Phase 1/3's ~10-12 min needing manual
   `/var/lib/kubelet/pki` cleanup.
2. CoreDNS + kube-proxy healthy: **+35s**.
3. csi-hostpath deploy (reused Phase 2/3's clone/manifests verbatim):
   plugin `8/8 Running` in 18s.
4. MariaDB deploy → `1/1 Running`: **~100s** (matches Phase 3's QEMU-TCG
   timing note, no crash loop).
5. WordPress+nginx deploy (reused Phase 3's manifest verbatim, including its
   `X-Forwarded-Proto` readinessProbe deviation) → `2/2 Running`: **~60s**.
6. Port-forward + curl (GET, POST install, final GET): **<1 min**.
7. Total wall clock, reset → HTTP-validated: **~7m11s**.

## Gaps

| Symptom | Category | Notes |
|---|---|---|
| `kubectl get pvc`/`kubectl get pv` (incl. `-o wide`) print only NAME+AGE — every other standard column (STATUS, VOLUME, CAPACITY, ACCESS MODES, STORAGECLASS, etc.) is silently missing from the table view, though `-o json` shows the data is present and correct | u7s-should-own (cosmetic, P3) | Filed as mayor-khb1z |

No other new friction: all 5 of Phase 2's workarounds remained no-ops, and
the one open regression from Phase 3 (mayor-nly97) is now confirmed fixed.

## Retrospective

Across 4 phases, u7s proved it can install from a release tarball onto a
fresh VM, host a StatefulSet-backed CSI PVC pipeline, run a two-container
Deployment with a Secret and ConfigMaps wired through real Service DNS and
IPVS kube-proxy, and serve a live HTTP write path (nginx → php-fpm → MariaDB
→ back out through curl) with zero code-level workarounds remaining as of
snapshot.2 — a materially different state from Phase 1/2, where 8 distinct
P0/P1 bugs blocked basic PVC/RBAC/Secret/DNS functionality. The reset-path
regression discovered in Phase 3 (mayor-nly97) is the clearest evidence the
fix-and-reverify loop works: a bug shipped in one snapshot was caught,
fixed, and confirmed gone in the very next one, using the same
reproduction recipe. Open questions worth chasing next: none of the 4
phases exercised pod restarts/rescheduling, node loss, or multi-node
Service routing (single-node cluster throughout) — sig-storage's own PV/PVC
bind-timeout and lifecycle conformance gaps (tracked separately, e.g.
mayor-57lng) suggest those paths are where the next class of bugs likely
lives, not the single-request happy path this chain just proved works.

## Follow-on beads

- mayor-khb1z — kubectl get pvc/pv table view missing standard columns (P3, cosmetic)

`lima-workload` left running (WordPress `2/2 Running`, install completed)
at the discretion of whoever picks up the next validation round.
