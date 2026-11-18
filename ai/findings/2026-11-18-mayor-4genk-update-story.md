# Update story audit: v0.4.5 to v0.4.6 in-place upgrade

Bead: mayor-4genk
Date: 2026-11-18 (probe 08:20-08:30Z, GCP `n1-custom-1-1024`, VPS `u7s-upg-1`, deleted)

## 1. Verdict

The in-place upgrade works on a single node today: re-running v0.4.6's
`install.sh` with no flags took 99 s, kept the CA, state and unrelated pods,
and the API had one failed `/readyz` sample at a 2 s poll (about 2-4 s down).
It is mechanically sound but unverified by CI, undocumented beyond one
section, and silent about what changed: nothing tells the user the old
version, the new version, or what to read. There is no supported-path
statement, no data-format guard, no rollback, no way to learn a newer
release exists, and no automated upgrade test. The probe also exposed two
defects unrelated to upgrading (section 3).

## 2. Current mechanism

- `docs/install.md:240-269` "Upgrading": re-run the newer `install.sh` per node,
  control plane first; dual-stack variant at `:271`. Worker skew: up to 3
  minor versions older (`:166`).
- `scripts/install.sh:1927-1930`: existing install = `ca.key` or `kubeconfig`
  present; prints "existing u7s install detected -- upgrading in place".
  Worker = kubeconfig without `ca.key` (`:1936`); `--join` on one is refused (`:1946`).
- `scripts/install.sh:2755-2768`: `systemctl enable` + `restart` of apiserver,
  KCM, kubelet (units rewritten, binaries swapped); `:1875-1900` fails the run
  if `ca.key`/`ca.crt` change.
- `$STATE_DIR/config` persists iface, node name, CIDRs; mismatch refused
  (`:2027-2045`, `:867-897`). Pod MTU persisted when explicit (CHANGELOG 0.4.6).
- Version reporting: `u7s-apiserver --version` prints
  `v1.37.1+u7s-0.4.6 (commit ..., built ...)`; `kubectl version` Server shows
  the same. `docs/install.md:50` shows how to derive the tag. Workers expose
  only the kubelet version (`v1.37.1`, identical across u7s releases).
- Release discovery: `CHANGELOG.md` (curated, from 0.4.6) and GitHub Releases.
  Mirror `https://u7s.dekiru.tech/`: `/`, `/latest`, `/latest.txt`,
  `/releases.json`, `/index.json`, `/versions.txt`, `/v0.4.6/` all return 404
  (only `/install.sh` unpinned and `/<tag>/...` assets exist).
- `docs/releasing.md` has no upgrade test step; `scripts/release-gate/`,
  `scripts/e2e-install/` and `scripts/e2e-workload/` contain no upgrade case.
- Store: SQLite `objects` + `meta` tables created with `IF NOT EXISTS`
  (`crates/store/src/sqlite.rs:494-515`); no schema/version marker anywhere.

## 3. Probe results

| Check | Result |
|---|---|
| Fresh v0.4.5 install | OK, ~3 min; `Server Version: v1.37.1+u7s-0.4.5` |
| Upgrade `curl .../v0.4.6/install.sh \| sudo bash` | 99 s wall, exit 0 |
| After | `Server Version: v1.37.1+u7s-0.4.6`, binary commit `dec6f6e3`, node Ready |
| API downtime (`/readyz` every 2 s) | 1 FAIL in 132 samples (about 2-4 s) |
| CA | "Control-plane identity preserved (ca.key, ca.crt unchanged)" |
| Unrelated pods | coredns, kube-proxy, servicelb: same UID, 0 restarts |
| flannel DS pod | recreated (new image/manifest), expected |
| hostPath marker | survived (`/var/lib/u7s-marker/marker` kept its 08:23:30 timestamp) |
| Idempotent re-run | 87 s, no FAIL sample, Deployment `dep` UID unchanged, 0 restarts |
| Persisted config | `config` unchanged; no flags needed |

User-visible output of the upgrade: the one line "existing u7s install
detected -- upgrading in place, preserving cluster state and CA.", then the
same script chatter as a fresh install (apt "0 upgraded", waits), ending with
"u7s bootstrap complete". No old/new version, no changelog pointer, no
"restart of apiserver causes a brief outage" note.

Probe-exposed defects (not upgrade logic):

1. v0.4.6's `install.sh` prints, on every run (fresh install too), four
   alarming lines such as `bash: line 491: /var/tmp/u7s-install.XXXX/u7s-v0.4.6-x86_64-unknown-linux-gnu.tar.gz.part: No such file or directory`.
   Cause: `size0="$(wc -c < "$dest" 2>/dev/null ...)"` (`scripts/install.sh:489`)
   applies the `<` redirect before `2>/dev/null`. Downloads and signature
   verification still succeed. v0.4.5's log had none. Cosmetic, LOW.
2. A StatefulSet pod is deleted and recreated about every 33 s on both
   v0.4.5 and v0.4.6: `status.collisionCount: 850`, `currentRevision` !=
   `updateRevision`, and `kubectl get controllerrevisions` answers "the server
   doesn't have a resource type" (apps/v1 discovery lists only daemonsets,
   deployments, replicasets, statefulsets). Closed beads mayor-g9m9 and
   mayor-tkwj claim ControllerRevision support, so this needs triage against
   `main`. Independent of upgrading, HIGH for any stateful workload. Not
   verified beyond this one hostPath StatefulSet.

## 4. Gaps

- HIGH: no upgrade-from-previous-release test (CI, gate or Lima). Everything
  above was verified by hand once.
- HIGH (defect 2): StatefulSet recreate loop; blocks any "stateful workload
  survives upgrade" claim.
- MED: no stated supported upgrade paths (skip versions, e.g. 0.4.4 to 0.4.6?
  downgrade? snapshot to release?). Only the dual-stack note names a floor
  (`v0.4.4-snapshot.1`).
- MED: no persistent-data version guard. A downgrade opens a newer store with
  an older binary silently; no marker records which release wrote it.
- MED: no rollback or backup guidance (the g3jip scope deferred it); a failed
  upgrade has no documented recovery besides tarring `/var/lib/u7s` by hand.
- MED: upgrade output does not say from/to versions or what changed;
  CHANGELOG exists but nothing links it from the script or docs/install.md.
- MED: no way to compare installed vs latest: mirror has no static
  latest/version file; docs suggest the GitHub API (rate-limited, no IPv6).
- MED: no pre-upgrade checklist (backup, read CHANGELOG, workers last, API
  blip expected) and no dedicated upgrade guide; the section is 30 lines.
- MED: multi-node ordering is documentation only; running a worker's
  `install.sh` newer than the control plane is not refused by the script.
- LOW: workers report no u7s release version (kubelet version is unchanged
  across u7s releases), so fleet drift is invisible.
- LOW: MTU change needs a manual flannel restart (CHANGELOG-only).
- LOW: noisy `wc` stderr (defect 1).

Not probed: worker upgrade, dual-stack upgrade, 1-minor Kubernetes bump,
`--tarball` path, ARM.

## 5. Decision options (operator)

(a) Supported paths policy: N-1 only; or any 0.x to later 0.x within the same
Kubernetes minor; or "latest only, reinstall otherwise"; plus downgrade
refused (needs the data-format guard) vs unsupported-undetected.

(b) Notification (project currently never phones home):
 1. None; docs and CHANGELOG only.
 2. User-run `install.sh --check-update` fetching a static `latest` file from
    the mirror; contacts the mirror only on explicit command (the mirror
    already sees every install).
 3. Opt-in check whose result is shown passively (log line, Kubernetes Event
    or Node condition); needs a recurring outbound call and an opt-in flag.
 4. Users subscribe to GitHub release RSS/watch; zero code, zero privacy cost.

(c) Upgrade test home: release-gate extension on GCP (authoritative x86,
real VPC, slow, costs money); a separate Lima test (cheap, arm64, fast
iteration); or both (Lima per-PR, GCP at release).

## 6. Verification and docs plan

- M: `scripts/e2e-upgrade/` test: install N-1 from the mirror, deploy marker
  workload plus Deployment, upgrade, assert CA hash, UIDs, marker, /readyz
  gap bound, versions; run on Lima (and GCP per option c).
- S: install.sh prints "upgrading from <old> to <new>" and CHANGELOG URL
  (needs no policy decision).
- S: fix the `wc` redirect noise.
- M: triage the StatefulSet loop (bead needed).
- M: store format marker plus refuse-on-newer guard (after decision a).
- M: docs/upgrading.md: checklist, ordering, expected blip, backup/rollback,
  supported paths (after decision a); link from README and install.md.
- S: static `latest` file publishing, only if option b2/b3 chosen.

Raw logs: `temp/e2e/upgrade-probe-2026-11-18/` in the mayor checkout, if
still present.
