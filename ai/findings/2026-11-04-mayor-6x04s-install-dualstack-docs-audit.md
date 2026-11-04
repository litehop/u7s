# Install + dual-stack docs audit vs shipped behaviour (2026-11-04)

Bead: mayor-6x04s

**Answer:** the user-facing docs are accurate for the single-node install and worker upgrade but say nothing about dual-stack, joining a worker, LoadBalancer, uninstall or the kernel >= 6.6 requirement; the top fix is a README "Dual-stack" section plus a rewritten control-plane upgrade section built from `install.sh --help` and the #2100 upgrade warning.

Audited at main `2b8dc2ab`. Docs in scope: `README.md`, `manifests/README.md`, `examples/e2e/wordpress/README.md`, `scripts/install.sh` header, `--help` and error text, `deploy/get-u7s/README.md`. Style guide: `docs/style-guide.md`. Pending, not flagged: kubectl/CNI moving into the tarball (mayor-r4umz) will change `install.sh:2072-2097` and any README prose about apt.

Not verified: README memory figures (450/320 MiB, 80-pod zram numbers); the `curl | bash` token-from-stdin behaviour; that the README public key matches the real signing key (releases do carry `.sig` assets: `gh release view v0.4.3-snapshot.4` lists `install.sh.sig` and tarball `.sig`/`.sha256.sig`; the openssl verification was not run).

## Findings

### F1 (HIGH) Control-plane upgrade section omits the single-to-dual recipe

- Doc: `README.md:96-100` says "re-run with no flags".
- Code: `install.sh:741-770` accepts `--service-cidr <existing>,<other-family>` and `--cluster-cidr <existing>,<other-family>` on an existing install and sets `DUAL_STACK_UPGRADE`; any other change is refused (`install.sh:771-776`). `install.sh:2522-2527` prints the follow-up: existing Nodes keep single-stack `spec.podCIDRs`, so each Node must be drained and deleted, kubelet restarted, flannel pods deleted (`-n kube-flannel -l app=flannel`) and the control-plane label re-applied; a joined worker must be re-joined.
- A user who follows the README stays single-stack with no hint that dual-stack exists.
- Fix: add an "Upgrading to dual-stack" numbered procedure (including that the node needs an address of each family, `install.sh:69-71`, `854`), quoting the commands from `install.sh:2526`.

### F2 (HIGH) No dual-stack install documentation anywhere user-facing

- Doc: README has no mention of `--service-cidr`, `--cluster-cidr`, `--node-ip`, `--cluster-dns` or IPv6.
- Code: the script header (`install.sh:60-84`) documents the flags and `--node-ip` semantics. `--help` (`install.sh:109-153`) lists `--service-cidr/--cluster-cidr/--cluster-dns` but NOT `--node-ip` (parsed at `install.sh:215`, env `U7S_NODE_IP`). The only other mention is `docs/dev-setup.md:138` (a cloud test script's `--dual-stack`).
- Fix: README "Dual-stack install" section with a copy-pasteable example (`--service-cidr 10.96.0.0/12,fd00:96::/108 --cluster-cidr 10.244.0.0/16,fd00:244::/56`, optional `--node-ip`), the "fixed at first install" rule, the IPv6 forwarding sysctl install writes (`install.sh:2019-2023`), and a note that IPv6-only and mixed-stack are unsupported (backlog mayor-8w6at.10). Add `--node-ip` to `--help`.

### F3 (HIGH) Kernel >= 6.6 and network/OS prerequisites undocumented

- Doc: `README.md:15` says "fresh Ubuntu LTS host".
- Code: `install.sh:259-268` hard-fails below kernel 6.6 (beep eBPF floor); Ubuntu 22.04 GA ships 5.15, so "Ubuntu LTS" is not sufficient. The install needs apt access to `slc-mirror.opensuse.org` (CRI-O, `install.sh:1969-1975`) and `pkgs.k8s.io` (kubectl, kubernetes-cni, `install.sh:2072-2097`). Interface auto-detect (`install.sh:1902-1913`) accepts only `en*/wl*/ww*/eth[0-9]*`. Only `x86_64-unknown-linux-gnu` assets are published.
- Only `manifests/README.md:31` mentions the kernel, in a maintainer-facing component README.
- Fix: a README "Prerequisites" list: Ubuntu with kernel >= 6.6 (24.04), x86_64, systemd, root, outbound HTTPS to the hosts above, OpenSSL >= 3.0, and the hardware minimum (F11).

### F4 (MED) No "join a worker" procedure

- Doc: `--mint-join-token` appears only inside the upgrade bullets (`README.md:107`); `--join` has no how-to.
- Code: `install.sh:1040-1072` prints a join command ending in `--tarball <path>`; a `curl | bash` user has no tarball path (`--tarball-url` exists). The token is read from a TTY prompt or piped stdin (`install.sh:1200-1212`), which conflicts with `curl ... | sudo bash` (stdin is the script), so the worker needs the saved script. A joiner learns Service/pod ranges from `kube-system/u7s-cluster-config` (`install.sh:75-79`), so it needs no CIDR flags; its `--node-ip` must fit the cluster's families.
- Fix: README "Add a worker" numbered steps: (1) on the control plane, `sudo bash install.sh --mint-join-token` (script saved first); (2) on the worker, download `install.sh`, run `sudo bash install.sh --join https://<cp-ip>:6443 --ca-cert-hash sha256:<hash>` and enter the token at the prompt; (3) `kubectl get nodes`. Change the hint at `install.sh:1070-1071` to mention `--tarball-url`.

### F5 (MED) LoadBalancer (beep) is not documented for users

- Doc: only `manifests/README.md:28-40` (maintainer-oriented). README never says u7s ships a LoadBalancer provider or how to use it. `examples/e2e/wordpress/README.md:35-36` says "`type=LoadBalancer` needs beep, which the conformance rig does not run", which reads as if beep is optional.
- Code: `manifests/beep.yaml:1` (beep v0.7.1) is auto-applied by default; `install.sh:259-268` refuses older kernels because of it.
- Fix: README "Expose a Service" section: example `type: LoadBalancer` Service, where the address appears (confirm against a live cluster before writing), the `externalTrafficPolicy` / `sessionAffinity` caveats (move from `manifests/README.md:31-37`), kernel >= 6.6, `ipFamilyPolicy` for dual-stack.

### F6 (HIGH, small) manifests/README.md pins a stale beep version

- Doc: `manifests/README.md:29` and `:40` say beep v0.6.0 and link `blob/v0.6.0/deploy/README.md`.
- Code: `manifests/beep.yaml:1` is "Vendored from litehop/beep v0.7.1" (#2096).
- Fix: drop the version from prose ("see the header of `beep.yaml`") so it stops rotting.

### F7 (MED) README calls the signing key a placeholder; releases are signed

- Doc: `README.md:38` "PLACEHOLDER until the first signed release"; the comment at `install.sh:368-371` says "empty until the operator generates the key".
- Evidence: the key is non-empty (`install.sh:373`), the release workflow refuses an empty key (`release-tarball.yaml:192-197`), and the latest release (`v0.4.3-snapshot.4`, 2026-11-04T00:00:53Z) carries `.sig` assets. A user reading "placeholder" may skip verification.
- Fix: remove the PLACEHOLDER wording in README and the install.sh comment once the operator confirms the key is the production key. If it is not, delete the key block rather than publish a key users cannot trust.

### F8 (MED) Interface default is described wrongly

- Doc: `README.md:66` and `--help` (`install.sh:123`) say "first non-loopback interface".
- Code: `install.sh:1902-1913` takes the first interface matching `en*|wl*|ww*|eth[0-9]+`; bond/bridge/VLAN hosts fail with "pass --iface explicitly". The header (`install.sh:60`) already says "physical".
- Fix: "first physical interface (`en*`, `wl*`, `ww*`, `eth*`)" in README and `--help`.

### F9 (MED) Missing: uninstall/reinstall, logs, config locations

- No doc collects the layout: state dir `/var/lib/u7s` and install config `/var/lib/u7s/config` (`install.sh:278-281`), binaries `/opt/u7s/bin`, manifests `/etc/u7s/manifests`, static pods `/etc/u7s/static-pods`, CRI-O drop-in `/etc/crio/crio.conf.d/10-memory.conf`, `/etc/sysctl.d/u7s-*.conf`, `/etc/modules-load.d/u7s-br-netfilter.conf`; units `u7s-apiserver`, `u7s-kcm`, `kubelet`, logs via `journalctl -u <unit>` (cited in error text, e.g. `install.sh:310`).
- There is no uninstaller. The "start over" recipes are scattered in errors: `systemctl stop kubelet; rm -rf /var/lib/u7s` (`install.sh:1561`, `1601`, `1749`); `install.sh:773` for the control plane. None removes CRI-O, apt sources, units or sysctl files.
- Fix: README "Files, logs and reinstalling" with the path/unit list and a reset recipe (stop `kubelet u7s-kcm u7s-apiserver`, `rm -rf /var/lib/u7s`, re-run), stating that there is no uninstaller and what remains. An uninstaller is a feature, not a doc fix.

### F10 (MED) kubectl logs/exec not mentioned

- Doc: README never says logs/exec work. `--help` documents one topology limit (`install.sh:136-141`); #2087 added SPDY exec/attach.
- Fix: one README sentence and example (`kubectl --kubeconfig=/var/lib/u7s/kubeconfig logs <pod>`, `exec -it <pod> -- sh`), confirmed on a live node, plus the topology limit.

### F11 (MED) Hardware minimums not stated as requirements

- Doc: `README.md:4` ("1 vCPU / 1 GiB is normal") and `:119-123` give figures but no minimum for disk, no first-boot time expectation, no mention that readiness waits up to 20 min (`U7S_READY_TIMEOUT_SECONDS`, `install.sh:96-99`, `1440`: 4-10 min measured on 10 GB pd-standard e2-micro).
- Gate shape: bd memory `release-gate-vm-shape-n1-custom-1-1024`: 1 dedicated vCPU, 1 GiB, no swap (README `:128` already says no swap).
- Fix: prerequisite bullet "Minimum: 1 dedicated vCPU, 1 GiB RAM, about 10 GB disk (the release gate runs this shape); first boot takes 4-10 min". Re-check the disk figure before writing.

### F12 (LOW) README points curl-installed users at a repo path

- Doc: `README.md:67` "see `scripts/install.sh --help`"; a user who ran the one-liner has no `scripts/` directory.
- Fix: "run `bash install.sh --help` on the downloaded script"; add `--node-ip` to usage (see F2).

### F13 (LOW) Style-guide deviations in README

- Style rules 6/7: step 1 and step 2 of Quick start mix prose and commands in one list item (`README.md:17-50`, `:63-69`); the 1 GiB section's bullets hold procedures. Rule 5: "snapshot", "prerelease" and "release" are used interchangeably (`:17-19`).
- Fix: apply during the F1-F5 rewrite; no standalone bead.

### F14 (LOW) deploy/get-u7s/README.md open item will rot

- `deploy/get-u7s/README.md:35` "both existing releases are prereleases" is already stale (`gh release list` shows at least three prereleases).
- Fix: "every release so far is a prerelease".

### F15 (LOW) wordpress example is test material

- `examples/e2e/wordpress/README.md:8-18` uses untagged code fences (rule 6) and cites the "conformance rig". It is e2e fixture documentation; keep it, but label it as a test fixture and fix the beep sentence (F5).

## Install-story completeness

| Task | Doc status |
|---|---|
| Single-node install | Documented (README Quick start); prerequisites missing (F3). |
| Join a worker | Missing (F4). |
| Dual-stack at install | Missing (F2). |
| Upgrade single to dual | Missing; README upgrade section implies "no flags" (F1). |
| LoadBalancer Service | Missing for users (F5). |
| kubectl logs/exec | Missing (F10). |
| Uninstall/reinstall | Missing; no uninstaller exists (F9). |
| Logs and config locations | Missing (F9). |
| Hardware minimums | Partial (F11). |

## Delete-vs-fix

Nothing is wrong enough to delete wholesale. Remove the README key block if the operator cannot confirm it is the production key (F7). Remove the beep version from `manifests/README.md` instead of bumping it (F6).

## Fix beads

(appended below)
