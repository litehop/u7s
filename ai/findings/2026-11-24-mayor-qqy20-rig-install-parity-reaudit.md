# Rig vs install parity: re-audit after #2206/#2210/#2214/#2216

Bead: mayor-qqy20
Date: 2026-11-24 (read-only; no VM started, nothing run; main at 1cd5ebf7)

**Verdict: `--install` mode now delivers the same control-plane configs as
`install.sh` (it runs `install.sh`), so the remaining config drift is in the host
rig's kubelet/node setup, the CI action's whole bring-up, and the run-meta
bookkeeping of rig-only additions; the host-side apiserver, konnectivity and
`rig-test-knobs` are structural to the host rig and are resolved by `--install`
being the sign-off path, not by more mirroring.**

Prior audit: `archive/mayor-2ffj5-findings:ai/findings/2026-11-20-mayor-2ffj5-rig-install-parity.md`.
Sources read: `scripts/install.sh`, `scripts/u7s-start.sh`,
`scripts/conformance/{run-all,install-run,install-bringup,lima-start,lima-unrig,
lima-install-test,04-start-kcm,01-build,06-run-sonobuoy,_lib}.sh`,
`scripts/lib/flannel-render.sh`, `scripts/release-gate/build-arm64-tarball.sh`,
`lima/kubelet.yaml`, `.github/actions/e2e-focus-run/action.yml`,
`.github/workflows/e2e-focus-resources/kubelet-config.yaml`,
`crates/apiserver/src/{tls.rs,args.rs}`.

## Prior items verified fixed on main

| Prior row | State on main | Evidence |
|---|---|---|
| 1 beep missing, 17/18 manifest renderers | Fixed: every `manifests/*.yaml` staged through install.sh's own `render_vendored_manifests` | `_lib.sh:559-591` (`rig_stage_manifests`), `scripts/lib/flannel-render.sh:8-41` |
| 2 host systemd kube-proxy | Fixed: DaemonSet shipped; old unit removed | `lima-start.sh:773-781` |
| 7 missing apiserver flags | Fixed | `u7s-start.sh:128` vs install `ExecStart=$BIN_DIR/u7s-apiserver` (`install.sh:2646`) |
| 8 standalone scheduler | Fixed: `EMBEDDED_SCHEDULER` defaults to true | `run-all.sh:500` |
| 11 KCM `--service-cluster-ip-range`, `--concurrent-gc-syncs` | Fixed | `04-start-kcm.sh:36`, `:171-188` vs `install.sh:2712` |
| 10 alpha kubelet gates | Fixed (the three are GA default-on in 1.37; rig no longer sets them) | `lima/kubelet.yaml:290`, `test-kubelet-featuregates-logic.sh` |
| 3/4/9/12/14/15 host topology | Resolved for `--install`: real systemd units, no konnectivity, no loopback node proxy, CSR join flow | `install-bringup.sh:94`, tarball built without features `build-arm64-tarball.sh:27-30` vs `01-build.sh:16` |
| 5/6 rig-only add-ons | Allowed; `--install` labels them `u7s.io/conformance-rig-only=true` | `install-bringup.sh:122-129`, `_lib.sh:588` |
| 16 AppArmor | Fixed: shared rig-only step in both modes, installed profile untouched | `_lib.sh:638-665`, `lima-start.sh:334-358` |

## Remaining divergences

Install-side lines are in `scripts/install.sh`. "Allowed" = a userspace addition conformance needs
(operator rule 2026-11-20). HR = host rig (`run-all.sh` default), IM = `--install` mode.

| # | Area | Rig vs install | Rig side | Install side | Allowed? | Sev | Bead |
|---|---|---|---|---|---|---|---|
| 1 | Kubelet config yaml | HR writes its own `/etc/kubelet-config.yaml`: `staticPodPath: /tmp/kubelet-pods`, `serializeImagePulls: false`, `maxParallelImagePulls: 10`, `registryPullQPS: 0`, gate `AtomicWriteVolumeUserFields: true` (default-off alpha), no `authentication.x509.clientCAFile`. Install ships none of these; HR passes specs (projected `defaultUser`/`user`, CSI image-pull bursts) that IM/users cannot. | `lima/kubelet.yaml:290`, `lima-start.sh:525-590` | `install.sh:1212-1240` | no | MED | NEW (A) |
| 2 | Kubelet identity, cert path, unit | HR: node client cert signed on the host with the CA key (365d), files at `/etc/kubelet-client.{crt,key}`, `--client-ca-file` CLI flag with only the cluster CA, no `--cert-dir` (rotated certs land in `/var/lib/kubelet/pki`, the reset-survival bug `install.sh:2517-2528` documents), kubelet from apt with a drop-in `ExecStart=` override, extra `--v=2`, `TZ=UTC`, `LimitNOFILE`. Install: bootstrap-token CSR join, `--cert-dir=$STATE_DIR/kubelet/pki`, own unit. Gate list duplicated by hand. | `lima-start.sh:473-540`, `:604-647` | `install.sh:2529`, `:2772`, `kubelet_round2_flags` | no | MED | NEW (B); gate-list duplication noted on mayor-r2omk |
| 3 | Host-side apiserver | HR runs `u7s-apiserver` on the Mac, `--advertise-address https://127.0.0.1:PORT`, own `--manifest-dir`, `kubernetes` EndpointSlice patched after boot, kube-proxy URL via `host.lima.internal`. Structural. | `u7s-start.sh:343-374`, `lima-start.sh:818-830` | `install.sh:2646` | no (topology) | DEFER | covered: `--install` is the sign-off path; run-meta gap in NEW (C) |
| 4 | Konnectivity | HR only: server on the Mac, agent pod, `--konnectivity-proxy-addr`. Users get none (`install.sh` never mentions it). Webhook/aggregation specs take a path users never take in HR. | `u7s-start.sh:185-310`, `lima-start.sh:659-770` | none | no (topology) | DEFER | NEW (C) records it in run-meta |
| 5 | `rig-test-knobs` build | HR always builds with `rig-test-knobs` (node proxy accepts loopback nodes, SSRF guard off). IM tarball builds default features. `pki-test-knobs`/`dhat` opt-in. | `01-build.sh:16`, `proxy.rs:2393-2410` | `build-arm64-tarball.sh:27-30` | no (needed for the loopback port-forward) | LOW | NEW (C) records features in run-meta/build.json |
| 6 | Rig-only add-ons: label and record | IM labels the three add-ons and records `rig_only_addons`. HR applies the same three unlabelled (`kubectl apply`, `kube-network-policies` during VM setup, before KCM) and `run-meta` has no `rig_only_addons` line. Also unrecorded in both modes: `20-test-handler.conf` runtime, `[Disruptive]` ssh key, sonobuoy LimitRange, nfs-common, journald/logrotate limits. | `run-all.sh:573-594`, `lima-start.sh:879`, `_lib.sh:667-679`, `lima/kubelet.yaml:143` | n/a | yes (additions) but must be recorded | MED | NEW (C) |
| 7 | nfs-common | Installed only by `lima-start.sh` (host path). IM never installs it, so `mount -t nfs` specs behave differently from HR; neither install.sh nor the golden provides it. Needs one live run to see which specs are affected. | `lima-start.sh:783-789` | none | yes (userspace addition) | MED | NEW (E) |
| 8 | Node prep not applied by HR | IPv6 forwarding sysctl (dual-stack) absent in HR (`rg forwarding` in `scripts/conformance` finds nothing); CRI-O `10-memory.conf` (`stream_idle_timeout`) absent in HR; sysctls are `sysctl -w` only, not persisted. IM gets all of them from install.sh. CNI plugin binary provenance in the HR VM unverified (install stages tarball binaries to `/opt/cni/bin`). | `lima-start.sh:792-818` | `install.sh:2309-2335`, `:2391-2392` | no | MED | NEW (D) |
| 9 | Shipped binary carries a rig SAN | `build_server_sans` always adds `host.lima.internal` to every user's serving cert; the rig could pass `--apiserver-cert-extra-sans` instead. | `tls.rs:579`, `lib.rs:3115` | `install.sh:2188` | no | LOW | NEW (F) |
| 10 | CI e2e-focus action | A third stack: admin static token (`--token-auth-file`), none of the install apiserver flags, standalone scheduler, KCM `--controllers` lacks `bootstrap-signer-controller,token-cleaner-controller` and the authn/authz kubeconfigs, kubelet has no gate flags, `authorization: AlwaysAllow`, `anonymous: false`, `staticPodPath: /tmp/kubelet-pods`, own kube-proxy binary, only `coredns.yaml` staged. Features are default (no rig-test-knobs): fine. | `action.yml:246-300`, `:343-360`, `:601-652`, `e2e-focus-resources/kubelet-config.yaml` | `install.sh:2646`, `:2712`, `:2529` | no | MED | mayor-3myx0 (re-scope note) + NEW (G) |
| 11 | VM provision on every boot | `lima/kubelet.yaml` re-runs on every boot: re-enables `10-crio-bridge.conflist`, rewrites `/etc/kubelet-config.yaml` and the kubelet drop-in. IM relies on `lima-unrig.sh` at install time only; a stop/start of an IM VM without re-running install.sh leaves a rig kubelet unit over install's. | `lima/kubelet.yaml:143-156`, `:290-291` | `install.sh:2338-2352` | no | LOW | NEW (H) |
| 12 | KCM supervision, binary, signing mirror | HR runs a downloaded KCM under `kcm-supervisor.sh` (not systemd, no `OOMScoreAdjust`), signing key mirrored to `/var/tmp` because a host mount delivers no inotify. Flags match. | `04-start-kcm.sh:131-188`, `kcm-supervisor.sh` | `install.sh:2712-2716` | no (topology) | LOW | mayor-r2omk (flag derivation) |
| 13 | Flag/unit mirrors are hand-copied | Parity test hard-codes expected flags; unit list hand-copied. | `test-install-flag-parity-logic.sh`, `clear-native-units.sh` | `install.sh:2646`, `:2712` | n/a | MED | mayor-r2omk |
| 14 | Manifest apply confirmation, per-node NIC | HR SIGHUPs once; beep `--uplink-iface` on a 2-node rig. | `lima-start.sh:871` | `install.sh:2616-2625` | n/a | LOW | mayor-azbbb |
| 15 | IM coverage gaps | `--install` rejects `--dual-stack`, `--service-cidr`, `--extra-node`; second node is mayor-06ha8. Dual-stack and custom CIDRs are untested on a real install path. | `run-all.sh:420-428` | `install.sh:118-120` | n/a | DEFER | 2-node: mayor-06ha8; rest: operator call |
| 16 | Resource envelope | 8 CPU / 8 GiB / 40 GiB VM for both modes vs the 1 GiB install target. `scripts/release-gate/u7s-vps-1g.yaml` exists as a second tier. | `lima/kubelet.yaml` | docs | n/a | DEFER | none (second tier is an operator call) |

Unverified (needs a VM): which specs NFS-mode IM drops (row 7); whether the rig's CNI plugin
binaries come from the cri-o apt package (row 8); whether `AtomicWriteVolumeUserFields`
becomes default-on in a later release (row 1).

## Existing children

- mayor-r2omk: still correct; its line refs (`~2636`, `~2702`) are now `install.sh:2646`/`:2712`. Also derive the kubelet gate list (`kubelet_round2_flags`) that `lima-start.sh` hand-copies.
- mayor-3myx0: too narrow. CI diverges on apiserver, KCM, scheduler and kubelet configs too (row 10); NEW (G) takes the wider job.
- mayor-azbbb, mayor-06ha8: unchanged.
