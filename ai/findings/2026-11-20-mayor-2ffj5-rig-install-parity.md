# Local conformance rig vs shipped install: parity audit

Bead: mayor-2ffj5
Date: 2026-11-20 (read-only audit; no VM started, nothing run)

**Verdict: the rig does not represent `install.sh`. It runs a different
topology (apiserver on the Mac host, kubelet-only VM), a different
kube-proxy (host systemd binary, not the shipped DaemonSet), omits beep, adds
three add-ons users never get, and diverges in about thirty further
flags/configs. Fix the manifest gap now, and make an install.sh-driven run
the sign-off configuration; keep the host rig as a labelled dev loop.**

Sources read: `scripts/install.sh`, `scripts/u7s-start.sh`,
`scripts/conformance/{run-all,lima-start,04-start-kcm,05-start-scheduler,
01-build,02-start-apiserver,_lib,06-run-sonobuoy,lima-install-test,
lima-unrig}.sh`, `scripts/lib/flannel-render.sh`, `lima/kubelet.yaml`,
`manifests/*`, `crates/apiserver/{Cargo.toml,src/args.rs,src/pki.rs,
src/sa_keys.rs,src/handlers/proxy.rs}`, `.github/actions/e2e-focus-run`
(skimmed), the two ADRs, `manifests/README.md`.

## Shape of the two stacks

Shipped (`install.sh`): everything on one Ubuntu node under systemd.
`u7s-apiserver.service` (:2604), `u7s-kcm.service` (:2631), `kubelet.service`
(:2716), `crio.service` (apt). Scheduler embedded. kube-proxy, CoreDNS,
flannel, beep arrive as DaemonSets/Deployments from `/etc/u7s/manifests`,
auto-applied by the apiserver at boot (:2588-2594).

Rig: `u7s-start.sh` runs the apiserver and konnectivity-server as
backgrounded processes on the Mac (`u7s-start.sh:310-340`). The Lima VM holds
only kubelet (drop-in over the apt unit, `lima-start.sh:644`), CRI-O, a
systemd kube-proxy (`:983`), and a `setsid`-supervised KCM
(`04-start-kcm.sh:174`). Scheduler is a separate host process unless
`--embedded-scheduler true` is passed (`run-all.sh:246`, default empty).

## Divergence table

Impact HIGH = a spec can pass on the rig and behave differently for users,
or the reverse. "Needed" = required to run sonobuoy at all.

| # | Divergence (rig vs install) | Impact | Needed? | Fix sketch |
|---|---|---|---|---|
| 1 | beep never deployed in rig. Install ships `manifests/beep.yaml` (`install.sh:2588-2594`, rendered by `render_vendored_manifests` :1118). Nothing under `scripts/conformance/` mentions it. LoadBalancer Services and beep's node-prep initContainer (privileged, hostPath, AppArmor Unconfined) are never exercised. | HIGH | no | Stage full `manifests/` through install.sh's render (see Recommendation). |
| 2 | kube-proxy: rig runs a host systemd binary extracted from the image (`lima-start.sh:857-1000`, token kubeconfig, `config.conf` :885). Shipped is the `kube-proxy` DaemonSet (`manifests/kube-proxy.yaml`: ConfigMap config, SA-token kubeconfig to `https://IFACE_IP:6443`, privileged hostNetwork pod, ClusterRoleBinding `system:node-proxier`). Different RBAC (rig hand-rolls a ClusterRole :903), different process cgroup, different iptables/conntrack provenance (host `conntrack` pkg :925 vs image), different API path. Mode is `iptables` on both (matches). | HIGH | no | Apply shipped DaemonSet, delete the systemd path. Rig comment (:857) says hostNetwork pods looped on sandbox recreation; unverified today, and users run those pods, so it is a bug to fix, not a reason to diverge. |
| 3 | Apiserver topology. Rig: host process, kubelet reaches `host.lima.internal:PORT`; kubernetes EndpointSlice patched to the host IP (`lima-start.sh:1046`); kube-proxy/pods reach apiserver through the Mac. Install: same-node systemd unit, real InternalIP. | HIGH | by design of the rig | Run install.sh in the VM (Recommendation B). |
| 4 | Konnectivity. Rig starts konnectivity-server on the host plus a `konnectivity-agent` pod (`lima-start.sh:760-830`, `--konnectivity-proxy-addr`) so webhook/aggregated calls reach pod IPs. Install has neither (`install.sh` never mentions konnectivity) and the apiserver sits on the pod network side. Webhook, conversion, aggregated-API and CRD specs therefore take a code path users never take. Existing memory `crfs-conversion-webhook-flake-is-u7s-bug-convert-on-write` shows this class already misled triage once. | HIGH | host-apiserver only | Disappears with B. |
| 5 | NetworkPolicy engine. Rig applies `kube-network-policies` (`lima-start.sh:1097`, `run-all.sh` wait loop). Users have no NetworkPolicy enforcement (flannel has none), so NetworkPolicy specs pass locally on an engine users do not get. | HIGH | no | Operator decision D1. |
| 6 | Rig-only add-ons: `metrics-server` and `external-snapshotter` (`run-all.sh:531,543`). `manifests/README.md` says u7s deliberately does not ship them. Specs for HPA/metrics and VolumeSnapshot pass locally on APIs users lack. | HIGH | for those specs | Operator decision D1. |
| 7 | Apiserver flags the rig omits that install sets (`install.sh:2617` vs `u7s-start.sh:330-345`): `--deny-service-external-ips` (install default ON; rig off, so externalIPs specs differ), `--local-node-name` (CSR approver exemption for the apiserver-IP SAN, `args.rs:138`), `--cluster-cidr` and `--kube-dns-cluster-ip` (publish `u7s-cluster-config`; rig derives DNS from the range only), `--embedded-scheduler true`. | HIGH | no | Pass them in `u7s-start.sh`; default embedded scheduler on. |
| 8 | Scheduler. Rig default runs standalone `u7s-scheduler` on the Mac (`05-start-scheduler.sh`); install runs it embedded in the apiserver (`install.sh:2617`; OOMScoreAdjust -997). The scheduler code path, process memory accounting and restart coupling differ. | HIGH | no | Make `--embedded-scheduler true` the rig default, keep standalone behind a flag. |
| 9 | Kubelet identity/PKI. Rig signs the initial node client cert on the Mac with the CA key (`lima-start.sh:508`) and copies kubeconfig/CA into the VM; install mints a bootstrap token and runs the CSR join flow (`install.sh:1549 issue_cp_kubelet_identity`, `join_cluster`). The rig never tests the bootstrap-token/CSR/auto-approve path or `--cert-dir` under `$STATE_DIR` (`install.sh:2743`). | MED | partly | B. |
| 10 | Kubelet config. Rig (`lima/kubelet.yaml:304`): alpha gates `ClusterTrustBundle`, `ClusterTrustBundleProjection`, `PodCertificateRequest` enabled (install enables none), `serializeImagePulls:false`, `maxParallelImagePulls:10`, `registryPullQPS:0`, `staticPodPath:/tmp/kubelet-pods` vs `/etc/u7s/static-pods`, no `serverTLSBootstrap` in base yaml (added by helper script). Rig kubelet comes from apt `pkgs.k8s.io` pin; install from the tarball. Specs that need the three gates (`FeatureGate:` filtered or not) pass only because the rig turned them on. Whether 1.37 defaults them on is unverified. | MED | check per gate | Align gate list to install; if a spec needs a gate, record it as rig-only. |
| 11 | KCM. Rig: binary fetched from dl.k8s.io at the VM's kubectl version (`04-start-kcm.sh:60-75`), `--concurrent-gc-syncs=5` (rig only), no `--service-cluster-ip-range` (install passes it, `install.sh:2683`), supervisor script not systemd, signing key synced to `/var/tmp` every 2 s. Same `--controllers` list. | MED | supervisor no | `--service-cluster-ip-range`; drop `--concurrent-gc-syncs`; B replaces the supervisor. |
| 12 | Build features. `rig-test-knobs` (always on, `01-build.sh:16`): `node_proxy_ip_allowed` accepts loopback node addresses (`handlers/proxy.rs:2396`), disabling the SSRF guard that applies to every user's node proxy. `pki-test-knobs` (only with `--pki-test-*`): shortens cert/SA/intermediate lifetimes via env. `dhat` (only `--profile`): swaps allocator, +82% wall and +318% RSS at depth 50 per its own comment (`main.rs:177`). A default run is therefore not the shipped binary. | MED | rig-test-knobs yes (loopback port-forward) | Gone with B for rig-test-knobs; pki/dhat stay opt-in, and results must be tagged. |
| 13 | Resource envelope. Rig VM: 8 CPU, 8 GiB, 40 GiB (`lima/kubelet.yaml`); apiserver, scheduler and konnectivity run outside it on the Mac. Install target is a 1 GiB node with apiserver + KCM + kubelet + CRI-O + flannel/kube-proxy/beep/coredns all sharing it. OOM/eviction/DiskPressure and timing-sensitive specs are far less stressed. | MED | no | B on a deliberately small VM profile as a second tier. |
| 14 | `kubernetes` Service endpoint and API access. Install: real node IP. Rig: host gateway IP patched in after boot. A restart of the apiserver can briefly reset it to 127.0.0.1 (apiserver comment at `lima-start.sh:1041`). | MED | rig only | B. |
| 15 | Process supervision. Install: systemd, `Restart=always`, boot-enabled, `OOMScoreAdjust=-997` on apiserver/KCM. Rig: `disown`ed/`nohup`/`setsid` processes, no restart policy, killed by `reset.sh`. A crash-restart bug (e.g. apiserver restarting under load) is invisible or handled by hand. | MED | no | B. |
| 16 | CRI-O. Same pin (1.37.3-1.1), same AppArmor profile extracted from install.sh, same `10-memory.conf` (`stream_idle_timeout`) only if present in the rig VM. Rig-only: `20-test-handler.conf` runtime (needed by RuntimeClass specs), extra stacked-peer AppArmor rule and host dig/nslookup profile overrides (`lima-start.sh:360-390`, arm64 rig), `--verbose` debug drop-in. CNI plugin binaries (bridge/host-local/loopback/portmap) come from the tarball on install (`install.sh:2361`); provenance on the rig VM is not established here. | LOW | test-handler and AppArmor yes | Document; verify CNI binary provenance. |
| 17 | CoreDNS. Both render `manifests/coredns.yaml`; rig via `rig_render_coredns` (`_lib.sh:572`), install via sed in `render_vendored_manifests` (:1177). Same file, two renderers (dual-stack clusterIP rewriting differs in implementation). | LOW | no | Single renderer (Recommendation A). |
| 18 | Flannel. Rig uses install.sh's own `render_flannel` through `lib/flannel-render.sh` (awk-extract + eval) with MTU read from the NIC (`lima-start.sh:1087`); install also runs `resolve_pod_mtu` (`--pod-mtu`, beep Geneve overhead). Matches on MTU formula; the other placeholders are not rendered by the rig because it calls `render_flannel` without `cidr_sed`. Applied by `kubectl apply` after node registration, not auto-applied at apiserver boot, so the boot-time apply path (`bootstrap_apply`, fatal-on-bad-manifest) is exercised only for CoreDNS. | LOW | no | A. |
| 19 | Networking. Rig NIC is Lima `user-v2` (IPv4-only, MTU of the usernet), IPv6 ULA `fd85:N::1` added by hand (`lima-start.sh:607`) or a shared /64 with `--dual-stack`; install reads the real NIC and derives both families. Pod CIDR constants (`RIG_POD_CIDR_*`) are hard-coded copies of the install docs' defaults. | LOW | yes | Accept; keep the constants test (`test-network-flag-logic`). |
| 20 | Extras only the rig does: logrotate/journald limits, SSH key for `[Disruptive]` specs, nfs-common/conntrack apt installs, br_netfilter modprobe, sonobuoy LimitRange, `FEATUREGATE_LABEL_FILTER` allow-set. Install loads `br_netfilter` itself (`install.sh:2294`) and sets ip_forward persistently. | LOW | yes | Test-harness only; keep. |

Not divergent: cgroups. Neither side sets `kubeReserved`, `systemReserved`,
`cgroupDriver` or QoS flags; both use kubelet defaults. The only resource
setting in install is Go env (`GOMEMLIMIT/GOGC/GOMAXPROCS`) and
`OOMScoreAdjust`, mirrored for kubelet and KCM in the rig, absent for the
rig's host apiserver. Not divergent: flannel manifest and `mode: iptables`.

Related third path (not in scope, noted): `.github/actions/e2e-focus-run`
brings up yet another topology (own kube-proxy binary, only `coredns.yaml`
staged in the manifest dir, no beep, no `rig-test-knobs`). Same drift risk;
it should consume whatever shared staging comes out of this work.

## Recommendation

Two independent fixes; do both in order.

**A. Stage the shipped `manifests/` folder through install.sh's own render
(cheap, do first).** `scripts/lib/flannel-render.sh` already extracts
`render_flannel`/`derive_pod_mtu` from install.sh with awk+eval; extend it to
extract `render_vendored_manifests` plus the helpers it calls
(`default_cluster_dns`, `parse_cidr_list`, `cluster_families_from_cidrs`) and
a small shim that sets the globals it reads (`IFACE`, `IFACE_IP`,
`POD_CLUSTER_CIDR*`, `SERVICE_CIDR*`, `CLUSTER_DNS`, `KUBE_VERSION`,
`POD_MTU`). `u7s-start.sh` then copies `manifests/*.yaml` to `$MANIFEST_DIR`
and renders, replacing the CoreDNS-only staging (`u7s-start.sh:197`) and the
separate `kubectl apply` of flannel. Every future shipped manifest is covered
automatically, and the apiserver's boot-time apply path gets exercised for
all of them. Caveats:
- It pulls in kube-proxy.yaml, so the rig's systemd kube-proxy must go in the
  same change (a DaemonSet and a host kube-proxy would fight over iptables).
  The DaemonSet's server URL is `https://IFACE_IP:6443`; the rig's apiserver
  port varies per slot and lives on the Mac, so the shim must substitute the
  slot port and host address, and the serving cert must carry that SAN.
- `render_vendored_manifests` assumes the CNI MTU; the shim reads the VM NIC.
- mayor-qwf1z (beep only when a LoadBalancer Service exists) is fine as long
  as the conditional lives in install.sh or the apiserver, since the rig then
  inherits it. If it lives only in an install.sh branch, extract that branch
  too. Do not hard-code "always deploy beep" in the rig.

**B. Make an install.sh-driven run the conformance sign-off configuration.**
`lima-install-test.sh` already unrigs a rig VM and runs the checkout's
install.sh there; `scripts/e2e-install/cloud-two-node.sh` does real installs
on GCP. A `run-all.sh --install` mode would build a tarball, run install.sh on
the VM (and `--join` for a second node), then run sonobuoy from the host
against the VM's kubeconfig. That removes in one step the host apiserver,
konnectivity, loopback node proxy (`rig-test-knobs`), host-signed kubelet
cert, supervisor scripts, EndpointSlice patching, standalone scheduler and
the KCM/kube-proxy variants: divergences 2-4, 7-9, 11, 12 (rig-test-knobs),
14, 15 and most of 17-18 vanish rather than being chased one by one.
Costs, none measured:
- Run time: install.sh adds apt + image pulls + `wait_for_cluster_ready`
  (its own comment estimates 4-10 min on e2-micro); a golden VM clone with
  CRI-O preinstalled should cut that. The Mac-native rebuild loop is lost:
  each change needs a Linux tarball (cross-build or build in the VM; `~` is
  mounted read-only, `lima/kubelet.yaml`).
- Debuggability: logs live in `journalctl` on the VM, not `temp/u7s/*.log`.
  install.sh has no `--verbose` or `RUST_LOG` hook; units carry none, so
  the harness would need a systemd drop-in for `RUST_LOG`, KCM `--v`, and
  the dhat/pki feature builds (those would still be opt-in builds).
- Resource fidelity improves: use a small VM profile (1-2 GiB) as a second tier
  to approximate the real target.

Keep the host-apiserver rig as the fast dev loop, but stamp each run's
`build.json` with `topology=host-rig` and a pointer to this doc so a
host-rig PASS is never read as a delivered-behaviour PASS. Gate releases on
the install-driven run.

## Operator decisions (separate from the fixes)

D1. Rig-only add-ons (`kube-network-policies`, `metrics-server`,
`external-snapshotter`). Options:
- (a) Keep them rig-only, matching `manifests/README.md` and the ADR, and tag
  every spec that needs them "rig-only, not delivered behaviour" in the run
  summary so the pass count is reported without them. Needs a spec list
  (NetworkPolicy, `[sig-instrumentation] Metrics`/HPA, VolumeSnapshot suites).
- (b) Ship NetworkPolicy enforcement by default. Contradicts nothing in the
  ADRs, but adds a DaemonSet and a new default surface.
- (c) Ship nothing and run without them, accepting the failures as the
  honest delivered result.
My read: (a) now; (b) is a product call on whether a distro that accepts
NetworkPolicy objects but does not enforce them is acceptable.

D2. Whether the install-driven run (B) replaces or only supplements the host
rig for release sign-off. My read: supplement for dev, replace for sign-off.

D3. Rig-enabled alpha kubelet gates (row 10). If a spec genuinely needs
`PodCertificateRequest`/`ClusterTrustBundle`, either ship them in install or
tag the specs rig-only.

## Not verified

- No VM or stack was started. Divergences are read from source only.
- Whether the three kubelet gates in row 10 are default-off in 1.37.
- Where the rig VM's CNI plugin binaries come from.
- The historic "hostNetwork pods loop on sandbox recreation" claim at
  `lima-start.sh:857` (row 2): needs one runtime check, scheduling the shipped
  kube-proxy DaemonSet on a rig VM.
- Wall-clock cost of option B.
