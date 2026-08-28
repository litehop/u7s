Bead: mayor-o04lc

# Golden Lima instance spec — Phase A of golden-clone initiative

## Recommendation

Bake every install step whose output is identical across all runs of a role
(packages, binaries, kernel modules, static config); leave anything
per-run-derived (identity, secrets, per-node addressing, tunables that churn)
to the starter script. One golden template covers every topology today.

## Baked-vs-runtime table

| # | Item | Decision | Why |
|---|---|---|---|
| 1 | Base OS + kernel + systemd | Baked | Already what `images:` pins; nothing in provisioning mutates the base image itself. |
| 2 | apt updates | Baked, frozen at bake time | `apt-get update`/installs run once during bake. The one runtime `apt-get install -y ipset conntrack nfs-common` in `lima-start.sh` (lines ~813-822) moves into the golden's provision script per the operator's "install all our dependencies" direction — nothing about those three is per-run. |
| 3 | kubelet, cri-o + runc/crun/conmon, CNI plugins, crictl, sonobuoy, ipset, conntrack, nfs-common, iptables, ip, jq | Baked | Install-once, version-pinned; none regenerate per run. `ipvsadm` folds in too — today it's only ad-hoc `apt-get`'d by `instrument-vip-capture.sh` for debugging; baking it removes that manual step. `socat` isn't referenced anywhere in the current provisioning path — omit unless a concrete caller surfaces. `sqlite3`: not applicable — u7s-apiserver (rusqlite) runs on the Mac host, not inside the VM; nothing in-VM needs the CLI. |
| 4 | Systemd unit files (kubelet.service, crio.service, kube-proxy.service) | Split | `crio.service` ships with the apt package — baked, `systemctl enable --now` already happens at bake time. `kubelet.service`'s base unit is baked but disabled (kubelet.yaml already does `systemctl disable kubelet` post-install); `kube-proxy.service` doesn't exist until first start. Both units' actual `ExecStart` args (hostname-override, node-ip, ports) are per-VM/per-run — starter continues to write/overwrite the drop-in (`kubelet.service.d/u7s.conf`) and the full unit (`kube-proxy.service`) every run, unchanged from today. |
| 5 | `/etc/crio/crio.conf` + `crio.conf.d/20-test-handler.conf` | Baked | Static package default + one CI-parity drop-in; identical across every node and run. |
| 6 | `kubelet.service.d/` drop-ins (GOMEMLIMIT etc.) | Runtime | Named in the bead as the thing likely to keep changing as Round-2 tuning lands — baking a value the starter overwrites every run anyway buys nothing and adds a staleness trap. Starter already writes this drop-in unconditionally each run (`lima-start.sh` line 538); keep that. |
| 7 | TLS certs (CA, apiserver, kubelet client/serving) | Runtime | Per-cluster secrets signed against a CA generated fresh per apiserver run. Baking any of these means a private key sitting inside a shared image — a real security defect, not just wasted work, and pointless anyway since every cert is per-run. |
| 8 | kubeconfig | Runtime | Embeds the per-run apiserver's port/cert; `lima-start.sh`'s own header already documents "just re-run this script" as the re-provisioning contract. |
| 9 | Lima cloud-init (users, SSH keys) | Baked | `kubelet.yaml` declares no custom users/keys today — Lima's stock cloud-init default is already static across runs. |
| 10 | Per-node CNI conflist rewrite (pod subnet, ipMasq), inter-node iptables NAT rules, journald/logrotate tuning, `modprobe ip_vs*`/`br_netfilter` | Runtime | Pod subnet is per-node-slot (`POD_SUBNET_OCTET`); NAT rules and inter-node routes depend on cluster topology at join time; journald/logrotate config is idempotent housekeeping already safely re-applied every invocation. Kernel module *load* doesn't survive `limactl stop`/clone regardless of bake, so it must stay in the starter no matter what. |

## Design decisions resolved

1. **Single golden template**, not per-role. Every current topology (single
   node, 2-node, N-node conformance) already provisions from one
   `lima/kubelet.yaml` base and diverges only via post-boot subnet/network
   patches — no role needs a different package set today. Per-role images
   cost more disk and bake cycles for zero measured benefit; revisit only if
   a genuinely divergent package set appears.
2. **Version pinning: keep today's convention** — the pinned Ubuntu image
   URL in `images:`, plus the explicit major.minor/version pins already in
   the provision script (cri-o 1.36, kubelet 1.36, crictl v1.36.0, sonobuoy
   0.57.3). No new apt-snapshot or package-hash pinning layer: the script
   already re-resolves latest patch within each pinned line at bake time,
   and changing that pinning granularity is a separate concern from this
   bead's baked-vs-runtime split.
3. **Golden lives as a stopped `lima-golden-<role>` VM in each operator's own
   `~/.lima/`**, produced by a bake script that runs the existing
   `lima/kubelet.yaml` provision to completion, then stops (never deletes)
   the instance. No shared image/registry: `limactl clone`'s copy-on-write
   only works within one host's filesystem (mayor-7agkf), so a shared
   artifact would need its own distribution pipeline for no clone-speed
   benefit.

## Sequencing

Phase B may proceed after this doc is approved by the operator; Phases C, D
follow B.

## Open questions for the operator

None — all three decisions above are picked with rationale; flag disagreement
in review rather than blocking on a question here.
