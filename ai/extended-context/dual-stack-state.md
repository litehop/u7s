---
as_of: 2026-10-30
kind: initiative-state
---

# Dual-stack (then IPv6-only): state as of 2026-10-30

Epic `mayor-8w6at`: a GCP-verified dual-stack u7s cluster (install, control
plane, node addressing, pod network, Services including beep LoadBalancer,
reachable over IPv4 and IPv6 from outside), then IPv6-only. Four of 13 children
are done; nothing is verified end to end yet.

## Corrections to the epic's premise

The audit (`mayor-8w6at.1`) found the earlier "already landed" items weak:
`mayor-7tqnq` only rejected dual-stack Services and `mayor-dqd2y` only added
dual node IPs to the Lima harness, not install.sh. kube-proxy runs
`mode: iptables`, not IPVS.

## Done

- #2036 (`.4`): apiserver dual Service CIDRs, per-family ClusterIP allocation,
  second `ipFamilies`/`clusterIPs`; also implements the default ServiceCIDR
  upgrade.
- #2037 (`.3`): GCP subnet `u7s-test` changed IN PLACE to IPV4_IPV6 (external
  IPv6; one-way, the IPv6 access type can never change), opt-in dual-stack VPS,
  firewall `u7s-test-allow-internal-v6` (source = subnet /64).
- #2040 (`.5`): IPv6 papercuts: `::1`/v6 SANs, `kubernetes` EndpointSlice
  family, CSR service-CIDR guard, v6-safe pod/kubelet proxy.

## Remaining, in dependency order

0. `.6` (#2047): install.sh dual `--service-cidr`/`--cluster-cidr`, per-family
   KCM `-ipv4`/`-ipv6` mask flags, IPv6 forwarding sysctl on the control plane.
1. `.7` manifests: flannel `EnableIPv6`, kube-proxy dual clusterCIDR and
   bracketed server URL, CoreDNS family, beep `--pod-cidr`. Needs `.6` and
   `rv1aw`.
2. `.8` beep: a release whose controller admits Pod backends of both families,
   then a vendored `manifests/beep.yaml` bump. The work is in the `../beep`
   tracker: `beep-6l6d` (repeatable per-family `--pod-cidr`), `beep-wt4i` (dual
   `--node-ip`), `beep-dxq6` (dual-stack smoke with a non-hostNetwork v6 pod
   backend; depends on 6l6d). Without it a v6 pod backend is rejected.
3. `.9` GCP harness: dual-stack variant of `cloud-two-node.sh` plus the upstream
   `IPv6DualStack` focus set. e2-micro saturation may force a smaller focus set
   or larger machine type.
4. `.12` (P3) upgrade an existing single-stack install to dual-stack on re-run
   (today refused).
5. `.13` (BUG) joining workers never learn the CIDRs, so they get no
   `net.ipv6.conf.all.forwarding=1`; coordinate with `rv1aw`.
6. `rv1aw` install `--iface`/`--external-iface`, multi-IP and dual-stack aware
   (dual `--node-ip`, v6 forwarding on workers). install.sh never sets
   `net.ipv4.ip_forward`; it flips on at first pod sandbox (unverified: likely
   the CNI bridge plugin).
7. `.11` Lima dual-stack rig, PR #2045: unverified VM-to-VM (only a
   single-VM smoke ran; NDP not measured). Verify on a same-network pair
   (`user-v2-workers-a`), before merge.
8. `.2` verify on GCP: node addresses, pod and Service families, AAAA/A, beep
   LoadBalancer reachable from outside over both families, upstream
   `[Feature:IPv6DualStack]` subset. Delete all VMs.
9. `.10` (P3) IPv6-only: install without IPv4, v6 `kubernetes` Service,
   DNS64/NAT64 and registry reachability on GCE.

## Notes

- Lima correction: user-v2 forwards IPv6 unicast between VMs but hands out no v6
  address and drops multicast, so Lima is not "hard IPv4-only". Seed static ULA
  addresses per VM, as beep does (`../beep` `scripts/k3s-common.sh`
  `k3s_seed_lan_v6`, `scripts/k3s-up.sh --dual-stack`). The default rig stays
  IPv4-only.
- GCP firewall: the external LB test needs its own narrow ingress rule (test
  port plus source; VMs carry no network tags, so add a tag in
  `gcp_vps_create` or scope by port), deleted afterwards; never allow-all from
  `::/0`. IAP SSH is IPv4-only, and returns 4047 for ~1 min after VM create
  (retry). Before `.2`, confirm the subnet's external /64 is not shared with
  another subnet or peering.
