---
as_of: 2026-10-31
kind: initiative-state
---

# Dual-stack (then IPv6-only): state as of 2026-10-31

Epic `mayor-8w6at`: a GCP-verified dual-stack u7s cluster (install, control
plane, node addressing, pod network, Services including beep LoadBalancer,
reachable over IPv4 and IPv6 from outside), then IPv6-only. Install, manifests,
beep v0.7.0 and worker forwarding render and unit-test dual-stack; nothing is
verified end to end at runtime yet (`.2` on GCP, or the #2045 Lima rig).

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
- #2047 (`.6`): install.sh dual `--service-cidr`/`--cluster-cidr`, per-family
  KCM mask flags, IPv6 forwarding sysctl on the control plane.
- #2058 (`.7` render, `.8`): flannel `EnableIPv6`/`IPv6Network`, kube-proxy
  dual clusterCIDR plus bracketed v6 server URL, CoreDNS `PreferDualStack` with
  the other family's tenth host as second clusterIP, beep v0.7.0 (digest
  registry-verified) with one `--pod-cidr` per family. Single-stack goldens are
  unchanged. `.7` stays open, blocked by `rv1aw` (IFACE_IP is IPv4-only, so the
  v6 server-URL path is unexercised).
- #2061 (`.14`): seed_services reserves the secondary kube-dns IP. Boot fails
  only if another Service's spec holds a bootstrap IP; orphan sentinels warn.
- #2066 (`.13`): joining workers enable v6 forwarding from their own Node's
  podCIDRs; every node sets `net.ipv4.ip_forward=1` explicitly (the CNI bridge
  plugin was setting it at first sandbox). Follow-ups in `.15`.

## Remaining, in dependency order

1. `rv1aw` install `--iface`/`--external-iface`, multi-IP and dual-stack aware
   (dual `--node-ip`). Unblocks closing `.7`.
2. `.9` GCP harness: dual-stack variant of `cloud-two-node.sh` plus the upstream
   `IPv6DualStack` focus set. e2-micro saturation may force a smaller focus set
   or larger machine type.
3. `.12` (P3) upgrade an existing single-stack install to dual-stack on re-run
   (today refused).
4. `.11` Lima dual-stack rig, PR #2045: unverified VM-to-VM (only a
   single-VM smoke ran; NDP not measured). Verify on a same-network pair
   (`user-v2-workers-a`), before merge.
5. `.2` verify on GCP (also covers a real `install.sh --join`, never run on
   the Lima rig): node addresses, pod and Service families, AAAA/A, beep
   LoadBalancer reachable from outside over both families, upstream
   `[Feature:IPv6DualStack]` subset. Delete all VMs.
6. `.10` (P3) IPv6-only: install without IPv4, v6 `kubernetes` Service,
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
