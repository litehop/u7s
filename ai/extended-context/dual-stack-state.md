---
as_of: 2026-11-03
kind: initiative-state
---

# Dual-stack (then IPv6-only): state as of 2026-11-03

Epic `mayor-8w6at`: the dual-stack goal is met. GCP verification passed
2026-11-02/03 on `v0.4.3-snapshot.2` (main 0c2f4398); IPv6-only is the
remaining phase.

## Verified on GCP

- Install plus a real `--join` of a second node.
- v4 and v6 node IPs and podCIDRs; dual ClusterIPs; CoreDNS A and AAAA.
- Pod-to-pod and pod-to-Service over both families, cross-node.
- beep LoadBalancer over v4 and v6 from an in-subnet client and from an
  outside-VPC probe: refused before the firewall rule, admitted after.
- Upstream sonobuoy focus `IPv6DualStack|dual-stack|DualStack|ipFamilyPolicy`:
  30/30.
- An IPv6-primary single node (kube-proxy via bracketed `https://[v6]:6443`)
  also passes (`.21`).

## What made it pass

- #2036, #2047, #2058, #2061, #2066: apiserver dual Service CIDRs, install
  dual CIDRs, flannel/kube-proxy/CoreDNS/beep v0.7.0 dual rendering, secondary
  kube-dns IP reservation, worker v6 forwarding. kube-proxy is `mode: iptables`.
- #2076: node address lists (`--iface` covers all families, `--node-ip`).
- #2078: node families must match the cluster's. Workers learn cluster ranges
  from the token-readable `kube-system/u7s-cluster-config`; the apiserver
  listens on every node address.
- #2080: proxy v6 host:port and upstream node-address type order.
- #2083: openssl-free node CSR; removed install.sh's 52-character node-name
  guard (the openssl CN limit). The effective limit is 63 because kubelet
  puts the node name in the `kubernetes.io/hostname` label; install.sh does
  not enforce it yet (`mayor-2qk05`).
- #2087: SPDY exec/attach passed through to the kubelet like upstream
  UpgradeAwareHandler.
- #2089: hostNetwork pods' podIPs follow `status.hostIPs`.
- Security fixes #2081, #2082.

## Harnesses

- GCP: `cloud-two-node.sh --release <tag> --dual-stack` (e2-standard-2,
  separate `u7s-probe` VPC for the outside probe, narrow per-run LB firewall
  rules; #2077, #2079, #2084, #2085, #2088). Subnet `u7s-test` us-west1
  IPV4_IPV6/EXTERNAL `10.80.0.0/24` + `2600:1900:4040:51a::/64` is dedicated,
  with no ULA internal v6; `u7s-probe` is `10.81.0.0/24`. IPv6 access type is
  one-way (#2037). IAP SSH is IPv4-only and returns 4047 for about a minute
  after VM create (retry; `mayor-8w6at.9` notes, #2037). Never run `vps.sh gc` during a live run.
- Lima: `run-all.sh --dual-stack` (#2045, #2090, #2091). user-v2 forwards v6
  unicast but drops multicast, so IPv6 neighbour discovery does not work. Each
  VM gets a static ULA address and the rig seeds neighbour entries (observed:
  a deleted entry went FAILED and ping6 returned "Address unreachable";
  `mayor-8w6at.11` notes). A v6 Service route is added; `--num-nodes`
  and `sonobuoy retrieve` are used. The default rig stays IPv4-only.
- Release tarballs are x86_64 only, so Lima (aarch64) cannot install from a
  release.

## Open beads

- `mayor-8w6at.10` (P3): IPv6-only phase, install without IPv4, v6
  `kubernetes` Service, DNS64/NAT64 and registry reachability on GCE.
- `mayor-8w6at.12` (P3): upgrade a single-stack install to dual-stack on
  re-run (refused today).
- `mayor-8w6at.15` (P3): worker v6 forwarding follow-ups.
- `mayor-8w6at.20` (P3): GCP harness results-step flake, transient, not
  reproduced.
- `mayor-m7pr7`: switch the GCP harness to `sonobuoy retrieve` once a release
  contains #2087.
- `mayor-sy83n`: re-mint serving cert on SAN change; persist auto-detected
  node IPs.
- `mayor-5f4ey`: harness hardening: per-family client source-IP assertion,
  `pipefail` in `sonobuoy_dual`, scope `vps.sh gc`'s LB-rule sweep by run id
  or age (the sweep itself shipped in #2079).
- `mayor-8w6at.22`: Lima dual-stack rig's v6 Service route ignores a custom
  `--service-cidr`.
- `mayor-l5wmt`: `--external-iface`/`--external-ip`, data-plane default iface,
  stable control-plane endpoint.
- `mayor-2qk05` (P2): label key/value validation across kinds, incl. Node.
- `mayor-8u3hh` (P2): create-time webhook clientConfig validation.
