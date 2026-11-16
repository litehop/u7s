# u7s over a WireGuard mesh

Run u7s on nodes whose only mutual path is a WireGuard tunnel by passing
`--iface wg0` to `install.sh` on every node; nothing else needs changing.
Verified on GCP with two nodes in separate VPCs (public IPs only) on
`v0.4.3-snapshot.4`, Ubuntu 26.04, kernel 7.0.

## Steps

1. Pick a tunnel subnet that overlaps neither `--service-cidr` (default
   `10.96.0.0/12`, i.e. 10.96-10.111) nor `--cluster-cidr` (default
   `10.244.0.0/16`). `10.200.0.0/24` worked. `install.sh` refuses a node
   address inside the service range (`10.99.0.1` failed).
2. On each node: `apt install wireguard-tools`, generate a key pair, and write
   `/etc/wireguard/wg0.conf` with one `[Peer]` per other node: that peer's
   public key, `AllowedIPs = <peer tunnel IP>/32`, its public `Endpoint`, and
   `PersistentKeepalive = 25` (nodes behind NAT need it). Then
   `systemctl enable --now wg-quick@wg0`. Only the tunnel `/32`s are needed in
   `AllowedIPs`: flannel carries pod traffic between node addresses, so pod
   and service CIDRs never enter the tunnel routing table.
3. Control plane: `sudo bash install.sh --iface wg0`. The auto pick skips
   VPN interfaces (it takes `en*`, `wl*`, `ww*`, `eth*`), so `--iface` is
   mandatory; without it install.sh picks the public NIC (not run).
4. Mint a token on the control plane (`install.sh --mint-join-token`). It
   prints a join URL on the tunnel address (`https://10.200.0.1:6443`).
5. Each worker: `echo <token> | sudo bash install.sh --join https://10.200.0.1:6443
   --token - --ca-cert-hash sha256:<hash> --node-name <name> --iface wg0`.

## What was verified

- `kubectl get nodes -o wide`: both `Ready`, `INTERNAL-IP` 10.200.0.1 and
  10.200.0.2; flannel's `public-ip` annotation and the pod IPs of the
  DaemonSets are the same tunnel addresses; flannel runs with `--iface=wg0`.
- VXLAN (UDP 8472) was seen on `wg0` and not on the public NIC; the only
  public-NIC traffic was WireGuard on UDP 51820.
- Cross-node pod-to-pod, pod-to-ClusterIP, and CoreDNS lookups from a pod on
  the worker all work; `kubectl logs` and `kubectl exec` work against the
  worker (the apiserver dials the kubelet at its tunnel IP).
- LoadBalancer (beep): `status.loadBalancer.ingress` lists the tunnel IP of
  every node. A third WireGuard peer (outside the cluster) curled both
  addresses with the backend pod on the worker. The control-plane address
  forwarded to the worker over Geneve inside `wg0`; the pod saw the client's
  own tunnel IP as the source. A 1 MB download and a 2 MB upload completed on
  both. With `externalTrafficPolicy: Local` only the worker is advertised,
  and the control-plane address still forwards (as the README states).

A LoadBalancer address is a node address on `--iface`, so clients must be on
the tunnel (a peer of the mesh) to reach it; the nodes' public IPs do not
answer.

## MTU

Nothing to set. flannel derives the pod MTU from the interface: `wg0` came up
at 1380 (the NIC's 1460 minus WireGuard's 80), `flannel.1` and pod `eth0` at
1330 (minus 50 for VXLAN). From the control plane, `ping -M do -s 1302 <worker pod IP>`
passed and `-s 1303` failed locally; a 1 MB cross-node transfer and the LB
transfers completed. Lowering the MTU is only needed if the underlay is
smaller than 1460; set `MTU = <n>` in `wg0.conf` before installing so flannel
inherits it. A wrong `wg0` MTU after install was not tested.

## Firewall

Allow UDP 51820 (the `ListenPort`) between the nodes' public addresses, and
nothing else; narrow each rule to the peer's `/32`. Cloud nodes also need
their normal egress (image pulls, the release mirror). Nodes in the same VPC
see each other's internal address, so use that as the `Endpoint` there.

## Known limits

- Tailscale is untested. install.sh's auto pick also skips `tailscale*`, so
  pass `--iface tailscale0`. A Headscale-based check is a follow-on.
- IPv4 only; dual-stack over the tunnel is untested.
- beep's `servicelb-controller` restarted once on each node during first
  start (30 s timeout creating its seed Secret); it was healthy afterwards.
  Not shown to be WireGuard-specific.
- Only two nodes plus one client peer were exercised, as a full mesh. Every
  peer must list every other peer; there is no hub routing in this setup.
