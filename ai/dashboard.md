---
updated: 2026-11-03T16:10Z
---
# Dashboard — session 2026-11-02/03 WRAPPED (main `ee5ca55a`, snapshot `v0.4.3-snapshot.2`)
**Stance:** pre-alpha, no users; conformance correctness > security > perf > features; match upstream 1.37.1 except secure crypto defaults; queue merge on green, never `--admin`. CI wall-clock is a ratchet.
**Resume:** `claude --settings .claude/settings.json`; paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons. Read `ai/extended-context/dual-stack-state.md` (refreshed). No workers, Lima VMs or GCP VMs running; GCP keeps only the `u7s-test`/`u7s-probe` networks.

## 🎯 Waiting on you
- **Permission rule (optional):** allow `gh api …/reviews/*/dismissals` (stale-review dismissal was denied as an external write).
- **Sonobuoy upstream (optional, not needed by u7s since #2087):** `temp/sonobuoy-spdy-retrieve-summary.md`; vmware-tanzu/sonobuoy#2033 already adds WebSocket-first retrieve.
- Carried from 10-31: `yfca9` MariaDB option, `feature-tests` as required check, `b6c59.1` CI cargo profile, review of #2064/#2061 design calls.

## 🏁 Session goal met: dual-stack u7s + beep verified on GCP (`mayor-8w6at.2` closed)
`v0.4.3-snapshot.2`: install + real `--join`; v4+v6 node IPs/podCIDRs; dual clusterIPs + CoreDNS A/AAAA; pod↔pod/Service both families cross-node; beep LB v4+v6 from in-subnet client and outside-VPC probe (refused→admitted); sonobuoy dual-stack **30/30**. IPv6-primary node + bracketed kube-proxy URL also PASS (`.21`). Caveat: harness results step flaked once → `.20`.

## ⏭ Next session
1. Dual-stack: `.10` IPv6-only phase; `.12` single→dual upgrade; `.15`; `.20` harness flake; `.22` custom `--service-cidr` route; `m7pr7` GCP harness → `sonobuoy retrieve` (needs a release with #2087).
2. Parity/security follow-ups: `2qk05` label validation (63-char node names), `8u3hh` create-time webhook config validation, `qap3i.56`/`.57`, `sy83n`, `l5wmt`, `5f4ey`.
3. Tooling: `mhmb5` hygiene deleted an open PR's local branch + ref-only pushes run full cargo test; `mp30b` detached fix-round worktrees not reaped; `fb1r4` lima-node-5 misprovisioned.
4. Carried: `yfca9` → `vw7jc`/`i4bvb`; CI Phase 2 (`b6c59.*`).

## ✅ Merged 2026-11-02/03 (dual-stack product: #2076 #2078 #2080 #2083 #2087 #2089; security: #2081 #2082)
- #2076 `rv1aw` node address lists (`--iface` all families, `--node-ip`) · #2078 `foh4j` node families match cluster; join reads `kube-system/u7s-cluster-config` (option D); apiserver listens on every node address.
- #2080 proxy v6 host:port + upstream node-address order (`lxgg3` invalid) · #2083 `okr7g` openssl-free node CSR · #2089 `.18` hostNetwork podIPs follow hostIPs.
- #2087 `zgpuq` SPDY exec/attach passed through to kubelet (no ADR) · #2081 security cluster · #2082 `i7k18` actionable 5xx text + webhook URL userinfo/query rejected.
- GCP harness: #2077 `--dual-stack` · #2079 outside-VPC probe (`u7s-probe` VPC) · #2084 #2085 #2088 probe-v6/WebSocket splat/results fixes.
- Lima rig: #2045 dual-stack rig · #2090 `sonobuoy retrieve` + `--num-nodes` · #2091 v6 Service route.
- Renovate: #2030 #2052 #2075. Docs: #2092 dual-stack-state refresh (if merged after this snapshot, see main).

## 📝 Decided 2026-11-02/03
- `rv1aw` narrowed to the dual-stack slice (rest → `l5wmt`); join learns cluster ranges via token-readable ConfigMap (option D; flat `system:bootstrappers` subject accepted).
- E2E may use larger instances when e2-micro would saturate; delete promptly. Outside-GCP reachability via a probe VM in a separate VPC.
- Snapshot scope: dual-stack apiserver + security clusters; 500/502 redaction kept with an explicit actionable marker.
- SPDY: exec/attach passed through to the kubelet like upstream (port-forward already was); no ADR. ADRs are never rewritten, only superseded (bd memory).
- Renovate: merge on green; not a priority unless security.

<!-- BEGIN AUTO: open-prs -->
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
none (cancelled at hand-off 2026-11-03)
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
<!-- END AUTO: review-queue -->
