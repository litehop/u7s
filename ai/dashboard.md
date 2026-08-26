# Dashboard
2026-08-25T18:20Z — Session wrap-up. Resume: `bd prime` → this file.

Stance: pre-alpha/greenfield, no backward compatibility, break freely, merge-on-green (auto).

## Session summary

Deep CNI/Service-LB/manifest-packaging investigation, ending in 3 formalized
ADRs and a real merged fix: `docs/decisions/flannel-for-cni.md`,
`docs/decisions/well-known-manifest-folder.md`, `docs/decisions/network-policy-engine.md`
(amended). Also: `ai/extended-context/lima-gvisor-cri-o-pull-defect-postmortem-2026-08-25.md`
(new Lima dev-tooling defect, dev-only, does not affect production).

## ✅ Merged this session
`#1358` checksum verification, `#1360` per-location error_page, `#1361` deploy
tweaks, `#1362` resolver, `#1363` admin-cert-survives-restart (`mayor-lgayh`),
`#1364` k8s version bump, `#1365` Flannel + node-ipam-controller cross-node fix
(`mayor-ua9gg`, two review rounds, both LGTM).

## 🎯 Decisions made, not yet implemented (ready to dispatch, sequenced)
Manifest-packaging chain (`docs/decisions/well-known-manifest-folder.md`):
```
mayor-tgvxq (apply mechanism, /etc/u7s/manifests, fatal-on-bad-manifest)  ← READY
├─ mayor-bh36n (SIGHUP reload, P3 follow-on)
├─ mayor-cfkix (test-harness reuse, P3)
└─ mayor-94sz3 (installer --manifest-output-dir flag)
   └─ mayor-liiv1 (vendor YAMLs in-repo, bundle into release tarball —
     NOT install-time fetch, GitHub has no IPv6 and some target nodes are
     IPv4-only)
     ├─ mayor-fiq79 (migrate CoreDNS off include_bytes!, bump stale v1.11.1)
     ├─ mayor-73lqh (migrate kube-proxy, watch the $KUBE_VERSION templating)
     └─ mayor-fptqu (migrate Flannel off its PR #1365 heredoc)
```
CNI decision (`docs/decisions/flannel-for-cni.md`): Flannel bundled as default,
already implemented via PR #1365. Service LB decision still pending its own
ADR — leading design is a forked/reimplemented klipper-lb (MASQUERADE bug
fixed), loxilb disqualified (crashes on 1GB RAM, confirmed live).

## 📥 Ready backlog (18 issues, `bd ready`)
P1: `mayor-ecmt4` (kube-proxy kubeconfig bootstrap deadlock — real, confirmed
live, blast radius is "every install.sh deployment," not conformance-visible),
`mayor-gtjmv` (install.sh enable→restart for upgrades to take effect),
`mayor-o61zz` (Lima ARP defect, upstream-blocked, has a documented workaround).
P2: `mayor-tgvxq` (see chain above), `mayor-6hog8` (CoreDNS RBAC SERVFAIL),
`mayor-biirm` (install.sh needs bash not sh), `mayor-72kil`, `mayor-lrpi2`,
`mayor-po8qf`, `mayor-0fdes` — held pending operator nod per prior sessions.
P3/P4: `mayor-gkgg9`, `mayor-tnzdi`, `mayor-fbxcy`, `mayor-9xsn3`, `mayor-u6ju`
(deferred SSA epic), `mayor-3g7fg`, `mayor-t8ucq` — operator-held.

## 🌲 Worktrees / branches
None outstanding — all worker worktrees and local branches cleaned up this
session; `git worktree list` shows only the mayor's own checkout.

## 🔁 Cron loops — NOT REGISTERED
Not set up this session (conversational/research-heavy, not a dispatch-drain
session). Next mayor should register the standard loops if resuming
dispatch-heavy work.

## Repo state
Main @ `2a6b974d`. Ruleset 18156794 ACTIVE, merge queue live, proven across 7
merges this session. No open PRs. No pending review-queue entries.
