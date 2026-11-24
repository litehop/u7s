---
updated: 2026-11-24T17:45Z
---
# Dashboard — session 2026-11-24 closed (main `44d412be`)
**Stance:** alpha (no compat promise); correctness > security > perf > features; upstream 1.37.1 except secure crypto; queue merge on green, never `--admin`; security PRs drafted for operator; every release gated (agent runs burst + upgrade gates, operator pushes tags + approves publish).
**Resume:** paste `ai/prompts/mayor-bootstrap.md`; `bd prime`; re-register crons; `bd recall operator-2026-11-24-capacity-docs-apiserver-perf-kubelet-port`; `bd show mayor-w9xt5`.

## 🎯 Waiting on you
- **#2239 KCM port design (`w9xt5`, draft):** read; confirm 4 MiB embedded-revisit trigger; then mayor un-drafts.
- **`jedol` first stamped artefact:** approve a ~1 h Lima run (`--allow-contended`, or stop `lima-node` first); GCP authoritative run at next minor release (now required to tag).

## ⏭ Next session — start here
- P2 `78t2x` proxy `*_forwards_query_string` tests flake on macOS pre-push (non-loopback test upstream) — slows every push; fix first.
- P2 `xq474` watch defaulting gaps + single source of truth for defaulting kind lists · `9ysgy` watch fan-out memory (lazy roots, prune sub-channels) · `7s8gr` apiserver RSS (re-take dhat first).
- Partial perf: `f3aaa` deployments LIST · `z37qr` protobuf needs direct bytes→proto.
- `qqy20` epic: only P3 `06ha8` (2-node) · `azbbb` left.
- P3 follow-ons filed today: `2tddc` `33659` `xyfts` `tqm01` `lgch7` `6q3oc` `o50e6` `thnxe` `qikno` `xhpbb` `lrwcy` `lvav9` `usprd`.
- Stale pre-11-20 in_progress claims still untriaged (`lwwze` `b6c59` `rdy7h` `83irk` `qap3i.35` `1xpj7` `xdw6u.11` `p3ktl` `l2imr` `ynfzk`).

## Decided today (detail in bead notes / PR bodies)
- Overload survival not a goal; limits via stamped benchmarks, required to tag a minor release; release gate stays 20 pods (roadmap fixed, #2236).
- KCM-first Rust port: separate process + loopback HTTP; memory-first gates (terminal per SHA, cumulative cap, strict void rule, pin scope); embedded re-measured each phase. Kubelet port undecided.
- Request limits: 3 MiB/413, 6 MiB incremental budget/429, 60 s body + response-header deadline for all requests incl. proxy (divergence documented in `docs/apiserver-request-limits.md`).
- CI e2e-focus runs real install.sh (option B, cached bins); 1.35.9 dropped. Stricter-than-upstream SAN validation approved.

## ✅ merged this session (31)
#2248 capacity benchmarks + docs/capacity.md · #2247 SAN validation · #2246 LIST hot path · #2245 rig kubelet flag parity · #2244 watch fan-out · #2243 proxy header timeout + limits doc · #2242 schedulerName · #2241 rig kubelet identity + shared VM setup · #2240 hot-path audit + bench · #2238 run-meta · #2237 KCM design (pre-decision) · #2236 roadmap · #2235 body budget · #2234 sa.key detect · #2233 CI runs all script tests · #2232 SAN drop · #2231 host-rig parity · #2230 CI via install.sh · #2229/#2226 scale JSON Patch · #2228 fresh-store · #2227 DNS ExternalName · #2225 parity tests · #2218–#2224 renovate.

<!-- BEGIN AUTO: open-prs -->
- #2250 chore(deps): update sigstore/cosign-installer action to v4.1.4 (`renovate/sigstore-cosign-installer-4.x`, CLEAN)
- #2249 chore(deps): update dependency sigstore/cosign to v3.1.5 (`renovate/sigstore-cosign-3.x`, CLEAN)
- #2239 docs(findings): KCM port design — apply operator gate decisions (mayor-w9xt5) (`worker/agent-a8c90fb16413c2450`, CLEAN)
<!-- END AUTO: open-prs -->
<!-- BEGIN AUTO: worktrees -->
- `/private/tmp/claude-502/-Users-balint-erdos-litehop-u7s/117bd8b0-1064-4695-8c40-180478835760/scratchpad/base` (`HEAD`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a016e470c9268482e` (`worker/agent-a016e470c9268482e`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a03fc6495a796d80b` (`worker/agent-a03fc6495a796d80b`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a0cf6b6c872adab86` (`worker/agent-a0cf6b6c872adab86`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a0e2410d0bb85907f` (`worker/agent-a0e2410d0bb85907f`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a17691ab260e8ff7b` (`worker/agent-a17691ab260e8ff7b`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a37f747f952b4b3ab` (`worker/agent-a37f747f952b4b3ab`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a44ca025a8f0f2fe8` (`worker/agent-a44ca025a8f0f2fe8`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a540f4ec0ff602adb` (`worker/agent-a540f4ec0ff602adb`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a569e9837ec3b7405` (`worker/agent-a569e9837ec3b7405`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a69e2a858d6ba4ae1` (`worker/agent-a69e2a858d6ba4ae1`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a76b8ddd2cc6ffca5` (`worker/agent-a76b8ddd2cc6ffca5`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a7c30d17fbf335154` (`worker/agent-a7c30d17fbf335154`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a7d6dea99408a1b09` (`worker/agent-a7d6dea99408a1b09`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a821d266c75172753` (`worker/agent-a821d266c75172753`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a8c90fb16413c2450` (`worker/agent-a8c90fb16413c2450`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-a8d9a2f4cd951dad3` (`worker/agent-a8d9a2f4cd951dad3`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ac8bf13f2cf637ce8` (`worker/agent-ac8bf13f2cf637ce8`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ad1a3bcbae86f35aa` (`worker/agent-ad1a3bcbae86f35aa`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ad5d3e71e3f50731d` (`worker/agent-ad5d3e71e3f50731d`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ad9c9d67e01bb4aee` (`worker/agent-ad9c9d67e01bb4aee`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ae1274ea472d55146` (`worker/agent-ae1274ea472d55146`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-ae36431d61dd85b1a` (`worker/agent-ae36431d61dd85b1a`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-aec6e1ac6b73dd20e` (`worker/agent-aec6e1ac6b73dd20e`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-aecedd3a13468fb62` (`worker/agent-aecedd3a13468fb62`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-af79e902ee1caddce` (`worker/agent-af79e902ee1caddce`)
- `/Users/balint.erdos/litehop/u7s/ai/worktrees/agent-afea1f4e19db5afd6` (`worker/agent-afea1f4e19db5afd6`)
<!-- END AUTO: worktrees -->
<!-- BEGIN AUTO: cron-loops -->
15m mayor tick (`scripts/mayor-tick.sh`) · 60m reread posture · 60m worktree hygiene
<!-- END AUTO: cron-loops -->
<!-- BEGIN AUTO: repo-state -->
As of 2026-11-24T17:39:00Z (last tick) — Branch `main` @ `44d412be`, dirty, up to date with origin/main.
<!-- END AUTO: repo-state -->
<!-- BEGIN AUTO: review-queue -->
0 pending review-queue entries.
<!-- END AUTO: review-queue -->
