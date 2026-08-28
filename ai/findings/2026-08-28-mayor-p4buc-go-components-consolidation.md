Bead: mayor-p4buc

# Go components consolidation: kubelet, kube-proxy, kube-controller-manager

Critical-review consolidation of three agent-produced findings docs
(`temp/kubelet-responsibilities-2026-08-28.md`,
`temp/kube-proxy-responsibilities-2026-08-28.md`,
`temp/kube-controller-manager-rust-evaluation-2026-08-28.md`), all researched
against kubernetes/kubernetes `v1.36.4`. This doc verifies their claims
against u7s source, upstream source, and prior audits, corrects what didn't
hold up, and frames operator decisions. It does not recommend on the
operator's behalf.

## Executive summary

All three Go components are upstream, unmodified, and load-bearing today.
**kubelet** (~139k LOC) is the largest by a wide margin and already has
proven Go-runtime memory tuning applied; a Rust rewrite cannot single-handedly
clear the Gate-4 budget and would forfeit the conformance-oracle guarantee.
**kube-proxy** is the smallest and least-analyzed of the three — the input
doc is purely descriptive (no rewrite argument) and is the one component of
the three that has *not* received the tuning pass the other two already got.
**kube-controller-manager** (52 controllers, u7s runs ~47) sits between the
two: its ~91 MiB idle footprint is ~85% fixed cost per the input doc's own
growth-curve reasoning, but that reasoning is undercut by a fact the input
doc didn't check — the same GOMEMLIMIT/GOGC/GOMAXPROCS tuning it proposes as
an untried lever is already applied and baked into the baseline it measures.

Decisions this doc is trying to inform:
- Whether to spend effort tuning kubelet/KCM further (config-only, e.g.
  `--max-pods`, `ConfigMapAndSecretChangeDetectionStrategy`, cAdvisor metric
  set, controller pruning) before any rewrite is considered.
- Whether to close the kube-proxy tuning gap the same way kubelet/KCM's was
  already closed (mayor-iefj5, mayor-kagyg).
- Whether to port the already-proven kubelet/KCM tuning from the conformance
  dev-loop scripts into the production install script, which currently ships
  untuned.
- Whether a Rust rewrite of any of the three is worth opening now, or should
  wait on kubelet's roadmap-mandated tuning-first gate (it should).

## kubelet

### What the input doc claims

Kubelet is the only component that turns desired state into a running
process, staying in the loop for every pod's lifetime (probing, stats,
mounting, exec/logs) unlike kube-proxy which programs the kernel and steps
away. At ~139k non-test LOC, `cm/` (cgroup/QoS/CPU/memory/topology managers,
24.8k lines) dominates. It holds a cluster-wide (non-headless) Services
informer purely to synthesize legacy Docker-link env vars, redundant with
kube-proxy's own Services watch. Against the 0827-1443-conformance baseline
(96.7→125.7 MB), a Rust kubelet folded into the apiserver+scheduler binary
saves an estimated 88% optimistic / 50% pessimistic — but the doc's own
conclusion is that **a Rust kubelet cannot reach Gate 4** even optimistically,
because KCM + CRI-O alone (184–225 MB) already exceed the 134.2 MB budget.
It lists GOMEMLIMIT, `--max-pods`, `ConfigMapAndSecretChangeDetectionStrategy`,
cAdvisor metric-set trimming, and feature-gating off unused managers as
"concrete levers found in source during this pass," to be tried before any
rewrite, per roadmap.md/north-star.md's tuning-first gate.

### Verification pass

**Checked out, verbatim:**
- `lima/kubelet.yaml:163` installs kubelet 1.36 from pkgs.k8s.io — confirmed.
- `crates/apiserver/src/handlers/proxy.rs` exists and implements exactly the
  log/exec/attach/portforward WebSocket-proxy-to-kubelet surface the doc
  describes.
- `pkg/kubelet/kubelet.go:543` (fetched via the mayor's cached sparse clone,
  `temp/k8s-src`) matches the doc's quoted field-selector line verbatim,
  confirming the cluster-wide non-headless Services informer claim exactly.
- bd memories `gate4-budget-excludes-pods-not-just-workloads`,
  `u7s-rust-owns-only-apiserver-scheduler-store`, and
  `kubelet-eviction-manager-cannot-preempt-sub-60s-bursts-upstream-limitation`
  all exist and match the doc's characterization.
- roadmap.md's kubelet row ("an upstream config-tuning audit is next, native
  rewrite is only considered after that") and north-star.md principle 3 ("a
  rewrite is not on the table until [tuning] has been tried") are quoted
  correctly.
- The scheduler-as-Rust-anchor figures (7.4 MB idle / 14.5 MB peak, 11.5k
  LOC) match `mayor-lulpm`'s own numbers and the scheduler crate's actual
  line count (11,600).

**Corrected — this is the most consequential finding of the whole audit:**
GOMEMLIMIT is presented as a not-yet-applied lever ("the same lever the 0827
audit recommended for CoreDNS"). It is **already applied and has been since
2026-08-19** — `scripts/conformance/lima-start.sh:550-552` sets
`GOMEMLIMIT=200MiB`, `GOGC=50`, `GOMAXPROCS=2` on the kubelet unit, closed as
bead mayor-iefj5 (PR #1263) with a measured before/after (a 31-pod cycle
dropped 167.5→104.6 MB post-cleanup, with the pre-tuning run showing the
exact GC-lag sawtooth the doc worries about). **The 96.7→125.7 MB baseline
the entire memory-estimate section is built on already includes this
tuning** — it is not a naive-default kubelet. This doesn't invalidate the
doc's Rust-vs-Go percentages (if anything, comparing Rust against an
already-tuned Go baseline is the more honest number), but the "GOMEMLIMIT as
next step" framing must be struck.

**Still valid, still untried:** `--max-pods`, `ConfigMapAndSecretChangeDetectionStrategy`,
cAdvisor metric-set trimming, and feature-gating are genuinely separate from
the closed GOMEMLIMIT/GOGC/GOMAXPROCS bead — mayor-iefj5's own notes
explicitly deferred `KubeletConfiguration` field changes as "a separate
follow-on." These remain open, unmeasured candidates.

**Unverified within budget:** whether a reduced-scope kubelet (dropping
topology/CPU/memory managers, DRA, most in-tree volume plugins) still passes
Conformance — the doc flags this itself and it was not independently
checked here.

### Decision-support options

1. **Do nothing.** Zero effort, zero risk. Keeps the conformance-oracle
   guarantee and Gate 7's re-join story intact. Leaves ~125.7 MB RSS as-is.
2. **Additional upstream config tuning** (`--max-pods`, change-detection
   strategy, cAdvisor metric set, feature gates). Config-only, low risk,
   reversible — but needs a conformance re-run to confirm no node-level
   coverage regression (unmeasured today). Unknown savings until measured.
3. **Fold a Rust kubelet into apiserver+scheduler** (Scenario A/B in the
   doc). ~139k LOC surface — order of the entire existing u7s workspace.
   High risk: forfeits the conformance oracle, forfeits Gate 7's
   unmodified-kubelet re-join advantage, and turns a restartable per-node
   agent failure into a same-process apiserver outage. Even the optimistic
   88% RSS cut doesn't clear Gate 4 alone (KCM + CRI-O already exceed it).
4. **Standalone Rust kubelet, separate process.** Not modeled by the input
   doc (it only estimated folded-in scenarios). Keeps restart isolation but
   forfeits the in-process cache-dedup savings that drive the "optimistic"
   case — would need its own memory model before it's comparable.

### Recommendation

Do not rewrite kubelet now. Run option 2 (cheap, reversible, config-only
tuning) and measure it before revisiting a rewrite — this is exactly what
roadmap.md's own gate requires, and the corrected GOMEMLIMIT finding above
means that gate is only partially satisfied, not fully closed as the input
doc implied. Confidence: high — the budget math (KCM + CRI-O alone exceed
Gate 4) is not sensitive to the correction, and the conformance-oracle
trade-off is a standing, already-banked project rule.

## kube-proxy

### What the input doc claims

Kube-proxy programs the kernel's Service-VIP DNAT/masquerade/conntrack
machinery and does not carry packets itself. The doc is purely descriptive:
watch scope (EndpointSlices + Node, not Endpoints), iptables/nftables rule
structure, session affinity, `CategorizeEndpoints` traffic-policy/topology
logic, two independent health servers, and an explicit "what it does not do"
list (headless Services, `ExternalName`, `service-proxy-name`-labeled
Services, pod networking, NetworkPolicy/Ingress/DNS). It makes **no
rewrite argument and no u7s-state memory claims** — its only "not verified"
item is whether kube-proxy is fully replaceable by CNI-native
implementations (Cilium/Calico eBPF), which it correctly declines to assert.

### Verification pass

**Checked out:** the shared kubelet-1.36 install claim (`lima/kubelet.yaml:163`).
Spot-fetched `pkg/proxy/util/utils.go` fresh from
`kubernetes/kubernetes@v1.36.4` (not in the cached sparse clone, saved to
this worktree's `temp/research/proxy-util-utils.go`) to check the doc's two
most load-bearing "what it does not do" citations: `ShouldSkipService` is at
line 56 exactly as described, the headless-skip check
(`!helper.IsServiceIPSet`) is at line 58 and the `ExternalName` skip is at
line 63 — both match the doc's cited line numbers exactly. Given this
precision on the one function independently re-fetched, the doc's other
~15 upstream line citations (not independently re-verified within budget)
are credible.

**No u7s-state claims to verify** — this is itself a finding: unlike the
other two docs, this one stayed entirely in its lane (upstream behavior
description) and made no claims about u7s's own code, memory posture, or
rewrite feasibility. No corrections needed.

**Gap this audit surfaces that the input doc doesn't address at all:**
kube-proxy is Go, runs under the same class of Go-runtime memory pressure as
kubelet and KCM (measured 53.3 MB peak in `mayor-lulpm`), but has received
**no** GOMEMLIMIT/GOGC/GOMAXPROCS tuning pass — confirmed absent from both
`scripts/conformance/lima-start.sh` and production `scripts/install.sh`. No
bd bead like mayor-iefj5/mayor-kagyg exists for it.

### Decision-support options

1. **Do nothing.** kube-proxy's absolute RSS (53.3 MB) is the smallest of
   the three Go components; the upside is smaller than kubelet's or KCM's.
2. **Apply the same GOMEMLIMIT/GOGC/GOMAXPROCS tuning already proven on
   kubelet and KCM.** Same lever class, same low risk, same reversibility.
   Effort is small — one `Environment=` block in kube-proxy's systemd unit,
   mirroring the two already-merged PRs (#1263, and the KCM equivalent).
   Unmeasured, but the prior on payoff is reasonable given it worked twice.
3. **Partial reimplementation** — not evaluated by any input doc; kube-proxy
   is "low-level networking, high-effort" per roadmap.md's own row, with "no
   presumption either way." Would need its own scoping pass before this is
   a live option.
4. **CNI-native replacement** (Cilium/Calico eBPF instead of kube-proxy) —
   explicitly out of scope for this doc (the input doc's own "not verified"
   item); would require a separate evaluation of u7s's CNI story.

### Recommendation

Close the tuning gap (option 2) — it's the cheapest, lowest-risk, most
directly-precedented action available for any of the three components, and
leaving the smallest Go component as the only untuned one is an
inconsistency, not a deliberate choice. Confidence: medium — the lever is
proven on two sibling components, but kube-proxy's actual RSS-vs-GC-headroom
shape has not been measured, so the payoff size is a guess, not a number.

## kube-controller-manager (KCM)

### What the input doc claims

One process, 52 registered controller descriptors (3 off by default), u7s
enables ~47 (production keeps node-ipam, conformance disables it — flagged
as a drift the doc itself catches). Measured baseline: 90.9 MB idle → 109.2
MB peak, stable across four runs, with ~85% attributed to fixed cost (text,
runtime, GC headroom, reflector goroutines) based on only ~17 MB of growth
across a full 446-spec conformance run. Four scenarios modeled: S0 (tune,
no rewrite: 60–82 MB), S1 (standalone Rust rewrite: 12–45 MB), S2 (folded
into apiserver+scheduler: 45–95 MB for all three), S3 (partial rewrite: 91–110
MB — argued to be strictly worse, a correctness hazard from split ownership).
Even S2's optimistic case leaves the control-plane node at 1.98× the Gate-4
budget once kubelet/CRI-O/kube-proxy are included. Explicitly flags that
KCM's `/metrics` is never scraped in any conformance run, so its own memory
decomposition is inference, not measurement.

### Verification pass

**Checked out, verbatim, against the mayor's cached upstream sparse clone
(`temp/k8s-src`):**
- `NewControllerDescriptors` registers exactly **52** controllers (counted
  via `register(` call sites in `controller_descriptor.go`) — exact match.
- Exactly 3 are `isDisabledByDefault: true`: bootstrap-signer (`bootstrap.go:32`),
  token-cleaner (`bootstrap.go:60`), selinux-warning (`core.go:1038`, one line
  off the doc's cited `:1036` — the descriptor struct starts at 1034, the
  field itself at 1038; a trivial citation drift, not a factual error).
- `scripts/install.sh:921` disables exactly the 4 named cloud controllers,
  and includes `--leader-elect=false` — confirmed.
- `scripts/conformance/04-start-kcm.sh:147` additionally disables node-ipam
  — confirmed, so the production-vs-conformance controller-set drift the
  doc flags is real.

**Corrected — same finding as kubelet, independently confirmed for KCM:**
S0's optimistic case credits GOMEMLIMIT ("caps GC headroom") as an untried
lever that could take KCM from 90.9 MB toward 60 MB. **This tuning is
already applied**: `scripts/conformance/04-start-kcm.sh:80-82` sets
`GOMEMLIMIT=200MiB`, `GOGC=50`, `GOMAXPROCS=2` (committed 2026-08-20, bead
mayor-kagyg, closed), and `--concurrent-gc-syncs=5` is already set at line
148 (bead mayor-pjtkz, "trial lowering KCM --concurrent-gc-syncs (20→5)",
closed). **The 90.9 MB idle baseline the whole S0–S3 analysis is anchored to
already reflects both of these.** S0's remaining honest headroom must come
from further controller pruning or a tighter GOMEMLIMIT value, not from
"turn on GOMEMLIMIT" — that step already happened before this run. This
does not change the S1/S2/S3 comparisons (they're all measured against the
same, already-tuned 90.9 MB baseline), but it means S0's 60 MB optimistic
figure needs re-scoping to name the *specific* further lever, since the one
named in the doc's own reasoning is spent.

**Internal inconsistency found, resolved:** the KCM doc's own Part 2 table
lists kubelet's peak as **116.1 MB**; the kubelet doc (and `mayor-lulpm`
dimension 1, the canonical source both docs cite) states kubelet's peak as
**125.7 MB**. Tracing this to `mayor-lulpm`: dimension 1 explicitly labels
125.7 MB "Peak RSS" (the true max across 102 samples); dimension 4's
CPU-per-byte table separately reports "116.9 MB" as kubelet's "Peak/final
RSS," which dimension 2's growth narrative ("steps to ~116–118 MB... holds
there") corroborates as the settled *end-of-run* value, not the run-wide
max. The KCM doc used the final-tick figure while labeling it "peak." **The
authoritative number is 125.7 MB** (mayor-lulpm's explicit Peak-RSS column);
this doesn't change any conclusion in either doc (both are in the same
90–130 MB neighborhood, well under the >200 MB pre-tuning sawtooth), but the
label should be corrected if either doc is revised.

**Not independently re-verified within budget:** the "stable across four
runs" claim (idle 90.9–97.8, peak 109.2–133.6) — the four run directories
(`0819-0255`, `0820-0510`, `0820-1426`, `0827-1443`) exist in `temp/e2e/`,
but re-aggregating all four was out of budget; only the cited `0827-1443`
run's KCM figures were cross-checked against `mayor-lulpm` (exact match).

### Decision-support options

1. **Do nothing / S0 as already-measured.** The already-applied
   GOMEMLIMIT/GOGC/GOMAXPROCS + `--concurrent-gc-syncs=5` tuning is the
   current state; 90.9 MB idle is the honest number to plan against, not a
   pre-tuning figure.
2. **Further upstream tuning** (name a *new* lever: prune more of the ~47
   enabled controllers if any are unused in practice, or push
   `--concurrent-*-syncs` further, or try a tighter GOMEMLIMIT). Effort:
   low, reversible. Payoff: unknown until measured — the doc's own "measure
   S0 before crediting S1/S2" caution applies doubly now that the easy lever
   is already spent.
3. **S1 — standalone Rust rewrite, parity with ~47 controllers.** 12–45 MB
   estimated vs 90.9 MB today. Effort: covers GC's ownerReference graph, PV
   binding/dynamic provisioning, HPA's scaling algorithm, disruption-budget
   math, taint-eviction rate limiting — each independently conformance-visible.
   Risk: high surface area for subtle behavioral drift; ~47 controllers is a
   large parity target even before rewrite quality is considered.
4. **S2 — fold into apiserver+scheduler binary.** Best-case combined number
   (45 MB for all three) but, per the doc's own honest accounting, does not
   clear Gate 4 alone (kubelet+CRI-O+kube-proxy = 209 MB untouched by this).
   Single-failure-domain risk: a reconciler panic takes down the API server.
5. **S3 — partial rewrite, split with upstream KCM.** The doc's own
   pessimistic case (+14 to +19 MB, worse than doing nothing) plus a named
   correctness hazard (duplicate informers, split ownership of the same
   objects) — the doc's own analysis argues against this option, and this
   audit found no reason to disagree.

### Recommendation

Treat S0 (option 2) as the next step, explicitly re-scoped to name a lever
other than GOMEMLIMIT/GOGC/GOMAXPROCS/`--concurrent-gc-syncs` (already
spent). Do not open a KCM rewrite (S1/S2) yet: like kubelet, it cannot clear
Gate 4 by itself, and — unlike kubelet, where the input doc's own conclusion
already says this — the KCM doc stops short of stating it as plainly. This
audit makes it explicit: the same "kubelet + CRI-O + kube-proxy = 209 MB
already exceeds 128 MB" fact from the kubelet doc applies here without
modification, so a KCM rewrite is gated on the same open kubelet/CRI-O
decisions, not a decision KCM can resolve alone. Confidence: medium-high —
strong on the "not yet" call given the budget math is unambiguous; weaker on
S0's remaining numeric potential now that the doc's named lever turned out
to be already-spent, since no substitute lever has been measured.

## Cross-cutting

**The GOMEMLIMIT/GOGC/GOMAXPROCS pattern is duplicated, not shared.**
kubelet (`scripts/conformance/lima-start.sh:550-552`) and KCM
(`scripts/conformance/04-start-kcm.sh:80-82`) both hand-set the identical
tuple (`200MiB`/`50`/`2`) via separate, independently-authored
`Environment=`/`export` blocks with near-duplicate justification comments.
kube-proxy has neither. A single documented default tuple (with a
one-line override point per component) would prevent the exact gap this
audit found — a component silently missing tuning its siblings already
proved out — and would make "did we already try this" answerable by
grep instead of by an audit like this one.

**Production ships untuned.** `scripts/install.sh` (the production install
path) sets **no** GOMEMLIMIT/GOGC/GOMAXPROCS anywhere, for either kubelet or
KCM — confirmed by grep, zero matches. Both tunings were proven and merged
in the *conformance dev-loop* scripts (`scripts/conformance/lima-start.sh`,
`scripts/conformance/04-start-kcm.sh`) but never ported to what a real
deployment actually runs. Every RSS number in all three input docs — and in
`mayor-lulpm`, the audit they all cite — is measured on the tuned
conformance path. **A production install today likely runs meaningfully
higher than the cited 125.7 MB (kubelet) / 109.2 MB (KCM) figures**, closer
to the pre-tuning numbers documented in mayor-iefj5's own before/after
(kubelet up to 235 MB sawtooth peak pre-tuning). This is the single most
actionable, lowest-risk finding in this whole consolidation.

**All three components are candid about their own uncertainty**, and none
of the three input docs argues for an immediate rewrite disproportionate to
the evidence — kubelet's doc concludes against a rewrite outright, kube-proxy's
doc makes no rewrite argument at all, and KCM's doc's own "what the numbers
don't say" section pre-empts the most likely overreach ("measure S0 before
crediting S1/S2... attributing tuning wins to the rewrite is the easiest way
to overstate this by 60%"). No scope-overreach correction was needed against
any of the three — an explicit non-finding, stated because Rule 12 requires
surfacing the absence of a problem as clearly as its presence.

## Not-reviewed / gaps

- **Whether a reduced-scope kubelet passes Conformance** (dropping
  topology/CPU/memory managers, DRA, most volume plugins) — flagged by the
  kubelet doc itself, not independently checked here; would gate option 2
  above before it can be trusted.
- **KCM's actual internal memory split** (text vs heap vs informer cache) —
  no `/metrics`/`go_memstats` scrape exists for KCM in any archived
  conformance run; the doc's own top recommendation (scrape it) was not
  acted on here, only confirmed as still-missing.
- **"Stable across four runs" KCM claim** — spot-checked against one of the
  four cited runs (`0827-1443`, exact match); the other three
  (`0819-0255`, `0820-0510`, `0820-1426`) were not re-aggregated within
  this audit's budget.
- **Kube-proxy's ~15 remaining upstream line citations** (beyond the one
  function independently re-fetched and confirmed exact) — not
  individually re-verified; treated as credible given the one spot-check's
  precision.
- **Whether u7s's store can serve KCM-equivalent controller reads without a
  per-controller cache** — the S2 optimistic case's central design
  assumption, explicitly untested per the input doc, not investigated
  further here (out of scope: this is a store-architecture question, not a
  claim to verify).
- **CNI-native kube-proxy replacement feasibility** — out of scope per the
  input doc's own framing and this audit's non-goals.

## Sources

- `temp/kubelet-responsibilities-2026-08-28.md`,
  `temp/kube-proxy-responsibilities-2026-08-28.md`,
  `temp/kube-controller-manager-rust-evaluation-2026-08-28.md` (input docs,
  not modified).
- `ai/findings/2026-08-28-mayor-lulpm-conformance-memory-analysis.md` (memory
  baseline all three input docs cite).
- `temp/k8s-src` (mayor's cached sparse clone, kubernetes/kubernetes
  `v1.36.4`) — used for `kubelet.go`, `controller_descriptor.go`,
  `controller_names.go`, `bootstrap.go`, `core.go` cross-checks.
- `kubernetes/kubernetes@v1.36.4:pkg/proxy/util/utils.go`, fetched fresh via
  `gh api` (not in the cached clone), saved to this worktree's
  `temp/research/proxy-util-utils.go`.
- `scripts/conformance/lima-start.sh`, `scripts/conformance/04-start-kcm.sh`,
  `scripts/install.sh`, `lima/kubelet.yaml`, `crates/apiserver/src/handlers/proxy.rs`,
  `crates/scheduler` (u7s source, cross-checked directly).
- `ai/extended-context/roadmap.md`, `ai/extended-context/north-star.md`,
  `docs/decisions/upstream-component-shipping-shape.md`,
  `ai/perf/mayor-5x0kh-k3s-matched-comparison-2026-08-20.md` (all
  cross-checked, all confirmed as cited).
- bd beads: mayor-iefj5, mayor-kagyg, mayor-e5b0j, mayor-pjtkz, mayor-0girw
  (closed prior tuning work, confirmed via `bd show`).
- bd memories: `gate4-budget-excludes-pods-not-just-workloads`,
  `u7s-rust-owns-only-apiserver-scheduler-store`,
  `kubelet-eviction-manager-cannot-preempt-sub-60s-bursts-upstream-limitation`
  (confirmed via `bd memories`).
