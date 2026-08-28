Bead: mayor-62611

# Stackelberg routing: what transfers to the mayor method

## Recommendation

When the mayor must serialize a hot-zone cluster (multiple beads that touch
the same file), order dispatch by descending conflict-risk — the most
invasive change goes first, while the surface is clean — not by filing
order or priority alone. This is the one Stackelberg move (Largest-Latency-
First) with a concrete, ship-able protocol change.

## Why

`ai/dashboard.md`'s "Longer queue" currently reads: "Tuning: 9dk3n, xpxj5,
kujf3 — serialize, all hot on `install.sh`." The rule says *serialize*, but
not in what order — and order matters. Whichever of the three lands last
inherits every prior sibling's diff as rebase debt; if the biggest change
lands last, its conflict cost balloons with each smaller PR ahead of it.
That is structurally identical to what LLF was built to prevent: a shared,
one-at-a-time resource (a link; here, a file) whose passing order determines
how much accumulated cost the last-in-line pays.

## The mapping

**1. Largest-Latency-First -> hot-zone dispatch order.** LLF: the leader
saturates the highest-latency paths of the optimal flow with its own
controlled flow first, before followers arrive and the path's effective
cost (to whoever is stuck on it) grows. Mapping: leader = mayor, shared
resource = the hot file, "latency" = diff-invasiveness/conflict-risk, which
only increases the longer a bead waits behind smaller siblings. Strain:
there's no follower choosing to defect to a cheaper path — this is a
scheduling call, not equilibrium-seeking. Rule: the hot-zone protocol
default should be biggest-blast-radius-first, not FIFO/priority-only, when
two-plus beads queue on the same surface.

**2. Leader pre-commitment vs. simultaneous (Nash) collision.** Stackelberg:
the leader commits and followers observe it before acting, avoiding the
worse simultaneous-move outcome. This is already practiced —
`dispatch-prompt-template.md:917`: "Hot-zone files cause merge conflicts.
Explicit hot-zone list in every prompt" — the mayor declares the partition
*before* workers act, rather than letting them discover the collision at
merge time. Not a new adoption; the refinement is to extend that static
"which files are hot" declaration to also carry "who goes first" (item 1's
ordering), so the hot-zone list becomes a full route commitment, not just a
collision warning.

**3. Price-of-Anarchy discipline (measure the gap before intervening).**
Stackelberg routing's bound is calibrated against a measured baseline, not
assumed. The mayor already does this: the "Awaiting operator" item on
raising `required_approving_review_count` explicitly sequences "land
mayor-ukzie -> re-measure the 26.7% no-review rate against the 120-PR
baseline -> then raise" rather than tightening blind. Corroborating
evidence of good instinct, not a new rule — worth naming explicitly in
`bootstrap.md` as a checklist step so future mayors do it by habit, not
luck.

## What does NOT map

- **Selfish best-response dynamics.** LLF's core trick is exploiting
  followers' predictable reaction to the leader's commitment. Workers are
  single-shot and cooperative — they don't observe or react to other
  workers' choices, so there is no follower best-response function for any
  assignment strategy to grip. Formal Price-of-Anarchy ratio bounds (e.g.
  4/(3+α)) don't transfer either: dispatch is discrete beads, not a
  continuous flow with a smooth latency function.
- **Braess's Paradox.** Requires decentralized agents choosing their own
  route such that added optionality perversely worsens things. Workers
  never choose their route — the mayor assigns worktree/VM/order directly.
  Over-parallelizing a hot zone causes ordinary congestion (merge
  conflicts), not the paradox.

## Alternatives considered

Auction/priority-queue mechanisms were the nearer candidate for VM-slot and
merge-queue allocation, since those already look like queueing problems.
But auctions solve preference-revelation under private valuations the
center doesn't know; beads already carry mayor-assigned P0-P3 priority and
GitHub's Merge Queue already serializes without bidding — there's no
informational asymmetry to resolve. Stackelberg fits because the friction
is sequencing under one known objective, not multi-party preference
discovery.
