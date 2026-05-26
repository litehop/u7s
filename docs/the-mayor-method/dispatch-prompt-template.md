# Dispatch Prompt Template

Mayor sessions should use the following canonical prompts when dispatching
to background agents to ensure safe delegation.

Placeholders used throughout (substitute per project):

- `<MAYOR_CHECKOUT>` — absolute path of the mayor's primary checkout
- `<WORKTREE_ROOT>` — absolute path of the directory holding worker
  worktrees. For this project: `<MAYOR_CHECKOUT>/ai/worktrees/` (inside
  the repo so workers inherit `.claude/settings.json` permissions
  automatically via the `WorktreeCreate` hook)
- `<ASSIGNED_WORKTREE>` — absolute path of the worktree the worker should
  edit (always a subdirectory of `<WORKTREE_ROOT>`)
- `<BEAD_ID>` — the bead identifier (project-specific prefix; here written
  generically rather than with any one project's prefix)

## Worktree boundary — mandatory in every editing dispatch

**Why this block exists.** Shell commands use `workdir`, but `apply_patch` and
some edit tools have no workdir, so relative patch paths can resolve against
the mayor checkout instead of the assigned worktree. "Use your worktree" is
not a strong enough prompt. Workers must verify before each edit and check
both checkouts after the first one.

**The path-resolution leak failure mode.** Observed repeatedly in audit
dispatches: the worker correctly ran the worktree guard and got the right
`WORKTREE_ROOT`, then a file `Write` (especially of a new `ai/findings/<name>.md`
file) landed in the mayor checkout because the edit tool resolved a
repo-relative path against the agent's session root instead of the worker's
git root. Symptoms:

- `git status` inside the worker worktree shows no new findings file.
- `git status` inside the mayor checkout shows a new untracked file under
  `ai/findings/` that the worker thinks it wrote to its worktree.
- The findings file is gitignored so neither side commits it — the boundary
  fails *silently*.

**Defence:** any `Write` of a brand-new file (especially under `ai/findings/`)
must be IMMEDIATELY followed by verifying the file landed in the worker
worktree and NOT in the mayor checkout (see the block below).

### The block (paste verbatim into every editing-worker dispatch)

```text
WORKTREE BOUNDARY - MANDATORY

Your assigned worktree is:
<ASSIGNED_WORKTREE>

The mayor checkout is:
<MAYOR_CHECKOUT>

Never edit the mayor checkout.

Shell workdir is not enough protection. apply_patch and Write tools have no
workdir, so relative patch / write paths can land in the mayor checkout.
This is the path-resolution leak failure mode — the worktree guard at
session start does NOT catch it, because the leak happens mid-session in a
single tool call.

Before every file edit, run:

pwd; git rev-parse --show-toplevel; git status --short --branch

Only edit if git rev-parse --show-toplevel prints exactly:
<ASSIGNED_WORKTREE>

When using apply_patch, Write, or any edit tool, use ABSOLUTE file paths
under <ASSIGNED_WORKTREE> wherever the tool accepts them. If the tool only
accepts relative paths, use paths relative to the session root that
explicitly target the worker worktree:
<WORKTREE_ROOT>/<WORKTREE_NAME>/<repo-relative-path>
Never use bare repo-relative paths unless `git rev-parse --show-toplevel`
for the agent session root is itself the assigned worktree.

After the first edit, immediately run:

git -C <ASSIGNED_WORKTREE> status --short --branch
git -C <MAYOR_CHECKOUT> status --short --branch

Continue only if the worker worktree is dirty and the mayor checkout did
not receive code edits.

NEW-FILE EXTRA CHECK (path-resolution leak). When you Write a brand-new
file (most-common offender: ai/findings/<name>.md from an audit), the
path-resolution leak silently routes the write into the mayor checkout
because the file did not previously exist in either tree. After every
new-file Write, verify BOTH locations:

  ls <ASSIGNED_WORKTREE>/<repo-relative-path>    # must exist
  ls <MAYOR_CHECKOUT>/<repo-relative-path>       # must NOT exist

Only the first should succeed. If the mayor-side ls returns a file, STOP —
you've leaked. Do not retry the write, do not delete the leaked file, do
not commit. Report the leak with both results and let the mayor decide.

If any edit lands outside <ASSIGNED_WORKTREE>, stop immediately and report
it. Do not repair, restore, commit, or push until the mayor tells you what
to do.
```

### Mayor checks after dispatch

- Check the mayor checkout immediately after dispatching:
  `git status --short --branch`.
- Also scan: `ls <MAYOR_CHECKOUT>/ai/findings/` to spot leaked gitignored
  findings the worker meant to put in its own worktree.
- If the mayor checkout gains unexpected code changes, interrupt the
  worker before it does more work.
- Preserve any accidental changes into the worker worktree before
  restoring the mayor checkout.
- Only restore specific known files after preservation. Do **not** use
  broad destructive reset commands.

## Mayor pre-dispatch checklist (run BEFORE calling Agent)

```bash
# 1. Create the worktree (settings.json is already present — it's tracked in git)
git worktree add ai/worktrees/<name> -b worker/<name>
# 2. Verify clean
git -C ai/worktrees/<name> status --short --branch
```

No file copying needed: `settings.json` is tracked in git and present in every
fresh worktree. `agents/worker.md` is loaded from the mayor's `.claude/agents/`
by the harness, not from the worktree.

## Common preamble (every dispatch)

```
You are implementing bead **<BEAD_ID>** in <project description>.

<include project stance obtained from operator>

## Tooling rules (mandatory)

- Use `jq` for JSON parsing in shell — never `python3 -c`.
- Use the `Read` tool for file reads — never `cat`, `head`, or `tail` via Bash.
- Use the `Edit` tool for targeted edits — never `sed` or `awk` via Bash.
- Use the `Grep` tool for search — never shell `grep` / `find` for file I/O.
- Bash is for runtime commands only: `git`, `cargo`, `gh`, `kubectl`, `bd`.
- These are not preferences — violating them triggers permission prompts that
  stall the session. Use the right tool the first time.

## Code style rules (mandatory)

- Write no comments by default. Only add one when the WHY is non-obvious: a hidden
  constraint, a subtle invariant, a workaround for a specific bug.
- Never reference bead IDs, PR numbers, issue refs, or task identifiers in source
  code or comments. Those belong in the PR body and git log — they rot in code.
- Never reference callers or "used by X" — that information belongs in git history.
- Test WHY, not WHAT. Test names and assertion messages must state why the behaviour
  matters (what breaks for a user if it regresses), not just describe what the code does.
```

## Worktree path convention

Per project policy, worker worktrees live under:

```
<WORKTREE_ROOT>
```

Not `.claude/worktrees/agent-*` (forbidden — leaks edits to mayor checkout
via tool-path-resolution quirks; see "Worktree boundary" above).
Not a sibling directory outside the repo (`.claude/settings.json` is tracked
in git and present in any worktree inside the repo — no copying needed).
For this project the correct root is `<MAYOR_CHECKOUT>/ai/worktrees/`.

---

## Shape 1 — Solo bead implementation

One bead, one PR. Standard shape. Sections: bead ID + verbatim title; 2–4
paragraphs of context with `file:line` citations; numbered concrete steps;
worktree at `<WORKTREE_ROOT>/<descriptive>-<BEAD_ID>` with branch
`worker/<descriptive>-<BEAD_ID>`; include worktree-boundary block; `bd
update <BEAD_ID> --claim` + `--status=in_progress`; quality gates with exact
commands; push + `gh pr create` titled `<scope>(<artefact>): <summary>
(<BEAD_ID>)`; return PR URL + per-step summary + test deltas, under <N> words.

Step 0 — verify (do NOT start with `cd`):
```bash
git -C <ASSIGNED_WORKTREE> rev-parse --show-toplevel
git -C <ASSIGNED_WORKTREE> branch --show-current
git -C <ASSIGNED_WORKTREE> status --short
```
Only proceed if `rev-parse --show-toplevel` prints exactly `<ASSIGNED_WORKTREE>`.

Quality gate — mandatory, run in this exact order, paste output into return:
```bash
cargo fmt --all
cargo fmt --all -- --check
cargo test --workspace --quiet
cargo clippy --workspace --tests --quiet -- -D warnings
```
Do not proceed to PR if any command fails. Note: `gh pr create` and `git push`
are intercepted by a pre-tool hook that re-runs fmt+test+clippy and will block
if they fail — running them here first means you see the failure with context.

---

## Shape 2 — Cluster (multiple beads, single PR, sequenced commits)

3–12 beads on a shared surface. Sections: cluster name + N beads + source
findings; numbered bead list ordered **smallest cleanup → biggest correctness
fix** (so a failing P1 fix doesn't strand the small cleanups); commit format
`<scope>(<artefact>): <summary> (<BEAD_ID>)`; worktree at
`<WORKTREE_ROOT>/<cluster-name>-<HEAD_BEAD_ID>`; pre-claim each bead BEFORE
its commit (so bd state mirrors history one-to-one and a stalled cluster
leaves a clean partial trail); quality gates after EACH commit + full
regression after ALL; PR titled `<scope>(<artefact>): <cluster name> (N beads
incl. <P1 highlights>)`; return PR URL + per-bead one-liner + cross-bead
unifications spotted. Disjoint-surface "small-misc" clusters are valid at
the tail of a drain — the binding rule is hot-zone parallelism, not strict
same-surface.

Key cluster discipline:

- **Smallest+safest commit first; biggest correctness fix last.** If the P1
  fix breaks something, the small refactors land cleanly first.
- **Spell out commit ordering.** Don't leave it to the agent.
- **Note cross-bead unifications.** They surface real wins.
- **Bead pre-claim before each commit.** So bd state mirrors commit history
  one-to-one and a stalled cluster leaves a clean partial trail.

---

## Shape 3 — Audit (read-only research)

One bead asks for a finding, not a fix. Sections: goal (read `<surface>`
end-to-end; identify correctness drifts, perf hotspots, API hygiene, testing
gaps, cross-artefact coupling); reference (surface paths, relevant spec
docs, recent landings that changed the surface, prior audit findings to avoid
re-discovering); worktree + boundary block + `--status=in_progress`;
**WRITE THE FINDINGS DOC FIRST** to `ai/findings/<surface>-audit-YYYY-MM-DD.md`
(gitignored — never commit findings); file follow-on beads ONE AT A TIME after
the doc lands, appending each bead ID to the audit-bead's notes so partial
progress is durable across a watchdog timeout; close audit-bead with verdict +
cross-refs; no PR by default (trivial one-line obvious fixes can ride along in
a small PR); return under 400 words with per-finding `file:line` citations +
follow-on bead IDs + severity counts (HIGH/MED/LOW/DEFER) + verdict.

Critical learnings:

- **Findings doc FIRST, before any `bd create`.** Audit work can stall
  mid-bead-filing (watchdog timeout, model error). Doc-first preserves
  the analysis even if the bead-filing loop never completes.
- **One bd-create at a time + update parent notes after each.** Partial
  progress survives a watchdog timeout.
- **Name the recent landings** so the audit reads the current reality.
- **Severity tags** (HIGH/MED/LOW/DEFER) make later cluster-formation trivial.
- **`ai/findings/` is gitignored.** Never open a PR that adds a findings doc.

---

## Shape 4 — Cluster reviewer (research + recommendation only, no dispatch)

Used between major dispatch waves to shape the next round. Read-only — no
worktree boundary block needed. Sections: cluster policy verbatim; in-flight
workers + their surfaces (do NOT recommend changes that touch these); enumerate
beads filed in the last ~30 min via
`git log -p --since='35 minutes ago' -- .beads/issues.jsonl`; per-bead decide:
(A) add to in-flight cluster / (B) form new cluster (3+ beads on shared
non-in-flight surface) / (C) solo (P0/P1 correctness, structural >250 LoC,
decision-resolved, cross-cutting) / (D) defer; structured output template;
net recommendation in 2–3 sentences with specific timing + dispatch shape.
**Do not change bd state.**

---

## Shape 5 — Fix CI failure on a specific PR

One PR has a failing check that isn't obviously irrelevant. Sections:
the failing check name + log lines verbatim; 2–3 root-cause hypotheses;
worktree at `<WORKTREE_ROOT>/<branch-name>-fix` checking out the existing
branch (not a new one); boundary block; investigation steps; pick the fix:
(A) surgical / (B) medium / (C) skip + file follow-on bead (appropriate when
stance allows a safe-out and the fix proves deeper than the bead's scope);
verify locally; **push to the existing PR branch, not main**; return under 300
words with root cause + fix chosen + verification. Diagnosis often surfaces
deeper insight than the failure log shows — test the hypothesis before applying
the fix.

---

## Lima VM protocol

### When to inject

Inject the block below for **any** bead that touches:
- `scripts/conformance/` or `scripts/*-start.sh` (script correctness)
- RBAC handlers, auth middleware, collection delete, namespace drain (sonobuoy smoke path)
- Any handler or middleware that the sonobuoy delete/run flow exercises

Cargo tests alone are not sufficient for these beads. `sonobuoy delete --all`
exercises a runtime code path (RBAC index, label selector filtering, namespace
termination) that unit tests cannot cover. A worker that passes `cargo test` but
skips VM verification is shipping untested code.

### The block (paste verbatim into applicable dispatch prompts)

```
## Lima VM protocol — MANDATORY for this bead

You have the lima-node MCP server available. Use `mcp__lima-node__run_shell_command`
to run commands directly inside the lima VM. You also have `limactl shell lima-node
<cmd>` via Bash. Both are in your allowlist. The VM is always available.

**Cargo tests are not sufficient.** This bead touches a runtime path that
sonobuoy exercises. You must verify against the live server.

Verification sequence (do not skip any step):

1. Build and start the server in the host terminal:
   ```bash
   cargo build -p u7s-apiserver --release 2>&1 | tail -5
   # kill any running instance, then:
   RUST_LOG=info ./target/release/u7s-apiserver &
   sleep 2
   ```
2. From the VM, run the sonobuoy smoke:
   ```
   mcp__lima-node__run_shell_command: ["sonobuoy", "delete", "--all", "--wait",
     "--kubeconfig", "/tmp/sonobuoy-kubeconfig"]
   ```
   Expected: exits 0 with no error lines. If it fails, read the server log and
   debug in the VM until it passes.
3. Your return MUST include the raw output of the sonobuoy delete command.
   A return without this output will be rejected.

For script-only beads (no server restart needed):
1. Run the exact commands manually in the VM first.
2. Then encode them in the script.
3. Run the script in the VM and verify exit 0.
4. Include at least one `mcp__lima-node__run_shell_command` output in your return.
```

### Mayor enforcement at return-review time

When a worker returns from a VM/sonobuoy-touching bead:
- Check the return for sonobuoy delete output or `mcp__lima-node__run_shell_command` evidence.
- If absent: **do not merge**. Send back: "Your return contains no VM execution
  evidence. Run `sonobuoy delete --all --wait` in the lima VM and show the output."
- The hook pre-checks cargo quality gates. VM verification is the mayor's gate.

---

## Common failure modes these patterns close

- **Agents add back-compat shims by default.** Pre-alpha posture must be
  explicit in every preamble.
- **Same-file races between concurrent agents.** "Concurrent agents on
  disjoint surfaces: <list>" prevents this.
- **Workers leak edits into mayor checkout.** The worktree-boundary block
  is the only reliable defence.
- **Path-resolution leak on new-file Write** (especially `ai/findings/*` from
  an audit) routes the file into the mayor checkout silently → new-file
  double-check with `ls` on both paths in the worktree-boundary block.
- **Stalled agents lose analysis.** "Findings doc FIRST" recovery protocol
  salvages partial progress.
- **Clusters split when they should be one PR.** Cluster reviewer
  pre-validates dispatch shape.
- **Hot-zone files cause merge conflicts.** Explicit hot-zone list in every prompt.
- **Agents re-discover known issues.** Naming recent landings + prior
  findings docs prevents this.
- **Workers use `gh pr create` to bypass the pre-push hook.** The PreToolUse
  hook intercepts `gh pr create` and `gh pr edit` the same way it intercepts
  `git push`. Dispatch prompt must also mandate running quality gates before
  pushing so workers see failures with context, not as a hook rejection.
- **Workers pass cargo tests but skip sonobuoy smoke verification.** Unit tests
  cannot cover the runtime RBAC/auth/collection-delete/namespace-drain path.
  Inject the Lima VM protocol block and enforce VM evidence at return-review time.
- **Workers use Python or shell tools instead of permitted built-ins.**
  `python3 -c` for JSON, `cat`/`head` for file reads, `sed`/`awk` for edits
  — all trigger permission prompts and slow the session. Always inject the
  common preamble verbatim.
- **Mayor "gets into the flow" and codes instead of dispatching.** The
  four-condition exception test is easy to rationalize past once the mayor has
  already read several files. The fourth condition (≤2 files read) is the
  circuit breaker. Workers have the lima-node MCP server and can debug live.
  Write a better brief.
- **Workers guess at VM behaviour instead of observing it.**
  `mcp__lima-node__*` and `limactl shell` are both available. Inject the Lima
  VM protocol block for any bead touching `scripts/conformance/`,
  `scripts/*-start.sh`, or sonobuoy-exercised handlers.
- **Workers embed bead IDs and task refs in source comments.** These rot
  immediately as beads close and PRs age. The common preamble bans bead IDs
  in source. Enforce it at review time — if a diff contains `(mayor-`, send
  the worker back.
- **Generic prompts produce generic work.** Always include file:line
  citations + concrete fix sketches.
- **Findings docs leak into PRs.** `ai/findings/` is gitignored; never
  commit one.
- **Mayor force-merges through a failing check with `--admin`.** NEVER use
  `--admin`. If a check fails: read the log first. If it is a transient GitHub
  infra flake (e.g. `fatal: could not read Username`, checkout auth failure,
  runner timeout unrelated to the diff), rerun the specific job with
  `gh run rerun <run-id> --failed` and wait for green. Only merge when ALL
  checks are green.
- **Branch-delete-on-merge fails.** See Mayor Merge Protocol in
  [`bootstrap.md`](./bootstrap.md) (the PR merge `/loop` block).

## What goes RIGHT with these patterns

A long-lived mayor session running these patterns end-to-end tends to produce,
in a single working day:

- A dozen or more audit umbrellas that surface dozens of follow-on beads;
  those beads cluster cleanly and ship as a small number of PRs with
  substantive per-PR scope rather than churn.
- Multiple P1 correctness fixes shipped alongside measurable performance wins
  (the audit-then-cluster cycle surfaces inefficiencies the bead system hadn't
  framed as bugs).
- API surfaces tighten as cross-bead unifications get spotted during cluster
  authoring.
- The project's stance becomes culture — agents reach for the right shape of
  fix by default instead of needing the policy re-stated in every prompt.

The compounding effect is the point: each audit informs the next cluster; each
merged cluster removes scope from the next audit; the operator's attention
concentrates on decisions instead of bookkeeping.

## Pointers to canonical examples

These are project-specific. When applying the method to a new project,
record your own canonical examples here once you have them:

- **Solo done well**: <bead-id + 1-line of why this is exemplary>
- **Cluster done well**: <cluster name + bead-count + a surprise the
  cluster surfaced that wasn't visible bead-by-bead>
- **Audit done well**: <audit bead-id + per-finding follow-on count +
  the analytical move that made it valuable>
- **CI fix done well**: <bead-id + the diagnosis-vs-surface-log
  distinction the worker drew>

Keep the list short. Three or four good examples teach a new mayor more
than thirty mediocre ones.
