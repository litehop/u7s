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

### Root cause (why the block exists)

Workers understand they're assigned to separate worktrees, and their shell
commands generally use the right `workdir`. The failure mode is subtler:
**`apply_patch` has no explicit `workdir`**, so relative patch paths can
resolve against the session/default checkout, not the shell worktree the
worker just used. "Use your worktree" is not a strong enough prompt. Patch
tools and shell tools do not share the same scoping guarantees.

### The safe delegation pattern

- Shell commands use `workdir` / `cd` inside the assigned worktree.
- Edit tools use paths that are **relative to the session root** and
  explicitly walk into the assigned worktree.
- The worker checks both the worker worktree AND the mayor checkout
  immediately after the first edit.


Repo-relative paths are **forbidden** for worker `apply_patch` calls
unless the agent session root is itself the assigned worker worktree.

### The block (paste verbatim into every editing-worker dispatch)

```text
WORKTREE BOUNDARY - MANDATORY

Your assigned worktree is:
<ASSIGNED_WORKTREE>

The mayor checkout is:
<MAYOR_CHECKOUT>

Never edit the mayor checkout.

Shell workdir is not enough protection. apply_patch has no workdir, so
relative patch paths can land in the mayor checkout.

Before every file edit, run:

pwd; git rev-parse --show-toplevel; git status --short --branch

Only edit if git rev-parse --show-toplevel prints exactly:
<ASSIGNED_WORKTREE>

When using apply_patch or any edit tool, use absolute file paths under
<ASSIGNED_WORKTREE> if the tool accepts them.

If the edit tool does not accept absolute paths, use paths relative to
the session root that explicitly target the worker worktree. That
usually means walking out of the mayor checkout and into the worktree
root:

<WORKTREE_ROOT>/<WORKTREE_NAME>/<repo-relative-path>

Never use repo-relative edit paths such as `<repo-relative-path>` on
their own unless `git rev-parse --show-toplevel` for the agent session
root itself is the assigned worktree.

After the first edit, immediately run:

git -C <ASSIGNED_WORKTREE> status --short --branch
git -C <MAYOR_CHECKOUT> status --short --branch

Continue only if the worker worktree is dirty and the mayor checkout
did not receive code edits.

If any edit lands outside <ASSIGNED_WORKTREE>, stop immediately and
report it. Do not repair, restore, clean up, commit, or push until the
mayor tells you what to do.
```

### Mayor checks after dispatch

- Check the mayor checkout immediately after dispatching:
  `git status --short --branch`.
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

```
<COMMON PREAMBLE>

## Bead

```
<verbatim bead title + priority + source-finding-doc>
```

## Context

<2-4 paragraphs explaining what's wrong and why it matters; cite file:line>

## Concrete steps

1. <numbered, file:line-precise actions>
2. ...

## Process

**Your worktree is already created by the mayor at `<WORKTREE_ROOT>/<descriptive>-<BEAD_ID>`, branch `worker/<descriptive>-<BEAD_ID>`.**

Step 0 — verify (do NOT start with `cd` — it is not in the Bash allowlist and will be denied):
```bash
git -C <ASSIGNED_WORKTREE> rev-parse --show-toplevel
git -C <ASSIGNED_WORKTREE> branch --show-current
git -C <ASSIGNED_WORKTREE> status --short
```
Only proceed if `rev-parse --show-toplevel` prints exactly `<ASSIGNED_WORKTREE>`.
You may `cd` into the worktree after these pass — but not as your first command.

1. `bd update <BEAD_ID> --claim` then `bd update <BEAD_ID> --status=in_progress`.
2. Implement.
3. **Quality gate — mandatory, run in this exact order, paste the output into your return:**
   ```bash
   cargo fmt --all
   cargo fmt --all -- --check
   cargo test --workspace --quiet
   cargo clippy --workspace --tests --quiet -- -D warnings
   ```
   Do not proceed to step 4 if any command fails. Fix the failure first.
   Note: `gh pr create` and `git push` are both intercepted by a pre-tool hook
   that re-runs fmt+test+clippy and will block if they fail. Running them here
   first means you see the failure with context, not as a cryptic hook rejection.
4. Push branch + `gh pr create` with title `<scope>(<artefact>): <summary> (<BEAD_ID>)`.

## Return

Under <N> words: PR URL + per-step summary + test deltas (how many tests before/after).

<COMMON CONSTRAINTS>
```

---

## Shape 2 — Cluster (multiple beads, single PR, sequenced commits)

```
<COMMON PREAMBLE adapted for "CLUSTER of N beads">

## Cluster: "<descriptive name>"

N beads from <audit/source>. Findings (local-only):
`ai/findings/<doc>.md`. Surface: <shared file/artefact>.

## Beads + commit ordering (smallest cleanup → biggest correctness fix)

**Commit format**: `<scope>(<artefact>): <summary> (<BEAD_ID>)`.

1. **<BEAD_ID-1> (P3)** — <one-line + scope>
2. **<BEAD_ID-2> (P3)** — <one-line>
...
N. **<BEAD_ID-N> (P1 BUG)** — <one-line + concrete fix sketch + regression test ask>

## Process

**Your worktree is already created by the mayor at `<WORKTREE_ROOT>/<cluster-name>-<HEAD_BEAD_ID>`, branch `worker/<cluster-name>-<HEAD_BEAD_ID>`.**

Step 0 — verify and enter:
```bash
cd /Users/balint.erdos/u7s/ai/worktrees/<cluster-name>-<HEAD_BEAD_ID>
pwd; git rev-parse --show-toplevel; git branch --show-current
```
Only proceed if show-toplevel prints `/Users/balint.erdos/u7s/ai/worktrees/<cluster-name>-<HEAD_BEAD_ID>`.

1. For each bead: `bd update <BEAD_ID> --claim` + `--status=in_progress`
   BEFORE that bead's commit.
2. Run quality gates after EACH commit. After ALL: full regression.
3. Push + `gh pr create` with title
   `<scope>(<artefact>): <cluster name> (N beads incl. <P1 highlights>)`.

## Return

Under <N> words: PR URL + per-bead one-line + test deltas + cross-bead unifications.

<COMMON CONSTRAINTS>
```

Key cluster discipline:

- **Smallest+safest commit first; biggest correctness fix last.** If the
  P1 fix breaks something, the small refactors land cleanly first.
- **Spell out commit ordering.** Don't leave it to the agent.
- **Note cross-bead unifications.** They surface real wins (e.g. a cluster
  may find a multi-commit refactor arc shared across several beads, or
  unify duplicate helper code that wasn't previously visible as a
  single concern).
- **Bead pre-claim before each commit.** So bd state mirrors commit
  history one-to-one and a stalled cluster leaves a clean partial trail.

---

## Shape 3 — Audit (read-only research)

```
<COMMON PREAMBLE adapted for "audit bead <BEAD_ID>">

## Goal

Read `<surface>` end-to-end and produce a findings report identifying:
1. **Correctness drifts** — places where impl diverges from spec
2. **Performance hotspots** — allocations, missed batching, double-walks
3. **API hygiene** — fn names, public surface, missing docstrings
4. **Testing gaps** — concurrency, hot-reload, error paths
5. **Cross-artefact coupling**

## Reference

- <surface paths>
- <relevant spec docs>
- <recent landings affecting this surface — name them so the audit reads
  the post-landing reality>
- <prior audit findings docs to avoid re-discovering>

## Process

**Your worktree is already created by the mayor at `<WORKTREE_ROOT>/<surface>-audit-<BEAD_ID>`, branch `worker/<surface>-audit-<BEAD_ID>`.**

Step 0 — verify and enter:
```bash
cd /Users/balint.erdos/u7s/ai/worktrees/<surface>-audit-<BEAD_ID>
pwd; git rev-parse --show-toplevel; git branch --show-current
```
Only proceed if show-toplevel prints `/Users/balint.erdos/u7s/ai/worktrees/<surface>-audit-<BEAD_ID>`.

1. Worktree at
   `<WORKTREE_ROOT>/<surface>-audit-<BEAD_ID>`
   with branch `worker/<surface>-audit-<BEAD_ID>`.
2. Include worktree-boundary block.
3. `bd update <BEAD_ID> --status=in_progress`.
4. **WRITE FINDINGS DOC FIRST** to
   `ai/findings/<surface>-slice-audit-YYYY-MM-DD.md`
   (local-only; gitignored — `ai/findings/` is not tracked).
   Do all analysis + write findings BEFORE running any `bd create`.
   Earlier audits stalled mid-bead-filing and lost analysis.
5. File follow-ons via `bd create` ONE AT A TIME (after each, append the
   new bead ID to <BEAD_ID> notes — partial progress stays durable).
6. Close <BEAD_ID> with verdict + cross-refs.
7. **No PR by default.** Findings docs are local-only and must NOT be
   committed. Trivial one-line obvious fixes are OK to bundle into a
   small PR.

## Return

Under 400 words: per-finding file:line citations + follow-on bead IDs +
severity counts (HIGH/MED/LOW/DEFER) + verdict.

<COMMON CONSTRAINTS adapted: "You're READING surfaces concurrent agents
are writing — that's fine for audits but flag any rendezvous concerns.">
```

Critical learnings:

- **Findings doc FIRST, before any `bd create`.** Audit work can stall
  mid-bead-filing (watchdog timeout, model error). Doc-first preserves
  the analysis even if the bead-filing loop never completes.
- **One bd-create at a time + update parent notes after each.** Partial
  progress survives a watchdog timeout.
- **Name the recent landings** so the audit reads the current reality,
  not a stale picture.
- **Severity tags** (HIGH/MED/LOW/DEFER) make later cluster-formation
  trivial.
- **`ai/findings/` is gitignored.** Never open a PR that adds a findings
  doc. Convert actionable findings into bead bodies / spec / docs.

---

## Shape 4 — Cluster reviewer (research + recommendation only, no dispatch)

```
You are a clustering reviewer for the project's bead queue.
**Research + recommendation only — do NOT dispatch agents, do NOT change
bd state.** Report findings.

## Context

<repo + time>

## Cluster policy (the operator's words verbatim)

> When multiple open beads target the same surface ... [policy text]

## In-flight (do NOT recommend changes that touch these)

<agents working + surfaces>
<PRs in queue + surfaces locked>

## Your task

1. Enumerate beads filed in last ~30 min via
   `git log -p --since='35 minutes ago' -- .beads/issues.jsonl`.
2. For each, determine surface via `bd show <id>`.
3. Decide per-bead:
   - (A) Add to in-flight cluster
   - (B) Form NEW cluster (3+ beads on shared non-in-flight surface)
   - (C) Solo dispatch (P0/P1 correctness, structural >250 LoC,
         decision-resolved, cross-cutting)
   - (D) Defer
4. <Specific question about this round's pattern>

## Output format

<structured template>

## Net recommendation

2-3 sentences. Specific timing + dispatch shape.
```

Used between major dispatch waves to shape the next round. Saves operator
effort by surfacing the optimal cluster shape from the audit-then-cluster
cycle. **Read-only — no worktree boundary block needed.**

---

## Shape 5 — Fix CI failure on a specific PR

```
<COMMON PREAMBLE>

PR #NNNN (`<title>`) has a CI failure: `<failing check>`.

## Failure

```
<paste failing log lines verbatim>
```

## Hypotheses (likely)

1. <root cause guess 1>
2. <root cause guess 2>

## Concrete steps

1. **Worktree**: `git worktree add
   <WORKTREE_ROOT>/<branch-name>-fix <branch>`.
2. Include worktree-boundary block.
3. <investigation steps>
4. **Pick the fix**:
   - **(A)** <surgical option>
   - **(B)** <medium option>
   - **(C)** Skip + file follow-on bead — appropriate when the project
     stance allows a safe-out (e.g. pre-alpha) and (A)/(B) prove deeper
     than the bead's scope.
5. Verify locally if possible.
6. Push fix to PR branch (not main).

## Return

Under 300 words: root cause + fix chosen + verification.

<COMMON CONSTRAINTS — additional: "Push to existing PR branch, not main.">
```

Diagnosis often surfaces deeper insight than the failure log shows. A
classic example: "X subsystem can't find port" turns out to be a missing
callback option in a higher layer, not the network failure the log
suggested. Worker should test their hypothesis before applying the fix.

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

## What goes WRONG without these patterns

- **Agents add back-compat shims by default.** Pre-alpha posture must be
  explicit in every prompt.
- **Same-file races between concurrent agents.** "Concurrent agents on
  disjoint surfaces: <list>" prevents this.
- **Workers leak edits into mayor checkout.** The worktree-boundary block
  (separate doc) is the only reliable defence.
- **Stalled agents lose analysis.** "Findings doc FIRST" recovery protocol
  salvages partial progress.
- **Clusters split when they should be one PR.** Cluster reviewer
  pre-validates dispatch shape.
- **Hot-zone files cause merge conflicts.** Explicit hot-zone list in every
  prompt.
- **Agents re-discover known issues.** Naming recent landings + prior
  findings docs prevents this.
- **Workers use `gh pr create` to bypass the pre-push hook.** The PreToolUse
  hook now intercepts `gh pr create` and `gh pr edit` the same way it intercepts
  `git push` — running fmt+test+clippy before either is allowed. But the dispatch
  prompt must also mandate running quality gates explicitly before pushing, so
  workers see failures with context rather than as a hook rejection.
- **Workers pass cargo tests but skip sonobuoy smoke verification.** Unit tests
  cannot cover the runtime RBAC/auth/collection-delete/namespace-drain path that
  sonobuoy exercises. For any bead touching those surfaces, inject the Lima VM
  protocol block and enforce VM evidence at return-review time. Do not merge
  without it.
- **Workers use Python or shell tools instead of permitted built-ins.** `python3 -c`
  for JSON, `cat`/`head` for file reads, `sed`/`awk` for edits — all trigger
  permission prompts and slow the session. The common preamble tooling rules
  prevent this if injected. Always inject the common preamble verbatim.
- **Mayor "gets into the flow" and codes instead of dispatching.** The three-
  condition exception test is easy to rationalize past once the mayor has already
  read several files. The fourth condition (≤2 files read) is the circuit breaker.
  If the mayor is debugging a runtime issue, it has already failed the test.
  Workers have the lima-node MCP server and can debug live. Write a better brief.
- **Workers guess at VM behaviour instead of observing it.** `mcp__lima-node__*`
  and `limactl shell` are both available. For any bead touching `scripts/conformance/`,
  `scripts/*-start.sh`, or sonobuoy-exercised handlers, inject the Lima VM protocol
  block verbatim.
- **Workers embed bead IDs and task refs in source comments.** These rot immediately
  as beads close and PRs age. The fix: the common preamble now explicitly bans bead
  IDs in source. Enforce it at review time — if a diff contains `(mayor-`, send
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
  checks are green. `--admin` bypasses branch protection and is not appropriate
  even for obvious infra flakes.
- **Branch-delete-on-merge fails.** See Mayor Merge Protocol in
  [`bootstrap.md`](./bootstrap.md) (the PR merge `/loop` block).

## What goes RIGHT with these patterns

A long live Mayor session that ran these patterns end-to-end tends to
produce, in a single working day:

- A dozen or more audit umbrellas that surface dozens of follow-on
  beads; those beads cluster cleanly and ship as a small number of PRs
  with substantive per-PR scope rather than churn.
- Multiple P1 correctness fixes shipped alongside measurable
  performance wins (the audit-then-cluster cycle surfaces inefficiencies
  the bead system hadn't framed as bugs).
- API surfaces tighten as cross-bead unifications get spotted during
  cluster authoring.
- The project's stance (pre-alpha, production-stable, refactor-only,
  etc.) becomes culture — agents reach for the right shape of fix by
  default instead of needing the policy re-stated in every prompt.

The compounding effect is the point: each audit informs the next
cluster; each merged cluster removes scope from the next audit; the
operator's attention concentrates on decisions instead of bookkeeping.

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
