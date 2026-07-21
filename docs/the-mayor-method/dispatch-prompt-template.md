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
# For VM-requiring beads only: assign an unused VM + port + kubelet port from the table above.
#   Check which VMs are in use: limactl list
#   Pick an unused or stopped VM; assign the matching port pair (6444+10251 … 6448+10255).
#   Include --port <PORT> and --kubelet-port <KUBELET_PORT> in dispatch.
#   Workers always bind to 127.0.0.1; port is the only isolation boundary.
```

No pre-create needed: `isolation="worktree"` in the Agent call creates the
worktree automatically and sets the subagent CWD to its root. `settings.json`
is tracked in git and present in every fresh worktree. `agents/worker.md` is
loaded from the mayor's `.claude/agents/` by the harness, not from the worktree.

**Agent tool call — mandatory fields:**

```python
Agent(
    subagent_type="worker",          # required — loads worker.md with permissionMode:auto
    run_in_background=True,
    isolation="worktree",            # creates worktree, sets CWD to its root
    prompt="... include Step 0 below ...",
)
```

**Every dispatch prompt must include Step 0:**

```bash
   pwd                              # confirm CWD is the worktree root
   git rev-parse --show-toplevel    # must match pwd
   git branch --show-current
   git -C <ASSIGNED_WORKTREE> status --short
   ```

## Common preamble (every dispatch)

```
You are implementing bead **<BEAD_ID>** in <project description>.

<include project stance obtained from operator>

## Tooling rules (mandatory)

### Command shaping — PERMISSION-CRITICAL (read first)

The Bash permission allowlist matches on the command's **first token** and the
**whole compound string**. Violating the shape below makes EVERY such call prompt
the operator for permission — which stalls the session. This is not style; it is
how the allowlist works. Three hard rules:

- **One command per Bash call. Never chain unrelated commands with `&&` / `;` / `|`.**
  A single non-allowlisted sub-command (or an unrecognized chain structure) taints
  the ENTIRE batch → prompt. Run `git status`, then `git branch`, then `kubectl …`
  as SEPARATE Bash calls. (Piping into `jq`/`grep` a single allowlisted producer is
  fine, e.g. `gh pr view … --json … | jq …`; the ban is on chaining multiple
  independent actions.)
- **Never use inline env vars or `export`.** Not `export KUBECONFIG=… && kubectl …`,
  and not the prefix form `KUBECONFIG=… kubectl …`. Both make the first token
  `export` / a `VAR=value` assignment instead of an allowlisted binary → prompt.
  The first token of every Bash call MUST be an allowlisted binary: `git`, `cargo`,
  `gh`, `kubectl`, `bd`, `limactl`, `jq`, `rustc`, `rustup`, or `scripts/…`.
- **kubeconfig: ALWAYS pass `--kubeconfig <path>` as a flag** — e.g.
  `kubectl --kubeconfig ./temp/u7s/kubeconfig get pods`. NEVER `export KUBECONFIG`.
  Same for any tool config: prefer the flag over an env var. If a command genuinely
  needs an env var (rare), it almost certainly has a flag equivalent — use that, or
  it belongs inside a script (e.g. `--verbose` sets `RUST_LOG` inside run-all.sh;
  never `export RUST_LOG=` by hand).
- Do NOT start a call with `cd` — `cd` is not allowlisted. Use `git -C <path> …`,
  or rely on your worktree CWD (Step 0 confirms it), and pass paths as arguments.

If a Bash call is denied, that denial is a SIGNAL your command was mis-shaped
(inline env, a batch, a leading `cd`/`export`, or a non-allowlisted first token) —
reshape it into single allowlisted commands; do not abandon the task.

### Other tooling

- Use `jq` for JSON parsing in shell — never `python3 -c`.
- Use the `Read` tool for file reads — never `cat`, `head`, or `tail` via Bash.
- Use the `Edit` tool for targeted edits — never `sed` or `awk` via Bash.
- Use the `Grep` tool for search — never shell `grep` / `find` for file I/O.
- For code navigation (callers, usage paths, rename impact, a symbol's type),
  use the `mcp__mcpls__*` LSP tools — they give the compiler's semantic view,
  not a text match. The Rust LSP (rust-analyzer) IS live and warm in this repo —
  verified working for hover/definition/references at a position. Workflow is
  **grep-then-LSP**: grep to find the symbol string + its line, then
  `get_references` / `get_definition` / `get_hover` at that `file_path` + 1-based
  `line`/`character` to get true refs/def/type (`prepare_call_hierarchy` +
  `get_incoming_calls` for multi-hop caller trees).
- **To understand an EXTERNAL / vendored crate's API (the `~/.cargo/registry/...`
  files): do NOT grep them.** `get_hover` on a call to an external symbol returns
  its full signature + resolved generics + doc comment + docs.rs link without
  reading any file; `get_definition` jumps straight to the exact vendored source
  file+line (e.g. hovering `Certificate::from_der` resolves the trait and jumps
  into `~/.cargo/.../der-0.8.1/src/decode.rs`). This is the correct tool for
  adapting to a dependency bump or checking a crate's real API — grepping the
  cargo registry by hand is slower, misses the resolved types, and triggers
  permission prompts.
- The ONE LSP caveat: `workspace_symbol_search` (whole-workspace search by *name*)
  needs a warm index and can return EMPTY in a fresh worktree. That caveat is
  SPECIFIC to name-search — it does NOT mean "LSP is unreliable, just grep."
  Hover/definition/references AT A POSITION work fine; grep only to find the
  anchor line, then use LSP-at-position for everything semantic.
- Bash is for runtime commands only: `git`, `cargo`, `gh`, `kubectl`, `bd`.
- These are not preferences — violating them triggers permission prompts that
  stall the session. Use the right tool the first time.

## Upstream source rules (mandatory)

Upstream Kubernetes source (e2e test bodies, controllers, API types) is NOT in
this repo. When you need it:

- **Stay inside the repo.** Never `find /`, never read or write files outside
  your worktree, never stash upstream source in `/tmp`.
- **`temp/research/` is the only upstream cache** (gitignored). Read from it,
  and write any upstream file you fetch INTO it. It is not checked out into a
  fresh worktree; if you need a file that lives in the mayor's `temp/research/`,
  ask the mayor to copy it into your worktree — do not reach into the mayor
  checkout or fetch a divergent copy elsewhere.
- **Fetch with `gh api` or `curl`, never `WebFetch`** (blocked for workers).
  E.g. `gh api -H "Accept: application/vnd.github.raw" "/repos/kubernetes/kubernetes/contents/test/e2e/node/pods.go?ref=release-1.36"`.
  Fetch each file ONCE, save it into `temp/research/<filename>`, then grep/read
  the cached copy locally for any further lookups — don't re-fetch per symbol.
- **Pin to the latest Kubernetes version: `1.36.2`** (as of 2026-07) — branch
  `release-1.36` for raw GitHub fetches, and reference 1.36.2 API/test
  semantics, not an older minor. Deviate only if a run's `serverversion.json`
  explicitly shows a different client version for that run.

## Evidence & time discipline (mandatory)

- Before asserting WHEN something happened or what a time gap MEANS, confirm it
  against an actual timestamp — never infer ordering from memory or vibes.
  Sources of truth: the log line's own timestamp, the run-directory name
  (e.g. `temp/e2e/0625-0927-...`), `gh pr view <n> --json mergedAt`, the
  binary/commit time. Run `date -u +"%Y-%m-%dT%H:%MZ"` before writing any
  timestamp; don't guess from session progress.
- Do NOT say "in a previous run", "this predates PR #X", "stale binary", or
  "N minutes later" unless you have checked the timestamps. A line from 20
  seconds ago in the run you just executed is THIS run, not a previous one.
- Watch timezones: apiserver logs are UTC; ginkgo/e2e logs and run-dir names are
  often local time. Normalize before comparing, or a delta is meaningless.
- Quote the evidence for any claim ("apiserver.log 09:35:01 shows…"), and if you
  did not verify it, say so explicitly rather than stating it as fact (Rule 12).

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
quality gates with exact commands; push + `gh pr create` titled
`<scope>(<artefact>): <summary> (<BEAD_ID>)`; return PR URL + per-step
summary + test deltas, under <N> words.

Step 0 — verify CWD is the worktree root:
```bash
pwd
git rev-parse --show-toplevel   # must match pwd
git branch --show-current       # must be worker/agent-<id>
git status --short              # must be clean
```

Quality gate — mandatory, run in this exact order, paste output into return:
```bash
cargo test --workspace --quiet
cargo clippy --workspace --tests --quiet -- -D warnings
```
Do not proceed to commit if any command fails. The pre-commit hook checks
`cargo fmt` (formatting only) and the pre-push hook re-runs test+clippy —
running them here first means you see failures with context, not as a hook
rejection that gives you no stacktrace.

Commit and push:
```bash
git add <files>
git commit -m "..."
git push
gh pr create --title "..." --body "..."
```

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

### Multi-VM model

Each worker that needs runtime verification gets its **own isolated VM stack** —
it does not share the mayor's VM. Up to 6 workers can run in parallel (soft
limit: ~4 GiB RAM per VM).

**Available VMs and their assigned ports:**

| VM name | Host port | Kubelet port | Companion kubelet port | Konnectivity | Notes |
|---|---|---|---|---|---|
| `lima-node` | `6443` | `10250` | `10260` | `8135` | Mayor's VM — never assign to workers |
| slot 1 | `6444` | `10251` | `10261` | `8235` | |
| slot 2 | `6445` | `10252` | `10262` | `8335` | |
| slot 3 | `6446` | `10253` | `10263` | `8435` | |
| slot 4 | `6447` | `10254` | `10264` | `8535` | |
| slot 5 | `6448` | `10255` | `10265` | `8635` | |

**Companion kubelet port** (`10260`-`10265`) is reserved for each slot's 2nd
(companion) node in a two-node conformance run — pass it as `--extra-kubelet-port`
alongside `--extra-node <vm>` to `run-all.sh` (see `scripts/conformance/add-node.sh`).
Unused unless a slot is explicitly running a two-node stack.

All workers bind to `127.0.0.1` — port is the isolation boundary between parallel
workers. Different loopback IPs are NOT reliably reachable from inside Lima VMs via
`host.lima.internal`; port is the only safe differentiator.

**Kubelet port** is the host-side port-forward for guest port 10250. Each slot must use
a distinct kubelet port so parallel workers don't collide on log/exec/attach requests.
Pass `--kubelet-port <N>` to `run-all.sh` and provision the VM with:
`scripts/worker-vm.sh start <vm-name> 127.0.0.1 <kubelet-port>`

The MCP server name mirrors the VM name: `mcp__lima-node-smoke__run_shell_command`
for `lima-node-smoke`, etc.

**Mayor assigns VM and port at dispatch time.** Run `limactl list` to see which VMs are
running; pick an unused or stopped one. Pass the VM name, port, and kubelet port in the
dispatch prompt:

```
Your assigned VM: lima-node-smoke
Your assigned port: 6444
Your assigned kubelet port: 10251
```

The worker uses these to invoke the conformance stack. `run-all.sh` is the single
entry point — it builds, resets, restarts all components, and runs sonobuoy:

Invoke it BARE — the first token of the command MUST be `scripts/...`. Do NOT
prefix with `bash`/`sh` and do NOT lead with `cd ... &&`: the Bash allowlist
matches commands that START WITH `scripts/conformance/run-all.sh`, so any prefix
gets the call denied. If a call is denied, retry the bare form — a denial is a
signal to fix the invocation, not to abort the task.

```
scripts/conformance/run-all.sh --vm lima-node-smoke --port 6444 --workdir ./temp/u7s [--reset] [--verbose] [--focus <regex>] [--stack-only]
```

**⚠️ NEVER dispatch a bare `run-all.sh` (no `--focus`, no `--stack-only`).** A bare
invocation runs the FULL conformance suite, which at the current state runs to the
6h timeout — a scout dispatched to investigate one thing will silently burn the
whole budget on a full run. Every VM dispatch prompt MUST tell the worker to use
EITHER `--stack-only` (investigate via kubectl / direct DB, no sonobuoy at all) OR
`--focus <regex>` (run one targeted test), and to reserve any `--focus` run for a
FINAL confirmation gate — never a bare full run unless a full run is explicitly the
stated goal of the bead.

- **`--stack-only`** — brings up steps 1–5 (build, apiserver, kubelet, KCM,
  scheduler) and SKIPS sonobuoy entirely. The stack is left running; the worker uses
  `kubectl --kubeconfig ./temp/u7s/kubeconfig ...` and `limactl shell <VM> sudo
  sqlite3 ...` / `... grep /tmp/kcm.log` to reproduce and diagnose in seconds. This
  is the DEFAULT for any investigation/scout bead — no sonobuoy needed to repro
  almost anything a conformance test asserts.
- **`--focus <regex>`** — runs sonobuoy for just the matching test(s). Use as the
  final gate once a fix is in, not for iterative diagnosis.
- `--stack-only` + `--focus` together: `--focus` is ignored (warning to stderr),
  stack-only wins.

`--workdir ./temp/u7s` (relative to CWD = worktree root) is where state lands.
`--verbose` turns on `RUST_LOG=debug` (set inside the script — never export it
inline). Omit `--binary` and the script builds the worktree itself, so no manual
`cargo build` is needed. Workers must not hard-code `lima-node` or `6443` anywhere.
`U7S_HOST_IP` is no longer used — workers always bind to `127.0.0.1` and use
`--port` for isolation. The konnectivity port auto-derives from `--port` (6443→8135,
6444→8235, 6445→8335, …); workers no longer need to pass `--konnectivity-server-port`
for standard slots. An explicit `--konnectivity-server-port` override remains available
when needed.

### Verify with kubectl first; reserve sonobuoy for the final gate

A `sonobuoy --focus` run takes 10+ min and can hang for 25 (watchdog reaps the
namespace at 10 min, then ginkgo flails against the dead namespace). Iterating
diagnosis on sonobuoy is the single biggest time sink in this work. Almost
everything a conformance test asserts is reproducible in seconds with `kubectl`
against the running stack. The mechanics (read the test source → reproduce via
kubectl + `/tmp/kcm.log` → fix → run sonobuoy once as the gate → read
`e2e.txt`) are documented in `ai/prompts/vm-operations.md`; a dispatch just needs
to point the worker there and require kubectl evidence in the return.

Worked example (why this matters): `[sig-apps] Job should delete a job` was chased
for hours via repeated sonobuoy runs with conflated symptoms. Reading the test
source revealed it just does create-Job → delete-Job(foreground) → assert-pods-
GC'd; the kubectl repro reproduced the exact failure (pods stuck Terminating) in
seconds and exposed the root cause in `/tmp/kcm.log` (`resource version
mismatch`). Sonobuoy only confirmed what kubectl already proved.

### When to inject

Inject the block below for **any** bead that touches:
- `scripts/conformance/` or `scripts/*-start.sh` (script correctness)
- RBAC handlers, auth middleware, collection delete, namespace drain (sonobuoy smoke path)
- Any handler or middleware that the sonobuoy delete/run flow exercises

Cargo tests alone are not sufficient for these beads. The runtime path (RBAC
index, label-selector filtering, namespace termination, GC/finalizer cascade,
optimistic-concurrency convergence) cannot be covered by unit tests. A worker
that passes `cargo test` but skips live verification is shipping untested code —
but "live verification" means **kubectl first, sonobuoy only as the final gate**
(see above), not a sonobuoy run per iteration.

### The block (paste verbatim into applicable dispatch prompts)

Fill in `<VM_NAME>`, `<PORT>`, and `<KUBELET_PORT>` from the mayor's assignment before pasting.

```
## Lima VM protocol — MANDATORY for this bead

Your assigned VM: <VM_NAME>
Your assigned port: <PORT>
Your assigned kubelet port: <KUBELET_PORT>
Your assigned worktree: <ASSIGNED_WORKTREE>

You have exclusive use of this VM for this bead. Do NOT use `lima-node` or
port `6443` — those belong to the mayor. All workers bind to `127.0.0.1` and
use `--port` for isolation. Use exactly the port assigned above — do not
pick a different port even if you think the assigned one is in use.

**Read `ai/prompts/vm-operations.md` IN FULL before any build or stack command.**
It is the single source of truth for how to build, bring up the stack, iterate,
and run the gate. Do NOT restate its steps in your dispatch — point the worker at
it. The essentials it covers (do not duplicate them here, just rely on them):
`run-all.sh` is the one allowlisted command (it builds, resets, restarts every
component, runs sonobuoy); omit `--binary` to build the worktree; `--verbose` for
debug logs; never `cargo build`/`kill`/`curl`/`export RUST_LOG=` by hand;
**diagnose with kubectl + `/tmp/kcm.log`, run sonobuoy only as the final gate**;
read the result from `podlogs/sonobuoy/.../logs/e2e.txt`, not `plugins/.../e2e.log`.

**Cargo tests are not sufficient** for this bead — it touches a runtime path. But
"verify live" means kubectl-first per vm-operations.md, not a sonobuoy run per
iteration.

Your return MUST include: (a) the kubectl before/after reproduction, and (b) the
sonobuoy PASS line from `e2e.txt`. A return without both will be rejected.

For script-only beads (no server restart needed): run the commands via
`limactl shell <VM_NAME>` first, encode them in the script, run it, verify exit 0,
and include at least one `limactl shell` / mcp tool output in your return.
```

### Mayor enforcement at return-review time

When a worker returns from a VM/sonobuoy-touching bead:
- Check the return for sonobuoy delete output or `mcp__<VM_NAME>__run_shell_command` evidence.
- If absent: **do not merge**. Send back: "Your return contains no VM execution
  evidence. Run `sonobuoy delete --all --wait` in your assigned VM and show the output."
- The hook pre-checks cargo quality gates. VM verification is the mayor's gate.

---

## Common failure modes these patterns close

- **Mayor omits `isolation="worktree"` in Agent tool call.** Without it the
  subagent CWD stays at the repo root on branch main — causing path-resolution
  and permission bugs. Always include `isolation="worktree"` so the harness
  creates the worktree and pins the CWD to its root automatically.
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
- **Workers grep `~/.cargo` vendored crate files to understand a dependency's
  API instead of using the LSP.** The `mcpls` Rust LSP is live and warm here
  (verified 2026-07-13). `get_hover` on an external symbol returns its signature
  + resolved generics + doc + docs.rs link without reading a file; `get_definition`
  jumps to the exact vendored file+line. Grepping the registry by hand is slower,
  misses resolved types, and triggers permission prompts. Two drivers, both fixed
  in the preamble: (1) the vendored-crate navigation case wasn't spelled out; (2)
  the `workspace_symbol_search`-returns-empty caveat got over-generalized into
  "LSP is unreliable here" — it is specific to name-search; hover/definition/
  references at a position work fine. See bd memory `mcpls-rust-lsp-works-dont-grep-cargo`.
- **Agents (and the mayor) fabricate temporal claims instead of checking timestamps.**
  Observed repeatedly: an agent calls a log line "from a previous run" when it was
  20 seconds earlier in the run it just executed; the mayor asserts evidence
  "predates PR #X" without checking `mergedAt`, conflating runs across different
  binaries and chasing the wrong root cause for hours. Before any "when / before /
  after / previous / stale" claim, verify against the log timestamp, run-dir name,
  `gh pr view --json mergedAt`, or commit time — and normalize timezones (apiserver
  UTC vs ginkgo/run-dir local). At review time, distrust any temporal claim in a
  worker's return that isn't backed by a quoted timestamp. See the "Evidence & time
  discipline" block — inject it via the common preamble.
- **Workers burn 10–25 min per sonobuoy run when kubectl would answer in seconds.**
  A `--focus` run is slow and can hang (watchdog reaps the namespace at 10 min,
  ginkgo then flails ~15 more min). Iterating diagnosis on sonobuoy is the single
  biggest time sink. Dispatch must direct the worker to: read the test source,
  reproduce via `kubectl` against the running stack + `/tmp/kcm.log`, root-cause
  and fix there, and run sonobuoy ONCE as the final gate. Also tell them the real
  result is in `podlogs/sonobuoy/.../logs/e2e.txt`, not `plugins/.../e2e.log`.
- **Workers (and scouts) hunt for the e2e test source in the wrong places.** The
  upstream Go test body is NOT in this repo, the sonobuoy archive, or `temp/e2e/`
  — so agents waste calls searching. Tell them exactly where: check
  `temp/research/` FIRST (gitignored; already holds curated upstream k8s source),
  and if the file isn't there, fetch it once with `gh api`/`curl` (never
  `WebFetch`, see Upstream source rules) and cache it into `temp/research/`
  before grepping it. The full protocol is in
  `ai/prompts/vm-operations.md` (Step 6, "Locating the failing test's source") —
  point the worker there. Reconstructing the test from the bare assertion string
  is unreliable: `Expected 2 to be equivalent to 1` is meaningless without the
  create→no-op-update→assert sequence around it.
- **Workers rebuild the stack by hand and stall on un-permitted tools.** When a
  bead needs a live run (especially with debug logs), workers tend to improvise:
  `cargo build` separately, `kill` stale processes, `curl` the apiserver, then
  `export RUST_LOG=debug` inline — none of which are on the Bash allowlist (they
  can be destructive), so the worker hits a permission wall and gives up or
  guesses. `run-all.sh` already does ALL of it via flags: build (omit `--binary`),
  reset/kill/reprovision (`--reset`), debug logging (`--verbose`), focus
  (`--focus`). Dispatch must point workers at the single `run-all.sh` command and
  explicitly forbid the manual path — see the flag table in the Lima VM protocol
  block. A worker that needs debug logs should add `--verbose`, never `export
  RUST_LOG=`.
- **Hook split: pre-commit checks fmt; pre-push checks test+clippy.** Workers
  who only run `cargo fmt` before committing will hit a test failure at push
  time with no stacktrace. Quality gate (test+clippy) must run before commit,
  not just before push.
- **Mayor "gets into the flow" and codes instead of dispatching.** The
  four-condition exception test is easy to rationalize past once the mayor has
  already read several files. The fourth condition (≤2 files read) is the
  circuit breaker. Workers have their own assigned VM with MCP access and can
  debug live. Write a better brief.
- **Workers guess at VM behaviour instead of observing it.**
  `mcp__<VM_NAME>__*` and `limactl shell <VM_NAME>` are both available. Inject
  the Lima VM protocol block for any bead touching `scripts/conformance/`,
  `scripts/*-start.sh`, or sonobuoy-exercised handlers.
- **Workers hard-code `lima-node`, port `6443`, or kubelet port `10250`.** Each worker gets an
  assigned VM name, port, and kubelet port from the mayor. Hard-coding the defaults causes
  collisions when multiple workers run in parallel. Always use the values from the dispatch
  prompt. Workers always bind to `127.0.0.1`; port is the only isolation boundary.
- **Worker skips `--reset` on first run.** The first `run-all.sh` call in a worktree
  must use `--reset` — the VM may have stale certs or port-forward config from a previous
  owner. Omitting it on the first run risks inheriting stale VM state. Subsequent calls
  in the same worktree should omit `--reset` to avoid the ~5 min VM reprovision penalty,
  but using it again is safe (everything regenerates consistently). The Lima VM protocol
  block states this explicitly; enforce it at return-review time.
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
