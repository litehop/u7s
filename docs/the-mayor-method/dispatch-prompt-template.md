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

### Git hooks & cargo verification (mandatory — know warm vs. cold cost per pass)

The repo has both a pre-commit and a pre-push hook. Knowing what each runs saves
minutes per iteration:

- **pre-commit** (`.githooks/pre-commit`) — runs `cargo fmt --check` only. Formatting,
  no test/clippy.
- **pre-push** (`.githooks/pre-push`) — runs `cargo test --workspace` AND
  `cargo clippy --workspace --tests --no-deps -- -D warnings`. This is authoritative; if it
  fails, `git push` is rejected with no stacktrace context.

**Warm vs. cold cache — this is the number that actually matters for Bash
timeouts.** As-of measurements (12-core Apple Silicon Mac, mayor-ektcp audit,
2026-08-17; expect drift as the workspace grows or on different hardware —
treat as a range, not a promise):

- **Warm cache** (target/ already built by a prior `cargo test`/`cargo build`
  in the SAME worktree, e.g. your own step-3 run below): `cargo test
  --workspace` ~25-30s, `cargo clippy --workspace --tests --no-deps -- -D
  warnings` ~15-20s. Both fit comfortably inside Bash's default 2-min timeout.
- **Cold cache** (a brand-new worktree with no prior `cargo` invocation at
  all — true for every worker's FIRST build/test/push): compiling test
  binaries from scratch adds ~55-60s on top of the warm numbers above, so a
  cold `cargo test --workspace` can run ~80-85s total. This is why a worker's
  first `git push` (which triggers the pre-push hook's test+clippy) can blow
  past a 2-min default Bash timeout even though later, warm-cache pushes
  finish quickly. If this is your worktree's first push, set a longer
  `timeout` param up front (300s is a safe buffer) rather than let the
  default fire and force a retry.

**Order of operations that minimises wasted work**:

1. Make your edit.
2. Sync with main before the quality gate. `git fetch origin main`, then
   `git rev-list --count HEAD..origin/main` — if that's nonzero, `git merge
   origin/main` and resolve any conflict now. Do this before every push, not
   just review-feedback fix rounds — it's cheap, and the branch has often
   drifted behind main during the dispatch → build → review → fix round-trip
   as other PRs merge. Merging first means the commit you're about to
   quality-gate and push already reflects current main, so the mayor's merge
   loop is less likely to need a separate `gh pr update-branch` + CI cycle.
   Caveat: this reduces but doesn't eliminate that extra cycle — another PR
   can still merge in the window between your push and the mayor's actual
   merge attempt, so the PR may show BEHIND again by then. The point is
   starting from a fresh base, not guaranteeing a final CLEAN state.
3. Run `cargo test --workspace` and `cargo clippy --workspace --tests --no-deps -- -D warnings`
   ONCE, before commit. This is your "see failures with context" pass — it's
   also what warms the cache for every later run in this worktree. If either
   fails, fix and re-run only the affected target (`cargo test -p <crate>` or
   `cargo test <testname>`) — never re-run the whole workspace on every edit iteration.
4. `git add` + `git commit`. Pre-commit runs `cargo fmt --check` — the ONLY new
   thing the hook adds. If `fmt` fails, run `cargo fmt` and re-commit.
5. `git push`. Pre-push re-runs test+clippy. Because you haven't touched source
   since step 3, compilation is cached and only test EXECUTION time is spent —
   see "warm cache" above for the expected wall-clock. Do NOT manually
   re-run test+clippy right before push — the hook is going to do it anyway;
   a manual pre-push run just doubles that warm-cache cost for zero signal.

**Reading `cargo test` output — do NOT grep for FAILURE/ERROR after a green run.**

`cargo test` (with or without `--quiet`) prints an authoritative summary line for
every test binary:

```
test result: ok. 2790 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 23.26s
```

`0 failed` IS the pass signal — nothing more to verify. Re-running `cargo test`
piped to `grep -E 'FAILED|ERROR'` duplicates the run above (warm-cache ~25-30s,
or ~80s+ if this is a cold worktree's first run — see "Git hooks & cargo
verification" above) for zero additional signal (a failure would have shown in
the first run's summary and the failing test's own output). If a test failed
and you need its stacktrace, use `cargo test -- --nocapture <testname>` on the
ONE test — never re-run the whole workspace.

If `--quiet` output feels sparse and you want fuller detail on the first run, drop
`--quiet` — the un-quiet output still ends with the same summary line but includes
per-test progress. Both are single-run and authoritative.

### Pinpoint conformance --focus gate (mandatory for runtime-path beads)

For any bead touching a runtime path — protobuf/JSON encoders, request handlers,
admission chain, store lifecycle, scheduler predicates, RBAC, subresource
handlers — the dispatch brief MUST include 1-3 `sonobuoy --focus` test regexes
the mayor believes MOST likely to be broken by the change. The worker's return
MUST include the PASS lines from `e2e.txt` for each.

Cargo tests + unit tests + sentinel-completeness tests are NECESSARY but NOT
SUFFICIENT — they cannot exercise the client-go-negotiated wire path that real
k8s clients (kubelet, controllers, e2e framework) use. PR #1130 shipped 26
silent conformance failures on cargo-green because no unit test exercised the
protobuf-negotiated GET path; PR #1157 later added sentinel-completeness tests
as the SECOND layer, but the pinpoint `--focus` gate is the THIRD and final
one, catching what encoder-shape tests still can't see.

The mayor's brief specifies WHICH `--focus` tests. If unsure, err on the side
of more — a `--focus` test takes 5-15 min and catches the exact class of bug
that costs full days to root-cause when it lands on `main`. Exemptions: pure
doc changes, script changes, dev-tooling scouts, and read-only investigations.

**Escape `[sig-xxx]` brackets in the regex, or it silently matches nothing.**
`--focus` is a regex; an unescaped `[sig-network]` is a character class (any
ONE of those literal characters), not the literal bracketed prefix — since
real spec text has a literal `]` right before the space, the char-class
version never matches and reports "Will run 0 of N specs" with no error,
indistinguishable from the spec genuinely not existing. Write
`\[sig-network\] Some spec text` instead.

**No Conformance-tagged spec exercises the codepath — check non-Conformance
e2e specs before falling back to a hand-rolled verification.** Upstream's
`[Conformance]` tag marks a curated subset; a real upstream e2e test body can
exercise the exact field/codepath without being Conformance-tagged (see
`test/e2e/` broadly, not just the Conformance-filtered subset). A worker
who finds zero `[Conformance]` hits should search upstream for ANY `ginkgo.It`
(tagged or not) touching the field before concluding a manual protobuf-wire
test is the only option — a real upstream test body, even non-Conformance,
exercises the actual client-go-negotiated request path in a way a hand-rolled
script can't fully replicate (real client, real informer/watch semantics,
real retry/backoff behavior). Only fall back to a manual wire-level test
(building the protobuf envelope by hand, as `mayor-zbkq1`/`mayor-tppdt` did
for `VolumeAttachment.inlineVolumeSpec`/`ServiceCIDR.observedGeneration`)
when NEITHER a Conformance nor a non-Conformance upstream spec touches the
field at all — confirmed via `gh api /search/code?q=<field>+repo:kubernetes/kubernetes`
across `test/e2e/`, not just a Conformance-filtered grep.

See bd memories `worker-brief-hypothesis-may-be-wrong-encourage-independent-diagnosis`
and `content-type-dispatch-must-key-on-apiversion-plus-kind` for concrete cases
where this gate caught (or would have caught) silent breakage.

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
- **Pin to the latest Kubernetes version: `1.36.4`** (as of 2026-08) — branch
  `release-1.36` for raw GitHub fetches, and reference 1.36.4 API/test
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

## Final step — reap your host processes (mandatory if you were assigned a VM/port)

If this dispatch assigned you a VM, port, and kubelet port (Lima VM protocol
block), your LAST action before ending the session — after quality gates pass
and your PR is open — must be:

```bash
scripts/conformance/reset.sh --host-only --workdir "$PWD/temp/u7s" --port <YOUR_ASSIGNED_PORT>
```

Always pass YOUR OWN assigned `--port` — never omit it and never let it
default to `6443`; an unscoped `--port` can kill whatever slot's stack is
bound there — kill only what you own, not another worker's. If your bead used a non-standard konnectivity
port slot (rare — standard slots auto-derive it from `--port`: 6443→8135,
6444→8235, 6445→8335, …), also pass
`--konnectivity-server-port <YOUR_DERIVED_KONNECTIVITY_PORT>`.

Why this matters: `git worktree remove` does NOT kill the host-side
`u7s-apiserver`, `u7s-scheduler`, or `konnectivity-server` processes your
`run-all.sh` call started — they are plain backgrounded (or, for
konnectivity-server, `disown`ed) processes that outlive their worktree, keep
squatting on this VM slot's ports, and keep serving a now-stale CA-signed
cert that breaks the NEXT dispatch to this same slot. See bd memory
`worktree-remove-does-not-kill-host-processes` and `mayor-yfvxn` for the
observed-orphan history this closes. `--host-only` kills exactly those three
process kinds, scoped to your own `--workdir`/`--port`, and exits before
touching `$WORKDIR` or the VM — safe to run even if your bead never brought
up a live stack.

If this bead had NO VM/port assignment (pure code/doc bead — you never ran
`run-all.sh`), skip this step entirely: there is nothing of yours to reap,
and running it with a default/omitted `--port` risks matching whatever's
running on `6443` instead of safely doing nothing.
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
summary + test deltas, under 250 words.

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
cargo clippy --workspace --tests --quiet --no-deps -- -D warnings
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

## Shape 6 — Durable doc change (ADR, roadmap, extended-context)

One bead asks for a decision recorded or durable context refreshed, not code.
Sections: what is being settled and what stays open; source material (findings
doc, bead thread, prior ADRs on the surface); the target file **and its word
budget** — `docs/decisions/` 400, `ai/extended-context/` 1200,
`ai/dashboard.md` 400, all enforced by `scripts/check-doc-budget.sh`; for a
new ADR, start from `docs/decisions/_template.md`; return under 200 words
with the paths written and their before/after word counts.

Critical learnings:

- **Budget the artefact, not just the return.** Shapes 1–5 cap the worker's
  message to the mayor, which is read once. This shape caps what lands in the
  repo, which is re-read by every session that touches the surface. State the
  target file's word budget in the brief: a brief that leaves it unstated
  reliably comes back with a doc that grew.
- **Require deletions.** An all-`+` diff on an existing doc is accretion, not
  editing. `Write` the whole file rather than appending to it.
- **Words, never lines.** Do not brief a line budget: joining lines satisfies
  it with zero content change.
- **A tracked doc must never cite `ai/findings/`.** That directory is
  gitignored, so the path resolves to nothing in every fresh checkout and
  every worktree — a findings citation in a committed file is a broken
  reference, not a pointer. Anything that must survive the session gets
  extracted into a tracked document under `docs/` or a tracked `ai/`
  subfolder; anything still open gets a bead. The brief must say which.
- **Only settled material becomes a durable doc.** Needs-data and deferred
  sections of a sketch are not ADR content. Name them in the brief as
  out-of-scope so the worker files beads for them instead of distilling
  half-decisions into prose that reads as settled.
- **No measurement is an acceptable rationale.** If a decision was a judgment
  call, the brief should say to name the principle applied rather than
  manufacture justification for it.

---

## Lima VM protocol

### Multi-VM model

Each worker that needs runtime verification gets its **own isolated VM stack** —
it does not share the mayor's VM. Up to 6 workers can run in parallel (soft
limit: ~4 GiB RAM per VM).

**Available VMs and their assigned ports:**

All 6 slots are dispatch-assignable to workers by default. If the operator
needs a slot for their own use, they will communicate it explicitly and it
will be dispatched only after that — do NOT preemptively reserve any slot as
"the operator's."

| VM name | Host port | Kubelet port | Companion kubelet port | Konnectivity | Network | Notes |
|---|---|---|---|---|---|---|
| `lima-node` | `6443` | `10250` | `10260` | `8135` | `user-v2-mayor` | assignable to workers; the operator will communicate if they need this slot |
| slot 1 = `lima-node-2` | `6444` | `10251`* | `10261` | `8235` | `user-v2-workers-a` | *currently live on `10252` — see caveat below |
| slot 2 = `lima-node-3` | `6445` | `10252` | `10262` | `8335` | `user-v2-workers-a` | workers may pair this slot with any other via `--extra-node <vm>` when a bead needs a 2-node topology — check `limactl list` / the dashboard before assuming it's free |
| slot 3 = `lima-node-4` | `6446` | `10253` | `10263` | `8435` | `user-v2-workers-a` | |
| slot 4 = `lima-node-5` | `6447` | `10254` | `10264` | `8535` | `user-v2-workers-b` | |
| slot 5 = `lima-node-smoke` | `6448` | `10255` | `10265` | `8635` | `user-v2-workers-b` | fixed 2026-07-23 (mayor-1rlwt) — was misconfigured at `10251`, colliding with slot 1 |

Pairing two slots via `--extra-node` for a 2-node topology requires the same
Network value — `lima-start.sh`'s inter-node route loop compares each VM's
recorded network and now fails loud on a mismatch instead of silently
programming a route with no L2 path behind it. Pick two slots from the same
column above (e.g. `lima-node-2` + `lima-node-3`, both `user-v2-workers-a`).

**Before assigning a slot, verify the LIVE port, not just this table**: run
`grep -A1 guestPort ~/.lima/<vm-name>/lima.yaml` for the VM you're about to assign —
this table records intent, but a VM's actual port can drift from it (see the
`lima-node-2`/`lima-node-smoke` history below) and the table is not proven to
self-correct. Treat a mismatch as a signal to reconcile, not to trust the table blindly.

**History (mayor-1rlwt, 2026-07-23):** `lima-node-smoke` was found live-configured on
port `10251` (slot 1's port) instead of its own `10255` — a previous provisioning
mistake, not a documented reservation. This silently caused `lima-node-2` (slot 1) to
lose the bind race whenever `lima-node-smoke` was already running, producing TLS/
BadGateway failures that looked like a kubelet cert problem but were actually traffic
reaching the WRONG VM's kubelet. Root-caused as a live port-forward collision, not a
cert issue — see `mayor-1rlwt` and `mayor-pgm5q.6`'s notes for the full misdiagnosis
trail. Fixed by reprovisioning `lima-node-smoke` onto `10255` (stop VM, edit
`~/.lima/lima-node-smoke/lima.yaml`'s `portForwards[0].hostPort`, restart — `limactl`
has no in-place port-edit command). The lesson stands regardless of which script
provisions a VM: **a live VM's ports can drift from this table; verify with
`grep -A1 guestPort ~/.lima/<vm-name>/lima.yaml` before assuming.** `lima-node-2` itself
was left on the workaround port `10252` from an earlier dispatch (mayor-6m0np) rather
than reverted to `10251` — no live collision exists at `10252` today, so it wasn't
worth the ~5 min reprovision to "fix" a non-problem (Rule 2). A future mayor MAY want
to align it back to `10251` when convenient, but it is not urgent.

**Companion kubelet port** (`10260`-`10265`) is reserved for each slot's 2nd
(companion) node in a two-node conformance run — pass it as `--extra-kubelet-port`
alongside `--extra-node <vm>` to `run-all.sh` (see `scripts/conformance/add-node.sh`).
Unused unless a slot is explicitly running a two-node stack.

All workers bind to `127.0.0.1` — port is the isolation boundary between parallel
workers. Different loopback IPs are NOT reliably reachable from inside Lima VMs via
`host.lima.internal`; port is the only safe differentiator.

**Kubelet port** is the host-side port-forward for guest port 10250. Each slot must use
a distinct kubelet port so parallel workers don't collide on log/exec/attach requests.
Pass `--kubelet-port <N>` to `run-all.sh` — `run-all.sh` (via `lima-start.sh`) provisions
the VM with the assigned `--kubelet-port` automatically on first run; no separate
provisioning step is needed.

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
invocation runs the FULL conformance suite (~25min at current state — PR #966 made
ginkgo's `--procs=16` the default, replacing a silently-serial certified-conformance
path (was ~2h before that fix, ~6h before an earlier optimization) — still far too
slow to iterate on, and a runaway burn if unintended). Every VM
dispatch prompt MUST tell the worker to use EITHER `--stack-only` (investigate via
kubectl / direct DB, no sonobuoy at all) OR `--focus <regex>` (run one targeted test),
and to reserve any `--focus` run for a FINAL confirmation gate — never a bare full run
unless a full run is explicitly the stated goal of the bead.

**CRITICAL — a bare command is a trap even in a REPRODUCTION step.** When you write the
worker's "reproduce the failure" or "verify the stack comes up" step, that command MUST
itself carry `--stack-only` (or `--focus`). Observed 2026-07-22 (pgm5q.13): a brief's
repro step said `run-all.sh --reset ... --verbose` with no `--stack-only`; on the broken
code it aborted early (safe), but after the fix it sailed past bring-up straight into the
full sonobuoy suite. The worker followed the brief literally. The lesson is on the
brief-author: never hand a worker a bare `run-all.sh`, not even to "just watch it start."
Consider having the worker echo back which run modes it will use before its first
`run-all`. (`sonobuoy --quick` exists as a fast single-test cluster-liveness check,
not wired into `run-all.sh` today — an option when you only need "is the cluster live".)

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
Workers should never pass `--ip` / rely on `U7S_HOST_IP` — always bind `127.0.0.1`
and use `--port` for isolation (the underlying flag still exists in
`run-all.sh`/`u7s-start.sh` but is not part of the worker workflow). The
konnectivity port auto-derives from `--port` (6443→8135,
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
  not just before push. See "Git hooks & cargo verification" in the common
  preamble for the full order-of-operations.
- **Workers re-run `cargo test` after a green pass to grep for FAILURE/ERROR.**
  Observed repeatedly: worker runs `cargo test --workspace --quiet`, sees no
  failure lines, doesn't trust the silent-success, re-runs piped to `grep -E
  'FAILED|ERROR'` — duplicating the test-suite run (~25-30s warm-cache, more
  on a cold worktree — see "Git hooks & cargo verification") for zero
  additional signal. `cargo test`'s summary line (`test result: ok. N passed;
  0 failed;`) IS authoritative; grep-verification adds nothing. The "Reading
  `cargo test` output" note in the common preamble tells the worker to trust
  the summary line and use `cargo test -- --nocapture <testname>` if a
  specific test's stacktrace is needed.
- **Workers manually re-run test+clippy right before `git push`.** They ran it
  before commit (correct), then re-run it before push "to be safe" — but the
  pre-push hook runs the exact same commands unconditionally right after. Cargo
  caches compilation across the two runs but test EXECUTION still re-runs:
  ~25-30s for `cargo test --workspace` plus ~15-20s for `cargo clippy
  --workspace --tests --no-deps -- -D warnings` (warm-cache numbers; clippy's
  `--no-deps` flag itself was a fix — mayor-patf1, PR #1212, measured 2.9x
  speedup from 45.5s to 15.8s warm, since propagated to `.claude/settings.json`
  (mayor-snjh1, PR #1214) and CI (mayor-dajfe, PR #1215)). Net: ~40-50s of
  duplicated wall-clock per push, for zero signal (the hook would have caught
  anything a manual re-run would have caught). Common preamble now explicitly
  says: run test+clippy ONCE before commit, do NOT re-run before push.
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
- **Timing PoCs asked to reproduce a "slow / minutes of CPU" claim without a wall-clock
  cap.** When a security or perf brief asks a worker to empirically confirm a pathological
  runtime cost (e.g. "compile boon on a 1MB pattern to confirm the audit's O(n²) claim"),
  the brief MUST specify a hard wall-clock cap (60-180s typical) AND direct the worker to
  demonstrate the scaling via GEOMETRICALLY-increasing sizes under the cap, not by running
  the worst case to completion. Two data points at N and 4N with a ~16x time ratio proves
  quadratic scaling as rigorously as one data point at 1024N taking minutes — and doesn't
  burn 10+ minutes of wall-clock. Also: any such PoC should be `#[test] #[ignore]` so it
  doesn't fire in normal `cargo test`, which the project convention says completes in a few
  minutes end-to-end. See `bd memories timing-pocs-must-be-bounded`.
- **Findings docs leak into PRs.** `ai/findings/` is gitignored; never
  commit one.
- **Mayor force-merges through a failing check with `--admin`.** NEVER use
  `--admin`. If a check fails: read the log first. If it is a transient GitHub
  infra flake (e.g. `fatal: could not read Username`, checkout auth failure,
  runner timeout unrelated to the diff), rerun the specific job with
  `gh run rerun <run-id> --failed` and wait for green. Only merge when ALL
  checks are green.

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
