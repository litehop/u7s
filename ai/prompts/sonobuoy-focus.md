# Sonobuoy failure investigation: `<FOCUS>`

A sonobuoy e2e run has been captured under `temp/e2e/` (relative to your worktree).
Find the most recent directory matching `*-<focus-lowercase>*`
(e.g. `temp/e2e/0529-1524-limitrange/`).

## Read the RIGHT result file

The full test timeline (what it created, waited for, asserted, and the actual
failure line) is in:

```
temp/e2e/<run>/podlogs/sonobuoy/<sonobuoy-e2e-...>/logs/e2e.txt
```

NOT `plugins/e2e/results/global/e2e.log` — that file omits the test body and will
mislead you into thinking the harness produced no output.

## Verify with kubectl FIRST; reserve sonobuoy for the final gate

A `sonobuoy --focus` run is 5+ minutes and can hang to 20 (the watchdog reaps the
test namespace at 5 min, then ginkgo flails against the dead namespace until its
own timeout). Do NOT iterate diagnosis on sonobuoy runs. Almost everything a
single conformance test asserts is reproducible in seconds with `kubectl`.

1. **Read the failing test's source** (`test/e2e/...` in kubernetes/kubernetes at
   the matching version tag) to learn its exact API sequence — create what, wait
   for what, assert what, delete/GC what. The failure line in e2e.txt tells you
   which step failed.
2. **Reproduce that sequence with kubectl** against the running stack:
   `kubectl --kubeconfig temp/u7s/kubeconfig ...` — create the object,
   `get -o yaml` / `-o jsonpath` / `get -w` the relevant field, delete and check
   GC. Inspect controller behavior with `limactl shell <VM> sudo tail /tmp/kcm.log`
   (KCM is where Job/GC/endpoint/SA controllers live; its errors — e.g.
   `resource version mismatch`, nil panics — are usually the root cause).
3. **Root-cause and fix using the kubectl loop.** If you need apiserver-side
   visibility, bring the stack up with `--verbose` (debug logs) — never add
   `tracing::debug!` + manual rebuild/restart by hand; `run-all.sh --verbose`
   does it correctly.
4. **Run `--focus` sonobuoy ONCE as the final gate**, after kubectl confirms the
   fix. Read the PASS from e2e.txt (see above).

## Bringing up / running the stack

See `ai/prompts/vm-operations.md` for the canonical commands (the one allowlisted
`run-all.sh` form, build via `--binary` omission, `--verbose` for debug logs, VM
provisioning, and per-component restarts). Do not restart the apiserver by hand or
pass `SONOBUOY_FOCUS=` inline. Prefer a unique no-metacharacter substring for
`--focus` (e.g. `should delete a job`) to avoid regex-escaping pitfalls.

## Workflow

1. Read e2e.txt to identify the failing test + exact failure step.
2. Read the test source; reproduce + diagnose with kubectl + `/tmp/kcm.log` before touching code.
3. File a bead (`bd create`) before starting a fix.
4. Fix; add a regression test (Rule 14: must fail if the fix is reverted); run `cargo test` + clippy.
5. Re-verify with kubectl, then run sonobuoy ONCE — confirm PASS in e2e.txt.
6. Close the bead, commit (source only — not `.beads/issues.jsonl`), push.

## Rules that matter most here

- Reference `crates/apiserver/proto/` for proto field numbers — don't guess; download missing files from GitHub into that folder if needed.
- Prefer `jq` over python for JSON in shell.
- Use `--kubeconfig temp/u7s/kubeconfig`, never `KUBECONFIG=` inline.
- Never hard-code `lima-node` / port `6443` / kubelet `10250` — those are the mayor's; use your assigned VM/ports.
