# Dashboard
2026-06-11T03:34Z — VM port-isolation confirmed working; ready to ship script fixes.

Resume: `bd prime`

## Operator attention needed

**Uncommitted script fixes on main checkout** — need a PR before workers can use them:
- `scripts/u7s-start.sh`: `--vm`, `--ip`, `--binary`, `--workdir` flags
- `scripts/conformance/lima-start.sh`: `--vm`, `--workdir`; all `lima-node` → `$VM_NAME`
- `scripts/conformance/04-start-kcm.sh`: `--vm`, `--workdir` flags
- `crates/apiserver/src/tls.rs`: kubeconfig uses `--advertise-address` as server URL
- `ai/prompts/vm-operations.md`: rewritten to use script flags

**VM port isolation (option A confirmed):** VZ NAT forwards all ports to `127.0.0.1` on host.
`host.lima.internal:6444` → `127.0.0.1:6444` works without any `limactl` config changes.
Remaining work: add `--port` flag to `u7s-start.sh` + port-aware rewrite in `lima-start.sh`.
Also update dispatch-prompt-template.md Lima section (still documents broken loopback-alias model).

**Worktree hygiene — confirm removal:**
- `ai/worktrees/proto-replicas-b7y4`: PR #509 merged; remote branch gone; no local commits. **Safe to remove.**
- `ai/worktrees/statefulset-rerun-audit`: no PR, no commits ahead of main. **Safe to remove.**
- `ai/worktrees/w5fd-scale-diag`: no PR, no commits ahead of main. **Safe to remove.**
  (Has `temp/u7s/` state from live repro attempt — will be lost on removal, that's fine.)

## Open PRs
None.

## In-flight workers
None.

## Recent merges
- #509 fix(proto): spec.replicas unconditional in workload decoders
- #508 fix(watch): full object body in DELETED tombstone
- #507 fix(defaults): inject rollingUpdate.partition=0 for StatefulSets

## Deferred
mayor-w5fd (script PR needed first) · mayor-27ix · mayor-52wo · mayor-j7to · mayor-rvkq
