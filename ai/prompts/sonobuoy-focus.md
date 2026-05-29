# Sonobuoy failure investigation: `<FOCUS>`

A sonobuoy e2e run has already been captured. The results are in `temp/e2e/` — find the most recent directory matching `*-<focus-lowercase>*` (e.g. `temp/e2e/0529-1524-limitrange/`).

## Environment

- u7s apiserver runs locally on the Mac (`target/release/u7s-apiserver`, port 6443)
- kubelet and kube-controller-manager run in the lima VM (`lima-node`)
- `kubectl --kubeconfig temp/u7s/kubeconfig` gives cluster access
- kcm logs: `/tmp/kcm.log` inside the VM (accessible via lima-node MCP)
- Restart apiserver: `scripts/u7s-start.sh --background` (kills existing, starts fresh, logs to `temp/u7s/apiserver.log`)
- Re-run sonobuoy: `SONOBUOY_FOCUS=<Focus> scripts/conformance/run-all.sh` — extracts results into `temp/e2e/` and prints the tarball path

## Workflow

1. Read the junit XML and e2e.log from the captured results to identify the failing test and error
2. Use `kubectl` and `sqlite3 temp/u7s/state.db` to reproduce and diagnose locally before touching code
3. File a bead (`bd create`) before starting a fix
4. When you need visibility into runtime behaviour, add `tracing::debug!` lines, rebuild (`cargo build -p u7s-apiserver --release`), restart, and re-run sonobuoy — don't guess
5. Fix, add regression tests (Rule 14: test must fail if fix is reverted), run `cargo test`, re-run sonobuoy to confirm `failures="0"`
6. Close the bead, commit, push

## Rules that matter most here

- Reference `crates/apiserver/proto/` for proto field numbers — don't guess; download missing files from GitHub into that folder if needed
- `BTreeMap<String, Quantity>` for resource maps (same pattern as LimitRange) — don't use raw `Value` maps for fields the apiserver reasons about
- Prefer `jq` over python for JSON in shell
- Use `--kubeconfig temp/u7s/kubeconfig` not `KUBECONFIG=`
