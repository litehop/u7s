# Dashboard
2026-05-22 (session active — refactoring wave complete, CSR API next)
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 4

## What needs the operator now

- **mayor-o2py (P2)** — CSR API (`certificates.k8s.io/v1`). Generic handler confirmed sufficient. Testing must include rejection paths (malformed PEM, denial, OCC conflict). Awaiting explicit "go" to dispatch.
- **mayor-suf0 (P2)** — kube-controller-manager smoke test. Blocked on mayor-o2py.
- **mayor-2ni (P3)** — sonobuoy conformance audit. Operator asked to hold.

## In-flight work

None.

## Forward look

- Dispatch mayor-o2py (CSR API) once operator gives green-light.
- Re-assess coverage on `handlers/generic.rs` and new sub-modules (`core.rs`, `json_patch.rs`) — smaller per-file targets now achievable.
- After mayor-o2py lands: dispatch mayor-suf0 (kube-controller-manager smoke test).

## Recent progress

Refactoring wave complete (PRs #151–#153):
- PR #151 (mayor-5vam): `tls.rs` dead code removed; 3 tests added (PEM encode, kubeconfig YAML, load-from-disk round-trip)
- PR #152 (mayor-6huu): JSON Patch extracted to `handlers/json_patch.rs`; ~240 lines of verbatim duplication in `pods.rs` deleted
- PR #153 (mayor-untj): `core_*` handler wrappers extracted to `handlers/core.rs` (328 lines); 5 helpers promoted to `pub(crate)`

Bug fixes (PRs #149–#150):
- PR #149 (mayor-f3ru): `encode_watch_event` skips corrupt events; JSON round-trip alloc eliminated
- PR #150 (mayor-5yfc + mayor-q04t): `store_err_cr` returns 409 on `RevisionMismatch`; `build_list_response` made `pub(crate)`

All P1 correctness bugs resolved. 19 PRs merged this session (#135–#153).

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
