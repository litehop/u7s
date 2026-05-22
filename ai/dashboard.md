# Dashboard
2026-05-22 (mayor session active — typing wave complete, iwyr dispatching)
`bd prime` in a fresh Claude Code session (or say "I am the Mayor now")
Open beads: 4

## What needs the operator now

- **mayor-o2py (P2)** — CSR API (`certificates.k8s.io/v1`). Generic handler sufficient. Rejection tests required (malformed PEM, denial, OCC conflict). Awaiting your "go".
- **mayor-suf0 (P2)** — kube-controller-manager smoke test. Blocked on mayor-o2py.
- **mayor-2ni (P3)** — sonobuoy conformance audit. On hold per your request.

## In-flight work

| Worker | Bead | Surface | Status |
|--------|------|---------|--------|
| iwyr | mayor-iwyr | `scheduler/src/lib.rs`, `controller-manager/src/lib.rs` | dispatching |

## Forward look

**HOLD — operator instruction**: reassess code quality and test coverage after in-flight work lands before dispatching further.

1. Merge mayor-iwyr PR when CI goes green.
2. Run quality/coverage assessment; bring findings to operator.
3. Operator decides next: mayor-o2py (CSR API) on your go, mayor-2ni when hold lifted.

## Recent progress

Typing wave complete (PRs #158, #159):
- PR #158 (mayor-1aoj + mayor-ln00): typed `NamespaceStatus` in namespaces.rs, typed `SecretData` in controller-manager. +4 tests.
- PR #159 (mayor-vnmv): typed `PodSpec`, `BindingTarget`, `Binding` in pods.rs + scheduler. +8 tests.
- mayor-cumk: closed as already-done (tokens.rs already used typed ObjectMeta, landed in PR #157).

Closed this session: mayor-vnmv, mayor-1aoj, mayor-ln00, mayor-cumk (4 beads).
Merged PRs this session: #154, #155, #156, #157, #158, #159.

## Stance

Pre-alpha/greenfield: break freely, no backward compat, correctness first, kubectl-compatible API, minimal crate deps. Merge on green CI; flag security/API/architecture PRs for operator review first.
