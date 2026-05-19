# Conformance Gap Analysis

Date: 2026-05-19
Bead: mayor-mti
Method: Source audit of u7s API surface vs Kubernetes conformance test categories (k8s.io/kubernetes/test/e2e tagged [Conformance])

## Estimated conformance coverage

~40-50% of API-level conformance tests passable with current architecture.
~15-20% require scheduler/kubelet (architectural — skip tier).
~30-40% blocked by specific API gaps filed below.

## Test categories and status

| Category | Status | Notes |
|---|---|---|
| Namespace CRUD | PARTIAL | Create/get/list/delete work; Terminating phase lifecycle missing (mayor-c3v) |
| ConfigMap CRUD | PASS | Full CRUD + watch |
| Secret CRUD | PASS | Full CRUD + watch |
| ServiceAccount CRUD | PASS | Full CRUD |
| Node CRUD | PASS | Full CRUD |
| Pod CRUD (API-level) | PARTIAL | pods/status subresource missing (mayor-b4g) |
| Deployment/ReplicaSet/StatefulSet | PASS | Full CRUD + scale + watch |
| RBAC (Role/Binding/Cluster) | PASS | Full CRUD + watch |
| CRD lifecycle | PASS | Create/get/list/delete + CR instances |
| Watch (all resource types) | PASS | Implemented in PR #37 |
| Strategic merge patch | PASS | Implemented in PR #39 |
| JSON Patch (RFC 6902) | FAIL | HTTP 415 (mayor-jf3) |
| fieldSelector | FAIL | Ignored (mayor-yx5) |
| generateName | FAIL | Not implemented (mayor-l8f) |
| List pagination (limit/continue) | FAIL | Ignored (mayor-ynx) |
| DELETE response body / finalizers | PARTIAL | Returns 204; finalizer soft-delete not implemented (mayor-qnc) |
| SubjectAccessReview | PASS | Implemented in PR #38 |
| TokenReview | PASS | Implemented in PR #38 |
| Pod exec/log/portforward | SKIP | Requires kubelet — architectural |
| Pod scheduling/lifecycle | SKIP | Requires scheduler + kubelet — architectural |
| PersistentVolume/PVC | SKIP | Not in scope for Phase 3 |
| Event recording | SKIP | Low priority; not in conformance critical path |

## Beads filed

| Bead | Gap | Priority |
|---|---|---|
| mayor-yx5 | fieldSelector support (metadata.name at minimum) | P2 |
| mayor-l8f | generateName — random suffix on object creation | P2 |
| mayor-jf3 | JSON Patch RFC 6902 (application/json-patch+json) | P2 |
| mayor-c3v | Namespace Terminating phase lifecycle on DELETE | P2 |
| mayor-ynx | List pagination: limit/continue token | P2 |
| mayor-b4g | Pod status subresource (pods/status GET/PUT/PATCH) | P2 |
| mayor-qnc | DELETE response body + finalizer soft-delete | P2 |
| mayor-ik3 | resourceVersion in watch ADDED events (replay correctness) | P2 |

## Not filed (architectural or deferred)

- Pod exec/log/portforward: requires kubelet, not API-implementable
- PersistentVolume binding: out of scope
- Admission webhook enforcement: stored but not enforced (intentional Phase 3 deferral)
- Schema validation for CRs: mayor-xy2 (already exists, deferred)

## Priority order for conformance improvement

1. **mayor-yx5** (fieldSelector) — blocks the most tests; metadata.name filter alone unblocks ~15% more
2. **mayor-l8f** (generateName) — needed for any test that creates objects without specifying names
3. **mayor-jf3** (JSON Patch) — some tests use it; small implementation effort
4. **mayor-b4g** (pods/status) — needed for pod condition conformance tests
5. **mayor-c3v** (Namespace Terminating) — watch-based namespace tests
6. **mayor-qnc** (DELETE body + finalizers) — affects test cleanup patterns
7. **mayor-ynx** (pagination) — relatively few tests depend on this path
8. **mayor-ik3** (watch ADDED rv) — verify first before implementing
