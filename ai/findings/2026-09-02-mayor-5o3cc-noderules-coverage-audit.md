Bead: mayor-5o3cc
Audit: full-coverage check of upstream `NodeRules()` vs u7s's `system:node` ClusterRole
Method: same as x1x2u/qrmmg — cached upstream source, line-by-line comparison

## VERDICT

**NOT fully covered.** Of 27 upstream `NodeRules()` rule entries (k/k
`release-1.36`), **8 are genuinely missing** from u7s's `system:node`
ClusterRole (`crates/apiserver/src/lib.rs:1420-1481`), all backed by
resources u7s already implements (i.e. not moot). One is P0 (blocks a
standard kubelet workflow, same class as mayor-u1g6k's PVC-mount P0); the
rest are P1/P2/P3. The 3 previously-flagged-as-unclear rules
(mayor-qrmmg) are now resolved: all 3 are genuinely MISSING, not
present-but-unannotated.

## Upstream source

Cached at `temp/research/policy_1.36.go` (mayor checkout; read directly,
not copied — `temp/` is gitignored per-checkout so this worker's temp/
doesn't have it). `NodeRules()` spans lines 200-292. Verified this is
release-1.36 by function-boundary grep; not re-fetched since already
cached correctly by a prior worker.

Feature-gate defaults for the four conditionally-appended NodeRules
entries, fetched fresh via `gh api .../pkg/features/kube_features.go?ref=release-1.36`
(not cached — this file didn't exist in temp/research/):

| Feature gate | Stage @ 1.36 | Default | NodeRules entry included in stock 1.36? |
|---|---|---|---|
| `DynamicResourceAllocation` | GA (since 1.34) | **true** | **yes** |
| `KubeletServiceAccountTokenForCredentialProviders` | Beta (since 1.34) | **true** | **yes** |
| `ClusterTrustBundle` | Beta (since 1.33) | false | no |
| `PodCertificateRequest` | Beta (since 1.35) | false | no |

So a stock upstream 1.36 cluster's `system:node` ClusterRole includes the
DRA and credential-provider rules by default, but not the other two. u7s
implements the resources for **all four** feature areas (`resource.k8s.io`
DRA types, `certificates.k8s.io` clustertrustbundles/podcertificaterequests
both wired per `handlers/certificates.rs`/`handlers/generic.rs`) — but u7s
has no equivalent of upstream's feature-gate concept, so "off by default in
1.36" is the right bar: only the two **default-true** rule sets count as
missing; the two default-false ones correctly have no u7s equivalent
(matches upstream absence, not a gap).

## Coverage table — every upstream NodeRules() entry

Legend: PRESENT (u7s line cited) / MISSING (bolded).

| # | Upstream rule (apiGroups/resources/verbs) | u7s system:node (line) | Status |
|---|---|---|---|
| 1 | `create` `authentication.k8s.io/tokenreviews` (policy.go:203) | `{"apiGroups":["authentication.k8s.io"],"resources":["tokenreviews"],"verbs":["create"]}` (lib.rs:1471) | PRESENT |
| 2a | `create` `authorization.k8s.io/subjectaccessreviews` (policy.go:204) | `{"apiGroups":["authorization.k8s.io"],"resources":["subjectaccessreviews"],"verbs":["create"]}` (lib.rs:1470) | PRESENT |
| 2b | `create` `authorization.k8s.io/localsubjectaccessreviews` (policy.go:204, same rule as 2a) | *(no rule in block)* | **MISSING** |
| 3 | `get,list,watch` `""/services` (policy.go:207) | `{"apiGroups":[""],"resources":["services"],"verbs":["get","list","watch"]}` (lib.rs:1449) | PRESENT |
| 4 | `create,get,list,watch` `""/nodes` (policy.go:211) | `{"apiGroups":[""],"resources":["nodes"],"verbs":["get","list","watch","create","update","patch"]}` (lib.rs:1428) | PRESENT (superset) |
| 5 | `update,patch` `""/nodes/status` (policy.go:212) | `{"apiGroups":[""],"resources":["nodes/status"],"verbs":["get","update","patch"]}` (lib.rs:1429) | PRESENT (superset: extra `get`) |
| 6 | `update,patch` `""/nodes` (policy.go:213) | same rule as #4 (lib.rs:1428) | PRESENT |
| 7 | `create,update,patch` `""` **and** `events.k8s.io` `/events` (policy.go:216) | `{"apiGroups":[""],"resources":["events"],"verbs":["create","patch","update"]}` (lib.rs:1440) — `events.k8s.io` apiGroup absent | **PARTIAL/MISSING** (apiGroup gap; u7s implements `events.k8s.io/v1` per `state.rs:1555`/`discovery.rs:171`, so a kubelet posting events via the modern API is denied) |
| 8 | `get,list,watch` `""/pods` (policy.go:219) | `{"apiGroups":[""],"resources":["pods"],"verbs":["get","list","watch","create","delete"]}` (lib.rs:1437) | PRESENT |
| 9 | `create,delete` `""/pods` (policy.go:223) | same rule as #8 (lib.rs:1437) | PRESENT |
| 10 | `update,patch` `""/pods/status` (policy.go:226) | `{"apiGroups":[""],"resources":["pods/status"],"verbs":["get","update","patch"]}` (lib.rs:1438) | PRESENT (superset: extra `get`) |
| 11 | `create` `""/pods/eviction` (policy.go:229) | *(no rule in block)* | **MISSING** |
| 12 | `get,list,watch` `""/secrets,configmaps` (policy.go:234) | `{"resources":["configmaps"],"verbs":["get","list","watch"]}` + `{"resources":["secrets"],"verbs":["get","list","watch"]}` (lib.rs:1450-1451) | PRESENT |
| 13 | `get` `""/persistentvolumeclaims,persistentvolumes` (policy.go:237) | `{"resources":["persistentvolumeclaims"],"verbs":["get"]}` + `{"resources":["persistentvolumes"],"verbs":["get"]}` (lib.rs:1461-1462) | PRESENT |
| 14 | `get` `""/endpoints` (policy.go:241) | *(no rule in block)* | **MISSING** |
| 15 | `create,get,list,watch` `certificates.k8s.io/certificatesigningrequests` (policy.go:244) | `{"apiGroups":["certificates.k8s.io"],"resources":["certificatesigningrequests"],"verbs":["create","get","list","watch"]}` (lib.rs:1478) | PRESENT (exact) |
| 16 | `get,create,update,patch,delete` `coordination.k8s.io/leases` (policy.go:247) | `{"apiGroups":["coordination.k8s.io"],"resources":["leases"],"verbs":["get","list","watch","create","update","patch"]}` (lib.rs:1456) | **PARTIAL** (missing `delete`; has extra `list,watch` not in upstream) |
| 17 | `get` `storage.k8s.io/volumeattachments` (policy.go:250) | `{"apiGroups":["storage.k8s.io"],"resources":["volumeattachments"],"verbs":["get"]}` (lib.rs:1466) | PRESENT |
| 18 | `create` `""/serviceaccounts/token` (policy.go:254) | `{"apiGroups":[""],"resources":["serviceaccounts/token"],"verbs":["create"]}` (lib.rs:1455) | PRESENT |
| 19 | `get,update,patch` `""/persistentvolumeclaims/status` (policy.go:259) | `{"apiGroups":[""],"resources":["persistentvolumeclaims/status"],"verbs":["get","update","patch"]}` (lib.rs:1463) | PRESENT (exact) |
| 20 | `get,watch,list` `storage.k8s.io/csidrivers` (policy.go:263) | `{"apiGroups":["storage.k8s.io"],"resources":["csidrivers"],"verbs":["get","list","watch"]}` (lib.rs:1458) | PRESENT |
| 21 | `get,create,update,patch,delete` `storage.k8s.io/csinodes` (policy.go:265) | `{"apiGroups":["storage.k8s.io"],"resources":["csinodes"],"verbs":["get","list","watch","create","update","patch"]}` (lib.rs:1457) | **PARTIAL** (missing `delete`; has extra `list,watch` not in upstream) |
| 22 | `get,list,watch` `node.k8s.io/runtimeclasses` (policy.go:269, unconditional) | *(no rule in block)* | **MISSING** (u7s implements `node.k8s.io/v1/runtimeclasses`, `state.rs:1682`) |
| 23 | `get` `resource.k8s.io/resourceclaims` (policy.go:273, DRA, default **true** @ 1.36) | *(no rule in block)* | **MISSING** (u7s implements `resource.k8s.io/v1/resourceclaims`, `state.rs:1724`) |
| 24 | `deletecollection` `resource.k8s.io/resourceslices` (policy.go:274, DRA, default **true** @ 1.36) | *(no rule in block)* | **MISSING** (u7s implements `resource.k8s.io/v1/resourceslices`, `state.rs:1732`) |
| 25 | `get,list,watch` `certificates.k8s.io/clustertrustbundles` (policy.go:278, gate default **false** @ 1.36) | *(no rule in block)* | matches upstream absence — not a gap |
| 26 | `get` `""/serviceaccounts` (policy.go:283, `KubeletServiceAccountTokenForCredentialProviders`, default **true** @ 1.34+) | *(no rule in block)* | **MISSING** (u7s implements core `serviceaccounts`, used pervasively) |
| 27 | `get,list,watch,create` `certificates.k8s.io/podcertificaterequests` (policy.go:288, gate default **false** @ 1.36) | *(no rule in block)* | matches upstream absence — not a gap |

Non-upstream extra grant noted for completeness, not a gap: u7s's
`system:node` also has `{"apiGroups":[""],"resources":["pods/log"],"verbs":["get"]}`
(lib.rs:1439) — no equivalent entry in upstream `NodeRules()` (kubelet
serves logs locally; this doesn't come from the Node's own RBAC identity
upstream). Extra permission, not a missing one — no follow-on filed.

## The 3 previously-flagged rules (mayor-qrmmg) — resolved

| Rule | qrmmg status | This audit's resolution |
|---|---|---|
| `pods/eviction` create | unclear | **genuinely MISSING** — see #11 above |
| `endpoints` get | unclear | **genuinely MISSING** — see #14 above |
| `localsubjectaccessreviews` create | unclear | **genuinely MISSING** — see #2b above |

## Missing rules — severity and follow-on beads

| Missing rule | Severity | Rationale | Follow-on |
|---|---|---|---|
| `create` `pods/eviction` | **P0** | Bead text names eviction explicitly as a P0-class example (same "silently blocks standard node workflow" pattern as mayor-u1g6k's PVC P0). Kubelet's node-pressure eviction path POSTs to the Eviction subresource (which u7s fully implements, `lib.rs:2163`) to respect PDBs; without this rule every such eviction 403s. | filed below |
| `get,list,watch` `node.k8s.io/runtimeclasses` | P1 | Unconditional upstream rule (not feature-gated). u7s fully implements RuntimeClass (`state.rs:1682`). Any pod with `spec.runtimeClassName` set would have kubelet's RuntimeClass lookup 403, failing pod start — a supported k8s feature silently broken. | filed below |
| `get` `resource.k8s.io/resourceclaims` + `deletecollection` `resource.k8s.io/resourceslices` (DRA) | P1 | DRA is GA and default-**true** in the version we track parity with (1.36); u7s fully implements `resource.k8s.io` (`state.rs:1718-1732`). Missing rules block kubelet's DRA plugin manager from resolving ResourceClaims for any pod using dynamic resource allocation (accelerators/devices) — full feature blockage, but DRA usage is narrower than PVC mounts (u1g6k), hence P1 not P0. | filed below |
| `create,update,patch` events **also under `events.k8s.io`** apiGroup | P1 | u7s fully implements `events.k8s.io/v1` (`state.rs:1555`). Kubelet's default event recorder posts via the modern `events.k8s.io/v1` API; missing apiGroup grant 403s all such postings — degrades observability (`kubectl describe pod` loses kubelet-sourced events) without blocking scheduling. | filed below |
| `create` `authorization.k8s.io/localsubjectaccessreviews` | P2 | Paired conceptually with the present `subjectaccessreviews` rule; concrete kubelet call site not identified (node's own webhook-authorization delegation typically uses cluster-scoped SAR, not the namespaced Local variant) — narrower/uncertain blast radius than the P1s above. | filed below |
| `get` `""/endpoints` | P2 | Upstream's own comment scopes this to glusterfs volumes, a legacy in-tree plugin; narrow blast radius. | filed below |
| `get` `""/serviceaccounts` (credential providers) | P2 | Gate is default-true but the behavior only activates when a kubelet `credentialProviders` config entry requests SA tokens — an opt-in kubelet feature, not exercised by default. | filed below |
| missing `delete` verb on `coordination.k8s.io/leases` and `storage.k8s.io/csinodes` | P3 | Cleanup-only verbs (stale Lease/CSINode removal on restart/deregistration); core get/update/patch heartbeat and registration paths are unaffected. | filed below |

## Cross-refs
- mayor-u1g6k: the P0 precedent this audit was checking against (4 missing volume rules blocked all PVC mounts).
- mayor-qrmmg: surfaced the 3 unclear rules resolved above.
- mayor-x1x2u: established the cached-upstream-source audit method reused here.
