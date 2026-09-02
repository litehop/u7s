# Node self-write of spec.podCIDR — allowlist viability for podIP SSRF fix

Bead: mayor-h3vp6

## Answer

**VERDICT: allowlist-defeated.** A `system:node:<name>` identity CAN set its own
node's `spec.podCIDR` (empty → valid) via a plain PATCH to `/api/v1/nodes/<name>`
(no subresource, no elevated privilege beyond its own kubelet identity). This was
proven live, not just inferred. A rogue/compromised node can therefore win the race
against kube-controller-manager's node-ipam-controller and set its own `podCIDR` to
any CIDR it likes before KCM ever assigns one, which trivially defeats a
`podIP ∈ node.spec.podCIDR` allowlist (the node just picks a `podCIDR` that contains
whatever external/internal IP it wants to report as a pod's `status.podIP`).
**Recommendation: proceed with mayor-npjfm's loopback/link-local/metadata blocklist**;
do not attempt to supersede it with the CIDR-allowlist design, since the allowlist's
load-bearing precondition (node cannot control its own podCIDR) does not hold in this
codebase.

## Load-bearing question

Can a `system:node:<name>` identity set its OWN `spec.podCIDR` the first time
(empty → valid), or race the ipam-controller to set it? If yes, the allowlist fix is
defeated regardless of `validate_node_spec_immutable`'s once-only guard, because the
node itself can be the one who does the once-only write.

## 1. RBAC finding (static)

The built-in `system:node` ClusterRole rule for the full `nodes` resource
(`crates/apiserver/src/lib.rs:1428`):

```rust
{ "apiGroups": [""], "resources": ["nodes"],        "verbs": ["get","list","watch","create","update","patch"] },
{ "apiGroups": [""], "resources": ["nodes/status"], "verbs": ["get","update","patch"] },
```

This grants `update`/`patch` on the FULL `nodes` resource (spec included), not just
`nodes/status` — but this ClusterRole's `ClusterRoleBinding` is seeded with **no
subjects** (`crates/apiserver/src/lib.rs:1489-1495`, comment: "a kubelet is authorized
by the Node authorizer... never by a cluster-wide RBAC grant to the whole
`system:nodes` group"). So RBAC alone grants a node identity nothing — the real
authorization path is a separate Node authorizer module, `node_authz.rs`.

## 2. Node-authorizer finding (static) — this is where the gap actually is

`crates/apiserver/src/auth.rs:1467-1469` wires request authorization as
`node_authz::authorize(...) || rbac_index.is_allowed(...)` — i.e. a request is
allowed if EITHER the Node authorizer OR RBAC allows it. `node_authz.rs`'s
`authorize_node` function (`crates/apiserver/src/node_authz.rs:331-343`):

```rust
fn authorize_node(node_name: &str, req: &AuthzRequest<'_>) -> bool {
    match req.subresource {
        "" => match req.verb {
            "create" => true,
            "get" | "list" | "watch" | "update" | "patch" => req.name == Some(node_name),
            _ => false,
        },
        "status" => matches!(req.verb, "update" | "patch") && req.name == Some(node_name),
        _ => false,
    }
}
```

The `"" =>` arm (empty subresource = the FULL node object, not just status) allows
`update`/`patch` whenever `req.name == Some(node_name)` — i.e. whenever the node is
writing to its own Node object. There is no field-level restriction: this grants a
node write access to its own **entire** `spec`, including `podCIDR`. This mirrors
upstream's Node authorizer's RBAC-equivalent grant, but **u7s has no
NodeRestriction-equivalent admission plugin** to additionally narrow which spec
fields a node may touch on its own object (upstream's real NodeRestriction admission
plugin restricts kubelet writes to labels/taints/status and does not let a kubelet
set its own `spec.podCIDR`; this is exactly the gap the bead's caveat flagged).

## 3. Admission finding (static)

`validate_node_spec_immutable` (`crates/apiserver/src/handlers/resource.rs:2165`) is
the ONLY admission-time check on Node spec updates. It is identity-agnostic: it only
enforces "podCIDR/podCIDRs may transition from empty to valid exactly once, then
frozen" — it does not know or care WHO is making that empty→valid write. The "only
`system:node:worker-1` may update this node" string found via grep
(`crates/apiserver/src/admission.rs:11150-11227`) is a ValidatingAdmissionPolicy CEL
*unit test fixture* exercising the general VAP engine — it is not a built-in, always-on
policy; nothing wires a `system:node`-self-only restriction into the real request
path by default. Confirmed: no admission gate blocks a node from performing the
empty→valid `spec.podCIDR` write itself.

## 4. Live test (empirical confirmation)

Stack brought up via `scripts/conformance/run-all.sh --vm lima-node-5 --port 6447
--kubelet-port 10254 --reset --stack-only` (`lima-node-5` registered `Ready`,
`spec: {"unschedulable":false}` — no `podCIDR` yet, KCM had not assigned one).

**SubjectAccessReview check** (`kubectl auth can-i`, `-v=8` request/response
recorded):

```
$ kubectl --kubeconfig temp/u7s/kubeconfig auth can-i patch nodes/lima-node-5 \
    --as=system:node:lima-node-5 --as-group=system:nodes --as-group=system:authenticated
yes

$ kubectl --kubeconfig temp/u7s/kubeconfig auth can-i patch nodes/lima-node-5 \
    --subresource=status --as=system:node:lima-node-5 --as-group=system:nodes --as-group=system:authenticated
yes

$ kubectl --kubeconfig temp/u7s/kubeconfig auth can-i patch nodes \
    --as=system:node:lima-node-5 --as-group=system:nodes
no   # (name-agnostic check — node_authz requires req.name == Some(node_name), expected)
```

**Actual PATCH of the full node object's spec.podCIDR**, impersonating
`system:node:lima-node-5` / group `system:nodes`:

```
$ kubectl --kubeconfig temp/u7s/kubeconfig patch node lima-node-5 --type=merge \
    -p '{"spec":{"podCIDR":"10.244.99.0/24","podCIDRs":["10.244.99.0/24"]}}' \
    --as=system:node:lima-node-5 --as-group=system:nodes --as-group=system:authenticated -v=8

PATCH https://127.0.0.1:6447/api/v1/nodes/lima-node-5?fieldManager=kubectl-patch
  Impersonate-User: system:node:lima-node-5
  Impersonate-Group: system:nodes
  Impersonate-Group: system:authenticated
Response: 200 OK
  "spec":{"podCIDR":"10.244.99.0/24","podCIDRs":["10.244.99.0/24"],"unschedulable":false}

node/lima-node-5 patched
```

The node identity's own PATCH to the **full node object** (no subresource) was
**ALLOWED** and set `spec.podCIDR` from empty to `10.244.99.0/24` — a value the node
itself chose, with no controller-manager involvement.

Confirming `validate_node_spec_immutable` still guards the *second* write (identity
does not matter to this check, only the empty→valid transition does):

```
$ kubectl ... patch node lima-node-5 --type=merge -p '{"spec":{"podCIDR":"10.244.100.0/24"}}' \
    --as=system:node:lima-node-5 --as-group=system:nodes --as-group=system:authenticated
Error: The request is invalid: spec.podCIDR: Forbidden: node updates may not change
podCIDR except from "" to valid

$ kubectl ... get node lima-node-5 -o jsonpath='{.spec}'
{"podCIDR":"10.244.99.0/24","podCIDRs":["10.244.99.0/24"],"unschedulable":false}
```

So the "once-only" guard holds — but the "once" is a race the node itself can win
(and did, in this test, with zero contention from KCM), which is exactly the
load-bearing gap.

## Decision impact

The two-branch podIP validation (`if hostNetwork { podIP == status.hostIP } else
{ podIP ∈ node.spec.podCIDR }`) is **NOT** a sound fix in this codebase: a rogue node
sets its own `podCIDR` to a range containing whatever address it wants to advertise
as a pod's `status.podIP`, then reports that podIP — the allowlist check passes
trivially. **mayor-npjfm's loopback/link-local/metadata blocklist should proceed
as-is; do not supersede it with the CIDR-allowlist.** The residual bound already noted
in npjfm/k6m4a stands (still requires node-compromise + `pods/proxy`, same as
upstream's own SSRF risk posture), and the allowlist idea should not be re-attempted
unless/until a real NodeRestriction-equivalent admission plugin is added to prevent a
node from writing non-status Node spec fields (a materially bigger change, out of
scope here).

## Follow-on

Filed mayor-node authorizer's own scope gap as a separate, standalone finding — see
bd note on mayor-h3vp6 for the filed bead ID (a node being able to write its own full
`spec` via `node_authz::authorize_node`'s `"" =>` arm, not just `status`, is itself a
broader-than-upstream authorization gap independent of the podIP-SSRF question, and
warrants its own fix bead).
