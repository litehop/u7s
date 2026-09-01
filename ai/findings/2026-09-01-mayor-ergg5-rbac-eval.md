# RBAC evaluation edge cases beyond system:node — Phase 1 deep-dive

Bead: mayor-ergg5
Scope: `crates/apiserver/src/rbac.rs` rule-matching/aggregation logic, plus the
escalation-prevention call sites in `crates/apiserver/src/handlers/generic.rs`
that consume it. Excludes: the `system:node` binding (mayor-tkv6j, fixed) and
the "matches upstream" comment audit in lib.rs (mayor-x1x2u).

## Verdict

Three HIGH-severity bugs, all reachable by a namespace-scoped `admin`/custom
RBAC-manager identity, not requiring a stolen credential:

1. `rbac.rs` subresource-wildcard matching diverges from upstream in both
   directions (`resource/*` over-grants; `*/subresource` under-grants).
2. The ClusterRoleBinding/RoleBinding creation bypass checks the wrong verb
   (`escalate` instead of upstream's `bind`), letting `escalate`-only holders
   bind arbitrary roles (including cluster-admin) to any subject.
3. Namespaced `Role` create/update has **no** escalation check at all — the
   two-step "bind first, define role second" attack that `check_clusterrole_
   escalation` exists to close for ClusterRoles is wide open for Roles.

Cross-checked against `pkg/apis/rbac/v1/evaluation_helpers.go`,
`pkg/registry/rbac/escalation_check.go`, and
`plugin/pkg/auth/authorizer/rbac/rbac.go` at `release-1.36` (cached under
`temp/research/`, not committed).

## Findings

### F1 — HIGH — subresource wildcard matching diverges from upstream both ways

`crates/apiserver/src/rbac.rs:576-592` (`resource_matches`):

```rust
if let Some((res, sub)) = r.split_once('/') {
    if res != resource { return false; }
    sub == "*" || sub == subresource
}
```

Upstream `ResourceMatches` (`pkg/apis/rbac/v1/evaluation_helpers.go:52-78`)
only special-cases a **`*/subresource`** pattern (wildcard on the resource,
fixed subresource, e.g. `*/scale` matches `deployments/scale`,
`statefulsets/scale`, ...). It has no notion of `resource/*` at all — a rule
literally spelled `"pods/*"` is compared only via exact string equality
against `"pods/<subresource>"` and never matches anything, on real
kube-apiserver.

u7s does the opposite: it implements `resource/*` (over-permissive) and does
not implement `*/subresource` at all (under-permissive):

- **Over-permissive**: a rule `resources: ["pods/*"]` matches
  `subresource == "*"` OR `subresource == "<anything>"` — but the check
  `sub == "*"` is comparing the *rule's own literal string* `"*"` to itself
  after the split, so it is always true regardless of the *request's*
  subresource, including the empty string. That means `"pods/*"` also grants
  the **bare `pods` resource** (get/list/watch/delete pods themselves), not
  just its subresources. The function's own doc comment at line 575
  (`"pods/*" matches resource=pods with any non-empty subresource`) is wrong
  about its own implementation — emptiness is never checked. A rule author
  writing `"pods/*"` to scope a grant to `pods/log`+`pods/exec`+`pods/status`
  etc. unexpectedly also gets base-resource access, which is broader than
  the rule text says and broader than upstream would ever grant for that
  literal string (upstream: never matches, full stop).
- **Under-permissive**: upstream's real `*/subresource` wildcard (e.g.
  `*/scale`, used by some cluster-admin-authored roles to grant a subresource
  verb across every scalable resource type) is not implemented — u7s's
  `split_once` treats the literal string `"*"` before the slash as a literal
  resource name, so `res != resource` is always true for any real resource
  and the rule silently never matches. Fail-safe (denies rather than
  over-grants) but breaks legitimate delegation and diverges from advertised
  "matches upstream" behavior.
- Confirmed live in a test fixture already: `crates/apiserver/src/auth.rs:3806`
  builds a ClusterRole with `resources: ["uids", "userextras/*"]` intending
  "impersonate any extra key" — this passes today only because of the F1 bug;
  on real kube-apiserver this rule grants nothing (impersonation of any extra
  key would be denied), so the test encodes non-conformant behavior as if it
  were correct.

Fix sketch: rewrite `resource_matches` to mirror `ResourceMatches` exactly —
exact match on `resource` or `resource/subresource`, plus a dedicated
`*/subresource` branch keyed off the rule string's *prefix* being literally
`"*/"`. Drop the `resource/*` interpretation entirely (or, if intentionally
extending upstream syntax, gate it behind an explicit non-empty-subresource
check so it stops granting the bare resource — but the safer, upstream-
matching fix is to drop it).

### F2 — HIGH — CRB/RoleBinding creation bypass checks `escalate`, not `bind`

`crates/apiserver/src/handlers/generic.rs:786-799` (`check_crb_escalation`)
and `crates/apiserver/src/handlers/generic.rs:890-911` (`check_rb_escalation`)
both build an `AuthzRequest { verb: "escalate", resource: "clusterroles"/"roles", ... }`
to decide whether to bypass the "caller must already hold the referenced
role's rules" check.

Upstream splits this into two distinct, separately-grantable verbs
(`pkg/registry/rbac/escalation_check.go`):

- `RoleEscalationAuthorized` (verb **`escalate`**) — bypasses the check when
  **creating/updating a Role or ClusterRole itself** with rules the author
  doesn't hold.
- `BindingAuthorized` (verb **`bind`**) — bypasses the check when **creating
  a RoleBinding/ClusterRoleBinding** that references a role the binder
  doesn't hold all the rules of.

u7s uses `escalate` for both binding-creation checks. Consequence: any
identity granted `escalate` on `clusterroles`/`roles` — a privilege meant
*only* to let them author new Role/ClusterRole rule sets — transitively
gains the upstream-distinct `bind` privilege: they can create a
ClusterRoleBinding/RoleBinding pointing ANY existing ClusterRole (including
`cluster-admin`) at themselves or any other subject, without holding `bind`
and without holding the target role's rules. This conflates two upstream-
separable grants into one, broadening the effective reach of an `escalate`-
only rule beyond its rule text. u7s's own bootstrap `admin` ClusterRole
(`crates/apiserver/src/lib.rs:2135`) grants both `bind` and `escalate`
together so it isn't directly exposed by this bug today, but any operator
who follows upstream RBAC docs and grants `escalate` alone (a documented,
intentional pattern for "role authors who shouldn't be able to bind
arbitrary existing roles") gets `bind` for free under u7s.

Secondary, same-root issue: even with the verb corrected, `check_rb_escalation`'s
namespace scoping for a RoleBinding→ClusterRole reference
(`generic.rs:896-899`, `escalate_namespace: None`) doesn't match upstream's
`BindingAuthorized`, which always scopes the check to `bindingNamespace` (the
RoleBinding's own namespace) *regardless* of `roleRef.Kind` — this is what
lets an operator delegate "bind ClusterRole X, but only via RoleBindings in
namespace N" without granting cluster-wide bind. u7s's `None` here means only
a cluster-wide bind/escalate grant can ever satisfy this bypass path,
silently dropping that upstream delegation pattern.

Fix sketch: rename the verb checked in both functions from `"escalate"` to
`"bind"`; for `check_rb_escalation`'s ClusterRole-via-RoleBinding case, pass
`namespace: Some(namespace)` (the RoleBinding's own namespace) instead of
`None`, matching upstream's `bindingNamespace` semantics.

### F3 — HIGH — no escalation check at all on namespaced Role create/update

No function analogous to `check_clusterrole_escalation`
(`crates/apiserver/src/handlers/generic.rs:821-847`) exists for namespaced
`Role` writes. Confirmed by exhaustive grep of every escalation-check call
site (`crates/apiserver/src/handlers/resource.rs:319-322, 552-555,
1162-1164, 1219-1221`): each call site invokes exactly
`check_crb_escalation` + `check_clusterrole_escalation` + `check_rb_escalation`
— `check_rb_escalation` validates *RoleBinding* creation against the
referenced role's rules, but nothing validates a `Role` object's own `rules`
field against its author's held permissions when that Role is (or later
becomes) bound.

`check_clusterrole_escalation`'s own doc comment
(`generic.rs:808-818`) states exactly why this check exists: *"(1) create CRB
→ references non-existent role → CRB check skipped; (2) create ClusterRole
with wildcard rules → instant cluster-admin"*. The identical two-step race is
open for namespaced Roles and is **not** closed by anything:

1. Low-privilege identity with plain `create`/`update` on `roles` +
   `rolebindings` in namespace `ns-a` (no `escalate`/`bind` needed — this bug
   requires none) creates a RoleBinding in `ns-a` referencing Role
   `not-yet-created`, subject = self. `check_rb_escalation` sees
   `role_rules.is_empty()` and allows it (upstream-matching "binding grants
   nothing yet" behavior).
2. The identity then creates Role `not-yet-created` in `ns-a` with
   `rules: [{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`. No check
   intercepts this create.
3. The pre-existing RoleBinding now grants the identity full admin over
   `ns-a`.

This is a genuine privilege-escalation path requiring only the ability to
manage Roles+RoleBindings in one's own namespace — a narrower, plausible
grant distinct from the built-in `admin` ClusterRole (which already holds
`escalate`+`bind` by design and would be a non-issue if F2 were also fixed).

Fix sketch: add `check_role_escalation` mirroring `check_clusterrole_escalation`
— on namespaced Role create/update with non-empty `rules`, look up whether
any RoleBinding in that namespace already references the role name
(`role_rules(namespace, name)`-style existence check on the binding side, not
the role side — needs a `namespace_binding_references_role(namespace, name)`
helper analogous to `clusterrole_has_bindings`), and if so require
`user_holds_all_rules_in_namespace` (or the corrected `bind`/`escalate`
bypass from F2) before persisting. Wire it into every call site listed above
alongside the other three checks.

## Checked, no bug found

- `resource_names` wildcard: `rule_covers` (`rbac.rs:556-565`) does plain
  string equality against `rule.resource_names`, with no special-casing of
  `"*"` — matches upstream's `ResourceNameMatches`, which also has zero
  wildcard handling for resource names. A wildcard resourceName does not
  match empty-string or arbitrary names; it would only match an object
  literally named `"*"`.
- Subject matching (`subject_matches`, `rbac.rs:427-450`): User/Group/
  ServiceAccount matching against upstream `appliesToUser`
  (`pkg/registry/rbac/validation/rule.go:281-304`) — exact match for User,
  group-membership for Group, fully-encoded `system:serviceaccount:<ns>:<name>`
  for ServiceAccount. No cross-kind collision possible (SA names are
  DNS-1123, can't contain `:`).
- ClusterRole/Role aggregation via bindings (`resolve_cluster_role_rules`,
  `resolve_role_rules`, `rbac.rs:452-485`): ClusterRoleBindings only resolve
  `ClusterRole` refs (matches upstream — CRBs can't reference a namespaced
  Role); RoleBindings resolve both `Role` (own namespace) and `ClusterRole`
  (applied in-namespace) — matches upstream `GetRoleReferenceRules`.
- `RbacIndex` update timing: `apply_object`/`remove_object`
  (`rbac.rs:88-147`) are called synchronously inside the create/update/delete
  request handlers themselves (`handlers/resource.rs:448, 824, 952, 973,
  1050, 3439, 3465, ...`), not via a background poll/refresh — no stale-allow
  window between a RoleBinding/Role deletion and the index reflecting it.
- Non-resource URL prefix matching (`non_resource_url_matches`,
  `rbac.rs:525-533`) matches upstream `NonResourceURLMatches`
  (`evaluation_helpers.go:94-108`) for the single-trailing-`*` case. DEFER:
  upstream's `strings.TrimRight(ruleURL, "*")` strips *all* trailing `*`
  characters vs. u7s's single `strip_suffix('*')` — only diverges for a
  pathological multi-star pattern like `"/api/**"`, not security relevant,
  no bead filed.

## Follow-on beads

- F1 (`resource_matches` subresource wildcard): mayor-9c8iq
- F2 (escalate/bind verb swap + RB namespace scoping): mayor-nm6l4
- F3 (missing Role-write escalation check): mayor-tih51
