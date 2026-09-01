Bead: mayor-qlgws

# Phase 1 deep-dive: admission chain + CRD/CEL sandbox

## Verdict

The Phase 0 CEL-cost-budget gap is fixed for the CRD path (wall-clock budget,
mayor-3ainu/PR #1388) but a second, unaudited CEL evaluator — the hand-rolled
VAP/MAP/webhook-matchCondition parser in `admission.rs` — has no recursion
depth guard at all and can very likely be stack-overflowed (process crash,
not just a hang) by a deeply nested expression (HIGH, new). The dry-run/
`sideEffects` gap is confirmed real and unmitigated: `sideEffects` is not
even deserialized into the webhook dispatch cache, so every webhook is
invoked unconditionally on dry-run requests (HIGH, confirmed from Phase 0).
matchCondition CEL eval errors are treated as "pass" unconditionally instead
of being governed by `failurePolicy`, diverging from upstream (MEDIUM, new).
The `admissionregistration.k8s.io` bootstrap exemption is coarser than
upstream's kind-list check but happens to be equivalently scoped today
because the group currently contains exactly the 6 kinds upstream exempts
(LOW, confirmed-benign-for-now). Admission ordering, namespaceSelector/
objectSelector matching, and failurePolicy-on-call-failure are all correct.

## Findings

### F1 — HIGH: hand-rolled VAP/MAP CEL evaluator has no recursion-depth guard (likely stack-overflow DoS)

`crates/apiserver/src/admission.rs:1591-2069` (`parse_vap_ternary` ->
`parse_vap_or` -> `parse_vap_and` -> `parse_vap_cmp` -> `parse_vap_add` ->
`parse_vap_mul` -> `parse_vap_unary` -> `parse_vap_primary`, whose `LParen`
arm at `admission.rs:2038-2048` recurses back into `parse_vap_ternary`) and
`admission.rs:2772-3035` (`parse_cel_value` <-> `parse_cel_primary` <->
`parse_cel_object_body`, used by `eval_cel_apply_config` for
MutatingAdmissionPolicy `applyConfiguration`) are both plain recursive-descent
parsers/evaluators with **no depth counter**. Every layer of `(...)` nesting
(or, in the second parser, nested `{}`/`[]` literals or chained unary `-`)
descends through the full precedence chain again with no bound other than
the native call stack.

These functions are reachable from three attacker-authored-CEL surfaces:
`eval_cel_bool_expr`/`eval_cel_vap_value` (ValidatingAdmissionPolicy
`validations`/`variables`/`messageExpression`, and
Mutating/ValidatingWebhookConfiguration `matchConditions` — see
`webhook_match_conditions_pass` at `admission.rs:368`), and
`eval_cel_apply_config` (MutatingAdmissionPolicy `applyConfiguration`
expressions, `admission.rs:1491`). A payload like `"(".repeat(2000) + "1" +
")".repeat(2000)` is ~4KB and, per the call-chain above, recurses roughly 8
native stack frames per paren level — order of 16,000 frames for that input,
comfortably enough to exhaust a typical 2MB-8MB thread stack. A Rust stack
overflow is not catchable (`panic::catch_unwind` does not intercept it); on
Linux it SIGSEGVs/aborts the **whole process**, taking down every tenant, not
just the request that triggered it — worse than the wall-clock hang class
mayor-3ainu already defends against for the CRD path.

Contrast: the CRD/CR path (`handlers/cr.rs`) uses the vendored `cel` crate
(0.14.3), whose `Parser` has a built-in `max_recursion_depth` (default 96,
`~/.cargo/registry/.../cel-0.14.3/src/parser/parser.rs:105-125`) that
`Program::compile`'s `Parser::default()` inherits — so the exact same class
of attack against `x-kubernetes-validations` is already closed by the
dependency, unprompted. The hand-rolled evaluator has no equivalent.

Not empirically reproduced in this audit (crashing the test process is out
of scope for a read-only Shape-3 pass with no code changes permitted), but
confidence is high from code inspection: the mutual recursion is
unconditional and there is no length/depth check anywhere upstream of these
parsers on the CEL source string.

**Fix sketch:** thread a `depth: &mut u32` (or a fixed recursion budget)
through both call chains and return `None`/a parse error past a small cap
(e.g. 32-64, well under any real policy's nesting), mirroring the `cel`
crate's own `max_recursion_depth`. Cheaper alternative: reject VAP/MAP/
matchCondition CEL source strings above a small nesting-depth or paren-count
threshold before tokenizing, analogous to `walk_schema_dos_bounds`'s
defense-in-depth stance for boon schemas (`handlers/crd.rs:195`). This is a
manual guard, not something obtainable from a crate's budget API — there is
no crate here, the evaluator itself needs the cap. Migrating this evaluator
to the `cel` crate (already tracked, `mayor-1y0h6`, deferred as P4 "no
observed defect") would fix it for free; this finding is the observed defect
that bead's own revisit trigger asks for.

### F2 — HIGH: dry-run requests invoke webhooks unconditionally regardless of declared `sideEffects` (confirms Phase 0)

`crates/apiserver/src/admission.rs:211-233` (`WebhookEntry` struct) does not
even have a `side_effects` field — `sideEffects` is never deserialized into
the in-memory webhook-dispatch cache that `run_mutating_webhooks`
(`admission.rs:3357`) and `run_validating_webhooks` (`admission.rs:3830`)
read from. `invoke_mutating_webhook` (`admission.rs:1223-1307`) runs the
full rules/namespaceSelector/objectSelector/matchConditions gauntlet and,
if all match, proceeds straight to resolving the webhook URL and making the
HTTP call (`admission.rs:1309` onward) with no `ctx.dry_run` check anywhere
in that path. `ctx.dry_run` (`admission.rs:831-832`) is plumbed through
solely to expose `request.dryRun` to VAP CEL expressions
(`admission.rs:3634`) — it is never read to gate the webhook call itself.

Upstream (`k8s.io/apiserver/pkg/admission/plugin/webhook/{mutating,validating}/dispatcher.go:248-254`,
fetched at `temp/research/{mutating,validating}_dispatcher.go`) checks, before
ever building the HTTP request: if the request `IsDryRun()` and the
webhook's `SideEffects` is not `None`/`NoneOnDryRun`, it returns
`NewDryRunUnsupportedErr` instead of calling the webhook — because the
webhook has no contractual guarantee it will honor `dryRun: true` in the
AdmissionReview it receives, so calling it could produce real side effects
(e.g. external provisioning, billing, notification) for a client that
explicitly asked for none via `kubectl --dry-run=server` or `apply
--server-side --dry-run=server`.

**Fix sketch:** add `side_effects: Option<String>` (or an enum) to
`WebhookEntry`, deserialize it in `admissionreg_gen_adapter.rs`'s webhook
cache builder (which already handles `sideEffects` for the typed
list/get path per `admissionreg_gen_adapter.rs:952-993`), and in
`invoke_mutating_webhook`/the validating-webhook equivalent, before the HTTP
call: if `ctx.dry_run && !matches!(side_effects, Some("None") |
Some("NoneOnDryRun"))`, return a `StatusError` (subject to the webhook's own
`failurePolicy` the same way an unreachable-webhook error is, per upstream's
`ErrCallingWebhook`/`DryRunUnsupportedErr` handling) instead of calling out.

### F3 — MEDIUM: matchCondition CEL eval errors are unconditionally treated as "pass", ignoring `failurePolicy`

`webhook_match_conditions_pass` doc comment (`admission.rs:362-367`) and the
VAP matchCondition loop (`admission.rs:3674-3681`) both deliberately treat a
matchCondition expression that fails to evaluate (parse error, or an
unsupported CEL construct like `authorizer`) as "condition satisfied" —
i.e. the webhook/policy always still runs — regardless of the webhook's or
policy's `failurePolicy`.

Upstream (`k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions/matcher.go:80-144`,
fetched at `temp/research/matchconditions_matcher.go`) ties this to
`failurePolicy` explicitly: on an eval error (no explicit `false` result),
`failurePolicy: Fail` returns the error itself, which fails the whole
request (does **not** call the webhook and does **not** admit the object);
`failurePolicy: Ignore` returns `Matches: false`, which **skips** the
webhook/policy entirely. u7s's current behavior — always run — matches
neither: under `Ignore` it wrongly applies a webhook/policy the operator
configured to be skippable-on-uncertainty; under `Fail` it wrongly proceeds
instead of refusing the request outright. Given the hand-rolled evaluator's
narrower CEL grammar (F1's sibling concern — no `authorizer` variable,
no macros), a legitimate matchCondition using an unsupported construct is a
realistic way to hit this path, not just a hypothetical.

**Fix sketch:** on eval error, look up the owning webhook's/binding's
`failurePolicy` (already parsed — `WebhookEntry::failure_policy`,
`admission.rs:216-217`) and either return a `StatusError` (`Fail`, default)
or treat the match as `false`/skip (`Ignore`), instead of the current
unconditional "treat as pass".

### F4 — LOW (currently benign): `admissionregistration.k8s.io` bootstrap exemption checks the whole API group, not specific kinds

`is_webhook_configuration_resource` (`admission.rs:3345-3347`) is
`ctx.group == "admissionregistration.k8s.io"` — coarser than upstream's
`IsExemptAdmissionConfigurationResource`
(`staging/.../webhook/predicates/rules/rules.go:119-129`, fetched at
`temp/research/rules.go`), which checks `gvk.Kind` against exactly
`ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`,
`ValidatingAdmissionPolicy`, `ValidatingAdmissionPolicyBinding`,
`MutatingAdmissionPolicy`, `MutatingAdmissionPolicyBinding`. Confirmed via
`handlers/discovery.rs:1246-1310` (`admissionregistration_v1_resources`)
that u7s's `admissionregistration.k8s.io/v1` group currently contains
exactly those 6 kinds and nothing else, so the group-level check is
equivalently scoped today — not exploitable now. It is fragile: any future
resource added to this group (or a v1beta1/v1alpha1 kind that isn't one of
the 6) would be silently, unintentionally exempted from all admission
webhooks with no test to catch the regression.

**Fix sketch:** switch the check to match on `ctx.kind` against the 6-name
list (mirroring upstream), not just `ctx.group`, the next time this function
is touched. Not urgent enough to justify a standalone change today given
zero current exposure.

### Confirmed correct (no finding)

- **Admission ordering:** every call site in `handlers/{resource,pods,cr,crd,
  namespaces,csr}.rs` runs `run_mutating_webhooks` before
  `run_validating_webhooks`; within the mutating phase,
  `run_cel_mutating_policies` (MutatingAdmissionPolicy) runs before the
  webhook chain (`admission.rs:3372`) — matches upstream ordering.
- **namespaceSelector/objectSelector matching:** `label_selector_matches`
  (`admission.rs:274-324`) correctly implements `In`/`NotIn`/`Exists`/
  `DoesNotExist` with `NotIn`-on-missing-key-matches semantics, matching
  upstream `labels.Selector`; `None` selector matches all (correct default).
- **failurePolicy on webhook-call failure** (unreachable/timeout/oversized
  response): already covered by existing tests
  (`run_{mutating,validating}_webhooks_unreachable_with_{ignore,fail}_policy_*`)
  and reviewed as correct.
- **CEL cost budget on the CRD/CR path:** present via
  `execute_cel_with_budget` (`handlers/cr.rs:1240-1259`, 250ms wall-clock
  per rule, `MAX_CONCURRENT_CEL_EVAL_THREADS=24` process-wide gate,
  panic-safe `GateGuard`) — mayor-3ainu, PR #1388. Residual gap: the budget
  is per-rule, not a cumulative per-request budget, so a CRD with many rules
  each just under 250ms can still make one CR write take several seconds
  (bounded, not unbounded — a latency/soft-DoS concern, not a hang). Not
  filing a follow-on for this; upstream's own per-request
  `RuntimeCELCostBudget` is a nice-to-have refinement, not a gap of the same
  class as F1/F2.

## Follow-on beads

- mayor-0lkgy — F1 (HIGH): no recursion-depth guard in hand-rolled VAP/MAP CEL evaluator (stack-overflow DoS)
- mayor-0xl6y — F2 (HIGH): dry-run requests invoke webhooks regardless of declared sideEffects
- mayor-404j6 — F3 (MEDIUM): matchCondition CEL eval errors ignore failurePolicy
- mayor-dds7d — F4 (LOW): admissionregistration.k8s.io group-level exemption should match upstream's kind list

Severity counts: HIGH 2, MEDIUM 1, LOW 1.

## Cross-refs

- mayor-s851y (Phase 0, parent)
- mayor-3ainu / PR #1388 (CEL wall-clock budget for CRD path — closes the
  original Phase 0 CEL-cost-budget gap for `x-kubernetes-validations`)
- mayor-1y0h6 (deferred: migrate VAP/MAP hand-rolled CEL evaluator to the
  `cel` crate — F1 is the "observed defect" this bead's revisit trigger asks
  for)
- `temp/research/{webhook_generic,mutating_dispatcher,validating_dispatcher,rules,matchconditions_matcher}.go`
  — upstream release-1.36 sources fetched for this audit (gitignored, not
  committed)
