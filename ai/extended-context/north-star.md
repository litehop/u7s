---
name: north-star
description: u7s's durable north star, decision framework, and guiding principles. Changes here need explicit operator sign-off. Current status, measurements, and priorities live in roadmap.md; broader founding/technical context lives in project-context.md; mayor/worker operating process (dispatch preamble, tooling rules, VM protocol) lives in docs/the-mayor-method/dispatch-prompt-template.md; project stance and policy are tracked as bd memories (see `bd memories "project stance"`).
metadata:
  type: project
as_of: 2026-08-13
kind: principles
---

# u7s North Star

This document holds what changes rarely: why u7s exists, how component
decisions get made, and what "done" means in principle. It should not need
editing every time a PR lands. Current state, measurements, and priorities
belong in `roadmap.md`, which links back here rather than restating any of
this.

## North star

u7s targets Kubernetes-conformant operation on resource-starved environments
— the kind of box where a 1 vCPU / 1 GiB RAM VPS is normal, not a worst case.
On boxes like these, memory is the constraint that actually causes failures
in practice, not CPU. This is drawn from direct, long-running operational
experience (a decade running k3s in production), not a guess: memory
pressure is what starts the failure cascades that take clusters down.

The project's resource focus is therefore memory-primary. Other resources
still matter — see the decision metric below — but memory is where the
north star points first.

k3s and k0s are useful as a sense of scale (both are still garbage-collected
Go control planes) but not as a precise benchmark. Any specific number
attached to them is illustrative, not a target to design against, until it's
measured with a methodology that's genuinely comparable — same scope (does
it include the container runtime? in-cluster addons like DNS?) and the same
load profile on both sides. Until that measurement exists, don't cite a
specific ratio as fact.

A simple, opinionated packaging and installation story (`curl | bash`-style)
is a real end-goal, not an afterthought — see Packaging below. Running real
in-cluster workloads (including GitOps tooling like Argo CD) is valuable as
a way to exercise u7s against realistic usage, not as a milestone in itself.

This document, together with roadmap.md, serves two audiences: it's a drift
check for the operator and any agent working on u7s, and it gives
prospective users a rough, honest sense of what to expect.

## Decision metric

For any component u7s could plausibly own natively instead of delegating to
an existing upstream binary:

> Can we do this with meaningfully less memory, without a disproportionate
> cost in CPU or disk? If yes, build/optimize it in u7s. If no, keep the
> upstream component.

Memory is the primary axis (see North star). CPU and disk are guardrails,
not primary targets: a change that saves a small amount of memory at the
cost of a large, disproportionate increase in CPU or disk is not a win.
There's no fixed formula for "disproportionate" — it's a judgment call made
at decision time, not a ratio to automate against.

## Guiding principles

1. **Conform, don't reinvent — especially at the API level.** Kubernetes'
   architecture is proven; u7s optimizes *on* it, it does not fork it. This
   is what lets real upstream components (KCM, kubelet, kube-scheduler) run
   against u7s as conformance oracles. Diverging at the API boundary would
   forfeit that. (Concrete precedent: choosing to let the real KCM
   namespace-controller own namespace-deletion lifecycle, rather than u7s
   reimplementing the controller's condition-setting logic, when both were
   on the table.)

2. **Correctness first, performance second.** Perf work on incorrect code
   optimizes the wrong thing. This applies beyond the conformance suite: a
   correctness gap found through any means — conformance, a
   non-conformance-tagged upstream e2e test, or a realistic representative
   workload — takes priority over in-progress perf work, the same as a
   conformance regression would. Conformance passing is necessary but not
   sufficient evidence of correctness; it has known blind spots (its heavy
   single-node bias means multi-node-only behavior can, and has, shipped
   broken).

3. **Every component decision is gated by evidence, evaluated in this
   order, with no fixed order of *which* component gets attention next:**
   - **Is it needed at all**, in the deployment shape u7s actually targets?
     Skip this question when the answer is obvious (apiserver, scheduler,
     the container runtime, kubelet); ask it explicitly when it isn't (a
     component whose current necessity may be an artifact of the current
     development/test topology rather than a real production requirement).
   - **What does it actually cost**, measured, not assumed.
   - **Can upstream configuration or tuning reduce that cost**, checked
     before anything else — a rewrite is not on the table until this has
     been tried.
   - **Only then**, is a native rewrite cost-justified — engineering effort
     versus realistic savings, using the same measurement methodology on
     both sides.

   Whichever component this process flags as the largest realistic
   opportunity gets attention next. There is no standing default sequence
   (e.g. no "apiserver, then scheduler, then eventually kubelet") — current
   evidence decides, and the evaluation is re-run as new data lands.

## Packaging philosophy

Simple installation is a real design goal, motivated by direct negative
experience with both k3s and k0s: both expose a large YAML configuration
surface that's under-documented, and where documentation exists, it drifts
out of sync with actual behavior — to the point of needing to read source to
find what a field does. k3s then fails by having defaults that work well
initially but fail in surprising ways later; k0s fails differently, with
defaults that don't produce a working cluster at all, while still installing
components nobody asked for.

u7s's answer: default everything possible, and keep the configurable
surface deliberately small. A zero-argument install should produce a working
cluster you know how to connect to. The things that should stay explicitly
configurable are node identity (defaulting to hostname) and networking —
specifically, which interface(s) to use for what, since real deployments may
need to route cluster traffic over something like a WireGuard mesh rather
than the default (first non-loopback) interface. Past that basic surface,
prefer forcing an opinionated, lightweight default over exposing a knob.

## Project stance

Pre-alpha / greenfield. No backward compatibility. Break freely.
