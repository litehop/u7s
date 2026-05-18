# Kubernetes API server implemented from scratch in Rust

**Status:** Accepted  
**Date:** 2026-05-18

## Context

u7s needs a Kubernetes-compatible API server. The alternatives are: wrap the upstream `kube-apiserver` binary, implement a proxy that translates to upstream, or implement the REST API from scratch in Rust.

## Decision

Implement the Kubernetes REST API from scratch in Rust.

## Rationale

The upstream `kube-apiserver` binary is a Go program that carries the Go runtime, etcd client, and reflection-heavy JSON codegen. It idles at ~150–200 MB RSS — consuming most of the 128 MB control plane budget on its own. Wrapping it defeats the purpose of u7s.

A proxy layer adds complexity without reducing footprint: it still requires running kube-apiserver behind the scenes.

A from-scratch Rust implementation with `axum` + `rustls` idles at 20–30 MB RSS. It implements only the API surface needed for the Argo CD milestone, which is a well-defined and bounded set (see `argocd-compat-matrix.md`).

## Key choices

- **HTTP framework:** `axum` — integrates natively with tokio, minimal overhead, tower middleware for RBAC
- **TLS:** `rustls` + `rcgen` — no C dependencies, self-signed CA + per-component certs (k3s pattern)
- **Object representation:** `serde_json::Value`-based `Object` type — no `kube-rs` dependency in the server; enables CRD support without code generation
- **CRD routing:** catch-all handler + `CrdRegistry` (no axum router mutation at runtime)

## Consequences

- Server-side apply (SSA) with `managedFields` is the hardest mechanic to implement. Argo CD requires it (field manager `argocd-controller`). This is the single largest implementation risk.
- The API surface is explicitly bounded: only what's needed for the Argo CD milestone. No aggregation layer, no admission webhooks in Phase 1–3.
- Kubernetes conformance tests are the acceptance criterion for covered APIs.
