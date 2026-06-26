# Apiserver code gotchas

Scope: non-obvious correctness constraints in the u7s apiserver that a fresh mayor (or worker) would not infer from the code alone — each has bitten conformance before. These are "why the code is shaped this way," not operational process (those live in `bd memories`). Recategorized from bead memories 2026-06-26 because they are code-findings, not operational rules.

## KCM panic propagation kills root-ca-cert-publisher
KCM controller goroutines run inside `sync.WaitGroup.Go`, which **re-panics after recovery** — so a panic in ANY single controller (e.g. the endpoints controller) kills the **entire** kube-controller-manager process. Symptom: all KCM controllers go silent at once, including `root-ca-cert-publisher`, so `kube-root-ca.crt` is never created in new namespaces → pods with projected ServiceAccount-token volumes stick in `ContainerCreating`. If you see broad "pods stuck ContainerCreating + no kube-root-ca.crt" symptoms, look for a panicking controller upstream, not a missing feature.

## fetch_initial_events / sendInitialEvents must apply read-time defaults
`fetch_initial_events` in `watch.rs` MUST call `apply_defaults` on each item before returning. Raw store bytes lack read-time defaults (e.g. `ipFamilies` on Services). Seeded objects (default/kubernetes, kube-system/kube-dns) are stored WITHOUT `ipFamilies` — defaults are applied at read time only. Bypassing this makes the KCM endpoints controller panic on `IPFamilies[0]` at startup (the `sendInitialEvents=true` watch path), which (per the panic-propagation gotcha above) kills the whole KCM. Fixed in c777cd7; regression test `fetch_initial_events_applies_defaults_to_snapshot_items` in watch.rs. General rule: any path that returns stored objects to a client/controller must apply the same read-time defaults the normal GET/LIST path does.

## exec/attach: kubelet uses different query-param names than kubectl
On the apiserver→kubelet exec/attach proxy path, the kubelet expects DIFFERENT param names than kubectl sends, and integer booleans:
- kubectl sends `stdin`/`stdout`/`stderr`; kubelet expects `input`/`output`/`error` (k8s api/core/types.go: ExecStdinParam=`input`, ExecStdoutParam=`output`, ExecStderrParam=`error`).
- kubelet expects integer booleans (`1`/`0`), not `true`/`false`.
- `command` passes through unchanged.
So the proxy must map e.g. inbound `stdin=true&stdout=true&command=echo` → outbound `input=1&output=1&command=echo`. (Original fix PR #366 handled the boolean encoding but the param-name translation is the load-bearing part.)

## CSINode has no status subresource / admission logic (known conformance gap)
In a real cluster, CSINode (storage.k8s.io/v1) has a custom status subresource and admission logic. The u7s generic handler serves CSINode without these. The kubelet does NOT depend on it for basic node registration, so it's not a startup blocker, but it IS a conformance gap — revisit when working on storage conformance or related sonobuoy failures.
