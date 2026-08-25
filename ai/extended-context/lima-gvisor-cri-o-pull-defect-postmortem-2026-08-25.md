---
as_of: 2026-08-25
kind: postmortem
---

# Postmortem: Lima `gvisor-tap-vsock` cri-o image-pull defect (new `mayor-o61zz` manifestation)

**Status:** Worked around, not permanently fixed. A reusable manual/scriptable
technique was verified end-to-end; no code fix landed — deliberately deprioritized
by the operator as not currently high priority.
**Duration:** Discovered 2026-08-24/25 during an operator-driven attempt to bring up
a 2-node Lima conformance stack (~1 hour of manual attempts before escalating);
diagnosed and worked around same-day across ~3 hours of dispatched-agent time.
**Severity:** Dev/test-tooling only. Confirmed specific to Lima's `gvisor-tap-vsock`
virtual networking — does **not** affect the operator's real production topology
(real cloud/VPS networking, not Lima). Blocked all Lima-based multi-node conformance
work until worked around.
**Root cause:** cri-o's own pull-path connection/session reuse degrades over Lima's
virtual network when fetching a multi-layer image's blobs concurrently — a single
image's own internal concurrency is sufficient to trigger it, no multi-VM contention
needed. A narrower, previously-undocumented manifestation of the `mayor-o61zz` defect
family (root cause: unfixed upstream `containers/gvisor-tap-vsock` PR #613).
**Fix:** None landed this session. A verified workaround exists (below); two options
for a permanent fix are noted but not pursued.

## Impact

- `--stack-only` provisioning failed deterministically (6/6 reproductions across two
  VM boots + manual retries) pulling `registry.k8s.io/e2e-test-images/agnhost:2.55`/
  `:2.63.0` and similar multi-layer images: `unexpected EOF (after reconnecting,
  fetching blob: StatusCode: 400 ...)`.
- **Not limited to provisioning**: recurred live mid-suite during the eventual
  successful full-conformance run, hitting an un-preseeded `registry.k8s.io/etcd:3.6.8-0`
  sidecar pulled on-demand by kubelet — the direct cause of the run's only failure
  (`[sig-api-machinery] Aggregator ... Sample API Server`, 445/446 specs otherwise
  passed).

## Root cause

Byte-exact host-side verification ruled out CDN/blob corruption — blobs fetched
directly from the host matched manifest-declared sizes exactly. A sequential `curl`
of the same blob from *inside* the VM succeeded every time; `crictl pull` of the same
multi-layer image (config + 11 layers for `agnhost:2.55`) failed identically every
time. Single-layer images (busybox, pause, the conformance image) pulled fine both
times. This isolates the defect to cri-o's own internal concurrent/parallel blob-fetch
behavior interacting badly with the `gvisor-tap-vsock` virtual network path — the same
defect class already flagged inline in `lima/kubelet.yaml`'s own provisioning-script
comment (a documented ~92s SYN-drop under 10 concurrent image-pull flows), except this
session showed a **single** multi-layer image's own internal concurrency is enough —
the existing "pull images one at a time" mitigation was incomplete.

## Workaround (verified, reusable)

For any image cri-o's own pull path fails on:

1. Fetch the manifest list + platform-specific manifest + every blob with
   **independent `curl` processes** (100% reliable across every trial — cri-o's own
   pull reuses connections/sessions in a way that degrades; sequential curl does not).
2. Assemble into a local `dir:` skopeo layout.
3. `skopeo copy dir:<path> containers-storage:<image-ref>` — this step touches zero
   network, so it cannot hit the defect.

Applied to 23 images across two nodes (`lima-node-2`, `lima-node-3`); every import
succeeded first try. **Does not cover on-demand pulls of images outside a known,
pre-seeded set** — the etcd-sidecar failure above is exactly this gap. A bare
`--all-e2e` run remains exposed to occasional single-spec flakes from this class of
defect until either the upstream issue is fixed or a more general fix lands.

## Fix — not built, two options if revisited

1. **Cheap**: bake the curl+skopeo technique into `lima-start.sh`'s provisioning
   pre-seed step by default (current one-at-a-time pull mitigation is confirmed
   insufficient).
2. **More durable**: a pull-through registry mirror on the Lima host, so the VM
   always fetches from a local, reliable endpoint instead of re-hitting the flaky
   path per image. Would also cover on-demand mid-suite pulls, which pre-seeding
   alone cannot.

## Cross-references

- `mayor-o61zz` (P1, OPEN, root-cause tracker) — this postmortem's findings are
  recorded there as two comments, 2026-08-25.
- `mayor-3g1ft` (closed scout) — original root-cause match to upstream
  `containers/gvisor-tap-vsock` PR #613.
