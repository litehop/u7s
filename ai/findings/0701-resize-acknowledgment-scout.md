# Resize Acknowledgment Scout: mayor-ma3q

**Bead:** mayor-ma3q  
**Date:** 2026-07-01  
**Stack used:** port 6445, lima-node-2, temp/ma3q-6445/  
**Run analyzed:** `temp/e2e/0701-2230-pod-inplace-resize-container/` (15 Passed / 54 Failed)

---

## Executive Summary

The bead asked: why do the bulk of 54 resize specs time out after 300s?

**They don't all time out.** The 54 failures split into four distinct bugs. The DOMINANT timeout bug (23 of 24 slow failures = ~43% of all failures) is a **proto-decode-drop of Container field 24 (`restartPolicy`)**, which causes sidecar init containers to become blocking traditional init containers. The pod never reaches Running+Ready → 300s timeout. This is the SAME proto-decode-drop family that caused the resizePolicy (field 23) bug in PR #631.

The prior spike conclusion ("PodResizePending/InProgress conditions NOT needed, status.resize='Proposed' suffices") remains correct. The 300s timeouts are NOT about resize-acknowledgment status fields — they are about the pod never starting because the init container restartPolicy is dropped on proto decode.

---

## Failure Taxonomy (54 total)

From the 0701-2230 focused run `e2e.txt` (`temp/e2e/0701-2230-pod-inplace-resize-container/podlogs/.../e2e.txt`):

| Bug | Spec count | Duration | Test line | Root cause |
|-----|-----------|----------|-----------|------------|
| Container.restartPolicy (proto field 24) dropped | ~23 | 302-310s | pod_resize.go:944 | Sidecar init containers become blocking; pod stuck Pending |
| GET /resize returns 405 MethodNotAllowed | 1 | ~304s | pod_resize.go:823 | /resize route has no GET handler; test polls resize state via GET |
| verifyPodContainerResources mismatch | ~22 | 2-8s | pod_resize.go:922 | containerStatuses.resources not immediately updated after PATCH /resize |
| Invalid resize not rejected with 422 | ~8 | 2s | pod_resize.go:389 | BestEffort/invalid resize PATCH returns 200, test expects error |

Total: 54 failed specs across four bugs.

---

## Bug 1: Container.restartPolicy (proto field 24) Dropped — PRIMARY ROOT CAUSE

### What the test does

All "guaranteed qos" resize specs (`doGuaranteedPodResizeTests`, pod_resize.go:121) create pods with a sidecar init container:

```yaml
initContainers:
- name: c1-init
  image: registry.k8s.io/e2e-test-images/busybox:1.37.0-1
  restartPolicy: Always          # SIDECAR (KEP-3939, k8s 1.33+)
  command: [/bin/sh, -c, "grep Cpus_allowed_list /proc/self/status | cut -f2 && sleep 1d"]
  resources:
    limits: {cpu: 20m, memory: 35Mi}
    requests: {cpu: 20m, memory: 35Mi}
```

With `restartPolicy: Always`, the init container is a **sidecar**. In k8s 1.33+ (KEP-3939), sidecars run alongside main containers and do NOT block readiness. The pod becomes Running+Ready while the sidecar continues running. This allows the test to:
1. Create the pod and wait for it to be Ready (sidecar + main container both running)
2. Resize the sidecar init container in-place (`InPlacePodVerticalScalingInitContainers` feature gate)
3. Resize the main container
4. Verify cgroup values updated

### What u7s does

The e2e binary uses the typed Go k8s client which sends pods as **protobuf**. The `Container` struct in `crates/apiserver/src/proto.rs` is missing field 24:

```rust
// crates/apiserver/src/proto.rs, struct Container (lines 852-907)
// Fields present: 1,2,3,4,6,7,8,9,10,11,12,13,14,19,20,22,23
// Field 23 = resizePolicy (added by PR #631)
// Field 24 = restartPolicy  ← MISSING — this is the bug
```

The proto definition confirms (`crates/apiserver/proto/api-core-v1-generated.proto:1584`):
```protobuf
optional string restartPolicy = 24;
```

Without field 24, prost silently drops the value. The stored pod has no `restartPolicy` on the init container. The kubelet receives the pod with a **traditional blocking** init container (not a sidecar). `sleep 1d` runs, never exits, `Initialized: False` stays forever, pod stuck Pending → 300s timeout.

### Live evidence from e2e.txt

Pod `resize-test-77df7` in namespace `pod-resize-tests-4722` (first 300s-timeout spec), from line 757 of the e2e.txt:

```
status.conditions:
  Initialized: False — ContainersNotInitialized: containers with incomplete status: [c1-init]
  Ready: False — ContainersNotReady: containers with unready status: [c1]
phase: Pending
```

The init container is started (containerID present, running since 13:08:47) but never exits. After 300s, `WaitTimeoutForPodReadyInNamespace` fires:

```
[FAILED] Timed out after 300.007s.
expected pod to be running and ready, got instead:
    phase: Pending
    initContainers: [{name: c1-init, ...}]   ← no restartPolicy field in stored spec
    Initialized: False — containers with incomplete status: [c1-init]
```

The stored pod spec (lines 784-830) shows NO `restartPolicy` field on `c1-init` — the proto decode dropped it.

### Kubectl-only repro

**JSON creation — works (bypasses proto decode):**
```sh
kubectl create --validate=false --kubeconfig temp/ma3q-6445/kubeconfig -f - <<'EOF'
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"sidecar-test","namespace":"default"},
 "spec":{"nodeName":"lima-node-2","restartPolicy":"OnFailure",
  "initContainers":[{"name":"c1-init","image":"registry.k8s.io/pause:3.10",
    "restartPolicy":"Always","resources":{"requests":{"cpu":"20m","memory":"35Mi"},
    "limits":{"cpu":"20m","memory":"35Mi"}}}],
  "containers":[{"name":"c1","image":"registry.k8s.io/pause:3.10",
    "resources":{"requests":{"cpu":"20m","memory":"35Mi"},"limits":{"cpu":"20m","memory":"35Mi"}}}]}}
EOF
sleep 5
kubectl --kubeconfig temp/ma3q-6445/kubeconfig get pod sidecar-test -o json | \
  jq '{phase:.status.phase, restartPolicy:.spec.initContainers[0].restartPolicy, ready:(.status.conditions[]|select(.type=="Ready")).status}'
```
Expected result:
```json
{
  "phase": "Running",
  "restartPolicy": "Always",
  "ready": "True"
}
```
Verified live on port 6445 stack: pod Running+Ready, `restartPolicy = "Always"` stored correctly.

**Proto creation (the e2e binary does this) — drops field 24:**
The e2e binary sends the identical pod via protobuf. Field 24 is dropped by u7s's prost struct. The stored pod has no `restartPolicy` on `c1-init`. Pod stays Pending.

To see the drop: examine any 300s-timeout spec's failure dump in `e2e.txt` — the pod spec printed shows `initContainers[0]` without `restartPolicy`.

### Fix target

**File:** `crates/apiserver/src/proto.rs`  
**Struct:** `Container` (line ~903, after `resize_policy`)  
**Add field:**
```rust
/// restartPolicy (field 24, optional string) — "Always" for sidecar init containers (KEP-3939,
/// k8s 1.33+). Without this field, init containers with restartPolicy=Always are stored as
/// blocking init containers; the pod never reaches Running, causing 300s timeouts in
/// guaranteed-qos resize conformance tests. Same proto-decode-drop family as field 23 (PR #631).
#[prost(string, optional, tag = "24")]
restart_policy: Option<String>,
```

**Function:** `container_to_json` (line ~5024, after `resize_policy` emit block)  
**Add emit:**
```rust
if let Some(rp) = c.restart_policy {
    if !rp.is_empty() {
        obj.insert("restartPolicy".to_string(), serde_json::Value::String(rp));
    }
}
```

**Regression test (must fail if field 24 removed):**
```rust
/// decode_pod_proto must preserve initContainer.restartPolicy (proto field 24) through decode.
/// restartPolicy="Always" makes an init container a sidecar (KEP-3939, k8s 1.33+). Without
/// field 24 in the Container prost struct, sidecar init containers become blocking traditional
/// init containers, causing pods to stay Pending indefinitely (300s timeout in resize conformance).
fn decode_pod_proto_preserves_init_container_restart_policy() {
    // ...encode a pod with initContainers[0].restartPolicy = "Always" (field 24)
    // ...decode and assert restartPolicy == "Always" in the JSON
}
```

**Size: S** (10 lines + 1 test, same pattern as PR #631 resizePolicy fix).

---

## Bug 2: GET /resize Returns 405 MethodNotAllowed (1 conformance spec)

**Spec:** "resize pod via the replace endpoint [Conformance]" (pod_resize.go:823)  
**Error:** "failed to fetch pod after resize: the server does not allow this method on the requested resource"  
**Duration:** ~304s (300s timeout + 4s test setup)

After doing a resize via PUT /pods/{name} (the replace endpoint), the test polls resize completion via `GET /pods/{name}/resize`. u7s's resize route:
```
PATCH /api/v1/namespaces/{ns}/pods/{name}/resize → patch_pod_resize
PUT   /api/v1/namespaces/{ns}/pods/{name}/resize → patch_pod_resize
```
No GET handler → 405 on every poll → 300s timeout.

Verified live: `kubectl get pod resize-probe -o json --subresource=resize` returns 405.

**Fix target:** Add GET handler for `/pods/{name}/resize` in `crates/apiserver/src/main.rs`. Handler returns the current pod (same as `get_pod`). **Size: S** (route + handler, or simply reuse `get_pod`).

---

## Bug 3: verifyPodContainerResources Mismatch (~22 specs, fast-fail 2-8s)

**Error:** "Expected object to be comparable, diff: v1.ResourceRequirements{ Requests: nil } vs Requests: {cpu:20m, memory:35Mi}"  
**Test line:** pod_resize.go:922  
**Duration:** 2-8s (fast fail, NOT 300s timeout)

Example diff from spec "burstable pods - 1 container - mem restart resizing - cpu limits":
```
Expected:
  Limits: {cpu: 35m}
  Requests: nil
Got:
  Limits: {cpu: 35m, memory: 45Mi}
  Requests: {cpu: 20m, memory: 35Mi}
```

The test sends PATCH /resize with only a cpu limit change, then immediately checks `containerStatuses[i].resources` in the response. The response body has OLD containerStatuses (kubelet hasn't written back yet; 2s elapsed). The old containerStatuses have the full original resources from pod creation.

The test expects the PATCH /resize response to immediately show `containerStatuses.resources` reflecting only the newly-patched values. This would require u7s to synthesize the containerStatuses.resources in the /resize handler before the kubelet writes back.

This is NOT a 300s timeout — it's a fast-fail 2-8s failure.

**Fix target (needs investigation):** In `apply_resize_patch` (pods.rs:1737), after updating `spec.containers[i].resources`, also update `status.containerStatuses[i].resources` to match. Verify with the test source what `verifyPodContainerResources` checks at line 922. **Size: M.**

---

## Bug 4: Invalid Resize Not Rejected with 422 (~8 specs, fast-fail 2s)

**Error:** "Expected an error to have occurred. Got: (no error)"  
**Test line:** pod_resize.go:389  
**Duration:** 2s (fast fail)

Tests send invalid resize patches and expect HTTP 422:
- Adding memory requests to a BestEffort pod (would change QoS class)
- Setting limits below requests
- Adding a new resource type not originally in the spec

u7s's `patch_pod_resize` accepts all resize requests without validation → 200 instead of 422.

**Fix target:** Add validation in `patch_pod_resize` (pods.rs:1761): check QoS class stability, limits >= requests, no new resource types. **Size: M.**

---

## Status.resize Is NOT the Issue

The prior spike's finding ("status.resize='Proposed' suffices, no need for PodResizePending/PodResizeInProgress conditions") is confirmed by live test on port 6445.

After PUT /resize on a Running pause pod:
```json
{
  "status.resize": null,
  "containerStatuses[0].allocatedResources": {"cpu":"200m","memory":"256Mi"},
  "containerStatuses[0].resources": {"limits":{"cpu":"400m","memory":"512Mi"},"requests":{"cpu":"200m","memory":"256Mi"}}
}
```

The kubelet applied the cgroup resize within 3-5 seconds and wrote back `allocatedResources` and `resources`. `status.resize` is null (kubelet cleared it). The resize lifecycle works correctly for pods that reach Running state.

**The 300s timeouts are not about resize acknowledgment — they are about pods never starting** because init container `restartPolicy: Always` is dropped on proto decode.

---

## Recommended Bead Breakdown

| Bead title | Size | Fixes | Impact |
|-----------|------|-------|--------|
| fix(proto): Container.restartPolicy (field 24) dropped on proto decode | S | Bug 1 | ~23 of 54 failures flip |
| fix(apiserver): GET /pods/{name}/resize returns 405 | S | Bug 2 | 1 conformance spec |
| fix(apiserver): synthesize containerStatuses.resources on /resize response | M | Bug 3 | ~22 fast failures |
| fix(apiserver): reject invalid resize patches with 422 | M | Bug 4 | ~8 fast failures |

**Start with the S fixes** — Container.restartPolicy proto field 24 is the highest-leverage (same effort as PR #631, highest spec count impact).

---

## Appendix: Code Locations

| Bug | File | Lines |
|-----|------|-------|
| Container.restartPolicy missing (add here) | crates/apiserver/src/proto.rs | ~903 (after resize_policy field) |
| container_to_json (emit restartPolicy here) | crates/apiserver/src/proto.rs | ~5024-5046 |
| Container proto field 24 definition | crates/apiserver/proto/api-core-v1-generated.proto | 1584 |
| GET /resize route missing | crates/apiserver/src/main.rs | route registration near PATCH/PUT /resize |
| apply_resize_patch (needs containerStatuses update) | crates/apiserver/src/handlers/pods.rs | 1737-1759 |
| patch_pod_resize (needs 422 validation) | crates/apiserver/src/handlers/pods.rs | 1761-1800 |
