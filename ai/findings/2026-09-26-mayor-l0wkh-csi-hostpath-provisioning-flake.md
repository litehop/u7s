Bead: mayor-l0wkh

## Answer

Not an apiserver code regression. Both failing specs are flaky by different,
independent mechanisms, neither of which traces to any commit touching
`crates/apiserver` or `crates/scheduler` in the 92-commit window since the
2026-09-10 baseline (`git log --since=2026-09-10 -- crates/apiserver` and
`-- crates/scheduler/src/lib.rs` both show zero hits on the relevant decode/
concurrency/topology-fit code paths). No PR opened — forcing a code change
without an identified defect would misrepresent the finding.

## Evidence

**Symptom #1 — "pvc data source in parallel [Slow]" HTTP 400 "invalid JSON:
expected value at line 1 column 1"**

- Original run (`temp/e2e/0926-1153-csi-hostpath/`): apiserver.log shows
  exactly one `method=POST...status=400` in the entire 55-minute run, landing
  inside a burst of 5 concurrent, byte-identical PVC-with-DataSourceRef
  creates (4 siblings got 201 within 2ms). Matches u7s's known "extract_body
  fell through to empty/undecodable bytes" class (`crates/apiserver/src/
  util.rs`), i.e. the apiserver received an empty body for that one request.
- `proto.rs` / `util.rs` / `content_type.rs` / `inflight.rs` (decode +
  concurrency-limiting layers) are unchanged since 2026-09-10.
- In-process repro against the real `serve_tls()` dispatcher: 20 concurrent
  HTTP/2-multiplexed POSTs with distinct bodies over one h2 connection, run
  30x — 0 failures, 0 body mixups. Rules out a body-cross-talk bug in u7s's
  own hyper/h2 plumbing at this concurrency. (Test was written, run, and then
  reverted — it found nothing to fix, so per Rule 3/14 it does not belong in
  the tree.)
- Live re-run today (`--focus 'csi-hostpath.*provisioning.*data source'`,
  fresh `--reset` on lima-node-5 + lima-node-smoke, same main@d9cb6a55): this
  spec PASSED cleanly. `grep -c 'method=POST.*status=400' apiserver.log` = 0
  for the whole run. Confirms symptom #1 is a rare flake, not deterministic.
- Coordinator lead: sibling bead mayor-a7uf6 root-caused ITS failure
  (CRConversionWebhook) to the rig's kube-proxy IPVS->iptables switch
  (2b5bbf04, 2026-09-15): iptables reprograms NAT rules ~1/s, so a **freshly
  created** Service's ClusterIP can refuse connections for up to ~1s, which
  exhausted the apiserver's outbound webhook-connect retry budget (fixed in
  PR #1688, `crates/apiserver/src/admission.rs` — not touched here). Checked
  whether this applies to my symptom: it does not. The failing POST in
  symptom #1 targets `https://10.96.0.1:443/api/v1/namespaces/.../
  persistentvolumeclaims` — the cluster-bootstrap `kubernetes` Service, which
  has existed (and been DNAT-programmed) for the ~7 minutes the run was
  already underway before this burst fires. Neither failing spec's request
  path in question goes through a webhook call or a Service created moments
  earlier. The PR #1688 mechanism does not explain symptom #1.

**Symptom #2 — "any volume data source [Serial]" (found on live re-run,
different from the original evidence)**

- On today's live re-run, THIS spec failed instead — with a completely
  different signature: `Failed to create client pod: Timed out after
  900.009s` (`fixtures.go:592`). Root events: the hello-populator's
  auto-created `populate-*` pod was scheduled onto `lima-node-smoke`, while
  the CSI hostpath driver (single-replica StatefulSet, so single-node) runs
  on `lima-node-5`; the dynamically-provisioned PV's CSI topology
  (`topology.hostpath.csi/node=lima-node-5`) then makes kubelet refuse the
  mount on `lima-node-smoke`: `MountVolume.NodeAffinity check failed ... no
  matching NodeSelectorTerms`. The pod never becomes Ready and the test times
  out at 900s.
- This is a genuine scheduler topology-fit gap for the AnyVolumeDataSource
  populator flow specifically (the PVC is unbound at scheduling time, so
  `csi_topology_fit`'s "does this node register the required CSI driver"
  check — not the separate bound-PV `pv_node_affinities` check, which has its
  own dedicated tests — is the one that should have steered the pod onto
  `lima-node-5`, and evidently didn't for this pod shape).
- `crates/scheduler/src/lib.rs` has **zero** commits since 2026-09-10
  (`git log --since=2026-09-10` on that file: 0 hits). This bug, if real, is
  pre-existing and latent, not part of this regression window. Filed
  separately as mayor-<TBD-by-mayor> rather than fixed here — investigating
  and fixing a scheduler topology-fit gap is out of scope for a bead about an
  apiserver-side JSON-decode 400, and conflating the two would misattribute
  root cause.

**On the 27% slowdown (2592s -> 3291s)**

- Confirmed real environment diff in the window: baseline (`0910-2329`) used
  `kube-proxy-lima-node-3.log` / `-4.log` showing `"Using ipvs Proxier"` and no
  `kube-flannel` namespace; today's run shows `"Using iptables Proxier"`
  (`kube-proxy-lima-node-5.log`) and a live `kube-flannel` namespace/DaemonSet
  — both from mayor-0v60z (233274e1) and mayor-8g7f6 (2b5bbf04). flannel's
  MTU auto-detection is correct on lima-node-5 (`eth0` 1500 / `flannel.1` +
  `cni0` + veths all 1450 — the textbook 50-byte VXLAN-overhead subtraction),
  ruling out an MTU misconfiguration as a contributor.
- iptables' linear rule-chain DNAT lookup vs IPVS's hash-table lookup, plus
  VXLAN encap/decap CPU cost, are plausible partial contributors to the
  slowdown, but this has **not** been isolated from other confounds in the
  same window (freshly rebaked golden image, ~90 other commits including new
  admission-webhook invocation on more write paths, typed-status GVK dispatch
  convergence, etc., each adding some per-request cost). Treat as unconfirmed
  — do not cite this as a settled explanation.

## Regressing commit(s)

No commit was found that mechanistically explains symptom #1. The two
infra commits that changed the network substrate in the regression window
and are the best available correlated candidates are:
- `233274e1` — feat(conformance): flannel multi-node rig, replace cri-o stock
  bridge CNI (mayor-0v60z)
- `2b5bbf04` — test(conformance): switch rig kube-proxy to iptables to match
  shipped + enable beep (mayor-8g7f6)

Unlike mayor-a7uf6's CRConversionWebhook failure, no causal mechanism from
either commit to symptom #1's empty-body 400 could be established — the
request in question doesn't touch a freshly-created Service or an outbound
webhook call. This should be read as "best correlated candidate, mechanism
unconfirmed," not as a proven root cause.

## What I did NOT do

Did not run the full ~55min `--focus csi-hostpath` gate. Two direct,
independent-mechanism failures already confirm flakiness without it: symptom
#1 (from the original evidence) did not reproduce on a fresh live run;
symptom #2 (found on that same fresh live run) is a different, pre-existing
bug outside this bead's code-owned surface. A third run buys little more
signal at ~55min cost given the goal (assess whether an apiserver code fix
exists) is already answered.
