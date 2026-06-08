# Dashboard
2026-06-08T~10:00 — focus runs in progress; coverage audit complete; 17 beads ready

## Resume
`SONOBUOY_FOCUS='StatefulSet Basic StatefulSet functionality' scripts/conformance/run-all.sh` — in progress

## Operator attention needed
- StatefulSet focused run in progress (bfmlhuqhs) — key test: does Burst/Predictable scaling now advance past 1/N?
- MutatingAdmissionPolicy focused run queued after StatefulSet

## Open PRs
None.

## Focus run status
```
✅ EndpointSliceMirroring — 20/21 (conformance passes; non-conformance hostname gap remains)
🔄 StatefulSet — IN PROGRESS (pod Watch label selector fix #462)
⏳ MutatingAdmissionPolicy — queued (spec preservation fix #463)
```

## Coverage audit (ai/findings/coverage-audit.md)
- Actual coverage: **91.4%** (threshold was 61% — now raised to 90%)
- Top gaps: proto decoders with no tests (mayor-j2xg), CEL tokenizer edge cases (mayor-2712), is_exec_status_frame (mayor-k2zw)

## Recent merges
#461 GC apiservices 404 fix · #462 pod Watch label selector · #463 MAP spec preservation
#458 MutatingAdmissionPolicy CEL · #459 Deployment cascade delete · #460 MAP proto decoders

## Bead queue (17 ready)
**P1:** mayor-zcnd StatefulSet scale-up · mayor-e539 coverage threshold (DONE — threshold raised)
**P2 coverage:** mayor-j2xg proto decoder tests · mayor-2712 CEL tokenizer tests · mayor-k2zw is_exec_status_frame test
**P2 correctness:** mayor-rzve SA JWT jti · mayor-ryds AcceptAnyCert without CA · mayor-2m6s rename client-util · mayor-ht9a split store/lib.rs · mayor-3w0r agnhost hostname · mayor-s3aq show-results.sh · mayor-y2cj annotation typing · mayor-z981 StatefulSet AfterEach · mayor-9k2w ValidatingWebhookConfiguration CEL · mayor-tkwj ControllerRevision template update

## Main at
833ad15 — pod Watch label selector + MAP spec + GC apiservices fix
