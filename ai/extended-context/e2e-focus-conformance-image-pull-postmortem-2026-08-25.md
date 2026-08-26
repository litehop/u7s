---
as_of: 2026-08-25
kind: postmortem
---

# Postmortem: `e2e-focus.yaml` CI timeouts from conformance-image CDN cache misses

**Status:** Root-caused, not fixed. No code/workflow change has landed; the real
exposure (zero image caching in the workflow) remains open.
**Duration:** Investigated 2026-08-25, single session.
**Severity:** CI-only. Caused four consecutive matrix-cell failures (1.34/1.35) via
opaque 5-minute step timeouts; recovered on its own (mechanism unconfirmed) after a
manual cache warm-fill.
**Root cause:** CDN edge-cache residency at `cdn.registry.k8s.io`, not a code
regression, version-pin bump, or CRI-O change.

## Symptom

`.github/workflows/e2e-focus.yaml`'s "Run sonobuoy" step fails with `The action
... has timed out after 5 minutes`. The tests never started: the
`sonobuoy-e2e-job` pod sits in `ImagePullBackOff` pulling
`registry.k8s.io/conformance:v<matrix.k8s>`, and `sonobuoy --wait` blocks on a
plugin pod that never runs until the step's `timeout-minutes: 5` fires. A healthy
job takes ~100-180s; a hung one runs ~370-390s before the timeout kills it.

The underlying error, visible only in the "Diagnose sonobuoy on failure" step
(`kubectl describe pods -n sonobuoy`), not in `--log-failed`:
`copying system image from manifest list: parsing image configuration: fetching
blob: StatusCode: 400, "<?xml ...<Error><Cod...`. That is the tiny CONFIG blob (a
few KB), not a large layer, so it is not a transfer-size or resume problem.
`containers/image` truncates the XML body, so the upstream error code itself is not
recoverable from logs.

## What it is not (all four ruled out with evidence)

1. **Not the k8s version pin.** PR #1364 bumped 1.34.9→1.34.11 / 1.35.6→1.35.8 /
   1.36.2→1.36.4; both its own PR run (32741695434) and merge run (32742803102)
   passed green on the new pins.
2. **Not PRs #1365/#1366.** `.github/workflows/e2e-focus.yaml` and
   `scripts/conformance/` are byte-identical since #1364 merged, and
   `e2e-focus.yaml` never invokes `scripts/install.sh`.
3. **Not a CRI-O regression.** CRI-O installs unpinned from the per-minor OpenSUSE
   channel, but the 1.34 branch failed on cri-o 1.34.10 — the exact build that had
   passed 16h earlier.
4. **Not corrupt images.** All 9 blobs (config + 8 layers) of v1.34.11, v1.35.8, and
   v1.36.4 verify sha256-clean against `registry.k8s.io`.

## Root cause (strongly evidenced; recovery mechanism unproven)

Measuring the `age` response header per blob showed all 9 v1.36.4 blobs resident
in the CDN edge cache (~6922s), while every v1.34.11/v1.35.8 blob was absent
entirely. The 24.5 MiB base layer shared by all three images had the oldest age
(~7259s) and never failed. v1.36.4 stays warm because it is the tag hardcoded in
`scripts/conformance/sonobuoy-plugin-e2e.yaml` and
`scripts/build-release-tarball.sh` and is the newest tag ecosystem-wide; the older
patch tags are unpopular and age out of cache. A failed pull never warms the cache,
so the failure is self-perpetuating and deterministic (1.34/1.35 failed 5/5 from
07:15-09:32 UTC), not flaky.

**Caveat:** a full manual fetch of every v1.34.11/v1.35.8 blob at 10:31-10:37 UTC
was followed by a green re-run at 10:39:38, but this cannot distinguish "the
warm-fill unblocked it via a shared cache tier" from "upstream recovered on its
own" — the age readings came from a laptop edge PoP, not the runner's. Cold full
downloads of untouched tags (v1.31.6, v1.30.8, age=0) completed clean at ~3.3 MB/s
locally, so the 400 does not reproduce off-runner. Prediction: recurs when those
blobs age out again.

## The real exposure

`e2e-focus.yaml` has zero container-image caching. Its four `actions/cache` uses
are release binaries, kubelet+kubectl, the cri-o apt package, and the sonobuoy
CLI — all host binaries and apt packages (grep for `docker save/load`, `skopeo`,
`crictl`, `containers/storage` in the workflow returns nothing). Every job pulls
~90 MiB of conformance image fresh from `registry.k8s.io` on every run, fully
exposed to this class of upstream CDN flake.

**Proposed fix (not implemented):** cache the conformance image per
`matrix.k8s` (`skopeo copy` to `docker-archive` + `actions/cache`, restored before
the sonobuoy run). Secondary: since the failure presents as an opaque 5-minute
timeout, poll for `ImagePullBackOff` and fail fast with the pull error instead of
waiting out the full timeout.

## How to re-derive

Failing runs: 32820737482, 32822023900, 32823039980, 32831485931. Green baseline:
32741695434, 32742803102. Job-level detail via `gh run view <id> --json jobs`.
Untruncated CRI errors are in the `e2e-focus-logs-<matrix.k8s>` artifact at
`home/runner/work/u7s/u7s/temp/u7s/kubelet.log`. CDN residency check:
`curl -s -o /dev/null -D- -r 0-63
https://cdn.registry.k8s.io/containers/images/<layer-digest> | grep -i '^age:'`.

## Cross-references

- bd memory: `e2e-focus-timeout-is-usually-conformance-image-pull-not-slow-tests`
  (short pointer to this doc).
