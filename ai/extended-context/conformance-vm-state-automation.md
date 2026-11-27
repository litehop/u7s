---
as_of: 2026-11-28
kind: project-state
---

# Conformance VM state automation

A deterministic script owns conformance VM lifecycle; no one changes VM state
by hand (operator stance). Landed in #2296, #2307, #2310, #2303.

## State markers

| State | Marker | Legacy marker |
|---|---|---|
| install | `/etc/u7s-install-started`: written first by `install.sh`, removed last by `install-teardown.sh` | `u7s-apiserver.service` |
| host rig | `/etc/systemd/system/kubelet.service.d/u7s.conf` | `kube-proxy.service` |

## What `run-all.sh` does

- A host-rig run tears down an install-state VM.
- `--install` unrigs a rig-state VM and reaps the rig's host processes on every
  run.
- Both markers present: abort, pointing at `run-all.sh --reset`.
- A stale extra node with a CA mismatch is torn down and rejoined.
- A probe error (for example an ssh failure) always fails loud and never tears
  down.

All of this lives in the harness (`install-bringup.sh`, `run-all.sh`,
`_lib.sh`). `scripts/install.sh` never auto-tears-down.

## Wait loops

`while`/`until` waits on `pgrep -f "<pat>"` match their own command line and
never exit; wait on the PID. Hygiene STEP I reaps an orphaned loop only if it
is a shell `-c` loop older than 10 minutes, owned by this user, with no
limactl/ssh/exec wrapper, and whose target is not running.

## Other conventions

- `sonobuoy` is not on the host PATH. The evidence is run-all's verified
  `Namespace "sonobuoy" has been deleted` line (per #2312).
- `--focus` regexes must use `.*` before trailing `[Serial]`/`[Conformance]`
  tags, or they match 0 specs.
