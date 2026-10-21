#!/usr/bin/env bash
# Unit test for scripts/worktree-hygiene.sh's pure functions.
#
# Exercises the REAL script as a subprocess via its `__call <fn> [args...]`
# entry point (same "real script, not a reimplementation" technique the
# sibling scripts/test-*-logic.sh suites use) -- a reimplementation of the
# process-line parsing, branch-guard logic, or patch-id check would keep
# passing even if the real logic regressed.
#
# Covers the four areas the extraction from mayor-bootstrap.md is load-bearing
# for:
#   1. STEP A orphan detection (find_orphans / proc_type_from_psline /
#      extract_worktree_path_from_psline / kill_pattern_for) against
#      synthetic `ps aux` output -- a regression here either leaves a real
#      orphan process squatting on a VM slot's ports (never detected) or
#      kills a live worker's process (false positive on a live worktree).
#   2. STEP C's in-flight guard (checked_out_branches / is_checked_out) --
#      the mechanism that keeps a worker mid-dispatch from having its
#      branch force-deleted out from under it.
#   3. STEP C's patch-id merge check (is_unmerged_by_patch_id) -- the only
#      thing that distinguishes "safe to delete" from "would silently
#      destroy unmerged work," including the squash-merge case
#      `git branch --merged` would misjudge.
#   4. STEP D's gone-upstream match (gone_upstream_branches) -- must only
#      match branches whose upstream is actually `[gone]`, not ones with no
#      upstream configured at all (e.g. `investigation/*`).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/worktree-hygiene.sh"

PASS=0
FAIL=0

assert() {
  local label="$1" ok="$2"
  if [ "$ok" = "1" ]; then
    echo "PASS: $label"
    PASS=$(( PASS + 1 ))
  else
    echo "FAIL: $label"
    FAIL=$(( FAIL + 1 ))
  fi
}

call() {  # runs the real script's __call entry point, capturing stdout
  bash "$SCRIPT" __call "$@"
}

new_sandbox() {
  local dir="$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "Test"
}

SANDBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$SANDBOX_ROOT"' EXIT

# ---------------------------------------------------------------------------
# 1. STEP A -- orphaned host process detection.
# ---------------------------------------------------------------------------

# Fixture argument styles match the real launchers in scripts/u7s-start.sh:
# apiserver/scheduler take `--kubeconfig <path>` space-separated; the
# konnectivity-server case below deliberately uses an `=`-joined flag
# (`--server-cert=<path>`, that binary's real style) to prove extraction
# doesn't leak the `--server-cert=` prefix into the matched worktree path.
# The sample-run-metrics.sh line matches its real launch shape (run-all.sh's
# `bash sample-run-metrics.sh start --workdir <path>/temp/u7s ...`, backgrounded
# via `sampler_loop &` so the surviving process keeps this exact argv) -- an
# orphan of this type is invisible resource use (RSS/vm-free polling against a
# VM slot that then looks free to the next dispatch), not a port bind, so it
# must be caught by the same pattern the other three types are.
PS_OUTPUT='alice  1111   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /Users/alice/worktrees/dead-worktree/temp/u7s/kubeconfig --port 6443
alice  1112   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-scheduler --kubeconfig /Users/alice/worktrees/live-worktree/temp/u7s/kubeconfig
alice  1113   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 konnectivity-server --logtostderr=true --server-cert=/Users/alice/worktrees/dead-worktree-2/temp/u7s/konnectivity-server.crt
alice  1114   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 bash scripts/conformance/sample-run-metrics.sh start --workdir /Users/alice/worktrees/dead-worktree-3/temp/u7s --port 6443 --vm lima-node-2'
LIVE_WORKTREES='/Users/alice/worktrees/live-worktree
/Users/alice/orchestrator-checkout'

ORPHANS=$(call find_orphans "$PS_OUTPUT" "$LIVE_WORKTREES")

assert "an apiserver process whose worktree is gone is flagged as an orphan" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1111|apiserver|/Users/alice/worktrees/dead-worktree' && echo 1 || echo 0)"
assert "a konnectivity-server process whose worktree is gone is flagged as an orphan (its --flag=path style must not leak the '--server-cert=' prefix into the matched path)" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1113|konnectivity-server|/Users/alice/worktrees/dead-worktree-2' && echo 1 || echo 0)"
assert "a sample-run-metrics.sh process whose worktree is gone is flagged as an orphan (regression: this type was dropped from STEP A's grep, letting it squat undetected)" \
  "$(printf '%s\n' "$ORPHANS" | grep -qF '1114|sample-run-metrics|/Users/alice/worktrees/dead-worktree-3' && echo 1 || echo 0)"
assert "a scheduler process whose worktree is still live is NOT flagged (must not kill a live worker's process)" \
  "$(! printf '%s\n' "$ORPHANS" | grep -q '^1112|' && echo 1 || echo 0)"
assert "exactly three orphans are found, not more (no false positives from the live-worktree line)" \
  "$([ "$(printf '%s\n' "$ORPHANS" | grep -c '|')" = "3" ] && echo 1 || echo 0)"

assert "an empty ps scan (no matching processes at all) yields no orphans" \
  "$([ -z "$(call find_orphans '' "$LIVE_WORKTREES")" ] && echo 1 || echo 0)"

assert "kill_pattern_for builds the apiserver pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for apiserver /dead)" = 'u7s-apiserver.*[ =]/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the scheduler pattern anchored on the dead worktree's kubeconfig path" \
  "$([ "$(call kill_pattern_for scheduler /dead)" = 'u7s-scheduler.*[ =]/dead/temp/u7s/kubeconfig' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the konnectivity-server pattern anchored on the dead worktree's workdir (no /kubeconfig suffix)" \
  "$([ "$(call kill_pattern_for konnectivity-server /dead)" = 'konnectivity-server.*[ =]/dead/temp/u7s([/ ]|$)' ] && echo 1 || echo 0)"
assert "kill_pattern_for builds the sample-run-metrics.sh pattern anchored on the dead worktree's workdir (no /kubeconfig suffix -- it has no cert to serve, just polls the VM)" \
  "$([ "$(call kill_pattern_for sample-run-metrics /dead)" = 'sample-run-metrics.sh.*[ =]/dead/temp/u7s([/ ]|$)' ] && echo 1 || echo 0)"

assert "proc_type_from_psline classifies a sample-run-metrics.sh line as its own type (must not be silently ignored as an unmatched process)" \
  "$([ "$(call proc_type_from_psline 'bash scripts/conformance/sample-run-metrics.sh start --workdir /x/temp/u7s')" = 'sample-run-metrics' ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1b. STEP A -- --live-agents protection. A worker whose worktree DIRECTORY
#     is already gone (the routine orphan case above) but whose agent-id
#     the mayor's ListAgents call still reports as running must never have
#     its host process killed -- path-existence alone is exactly the signal
#     that misclassified a genuinely live worker before this fix.
# ---------------------------------------------------------------------------

assert "agent_id_from_worktree_path extracts the trailing agent-<id> path component" \
  "$([ "$(call agent_id_from_worktree_path '/repo/ai/worktrees/agent-liveid123')" = "liveid123" ] && echo 1 || echo 0)"
assert "agent_id_from_worktree_path returns empty for a path with no ai/worktrees/agent-<id> suffix (e.g. the mayor's own checkout) -- never a candidate for the live-agents guard" \
  "$([ -z "$(call agent_id_from_worktree_path '/repo')" ] && echo 1 || echo 0)"

PS_OUTPUT_LIVE_AGENT='alice  2222   0.0  0.1  123456  1234 s001  S+   10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /repo/ai/worktrees/agent-liveid123/temp/u7s/kubeconfig --port 6444'
RAW_ORPHAN_LIVE_AGENT=$(call find_orphans "$PS_OUTPUT_LIVE_AGENT" '')
assert "sanity: without the live-agents filter, this process is classified an orphan by path alone (its worktree isn't in the live-worktree-path list)" \
  "$(printf '%s\n' "$RAW_ORPHAN_LIVE_AGENT" | grep -qF '2222|apiserver|/repo/ai/worktrees/agent-liveid123' && echo 1 || echo 0)"

FILTERED_PROTECTED=$(call filter_orphans_by_live_agents "$RAW_ORPHAN_LIVE_AGENT" "liveid123")
assert "an orphan process whose embedded worktree belongs to an agent-id IN --live-agents is filtered out -- its host process must never be killed just because path-existence alone looks orphaned (the original bug: a ListAgents-confirmed-live worker's worktree/branch was reaped anyway)" \
  "$([ -z "$FILTERED_PROTECTED" ] && echo 1 || echo 0)"

FILTERED_STALE=$(call filter_orphans_by_live_agents "$RAW_ORPHAN_LIVE_AGENT" "some-other-agent")
assert "the SAME orphan record, with a --live-agents set that does NOT include its agent-id, survives filtering and remains a genuine kill target" \
  "$(printf '%s\n' "$FILTERED_STALE" | grep -qF '2222|apiserver|/repo/ai/worktrees/agent-liveid123' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 1c. STEP A -- apiserver-less konnectivity-server in a LIVE worktree (e.g.
#     the mayor checkout): the leftover that squats a worker slot's
#     konnectivity ports while find_orphans can't see it.
# ---------------------------------------------------------------------------

KONN_LINE='alice  3001   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=/repo/temp/u7s/konnectivity-server.crt --server-port=8235'
API_LINE='alice  3002   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /repo/temp/u7s/kubeconfig --port 6444'
LIVE_WITH_MAYOR='/repo
/repo/ai/worktrees/agent-liveid123'

SQUATTER=$(call find_apiserverless_konnectivity "$KONN_LINE" "$LIVE_WITH_MAYOR")
assert "a konnectivity-server in a live (mayor) checkout with no apiserver of that workdir is flagged -- it is the slot squatter no other reaper sees" \
  "$([ "$SQUATTER" = '3001|konnectivity-server|/repo' ] && echo 1 || echo 0)"

assert "the same konnectivity-server is NOT flagged while its workdir's apiserver is running -- an operator's healthy stack must never be reaped" \
  "$([ -z "$(call find_apiserverless_konnectivity "$KONN_LINE
$API_LINE" "$LIVE_WITH_MAYOR")" ] && echo 1 || echo 0)"

OTHER_API_LINE='alice  3003   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 target/release/u7s-apiserver --kubeconfig /repo/ai/worktrees/agent-liveid123/temp/u7s/kubeconfig --port 6445'
assert "another workdir's apiserver does not vouch for this workdir's konnectivity-server (staleness is per workdir, not global)" \
  "$([ "$(call find_apiserverless_konnectivity "$KONN_LINE
$OTHER_API_LINE" "$LIVE_WITH_MAYOR")" = '3001|konnectivity-server|/repo' ] && echo 1 || echo 0)"

assert "a konnectivity-server whose worktree is gone is left to find_orphans, not double-reported here" \
  "$([ -z "$(call find_apiserverless_konnectivity "$KONN_LINE" '/elsewhere')" ] && echo 1 || echo 0)"

LIVE_AGENT_KONN='alice  3004   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=/repo/ai/worktrees/agent-liveid123/temp/u7s/konnectivity-server.crt --server-port=8335'
LIVE_AGENT_REC=$(call find_apiserverless_konnectivity "$LIVE_AGENT_KONN" "$LIVE_WITH_MAYOR")
assert "sanity: a live worker's apiserver-less konnectivity-server is a candidate before the live-agents filter" \
  "$([ "$LIVE_AGENT_REC" = '3004|konnectivity-server|/repo/ai/worktrees/agent-liveid123' ] && echo 1 || echo 0)"
assert "...and the live-agents filter drops it, so a live worker mid-restart is never reaped" \
  "$([ -z "$(call filter_orphans_by_live_agents "$LIVE_AGENT_REC" liveid123)" ] && echo 1 || echo 0)"

KONN_SLOT0='alice  3005   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=/repo/temp/u7s/konnectivity-server.crt --server-port=8135'
KONN_NOPORT='alice  3006   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=/repo/temp/u7s/konnectivity-server.crt'
KONN_SLOT2='alice  3007   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=/repo/temp/u7s/konnectivity-server.crt --server-port=8335'
assert "an apiserver-less mayor checkout konnectivity-server on slot 0 (8135) is NOT flagged -- that is the operator's own stack" \
  "$([ -z "$(call find_apiserverless_konnectivity "$KONN_SLOT0" "$LIVE_WITH_MAYOR")" ] && echo 1 || echo 0)"
assert "a mayor checkout konnectivity-server with no --server-port is NOT flagged -- no proof it squats a worker slot" \
  "$([ -z "$(call find_apiserverless_konnectivity "$KONN_NOPORT" "$LIVE_WITH_MAYOR")" ] && echo 1 || echo 0)"
assert "a mayor checkout konnectivity-server on worker slot 2 (8335) IS flagged" \
  "$([ "$(call find_apiserverless_konnectivity "$KONN_SLOT2" "$LIVE_WITH_MAYOR")" = '3007|konnectivity-server|/repo' ] && echo 1 || echo 0)"

TAIL_LINE='alice  3008   0.0  0.0  123456  1234 s001  S    10:00AM   0:00.01 tail -f /repo/temp/u7s/konnectivity-server.log'
REAL_KONN='alice  3009   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 /Users/alice/.cache/u7s/konnectivity/v0.35.0/proxy-server-darwin-arm64 --server-cert=/repo/ai/worktrees/agent-x/temp/u7s/konnectivity-server.crt --server-port=8335'
assert "a 'tail -f .../konnectivity-server.log' line is not typed as a konnectivity-server -- it must never be a kill candidate" \
  "$([ -z "$(call proc_type_from_psline "$TAIL_LINE")" ] && echo 1 || echo 0)"
assert "the real cached binary (proxy-server-<os>-<arch>) IS typed as a konnectivity-server, whose name appears only in its flags" \
  "$([ "$(call proc_type_from_psline "$REAL_KONN")" = 'konnectivity-server' ] && echo 1 || echo 0)"

# 1d. STEP A -- mayor checkout apiserver/scheduler squatting a worker-slot port.
SQ_DIR="$SANDBOX_ROOT/sq"
mkdir -p "$SQ_DIR/temp/u7s"
printf 'clusters:\n- cluster:\n    server: https://127.0.0.1:6445\n' > "$SQ_DIR/temp/u7s/kubeconfig-scheduler"
printf 'clusters:\n- cluster:\n    server: https://127.0.0.1:6443\n' > "$SQ_DIR/temp/u7s/kubeconfig-slot0"
SQ_LIVE="$SQ_DIR"
mk_api() {  # pid listen-port wpath
  echo "alice  $1   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 /repo/target/release/u7s-apiserver --db $3/temp/u7s/state.db --listen 127.0.0.1:$2 --kubeconfig $3/temp/u7s/kubeconfig"
}
mk_sched() {  # pid kubeconfig-file wpath
  echo "alice  $1   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 /repo/target/release/u7s-scheduler --kubeconfig $3/temp/u7s/$2"
}
squat() { call find_mayor_worker_slot_squatters "$1" "$SQ_LIVE"; }

assert "a mayor checkout apiserver on slot 0 (6443) is NOT flagged -- that is the operator's own stack" \
  "$([ -z "$(squat "$(mk_api 4001 6443 "$SQ_DIR")")" ] && echo 1 || echo 0)"
assert "a mayor checkout apiserver on worker slot 2 (6445) with no live worker on it IS flagged -- the mayor never owns a worker slot" \
  "$([ "$(squat "$(mk_api 4002 6445 "$SQ_DIR")")" = "4002|slot-squatter-apiserver|$SQ_DIR" ] && echo 1 || echo 0)"
AGENT_API="$(mk_api 4003 6445 "/repo/ai/worktrees/agent-liveid9")"
assert "a mayor checkout apiserver on 6445 is NOT flagged while a live worker's apiserver is on 6445 -- slot ownership unclear, never kill" \
  "$([ -z "$(squat "$(mk_api 4002 6445 "$SQ_DIR")
$AGENT_API")" ] && echo 1 || echo 0)"
assert "a live worker's apiserver on a worker slot is never flagged by the mayor squatter rule" \
  "$([ -z "$(call find_mayor_worker_slot_squatters "$AGENT_API" "/repo/ai/worktrees/agent-liveid9")" ] && echo 1 || echo 0)"
assert "a mayor checkout scheduler whose kubeconfig points at worker slot 6445 IS flagged" \
  "$([ "$(squat "$(mk_sched 4004 kubeconfig-scheduler "$SQ_DIR")")" = "4004|slot-squatter-scheduler|$SQ_DIR" ] && echo 1 || echo 0)"
assert "a mayor checkout scheduler whose kubeconfig points at slot 0 (6443) is NOT flagged" \
  "$([ -z "$(squat "$(mk_sched 4005 kubeconfig-slot0 "$SQ_DIR")")" ] && echo 1 || echo 0)"
assert "a mayor checkout scheduler with an unreadable kubeconfig is NOT flagged -- port unprovable" \
  "$([ -z "$(squat "$(mk_sched 4006 kubeconfig-missing "$SQ_DIR")")" ] && echo 1 || echo 0)"
CARGO_LINE="alice  4007   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 cargo build --release -p u7s-apiserver -p u7s-scheduler --listen 127.0.0.1:6445 --manifest-path $SQ_DIR/temp/u7s/kubeconfig"
assert "a non-u7s process merely mentioning u7s-apiserver (cargo build) is not typed, so never a kill candidate" \
  "$([ -z "$(call proc_type_from_psline "$CARGO_LINE")" ] && [ -z "$(squat "$CARGO_LINE")" ] && echo 1 || echo 0)"
assert "the live-agents filter passes a mayor checkout record through (no agent-id in its path must not abort the set -e script, or the squatter is silently never reaped)" \
  "$([ "$(call filter_orphans_by_live_agents "4002|slot-squatter-apiserver|$SQ_DIR" liveid9)" = "4002|slot-squatter-apiserver|$SQ_DIR" ] && echo 1 || echo 0)"
assert "u7s-apiserver is typed by argv[0] basename, even from a full path" \
  "$([ "$(call proc_type_from_psline "$(mk_api 4008 6445 "$SQ_DIR")")" = apiserver ] && echo 1 || echo 0)"

# 1e. STEP A end to end (DRY_RUN=1, stubbed scan_ps): the real entry point must
# signal exactly the squatter's pid -- a `pkill -f` path pattern would also
# kill the operator's slot-0 stack, which shares the mayor checkout path.
SA_DIR="$SANDBOX_ROOT/stepa"
mkdir -p "$SA_DIR/temp/u7s"
new_sandbox "$SA_DIR"
SA_REAL=$(cd -P "$SA_DIR" && pwd)
mk_konn() {  # pid server-port wpath
  echo "alice  $1   0.0  0.1  123456  1234 s001  S    10:00AM   0:00.05 konnectivity-server --server-cert=$3/temp/u7s/konnectivity-server.crt --server-port=$2"
}
step_a_dry() {  # ps lines -> every "would run:" line of a dry-run STEP A
  local out
  out=$(
    export DRY_RUN=1 HYGIENE_RESCAN_GRACE_S=0 WORKTREE_HYGIENE_REPO_ROOT="$SA_REAL"
    # shellcheck disable=SC1090
    source "$SCRIPT"
    LIVE_AGENTS="liveid9"
    PS_FIXTURE="$1"
    scan_ps() { printf '%s\n' "$PS_FIXTURE"; }
    step_a_orphaned_processes 2>&1
  )
  printf '%s\n' "$out" | grep 'would run:' || true
}
SA_API_6445=$(mk_api 5001 6445 "$SA_REAL")
SA_API_6443=$(mk_api 5002 6443 "$SA_REAL")
SA_KONN_SLOT0=$(mk_konn 5003 8135 "$SA_REAL")
SA_KONN_8335=$(mk_konn 5004 8335 "$SA_REAL")
SA_WORKER_API=$(mk_api 5005 6446 "/repo/ai/worktrees/agent-liveid9")

assert "STEP A (a): a mayor checkout apiserver on 6445 is killed by pid alone -- the only signal that spares the slot-0 stack at the same path" \
  "$([ "$(step_a_dry "$SA_API_6445")" = "[dry-run] would run: kill 5001" ] && echo 1 || echo 0)"
assert "STEP A (b): the operator's slot-0 stack (apiserver 6443 + konnectivity 8135) is never signalled, and no pkill -f pattern is issued" \
  "$([ -z "$(step_a_dry "$SA_API_6443
$SA_KONN_SLOT0")" ] && echo 1 || echo 0)"
assert "STEP A (b'): a 6445 squatter next to the slot-0 stack is killed by pid only -- no pkill -f that would match slot 0" \
  "$([ "$(step_a_dry "$SA_API_6443
$SA_KONN_SLOT0
$SA_API_6445")" = "[dry-run] would run: kill 5001" ] && echo 1 || echo 0)"
assert "STEP A (c): an apiserver-less mayor checkout konnectivity on 8335 is reaped by pid (exactly one kill)" \
  "$([ "$(step_a_dry "$SA_KONN_8335")" = "[dry-run] would run: kill 5004" ] && echo 1 || echo 0)"
assert "STEP A (b''): a stale 8335 konnectivity beside the operator's slot-0 konnectivity (same path) is killed by pid only -- a path pkill would take down slot 0" \
  "$([ "$(step_a_dry "$SA_KONN_SLOT0
$SA_KONN_8335")" = "[dry-run] would run: kill 5004" ] && echo 1 || echo 0)"
assert "STEP A (d): a live worker's 6446 apiserver is untouched even beside a real squatter, which alone is killed" \
  "$([ "$(step_a_dry "$SA_WORKER_API
$SA_API_6445")" = "[dry-run] would run: kill 5001" ] && echo 1 || echo 0)"
assert "STEP A (d'): a live worker's 6446 apiserver alone produces no kill" \
  "$([ -z "$(step_a_dry "$SA_WORKER_API")" ] && echo 1 || echo 0)"

# A dead worktree whose path is a suffix of the live one (/stepa vs
# <tmp>/stepa) must yield a pkill -f pattern that cannot match the live
# process's argv -- otherwise reaping the dead one kills a live stack.
SA_DEAD_SUFFIX="/$(basename "$SA_REAL")"
SA_API_DEAD=$(mk_api 5006 6447 "$SA_DEAD_SUFFIX")
SA_API_LIVE=$(mk_api 5007 6443 "$SA_REAL")
SA_KILLS=$(step_a_dry "$SA_API_LIVE
$SA_API_DEAD")
SA_PAT="${SA_KILLS#*pkill -f }"
assert "STEP A suffix collision: exactly one pkill is issued, for the dead worktree" \
  "$([ "$(printf '%s\n' "$SA_KILLS" | grep -c 'would run: pkill -f ')" = 1 ] && echo 1 || echo 0)"
assert "STEP A suffix collision: the pattern matches the dead worktree's process" \
  "$(printf '%s\n' "$SA_API_DEAD" | grep -qE -- "$SA_PAT" && echo 1 || echo 0)"
assert "STEP A suffix collision: the pattern does NOT match the live worktree's process whose path ends with the dead path" \
  "$(! printf '%s\n' "$SA_API_LIVE" | grep -qE -- "$SA_PAT" && echo 1 || echo 0)"
assert "kill_pattern_for escapes regex metacharacters: /a.b must not match /aXb" \
  "$(! echo 'u7s-apiserver --kubeconfig /aXb/temp/u7s/kubeconfig' | grep -qE -- "$(call kill_pattern_for apiserver /a.b)" && echo 1 || echo 0)"
assert "kill_pattern_for ends /temp/u7s at a separator: /temp/u7s2 is another workdir" \
  "$(! echo 'konnectivity-server --server-cert=/dead/temp/u7s2/x.crt' | grep -qE -- "$(call kill_pattern_for konnectivity-server /dead)" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. STEP C -- in-flight guard.
# ---------------------------------------------------------------------------

PORCELAIN='worktree /repo
HEAD abc123
branch refs/heads/main

worktree /worktrees/agent-live
HEAD def456
branch refs/heads/worker/agent-live'

CHECKED_OUT=$(call checked_out_branches "$PORCELAIN")
assert "checked_out_branches extracts every worktree's checked-out branch" \
  "$(printf '%s\n' "$CHECKED_OUT" | grep -qxF 'worker/agent-live' && printf '%s\n' "$CHECKED_OUT" | grep -qxF 'main' && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-live' "$CHECKED_OUT" || RC=$?
assert "a branch checked out in a live worktree is guarded as in-flight (must not be force-deleted)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_checked_out 'worker/agent-gone' "$CHECKED_OUT" || RC=$?
assert "a branch NOT checked out in any worktree is not guarded by the in-flight check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. STEP C -- patch-id merge check. Runs real git (not synthetic text)
#    against a disposable sandbox repo with a real `origin` remote, since
#    patch-id comparison genuinely needs two commit graphs.
# ---------------------------------------------------------------------------

BARE="$SANDBOX_ROOT/origin.git"
git init -q --bare "$BARE"

S="$SANDBOX_ROOT/patchid-repo"
new_sandbox "$S"
printf 'line one\n' > "$S/file.txt"
git -C "$S" add -A
git -C "$S" commit -q -m initial
git -C "$S" remote add origin "$BARE"
git -C "$S" push -q origin main

# Genuinely unmerged: a worker branch with a commit `origin/main` has never
# seen at all.
git -C "$S" branch worker/agent-unmerged main
git -C "$S" checkout -q worker/agent-unmerged
printf 'line one\nunmerged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'unmerged work'
git -C "$S" checkout -q main

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-unmerged >/dev/null 2>&1 || RC=$?
assert "a branch with commits origin/main has never seen at all is flagged unmerged (skip deletion)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# Genuinely merged: a branch that is a literal ancestor of origin/main (its
# commit was pushed straight to main) -- `git cherry` reports no output at
# all, since every commit in the branch is already reachable from upstream.
git -C "$S" branch worker/agent-ff-merged main
printf 'line one\nff merged addition\n' > "$S/file.txt"
git -C "$S" commit -q -am 'ff-mergeable work'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-ff-merged >/dev/null 2>&1 || RC=$?
assert "a branch whose commits are already an ancestor of origin/main is NOT flagged unmerged (safe to delete)" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# The squash-merge case mayor-bootstrap.md's design specifically calls out:
# origin/main gains a NEW commit with the same net patch as the branch's
# commit (a different SHA, as a real squash-merge produces) --
# `git branch --merged` would call this branch unmerged (its commit SHA
# isn't an ancestor), but `git cherry` detects the patch-id match and still
# produces output (a `-`-prefixed line) -- so this branch is ALSO guarded
# as "has output, skip" under the loop body's literal semantics, same as
# the genuinely-unmerged case above (the loop is a conservative backstop,
# not the primary merge-cleanup path -- that's the merge/dashboard script's
# job once a PR is confirmed merged).
git -C "$S" checkout -q -b worker/agent-squashed main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload'
git -C "$S" checkout -q main
printf 'line one\nsquash payload\n' > "$S/file.txt"
git -C "$S" commit -q -am 'squash payload (squash-merged onto main under a new SHA)'
git -C "$S" push -q origin main
RC=0
WORKTREE_HYGIENE_REPO_ROOT="$S" call is_unmerged_by_patch_id worker/agent-squashed >/dev/null 2>&1 || RC=$?
assert "a squash-merged branch (same patch, different SHA) still produces cherry output and is guarded, matching mayor-bootstrap.md's literal 'any output -> skip' rule" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3b. STEP C -- open-PR guard. Observed 2026-08-28: PR #1433's
#    commits reached main via a DIFFERENT PR (#1435) while #1433 itself was
#    still open -- patch-id alone would call #1433's branch safe to delete,
#    but deleting it would auto-close the still-open PR and destroy its
#    review state. This must be judged on PR state, not patch-id.
# ---------------------------------------------------------------------------
OPEN_PRS='worker/agent-has-open-pr
worker/agent-other-open-pr'

RC=0
call has_open_pr 'worker/agent-has-open-pr' "$OPEN_PRS" || RC=$?
assert "a branch with an open PR is guarded, even though its commits might already be merged elsewhere by patch-id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_open_pr 'worker/agent-no-pr' "$OPEN_PRS" || RC=$?
assert "a branch with no open PR is not guarded by the open-PR check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3c. STEP C -- live-worktree-directory guard. Observed
#    2026-08-28: a worker switched its worktree to a scratch branch
#    mid-dispatch, leaving worker/agent-<id> checked out nowhere --
#    is_checked_out alone is blind to this since it only sees what's
#    checked out RIGHT NOW, not which worktree directories still exist.
# ---------------------------------------------------------------------------
LIVE_AGENT_DIR="$SANDBOX_ROOT/live-agent-worktrees/ai/worktrees/agent-live123"
mkdir -p "$LIVE_AGENT_DIR"

RC=0
call has_live_worktree_dir 'worker/agent-live123' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with a live worktree directory is guarded, regardless of what that worktree currently has checked out" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'worker/agent-gone456' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a worker/agent-<id> branch with no matching worktree directory is not guarded by this check" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call has_live_worktree_dir 'main' "$SANDBOX_ROOT/live-agent-worktrees" || RC=$?
assert "a non-worker/agent-* branch name (e.g. main) never matches this check, even if a coincidentally-named directory existed" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3d. STEP C -- --live-agents guard. THE only reliable liveness signal for
#    an in-process worker sub-agent (a sub-agent cannot call ListAgents on
#    itself, and `claude agents --json` doesn't enumerate in-process
#    subagents -- both confirmed directly). Fires FIRST and unconditionally,
#    ahead of every other STEP C guard, since it's the only one that isn't
#    itself derivable from stale git/filesystem state.
# ---------------------------------------------------------------------------

RC=0
call is_live_agent_branch 'worker/agent-abc123' 'xyz999,abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is ANY entry in a comma-separated --live-agents list is protected" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'abc123,def456' || RC=$?
assert "a worker/agent-<id> branch whose id is NOT in --live-agents is not protected by this guard -- a genuinely stale branch must still be reapable" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-abc123' '' || RC=$?
assert "an empty --live-agents set protects nothing -- an unknown agent must never be assumed live" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'main' 'main' || RC=$?
assert "a non-worker/agent-* branch name never matches, even if it coincidentally equals a --live-agents entry" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# --live-agents entries given as agent-<id> or worker/agent-<id> must still
# protect the worker: a mismatch silently strips protection from the
# destructive steps.
for LIVE_FORM in 'abc123' 'agent-abc123' 'worker/agent-abc123' 'xyz999, agent-abc123' 'xyz999, worker/agent-abc123'; do
  RC=0
  call is_live_agent_branch 'worker/agent-abc123' "$LIVE_FORM" || RC=$?
  assert "--live-agents entry form '${LIVE_FORM}' protects worker/agent-abc123 -- a prefixed id must not leave a live worker reapable" \
    "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
done

RC=0
call is_live_agent_branch 'worker/agent-gone999' 'agent-abc123,worker/agent-def456' || RC=$?
assert "prefixed --live-agents entries still do not protect an unrelated worker branch" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3e. Whitespace-tolerant --live-agents membership match. A comma-space-
#    joined list (e.g. "a, b, c") must protect EVERY id, not just the
#    first -- without normalization, the naive ",${live_agents}," substring
#    match leaves a leading space on every id after the first, so only the
#    first id in the list ever matches and every subsequent live worker is
#    left unprotected/reapable.
# ---------------------------------------------------------------------------

RC=0
call agent_id_is_live 'abc123' 'abc123, def456, ghi789' || RC=$?
assert "sanity: a comma-space-joined --live-agents list protects the FIRST id" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'def456' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the MIDDLE id too -- fails without normalization, since \", \" leaves the id as \" def456\", which never equals the bare \"def456\" the substring match searches for" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call agent_id_is_live 'ghi789' 'abc123, def456, ghi789' || RC=$?
assert "...and it protects the LAST id too, proving every id in a comma-space-joined list is protected, not just the first" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_live_agent_branch 'worker/agent-def456' 'abc123, def456, ghi789' || RC=$?
assert "the same whitespace tolerance holds at the STEP C/D branch-guard level (is_live_agent_branch) -- this is what actually protects a live worker's branch from force-delete" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3f. STEP C -- reap-all (--no-live-workers) end-to-end. --no-live-workers
#    sets LIVE_AGENTS="" (see main()); this proves that with an EMPTY live
#    set, STEP C's merge-state and open-PR checks -- not --live-agents --
#    are what decide what's safe to delete. That's the safety constraint
#    --no-live-workers depends on: waiving the live-agent dimension must
#    never lower the staleness bar, or reap-all mode would nuke a branch
#    with a pending PR the instant zero workers are running. Mirrors the
#    real scenario this flag exists for: several completed workers' branches
#    have OPEN PRs (queued-to-merge or draft) and must survive a zero-live-
#    worker hygiene tick, while a genuinely merged, no-PR branch is reaped.
# ---------------------------------------------------------------------------
BARE_NLW="$SANDBOX_ROOT/origin-nlw.git"
git init -q --bare "$BARE_NLW"

NLW="$SANDBOX_ROOT/reap-all-repo"
new_sandbox "$NLW"
printf 'line one\n' > "$NLW/file.txt"
git -C "$NLW" add -A
git -C "$NLW" commit -q -m initial
git -C "$NLW" remote add origin "$BARE_NLW"
git -C "$NLW" push -q origin main

# Reapable: merged by patch-id (ff push straight to main), no open PR.
git -C "$NLW" branch worker/agent-mergednopr main
printf 'line one\nmerged no-pr work\n' > "$NLW/file.txt"
git -C "$NLW" commit -q -am 'merged, no open PR'
git -C "$NLW" push -q origin main

# NOT reapable despite ALSO being merged by patch-id: an OPEN PR still
# references it (the #1433/#1435 case STEP C's header documents) -- only
# has_open_pr, not patch-id, can see this.
git -C "$NLW" checkout -q -b worker/agent-openpr main
printf 'line one\nqueued-to-merge work\n' > "$NLW/file.txt"
git -C "$NLW" commit -q -am 'queued-to-merge work'
git -C "$NLW" checkout -q main
printf 'line one\nqueued-to-merge work\n' > "$NLW/file.txt"
git -C "$NLW" commit -q -am 'queued-to-merge work (already landed on main by patch-id, e.g. via a different PR)'
git -C "$NLW" push -q origin main

STUB_GH_ONE_OPEN_PR="$SANDBOX_ROOT/stub-gh-one-open-pr"
mkdir -p "$STUB_GH_ONE_OPEN_PR"
cat > "$STUB_GH_ONE_OPEN_PR/gh" <<'EOF'
#!/usr/bin/env bash
echo 'worker/agent-openpr'
EOF
chmod +x "$STUB_GH_ONE_OPEN_PR/gh"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$NLW" PATH="$STUB_GH_ONE_OPEN_PR:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1

assert "reap-all mode (LIVE_AGENTS=\"\", what --no-live-workers sets) reaps a branch that is merged by patch-id AND has no open PR -- the idle-state win this flag exists for" \
  "$(! git -C "$NLW" branch --list worker/agent-mergednopr | grep -q worker/agent-mergednopr && echo 1 || echo 0)"

assert "...but PRESERVES a branch in that SAME empty live-set run when an OPEN PR still references it, even though patch-id alone says it's already merged -- proves reap-all mode does not lower STEP C's staleness bar, it only waives the live-agent dimension (the safety constraint --no-live-workers must uphold, checked on revert: deleting has_open_pr's guard would flip this to reaped)" \
  "$(git -C "$NLW" branch --list worker/agent-openpr | grep -q worker/agent-openpr && echo 1 || echo 0)"

# End-to-end: a worker branch that is ALREADY MERGED (ff-mergeable, so
# is_unmerged_by_patch_id says false), has no open PR, and no live worktree
# directory -- by every OTHER STEP C guard this branch is indistinguishable
# from a genuinely stale, safe-to-delete one. Only --live-agents membership
# can save it, proving the guard fires "unconditionally, regardless of dir
# existence or merge state" (the exact original bug: a ListAgents-confirmed-
# live worker's branch was force-deleted anyway because every OTHER signal
# said "safe").
BARE_LIVE="$SANDBOX_ROOT/origin-live.git"
git init -q --bare "$BARE_LIVE"

L="$SANDBOX_ROOT/step-c-live-agent-repo"
new_sandbox "$L"
printf 'line one\n' > "$L/file.txt"
git -C "$L" add -A
git -C "$L" commit -q -m initial
git -C "$L" remote add origin "$BARE_LIVE"
git -C "$L" push -q origin main

git -C "$L" branch worker/agent-liveagent456 main
printf 'line one\nmore work on main\n' > "$L/file.txt"
git -C "$L" commit -q -am 'advance main'
git -C "$L" push -q origin main

STUB_GH_NO_OPEN_PRS="$SANDBOX_ROOT/stub-gh-no-open-prs"
mkdir -p "$STUB_GH_NO_OPEN_PRS"
cat > "$STUB_GH_NO_OPEN_PRS/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB_GH_NO_OPEN_PRS/gh"

LIVE_AGENTS="liveagent456" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "STEP C protects a worker/agent-<id> branch whose id IS in --live-agents even though it's already merged, has no open PR, and no live worktree directory -- every other guard alone would have called it safe to delete" \
  "$(git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$L" PATH="$STUB_GH_NO_OPEN_PRS:$PATH" \
  call step_c_stale_worker_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is force-deleted -- proving the guard (not some accident of the other checks) is what protected it above" \
  "$(! git -C "$L" branch --list worker/agent-liveagent456 | grep -q worker/agent-liveagent456 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. STEP D -- gone-upstream match.
# ---------------------------------------------------------------------------

FOR_EACH_REF='main [ahead 1]
worker/agent-done [gone]
investigation/scratch
worker/agent-active [behind 2]'

GONE=$(call gone_upstream_branches "$FOR_EACH_REF")
assert "a branch with a [gone] upstream is matched for deletion" \
  "$(printf '%s\n' "$GONE" | grep -qxF 'worker/agent-done' && echo 1 || echo 0)"
assert "a branch with no upstream configured at all (no track field) is NOT matched (only [gone] counts, not merely absent)" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'investigation/scratch' && echo 1 || echo 0)"
assert "a branch that is merely behind (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'worker/agent-active' && echo 1 || echo 0)"
assert "a branch that is ahead (not gone) is NOT matched" \
  "$(! printf '%s\n' "$GONE" | grep -qxF 'main' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4b. STEP D -- checked-out guard, exercised end-to-end (not via a
#    reimplemented text check) against a disposable sandbox repo with a real
#    worktree, since the bug is a genuine `git branch -d` refusal, not a
#    text-matching mistake. Regression: observed 2026-09-06 twice (PRs
#    #1595, #1599) -- a worker branch's upstream goes `[gone]` the instant
#    the merge queue deletes its remote head, which can race ahead of the
#    tick that reaps its worktree. Unlike STEP C, STEP D had no
#    is_checked_out guard, so `git branch -d` on that still-checked-out
#    branch made git refuse, and this script's `set -e` turned that refusal
#    into a whole-run abort (skipping STEP E) on what is actually a benign,
#    self-resolving race.
# ---------------------------------------------------------------------------

BARE_D="$SANDBOX_ROOT/origin-d.git"
git init -q --bare "$BARE_D"

D="$SANDBOX_ROOT/step-d-repo"
new_sandbox "$D"
printf 'line one\n' > "$D/file.txt"
git -C "$D" add -A
git -C "$D" commit -q -m initial
git -C "$D" remote add origin "$BARE_D"
git -C "$D" push -q origin main

# A branch checked out in a second worktree, then merged and its remote
# head deleted -- exactly the merge-queue race: local upstream tracking
# still points at origin/worker/agent-gone, but that ref is gone.
git -C "$D" branch worker/agent-gone main
git -C "$D" push -q -u origin worker/agent-gone
git -C "$D" worktree add -q "$SANDBOX_ROOT/step-d-worktree" worker/agent-gone
git -C "$D" push -q origin --delete worker/agent-gone
git -C "$D" fetch -q --prune origin

RC=0
WORKTREE_HYGIENE_REPO_ROOT="$D" call step_d_gone_upstream_branches >/dev/null 2>&1 || RC=$?
assert "STEP D does not abort the whole hygiene tick (skipping STEP E) when a gone-upstream branch is still checked out in a live worktree" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"
assert "...and the branch itself survives -- skipped for the tick's reap, not force-deleted out from under the live worktree" \
  "$(git -C "$D" branch --list worker/agent-gone | grep -q worker/agent-gone && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4c. STEP D -- --live-agents guard, exercised end-to-end against a
#    gone-upstream branch that is NOT checked out anywhere (unlike 4b
#    above, which covers the is_checked_out guard specifically) -- by
#    STEP D's only OTHER guard this branch is fully reapable via `-d`.
#    Only --live-agents membership can save it.
# ---------------------------------------------------------------------------

BARE_D2="$SANDBOX_ROOT/origin-d2.git"
git init -q --bare "$BARE_D2"

D2="$SANDBOX_ROOT/step-d-live-agent-repo"
new_sandbox "$D2"
printf 'line one\n' > "$D2/file.txt"
git -C "$D2" add -A
git -C "$D2" commit -q -m initial
git -C "$D2" remote add origin "$BARE_D2"
git -C "$D2" push -q origin main

git -C "$D2" branch worker/agent-liveagent789 main
git -C "$D2" push -q -u origin worker/agent-liveagent789
git -C "$D2" push -q origin --delete worker/agent-liveagent789
git -C "$D2" fetch -q --prune origin

LIVE_AGENTS="liveagent789" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "STEP D protects a gone-upstream worker/agent-<id> branch whose id IS in --live-agents, even though it's not checked out anywhere (STEP D's only other guard)" \
  "$(git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$D2" call step_d_gone_upstream_branches >/dev/null 2>&1
assert "...the SAME branch, with no matching --live-agents entry, is deleted -- proving the guard is what saved it above" \
  "$(! git -C "$D2" branch --list worker/agent-liveagent789 | grep -q worker/agent-liveagent789 && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 5. run_cmd dry-run gate -- the mechanism that keeps THIS test suite (and
#    any manual dry-run) from ever killing a real process or deleting a
#    real branch.
# ---------------------------------------------------------------------------

MARKER="$SANDBOX_ROOT/marker"
OUT=$(DRY_RUN=1 call run_cmd touch "$MARKER")
assert "DRY_RUN=1 logs the command instead of running it" \
  "$(printf '%s' "$OUT" | grep -q 'would run: touch' && echo 1 || echo 0)"
assert "...and the gated command genuinely did not execute" \
  "$([ ! -e "$MARKER" ] && echo 1 || echo 0)"

call run_cmd touch "$MARKER" >/dev/null
assert "without DRY_RUN, run_cmd executes the real command" \
  "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 6. STEP E -- findings-enforcement drift backstop. Only the two pure
#    functions are covered here (bead-id extraction and staleness
#    classification, which together fully capture the branching logic);
#    step_e_stale_findings() itself isn't, since it calls live `bd show`
#    against this repo's real, mutable bead state -- referencing a real
#    bead ID here would make the test's outcome depend on that bead's
#    status at whatever moment CI happens to run, silently flipping
#    PASS/FAIL as unrelated bead lifecycle events occur elsewhere. This was
#    instead verified manually against real live bd state during
#    development (a scratch ai/findings/*.md staged against a genuinely
#    closed bead, a genuinely open bead, and a nonexistent bead ID all
#    produced the expected warn/silent split) -- the same "exercise the
#    real thing, not a synthetic stand-in" principle this suite follows
#    elsewhere, just not automatable here without a disposable bd database.
# ---------------------------------------------------------------------------

# Fixture suffixes below are intentionally 2 chars, one below the real
# generator's 3-5 char range (see check-bead-id-refs.sh), so these
# synthetic bead-ID-shaped strings don't trip that guard's rot check --
# they're placeholders for the parser test, not references to real beads.
FINDING_CLOSED="$SANDBOX_ROOT/finding-closed.md"
printf 'Bead: mayor-fx\n\nBody text.\n' > "$FINDING_CLOSED"
assert "bead_id_from_finding extracts the bead id from a well-formed header" \
  "$([ "$(call bead_id_from_finding "$FINDING_CLOSED")" = "mayor-fx" ] && echo 1 || echo 0)"

FINDING_NO_HEADER="$SANDBOX_ROOT/finding-no-header.md"
printf 'Just prose, no bead reference.\n' > "$FINDING_NO_HEADER"
assert "bead_id_from_finding returns empty for a file with no Bead: header (must not be treated as a match for any bead)" \
  "$([ -z "$(call bead_id_from_finding "$FINDING_NO_HEADER")" ] && echo 1 || echo 0)"

# Regression: a header with trailing descriptive text (e.g. a parenthetical
# naming related beads) used to be slurped whole, whitespace stripped, into
# one mangled compound token that matches no live bd record -- so a real,
# still-open finding got flagged stale and recommended for deletion. The
# parser must stop at the first bead-ID token and ignore everything after.
FINDING_TRAILING="$SANDBOX_ROOT/finding-trailing.md"
printf 'Bead: mayor-tp (decision-prep for mayor-ab Phase 3 / mayor-cd)\n\nBody text.\n' > "$FINDING_TRAILING"
EXTRACTED_TRAILING=$(call bead_id_from_finding "$FINDING_TRAILING")
assert "bead_id_from_finding stops at the bead-ID token instead of slurping trailing text (incl. other mayor-* mentions) into a mangled string that would never match any live bead" \
  "$([ "$EXTRACTED_TRAILING" = "mayor-tp" ] && echo 1 || echo 0)"

# Feeding the correctly-extracted id's status through is_stale_bead_status
# as "open" proves the fix, not a coincidental match, is what keeps a live
# finding with a trailing-parenthetical header from being flagged stale.
RC=0
call is_stale_bead_status "open" || RC=$?
assert "a trailing-parenthetical header for an open bead ($EXTRACTED_TRAILING) is NOT flagged stale once the id is extracted correctly" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "closed" || RC=$?
assert "is_stale_bead_status flags a closed bead as stale (the case check-findings-closed-bead-refs.sh already catches via the export)" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "" || RC=$?
assert "is_stale_bead_status flags an empty (no live bd record) status as stale -- the pruned-bead hole the export-based CI check cannot see" \
  "$([ "$RC" -eq 0 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "open" || RC=$?
assert "is_stale_bead_status does NOT flag an open bead -- must not warn on every routine in-flight finding" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

RC=0
call is_stale_bead_status "in_progress" || RC=$?
assert "is_stale_bead_status does NOT flag an in_progress bead" \
  "$([ "$RC" -eq 1 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7. main()'s fail-safe refusal without --live-agents. STEP A/C/D are
#    destructive (process kill, branch delete); dir-existence and
#    merge-state checks alone already proved insufficient to tell a live
#    worker apart from a stale one, so a missing flag must abort the whole
#    run rather than guess "assume none live" or "assume all live". This
#    permanently forecloses the reap-a-live-worker bug class via
#    mis-invocation. Invokes the real script directly (not via __call,
#    which bypasses main()'s own argv parsing and this exact gate) with no
#    args at all -- safe because the refusal fires before any step runs, so
#    no real `ps aux`/git state is ever touched.
# ---------------------------------------------------------------------------

FAILSAFE_RC=0
FAILSAFE_OUT=$(bash "$SCRIPT" 2>&1) || FAILSAFE_RC=$?
assert "worktree-hygiene refuses to run at all when --live-agents is omitted, exiting non-zero instead of silently defaulting" \
  "$([ "$FAILSAFE_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and the refusal is explained on stderr naming the missing flag, not a silent no-op" \
  "$(printf '%s' "$FAILSAFE_OUT" | grep -q -- '--live-agents' && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all -- STEP A/B/C/D/E never even started" \
  "$(! printf '%s' "$FAILSAFE_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

# Same fail-safe, but for a PRESENT --live-agents flag whose VALUE is empty
# or whitespace-only -- the flag TOKEN appearing in argv is not enough on
# its own; without checking the value too, `--live-agents ""` (e.g. a
# ListAgents call that returned zero running agents, mis-joined into an
# empty string instead of omitting the flag) would sail past a
# presence-only check and run the destructive steps with an effectively
# empty live set, reaping any genuinely live worker.
FAILSAFE_EMPTY_RC=0
FAILSAFE_EMPTY_OUT=$(bash "$SCRIPT" --live-agents "" 2>&1) || FAILSAFE_EMPTY_RC=$?
assert "worktree-hygiene refuses to run when --live-agents is present but its value is the empty string, exiting non-zero rather than treating it as a valid (if empty) live set" \
  "$([ "$FAILSAFE_EMPTY_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all for the empty-value case either" \
  "$(! printf '%s' "$FAILSAFE_EMPTY_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

FAILSAFE_WS_RC=0
FAILSAFE_WS_OUT=$(bash "$SCRIPT" --live-agents "   " 2>&1) || FAILSAFE_WS_RC=$?
assert "worktree-hygiene also refuses to run when --live-agents is whitespace-only -- a value that is non-empty as a raw string but carries no actual agent id must not bypass the fail-safe" \
  "$([ "$FAILSAFE_WS_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and no destructive-step log output appears at all for the whitespace-only case either" \
  "$(! printf '%s' "$FAILSAFE_WS_OUT" | grep -qE '\[hygiene\]|worktree prune' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 7b. main() -- --no-live-workers: an explicit, affirmative "zero live
#    workers" declaration, DISTINCT from the forgot-the-flag case above
#    (which --live-agents "" and omitting both flags both still trigger).
#    Without this flag, the idle state -- exactly when orphaned host
#    processes and stale branches accumulate -- could never be reaped,
#    since an empty --live-agents value is indistinguishable from a
#    forgotten flag. Mutually exclusive with --live-agents: passing both
#    leaves no way to tell which one the caller meant.
# ---------------------------------------------------------------------------

BOTH_RC=0
BOTH_OUT=$(bash "$SCRIPT" --live-agents abc123 --no-live-workers 2>&1) || BOTH_RC=$?
assert "worktree-hygiene refuses to run when BOTH --live-agents and --no-live-workers are given -- ambiguous which one the caller meant" \
  "$([ "$BOTH_RC" -eq 2 ] && echo 1 || echo 0)"
assert "...and the refusal names both flags as mutually exclusive, not a silent pick-one" \
  "$(printf '%s' "$BOTH_OUT" | grep -q -- '--no-live-workers' && printf '%s' "$BOTH_OUT" | grep -q -- '--live-agents' && echo 1 || echo 0)"

# --no-live-workers alone must NOT trip the fail-safe -- exercised through
# the REAL main() (not __call, which bypasses argv parsing) against a
# disposable sandbox repo. DRY_RUN=1 so STEP A's real `ps aux` scan of the
# host machine can never actually kill a real process regardless of what
# else happens to be running on the machine this test executes on, and
# `gh` is stubbed so STEP C never hits the real network.
BARE_NLW_MAIN="$SANDBOX_ROOT/origin-nlw-main.git"
git init -q --bare "$BARE_NLW_MAIN"
NLW_MAIN="$SANDBOX_ROOT/no-live-workers-main-repo"
new_sandbox "$NLW_MAIN"
printf 'line one\n' > "$NLW_MAIN/file.txt"
git -C "$NLW_MAIN" add -A
git -C "$NLW_MAIN" commit -q -m initial
git -C "$NLW_MAIN" remote add origin "$BARE_NLW_MAIN"
git -C "$NLW_MAIN" push -q origin main

STUB_GH_EMPTY="$SANDBOX_ROOT/stub-gh-empty"
mkdir -p "$STUB_GH_EMPTY"
cat > "$STUB_GH_EMPTY/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$STUB_GH_EMPTY/gh"

NLW_MAIN_RC=0
NLW_MAIN_OUT=$(DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_MAIN" PATH="$STUB_GH_EMPTY:$PATH" \
  bash "$SCRIPT" --no-live-workers 2>&1) || NLW_MAIN_RC=$?
assert "worktree-hygiene runs (does not refuse) with --no-live-workers alone, unlike an omitted or empty --live-agents -- this is the idle-state reap path the flag exists to unlock" \
  "$([ "$NLW_MAIN_RC" -eq 0 ] && echo 1 || echo 0)"
assert "...and the fail-safe refusal message never appears for --no-live-workers" \
  "$(! printf '%s' "$NLW_MAIN_OUT" | grep -q 'refusing to run' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 8. STEP F -- orphaned origin/worker/agent-* branches. Mirrors STEP C/D's
#    end-to-end sandbox style (a real bare "origin" repo, a stub `gh`), but
#    each branch under test is pushed to origin and then deleted LOCALLY --
#    the exact crashed-worker shape this step exists for (its worktree, and
#    often its local branch, are already gone; only the origin ref
#    remains). This proves origin_worker_branches() finds such a branch via
#    `ls-remote` -- STEP C's local `refs/heads/*` iteration cannot see it at
#    all, since there IS no local branch.
# ---------------------------------------------------------------------------

BARE_F="$SANDBOX_ROOT/origin-f.git"
git init -q --bare "$BARE_F"

F="$SANDBOX_ROOT/step-f-repo"
new_sandbox "$F"
printf 'line one\n' > "$F/file.txt"
git -C "$F" add -A
git -C "$F" commit -q -m initial
git -C "$F" remote add origin "$BARE_F"
git -C "$F" push -q origin main

# Reapable: crashed worker, no PR ever opened, id not in --live-agents.
git -C "$F" branch worker/agent-crashed main
git -C "$F" push -q origin worker/agent-crashed
git -C "$F" branch -D worker/agent-crashed

# NOT reapable: an OPEN PR still references this branch, even though it
# looks just as "crashed" (zero local trace) as the one above.
git -C "$F" branch worker/agent-openpr main
git -C "$F" push -q origin worker/agent-openpr
git -C "$F" branch -D worker/agent-openpr

# NOT reapable: id IS in --live-agents, even with no PR at all -- an
# in-flight worker that simply hasn't opened a PR yet.
git -C "$F" branch worker/agent-liveagent main
git -C "$F" push -q origin worker/agent-liveagent
git -C "$F" branch -D worker/agent-liveagent

assert "origin_worker_branches finds a branch via ls-remote even with zero local trace -- the crashed-worker shape STEP C's local refs/heads/* iteration cannot see" \
  "$(printf '%s\n' "$(call origin_worker_branches "$F")" | grep -qxF 'worker/agent-openpr' && echo 1 || echo 0)"

STUB_GH_STEP_F="$SANDBOX_ROOT/stub-gh-step-f"
mkdir -p "$STUB_GH_STEP_F"
cat > "$STUB_GH_STEP_F/gh" <<'EOF'
#!/usr/bin/env bash
echo 'worker/agent-openpr'
EOF
chmod +x "$STUB_GH_STEP_F/gh"

# Reapable only after archiving: an audit worker's PR-less branch whose sole
# commit is the findings doc.
BEAD_PFX="mayo""r-"
git -C "$F" checkout -q -b worker/agent-audit main
mkdir -p "$F/ai/findings"
printf 'Bead: %saudit1\n' "$BEAD_PFX" > "$F/ai/findings/2026-01-01-${BEAD_PFX}audit1-cis.md"
git -C "$F" add -A
git -C "$F" commit -q -m "findings"
AUDIT_TIP=$(git -C "$F" rev-parse HEAD)
git -C "$F" push -q origin worker/agent-audit
git -C "$F" checkout -q main
git -C "$F" branch -D worker/agent-audit

LIVE_AGENTS="liveagent" WORKTREE_HYGIENE_REPO_ROOT="$F" PATH="$STUB_GH_STEP_F:$PATH" \
  call step_f_orphaned_origin_branches >/dev/null 2>&1

assert "STEP F tags an orphan branch whose commits touch ai/findings/ as archive/<bead>-findings at its tip, on origin -- otherwise deleting it destroys the only copy of an audit doc" \
  "$([ "$(git -C "$BARE_F" rev-parse "refs/tags/archive/${BEAD_PFX}audit1-findings^{commit}" 2>/dev/null)" = "$AUDIT_TIP" ] && echo 1 || echo 0)"
assert "...and only then deletes that branch from origin" \
  "$(! git -C "$F" ls-remote --heads origin 'worker/agent-audit' | grep -q . && echo 1 || echo 0)"
assert "a findings-free orphan branch gets no archive tag -- tags are for branches with unique findings only" \
  "$([ "$(git -C "$BARE_F" tag -l 'archive/*' | wc -l | tr -d ' ')" = "1" ] && echo 1 || echo 0)"

origin_f_heads() {
  git -C "$F" ls-remote --heads origin 'worker/agent-*' | awk '{print $2}'
}

assert "STEP F deletes a crashed-worker branch that exists ONLY on origin, has no open PR, and whose id is not in --live-agents -- the class of branch nothing else in this script or the merge queue ever revisits" \
  "$(! origin_f_heads | grep -qxF 'refs/heads/worker/agent-crashed' && echo 1 || echo 0)"
assert "...but PRESERVES a same-shaped orphan-looking branch when an OPEN PR still references it -- has_open_pr, not liveness, is what saves it here" \
  "$(origin_f_heads | grep -qxF 'refs/heads/worker/agent-openpr' && echo 1 || echo 0)"
assert "...and PRESERVES a branch whose id IS in --live-agents even with no PR at all -- an in-flight worker that hasn't opened a PR yet must never be reaped" \
  "$(origin_f_heads | grep -qxF 'refs/heads/worker/agent-liveagent' && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 9. STEP G -- fix-round worktrees on fix-<PR> branches. STEP C only knows
#    worker/agent-* names, so without STEP G these worktrees accumulate
#    forever after the worker finishes.
# ---------------------------------------------------------------------------

BARE_G="$SANDBOX_ROOT/origin-g.git"
git init -q --bare "$BARE_G"
G="$SANDBOX_ROOT/step-g-repo"
new_sandbox "$G"
printf 'x\n' > "$G/file.txt"
git -C "$G" add -A
git -C "$G" commit -q -m initial
git -C "$G" remote add origin "$BARE_G"
git -C "$G" push -q origin main
mkdir -p "$G/ai/worktrees"
for pair in done:fix-1 live:fix-2 dirty:fix-3 unpushed:fix-4; do
  id="${pair%%:*}"; br="${pair##*:}"
  git -C "$G" branch "$br" main
  git -C "$G" push -q origin "$br"
  git -C "$G" worktree add -q "$G/ai/worktrees/agent-$id" "$br"
done
printf 'wip\n' > "$G/ai/worktrees/agent-dirty/wip.txt"
git -C "$G/ai/worktrees/agent-dirty" add wip.txt
git -C "$G/ai/worktrees/agent-unpushed" config user.email test@example.com
git -C "$G/ai/worktrees/agent-unpushed" config user.name Test
git -C "$G/ai/worktrees/agent-unpushed" commit -q --allow-empty -m "local only"

LIVE_AGENTS="live" WORKTREE_HYGIENE_REPO_ROOT="$G" call step_g_fix_round_worktrees >/dev/null 2>&1
assert "STEP G reaps a finished fix-<PR> worktree (clean, pushed, agent not live) -- otherwise it survives every hygiene run until the mayor deletes it by hand" \
  "$([ ! -d "$G/ai/worktrees/agent-done" ] && echo 1 || echo 0)"
assert "...and deletes its local fix-<PR> branch" \
  "$(! git -C "$G" rev-parse --verify -q refs/heads/fix-1 >/dev/null && echo 1 || echo 0)"
assert "STEP G keeps a fix-<PR> worktree whose agent id is live -- reaping would pull the checkout from under a running worker" \
  "$([ -d "$G/ai/worktrees/agent-live" ] && echo 1 || echo 0)"
assert "STEP G keeps a worktree with uncommitted changes -- they exist nowhere else" \
  "$([ -d "$G/ai/worktrees/agent-dirty" ] && echo 1 || echo 0)"
assert "STEP G keeps a worktree with commits on no remote -- reaping would destroy unpushed work" \
  "$([ -d "$G/ai/worktrees/agent-unpushed" ] && echo 1 || echo 0)"
assert "STEP G returns 0 when every removal succeeded -- a nonzero rc on a clean run would make every hygiene tick report an anomaly" \
  "$(LIVE_AGENTS="live" WORKTREE_HYGIENE_REPO_ROOT="$G" call step_g_fix_round_worktrees >/dev/null 2>&1 && echo 1 || echo 0)"

# --no-live-workers sets LIVE_AGENTS="" (see main()): a worktree whose agent
# id would be live under --live-agents is reaped, while the clean/pushed
# guards still protect dirty and unpushed ones.
for pair in idle:fix-5 idledirty:fix-6; do
  id="${pair%%:*}"; br="${pair##*:}"
  git -C "$G" branch "$br" main
  git -C "$G" push -q origin "$br"
  git -C "$G" worktree add -q "$G/ai/worktrees/agent-$id" "$br"
done
printf 'wip\n' > "$G/ai/worktrees/agent-idledirty/wip.txt"
git -C "$G/ai/worktrees/agent-idledirty" add wip.txt
LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$G" call step_g_fix_round_worktrees >/dev/null 2>&1
assert "STEP G with an empty live set (--no-live-workers) reaps a finished fix-<PR> worktree, including one whose id was live in the earlier run -- otherwise idle-state ticks leave fix worktrees forever" \
  "$([ ! -d "$G/ai/worktrees/agent-idle" ] && [ ! -d "$G/ai/worktrees/agent-live" ] && echo 1 || echo 0)"
assert "...but an empty live set still keeps a dirty worktree -- waiving liveness must not waive the uncommitted-work guard" \
  "$([ -d "$G/ai/worktrees/agent-idledirty" ] && echo 1 || echo 0)"
assert "...and still keeps a worktree with unpushed commits" \
  "$([ -d "$G/ai/worktrees/agent-unpushed" ] && echo 1 || echo 0)"

# A worktree whose removal fails (locked) must not abort the step: later
# worktrees are still reaped and the failure surfaces as a nonzero rc.
for pair in aaalocked:fix-7 zzafter:fix-8; do
  id="${pair%%:*}"; br="${pair##*:}"
  git -C "$G" branch "$br" main
  git -C "$G" push -q origin "$br"
  git -C "$G" worktree add -q "$G/ai/worktrees/agent-$id" "$br"
done
git -C "$G" worktree lock "$G/ai/worktrees/agent-aaalocked"
G_RC=0
LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$G" call step_g_fix_round_worktrees >/dev/null 2>&1 || G_RC=$?
assert "STEP G keeps going after a failed worktree remove -- one locked worktree must not strand every later fix-<PR> worktree" \
  "$([ ! -d "$G/ai/worktrees/agent-zzafter" ] && echo 1 || echo 0)"
assert "...keeps the locked worktree and its branch" \
  "$([ -d "$G/ai/worktrees/agent-aaalocked" ] && git -C "$G" rev-parse --verify -q refs/heads/fix-7 >/dev/null && echo 1 || echo 0)"
assert "...and returns nonzero so the failed removal counts as an anomaly" \
  "$([ "$G_RC" -ne 0 ] && echo 1 || echo 0)"

# A failing `git branch -D` after a successful remove (a stale ref lock stands
# in for any failure) must not abort the step either.
for pair in aaabranchfail:fix-9 zzafter2:fix-10; do
  id="${pair%%:*}"; br="${pair##*:}"
  git -C "$G" branch "$br" main
  git -C "$G" push -q origin "$br"
  git -C "$G" worktree add -q "$G/ai/worktrees/agent-$id" "$br"
done
git -C "$G" worktree unlock "$G/ai/worktrees/agent-aaalocked"
git -C "$G" worktree remove --force "$G/ai/worktrees/agent-aaalocked"
touch "$G/.git/refs/heads/fix-9.lock"
G_RC=0
LIVE_AGENTS="" WORKTREE_HYGIENE_REPO_ROOT="$G" call step_g_fix_round_worktrees >/dev/null 2>&1 || G_RC=$?
assert "STEP G keeps going after a failed branch delete -- one undeletable branch must not strand every later fix-<PR> worktree" \
  "$([ ! -d "$G/ai/worktrees/agent-zzafter2" ] && echo 1 || echo 0)"
assert "...and returns nonzero so the failed branch delete counts as an anomaly" \
  "$([ "$G_RC" -ne 0 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# STEP H: main's audit status. A red main audit is otherwise invisible
# (the audit is non-blocking for PRs), so the verdict and exit code are what
# make the mayor notice.
# ---------------------------------------------------------------------------
FAIL_JSON='[{"databaseId":42,"conclusion":"failure","url":"https://example.test/runs/42"}]'
assert "audit_verdict: a success conclusion is ok" \
  "$([ "$(call audit_verdict '[{"conclusion":"success"}]')" = ok ] && echo 1 || echo 0)"
assert "audit_verdict: a failure conclusion is failing (the whole point: a red main audit must not read as ok)" \
  "$([ "$(call audit_verdict "$FAIL_JSON")" = failing ] && echo 1 || echo 0)"
assert "audit_verdict: a cancelled run is unknown, not failing -- a manual cancel must not raise a false red-audit alert" \
  "$([ "$(call audit_verdict '[{"conclusion":"cancelled"}]')" = unknown ] && echo 1 || echo 0)"
assert "audit_verdict: a skipped run is unknown, not failing" \
  "$([ "$(call audit_verdict '[{"conclusion":"skipped"}]')" = unknown ] && echo 1 || echo 0)"
assert "audit_verdict: a cancelled newest run over an older failure is still failing -- a cancel must not mask a red audit" \
  "$([ "$(call audit_verdict '[{"conclusion":"cancelled"},{"conclusion":"failure"}]')" = failing ] && echo 1 || echo 0)"
assert "audit_verdict: a cancelled newest run over an older success is ok -- a cancel must not raise a false alert" \
  "$([ "$(call audit_verdict '[{"conclusion":"cancelled"},{"conclusion":"success"}]')" = ok ] && echo 1 || echo 0)"
assert "audit_verdict: timed_out is failing -- an audit that cannot complete is as actionable as a red one" \
  "$([ "$(call audit_verdict '[{"conclusion":"timed_out"}]')" = failing ] && echo 1 || echo 0)"
assert "audit_verdict: startup_failure is failing -- a broken audit workflow must not read as healthy" \
  "$([ "$(call audit_verdict '[{"conclusion":"startup_failure"}]')" = failing ] && echo 1 || echo 0)"
assert "audit_verdict: all-cancelled history is unknown, nothing decisive to judge" \
  "$([ "$(call audit_verdict '[{"conclusion":"cancelled"},{"conclusion":"skipped"},{"conclusion":"neutral"}]')" = unknown ] && echo 1 || echo 0)"
assert "audit_verdict: an empty run list is unknown, not failing" \
  "$([ "$(call audit_verdict '[]')" = unknown ] && echo 1 || echo 0)"
assert "audit_verdict: garbage input is unknown, not failing" \
  "$([ "$(call audit_verdict 'not json')" = unknown ] && echo 1 || echo 0)"

STUB_GH_AUDIT="$SANDBOX_ROOT/stub-gh-audit"
mkdir -p "$STUB_GH_AUDIT"
cat > "$STUB_GH_AUDIT/gh" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
  "run list")
    [ -n "${STUB_AUDIT_LIST_FAIL:-}" ] && exit 1
    printf '%s' "${STUB_AUDIT_JSON:-}" ;;
  "run view") echo "error: RUSTSEC-2026-0001 found; also GHSA-abcd-1234-wxyz and RUSTSEC-2026-0001" ;;
esac
exit 0
EOF
chmod +x "$STUB_GH_AUDIT/gh"

H_OUT=$(PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON="$FAIL_JSON" bash "$SCRIPT" __call step_h_main_audit 2>&1) && H_RC=0 || H_RC=$?
assert "STEP H returns 4 when main's audit failed, so the mayor tick sees a distinct code" \
  "$([ "$H_RC" -eq 4 ] && echo 1 || echo 0)"
assert "...and the alert carries the run URL and the deduplicated advisory ids" \
  "$(echo "$H_OUT" | grep -q 'https://example.test/runs/42' && echo "$H_OUT" | grep -q 'GHSA-abcd-1234-wxyz' && [ "$(echo "$H_OUT" | grep -o 'RUSTSEC-2026-0001' | wc -l)" -eq 1 ] && echo 1 || echo 0)"

H_OUT=$(PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON='[{"databaseId":50,"conclusion":"cancelled","url":"https://example.test/runs/50"},{"databaseId":42,"conclusion":"timed_out","createdAt":"2026-01-02T03:04:05Z","url":"https://example.test/runs/42"}]' bash "$SCRIPT" __call step_h_main_audit 2>&1) && H_RC=0 || H_RC=$?
assert "STEP H alert names the decisive run (id, conclusion, created time, URL), not the cancelled newest one" \
  "$([ "$H_RC" -eq 4 ] && echo "$H_OUT" | grep -q 'run 42 timed_out at 2026-01-02T03:04:05Z: https://example.test/runs/42' && echo 1 || echo 0)"

H_RC=0
PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON='[{"conclusion":"success"}]' bash "$SCRIPT" __call step_h_main_audit >/dev/null 2>&1 || H_RC=$?
assert "STEP H returns 0 when main's audit is green" \
  "$([ "$H_RC" -eq 0 ] && echo 1 || echo 0)"

H_RC=0
H_OUT=$(PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_LIST_FAIL=1 bash "$SCRIPT" __call step_h_main_audit 2>&1) || H_RC=$?
assert "STEP H returns 0 with a warning when gh errors -- an offline tick must not be reported as a failing audit" \
  "$([ "$H_RC" -eq 0 ] && echo "$H_OUT" | grep -q 'WARNING' && echo 1 || echo 0)"

H_RC=0
PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON='[]' bash "$SCRIPT" __call step_h_main_audit >/dev/null 2>&1 || H_RC=$?
assert "STEP H returns 0 when there is no completed audit run yet" \
  "$([ "$H_RC" -eq 0 ] && echo 1 || echo 0)"

# End to end: the destructive-step guards (the refusal, the live-agent
# sets) must not hide the audit result, in either live-set mode.
H_RC=0
DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_MAIN" PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON="$FAIL_JSON" \
  bash "$SCRIPT" --no-live-workers >/dev/null 2>&1 || H_RC=$?
assert "main() exits with the audit bit (4) under --no-live-workers when main's audit failed" \
  "$([ "$H_RC" -eq 4 ] && echo 1 || echo 0)"
H_RC=0
DRY_RUN=1 WORKTREE_HYGIENE_REPO_ROOT="$NLW_MAIN" PATH="$STUB_GH_AUDIT:$PATH" STUB_AUDIT_JSON="$FAIL_JSON" \
  bash "$SCRIPT" --live-agents someagent >/dev/null 2>&1 || H_RC=$?
assert "main() exits with the audit bit (4) under --live-agents when main's audit failed" \
  "$([ "$H_RC" -eq 4 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
