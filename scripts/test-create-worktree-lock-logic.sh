#!/usr/bin/env bash
# Guard: scripts/create-worktree.sh must serialize `git worktree add` across
# parallel harness dispatches and must not leave an orphan worker/<id> branch
# when the add fails. Runs against throwaway repos only.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_SCRIPT="$DIR/create-worktree.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
assert_true() {
  local label="$1"
  shift
  if "$@"; then echo "PASS: $label"; PASS=$(( PASS + 1 )); else echo "FAIL: $label"; FAIL=$(( FAIL + 1 )); fi
}

new_repo() {
  local r="$TMP/$1"
  mkdir -p "$r/.claude"
  git -C "$r" init -q
  echo '{}' > "$r/.claude/settings.json"
  git -C "$r" add .claude/settings.json
  git -C "$r" -c user.name=t -c user.email=t@t commit -q -m init
  echo "$r"
}

input_for() { printf '{"cwd":"%s","name":"%s"}' "$1" "$2"; }
not() { ! "$@"; }

# Hook that records start/end of the critical section; overlapping holders
# produce two "start" lines in a row.
cat > "$TMP/hook.sh" <<'EOF'
echo "start" >> "$OVERLAP_LOG"
sleep 0.3
echo "end" >> "$OVERLAP_LOG"
EOF

no_overlap() {
  [ "$(grep -c . "$1")" -eq "$2" ] && awk 'NR%2==1 && $0!="start" {exit 1} NR%2==0 && $0!="end" {exit 1}' "$1"
}

run_concurrent() { # script repo n -> sets CONC_FAILS
  local script="$1" repo="$2" n="$3" pids=() i
  : > "$TMP/overlap.log"
  for i in $(seq 1 "$n"); do
    input_for "$repo" "agent-$i" | OVERLAP_LOG="$TMP/overlap.log" \
      U7S_TEST_CRITICAL_SECTION_HOOK="bash $TMP/hook.sh" bash "$script" > "$TMP/out-$i" 2>&1 &
    pids+=("$!")
  done
  CONC_FAILS=0
  for p in "${pids[@]}"; do wait "$p" || CONC_FAILS=$((CONC_FAILS + 1)); done
}

N=8
repo=$(new_repo concurrent)
run_concurrent "$REAL_SCRIPT" "$repo" "$N"
assert_true "all $N concurrent creations succeed" [ "$CONC_FAILS" -eq 0 ]
assert_true "critical sections never overlap (else git reads half-written sibling admin dirs)" no_overlap "$TMP/overlap.log" $((2 * N))
assert_true "$N distinct worktrees registered" [ "$(git -C "$repo" worktree list | grep -c 'ai/worktrees/agent-')" -eq "$N" ]
assert_true "lock released afterwards" [ ! -e "$repo/.git/u7s-create-worktree.lock" ]
assert_true "stdout contract: last line is the worktree path" [ "$(tail -n1 "$TMP/out-1")" = "$repo/ai/worktrees/agent-1" ]
assert_true "settings.json synced into worktree" [ -f "$repo/ai/worktrees/agent-1/.claude/settings.json" ]

# Revert check: without the lock the overlap assertion must fail.
sed 's/^acquire_lock$/:/' "$REAL_SCRIPT" > "$TMP/nolock.sh"
assert_true "mutation copy really drops the lock call" not cmp -s "$TMP/nolock.sh" "$REAL_SCRIPT"
repo2=$(new_repo nolock)
run_concurrent "$TMP/nolock.sh" "$repo2" "$N"
assert_true "test detects the race when the lock is removed" not no_overlap "$TMP/overlap.log" $((2 * N))

# Failed add leaves no orphan branch: shim git creates the branch then fails the add.
repo3=$(new_repo failure)
mkdir -p "$TMP/shim"
REAL_GIT=$(command -v git)
cat > "$TMP/shim/git" <<EOF
#!/usr/bin/env bash
case " \$* " in *" worktree add "*) "$REAL_GIT" -C "\$2" branch "\$7" HEAD; exit 1;; esac
exec "$REAL_GIT" "\$@"
EOF
chmod +x "$TMP/shim/git"
rc=0
input_for "$repo3" agent-fail | PATH="$TMP/shim:$PATH" bash "$REAL_SCRIPT" > /dev/null 2>&1 || rc=$?
assert_true "failed add exits non-zero" [ "$rc" -ne 0 ]
assert_true "failed add leaves no orphan worker/agent-fail branch" [ -z "$(git -C "$repo3" branch --list 'worker/agent-fail')" ]
assert_true "lock released after failure" [ ! -e "$repo3/.git/u7s-create-worktree.lock" ]

# A pre-existing branch is not ours to delete.
git -C "$repo3" branch worker/agent-keep
rc=0
input_for "$repo3" agent-keep | bash "$REAL_SCRIPT" > /dev/null 2>&1 || rc=$?
assert_true "add onto an existing branch fails" [ "$rc" -ne 0 ]
assert_true "pre-existing branch survives the failure" [ -n "$(git -C "$repo3" branch --list 'worker/agent-keep')" ]

# Stale lock from a killed process must not deadlock.
repo4=$(new_repo stale)
sleep 0 & dead=$!
wait "$dead"
mkdir "$repo4/.git/u7s-create-worktree.lock"
echo "$dead" > "$repo4/.git/u7s-create-worktree.lock/pid"
rc=0
input_for "$repo4" agent-stale | U7S_CREATE_WORKTREE_LOCK_WAIT_SECS=5 bash "$REAL_SCRIPT" > /dev/null 2>&1 || rc=$?
assert_true "stale lock (dead owner pid) is reclaimed" [ "$rc" -eq 0 ]

# A live holder with no progress yields a bounded, clear failure.
repo5=$(new_repo live)
mkdir "$repo5/.git/u7s-create-worktree.lock"
echo "$$" > "$repo5/.git/u7s-create-worktree.lock/pid"
rc=0
input_for "$repo5" agent-live | U7S_CREATE_WORKTREE_LOCK_WAIT_SECS=1 bash "$REAL_SCRIPT" > "$TMP/live.out" 2>&1 || rc=$?
assert_true "live lock times out non-zero instead of hanging" [ "$rc" -ne 0 ]
assert_true "timeout message names the lock" grep -q 'timed out' "$TMP/live.out"

echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
