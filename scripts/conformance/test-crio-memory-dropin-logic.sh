#!/usr/bin/env bash
# Unit test proving scripts/install.sh actually writes the cri-o
# stream_idle_timeout memory drop-in, and only that knob.
#
# stream_idle_timeout reaps idle exec/attach/logs/port-forward streaming
# connections' goroutines and buffers instead of holding them open for
# cri-o's 4h default -- the one real memory lever from the original
# memory-tuning proposal. log_size_max and log_level were operator-dropped
# from that proposal (log_size_max caps the on-disk log file, already
# enforced by kubelet --container-log-max-size -- zero memory benefit;
# log_level stays at current for debuggability), so this test also locks in
# that scoping: it must fail if either knob creeps back in without a
# matching decision.
#
# Exits 0 on success, 1 on any assertion failure.
set -euo pipefail

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

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO/scripts/install.sh"

assert "install.sh writes /etc/crio/crio.conf.d/10-memory.conf" \
  "$(grep -qF 'cat > /etc/crio/crio.conf.d/10-memory.conf' "$INSTALL_SH" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Ordering: the drop-in must land after crio.conf.d exists and before crio is
# restarted, or the restart won't pick it up.
# ---------------------------------------------------------------------------
# Each lookup is allowed to come back empty (no match) rather than aborting
# the whole script under set -e/pipefail -- a missing line must show up as a
# FAIL assertion below, not a silent early exit that skips every other check.
MKDIR_LINE=$( (grep -n '^mkdir -p /etc/crio/crio.conf.d$' "$INSTALL_SH" || true) | head -1 | cut -d: -f1)
DROPIN_LINE=$( (grep -n 'cat > /etc/crio/crio.conf.d/10-memory.conf' "$INSTALL_SH" || true) | head -1 | cut -d: -f1)
RESTART_LINE=$( (grep -n '^systemctl restart crio$' "$INSTALL_SH" || true) | head -1 | cut -d: -f1)

assert "drop-in write comes after 'mkdir -p /etc/crio/crio.conf.d'" \
  "$([ -n "$DROPIN_LINE" ] && [ -n "$MKDIR_LINE" ] && [ "$DROPIN_LINE" -gt "$MKDIR_LINE" ] && echo 1 || echo 0)"

assert "drop-in write comes before 'systemctl restart crio' so the restart picks it up" \
  "$([ -n "$DROPIN_LINE" ] && [ -n "$RESTART_LINE" ] && [ "$DROPIN_LINE" -lt "$RESTART_LINE" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Simulation: actually run install.sh's own heredoc write (extracted, not
# re-typed) against a scratch file, so this fails if the fix is reverted --
# either by deleting the write entirely or by changing what it writes.
# ---------------------------------------------------------------------------
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
DROPIN_FILE="$SCRATCH/10-memory.conf"

sed -n '/^cat > \/etc\/crio\/crio.conf.d\/10-memory.conf <<.CRIO_MEM_EOF.$/,/^CRIO_MEM_EOF$/p' "$INSTALL_SH" \
  | sed '1d;$d' > "$DROPIN_FILE"

assert "the extracted drop-in body is non-empty" \
  "$([ -s "$DROPIN_FILE" ] && echo 1 || echo 0)"

assert "the drop-in sets [crio.runtime] stream_idle_timeout = \"5m\" (the actual memory lever)" \
  "$(grep -qF 'stream_idle_timeout = "5m"' "$DROPIN_FILE" && echo 1 || echo 0)"

assert "stream_idle_timeout is scoped under [crio.runtime]" \
  "$(grep -qF '[crio.runtime]' "$DROPIN_FILE" && echo 1 || echo 0)"

assert "the drop-in has exactly two lines: [crio.runtime] then stream_idle_timeout (no stray knobs)" \
  "$([ "$(wc -l < "$DROPIN_FILE" | tr -d ' ')" = "2" ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# Operator scoping: log_size_max ([crio.image]) and log_level were dropped
# from the original proposal -- neither has a memory benefit worth the risk
# right now. If either reappears in this drop-in, that's a scope change that
# needs its own decision, not a silent re-add.
# ---------------------------------------------------------------------------
assert "log_size_max was operator-dropped (redundant with kubelet --container-log-max-size) and stays out" \
  "$(grep -qF 'log_size_max' "$DROPIN_FILE" && echo 0 || echo 1)"

assert "log_level was operator-dropped (kept at current for debuggability) and stays out" \
  "$(grep -qF 'log_level' "$DROPIN_FILE" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
