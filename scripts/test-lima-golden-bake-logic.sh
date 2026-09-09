#!/usr/bin/env bash
# Unit test for scripts/conformance/lima-golden-bake.sh's idempotency logic.
#
# The whole point of baking a golden template once is that re-running the
# bake script is safe and cheap: a healthy already-stopped golden must be a
# no-op (never re-provision, which costs ~9min), a golden left Running from
# an interrupted prior bake must just get stopped (never re-provisioned from
# scratch), and --force must delete-then-reprovision on demand. If any of
# these regress, an operator re-running the bake script "just to be safe"
# either eats an unnecessary 9min reprovision or leaves the golden in the
# wrong state for scripts/conformance/lima-start.sh's clone path to use.
#
# Exercises the REAL lima-golden-bake.sh as a subprocess against a stubbed
# `limactl` on PATH (no real VM/lima install needed) and a temp $HOME so the
# script's `~/.lima/lima-golden` existence check is fully test-controlled.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/conformance/lima-golden-bake.sh"

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

# Stubs `limactl` on PATH: records every invocation to $LIMACTL_LOG and fakes
# just enough of `list`/`start`/`stop`/`delete` for the bake script to run to
# completion without a real lima install. $GOLDEN_STATUS controls what `list`
# reports for lima-golden.
setup_stub_bin() {
  local bindir="$1"
  mkdir -p "$bindir"
  cat > "$bindir/limactl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$LIMACTL_LOG"
case "$1" in
  list)
    echo "lima-golden ${GOLDEN_STATUS:-Stopped}"
    ;;
  start)
    # Mirror real limactl: --name=X creates ~/.lima/X.
    for arg in "$@"; do
      case "$arg" in
        --name=*) mkdir -p "$HOME/.lima/${arg#--name=}" ;;
      esac
    done
    ;;
  delete)
    shift
    for arg in "$@"; do
      case "$arg" in
        --*) ;;
        *) rm -rf "$HOME/.lima/$arg" ;;
      esac
    done
    ;;
  stop)
    :
    ;;
esac
exit 0
STUB
  chmod +x "$bindir/limactl"
}

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

STUBBIN="$WORKDIR/bin"
setup_stub_bin "$STUBBIN"
export PATH="$STUBBIN:$PATH"
export LIMACTL_LOG="$WORKDIR/limactl.log"

# ---------------------------------------------------------------------------
# 1. No golden yet -> must provision (limactl start) then stop, never skip.
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-absent"
mkdir -p "$HOME"
bash "$SCRIPT" >/dev/null 2>&1
assert "absent golden: bake script provisions it (limactl start invoked)" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 1 || echo 0)"
assert "absent golden: bake script stops it after provisioning (limactl stop invoked)" \
  "$(grep -q '^stop ' "$LIMACTL_LOG" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 2. Already-baked (Stopped) golden -> no-op. A re-provision here would waste
#    ~9min on every operator who runs this "just to check".
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-stopped"
mkdir -p "$HOME/.lima/lima-golden"
export GOLDEN_STATUS="Stopped"
OUT=$(bash "$SCRIPT" 2>&1)
assert "stopped golden: bake script is a no-op (no limactl start)" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 0 || echo 1)"
assert "stopped golden: bake script reports nothing to do" \
  "$(echo "$OUT" | grep -qF "nothing to do" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 3. Golden left Running (e.g. an interrupted prior bake) -> must stop it,
#    not re-provision from scratch (the disk state is already correct).
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-running"
mkdir -p "$HOME/.lima/lima-golden"
export GOLDEN_STATUS="Running"
bash "$SCRIPT" >/dev/null 2>&1
assert "running golden: bake script stops it without re-provisioning" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 0 || echo 1)"
assert "running golden: bake script issues limactl stop" \
  "$(grep -q '^stop ' "$LIMACTL_LOG" && echo 1 || echo 0)"

# ---------------------------------------------------------------------------
# 4. --force with an existing golden -> delete then re-provision, the
#    operator's only lever to refresh a stale template (Phase E's automatic
#    staleness gate is deliberately out of scope here).
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-force"
mkdir -p "$HOME/.lima/lima-golden"
export GOLDEN_STATUS="Stopped"
bash "$SCRIPT" --force >/dev/null 2>&1
assert "--force: bake script deletes the existing golden" \
  "$(grep -q '^delete ' "$LIMACTL_LOG" && echo 1 || echo 0)"
assert "--force: bake script re-provisions after deleting" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 1 || echo 0)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
