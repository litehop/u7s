#!/usr/bin/env bash
# Unit test for scripts/conformance/lima-start.sh's golden-clone branch
# selection: it must clone lima-golden only when the template is in a
# *usable* (Stopped) state.
#
# `limactl clone` only refuses a Running source -- a golden left
# Broken/Installing/Uninitialized by a failed bake is NOT blocked by a
# directory-existence check alone. Before this test's fix, that state
# would still be silently cloned into a broken worker VM instead of
# falling back to a fresh `limactl start` provision. If the status gate
# is ever removed or loosened back to a directory-existence check, this
# test must fail.
#
# Exercises the REAL lima-start.sh as a subprocess against stubbed
# `limactl`/`kubectl` on PATH (no real VM/lima install, no live apiserver
# needed). The script legitimately aborts shortly after the provisioning
# decision (this fake workdir has no ca.crt, so the konnectivity-agent
# cert step's real `openssl` call fails) -- that's fine, the branch
# decision and the resulting limactl invocation both happen well before
# that point, which is all this test asserts on.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/scripts/conformance/lima-start.sh"

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

# Stubs `limactl` and `kubectl` on PATH: records every limactl invocation to
# $LIMACTL_LOG and fakes just enough for lima-start.sh to reach and act on
# its golden-clone decision. $GOLDEN_STATUS controls what `list` reports for
# lima-golden. Every subcommand exits 0 (including unhandled ones) so the
# script proceeds past this decision instead of aborting on a stub gap --
# it aborts naturally a bit later (missing ca.crt), which this test doesn't
# care about.
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
    for arg in "$@"; do
      case "$arg" in
        --name=*) mkdir -p "$HOME/.lima/${arg#--name=}" ;;
      esac
    done
    ;;
  clone)
    mkdir -p "$HOME/.lima/$3"
    ;;
esac
exit 0
STUB
  cat > "$bindir/kubectl" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "$bindir/limactl" "$bindir/kubectl"
}

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

STUBBIN="$WORKDIR/bin"
setup_stub_bin "$STUBBIN"
export PATH="$STUBBIN:$PATH"
export LIMACTL_LOG="$WORKDIR/limactl.log"

run_lima_start() {
  # --workdir also becomes the kubeconfig dir (find_kubeconfig requires the
  # file to already exist); a fake, unused, high port pair avoids colliding
  # with anything a real run might have bound on this machine.
  local rundir="$1"
  mkdir -p "$rundir"
  : > "$rundir/kubeconfig"
  set +e
  bash "$SCRIPT" --vm test-clone-vm --workdir "$rundir" \
    --port 19999 --kubelet-port 19998 >/dev/null 2>&1
  set -e
}

# ---------------------------------------------------------------------------
# 1. No golden at all -> fresh-provision path (limactl start), never clone.
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-absent"
mkdir -p "$HOME"
run_lima_start "$WORKDIR/run-absent"
assert "no golden: lima-start.sh provisions fresh (limactl start invoked)" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 1 || echo 0)"
assert "no golden: lima-start.sh never clones" \
  "$(grep -q '^clone ' "$LIMACTL_LOG" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 2. Golden present and Stopped (the only state limactl clone can actually
#    use) -> golden-clone path.
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-stopped"
mkdir -p "$HOME/.lima/lima-golden"
export GOLDEN_STATUS="Stopped"
run_lima_start "$WORKDIR/run-stopped"
assert "stopped golden: lima-start.sh clones it (limactl clone invoked)" \
  "$(grep -q '^clone lima-golden test-clone-vm' "$LIMACTL_LOG" && echo 1 || echo 0)"
assert "stopped golden: lima-start.sh does not fresh-provision" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 3. Golden present but Broken (e.g. an interrupted/failed bake) -> must
#    fall back to fresh-provision, NOT clone a broken template into a new
#    worker VM. This is the regression case for the directory-existence-only
#    bug: before the Stopped-status gate, this scenario wrongly cloned.
# ---------------------------------------------------------------------------
: > "$LIMACTL_LOG"
export HOME="$WORKDIR/home-broken"
mkdir -p "$HOME/.lima/lima-golden"
export GOLDEN_STATUS="Broken"
run_lima_start "$WORKDIR/run-broken"
assert "broken golden: lima-start.sh falls back to fresh-provision (limactl start invoked)" \
  "$(grep -q '^start ' "$LIMACTL_LOG" && echo 1 || echo 0)"
assert "broken golden: lima-start.sh does not clone a broken template" \
  "$(grep -q '^clone ' "$LIMACTL_LOG" && echo 0 || echo 1)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
