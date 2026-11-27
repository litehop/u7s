#!/usr/bin/env bash
# Mayor review demands namespace-cleanup evidence from a --focus run. `sonobuoy
# delete` prints nothing when no previous run exists, so 06-run-sonobuoy.sh logs
# the line itself, but only when the sonobuoy namespace is verifiably gone -- a
# line printed unconditionally would be false evidence. The real function is
# extracted from the real script and run against a kubectl stub.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/conformance/06-run-sonobuoy.sh"

PASS=0
FAIL=0
check() {
  if [ "$2" = "$3" ]; then echo "PASS: $1"; PASS=$(( PASS + 1 )); else echo "FAIL: $1 (got '$3', want '$2')"; FAIL=$(( FAIL + 1 )); fi
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
sed -n '/^log_sonobuoy_namespace_gone() {/,/^}/p' "$SCRIPT" > "$T/fn.sh"
[ -s "$T/fn.sh" ] || { echo "FAIL: log_sonobuoy_namespace_gone not found in $SCRIPT"; exit 1; }

mkdir "$T/bin"
# MODE=present: namespace exists; notfound: API says NotFound; down: connection refused.
cat > "$T/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
case "$MODE" in
  present) echo "NAME      STATUS   AGE"; exit 0 ;;
  notfound) echo 'Error from server (NotFound): namespaces "sonobuoy" not found' >&2; exit 1 ;;
  down) echo 'The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?' >&2; exit 1 ;;
esac
STUB
chmod +x "$T/bin/kubectl"

run() {
  PATH="$T/bin:$PATH" MODE="$1" KUBECONFIG=/dev/null \
    bash -c "source '$T/fn.sh'; log_sonobuoy_namespace_gone"
}

check "logs the cleanup line only when the API reports NotFound (also when no previous run existed)" \
  'Namespace "sonobuoy" has been deleted' "$(run notfound)"
check "API failure warns instead of claiming deletion -- an unreachable API is not evidence the namespace is gone" \
  'WARN: could not verify sonobuoy namespace deletion: The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?' "$(run down)"
check "logs nothing while the sonobuoy namespace still exists -- false evidence would hide a stuck cleanup" \
  "" "$(run present)"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
