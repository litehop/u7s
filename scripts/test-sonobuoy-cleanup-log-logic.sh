#!/usr/bin/env bash
# Mayor review demands namespace-cleanup evidence from a --focus run. `sonobuoy
# delete` prints nothing when no previous run exists, so 06-run-sonobuoy.sh logs
# the line itself once the sonobuoy namespace is verifiably gone. The real
# function is extracted from the real script and run against a kubectl stub.
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
sed -n '/^wait_sonobuoy_namespace_gone() {/,/^}/p' "$SCRIPT" > "$T/fn.sh"
[ -s "$T/fn.sh" ] || { echo "FAIL: wait_sonobuoy_namespace_gone not found in $SCRIPT"; exit 1; }

mkdir "$T/bin"
# The namespace exists for the first $EXISTS_CALLS lookups, then is gone.
cat > "$T/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
n=$(cat "$STATE" 2>/dev/null || echo 0)
echo $(( n + 1 )) > "$STATE"
[ "$n" -lt "$EXISTS_CALLS" ]
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/bin/sleep"
chmod +x "$T/bin/kubectl" "$T/bin/sleep"

run() {
  rm -f "$T/state"
  PATH="$T/bin:$PATH" STATE="$T/state" EXISTS_CALLS="$1" KUBECONFIG=/dev/null \
    bash -c "source '$T/fn.sh'; wait_sonobuoy_namespace_gone"
}

want='Namespace "sonobuoy" has been deleted'
check "logs the cleanup line when no previous run existed (namespace already gone)" "$want" "$(run 0)"
check "logs the cleanup line only after a draining namespace disappears" "$want" "$(run 3)"
check "kubectl was polled until the namespace was gone" "4" "$(cat "$T/state")"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
