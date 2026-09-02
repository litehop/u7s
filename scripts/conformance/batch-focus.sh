#!/usr/bin/env bash
# Batch-bisection spec runner — productized from a prior debugging spike.
#
# Problem: a full `--focus` sonobuoy run (06-run-sonobuoy.sh) re-applies
# manifests, waits for the aggregator, and tears down a fresh namespace per
# spec — 10+ min even for a slim focus, and a single crashing/hanging spec
# aborts the WHOLE run with no per-spec signal (a crashed ginkgo proc writes
# no junit at all). This script instead brings up ONE long-lived
# debug Pod (the same conformance image, `sleep infinity`) and drives
# /usr/local/bin/e2e.test directly via `kubectl exec`, split into small
# batches of exactly-anchored spec regexes. Per batch is a few seconds of
# exec overhead instead of a fresh sonobuoy plugin lifecycle, so a crashing
# batch is identified (by name, from --batch-size down to 1 if needed) in
# minutes instead of aborting a 30-40min run with no signal at all.
#
# Ground-truth mechanics (verified live against registry.k8s.io/conformance
# :v1.36.4 on a real u7s stack, not reconstructed from memory):
#
#   1. `/usr/local/bin/e2e.test -list-tests` prints every spec's full name
#      (already correctly space-joined, empty container-hierarchy entries
#      already filtered — see below) with NO cluster contact and NO
#      --json-report involved at all. This obsoletes the "ContainerHierarchy
#      Texts empty-string-join" fix the spike needed: that fix reconstructed
#      full names by hand from a --json-report dry run, which is exactly the
#      pipeline -list-tests already does correctly for us. Verified: a spec
#      whose JSON ContainerHierarchyTexts contains a "" entry (e.g. the
#      csi-hostpath snapshottable specs) round-trips through -list-tests with
#      a single space, not the double space a naive join would produce.
#
#   2. Ginkgo's `--focus` matches against "Kubernetes e2e suite " + the
#      space-joined spec text — NOT the spec text alone. `--focus=
#      '^\[sig-storage\]...'` (anchored, no suite-title prefix) reproducibly
#      matched ZERO specs live; the identical pattern with `^Kubernetes e2e
#      suite ` prepended matched exactly 1. This is undocumented in any
#      cached research and is the reason each spec below is anchored as
#      `^Kubernetes e2e suite <escaped-full-name>$` rather than the bare name
#      — an exact per-spec anchor is what makes batch membership exact (no
#      accidental cross-matches, no silently-oversized batches).
#
#   3. e2e.test's OWN `--ginkgo.parallel.total` defaults to 1 (serial) when
#      the binary is invoked directly — the separate `ginkgo` CLI binary is
#      only needed to fan out to procs>1. Since the whole point of this tool
#      is per-spec attribution (matching the spike's --procs=1 crash-hunting
#      mode), invoking e2e.test directly skips the ginkgo CLI wrapper
#      entirely, which in turn sidesteps the spike's "--json-report
#      filepath.Join path-mangling" gotcha completely (that bug is in the
#      ginkgo CLI's suite-relative path handling; we never invoke it, and we
#      never pass --json-report to a real batch run either way, per the
#      spike's own recommendation to parse the plain stdout Ran/SUCCESS!/
#      FAIL! block instead).
#
# Refinements folded in from the spike:
#   - Namespace-TTL watchdog (a real sonobuoy run has one; this harness's
#     prototype omitted it, and the spike's own leaked-namespace incident is
#     exactly why omitting it is unsafe).
#   - --json-report dropped entirely (see point 3 above).
#   - The ContainerHierarchyTexts empty-string-join bug is obsoleted, not
#     reimplemented — see point 1 above.
set -euo pipefail

VM_NAME="${U7S_VM_NAME:-lima-node}"
PORT="${U7S_PORT:-6443}"
WORKDIR="$PWD/temp/u7s"
FOCUS=""
SKIP=""
BATCH_SIZE=12
TIMEOUT="5m"
POD_NAME="batch-focus"
KEEP_POD=0
LIST_ONLY=0
IMAGE="registry.k8s.io/conformance:v1.36.4"

usage() {
  cat <<'EOF'
Usage: scripts/conformance/batch-focus.sh --focus <regex> [options]

Runs a --focus suite in small serial batches against one long-lived debug
Pod, instead of a full sonobuoy plugin lifecycle per spec. Use this to
bisect which spec in a suite hangs or crashes.

Required:
  --focus <regex>       grep -E pattern selecting the spec pool to bisect
                         (matched against `e2e.test -list-tests` output),
                         e.g. --focus csi-hostpath or --focus '\[Conformance\]'

Options:
  --skip <regex>        grep -E pattern excluding specs from the pool
  --batch-size <N>      specs per batch (default: 12)
  --timeout <duration>  per-batch ginkgo timeout, e.g. 5m (default: 5m)
  --vm <name>           lima VM (default: lima-node, or $U7S_VM_NAME)
  --port <port>         apiserver host port (default: 6443, or $U7S_PORT)
  --workdir <path>      cluster state dir (default: $PWD/temp/u7s)
  --pod-name <name>     debug pod/configmap name (default: batch-focus)
  --keep-pod            reuse an existing Running pod; skip final cleanup
  --list-only           print the batch plan (spec names per batch) and exit
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus) FOCUS="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    --batch-size) BATCH_SIZE="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --vm) VM_NAME="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --pod-name) POD_NAME="$2"; shift 2 ;;
    --keep-pod) KEEP_POD=1; shift ;;
    --list-only) LIST_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

echo "=== Batch-bisection focus runner ==="

if [ -z "$FOCUS" ]; then
  echo "error: --focus is required" >&2
  usage >&2
  exit 1
fi
case "$BATCH_SIZE" in
  ''|*[!0-9]*|0) echo "error: --batch-size must be a positive integer, got '$BATCH_SIZE'" >&2; exit 1 ;;
esac
if ! command -v limactl &>/dev/null; then
  echo "error: limactl not found — install with: brew install lima" >&2; exit 1
fi

KUBECONFIG="${KUBECONFIG:-$WORKDIR/kubeconfig}"
if [ ! -f "$KUBECONFIG" ]; then
  echo "error: kubeconfig not found at $KUBECONFIG — start u7s first (run-all.sh --stack-only)" >&2
  exit 1
fi
if ! kubectl --kubeconfig="$KUBECONFIG" get nodes -o name 2>/dev/null | grep -Fxq "node/$VM_NAME"; then
  echo "error: $VM_NAME not registered — run scripts/conformance/run-all.sh --stack-only first" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Spec enumeration — no cluster contact, no --json-report (see file header
# point 1). -list-tests emits "<file>:<line>: <full spec name>"; strip the
# location prefix by cutting at the FIRST colon-run (file paths here never
# contain a colon, so this can't accidentally truncate a spec name that
# happens to contain "word: word" later in its own text, e.g. "[Driver:
# csi-hostpath]").
# ---------------------------------------------------------------------------
ALL_SPECS=$(mktemp)
MATCHED_SPECS=$(mktemp)
REWRITTEN=$(mktemp)
trap 'rm -f "$ALL_SPECS" "$MATCHED_SPECS" "$REWRITTEN"' EXIT

# ---------------------------------------------------------------------------
# Debug pod + kubeconfig ConfigMap. Lives in `default` (not a throwaway
# namespace) so the watchdog below — which reaps everything except
# default/kube-*/sonobuoy — never reaps the harness out from under itself.
# ---------------------------------------------------------------------------
LIMA_HOST_IP=$(limactl shell "$VM_NAME" getent hosts host.lima.internal 2>/dev/null | awk '{print $1}')
if [ -z "$LIMA_HOST_IP" ]; then
  echo "error: could not resolve host.lima.internal inside ${VM_NAME} for the debug pod's hostAlias" >&2
  exit 1
fi

sed "s|https://127\.[0-9]*\.[0-9]*\.[0-9]*:[0-9]*|https://host.lima.internal:${PORT}|g" "$KUBECONFIG" > "$REWRITTEN"

kubectl --kubeconfig="$KUBECONFIG" create configmap "${POD_NAME}-kubeconfig" \
  --from-file=kubeconfig="$REWRITTEN" -n default \
  --dry-run=client -o yaml | kubectl --kubeconfig="$KUBECONFIG" apply -f - >/dev/null

POD_READY=0
if [ "$KEEP_POD" -eq 1 ]; then
  PHASE=$(kubectl --kubeconfig="$KUBECONFIG" get pod "$POD_NAME" -n default -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$PHASE" = "Running" ] && POD_READY=1
fi

if [ "$POD_READY" -eq 0 ]; then
  echo "Creating debug pod ${POD_NAME} (${IMAGE})..."
  kubectl --kubeconfig="$KUBECONFIG" delete pod "$POD_NAME" -n default --ignore-not-found --wait=true >/dev/null
  kubectl --kubeconfig="$KUBECONFIG" apply -f - >/dev/null <<PODEOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  namespace: default
  labels:
    app: batch-focus
spec:
  hostAliases:
  - ip: "${LIMA_HOST_IP}"
    hostnames: ["host.lima.internal"]
  priorityClassName: system-cluster-critical
  tolerations:
  - operator: Exists
  restartPolicy: Never
  containers:
  - name: e2e
    image: ${IMAGE}
    command: ["sleep", "infinity"]
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
    volumeMounts:
    - name: kubeconfig
      mountPath: /tmp/kubeconfig-dir
  volumes:
  - name: kubeconfig
    configMap:
      name: ${POD_NAME}-kubeconfig
PODEOF
  for _ in $(seq 1 30); do
    PHASE=$(kubectl --kubeconfig="$KUBECONFIG" get pod "$POD_NAME" -n default -o jsonpath='{.status.phase}' 2>/dev/null || true)
    [ "$PHASE" = "Running" ] && break
    sleep 2
  done
  if [ "$PHASE" != "Running" ]; then
    echo "error: ${POD_NAME} did not reach Running (phase=$PHASE)" >&2
    kubectl --kubeconfig="$KUBECONFIG" describe pod "$POD_NAME" -n default >&2 || true
    exit 1
  fi
fi

echo "Enumerating specs (e2e.test -list-tests, no cluster contact)..."
kubectl --kubeconfig="$KUBECONFIG" exec "$POD_NAME" -n default -- /usr/local/bin/e2e.test -list-tests > "$ALL_SPECS" 2>&1
tail -n +2 "$ALL_SPECS" | sed -E 's/^[^:]+:[0-9]+: //' > "${ALL_SPECS}.names"

grep -E "$FOCUS" "${ALL_SPECS}.names" > "$MATCHED_SPECS" || true
if [ -n "$SKIP" ]; then
  grep -vE "$SKIP" "$MATCHED_SPECS" > "${MATCHED_SPECS}.tmp" || true
  mv "${MATCHED_SPECS}.tmp" "$MATCHED_SPECS"
fi
rm -f "${ALL_SPECS}.names"

TOTAL=$(wc -l < "$MATCHED_SPECS" | tr -d ' ')
if [ "$TOTAL" -eq 0 ]; then
  echo "error: --focus '$FOCUS' matched 0 specs (skip: '${SKIP:-none}')" >&2
  echo "  Note: this is a plain grep -E match against -list-tests output — remember to" >&2
  echo "  escape sig-tag brackets, e.g. --focus '\\[sig-storage\\]', not --focus '[sig-storage]'." >&2
  exit 1
fi
NUM_BATCHES=$(( (TOTAL + BATCH_SIZE - 1) / BATCH_SIZE ))
echo "Matched $TOTAL specs for focus '$FOCUS' -> $NUM_BATCHES batch(es) of up to $BATCH_SIZE."

# Escapes ERE/RE2 metacharacters so a spec's own regex matches ONLY itself —
# without this, e.g. the literal parens in "(block volmode)" would be
# mis-parsed as a capture group.
escape_spec() {
  printf '%s' "$1" | sed -E 's/(\]|\[|\.|\^|\$|\*|\+|\?|\(|\)|\{|\}|\||\\)/\\\1/g'
}

if [ "$LIST_ONLY" -eq 1 ]; then
  BATCH_NUM=0
  START=1
  while [ "$START" -le "$TOTAL" ]; do
    BATCH_NUM=$((BATCH_NUM + 1))
    END=$((START + BATCH_SIZE - 1))
    [ "$END" -gt "$TOTAL" ] && END=$TOTAL
    echo "--- batch $BATCH_NUM/$NUM_BATCHES (specs $START-$END) ---"
    sed -n "${START},${END}p" "$MATCHED_SPECS"
    START=$((END + 1))
  done
  exit 0
fi

# ---------------------------------------------------------------------------
# Namespace TTL watchdog — mirrors 06-run-sonobuoy.sh's watchdog_loop
# verbatim (same 10m Active / 15m any-phase thresholds; DO NOT change them,
# see bd memory watchdog-thresholds-are-final-do-not-raise). A real sonobuoy
# run has this; the 4t2c9 spike's prototype omitted it and hit exactly the
# failure mode it exists to prevent — a namespace a crashing spec never
# cleaned up starving every later batch's own namespace-scoped waits.
# ---------------------------------------------------------------------------
watchdog_loop() {
  local kubeconfig="$1"
  while true; do
    sleep 30
    local now
    now=$(date -u +%s)
    local ns_json
    ns_json=$(kubectl --kubeconfig="$kubeconfig" get ns -o json 2>/dev/null) || continue
    while IFS= read -r line; do
      local ns phase created age_s
      ns=$(     printf '%s' "$line" | jq -r '.name')
      phase=$(  printf '%s' "$line" | jq -r '.phase')
      created=$(printf '%s' "$line" | jq -r '.created')
      case "$ns" in
        default|sonobuoy|kube-*) continue ;;
      esac
      if [[ "$ns" =~ ^(.+-[0-9]+)-[0-9]+$ ]]; then
        local parent_ns="${BASH_REMATCH[1]}"
        if kubectl --kubeconfig="$kubeconfig" get ns "$parent_ns" >/dev/null 2>&1; then
          continue
        fi
      fi
      local created_s
      created_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "${created}" "+%s" 2>/dev/null) || continue
      age_s=$(( now - created_s ))
      local should_delete=0 reason=""
      if [ "$phase" = "Active" ] && [ "$age_s" -ge 600 ]; then
        should_delete=1
        reason="Active for ${age_s}s (>= 10m threshold)"
      elif [ "$age_s" -ge 900 ]; then
        should_delete=1
        reason="age=${age_s}s (>= 15m threshold, phase=${phase})"
      fi
      if [ "$should_delete" -eq 1 ]; then
        echo "[watchdog] $(date -u +%Y-%m-%dT%H:%M:%SZ) force-deleting namespace '${ns}' (${reason})"
        kubectl --kubeconfig="$kubeconfig" patch ns "$ns" \
          -p '{"spec":{"finalizers":[]}}' --type=merge 2>/dev/null || true
        kubectl --kubeconfig="$kubeconfig" delete ns "$ns" \
          --grace-period=0 --force 2>/dev/null || true
      fi
    done < <(printf '%s' "$ns_json" \
      | jq -c '.items[] | {name: .metadata.name, phase: .status.phase, created: .metadata.creationTimestamp}')
  done
}

_WATCHDOG_PID=""
cleanup() {
  [ -n "$_WATCHDOG_PID" ] && kill "$_WATCHDOG_PID" 2>/dev/null || true
  rm -f "$ALL_SPECS" "$MATCHED_SPECS" "$REWRITTEN"
  if [ "$KEEP_POD" -eq 0 ]; then
    kubectl --kubeconfig="$KUBECONFIG" delete pod "$POD_NAME" -n default --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl --kubeconfig="$KUBECONFIG" delete configmap "${POD_NAME}-kubeconfig" -n default --ignore-not-found >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

watchdog_loop "$KUBECONFIG" &
_WATCHDOG_PID=$!
echo "[watchdog] started (pid=${_WATCHDOG_PID})"

TIMESTAMP=$(date -u +%m%d-%H%M)
FOCUS_SLUG=$(echo "$FOCUS" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//')
LOG_DIR="$WORKDIR/../e2e/batch-focus-${TIMESTAMP}-${FOCUS_SLUG}"
mkdir -p "$LOG_DIR"
echo "Per-batch logs: $LOG_DIR"

WORST_EXIT=0
BATCH_NUM=0
START=1
while [ "$START" -le "$TOTAL" ]; do
  BATCH_NUM=$((BATCH_NUM + 1))
  END=$((START + BATCH_SIZE - 1))
  [ "$END" -gt "$TOTAL" ] && END=$TOTAL
  # `mapfile`/`readarray` are bash 4+ only — macOS ships bash 3.2 (GPLv2-only
  # license cutoff) as the only `bash` on PATH, so build the array by hand.
  BATCH_SPECS=()
  while IFS= read -r spec_line; do
    BATCH_SPECS+=("$spec_line")
  done < <(sed -n "${START},${END}p" "$MATCHED_SPECS")

  BATCH_FOCUS=""
  for spec in "${BATCH_SPECS[@]}"; do
    esc=$(escape_spec "$spec")
    if [ -z "$BATCH_FOCUS" ]; then
      BATCH_FOCUS="^Kubernetes e2e suite ${esc}\$"
    else
      BATCH_FOCUS="${BATCH_FOCUS}|^Kubernetes e2e suite ${esc}\$"
    fi
  done

  BATCH_LOG="$LOG_DIR/batch-${BATCH_NUM}.log"
  BATCH_EXIT=0
  kubectl --kubeconfig="$KUBECONFIG" exec "$POD_NAME" -n default -- /usr/local/bin/e2e.test \
    --ginkgo.focus="$BATCH_FOCUS" \
    --ginkgo.no-color \
    --ginkgo.silence-skips \
    --ginkgo.output-interceptor-mode=none \
    --ginkgo.timeout="$TIMEOUT" \
    -disable-log-dump=true \
    -kubeconfig=/tmp/kubeconfig-dir/kubeconfig \
    > "$BATCH_LOG" 2>&1 || BATCH_EXIT=$?

  SUMMARY=$(grep -E "^(Ran |SUCCESS!|FAIL!)" "$BATCH_LOG" | tr '\n' ' ')
  echo "[batch $BATCH_NUM/$NUM_BATCHES] specs=${#BATCH_SPECS[@]} exit=$BATCH_EXIT ${SUMMARY:-<no summary line — see $BATCH_LOG>}"
  if [ "$BATCH_EXIT" -eq 2 ]; then
    echo "  *** CRASH (exit 2) — likely an unrecovered panic. Log: $BATCH_LOG ***"
    echo "  Suspect specs in this batch:"
    printf '    - %s\n' "${BATCH_SPECS[@]}"
    tail -20 "$BATCH_LOG" | sed 's/^/  | /'
  fi
  [ "$BATCH_EXIT" -gt "$WORST_EXIT" ] && WORST_EXIT=$BATCH_EXIT

  START=$((END + 1))
done

echo "=== Done: $NUM_BATCHES batch(es), $TOTAL specs, worst exit=$WORST_EXIT ==="
exit "$WORST_EXIT"
