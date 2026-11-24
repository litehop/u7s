#!/usr/bin/env bash
# apiserver-hot-paths.sh — repeatable apiserver workload for before/after perf
# measurement against a running rig apiserver (host process). bash 3.2 safe.
#
# Seeds NS namespaces x PER_NS each of Deployments/ConfigMaps/Secrets/Pods, then
# runs, in order:
#   1. get   — single-object GET per kind
#   2. list  — namespaced LIST, all-namespaces LIST, labelSelector LIST per kind
#   3. mixed — WATCHERS informer-like LIST+WATCH clients, READERS concurrent
#              GET/LIST loops and one writer (create/update/patch/delete) for
#              DURATION seconds
# Prints per verb/kind p50/p99 (ms), apiserver CPU ms and RSS. Pass --pid
# <apiserver pid> for CPU/RSS; a profiler (samply record -p <pid>) can be
# attached to the same pid for phase 3.
#
# Usage: scripts/bench/apiserver-hot-paths.sh --kubeconfig temp/u7s/kubeconfig \
#          --pid <pid> --i-know-this-is-a-test-cluster [--ns 10] [--per-ns 50] \
#          [--watchers 20] [--readers 4] [--duration 30] [--gets 2000] \
#          [--lists 100] [--writes 200] [--out results.txt] [--skip-seed]
#        scripts/bench/apiserver-hot-paths.sh --kubeconfig <path> \
#          --i-know-this-is-a-test-cluster --cleanup
#
# Seeds and mutates the cluster (bench-* namespaces, node bench-node), so it
# refuses to run unless the flag is given and the server URL is loopback.
# --cleanup deletes the bench-* namespaces and bench-node.
set -euo pipefail

KUBECONFIG_PATH=""; PID=""; NS=10; PER_NS=50; WATCHERS=20; READERS=4
DURATION=30; GETS=2000; LISTS=100; WRITES=200; FANOUT=100; FANOUT_WRITES=500; OUT=""; SKIP_SEED=0; ACK=0; CLEANUP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
        --pid) PID="$2"; shift 2 ;;
        --ns) NS="$2"; shift 2 ;;
        --per-ns) PER_NS="$2"; shift 2 ;;
        --watchers) WATCHERS="$2"; shift 2 ;;
        --readers) READERS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --gets) GETS="$2"; shift 2 ;;
        --lists) LISTS="$2"; shift 2 ;;
        --writes) WRITES="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --skip-seed) SKIP_SEED=1; shift ;;
        --i-know-this-is-a-test-cluster) ACK=1; shift ;;
        --cleanup) CLEANUP=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[ -n "$KUBECONFIG_PATH" ] || { echo "--kubeconfig required" >&2; exit 2; }

K=(kubectl --kubeconfig "$KUBECONFIG_PATH")
cfg() { "${K[@]}" config view --minify --raw -o jsonpath="$1"; }
SERVER="$(cfg '{.clusters[0].cluster.server}')"
CA="$(cfg '{.clusters[0].cluster.certificate-authority}')"
CERT="$(cfg '{.users[0].user.client-certificate}')"
KEY="$(cfg '{.users[0].user.client-key}')"
[ -n "$KEY" ] || KEY="$CERT"
case "$SERVER" in
    https://127.0.0.1[:/]*|https://localhost[:/]*|https://\[::1\][:/]*) ;;
    *) echo "refusing: server $SERVER is not loopback" >&2; exit 2 ;;
esac
[ "$ACK" = 1 ] || { echo "refusing: pass --i-know-this-is-a-test-cluster (this script creates and deletes objects)" >&2; exit 2; }
if [ "$CLEANUP" = 1 ]; then
    for ns in $("${K[@]}" get namespaces -o name | { grep '^namespace/bench-' || true; }); do
        "${K[@]}" delete "$ns" --wait=false
    done
    "${K[@]}" delete node bench-node --ignore-not-found
    exit 0
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/u7s-bench-hot-XXXXXX")"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT
TIMINGS="$WORK/timings.tsv"; : > "$TIMINGS"
CURL_OPTS=(-s --cacert "$CA" --cert "$CERT" --key "$KEY")
CURL=(curl "${CURL_OPTS[@]}")
EXTRA=()
FMT='%{time_total}\t%{http_code}\n'

# One curl process per call so the TLS connection is reused across the URLs.
timed() { # label url...
    local label="$1"; shift
    # -o applies to the first URL only, so bodies go to /dev/null via the shell
    # and the per-URL write-out goes to stderr (appended to the timings file).
    local out; out="$("${CURL[@]}" ${EXTRA[@]+"${EXTRA[@]}"} -w "%{stderr}$label\t$FMT" "$@" 2>&1 >/dev/null)"; printf '%s\n' "$out" >> "$TIMINGS"
}
ns_name() { echo "bench-$1"; }
repeat_timed() { # label count url
    local label="$1" count="$2" url="$3" args=() i
    for i in $(seq 1 "$count"); do args+=("$url"); done
    timed "$label" "${args[@]}"
}
write_timed() { # label method content-type body url
    local out; out="$("${CURL[@]}" -o /dev/null -w "$1\t$FMT" -X "$2" -H "Content-Type: $3" ${4:+-d "$4"} "$5")"; printf '%s\n' "$out" >> "$TIMINGS"
}

gen_items() {
    local i lbl pad_a pad_b sec
    pad_a="$(head -c 200 /dev/zero | tr '\0' a)"
    pad_b="$(head -c 400 /dev/zero | tr '\0' b)"
    sec="$(head -c 300 /dev/zero | tr '\0' a | base64 | tr -d '\n')"
    for i in $(seq 1 "$PER_NS"); do
        lbl="\"app\":\"app-$((i % 5))\",\"bench\":\"hot\""
        printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm-%s","labels":{%s}},"data":{"a":"%s","b":"%s","c":"x"}}\n' "$i" "$lbl" "$pad_a" "$pad_b"
        printf '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"sec-%s","labels":{%s}},"type":"Opaque","data":{"k":"%s"}}\n' "$i" "$lbl" "$sec"
        printf '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"dep-%s","labels":{%s}},"spec":{"replicas":0,"selector":{"matchLabels":{"app":"dep-%s"}},"template":{"metadata":{"labels":{"app":"dep-%s"}},"spec":{"containers":[{"name":"c","image":"registry.k8s.io/pause:3.10","resources":{"requests":{"cpu":"10m","memory":"16Mi"}}}]}}}}\n' "$i" "$lbl" "$i" "$i"
        printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pod-%s","labels":{%s}},"spec":{"nodeName":"bench-node","tolerations":[{"operator":"Exists"}],"containers":[{"name":"c1","image":"registry.k8s.io/pause:3.10","env":[{"name":"A","value":"1"},{"name":"B","value":"2"}],"resources":{"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"100m","memory":"64Mi"}},"volumeMounts":[{"name":"v","mountPath":"/v"}]},{"name":"c2","image":"registry.k8s.io/pause:3.10"}],"volumes":[{"name":"v","emptyDir":{}}]}}\n' "$i" "$lbl"
    done
}

if [ "$SKIP_SEED" = 0 ]; then
    echo "==> Seeding $NS namespaces x $PER_NS x 4 kinds"
    # Pods bind to a node with no kubelet and tolerate everything, so the
    # scheduler, kubelet and node-lifecycle controller leave them alone.
    echo '{"apiVersion":"v1","kind":"Node","metadata":{"name":"bench-node"}}' | "${K[@]}" apply -f - >/dev/null
    for n in $(seq 1 "$NS"); do
        ns="$(ns_name "$n")"
        "${K[@]}" get namespace "$ns" >/dev/null 2>&1 || "${K[@]}" create namespace "$ns" >/dev/null
        for _ in $(seq 1 60); do "${K[@]}" -n "$ns" get sa default >/dev/null 2>&1 && break; sleep 1; done
        gen_items | jq -s '{apiVersion:"v1",kind:"List",items:.}' | "${K[@]}" -n "$ns" apply -f - >/dev/null
    done
fi

cpu_ms() {
    [ -n "$PID" ] || { echo 0; return; }
    ps -o cputime= -p "$PID" | awk -F'[:.]' '{ if (NF==3) print ($1*60+$2)*1000+$3*10; else print ($1*3600+$2*60+$3)*1000+$4*10 }'
}
rss_kb() { [ -n "$PID" ] && ps -o rss= -p "$PID" | tr -d ' ' || echo 0; }

# Sequential phases attribute apiserver CPU to a label (ps resolution is 10 ms,
# so counts are sized to give each label >= ~100 ms of CPU).
CPU_LOG="$WORK/cpu.tsv"; : > "$CPU_LOG"
with_cpu() { # label n cmd...
    local label="$1" n="$2" c0 c1; shift 2
    c0="$(cpu_ms)"; "$@"; c1="$(cpu_ms)"
    printf '%s\t%s\t%s\n' "$label" "$n" "$((c1 - c0))" >> "$CPU_LOG"
}
# label method content-type count; body/url come from the BODY_FN/URL_FN
# functions called with the 1-based index. One curl process, --next groups.
batch() {
    local label="$1" method="$2" ctype="$3" count="$4" args=() i body
    for i in $(seq 1 "$count"); do
        body="$($BODY_FN "$i")"
        args+=(--next "${CURL_OPTS[@]}" -X "$method" -w "%{stderr}$label\t$FMT")
        [ -z "$ctype" ] || args+=(-H "Content-Type: $ctype")
        [ -z "$body" ] || args+=(-d "$body")
        args+=("$($URL_FN "$i")")
    done
    local out; out="$(curl "${args[@]:1}" 2>&1 >/dev/null)"; printf '%s\n' "$out" >> "$TIMINGS"
}
CPU0="$(cpu_ms)"; RSS0="$(rss_kb)"

echo "==> Phase 1: GET"
for kind in configmaps:cm secrets:sec pods:pod; do
    res="${kind%%:*}"; pfx="${kind##*:}"; urls=()
    for i in $(seq 1 "$GETS"); do urls+=("$SERVER/api/v1/namespaces/$(ns_name $((i % NS + 1)))/$res/$pfx-$((i % PER_NS + 1))"); done
    with_cpu "GET $res" "$GETS" timed "GET $res" "${urls[@]}"
done
urls=()
for i in $(seq 1 "$GETS"); do urls+=("$SERVER/apis/apps/v1/namespaces/$(ns_name $((i % NS + 1)))/deployments/dep-$((i % PER_NS + 1))"); done
with_cpu "GET deployments" "$GETS" timed "GET deployments" "${urls[@]}"

echo "==> Phase 2: LIST"
for res in configmaps secrets pods; do
    with_cpu "LIST ns $res" "$LISTS" repeat_timed "LIST ns $res" "$LISTS" "$SERVER/api/v1/namespaces/$(ns_name 1)/$res"
    with_cpu "LIST all-ns $res" "$LISTS" repeat_timed "LIST all-ns $res" "$LISTS" "$SERVER/api/v1/$res"
    with_cpu "LIST all-ns selector $res" "$LISTS" repeat_timed "LIST all-ns selector $res" "$LISTS" "$SERVER/api/v1/$res?labelSelector=app%3Dapp-1"
done
with_cpu "LIST ns deployments" "$LISTS" repeat_timed "LIST ns deployments" "$LISTS" "$SERVER/apis/apps/v1/namespaces/$(ns_name 1)/deployments"
with_cpu "LIST all-ns deployments" "$LISTS" repeat_timed "LIST all-ns deployments" "$LISTS" "$SERVER/apis/apps/v1/deployments"
with_cpu "LIST all-ns pods limit=100" "$LISTS" repeat_timed "LIST all-ns pods limit=100" "$LISTS" "$SERVER/api/v1/pods?limit=100"

# kubelet and kube-controller-manager negotiate protobuf; the apiserver falls
# back to JSON for kinds without an encoder, so these rows show which path wins.
EXTRA=(-H "Accept: application/vnd.kubernetes.protobuf,application/json")
with_cpu "LIST all-ns pods (protobuf accept)" "$LISTS" repeat_timed "LIST all-ns pods (protobuf accept)" "$LISTS" "$SERVER/api/v1/pods"
with_cpu "LIST all-ns configmaps (protobuf accept)" "$LISTS" repeat_timed "LIST all-ns configmaps (protobuf accept)" "$LISTS" "$SERVER/api/v1/configmaps"
urls=()
for i in $(seq 1 "$GETS"); do urls+=("$SERVER/api/v1/namespaces/$(ns_name $((i % NS + 1)))/pods/pod-$((i % PER_NS + 1))"); done
with_cpu "GET pods (protobuf accept)" "$GETS" timed "GET pods (protobuf accept)" "${urls[@]}"
EXTRA=()

echo "==> Phase 2b: writes ($WRITES each, sequential)"
WNS="$(ns_name 1)"
cm_body() { printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"wb-%s","labels":{"app":"wb"}},"data":{"s":"%s"}}' "$1" "$1"; }
cm_upd() { printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"wb-%s","labels":{"app":"wb"}},"data":{"s":"u%s"}}' "$1" "$1"; }
pod_body() { printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"wb-%s","labels":{"app":"wb"}},"spec":{"nodeName":"bench-node","tolerations":[{"operator":"Exists"}],"containers":[{"name":"c","image":"registry.k8s.io/pause:3.10","resources":{"requests":{"cpu":"10m"}}}]}}' "$1"; }
sec_body() { printf '{"apiVersion":"v1","kind":"Secret","metadata":{"name":"wb-%s"},"type":"Opaque","data":{"k":"dmFsdWU="}}' "$1"; }
patch_body() { printf '{"metadata":{"labels":{"p":"%s"}}}' "$1"; }
none_body() { :; }
url_cm() { echo "$SERVER/api/v1/namespaces/$WNS/configmaps"; }
url_cm_n() { echo "$SERVER/api/v1/namespaces/$WNS/configmaps/wb-$1"; }
url_pod() { echo "$SERVER/api/v1/namespaces/$WNS/pods"; }
url_pod_n() { echo "$SERVER/api/v1/namespaces/$WNS/pods/wb-$1"; }
url_pod_del() { echo "$SERVER/api/v1/namespaces/$WNS/pods/wb-$1?gracePeriodSeconds=0"; }
url_sec() { echo "$SERVER/api/v1/namespaces/$WNS/secrets"; }
url_sec_n() { echo "$SERVER/api/v1/namespaces/$WNS/secrets/wb-$1"; }
url_dep1() { echo "$SERVER/apis/apps/v1/namespaces/$WNS/deployments/dep-1"; }
run_batch() { BODY_FN="$1"; URL_FN="$2"; with_cpu "$3 $4" "$WRITES" batch "$3 $4" "$3" "$5" "$WRITES"; }
run_batch cm_body url_cm POST configmaps application/json
run_batch cm_upd url_cm_n PUT configmaps application/json
run_batch patch_body url_cm_n PATCH configmaps application/merge-patch+json
run_batch none_body url_cm_n DELETE configmaps ""
run_batch pod_body url_pod POST pods application/json
run_batch patch_body url_pod_n PATCH pods application/merge-patch+json
run_batch none_body url_pod_del DELETE pods ""
run_batch sec_body url_sec POST secrets application/json
run_batch none_body url_sec_n DELETE secrets ""
run_batch patch_body url_dep1 PATCH deployments application/merge-patch+json

echo "==> Phase 2c: watch fan-out ($FANOUT idle non-matching watchers, then $FANOUT_WRITES PUTs)"
fan_writes() {
    BODY_FN=fan_body; URL_FN=url_fan
    with_cpu "$1" "$FANOUT_WRITES" batch "$1" PUT application/json "$FANOUT_WRITES"
}
fan_body() { printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"fan"},"data":{"s":"%s"}}' "$1"; }
url_fan() { echo "$SERVER/api/v1/namespaces/$WNS/configmaps/fan"; }
write_timed "fanout setup" POST application/json "$(fan_body 0)" "$SERVER/api/v1/namespaces/$WNS/configmaps" >/dev/null
fan_writes "fanout PUT, 0 extra watchers"
for _ in $(seq 1 "$FANOUT"); do
    "${CURL[@]}" -N --max-time 120 "$SERVER/api/v1/namespaces/$(ns_name "$NS")/secrets?watch=1&resourceVersion=0" >/dev/null 2>&1 &
done
sleep 3
fan_writes "fanout PUT, $FANOUT non-matching watchers"
kill $(jobs -p) 2>/dev/null || true
CPU_P12="$(cpu_ms)"

echo "==> Phase 3: mixed ($WATCHERS watchers, $READERS readers, 1 writer, ${DURATION}s)"
END=$(( $(date +%s) + DURATION ))
WATCH_EVENTS="$WORK/watch-events"; : > "$WATCH_EVENTS"
RSS_PEAK_FILE="$WORK/rss-peak"; echo 0 > "$RSS_PEAK_FILE"
if [ -n "$PID" ]; then
    (
        peak=0
        while [ "$(date +%s)" -lt "$END" ]; do
            r="$(rss_kb)"; [ "$r" -le "$peak" ] || peak="$r"
            sleep 0.5
        done
        echo "$peak" > "$RSS_PEAK_FILE"
    ) &
fi
kinds=(pods configmaps secrets)
for w in $(seq 1 "$WATCHERS"); do
    (
        kind="${kinds[$((w % 3))]}"
        rv="$("${CURL[@]}" "$SERVER/api/v1/$kind?limit=1" | jq -r .metadata.resourceVersion)"
        timed "LIST informer all-ns $kind" "$SERVER/api/v1/$kind"
        "${CURL[@]}" -N --max-time "$DURATION" "$SERVER/api/v1/$kind?watch=1&allowWatchBookmarks=true&resourceVersion=$rv" | wc -l >> "$WATCH_EVENTS" || true
    ) &
done
# Readers and the writer batch 10 requests per curl process so the connection
# is reused, as an informer/controller client would.
for r in $(seq 1 "$READERS"); do
    (
        while [ "$(date +%s)" -lt "$END" ]; do
            a=(); b=(); c=()
            for _ in $(seq 1 10); do
                ns="$(ns_name $((RANDOM % NS + 1)))"; i=$((RANDOM % PER_NS + 1))
                a+=("$SERVER/api/v1/namespaces/$ns/configmaps/cm-$i"); b+=("$SERVER/api/v1/namespaces/$ns/pods/pod-$i"); c+=("$SERVER/api/v1/namespaces/$ns/pods")
            done
            timed "mixed GET configmaps" "${a[@]}"
            timed "mixed GET pods" "${b[@]}"
            timed "mixed LIST ns pods" "${c[@]}"
            repeat_timed "mixed LIST all-ns configmaps" 5 "$SERVER/api/v1/configmaps"
        done
    ) &
done
(
    n=0
    while [ "$(date +%s)" -lt "$END" ]; do
        # distinct name range from the sequential write phase
        args=(); for i in $(seq 1 10); do n=$((n + 1)); args+=(--next "${CURL_OPTS[@]}" -X POST -H "Content-Type: application/json" -w "%{stderr}mixed POST configmaps\t$FMT" -d "$(printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"mx-%s"},"data":{"s":"%s"}}' "$n" "$n")" "$(url_cm)"); done
        for i in $(seq $((n - 9)) "$n"); do
            args+=(--next "${CURL_OPTS[@]}" -X PUT -H "Content-Type: application/json" -w "%{stderr}mixed PUT configmaps\t$FMT" -d "$(printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"mx-%s"},"data":{"s":"u"}}' "$i")" "$SERVER/api/v1/namespaces/$WNS/configmaps/mx-$i")
            args+=(--next "${CURL_OPTS[@]}" -X PATCH -H "Content-Type: application/merge-patch+json" -w "%{stderr}mixed PATCH deployments\t$FMT" -d "$(patch_body "$i")" "$(url_dep1)")
            args+=(--next "${CURL_OPTS[@]}" -X POST -H "Content-Type: application/json" -w "%{stderr}mixed POST pods\t$FMT" -d "$(printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"mx-%s"},"spec":{"nodeName":"bench-node","tolerations":[{"operator":"Exists"}],"containers":[{"name":"c","image":"registry.k8s.io/pause:3.10"}]}}' "$i")" "$(url_pod)")
            args+=(--next "${CURL_OPTS[@]}" -X DELETE -w "%{stderr}mixed DELETE configmaps\t$FMT" "$SERVER/api/v1/namespaces/$WNS/configmaps/mx-$i")
            args+=(--next "${CURL_OPTS[@]}" -X DELETE -w "%{stderr}mixed DELETE pods\t$FMT" "$SERVER/api/v1/namespaces/$WNS/pods/mx-$i?gracePeriodSeconds=0")
        done
        out="$(curl "${args[@]:1}" 2>&1 >/dev/null)"; printf '%s\n' "$out" >> "$TIMINGS"
    done
) &
wait
CPU1="$(cpu_ms)"; RSS1="$(rss_kb)"

{
    echo "==> Latency (ms); client time_total, connection reused within a batch"
    sort -t "$(printf '\t')" -k1,1 -k2,2n "$TIMINGS" | awk -F'\t' '
        function flush() { if (n) { k = int(n * 0.99); if (k < 1) k = 1
            printf "%-34s n=%-5d p50=%9.2f p99=%9.2f non2xx=%d\n", label, n, v[int((n + 1) / 2)] * 1000, v[k] * 1000, bad } }
        $1 != label { flush(); label = $1; n = 0; bad = 0 }
        { v[++n] = $2; if ($3 !~ /^2/) bad++ }
        END { flush() }'
    if [ -n "$PID" ]; then
        echo "==> apiserver CPU per request, sequential phases (ms/request; 10 ms ps resolution)"
        awk -F'\t' '{ printf "%-34s n=%-5d cpu=%9.3f ms/req\n", $1, $2, $3 / $2 }' "$CPU_LOG"
    fi
    echo "watch events delivered (all watchers): $(awk '{s+=$1} END {print s+0}' "$WATCH_EVENTS")"
    echo "requests timed: $(wc -l < "$TIMINGS" | tr -d ' ') (watch streams excluded)"
    if [ -n "$PID" ]; then
        echo "apiserver CPU: total $((CPU1 - CPU0)) ms; phases 1-2b $((CPU_P12 - CPU0)) ms; phase 3 $((CPU1 - CPU_P12)) ms"
        echo "apiserver RSS start / phase-3 peak / end: $RSS0 / $(cat "$RSS_PEAK_FILE") / $RSS1 KiB"
    fi
} | tee "${OUT:-/dev/null}"
