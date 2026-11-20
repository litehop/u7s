#!/usr/bin/env bash
# Runs inside the VM as root (driven by upgrade-gate.sh). Installs the PREVIOUS release, deploys a
# marker workload, then re-runs the CANDIDATE install.sh with no flags (docs/install.md,
# "Upgrading") while a 2 s /readyz poller runs, and again to prove the re-run is idempotent.
# Writes $RG/out/results.env (format: upgrade-lib.sh).
set -uo pipefail

RG="${RG_DIR:-/var/tmp/rg}"
OUT="$RG/out"
KCFG=/var/lib/u7s/kubeconfig
STATE=/var/lib/u7s
POLL_SECS=2

# shellcheck source=lib.sh
. "$RG/lib.sh"
# shellcheck source=upgrade-lib.sh
. "$RG/upgrade-lib.sh"
PREV_INSTALL=""; CAND_INSTALL=""; CAND_EXPECT=""
# shellcheck disable=SC1091
. "$RG/upgrade.env"

mkdir -p "$OUT"
: > "$OUT/results.env"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
res() { echo "$1=$2" >> "$OUT/results.env"; }
k() { timeout -k 1 "${K_TIMEOUT:-30}" kubectl --kubeconfig "$KCFG" "$@"; }
abort() { log "harness error: $*"; res harness_error "$*"; exit 0; }

wait_node_ready() {
  for _ in $(seq 1 "${1:-120}"); do
    [ "$(k get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && return 0
    sleep 2
  done
  return 1
}

server_version() { k version 2>/dev/null | awk '/^Server Version:/ {print $3}'; }
state_hashes() { (cd "$STATE" && sha256sum ca.key ca.crt sa.pub 2>/dev/null); }
# "<ns>/<name> <uid> <restartCount per container, comma separated>" for the default namespace.
pod_state() {
  k get pods -n default -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.metadata.uid} {range .status.containerStatuses[*]}{.restartCount},{end}{"\n"}{end}' | sort
}
marker_read() {
  local pod
  pod="$(k get pods -n default -l app=ug-dep -o jsonpath='{.items[0].metadata.name}')" || return 1
  echo "cm=$(k get cm ug-marker -o jsonpath='{.data.v}') pod=$(k exec -n default "$pod" -- cat /data/marker)"
}

install_cand() { # $1 label
  local t0=$SECONDS rc
  $CAND_INSTALL > "$OUT/install-$1.log" 2>&1; rc=$?
  log "$1 install.sh exit $rc after $((SECONDS - t0)) s"
  return $rc
}

log "install previous release"
$PREV_INSTALL > "$OUT/install-prev.log" 2>&1 || { tail -20 "$OUT/install-prev.log"; abort "previous release install.sh failed"; }
wait_node_ready || abort "node never Ready after the previous release install"

MARKER="ug-$(date +%s)-$RANDOM"
log "deploy workload (marker $MARKER)"
k apply -f - >> "$OUT/run.log" 2>&1 <<EOF || abort "workload apply failed"
apiVersion: v1
kind: ConfigMap
metadata: {name: ug-marker}
data: {v: "$MARKER"}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ug-dep}
spec:
  replicas: 2
  selector: {matchLabels: {app: ug-dep}}
  template:
    metadata: {labels: {app: ug-dep}}
    spec:
      containers:
      - name: c
        image: docker.io/library/busybox:1.36
        command: ["sh","-c","echo $MARKER > /data/marker; sleep 100000"]
        volumeMounts: [{name: d, mountPath: /data}]
      volumes: [{name: d, emptyDir: {}}]
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ug-ds}
spec:
  selector: {matchLabels: {app: ug-ds}}
  template:
    metadata: {labels: {app: ug-ds}}
    spec:
      containers:
      - name: c
        image: docker.io/library/busybox:1.36
        command: ["sleep","100000"]
EOF
kubectl --kubeconfig "$KCFG" -n default rollout status deployment/ug-dep --timeout=300s >> "$OUT/run.log" 2>&1 || abort "ug-dep never rolled out"
kubectl --kubeconfig "$KCFG" -n default rollout status daemonset/ug-ds --timeout=300s >> "$OUT/run.log" 2>&1 || abort "ug-ds never rolled out"
grep -q "cm=$MARKER pod=$MARKER" < <(marker_read) || abort "marker not readable before the upgrade"

VER_PRE="$(server_version)"
state_hashes > "$OUT/hashes-pre.txt"
pod_state > "$OUT/pods-pre.txt"
k get pods -A -o wide > "$OUT/pods-all-pre.txt" 2>&1
log "pre-upgrade: server $VER_PRE; $(wc -l < "$OUT/pods-pre.txt") default-namespace pods"
res version_pre "$VER_PRE"

IP="$(hostname -I | cut -d' ' -f1)"
( while :; do
    c="$(curl -sk --max-time 2 -o /dev/null -w '%{http_code}' "https://$IP:6443/readyz")" || c=FAIL
    echo "$(date +%s.%N) $c"
    sleep "$POLL_SECS"
  done ) >> "$OUT/readyz.log" 2>/dev/null &
POLL_PID=$!
trap 'kill $POLL_PID 2>/dev/null' EXIT
sleep 6

log "upgrade: candidate install.sh, no flags"
T_UP0="$(date +%s)"
install_cand upgrade; UP_RC=$?
NODE_UP=1; wait_node_ready 150 || { NODE_UP=0; log "node not Ready 5 min after the upgrade"; }
sleep 20
T_UP1="$(date +%s)"
res node_ready "$NODE_UP"

res cand_install "$([ "$UP_RC" = 0 ] && echo 1 || echo 0)"
res cand_install_detail "exit $UP_RC"

VER_POST="$(server_version)"
prob="$(ug_version_problem "$VER_PRE" "$VER_POST" "$CAND_EXPECT")"
res version "$([ -z "$prob" ] && echo 1 || echo 0)"
res version_detail "${prob:-$VER_PRE -> $VER_POST}"

state_hashes > "$OUT/hashes-post.txt"
for pair in "ca|ca.key ca.crt" "sa_pub|sa.pub"; do
  key="${pair%%|*}"; files="${pair#*|}"; changed=""
  for f in $files; do
    ug_hash_preserved "$OUT/hashes-pre.txt" "$OUT/hashes-post.txt" "$f" || changed="$changed $f"
  done
  res "$key" "$([ -z "$changed" ] && echo 1 || echo 0)"
  res "${key}_detail" "${changed:+changed:$changed}"
done

m="$(marker_read 2>&1)"
res marker "$([ "$m" = "cm=$MARKER pod=$MARKER" ] && echo 1 || echo 0)"
res marker_detail "$m"

pod_state > "$OUT/pods-post.txt"
k get pods -A -o wide > "$OUT/pods-all-post.txt" 2>&1
cont="$(ug_continuity_problems "$OUT/pods-pre.txt" "$OUT/pods-post.txt")"
res workload "$([ -z "$cont" ] && [ -s "$OUT/pods-post.txt" ] && echo 1 || echo 0)"
res workload_detail "$(echo "${cont:-$(wc -l < "$OUT/pods-pre.txt") pods unchanged}" | tr '\n' ';')"

dt="$(ug_downtime_summary "$OUT/readyz.log" "$T_UP0" "$T_UP1")"
if ug_downtime_ok "$dt"; then res downtime 1; else res downtime 0; fi
res downtime_detail "$dt, install ran $((T_UP1 - T_UP0)) s incl. 20 s settle; bound ${UG_MAX_DOWNTIME_SECS} s"
log "upgrade API downtime: $dt"

log "idempotence: candidate install.sh again"
T_RE0="$(date +%s)"
install_cand rerun; RE_RC=$?
NODE_RE=1; wait_node_ready 150 || { NODE_RE=0; log "node not Ready after the re-run"; }
sleep 20
T_RE1="$(date +%s)"
res rerun_install "$([ "$RE_RC" = 0 ] && echo 1 || echo 0)"
res rerun_install_detail "exit $RE_RC"
pod_state > "$OUT/pods-rerun.txt"
cont2="$(ug_continuity_problems "$OUT/pods-post.txt" "$OUT/pods-rerun.txt")"
dt2="$(ug_downtime_summary "$OUT/readyz.log" "$T_RE0" "$T_RE1")"
ok2=0; [ -z "$cont2" ] && ug_downtime_ok "$dt2" && [ "$NODE_RE" = 1 ] && ok2=1
res rerun_quiet "$ok2"
res rerun_quiet_detail "$(echo "${cont2:+$cont2; }$dt2" | tr '\n' ';')"
log "re-run API downtime: $dt2"

res "done" 1
