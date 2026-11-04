#!/usr/bin/env bash
# usage: observers.sh VM SECONDS -- from the workstation: the same 10 streaming ssh sessions an observed Lima
# run uses (1 s sampler, 2 journalctl -f, 7 API/curl|jq streams), for SECONDS; killed on exit
VM="$1"; SECS="$2"; HERE="$(cd "$(dirname "$0")/../.." && pwd)"
G="$HERE/scripts/gcp/vps.sh"
pids=()
"$G" ssh "$VM" -- sudo bash /var/tmp/obs-sample.sh >/dev/null 2>&1 & pids+=($!)
"$G" ssh "$VM" -- sudo journalctl -f -n 0 -o short-iso-precise -u kubelet -u crio -u u7s-kcm -u u7s-apiserver -u u7s-scheduler >/dev/null 2>&1 & pids+=($!)
"$G" ssh "$VM" -- sudo journalctl -k -f -n 0 -o short-iso-precise >/dev/null 2>&1 & pids+=($!)
for s in lease node events deploy podphase probe metrics; do
  "$G" ssh "$VM" -- sudo bash /var/tmp/obs-api.sh "$s" >/dev/null 2>&1 & pids+=($!)
done
sleep "$SECS"
kill "${pids[@]}" 2>/dev/null
wait 2>/dev/null
