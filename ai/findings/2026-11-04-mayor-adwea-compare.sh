#!/usr/bin/env bash
# usage: compare.sh RAWDIR  -- cross-release table from per-release raw/<tag>/{m-idle,m-wp}
R="$1"
mi() { awk -v k="$1" '$1==k":" {printf "%d", $2/1024}' "$2/meminfo"; }
printf '%-22s %-4s %5s %5s %5s %5s %5s %5s %5s %5s | %s\n' release ph avail anon cache slab sunrc kstk ptbl floor "kernel"
for t in v0.3.0-snapshot.1 v0.4.0-snapshot.1 v0.4.1-snapshot.1 v0.4.2-snapshot.1 v0.4.2-snapshot.2 v0.4.3-snapshot.1 v0.4.3-snapshot.2 v0.4.3-snapshot.4; do
  for p in idle wp s20; do
    d="$R/$t/m-$p"; [ -d "$d" ] || continue
    a=$(mi MemAvailable "$d"); an=$(mi AnonPages "$d"); c=$(mi Cached "$d"); s=$(mi Slab "$d"); su=$(mi SUnreclaim "$d"); k=$(mi KernelStack "$d"); pt=$(mi PageTables "$d")
    printf '%-22s %-4s %5s %5s %5s %5s %5s %5s %5s %5s | %s\n' "$t" "$p" "$a" "$an" "$c" "$s" "$su" "$k" "$pt" "$((an+su+k+pt))" "$(cat "$d/kernel")"
  done
done
echo
echo "binary sizes MiB (idle snapshot)"
for t in v0.3.0-snapshot.1 v0.4.0-snapshot.1 v0.4.1-snapshot.1 v0.4.2-snapshot.1 v0.4.2-snapshot.2 v0.4.3-snapshot.1 v0.4.3-snapshot.2 v0.4.3-snapshot.4; do
  d="$R/$t/m-idle"; [ -d "$d" ] || continue
  printf '%-22s ' "$t"
  awk 'NR>2 && ($3 ~ /\/kubelet$|kube-controller-manager$|u7s-apiserver$|\/crio$|u7s-scheduler$/) {n=split($3,a,"/"); printf "%s=%.1f ", a[n], $2/1048576}' "$d/fincore.txt"
  echo
done
echo
echo "pods (idle snapshot), namespace/name prefix"
for t in v0.3.0-snapshot.1 v0.4.0-snapshot.1 v0.4.1-snapshot.1 v0.4.2-snapshot.1 v0.4.2-snapshot.2 v0.4.3-snapshot.1 v0.4.3-snapshot.2 v0.4.3-snapshot.4; do
  d="$R/$t/m-idle"; [ -d "$d" ] || continue
  printf '%-22s ' "$t"
  awk 'NR>1 {print $1"/"substr($2,1,14)}' "$d/pods.txt" | tr '\n' ' '
  echo
done
echo
echo "running services (idle snapshot), count and u7s-related"
for t in v0.3.0-snapshot.1 v0.4.0-snapshot.1 v0.4.1-snapshot.1 v0.4.2-snapshot.1 v0.4.2-snapshot.2 v0.4.3-snapshot.1 v0.4.3-snapshot.2 v0.4.3-snapshot.4; do
  d="$R/$t/m-idle"; [ -d "$d" ] || continue
  printf '%-22s %s\n' "$t" "$(awk '{print $1}' "$d/services.txt" | sed 's/.service//' | sort | tr '\n' ' ')"
done
