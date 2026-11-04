#!/usr/bin/env bash
# usage: compare2.sh RAWDIR PHASE -- per-release PSS (MiB) of the control-plane processes and kubepods cgroup
R="$1"; P="$2"
printf '%-20s' release; for c in kube-controller kubelet crio u7s-apiserver coredns flanneld kube-proxy beep-controller mariadbd; do printf '%9s' "${c:0:8}"; done; printf '%9s %9s %9s\n' kubepods allPSS sys.slice
for t in v0.3.0-snapshot.1 v0.4.0-snapshot.1 v0.4.1-snapshot.1 v0.4.2-snapshot.1 v0.4.2-snapshot.2 v0.4.3-snapshot.1 v0.4.3-snapshot.2 v0.4.3-snapshot.4; do
  d="$R/$t/m-$P"; [ -d "$d" ] || continue
  printf '%-20s' "$t"
  for c in kube-controller kubelet crio u7s-apiserver coredns flanneld kube-proxy beep-controller mariadbd; do
    awk -F'\t' -v c="$c" '$2==c {s+=$5} END {printf "%9.1f", s/1024}' "$d/procs.tsv"
  done
  awk -F'\t' '{s+=$5} END {printf "%9.0f", s/1024}' "$d/procs.tsv" > /dev/null
  kp=$(awk -F'\t' '$1=="/kubepods.slice" && NF>=9 {split($2,a,"="); printf "%.0f", a[2]/1048576}' "$d/cgroups.tsv")
  ap=$(awk -F'\t' '{s+=$5} END {printf "%.0f", s/1024}' "$d/procs.tsv")
  ss=$(awk -F'\t' '$1=="/system.slice" && NF>=9 {split($2,a,"="); printf "%.0f", a[2]/1048576}' "$d/cgroups.tsv")
  printf '%9s %9s %9s\n' "$kp" "$ap" "$ss"
done
