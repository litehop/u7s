#!/usr/bin/env bash
# usage: cgmem.sh <out-dir> <phase>
# CGMEM (memory.current, includes page cache) over a phase, MiB, t=0 at the first row:
# t_s  kubepods  u7s-apiserver  u7s-kcm  kubelet  crio  sum(crio-conmon-*)
awk -F'\t' -v p="$2" '
$2==p && $3=="CGMEM" {
  if (!t0) t0=$1
  if ($1!=cur) { if (cur) flush(); cur=$1; kp=api=kcm=kl=cr=cm=0 }
  if ($4=="/kubepods.slice") kp=$5
  else if ($4=="/system.slice/u7s-apiserver.service") api=$5
  else if ($4=="/system.slice/u7s-kcm.service") kcm=$5
  else if ($4=="/system.slice/kubelet.service") kl=$5
  else if ($4=="/system.slice/crio.service") cr=$5
  else if ($4 ~ /^\/system.slice\/crio-conmon-/) cm+=$5
}
function flush() { printf "%d\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\t%.0f\n", cur-t0, kp/1048576, api/1048576, kcm/1048576, kl/1048576, cr/1048576, cm/1048576 }
END { if (cur) flush() }' "$1/attrib.tsv"
