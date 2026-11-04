#!/usr/bin/env bash
# usage: summarize.sh SNAPSHOTDIR  -- one-line-per-metric summary of a collect.sh snapshot (MiB)
D="$1"
mi() { awk -v k="$1" '$1==k":" {printf "%.0f", $2/1024}' "$D/meminfo"; }
echo "avail=$(mi MemAvailable) free=$(mi MemFree) cached=$(mi Cached) buffers=$(mi Buffers) anon=$(mi AnonPages) slab=$(mi Slab) sunrec=$(mi SUnreclaim) srecl=$(mi SReclaimable) kstack=$(mi KernelStack) ptables=$(mi PageTables) actfile=$(mi 'Active(file)') inactfile=$(mi 'Inactive(file)')"
echo "refault_file=$(awk '$1=="workingset_refault_file"{print $2}' "$D/vmstat") pgmajfault=$(awk '$1=="pgmajfault"{print $2}' "$D/vmstat")"
echo "-- per-process PSS MiB (pss/anon/file), grouped by comm"
awk -F'\t' '{pss[$2]+=$5; anon[$2]+=$7; file[$2]+=$8; rss[$2]+=$4; n[$2]++} END {for (c in pss) printf "%7.1f %7.1f %7.1f %7.1f n=%d %s\n", pss[c]/1024, anon[c]/1024, file[c]/1024, rss[c]/1024, n[c], c}' "$D/procs.tsv" | sort -nr | head -${2:-16}
echo "-- total PSS all processes MiB: $(awk -F'\t' '{s+=$5} END {printf "%.0f", s/1024}' "$D/procs.tsv")"
echo "-- cgroups (cur MiB, anon, file, kernel, slab)"
awk -F'\t' 'NF>=9 {split($2,a,"=");split($3,b,"=");split($4,c,"=");split($5,d,"=");split($6,e,"="); printf "%6.1f %6.1f %6.1f %6.1f %6.1f %s\n", a[2]/1048576,b[2]/1048576,c[2]/1048576,d[2]/1048576,e[2]/1048576,$1}' "$D/cgroups.tsv" | sort -nr | head -${3:-12}
echo "-- slab top"
sed -n 8,14p "$D/slabtop" | awk '{print $1,$2,$5,$6,$7,$8}'
echo "-- fincore resident MiB (nonzero)"
awk 'NR>2 && $1>0 {printf "%.1f/%.1f %s\n", $1/1048576, $2/1048576, $3}' "$D/fincore.txt" | sort -nr | head -8
