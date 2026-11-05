#!/bin/bash
# usage: sudo bash snap.sh LABEL
echo "=== $1 $(date -u +%T)"
grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|AnonPages|Slab|SReclaimable|SUnreclaim|KernelStack|PageTables|Shmem|Active\(file\)|Inactive\(file\)):' /proc/meminfo | tr -s ' ' | tr '\n' ' '; echo
echo "--- PSS kB by comm (n, pss, anon)"
for p in /proc/[0-9]*; do
  c=$(cat $p/comm 2>/dev/null) || continue
  awk -v c="$c" '/^Pss:/{p=$2}/^Pss_Anon:/{a=$2}END{if(p!="")print c, p, a}' $p/smaps_rollup 2>/dev/null
done | awk '{n[$1]++;p[$1]+=$2;a[$1]+=$3}END{for(k in n)print k,n[k],p[k],a[k]}' | sort -k3 -nr | head -14
echo "--- cgroup memory.stat MiB"
for d in /sys/fs/cgroup/kubepods.slice /sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice /sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice /sys/fs/cgroup/system.slice /sys/fs/cgroup/user.slice; do
  [ -f $d/memory.stat ] && awk -v d="$(basename $d)" '$1=="anon"{a=$2}$1=="file"{f=$2}$1=="kernel"{k=$2}$1=="slab"{s=$2}$1=="sock"{o=$2}END{printf "%s anon=%d file=%d kernel=%d slab=%d sock=%d\n",d,a/1048576,f/1048576,k/1048576,s/1048576,o/1048576}' $d/memory.stat
done
echo "--- besteffort pod cgroups (kB sums) then count"
ls -d /sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod*.slice 2>/dev/null | while read d; do cat $d/memory.stat; done | awk '$1=="anon"{a+=$2}$1=="file"{f+=$2}$1=="kernel"{k+=$2}$1=="slab"{s+=$2}END{printf "anon=%d file=%d kernel=%d slab=%d\n",a/1024,f/1024,k/1024,s/1024}'
ls -d /sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod*.slice 2>/dev/null | wc -l
echo "--- system.slice services (MiB cur)"
for d in /sys/fs/cgroup/system.slice/*.service; do [ -f $d/memory.current ] && echo "$(( $(cat $d/memory.current)/1048576 )) $(basename $d)"; done | sort -nr | head -8
echo "--- slab top (kB name objs)"
awk 'NR>2{printf "%d %s %d\n",$3*$4/1024,$1,$3}' /proc/slabinfo | sort -nr | head -8
echo "--- netns=$(ls /run/netns 2>/dev/null | wc -l) veth=$(ls /sys/class/net | grep -c '^veth') pause_procs=$(pgrep -c -x pause) conmon=$(pgrep -c -x conmon)"
echo "--- vmstat: $(grep -E '^(pgmajfault|workingset_refault_file|pgscan_direct) ' /proc/vmstat | tr '\n' ' ')"
