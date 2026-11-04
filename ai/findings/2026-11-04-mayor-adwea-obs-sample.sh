#!/bin/bash
# In-VM streaming sampler: one tick per second on stdout, line-buffered.
while :; do
  ts=$(date +%s.%N)
  awk -v ts="$ts" '
    function emit(f,   l, a) { while ((getline l < f) > 0) { split(l, a, " "); printf "T %s PSI %s %s %s %s %s %s\n", ts, f, a[1], a[2], a[3], a[4], a[5] } close(f) }
    function cg(d,   l, r) { r = ""; while ((getline l < ("/sys/fs/cgroup/" d "/memory.stat")) > 0) if (l ~ /^workingset_refault_file /) r = substr(l, 24); close("/sys/fs/cgroup/" d "/memory.stat"); if (r != "") printf "T %s CGREF %s %s\n", ts, d, r }
    BEGIN {
      emit("/proc/pressure/cpu"); emit("/proc/pressure/memory"); emit("/proc/pressure/io")
      while ((getline l < "/proc/stat") > 0) if (l ~ /^cpu /) printf "T %s STAT %s\n", ts, l
      close("/proc/stat")
      while ((getline l < "/proc/meminfo") > 0) if (l ~ /^(MemAvailable|MemFree|Cached|Active\(file\)|Inactive\(file\)|AnonPages|Slab|Shmem|Dirty|Writeback):/) { gsub(/ +/, " ", l); printf "T %s MEM %s\n", ts, l }
      close("/proc/meminfo")
      while ((getline l < "/proc/vmstat") > 0) if (l ~ /^(workingset_refault_file|workingset_refault_anon|pgmajfault|pgscan_kswapd|pgscan_direct|pgsteal_kswapd|pgsteal_direct|allocstall_normal|pgpgin|pgpgout|oom_kill) /) printf "T %s VM %s\n", ts, l
      close("/proc/vmstat")
      while ((getline l < "/proc/loadavg") > 0) printf "T %s LOAD %s\n", ts, l
      close("/proc/loadavg")
      while ((getline l < "/proc/diskstats") > 0) if (l ~ / vda /) printf "T %s DISK %s\n", ts, l
      close("/proc/diskstats")
      cg("system.slice"); cg("kubepods.slice"); cg("user.slice"); cg("system.slice/crio.service"); cg("system.slice/kubelet.service"); cg("system.slice/u7s-kcm.service"); cg("system.slice/u7s-apiserver.service"); cg("kubepods.slice/kubepods-burstable.slice"); cg("kubepods.slice/kubepods-besteffort.slice")
    }'
  awk -v ts="$ts" '
    { s=$0; i=index(s,"("); j=0; for (k=length(s); k>0; k--) if (substr(s,k,1)==")") {j=k; break}
      comm=substr(s,i+1,j-i-1); rest=substr(s,j+2); split(rest,f," ")
      n[comm]++; mj[comm]+=f[10]; cmj[comm]+=f[11]; u[comm]+=f[12]; sy[comm]+=f[13]; cu[comm]+=f[14]; cs[comm]+=f[15]; r[comm]+=f[22]; if (f[1]=="D") d[comm]++
    }
    END { for (k in n) if (u[k]+sy[k]+mj[k]+cmj[k]+cu[k]+cs[k] > 0) printf "T %s PROC %s n=%d utime=%d stime=%d rss_pages=%d dstate=%d majflt=%d cmajflt=%d cutime=%d cstime=%d\n", ts, k, n[k], u[k], sy[k], r[k], d[k], mj[k], cmj[k], cu[k], cs[k] }
  ' /proc/[0-9]*/stat 2>/dev/null
  awk -v ts="$ts" '/^procs_(running|blocked)/ {printf "T %s PROCS %s %s\n", ts, $1, $2}' /proc/stat
  sleep 1
done
