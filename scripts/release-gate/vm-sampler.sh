#!/usr/bin/env bash
# Runs inside the gate VM (as root). Every INTERVAL seconds appends to $OUT/samples.tsv:
#   <epoch>\t<phase>\tMEM\t<MemAvailable kB>
#   <epoch>\t<phase>\t<component>\t<PSS kB>\t<RSS kB>\t<Pss_Anon kB>\t<Pss_File kB>   (summed over all pids of a comm)
# and to $OUT/attrib.tsv, <epoch>\t<phase>\t<kind>\t<fields>. Cumulative unless marked instantaneous (diff consecutive rows):
#   MEMI  <AnonPages> <Active(file)> <Inactive(file)> <Slab> <SReclaimable> <SUnreclaim> <PageTables> <KernelStack> <Shmem> <MemAvailable>
#         (kB, instantaneous, every 2 s in burst*/overload*/recover* phases, else once per sample)
#   SELF  <jiffies>   (utime+stime+cutime+cstime of this sampler: its own CPU cost)
#   CGSTAT <cgroup> <anon B> <file B> <slab B> <workingset_refault_file>   (anon/file/slab instantaneous; system.slice/*, kubepods.slice, its QoS and pod children)
#   CGPSI <cgroup> <memory some_us> <memory full_us>                       (same cgroups)
#   PSI   <cpu|io|memory> <some_total_us> <full_total_us>
#   STAT  <user+nice> <system> <iowait> <steal>                     (jiffies, /proc/stat)
#   DISK  <dev> <rd_ios> <rd_sectors> <wr_ios> <wr_sectors> <io_ms>
#   CG    <cgroup> <usage_usec> <throttled_usec>                    (root, top slices+scopes, system.slice/*, kubepods.slice/*)
#   VM    <counter> <value>   (workingset_refault_file/anon, pgmajfault, pgscan_*, pgsteal_*, oom_kill; pages, /proc/vmstat)
#   CGMEM <cgroup> <memory.current bytes>   (instantaneous, not cumulative; system.slice/*, kubepods.slice)
#   CGIO  <cgroup> <rbytes> <wbytes> <rios> <wios>
#   PROC  <pid> <comm> <cpu_jiffies> <read_bytes> <write_bytes>     (pids with any activity, only every
#         SAMPLER_PROC_INTERVAL=30 s: the walk reads 2 files per pid; reaped children's
#         IO is folded into the parent, their CPU is not, so use CG for CPU attribution)
# <phase> is the current content of $OUT/phase. Pure /proc reads: no kubectl, no forks
# beyond pgrep and one awk per sample, so the probe stays cheap on a 1 vCPU box.
# SAMPLER_ROOT prefixes /proc and /sys, SAMPLER_ONCE=1 stops after one sample (tests).
set -u
OUT="${1:?usage: $0 <out-dir> [interval-secs]}"
INTERVAL="${2:-5}"
PROC_INTERVAL="${SAMPLER_PROC_INTERVAL:-30}"
FAST_INTERVAL=2
last_proc=0
R="${SAMPLER_ROOT:-}"

# component:comm (comm is the kernel's 15-char truncated process name). The scheduler has no row:
# u7s-apiserver runs apiserver and scheduler as one process (--embedded-scheduler true).
COMPONENTS="apiserver:u7s-apiserver kcm:kube-controller kubelet:kubelet crio:crio conmon:conmon pause:pause kube-proxy:kube-proxy coredns:coredns flanneld:flanneld mariadb:mariadbd php-fpm:php-fpm nginx:nginx"

shopt -s nullglob

sample_attrib() {
  local ts="$1" phase="$2" with_proc="$3" cg="$R/sys/fs/cgroup" procfiles=()
  [ "$with_proc" = 1 ] && procfiles=("$R"/proc/[0-9]*/stat "$R"/proc/[0-9]*/io)
  # tail -n +1 prints a "==> file <==" header per file and skips unreadable ones (a pid that exits
  # mid-sample, kernel-thread io); awk would abort on them. [x] globs match only existing files.
  tail -n +1 -- "$R"/proc/pressure/* "$R"/proc/s[t]at "$R"/proc/diskstat[s] \
    ${procfiles[@]+"${procfiles[@]}"} \
    "$cg"/[c]pu.stat "$cg"/[i]o.stat "$cg"/*.slice/cpu.stat "$cg"/*.slice/io.stat "$cg"/*.scope/cpu.stat "$cg"/*.scope/io.stat \
    "$cg"/system.slice/*/cpu.stat "$cg"/system.slice/*/io.stat \
    "$cg"/kubepods.slice/*/cpu.stat "$cg"/kubepods.slice/*/*/cpu.stat \
    "$cg"/kubepods.slice/*/io.stat "$cg"/kubepods.slice/*/*/io.stat \
    "$R"/proc/vmstat "$cg"/system.slice/*/memory.current "$cg"/kubepods.slice/memory.current \
    "$cg"/system.slice/*/memory.stat "$cg"/system.slice/*/memory.pressure \
    "$cg"/kubepods.slice/memory.stat "$cg"/kubepods.slice/memory.pressure \
    "$cg"/kubepods.slice/*/memory.stat "$cg"/kubepods.slice/*/memory.pressure \
    "$cg"/kubepods.slice/*/*/memory.stat "$cg"/kubepods.slice/*/*/memory.pressure 2>/dev/null | awk -v ts="$ts" -v ph="$phase" -v cglen="${#cg}" '
    function emit(kind, rest) { printf "%s\t%s\t%s\t%s\n", ts, ph, kind, rest }
    function cgname(f, suffix,   n) {
      n = substr(f, cglen + 1)
      sub(suffix, "", n)
      return n == "" ? "/" : n
    }
    /^==> .* <==$/ { fn = substr($0, 5, length($0) - 8); next }
    NF == 0 { next }
    fn ~ /\/pressure\/[a-z]+$/ {
      n = fn; sub(/.*\//, "", n)
      split($5, a, "=")
      if ($1 == "some") some[n] = a[2]
      if ($1 == "full") full[n] = a[2]
      next
    }
    fn ~ /\/proc\/stat$/ { if ($1 == "cpu") emit("STAT", ($2 + $3) "\t" $4 "\t" $6 "\t" $9); next }
    fn ~ /\/proc\/vmstat$/ {
      if ($1 ~ /^(workingset_refault_file|workingset_refault_anon|pgmajfault|pgscan_[a-z]+|pgsteal_[a-z]+|oom_kill)$/) vm[$1] = $2
      next
    }
    fn ~ /\/memory\.stat$/ {
      if ($1 == "anon") sa[fn] = $2
      if ($1 == "file") sf[fn] = $2
      if ($1 == "slab") ss[fn] = $2
      if ($1 == "workingset_refault_file") sr[fn] = $2
      next
    }
    fn ~ /\/memory\.pressure$/ {
      split($5, a, "=")
      if ($1 == "some") ps[fn] = a[2]
      if ($1 == "full") pf[fn] = a[2]
      next
    }
    fn ~ /\/memory\.current$/ { mc[fn] = $1; next }
    fn ~ /\/proc\/diskstats$/ {
      if ($3 ~ /^(sd[a-z]|vd[a-z]|nvme[0-9]+n[0-9]+)$/) emit("DISK", $3 "\t" $4 "\t" $6 "\t" $8 "\t" $10 "\t" $13)
      next
    }
    fn ~ /\/proc\/[0-9]+\/stat$/ {
      pid = fn; sub(/\/stat$/, "", pid); sub(/.*\//, "", pid)
      line = $0
      c = line; sub(/^[^(]*\(/, "", c); sub(/\)[^)]*$/, "", c)
      sub(/^.*\) /, "", line); split(line, fld, " ")
      comm[pid] = c; ticks[pid] = fld[12] + fld[13]
      next
    }
    fn ~ /\/proc\/[0-9]+\/io$/ {
      pid = fn; sub(/\/io$/, "", pid); sub(/.*\//, "", pid)
      if ($1 == "read_bytes:") prb[pid] = $2
      if ($1 == "write_bytes:") pwb[pid] = $2
      next
    }
    fn ~ /\/cpu\.stat$/ {
      if ($1 == "usage_usec") u[fn] = $2
      if ($1 == "throttled_usec") t[fn] = $2
      next
    }
    fn ~ /\/io\.stat$/ {
      rb[fn] += 0; wb[fn] += 0; ri[fn] += 0; wi[fn] += 0
      for (i = 2; i <= NF; i++) {
        split($i, a, "=")
        if (a[1] == "rbytes") rb[fn] += a[2]
        if (a[1] == "wbytes") wb[fn] += a[2]
        if (a[1] == "rios") ri[fn] += a[2]
        if (a[1] == "wios") wi[fn] += a[2]
      }
      next
    }
    END {
      for (n in some) emit("PSI", n "\t" some[n] "\t" (n in full ? full[n] : 0))
      for (n in vm) emit("VM", n "\t" vm[n])
      for (f in mc) emit("CGMEM", cgname(f, "/memory\\.current$") "\t" mc[f])
      for (f in sa) emit("CGSTAT", cgname(f, "/memory\\.stat$") "\t" sa[f] "\t" sf[f] + 0 "\t" ss[f] + 0 "\t" sr[f] + 0)
      for (f in ps) emit("CGPSI", cgname(f, "/memory\\.pressure$") "\t" ps[f] "\t" pf[f] + 0)
      for (f in u) emit("CG", cgname(f, "/cpu\\.stat$") "\t" u[f] "\t" t[f] + 0)
      for (f in rb) emit("CGIO", cgname(f, "/io\\.stat$") "\t" rb[f] "\t" wb[f] "\t" ri[f] "\t" wi[f])
      for (p in ticks) if (ticks[p] > 0 || prb[p] > 0 || pwb[p] > 0) emit("PROC", p "\t" comm[p] "\t" ticks[p] "\t" prb[p] + 0 "\t" pwb[p] + 0)
    }
  ' >> "$OUT/attrib.tsv"
}

# One pass over /proc/*/comm picks the pids of every component and one tail reads their
# smaps_rollup: forks per sample stay constant however many pause/conmon processes exist.
sample_components() {
  local ts="$1" phase="$2" pidnames files=() pid _n
  pidnames="$(grep -H '' "$R"/proc/[0-9]*/comm 2>/dev/null | awk -v comps="$COMPONENTS" '
    BEGIN { n = split(comps, c, " "); for (i = 1; i <= n; i++) { split(c[i], kv, ":"); m[kv[2]] = kv[1] } }
    { i = index($0, "/comm:"); if (i == 0) next
      comm = substr($0, i + 6); if (!(comm in m)) next
      pid = substr($0, 1, i - 1); sub(/.*\//, "", pid); print pid " " m[comm] }')"
  [ -n "$pidnames" ] || return 0
  while read -r pid _n; do files+=("$R/proc/$pid/smaps_rollup"); done <<< "$pidnames"
  tail -n +1 -- "${files[@]}" 2>/dev/null | awk -v ts="$ts" -v ph="$phase" -v map="${pidnames//$'\n'/,}" '
    BEGIN { n = split(map, l, ","); for (i = 1; i <= n; i++) { split(l[i], kv, " "); name[kv[1]] = kv[2] } }
    /^==> .* <==$/ { p = substr($0, 5, length($0) - 8); sub(/\/smaps_rollup$/, "", p); sub(/.*\//, "", p); nm = name[p]; seen[nm] = 1; next }
    /^Pss:/ { pss[nm] += $2 }
    /^Rss:/ { rss[nm] += $2 }
    /^Pss_Anon:/ { an[nm] += $2 }
    /^Pss_File:/ { fi[nm] += $2 }
    END { for (nm in seen) printf "%s\t%s\t%s\t%d\t%d\t%d\t%d\n", ts, ph, nm, pss[nm], rss[nm], an[nm], fi[nm] }
  ' >> "$OUT/samples.tsv"
}

# MemAvailable goes to samples.tsv (what the gate verdict reads); the kernel-side breakdown
# that tells anon growth from slab/page-table/file-cache loss goes to attrib.tsv.
sample_meminfo() {
  awk -v ts="$1" -v ph="$2" -v s="$OUT/samples.tsv" -v a="$OUT/attrib.tsv" '
    $1 ~ /^(MemAvailable|AnonPages|Active\(file\)|Inactive\(file\)|Slab|SReclaimable|SUnreclaim|PageTables|KernelStack|Shmem):$/ { v[$1] = $2 }
    END {
      printf "%s\t%s\tMEM\t%s\n", ts, ph, v["MemAvailable:"] >> s
      printf "%s\t%s\tMEMI\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ts, ph, v["AnonPages:"], v["Active(file):"], v["Inactive(file):"], \
        v["Slab:"], v["SReclaimable:"], v["SUnreclaim:"], v["PageTables:"], v["KernelStack:"], v["Shmem:"], v["MemAvailable:"] >> a
    }' "$R/proc/meminfo"
}

sample_self() {
  local line ticks
  { read -r line < "$R/proc/${SAMPLER_SELF:-$$}/stat"; } 2>/dev/null || return 0
  # shellcheck disable=SC2086
  set -- ${line##*) }
  ticks=$(( ${12} + ${13} + ${14} + ${15} ))
  printf '%s\t%s\tSELF\t%s\n' "$ts" "$phase" "$ticks" >> "$OUT/attrib.tsv"
}

last_full=0
while true; do
  ts="$(date +%s)"
  read -r phase < "$OUT/phase" 2>/dev/null || phase=none
  full=0
  if [ "$ts" -ge $((last_full + INTERVAL)) ]; then full=1; last_full="$ts"; fi
  case "$phase" in burst*|overload*|recover*) fast=1 ;; *) fast=0 ;; esac
  if [ "$full" = 1 ] || [ "$fast" = 1 ]; then sample_meminfo "$ts" "$phase"; fi
  if [ "$full" = 1 ]; then
    if [ "$ts" -ge $((last_proc + PROC_INTERVAL)) ]; then with_proc=1; last_proc="$ts"; else with_proc=0; fi
    sample_attrib "$ts" "$phase" "$with_proc"
    sample_components "$ts" "$phase"
    sample_self
  fi
  [ -z "${SAMPLER_ONCE:-}" ] || exit 0
  if [ "$fast" = 1 ]; then sleep "$FAST_INTERVAL"; else sleep "$INTERVAL"; fi
done
