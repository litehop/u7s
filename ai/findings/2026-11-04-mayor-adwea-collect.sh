#!/usr/bin/env bash
# usage: collect.sh OUTDIR  (run as root on the VM) -- memory snapshot used by the adwea findings
O="$1"; mkdir -p "$O"
date -u +%FT%TZ > "$O/time"
uname -r > "$O/kernel"
cat /proc/meminfo > "$O/meminfo"
cat /proc/vmstat > "$O/vmstat"
cat /proc/pressure/memory > "$O/psi-mem" 2>&1
dmesg 2>&1 | grep -i -E 'memory' > "$O/dmesg-memory"
cat /proc/cmdline > "$O/cmdline"
slabtop -o -s c 2>/dev/null | head -30 > "$O/slabtop"
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  [ -r "$p/smaps_rollup" ] || continue
  comm=$(cat $p/comm 2>/dev/null) || continue
  cg=$(sed 's|^0::||' $p/cgroup 2>/dev/null | head -1)
  awk -v pid=$pid -v comm="$comm" -v cg="$cg" '
    /^Rss:/ {rss=$2} /^Pss:/ {pss=$2} /^Private_Clean:/ {pc=$2} /^Private_Dirty:/ {pd=$2}
    /^Pss_Anon:/ {pa=$2} /^Pss_File:/ {pf=$2} /^Pss_Shmem:/ {ps=$2}
    END {printf "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n", pid, comm, cg, rss, pss, pc+pd, pa, pf, ps}' $p/smaps_rollup
done | sort -t$'\t' -k5 -nr > "$O/procs.tsv"
: > "$O/cgroups.tsv"
for d in /sys/fs/cgroup /sys/fs/cgroup/system.slice /sys/fs/cgroup/system.slice/*.service /sys/fs/cgroup/u7s.slice /sys/fs/cgroup/u7s.slice/*.service /sys/fs/cgroup/kubepods.slice /sys/fs/cgroup/user.slice /sys/fs/cgroup/init.scope; do
  [ -f "$d/memory.stat" ] || continue
  cur=$(cat $d/memory.current 2>/dev/null)
  awk -v d="${d#/sys/fs/cgroup}" -v cur="$cur" '{s[$1]=$2} END {printf "%s\tcur=%d\tanon=%d\tfile=%d\tkernel=%d\tslab=%d\tsock=%d\tshmem=%d\tkstack=%d\tpagetables=%d\n", d, cur, s["anon"], s["file"], s["kernel"], s["slab"], s["sock"], s["shmem"], s["kernel_stack"], s["pagetables"]}' $d/memory.stat >> "$O/cgroups.tsv"
done
for d in $(find /sys/fs/cgroup/kubepods.slice -maxdepth 3 -name '*pod*.slice' 2>/dev/null); do
  echo -e "${d#/sys/fs/cgroup}\tcur=$(cat $d/memory.current)" >> "$O/cgroups.tsv"
done
{ for f in /opt/u7s/bin/* /usr/local/bin/* /opt/cni/bin/* /usr/bin/crio /usr/bin/crun /usr/bin/conmon /usr/libexec/crio/*; do [ -f "$f" ] && echo "$f"; done; } | sort -u > "$O/bin.list"
{ echo "# fincore bytes: RES SIZE FILE"; xargs -a "$O/bin.list" fincore -b -o RES,SIZE,FILE 2>&1; } > "$O/fincore.txt"
ls -lR /opt/u7s /usr/local/bin /opt/cni/bin > "$O/binsizes.txt" 2>&1
KC=/var/lib/u7s/kubeconfig
kubectl --kubeconfig "$KC" get pods -A -o wide > "$O/pods.txt" 2>&1
crictl images > "$O/images.txt" 2>&1
free -m > "$O/free"
systemctl list-units --type=service --state=running --no-legend > "$O/services.txt"
cat /proc/swaps > "$O/swaps"
