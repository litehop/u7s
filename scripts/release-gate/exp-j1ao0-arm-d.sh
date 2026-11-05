#!/usr/bin/env bash
# EXPERIMENT (never product): arm D = MemoryMin on control-plane units + earlier kubelet eviction.
# Runs in the VM as root after install, before the overload.
set -uo pipefail
# MiB: (Pss_Anon+Pss_File of the last pre-overload sample, WordPress resident) x 1.25
declare -A MIN=( [u7s-apiserver]=29 [u7s-kcm]=88 [kubelet]=62 [crio]=67 )
total=0
for u in "${!MIN[@]}"; do
  mkdir -p "/etc/systemd/system/$u.service.d"
  printf '[Service]\nMemoryAccounting=yes\nMemoryMin=%sM\n' "${MIN[$u]}" > "/etc/systemd/system/$u.service.d/memmin.conf"
  total=$(( total + MIN[$u] ))
done
mkdir -p /etc/systemd/system/system.slice.d
printf '[Slice]\nMemoryMin=%sM\n' "$((total + 20))" > /etc/systemd/system/system.slice.d/memmin.conf
systemctl daemon-reload
for u in "${!MIN[@]}"; do systemctl set-property --runtime "$u.service" "MemoryMin=${MIN[$u]}M"; done
systemctl set-property --runtime system.slice "MemoryMin=$((total + 20))M"
for u in "${!MIN[@]}"; do
  cg="$(systemctl show -p ControlGroup --value "$u.service")"
  echo "memory.min $u ($cg) = $(cat "/sys/fs/cgroup$cg/memory.min")"
done
echo "memory.min system.slice = $(cat /sys/fs/cgroup/system.slice/memory.min) root-children: $(cat /sys/fs/cgroup/cgroup.subtree_control)"
cat >> /var/lib/u7s/kubelet-config.yaml <<'YAML'
evictionHard:
  memory.available: 200Mi
evictionSoft:
  memory.available: 300Mi
evictionSoftGracePeriod:
  memory.available: 10s
kernelMemcgNotification: true
YAML
systemctl restart kubelet.service
sleep 20
journalctl -u kubelet --no-pager | grep -i "memcg\|eviction manager\|threshold" | tail -10
systemctl is-active kubelet.service
