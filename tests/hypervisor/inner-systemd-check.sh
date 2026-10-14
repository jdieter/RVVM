#!/bin/bash
set -euxo pipefail
exec > /root/kvm-systemd-result.log 2>&1
test "$(cat /proc/1/comm)" = systemd
expected_cpus=2
if [ -r /root/kvm-expected-cpus ]; then expected_cpus=$(cat /root/kvm-expected-cpus); fi
test "$(getconf _NPROCESSORS_ONLN)" -eq "$expected_cpus"
test "$(uname -m)" = riscv64
systemctl is-active systemd-udevd
rpm --eval '%{_arch}'
printf 'RVVM_KVM_SYSTEMD_STORAGE_PASS\n' > /root/kvm-systemd-storage.txt
sync
sha256sum /root/kvm-systemd-storage.txt
start=$(date +%s)
sleep 2
test "$(date +%s)" -ge "$((start + 2))"
interface=$(ls /sys/class/net | grep -v '^lo$' | head -1)
ip link set "$interface" up
ip address replace 10.0.2.15/24 dev "$interface"
ping -c 3 -W 5 10.0.2.2
if [ -e /root/kvm-workload-required ]; then
    gcc -O2 -Wall -Wextra -pthread /root/test-guest-workload.c -o /root/test-guest-workload
    timeout -s KILL 120s /root/test-guest-workload
    dnf check
fi
if [ -r /root/kvm-soak-seconds ]; then
    /root/inner-soak.sh "$(cat /root/kvm-soak-seconds)"
fi
echo INNER_SYSTEMD_PASS
sync
if [ ! -e /root/kvm-keep-running ]; then
    systemctl --no-block poweroff
fi
