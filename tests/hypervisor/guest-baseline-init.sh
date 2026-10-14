#!/bin/bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
result=/root/non-h-baseline-result.log
{
    uname -a
    test "$(getconf _NPROCESSORS_ONLN)" -eq 2 &&
        test ! -e /dev/kvm &&
        rpm --eval '%{_arch}' &&
        printf 'NON_H_STORAGE_PASS\n' > /root/non-h-storage.txt &&
        sync && sha256sum /root/non-h-storage.txt && echo NON_H_BASELINE_PASS
} > "$result" 2>&1
cat "$result"
sync
sleep 2
poweroff -f
