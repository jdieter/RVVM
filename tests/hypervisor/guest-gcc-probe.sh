#!/bin/bash
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
result=/root/kvm-lifecycle-result.log
gcc -O2 -Wall -Wextra -pthread /root/test-kvm-lifecycle.c -o /root/test-kvm-lifecycle > "$result" 2>&1
compile_status=$?
echo "COMPILE_EXIT=$compile_status" >> "$result"
if [ "$compile_status" -eq 0 ]; then
    timeout -s KILL 90s /root/test-kvm-lifecycle >> "$result" 2>&1
    echo "TEST_EXIT=$?" >> "$result"
fi
cat "$result"
sync
sleep 2
poweroff -f
