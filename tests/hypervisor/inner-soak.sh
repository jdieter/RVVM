#!/bin/bash
# Run independent FPU/atomic/fork/storage workers alongside packet traffic.
set -euo pipefail
seconds=${1:-600}
gcc -O2 -Wall -Wextra -pthread /root/test-guest-workload.c -o /root/test-guest-workload
deadline=$((SECONDS + seconds))
iterations=0
while [ "$SECONDS" -lt "$deadline" ]; do
    jobs=()
    for worker in 1 2 3; do
        mkdir -p "/root/kvm-soak-$worker"
        timeout -s KILL 120s /root/test-guest-workload "/root/kvm-soak-$worker/storage" &
        jobs+=("$!")
    done
    ping -c 20 -i 0.1 -W 5 10.0.2.2 > /root/kvm-soak-network.log &
    jobs+=("$!")
    dd if=/dev/urandom of=/root/kvm-soak-storage bs=1M count=64 conv=fsync status=none
    sha256sum /root/kvm-soak-storage > /root/kvm-soak-storage.sha256
    for job in "${jobs[@]}"; do wait "$job"; done
    sha256sum -c /root/kvm-soak-storage.sha256
    iterations=$((iterations + 1))
done
sync
echo "INNER_SOAK_PASS seconds=$seconds iterations=$iterations cpus=$(getconf _NPROCESSORS_ONLN)"
