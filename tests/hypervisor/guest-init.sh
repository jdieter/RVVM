#!/bin/bash
# Fast diagnostic boot; the normal systemd boot is tested separately.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
source /root/kvm-test.conf
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
# Allow local SSH inspection when RVVM supplies a userspace NIC/port forward.
modprobe r8169
for interface in /sys/class/net/*; do
    interface=${interface##*/}
    [ "$interface" = lo ] && continue
    ip link set "$interface" up
    ip address replace 192.168.0.100/24 dev "$interface"
    ip route replace default via 192.168.0.1 dev "$interface"
done
mkdir -p /run/sshd
/usr/sbin/sshd
mkdir -p /run/systemd/resolve /run/NetworkManager
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
printf '\nOUTER KVM PROBE\n'
timeout -s KILL 20s /root/test-kvm-run
printf '\nKVM LIFECYCLE, ISOLATION AND DIRTY LOGGING\n'
gcc -O2 -Wall -Wextra -pthread /root/test-kvm-lifecycle.c -o /root/test-kvm-lifecycle
timeout -s KILL 90s /root/test-kvm-lifecycle
printf '\nINNER QEMU KVM KERNEL\n'
outer_root=$(blkid -U "$OUTER_UUID")
inner_root=$(blkid -U "$INNER_UUID")
mount "${outer_root%p3}p2" /boot
timeout -s KILL 1200s qemu-system-riscv64 \
    -machine virt -accel kvm -cpu host -bios none -kernel /root/inner-Image \
    -initrd /boot/initramfs-6.19.8-200.0.riscv64.fc43.riscv64.img \
    -drive file="${inner_root%p3}",format=raw,if=none,id=inner \
    -device virtio-blk-pci,drive=inner \
    -m 2G -smp "${INNER_CPUS:-4}" -display none -serial stdio -monitor none \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22422-:22 -device virtio-net-pci,netdev=net0 \
    -append 'console=ttyS0 earlycon nokaslr root=/dev/vda3 rootflags=subvol=root rw selinux=0'
printf '\nINNER TEST FINISHED\n'
sync
poweroff -f
