# Using guest KVM in runroot

For runroot, we need RV64 RVVM with its default H support, an H-enabled DTB,
an outer Linux kernel with `CONFIG_KVM`, and access to `/dev/kvm` inside
the container. Stock OpenSBI 1.7 worked. QEMU must use `-accel kvm -cpu host`;
a successful TCG boot doesn't tell us whether KVM works.

`mock-kvm.cfg` binds `/dev/kvm` and the test assets into a Fedora RISC-V
Mock `--new-chroot` container. That setup passed the API probe and full
inner Linux workload on the ARM64 dev host, with SELinux disabled in the
test images. When you set up production runroot, check its generated device
mounts too; don't assume Mock exposes KVM by default.

Two production prerequisites remain in the toolkit's `automation/` directory:

* `check-vm-update` submits Koji runroot with `--new-chroot` on the `runroot`
  channel. It skips Rocky 10 RISC-V because there's no published qcow2.
* `vm-update-worker` handles x86_64, aarch64 and s390x. It needs a RISC-V
  image and boot case before it can run its SSH package-update checks.

The [Rocky 10 RISC-V image directory](https://dl.rockylinux.org/pub/rocky/10/images/riscv64/)
had container archives but no GenericCloud qcow2 on 2026-10-14. We need to
choose or publish a Rocky VM image first. Fedora was used to test the
emulator; it doesn't establish that the Rocky image-update workflow passes.

The tested inner QEMU boot uses `-machine virt -accel kvm -cpu host -bios none
-kernel Image -initrd INITRAMFS`, virtio PCI disk/network, and the image's
root/subvolume command line. Extract `Image` from EFI zboot if needed, and
use the matching initramfs. Linux KVM provides SBI to its supervisor guest;
M-mode OpenSBI isn't an inner KVM boot option. Firmware boot needs a tested
S-mode firmware path.

Once the worker supports the image, run its normal update flow, including
booting the newest installed kernel and checking packages over SSH. Require
explicit KVM, working disk/network I/O, and a successful normal H-disabled
RVVM boot. No toolkit files or production configuration were changed here.
