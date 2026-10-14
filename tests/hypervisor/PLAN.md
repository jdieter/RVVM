# Guest KVM implementation and results

We need to run QEMU inside an RVVM guest for runroot. The problem is that
host KVM can't execute RISC-V instructions on an x86 or ARM host.
RVVM now implements the RISC-V H extension, so the outer Linux kernel can
provide KVM and QEMU can supply the inner guest's devices. This means we
can use stock Linux and QEMU for the inner VM.

The implementation covers HS/VS CSR banks, trap delegation and returns,
virtual interrupts and timers, two-stage Sv39x4/Sv48x4 translation, H memory
instructions, HFENCE and translation/JIT invalidation. Review also found
IRQ races in NVMe, PCI and RTL8169, along with stale MPRV translations and
incorrect timer/page-table permissions. Those fixes have regression tests.

H-register serialization and live VS snapshot resume remain in this worktree.
General DMA/device snapshot fixes and tests have moved to `snapshot-fixes`,
based on the current Rocky source. The earlier whole-machine tests below
used the combined implementation; their results depend on those fixes.

## What passed

We tested on x86 and ARM64 hosts using stock Fedora Linux and explicit
QEMU `-accel kvm -cpu host`, with RVVM's default isolation enabled.
The integration images used `selinux=0` for the staged test scripts, so
we haven't verified enforcing SELinux. These checks passed:

* Nine KVM architectural/device tests, the independent QEMU H instruction
  comparison, and RVVM JIT/interpreter streams. RV32 H-disabled builds and
  instruction tests pass too. See [README.md](README.md) for QEMU differences.
* Normal inner systemd, SMP, timers, PCI virtio disk/network, SSH, a GCC
  package install and compilation, FPU thread state, shared atomics,
  fork/exec, mapped-file writes and `dnf check`.
* 384 stress VM lifecycles with parallel execution, RAM isolation and dirty
  logging, in addition to the initial 32-lifecycle check.
* Eight inner CPUs over a 600-second soak spanning whole-machine save/reload:
  40 disk write/hash rounds (2.5 GiB), 120 concurrent workloads,
  48 million atomic increments and 800 ping packets.
* Actual ARM64 Mock `--new-chroot` execution with `/dev/kvm` bound into the
  container: the API probe and full four-CPU inner Linux workload passed.
* Final ARM64 whole-machine save/reload: fresh outer/inner SSH, unchanged
  storage hash, repeated compiler/FPU/atomic/fork/storage checks, network
  traffic and clean shutdown. No MAC override was needed.

Results were saved to guest disks and read back after shutdown. Independent
review reproduced the CPU and device bugs, checked the fixes and found no
remaining concrete blocker in the combined implementation. The tested
combined ARM64 binary SHA256 is
`b4e951efd8099f17e46f452d91a77971fca1386f46e5334f3e5ef7d2a46cdb68`.

The logs are under `.guest-kvm-assets/`:

| Check | Evidence |
|---|---|
| Architecture and RV32 | `architecture-default-kvm.log`, `architecture-default-kvm-rv64.log`, `arm64-native-default-kvm.log`, `rv32-only-stream.log` |
| Eight-CPU soak | `eight-cpu-soak-result.log` |
| Mock container | `mock-arm64-persisted-acceptance.log` |
| Final ARM64 snapshot restore | `arm64-final-snapshot-acceptance.log` |

## Limits

H is enabled by default on RV64, with fixed VSXL/UXL=64; `-nokvm` disables it.
RV32 and userspace emulation keep H off. RV32 H, guest AIA and
hardware guest external interrupt files aren't advertised; GEILEN is zero.
Linux reports the KVM capabilities it actually provides.

Eight inner CPUs on two outer harts hit
systemd device-discovery deadlines; the successful soak used four outer harts
and 6 GiB. Whole-device save/reload needs the separate snapshot fixes.

Production runroot still needs the image and worker changes in
[RUNROOT.md](RUNROOT.md). The implementation is based on `0b3dbc0`.
