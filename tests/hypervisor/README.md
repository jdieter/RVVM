# Guest KVM tests

RVVM exposes the RISC-V H extension by default on RV64. The outer Linux
kernel then provides `/dev/kvm`, which QEMU can use to run another RISC-V
Linux guest. Use `-nokvm` to disable H; RV32 and userspace emulation keep it off.

## Running the tests

You'll need GCC, Clang's RISC-V assembler, `llvm-objcopy`, LLD and QEMU 11.1+.
From the worktree root, run:

```sh
python3 tests/hypervisor/run-tests.py --linker /path/to/ld.lld
```

The runner builds RVVM, runs nine architecture/device tests, and checks
the same H instruction stream in QEMU and RVVM's JIT and interpreter.
You can use `--qemu PATH` to select another QEMU binary, `--rv32` to include RV32
checks, or `--native-only` to run without the RISC-V toolchain and QEMU.
If you're using an extracted LLD, add its library directory to
`LD_LIBRARY_PATH` if the loader can't find it.
Builds default to `release.OS.ARCH`; `--builddir` keeps them separate from
running VMs. Test assets and logs go in `.guest-kvm-assets/`.

QEMU is useful as a comparison, but it has bugs too. QEMU 10.2.2 mishandles
VU SRET (issue 3622), so it can't run the shared test. QEMU 11.1.2 passes
that test but retains incorrect `htval` on a physical PTE-fetch failure;
the native MMU test checks that field separately. It also still lets MXR
relax implicit page-table reads, contrary to the
[ISA clarification](https://github.com/riscv/riscv-isa-manual/pull/1543).
That separate stream therefore runs only on RVVM's JIT and interpreter.
The architectural reference is the
[RISC-V H specification](https://docs.riscv.org/reference/isa/v20260120/priv/hypervisor.html).

## Testing with Fedora

We tested the [Fedora 44 Server image](https://dl.fedoraproject.org/pub/alt/risc-v/release/44/Server/riscv64/images/Fedora-Server-Host-Generic-44-20260604.0.riscv64.raw.xz).
Check its adjacent SHA256 file before extracting it. Use separate disposable
outer and inner disks with distinct filesystem UUIDs, and select the outer
root by UUID: NVMe disks can enumerate in either order. Keep SSH forwards
bound to localhost and stop the VM before editing its disk with guestfish.

The image's kernel is an EFI zboot image. Extract its zstd payload to `Image`,
then bundle it with the matching initramfs and an H-enabled DTB generated
with RVVM's `-dumpdtb`:

```sh
python3 tests/hypervisor/prepare-boot.py --image Image \
  --initramfs initramfs.img --dtb outer.dtb --output linux-initramfs.elf
```

Launch stock OpenSBI with `-k linux-initramfs.elf -dtb outer.dtb`.
Custom DTBs must match the CPU model: advertise H by default and omit it
with `-nokvm`. RVVM does not rewrite a supplied DTB.
Also pass `initrdmem=0x88000000,SIZE` in the kernel command line, where SIZE
is the initramfs size in bytes; the DTB-only handoff didn't suffice in these
tests. The outer kernel needs `CONFIG_KVM=y`; stock OpenSBI 1.7 worked.

`guest-init.sh` reads `/root/kvm-test.conf` (`OUTER_UUID`, `INNER_UUID`,
`INNER_CPUS`) and runs the KVM API probe, lifecycle test and inner QEMU.
It needs the boot files and test programs staged at the paths in that script.
Use it for quick checks; use normal inner systemd for the full workload.

Stage `inner-systemd-check.sh` as `/root/kvm-systemd-check`, install its unit
in `/etc/systemd/system/` and its preset as
`/etc/systemd/system-preset/00-rvvm-kvm.preset`, then enable the unit.
The preset prevents first-boot setup from disabling it. Read
`/root/kvm-systemd-result.log` after shutdown; require `INNER_SYSTEMD_PASS`.
`guest-gcc-probe.sh` similarly saves compile/test results before poweroff.
Set `/root/kvm-expected-cpus` to match `INNER_CPUS`; the check defaults to two.
For the compiler workload, install GCC, stage `test-guest-workload.c` under
`/root/`, and create `/root/kvm-workload-required`. For a soak, also stage
`inner-soak.sh` under `/root/` and set `/root/kvm-soak-seconds`.
Eight inner CPUs needed four outer harts.

Bound runs with `timeout`. Ctrl-A followed by `x` exits RVVM; Ctrl-C goes to
the guest. The diagnostic scripts power off the disposable outer guest.

H-register snapshot roundtrip, model rejection and live VS execution remain
covered by `test-snapshot.c`. Keep the saved CPU model: an H-disabled snapshot
needs `-nokvm`, and an H snapshot needs the default H-enabled model.
General DMA/device snapshot fixes and their tests are in the separate
`snapshot-fixes` worktree. Earlier whole-machine restore results tested the
combined code, including those fixes.

See [PLAN.md](PLAN.md) for verified results and limits, and
[RUNROOT.md](RUNROOT.md) for the production runroot prerequisites.
