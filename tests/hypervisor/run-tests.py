#!/usr/bin/env python3
"""Run architecture state tests and the independent H instruction-stream oracle."""
import argparse
import os
import platform
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument("--linker", type=Path)
p.add_argument("--qemu", default="qemu-system-riscv64")
p.add_argument("--native-only", action="store_true")
p.add_argument("--rv32", action="store_true", help="Build normal RV32 support alongside RV64 H")
p.add_argument("--builddir", type=Path, help="Keep qualification builds separate from running VMs")
p.add_argument("--assets", type=Path, default=Path(".guest-kvm-assets"))
a = p.parse_args()
if not a.native_only and a.linker is None:
    p.error("--linker is required for instruction-stream tests")
a.assets.mkdir(exist_ok=True)
env = os.environ.copy()
env.setdefault("CCACHE_DIR", "/tmp/guest-kvm-ccache")

def run(command, timeout=120):
    result = subprocess.run([str(x) for x in command], env=env,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        result.check_returncode()
    return result.stdout

architecture = {"aarch64": "arm64"}.get(platform.machine(), platform.machine())
build = a.builddir or Path(f"release.{platform.system().lower()}.{architecture}")
run(["make", "-j4", f"BUILDDIR={build}", "USE_GUI=0", "USE_LIB=0", "USE_LIB_STATIC=1",
     f"USE_RV32={int(a.rv32)}"])
for case in ("model", "state", "mmu", "interrupts", "timer", "snapshot", "nvme-irq", "pci-irq", "rtl-irq"):
    executable = a.assets / f"test-{case}"
    run(["gcc", "-O2", "-Wall", "-Wextra", "-Iinclude", "-Isrc", "-Isrc/util",
         "-DUSE_RV64=1", "-DUSE_FPU=1", "-DUSE_JIT=1",
         *(["-DUSE_RV32=1"] if a.rv32 else []),
         f"tests/hypervisor/test-{case}.c", build / "librvvm_static.a",
         "-pthread", "-ldl", "-lm", "-latomic", "-o", executable])
    print(run([executable]).strip())

if a.native_only:
    raise SystemExit(0)

for stream in ("test-stream", "test-mxr-stream"):
    obj = a.assets / f"{stream}.o"
    elf = a.assets / f"{stream}.elf"
    binary = a.assets / f"{stream}.bin"
    run(["clang", "--target=riscv64", "-march=rv64gch", "-mabi=lp64d", "-c",
         f"tests/hypervisor/{stream}.S", "-o", obj])
    run([a.linker, "-Ttext=0x80000000", "--entry=_start", obj, "-o", elf])
    run(["llvm-objcopy", "-O", "binary", elf, binary])
    commands = {
        "QEMU H oracle": [a.qemu, "-machine", "virt", "-cpu", "rv64,h=true",
                           "-nographic", "-m", "128M", "-bios", binary],
        "RVVM JIT": [build / f"rvvm_{architecture}", binary, "-m", "128M", "-nogui",
                      "-nogpu", "-nonet", "-noisolation"],
    }
    commands["RVVM interpreter"] = commands["RVVM JIT"] + ["-nojit"]
    for name, command in commands.items():
        # QEMU 11 still applies MXR to implicit G-stage reads, contrary to
        # the ISA manual clarification in riscv/riscv-isa-manual#1543.
        if stream == "test-mxr-stream" and name == "QEMU H oracle":
            continue
        output = run(command, timeout=15)
        assert "PASS\n" in output and "FAIL" not in output, (name, stream, output)
        print(f"PASS {name}: {stream}")

if a.rv32:
    obj = a.assets / "test-rv32-stream.o"
    elf = a.assets / "test-rv32-stream.elf"
    binary = a.assets / "test-rv32-stream.bin"
    run(["clang", "--target=riscv32", "-march=rv32gc", "-mabi=ilp32d", "-c",
         "tests/hypervisor/test-rv32-stream.S", "-o", obj])
    run([a.linker, "-Ttext=0x80000000", "--entry=_start", obj, "-o", elf])
    run(["llvm-objcopy", "-O", "binary", elf, binary])
    for mode in ([], ["-nojit"]):
        output = run([build / f"rvvm_{architecture}", binary, "-rv32",
                      "-m", "128M", "-nogui", "-nogpu", "-nonet", *mode], timeout=15)
        assert "PASS\n" in output and "FAIL" not in output, output
        print(f"PASS RV32 H-disabled {'interpreter' if mode else 'JIT'} baseline")
