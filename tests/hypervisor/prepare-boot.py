#!/usr/bin/env python3
"""Bundle a stock RISC-V Image and initramfs for RVVM's existing ELF loader."""
import argparse
import ctypes
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--image", type=Path, required=True)
p.add_argument("--initramfs", type=Path, required=True)
p.add_argument("--dtb", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()

kernel = a.image.read_bytes()
initramfs = a.initramfs.read_bytes()
kernel_address = 0x80200000
initramfs_address = 0x88000000
assert kernel_address + len(kernel) < initramfs_address
kernel_offset = 4096
initramfs_offset = (kernel_offset + len(kernel) + 4095) & ~4095
ident = b"\x7fELF\x02\x01\x01" + bytes(9)
header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 243, 1, kernel_address,
                     64, 0, 0, 64, 56, 2, 0, 0, 0)
segments = b"".join(struct.pack("<IIQQQQQQ", 1, 7, offset, addr, addr, len(data), len(data), 4096)
                    for offset, addr, data in [(kernel_offset, kernel_address, kernel),
                                               (initramfs_offset, initramfs_address, initramfs)])
with a.output.open("wb") as f:
    f.write(header + segments)
    f.seek(kernel_offset)
    f.write(kernel)
    f.seek(initramfs_offset)
    f.write(initramfs)

fdt = ctypes.CDLL("libfdt.so.1")
source = ctypes.create_string_buffer(a.dtb.read_bytes())
target = ctypes.create_string_buffer(len(source) + 4096)
assert fdt.fdt_open_into(source, target, len(target)) == 0
chosen = fdt.fdt_path_offset(target, b"/chosen")
assert chosen >= 0
for name, value in [(b"linux,initrd-start", initramfs_address),
                    (b"linux,initrd-end", initramfs_address + len(initramfs))]:
    encoded = struct.pack(">Q", value)
    assert fdt.fdt_setprop(target, chosen, name, encoded, len(encoded)) == 0
assert fdt.fdt_pack(target) == 0
size = struct.unpack_from(">I", target.raw, 4)[0]
a.dtb.write_bytes(target.raw[:size])
print(f"Prepared {a.output} and {a.dtb}; initramfs at {initramfs_address:#x}")
