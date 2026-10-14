#!/usr/bin/env python3
"""Derive a matching H-disabled FDT for the non-H guest baseline."""
import ctypes
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
fdt = ctypes.CDLL("libfdt.so.1")
fdt.fdt_getprop.restype = ctypes.c_void_p
buffer = ctypes.create_string_buffer(source.read_bytes(), source.stat().st_size + 4096)
assert fdt.fdt_open_into(buffer, buffer, len(buffer)) == 0

def prop(node, name):
    size = ctypes.c_int()
    pointer = fdt.fdt_getprop(buffer, node, name, ctypes.byref(size))
    return ctypes.string_at(pointer, size.value) if pointer else None

def setprop(node, name, data):
    assert fdt.fdt_setprop(buffer, node, name, data, len(data)) == 0

node = fdt.fdt_first_subnode(buffer, fdt.fdt_path_offset(buffer, b"/cpus"))
while node >= 0:
    isa = prop(node, b"riscv,isa")
    if isa:
        parts = isa.split(b"_", 1)
        parts[0] = parts[0].replace(b"h", b"")
        setprop(node, b"riscv,isa", b"_".join(parts))
    extensions = prop(node, b"riscv,isa-extensions")
    if extensions:
        setprop(node, b"riscv,isa-extensions", b"\0".join(x for x in extensions.split(b"\0") if x != b"h"))
    node = fdt.fdt_next_subnode(buffer, node)
chosen = fdt.fdt_path_offset(buffer, b"/chosen")
args = prop(chosen, b"bootargs")
assert args and b"init=/root/kvm-test-init" in args
setprop(chosen, b"bootargs", args.replace(b"init=/root/kvm-test-init", b"init=/root/non-h-baseline-init"))
assert fdt.fdt_pack(buffer) == 0
size = int.from_bytes(buffer.raw[4:8], "big")
destination.write_bytes(buffer.raw[:size])
