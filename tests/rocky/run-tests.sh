#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
ulimit -c 0
root=$(cd "$(dirname "$0")/../.." && pwd)
build=$(mktemp -d /tmp/rvvm-rocky-tests.XXXXXX)
trap 'rm -rf "$build"' EXIT
cc=${CC:-cc}
flags=(-O2 -g -pthread -DRVVM_USER_TEST -ffunction-sections -fdata-sections
       -I"$root/src" -I"$root/src/util" -I"$root/include" -Wl,--gc-sections)
for name in test-exe-fd test-fd-lock test-process-state test-exec-ranges test-replay test-vm-backing test-vm-runtime test-brk; do
    extra=()
    if [[ $name == test-replay ]]; then extra=("$root/src/core/user_ptrace/user_ptrace_replay.c"); fi
    "$cc" "${flags[@]}" "$root/tests/rocky/$name.c" "${extra[@]}" "$root"/src/util/*.c \
        -ldl -lm -o "$build/$name"
    timeout 20 "$build/$name"
done
if (($#)); then
    for guest in test-clone-flags test-clone-thread test-thread-exit test-vfork test-openat2 test-seccomp test-jit-limits; do
        "${RISCV_CC:-clang}" --target=riscv64-linux-gnu -march=rv64gc -mabi=lp64d \
            -fuse-ld="${RISCV_LD:-lld}" -nostdlib -static -Wl,--build-id=none \
            "$root/tests/rocky/$guest.S" -o "$build/$guest"
        for emulator in "$@"; do
            prefixes=("")
            if [[ $guest == test-openat2 ]]; then prefixes+=(/); fi
            for prefix in "${prefixes[@]}"; do
                for bits in 39 48; do
                    RVVM_USER_PREFIX=$prefix RVVM_USER_VA_BITS=$bits timeout 20 "$emulator" "$build/$guest" >"$build/stdout" 2>"$build/stderr"
                    [[ ! -s $build/stdout && ! -s $build/stderr ]]
                    RVVM_USER_PREFIX=$prefix RVVM_USER_VA_BITS=$bits RVVM_NOJIT=1 timeout 20 "$emulator" "$build/$guest" >"$build/stdout" 2>"$build/stderr"
                    [[ ! -s $build/stdout && ! -s $build/stderr ]]
                done
            done
            echo "PASS $guest: $emulator"
        done
    done
fi
