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
for name in test-exe-fd test-fd-lock test-fd-limits test-fork-cache test-process-state test-exec-ranges test-replay test-vm-backing test-vm-runtime test-vma-oom test-brk; do
    extra=()
    if [[ $name == test-replay ]]; then extra=("$root/src/core/user_ptrace/user_ptrace_replay.c"); fi
    "$cc" "${flags[@]}" "$root/tests/rocky/$name.c" "${extra[@]}" "$root"/src/util/*.c \
        -ldl -lm -o "$build/$name"
    timeout 20 "$build/$name"
done
"$cc" "${flags[@]}" -DUSE_JIT -DUSER_FAULT_META -Wl,--wrap=realloc -Wl,--wrap=calloc \
    "$root/tests/rocky/test-jit-oom.c" "$root"/src/rvjit/*.c "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-oom"
timeout 20 "$build/test-jit-oom"
"$cc" "${flags[@]}" -DUSE_JIT -DUSER_FAULT_META \
    "$root/tests/rocky/test-jit-pressure.c" "$root"/src/rvjit/*.c "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-pressure"
timeout 20 "$build/test-jit-pressure"
"$cc" "${flags[@]}" -DUSE_JIT -DUSER_FAULT_META \
    "$root/tests/rocky/test-jit-memory-probe.c" "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-memory-probe"
timeout 20 "$build/test-jit-memory-probe"
if [[ -f $root/compile_flags.txt ]] && grep -q -- '-DRVVM_STATIC_GLIBC_FORK' "$root/compile_flags.txt"; then
    "$cc" "${flags[@]}" -DRVVM_STATIC_GLIBC_FORK -fPIE -static-pie -Wl,--wrap=_Fork \
        "$root/tests/rocky/test-host-fork.c" -o "$build/test-host-fork"
    timeout 20 "$build/test-host-fork"
fi
if (($#)); then
    for guest in test-clone-flags test-clone-files test-fork-cache test-clone-thread test-clone-thread-private test-thread-exit test-vfork test-vfork-nofile test-vfork-concurrent test-openat2 test-seccomp test-pidfd-getfd test-kcmp test-jit-limits test-fpu-tininess test-mmap-huge test-mprotect-errors test-proc-exe; do
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
                    if [[ $guest == test-vfork ]]; then
                        for nojit in 0 1; do
                            (ulimit -S -n 64; ulimit -H -n 64; exec 63</dev/null
                             if [[ $nojit = 0 ]]; then unset RVVM_NOJIT; else export RVVM_NOJIT=1; fi
                             RVVM_USER_PREFIX=$prefix RVVM_USER_VA_BITS=$bits \
                                 timeout 20 "$emulator" "$build/$guest") >"$build/stdout" 2>"$build/stderr"
                            [[ ! -s $build/stdout && ! -s $build/stderr ]]
                        done
                    fi
                done
            done
            echo "PASS $guest: $emulator"
        done
    done
fi
