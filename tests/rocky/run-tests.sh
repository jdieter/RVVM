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
for name in test-exe-fd test-fd-lock test-fd-limits test-fork-cache test-process-state test-exec-ranges test-replay test-vma-oom test-brk test-proc-maps test-seccomp-filter test-aio test-elf-file-pages; do
    extra=()
    if [[ $name == test-replay ]]; then extra=("$root/src/core/user_ptrace/user_ptrace_replay.c"); fi
    "$cc" "${flags[@]}" "$root/tests/rocky/$name.c" "${extra[@]}" "$root"/src/util/*.c \
        -ldl -lm -o "$build/$name"
    timeout 20 "$build/$name"
done
"$cc" "${flags[@]}" "$root/tests/rocky/test-user-malloc.c" "$root/src/core/rvvm_user_malloc.c" \
    -o "$build/test-user-malloc"
timeout 60 "$build/test-user-malloc"
"$cc" "${flags[@]}" -DUSE_JIT -Wl,--wrap=realloc -Wl,--wrap=calloc \
    "$root/tests/rocky/test-jit-oom.c" "$root"/src/rvjit/*.c "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-oom"
timeout 20 "$build/test-jit-oom"
"$cc" "${flags[@]}" -DUSE_JIT \
    "$root/tests/rocky/test-jit-pressure.c" "$root"/src/rvjit/*.c "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-pressure"
timeout 20 "$build/test-jit-pressure"
"$cc" "${flags[@]}" -DUSE_JIT \
    "$root/tests/rocky/test-jit-memory-probe.c" "$root"/src/util/*.c \
    -ldl -lm -o "$build/test-jit-memory-probe"
timeout 20 "$build/test-jit-memory-probe"
bash "$root/tests/rocky/check-libc-rule.sh"
# Raw forks use only the public libc API: test dynamic and static links.
for link in -pie -static-pie; do
    if [[ $link == -static-pie ]] && ! echo 'int main(void){return 0;}' \
        | "$cc" -fPIE -static-pie -x c - -o "$build/static-probe" 2>/dev/null; then
        echo "SKIP static-pie test-host-fork: no static libc"
        continue
    fi
    "$cc" "${flags[@]}" -fPIE $link "$root/tests/rocky/test-host-fork.c" \
        "$root/src/core/rvvm_user_malloc.c" "$root"/src/util/*.c -ldl -lm -o "$build/test-host-fork"
    timeout 60 "$build/test-host-fork"
done
if (($#)); then
    "$cc" -O2 "$root/tests/rocky/noclone3.c" -o "$build/noclone3"
    "$cc" -O2 "$root/tests/rocky/test-proc-exe-race.c" -o "$build/test-proc-exe-race"
    for guest in test-clone-flags test-clone-files test-fork-cache test-clone-thread test-clone-thread-private test-thread-exit test-vfork test-vfork-nofile test-vfork-concurrent test-openat2 test-seccomp test-pidfd-getfd test-kcmp test-jit-limits test-jit-fault-regs test-fpu-tininess test-mmap-huge test-mprotect-errors test-proc-exe test-proc-cmdline test-signalfd test-sigaction-query test-ptrace-redirect test-proc-maps; do
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
            # Hosts that refuse clone3 (container seccomp profiles) get
            # VFORK children through clone(2).
            if [[ $guest == test-vfork* || $guest == test-clone-thread* ]]; then
                for nojit in 0 1; do
                    (if [[ $nojit = 0 ]]; then unset RVVM_NOJIT; else export RVVM_NOJIT=1; fi
                     timeout 20 "$build/noclone3" "$emulator" "$build/$guest") >"$build/stdout" 2>"$build/stderr"
                    [[ ! -s $build/stdout && ! -s $build/stderr ]]
                done
            fi
            if [[ $guest == test-proc-exe ]]; then
                for bits in 39 48; do
                    for nojit in "" 1; do
                        for sharing in "" shared; do
                            opts=(-u RVVM_NOJIT RVVM_USER_PREFIX= RVVM_USER_VA_BITS=$bits)
                            if [[ $nojit ]]; then opts+=(RVVM_NOJIT=1); fi
                            result=0
                            env "${opts[@]}" timeout 20 "$build/test-proc-exe-race" \
                                "$emulator" "$build/$guest" ${sharing:+"$sharing"} \
                                >"$build/stdout" 2>"$build/stderr" || result=$?
                            if [[ $result = 77 ]]; then
                                echo "SKIP proc/exe before child initialization: host ptrace denied"
                                continue
                            fi
                            [[ $result = 0 && ! -s $build/stderr ]]
                            grep -qx 'PASS proc/exe before child initialization' "$build/stdout"
                        done
                    done
                done
            fi
            echo "PASS $guest: $emulator"
        done
    done
    # Hosts may refuse EXEC, which guest code never needs: under MDWE, and for
    # a file on a noexec tmpfs (in a user and mount namespace, where allowed).
    "${RISCV_CC:-clang}" --target=riscv64-linux-gnu -march=rv64gc -mabi=lp64d \
        -fuse-ld="${RISCV_LD:-lld}" -nostdlib -static -Wl,--build-id=none \
        "$root/tests/rocky/test-exec-refused.S" -o "$build/test-exec-refused"
    "$cc" -O2 "$root/tests/rocky/mdwe-exec.c" -o "$build/mdwe-exec"
    printf '\x13\x05\xa0\x02\x67\x80\x00\x00' >"$build/code"
    mdwe=1 noexec=1
    "$build/mdwe-exec" true || { echo "SKIP test-exec-refused under MDWE: unsupported"; mdwe=0; }
    mkdir "$build/noexec"
    unshare -rm true 2>/dev/null || { echo "SKIP test-exec-refused on noexec: no user namespace"; noexec=0; }
    for emulator in "$@"; do
        for nojit in "" 1; do
            env ${nojit:+RVVM_NOJIT=1} timeout 20 "$emulator" "$build/test-exec-refused" "$build/code"
            if ((mdwe)); then
                env ${nojit:+RVVM_NOJIT=1} timeout 20 "$build/mdwe-exec" "$emulator" \
                    "$build/test-exec-refused" "$build/code"
            fi
            if ((noexec)); then
                env ${nojit:+RVVM_NOJIT=1} unshare -rm sh -c \
                    'mount -t tmpfs -o noexec tmpfs "$1" && cp "$2" "$1/code" && exec timeout 20 "$3" "$4" "$1/code"' \
                    sh "$build/noexec" "$build/code" "$emulator" "$build/test-exec-refused"
            fi
        done
        echo "PASS test-exec-refused: $emulator"
    done
fi
