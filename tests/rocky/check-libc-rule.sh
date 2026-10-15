#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# The libc rule (src/core/rvvm_user_fork.h): rvvm_user's raw forks run no libc
# recovery, so code that runs on its threads after startup must not call libc
# functions holding process-wide locks. Compile the userland sources and the
# shared code they run, and fail on any import of such a function outside
# the files allowed to use it.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
build=$(mktemp -d /tmp/rvvm-libc-rule.XXXXXX)
trap 'rm -rf "$build"' EXIT
cc=${CC:-cc}
flags=(-c -O2 -DRVVM_USER_TEST -DUSE_JIT=1 -DUSE_RV64=1 -DUSE_FPU=1 -DUSE_NO_DLIB=1
       -I"$root/src" -I"$root/src/util" -I"$root/include")
denied='^(fopen|fopen64|fdopen|freopen|fclose|fputs|fputc|fprintf|vfprintf|printf|vprintf|puts|putchar|fflush|fgets|fgetc|getline|getdelim|fwrite|fread|fscanf|scanf|rewind|fseek|ftell|setvbuf|stdin|stdout|stderr|perror|popen|pclose|system|getpw[a-z_]*|getgr[a-z_]*|getspnam[a-z_]*|initgroups|dlopen|dlsym|dlclose|setenv|putenv|unsetenv|clearenv|getrandom|arc4random[a-z_]*|exit|atexit|on_exit|setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid|setresgid|setgroups|pthread_create|pthread_join|pthread_tryjoin_np|pthread_timedjoin_np|pthread_detach|opendir|fdopendir|readdir|readdir64|closedir|localtime|localtime_r|tzset|mktime|strftime|syslog|setlocale|gettext|dcgettext|mallopt)$'
# Startup-only and fatal-only uses: the reason is recorded with each entry.
declare -A allowed=(
    [src/rvvm_user_main.c:fprintf]="usage message before any thread"
    [src/rvvm_user_main.c:stderr]="usage message before any thread"
    [src/util/threading.c:pthread_create]="rvvm_thread_* holds the lifecycle lock"
    [src/util/threading.c:pthread_join]="rvvm_thread_* holds the lifecycle lock"
    [src/util/threading.c:pthread_tryjoin_np]="rvvm_thread_* holds the lifecycle lock"
    [src/util/threading.c:pthread_detach]="rvvm_thread_* holds the lifecycle lock"
    [src/util/utils.c:stderr]="log_print writes directly on POSIX; fputs is the non-POSIX fallback"
    [src/util/utils.c:fputs]="non-POSIX fallback only"
)
sources=("$root"/src/rvvm_user_main.c "$root"/src/core/rvvm_user.c "$root"/src/core/rvvm_user_malloc.c
         "$root"/src/core/user_ptrace/*.c "$root"/src/core/rvvm.c "$root"/src/util/threading.c
         "$root"/src/util/locking.c "$root"/src/util/user_fd_guard.c "$root"/src/util/utils.c
         "$root"/src/util/vma_ops.c "$root"/src/util/vector.c "$root"/src/util/hashmap.c
         "$root"/src/util/rvtimer.c "$root"/src/util/elf_load.c "$root"/src/util/blk_io.c
         "$root"/src/rvjit/rvjit.c "$root"/src/rvjit/rvjit_emit.c "$root"/src/cpu/riscv_hart.c
         "$root"/src/cpu/riscv_mmu.c "$root"/src/cpu/riscv_cpu.c "$root"/src/cpu/riscv_priv.c
         "$root"/src/cpu/riscv_csr.c "$root"/src/cpu/riscv64_user_interpreter.c)
failed=0
for source in "${sources[@]}"; do
    name=${source#"$root"/}
    object=$build/$(echo "$name" | tr / _).o
    "$cc" "${flags[@]}" "$source" -o "$object"
    while read -r symbol; do
        if [[ -v allowed[$name:$symbol] ]]; then continue; fi
        echo "libc rule: $name imports $symbol"
        failed=1
    done < <(nm -u "$object" | awk '{print $2}' | sed 's/@.*//' | grep -E "$denied" || true)
done
((!failed))
echo "PASS libc rule: no lock-holding libc imports in rvvm_user's runtime code"
